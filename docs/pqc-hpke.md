# pqc-hpke

The **pqc-hpke** key reader derives Arnika's 32-byte PQC key by running an HPKE
(RFC 9180) key agreement directly with the Arnika peer, over the socket Arnika
already owns. It replaces reading the PQC key via file from an external PQC
provider: no external daemon, no key on disk, no new port.

## Table of Contents

- [At a Glance](#at-a-glance)
- [How the Module Works](#how-the-module-works)
- [How the Module Is Constructed](#how-the-module-is-constructed)
- [Part 1 — Prepare the Host](#part-1--prepare-the-host)
- [Part 2 — Configuration Reference](#part-2--configuration-reference)
- [Part 3 — Compile](#part-3--compile)
- [Part 4 — Run](#part-4--run)
- [Migrating from an External PQC Provider](#migrating-from-an-external-pqc-provider)
- [Testing the Module](#testing-the-module)
- [Security Notes](#security-notes)
- [References](#references)

## At a Glance

| Property | Value |
|---|---|
| Kind | Key reader (unmanaged) |
| Exchange | 3 messages, 2 round trips, 5 datagrams per round |
| Selection | Runtime, via `PQC_ENABLED`, **enabled by default** |
| Build tag | _(none, the sole PQC backend, always compiled)_ |
| Platform | any |
| Adapter | [`repositories/pqc-hpke.go`](../repositories/pqc-hpke.go) |
| Tests | [`repositories/pqc-hpke_test.go`](../repositories/pqc-hpke_test.go) |
| Ciphersuite | MLKEM1024-P384 · HKDF-SHA384 · ExportOnly |
| Dependencies | Go standard library only (`crypto/hpke`, `crypto/hkdf`, `crypto/sha3`) |
| Key at rest | none |
| Replaces | External PQC provider via `PQC_PSK_FILE` |

## How the Module Works

One round per interval, **three messages, two round trips**:

```
initiator -> responder   pubKey        2 frames, 1007 + 872 bytes on the wire
initiator <- responder   enc ‖ tag_R   2 frames, 1007 + 888 bytes
initiator -> responder   tag_I         1 frame,  123 bytes
```

1. **The initiator generates a fresh HPKE key pair.** A new pair every round is
   what provides forward secrecy: a key recovered later cannot decrypt earlier
   rounds.
2. **It sends the public key to the peer** — 1665 bytes (1568 for ML-KEM-1024
   plus 97 for P-384), split into two frames, each sealed with AES-256-GCM and
   signed with HMAC-SHA256 under `ARNIKA_PSK`. This is the same envelope that
   already protects the QKD key-id exchange, on the same port.
3. **The responder encapsulates and exports 32 bytes** with `hpke.NewSender`
   against that public key, then answers with the encapsulation **and its own
   confirmation tag as one message**. The reply is also the acknowledgement:
   there is no separate ack.
4. **The initiator decapsulates, exports the same 32 bytes, and checks the
   responder's tag.** Nothing is published unless it matches.
5. **The initiator sends its own tag and publishes.** The responder verifies it
   and publishes too. That tag is both the confirmation and the acknowledgement
   of the reply.

The exchange is the same shape `udpClient` uses for the QKD key id: send a
request, read the reply off the dialled socket, retry the whole message on
timeout. The initiator owns the schedule, the retries and the timeout; the
responder has none of the three, because the initiator's first message is what
starts its side of the round.

### Why the confirmation tags are mandatory

ML-KEM uses **implicit rejection**. FIPS 203 decapsulation never fails: handed a
malformed ciphertext it returns a *pseudorandom* shared secret rather than an
error. Without an explicit check, a corrupted encapsulation would leave the two
peers holding **different keys, silently, with no error anywhere** — and the
first symptom would be a WireGuard handshake failure one interval later,
carrying no diagnostic that points at the PQC layer.

So each peer derives a 16-byte tag from the agreed key with HKDF-SHA3-256,
exchanges it, and compares in constant time. **Nothing is published until the
peer's tag matches.** On a mismatch the round fails, the previous key stays live
until `PQC_MAX_KEY_AGE`, and the next round retries. The tunnel is never
poisoned by a divergent key.

This looks redundant — both peers export from one HPKE context, so they
"cannot" disagree. Implicit rejection is precisely the case where that intuition
fails. Do not remove the check.

**The tag is bound to the sender's role**, `I` or `R`, as well as to the round.
Without the role label both peers compute the *identical* tag, and the second
one sent is a pure echo of the first: it proves possession of `ARNIKA_PSK`,
which the envelope already proved, and nothing at all about the agreed key. With
the label, each direction is a real possession proof.
`TestPQCConfirmTagsAreRoleSeparated` pins this.

### Recovering from a backward clock step

Publication keeps the highest round, which is what makes two peers converge when
overlapping rounds complete in different orders. Round numbers come from wall
time, so a backward step across a boundary put every newly confirmed round
*below* the published one: the old key kept aging on the monotonic clock,
`GetNewKey()` began failing once it passed `PQC_MAX_KEY_AGE`, and no lower round
could replace it until wall time reached the previous round again or the process
restarted.

A confirmed lower round therefore becomes the new publication baseline **once
the published key is stale**, and only then. The staleness decision reads
`time.Since`, hence the monotonic clock, so the adjusted wall clock that caused
the problem cannot also mask it. The reset zeroes the superseded key under the
same write lock as any other publication and logs a warning with both rounds and
the old key's age.

Nothing else is relaxed. The frame still has to pass the envelope's HMAC and
timestamp checks, still has to fall inside the `[current-1, current+1]` round
window, and still has to confirm, so a malformed, unauthenticated, out-of-window
or unconfirmed lower round is never published however stale the current key is.
While the published key is fresh, higher-round-wins is unchanged.

`HandleFrame` additionally abandons a round in flight once it falls outside that
window: its confirmation tag would be rejected there, so the pending key could
never be published, and keeping the state live made `respondPubKey` reject every
newly current round as behind it — the responder could take no part in the
recovery. Two peers whose old keys go stale moments apart converge on the first
round both are eligible to reset on.

A residual remains, as it must for any protocol whose last message is
unacknowledged: if `tag_I` is lost, the initiator has published and the
responder has not, so for one interval the two may feed different keys into the
PSK. The next round reconverges them, and `PQC_MAX_KEY_AGE` bounds how long a
lone key can be used. `TestPQCLostTagLeavesOnlyTheInitiatorPublished` holds this
behaviour in place: the responder must end up **without** a key, never with a
different one.

### Round scheduling

- The round index is derived from the clock, `unix / PQC_ROUND_INTERVAL`, so it
  survives an asymmetric restart. An in-memory counter would deadlock when one
  peer restarts and the other does not.
- **A round runs immediately at startup**, after a 100 ms grace so a peer
  booting at the same moment has time to bind its listener. Waiting for the
  first boundary left the first rekey with no key at all — a "failed to retrieve
  PQC key" warning and a fallback for one whole interval. This round only
  completes if both peers start inside the same interval, so a failure is
  expected and logged at INFO.
- **Later rounds are scheduled to finish before their boundary**, by waking one
  round timeout early, so a key for that boundary exists rather than being
  published at it. The round served is always the boundary that *follows* now,
  so it is in the future by construction; if the ideal start has already passed
  the round begins late rather than being skipped, because skipping made the
  choice depend on which side of the wake instant each peer evaluated, and peers
  milliseconds apart then picked different rounds.
- **Each iteration waits out its round's boundary** before asking for the next
  one. The index is clock-derived, so looping while the boundary is still ahead
  names the same round again, and a round that finished in milliseconds would be
  re-run until the boundary passed. `TestPQCRunServesEachRoundOnce` pins this.
- **A failed write costs a retry, not the round.** At startup the peer's
  listener can be milliseconds behind, and the kernel reports the gap as ICMP
  port-unreachable on the next send. The initiator retries a failed write three
  times at 50 ms spacing. The responder does not: it answers the source address
  of a datagram it just received, so that port is bound by definition, and a
  sleep on its path would block the UDP read loop.
- **The role is decided once per round** from the round index, using the same
  derivation that elects PRIMARY/BACKUP for an interval. Both peers compute it
  from the same PSK, so exactly one of them initiates; the other only answers.
  Deriving it mid-round would flip initiator and responder in flight.
- Only the initiator of a round does anything on the schedule. A node that is
  not the initiator sleeps: it needs no timer, because the peer's first message
  drives it.
- The public key is sent with **three attempts**, each waiting
  `PQC_ROUND_TIMEOUT / 3` for the reply. HPKE is single-shot, so an exhausted
  budget has no partial state to recover: the round fails and the next proceeds.
- A retried public key is answered from the **stored** reply, not by
  encapsulating again. A second encapsulation would agree a second key for the
  same round, and whichever reply reached the initiator first would decide which
  key it confirmed while the responder kept the other.
  `TestPQCRetriedPubKeyIsAnsweredFromTheStoredReply` pins this.

> [!IMPORTANT]
> **Scheduling does not align the two peers' reads.** Arnika's rekey instant is
> independent of the round boundary, so if a publish lands between the two
> peers' `setPSK` calls, one derives the PSK from round *N* and the other from
> *N−1*, and the tunnel drops until the next rekey. The probability is the read
> gap divided by the interval — a few tens of milliseconds over
> `PQC_ROUND_INTERVAL` — and it does not depend on where in the interval the
> publish sits, so no schedule can remove it. Closing it needs the peers to
> agree on *which* round's key a given rekey uses. That is an open design
> question, not a settled part of this module.

## How the Module Is Constructed

| Concern | Location |
|---|---|
| Frame layer, HPKE core, transport, scheduler | [`repositories/pqc-hpke.go`](../repositories/pqc-hpke.go) |
| Wiring, envelope sealing, peer socket | [`pqchpke.go`](../pqchpke.go) |
| Packet type and dispatch | [`auth/auth.go`](../auth/auth.go), [`udpserver.go`](../udpserver.go) |
| Configuration | [`config/config.go`](../config/config.go) |

The adapter owns **no socket**. As initiator it sends and receives plaintext
frames through two functions; as responder it is handed already-verified,
already-decrypted frames through `HandleFrame` and answers through the `reply`
function that comes with them. All four are supplied by the wiring. That is what
lets a full round run in tests over an in-memory pipe, with no network.

PQC traffic rides the existing Arnika port as `auth.PacketPQC` (`'Q'`), through
the same verify-then-decrypt pipeline with the same silent-drop-on-failure
behaviour. The frame kind lives **inside** the encrypted payload, so only one
new type byte is observable on the wire.

The responder answers on the **listening** socket, back to the source address,
exactly as the QKD ACK does — a reply goes out only after the rate limit, the
HMAC and the timestamp have passed, so eliciting one requires `ARNIKA_PSK` and
this is not a reflection primitive. That reply lands on the initiator's dialled
socket, which is what makes the exchange synchronous and removes the inbound
channel, the reassembly-by-round bookkeeping and the ack state machine the
earlier asynchronous version needed. `HandleFrame` runs on the UDP read loop, so
neither it nor `reply` may block: `TestPQCFloodDoesNotStallQKDPath` fails if
either ever does.

## Part 1 — Prepare the Host

**There is no new port to open.** PQC frames use the port Arnika already binds
for `LISTEN_ADDRESS`. Outbound frames go to `SERVER_ADDRESS` from a dialled
socket with an ephemeral source port, which adds no listener.

Requirements:

- Both peers reachable on their existing Arnika ports, in both directions.
- `ARNIKA_PSK` set, identical on both peers, at least 32 bytes:

  ```bash
  openssl rand -base64 32
  ```

  This is the **sole** authentication root for the exchange. Arnika refuses to
  start without it.
- Clocks in reasonable sync. The round index is clock-derived, and the envelope
  enforces `MAX_CLOCK_SKEW`.
- No external PQC daemon, no certificates, no key files.

## Part 2 — Configuration Reference

| Env var | Required | Default | Description |
|---|---|---|---|
| `PQC_ENABLED` | ➖ | `true` | The PQC key agreement. **On by default**: set `false` to run QKD-only |
| `PQC_ROUND_INTERVAL` | ➖ | `INTERVAL` | Period of one agreement round |
| `PQC_MAX_KEY_AGE` | ➖ | `2 × PQC_ROUND_INTERVAL` | Staleness threshold; one round of loss tolerance. **Must be longer than `PQC_ROUND_INTERVAL`** — a shorter value makes the key stale during every healthy round, so it is rejected at startup with both durations in the error, and `NewPQCHPKERepository` enforces the same invariant |
| `PQC_ROUND_TIMEOUT` | ➖ | `INTERVAL / 4` | Per-round deadline. **Must be shorter than `PQC_ROUND_INTERVAL`**, or rounds would overlap; this is rejected at startup |

These must be **identical on both peers**: `PQC_ENABLED`, `PQC_ROUND_INTERVAL`
and `MODE`. `INTERVAL` must already match for role election to work.

`PQC_MAX_KEY_AGE` derives from `PQC_ROUND_INTERVAL` and not from `INTERVAL`: the
key ages against the round cadence, so with `INTERVAL=10s` and
`PQC_ROUND_INTERVAL=120s` the old derivation gave an effective maximum age of
`20s` and left a healthy key stale for the remaining ~100 s of every round. In a
PQC-requiring mode each rotation in that window invalidated the tunnel.

A successful round also contributes to the per-IP rate-limit budget: two
public-key fragments, retried up to three times, plus the one-frame
confirmation tag, so seven inbound packets per round on the responder's
listening socket. The reply frames leave that socket rather than arriving on it,
and rate limiting applies only to inbound reads, so they cost nothing. `RATE_LIMIT`
is sized from these counts when it is unset — see
[`ratebudget.go`](../ratebudget.go) and the `RATE_LIMIT` row in
[`README.md`](../README.md).

The agreement runs unless it is switched off, so an upgraded deployment starts
negotiating PQC material without any configuration change. Until the first
round completes, `GetNewKey()` has nothing to return and `MODE` decides what
happens — and with the default `QkdAndPqcRequired` that is **not** a warning
but an abort: the interval is failed and the tunnel invalidated with a random
PSK. This is why a round runs at startup rather than waiting for the first
boundary.

`MODE` decides what happens when the PQC key is missing or stale — unchanged
from the file-based reader:

| `MODE` | PQC key unavailable |
|---|---|
| `QkdAndPqcRequired` _(default)_ | Fatal for the interval; the tunnel is invalidated |
| `AtLeastPqcRequired` | Fatal for the interval |
| `AtLeastQkdRequired` | Falls back to the QKD key alone |
| `EitherQkdOrPqcRequired` | Falls back to whichever source answered |

## Part 3 — Compile

No build tag. The adapter compiles on every platform, including the build-only
darwin targets — it depends on nothing platform-bound.

```bash
make build
```

Go **1.26 or newer** is required for `crypto/hpke`, and every `go` command needs
`GOEXPERIMENT=runtimesecret`:

```bash
GOEXPERIMENT=runtimesecret go build ./...
GOEXPERIMENT=runtimesecret go test ./...
```

Both peers must run a build that has this module: a peer without it cannot
answer, and rounds will simply fail.

## Part 4 — Run

Two peers, hybrid mode. Alice:

```bash
LISTEN_ADDRESS=10.0.0.1:9999 \
SERVER_ADDRESS=10.0.0.2:9999 \
ARNIKA_ID=9999 \
ARNIKA_PSK="<same 32+ byte secret on both peers>" \
INTERVAL=120s \
MODE=QkdAndPqcRequired \
PQC_ENABLED=true \
KMS_URL="https://kms-a.example:8443/api/v1/keys/CONSA" \
WIREGUARD_INTERFACE=qcicat0 \
WIREGUARD_PEER_PUBLIC_KEY="<bob's public key>" \
arnika
```

Bob is the same with the addresses swapped, `ARNIKA_ID=9998` (the two IDs must
differ in parity), and its own `KMS_URL`.

The startup banner reports the agreement settings:

```
PQC key agreement:        ENABLED (pqc-hpke)
PQC round interval:       2m0s
PQC round timeout:        30s
PQC max key age:          4m0s
```

A successful round logs:

```
[INFO] PQC-HPKE[9999] [OK] round 13845672 agreed a fresh PQC key (initiator)
[INFO] PRIMARY[9999] [OK] HKDF derivation completed for QKD+PQC key
```

Confirm the PSK rotates on the interface:

```bash
sudo wg show qcicat0 preshared-keys
```

## Migrating from an External PQC Provider

1. Stop and disable the external PQC provider on both hosts.
2. Remove `PQC_PSK_FILE` from the Arnika environment; it no longer exists and is
   ignored.
3. Nothing to enable: `PQC_ENABLED` defaults to `true`. Set it to `false` only
   to opt out of PQC entirely.
4. Confirm `ARNIKA_PSK` is set, identical, and at least 32 bytes.
5. Restart **both peers together.** A peer running the new build cannot
   authenticate one running an older build: the envelope now derives its HMAC
   key per direction.
6. Watch for `PQC-HPKE[…] [OK] round … agreed a fresh PQC key` on both ends.

The key material the external provider wrote is no longer read. Delete the key
files and their directory once the tunnel is confirmed working.

## Testing the Module

```bash
GOEXPERIMENT=runtimesecret go test ./repositories/ -run PQC -v
GOEXPERIMENT=runtimesecret go test ./repositories/ -run PQC -race
GOEXPERIMENT=runtimesecret go test ./repositories/ -fuzz FuzzDecodeFrame -fuzztime 60s
```

| Test | What it pins down |
|---|---|
| `TestPQCFrameRoundTrip` | 1- and 2-frame messages, including exact boundaries |
| `TestPQCFrameRejectsMalformed` | Truncated and inconsistent frames rejected, never a panic |
| `TestPQCJoinerOutOfOrderAndDuplicate` | Reordering and duplicates handled |
| `TestPQCJoinerRestartsOnOtherRoundOrKind` | Frames of two messages are never stitched into one |
| `TestPQCEncMessageFitsTheFrameBudget` | The suite's largest message still fits `pqcMaxFrames` |
| `TestPQCAgreementDerivesIdenticalKeys` | Both roles derive the same 32 bytes |
| `TestPQCRoundBindingSeparatesKeys` | A cross-round message cannot produce a usable key |
| `TestPQCSealIsRefused` | `ExportOnly` really is export-only |
| **`TestPQCConfirmationCatchesImplicitRejection`** | **A corrupted encapsulation raises no error from decapsulation and is caught by confirmation** |
| **`TestPQCConfirmTagsAreRoleSeparated`** | **The two tags differ, so neither direction can be satisfied by an echo** |
| `TestPQCRoundIsThreeMessagesAndFiveDatagrams` | The exchange stays at two round trips |
| `TestPQCRoundUnderLoss` | 1%, 5% and 20% frame loss: completes or fails cleanly, never hangs |
| **`TestPQCLostReplyFailsBothSides`** | **A lost reply publishes on neither side** |
| **`TestPQCLostTagLeavesOnlyTheInitiatorPublished`** | **The documented residual, and never a divergent key** |
| **`TestPQCRetriedPubKeyIsAnsweredFromTheStoredReply`** | **A retry never triggers a second encapsulation** |
| `TestPQCResponderRejectsForgedTag` | A tag that does not match the agreed key publishes nothing |
| `TestPQCResponderIgnoresUnexpectedFrames` | Frames with no state behind them, and rounds outside the freshness window |
| **`TestPQCReplayedPubKeyDoesNotDisplaceTheRoundInFlight`** | **An off-path replay cannot make the initiator publish alone** |
| `TestPQCFollowingRoundNeverRepeats` | The boundary wait waking a hair early does not repeat a round |
| **`TestPQCPublishKeepsTheNewerRound`** | **Two rounds completing at once converge on one key on both peers** |
| `TestPQCRunAgreesAKeyBeforeTheFirstBoundary` | The startup round runs without waiting for a boundary |
| `TestPQCNextRoundServesAFutureBoundary` | The scheduling contract across a whole interval, in 10 ms steps |
| `TestPQCNextRoundAgreesAcrossPeers` | Peers 62 ms apart still target the same round |
| **`TestPQCRunServesEachRoundOnce`** | **The scheduler never starts the same round twice** |
| `TestPQCRoundSurvivesTransientSendFailure` | Two failed writes cost retries, not the round |
| `TestPQCAgreementOverRealSockets` _(root package)_ | The full wiring over two real UDP sockets: the reply reaches the initiator's dialled socket |

## Security Notes

- **`ARNIKA_PSK` is the sole authentication root** for this exchange. There is
  no second, independent factor: an attacker holding it can MITM the agreement.
  See [`SECURITY.md`](../SECURITY.md).
- **Confidentiality** rests on ML-KEM-1024 *and* ECDH P-384 through the HPKE key
  schedule; recovery requires breaking both. Against a quantum adversary the
  P-384 half contributes nothing — it falls to Shor — and exists to cover an
  ML-KEM *implementation* flaw exploited classically. QKD, when present, is the
  only non-computational hedge.
- **Forward secrecy** per round: no long-term key material exists in this path.
- **No key at rest.** The agreed key lives in process memory only and is zeroed
  when superseded. The zeroing and the read in `GetNewKey` are serialised by
  `keyMu`: an `atomic.Pointer` orders the pointer but not the bytes behind it, so
  with one the supersede could zero a buffer a caller was still copying out of
  and hand it an all-zero key.
- **The register keeps the highest round, not the last publish.** Two rounds can
  complete at the same instant: at startup the round for the current index and
  the round for the next boundary are both due, and one peer initiates each, so
  both publishes land on both peers - in opposite orders. Keeping the last one
  left the two holding different keys and deriving two different PSKs, with no
  symptom until the WireGuard handshake failed.
  `TestPQCPublishKeepsTheNewerRound` pins this.
- **The per-round HPKE private key is not zeroed.** `hpke.PrivateKey` exposes no
  destroy method, so the decapsulation key stays in the heap until the GC
  reclaims it. It is per-round and useless without that round's encapsulation off
  the wire, and anyone able to read Arnika's heap can read the published key
  directly. `hardenProcess()` is what keeps the heap unreadable: `PR_SET_DUMPABLE=0`,
  `RLIMIT_CORE=0` and `mlockall`, see [`CODEFLOW.md`](../CODEFLOW.md).
- **Replay freshness.** The envelope authenticates a frame but does not make it
  fresh: its timestamp is only bounded by `MAX_CLOCK_SKEW`, a minute by default,
  so a captured public key stays replayable for several rounds and replaying it
  needs no PSK. The responder therefore accepts only a round the schedule could
  be serving — the boundary that follows now, the current index the startup
  round uses, and one interval of slack for clock skew — and never lets a public
  key for an *older* round replace the round in flight. Without both guards a
  replay landing between the real public key and the real confirmation discarded
  the pending key, so the responder could not confirm and the initiator
  published alone.
  `TestPQCReplayedPubKeyDoesNotDisplaceTheRoundInFlight` pins this.
- **Denial of service:** nothing reaches `crypto/hpke` before HMAC verification
  and AEAD decryption succeed, so an unauthenticated packet costs one
  HMAC-SHA256. Frames go only to the pinned peer address, never to an observed
  source, so there is no reflection primitive.
- **Unscannable, not unfingerprintable.** Every authentication failure is a bare
  drop, so a scanner gets nothing. But the envelope's type byte and Unix
  timestamp are authenticated rather than encrypted, so passive DPI can still
  classify Arnika traffic by its fixed 43-byte overhead and type byte. This is
  pre-existing and shared with WireGuard's cleartext message-type byte.
- **`draft-ietf-hpke-pq` is not yet an RFC.** MLKEM1024-P384 comes from a draft:
  pin the Go version and re-verify interoperability on upgrade.

## References

- [RFC 9180 — Hybrid Public Key Encryption](https://www.rfc-editor.org/rfc/rfc9180.html)
- [FIPS 203 — Module-Lattice-Based Key-Encapsulation Mechanism](https://csrc.nist.gov/pubs/fips/203/final)
- `draft-ietf-hpke-pq` — post-quantum KEMs for HPKE
- BSI TR-02102-1 — cryptographic mechanisms, key lengths
- Alwen et al., *Analysing the HPKE Standard*, Eurocrypt 2021 ([ePrint 2020/1499](https://eprint.iacr.org/2020/1499))
- Key I/O architecture: [`KEYCONTROL.md`](../KEYCONTROL.md)
- Protocol flow: [`CODEFLOW.md`](../CODEFLOW.md)
