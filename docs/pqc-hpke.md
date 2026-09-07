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
| Selection | Runtime, via `PQC_ENABLED` |
| Build tag | _(none — always compiled)_ |
| Platform | any |
| Adapter | [`repositories/pqc-hpke.go`](../repositories/pqc-hpke.go) |
| Tests | [`repositories/pqc-hpke_test.go`](../repositories/pqc-hpke_test.go) |
| Ciphersuite | MLKEM1024-P384 · HKDF-SHA384 · ExportOnly |
| Dependencies | Go standard library only (`crypto/hpke`, `crypto/hkdf`, `crypto/sha3`) |
| Key at rest | none |
| Replaces | External PQC provider via `PQC_PSK_FILE` |

## How the Module Works

One round per interval, two messages, six steps.

1. **The initiator generates a fresh HPKE key pair.** A new pair every round is
   what provides forward secrecy: a key recovered later cannot decrypt earlier
   rounds.
2. **It sends the public key to the peer** — 1665 bytes (1568 for ML-KEM-1024
   plus 97 for P-384), split into two frames, each sealed with AES-256-GCM and
   signed with HMAC-SHA256 under `ARNIKA_PSK`. This is the same envelope that
   already protects the QKD key-id exchange, on the same port.
3. **The responder encapsulates and exports 32 bytes** with `hpke.NewSender`
   against that public key.
4. **It returns the encapsulation** — also 1665 bytes, two frames.
5. **The initiator decapsulates and exports the same 32 bytes.**
6. **Both peers confirm they hold the same key**, then the key is published for
   `setPSK()` to combine with the QKD key via `HKDF-SHA3-256`.

### Why step 6 is mandatory

ML-KEM uses **implicit rejection**. FIPS 203 decapsulation never fails: handed a
malformed ciphertext it returns a *pseudorandom* shared secret rather than an
error. Without an explicit check, a corrupted encapsulation would leave the two
peers holding **different keys, silently, with no error anywhere** — and the
first symptom would be a WireGuard handshake failure one interval later,
carrying no diagnostic that points at the PQC layer.

So each peer derives a 16-byte tag from the agreed key with HKDF, exchanges it,
and compares in constant time. **Nothing is published until the tags match.** On
a mismatch the round fails, the previous key stays live until `PQC_MAX_KEY_AGE`,
and the next round retries. The tunnel is never poisoned by a divergent key.

This looks redundant — both peers export from one HPKE context, so they
"cannot" disagree. Implicit rejection is precisely the case where that intuition
fails. Do not remove the check.

### Round scheduling

- The round index is derived from the clock, `unix / PQC_ROUND_INTERVAL`, so it
  survives an asymmetric restart. An in-memory counter would deadlock when one
  peer restarts and the other does not.
- **The role is pinned once at round start** and held for the whole round.
  Arnika's PRIMARY/BACKUP role alternates per interval, so re-deriving it
  mid-round would flip initiator and responder in flight and fail the round
  intermittently — the worst kind of failure to diagnose.
- At most one round is active. Frames for any other round are dropped, so there
  is no reassembly state to garbage-collect.
- Messages are sent with an ack and three retries. HPKE is single-shot, so an
  exhausted retry budget has no partial state to recover: the round fails and
  the next one proceeds.

## How the Module Is Constructed

| Concern | Location |
|---|---|
| Frame layer, HPKE core, transport, scheduler | [`repositories/pqc-hpke.go`](../repositories/pqc-hpke.go) |
| Wiring, envelope sealing, peer socket | [`keyreader.go`](../keyreader.go) |
| Packet type and dispatch | [`auth/auth.go`](../auth/auth.go), [`udpserver.go`](../udpserver.go) |
| Configuration | [`config/config.go`](../config/config.go) |

The adapter owns **no socket**. It receives already-verified, already-decrypted
frames on a channel and emits plaintext frames through a function, both supplied
by the wiring. That is what lets a full round run in tests over an in-memory
pipe, with no network.

PQC traffic rides the existing Arnika port as `auth.PacketPQC` (`'Q'`), through
the same verify-then-decrypt pipeline with the same silent-drop-on-failure
behaviour. The frame kind lives **inside** the encrypted payload, so only one
new type byte is observable on the wire. Delivery to the agreement goroutine is
a non-blocking send on a buffered channel: a slow or absent PQC consumer can
never stall the QKD path.

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
| `PQC_ENABLED` | ➖ | `false` | Enables the PQC key agreement |
| `PQC_ROUND_INTERVAL` | ➖ | `INTERVAL` | Period of one agreement round |
| `PQC_MAX_KEY_AGE` | ➖ | `2 × INTERVAL` | Staleness threshold; one round of loss tolerance |
| `PQC_ROUND_TIMEOUT` | ➖ | `INTERVAL / 4` | Per-round deadline. **Must be shorter than `PQC_ROUND_INTERVAL`**, or rounds would overlap; this is rejected at startup |

These must be **identical on both peers**: `PQC_ENABLED`, `PQC_ROUND_INTERVAL`
and `MODE`. `INTERVAL` must already match for role election to work.

`MODE` decides what happens when the PQC key is missing or stale — unchanged
from the file-based reader:

| `MODE` | PQC key unavailable |
|---|---|
| `QkdAndPqcRequired` | Fatal for the interval; the tunnel is invalidated |
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
[INFO] pqc-hpke: round 13845672 agreed a fresh PQC key
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
3. Set `PQC_ENABLED=true` on both peers.
4. Confirm `ARNIKA_PSK` is set, identical, and at least 32 bytes.
5. Restart **both peers together.** A peer running the new build cannot
   authenticate one running an older build: the envelope now derives its HMAC
   key per direction.
6. Watch for `pqc-hpke: round … agreed a fresh PQC key` on both ends.

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
| `TestPQCReassemblyOutOfOrderAndDuplicate` | Reordering and duplicates handled |
| `TestPQCReassemblyDropsOtherRounds` | Frames from an inactive round ignored |
| `TestPQCAgreementDerivesIdenticalKeys` | Both roles derive the same 32 bytes |
| `TestPQCRoundBindingSeparatesKeys` | A cross-round message cannot produce a usable key |
| `TestPQCSealIsRefused` | `ExportOnly` really is export-only |
| **`TestPQCConfirmationCatchesImplicitRejection`** | **A corrupted encapsulation raises no error from decapsulation and is caught by confirmation** |
| `TestPQCRoundUnderLoss` | 1%, 5% and 20% frame loss: completes or fails cleanly, never hangs |
| `TestPQCConcurrentRoundRejected` | Only one round is ever active |

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
- **The per-round HPKE private key is not zeroed.** `hpke.PrivateKey` exposes no
  destroy method, so the decapsulation key stays in the heap until the GC
  reclaims it. It is per-round and useless without that round's encapsulation off
  the wire, and anyone able to read Arnika's heap can read the published key
  directly. `hardenProcess()` is what keeps the heap unreadable: `PR_SET_DUMPABLE=0`,
  `RLIMIT_CORE=0` and `mlockall`, see [`CODEFLOW.md`](../CODEFLOW.md).
- **Denial of service:** nothing reaches `crypto/hpke` before HMAC verification
  and AEAD decryption succeed, so an unauthenticated packet costs one
  HMAC-SHA256. Frames go only to the pinned peer address, never to an observed
  source, so there is no reflection primitive.
- **Unscannable, not unfingerprintable.** Every authentication failure is a bare
  drop, so a scanner gets nothing. But the envelope's type byte and Unix
  timestamp are authenticated rather than encrypted, and the payload is base64,
  so passive DPI can still classify Arnika traffic. This is pre-existing and
  shared with WireGuard's cleartext message-type byte.
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
