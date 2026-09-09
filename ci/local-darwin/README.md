# Native macOS test

An end-to-end Arnika run on macOS, using **real WireGuard** — two interfaces on
loopback, the bundled KMS simulator, and two Arnika instances rotating the PSK
on both ends. No Docker, no containerlab, no Linux.

The containerlab suite in [`ci/`](../) remains the authority; this is the local
equivalent, for checking a change before pushing.

## Prerequisites

macOS has no kernel WireGuard, so the userspace implementation is used. Both
come from Homebrew:

```bash
brew install wireguard-tools wireguard-go
```

`wireguard-tools` provides `wg` and `wg-quick`; `wg-quick` starts
`wireguard-go` for you and creates a `utun` device.

You also need Go 1.26+ and `sudo`. Root is unavoidable: `wg-quick` creates the
interfaces, their control sockets belong to root, and Arnika has to be able to
write to them — the same privilege it needs on Linux, where it is
`CAP_NET_ADMIN`. The script obtains it up front, once, so it cannot fail
halfway through a run: `sudo -n` first, and if that ticket is missing it asks
with `sudo -v` and says so. That is not gated on a terminal — with `pam_tid`
(Touch ID for sudo, via `/etc/pam.d/sudo_local`) the prompt is biometric and
needs no tty, which is what lets the script run from an editor or an agent
rather than a shell. It gives up with one line only when `sudo` itself says it
cannot ask. Tickets are per session, so priming in another window does not
carry in.

## Running it

```bash
./run.sh             # all three modes, CYCLES rotation cycles each
./run.sh --keep      # leave the interfaces and logs in place afterwards
./run.sh --quiet     # do not stream the Arnika and KMS logs
./run.sh --clean     # only clear leftovers from an earlier run, then stop
./run.sh --list      # print the numbered test list and stop
```

Every run **starts by clearing leftovers**: any `arnika` or KMS process from an
earlier run under `/tmp/arnika-darwin.*`, and both tunnels. A stranded peer
still writing a PSK to an interface is the worst kind of leftover — it makes the
next run's results a coin toss — so this is not optional, and `--clean` does
just that step if you want it on its own. Anything it kills is printed first,
and is killed with `SIGCONT` before `SIGTERM` — Arnika handles `SIGTERM`
itself, so a process left stopped would otherwise sit on the signal — then
`SIGKILL` if it is still there a second later.

Old log directories are left in `/tmp` and only counted; remove them with
`rm -rf /tmp/arnika-darwin.*`.

It builds `arnika` and the KMS simulator, brings the two interfaces up once,
**pre-tests WireGuard on its own** (see below — it stops there if the tunnel is
not working), starts the simulator, and then runs a peer pair in each of the
three operational modes in turn:

| `MODE` | Mode | Key sources |
|---|---|---|
| `QkdAndPqcRequired` | (C) hybrid | both mandatory, no fallback |
| `AtLeastQkdRequired` | (A) QKD | QKD mandatory, PQC mixed in |
| `AtLeastPqcRequired` | (B) PQC | PQC mandatory, QKD optional |

`EitherQkdOrPqcRequired` is not in `MODES`: both sources are optional to it, so
the missing-source tests below have nothing to assert for it beyond what the
other three already cover.

Each mode gets a numbered section of its own — 3, 4 and 5 — with the same 23
tests in it. `x` below stands for that section number:

- **x.1** both ends report `[OK] PSK configured on WireGuard interface`
- **x.2** **both interfaces hold the same preshared key** — the property that
  matters; different keys mean a dead handshake
- **x.3** traffic really traverses the tunnel and **decrypts at the far end** —
  see [How the tunnel is checked](#how-the-tunnel-is-checked)
- **x.4**–**x.6** the PSK **rotates over `CYCLES` consecutive cycles** (3 by
  default), both ends holding the identical key on every one, with a
  **`wg show … dump` of both interfaces after every write** so a failure can be
  read against the state that produced it
- **x.7** the tunnel still passes traffic after those rotations
- **x.8**–**x.18** **the mode honours its own contract** when a key source
  disappears — three faults, each with a recovery: the KMS hung, the KMS not
  running at all, PQC unable to agree. See
  [The missing-source tests](#the-missing-source-tests)
- **x.19**–**x.23** **a deliberate desync breaks it** — and the peers put it
  back; see [The intentional failure test](#the-intentional-failure-test)

The full list, with the exact numbers, is under
[What the run asserts](#what-the-run-asserts) or from `./run.sh --list`.

At `INTERVAL=7s` each mode takes three to four minutes — most of it waiting out
the four deliberate failures and the recovery after each — so a whole run is
roughly twelve. `MODES` and `CYCLES` sit at the top of the script — narrow them if
you only care about one mode, or want fewer rotations. Teardown runs even on
failure, so a `wg-quick down` is never left to you.

### Debug output

The two peers and the simulator do **not** write to the console. Three
processes writing at once interleave mid-line and land in the middle of a
result — the reason an earlier version of this script produced staircased,
half-overwritten output. They log to files instead, and the script prints what
is new at the points where it owns the console: once a second while it is
waiting, and always immediately before a verdict. So a result is never
interrupted, and every log line that led to a result appears above it.

Lines from all three are merged in timestamp order, prefixed by peer, and set
in a **gutter of their own** so a block of log output can never be read as part
of a result. A blank line goes in wherever the output changes kind:

```
  ─── cycle 1/3 ─────────────────────────────────

    │ kms| 2026/09/08 10:00:01 [DEBUG] [REQ] method=POST path=/api/v1/keys/CONSA/enc_keys
    │ a1| 2026/09/08 10:00:01.001111 [INFO] PRIMARY[9998] [SND] send key_id ffffffff-…
    │ a2| 2026/09/08 10:00:01.001161 [INFO] BACKUP[9999] [RCV] received key_id ffffffff-…
    │ a1| 2026/09/08 10:00:02.002222 [INFO] PQC-HPKE[9998] [OK] round 357756369 agreed a fresh PQC key

    PASS  cycle 1/3: rotated, both ends match (key …fjz6mmI4=)
          wg dump utun23 (profile qcicat1, ARNIKA_ID 9998):
          …

  ─── cycle 2/3 ─────────────────────────────────
```

Each rotation cycle is fenced off that way: **cycle heading → the cycle's log
lines → the cycle's result → the next cycle.** Log lines sit at `│`, the run's
own output at `PASS`/`FAIL` and the indent below them, and the two are never
adjacent without a blank line between. `a1` is `ARNIKA_ID` 9998 on qcicat1,
`a2` is 9999 on qcicat2.

The simulator needs `DEBUG=true` for its request and response logging, and
`run.sh` sets it. Arnika's own `[DEBUG]` lines — rejected packets, ACK
timeouts, dropped PQC frames — are unconditional and need no flag.

`--quiet` stops the log lines being printed at all and reports only the checks.
Either way they are written to files, and each mode ends with a count per log so
an anomaly is visible at a glance:

```
==> MODE=QkdAndPqcRequired log summary
          peer a[9998]: 7 PQC exchanges, 6 PSK writes, 0 debug lines, 0 warnings/errors
          peer b[9999]: 7 PQC exchanges, 6 PSK writes, 0 debug lines, 0 warnings/errors
```

`wg show … dump` is printed after every write and every failure, and the log
tails on a failed write. `--keep` leaves the logs and the interfaces in place so
you can keep poking with the commands below.

### The summary

The run ends with **the whole numbered list and each test's result** — the
message actually observed for a test that ran, its declared description for one
that did not. A failed pre-test prints it too, before it stops the run, which is
when the `SKIP` lines say the most:

```
─── summary ──────────────────────────

  1  setup
       1.1  PASS  wg, wg-quick, wireguard-go and go are present
       …
       1.8  PASS  listening on 127.0.0.1:8080 with debug logging

  2  pre-test: WireGuard alone, no Arnika
       2.1  PASS  utun24[9998] and utun25[9999] are live
       …

  3  MODE=QkdAndPqcRequired
       3.1  PASS  both ends reported a successful write
       3.2  PASS  identical on both ends (key …fjz6mmI4=)
       …
       3.5  FAIL  cycle 2/3: the PSK did not change within 30s
       3.6  SKIP  rotation cycle 3/3: the PSK changed and both ends match
       …
       3.9  FAIL  QkdAndPqcRequired kept both ends on one key with no qkd key available

  ──────────────────────────────────────────────────────────────────
  85 tests: 76 passed, 8 failed, 1 skipped   (33 of them intentional)

  failed:
  [3.5] MODE=QkdAndPqcRequired: cycle 2/3: the PSK did not change within 30s
  [3.6] MODE=QkdAndPqcRequired: QkdAndPqcRequired kept both ends on one key …

  2 of the failures is a check of a deliberately broken state:
  it failed because the break went undetected, or did not happen.
```

Three verdicts, and the distinction between them is the point:

- **PASS** / **FAIL** — the check ran.
- **SKIP** — the check never ran, because something before it stopped its
  section. A `SKIP` is not a pass: it means that test has no result this run.
- an **`[intentional]`** failure means the deliberate break **was not detected,
  or did not happen** — either the mode ignored its own contract, or the checks
  cannot see a broken tunnel at all. The second is the worse of the two, because
  it puts every other pass in the run in doubt. A plain failure is Arnika or the
  tunnel misbehaving.

A **`[ !! ] HARNESS`** line is neither: it is the harness itself failing — the
KMS not coming back up after a restart, or a check citing a test id that its
section does not declare (printed as `[  ?.?]`). Those have no number, so they
cannot renumber anything, and they are counted on their own line.

The exit status is the number of failed checks plus any harness errors, so
`./run.sh && echo ok` works.

> **The simulator's debug output contains key material.** `[RESP] body=` lines
> carry the QKD keys it hands out, in full. They are pseudo-random keys from a
> mock, not real QKD material, but do not paste that output anywhere without
> reading it first. Arnika's own output is clean: it logs key *IDs*, and the
> startup banner reports only the length of `ARNIKA_PSK`.
>
> **This script prints the last 9 base64 characters of a preshared key**, as
> `…fjz6mmI4=`, so two keys can be told apart at a glance and matched against a
> line in a log. That is deliberately real key material — roughly 50 bits of a
> 256-bit key. It is safe here because every key in a run comes from the mock
> KMS or from `openssl rand` on this machine, and dies with the run. It is also
> a reason not to point this script at anything real, and a reason to read its
> output before pasting it anywhere.

## Reading the output

Two conventions run through it:

- **`utun23[9998]`** — a device with the `ARNIKA_ID` of the peer that owns it,
  matching the `PRIMARY[9998]` / `BACKUP[9999]` prefix in that peer's own log,
  so a line from the harness can be lined up against the peer that produced it.
  `qcicat1` is `ARNIKA_ID` 9998, `qcicat2` is 9999; the IDs double as the peers'
  UDP ports, and have to differ in parity because only the lowest bit takes part
  in the PRIMARY/BACKUP election.
- **`…fjz6mmI4=`** — a preshared key by its last 9 characters (see the note
  above).

`wg show … dump` is printed for the devices a check actually concerns, each
under a heading naming the device, its profile and its `ARNIKA_ID`, because the
dump itself carries no name:

```
          wg dump utun23 (profile qcicat1, ARNIKA_ID 9998):
          PRIVKEY=	PUBKEY=	41194	off
          PEERKEY=	(none)	127.0.0.1:41195	100.1.2.2/32,100.1.2.3/32	1788813930	92	180	10
```

The run closes with a ruled verdict, so it is not lost in the scrollback:

```
══════════════════════════════════════════════════════════════════════
  PASS - all checks passed
══════════════════════════════════════════════════════════════════════
```

## How the tunnel is checked

Both ends are on this one host, so `100.1.2.2` is a *local* address — it is
assigned to the second `utun`. A packet to a local address never reaches the
route that points into the tunnel; the stack answers it over loopback. So
`ping 100.1.2.2` reports `0.0% packet loss` with WireGuard entirely broken, or
with the two ends holding **different** preshared keys. It was a false pass.
(`ping -b <utun>` does not rescue it either: the local route still shadows the
tunnel route and the send fails outright with `No route to host`.)

Two things fix it. `qcicat1.conf` carries a **probe address** that belongs to no
interface, so the tunnel route is the only match for it:

```
AllowedIPs = 100.1.2.2/32, 100.1.2.3/32, fdac::2/128
```

And the verdict comes from the **`wg` transfer counters**, not from a reply:

- qcicat1 **tx** must grow — the packets reached the interface and were
  encrypted;
- qcicat2 **rx** must grow — `wireguard-go` counts rx only after a packet
  *decrypts* and passes that peer's `AllowedIPs`, which is what makes this a
  real test of the installed preshared key.

Four 1000-byte pings, so both must grow by more than 2 KB — well clear of the
32-byte keepalives moving in the same window. Nothing owns the probe address,
so there is no reply and nothing to print; one line comes out:

```
    PASS  traffic traversed the tunnel: utun23 tx +4304 B, utun24 rx +4304 B
```

The measurement is one-way by nature, and one direction is enough: a handshake
is bilateral, so a key that works one way works both.

## The pre-test

A broken tunnel makes every Arnika check meaningless, so `run.sh` puts
WireGuard through its own paces first, with no Arnika running, and **exits
before starting Arnika** if any of it fails:

- **2.1** both interfaces answer `wg`;
- **2.2** the peers complete a handshake with no preshared key;
- **2.3** payload crosses the tunnel and decrypts at the far end;
- **2.4**, **2.5** with the **same** preshared key set on both ends, a fresh
  handshake still completes and payload still crosses;
- **2.6**, **2.7** with a **different** key on one end, a fresh handshake must
  **not** complete and nothing may decrypt — the negative control. Without a
  check that is known to fail on a broken tunnel, every green tick in the Arnika
  run could be a false pass;
- **2.8** the keys are cleared again so Arnika starts from a clean interface.

Tests 2.2 and 2.4–2.8 each need a handshake on demand, and a preshared key is used *only*
in the handshake — a live session keeps working after the key changes
underneath it. So the script removes the peer and adds it back, which throws the
session away and forces the next packet to handshake with the current key. That
is also why the per-mode checks assert *matching keys on both ends* rather than
a handshake per rotation: at `INTERVAL=7s` the key rotates far faster than
WireGuard's ~2-minute rekey, so most rotations are never exercised by a
handshake at all.

## The tests

### What each mode promises

The contract under test, from `IsQKDRequired` / `IsPQCRequired` in
[`config/config.go`](../../config/config.go) and the branches of `setPSK` in
[`main.go`](../../main.go):

| `MODE` | PQC | QKD | PSK `setPSK` installs | Invalidates with a random PSK |
|---|---|---|---|---|
| `QkdAndPqcRequired` _(default)_ | must | must | `HKDF(QKD ‖ PQC)` | QKD **or** PQC is missing |
| `AtLeastQkdRequired` | can fail | must | `HKDF(QKD ‖ PQC)`, else QKD alone | QKD is missing |
| `AtLeastPqcRequired` | must | can fail | `HKDF(QKD ‖ PQC)`, else PQC alone | PQC is missing |
| `EitherQkdOrPqcRequired` | can fail | can fail | whichever source answered | both are missing |

The two fallbacks are **not** symmetric, and the difference is easy to miss:

- **QKD alone** — `setPSK` skips the derivation entirely, so the installed PSK is
  the KMS key **as-is**, never hashed.
- **PQC alone** — `kdf.DeriveKey` still runs, with the QKD half empty, so the
  installed PSK is `HKDF-SHA3-256(PQC)` rather than the agreed key itself.

The fourth row is listed for completeness only — `EitherQkdOrPqcRequired` is not
in `MODES`, for the reason given under [Running it](#running-it).

### What the run asserts

Every check has a **fixed number**, `<section>.<n>`, and the run prints it beside
each verdict:

```
    [  3.5] PASS  cycle 2/3: rotated, both ends match (key …fjz6mmI4=)
```

The numbers come from a declared list in `run.sh` — `list_setup`, `list_pretest`
and `list_mode` — not from the order checks happen to run in. That is what makes
a number citable: checks *do* get skipped (a failed pre-test stops the run, a
mode that never installs a PSK abandons the rest of its checks, a failed
rotation cycle breaks out of the loop), and a counter would renumber everything
below the gap. Declared, a skipped check is reported `SKIP` under its own number
and its neighbours keep theirs.

Sections 1 and 2 run once. Sections 3 and up are **one per `MODE`**, sharing one
list, so `3.9` and `4.9` are the same test under two different modes. The
rotation-cycle entries are generated from `CYCLES`, so changing it moves the
numbers below them — the one case where they shift, and `--list` shows the
current numbering.

`./run.sh --list` prints it:

```
1  setup
     1.1  wg, wg-quick, wireguard-go and go are present
     1.2  sudo is available
     1.3  no arnika or KMS process is left running from an earlier run
     1.4  qcicat1 is not left up from an earlier run
     1.5  qcicat2 is not left up from an earlier run
     1.6  arnika and the KMS simulator build
     1.7  both WireGuard interfaces come up
     1.8  the KMS simulator listens on 127.0.0.1:8080 with debug logging

2  pre-test: WireGuard alone, no Arnika
     2.1  both interfaces answer wg
     2.2  the peers handshake with no preshared key
     2.3  payload crosses the tunnel and decrypts at the far end
     2.4  a matching preshared key on both ends still handshakes
     2.5  payload still crosses with that key installed
     2.6  [intentional] a mismatched preshared key must break the handshake
     2.7  [intentional] nothing may decrypt at the far end while the keys differ
     2.8  the tunnel comes back once the keys are cleared for Arnika

3  MODE=QkdAndPqcRequired
     3.1  both ends report a successful PSK write
     3.2  both interfaces hold the same preshared key
     3.3  traffic traverses the tunnel on the first installed key
     3.4  rotation cycle 1/3: the PSK changed and both ends match
     3.5  rotation cycle 2/3: the PSK changed and both ends match
     3.6  rotation cycle 3/3: the PSK changed and both ends match
     3.7  traffic still traverses the tunnel after 3 rotations
     3.8  [intentional] the KMS restarts with both SAE frozen
     3.9  [intentional] no QKD key: the ends diverge or keep rotating, per the mode
    3.10  [intentional] no QKD key: peer a logs its own decision
    3.11  QKD back: both ends return to one fresh key
    3.12  [intentional] KMS not running: the ends diverge or keep rotating, per the mode
    3.13  [intentional] KMS not running: peer a logs its own decision
    3.14  [intentional] KMS not running: nothing was listening and no request reached one
    3.15  KMS back: both ends return to one fresh key
    3.16  [intentional] no PQC key: the ends diverge or keep rotating, per the mode
    3.17  [intentional] no PQC key: peer a logs its own decision
    3.18  PQC back: both ends return to one fresh key
    3.19  [intentional] desync: the handshake must fail while the keys differ
    3.20  [intentional] desync: nothing may decrypt at the far end
    3.21  desync: the peers resync onto one key
    3.22  desync: the tunnel handshakes on the resynced key
    3.23  desync: traffic traverses the tunnel again

4  MODE=AtLeastQkdRequired
     4.1  both ends report a successful PSK write
     4.2  both interfaces hold the same preshared key
     4.3  traffic traverses the tunnel on the first installed key
     4.4  rotation cycle 1/3: the PSK changed and both ends match
     4.5  rotation cycle 2/3: the PSK changed and both ends match
     4.6  rotation cycle 3/3: the PSK changed and both ends match
     4.7  traffic still traverses the tunnel after 3 rotations
     4.8  [intentional] the KMS restarts with both SAE frozen
     4.9  [intentional] no QKD key: the ends diverge or keep rotating, per the mode
    4.10  [intentional] no QKD key: peer a logs its own decision
    4.11  QKD back: both ends return to one fresh key
    4.12  [intentional] KMS not running: the ends diverge or keep rotating, per the mode
    4.13  [intentional] KMS not running: peer a logs its own decision
    4.14  [intentional] KMS not running: nothing was listening and no request reached one
    4.15  KMS back: both ends return to one fresh key
    4.16  [intentional] no PQC key: the ends diverge or keep rotating, per the mode
    4.17  [intentional] no PQC key: peer a logs its own decision
    4.18  PQC back: both ends return to one fresh key
    4.19  [intentional] desync: the handshake must fail while the keys differ
    4.20  [intentional] desync: nothing may decrypt at the far end
    4.21  desync: the peers resync onto one key
    4.22  desync: the tunnel handshakes on the resynced key
    4.23  desync: traffic traverses the tunnel again

5  MODE=AtLeastPqcRequired
     5.1  both ends report a successful PSK write
     5.2  both interfaces hold the same preshared key
     5.3  traffic traverses the tunnel on the first installed key
     5.4  rotation cycle 1/3: the PSK changed and both ends match
     5.5  rotation cycle 2/3: the PSK changed and both ends match
     5.6  rotation cycle 3/3: the PSK changed and both ends match
     5.7  traffic still traverses the tunnel after 3 rotations
     5.8  [intentional] the KMS restarts with both SAE frozen
     5.9  [intentional] no QKD key: the ends diverge or keep rotating, per the mode
    5.10  [intentional] no QKD key: peer a logs its own decision
    5.11  QKD back: both ends return to one fresh key
    5.12  [intentional] KMS not running: the ends diverge or keep rotating, per the mode
    5.13  [intentional] KMS not running: peer a logs its own decision
    5.14  [intentional] KMS not running: nothing was listening and no request reached one
    5.15  KMS back: both ends return to one fresh key
    5.16  [intentional] no PQC key: the ends diverge or keep rotating, per the mode
    5.17  [intentional] no PQC key: peer a logs its own decision
    5.18  PQC back: both ends return to one fresh key
    5.19  [intentional] desync: the handshake must fail while the keys differ
    5.20  [intentional] desync: nothing may decrypt at the far end
    5.21  desync: the peers resync onto one key
    5.22  desync: the tunnel handshakes on the resynced key
    5.23  desync: traffic traverses the tunnel again
```

`[intentional]` marks a check that runs against a deliberately broken state — it
passes *because* something is broken. The label lives in that list and nowhere
else, which is where the summary's count comes from.

### Known failures in the QKD column

> [!WARNING]
> The QKD-gone tests — **x.9/x.10** with the KMS frozen and **x.12/x.13** with
> it stopped, in all three modes — describe the contract, not current
> behaviour. They fail today, and the cause is not in this script.

In a binary with a QKD reader compiled in, `setPSK` is only ever reached with a
key from a **successful** KMS fetch: the PRIMARY has the call in the `else` of
its `qkd.GetNewKey()` error check, and the BACKUP does `continue` when
`GetKeyByID` fails. So with no QKD key to be had neither end calls `setPSK` at
all — it keeps the PSK it already had, `InvalidateTunnel` never runs, and
`setPSK`'s `len(qkd) == 0` branch, the only place `no QKD key received` and
`switching to PQC key` are logged, is unreachable.

It makes no difference *how* QKD is gone: a timed-out fetch and a refused one
both return an error from `GetNewKey`, and that error goes to the same
`ticker.Reset(KMSRetryInterval)`. So the frozen and the stopped phases fail
identically, in every mode:

| Tests | Symptom |
|---|---|
| **3.9/3.10** and **3.12/3.13** (`QkdAndPqcRequired`) | `kept both ends on one key`, and `no QKD key received` never logged |
| **4.9/4.10** and **4.12/4.13** (`AtLeastQkdRequired`) | same |
| **5.9/5.10** and **5.12/5.13** (`AtLeastPqcRequired`) | `stopped rotating in step`, and `switching to PQC key` never logged — rotation cannot carry on when nothing calls `setPSK` |

**x.14** and the recoveries **x.11**/**x.15** are unaffected and pass: the
harness really does take the KMS away, and the pair really does come back once
it returns.

Making these pass means changing the QKD rotation loop so a failed fetch still
reaches `setPSK`, which is a decision about Arnika's behaviour rather than about
this test.

## The missing-source tests

A mode is a statement about which key source may be absent. Tests
**x.8**–**x.18** put that statement to the test, by taking each source away in
turn — **three faults, each followed by a recovery**:

| Tests | Fault | How |
|---|---|---|
| **x.8**–**x.11** | the KMS is **hung** | the simulator is restarted with `FREEZE=CONSA,CONSB` |
| **x.12**–**x.15** | the KMS is **not running** | the simulator is stopped |
| **x.16**–**x.18** | **PQC** cannot agree a key | the pair is restarted with `PQC_ROUND_TIMEOUT=1ns` |

QKD gets two of them because *unresponsive* and *absent* are different faults
and reach Arnika through different code paths — a client timeout versus a
refused connection — and a mode has to answer both the same way. Neither
substitutes for the other: the frozen KMS is the one that leaves a KMS-side
record of every request Arnika made into the failure, and the stopped KMS is the
one that proves the mode reaches its decision without a KMS being reachable at
all. **x.14** asserts that second property directly: nothing was listening on
`127.0.0.1:8080` for the whole window, and the KMS log gained no lines. It is
not the tautology it looks like — `pkill` can miss, and a stale simulator from
an earlier run or a real KMS on this host could be holding the port, either of
which would leave the pair quietly talking to a KMS while the check believed
there was none.

What each mode must do, with the same expectation for both QKD faults:

| Section, `MODE` | QKD gone (x.9, x.12) | in peer a's log (x.10, x.13) | PQC gone (x.16) | in peer a's log (x.17) |
|---|---|---|---|---|
| 3 `QkdAndPqcRequired` | invalidate | `no QKD key received` | invalidate | `Abort since mode is set to` |
| 4 `AtLeastQkdRequired` | invalidate | `no QKD key received` | keep rotating | `switching to QKD key` |
| 5 `AtLeastPqcRequired` | keep rotating | `switching to PQC key` | invalidate | `Abort since mode is set to` |

**x.11**, **x.15** and **x.18** are the recoveries: the source is restored, the
pair restarted, and both ends have to come back onto one fresh key within 30s.
**x.8** is the freeze itself — the simulator has to confirm from its own
`[CONF]` line that it came back up with both SAE frozen, since a `FREEZE` value
it does not recognise is silently ignored and would leave a healthy KMS behind a
check expecting a broken one.

*Invalidate* is Arnika's own answer to a missing required source: rather than
leave the previous PSK in place, `setPSK` installs a **random** one
(`InvalidateTunnel`), so a failed rotation cannot silently extend the life of
the key it was meant to replace. Each end draws its own random key, so **the two
ends landing on different keys is the signal**. *Keep rotating* is the opposite:
both ends stay in step, on a key derived from whichever source is left.

How each source is taken away:

- **QKD, hung** (x.8–x.11) — the simulator is restarted with
  `FREEZE=CONSA,CONSB` (see [`KMS.md`](../../KMS.md)), so it accepts every
  `enc_keys`/`dec_keys` request and never answers one; each is logged as
  `[FREEZE]`, so the KMS side of the fault is visible in the run's output. A
  frozen KMS fails only on the client's timeout, so the pair is restarted with
  `KMS_HTTP_TIMEOUT=1s KMS_BACKOFF_MAX_RETRIES=1` — roughly 2s per fetch,
  rather than the minute the 10s/5-retry defaults would take.
- **QKD, absent** (x.12–x.15) — the simulator is **stopped**. Nothing is
  listening, so every connection is refused outright and no request ever reaches
  a KMS. This one fails *fast* rather than on a timeout, so the timeouts are
  left at their defaults: refused connections cost nothing and the retry backoff
  fits inside the interval. It is also the phase that covers Arnika starting up
  with no KMS there at all, rather than one that stops answering mid-run.
- **PQC** — the pair is restarted with `PQC_ROUND_TIMEOUT=1ns`. Every attempt
  then dies on its deadline waiting for the peer's answer, which has to cross
  the socket, so the **initiating** peer never agrees a key and `GetNewKey` has
  nothing to return. `1ns` and not `1ms` because an attempt over loopback can
  finish inside a millisecond. The responding peer can still answer a frame or
  two of its own — both its frames are already queued when it starts — so the
  check reads peer a's log, whose even `ARNIKA_ID` makes it the initiator and
  the end whose decision is deterministic.

Each check asserts **both** halves: the PSK state above, *and* the line Arnika
logs about its own decision — `no QKD key received`, `Abort since mode is set
to`, `switching to PQC key`, `switching to QKD key`. The PSK state alone cannot
say the mode *reasoned* correctly, only that something happened. The log line is
polled rather than grepped once, because Arnika logs the decision just before it
writes the PSK and the line reaches the file through a pipe and `tee`.

Afterwards the source is restored, the pair restarted, and both ends have to
come back onto one key.

## The intentional failure test

Every mode ends by breaking its own tunnel. Without it a green run only shows
that the checks *can* pass — not that they would notice if the tunnel were dead,
which is the failure the suite exists to catch. The pre-test proves the
apparatus works before Arnika starts; this proves it still works with Arnika
driving, in each mode.

It cannot simply overwrite a key and look: at `INTERVAL=7s` a running pair
resyncs faster than the check can measure. So the peers are **stopped** first:

1. stop both Arnika processes — they can no longer write a PSK;
2. overwrite qcicat2's preshared key with a random one;
3. remove and re-add qcicat1's peer, which throws away the live session and
   forces a fresh handshake — remember a running session survives a key change,
   so without this the break would not show;
4. **x.19** require the handshake to fail, and **x.20** require nothing to
   decrypt at the far end (`tunnel_traffic … broken` — the same counter check,
   verdict inverted);
5. start the pair again: **x.21** requires them to resync, both ends back on one
   identical key that is neither the random one nor stale, within 30s;
6. **x.22** requires a handshake on that resynced key and **x.23** the payload
   to traverse again.

`SIGSTOP` would be the lighter touch and is **not usable here**: Arnika runs
under `sudo`, and `sudo` answers a stopped child by suspending itself and
passing the stop to its process group — which is the script. That reads as
`[2] + suspended (signal) ./run.sh` and hangs the run. Stopping and restarting
the pair is both safe and a slightly better test, since it also covers a peer
starting up against an interface whose key is wrong.

**x.19** and **x.20** failing is the serious case — it means a dead tunnel would
pass unnoticed in that mode. **x.21**–**x.23** failing means Arnika cannot
recover from a PSK written behind its back.

The restart leaves ACK timeouts and warnings in both Arnika logs. That is
expected; the per-mode log summary counts them, and nothing fails on the count.
The logs are appended across the restart, so the counts cover the whole mode.

## The interfaces

[`qcicat1.conf`](qcicat1.conf) and [`qcicat2.conf`](qcicat2.conf) are a matched
pair on loopback: `100.1.1.1` ↔ `100.1.2.2`, ports 41194 and 41195. The
templates carry fixed test keys, so they are for local testing only.

```bash
sudo wg-quick up ./qcicat1.conf
sudo wg-quick up ./qcicat2.conf
```

On macOS the profile name is not the interface name. `wg-quick` records the real
`utun` device it created, and every `wg` command needs that name — the same
mapping [`ci/show-psk.sh`](../show-psk.sh) makes:

```bash
echo $(cat /var/run/wireguard/qcicat1.name)
echo $(cat /var/run/wireguard/qcicat2.name)

sudo wg show $(sudo cat /var/run/wireguard/qcicat1.name) preshared-keys
sudo wg show $(sudo cat /var/run/wireguard/qcicat1.name) latest-handshakes
sudo wg show $(sudo cat /var/run/wireguard/qcicat1.name) transfer
sudo wg show $(sudo cat /var/run/wireguard/qcicat1.name) dump
```

`run.sh` passes that `utun` name to Arnika as `WIREGUARD_INTERFACE`, and takes
each side's `WIREGUARD_PEER_PUBLIC_KEY` from the `[Peer]` block of its own
config, so the two can never drift apart.

Tear down with:

```bash
sudo wg-quick down ./qcicat1.conf
sudo wg-quick down ./qcicat2.conf
```

## Notes

- **`ARNIKA_ID` values must differ in parity.** Only the lowest bit takes part
  in PRIMARY/BACKUP election, so two odd or two even IDs make both ends choose
  the same role and nothing progresses. `run.sh` uses 9998 and 9999.
- **`100.1.2.3` is a probe address, not a peer.** It exists only so there is
  something inside `qcicat1.conf`'s `AllowedIPs` that this host does not own —
  see [How the tunnel is checked](#how-the-tunnel-is-checked).
- **Every address here is a `/32` or a `/128`, deliberately.** Two interfaces on
  one host asking for the same route collide, and `wg-quick` refuses the second
  `up` with `route: File exists`. An earlier version of these configs carried
  `fdac::/64` on both sides and hit exactly that; single-host addresses have to
  be host routes.
- The simulator is not a QKD device. It generates pseudo-random keys for
  testing — see [`KMS.md`](../../KMS.md).
- Process hardening and `runtime/secret` erasure are Linux facilities, and
  Arnika says so in two warnings at startup on darwin. Nothing here covers them.
  `run.sh` still builds `arnika` with `GOEXPERIMENT=runtimesecret
  CGO_ENABLED=0` — the flags the `Makefile` uses — because the experiment is
  what makes `runtime/secret` exist at all; without it the build fails. On
  darwin the erasure is inert, but the code path is the same one Linux takes.
  The KMS simulator does not touch `runtime/secret` and is built without it.
