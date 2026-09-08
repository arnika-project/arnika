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

For each mode it checks that:

- both ends report `[OK] PSK configured on WireGuard interface`
- **both interfaces hold the same preshared key** — the property that matters;
  different keys mean a dead handshake
- traffic really traverses the tunnel and **decrypts at the far end** — see
  [How the tunnel is checked](#how-the-tunnel-is-checked)
- the PSK **rotates over `CYCLES` consecutive cycles** (3 by default), both ends
  holding the identical key on every one, with a **`wg show … dump` of both
  interfaces after every write** so a failure can be read against the state that
  produced it
- the tunnel still passes traffic after those rotations
- **the mode honours its own contract** when a key source disappears — see
  [The missing-source tests](#the-missing-source-tests)
- **a deliberate desync breaks it** — and the peers put it back; see
  [The intentional failure test](#the-intentional-failure-test)

At `INTERVAL=5s` each mode takes two to three minutes — most of it waiting out
the three deliberate failures and the recovery after each — so a whole run is
roughly ten. `MODES` and `CYCLES` sit at the top of the script — narrow them if
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

Every check is tallied by section, and the run ends with the score. A failed
pre-test prints it too, before it stops the run:

```
─── summary ──────────────────────────
  setup                                      8 passed    0 failed
  pre-test: WireGuard alone, no Arnika       8 passed    0 failed    2 intentional
  MODE=QkdAndPqcRequired                    18 passed    0 failed    6 intentional
  MODE=AtLeastQkdRequired                   17 passed    1 failed    6 intentional
  MODE=AtLeastPqcRequired                   17 passed    1 failed    6 intentional
  ──────────────────────────────────────────────────────────────
  total                                     68 passed    2 failed   20 intentional

  failed:
    MODE=AtLeastQkdRequired: cycle 2/3: the PSK did not change within 30s
    MODE=AtLeastPqcRequired [intentional]: 4304 B decrypted on a desynced tunnel

  [intentional] marks a check of a deliberately broken state:
  it failed because the break went undetected, or did not happen.
```

**Intentional** counts the checks that ran against a deliberately broken
state — the missing-source tests, the desync, and the pre-test's mismatched
key. Those pass *because* something is broken, so they are worth telling apart
from a check of a healthy tunnel, and the step that produces them is labelled
`[intentional]` as it runs. The distinction matters most in the failure list:

- a plain failure is Arnika or the tunnel misbehaving;
- an `[intentional]` failure means the deliberate break **was not detected, or
  did not happen** — either the mode ignored its own contract, or the checks
  cannot see a broken tunnel at all. The second is the worse of the two, because
  it puts every other pass in the run in doubt.

The exit status is the number of failed checks, so `./run.sh && echo ok` works.

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

1. both interfaces answer `wg`;
2. the peers complete a handshake with no preshared key;
3. payload crosses the tunnel and decrypts at the far end;
4. with the **same** preshared key set on both ends, a fresh handshake still
   completes and payload still crosses;
5. with a **different** key on one end, a fresh handshake must **not**
   complete — the negative control. Without a check that is known to fail on a
   broken tunnel, every green tick in the Arnika run could be a false pass;
6. the keys are cleared again so Arnika starts from a clean interface.

Steps 2 and 4–6 each need a handshake on demand, and a preshared key is used *only*
in the handshake — a live session keeps working after the key changes
underneath it. So the script removes the peer and adds it back, which throws the
session away and forces the next packet to handshake with the current key. That
is also why the per-mode checks assert *matching keys on both ends* rather than
a handshake per rotation: at `INTERVAL=5s` the key rotates far faster than
WireGuard's ~2-minute rekey, so most rotations are never exercised by a
handshake at all.

## The missing-source tests

A mode is a statement about which key source may be absent. Two checks per mode
put that statement to the test, by taking each source away in turn:

| `MODE` | QKD gone | PQC gone |
|---|---|---|
| `QkdAndPqcRequired` | invalidate | invalidate |
| `AtLeastQkdRequired` | invalidate | keep rotating |
| `AtLeastPqcRequired` | keep rotating | invalidate |

*Invalidate* is Arnika's own answer to a missing required source: rather than
leave the previous PSK in place, `setPSK` installs a **random** one
(`InvalidateTunnel`), so a failed rotation cannot silently extend the life of
the key it was meant to replace. Each end draws its own random key, so **the two
ends landing on different keys is the signal**. *Keep rotating* is the opposite:
both ends stay in step, on a key derived from whichever source is left.

How each source is taken away:

- **QKD** — the KMS simulator is stopped, so every `enc_keys`/`dec_keys`
  request fails, and started again afterwards.
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

It cannot simply overwrite a key and look: at `INTERVAL=5s` a running pair
resyncs faster than the check can measure. So the peers are **stopped** first:

1. stop both Arnika processes — they can no longer write a PSK;
2. overwrite qcicat2's preshared key with a random one;
3. remove and re-add qcicat1's peer, which throws away the live session and
   forces a fresh handshake — remember a running session survives a key change,
   so without this the break would not show;
4. **require the handshake to fail**, and require nothing to decrypt at the far
   end (`tunnel_traffic broken` — the same counter check, verdict inverted);
5. start the pair again, and **require them to resync**: both ends back on one
   identical key that is neither the random one nor stale, within 30s;
6. require a handshake on that resynced key, and the payload to traverse again.

`SIGSTOP` would be the lighter touch and is **not usable here**: Arnika runs
under `sudo`, and `sudo` answers a stopped child by suspending itself and
passing the stop to its process group — which is the script. That reads as
`[2] + suspended (signal) ./run.sh` and hangs the run. Stopping and restarting
the pair is both safe and a slightly better test, since it also covers a peer
starting up against an interface whose key is wrong.

Step 4 failing is the serious one — it means a dead tunnel would pass unnoticed
in that mode. Steps 5 and 6 failing means Arnika cannot recover from a PSK
written behind its back.

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
