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
`CAP_NET_ADMIN`.

## Running it

```bash
./run.sh             # bring up, watch five rotation cycles, tear down
./run.sh --keep      # leave the interfaces and logs in place afterwards
./run.sh --quiet     # do not stream the logs, only report the checks
VERBOSE=1 ./run.sh   # also print the wg dumps at the end
```

It builds `arnika` and the KMS simulator, brings up both interfaces, starts the
simulator and two Arnika instances, then checks that:

- both ends report `[OK] PSK configured on WireGuard interface`
- **both interfaces hold the same preshared key** — the property that matters;
  different keys mean a dead handshake
- the tunnel carries traffic: `100.1.1.1 → 100.1.2.2` pings, a handshake
  completed, and `wg show … transfer` shows bytes moving
- the PSK **rotates over five consecutive cycles**, and both ends hold the
  identical key on every one of them
- the tunnel still passes traffic after those five rotations

At `INTERVAL=5s` the five cycles take about half a minute. One rotation proves
the mechanism; five prove it keeps working — a single divergence is what a dead
handshake looks like in production.

Teardown runs even on failure, so a `wg-quick down` is not left to you.

### Debug output

All three processes log to the console as they run, prefixed so the interleaved
streams stay readable:

```
kms| 2026/09/07 15:30:09 [CONF] debug logging enabled=true (set DEBUG=true to enable)
kms| 2026/09/07 15:30:10 [DEBUG] [REQ] method=POST path=/api/v1/keys/CONSA/enc_keys
a1|  2026/09/07 15:30:11 [INFO] PRIMARY[9998] [SND] send key_id ffffffff-…
a2|  2026/09/07 15:30:11 [INFO] BACKUP[9999] [RCV] received key_id ffffffff-…
a1|  2026/09/07 15:30:11 [INFO] pqc-hpke: round 357756369 agreed a fresh PQC key
```

The simulator needs `DEBUG=true` for its request and response logging, and
`run.sh` sets it. Arnika's own `[DEBUG]` lines — rejected packets, ACK
timeouts, dropped PQC frames — are unconditional and need no flag.

`--quiet` turns the streams off and reports only the checks. Either way the
logs are written to files, and every run ends with a count per log so an anomaly
is visible at a glance:

```
==> debug output
          logs: /tmp/arnika-darwin.XXXX
          arnika1: 7 PQC rounds, 6 PSK writes, 0 debug lines, 0 warnings/errors
          arnika2: 7 PQC rounds, 6 PSK writes, 0 debug lines, 0 warnings/errors
          kms: 26 requests logged
```

On failure — or with `VERBOSE=1` — it also prints `wg show … dump` for both
interfaces, and the log tails if they were not streamed. `--keep` leaves the
logs and the interfaces in place so you can keep poking with the commands
below.

> **The simulator's debug output contains key material.** `[RESP] body=` lines
> carry the QKD keys it hands out, in full. They are pseudo-random keys from a
> mock, not real QKD material, but do not paste that output anywhere without
> reading it first. Arnika's own output is clean: it logs key *IDs*, and the
> startup banner reports only the length of `ARNIKA_PSK`. Preshared keys are
> reported as a `sha256:` prefix and never printed.

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
- **Both configs claim `fdac::/64` in `AllowedIPs`.** Two interfaces on one host
  asking for the same IPv6 route can collide, and `wg-quick` may refuse the
  second `up` with `route: File exists`. If that happens, drop the IPv6 entry
  from one side, or narrow them to `fdac::1/128` and `fdac::2/128`. The IPv4
  `/32`s do not collide.
- The simulator is not a QKD device. It generates pseudo-random keys for
  testing — see [`KMS.md`](../../KMS.md).
- Process hardening and `runtime/secret` erasure are Linux facilities, and
  Arnika says so in two warnings at startup on darwin. Nothing here covers them.
