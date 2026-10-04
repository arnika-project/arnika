# wireguard-netlink-netns

**Key writer module - installs the WireGuard PSK into a local WireGuard interface inside a network namespace through the kernel's netlink API.**

This is the single document for the `wireguard-netlink-netns` module. For the generic architecture all key reader and key writer modules follow, see [`KEYCONTROL.md`](../KEYCONTROL.md).

---

## At a Glance

| | |
| --- | --- |
| **Module name** | `wireguard-netlink-netns` |
| **Kind** | Key writer (sink) |
| **Build tag** | `wireguard_netlink_netns` |
| **Adapter** | [`repositories/wgnetlink/netns.go`](../repositories/wgnetlink/netns.go) |
| **Tests** | _no unit tests_, only integration tests in `ci/namespaces` ran by the CI |
| **Wiring** | [`wire_wireguard_netlink_netns.go`](../wire_wireguard_netlink_netns.go) |
| **Target** | A **local** WireGuard interface in a network namespace |
| **Transport** | `wgctrl` over netlink inside the namespace |
| **Dependencies** | `golang.zx2c4.com/wireguard/wgctrl`, `github.com/containernetworking/plugins/pkg/ns` |
| **Privileges** | `CAP_NET_ADMIN`, `CAP_SYS_ADMIN` — it reconfigures a network device inside a namespace |
| **Platform** | Linux only |

---

## How the Module Works

Same as [`wireguard-netlink`](wireguard-netlink.md), but executes inside a network namespace. Uses `containernetworking/plugins/pkg/ns` to enter the namespace and then delegates to `WireguardNetlinkRepository`.

---

## Part 1 — Prepare the Host

Same as [`wireguard-netlink`](wireguard-netlink.md), but the WireGuard interface must exist inside the specified network namespace.

---

## Part 2 — Configuration Reference

| Env var | Required | Description |
| --- | :---: | --- |
| `WIREGUARD_INTERFACE` | yes | Name of the WireGuard interface inside the namespace |
| `WIREGUARD_PEER_PUBLIC_KEY` | yes | Public key of the peer whose PSK is rotated |
| `WIREGUARD_NETNS_PATH` | yes | Path to the network namespace (e.g., `/var/run/netns/myns`) |

---

## Part 3 — Compile

```bash
GOEXPERIMENT=runtimesecret go build -tags wireguard_netlink_netns .
```

Via the Makefile:

```bash
make build BUILD_TAGS=wireguard_netlink_netns
```

---

## Part 4 — Run

Arnika must start after the interface and namespace exist. Requires `CAP_NET_ADMIN` and `CAP_SYS_ADMIN` (for namespace operations).

---

## Security Considerations

### Namespace path permissions

`WIREGUARD_NETNS_PATH` is trusted without further verification. Thus if an attacker controls the namespace at that path, Arnika will happily inject the PSK into their interface instead of the intended one. Ensure the namespace file and its parent directory are owned by the service account running Arnika with restrictive permissions (e.g. `0700`), and avoid symlinks that could be repointed by an untrusted process.

## References

- Module architecture: [`KEYCONTROL.md`](../KEYCONTROL.md)
- Base module: [`wireguard-netlink.md`](wireguard-netlink.md)
- `wgctrl` package: <https://pkg.go.dev/golang.zx2c4.com/wireguard/wgctrl>
- `containernetworking/plugins/pkg/ns`: <https://pkg.go.dev/github.com/containernetworking/plugins/pkg/ns>
- WireGuard network namespace documentation: <https://www.wireguard.com/netns/#the-new-namespace-solution>
