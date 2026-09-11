# Security Policy

## Overview

**Arnika** is a security-critical component designed to supply quantum-resistant Pre-Shared Keys
(PSK) to WireGuard VPN by integrating keys from a Quantum Key Distribution (QKD) Key Management
System (KMS) via ETSI GS QKD 014 and/or Post-Quantum Cryptography (PQC). It is
developed in the scope of the EU **EUROQCI / QCI-CAT** research program.

Arnika installs the derived PSK through a **key writer** adapter. Two are shipped
(see [`KEYCONTROL.md`](KEYCONTROL.md)), and they have different security boundaries:

| Key writer | Build tag | How the PSK reaches WireGuard | Security boundary |
|---|---|---|---|
| netlink (default) | _(none)_ / `wireguard_netlink` | Local kernel WireGuard interface via Generic Netlink (`NETLINK_GENERIC`) using `wgctrl` | Kernel Netlink socket, `CAP_NET_ADMIN` |
| MikroTik | `wireguard_mikrotik` | REST API call to a remote RouterOS router over HTTPS | Authenticated TLS session to the router |

Both boundaries are treated as core security boundaries throughout this policy. Where a rule
applies to only one writer, it is marked accordingly.

Because Arnika operates at the intersection of cryptographic key material handling, VPN
infrastructure, kernel Netlink communication, and quantum-secure cryptographic protocols, security
vulnerabilities in this project may have serious consequences for the confidentiality and integrity
of protected VPN sessions.

We take security very seriously and encourage responsible disclosure from the community.

---

## Supported Versions

Only the latest stable release receives security fixes. Please ensure you are running the latest
release before reporting a vulnerability.

| Version       | Supported          |
|---------------|--------------------|
| latest (main) | ✅ Yes              |
| v1.x          | ✅ Yes              |
| < v1.x        | ❌ No               |

---

## Reporting a Vulnerability

**Please do NOT open a public GitHub issue for security vulnerabilities.**

Report security vulnerabilities via one of the following channels:

- **GitHub Private Security Advisory** (preferred):
  [https://github.com/arnika-project/arnika/security/advisories/new](https://github.com/arnika-project/arnika/security/advisories/new)

- **Email**: Send a detailed report to the maintainers. Contact information is available in the
  repository's contributor profiles or via the
  [arnika-project GitHub organization](https://github.com/arnika-project).

Please include the following in your report:

- A clear description of the vulnerability and its potential impact
- Affected component(s): Arnika core, KMS connector (ETSI014), PQC/QKD key derivation (KDF),
  WireGuard PSK injection (netlink or MikroTik key writer), UDP inter-peer channel, or KMS
  mock/tooling
- Steps to reproduce or a proof-of-concept (PoC) if available
- Affected version(s) and environment (OS, kernel version, Go version, WireGuard version)
- Any suggested mitigations or patches

---

## Disclosure Policy

We follow **coordinated responsible disclosure**:

1. You report the vulnerability privately.
2. The maintainers acknowledge receipt within **5 business days**.
3. We assess severity and triage within **10 business days**.
4. A fix is developed, tested, and released, aiming for resolution within **90 days** of the
   initial report (sooner for critical issues).
5. A public security advisory is issued after the fix is released.
6. Credit is given to the reporter unless anonymity is requested.

---

## Scope

The following are **in scope** for security reports:

### Key Writers / WireGuard PSK Injection

The following apply to the **netlink key writer** (the default):

- **Privilege escalation via Netlink**: Arnika uses `wgctrl` over `NETLINK_GENERIC` to write PSKs
  into the WireGuard kernel interface. Any vulnerability that allows unauthorized processes to
  trigger, spoof, or intercept this Netlink communication is critical.
- **PSK injection into wrong peer**: Incorrect peer public key matching
  (`WIREGUARD_PEER_PUBLIC_KEY`) causing the PSK to be applied to the wrong WireGuard peer.
- **PSK injection failure silently ignored**: Failures in the Netlink call that result in
  WireGuard falling back to an all-zero PSK (no quantum protection) without alerting the operator.
- **Race conditions on Netlink access**: Multiple Arnika instances or external processes racing to
  configure the same WireGuard interface via Netlink simultaneously.
- **Insufficient privilege isolation**: The Arnika process requires sufficient Linux capabilities
  to write to the WireGuard Netlink family (`wireguard` genetlink). Any configuration that
  inadvertently grants broader kernel capabilities (e.g., full `CAP_NET_ADMIN`) beyond what is
  strictly needed is in scope.

The following apply to **remote key writers** such as the MikroTik RouterOS adapter
(`wireguard_mikrotik`, see [`docs/wireguard-mikrotik.md`](docs/wireguard-mikrotik.md)):

- **PSK in transit to the router**: the derived PSK leaves the Arnika host. Weak or absent TLS
  verification (`MIKROTIK_TLS_INSECURE=true` outside a lab, missing
  `MIKROTIK_CA_CERTIFICATE`), or any flaw exposing the PSK on the management network, is in scope.
- **Router credential handling**: leakage or misuse of `MIKROTIK_USERNAME` /
  `MIKROTIK_PASSWORD`, or a router account with privileges beyond writing the peer PSK.
- **PSK written to the wrong peer or interface** on the router, or a failed write that leaves a
  stale PSK in place without alerting the operator.

### Key Material Handling

- Incorrect derivation, leakage, or misuse of QKD or PQC keys in memory
- HKDF/SHA3-256 key derivation (`kdf/` module): implementation flaws in the hybrid QKD+PQC key
  derivation

### KMS Communication

- Authentication bypass, MITM susceptibility, or missing TLS enforcement on the `KMS_URL`
  endpoint (ETSI GS QKD 014 API)

### Inter-Peer Key ID Exchange (UDP Channel)

The peer channel is UDP, authenticated and encrypted with `ARNIKA_PSK` (HMAC-SHA256 signature +
AES-256-GCM payload, see [`CODEFLOW.md`](CODEFLOW.md)):

- Spoofing, replay attacks, or tampering with key IDs transmitted over the Arnika UDP channel
- Weaknesses in packet signing, encryption, timestamp validation (`MAX_CLOCK_SKEW`) or per-IP
  rate limiting (`RATE_LIMIT`, `RATE_WINDOW`)
- Any leakage of `ARNIKA_PSK`, or a code path that accepts packets that fail verification


### Dependencies

- Vulnerabilities in Go modules: `golang.zx2c4.com/wireguard/wgctrl`,
  `github.com/mdlayher/genetlink`, `github.com/mdlayher/netlink`, `github.com/mdlayher/socket`,
  `golang.org/x/crypto` (HKDF, SHA-3), `golang.org/x/net`, `golang.org/x/sys`,
  `github.com/google/uuid`

### Mode Downgrade

- Attacks that force a weaker operational mode (e.g., from `QkdAndPqcRequired` to
  `EitherQkdOrPqcRequired`)

## Out of scope

The following are **out of scope**:

- Vulnerabilities in WireGuard itself (report to [WireGuard project](https://www.wireguard.com/))
- Vulnerabilities in external PQC key provider
- Vulnerabilities in the underlying QKD hardware or ETSI014-compliant KMS (report to the
  respective vendor)
- Security issues in the Linux kernel Netlink subsystem or kernel WireGuard driver itself
- Security issues in the underlying OS or hardware
- Theoretical attacks requiring physical access to the QKD optical channel
- The KMS mock (`tools/kms`) is **not** intended for production; misconfigurations in
  development/test environments are out of scope
- `PQC_PSK_FILE`: insecure file permissions, symlink attacks, or file descriptor leakage from PQK key provider integration

---

## Security Design Principles

### Netlink Interface & Required Privileges

Arnika uses `wgctrl` to communicate with the Linux kernel WireGuard driver via **Generic Netlink
(`NETLINK_GENERIC`)**, specifically the `wireguard` genetlink family. This is the mechanism by
which the PSK is atomically set on a per-peer basis in the kernel.

Key implications for security:

- **`CAP_NET_ADMIN` is required** for Arnika to write to the WireGuard Netlink interface. In
  production, this capability should be granted **exclusively and minimally** — ideally via a
  systemd service unit with `AmbientCapabilities=CAP_NET_ADMIN` and
  `CapabilityBoundingSet=CAP_NET_ADMIN`, combined with a dedicated unprivileged service user.
  Running Arnika as `root` is acceptable in **testing, demo, or PoC environments**, and may also
  be acceptable in production environments that are sufficiently hardened and isolated (e.g., a
  dedicated node with no untrusted local users, strict MAC enforcement, and full network perimeter
  control). For all other production use, running as root is strongly discouraged in favour of
  capability-scoped service accounts.
- **With the netlink key writer, Arnika and WireGuard MUST run on the same host and kernel
  instance.** The PSK is injected directly into the local kernel interface. Remote PSK injection
  requires a key writer built for it, such as the MikroTik RouterOS adapter, which carries its own
  transport security requirements (see below).
- **The Netlink socket is not authenticated at the application level.** Isolation of the Arnika
  process via Linux namespaces, cgroups, or Mandatory Access Control (e.g., AppArmor, SELinux) is
  strongly recommended to prevent other local processes from interfering with or observing the
  Netlink communication.
- **No PSK is persisted to disk.** Key material is held in memory only during the active rekeying
  window and passed directly to the kernel via Netlink. Any path that causes the PSK to be logged
  or written to disk is a high-severity finding.

### Inter-Peer Channel Authentication (`ARNIKA_PSK`)

The channel used to exchange QKD key IDs is **UDP**, and its only cryptographic protection is the
shared secret `ARNIKA_PSK`. Packets are signed with HMAC-SHA256 and their payload encrypted with
AES-256-GCM, using two keys derived from that secret with domain separation (`auth/auth.go`).

- **`ARNIKA_PSK` MUST be set, identical on both peers, and secret.** It is not read from a file
  and not negotiated — there is no fallback and no alternative authentication mechanism for this
  channel.
- **An unset `ARNIKA_PSK` is a critical misconfiguration.** The variable defaults to the empty
  string and is not rejected at startup. Both derived keys then depend only on the empty string
  and are trivially computable by anyone, so any host that can reach `LISTEN_ADDRESS` can inject
  or decrypt key IDs. Arnika still starts and appears to work.
- **Generate it with a CSPRNG**, at least 32 bytes of entropy, e.g. `openssl rand -base64 32`.
  Distribute it out of band and rotate it on both peers together.
- **The startup banner prints `ARNIKA_PSK` in cleartext** (`Arnika PSK: …`). Treat Arnika's stdout
  and journal as secret material, or redact it before sharing logs.
- **Supporting controls on the same channel**: per-IP rate limiting (`RATE_LIMIT`, `RATE_WINDOW`,
  default 30/min) and timestamp replay protection (`MAX_CLOCK_SKEW`, default `1m`). Lowering
  `MAX_CLOCK_SKEW` reduces the replay window but requires closer clock synchronisation between
  peers.

Mutual TLS is **not** available on this channel. `CERTIFICATE`, `PRIVATE_KEY` and
`CA_CERTIFICATE` do not apply to it — see the next section.

### Role Election Integrity (`ARNIKA_ID`)

Which peer requests a new key in a given interval is decided locally by
`HMAC-SHA256(ARNIKA_PSK, intervalNumber)` XOR `ARNIKA_ID` (`config/config.go`, `IsPrimary`).

- **The two peers' `ARNIKA_ID` values MUST have different parity** — one odd, one even. Only the
  lowest bit of `ARNIKA_ID` enters the decision, so two peers with different but same-parity IDs
  (e.g. `100` and `102`) elect the *same* role in every interval, and both or neither will rotate.
- **`ARNIKA_ID` defaults to the port from `LISTEN_ADDRESS`.** If both peers listen on the same
  port, they inherit the same ID and role election never separates them. Set it explicitly.
- **Both peers MUST use the same `INTERVAL`.** The election is only guaranteed to produce opposite
  roles for the same interval number; different interval lengths make the counters drift apart and
  the roles independent.

### KMS Client Certificates (`CERTIFICATE`, `PRIVATE_KEY`, `CA_CERTIFICATE`)

These three variables configure **client-certificate authentication towards the KMS only**
(`repositories/kms.go`, wired in `keyreader.go`). They are used for the ETSI GS QKD 014 HTTPS
connection and for nothing else — in particular they do not protect the inter-peer channel.

They are **all-or-nothing**: if any one of them is empty, client-certificate authentication is
silently disabled and the KMS connection falls back to server-only validation against the system
root store (TLS 1.2 minimum). Where the KMS requires mutual TLS, configure all three, keep the
private key `0600` and owned by the Arnika user, and note that `CA_CERTIFICATE` then *replaces*
the system roots for that connection.

A deployment that believes it is using mutual TLS towards the KMS while one of the three variables
is unset is a misconfiguration worth reporting.

### KMS Endpoint Security

The KMS (ETSI GS QKD 014) endpoint must be accessed over HTTPS with valid certificates in
production. Using `http://` for `KMS_URL` in production is a security misconfiguration.

### Hybrid Key Derivation

Key derivation in hybrid mode (QKD + PQC) uses HKDF with SHA3-256. Any deviation from this
construction or weakness in the implementation is a high-severity finding.

### Operational Modes

Operation modes (`QkdAndPqcRequired`, `AtLeastQkdRequired`, `AtLeastPqcRequired`,
`EitherQkdOrPqcRequired`) define the minimum security level. Downgrade attacks that force a weaker
mode are in scope.

### PQC Key File & Directory Hardening

The `PQC_PSK_FILE` mechanism reads PSK material from a file provided an external
key provider. While setting the file to `0600` restricts access, this alone is insufficient if the
parent directory remains writable by the Arnika process user.

**Attack vector**: As demonstrated via [GHSA-rc6v-5rmx-w5m](https://github.com/arnika-project/arnika/security/advisories/GHSA-rc6v-5rmx-w5mv) , if an attacker has write access to the directory containing `PQC_PSK_FILE`, they
can:

- Delete the original file and replace it with attacker-controlled content
- Create a symlink to a different file they control
- Bypass application-level validation entirely

**Mitigation**: The directory containing `PQC_PSK_FILE` must have permissions that prevent the
Arnika process user from modifying its contents. Recommended: `0700` or `0750` owned by root, with
the Arnika user having read access only.

**Directory permissions**: The parent directory containing `PQC_PSK_FILE` must not be writable
  by the Arnika process user. Even with `0600` on the file, if the directory is writable, an
  attacker with access to that directory can delete/replace the file or symlink, bypassing file
  permission protections entirely.

This is a defense-in-depth measure complementary to the application-level validation that checks
for empty or whitespace-only keys.

### SKIP Protocol (`KMS_PROTOCOL=skip`)

When configured to use the alternative SKIP protocol (`KMS_PROTOCOL=skip`), Arnika relies on `SKIP_REMOTE_SYSTEM_ID` to correctly target the remote peer's identifier on the KMS endpoint.

- **Remote System ID Validation**: Both peers must correctly configure `SKIP_REMOTE_SYSTEM_ID` to match the expected remote system ID. A mismatch leads to key retrieval failures or incorrect key mapping.
- **Transport Security**: The `KMS_URL` endpoint must enforce TLS validation (using proper `CA_CERTIFICATE` or system roots) to prevent man-in-the-middle attacks, identical to the standard ETSI014 protocol adapter.
- **Input Sanitization**: All incoming identifiers and key material values handled via the SKIP adapter are strictly validated and hex-encoded.


---

## Secure Deployment Checklist

- [ ] Arnika runs as a **dedicated, unprivileged service user** (not root)
  > **Note:** Running Arnika as `root` is acceptable in testing, demo, or proof-of-concept
  > environments, and may be acceptable in production if the host is sufficiently hardened and
  > isolated (e.g., dedicated bare-metal node, strict MAC policy, no untrusted local users). In
  > all other production deployments, a dedicated service user with
  > `AmbientCapabilities=CAP_NET_ADMIN` is strongly preferred.
- [ ] `CAP_NET_ADMIN` is granted **only** via `AmbientCapabilities` in the systemd unit — no
  broader root or wildcard capability grants
- [ ] Arnika and WireGuard run on the **same hardened Linux host** (netlink key writer); for a
  remote key writer, the management path to the target device is trusted and TLS-verified
- [ ] Host is hardened with MAC (AppArmor or SELinux) to restrict Arnika's Netlink access to the
  `wireguard` genetlink family only
- [ ] `KMS_URL` uses `https://` with a trusted, validated certificate
- [ ] `ARNIKA_PSK` is set to at least 32 bytes of CSPRNG output, **identical on both peers**, and
  never left unset
- [ ] `ARNIKA_ID` is set explicitly on both peers, with **different parity** (one odd, one even)
- [ ] Both peers use the **same `INTERVAL`**
- [ ] `CERTIFICATE`, `PRIVATE_KEY`, and `CA_CERTIFICATE` are configured where the **KMS** requires
  client-certificate authentication (these do not apply to the inter-peer channel)
- [ ] For the MikroTik key writer: `MIKROTIK_CA_CERTIFICATE` is set, `MIKROTIK_TLS_INSECURE` is
  **not** enabled, and the router account is restricted to writing the peer PSK
- [ ] `PQC_PSK_FILE` has permissions `0600` and is owned by the Arnika process user
- [ ] The parent directory containing `PQC_PSK_FILE` is **not writable** by the Arnika process user
- [ ] The KMS mock (`tools/kms`) is **not** deployed or reachable in production
- [ ] WireGuard `INTERVAL` and Arnika `INTERVAL` are aligned (recommended: `120s`)
- [ ] Go version `>= 1.26` is used, with `GOEXPERIMENT=runtimesecret` set for every `go` command
  (required by the `runtime/secret` memory hardening; the `Makefile` sets it already)
- [ ] Dependency integrity is verified via `go.sum` before building from source
- [ ] Arnika logs are monitored for PSK injection failures or fallback-to-zero-PSK events —
  these indicate loss of quantum protection
- [ ] Arnika logs are treated as sensitive: the startup banner prints `ARNIKA_PSK` in cleartext
- [ ] Process is isolated with `ProtectSystem=strict`, `PrivateTmp=true`, and
  `NoNewPrivileges=true` in the systemd unit
- [ ] When using `KMS_PROTOCOL=skip`, `SKIP_REMOTE_SYSTEM_ID` is correctly configured and matches the expected peer identifier

### Example Minimal systemd Hardening Snippet

```ini
[Service]
User=arnika
Group=arnika
AmbientCapabilities=CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_ADMIN
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
RestrictNamespaces=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_NETLINK
SystemCallFilter=@system-service @network-io
```
