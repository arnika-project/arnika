# Security Policy

## Overview

**Arnika** is a security-critical component designed to supply quantum-resistant Pre-Shared Keys
(PSK) to WireGuard VPN by integrating keys from a Quantum Key Distribution (QKD) Key Management
System (KMS) via ETSI GS QKD 014 and/or Post-Quantum Cryptography (PQC) via Rosenpass. It is
developed in the scope of the EU **EUROQCI / QCI-CAT** research program.

Arnika injects the derived PSK **directly into a kernel WireGuard interface via the Linux Netlink /
Generic Netlink (`NETLINK_GENERIC`) interface** using `wgctrl`
(`golang.zx2c4.com/wireguard/wgctrl`). This kernel-level interface interaction is a core security
boundary and is treated as such throughout this policy.

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
| < latest      | ❌ No               |

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
  WireGuard Netlink PSK injection, TCP inter-peer channel, or KMS mock/tooling
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

### Netlink / WireGuard PSK Injection

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

### Key Material Handling

- Incorrect derivation, leakage, or misuse of QKD or PQC keys in memory
- HKDF/SHA3-256 key derivation (`kdf/` module): implementation flaws in the hybrid QKD+PQC key
  derivation

### KMS Communication

- Authentication bypass, MITM susceptibility, or missing TLS enforcement on the `KMS_URL`
  endpoint (ETSI GS QKD 014 API)

### Inter-Peer Key ID Exchange (TCP Channel)

- Spoofing, replay attacks, or tampering with key IDs transmitted over the Arnika TCP channel
- Missing or misconfigured mTLS (`CERTIFICATE`, `PRIVATE_KEY`, `CA_CERTIFICATE`)

### PQC Key File

- `PQC_PSK_FILE`: insecure file permissions, symlink attacks, or file descriptor leakage from
  Rosenpass integration

### Dependencies

- Vulnerabilities in Go modules: `golang.zx2c4.com/wireguard/wgctrl`,
  `github.com/mdlayher/genetlink`, `github.com/mdlayher/netlink`, `github.com/mdlayher/socket`,
  `golang.org/x/crypto`, `golang.org/x/sys`

### Mode Downgrade

- Attacks that force a weaker operational mode (e.g., from `QkdAndPqcRequired` to
  `EitherQkdOrPqcRequired`)

The following are **out of scope**:

- Vulnerabilities in WireGuard itself (report to [WireGuard project](https://www.wireguard.com/))
- Vulnerabilities in Rosenpass (report to
  [Rosenpass project](https://github.com/rosenpass/rosenpass))
- Vulnerabilities in the underlying QKD hardware or ETSI014-compliant KMS (report to the
  respective vendor)
- Security issues in the Linux kernel Netlink subsystem or kernel WireGuard driver itself
- Security issues in the underlying OS or hardware
- Theoretical attacks requiring physical access to the QKD optical channel
- The KMS mock (`tools/kms`) is **not** intended for production; misconfigurations in
  development/test environments are out of scope

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
- **Arnika and WireGuard MUST run on the same host and kernel instance.** The PSK is injected
  directly into the kernel interface; there is no mechanism for remote PSK injection.
- **The Netlink socket is not authenticated at the application level.** Isolation of the Arnika
  process via Linux namespaces, cgroups, or Mandatory Access Control (e.g., AppArmor, SELinux) is
  strongly recommended to prevent other local processes from interfering with or observing the
  Netlink communication.
- **No PSK is persisted to disk.** Key material is held in memory only during the active rekeying
  window and passed directly to the kernel via Netlink. Any path that causes the PSK to be logged
  or written to disk is a high-severity finding.

### mTLS for Inter-Peer Channel

Mutual TLS is strongly recommended for the inter-peer TCP channel used to exchange QKD key IDs.
Running without mTLS (`CERTIFICATE`, `PRIVATE_KEY`, `CA_CERTIFICATE` not configured) is only
acceptable in isolated lab environments.

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
- [ ] Arnika and WireGuard run on the **same hardened Linux host**
- [ ] Host is hardened with MAC (AppArmor or SELinux) to restrict Arnika's Netlink access to the
  `wireguard` genetlink family only
- [ ] `KMS_URL` uses `https://` with a trusted, validated certificate
- [ ] `CERTIFICATE`, `PRIVATE_KEY`, and `CA_CERTIFICATE` are configured for mTLS between Arnika
  peers
- [ ] `PQC_PSK_FILE` has permissions `0600` and is owned by the Arnika process user
- [ ] The KMS mock (`tools/kms`) is **not** deployed or reachable in production
- [ ] WireGuard `INTERVAL` and Arnika `INTERVAL` are aligned (recommended: `120s`)
- [ ] Go version `>= 1.22` (recommended: latest `1.24.x`) is used
- [ ] Dependency integrity is verified via `go.sum` before building from source
- [ ] Arnika logs are monitored for PSK injection failures or fallback-to-zero-PSK events —
  these indicate loss of quantum protection
- [ ] Process is isolated with `ProtectSystem=strict`, `PrivateTmp=true`, and
  `NoNewPrivileges=true` in the systemd unit

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
