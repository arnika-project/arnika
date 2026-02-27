# Security Policy

## Overview

**Arnika** is a security-critical component designed to supply quantum-resistant Pre-Shared Keys (PSK) to WireGuard VPN by integrating keys from a Quantum Key Distribution (QKD) Key Management System (KMS) via ETSI GS QKD 014 and/or Post-Quantum Cryptography (PQC) via Rosenpass. It is developed in the scope of the EU **EUROQCI / QCI-CAT** research program.

Because Arnika operates at the intersection of cryptographic key material handling, VPN infrastructure, and quantum-secure communication protocols, security vulnerabilities in this project may have serious consequences for the confidentiality and integrity of protected VPN sessions.

We take security very seriously and encourage responsible disclosure from the community.

---

## Supported Versions

Only the latest stable release receives security fixes. Please ensure you are running the latest release before reporting a vulnerability.

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

- **Email**: Send a detailed report to the maintainers. Contact information is available in the repository's contributor profiles or via the [arnika-project GitHub organization](https://github.com/arnika-project).

Please include the following information in your report:

- A clear description of the vulnerability and its potential impact
- Affected component(s): Arnika core, KMS connector (ETSI014), PQC/QKD key derivation (KDF), WireGuard PSK injection, or KMS mock/tooling
- Steps to reproduce or a proof-of-concept (PoC) if available
- Affected version(s) and operating environment (OS, Go version, WireGuard version)
- Any suggested mitigations or patches

---

## Disclosure Policy

We follow **coordinated responsible disclosure**:

1. You report the vulnerability privately.
2. The maintainers acknowledge receipt within **5 business days**.
3. We assess severity and triage within **10 business days**.
4. A fix is developed, tested, and released, aiming for resolution within **90 days** of the initial report (or sooner for critical issues).
5. A public security advisory is issued after the fix is released.
6. Credit is given to the reporter unless anonymity is requested.

---

## Scope

The following are **in scope** for security reports:

- **Key material handling**: incorrect derivation, leakage, or misuse of QKD or PQC keys
- **KMS communication** (`KMS_URL`, ETSI GS QKD 014 API): authentication bypass, MITM susceptibility, missing TLS enforcement
- **PSK injection into WireGuard**: race conditions, unauthorized PSK overwrite, privilege escalation via WireGuard socket/API
- **Inter-peer key ID exchange protocol**: spoofing, replay attacks, tampering with key IDs transmitted over the TCP channel
- **TLS configuration**: weak cipher suites, missing mutual TLS (mTLS) enforcement between Arnika peers (`CERTIFICATE`, `PRIVATE_KEY`, `CA_CERTIFICATE`)
- **PQC key file handling** (`PQC_PSK_FILE`): insecure file permissions, symlink attacks, file descriptor leakage from Rosenpass integration
- **HKDF/SHA3-256 key derivation** (`kdf/` module): implementation flaws in the hybrid QKD+PQC key derivation
- **Dependency vulnerabilities** in Go modules (`golang.org/x/crypto`, `wgctrl`, etc.)
- **KMS mock/simulator** (`tools/kms`): vulnerabilities that could mislead users into deploying it in production

The following are **out of scope**:

- Vulnerabilities in WireGuard itself (report to [WireGuard project](https://www.wireguard.com/))
- Vulnerabilities in Rosenpass (report to [Rosenpass project](https://github.com/rosenpass/rosenpass))
- Vulnerabilities in the underlying QKD hardware or the ETSI014-compliant KMS (report to the respective vendor)
- Security issues in the underlying Linux kernel, OS, or hardware
- Theoretical attacks requiring physical access to the QKD optical channel
- The KMS mock (`tools/kms`) is **not** intended for production use; misconfigurations in development/test environments are out of scope

---

## Security Design Principles

Understanding the security assumptions of Arnika helps contextualize vulnerability reports:

- **Arnika and WireGuard must run on the same host.** The PSK is injected into the local WireGuard instance via the kernel API. Any vulnerability allowing unauthorized local process access to the WireGuard socket is critical.
- **Mutual TLS is strongly recommended** for the inter-peer TCP channel used to exchange QKD key IDs. Running without mTLS (`CERTIFICATE`, `PRIVATE_KEY`, `CA_CERTIFICATE` not configured) is only acceptable in isolated lab environments.
- **The KMS (ETSI GS QKD 014) endpoint must be accessed over HTTPS** with valid certificates in production. Using `http://` for `KMS_URL` in production is a security misconfiguration.
- **Key derivation** in hybrid mode (QKD + PQC) uses HKDF with SHA3-256. Any deviation from this construction or weakness in the implementation is a high-severity finding.
- **The PQC PSK file** (`PQC_PSK_FILE`) must be readable only by the Arnika process. Permissions wider than `0600` owned by the Arnika runtime user are a misconfiguration.
- **Arnika does not store key material on disk.** Keys are held in memory only during the active rekeying window.
- **Operation modes** (`QkdAndPqcRequired`, `AtLeastQkdRequired`, `AtLeastPqcRequired`, `EitherQkdOrPqcRequired`) define the security level; downgrade attacks that force a weaker mode are in scope.

---

## Secure Deployment Checklist

Deployers should verify the following before production use:

- [ ] `KMS_URL` uses `https://` with a trusted, validated certificate
- [ ] `CERTIFICATE`, `PRIVATE_KEY`, and `CA_CERTIFICATE` are configured for mTLS between Arnika peers
- [ ] `PQC_PSK_FILE` has permissions `0600` and is owned by the Arnika process user
- [ ] Arnika and WireGuard run on a **hardened Linux host** with minimal attack surface
- [ ] The KMS mock (`tools/kms`) is **not** deployed or reachable in production
- [ ] WireGuard `INTERVAL` and Arnika `INTERVAL` are aligned (recommended: `120s`)
- [ ] Arnika process runs with **least-privilege** (dedicated service user, no root unless required by WireGuard socket access)
- [ ] Go version `>= 1.22` is used to avoid known vulnerabilities in older standard library versions
- [ ] Dependency integrity is verified via `go.sum` before building from source

---

## Severity Classification

We use the [CVSS v3.1](https://www.first.org/cvss/calculator/3.1) scoring system and the following classification:

| Severity | Description | Target Response Time |
|----------|-------------|----------------------|
| **Critical** | Key material exposure, PSK forgery, full compromise of WireGuard session security | 7 days |
| **High** | Authentication bypass, mTLS bypass, mode downgrade attack | 14 days |
| **Medium** | Denial of service to Arnika daemon, partial information leakage | 30 days |
| **Low** | Hardening issues, non-exploitable misconfigurations | 90 days |

---

## Known Limitations & Accepted Risks

The following are documented limitations acknowledged by the maintainers. They are **not** considered vulnerabilities unless a new attack vector is identified:

- A **race condition** can occur when Arnika instances are started simultaneously in development environments. This is a known, intentional design consequence and has no impact on production deployments with staggered startup.
- The **KMS mock** (`tools/kms`) uses HTTP only, pseudo-random keys, and hardcoded SAE identifiers (`CONSA`, `CONSB`). It must never be used in production.
- Arnika transmits **only the key ID** (UUID) over the inter-peer TCP channel — never the key material itself. The key material is retrieved independently from the KMS by each peer.

---

## Acknowledgements

We thank all security researchers and contributors who help improve the security of Arnika and, by extension, quantum-secure communication infrastructure.

---

## References

- [ETSI GS QKD 014 – Key Delivery API](https://www.etsi.org/deliver/etsi_gs/QKD/001_099/014/)
- [WireGuard Protocol & Security Model](https://www.wireguard.com/protocol/)
- [Rosenpass – Post-Quantum WireGuard](https://rosenpass.eu/)
- [QCI-CAT Project](https://qci-cat.at/)
- [Apache-2.0 License](https://www.apache.org/licenses/LICENSE-2.0)
