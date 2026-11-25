# SKIP Protocol Integration

The SKIP (Secure Key Integration Protocol) provides an alternative key management interface for Arnika. This adapter implements **draft-cisco-skip-02** and integrates a SKIP-compatible Key Provider (KP) as a `KeyReaderManaged` backend, allowing dynamic provisioning of quantum-resistant keys.

## Configuration

To use SKIP instead of ETSI GS QKD 014, configure the following environment variables:

| Environment Variable      | Description                              | Example                          | Required |
| :---                       | :---                                     | :---                             | :---     |
| `KMS_PROTOCOL`            | Protocol selector                        | `skip`                           | Yes      |
| `KMS_URL`                 | SKIP KP endpoint (HTTPS only)            | `https://kp.example.com:8200`    | Yes      |
| `SKIP_REMOTE_SYSTEM_ID`   | This peer's identifier at the KP         | `qkdsystem1`                     | Yes      |
| `CERTIFICATE`             | Client certificate (mutual TLS)          | `/etc/arnika/cert.pem`           | No*      |
| `PRIVATE_KEY`             | Private key for certificate              | `/etc/arnika/key.pem`            | No*      |
| `CA_CERTIFICATE`          | CA bundle for server verification        | `/etc/arnika/ca.pem`             | No*      |

*All three must be set together, or all must be empty (system root CA store used instead).

## Protocol Specification

- **Specification**: [draft-cisco-skip-02](https://datatracker.ietf.org/doc/draft-cisco-skip/)
- **Transport**: HTTPS 1.2 or 1.3 (TLS required)
- **Authentication**: Certificate or PSK-based TLS authentication
- **Endpoints**:
  - `GET /key?remoteSystemID=...` — obtain new key
  - `GET /key/{keyId}?remoteSystemID=...` — retrieve key by ID
  - `GET /capabilities` — query KP capabilities (not yet implemented)

- **Key Format**: 256-bit (32-byte) keys, hex-encoded in JSON responses
- **Key ID Format**: Hex-encoded identifier (default 128 bits), validated and URL-escaped before transmission

## Security Limitations

**Important**: Go's `crypto/tls` does not support the TLS_DHE_PSK suites recommended by the SKIP spec for quantum-safe authentication. This implementation uses certificate-based TLS only, providing **classical (non-quantum) security** on the KP-to-Arnika link. The key material itself benefits from the KP's post-quantum key generation, but the transport channel between KP and Arnika is classically protected.

**Mitigation strategies**:
- Co-locate KP and Arnika on the same secure network segment
- Use network segmentation or a dedicated VPN for the KP-to-Arnika link
- Consider running KP as a co-process or hosted application on the same host as Arnika

## Trust Path

1. **Arnika peer** → **local KP** (configured `KMS_URL`) via HTTPS → obtains key
2. **Remote peer** → **remote KP** (via SKIP protocol) → obtains same key using keyId
3. Key validated: exactly 32 bytes, valid hex format
4. Key mixed into WireGuard PSK via HKDF-SHA3-256

## Operational Notes

- **KMS_PROTOCOL must match on both peers**: Set to `skip` on both sides, or both sides must use `etsi014` (default)
- **SKIP_REMOTE_SYSTEM_ID is the peer's KP identifier**: Used in API requests to identify which remote KP should provide the key
- **Key IDs are peer-supplied data**: All keyID values from the remote peer are validated as hex strings with bounded length and escaped before use in URLs
- **No key caching**: Keys are requested fresh each rotation interval; stale keys are not stored

## Example Configuration

```bash
export KMS_PROTOCOL=skip
export KMS_URL=https://kp.local:8200
export SKIP_REMOTE_SYSTEM_ID=arnika-site-b
export CERTIFICATE=/etc/arnika/client.crt
export PRIVATE_KEY=/etc/arnika/client.key
export CA_CERTIFICATE=/etc/arnika/ca.crt
export INTERVAL=120s
export ARNIKA_PSK="<shared secret between peers>"
```

## Troubleshooting

| Error | Cause | Solution |
| :--- | :--- | :--- |
| `keyID is not a valid hex string` | Remote peer sent malformed keyID | Verify remote peer is trusted and online |
| `keyID is too long` | keyID exceeds 128 characters | Check SKIP_REMOTE_SYSTEM_ID and KMS setup |
| `invalid key length: got X bytes, expected 32` | KP returned wrong key size | Verify KP is configured to return 256-bit keys |
| `failed to connect` | KP unreachable | Check KMS_URL, network connectivity, firewall rules |
| `HTTPS connection failed` | Certificate validation failed | Verify CA_CERTIFICATE matches KP's cert issuer |

## References

- [SKIP Protocol Specification](https://datatracker.ietf.org/doc/draft-cisco-skip/) (draft-cisco-skip-02)
- [RFC 8784 - IKEv2 Post-Quantum Pre-Shared Keys](https://rfc-editor.org/rfc/rfc8784)