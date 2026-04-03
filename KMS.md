# QKD KMS Simulator

The KMS simulator (`tools/mock.go`) provides a lightweight ETSI GS QKD 014 v1.1.1 compliant key management endpoint for testing [Arnika](README.md). It is **not** a production KMS — it generates deterministic pseudo-keys for development, integration testing, and interoperability validation.

---

## Quick Start

```bash
# compile
go build -o build/kms ./tools

# run (default port 8080)
./build/kms

# run with debug logging
DEBUG=true ./build/kms
```

---

## ETSI GS QKD 014 v1.1.1 Compliance

### Endpoint & Method Matrix (Table 2)

| # | Method | URL | Access Method | Supported |
|---|--------|-----|---------------|-----------|
| 1 | Get status | `/api/v1/keys/{slave_SAE_ID}/status` | GET | **Yes** |
| 2 | Get key | `/api/v1/keys/{slave_SAE_ID}/enc_keys` | POST (or GET) | **Yes** |
| 3 | Get key with key IDs | `/api/v1/keys/{master_SAE_ID}/dec_keys` | POST (or GET) | **Yes** |

### Registered SAE Paths

| SAE ID | enc_keys | dec_keys | status |
|--------|----------|----------|--------|
| CONSA | `/api/v1/keys/CONSA/enc_keys` | `/api/v1/keys/CONSA/dec_keys` | `/api/v1/keys/CONSA/status` |
| CONSB | `/api/v1/keys/CONSB/enc_keys` | `/api/v1/keys/CONSB/dec_keys` | `/api/v1/keys/CONSB/status` |

---

### Status Response (Section 6.1, Table 9)

| Field | Type | Value | Compliant |
|-------|------|-------|-----------|
| `source_KME_ID` | string | SAE ID from path | Yes |
| `target_KME_ID` | string | Paired SAE ID | Yes |
| `master_SAE_ID` | string | SAE ID from path | Yes |
| `slave_SAE_ID` | string | Paired SAE ID | Yes |
| `key_size` | integer | 256 | Yes |
| `stored_key_count` | integer | Dummy (10–10000) | Yes |
| `max_key_count` | integer | Dummy (10–10000) | Yes |
| `max_key_per_request` | integer | 1 | Yes |
| `max_key_size` | integer | 256 | Yes |
| `min_key_size` | integer | 256 | Yes |
| `max_SAE_ID_count` | integer | 0 (no multicast) | Yes |
| `status_extension` | object | Omitted (optional) | Yes |

### Key Container Response (Section 6.3, Table 11)

| Field | Type | Present | Compliant |
|-------|------|---------|-----------|
| `keys` | array | Yes (always 1 element) | Yes |
| `key_ID` | string (UUID) | Yes | Yes |
| `key` | string (base64) | Yes | Yes |
| `key_ID_extension` | object | Omitted (optional) | Yes |
| `key_extension` | object | Omitted (optional) | Yes |
| `key_container_extension` | object | Omitted (optional) | Yes |

### Error Response (Section 6.5, Table 13)

| Field | Type | Present | Compliant |
|-------|------|---------|-----------|
| `message` | string | Yes | Yes |
| `details` | array | Omitted (optional) | Yes |

Content-Type for errors is `application/json`.

### Key Request Parameters (Section 6.2, Table 10)

| Parameter | Supported | Notes |
|-----------|-----------|-------|
| `number` | Yes | Only `1` accepted; other values return 400 |
| `size` | Yes | Only `256` accepted; other values return 400 |
| `additional_slave_SAE_IDs` | No | `max_SAE_ID_count=0` advertised in status |
| `extension_mandatory` | No | Not yet implemented |
| `extension_optional` | No | Not yet implemented |

### HTTP Status Codes

| Code | When |
|------|------|
| 200 | Successful key operation or status query |
| 400 | Bad request (invalid params, unsupported number/size, missing key_ID) |
| 404 | Key not found (dec_keys with unknown key_ID) |
| 405 | Method not allowed (e.g. POST on /status) |

---

## Known Simulator Limitations

| Feature | ETSI-014 Spec | Simulator Behavior |
|---------|---------------|--------------------|
| Multiple keys per request | Supported via `number` param | Only `number=1` supported |
| Variable key sizes | Supported via `size` param | Only `size=256` supported |
| Key multicast | Optional (`additional_slave_SAE_IDs`) | Not supported (`max_SAE_ID_count=0`) |
| Extension parameters | Optional (`extension_mandatory`/`extension_optional`) | Not supported |
| Persistent key storage | Implementation-defined | In-memory only; keys lost on restart |
| TLS / mTLS | Required by spec (HTTPS) | HTTP only; use reverse proxy for TLS offloading |
| `status_extension` | Optional | Not included in response |
| `key_ID_extension`, `key_extension`, `key_container_extension` | Optional | Not included in response |
| SAE authentication | Required by spec | Not implemented; any client can connect |

---

## Test Request Commands

All examples assume the simulator is running at `http://127.0.0.1:8080`.

### 1. Get Status

```bash
curl -sS http://127.0.0.1:8080/api/v1/keys/CONSA/status
```

Response (`200`):
```json
{
  "source_KME_ID": "CONSA",
  "target_KME_ID": "CONSB",
  "master_SAE_ID": "CONSA",
  "slave_SAE_ID": "CONSB",
  "key_size": 256,
  "stored_key_count": 6415,
  "max_key_count": 6415,
  "max_key_per_request": 1,
  "max_key_size": 256,
  "min_key_size": 256,
  "max_SAE_ID_count": 0
}
```

### 2. Get Status — Method Not Allowed

```bash
curl -sS -X POST http://127.0.0.1:8080/api/v1/keys/CONSA/status \
  -H 'Content-Type: application/json' -d '{}'
```

Response (`405`):
```json
{"message":"Method not allowed"}
```

### 3. Get Key — POST with JSON Body

```bash
curl -sS -X POST http://127.0.0.1:8080/api/v1/keys/CONSA/enc_keys \
  -H 'Content-Type: application/json' \
  -d '{"number":1,"size":256}'
```

Response (`200`):
```json
{
  "keys": [
    {
      "key_ID": "ffffffff-c1bf-4ac5-89f7-2f4239c2479d",
      "key": "1nE6t/U1tHzyuxNPUMbk+oMZNg1WROLfEJz7Fe0n/XI="
    }
  ]
}
```

### 4. Get Key — POST with Empty Body

```bash
curl -sS -X POST http://127.0.0.1:8080/api/v1/keys/CONSA/enc_keys \
  -H 'Content-Type: application/json' -d '{}'
```

Response (`200`): Same format as above (defaults to `number=1`, `size=256`).

### 5. Get Key — GET with Query Parameters

```bash
curl -sS 'http://127.0.0.1:8080/api/v1/keys/CONSA/enc_keys?number=1&size=256'
```

Response (`200`): Same key container format.

### 6. Get Key — GET with Defaults (No Parameters)

```bash
curl -sS http://127.0.0.1:8080/api/v1/keys/CONSA/enc_keys
```

Response (`200`): Same format (defaults apply).

### 7. Get Key — Unsupported Number

```bash
curl -sS 'http://127.0.0.1:8080/api/v1/keys/CONSA/enc_keys?number=2&size=256'
```

Response (`400`):
```json
{"message":"unsupported number: 2"}
```

### 8. Get Key with Key IDs — POST

```bash
# First, obtain a key_ID:
KEY_ID=$(curl -sS -X POST http://127.0.0.1:8080/api/v1/keys/CONSA/enc_keys \
  -H 'Content-Type: application/json' -d '{"number":1,"size":256}' \
  | sed -n 's/.*"key_ID":"\([^"]*\)".*/\1/p')

# Then retrieve it:
curl -sS -X POST http://127.0.0.1:8080/api/v1/keys/CONSA/dec_keys \
  -H 'Content-Type: application/json' \
  -d "{\"key_IDs\":[\"$KEY_ID\"]}"
```

Response (`200`):
```json
{
  "keys": [
    {
      "key_ID": "ffffffff-2f3e-48ac-a399-2e6ee3ab8002",
      "key": "WeJqBGEiLP9gbMmBltVvEG2cvWcWluPMUQqOs4xRPFM="
    }
  ]
}
```

### 9. Get Key with Key IDs — GET with Query Parameter

```bash
curl -sS "http://127.0.0.1:8080/api/v1/keys/CONSA/dec_keys?key_ID=$KEY_ID"
```

Response (`200`): Same key container format with matching key material.

### 10. Get Key with Key IDs — Key Not Found

```bash
curl -sS "http://127.0.0.1:8080/api/v1/keys/CONSA/dec_keys?key_ID=00000000-0000-0000-0000-000000000000"
```

Response (`404`):
```json
{"message":"key not found"}
```

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DEBUG` | `false` | Set to `true` to enable request/response debug logging |

When `DEBUG=true`, the simulator logs full request details (method, path, query, headers, body) and full response details (status, content type, body) under the `[DEBUG]` prefix.

---

## CI Test Script

A test script is available at `ci/test-kms.sh` that exercises all supported request patterns:

```bash
# Start the simulator
./build/kms &

# Run tests
bash ci/test-kms.sh

# Stop the simulator
kill %1
```

The script tests 13 cases covering GET/POST for enc_keys, dec_keys, and status, including expected error cases (POST on status → 405, number=2 → 400).

---

## References

- [ETSI GS QKD 014 V1.1.1 (2019-02)](https://www.etsi.org/deliver/etsi_gs/QKD/001_099/014/01.01.01_60/gs_qkd014v010101p.pdf) — Protocol and data format of REST-based key delivery API
- [Arnika README](README.md) — Main project documentation
- [Arnika SECURITY](SECURITY.md) — Security considerations and deployment checklist
