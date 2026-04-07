# QKD KMS Simulator

The KMS simulator (`tools/mock.go`) provides a lightweight ETSI GS QKD 014 v1.1.1 compliant key management endpoint for testing [Arnika](README.md). It is **not** a production KMS — it generates pseudo-random keys for development, integration testing, and interoperability validation.

---

## Quick Start

```bash
# compile
go build -o build/kms ./tools

# run (default *:8080)
./build/kms

# run on a specific address and port
LISTEN=192.168.3.151:8080 ./build/kms

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

Quick-reference curl examples. For authoritative test coverage see the [CI Test Script](#ci-test-script) section below.

All examples assume the simulator is running at `http://127.0.0.1:8080`. UUIDs, key material, and `stored_key_count` / `max_key_count` values will differ on each run.

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
| `LISTEN` | `:8080` | Listen address in `host:port` format (e.g. `192.168.3.151:8080`) |

When `DEBUG=true`, the simulator logs full request details (method, path, query, headers, body) and full response details (status, content type, body) under the `[DEBUG]` prefix.

---

## CI Test Script

A test script is available at `ci/test-kms.sh` that exercises all supported request patterns:

```bash
# Start the simulator
./build/kms &

# Run tests
bash ci/test-kms.sh

# Override target SAE or KMS URL
SAE=CONSB KMS=http://10.0.0.1:9090/api/v1/keys/CONSB bash ci/test-kms.sh

# Stop the simulator
kill %1
```

### Test Cases (ref: ETSI GS QKD 014 V1.1.1)

| # | Method | Endpoint | Description | Spec | Expect |
|---|--------|----------|-------------|------|--------|
| 01 | POST | /status | Reject POST on status endpoint (GET only) | §6.1 | 405 |
| 02 | GET | /status | Retrieve KMS status | §6.1 | 200 |
| 03 | POST | /enc\_keys | Request key with empty JSON body `{}`, defaults apply | §6.2 | 200 |
| 04 | GET | /enc\_keys | Request key with no parameters, defaults apply | §6.2 | 200 |
| 05 | POST | /enc\_keys?number=1&size=256 | Request key via query params on POST | §6.2 | 200 |
| 06 | GET | /enc\_keys?number=1&size=256 | Request key via query params on GET | §6.2 | 200 |
| 07 | GET | /enc\_keys?number=2&size=256 | Reject unsupported number=2 | §6.2 | 400 |
| 08 | POST | /enc\_keys | Request key with full JSON body `{"number":1,"size":256}` | §6.2 | 200 |
| 09 | GET | /enc\_keys | Request key with JSON body on GET `{"number":1,"size":256}` | §6.2 | 200 |
| 10 | POST | /enc\_keys | Request key with minimum JSON body `{"number":1}` | §6.2 | 200 |
| 11 | GET | /enc\_keys | Request key with minimum JSON body on GET `{"number":1}` | §6.2 | 200 |
| 12 | POST | /enc\_keys | Reject POST without JSON body (RFC 8259 validation) | — | 400 |
| 13 | GET | /enc\_keys | Request key with no body on GET, defaults apply | §6.2 | 200 |
| 14 | POST | /dec\_keys | Retrieve key by ID via POST `{"key_IDs":["..."]}` | §6.3 | 200 |
| 15 | GET | /dec\_keys?key\_ID=... | Retrieve key by ID via query param | §6.3 | 200 |
| 16 | POST | /dec\_keys | Verify repeatability with distinct key (POST) | §6.3 | 200 |
| 17 | GET | /dec\_keys?key\_ID=... | Verify repeatability with distinct key (GET) | §6.3 | 200 |

### Sample Output

> **Note:** UUIDs, key material, and status counts are pseudo-random and will differ on each run. The output below is a representative snapshot.

```shell
# Started at 2026-04-07 18:08:09
---
01: POST /status (expect 405)
[CMD] curl -sS -X POST 'http://127.0.0.1:8080/api/v1/keys/CONSA/status' -H "Content-Type: application/json" -d '{}'
HTTP 405
{"message":"Method not allowed"}
---
02: GET /status
[CMD] curl -sS -X GET 'http://127.0.0.1:8080/api/v1/keys/CONSA/status'
HTTP 200
{"source_KME_ID":"CONSA","target_KME_ID":"CONSB","master_SAE_ID":"CONSA","slave_SAE_ID":"CONSB","key_size":256,"stored_key_count":6407,"max_key_count":6407,"max_key_per_request":1,"max_key_size":256,"min_key_size":256,"max_SAE_ID_count":0}
---
03: POST /enc_keys (empty body)
[CMD] curl -sS -X POST 'http://127.0.0.1:8080/api/v1/keys/CONSA/enc_keys' -H "Content-Type: application/json" -d '{}'
HTTP 200
{"keys":[{"key_ID":"ffffffff-5482-47d9-8420-3d5b2890bf19","key":"SKiXMN5lW725N1/A+I590joXvt71sSwCQU49bkMXNQY="}]}
---
04: GET /enc_keys
[CMD] curl -sS -X GET 'http://127.0.0.1:8080/api/v1/keys/CONSA/enc_keys'
HTTP 200
{"keys":[{"key_ID":"ffffffff-cd3e-401d-8848-a285a2c0903b","key":"8bOYCzKR35e4qbNIOHLpSEVbaxqUhfej1QD9DagoCzc="}]}
---
05: POST /enc_keys?number=1&size=256
[CMD] curl -sS -X POST 'http://127.0.0.1:8080/api/v1/keys/CONSA/enc_keys?number=1&size=256' -H "Content-Type: application/json" -d '{}'
HTTP 200
{"keys":[{"key_ID":"ffffffff-4e0c-4c5b-93f5-2f02d26a4fc1","key":"vZwNTT97OrQRJPG8ga/AFB5QldxOmFqU2UEmMEBOhfo="}]}
---
06: GET /enc_keys?number=1&size=256
[CMD] curl -sS -X GET 'http://127.0.0.1:8080/api/v1/keys/CONSA/enc_keys?number=1&size=256'
HTTP 200
{"keys":[{"key_ID":"ffffffff-7930-479f-87cd-36a9c116816f","key":"CAqo3AVKqkLhMpRyrN+afeUgABZFyd38GvAEcZcZzHc="}]}
---
07: GET /enc_keys?number=2&size=256 (expect 400)
[CMD] curl -sS -X GET 'http://127.0.0.1:8080/api/v1/keys/CONSA/enc_keys?number=2&size=256'
HTTP 400
{"message":"unsupported number: 2"}
---
08: POST /enc_keys with {"number":1,"size":256}
[CMD] curl -sS -X POST 'http://127.0.0.1:8080/api/v1/keys/CONSA/enc_keys' -H "Content-Type: application/json" -d '{"number":1,"size":256}'
HTTP 200
{"keys":[{"key_ID":"ffffffff-267c-463b-92d8-4c6e4bd7e187","key":"FScNyVx2fq4aIr/0m9fM+o/MmH60gF0dy8J5VsYw+4Q="}]}
---
09: GET /enc_keys with {"number":1,"size":256}
[CMD] curl -sS -X GET 'http://127.0.0.1:8080/api/v1/keys/CONSA/enc_keys' -H "Content-Type: application/json" -d '{"number":1,"size":256}'
HTTP 200
{"keys":[{"key_ID":"ffffffff-6050-4f47-bbf8-64e222ca29f1","key":"faV7qs71qrmy+/5x9NmBhjAMhrsH1R1IviOQsnNqDBk="}]}
---
10: POST /enc_keys with {"number":1} (minimum body)
[CMD] curl -sS -X POST 'http://127.0.0.1:8080/api/v1/keys/CONSA/enc_keys' -H "Content-Type: application/json" -d '{"number":1}'
HTTP 200
{"keys":[{"key_ID":"ffffffff-419c-4414-9d15-3e05ac6d7fe7","key":"yEdEvJYo3355smB8jCYxMTQn1aenj+AxgouRHpEU7PU="}]}
---
11: GET /enc_keys with {"number":1} (minimum body)
[CMD] curl -sS -X GET 'http://127.0.0.1:8080/api/v1/keys/CONSA/enc_keys' -H "Content-Type: application/json" -d '{"number":1}'
HTTP 200
{"keys":[{"key_ID":"ffffffff-725c-40b9-90c5-33f8fef1cf85","key":"+FUtpp3/M0lTZ4j4W7gJP9h0IkEUQnWtQtSNtO6aE7A="}]}
---
12: POST /enc_keys (no body, expect 400)
[CMD] curl -sS -X POST 'http://127.0.0.1:8080/api/v1/keys/CONSA/enc_keys'
HTTP 400
{"message":"invalid JSON payload"}
---
13: GET /enc_keys (no body)
[CMD] curl -sS -X GET 'http://127.0.0.1:8080/api/v1/keys/CONSA/enc_keys'
HTTP 200
{"keys":[{"key_ID":"ffffffff-86d4-40eb-9939-51719f34599b","key":"NS2Jp4GWCaKjXBVbsx+DPmqUyvL7/VyTUixt/O8AkeI="}]}
---
14: POST /dec_keys with {"key_IDs":["ffffffff-ea76-4c10-84b8-503c06ad7bd4"]}
[CMD] curl -sS -X POST 'http://127.0.0.1:8080/api/v1/keys/CONSA/dec_keys' -H "Content-Type: application/json" -d '{"key_IDs":["ffffffff-ea76-4c10-84b8-503c06ad7bd4"]}'
HTTP 200
{"keys":[{"key_ID":"ffffffff-ea76-4c10-84b8-503c06ad7bd4","key":"VaqZteJROdCwX+LtaoeUtiQv9cJwvmREfqfG9zaiUO4="}]}
---
15: GET /dec_keys?key_ID=ffffffff-2e08-40b3-9030-f37883416439
[CMD] curl -sS -X GET 'http://127.0.0.1:8080/api/v1/keys/CONSA/dec_keys?key_ID=ffffffff-2e08-40b3-9030-f37883416439'
HTTP 200
{"keys":[{"key_ID":"ffffffff-2e08-40b3-9030-f37883416439","key":"KRZdOXJYZQujHWe5Pzq1/YldjoPYNMvgAtu7fakxqAU="}]}
---
16: POST /dec_keys (repeat) with {"key_IDs":["ffffffff-ee65-4568-a880-d68374767d15"]}
[CMD] curl -sS -X POST 'http://127.0.0.1:8080/api/v1/keys/CONSA/dec_keys' -H "Content-Type: application/json" -d '{"key_IDs":["ffffffff-ee65-4568-a880-d68374767d15"]}'
HTTP 200
{"keys":[{"key_ID":"ffffffff-ee65-4568-a880-d68374767d15","key":"1WbHe38TUPH7fyrzSBrJYWsqbHYwtmkSb16CHf7egyc="}]}
---
17: GET /dec_keys (repeat) ?key_ID=ffffffff-6a39-4b78-a728-fac1c2a129fa
[CMD] curl -sS -X GET 'http://127.0.0.1:8080/api/v1/keys/CONSA/dec_keys?key_ID=ffffffff-6a39-4b78-a728-fac1c2a129fa'
HTTP 200
{"keys":[{"key_ID":"ffffffff-6a39-4b78-a728-fac1c2a129fa","key":"lhxKeRF+XCJU0V4YWi09JIq9E8/+t0zdKahoFPshcGM="}]}
---
# Finished at 2026-04-07 18:08:09 — 17 passed, 0 failed
```

---

## References

- [ETSI GS QKD 014 V1.1.1 (2019-02)](https://www.etsi.org/deliver/etsi_gs/QKD/001_099/014/01.01.01_60/gs_qkd014v010101p.pdf) — Protocol and data format of REST-based key delivery API
- [Arnika README](README.md) — Main project documentation
- [Arnika SECURITY](SECURITY.md) — Security considerations and deployment checklist
