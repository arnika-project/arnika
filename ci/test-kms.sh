#!/bin/bash

set -eu

# This version of the test script is designed to be run against a KMS instance,
# and will print the HTTP status code and response body for each test case.
# It is for HTTP only, no TLS support.
#
# Test cases (ref: ETSI GS QKD 014 V1.1.1)
#
# 01  POST /status               — reject POST on status endpoint (ETSI 014 §5.2: GET only)               expect 405
# 02  GET  /status               — retrieve KMS status (ETSI 014 §5.2, §6.1)                              expect 200
# 03  POST /enc_keys {}          — request key with empty JSON body, defaults apply (ETSI 014 §6.2)       expect 200
# 04  GET  /enc_keys             — request key with no parameters, defaults apply (ETSI 014 §6.2)         expect 200
# 05  POST /enc_keys?n=1&s=256   — request key via query params on POST (ETSI 014 §6.2)                   expect 200
# 06  GET  /enc_keys?n=1&s=256   — request key via query params on GET (ETSI 014 §6.2)                    expect 200
# 07  GET  /enc_keys?n=2&s=256   — reject unsupported number=2 (ETSI 014 §6.2)                            expect 400
# 08  POST /enc_keys {n:1,s:256} — request key with full JSON body (ETSI 014 §6.2)                        expect 200
# 09  GET  /enc_keys {n:1,s:256} — request key with JSON body on GET (ETSI 014 §6.2)                      expect 200
# 10  POST /enc_keys {n:1}       — request key with minimum JSON body (ETSI 014 §6.2)                     expect 200
# 11  GET  /enc_keys {n:1}       — request key with minimum JSON body on GET (ETSI 014 §6.2)              expect 200
# 12  POST /enc_keys (no body)   — reject POST without JSON body (RFC 8259 validation)                    expect 400
# 13  GET  /enc_keys (no body)   — request key with no body on GET, defaults apply (ETSI 014 §6.2)        expect 200
# 14  GET  /dec_keys?key_ID=...  — retrieve key by ID via query param (ETSI 014 §5.4, §6.4)               expect 200
# 15  POST /dec_keys {key_IDs}   — retrieve key by ID via POST with Key IDs format (ETSI 014 §5.4, §6.4)  expect 200


SAE="${SAE:-CONSA}"
KMS="${KMS:-http://127.0.0.1:8080/api/v1/keys/${SAE}}"

PASS=0
FAIL=0

printf '# Started at %s\n---\n' "$(date '+%Y-%m-%d %H:%M:%S')"

run_case() {
  local label="$1"
  local method="$2"
  local url="$3"
  local data="$4"
  local expected_code="${5:-}"
  local response code body
  printf '%s\n' "$label"
  if [[ -n "$data" ]]; then
    printf '[CMD] curl -sS -X %s '\''%s'\'' -H "Content-Type: application/json" -d '\''%s'\''\n' "$method" "$url" "$data"
    response=$(curl -sS -w $'\n''%{http_code}' -X "$method" "$url" -H 'Content-Type: application/json' -d "$data")
  else
    printf '[CMD] curl -sS -X %s '\''%s'\''\n' "$method" "$url"
    response=$(curl -sS -w $'\n''%{http_code}' -X "$method" "$url")
  fi
  code="${response##*$'\n'}"
  body="${response%$'\n'"$code"}"
  local ok=false
  if [[ -n "$expected_code" ]]; then
    [[ "$code" -eq "$expected_code" ]] && ok=true
  else
    [[ "$code" -ge 200 && "$code" -lt 300 ]] && ok=true
  fi
  if $ok; then ((PASS++)); else ((FAIL++)); fi
  printf '%s\n%s\n---\n' "HTTP $code" "$body"
}

fetch_key_id() {
  local resp
  resp=$(curl -sS -X POST "$KMS/enc_keys" -H 'Content-Type: application/json' -d '{"number":1,"size":256}')
  local kid
  kid=$(printf '%s' "$resp" | sed -n 's/.*"key_ID":"\([^"]*\)".*/\1/p')
  [[ -n "$kid" ]] || { printf 'ERROR: failed to extract key_ID from enc_keys response\n' >&2; exit 1; }
  printf '%s' "$kid"
}

run_case '01: POST /status (expect 405)' 'POST' "$KMS/status" '{}' 405
run_case '02: GET /status' 'GET' "$KMS/status" ''
run_case '03: POST /enc_keys (empty body)' 'POST' "$KMS/enc_keys" '{}'
run_case '04: GET /enc_keys' 'GET' "$KMS/enc_keys" ''
run_case '05: POST /enc_keys?number=1&size=256' 'POST' "$KMS/enc_keys?number=1&size=256" '{}'
run_case '06: GET /enc_keys?number=1&size=256' 'GET' "$KMS/enc_keys?number=1&size=256" ''
run_case '07: GET /enc_keys?number=2&size=256 (expect 400)' 'GET' "$KMS/enc_keys?number=2&size=256" '' 400
run_case '08: POST /enc_keys with {"number":1,"size":256}' 'POST' "$KMS/enc_keys" '{"number":1,"size":256}'
run_case '09: GET /enc_keys with {"number":1,"size":256}' 'GET' "$KMS/enc_keys" '{"number":1,"size":256}'
run_case '10: POST /enc_keys with {"number":1} (minimum body)' 'POST' "$KMS/enc_keys" '{"number":1}'
run_case '11: GET /enc_keys with {"number":1} (minimum body)' 'GET' "$KMS/enc_keys" '{"number":1}'
run_case '12: POST /enc_keys (no body, expect 400)' 'POST' "$KMS/enc_keys" '' 400
run_case '13: GET /enc_keys (no body)' 'GET' "$KMS/enc_keys" ''

# Get a fresh key_ID for each dec_keys test
KEY_ID=$(fetch_key_id)
run_case "14: GET /dec_keys?key_ID=$KEY_ID" 'GET' "$KMS/dec_keys?key_ID=$KEY_ID" ''

KEY_ID=$(fetch_key_id)
run_case "15: POST /dec_keys with {\"key_IDs\":[{\"key_ID\":\"$KEY_ID\"}]}" 'POST' "$KMS/dec_keys" '{"key_IDs":[{"key_ID":"'"$KEY_ID"'"}]}'

printf '# Finished at %s — %d passed, %d failed\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]


