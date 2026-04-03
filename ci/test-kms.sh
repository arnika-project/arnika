#!/bin/bash

set -eu

# This version of the test script is designed to be run against a KMS instance, and will print the HTTP status code and response body for each test case. It is for HTTP only, no TLS support.

# It covers the following endpoints:
# - POST /status
# - GET /status
# - POST /enc_keys (with and without query parameters)
# - GET /enc_keys (with and without query parameters)
# - POST /dec_keys (with key_IDs in the body)
# - GET /dec_keys (with key_ID as a query parameter)

SAE="${SAE:-CONSA}"
KMS="${KMS:-http://127.0.0.1:8080/api/v1/keys/${SAE}}"

PASS=0
FAIL=0

printf 'Started at %s\n---\n' "$(date '+%Y-%m-%d %H:%M:%S')"

run_case() {
  local label="$1"
  local method="$2"
  local url="$3"
  local data="$4"
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
  if [[ "$code" -ge 200 && "$code" -lt 300 ]]; then ((PASS++)); else ((FAIL++)); fi
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

run_case '01: POST /status' 'POST' "$KMS/status" '{}'
run_case '02: GET /status' 'GET' "$KMS/status" ''
run_case '03: POST /enc_keys (empty body)' 'POST' "$KMS/enc_keys" '{}'
run_case '04: GET /enc_keys' 'GET' "$KMS/enc_keys" ''
run_case '05: POST /enc_keys?number=1&size=256' 'POST' "$KMS/enc_keys?number=1&size=256" '{}'
run_case '06: GET /enc_keys?number=1&size=256' 'GET' "$KMS/enc_keys?number=1&size=256" ''
run_case '07: GET /enc_keys?number=2&size=256' 'GET' "$KMS/enc_keys?number=2&size=256" ''
run_case '08: POST /enc_keys with {"number":1,"size":256}' 'POST' "$KMS/enc_keys" '{"number":1,"size":256}'
run_case '09: GET /enc_keys with {"number":1,"size":256}' 'GET' "$KMS/enc_keys" '{"number":1,"size":256}'

# Get a fresh key_ID for each dec_keys test
KEY_ID=$(fetch_key_id)
run_case "10: POST /dec_keys with {\"key_IDs\":[\"$KEY_ID\"]}" 'POST' "$KMS/dec_keys" '{"key_IDs":["'"$KEY_ID"'"]}'

KEY_ID=$(fetch_key_id)
run_case "11: GET /dec_keys?key_ID=$KEY_ID" 'GET' "$KMS/dec_keys?key_ID=$KEY_ID" ''

# Repeat dec_keys tests to verify repeatability with distinct keys
KEY_ID=$(fetch_key_id)
run_case "12: POST /dec_keys (repeat) with {\"key_IDs\":[\"$KEY_ID\"]}" 'POST' "$KMS/dec_keys" '{"key_IDs":["'"$KEY_ID"'"]}'

KEY_ID=$(fetch_key_id)
run_case "13: GET /dec_keys (repeat) ?key_ID=$KEY_ID" 'GET' "$KMS/dec_keys?key_ID=$KEY_ID" ''

printf 'Finished at %s — %d passed, %d failed\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]


