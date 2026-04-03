set -e
SAE=CONSA
BASE="http://127.0.0.1:8080/api/v1/keys/${SAE}"

run_case() {
  local label="$1"
  local method="$2"
  local url="$3"
  local data="$4"
  local tmp
  tmp=$(mktemp)
  local code
  printf '%s\n' "$label"
  if [[ -n "$data" ]]; then
    printf '[CMD] curl -sS -X %s '\''%s'\'' -H "Content-Type: application/json" -d '\''%s'\''\n' "$method" "$url" "$data"
    code=$(curl -sS -o "$tmp" -w "%{http_code}" -X "$method" "$url" -H 'Content-Type: application/json' -d "$data")
  else
    printf '[CMD] curl -sS -X %s '\''%s'\''\n' "$method" "$url"
    code=$(curl -sS -o "$tmp" -w "%{http_code}" -X "$method" "$url")
  fi
  local body
  body=$(cat "$tmp")
  rm -f "$tmp"
  printf '%s\n%s\n---\n' "HTTP $code" "$body"
}

run_case '01: POST /status' 'POST' "$BASE/status" '{}'
run_case '02: GET /status' 'GET' "$BASE/status" ''
run_case '03: POST /enc_keys (empty body)' 'POST' "$BASE/enc_keys" '{}'
run_case '04: GET /enc_keys' 'GET' "$BASE/enc_keys" ''
run_case '05: POST /enc_keys?number=1&size=256' 'POST' "$BASE/enc_keys?number=1&size=256" '{}'
run_case '06: GET /enc_keys?number=1&size=256' 'GET' "$BASE/enc_keys?number=1&size=256" ''
run_case '07: GET /enc_keys?number=2&size=256' 'GET' "$BASE/enc_keys?number=2&size=256" ''
run_case '08: POST /enc_keys with {"number":1,"size":256}' 'POST' "$BASE/enc_keys" '{"number":1,"size":256}'
run_case '09: GET /enc_keys with {"number":1,"size":256}' 'GET' "$BASE/enc_keys" '{"number":1,"size":256}'

# Get a fresh key_ID for each dec_keys test
enc_resp=$(curl -sS -X POST "$BASE/enc_keys" -H 'Content-Type: application/json' -d '{"number":1,"size":256}')
KEY_ID=$(printf '%s' "$enc_resp" | sed -n 's/.*"key_ID":"\([^"]*\)".*/\1/p')
run_case "10: POST /dec_keys with {\"key_IDs\":[\"$KEY_ID\"]}" 'POST' "$BASE/dec_keys" '{"key_IDs":["'"$KEY_ID"'"]}'

enc_resp=$(curl -sS -X POST "$BASE/enc_keys" -H 'Content-Type: application/json' -d '{"number":1,"size":256}')
KEY_ID=$(printf '%s' "$enc_resp" | sed -n 's/.*"key_ID":"\([^"]*\)".*/\1/p')
run_case "11: GET /dec_keys?key_ID=$KEY_ID" 'GET' "$BASE/dec_keys?key_ID=$KEY_ID" ''

enc_resp=$(curl -sS -X POST "$BASE/enc_keys" -H 'Content-Type: application/json' -d '{"number":1,"size":256}')
KEY_ID=$(printf '%s' "$enc_resp" | sed -n 's/.*"key_ID":"\([^"]*\)".*/\1/p')
run_case "12: POST /dec_keys with {\"key_IDs\":[\"$KEY_ID\"]}" 'POST' "$BASE/dec_keys" '{"key_IDs":["'"$KEY_ID"'"]}'

enc_resp=$(curl -sS -X POST "$BASE/enc_keys" -H 'Content-Type: application/json' -d '{"number":1,"size":256}')
KEY_ID=$(printf '%s' "$enc_resp" | sed -n 's/.*"key_ID":"\([^"]*\)".*/\1/p')
run_case "13: GET /dec_keys?key_ID=$KEY_ID" 'GET' "$BASE/dec_keys?key_ID=$KEY_ID" ''


