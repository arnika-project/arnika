#!/usr/bin/env bash
#
# Native macOS end-to-end test: two real WireGuard interfaces on loopback, the
# bundled KMS simulator, and two Arnika instances rotating the PSK on both ends.
#
# Needs sudo: wg-quick creates the interfaces and their control sockets are
# owned by root, so Arnika has to run as root to write the PSK - the same
# privilege it needs on Linux.
#
#   ./run.sh            bring up, watch five rotation cycles, tear down
#   ./run.sh --keep     leave the interfaces and logs in place afterwards
#   ./run.sh --quiet    do not stream the logs, only report the checks
#   VERBOSE=1 ./run.sh  also print the wg dumps at the end
#
# Arnika and the KMS simulator log to the console as they run, prefixed a1|,
# a2| and kms|. The simulator needs DEBUG=true for its request and response
# logging; Arnika's [DEBUG] lines are unconditional.
#
# See README.md for prerequisites.

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
WORK="$(mktemp -d /tmp/arnika-darwin.XXXXXX)"
KEEP=0
STREAM=1
for arg in "$@"; do
    case "$arg" in
        --keep)  KEEP=1 ;;
        --quiet) STREAM=0 ;;
        *) echo "unknown option: $arg"; exit 2 ;;
    esac
done

if [ -t 1 ]; then
    C_RESET=$'\033[0m'; C_DIM=$'\033[2m'; C_BOLD=$'\033[1m'
    C_A1=$'\033[36m'; C_A2=$'\033[35m'
else
    C_RESET=""; C_DIM=""; C_BOLD=""; C_A1=""; C_A2=""
fi

# stream prefixes each line of a process's output so three interleaved logs
# stay readable. fflush keeps it live rather than block-buffered.
stream() {
    if [ "$STREAM" = "1" ]; then
        awk -v p="$1" '{print p $0; fflush()}'
    else
        cat > /dev/null
    fi
}

# Peer public keys, taken from the templates so the two never drift apart.
PUB1="$(awk -F' = ' '/^PublicKey/ {print $2}' "$HERE/qcicat1.conf")"
PUB2="$(awk -F' = ' '/^PublicKey/ {print $2}' "$HERE/qcicat2.conf")"

FAILURES=0
step() { printf '\n%s==> %s%s\n' "$C_BOLD" "$*" "$C_RESET"; }
pass() { printf '%s    PASS  %s%s\n' "$C_BOLD" "$*" "$C_RESET"; }
fail() { printf '%s    FAIL  %s%s\n' "$C_BOLD" "$*" "$C_RESET"; FAILURES=$((FAILURES + 1)); }
info() { printf '          %s\n' "$*"; }

# iface maps a profile name to the interface wg-quick actually created. On
# darwin that is a utun device, and wg-quick records it in a .name file.
iface() { sudo cat "/var/run/wireguard/$1.name"; }

# psk_of reads the preshared key installed on an interface.
psk_of() { sudo wg show "$1" preshared-keys | awk '{print $2; exit}'; }

# digest identifies a key without printing it, so a log or a screenshot of a
# test run never carries key material.
digest() { printf '%s' "$1" | shasum -a 256 | cut -c1-12; }

teardown() {
    [ "$KEEP" = "1" ] && { printf '\nkept: interfaces up, logs in %s\n' "$WORK"; return 0; }
    sudo pkill -f "$WORK/arnika" 2>/dev/null || true
    pkill -f "$WORK/kms" 2>/dev/null || true
    sudo wg-quick down "$HERE/qcicat1.conf" > /dev/null 2>&1 || true
    sudo wg-quick down "$HERE/qcicat2.conf" > /dev/null 2>&1 || true
    rm -rf "$WORK"
}
trap teardown EXIT

step "prerequisites"
for tool in wg wg-quick wireguard-go go; do
    command -v "$tool" > /dev/null || { echo "missing: $tool - see README.md"; exit 1; }
done
pass "wg, wg-quick, wireguard-go and go are present"
sudo -v || { echo "sudo is required"; exit 1; }

step "building arnika and the KMS simulator"
( cd "$REPO" && GOEXPERIMENT=runtimesecret CGO_ENABLED=0 go build -o "$WORK/arnika" . )
( cd "$REPO" && CGO_ENABLED=0 go build -o "$WORK/kms" ./tools )
pass "built into $WORK"

step "bringing up the two WireGuard interfaces"
sudo wg-quick down "$HERE/qcicat1.conf" > /dev/null 2>&1 || true
sudo wg-quick down "$HERE/qcicat2.conf" > /dev/null 2>&1 || true
sudo wg-quick up "$HERE/qcicat1.conf"
sudo wg-quick up "$HERE/qcicat2.conf"
DEV1="$(iface qcicat1)"
DEV2="$(iface qcicat2)"
info "qcicat1 -> $DEV1"
info "qcicat2 -> $DEV2"
pass "both interfaces are up"

step "starting the KMS simulator"
# The simulator only logs requests and responses when DEBUG is set; Arnika's
# own [DEBUG] lines are unconditional, so it needs no flag.
( LISTEN=127.0.0.1:8080 DEBUG=true "$WORK/kms" 2>&1 \
    | tee "$WORK/kms.log" | stream "${C_DIM}kms|${C_RESET} " ) &
sleep 1
grep -q 'QKD KMS Simulator' "$WORK/kms.log" || { cat "$WORK/kms.log"; exit 1; }
grep -q 'debug logging enabled=true' "$WORK/kms.log" &&
    pass "listening on 127.0.0.1:8080 with debug logging" ||
    fail "the simulator did not enable debug logging"

step "starting Arnika on both ends"
PSK="$(openssl rand -base64 32)"
# ARNIKA_ID values must differ in parity: only the lowest bit takes part in
# PRIMARY/BACKUP election, so two odd or two even IDs stall the exchange.
sudo env \
    LISTEN_ADDRESS=127.0.0.1:9998 SERVER_ADDRESS=127.0.0.1:9999 \
    ARNIKA_ID=9998 ARNIKA_PSK="$PSK" INTERVAL=5s DEBUG=true \
    KMS_URL="http://127.0.0.1:8080/api/v1/keys/CONSA" \
    WIREGUARD_INTERFACE="$DEV1" WIREGUARD_PEER_PUBLIC_KEY="$PUB1" \
    "$WORK/arnika" 2>&1 | tee "$WORK/arnika1.log" | stream "${C_A1}a1|${C_RESET} " &
sudo env \
    LISTEN_ADDRESS=127.0.0.1:9999 SERVER_ADDRESS=127.0.0.1:9998 \
    ARNIKA_ID=9999 ARNIKA_PSK="$PSK" INTERVAL=5s DEBUG=true \
    KMS_URL="http://127.0.0.1:8080/api/v1/keys/CONSB" \
    WIREGUARD_INTERFACE="$DEV2" WIREGUARD_PEER_PUBLIC_KEY="$PUB2" \
    "$WORK/arnika" 2>&1 | tee "$WORK/arnika2.log" | stream "${C_A2}a2|${C_RESET} " &
info "logs in $WORK"

step "waiting for both ends to install a PSK"
for _ in $(seq 1 40); do
    if grep -q 'PSK configured on WireGuard interface' "$WORK/arnika1.log" 2>/dev/null &&
       grep -q 'PSK configured on WireGuard interface' "$WORK/arnika2.log" 2>/dev/null; then
        break
    fi
    sleep 1
done
if grep -q 'PSK configured on WireGuard interface' "$WORK/arnika1.log" &&
   grep -q 'PSK configured on WireGuard interface' "$WORK/arnika2.log"; then
    pass "both ends reported a successful write"
else
    fail "at least one end never wrote a PSK"
    tail -n 15 "$WORK/arnika1.log" "$WORK/arnika2.log"
fi

step "both interfaces hold the same PSK"
PSK1="$(psk_of "$DEV1")"
PSK2="$(psk_of "$DEV2")"
if [ -z "$PSK1" ] || [ "$PSK1" = "(none)" ]; then
    fail "$DEV1 has no preshared key"
elif [ "$PSK1" = "$PSK2" ]; then
    pass "identical on both ends (sha256:$(digest "$PSK1"))"
else
    fail "the two ends installed different keys - the tunnel would show a dead handshake"
fi

step "the tunnel actually carries traffic"
if ping -c 3 -t 5 100.1.2.2 > /dev/null 2>&1; then
    pass "100.1.1.1 -> 100.1.2.2 over the tunnel"
else
    fail "no ping over the tunnel"
fi
HS="$(sudo wg show "$DEV1" latest-handshakes | awk '{print $2; exit}')"
if [ -n "${HS:-}" ] && [ "$HS" -gt 0 ] 2>/dev/null; then
    pass "a handshake completed with the PSK in place"
else
    fail "no handshake on $DEV1 (latest-handshakes: ${HS:-empty})"
fi
sudo wg show "$DEV1" transfer | awk '{printf "          transfer: rx %s tx %s bytes\n", $2, $3}'

step "five rotation cycles"
# One rotation proves the mechanism; five prove it keeps working. Each cycle
# must produce a new key on one end and the identical key on the other - a
# single divergence is what a dead handshake looks like in production.
CYCLES=5
PREV="$PSK1"
for cycle in $(seq 1 "$CYCLES"); do
    CUR=""
    for _ in $(seq 1 30); do
        CUR="$(psk_of "$DEV1")"
        [ -n "$CUR" ] && [ "$CUR" != "(none)" ] && [ "$CUR" != "$PREV" ] && break
        sleep 1
    done
    if [ -z "$CUR" ] || [ "$CUR" = "$PREV" ]; then
        fail "cycle $cycle/$CYCLES: the PSK did not change within 30s"
        break
    fi
    OTHER="$(psk_of "$DEV2")"
    if [ "$CUR" = "$OTHER" ]; then
        pass "cycle $cycle/$CYCLES: rotated, both ends match (sha256:$(digest "$CUR"))"
    else
        fail "cycle $cycle/$CYCLES: the ends diverged - $DEV1 sha256:$(digest "$CUR"), $DEV2 sha256:$(digest "$OTHER")"
    fi
    PREV="$CUR"
done

step "the tunnel still works after rotating"
if ping -c 3 -t 5 100.1.2.2 > /dev/null 2>&1; then
    pass "still passing traffic after $CYCLES rotations"
else
    fail "the tunnel stopped passing traffic"
fi

step "debug output"
info "logs: $WORK"
for pair in "arnika1:$WORK/arnika1.log" "arnika2:$WORK/arnika2.log"; do
    name="${pair%%:*}"; log="${pair##*:}"
    rounds="$( { grep -c 'agreed a fresh PQC key' "$log" || true; } | head -1)"
    writes="$( { grep -c 'PSK configured on WireGuard interface' "$log" || true; } | head -1)"
    dbg="$( { grep -c '\[DEBUG\]' "$log" || true; } | head -1)"
    warn="$( { grep -c '\[WARNING\]\|\[ERROR\]' "$log" || true; } | head -1)"
    info "$name: $rounds PQC rounds, $writes PSK writes, $dbg debug lines, $warn warnings/errors"
done
info "kms: $( { grep -c '\[REQ\]' "$WORK/kms.log" || true; } | head -1) requests logged"
if [ "$FAILURES" != "0" ] || [ "${VERBOSE:-0}" = "1" ]; then
    if [ "$STREAM" != "1" ]; then
        # Not streamed, so the logs have not been seen yet.
        printf '\n--- arnika1 (last 25) ---\n'; tail -n 25 "$WORK/arnika1.log"
        printf '\n--- arnika2 (last 25) ---\n'; tail -n 25 "$WORK/arnika2.log"
    fi
    printf '\n--- wg dump ---\n'; sudo wg show "$DEV1" dump; sudo wg show "$DEV2" dump
fi

printf '\n'
[ "$FAILURES" = "0" ] && echo "all checks passed" || echo "$FAILURES check(s) failed"
exit "$FAILURES"
