#!/usr/bin/env bash
#
# Native macOS end-to-end test: two real WireGuard interfaces on loopback, the
# bundled KMS simulator, and two Arnika instances rotating the PSK on both ends.
#
# Each mode is put through its rotation cycles and then four deliberate
# failures - the KMS frozen, the KMS not running at all, PQC taken away, the PSK
# desynced behind Arnika's back - each followed by a recovery. WireGuard itself is pre-tested first, and
# the run stops there if that fails. README.md explains why the tunnel check
# looks the way it does: both ends are on one host, so a bare ping to the peer
# address proves nothing.
#
# Needs sudo: wg-quick creates the interfaces and their control sockets are
# owned by root, so Arnika has to run as root to write the PSK - the same
# privilege it needs on Linux.
#
#   ./run.sh            all modes
#   ./run.sh --keep     leave the interfaces and logs in place afterwards
#   ./run.sh --quiet    do not print the Arnika and KMS log lines
#   ./run.sh --clean    only clear leftovers from earlier runs, then stop
#   ./run.sh --list     print the numbered test list and stop
#
# Every check has a fixed number, <section>.<n>, and the run prints it beside
# each verdict; the summary lists every number with its result. The numbers come
# from the registry below, not from execution order, so a check that does not
# run is reported SKIP under its own number and the ones after it do not shift.
#
# Every run starts by clearing what an earlier one left behind, so a stranded
# process cannot write a PSK underneath the run that follows it.
#
# The KMS simulator runs with DEBUG=true so its requests and responses are
# logged. Arnika's [DEBUG] lines are unconditional. QKD is taken away twice per
# mode: once by freezing the simulator (FREEZE, see KMS.md), which keeps the
# requests Arnika makes into the failure in the log, and once by stopping it, so
# that no request reaches a KMS at all.
#
# See README.md for prerequisites.

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
WORK="$(mktemp -d /tmp/arnika-darwin.XXXXXX)"
CYCLES=3
MODES="QkdAndPqcRequired AtLeastQkdRequired AtLeastPqcRequired"

KEEP=0
STREAM=1
CLEAN_ONLY=0
LIST_ONLY=0
for arg in "$@"; do
    case "$arg" in
        --keep)  KEEP=1 ;;
        --quiet) STREAM=0 ;;
        --clean) CLEAN_ONLY=1 ;;
        --list)  LIST_ONLY=1 ;;
        *) echo "unknown option: $arg"; exit 2 ;;
    esac
done

# Patterns for pkill. The bracket keeps the pattern from matching the pkill
# command line itself: sudo's argv carries the pattern verbatim, so without it
# pkill signals the sudo that is running it.
# Anchored, so a log path like .../kms.log or the tee writing it never matches.
PAT_PEERS="$WORK/[a]rnika\$"
PAT_KMS="$WORK/[k]ms\$"
PAT_STALE='/tmp/arnika-darwin[.][^/]*/([a]rnika|[k]ms)$'

if [ -t 1 ]; then
    C_RESET=$'\033[0m'; C_DIM=$'\033[2m'; C_BOLD=$'\033[1m'
    C_A1=$'\033[36m'; C_A2=$'\033[35m'
else
    C_RESET=""; C_DIM=""; C_BOLD=""; C_A1=""; C_A2=""
fi

FAILURES=0
HARNESS_ERRORS=0

# ----------------------------------------------------- the numbered test list
#
# Every check in the run is declared here, in order, and its number is its
# position: section 1's third entry is test 1.3. Nothing else assigns a number.
#
# It is a declared list rather than a counter incremented as checks run because
# checks do get skipped - a failed pre-test stops the run, a mode that never
# installs a PSK abandons its remaining checks, a failed rotation cycle breaks
# out of the loop. A counter would renumber everything below the gap, which is
# exactly when a stable number is worth having. Declared, a skipped check is
# reported SKIP under its own number and its neighbours keep theirs.
#
# Sections 1 and 2 run once. Sections 3 and up are one per MODE and share one
# list, so 3.9 and 4.9 are the same test under two different modes.
#
# Each line is id|description. The id is what a check cites; the description is
# what the summary prints for a check that never ran. A description opening with
# [intentional] marks a check of a deliberately broken state - it passes
# *because* something is broken - and is what the summary counts under that
# heading, so the label lives in one place instead of being set as checks run.
#
# ./run.sh --list prints the whole list.

list_setup() {
    cat <<'EOF'
tools|wg, wg-quick, wireguard-go and go are present
sudo|sudo is available
leftover-procs|no arnika or KMS process is left running from an earlier run
leftover-qcicat1|qcicat1 is not left up from an earlier run
leftover-qcicat2|qcicat2 is not left up from an earlier run
build|arnika and the KMS simulator build
ifaces|both WireGuard interfaces come up
kms|the KMS simulator listens on 127.0.0.1:8080 with debug logging
EOF
}

list_pretest() {
    cat <<'EOF'
wg-answers|both interfaces answer wg
hs-nopsk|the peers handshake with no preshared key
payload-nopsk|payload crosses the tunnel and decrypts at the far end
hs-samekey|a matching preshared key on both ends still handshakes
payload-samekey|payload still crosses with that key installed
hs-mismatch|[intentional] a mismatched preshared key must break the handshake
nodecrypt-mismatch|[intentional] nothing may decrypt at the far end while the keys differ
hs-cleared|the tunnel comes back once the keys are cleared for Arnika
EOF
}

# One MODE's checks. The rotation cycles are generated, so CYCLES stays the one
# place the count is set and the numbers below it move with it.
list_mode() {
    local c
    cat <<'EOF'
psk-written|both ends report a successful PSK write
psk-identical|both interfaces hold the same preshared key
tunnel-initial|traffic traverses the tunnel on the first installed key
EOF
    for c in $(seq 1 "$CYCLES"); do
        printf 'rotate-%s|rotation cycle %s/%s: the PSK changed and both ends match\n' \
            "$c" "$c" "$CYCLES"
    done
    cat <<EOF
tunnel-rotated|traffic still traverses the tunnel after $CYCLES rotations
qkd-freeze|[intentional] the KMS restarts with both SAE frozen
qkd-state|[intentional] no QKD key: the ends diverge or keep rotating, per the mode
qkd-logline|[intentional] no QKD key: peer a logs its own decision
qkd-recovery|QKD back: both ends return to one fresh key
kmsdown-state|[intentional] KMS not running: the ends diverge or keep rotating, per the mode
kmsdown-logline|[intentional] KMS not running: peer a logs its own decision
kmsdown-noreq|[intentional] KMS not running: nothing was listening and no request reached one
kmsdown-recovery|KMS back: both ends return to one fresh key
pqc-state|[intentional] no PQC key: the ends diverge or keep rotating, per the mode
pqc-logline|[intentional] no PQC key: peer a logs its own decision
pqc-recovery|PQC back: both ends return to one fresh key
desync-no-hs|[intentional] desync: the handshake must fail while the keys differ
desync-nodecrypt|[intentional] desync: nothing may decrypt at the far end
desync-resync|desync: the peers resync onto one key
desync-hs|desync: the tunnel handshakes on the resynced key
desync-tunnel|desync: traffic traverses the tunnel again
EOF
}

# SEC_LIST and SEC_TITLE are indexed by section number - plain arrays, since
# macOS ships bash 3.2 and has no associative ones.
SEC=1
SEC_MAX=2
SEC_TITLE[1]="setup"
SEC_TITLE[2]="pre-test: WireGuard alone, no Arnika"
SEC_LIST[1]="$(list_setup)"
SEC_LIST[2]="$(list_pretest)"
for mode in $MODES; do
    SEC_MAX=$((SEC_MAX + 1))
    SEC_TITLE[$SEC_MAX]="MODE=$mode"
    SEC_LIST[$SEC_MAX]="$(list_mode)"
done
# Which section a mode's checks belong to, so run_mode can select it by name.
sec_of_mode() {
    local i
    for i in $(seq 3 "$SEC_MAX"); do
        [ "${SEC_TITLE[$i]}" = "MODE=$1" ] && { printf '%s' "$i"; return 0; }
    done
    printf '3'
}

print_list() {
    local sec num id desc
    for sec in $(seq 1 "$SEC_MAX"); do
        printf '\n%s%s  %s%s\n' "$C_BOLD" "$sec" "${SEC_TITLE[$sec]}" "$C_RESET"
        num=0
        while IFS='|' read -r id desc; do
            [ -n "$id" ] || continue
            num=$((num + 1))
            printf '  %6s  %s\n' "$sec.$num" "$desc"
        done <<< "${SEC_LIST[$sec]}"
    done
    printf '\n'
}

# test_number maps a cited id to its number within the current section. An id
# the current section does not declare - a typo, or a check citing an id from
# another section - is a bug in the script rather than a test result, so it is
# loud: ?.? in the output, and check counts it as a harness error. The counting
# has to happen in check: this runs in $(...) and a subshell cannot increment
# its caller's variable.
test_number() {
    local n
    n="$(printf '%s\n' "${SEC_LIST[$SEC]}" | grep -n "^$1|" | head -1 | cut -d: -f1)"
    if [ -z "$n" ]; then
        printf '?.?'
        return 0
    fi
    printf '%s.%s' "$SEC" "$n"
}

# LAST_WAS_LOG remembers whether the last thing on the console came from a peer
# log or from the run itself. gap puts a blank line between the two whenever it
# changes, so a block of log lines can never be read as part of a result.
LAST_WAS_LOG=0
gap() {
    if [ "$LAST_WAS_LOG" = "1" ]; then printf '\n'; fi
    LAST_WAS_LOG=0
}
# step and section open with a blank line of their own; everything else asks gap
# for the break.
step()       { LAST_WAS_LOG=0; printf '\n%s==> %s%s\n' "$C_BOLD" "$*" "$C_RESET"; }
step_fault() { LAST_WAS_LOG=0; printf '\n%s==> %s%s%s\n' "$C_BOLD" "$*" " [intentional]" "$C_RESET"; }
banner() { LAST_WAS_LOG=0; printf '\n%s─── %s %s%s\n' "$C_BOLD" "$*" "──────────────────────────" "$C_RESET"; }
# section opens a numbered section and makes it the one check ids resolve in.
section() { SEC="$1"; banner "$1  ${SEC_TITLE[$1]}"; }

# check records one numbered result. $1 is the id from the list above, $2 the
# verdict, $3 what was actually observed.
check() {
    local num
    num="$(test_number "$1")"
    if [ "$num" = "?.?" ]; then HARNESS_ERRORS=$((HARNESS_ERRORS + 1)); fi
    logs; gap
    printf '%s    [%5s] %-4s %s%s\n' "$C_BOLD" "$num" "$2" "$3" "$C_RESET"
    printf '%s\t%s\t%s\t%s\n' "$num" "$2" "$1" "$3" >> "$WORK/tally"
    if [ "$2" = "FAIL" ]; then FAILURES=$((FAILURES + 1)); fi
    return 0
}
pass() { check "$1" PASS "$2"; }
fail() { check "$1" FAIL "$2"; }
# abort is for the harness itself failing - the KMS not coming back up, say.
# It is not a test and has no number, so it is counted separately and never
# renumbers anything.
abort() {
    logs; gap
    printf '%s    [ !! ] HARNESS  %s%s\n' "$C_BOLD" "$*" "$C_RESET"
    HARNESS_ERRORS=$((HARNESS_ERRORS + 1))
    return 0
}
info()  { gap; printf '          %s\n' "$*"; }
# out indents a command's own output so it stays readable inside a step. No gap
# here: out runs in a pipeline, so its own LAST_WAS_LOG=0 would be lost with the
# subshell, and every caller prints an info or a verdict line first anyway.
out()   { sed 's/^/          /'; }
# sep divides one cycle from the next, so a cycle's log lines, its result and
# the cycle after it cannot be read as one another.
sep()   { gap; printf '%s  ─── %s ─────────────────────────────────%s\n' "$C_DIM" "$*" "$C_RESET"; }
# rule closes off the run, so the verdict is not lost in the scrollback.
rule()  { gap; printf '%s%s%s\n' "$C_BOLD" "══════════════════════════════════════════════════════════════════════" "$C_RESET"; }

# summary walks the whole numbered list and prints every test with its result:
# the message actually observed for one that ran, its declared description for
# one that did not. Printed at the end of a run, and by the pre-test gate when
# it stops the run early - which is when the SKIP lines say the most.
summary() {
    local sec num id desc rec verdict msg
    local total=0 np=0 nf=0 ns=0 ni=0 nif=0
    local failed="" skipped=0
    banner "summary"
    for sec in $(seq 1 "$SEC_MAX"); do
        printf '\n  %s%s  %s%s\n' "$C_BOLD" "$sec" "${SEC_TITLE[$sec]}" "$C_RESET"
        num=0
        while IFS='|' read -r id desc; do
            [ -n "$id" ] || continue
            num=$((num + 1))
            total=$((total + 1))
            # $1 "" == n "" forces a string comparison. Bare $1 == n makes awk
            # compare two numeric-looking fields as numbers, and 3.10 == 3.1 is
            # then true - test 3.10 reported test 3.1's result.
            rec="$(awk -F'\t' -v n="$sec.$num" '$1 "" == n "" {print; exit}' "$WORK/tally")"
            if [ -n "$rec" ]; then
                verdict="$(printf '%s' "$rec" | cut -f2)"
                msg="$(printf '%s' "$rec" | cut -f4)"
            else
                verdict="SKIP"
                msg="$desc"
            fi
            case "$desc" in "[intentional]"*) ni=$((ni + 1)) ;; esac
            case "$verdict" in
                PASS) np=$((np + 1)) ;;
                FAIL)
                    nf=$((nf + 1))
                    case "$desc" in "[intentional]"*) nif=$((nif + 1)) ;; esac
                    failed="$failed  [$sec.$num] ${SEC_TITLE[$sec]}: $msg"$'\n' ;;
                *)    ns=$((ns + 1)) ;;
            esac
            printf '    %s%6s%s  %-4s  %s\n' "$C_DIM" "$sec.$num" "$C_RESET" "$verdict" "$msg"
        done <<< "${SEC_LIST[$sec]}"
    done
    printf '\n  %s\n' "──────────────────────────────────────────────────────────────────"
    printf '  %d tests: %d passed, %d failed, %d skipped   (%d of them intentional)\n' \
        "$total" "$np" "$nf" "$ns" "$ni"
    [ "$HARNESS_ERRORS" = "0" ] || printf '  %d harness error(s) - see [ !! ] in the run output\n' "$HARNESS_ERRORS"
    if [ -n "$failed" ]; then
        printf '\n  failed:\n'
        printf '%s' "$failed"
    fi
    if [ "$nif" != "0" ]; then
        printf '\n  %d of the failures is a check of a deliberately broken state:\n' "$nif"
        printf '  it failed because the break went undetected, or did not happen.\n'
    fi
}

# The peers and the simulator do not write to the console: three processes
# writing at once interleave mid-line and bleed into the results. Their output
# is teed to files, and logs() prints whatever is new - merged in timestamp
# order, prefixed by peer - at the points where the run controls the console.
# pass and fail call it before printing a verdict, and wait_for calls it once a
# second, so output stays near-live without ever landing inside a result.
LOG_A=""
LOG_B=""
LOG_KMS=""
MARK_A=0
MARK_B=0
MARK_KMS=0

# flush_one appends log $1's lines after line $2 to file $4, prefixed with $3,
# and prints the line number it stopped at for the caller to remember.
#
# The count is taken first and the range bounded by it, rather than tailing to
# the end of the file and counting afterwards: the peers are still writing, and
# a line landing between a read-to-EOF and the count would be recorded as shown
# without ever being shown. Anything appended after the count simply waits for
# the next flush. wc counts newlines, so a half-written line is not counted.
flush_one() {
    local n
    [ -n "$1" ] && [ -f "$1" ] || { printf '%s' "$2"; return 0; }
    n="$(wc -l < "$1" | tr -d ' ')"
    if [ "$n" -gt "$2" ]; then
        sed -n "$(($2 + 1)),${n}p" "$1" | awk -v p="$3" '{print p " " $0}' >> "$4"
    fi
    printf '%s' "$n"
}

logs() {
    [ "$STREAM" = "1" ] || return 0
    local merged="$WORK/.merged"
    : > "$merged"
    MARK_A="$(flush_one "$LOG_A" "$MARK_A" "${C_A1}a1|${C_RESET}" "$merged")"
    MARK_B="$(flush_one "$LOG_B" "$MARK_B" "${C_A2}a2|${C_RESET}" "$merged")"
    MARK_KMS="$(flush_one "$LOG_KMS" "$MARK_KMS" "${C_DIM}kms|${C_RESET}" "$merged")"
    if [ -s "$merged" ]; then
        # A gutter of its own, so a block of log lines is never mistaken for
        # the indented output of a check. Field 1 is the peer prefix, 2 and 3
        # the date and time every line starts with.
        #
        # -s because sort falls back to comparing whole lines when the keys tie,
        # and lines that share a timestamp do tie: that reordered same-instant
        # blocks alphabetically, which is why a KMS startup banner appeared
        # *after* the requests it precedes. Stable, each peer's own lines keep
        # the order they were written in.
        if [ "$LAST_WAS_LOG" = "0" ]; then printf '\n'; fi
        sort -s -k2,3 "$merged" | sed "s/^/    ${C_DIM}│${C_RESET} /"
        LAST_WAS_LOG=1
    fi
    return 0
}

# iface maps a profile name to the interface wg-quick actually created. On
# darwin that is a utun device, and wg-quick records it in a .name file.
iface()  { sudo cat "/var/run/wireguard/$1.name"; }
psk_of() { sudo wg show "$1" preshared-keys | awk '{print $2; exit}'; }
wrote_psk() { grep -q 'PSK configured on WireGuard interface' "$1" 2> /dev/null; }
# keytail identifies a key by its last 9 base64 characters. Enough to tell two
# keys apart at a glance, and to match against a line in a log. These are local
# test keys from a mock KMS - see the note in README.md.
keytail() {
    case "$1" in
        "") printf '(unset)' ;;
        "(none)") printf '(none)' ;;
        # ${x: -9} yields nothing at all when x is shorter than 9.
        *) if [ "${#1}" -le 9 ]; then printf '%s' "$1"; else printf '…%s' "${1: -9}"; fi ;;
    esac
}

# A device is the handle everything passes around; dev_id and pub_of map it back
# to the peer that owns it, so an interface is paired with its peer's public key
# in one place. tag prints a device the way arnika names itself, dev[ARNIKA_ID],
# to line a message up against that peer's own log prefix.
dev_id() {
    case "$1" in
        "$DEV1") printf '%s' "$ID1" ;;
        "$DEV2") printf '%s' "$ID2" ;;
        *) printf '?' ;;
    esac
}
pub_of() {
    case "$1" in
        "$DEV1") printf '%s' "$PUB1" ;;
        "$DEV2") printf '%s' "$PUB2" ;;
    esac
}
tag() { printf '%s[%s]' "$1" "$(dev_id "$1")"; }

stop_peers() {
    sudo pkill -f "$PAT_PEERS" 2> /dev/null || true
    sleep 1
}

# clean_leftovers clears anything an earlier run left behind: its arnika and
# KMS processes, and the two tunnels. Runs at the start of every run, and on
# its own with --clean.
clean_leftovers() {
    local left dirs name
    step "leftovers from earlier runs"

    left="$(pgrep -fl "$PAT_STALE" 2> /dev/null || true)"
    if [ -n "$left" ]; then
        printf '%s\n' "$left" | out
        # SIGCONT first in case one was left stopped: arnika handles SIGTERM
        # itself (udpserver.go), so a stopped one would sit on the signal.
        sudo pkill -CONT -f "$PAT_STALE" 2> /dev/null || true
        sudo pkill -f "$PAT_STALE" 2> /dev/null || true
        sleep 1
        sudo pkill -KILL -f "$PAT_STALE" 2> /dev/null || true
        pass leftover-procs "killed the processes above"
    else
        pass leftover-procs "no arnika or KMS process left running"
    fi

    for name in qcicat1 qcicat2; do
        if sudo wg-quick down "$HERE/$name.conf" > /dev/null 2>&1; then
            pass "leftover-$name" "$name was still up - taken down"
        else
            pass "leftover-$name" "$name was not up"
        fi
    done

    # /tmp/ with the slash: /tmp is a symlink and find will not descend it.
    dirs="$(find /tmp/ -maxdepth 1 -name 'arnika-darwin.*' -type d ! -path "$WORK" 2> /dev/null | wc -l | tr -d ' ')"
    [ "$dirs" = "0" ] || info "$dirs old log dir(s) kept in /tmp - rm -rf /tmp/arnika-darwin.*"
}

teardown() {
    [ "$KEEP" = "1" ] && { printf '\nkept: interfaces up, logs in %s\n' "$WORK"; return 0; }
    stop_peers
    pkill -f "$PAT_KMS" 2> /dev/null || true
    sudo wg-quick down "$HERE/qcicat1.conf" > /dev/null 2>&1 || true
    sudo wg-quick down "$HERE/qcicat2.conf" > /dev/null 2>&1 || true
    rm -rf "$WORK"
}
trap teardown EXIT

# ---------------------------------------------------------------- preflight
: > "$WORK/tally"
if [ "$LIST_ONLY" = "1" ]; then
    print_list
    exit 0
fi

section 1
step "prerequisites"
for tool in wg wg-quick wireguard-go go; do
    command -v "$tool" > /dev/null || { echo "missing: $tool - see README.md"; exit 1; }
done
pass tools "wg, wg-quick, wireguard-go and go are present"
# Prime sudo here, once, so it cannot fail halfway through the run. This is not
# gated on a terminal: with pam_tid (Touch ID for sudo, /etc/pam.d/sudo_local)
# the prompt is biometric and needs no tty, which is what makes this work when
# it is started from an editor or an agent rather than a shell. Let sudo decide
# whether it can ask, and only give up when it says it cannot.
#
# It has to be this process that asks: sudo tickets are per session, so priming
# in another window does not carry in here.
if ! sudo -n true 2> /dev/null; then
    info "sudo is not primed - approve the prompt (Touch ID, or type a password)"
    if ! sudo -v; then
        echo "sudo is required and could not be obtained."
        echo "Run this from a shell where sudo works, or prime it first: sudo -v"
        exit 1
    fi
fi
pass sudo "sudo is available"

clean_leftovers
if [ "$CLEAN_ONLY" = "1" ]; then
    exit $((FAILURES + HARNESS_ERRORS))
fi

step "building arnika and the KMS simulator"
( cd "$REPO" && GOEXPERIMENT=runtimesecret CGO_ENABLED=0 go build -o "$WORK/arnika" . )
( cd "$REPO" && CGO_ENABLED=0 go build -o "$WORK/kms" ./tools )
pass build "built into $WORK"

step "bringing up the two WireGuard interfaces"
sudo wg-quick up "$HERE/qcicat1.conf"
sudo wg-quick up "$HERE/qcicat2.conf"
DEV1="$(iface qcicat1)"
DEV2="$(iface qcicat2)"
info "qcicat1 -> $DEV1"
info "qcicat2 -> $DEV2"
pass ifaces "both interfaces are up"

# Peer public keys, taken from the templates so the two never drift apart.
PUB1="$(awk -F' = ' '/^PublicKey/ {print $2}' "$HERE/qcicat1.conf")"
PUB2="$(awk -F' = ' '/^PublicKey/ {print $2}' "$HERE/qcicat2.conf")"
PSK="$(openssl rand -base64 32)"
# PROBE is routed into qcicat1's tunnel by its AllowedIPs and belongs to no
# interface, so packets to it cannot be short-circuited over loopback the way
# packets to the peer's own 100.1.2.2 are. SRC is qcicat1's address, which is
# what the far end's AllowedIPs accepts as an inner source.
SRC="100.1.1.1"
PROBE="100.1.2.3"
# The two peers, named by their ARNIKA_ID throughout. The IDs double as the
# peers' UDP ports, and have to differ in parity: only the lowest bit takes part
# in role election, and the PQC initiator is picked from it too.
ID1=9998
ID2=9999
# wg reports an all-zero preshared key as "(none)", and setting it is how a key
# is removed again.
ZERO_PSK="$(head -c 32 /dev/zero | base64)"

# ------------------------------------------------------------------- checks

# wg_dump prints wg's own view of the devices it is given - only those, and each
# under a heading that says which device, profile and peer it belongs to, since
# the dump itself carries no name.
wg_dump() {
    local dev prof
    [ "$#" -gt 0 ] || set -- "$DEV1" "$DEV2"
    for dev in "$@"; do
        case "$dev" in "$DEV1") prof=qcicat1 ;; "$DEV2") prof=qcicat2 ;; *) prof=unknown ;; esac
        info "wg dump $dev (profile $prof, ARNIKA_ID $(dev_id "$dev")):"
        sudo wg show "$dev" dump | out
    done
}

# xfer prints "rx tx" for the first peer, hs_of the epoch of its last handshake.
# Both report 0 while the peer is briefly absent, so a delta is always safe.
xfer()  { sudo wg show "$1" transfer | awk 'NR==1 {print $2+0, $3+0; exit} END {if (NR==0) print 0, 0}'; }
hs_of() { sudo wg show "$1" latest-handshakes | awk 'NR==1 {print $2+0; exit} END {if (NR==0) print 0}'; }

# wait_for runs a predicate once a second until it succeeds, for at most $1
# seconds, and leaves the elapsed count in WAITED for the caller to report.
# Predicates are plain functions, so bash's dynamic scoping lets them leave what
# they found in the caller's p1 and p2.
WAITED=0
wait_for() {
    local secs="$1"
    shift
    WAITED=0
    while [ "$WAITED" -lt "$secs" ]; do
        "$@" && return 0
        logs
        sleep 1
        WAITED=$((WAITED + 1))
    done
    return 1
}

# hs_done asks whether qcicat1 has handshaked at all. Always qcicat1, and always
# "at all": reset_session is what forces a handshake, and it wipes that end's
# session, which takes its last-handshake time back to 0.
hs_done()     { [ "$(hs_of "$DEV1")" -gt 0 ]; }
wait_hs()     { wait_for "$1" hs_done; }
both_wrote()  { wrote_psk "$LOG_A" && wrote_psk "$LOG_B"; }
kms_up()      { nc -z 127.0.0.1 8080 2> /dev/null; }
log_has()     { tail -n "+$(($2 + 1))" "$1" | grep -q "$3"; }
psk_changed() { p1="$(psk_of "$1")"; [ -n "$p1" ] && [ "$p1" != "(none)" ] && [ "$p1" != "$2" ]; }
psks_differ() { p1="$(psk_of "$DEV1")"; p2="$(psk_of "$DEV2")"; [ -n "$p1" ] && [ "$p1" != "$p2" ]; }
# psks_agree_new: both ends on one usable key, and not the one $1 names.
psks_agree_new() {
    p1="$(psk_of "$DEV1")"
    p2="$(psk_of "$DEV2")"
    [ -n "$p1" ] && [ "$p1" != "(none)" ] && [ "$p1" = "$p2" ] && [ "$p1" != "$1" ]
}

set_psk() { printf '%s\n' "$2" | sudo wg set "$1" peer "$(pub_of "$1")" preshared-key /dev/stdin; }

# reset_session drops qcicat1's peer and adds it back with $1 as its preshared
# key. That throws away the current session, so the next packet has to complete
# a fresh handshake - the only way to put a preshared key to the test on demand.
# A live session survives a key change: the key is used in the handshake alone.
# Always qcicat1's side - the end every handshake check watches.
reset_session() {
    local conf="$HERE/qcicat1.conf" allowed endpoint
    allowed="$(awk -F' = ' '/^AllowedIPs/ {print $2}' "$conf" | tr -d ' ')"
    endpoint="$(awk -F' = ' '/^Endpoint/ {print $2}' "$conf")"
    sudo wg set "$DEV1" peer "$PUB1" remove
    printf '%s\n' "$1" | sudo wg set "$DEV1" peer "$PUB1" \
        allowed-ips "$allowed" endpoint "$endpoint" persistent-keepalive 10 \
        preshared-key /dev/stdin
}

# tunnel_traffic is the whole tunnel check: send 4 KB to PROBE and see whether
# the far end decrypted it. wireguard-go counts rx only for packets that
# decrypt and pass that peer's AllowedIPs, so $DEV2 rx growing is proof the
# payload traversed the tunnel and the two ends agree on the preshared key.
# 4 KB is far more than the 32-byte keepalives that also move in that window.
#
# Nothing owns PROBE, so there is no reply and nothing to print; the ping is
# only a way to put bytes into the interface.
#
# $1 is the number this check reports under. With "broken" as $2 it asserts the
# opposite - nothing may decrypt - which is how each mode proves its checks can
# actually fail.
tunnel_traffic() {
    local id="$1" expect="${2:-intact}" t1 r2 t1b r2b sent got

    # Only $DEV1 tx and $DEV2 rx say anything here: the replies never come back
    # through the tunnel, so the other two counters are not read.
    read -r _ t1 <<< "$(xfer "$DEV1")"
    read -r r2 _ <<< "$(xfer "$DEV2")"
    ping -S "$SRC" -c 4 -s 1000 -t 6 "$PROBE" > /dev/null 2>&1 || true
    read -r _ t1b <<< "$(xfer "$DEV1")"
    read -r r2b _ <<< "$(xfer "$DEV2")"
    sent=$((t1b - t1))
    got=$((r2b - r2))

    if [ "$expect" = "broken" ]; then
        if [ "$got" -gt 2000 ]; then
            fail "$id" "$got B decrypted on a desynced tunnel - a break is invisible here"
        else
            pass "$id" "nothing decrypted at the far end ($(tag "$DEV2") rx +$got B), as a break should look"
        fi
        return 0
    fi

    if [ "$sent" -gt 2000 ] && [ "$got" -gt 2000 ]; then
        pass "$id" "traffic traversed the tunnel: $(tag "$DEV1") tx +$sent B, $(tag "$DEV2") rx +$got B"
        return 0
    fi

    fail "$id" "the payload did not traverse the tunnel: $(tag "$DEV1") tx +$sent B, $(tag "$DEV2") rx +$got B"
    if [ "$sent" -le 2000 ]; then
        info "$(tag "$DEV1") encrypted nothing, so the packets never reached it."
        info "$PROBE has to be in qcicat1.conf AllowedIPs and routed there, and"
        info "must belong to no interface here - route -n get $PROBE"
    else
        info "$(tag "$DEV2") decrypted none of it: either the ends hold different preshared"
        info "keys, or $SRC is missing from qcicat2.conf AllowedIPs"
    fi
    return 1
}

# pretest exercises WireGuard on its own, before Arnika touches anything. The
# mismatched-key step is the point of it: without a check that is known to fail
# on a broken tunnel, every green tick below could be a false pass.
pretest() {
    local k_a
    section 2

    step "both interfaces answer wg"
    if sudo wg show "$DEV1" > /dev/null 2>&1 && sudo wg show "$DEV2" > /dev/null 2>&1; then
        pass wg-answers "$(tag "$DEV1") and $(tag "$DEV2") are live"
    else
        fail wg-answers "one of the two interfaces does not answer wg"
        return 1
    fi

    step "the peers handshake with no preshared key"
    set_psk "$DEV1" "$ZERO_PSK"
    set_psk "$DEV2" "$ZERO_PSK"
    reset_session "$ZERO_PSK"
    if wait_hs 20; then
        pass hs-nopsk "handshake completed"
    else
        fail hs-nopsk "no handshake in 20s - WireGuard itself is not working"
        wg_dump
        return 1
    fi

    step "payload crosses the tunnel"
    tunnel_traffic payload-nopsk || { wg_dump; return 1; }

    step "a matching preshared key keeps the tunnel up"
    k_a="$(openssl rand -base64 32)"
    set_psk "$DEV1" "$k_a"
    set_psk "$DEV2" "$k_a"
    reset_session "$k_a"
    if wait_hs 20; then
        pass hs-samekey "handshake completed with a shared key ($(keytail "$k_a"))"
    else
        fail hs-samekey "a matching preshared key did not handshake"
        wg_dump
        return 1
    fi
    tunnel_traffic payload-samekey || { wg_dump; return 1; }

    step_fault "a mismatched preshared key must break the tunnel"
    set_psk "$DEV2" "$(openssl rand -base64 32)"
    reset_session "$k_a"
    if wait_hs 15; then
        fail hs-mismatch "the ends handshaked while holding different keys - these checks"
        info "cannot tell a working tunnel from a broken one, so the Arnika"
        info "results below would be worthless"
        wg_dump
        return 1
    fi
    pass hs-mismatch "no handshake with different keys - a broken tunnel does get caught"
    # And the traffic check has to say so too: it is the measurement every
    # check below leans on, so it is the one that must be known to fail.
    tunnel_traffic nodecrypt-mismatch broken

    step "back to no preshared key, for Arnika to install its own"
    set_psk "$DEV1" "$ZERO_PSK"
    set_psk "$DEV2" "$ZERO_PSK"
    reset_session "$ZERO_PSK"
    if wait_hs 20; then
        pass hs-cleared "the tunnel is up again and Arnika can take over"
    else
        fail hs-cleared "the tunnel did not come back after the pre-test"
        wg_dump
        return 1
    fi
}

# source_check takes one key source away and holds the mode to its contract.
# Arnika answers a missing *required* source by invalidating the tunnel with a
# random PSK (main.go setPSK), and each end draws its own, so the two ends
# landing on different keys is the signal. A missing *optional* source must
# instead leave rotation running, both ends in step on the other source.
#
# $4 says how QKD is taken away, and the two ways are different faults:
#
#   freeze - the simulator is restarted with both SAE frozen. It accepts and logs
#            every request as usual and never answers one, so a fetch fails on
#            the client's own timeout. That is a hung KMS, or one whose key pool
#            is exhausted and never resolves, and the requests Arnika made into
#            the failure are all in the KMS log as [FREEZE].
#   down   - the simulator is stopped. Nothing is listening, so every connection
#            is refused outright and no request ever reaches a KMS - the KMS is
#            not merely unresponsive, it is absent. It fails fast rather than on
#            a timeout, which is a different code path in kmsRequest, so the
#            defaults are left alone here: refused connections cost nothing and
#            the retry backoff fits inside the interval.
#
# Both must produce the same answer from the mode, and neither is a substitute
# for the other: freeze is the one that leaves a KMS-side record, down is the one
# that proves the mode does not need a KMS to be *reachable* to make a decision.
#
# PQC is taken away with
# PQC_ROUND_TIMEOUT=1ns: every attempt then dies on its deadline waiting for the
# peer's answer, which has to cross the socket, so the *initiating* peer never
# agrees a key and GetNewKey has nothing to return. 1ns rather than 1ms because
# an attempt over loopback can finish inside a millisecond.
#
# The responding peer may still answer a frame or two of its own, since both its
# frames are already queued when it starts - so it can hold a key the initiator
# never confirmed. That is why this check reads LOG_A: peer a's ARNIKA_ID is
# even, which is what makes it the PQC initiator (pqchpke.go), and therefore the
# end whose decision is deterministic. Swap the IDs' parity and this has to
# follow.
#
# Both halves are checked - the PSKs, and the line arnika logs about its own
# decision - because the PSK state alone cannot say the mode reasoned correctly.
source_check() {
    local mode="$1" source="$2" required="$3" how="${4:-}"
    local mark extra="" pattern p1 p2 before
    local idp="$source" what="no $source key" kms_mark=0

    # The KMS-down phase reports under its own ids, so its numbers are separate
    # from the frozen phase's rather than the two overwriting each other.
    if [ "$how" = "down" ]; then
        idp="kmsdown"
        what="KMS not running at all"
    fi

    if [ "$required" = "yes" ]; then
        step_fault "$what: $mode requires $source, so the tunnel must be invalidated"
    else
        step_fault "$what: $mode has $source optional, so rotation must carry on"
    fi

    before="$(psk_of "$DEV1")"
    stop_peers
    mark="$(wc -l < "$LOG_A")"
    if [ "$how" = "down" ]; then
        kms_mark="$(wc -l < "$LOG_KMS" | tr -d ' ')"
        stop_kms
        info "KMS stopped - nothing is listening on 127.0.0.1:8080"
    elif [ "$source" = "qkd" ]; then
        freeze_kms CONSA,CONSB
        # A frozen KMS never answers, so a fetch fails only once the HTTP client
        # gives up: at the 10s default with 5 retries that is over a minute per
        # fetch, far past the windows below. The pair is restarted with a short
        # timeout and one retry instead, ~2s per fetch. The down phase needs no
        # such override - a refused connection returns at once.
        extra="KMS_HTTP_TIMEOUT=1s KMS_BACKOFF_MAX_RETRIES=1"
    else
        extra="PQC_ROUND_TIMEOUT=1ns"
    fi
    start_pair "$mode" "$extra"

    # What arnika should say about its own decision, from main.go setPSK.
    case "$source $required" in
        "qkd yes") pattern="no QKD key received" ;;
        "qkd no")  pattern="switching to PQC key" ;;
        "pqc yes") pattern="Abort since mode is set to" ;;
        "pqc no")  pattern="switching to QKD key" ;;
    esac

    if [ "$required" = "yes" ]; then
        if wait_for 25 psks_differ; then
            pass "$idp-state" "the ends were invalidated onto different keys after ${WAITED}s"
        else
            fail "$idp-state" "$mode kept both ends on one key with $what"
        fi
    else
        if wait_for 25 psks_agree_new "$before"; then
            pass "$idp-state" "rotation carried on with $what, both ends in step after ${WAITED}s"
        else
            fail "$idp-state" "$mode stopped rotating in step although $source is optional to it"
        fi
    fi

    # Polled, not grepped once: arnika logs the decision just before it writes
    # the PSK, but the line reaches the file through a pipe and tee, so the PSK
    # can be visible here a moment before the line that explains it.
    if wait_for 10 log_has "$LOG_A" "$mark" "$pattern"; then
        pass "$idp-logline" "peer a[$ID1] logged the decision: \"$pattern\""
    else
        fail "$idp-logline" "peer a[$ID1] never logged \"$pattern\""
        tail -n 6 "$LOG_A" | out
    fi

    # Checked at the end of the window rather than the start, so it covers the
    # whole phase. Two ways this is not the tautology it looks like: pkill can
    # miss, and something else - a stale simulator from another run, a real KMS
    # on this host - can be holding 8080. Either would leave the pair talking to
    # a KMS while the check believes there is none, and a pass here would then
    # mean nothing. A stopped process cannot write, so any growth in its log is
    # somebody else's.
    if [ "$how" = "down" ]; then
        local kms_now
        kms_now="$(wc -l < "$LOG_KMS" | tr -d ' ')"
        if kms_up; then
            fail kmsdown-noreq "something is still listening on 127.0.0.1:8080"
        elif [ "$kms_now" != "$kms_mark" ]; then
            fail kmsdown-noreq "the KMS log gained $((kms_now - kms_mark)) line(s) with the simulator stopped"
        else
            pass kmsdown-noreq "nothing listening on 127.0.0.1:8080, and the KMS log gained no lines"
        fi
    fi

    step "$source back: the pair has to recover"
    stop_peers
    if [ "$source" = "qkd" ]; then
        kms_back
    fi
    start_pair "$mode"
    if wait_for 30 psks_agree_new "$before"; then
        pass "$idp-recovery" "both ends back in step after ${WAITED}s (key $(keytail "$p1"))"
    else
        fail "$idp-recovery" "the pair did not recover once $source was available again"
        wg_dump
    fi
}

# desync_check is the intentional failure test, run once per mode. The peers are
# stopped so they cannot heal it, one end's PSK is overwritten, and a fresh
# handshake is forced: the tunnel has to break. A mode whose checks cannot see a
# desync is a mode whose passes mean nothing. Then the peers are started again
# and have to put it back.
#
# Stopping them is what makes it deterministic - at INTERVAL=7s a running pair
# heals a desync faster than it can be measured. SIGSTOP would be the lighter
# touch but cannot be used: arnika runs under sudo, and sudo answers a stopped
# child by stopping itself and passing the signal to its process group, which
# is this script.
desync_check() {
    local mode="$1" psk_before bad p1 p2

    step_fault "desync: one end's PSK overwritten with the peers stopped"
    psk_before="$(psk_of "$DEV1")"
    bad="$(openssl rand -base64 32)"
    stop_peers
    set_psk "$DEV2" "$bad"
    reset_session "$psk_before"
    info "peers stopped; $(tag "$DEV1") keeps $(keytail "$psk_before"), $(tag "$DEV2") now holds $(keytail "$bad")"
    if wait_hs 12; then
        fail desync-no-hs "the two ends handshaked while holding different keys"
    else
        pass desync-no-hs "no handshake while the keys differ - the break is real"
    fi
    tunnel_traffic desync-nodecrypt broken

    step "recovery: the peers have to resync it when they come back"
    start_pair "$mode"
    if ! wait_for 30 psks_agree_new "$bad"; then
        fail desync-resync "still out of sync after 30s - $(tag "$DEV1") $(keytail "$p1"), $(tag "$DEV2") $(keytail "$p2")"
        wg_dump
        return 0
    fi
    pass desync-resync "both ends back on one key after ${WAITED}s (key $(keytail "$p1"))"
    if wait_hs 25; then
        pass desync-hs "the tunnel handshaked again on the resynced key"
    else
        fail desync-hs "the keys match again but there was no handshake in 25s"
        wg_dump
    fi
    tunnel_traffic desync-tunnel || true
}

# start_kms, freeze_kms, stop_kms and kms_back exist so source_check can take
# QKD away - by freezing the simulator or by stopping it - and give it back. The log is appended across restarts, like the peers' own.
#
# $1, when given, is passed as FREEZE: those SAE then accept and log requests and
# never answer them. FREEZE is read once at startup, so switching it is a
# restart rather than a signal.
start_kms() {
    LOG_KMS="$WORK/kms.log"
    ( LISTEN=127.0.0.1:8080 DEBUG=true FREEZE="${1:-}" "$WORK/kms" >> "$LOG_KMS" 2>&1 ) &
    wait_for 10 kms_up || abort "the KMS is not listening on 127.0.0.1:8080"
}

# freeze_kms restarts the simulator with $1 frozen, and confirms it from the
# simulator's own [CONF] line - a FREEZE value it does not recognise is silently
# ignored, which would leave a healthy KMS behind a check expecting a broken one.
# Marked before the restart because the log is appended: an earlier mode's
# freeze is in there too.
freeze_kms() {
    local mark
    mark="$(wc -l < "$LOG_KMS" | tr -d ' ')"
    stop_kms
    start_kms "$1"
    if log_has "$LOG_KMS" "$mark" "frozen SAE=$1"; then
        pass qkd-freeze "KMS restarted with $1 frozen - requests accepted, never answered"
    else
        fail qkd-freeze "the KMS did not report $1 as frozen"
    fi
}

# kms_back puts a healthy simulator back, whichever way the phase took it away:
# stopping one that is already stopped is a no-op, so this covers both.
kms_back() {
    stop_kms
    start_kms
}

stop_kms() {
    pkill -f "$PAT_KMS" 2> /dev/null || true
    sleep 1
}

# start_pair starts both Arnika instances for one MODE. desync_check calls it
# again after stopping them, so the logs are appended rather than truncated.
start_pair() {
    local mode="$1" extra="${2:-}"

    # A new mode writes to new files, so the marks logs() reads from start over.
    # A restart within a mode appends, and must not.
    if [ "$LOG_A" != "$WORK/$mode-a.log" ]; then
        LOG_A="$WORK/$mode-a.log"
        LOG_B="$WORK/$mode-b.log"
        MARK_A=0
        MARK_B=0
    fi

    # $1 is this peer's ARNIKA_ID, which doubles as its port; $2 is the other's.
    start_peer() {
        sudo env \
            LISTEN_ADDRESS="127.0.0.1:$1" SERVER_ADDRESS="127.0.0.1:$2" \
            ARNIKA_ID="$1" ARNIKA_PSK="$PSK" INTERVAL=7s MODE="$mode" DEBUG=true \
            KMS_URL="http://127.0.0.1:8080/api/v1/keys/$3" \
            WIREGUARD_INTERFACE="$4" WIREGUARD_PEER_PUBLIC_KEY="$5" \
            ${extra} \
            "$WORK/arnika" >> "$6" 2>&1 &
    }
    start_peer "$ID1" "$ID2" CONSA "$DEV1" "$PUB1" "$LOG_A"
    start_peer "$ID2" "$ID1" CONSB "$DEV2" "$PUB2" "$LOG_B"
}

# run_mode starts a peer pair in one MODE and puts it through the checks.
run_mode() {
    local mode="$1"

    section "$(sec_of_mode "$mode")"
    start_pair "$mode"

    step "waiting for both ends to install a PSK"
    if ! wait_for 40 both_wrote; then
        fail psk-written "at least one end never wrote a PSK in MODE=$mode"
        tail -n 15 "$LOG_A" "$LOG_B" | out
        stop_peers
        return
    fi
    pass psk-written "both ends reported a successful write"

    step "both interfaces hold the same PSK"
    local psk1 psk2
    psk1="$(psk_of "$DEV1")"
    psk2="$(psk_of "$DEV2")"
    if [ -z "$psk1" ] || [ "$psk1" = "(none)" ]; then
        # Stop here. Everything below compares against this key, and the first
        # rotation cycle would count any key at all as a change from nothing -
        # reporting a rotation that never happened.
        fail psk-identical "$(tag "$DEV1") has no preshared key, so nothing below can be judged"
        wg_dump
        stop_peers
        return
    fi
    if [ "$psk1" = "$psk2" ]; then
        pass psk-identical "identical on both ends (key $(keytail "$psk1"))"
    else
        # A divergence is still a usable baseline: both ends hold a real key, so
        # the cycles below report the divergence per cycle rather than guessing.
        fail psk-identical "the two ends installed different keys - $(tag "$DEV1") $(keytail "$psk1"), $(tag "$DEV2") $(keytail "$psk2")"
    fi
    wg_dump
    tunnel_traffic tunnel-initial || true

    step "$CYCLES rotation cycles"
    local prev="$psk1" cur other cycle p1
    for cycle in $(seq 1 "$CYCLES"); do
        sep "cycle $cycle/$CYCLES"
        if ! wait_for 30 psk_changed "$DEV1" "$prev"; then
            fail "rotate-$cycle" "cycle $cycle/$CYCLES: the PSK did not change within 30s"
            break
        fi
        cur="$p1"
        other="$(psk_of "$DEV2")"
        if [ "$cur" = "$other" ]; then
            pass "rotate-$cycle" "cycle $cycle/$CYCLES: rotated, both ends match (key $(keytail "$cur"))"
        else
            fail "rotate-$cycle" "cycle $cycle/$CYCLES: the ends diverged - $(tag "$DEV1") $(keytail "$cur"), $(tag "$DEV2") $(keytail "$other")"
        fi
        wg_dump
        prev="$cur"
    done
    sep "end of cycles"

    step "the tunnel after $CYCLES rotations"
    tunnel_traffic tunnel-rotated || true

    # Which source this mode may do without - the contract under test. Mirrors
    # IsQKDRequired and IsPQCRequired in config/config.go, so a mode that is in
    # neither list (EitherQkdOrPqcRequired) correctly gets "optional" for both.
    local qkd_req=no pqc_req=no
    case "$mode" in QkdAndPqcRequired | AtLeastQkdRequired) qkd_req=yes ;; esac
    case "$mode" in QkdAndPqcRequired | AtLeastPqcRequired) pqc_req=yes ;; esac
    # Two ways for QKD to be gone, and a mode has to answer both the same: the
    # simulator hung, and the simulator absent.
    source_check "$mode" qkd "$qkd_req" freeze
    source_check "$mode" qkd "$qkd_req" down
    source_check "$mode" pqc "$pqc_req"

    desync_check "$mode"

    step "MODE=$mode log summary"
    local name log rounds writes dbg warn id
    for name in a b; do
        if [ "$name" = "a" ]; then id="$ID1"; log="$LOG_A"; else id="$ID2"; log="$LOG_B"; fi
        rounds="$(grep -c 'agreed a fresh PQC key' "$log" || true)"
        writes="$(grep -c 'PSK configured on WireGuard interface' "$log" || true)"
        dbg="$(grep -c '\[DEBUG\]' "$log" || true)"
        warn="$(grep -c '\[WARNING\]\|\[ERROR\]' "$log" || true)"
        info "peer $name[$id]: $rounds PQC exchanges, $writes PSK writes, $dbg debug lines, $warn warnings/errors"
    done

    stop_peers
}

pretest || {
    printf '\n%sWireGuard is not working on its own - stopping before Arnika.%s\n' \
        "$C_BOLD" "$C_RESET"
    summary
    rule
    printf '%s  FAIL - WireGuard is broken, Arnika was not tested%s\n' "$C_BOLD" "$C_RESET"
    rule
    exit 1
}

# Back to section 1: this runs after the pre-test, so without it the check would
# resolve its id against the pre-test's list and come out ?.?.
section 1
step "starting the KMS simulator"
start_kms
grep -q 'debug logging enabled=true' "$WORK/kms.log" \
    && pass kms "listening on 127.0.0.1:8080 with debug logging" \
    || fail kms "the simulator did not enable debug logging"

for mode in $MODES; do
    run_mode "$mode"
done

logs
summary
info "logs: $WORK"
rule
if [ "$FAILURES" = "0" ] && [ "$HARNESS_ERRORS" = "0" ]; then
    printf '%s  PASS - all checks passed%s\n' "$C_BOLD" "$C_RESET"
else
    printf '%s  FAIL - %s check(s) failed%s\n' "$C_BOLD" "$FAILURES" "$C_RESET"
fi
rule
exit $((FAILURES + HARNESS_ERRORS))
