#!/bin/bash
set -e

echo "====== Arnika CI Integration Test - Key Verification ======"

# Function to extract PSK from WireGuard interface
get_psk() {
    local node=$1
    docker exec clab-arnika-ci-test-${node} wg show wg0 preshared-keys | awk '{print $2}'
}

# Poll until both nodes report the same non-empty PSK, instead of sleeping for
# the worst case. The rotation interval is 5 s, so a healthy pair converges in
# well under 15 s; polling also covers the case where the two sequential
# docker-exec calls straddle a rotation boundary (a single mismatched snapshot
# is not a real failure). On timeout we fall through to the checks below, which
# report exactly what was wrong - the assertions are unchanged.
VERIFY_TIMEOUT="${VERIFY_TIMEOUT:-90}"
POLL_INTERVAL=2
DEADLINE=$((SECONDS + VERIFY_TIMEOUT))
ATTEMPT=0
PSK_A=""
PSK_B=""

echo "Waiting for Arnika instances to exchange keys (timeout ${VERIFY_TIMEOUT}s)..."
while : ; do
    ATTEMPT=$((ATTEMPT + 1))
    PSK_A=$(get_psk "node-a" || true)
    PSK_B=$(get_psk "node-b" || true)

    if [ -n "$PSK_A" ] && [ "$PSK_A" != "(none)" ] && \
       [ -n "$PSK_B" ] && [ "$PSK_B" != "(none)" ] && \
       [ "$PSK_A" = "$PSK_B" ]; then
        echo "PSKs converged after ${SECONDS}s (attempt ${ATTEMPT})"
        break
    fi

    if [ "$SECONDS" -ge "$DEADLINE" ]; then
        echo "Timed out after ${VERIFY_TIMEOUT}s waiting for a matching PSK on both nodes"
        break
    fi

    sleep "$POLL_INTERVAL"
done

echo ""
echo "====== Verification Results ======"

if [ -z "$PSK_A" ] || [ "$PSK_A" = "(none)" ]; then
    echo "❌ FAILED: Node-A has no PSK configured"
    exit 1
fi

if [ -z "$PSK_B" ] || [ "$PSK_B" = "(none)" ]; then
    echo "❌ FAILED: Node-B has no PSK configured"
    exit 1
fi

if [ "$PSK_A" = "$PSK_B" ]; then
    echo "✅ SUCCESS: Both nodes have the same PSK!"
    echo "PSK: ${PSK_A}"

    # Additional checks
    echo ""
    echo "====== Additional Checks ======"

    # Check if nodes can ping each other over WireGuard
    echo "Testing connectivity between nodes..."
    if docker exec clab-arnika-ci-test-node-a ping -c 3 -W 2 172.16.0.2 > /dev/null 2>&1; then
        echo "✅ Node-A can ping Node-B through WireGuard tunnel"
    else
        echo "⚠️  WARNING: Node-A cannot ping Node-B (may need more time)"
    fi

    # Check Arnika logs
    echo ""
    echo "Node-A Arnika logs (last 40 lines):"
    docker exec clab-arnika-ci-test-node-a tail -n 40 /tmp/arnika.log || echo "No logs available"

    echo ""
    echo "Node-B Arnika logs (last 40 lines):"
    docker exec clab-arnika-ci-test-node-b tail -n 40 /tmp/arnika.log || echo "No logs available"

    exit 0
else
    echo "❌ FAILED: PSKs do not match!"
    echo "Node-A PSK: ${PSK_A}"
    echo "Node-B PSK: ${PSK_B}"

    echo ""
    echo "====== Debug Information ======"
    echo "Node-A Arnika logs:"
    docker exec clab-arnika-ci-test-node-a cat /tmp/arnika.log || echo "No logs available"

    echo ""
    echo "Node-B Arnika logs:"
    docker exec clab-arnika-ci-test-node-b cat /tmp/arnika.log || echo "No logs available"

    exit 1
fi
