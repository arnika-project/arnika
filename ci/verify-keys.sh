#!/bin/bash
set -e

echo "====== Arnika CI Integration Test - Key Verification ======"

# Wait for both nodes to start and exchange keys
echo "Waiting for Arnika instances to exchange keys (32 seconds)..."
sleep 32

# Function to extract PSK from WireGuard interface
get_psk() {
    local node=$1
    docker exec clab-arnika-ci-test-${node} wg show wg0 preshared-keys | awk '{print $2}'
}

# Retry loop: read both PSKs and compare. Retries handle the case where
# the two sequential docker-exec calls straddle a key-rotation boundary
# (rotation interval is 5 s; a single mismatch snapshot is not a real failure).
MAX_ATTEMPTS=5
ATTEMPT=0
PSK_A=""
PSK_B=""
while [ $ATTEMPT -lt $MAX_ATTEMPTS ]; do
    echo ""
    echo "Extracting PSK from node-a (attempt $((ATTEMPT + 1))/$MAX_ATTEMPTS)..."
    PSK_A=$(get_psk "node-a")
    echo "Node-A PSK: ${PSK_A}"

    echo ""
    echo "Extracting PSK from node-b (attempt $((ATTEMPT + 1))/$MAX_ATTEMPTS)..."
    PSK_B=$(get_psk "node-b")
    echo "Node-B PSK: ${PSK_B}"

    if [ -n "$PSK_A" ] && [ "$PSK_A" != "(none)" ] && \
       [ -n "$PSK_B" ] && [ "$PSK_B" != "(none)" ] && \
       [ "$PSK_A" = "$PSK_B" ]; then
        break
    fi

    ATTEMPT=$((ATTEMPT + 1))
    if [ $ATTEMPT -lt $MAX_ATTEMPTS ]; then
        echo ""
        echo "PSKs not yet in sync, retrying in 2 seconds..."
        sleep 2
    fi
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
    echo "Node-A Arnika logs (last 10 lines):"
    docker exec clab-arnika-ci-test-node-a tail -n 10 /tmp/arnika.log || echo "No logs available"

    echo ""
    echo "Node-B Arnika logs (last 10 lines):"
    docker exec clab-arnika-ci-test-node-b tail -n 10 /tmp/arnika.log || echo "No logs available"

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
