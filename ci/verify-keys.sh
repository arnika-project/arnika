#!/bin/bash
set -e

echo "====== Arnika CI Integration Test - Key Verification ======"

# Wait for both nodes to start and exchange keys
echo "Waiting for Arnika instances to exchange keys (30 seconds)..."
sleep 30

# Function to extract PSK from WireGuard interface
get_psk() {
    local node=$1
    docker exec clab-arnika-ci-test-${node} wg show wg0 preshared-keys | awk '{print $2}'
}

echo ""
echo "Extracting PSK from node-a..."
PSK_A=$(get_psk "node-a")
echo "Node-A PSK: ${PSK_A}"

echo ""
echo "Extracting PSK from node-b..."
PSK_B=$(get_psk "node-b")
echo "Node-B PSK: ${PSK_B}"

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
