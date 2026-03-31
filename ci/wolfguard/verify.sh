#!/bin/bash
# Verifies that arnika successfully injected matching PSKs into wolfGuard interfaces.
set -e

echo "====== wolfGuard Integration Test - Verification ======"

echo "Waiting for key exchange (30 seconds)..."
sleep 30

# Extract PSKs
PSK_A=$(ip netns exec ns-a wg-fips show wg0 preshared-keys | awk '{print $2}')
PSK_B=$(ip netns exec ns-b wg-fips show wg0 preshared-keys | awk '{print $2}')

echo "Node-A PSK: ${PSK_A}"
echo "Node-B PSK: ${PSK_B}"

echo ""
echo "====== Verification Results ======"

if [ -z "$PSK_A" ] || [ "$PSK_A" = "(none)" ]; then
    echo "FAILED: Node-A has no PSK configured"
    exit 1
fi

if [ -z "$PSK_B" ] || [ "$PSK_B" = "(none)" ]; then
    echo "FAILED: Node-B has no PSK configured"
    exit 1
fi

if [ "$PSK_A" = "$PSK_B" ]; then
    echo "SUCCESS: Both wolfGuard nodes have the same PSK"
    echo "PSK: ${PSK_A}"

    echo ""
    echo "====== Tunnel Connectivity ======"
    if ip netns exec ns-a ping -c 3 -W 2 172.16.0.2 > /dev/null 2>&1; then
        echo "SUCCESS: Node-A can ping Node-B through wolfGuard tunnel"
    else
        echo "WARNING: Tunnel ping failed (may need more time)"
    fi

    echo ""
    echo "====== wolfGuard Interface Info ======"
    echo "--- ns-a ---"
    ip netns exec ns-a wg-fips show wg0
    echo "--- ns-b ---"
    ip netns exec ns-b wg-fips show wg0

    exit 0
else
    echo "FAILED: PSKs do not match"
    echo "Node-A PSK: ${PSK_A}"
    echo "Node-B PSK: ${PSK_B}"

    echo ""
    echo "====== Debug Logs ======"
    echo "--- Node-A ---"
    cat /tmp/wolfguard-test/node-a/arnika.log || true
    echo "--- Node-B ---"
    cat /tmp/wolfguard-test/node-b/arnika.log || true

    exit 1
fi
