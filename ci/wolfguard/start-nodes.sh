#!/bin/bash
# Starts arnika in both namespaces: node-a as MASTER, node-b as BACKUP.
set -e

ARNIKA="$(pwd)/build/arnika"
PUBKEY_A=$(cat /tmp/wolfguard-test/node-a/public.key)
PUBKEY_B=$(cat /tmp/wolfguard-test/node-b/public.key)

# Start node-a (MASTER)
ip netns exec ns-a env \
    LISTEN_ADDRESS=10.0.0.1:9998 \
    SERVER_ADDRESS=10.0.0.2:9998 \
    INTERVAL=5s \
    KMS_URL="http://192.168.100.1:8080/api/v1/keys/CONSB" \
    KEY_HANDLER=wolfguard \
    WIREGUARD_INTERFACE=wg0 \
    WIREGUARD_PEER_PUBLIC_KEY="$PUBKEY_B" \
    "$ARNIKA" &> /tmp/wolfguard-test/node-a/arnika.log &
echo $! > /tmp/wolfguard-test/node-a/arnika.pid
echo "Started arnika node-a (MASTER) pid=$(cat /tmp/wolfguard-test/node-a/arnika.pid)"

# Start node-b (BACKUP)
ip netns exec ns-b env \
    LISTEN_ADDRESS=10.0.0.2:9998 \
    SERVER_ADDRESS=10.0.0.1:9998 \
    INTERVAL=5s \
    KMS_URL="http://192.168.101.1:8080/api/v1/keys/CONSB" \
    KEY_HANDLER=wolfguard \
    WIREGUARD_INTERFACE=wg0 \
    WIREGUARD_PEER_PUBLIC_KEY="$PUBKEY_A" \
    "$ARNIKA" &> /tmp/wolfguard-test/node-b/arnika.log &
echo $! > /tmp/wolfguard-test/node-b/arnika.pid
echo "Started arnika node-b (BACKUP) pid=$(cat /tmp/wolfguard-test/node-b/arnika.pid)"
