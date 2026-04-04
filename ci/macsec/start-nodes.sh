#!/bin/bash
# Starts arnika in both namespaces: node-a as MASTER, node-b as BACKUP.
# Each node uses KEY_HANDLER=macsec with the peer's SCI as MACSEC_RX_SCI.
set -e

ARNIKA="$(pwd)/build/arnika"
SCI_A=$(cat /tmp/macsec-test/sci-a)
SCI_B=$(cat /tmp/macsec-test/sci-b)

# Start node-a (MASTER) — receives from node-b, so RX SCI = node-b's SCI
ip netns exec ns-a env \
    LISTEN_ADDRESS=10.0.0.1:9998 \
    SERVER_ADDRESS=10.0.0.2:9998 \
    INTERVAL=5s \
    KMS_URL="http://192.168.100.1:8080/api/v1/keys/CONSB" \
    KEY_HANDLER=macsec \
    MACSEC_INTERFACE=macsec0 \
    MACSEC_RX_SCI="$SCI_B" \
    "$ARNIKA" &> /tmp/macsec-test/node-a/arnika.log &
echo $! > /tmp/macsec-test/node-a/arnika.pid
echo "Started arnika node-a (MASTER) pid=$(cat /tmp/macsec-test/node-a/arnika.pid)"

# Start node-b (BACKUP) — receives from node-a, so RX SCI = node-a's SCI
ip netns exec ns-b env \
    LISTEN_ADDRESS=10.0.0.2:9998 \
    SERVER_ADDRESS=10.0.0.1:9998 \
    INTERVAL=5s \
    KMS_URL="http://192.168.101.1:8080/api/v1/keys/CONSB" \
    KEY_HANDLER=macsec \
    MACSEC_INTERFACE=macsec0 \
    MACSEC_RX_SCI="$SCI_A" \
    "$ARNIKA" &> /tmp/macsec-test/node-b/arnika.log &
echo $! > /tmp/macsec-test/node-b/arnika.pid
echo "Started arnika node-b (BACKUP) pid=$(cat /tmp/macsec-test/node-b/arnika.pid)"
