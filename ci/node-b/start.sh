#!/bin/bash
set -e

# Wait for QKD simulator to be ready
echo "Waiting for QKD simulator..."
for i in {1..30}; do
    if curl -s http://192.168.101.1:8080/api/v1/keys/CONSB/enc_keys > /dev/null; then
        echo "QKD simulator is ready!"
        break
    fi
    sleep 1
done

# Set up WireGuard interface
echo "Setting up WireGuard interface..."
ip link add dev wg0 type wireguard
ip addr add 172.16.0.2/24 dev wg0
wg set wg0 private-key /etc/arnika/node-b.key listen-port 51820
wg set wg0 peer $(cat /etc/arnika/node-a.pub) allowed-ips 172.16.0.1/32 endpoint 10.0.0.1:51820
ip link set wg0 up

# Start Arnika as BACKUP (responder)
echo "Starting Arnika on node-b (BACKUP)..."
LISTEN_ADDRESS=10.0.0.2:9998 \
SERVER_ADDRESS=10.0.0.1:9998 \
INTERVAL=5s \
KMS_URL="http://192.168.101.1:8080/api/v1/keys/CONSB" \
WIREGUARD_INTERFACE=wg0 \
WIREGUARD_PEER_PUBLIC_KEY="$(cat /etc/arnika/node-a.pub)" \
arnika &>> /tmp/arnika.log &

echo "Node-b started successfully"
