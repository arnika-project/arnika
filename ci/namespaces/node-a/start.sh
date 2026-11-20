#!/bin/bash
set -e

ip netns add arnika-ns-a

ip link add dev wg0 type wireguard
ip link set wg0 netns arnika-ns-a

ip -n arnika-ns-a addr add 172.16.0.1/24 dev wg0

ip netns exec arnika-ns-a wg set wg0 \
    private-key /etc/arnika/node-a.key \
    listen-port 51820

ip netns exec arnika-ns-a wg set wg0 \
    peer "$(cat /etc/arnika/node-b.pub)" \
    allowed-ips 172.16.0.2/32 \
    endpoint 10.0.0.2:51820

ip -n arnika-ns-a link set wg0 up

NETNS_PATH="/var/run/netns/arnika-ns-a"

echo "Waiting for QKD simulator..."
for _ in {1..30}; do
    if curl -s http://192.168.100.1:8080/api/v1/keys/CONSB/enc_keys > /dev/null; then
        echo "QKD simulator is ready!"
        break
    fi
    sleep 1
done

echo "Starting Arnika on node-a (MASTER) with netns support..."

SERVER_ADDRESS=10.0.0.2:9998 \
INTERVAL=5s \
KMS_URL="http://192.168.100.1:8080/api/v1/keys/CONSB" \
WIREGUARD_INTERFACE=wg0 \
WIREGUARD_PEER_PUBLIC_KEY="$(cat /etc/arnika/node-b.pub)" \
WIREGUARD_NETNS_PATH="$NETNS_PATH" \
ARNIKA_PSK="mJNYzLNLRCl9jRRkP/Qsa74v4bem4BC+KbqQz+Ft9lQ=" \
arnika &>> /tmp/arnika-ns-a.log &