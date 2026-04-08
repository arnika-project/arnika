#!/bin/bash
# Sets up two network namespaces (ns-a, ns-b) connected via veth pairs.
#
# Network topology:
#   ns-a (192.168.100.2) <--veth--> host (192.168.100.1)  [KMS access for node-a]
#   ns-b (192.168.101.2) <--veth--> host (192.168.101.1)  [KMS access for node-b]
#   ns-a (10.0.0.1)      <--veth--> ns-b (10.0.0.2)       [arnika TCP + WireGuard]
#
set -e

# Create namespaces
ip netns add ns-a
ip netns add ns-b

# --- veth pair: host <-> ns-a (for KMS access) ---
ip link add veth-host-a type veth peer name veth-a-host
ip link set veth-a-host netns ns-a
ip addr add 192.168.100.1/30 dev veth-host-a
ip link set veth-host-a up
ip netns exec ns-a ip addr add 192.168.100.2/30 dev veth-a-host
ip netns exec ns-a ip link set veth-a-host up
ip netns exec ns-a ip link set lo up

# --- veth pair: host <-> ns-b (for KMS access) ---
ip link add veth-host-b type veth peer name veth-b-host
ip link set veth-b-host netns ns-b
ip addr add 192.168.101.1/30 dev veth-host-b
ip link set veth-host-b up
ip netns exec ns-b ip addr add 192.168.101.2/30 dev veth-b-host
ip netns exec ns-b ip link set veth-b-host up
ip netns exec ns-b ip link set lo up

# --- veth pair: ns-a <-> ns-b (for arnika TCP + WireGuard endpoint) ---
ip link add veth-a-b type veth peer name veth-b-a
ip link set veth-a-b netns ns-a
ip link set veth-b-a netns ns-b
ip netns exec ns-a ip addr add 10.0.0.1/30 dev veth-a-b
ip netns exec ns-a ip link set veth-a-b up
ip netns exec ns-b ip addr add 10.0.0.2/30 dev veth-b-a
ip netns exec ns-b ip link set veth-b-a up

# --- WireGuard interfaces (using wolfGuard kernel module) ---
PUBKEY_A=$(cat /tmp/wolfguard-test/node-a/public.key)
PUBKEY_B=$(cat /tmp/wolfguard-test/node-b/public.key)

# node-a wg0
ip netns exec ns-a ip link add dev wg0 type wolfguard
ip netns exec ns-a ip addr add 172.16.0.1/24 dev wg0
ip netns exec ns-a wg-fips set wg0 \
    private-key /tmp/wolfguard-test/node-a/private.key \
    listen-port 51820
ip netns exec ns-a wg-fips set wg0 \
    peer "$PUBKEY_B" \
    allowed-ips 172.16.0.2/32 \
    endpoint 10.0.0.2:51820
ip netns exec ns-a ip link set wg0 up

# node-b wg0
ip netns exec ns-b ip link add dev wg0 type wolfguard
ip netns exec ns-b ip addr add 172.16.0.2/24 dev wg0
ip netns exec ns-b wg-fips set wg0 \
    private-key /tmp/wolfguard-test/node-b/private.key \
    listen-port 51820
ip netns exec ns-b wg-fips set wg0 \
    peer "$PUBKEY_A" \
    allowed-ips 172.16.0.1/32 \
    endpoint 10.0.0.1:51820
ip netns exec ns-b ip link set wg0 up

echo "Network namespaces and WireGuard interfaces configured"
echo "  ns-a wg0: 172.16.0.1 (wolfGuard)"
echo "  ns-b wg0: 172.16.0.2 (wolfGuard)"
