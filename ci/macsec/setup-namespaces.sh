#!/bin/bash
# Sets up two network namespaces (ns-a, ns-b) with MACsec interfaces.
#
# Network topology:
#   ns-a (192.168.100.2) <--veth--> host (192.168.100.1)  [KMS access for node-a]
#   ns-b (192.168.101.2) <--veth--> host (192.168.101.1)  [KMS access for node-b]
#   ns-a (10.0.0.1/veth) <--veth--> ns-b (10.0.0.2/veth)  [arnika TCP]
#   ns-a (172.16.0.1/macsec0) --- MACsec --- ns-b (172.16.0.2/macsec0)
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

# --- veth pair: ns-a <-> ns-b (underlay for arnika TCP + MACsec) ---
ip link add veth-a-b type veth peer name veth-b-a
ip link set veth-a-b netns ns-a
ip link set veth-b-a netns ns-b
ip netns exec ns-a ip addr add 10.0.0.1/30 dev veth-a-b
ip netns exec ns-a ip link set veth-a-b up
ip netns exec ns-b ip addr add 10.0.0.2/30 dev veth-b-a
ip netns exec ns-b ip link set veth-b-a up

# --- MACsec interfaces on top of the peer-to-peer veth ---
# Get MAC addresses for SCI derivation
MAC_A=$(ip netns exec ns-a cat /sys/class/net/veth-a-b/address | tr -d ':')
MAC_B=$(ip netns exec ns-b cat /sys/class/net/veth-b-a/address | tr -d ':')
# SCI = MAC (6 bytes) + port (2 bytes, we use 0001)
SCI_A="${MAC_A}0001"
SCI_B="${MAC_B}0001"

# node-a macsec0 (encrypt on, using node-a's SCI)
ip netns exec ns-a ip link add link veth-a-b macsec0 type macsec \
    sci "${SCI_A}" encrypt on
ip netns exec ns-a ip addr add 172.16.0.1/24 dev macsec0
ip netns exec ns-a ip link set macsec0 up

# node-b macsec0 (encrypt on, using node-b's SCI)
ip netns exec ns-b ip link add link veth-b-a macsec0 type macsec \
    sci "${SCI_B}" encrypt on
ip netns exec ns-b ip addr add 172.16.0.2/24 dev macsec0
ip netns exec ns-b ip link set macsec0 up

# Save SCIs for use by start-nodes.sh
echo -n "$SCI_A" > /tmp/macsec-test/sci-a
echo -n "$SCI_B" > /tmp/macsec-test/sci-b

echo "Network namespaces and MACsec interfaces configured"
echo "  ns-a macsec0: 172.16.0.1 (SCI: ${SCI_A})"
echo "  ns-b macsec0: 172.16.0.2 (SCI: ${SCI_B})"
