#!/bin/bash
set -e

echo "====== Arnika local Test - show PSK ======"

wg_show_os_aware() {
    local profile="$1"          # e.g. qcicat1
    local field="${2-}"         # optional: "latest-handshakes" | "transfer" | "dump" | "preshared-keys"

    if [[ $OSTYPE == darwin* ]]; then
        # macOS: map profile -> real interface name from .name file
        local iface
        iface="$(sudo cat "/var/run/wireguard/${profile}.name")" || return 1
        if [[ -n "$field" ]]; then
            echo "profile: $profile"
            echo "interface: $iface"
            echo "Peer:                                           PresharedKey:"
            sudo wg show "$iface" "$field"
        else
            echo "profile: $profile"
            sudo wg show "$iface"
        fi
    else
        # Linux/other: use profile name directly
        if [[ -n "$field" ]]; then
            sudo wg show "$profile" "$field"
        else
            sudo wg show "$profile"
        fi
    fi
}

# Usage: wg show { <interface> | all | interfaces } [public-key | private-key | listen-port | fwmark | peers | preshared-keys | endpoints | allowed-ips | latest-handshakes | transfer | persistent-keepalive | dump]

# wg_show_os_aware qcicat1
# echo
# wg_show_os_aware qcicat2
# echo

wg_show_os_aware qcicat1 preshared-keys
echo

wg_show_os_aware qcicat2 preshared-keys
echo
