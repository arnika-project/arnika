#!/bin/bash
set -e

echo "====== Arnika local Test - show PSK ======"

wg_show_os_aware() {
    local profile="$1"
    local field="${2-}"

    if [[ $OSTYPE == darwin* ]]; then
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
        if [[ -n "$field" ]]; then
            sudo wg show "$profile" "$field"
        else
            sudo wg show "$profile"
        fi
    fi
}

wg_show_os_aware qcicat1 preshared-keys
echo

wg_show_os_aware qcicat2 preshared-keys
echo
