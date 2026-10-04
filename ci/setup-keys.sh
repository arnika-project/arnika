#!/bin/bash
set -e

WG_IMAGE="${WG_IMAGE:-arnika-node:ci}"
if command -v wg > /dev/null 2>&1 ; then
    wg_cmd() { wg "$@" ; }
else
    if ! docker image inspect "$WG_IMAGE" > /dev/null 2>&1 ; then
        echo "ERROR: no 'wg' on PATH and image '$WG_IMAGE' is not present." >&2
        echo "Build the node image first, or install wireguard-tools." >&2
        exit 1
    fi
    echo "wg not on PATH - using $WG_IMAGE"
    wg_cmd() { docker run --rm -i "$WG_IMAGE" wg "$@" ; }
fi

mkdir -p ci/node-a
wg_cmd genkey | tee ci/node-a/node-a.key | wg_cmd pubkey > ci/node-a/node-a.pub

mkdir -p ci/node-b
wg_cmd genkey | tee ci/node-b/node-b.key | wg_cmd pubkey > ci/node-b/node-b.pub

cp ci/node-a/node-a.pub ci/node-b/node-a.pub
cp ci/node-b/node-b.pub ci/node-a/node-b.pub

chmod 600 ci/node-a/node-a.key ci/node-b/node-b.key
chmod 644 ci/node-a/*.pub ci/node-b/*.pub
chmod +x ci/node-a/start.sh ci/node-b/start.sh

echo "WireGuard keys generated successfully!"
echo "Node-A public key: $(cat ci/node-a/node-a.pub)"
echo "Node-B public key: $(cat ci/node-b/node-b.pub)"
