#!/bin/bash
set -e

# Generate WireGuard keys for node-a
mkdir -p ci/node-a
wg genkey | tee ci/node-a/node-a.key | wg pubkey > ci/node-a/node-a.pub

# Generate WireGuard keys for node-b
mkdir -p ci/node-b
wg genkey | tee ci/node-b/node-b.key | wg pubkey > ci/node-b/node-b.pub

# Copy public keys to opposite nodes for peer configuration
cp ci/node-a/node-a.pub ci/node-b/node-a.pub
cp ci/node-b/node-b.pub ci/node-a/node-b.pub

# Set proper permissions
chmod 600 ci/node-a/node-a.key ci/node-b/node-b.key
chmod 644 ci/node-a/*.pub ci/node-b/*.pub
chmod +x ci/node-a/start.sh ci/node-b/start.sh

echo "WireGuard keys generated successfully!"
echo "Node-A public key: $(cat ci/node-a/node-a.pub)"
echo "Node-B public key: $(cat ci/node-b/node-b.pub)"
