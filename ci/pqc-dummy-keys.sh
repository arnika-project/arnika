#!/bin/bash
set -e

echo "====== Arnika local Test - generate dummy PQC keys ======"

# Function to generate PQC dummy keys
generate_keys() {

    [ -d ci/node-a ] || mkdir ci/node-a
    [ -d ci/node-b ] || mkdir ci/node-b


    echo "$(date): Generating new PQC dummy keys..."

    # Generate PQC dummy keys
    wg genkey | tee ci/node-a/node-a-pqc.key > ci/node-b/node-b-pqc.key && \
    echo "PQC dummy keys generated successfully!"

    # Set proper permissions
    chmod 600 ci/node-a/node-a-pqc.key ci/node-b/node-b-pqc.key

    # WARNING: exposing keys only for testing purposes !
    echo "Node-A PQC dummy key: $(cat ci/node-a/node-a-pqc.key)"
    echo "Node-B PQC dummy key: $(cat ci/node-b/node-b-pqc.key)"
    echo ""
}

# Infinite loop to regenerate keys every 10 seconds
while true; do
    generate_keys
    sleep 10
done
