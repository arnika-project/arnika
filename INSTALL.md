<!--
NOTE: Documentation is generated based on an Ansible playbook.
prompt:
Analyze the attached Ansible playbook and directory structure.
Generate a comprehensive, step-by-step installation manual in Markdown format named `installation.md`.
The documentation should include:
* All prerequisites (system requirements, dependencies, required software, etc.)
*	Detailed, sequential manual installation instructions, clearly broken down by step
*	Instructions on how to manually start all relevant services after installation
    Replace any sensitive information such as keys or passwords with clear placeholders (e.g., `<YOUR_PASSWORD_HERE>`).
*	Include all tools and scripts (eg.: those starting with init_*) that are part of the installation, with explanations of their purpose.
* use "alice" instead of "o93" or "qcicat-o93-app01"
* use "bob" instead of "o73" or "qcicat-o73-app02"
* create and exlpain config files for both hosts "alice" and "bob" with appropriate placeholders for IP addresses, keys, etc.

Ensure the documentation is clear, concise, and suitable for a technical audience.
create a new file `INSTALL.md` with the content.
-->

# Arnika Quantum-Secure VPN Installation Guide

This guide provides step-by-step instructions for manually installing the Arnika Quantum-Secure VPN system and all its dependencies on Ubuntu systems for both "Alice" and "Bob" endpoints.

## Table of Contents

1. Prerequisites
2. Ubuntu System Configuration
3. Wireguard Installation
4. Rosenpass Installation (Optional - for PQC mode)
5. KMS Installation (Optional - for KMS mode)
6. Arnika Installation
7. Tools Installation
8. Service Management
9. Verification

## Prerequisites

- Ubuntu operating system
- Root or sudo access
- Internet connectivity
- Pre-generated Wireguard keys for both hosts (private keys, public keys, and PSK)
- (Optional) Rosenpass keys for PQC mode
- (Optional) KMS certificates for KMS mode
- Arnika version v0.2.2 (current stable version)

## Ubuntu System Configuration

Perform these steps on both Alice and Bob servers:

1. Update the package repositories and upgrade installed packages:

   ```bash
   sudo apt update
   sudo apt upgrade -y
   ```

2. Install required packages:

   ```bash
   sudo apt install -y net-tools iputils-ping dnsutils socat less vim tmux lsof traceroute tcptraceroute fping htop bash-completion jq iotop apt-transport-https ca-certificates curl
   ```

3. Set the timezone:

   ```bash
   sudo timedatectl set-timezone Europe/Vienna
   ```

4. Configure time synchronization:

   ```bash
   # Create timesyncd configuration file
   sudo tee /etc/systemd/timesyncd.conf > /dev/null << EOF
   [Time]
   NTP=ntp.ubuntu.com
   FallbackNTP=0.ubuntu.pool.ntp.org 1.ubuntu.pool.ntp.org 2.ubuntu.pool.ntp.org 3.ubuntu.pool.ntp.org
   EOF

   # Enable and restart the timesyncd service
   sudo systemctl restart systemd-timesyncd.service
   sudo timedatectl set-ntp true
   ```

5. Configure locale:

   ```bash
   sudo tee /etc/default/locale > /dev/null << EOF
   LANG="en_US.UTF-8"
   LC_TIME="en_US.UTF-8"
   EOF

   sudo localectl set-locale LANG="en_US.UTF-8" LC_TIME="en_US.UTF-8"
   ```

## Wireguard Installation

Perform these steps on both Alice and Bob servers:

1. Enable IP forwarding:

   ```bash
   sudo tee /etc/sysctl.d/99-wireguard.conf > /dev/null << EOF
   net.ipv4.ip_forward = 1
   net.ipv4.conf.all.forwarding = 1
   EOF

   sudo sysctl -p /etc/sysctl.d/99-wireguard.conf
   ```

2. Install Wireguard:

   ```bash
   sudo apt install -y wireguard wireguard-tools
   ```

3. Create the Wireguard configuration files for each host:

   ```bash
   # Create the wireguard directory if it doesn't exist
   sudo mkdir -p /etc/wireguard
   ```

   **For Alice**:
   ```bash
   sudo tee /etc/wireguard/qcicat0.conf > /dev/null << EOF
   [Interface]
   Address = 10.127.254.9/30, fdac::1/64
   ListenPort = 44222
   PrivateKey = <ALICE_PRIVATE_KEY>

   [Peer]
   PublicKey = <BOB_PUBLIC_KEY>
   PresharedKey = <WIREGUARD_PSK>
   AllowedIPs = 100.127.255.210/32, 100.127.255.211/32, 10.127.254.10/32, fdac::/64
   Endpoint = <BOB_IP>:53991
   EOF
   ```

   **For Bob**:
   ```bash
   sudo tee /etc/wireguard/qcicat0.conf > /dev/null << EOF
   [Interface]
   Address = 10.127.254.10/30, fdac::2/64
   ListenPort = 53991
   PrivateKey = <BOB_PRIVATE_KEY>

   [Peer]
   PublicKey = <ALICE_PUBLIC_KEY>
   PresharedKey = <WIREGUARD_PSK>
   AllowedIPs = 100.127.255.82/32, 100.127.255.83/32, 10.127.254.9/32, fdac::/64
   Endpoint = <ALICE_IP>:44222
   EOF
   ```

4. Set proper permissions and secure the configuration file:

   ```bash
   sudo chmod 600 /etc/wireguard/qcicat0.conf
   ```

5. Enable and start the Wireguard service:

   ```bash
   sudo systemctl enable wg-quick@qcicat0
   sudo systemctl start wg-quick@qcicat0
   ```

## Rosenpass Installation

> Note: This section is only required if you want to enable Post-Quantum Cryptography (PQC) mode.

Perform these steps on both Alice and Bob servers:

1. Create required directories:

   ```bash
   sudo mkdir -p /opt/rosenpass
   sudo mkdir -p /opt/rosenpass/alice  # on Alice's server
   sudo mkdir -p /opt/rosenpass/bob    # on both servers
   sudo mkdir -p /opt/rosenpass/key_out
   ```

2. Download and extract Rosenpass:

   ```bash
   wget https://github.com/rosenpass/rosenpass/releases/download/v0.2.2/rosenpass-x86_64-linux-0.2.2.tar -O /tmp/rosenpass.tar
   sudo tar -xf /tmp/rosenpass.tar -C /opt/rosenpass
   ```

3. Create a symlink to the binary:

   ```bash
   sudo ln -sf /opt/rosenpass/bin/rosenpass /usr/local/sbin/rosenpass
   ```

4. Copy your pre-generated Rosenpass keys to the appropriate directories:

   **For Alice**:
   ```bash
   sudo cp <ALICE_PRIVATE_KEY_FILE> /opt/rosenpass/alice/pqsk
   sudo cp <ALICE_PUBLIC_KEY_FILE> /opt/rosenpass/alice/pqpk
   sudo cp <BOB_PUBLIC_KEY_FILE> /opt/rosenpass/bob/pqpk

   sudo chmod 640 /opt/rosenpass/alice/pqsk
   sudo chmod 640 /opt/rosenpass/alice/pqpk
   sudo chmod 640 /opt/rosenpass/bob/pqpk
   ```

   **For Bob**:
   ```bash
   sudo cp <BOB_PRIVATE_KEY_FILE> /opt/rosenpass/bob/pqsk
   sudo cp <BOB_PUBLIC_KEY_FILE> /opt/rosenpass/bob/pqpk
   sudo cp <ALICE_PUBLIC_KEY_FILE> /opt/rosenpass/alice/pqpk

   sudo chmod 640 /opt/rosenpass/bob/pqsk
   sudo chmod 640 /opt/rosenpass/bob/pqpk
   sudo chmod 640 /opt/rosenpass/alice/pqpk
   ```

5. Create the Rosenpass configuration file:

   **For Alice (client mode)**:
   ```bash
   sudo tee /opt/rosenpass/rp.toml > /dev/null << EOF
   ## rp.toml ###################################
   secret_key = "/opt/rosenpass/alice/pqsk"
   public_key = "/opt/rosenpass/alice/pqpk"
   listen = ["[::]:9998"]
   verbosity = "Verbose"

   [[peers]]
   public_key = "/opt/rosenpass/bob/pqpk"
   endpoint = "<BOB_IP>:9998"
   key_out = "/opt/rosenpass/key_out/pqc_psk"
   EOF
   ```

   **For Bob (server mode)**:
   ```bash
   sudo tee /opt/rosenpass/rp.toml > /dev/null << EOF
   ## rp.toml ###################################
   secret_key = "/opt/rosenpass/bob/pqsk"
   public_key = "/opt/rosenpass/bob/pqpk"
   listen = ["<BOB_IP>:9998"]
   verbosity = "Verbose"

   [[peers]]
   public_key = "/opt/rosenpass/alice/pqpk"
   # No endpoint as this is server mode
   key_out = "/opt/rosenpass/key_out/pqc_psk"
   EOF
   ```

6. Create a systemd service for Rosenpass:

   ```bash
   sudo tee /etc/systemd/system/rp.service > /dev/null << EOF
   # /etc/systemd/system/rp.service
   [Unit]
   Description=Rosenpass PQC Service

   [Service]
   Type=simple
   ExecStart=/opt/rosenpass/bin/rosenpass exchange-config /opt/rosenpass/rp.toml
   Restart=on-failure

   [Install]
   WantedBy=multi-user.target
   EOF
   ```

7. Enable and start the Rosenpass service:

   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable rp.service
   sudo systemctl start rp.service
   ```

## KMS Installation

> Note: This section is only required if you want to enable KMS (Key Management System) mode.

Perform these steps on both Alice and Bob servers:

1. Create the KMS directory:

   ```bash
   sudo mkdir -p /opt/kms
   ```

2. Download and extract the KMS simulator:

   ```bash
   wget https://github.com/arnika-project/arnika/releases/download/v0.2.1/kms-v0.2.1_linux_arm64.tar.gz -O /tmp/kms.tar.gz
   sudo tar -xzf /tmp/kms.tar.gz -C /opt/kms
   ```

3. Create a symlink to the binary:

   ```bash
   sudo ln -sf /opt/kms/kms /usr/local/sbin/kms
   ```

4. Create a systemd service for KMS:

   ```bash
   sudo tee /etc/systemd/system/kms.service > /dev/null << EOF
   # /etc/systemd/system/kms.service
   [Unit]
   Description=KMS ETSI014 Simulator on http://127.0.0.1:8080

   [Service]
   Type=simple
   ExecStart=/opt/kms/kms
   Restart=on-failure

   [Install]
   WantedBy=multi-user.target
   EOF
   ```

5. Enable and start the KMS service:

   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable kms.service
   sudo systemctl start kms.service
   ```

## Arnika Installation

Perform these steps on both Alice and Bob servers:

1. Create required directories:

   ```bash
   sudo mkdir -p /opt/arnika
   sudo mkdir -p /opt/arnika/kms_certs
   ```

2. Download and extract Arnika:

   ```bash
   wget https://github.com/arnika-project/arnika/releases/download/v0.2.2/arnika-v0.2.2_linux_amd64.tar.gz -O /tmp/arnika.tar.gz
   sudo tar -xzf /tmp/arnika.tar.gz -C /opt/arnika
   ```

3. Create a symlink to the binary:

   ```bash
   sudo ln -sf /opt/arnika/arnika /usr/local/sbin/arnika
   ```

4. Copy certificates for KMS (if using KMS mode):

   **For Alice**:
   ```bash
   sudo cp <CA_CERT_FILE> /opt/arnika/kms_certs/ca.crt
   sudo cp <ALICE_CERT_FILE> /opt/arnika/kms_certs/arnika-alice.crt
   sudo cp <ALICE_KEY_FILE> /opt/arnika/kms_certs/arnika-alice.key

   sudo chmod 660 /opt/arnika/kms_certs/*
   ```

   **For Bob**:
   ```bash
   sudo cp <CA_CERT_FILE> /opt/arnika/kms_certs/ca.crt
   sudo cp <BOB_CERT_FILE> /opt/arnika/kms_certs/arnika-bob.crt
   sudo cp <BOB_KEY_FILE> /opt/arnika/kms_certs/arnika-bob.key

   sudo chmod 660 /opt/arnika/kms_certs/*
   ```

5. Create an environment file for Arnika:

   **For Alice**:
   ```bash
   sudo tee /opt/arnika/arnika.env > /dev/null << EOF
   INTERVAL="120s"
   LISTEN_ADDRESS="<ALICE_IP>:9999"
   SERVER_ADDRESS="<BOB_IP>:9999"
   CERTIFICATE="/opt/arnika/kms_certs/arnika-alice.crt"
   PRIVATE_KEY="/opt/arnika/kms_certs/arnika-alice.key"
   CA_CERTIFICATE="/opt/arnika/kms_certs/ca.crt"
   KMS_URL="https://<ALICE_KMS_SERVER>:7000/api/v1/keys/arnika-bob"
   WIREGUARD_INTERFACE="qcicat0"
   WIREGUARD_PEER_PUBLIC_KEY="<BOB_WIREGUARD_PUBLIC_KEY>"
   # Uncomment if using PQC mode:
   PQC_PSK_FILE="/opt/rosenpass/key_out/pqc_psk"
   EOF
   ```

   **For Bob**:
   ```bash
   sudo tee /opt/arnika/arnika.env > /dev/null << EOF
   INTERVAL="120s"
   LISTEN_ADDRESS="<BOB_IP>:9999"
   SERVER_ADDRESS="<ALICE_IP>:9999"
   CERTIFICATE="/opt/arnika/kms_certs/arnika-bob.crt"
   PRIVATE_KEY="/opt/arnika/kms_certs/arnika-bob.key"
   CA_CERTIFICATE="/opt/arnika/kms_certs/ca.crt"
   KMS_URL="https://<BOB_KMS_SERVER>:7000/api/v1/keys/arnika-alice"
   WIREGUARD_INTERFACE="qcicat0"
   WIREGUARD_PEER_PUBLIC_KEY="<ALICE_WIREGUARD_PUBLIC_KEY>"
   # Uncomment if using PQC mode:
   PQC_PSK_FILE="/opt/rosenpass/key_out/pqc_psk"
   EOF
   ```

6. Create a systemd service for Arnika:

   ```bash
   sudo tee /etc/systemd/system/arnika.service > /dev/null << EOF
   # /etc/systemd/system/arnika.service
   [Unit]
   Description=Arnika Quantum Secure VPN
   After=wg-quick.target
   Requires=wg-quick.target

   [Service]
   Type=simple
   ExecStart=/opt/arnika/arnika
   EnvironmentFile=/opt/arnika/arnika.env
   Restart=on-failure

   [Install]
   WantedBy=multi-user.target
   EOF
   ```

7. Enable and start the Arnika service:

   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable arnika.service
   sudo systemctl start arnika.service
   ```

## Tools Installation

Perform these steps on both Alice and Bob servers:

1. Install required packages for tools:

   ```bash
   sudo apt install -y tmux fping curl iperf3 iftop mtr
   ```

2. Create a directory for the tools:

   ```bash
   sudo mkdir -p /opt/arnika-tools
   ```

3. Create utility scripts:

   **KMS key request script** (for retrieving and managing keys from the KMS server):
   ```bash
   sudo tee /opt/arnika-tools/keyreq.sh > /dev/null << EOF
   #!/bin/bash

   INPUT="\$1"

   KMS=https://<KMS_SERVER>:7000
   SAE_ID="arnika-bob"  # Use "arnika-alice" on Bob's server

   CACERT="/opt/arnika/kms_certs/ca.crt"
   CERT="/opt/arnika/kms_certs/arnika-alice.crt"  # Use "arnika-bob.crt" on Bob's server
   KEY="/opt/arnika/kms_certs/arnika-alice.key"   # Use "arnika-bob.key" on Bob's server

   if [[ ! -n "\$INPUT" ]]
   then
       echo "Usage: \$0 status, new, <keyid>"
       exit 1
   fi

   if [[ "\$INPUT" == "status" ]]
   then
       echo "STATUS:"
       curl --url \$KMS/api/v1/keys/\$SAE_ID/status --cacert \$CACERT --cert \$CERT --key \$KEY --header "Content-Type: application/json"
   elif [[ "\$INPUT" == "new" ]]
   then
       echo "NEW KEY:"
       curl --url \$KMS/api/v1/keys/\$SAE_ID/enc_keys --cacert \$CACERT --cert \$CERT --key \$KEY --header "Content-Type: application/json"
   else
       echo "KEY_ID:"
       curl --url \$KMS/api/v1/keys/\$SAE_ID/dec_keys?key_ID=\$INPUT --cacert \$CACERT --cert \$CERT --key \$KEY --header "Content-Type: application/json"
   fi
   EOF
   ```

   **Arnika service management script** (for starting/stopping all services):
   ```bash
   sudo tee /opt/arnika-tools/init_arnika.sh > /dev/null << EOF
   #!/bin/bash

   INPUT="\$1"

   if [[ ! -n "\$INPUT" ]]
   then
       echo "Usage: \$0 start, stop, status"
       exit 1
   fi

   if [[ "\$INPUT" == "start" ]]
   then
       echo "start: systemctl start wg-quick@qcicat0 rp kms arnika"
       systemctl start wg-quick@qcicat0 rp kms arnika
   elif [[ "\$INPUT" == "stop" ]]
   then
       echo "stop: systemctl stop wg-quick@qcicat0 rp kms arnika"
       systemctl stop wg-quick@qcicat0 rp kms arnika
   else
       echo "status: systemctl status wg-quick@qcicat0 rp kms arnika"
       systemctl status wg-quick@qcicat0 rp kms arnika
   fi

   echo
   echo "journalctl -f -u wg-quick@qcicat0 -u arnika -u rp -u kms"
   echo
   EOF
   ```

   **Wireguard show script** (displays the current Wireguard status):
   ```bash
   sudo tee /opt/arnika-tools/wg-show.sh > /dev/null << EOF
   #!/bin/bash
   wg show
   EOF
   ```

   **Wireguard watch script** (continuously monitors Wireguard status):
   ```bash
   sudo tee /opt/arnika-tools/wg-watch.sh > /dev/null << EOF
   #!/bin/bash
   watch -n 1 wg show
   EOF
   ```

   **Tmux init script** (for starting all services in tmux sessions):
   ```bash
   sudo tee /opt/arnika-tools/init_tmux.sh > /dev/null << EOF
   #!/bin/sh

   wg-quick up qcicat0

   wg showconf qcicat0

   # For PQC mode
   tmux new -d -s rp 'rosenpass exchange-config /opt/rosenpass/rp.toml' \;

   # For KMS mode
   tmux new -d -s kms '/opt/kms/kms' \;

   # Arnika
   tmux new -d -s arnika 'env \$(cat /opt/arnika/arnika.env | xargs) /opt/arnika/arnika' \;

   # WG watch
   tmux new -d -s wg 'wg-watch.sh' \;

   # Ping
   # For Alice
   tmux new -d -s ping 'fping -l -D -e -o -s fdac::2' \;
   # For Bob, uncomment:
   # tmux new -d -s ping 'fping -l -D -e -o -s fdac::1' \;
   EOF
   ```

   **Fping init script** (for monitoring connectivity):
   ```bash
   sudo tee /opt/arnika-tools/init_fping.sh > /dev/null << EOF
   #!/bin/bash

   # On Alice:
   fping -l -D -e -o -s fdac::2

   # On Bob (uncomment):
   # fping -l -D -e -o -s fdac::1
   EOF
   ```

   **Iperf init script** (for testing network performance):
   ```bash
   sudo tee /opt/arnika-tools/init_iperf.sh > /dev/null << EOF
   #!/bin/bash

   # On Alice (server):
   iperf3 -s

   # On Bob (client, uncomment):
   # iperf3 -c 10.127.254.9
   EOF
   ```

   **Tcpdump init script** (for capturing and analyzing packets):
   ```bash
   sudo tee /opt/arnika-tools/init_tcpdump.sh > /dev/null << EOF
   #!/bin/bash

   tcpdump -i qcicat0 -n
   EOF
   ```

4. Make the scripts executable and create symlinks:

   ```bash
   sudo chmod 750 /opt/arnika-tools/*.sh

   sudo ln -sf /opt/arnika-tools/keyreq.sh /usr/local/sbin/keyreq.sh
   sudo ln -sf /opt/arnika-tools/wg-show.sh /usr/local/sbin/wg-show.sh
   sudo ln -sf /opt/arnika-tools/wg-watch.sh /usr/local/sbin/wg-watch.sh
   sudo ln -sf /opt/arnika-tools/init_arnika.sh /usr/local/sbin/init_arnika.sh
   sudo ln -sf /opt/arnika-tools/init_tmux.sh /usr/local/sbin/init_tmux.sh
   sudo ln -sf /opt/arnika-tools/init_fping.sh /usr/local/sbin/init_fping.sh
   sudo ln -sf /opt/arnika-tools/init_iperf.sh /usr/local/sbin/init_iperf.sh
   sudo ln -sf /opt/arnika-tools/init_tcpdump.sh /usr/local/sbin/init_tcpdump.sh
   ```

## Service Management

You can manage all services using the provided `init_arnika.sh` script:

```bash
# Start all services
init_arnika.sh start

# Check status of all services
init_arnika.sh status

# Stop all services
init_arnika.sh stop
```

Or manage individual services with systemctl:

```bash
# Wireguard
sudo systemctl status wg-quick@qcicat0
sudo systemctl start wg-quick@qcicat0
sudo systemctl stop wg-quick@qcicat0

# Rosenpass (PQC mode)
sudo systemctl status rp
sudo systemctl start rp
sudo systemctl stop rp

# KMS (KMS mode)
sudo systemctl status kms
sudo systemctl start kms
sudo systemctl stop kms

# Arnika
sudo systemctl status arnika
sudo systemctl start arnika
sudo systemctl stop arnika
```

Alternatively, you can use the `init_tmux.sh` script to start all services in separate tmux sessions:

```bash
init_tmux.sh
```

This allows you to manage and monitor each service easily. You can attach to any session using:

```bash
tmux attach -t [session_name]  # where session_name is: rp, kms, arnika, wg, ping
```

## Verification

1. Check that all services are running:

   ```bash
   init_arnika.sh status
   ```

2. Verify Wireguard configuration:

   ```bash
   wg-show.sh
   ```

3. If using KMS, check key status:

   ```bash
   keyreq.sh status
   ```

4. Check logs for any issues:

   ```bash
   journalctl -u wg-quick@qcicat0
   journalctl -u rp
   journalctl -u kms
   journalctl -u arnika
   ```

5. Test connectivity between Alice and Bob:

   **On Alice**:
   ```bash
   # Ping Bob's IPv6 address
   ping fdac::2

   # Ping Bob's IPv4 address
   ping 10.127.254.10
   ```

   **On Bob**:
   ```bash
   # Ping Alice's IPv6 address
   ping fdac::1

   # Ping Alice's IPv4 address
   ping 10.127.254.9
   ```

6. Test network performance (optional):

   **On Alice**:
   ```bash
   init_iperf.sh
   ```

   **On Bob**:
   ```bash
   # Edit the script first to uncomment the client line
   init_iperf.sh
   ```

This completes the manual installation of the Arnika Quantum-Secure VPN system on both Alice and Bob servers.
