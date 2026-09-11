# Arnika Quantum-Secure VPN Installation Guide

Manual installation of Arnika and its dependencies on Ubuntu, for a pair of peers named **Alice**
and **Bob** joined by a single WireGuard tunnel.

## Table of Contents

- [Arnika Quantum-Secure VPN Installation Guide](#arnika-quantum-secure-vpn-installation-guide)
  - [Table of Contents](#table-of-contents)
  - [Prerequisites](#prerequisites)
  - [Ubuntu System Configuration](#ubuntu-system-configuration)
  - [Wireguard Installation](#wireguard-installation)
  - [PQC key provider Installation](#pqc-key-provider-installation)
  - [Build from Source](#build-from-source)
  - [KMS Installation](#kms-installation)
  - [Arnika Installation](#arnika-installation)
  - [Tools Installation](#tools-installation)
  - [Service Management](#service-management)
  - [Verification](#verification)

## Prerequisites

- Ubuntu operating system
- Root or sudo access
- Internet connectivity
- Pre-generated Wireguard keys for both hosts (private keys, public keys, and PSK)
- A shared Arnika peer secret (`ARNIKA_PSK`) — one value used on **both** hosts, generated with
  `openssl rand -base64 32`. It is mandatory and must be at least 32 bytes: Arnika refuses to
  start otherwise, and a chosen passphrase is not acceptable
- (Optional) PQC keys for PQC mode
- (Optional) KMS certificates for KMS mode
- Build tools to compile Arnika from source: `git`, `make` and a **Go 1.26+** toolchain — see
  [Build from Source](#build-from-source)

> [!NOTE]
> This guide installs the default **netlink** key writer, which requires Arnika and WireGuard on
> the same host. To rotate the PSK on a remote MikroTik router instead, build with the
> `wireguard_mikrotik` tag and follow
> [`docs/wireguard-mikrotik.md`](docs/wireguard-mikrotik.md). Building from source requires
> **Go 1.26+** and `GOEXPERIMENT=runtimesecret` — see [`KEYCONTROL.md`](KEYCONTROL.md).

## Ubuntu System Configuration

Run on both Alice and Bob:

- Update the package repositories and upgrade installed packages:

  ```bash
  sudo apt update
  sudo apt upgrade -y
  ```

- Install required packages:

  ```bash
  sudo apt install -y net-tools iputils-ping dnsutils socat less vim tmux lsof traceroute tcptraceroute fping htop bash-completion jq iotop apt-transport-https ca-certificates curl
  ```

- Set the timezone:

  ```bash
  sudo timedatectl set-timezone Europe/Vienna
  ```

- Configure time synchronization:

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

- Configure locale:

  ```bash
  sudo tee /etc/default/locale > /dev/null << EOF
  LANG="en_US.UTF-8"
  LC_TIME="en_US.UTF-8"
  EOF

  sudo localectl set-locale LANG="en_US.UTF-8" LC_TIME="en_US.UTF-8"
  ```

## Wireguard Installation

Run on both Alice and Bob:

- Enable IP forwarding:

  ```bash
  sudo tee /etc/sysctl.d/99-wireguard.conf > /dev/null << EOF
  net.ipv4.ip_forward = 1
  net.ipv4.conf.all.forwarding = 1
  EOF

  sudo sysctl -p /etc/sysctl.d/99-wireguard.conf
  ```

- Install Wireguard:

  ```bash
  sudo apt install -y wireguard wireguard-tools
  ```

- Create the Wireguard configuration files for each host:

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

- Set proper permissions and secure the configuration file:

  ```bash
  sudo chmod 600 /etc/wireguard/qcicat0.conf
  ```

- Enable and start the Wireguard service:

  ```bash
  sudo systemctl enable wg-quick@qcicat0
  sudo systemctl start wg-quick@qcicat0
  ```

## PQC key provider Installation

> [!NOTE]
> Only required for Post-Quantum Cryptography (PQC) mode.

**No external PQC provider is required.** Arnika agrees the PQC key with its peer itself, using
HPKE (RFC 9180) over the socket it already binds: no daemon to install, no key on disk, no extra
port. It is **enabled by default** on both peers — see
[`docs/pqc-hpke.md`](docs/pqc-hpke.md). Set `PQC_ENABLED="false"` to run QKD-only.

Earlier releases read the key via file from an external PQC provider, configured with
`PQC_PSK_FILE`. That mechanism has been removed; the variable is ignored.

## Build from Source

Arnika 2.x lives on the `main` branch, so both binaries are built from source rather than
downloaded from a release. They are statically linked and self-contained: build once per
architecture and copy the binaries to both hosts, or repeat these steps on Alice and Bob.

- Install the build dependencies. Go **1.26 or newer** is required and distribution packages are
  usually older, so install the official toolchain:

  ```bash
  sudo apt install -y git make curl

  GOVER=1.26.0        # or any newer 1.26+ release from https://go.dev/dl/
  curl -fsSLO https://go.dev/dl/go${GOVER}.linux-amd64.tar.gz
  sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go${GOVER}.linux-amd64.tar.gz
  export PATH=/usr/local/go/bin:$PATH
  ```

  ```shell
  $ go version
  go version go1.26.0 linux/amd64
  ```

- Clone the repository:

  ```bash
  git clone https://github.com/arnika-project/arnika.git ~/arnika
  cd ~/arnika
  ```

- Build Arnika:

  ```bash
  make build
  ```

  The result is `~/arnika/build/arnika`, built with the default **netlink** key writer — the PSK
  is written into a local kernel WireGuard interface, which is what the rest of this guide
  assumes.

  > [!IMPORTANT]
  > Arnika needs `GOEXPERIMENT=runtimesecret` for its `runtime/secret` memory hardening.
  > `make build` sets it; a plain `go build .` fails. To rotate the PSK on a remote MikroTik
  > router instead, build with `make build-mikrotik` and follow
  > [`docs/wireguard-mikrotik.md`](docs/wireguard-mikrotik.md) rather than the steps below.

- Build the KMS simulator, only if you intend to use the bundled simulator instead of a real
  ETSI GS QKD 014 KMS:

  ```bash
  go build -o build/kms ./tools
  ```

  The simulator does not use `runtime/secret`, so it needs no `GOEXPERIMENT`.

- Confirm both binaries are present and self-contained:

  ```bash
  ls -l build/
  file build/arnika build/kms      # "statically linked"
  ```

  To cross-build for another architecture (e.g. on an amd64 workstation for an arm64 host):

  ```bash
  GOOS=linux GOARCH=arm64 make build BINARY_NAME=arnika-linux-arm64
  ```

## KMS Installation

> [!NOTE]
> Only required if you use the bundled KMS simulator instead of a real ETSI GS QKD 014 KMS. See
> [`KMS.md`](KMS.md) for its endpoints and limitations.

Run on both Alice and Bob:

- Create the KMS directory:

  ```bash
  sudo mkdir -p /opt/kms
  ```

- Install the KMS simulator binary built in [Build from Source](#build-from-source):

  ```bash
  sudo install -o root -g root -m 0755 ~/arnika/build/kms /opt/kms/kms
  ```

- Create a symlink to the binary:

  ```bash
  sudo ln -sf /opt/kms/kms /usr/local/sbin/kms
  ```

- Create a systemd service for KMS:

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

- Enable and start the KMS service:

  ```bash
  sudo systemctl daemon-reload
  sudo systemctl enable kms.service
  sudo systemctl start kms.service
  ```

## Arnika Installation

Run on both Alice and Bob:

- Create required directories:

  ```bash
  sudo mkdir -p /opt/arnika
  sudo mkdir -p /opt/arnika/kms_certs
  ```

- Install the Arnika binary built in [Build from Source](#build-from-source):

  ```bash
  sudo install -o root -g root -m 0755 ~/arnika/build/arnika /opt/arnika/arnika
  ```

  To upgrade later: `git pull` in `~/arnika`, run `make build` again, then stop the service,
  re-run this `install` command and start the service.

- Create a symlink to the binary:

  ```bash
  sudo ln -sf /opt/arnika/arnika /usr/local/sbin/arnika
  ```

- Copy certificates for KMS (if using KMS mode):

  **For Alice**:

  ```bash
  sudo cp <CA_CERT_FILE> /opt/arnika/kms_certs/ca.crt
  sudo cp <ALICE_CERT_FILE> /opt/arnika/kms_certs/arnika-alice.crt
  sudo cp <ALICE_KEY_FILE> /opt/arnika/kms_certs/arnika-alice.key

  sudo chmod 644 /opt/arnika/kms_certs/*.crt
  sudo chmod 600 /opt/arnika/kms_certs/*.key
  ```

  **For Bob**:

  ```bash
  sudo cp <CA_CERT_FILE> /opt/arnika/kms_certs/ca.crt
  sudo cp <BOB_CERT_FILE> /opt/arnika/kms_certs/arnika-bob.crt
  sudo cp <BOB_KEY_FILE> /opt/arnika/kms_certs/arnika-bob.key

  sudo chmod 644 /opt/arnika/kms_certs/*.crt
  sudo chmod 600 /opt/arnika/kms_certs/*.key
  ```

- Create an environment file for Arnika:

  **For Alice**:

  ```bash
  sudo tee /opt/arnika/arnika.env > /dev/null << EOF
  INTERVAL="120s"
  LISTEN_ADDRESS="<ALICE_IP>:9999"
  SERVER_ADDRESS="<BOB_IP>:9999"
  ARNIKA_ID="9999"
  ARNIKA_PSK="<SHARED_ARNIKA_PSK>"
  # KMS client certificate (KMS connection only - not the peer channel):
  CERTIFICATE="/opt/arnika/kms_certs/arnika-alice.crt"
  PRIVATE_KEY="/opt/arnika/kms_certs/arnika-alice.key"
  CA_CERTIFICATE="/opt/arnika/kms_certs/ca.crt"
  KMS_URL="https://<ALICE_KMS_SERVER>:7000/api/v1/keys/arnika-bob"
  WIREGUARD_INTERFACE="qcicat0"
  WIREGUARD_PEER_PUBLIC_KEY="<BOB_WIREGUARD_PUBLIC_KEY>"
  # The PQC key agreement is on by default; uncomment to run QKD-only
  # (must match on both peers):
  #PQC_ENABLED="false"
  EOF

  sudo chmod 600 /opt/arnika/arnika.env
  ```

  **For Bob**:

  ```bash
  sudo tee /opt/arnika/arnika.env > /dev/null << EOF
  INTERVAL="120s"
  LISTEN_ADDRESS="<BOB_IP>:9999"
  SERVER_ADDRESS="<ALICE_IP>:9999"
  ARNIKA_ID="9998"
  ARNIKA_PSK="<SHARED_ARNIKA_PSK>"
  # KMS client certificate (KMS connection only - not the peer channel):
  CERTIFICATE="/opt/arnika/kms_certs/arnika-bob.crt"
  PRIVATE_KEY="/opt/arnika/kms_certs/arnika-bob.key"
  CA_CERTIFICATE="/opt/arnika/kms_certs/ca.crt"
  KMS_URL="https://<BOB_KMS_SERVER>:7000/api/v1/keys/arnika-alice"
  WIREGUARD_INTERFACE="qcicat0"
  WIREGUARD_PEER_PUBLIC_KEY="<ALICE_WIREGUARD_PUBLIC_KEY>"
  # The PQC key agreement is on by default; uncomment to run QKD-only
  # (must match on both peers):
  #PQC_ENABLED="false"
  EOF

  sudo chmod 600 /opt/arnika/arnika.env
  ```

  > [!IMPORTANT]
  > Three values must line up between the two peers, or key rotation silently misbehaves:
  >
  > - **`ARNIKA_PSK` must be identical.** It authenticates and encrypts the peer channel. If it
  >   is unset, Arnika starts but the channel keys derive from the empty string and offer no
  >   protection.
  > - **`ARNIKA_ID` must differ in parity** — one odd, one even (`9999` and `9998` above). Only
  >   the lowest bit takes part in PRIMARY/BACKUP election, so two even or two odd IDs make both
  >   peers pick the *same* role every interval. Without an explicit `ARNIKA_ID` each peer
  >   defaults to its own listen port, which is `9999` on both hosts here — identical, and
  >   therefore broken.
  > - **`INTERVAL` must be identical.** Roles are elected per interval number, so different
  >   interval lengths drift the two peers apart. Earlier releases suggested offsetting Bob's
  >   interval to avoid flapping; that is obsolete and now harmful.

  <!-- -->

  > [!NOTE]
  > The `KMS_URL` above points at a real KMS. With the bundled simulator instead, use
  > `http://127.0.0.1:8080/api/v1/keys/CONSA` on Alice and `.../CONSB` on Bob, and leave
  > `CERTIFICATE`, `PRIVATE_KEY` and `CA_CERTIFICATE` unset — the simulator is HTTP-only and
  > needs no client certificate.

- Create a systemd service for Arnika:

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

  > [!NOTE]
  > This unit runs Arnika as `root`, which is acceptable for a lab or PoC. For production, add a
  > dedicated service user with `AmbientCapabilities=CAP_NET_ADMIN` and the isolation directives
  > from the hardening snippet in [`SECURITY.md`](SECURITY.md).

- Enable and start the Arnika service:

  ```bash
  sudo systemctl daemon-reload
  sudo systemctl enable arnika.service
  sudo systemctl start arnika.service
  ```

## Tools Installation

Run on both Alice and Bob:

- Install required packages for tools:

  ```bash
  sudo apt install -y tmux fping curl iperf3 iftop mtr
  ```

- Create a directory for the tools:

  ```bash
  sudo mkdir -p /opt/arnika-tools
  ```

- Create utility scripts:

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
      echo "start: systemctl start wg-quick@qcicat0 kms arnika"
      systemctl start wg-quick@qcicat0 kms arnika
  elif [[ "\$INPUT" == "stop" ]]
  then
      echo "stop: systemctl stop wg-quick@qcicat0 kms arnika"
      systemctl stop wg-quick@qcicat0 kms arnika
  else
      echo "status: systemctl status wg-quick@qcicat0 kms arnika"
      systemctl status wg-quick@qcicat0 kms arnika
  fi

  echo
  echo "journalctl -f -u wg-quick@qcicat0 -u arnika -u kms"
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

- Make the scripts executable and create symlinks:

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

Manage all services with the `init_arnika.sh` script:

```bash
# Start all services
init_arnika.sh start

# Check status of all services
init_arnika.sh status

# Stop all services
init_arnika.sh stop
```

Or individually with `systemctl`:

```bash
# Wireguard
sudo systemctl status wg-quick@qcicat0
sudo systemctl start wg-quick@qcicat0
sudo systemctl stop wg-quick@qcicat0

# KMS (KMS mode)
sudo systemctl status kms
sudo systemctl start kms
sudo systemctl stop kms

# Arnika
sudo systemctl status arnika
sudo systemctl start arnika
sudo systemctl stop arnika
```

To run the services in separate tmux sessions instead:

```bash
init_tmux.sh
```

Attach to a session with:

```bash
tmux attach -t <session>   # kms, arnika, wg or ping
```

## Verification

- Check that all services are running:

  ```bash
  init_arnika.sh status
  ```

- Verify Wireguard configuration:

  ```bash
  wg-show.sh
  ```

- If using KMS, check key status:

  ```bash
  keyreq.sh status
  ```

- Check logs for any issues:

  ```bash
  journalctl -u wg-quick@qcicat0
  journalctl -u kms
  journalctl -u arnika
  ```

  > [!NOTE]
  > The startup banner redacts `ARNIKA_PSK`, printing only its length.

- Verify that key rotation and role election work:

  ```bash
  journalctl -u arnika -f | grep -E 'PRIMARY|BACKUP'
  ```

  Across consecutive intervals exactly **one** of the two hosts must log `PRIMARY` at a time, and
  both must log `[OK] PSK configured on WireGuard interface`. If both hosts log `PRIMARY` for the
  same interval, or neither does, check that `ARNIKA_PSK` is identical, `INTERVAL` is identical,
  and the two `ARNIKA_ID` values differ in parity.

- Confirm WireGuard is actually receiving a PSK:

  ```bash
  sudo wg show qcicat0 preshared-keys
  ```

  An all-zero value means the PSK was never installed — the tunnel is running without quantum
  protection.

- Test connectivity between Alice and Bob:

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

- Test network performance (optional):

  **On Alice**:

  ```bash
  init_iperf.sh
  ```

  **On Bob**:

  ```bash
  # Edit the script first to uncomment the client line
  init_iperf.sh
  ```

Installation is complete on both hosts. Before going to production, work through the deployment
checklist in [`SECURITY.md`](SECURITY.md) — it covers service users and capabilities, the
`ARNIKA_PSK` handling, certificate validation and log sensitivity.
