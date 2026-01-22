<!--
# Arnika - Quantum secure VPN
![Arnika](img/ARNIKA-logo_128_2x.png)
-->

<div align="center">
    <img src="img/ARNIKA_banner.png">
    <h1> Arnika - Quantum secure VPN</h1>
</div>


**Arnika** is a compact, **lightweight external extension for Wireguard VPN**, engineered to incorporate symmetric keys as Pre-Shared Keys (**PSK**) into Wireguard. This integration ensures the establishment of a quantum-secure VPN (safeguarding against compromise of session keys).

It gathers a 256-bit symmetric encryption key from a Key Management System (**KMS**) within a Quantum Key Distribution (**QKD**) infrastructure, shares the associated key ID with an Arnika peer, and configures an additional Pre-Shared Key (**PSK**) for Wireguard using the obtained key material.

Arnika offers an additional security layer for cryptography enthusiasts. It can integrate Post-Quantum Cryptography (**PQC**) by leveraging a PQC key provided by a system like **Rosenpass**. This key is then used to create an even stronger Preshared Key (PSK) for WireGuard. This PSK benefits from both **PQC** and **QKD**, offering enhanced protection against potential security threats.


Arnika integrates with WireGuard to establish quantum-resistant VPN connections, adding a significant layer of security to your communication

Arnika has been developed in scope of EU **EUROQCI** / **QCI-CAT** research program for the Use-Case **HSM BACKUP USING QKD** - https://qci-cat.at/hsm-backup-using-qkd

## Quantum secure VPN

![Arnika Encapsulation Pipe, Figure 1](img/Arnika-Encapsulations-pipe.png)
<br/>_Figure 1_

![Arnika Wireguard PSK, Figure 2](img/Arnika-Wireguard-PSK.png)
<br/>_Figure 2_

## Wireguard + Rosenpass + Arnika

SAE (Secure Application Entity) = Wireguard + Rosenpass + Arnika

### QKD and PQC to achieve quantum resistance

The approach of combining symmetric keys from Quantum Key Distribution (QKD) and/or Post-Quantum Cryptography (PQC) with [WireGuard](https://www.wireguard.com/) as preshared key (PSK) has been used to enhance the security to achieve a post-quantum secure VPN.

### QKD | PQC key handling

The setup supports 3 operational modes, A, B, and C
* (A) ... QKD mode
* (B) ... PQC mode
* (C) ... QKD+PQC hyprid mode

Regardless of the selected mode, WireGuard always receives a single 256bit (32byte) key as PSK which is used for WireGuard internal `MixKeyAndHash()` using **HKDF**.

_Figure 3_ shows the key path of 2 interconnected sites for the hyprid mode (C) (QKD+PQC). In this scenario, the **KEY-CONTROL function** serves as a control entity, responsible for obtaining a **key** and transferring it to the encryption function (WireGuard).


![QKD | PQC functions post-quantum secure VPN, Figure 3](img/QKD-PQC-functions_post-quantum-secure-VPN.png)
<br/>_Figure 3_

The QKD key is obtained via ETSI014 from the QKDs embedded KMS and the PQC key is obtained via API or pointer/filedescriptor from a source such as **Rosenpass** or an alternative/already existing PQC function/implementation.


Subsequently, the **KEY-CONTROL function** uses the **QKD key** and **PQC key** by using a **HKDF HMAC Key Derivation Function** with SHA3-256 as the hash function, to derive a single key from the two input keys (QKD, PQC).
The specific derivation function, whether **HKDF** or an alternative, is a topic open for discussion among cryptographic experts.


# Advantages

QKD/PQC operation on **Layer 3** offers several notable advantages:

* Very low keyrate -> 1key per 120seconds (Rekey-After-Time, Rekey-After-Messages)
* PQC/QKD keys can be injected as preshared key at runtime by design
* no change in existing WireGuard setups
* L3 based VPN can go over any existing, affortable, foreign infrastructure over the internet
* Rosenpass (PQC) already implemented in netbird commercial VPN service [Netbird](https://netbird.io/) that supports mesh functionality
* unaffected by patent "Method of integrating QKD with IPSec" (US7602919B2,CN101142779A,...)



---


# Requirements

The `Secure Application Entity` consists of following components running on a secure and hardened linux system:
* WireGuard
* Arnika
* Rosenpass (optional)

### WireGuard

WireGuard must be installed/setup separately before Arnika can be used. For further installation instructions, refer to the [WireGuard](https://www.wireguard.com/) homepage.

### Rosenpass

Rosenpass is optional, Arnika can run without Rosenpass / PQC, then it will run in QKD mode only. For further installation instructions, refer to the [Rosenpass](https://rosenpass.eu/) homepage.

### golang version

Version >1.22 => `golang-1.22`


# Limitations

> [!IMPORTANT]
> **ARNIKA** is intended to supply a **PSK** exclusively to a local WireGuard instance.
>
> As a result, **WireGuard** and **ARNIKA** are required to operate on the same host and kernel instance.
>
> A race condition may occur if **ARNIKA** is started in development environments on the same host at _exactly_ the same time.
> This is intentional and a consequence of the simple yet robust state mechanism.
> This will be changed in an upcoming major release and it has no impact on production and can be avoided by starting both with a random delay and using the recommended interval values.
>

---


# Install golang

## Ubuntu 22.04.x

```bash
apt install golang-1.22
export PATH=/usr/lib/go-1.22/bin/:$PATH
```

```shell
$ go version
go version go1.22.2 linux/amd64
```



> [!CAUTION]
> The default golang version shipped with Ubuntu 22.04 is outdated and does not meet the requirements. Install and use `golang-1.22` instead.
> ```shell
> $ apt install golang-go
> $ go version
> go version go1.18.1 linux/amd64
> $ make build
> /home/arnika/arnika/go.mod:3: invalid go version '1.22.1': > must match format 1.23
> ```


---


# Build binaries from source

> [!NOTE]
> **Arnika** and **kms** (mock) can be downloaded as a compiled binary from the release page and run without the need for golang.

Following steps are required to build the binaries from source.

The binaries can be copied to the target system (matching architecture) or directory and executed.
No further dependencies are required, all necessary libraries are statically linked, and the binaries are self-contained.

The configuration for **Arnika** is done via environment variables.

# compile Arnika

```bash
git clone git@github.com:arnika-project/arnika.git
cd arnika
go mod tidy
make build
```

```shell
nean@qcicat01:~/arnika$ make build
Building arnika
CGO_ENABLED=0 go build -trimpath -ldflags "-w -s -extldflags=-Wl,-Bsymbolic -X 'main.Version=v0.2.0-14-gd429061' -X 'main.APPName=arnika'" -o build/arnika .
go: downloading golang.org/x/crypto v0.8.0
go: downloading golang.zx2c4.com/wireguard/wgctrl v0.0.0-20230429144221-925a1e7659e6
go: downloading golang.zx2c4.com/wireguard v0.0.0-20230325221338-052af4a8072b
go: downloading github.com/mdlayher/genetlink v1.3.2
go: downloading github.com/mdlayher/netlink v1.7.2
go: downloading golang.org/x/sys v0.7.0
go: downloading golang.org/x/net v0.9.0
go: downloading github.com/josharian/native v1.1.0
go: downloading github.com/mdlayher/socket v0.4.1
go: downloading golang.org/x/sync v0.1.0
```

The result is a single binary `arnika` located in the new created subdirecory `build` (`build/arnika`).

```shell
./build/arnika
=== Arnika Configuration ===
Arnika Mode:              AtLeastQkdRequired
Arnika Interval:          10s
Arnika ID:                9999
Arnika Listen Address:    127.0.0.1:9999
Arnika Peer Address:      127.0.0.1:9998
KMS URL:                  http://localhost:8080/api/v1/keys/CONSA
KMS HTTP Timeout:         10s
KMS Backoff Max Retries:  5
KMS Backoff Base Delay:   100ms
KMS Retry Interval:       5s
Client Certificate:       (not configured)
Private Key:              (not configured)
CA Certificate:           (not configured)
PQC key provider:        DISABLED
WireGuard Interface:      qcicat0
WireGuard Peer PublicKey: ****************=
============================
2026/01/22 18:04:40.628630 [INFO] MASTER[9999] [REQ] request QKD key from http://localhost:8080/api/v1/keys/CONSA
2026/01/22 18:04:40.629081 [INFO] ARNIKA[9999] TCP server started on 127.0.0.1:9999
2026/01/22 18:04:40.635236 [INFO] MASTER[9999] [SND] send key_id ffffffff-fe92-4fdc-bef3-c0cdc73ff774 to 127.0.0.1:9998
2026/01/22 18:04:40.636669 [INFO] MASTER[9999] [OK] PSK configured on WireGuard interface: qcicat0 for peer: ****************=
2026/01/22 18:04:43.399193 [INFO] BACKUP[9999] [RCV] received key_id ffffffff-bcec-4858-838e-623c79eabf61 from 127.0.0.1:58905
2026/01/22 18:04:43.399195 [INFO] BACKUP[9999] [REQ] request QKD key for key_id ffffffff-bcec-4858-838e-623c79eabf61 from http://localhost:8080/api/v1/keys/CONSA
2026/01/22 18:04:43.399760 [INFO] BACKUP[9999] [OK] PSK configured on WireGuard interface: qcicat0 for peer: ****************=
2026/01/22 18:04:55.399323 [INFO] BACKUP[9999] [RCV] received key_id ffffffff-8a32-4540-9b78-7d4e1afebb5f from 127.0.0.1:58927
```

## compile QKD KMS simulator

```bash
git clone git@github.com:arnika-project/arnika.git
cd arnika/tools
go mod tidy
go build -o kms
```

The result is a single binary `kms` located in the new created subdirecory `tools` (`tools/kms`). If build without `-o` was used, it is recommended to rename it eg. to `kms` (`mv tools/tools tools/kms`).

> [!Note]
> **kms** aka `mock` is designed to test **Arnika**, it is **NOT** a full featured ETSI014 Simulator.
>
> pseudo values are used, if adoption is required please consider change the source code:
> * listening port is `8080`
> * `http` only
> * `CONSA` and `CONSB` as **SAE**
> * `key` and `key_ID`
> * key `size=256`
> * key `number=1`




---


# Start Dev Environment

## Start QKD KMS Simulator

To start the simulator using Go:

```bash
go run tools/mock.go
```

Or, if you have already compiled the binary:

```bash
tools/kms
```

The QKD KMS simulator is now accessible at `http://127.0.0.1:8080`.


## Start Arnika #1

```bash
http_proxy=http://127.0.0.1:8080 \
no_proxy=127.0.0.1 \
LISTEN_ADDRESS=127.0.0.1:9999 \
SERVER_ADDRESS=127.0.0.1:9998 \
INTERVAL=120s \
KMS_URL="http://localhost:8080/api/v1/keys/CONSA" \
WIREGUARD_INTERFACE=qcicat0 \
WIREGUARD_PEER_PUBLIC_KEY="****************=" \
build/arnika
```


## Start Arnika #2

```bash
http_proxy=http://127.0.0.1:8080 \
no_proxy=127.0.0.1 \
LISTEN_ADDRESS=127.0.0.1:9998 \
SERVER_ADDRESS=127.0.0.1:9999 \
INTERVAL=120s \
KMS_URL="http://localhost:8080/api/v1/keys/CONSB" \
WIREGUARD_INTERFACE=qcicat0 \
WIREGUARD_PEER_PUBLIC_KEY="****************=" \
build/arnika
```


# Configuration

Arnika must be configured via environment variables, following are available:

| Variable                  | Description                                                                                                  | Example                                  |
|---------------------------|--------------------------------------------------------------------------------------------------------------|------------------------------------------|
| LISTEN_ADDRESS            | IP address and port where Arnika listens for incoming connections                                            | 127.0.0.1:9998                           |
| SERVER_ADDRESS            | IP address and port of the remote Arnika peer to connect to                                                  | 127.0.0.1:9998                           |
| CERTIFICATE               | File path to the TLS certificate used for secure communication                                               | /etc/ssl/certs/arnika.crt                |
| PRIVATE_KEY               | File path to the private key corresponding to the TLS certificate                                            | /etc/ssl/private/arnika.key              |
| CA_CERTIFICATE            | File path to the CA certificate bundle for verifying peer certificates                                       | /etc/ssl/certs/ca-bundle.crt             |
| KMS_HTTP_TIMEOUT          | Timeout duration for HTTP requests to the KMS (ETSI014)                                                      | 10s                                      |
| KMS_URL                   | URL endpoint of the ETSI014 QKD Key Management System                                                        | https://localhost:8080/api/v1/keys/CONSA |
| KMS_BACKOFF_MAX_RETRIES   | Maximum number of retry attempts for failed KMS requests                                                     | 5                                        |
| KMS_BACKOFF_BASE_DELAY    | Initial delay before retrying a failed KMS request (exponential backoff applies)                             | 100ms                                    |
| KMS_RETRY_INTERVAL        | Time interval between retry attempts after a failed KMS key request                                          | 60s                                      |
| INTERVAL                  | Interval between regular key requests to the KMS; should align with WireGuard rekey interval                 | 120s                                     |
| WIREGUARD_INTERFACE       | Name of the WireGuard network interface to configure                                                         | qcicat0                                  |
| WIREGUARD_PEER_PUBLIC_KEY | Public key of the WireGuard peer for secure association                                                      | 8978940b-fb48-4ebf-ad7d-ca36a987fc32     |
| PQC_PSK_FILE              | File path containing the PQC-generated preshared key (from Rosenpass or similar)                             | /rosenpass/pqc.psk                       |
| MODE                      | Operation mode: "QkdAndPqcRequired", "AtLeastQkdRequired", "AtLeastPqcRequired", or "EitherQkdOrPqcRequired" | AtLeastQkdRequired                       |
| ARNIKA_ID                 | Optional identifier (up to 5 digits); defaults to LISTEN_PORT; used for logging and identification           | 9998                                     |


---


#  Credits

## CANCOM Converged Services GmbH (CCS)

**Arnika** was developed by
[CANCOM Converged Services](https://www.cancom.at/en/industry-focus/provider) as part of the [QCI-CAT](https://qci-cat.at/) project, and the source code was released under the [Apache-2.0](https://www.apache.org/licenses/LICENSE-2.0) license.


## WireGuard

[WireGuard](https://www.wireguard.com/) is an extremely simple fast and modern VPN that utilizes state-of-the-art cryptography.

[WireGuard](https://www.wireguard.com/) is designed as a general purpose VPN for running on embedded interfaces and super computers alike, fit for many different circumstances.

[WireGuard](https://www.wireguard.com/) uses state-of-the-art cryptography, like the Noise protocol framework, Curve25519, ChaCha20, Poly1305, BLAKE2, SipHash24, HKDF, and secure trusted constructions. It makes conservative and reasonable choices and has been reviewed by cryptographers.

[WireGuard](https://www.wireguard.com/) supports the use of an optional 256-bit (32-byte) preshared key (PSK) as an additional layer of security. The preshared key (PSK) is combined with the ephemeral keys generated during the initial handshake using the HKDF (HMAC-based Key Derivation Function). When a preshared key (PSK) is not used, the preshared key value used internally is an all-zero string of 32 bytes.



To ensure perfect forward secrecy (**PFS**) and minimizing the impact of key compromise [WireGuard](https://www.wireguard.com/) re-keying timer is **120 seconds** or **2^60 messages**.

Refer to [WireGuard](https://www.wireguard.com/) Homepage [https://www.wireguard.com/protocol/] and Whitepaper [https://www.wireguard.com/papers/wireguard.pdf] for more technical details.

[WireGuard Source Code Repositories and Official Projects](https://www.wireguard.com/repositories/)



[WireGuard](https://www.wireguard.com/) is free and open-source software (FOSS) and licensed under GPLv2.

[WireGuard](https://www.wireguard.com/) and the [WireGuard](https://www.wireguard.com/) **logo** are registered trademarks of Jason A. Donenfeld.


## Rosenpass

The Rosenpass protocol provides a post-quantum-secure authenticated key exchange, based on the work [Post-quantum WireGuard (PQWG)](https://eprint.iacr.org/2020/379) by Hülsing, Ning, Schwabe, Weber, and Zimmermann, but also adds security against state disruption attacks CVE-2021-46873.

While Rosenpass is designed with WireGuard in mind, it can be used as a stand-alone tool to exchange keys. Using this mode, it can be employed to secure other protocols against attacks from quantum computers. Rosenpass will provide a Post-Quantum Cryptography (PQC) key every 120 seconds.

Rosenpass is using two different Key Encapsulation Mechanisms (KEMs) Classic McEliece and Kyber (refer to the presentation on Classic McEliece at the [Fifth NIST PQC workshop](https://classic.mceliece.org/talks/20240410.pdf)): Classic McEliece is used for long-term keys, the foundation of security for identifying and authenticating the server, as well as for encrypting data to achieve authenticity and confidentiality. Kyber is only used for forward secrecy. A break of the lattice system does not damage security unless the attacker can also steal secret keys through, e.g., hardware theft.

Rosenpass was funded through NLnet with financial support from the European Commission's NGI Assure program and ProtoType Fund of the Open Knowledge Foundation Germany, financed by the Federal Ministry of Education and Research (BMBF).

Refer to Rosenpass [homepage](https://rosenpass.eu/) and [whitepaper](https://rosenpass.eu/whitepaper.pdf) for more technical details.

Rosenpass is free and open-source software (FOSS) and licensed under Apache 2.0 license.

Many thanks to [Karo](https://github.com/koraa) and [Paul](https://github.com/aparcar) from the [**Rosenpass**](https://github.com/rosenpass/rosenpass) project.



## QCI-CAT

Building on the long research experience of Austrian institutions in the field of quantum technologies, the project [QCI-CAT](https://qci-cat.at/) aims at an adoption of modern encryption technology based on QKD for highly secure communication between public authorities.

[QCI-CAT](https://qci-cat.at/) will investigate and verify new security applications for public authorities, such as secret sharing and message authentication.

Additionally, [QCI-CAT](https://qci-cat.at/) will also leverage a research testbed for new technological approaches such as the combination of post-quantum encryption with QKD, long-distance QKD with secured trusted nodes and field trials of quantum repeaters.
<br/>

This project has received funding from the [DIGITAL-2021-QCI-01 Digital European Program](https://ec.europa.eu/info/funding-tenders/opportunities/portal/screen/opportunities/topic-details/digital-2021-qci-01-deploy-national) under Project number No 101091642 and the [National Foundation for Research, Technology and Development](https://www.stiftung-fte.at/).


## AIT Austrian Institute of Technology

[AIT Austrian Institute of Technology (AIT)](https://www.ait.ac.at/) is Austria’s largest research and technology organization.
The institute takes a leading position in the Austrian innovation system and a key role in Europe.
With its expertise of handling large EU quantum communication projects such as [OPENQKD](https://openqkd.eu/), [AIT](https://www.ait.ac.at/) will coordinate [QCI-CAT](https://qci-cat.at/) from an administrative point, as well as act as the technical manager and project lead.
