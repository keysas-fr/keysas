<div align="center">
<img  src ="img/logo-keysas.png"  alt="Keysas"  width=300px/>
</div>

# USB virus cleaning station (WIP)

Warning: This is only a work in progress for now.

# Main features
- Retrieve untrusted files from USB (via keysas-io) or over the network
- Perform multiple checks
    - Run anti-virus check (ClamAV)
    - Run Yara parsing
    - Run extensions and size checks
- Signatures
    - Trusted (Outgoing) USB device must be signed with Keysas-admin app
    - Each verified file signature is stored in the corresponding file report  
    - Signatures are post-quantum proof (hybrid ed25519/Diltithium5 scheme)
    - Keypairs are stored using PKCS#8 format

# Keysas-core
## Architecture

<div align="center">
<img  src ="img/keysas-core-architecture.png"  alt="keysas-core architecture"  width=900px/>
</div>

Files are passed between daemons as raw file descriptors and using abstract sockets (GNU/Linux only). Each daemon adds metadata and send it to the next daemon using a dedicated abstract socket. Finally, the last daemon (Keysas-out) chooses whether or not to write the file to the output directory according to the corresponding metadata. For each file, a report is systematically created in the output directory (sas_out).

 - Daemons are running under unprivileged users
 - Daemons are sandboxed using systemd (Security drop-in)
 - Daemons are sandboxed using LandLock
 - Daemons are sandboxed using Seccomp (TODO)

## Other binaries or applications available
 - Keysas-io: Daemon watching udev events to verify the signature of any mass storage USB devices and mount it as a IN (no or invalid signature) or OUT device (valid signature). It also send json values to keysas-frontend for visualization
 - Keysas-sign: Command line utility to sign or verify the signature of a USB device
 - Keysas-fido: Manage Yubikeys 5 enrollment
 - Keysas-backend: Create a websocket server to send different json values to the keysas-frontend
 - Keysas-frontend: VueJS3 Frontend for the final user
 - Keysas-admin: Desktop application for managing several Keysas stations (Tauri + VueJS3). It also provides a PKI to sign USB outgoing devices, sign certificat signing reqests (csr) from Keysas stations.

## Installation

On Debian stable:
```
echo "deb http://deb.debian.org/debian bullseye-backports main contrib non-free" > /etc/apt/sources.list.d/backports.list
apt-get update -yq
apt -qy -t bullseye-backports install libyara-dev libyara9
apt-get install -y wget make lsb-release software-properties-common libseccomp-dev clamav-daemon clamav-freshclam pkg-config git bash libudev-dev
bash -c "$(wget -O - https://apt.llvm.org/llvm.sh)"
curl https://sh.rustup.rs -sSf | sh -s -- --default-toolchain nightly -y
git clone --depth=1 https://github.com/r3dlight/keysas && cd keysas
make help
make build
make install
```
## User documentation

User documentation can be found here : [https://keysas.fr](https://keysas.fr)

