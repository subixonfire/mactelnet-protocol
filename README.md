# MikroTik MAC-Telnet Client

A pure Python implementation of the MikroTik MAC-Telnet protocol — Layer 2 terminal access to RouterOS devices using only their MAC address, no IP required.

Loosely based on [haakonnessjoen/MAC-Telnet](https://github.com/haakonnessjoen/MAC-Telnet).

## What is MAC-Telnet?

MAC-Telnet is a MikroTik-proprietary Layer 2 protocol that provides terminal access to RouterOS devices over **UDP broadcast on port 20561**. Unlike SSH or Telnet, it requires no IP configuration — you connect directly by MAC address on the same broadcast domain.

This is particularly useful for:
- Initial device setup (no IP configured yet)
- Recovery when IP is lost or misconfigured
- Accessing devices on the same switch segment

## Features

- **EC-SRP5 authentication** (RouterOS >= 6.43) — secure elliptic-curve password verification
- **MNDP discovery** — scan the local network for MikroTik devices (UDP port 5678)
- **Interactive terminal** with proper TTY handling
- **Terminal resize** (SIGWINCH) — automatically updates remote terminal dimensions
- **Keepalive** — prevents idle session timeout
- **Self-contained** — single Python file, no RouterOS API dependency

## Setup

```bash
git clone https://github.com/subixonfire/mactelnet-protocol.git
cd mactelnet-protocol
python3 -m venv .venv
source .venv/bin/activate
pip install pycryptodome ecdsa
```

## Usage

### Discover devices on the network

```bash
python3 mactelnet_client.py scan
```

### Connect to a device by MAC address

```bash
python3 mactelnet_client.py AA:BB:CC:DD:EE:FF -u admin -p yourpassword
```

### Exit the session

Press `Ctrl+]` to disconnect.

## Protocol Overview

| Component | Port | Transport | Purpose |
|-----------|------|-----------|---------|
| MAC-Telnet | UDP 20561 | Broadcast (Layer 2) | Terminal session |
| MNDP | UDP 5678 | Broadcast (Layer 2) | Device discovery |

### Security Note

MAC-Telnet is a **plaintext protocol** — terminal data is not encrypted after authentication. This is an inherent limitation of the protocol design. Use it only on trusted network segments.

The authentication handshake itself uses EC-SRP5 (elliptic-curve Secure Remote Password), so the password is never transmitted in cleartext.

## Protocol Documentation

See [PROTOCOL.md](PROTOCOL.md) for a detailed specification of the MAC-Telnet and MNDP protocols, including packet formats, authentication flow, and control messages.

## Known Limitations

- Layer 2 only — both client and target must be on the same broadcast domain
- No encryption for terminal data (protocol limitation)
- MNDP only advertises one IP per device (RouterOS limitation)
- Requires root/admin privileges on some systems for raw UDP broadcast

## License

MIT
