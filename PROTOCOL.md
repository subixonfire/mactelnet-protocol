# MikroTik MAC-Telnet Protocol

## Overview

MAC-Telnet is a MikroTik-proprietary Layer 2 protocol that provides terminal
access to RouterOS devices using only their MAC address — no IP configuration
required. It runs over **UDP broadcast on port 20561**.

A companion discovery protocol, **MNDP** (MikroTik Neighbor Discovery Protocol),
runs on **UDP broadcast port 5678** and allows scanning the local segment for
RouterOS devices.

---

## 1. Transport

- **Protocol**: UDP
- **Port**: 20561 (MAC-Telnet), 5678 (MNDP)
- **Addressing**: All packets sent to `255.255.255.255` (broadcast)
- **MTU**: Standard Ethernet (1500 bytes max)
- **Target identification**: Destination MAC address in the packet header
  (not the IP/UDP destination)

---

## 2. Packet Header (22 bytes)

All MAC-Telnet packets share the same header, big-endian:

```
Offset  Size  Field         Description
------  ----  -----         -----------
0       1     version       Protocol version (always 1)
1       1     ptype         Packet type (see below)
2       6     src_mac       Source MAC address
8       6     dst_mac       Destination MAC address
14      2     session_id    Session identifier (client-chosen, 16-bit)
16      2     client_type   Client type (0x0015 for MAC-Telnet)
18      4     counter       Byte counter (cumulative payload bytes sent)
22      ...   payload       Variable-length data
```

Struct format: `>BB6s6sHHI`

### Packet Types

| Value | Name           | Description                            |
|-------|----------------|----------------------------------------|
| 0     | SESSION_START  | Client initiates session               |
| 1     | DATA           | Terminal data or control packets       |
| 2     | ACK            | Acknowledge received data              |
| 4     | PING           | Keepalive ping                         |
| 5     | PONG           | Keepalive pong                         |
| 255   | END            | Session terminated                     |

---

## 3. Counter / ACK Mechanism

- The `counter` field tracks the cumulative number of **payload bytes** sent
  (not packet count).
- Incremented by `len(payload)` after each DATA packet.
- Wraps at **65536** (treated as 16-bit despite 32-bit field).
- ACK packets set `counter` to `received_counter + received_data_len`,
  indicating the next expected byte offset.
- Keepalive ACKs use the current `recv_counter` with no payload.

Duplicate detection: a packet is new if
`pkt.counter + pkt.data_len > recv_counter` or if the counter has wrapped
(`recv_counter + pkt.data_len > 65535`).

---

## 4. Control Packets

Control packets are embedded inside DATA packet payloads. They are identified
by a 4-byte magic prefix and use a type-length-value structure:

```
Offset  Size  Field      Description
------  ----  -----      -----------
0       4     magic      0x563412FF
4       1     cp_type    Control packet type (signed byte)
5       4     data_len   Payload length (big-endian uint32)
9       ...   data       Payload
```

Multiple control packets can be concatenated in a single DATA payload.

### Control Packet Types

| Value | Name            | Description                              |
|-------|-----------------|------------------------------------------|
| 0     | BEGIN_AUTH      | Start authentication (empty payload)     |
| 1     | ENCRYPTION_KEY  | Public key exchange (username + key)      |
| 2     | PASSWORD        | Confirmation code (SHA-256 digest)        |
| 3     | USERNAME        | Username string                          |
| 4     | TERM_TYPE       | Terminal type string (e.g. "xterm")      |
| 5     | TERM_WIDTH      | Terminal width (2 bytes, little-endian)   |
| 6     | TERM_HEIGHT     | Terminal height (2 bytes, little-endian)  |
| 7     | PACKET_ERROR    | Error notification                       |
| 9     | END_AUTH        | Authentication complete                  |

---

## 5. Authentication Flow (EC-SRP5)

MAC-Telnet uses the same EC-SRP5 (Elliptic Curve Secure Remote Password)
authentication as the WinBox protocol, operating on Curve25519 in Weierstrass
form.

### Phase 1: Session Start

1. **Client** sends `SESSION_START` (no payload).
2. **Server** responds with `ACK`.

### Phase 2: Key Exchange

3. **Client** sends DATA containing:
   - `CP_BEGIN_AUTH` (empty)
   - `CP_ENCRYPTION_KEY` with:
     - Username (null-terminated UTF-8 string)
     - Client public key (32 bytes)
     - Client public key parity (1 byte)

4. **Server** responds with DATA containing:
   - `CP_ENCRYPTION_KEY` with:
     - Server public key (32 bytes, offset 0x00)
     - Server public key parity (1 byte, offset 0x20)
     - Salt (16 bytes, offset 0x21)

### Phase 3: Confirmation

5. **Client** computes the EC-SRP5 confirmation code:
   ```
   validator = SHA256(salt + SHA256(username + ":" + password))
   validator_point = redp1(gen_public_key(validator).x, parity=1)
   server_clean = lift_x(server_public) + validator_point  // disentangle
   h = SHA256(client_public + server_public)
   vh = (validator_int * h_int + client_private_int) mod r
   z = (vh * server_clean).to_montgomery().x
   confirmation = SHA256(h + z)
   ```

6. **Client** sends DATA containing:
   - `CP_PASSWORD` (32-byte confirmation code)
   - `CP_USERNAME` (username string)
   - `CP_TERM_TYPE` (terminal type)
   - `CP_TERM_WIDTH` (terminal width, 2 bytes LE)
   - `CP_TERM_HEIGHT` (terminal height, 2 bytes LE)

7. **Server** responds with `CP_END_AUTH` (sent twice), then terminal data
   begins flowing. Authentication failures arrive as terminal text, not as
   a special error packet.

---

## 6. Terminal Session

After authentication:

- **Client → Server**: Raw terminal input sent as DATA payload (no control
  packet wrapping). Each keystroke or paste is a separate DATA packet.
- **Server → Client**: Terminal output (VT100/ANSI) sent as DATA payload.
- **Terminal resize**: Client sends DATA with `CP_TERM_WIDTH` + `CP_TERM_HEIGHT`
  control packets (triggered by SIGWINCH).
- **Keepalive**: Client sends ACK with current `recv_counter` every 10 seconds.
- **Session end**: Either side sends `END` packet.

---

## 7. MNDP — Neighbor Discovery (UDP 5678)

### Request

Send 4 null bytes (`\x00\x00\x00\x00`) as UDP broadcast to port 5678.

### Response

RouterOS devices respond with a TLV packet:

```
Offset  Size  Field
------  ----  -----
0       4     Header (typically 0x00000000)
4       ...   TLV fields
```

Each TLV field:
```
Offset  Size  Field
------  ----  -----
0       2     Type (big-endian uint16)
2       2     Length (big-endian uint16)
4       N     Data
```

### MNDP TLV Types

| Type   | Name         | Format                            |
|--------|--------------|-----------------------------------|
| 0x0001 | MAC          | 6 bytes                           |
| 0x0005 | Identity     | UTF-8 string                      |
| 0x0007 | Version      | UTF-8 string (e.g. "7.20.7 ...") |
| 0x0008 | Platform     | UTF-8 string (e.g. "MikroTik")   |
| 0x000A | Uptime       | 4 bytes, little-endian seconds    |
| 0x000B | Software ID  | UTF-8 string                      |
| 0x000C | Board        | UTF-8 string (e.g. "RB5009UPr+S+")|
| 0x000E | Unpack       | 1 byte                            |
| 0x000F | IPv6         | IPv6 address                      |
| 0x0010 | Interface    | UTF-8 string (e.g. "ether1")     |
| 0x0011 | IPv4         | 4 bytes (network byte order)      |

---

## 8. Differences from WinBox Protocol

| Aspect           | MAC-Telnet                | WinBox                        |
|------------------|---------------------------|-------------------------------|
| Transport        | UDP broadcast port 20561  | TCP port 8291                 |
| Layer            | Layer 2 (MAC addressing)  | Layer 3 (IP addressing)       |
| Encryption       | None (plaintext terminal) | AES-128-CBC + HMAC after auth |
| Message format   | Raw terminal + control packets | M2 binary TLV              |
| Authentication   | EC-SRP5 (same math)       | EC-SRP5 (same math)           |
| Framing          | UDP datagrams             | Chunked TCP frames            |
| Reliable delivery| ACK counter mechanism     | TCP provides reliability       |
