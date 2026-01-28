#!/usr/bin/env python3
"""
MikroTik MAC-Telnet Client

A synchronous, self-contained MAC-Telnet client for MikroTik RouterOS.
Connects to RouterOS devices using only their MAC address (Layer 2, no IP needed).

Protocol: UDP broadcast on port 20561
Authentication: EC-SRP5 (RouterOS >= 6.43)

Usage:
    python3 mactelnet_client.py BC:24:11:5B:0A:22 -u admin -p password
    python3 mactelnet_client.py BC:24:11:5B:0A:22  # prompts for credentials

Dependencies: pycryptodome, ecdsa
"""

import argparse
import getpass
import hashlib
import os
import secrets
import select
import signal
import socket
import struct
import sys
import termios
import time
import tty

from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA1, SHA256
import ecdsa


# =============================================================================
# Protocol constants
# =============================================================================

MT_PORT = 20561
MT_HEADER_LEN = 22
MT_MAX_PACKET = 1500

# Packet types
PT_SESSION_START = 0
PT_DATA = 1
PT_ACK = 2
PT_PING = 4
PT_PONG = 5
PT_END = 255

# Control packet magic
CP_MAGIC = b'\x56\x34\x12\xff'

# Control packet types
CP_BEGIN_AUTH = 0
CP_ENCRYPTION_KEY = 1
CP_PASSWORD = 2
CP_USERNAME = 3
CP_TERM_TYPE = 4
CP_TERM_WIDTH = 5
CP_TERM_HEIGHT = 6
CP_PACKET_ERROR = 7
CP_END_AUTH = 9

# Client type for MAC-Telnet
CLIENT_TYPE = 0x0015


# =============================================================================
# Elliptic curve math (Curve25519 in Weierstrass form for EC-SRP5)
# =============================================================================

def _egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    g, y, x = _egcd(b % a, a)
    return (g, x - (b // a) * y, y)


def _modinv(a, p):
    if a < 0:
        a = a % p
    g, x, _ = _egcd(a, p)
    if g != 1:
        raise Exception('modular inverse does not exist')
    return x % p


def _prime_mod_sqrt(a, p):
    a %= p
    if a == 0:
        return [0]
    if p == 2:
        return [a]
    if pow(a, (p - 1) // 2, p) != 1:
        return []
    if p % 4 == 3:
        x = pow(a, (p + 1) // 4, p)
        return [x, p - x]
    q, s = p - 1, 0
    while q % 2 == 0:
        s += 1
        q //= 2
    z = 1
    while pow(z, (p - 1) // 2, p) != p - 1:
        z += 1
    c = pow(z, q, p)
    x = pow(a, (q + 1) // 2, p)
    t = pow(a, q, p)
    m = s
    while t != 1:
        i, e = 0, 2
        for i in range(1, m):
            if pow(t, e, p) == 1:
                break
            e *= 2
        b = pow(c, 2 ** (m - i - 1), p)
        x = (x * b) % p
        t = (t * b * b) % p
        c = (b * b) % p
        m = i
    return [x, p - x]


class WCurve:
    """Weierstrass form of Curve25519 for MikroTik EC-SRP5."""

    def __init__(self):
        self._p = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
        self._r = 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed
        self._mont_a = 486662
        self._conv_from_m = self._mont_a * _modinv(3, self._p) % self._p
        self._conv = (self._p - self._mont_a * _modinv(3, self._p)) % self._p
        self._a = 0x2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa984914a144
        self._b = 0x7b425ed097b425ed097b425ed097b425ed097b425ed097b4260b5e9c7710c864
        self._h = 8
        self._curve = ecdsa.ellipticcurve.CurveFp(self._p, self._a, self._b, self._h)
        self._g = self.lift_x(9, 0)

    def gen_public_key(self, priv):
        priv_int = int.from_bytes(priv, "big")
        pt = priv_int * self._g
        return self.to_montgomery(pt)

    def to_montgomery(self, pt):
        x = (pt.x() + self._conv) % self._p
        return int(x).to_bytes(32, "big"), pt.y() & 1

    def lift_x(self, x, parity):
        x = x % self._p
        y_sq = (x ** 3 + self._mont_a * x ** 2 + x) % self._p
        x = (x + self._conv_from_m) % self._p
        ys = _prime_mod_sqrt(y_sq, self._p)
        if not ys:
            return None
        pt1 = ecdsa.ellipticcurve.PointJacobi(self._curve, x, ys[0], 1, self._r)
        pt2 = ecdsa.ellipticcurve.PointJacobi(self._curve, x, ys[1], 1, self._r)
        if parity:
            return pt1 if pt1.y() & 1 == 1 else pt2
        else:
            return pt1 if pt1.y() & 1 == 0 else pt2

    def redp1(self, x_bytes, parity):
        x = hashlib.sha256(x_bytes).digest()
        while True:
            x2 = hashlib.sha256(x).digest()
            pt = self.lift_x(int.from_bytes(x2, "big"), parity)
            if pt is None:
                x = (int.from_bytes(x, "big") + 1).to_bytes(32, "big")
            else:
                return pt

    def gen_password_validator(self, username, password, salt):
        return hashlib.sha256(
            salt + hashlib.sha256((username + ":" + password).encode()).digest()
        ).digest()

    def finite_field_value(self, a):
        return a % self._r


# =============================================================================
# HKDF / key derivation (same as WinBox protocol)
# =============================================================================

def _hkdf(message):
    h = HMAC.new(b'\x00' * 0x40, b'', SHA1)
    h.update(message)
    h1 = h.digest()
    h2 = b''
    res = b''
    for i in range(2):
        h = HMAC.new(h1, b'', SHA1)
        h.update(h2)
        h.update((i + 1).to_bytes(1, "big"))
        h2 = h.digest()
        res += h2
    return res[:0x24]


def _sha256(data):
    return SHA256.new(data).digest()


# =============================================================================
# Packet structures
# =============================================================================

class ControlPacket:
    """MAC-Telnet control packet (embedded in DATA packets)."""

    def __init__(self, cp_type=0, data=b''):
        self.type = cp_type
        self.data = data

    def to_bytes(self):
        return CP_MAGIC + struct.pack('>bI', self.type, len(self.data)) + self.data

    @staticmethod
    def parse_all(raw):
        """Parse all control packets from raw data. Returns list of ControlPacket."""
        packets = []
        pos = 0
        while pos < len(raw):
            if pos + 9 > len(raw) or raw[pos:pos + 4] != CP_MAGIC:
                break
            cp_type = raw[pos + 4]
            # Handle signed byte from struct
            if cp_type > 127:
                cp_type -= 256
            data_len = struct.unpack('>I', raw[pos + 5:pos + 9])[0]
            data = raw[pos + 9:pos + 9 + data_len]
            packets.append(ControlPacket(cp_type, data))
            pos += 9 + data_len
        return packets

    def __repr__(self):
        names = {0: 'BEGIN_AUTH', 1: 'ENC_KEY', 2: 'PASSWORD', 3: 'USERNAME',
                 4: 'TERM_TYPE', 5: 'TERM_WIDTH', 6: 'TERM_HEIGHT',
                 7: 'ERROR', 9: 'END_AUTH'}
        name = names.get(self.type, f'UNKNOWN({self.type})')
        return f'CP({name}, {len(self.data)}b)'


class MTPacket:
    """MAC-Telnet protocol packet (22-byte header + data)."""

    def __init__(self):
        self.version = 1
        self.ptype = 0
        self.src_mac = b'\x00' * 6
        self.dst_mac = b'\x00' * 6
        self.session_id = 0
        self.client_type = CLIENT_TYPE
        self.counter = 0
        self.payload = b''

    def to_bytes(self):
        header = struct.pack('>BB6s6sHHI',
                             self.version, self.ptype,
                             self.src_mac, self.dst_mac,
                             self.session_id, self.client_type,
                             self.counter)
        return header + self.payload

    @staticmethod
    def from_bytes(data):
        if len(data) < MT_HEADER_LEN:
            return None
        pkt = MTPacket()
        (pkt.version, pkt.ptype, pkt.src_mac, pkt.dst_mac,
         pkt.session_id, pkt.client_type, pkt.counter) = \
            struct.unpack('>BB6s6sHHI', data[:MT_HEADER_LEN])
        pkt.payload = data[MT_HEADER_LEN:]
        return pkt

    def data_len(self):
        """Length of payload (for counter tracking)."""
        return len(self.payload)

    def __repr__(self):
        names = {0: 'START', 1: 'DATA', 2: 'ACK', 4: 'PING', 5: 'PONG', 255: 'END'}
        return f'MT({names.get(self.ptype, self.ptype)}, cnt={self.counter}, {len(self.payload)}b)'


# =============================================================================
# MAC-Telnet Client
# =============================================================================

class MACTelnetClient:
    """Synchronous MikroTik MAC-Telnet client."""

    def __init__(self, dst_mac, username='admin', password='', debug=False):
        self.dst_mac = bytes.fromhex(dst_mac.replace(':', '').replace('-', ''))
        self.username = username
        self.password = password
        self.debug = debug

        # Get our own MAC address
        import uuid
        self.src_mac = uuid.getnode().to_bytes(6, 'big')

        self.session_id = secrets.randbits(16)
        self.send_counter = 0
        self.recv_counter = 0
        self.acked_counter = 0

        self.sock = None
        self.my_ip = None
        self.server_session_id = None
        self.authenticated = False
        self.session_ended = False

        # EC-SRP5 state
        self.wcurve = WCurve()
        self.client_private = None
        self.client_public = None
        self.client_parity = None
        self.server_public = None
        self.server_parity = None
        self.salt = None

    def connect(self):
        """Create UDP broadcast socket and start session."""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(('0.0.0.0', MT_PORT))

        # Detect our own IP so we can filter our own broadcast echoes
        try:
            probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            probe.connect(('10.255.255.255', 1))
            self.my_ip = probe.getsockname()[0]
            probe.close()
        except Exception:
            self.my_ip = '127.0.0.1'
        if self.debug:
            print(f'[DBG] my_ip={self.my_ip}, src_mac={format_mac(self.src_mac)}, '
                  f'session_id={self.session_id}', file=sys.stderr)

        # Send SESSION_START
        pkt = self._make_packet(PT_SESSION_START)
        self._send(pkt)

        # Wait for ACK
        deadline = time.time() + 5.0
        while time.time() < deadline:
            resp = self._recv(timeout=1.0)
            if resp and resp.ptype == PT_ACK:
                break
        else:
            raise ConnectionError("No ACK received for session start")

        # Begin authentication
        self._authenticate()

    def _make_packet(self, ptype):
        pkt = MTPacket()
        pkt.ptype = ptype
        pkt.src_mac = self.src_mac
        pkt.dst_mac = self.dst_mac
        pkt.session_id = self.session_id
        pkt.counter = self.send_counter
        return pkt

    def _send(self, pkt):
        """Send packet and update counter."""
        data = pkt.to_bytes()
        if self.debug:
            print(f'[TX] {pkt} -> 255.255.255.255:{MT_PORT}', file=sys.stderr)
        self.sock.sendto(data, ('255.255.255.255', MT_PORT))
        if pkt.ptype == PT_DATA:
            self.send_counter += pkt.data_len()
            if self.send_counter > 65535:
                self.send_counter -= 65536

    def _send_ack(self, for_pkt):
        """Send ACK for a received packet."""
        ack = self._make_packet(PT_ACK)
        if for_pkt:
            ack.counter = for_pkt.counter + for_pkt.data_len()
        else:
            ack.counter = self.recv_counter
        self.sock.sendto(ack.to_bytes(), ('255.255.255.255', MT_PORT))

    def _recv(self, timeout=0.5):
        """Receive one packet, filtering by source MAC address."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            remaining = max(0.01, deadline - time.time())
            rlist, _, _ = select.select([self.sock], [], [], remaining)
            if not rlist:
                return None
            data, addr = self.sock.recvfrom(MT_MAX_PACKET)
            # Skip our own broadcast packets
            if addr[0] == self.my_ip:
                if self.debug:
                    print(f'[RX] skip own echo from {addr[0]}', file=sys.stderr)
                continue
            pkt = MTPacket.from_bytes(data)
            if self.debug:
                print(f'[RX] {pkt} src={format_mac(pkt.src_mac)} '
                      f'dst={format_mac(pkt.dst_mac)} from {addr[0]}', file=sys.stderr)
            # Match by source MAC = our target router
            if pkt and pkt.src_mac == self.dst_mac:
                # Learn the server's session_id on first response
                if self.server_session_id is None:
                    self.server_session_id = pkt.session_id
                    if self.debug:
                        print(f'[RX]   learned server session_id={self.server_session_id}', file=sys.stderr)
                return pkt
            elif self.debug and pkt:
                print(f'[RX]   ignored (src_mac mismatch)', file=sys.stderr)
        return None

    def _authenticate(self):
        """Perform EC-SRP5 authentication handshake."""
        # Generate client keypair
        self.client_private = secrets.token_bytes(32)
        self.client_public, self.client_parity = self.wcurve.gen_public_key(self.client_private)

        # Send BEGIN_AUTH + our public key
        key_data = self.username.encode() + b'\x00'
        key_data += self.client_public
        key_data += int(self.client_parity).to_bytes(1, 'big')

        pkt = self._make_packet(PT_DATA)
        pkt.payload = (
            ControlPacket(CP_BEGIN_AUTH).to_bytes() +
            ControlPacket(CP_ENCRYPTION_KEY, key_data).to_bytes()
        )
        self._send(pkt)

        # Wait for server's public key + salt
        deadline = time.time() + 5.0
        while time.time() < deadline:
            resp = self._recv(timeout=1.0)
            if not resp:
                continue
            if resp.ptype == PT_ACK:
                continue
            if resp.ptype == PT_DATA:
                self._send_ack(resp)
                self.recv_counter += resp.data_len()
                cps = ControlPacket.parse_all(resp.payload)
                for cp in cps:
                    if cp.type == CP_ENCRYPTION_KEY:
                        self.server_public = cp.data[:32]
                        self.server_parity = cp.data[32]
                        self.salt = cp.data[33:]
                        break
                if self.server_public:
                    break

        if not self.server_public or len(self.salt) != 16:
            raise ConnectionError("Authentication failed: no valid server key/salt")

        # Compute confirmation code
        confirmation = self._gen_confirmation()

        # Send confirmation + credentials + terminal info
        term_type = os.getenv('TERM', 'xterm').encode()
        try:
            ts = os.get_terminal_size()
            width, height = ts.columns, ts.lines
        except OSError:
            width, height = 80, 24

        pkt = self._make_packet(PT_DATA)
        pkt.payload = (
            ControlPacket(CP_PASSWORD, confirmation).to_bytes() +
            ControlPacket(CP_USERNAME, self.username.encode()).to_bytes() +
            ControlPacket(CP_TERM_TYPE, term_type).to_bytes() +
            ControlPacket(CP_TERM_WIDTH, width.to_bytes(2, 'little')).to_bytes() +
            ControlPacket(CP_TERM_HEIGHT, height.to_bytes(2, 'little')).to_bytes()
        )
        self._send(pkt)

        # Wait for END_AUTH (server sends it twice) then terminal data
        deadline = time.time() + 5.0
        end_auth_count = 0
        while time.time() < deadline:
            resp = self._recv(timeout=0.5)
            if not resp:
                continue
            if resp.ptype == PT_ACK:
                self.acked_counter = resp.counter
                continue
            if resp.ptype == PT_DATA:
                self._send_ack(resp)
                new_data = resp.counter + resp.data_len() > self.recv_counter or \
                           self.recv_counter + resp.data_len() > 65535
                if new_data:
                    self.recv_counter += resp.data_len()
                else:
                    continue
                if resp.payload[:4] == CP_MAGIC:
                    cps = ControlPacket.parse_all(resp.payload)
                    for cp in cps:
                        if cp.type == CP_END_AUTH:
                            end_auth_count += 1
                    if end_auth_count >= 2:
                        self.authenticated = True
                        return
                else:
                    # Terminal data — check if it's an auth failure message
                    text = resp.payload.decode('utf-8', errors='replace').lower()
                    if 'login failed' in text or 'incorrect' in text:
                        raise ConnectionError(
                            "Authentication failed: wrong username or password")
                    sys.stdout.buffer.write(resp.payload)
                    sys.stdout.flush()
                    self.authenticated = True
                    return
            if resp.ptype == PT_END:
                raise ConnectionError("Authentication failed: wrong username or password")

        if not self.authenticated:
            raise ConnectionError("Authentication timed out")

    def _gen_confirmation(self):
        """Generate EC-SRP5 confirmation code."""
        validator = self.wcurve.gen_password_validator(
            self.username, self.password, self.salt)
        validator_point = self.wcurve.redp1(
            self.wcurve.gen_public_key(validator)[0], 1)
        server_point = self.wcurve.lift_x(
            int.from_bytes(self.server_public, 'big'), self.server_parity)
        server_point_clean = server_point + validator_point  # disentangle

        pubkeys_hash = _sha256(self.client_public + self.server_public)
        vh = int.from_bytes(validator, 'big') * int.from_bytes(pubkeys_hash, 'big')
        vh += int.from_bytes(self.client_private, 'big')
        vh = self.wcurve.finite_field_value(vh)
        z_point = vh * server_point_clean
        z_x, _ = self.wcurve.to_montgomery(z_point)
        return _sha256(pubkeys_hash + z_x)

    def send_data(self, data):
        """Send terminal data to the router."""
        pkt = self._make_packet(PT_DATA)
        pkt.payload = data
        self._send(pkt)

    def send_winch(self, width, height):
        """Send terminal resize notification."""
        pkt = self._make_packet(PT_DATA)
        pkt.payload = (
            ControlPacket(CP_TERM_WIDTH, width.to_bytes(2, 'little')).to_bytes() +
            ControlPacket(CP_TERM_HEIGHT, height.to_bytes(2, 'little')).to_bytes()
        )
        self._send(pkt)

    def close(self):
        """Send END and close socket."""
        if self.sock:
            try:
                end = self._make_packet(PT_END)
                self._send(end)
            except Exception:
                pass
            self.sock.close()
            self.sock = None

    def interactive_loop(self):
        """Run interactive terminal session."""
        old_tty = termios.tcgetattr(sys.stdin.fileno())
        last_keepalive = time.time()

        def handle_winch(*_):
            try:
                ts = os.get_terminal_size()
                self.send_winch(ts.columns, ts.lines)
            except Exception:
                pass

        signal.signal(signal.SIGWINCH, handle_winch)
        # Send initial window size after brief delay
        try:
            ts = os.get_terminal_size()
            self.send_winch(ts.columns, ts.lines)
        except Exception:
            pass

        sys.stdout.write("\r\n[Connected. Press Ctrl+\\ to disconnect.]\r\n")
        sys.stdout.flush()

        # Buffer to track typed input for "exit" detection
        input_line = b''

        try:
            tty.setraw(sys.stdin)

            while not self.session_ended:
                rlist, _, _ = select.select([sys.stdin, self.sock], [], [], 0.1)

                if sys.stdin in rlist:
                    data = sys.stdin.buffer.raw.read(1024)
                    if not data:
                        break
                    # Ctrl+\ (0x1c) or Ctrl+] (0x1d)
                    if b'\x1c' in data or b'\x1d' in data:
                        sys.stdout.write("\r\n[Disconnected.]\r\n")
                        sys.stdout.flush()
                        break

                    # Track typed characters to detect "exit" + Enter
                    for byte in data:
                        if byte in (0x0d, 0x0a):  # Enter
                            if input_line.strip() == b'exit':
                                sys.stdout.write("\r\n[Disconnected.]\r\n")
                                sys.stdout.flush()
                                self.send_data(data)
                                return
                            input_line = b''
                        elif byte == 0x7f or byte == 0x08:  # Backspace
                            input_line = input_line[:-1]
                        elif byte >= 0x20:  # printable
                            input_line += bytes([byte])
                        else:
                            input_line = b''

                    self.send_data(data)

                if self.sock in rlist:
                    try:
                        data, addr = self.sock.recvfrom(MT_MAX_PACKET)
                    except OSError:
                        break
                    if addr[0] == self.my_ip:
                        continue
                    pkt = MTPacket.from_bytes(data)
                    if not pkt or pkt.src_mac != self.dst_mac:
                        continue

                    if pkt.ptype == PT_DATA:
                        self._send_ack(pkt)
                        new_data = pkt.counter + pkt.data_len() > self.recv_counter or \
                                   self.recv_counter + pkt.data_len() > 65535
                        if new_data:
                            self.recv_counter += pkt.data_len()
                        else:
                            continue
                        if pkt.payload[:4] == CP_MAGIC:
                            # Control packet during session (ignore)
                            pass
                        else:
                            sys.stdout.buffer.write(pkt.payload)
                            sys.stdout.flush()

                    elif pkt.ptype == PT_ACK:
                        self.acked_counter = pkt.counter

                    elif pkt.ptype == PT_END:
                        self._send_ack(pkt)
                        self.session_ended = True

                # Keepalive every 10 seconds
                now = time.time()
                if now - last_keepalive > 10:
                    self._send_ack(None)
                    last_keepalive = now

        finally:
            termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, old_tty)
            signal.signal(signal.SIGWINCH, signal.SIG_DFL)

    def dump_loop(self, duration=10.0):
        """Non-interactive mode: receive and print terminal output for duration seconds."""
        deadline = time.time() + duration
        last_keepalive = time.time()

        while not self.session_ended and time.time() < deadline:
            rlist, _, _ = select.select([self.sock], [], [], 0.5)

            if self.sock in rlist:
                try:
                    data, addr = self.sock.recvfrom(MT_MAX_PACKET)
                except OSError:
                    break
                if addr[0] == self.my_ip:
                    continue
                pkt = MTPacket.from_bytes(data)
                if not pkt or pkt.src_mac != self.dst_mac:
                    continue

                if pkt.ptype == PT_DATA:
                    self._send_ack(pkt)
                    new_data = pkt.counter + pkt.data_len() > self.recv_counter or \
                               self.recv_counter + pkt.data_len() > 65535
                    if new_data:
                        self.recv_counter += pkt.data_len()
                    else:
                        continue
                    if pkt.payload[:4] != CP_MAGIC:
                        sys.stdout.buffer.write(pkt.payload)
                        sys.stdout.flush()

                elif pkt.ptype == PT_ACK:
                    self.acked_counter = pkt.counter

                elif pkt.ptype == PT_END:
                    self._send_ack(pkt)
                    self.session_ended = True

            now = time.time()
            if now - last_keepalive > 10:
                self._send_ack(None)
                last_keepalive = now


# =============================================================================
# Helper: format MAC address
# =============================================================================

def format_mac(mac_bytes):
    return ':'.join(f'{b:02X}' for b in mac_bytes)


# =============================================================================
# MNDP — MikroTik Neighbor Discovery Protocol (UDP 5678)
# =============================================================================

MNDP_PORT = 5678

# MNDP TLV type IDs
MNDP_MAC       = 0x0001
MNDP_IDENTITY  = 0x0005
MNDP_VERSION   = 0x0007
MNDP_PLATFORM  = 0x0008
MNDP_UPTIME    = 0x000A
MNDP_SWID      = 0x000B
MNDP_BOARD     = 0x000C
MNDP_UNPACK    = 0x000E
MNDP_IPV6      = 0x000F
MNDP_IFACE     = 0x0010
MNDP_IPV4      = 0x0011

MNDP_FIELD_NAMES = {
    MNDP_MAC: 'mac', MNDP_IDENTITY: 'identity', MNDP_VERSION: 'version',
    MNDP_PLATFORM: 'platform', MNDP_UPTIME: 'uptime', MNDP_SWID: 'software-id',
    MNDP_BOARD: 'board', MNDP_UNPACK: 'unpack', MNDP_IPV6: 'ipv6',
    MNDP_IFACE: 'interface', MNDP_IPV4: 'ipv4',
}


def parse_mndp(data):
    """Parse an MNDP response packet into a dict of fields."""
    if len(data) < 8:
        return None
    # Skip 4-byte header
    pos = 4
    result = {}
    while pos + 4 <= len(data):
        tlv_type = struct.unpack('>H', data[pos:pos + 2])[0]
        tlv_len = struct.unpack('>H', data[pos + 2:pos + 4])[0]
        tlv_data = data[pos + 4:pos + 4 + tlv_len]
        pos += 4 + tlv_len

        name = MNDP_FIELD_NAMES.get(tlv_type, f'unknown-0x{tlv_type:04x}')
        if tlv_type == MNDP_MAC:
            result[name] = format_mac(tlv_data)
        elif tlv_type == MNDP_UPTIME:
            if len(tlv_data) == 4:
                secs = struct.unpack('<I', tlv_data)[0]
                days, rem = divmod(secs, 86400)
                hours, rem = divmod(rem, 3600)
                mins, s = divmod(rem, 60)
                result[name] = f'{days}d {hours:02d}:{mins:02d}:{s:02d}'
            else:
                result[name] = tlv_data.hex()
        elif tlv_type == MNDP_UNPACK:
            result[name] = tlv_data[0] if tlv_data else 0
        elif tlv_type == MNDP_IPV4:
            if len(tlv_data) == 4:
                result[name] = socket.inet_ntoa(tlv_data)
            else:
                result[name] = tlv_data.hex()
        else:
            # String fields
            result[name] = tlv_data.decode('utf-8', errors='replace').rstrip('\x00')
    return result


def mndp_scan(duration=5.0):
    """Send MNDP discovery request and collect responses.

    Devices with multiple IPs may send multiple MNDP packets.
    These are merged, collecting all IPs in 'ipv4_list' and interfaces
    in 'interface_list'.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # Allow multiple listeners on the same port (macOS/BSD)
    if hasattr(socket, 'SO_REUSEPORT'):
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)

    # Try MNDP port first, fall back to ephemeral if already in use
    try:
        sock.bind(('0.0.0.0', MNDP_PORT))
    except OSError as e:
        if e.errno == 48:  # Address already in use
            sock.bind(('0.0.0.0', 0))
        else:
            raise

    # Send discovery request (4 null bytes)
    sock.sendto(b'\x00\x00\x00\x00', ('255.255.255.255', MNDP_PORT))

    devices = {}
    deadline = time.time() + duration
    while time.time() < deadline:
        remaining = max(0.01, deadline - time.time())
        rlist, _, _ = select.select([sock], [], [], remaining)
        if not rlist:
            continue
        data, addr = sock.recvfrom(1500)
        if len(data) < 8:
            continue
        info = parse_mndp(data)
        if info and 'mac' in info:
            mac = info['mac']
            info['_addr'] = addr[0]

            if mac in devices:
                existing = devices[mac]
                # Collect all IPv4 addresses
                if 'ipv4_list' not in existing:
                    existing['ipv4_list'] = [existing.get('ipv4')] if existing.get('ipv4') else []
                new_ip = info.get('ipv4')
                if new_ip and new_ip not in existing['ipv4_list']:
                    existing['ipv4_list'].append(new_ip)
                # Collect all interfaces
                if 'interface_list' not in existing:
                    existing['interface_list'] = [existing.get('interface')] if existing.get('interface') else []
                new_iface = info.get('interface')
                if new_iface and new_iface not in existing['interface_list']:
                    existing['interface_list'].append(new_iface)
            else:
                devices[mac] = info

    sock.close()
    return devices


# =============================================================================
# Main
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description='MikroTik MAC-Telnet Client',
        epilog='Exit with Ctrl+]')
    parser.add_argument('mac', nargs='?', default=None,
                        help='Target MAC address, or "scan" to discover devices')
    parser.add_argument('-u', '--username', default=None, help='Username')
    parser.add_argument('-p', '--password', default=None, help='Password')
    parser.add_argument('-d', '--debug', action='store_true', help='Debug output')
    parser.add_argument('--dump', action='store_true',
                        help='Non-interactive: receive output then exit')
    parser.add_argument('-t', '--timeout', type=float, default=5.0,
                        help='Scan duration in seconds (default: 5)')
    args = parser.parse_args()

    if args.mac is None:
        print(f'Scanning for MikroTik devices ({args.timeout}s)...')
        devices = mndp_scan(args.timeout)
        if not devices:
            print('No devices found.')
            return
        dev_list = sorted(devices.values(), key=lambda d: d.get('identity', ''))
        print(f'\n {"#":<4} {"MAC":<20} {"Identity":<20} {"IP":<16} {"Board":<16} {"Version"}')
        print('-' * 90)
        for i, info in enumerate(dev_list, 1):
            print(f' {i:<4} {info.get("mac", "?"):<20} '
                  f'{info.get("identity", "?"):<20} '
                  f'{info.get("ipv4", info.get("_addr", "?")):<16} '
                  f'{info.get("board", "?"):<16} '
                  f'{info.get("version", "?")}')
        print()
        try:
            choice = input(f'Select device [1-{len(dev_list)}] (or q to quit): ').strip()
        except (EOFError, KeyboardInterrupt):
            return
        if choice.lower() == 'q' or not choice:
            return
        try:
            idx = int(choice) - 1
            if not 0 <= idx < len(dev_list):
                raise ValueError
        except ValueError:
            print('Invalid selection.')
            return
        args.mac = dev_list[idx]['mac']

    # connect mode
    username = args.username if args.username else input('Username: ')
    password = args.password if args.password is not None else getpass.getpass('Password: ')

    mac = args.mac.upper()
    print(f'Trying {mac}...')

    client = MACTelnetClient(mac, username, password, debug=args.debug)
    try:
        client.connect()
        print(f'Connected to {mac}')
        if args.dump:
            client.dump_loop()
        else:
            client.interactive_loop()
    except ConnectionError as e:
        print(f'\nConnection error: {e}', file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        pass
    finally:
        client.close()
        print(f'\nConnection to {mac} closed.')


if __name__ == '__main__':
    main()
