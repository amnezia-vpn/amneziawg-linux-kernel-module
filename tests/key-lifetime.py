# SPDX-License-Identifier: GPL-2.0
"""Exercise native AWG RX/TX key expiration in an isolated loopback namespace.

No production peer, address, route, firewall or client key is used.
"""

import argparse
import base64
import hashlib
import hmac
import json
import os
import pathlib
import secrets
import socket
import struct
import subprocess
import sys
import time
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

NS = "awg-rat-regression"
IFACE = "rat0"
PORT = 51998


def H(x):
    return hashlib.blake2s(x).digest()


def kdf(ck, data, n=2):
    temp = hmac.new(ck, data, hashlib.blake2s).digest()
    out = []
    last = b""
    for i in range(1, n + 1):
        last = hmac.new(temp, last + bytes([i]), hashlib.blake2s).digest()
        out.append(last)
    return out


def pub(key):
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


def rawkey(key):
    return key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )


def enc(key, data, aad):
    return ChaCha20Poly1305(key).encrypt(bytes(12), data, aad)


def checksum(data):
    data += b"\0" * (len(data) % 2)
    s = sum(struct.unpack("!" + str(len(data) // 2) + "H", data))
    while s >> 16:
        s = (s & 65535) + (s >> 16)
    return ~s & 65535


def icmp(kind, seq):
    packet = struct.pack("!BBHHH", kind, 0, 0, 12345, seq) + b"awg-rat-regression"
    return packet[:2] + struct.pack("!H", checksum(packet)) + packet[4:]


def ip_packet(payload):
    head = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        len(payload) + 20,
        1,
        0,
        64,
        1,
        0,
        socket.inet_aton("10.253.90.2"),
        socket.inet_aton("10.253.90.1"),
    )
    return head[:10] + struct.pack("!H", checksum(head)) + head[12:] + payload


class Client:
    def __init__(self, server, private, psk):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.connect(("127.0.0.1", PORT))
        self.sock.settimeout(0.1)
        self.index = secrets.randbits(32)
        self.counter = 0
        e = X25519PrivateKey.generate()
        ep = pub(e)
        ck = H(b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s")
        hh = H(H(ck + b"WireGuard v1 zx2c4 Jason@zx2c4.com") + server)
        hh = H(hh + ep)
        ck = kdf(ck, ep, 1)[0]
        ck, key = kdf(ck, e.exchange(X25519PublicKey.from_public_bytes(server)))
        static = enc(key, pub(private), hh)
        hh = H(hh + static)
        ck, key = kdf(ck, private.exchange(X25519PublicKey.from_public_bytes(server)))
        now = time.time_ns()
        stamp = struct.pack("!QI", now // 10**9 + 0x400000000000000A, now % 10**9)
        encrypted = enc(key, stamp, hh)
        hh = H(hh + encrypted)
        message = struct.pack("<II", 1, self.index) + ep + static + encrypted
        message += hashlib.blake2s(
            message, key=H(b"mac1----" + server), digest_size=16
        ).digest() + bytes(16)
        self.sock.send(message)
        deadline = time.monotonic() + 3
        response = None
        while time.monotonic() < deadline:
            try:
                candidate = self.sock.recv(4096)
                if len(candidate) == 92 and struct.unpack_from("<I", candidate)[0] == 2:
                    response = candidate
                    break
            except socket.timeout:
                pass
        assert response is not None, "No native module handshake response"
        _, self.remote_index, index = struct.unpack_from("<III", response)
        assert index == self.index
        assert hmac.compare_digest(
            response[60:76],
            hashlib.blake2s(
                response[:60], key=H(b"mac1----" + pub(private)), digest_size=16
            ).digest(),
        )
        peer_ep = response[12:44]
        hh = H(hh + peer_ep)
        ck = kdf(ck, peer_ep, 1)[0]
        ck = kdf(ck, e.exchange(X25519PublicKey.from_public_bytes(peer_ep)), 1)[0]
        ck = kdf(ck, private.exchange(X25519PublicKey.from_public_bytes(peer_ep)), 1)[0]
        ck, temp, key = kdf(ck, psk, 3)
        hh = H(hh + temp)
        assert ChaCha20Poly1305(key).decrypt(bytes(12), response[44:60], hh) == b""
        self.sendkey, self.recvkey = kdf(ck, b"")
        self.started = time.monotonic()

    def send_ping(self, seq):
        data = ip_packet(icmp(8, seq))
        data += bytes((-len(data)) % 16)
        counter = self.counter
        self.counter += 1
        packet = struct.pack("<IIQ", 4, self.remote_index, counter) + ChaCha20Poly1305(
            self.sendkey
        ).encrypt(struct.pack("<IQ", 0, counter), data, b"")
        self.sock.send(packet)

    def receive(self, kind, seq, timeout=0.6):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                packet = self.sock.recv(4096)
            except socket.timeout:
                continue
            if len(packet) < 32 or struct.unpack_from("<I", packet)[0] != 4:
                continue
            _, idx, counter = struct.unpack_from("<IIQ", packet)
            if idx != self.index:
                continue
            data = ChaCha20Poly1305(self.recvkey).decrypt(
                struct.pack("<IQ", 0, counter), packet[16:], b""
            )
            if len(data) < 28 or data[9] != 1:
                continue
            offset = (data[0] & 15) * 4
            if (
                len(data) >= offset + 8
                and data[offset] == kind
                and struct.unpack_from("!HH", data, offset + 4) == (12345, seq)
            ):
                return True
        return False


def case(lifetime, late, expect_expired=True, intermediate=None):
    server = X25519PrivateKey.generate()
    client = X25519PrivateKey.generate()
    psk = os.urandom(32)
    subprocess.run(["ip", "link", "add", IFACE, "type", "amneziawg"], check=True)
    s = None
    raw = None
    try:
        config = (
            "[Interface]\nPrivateKey = "
            + base64.b64encode(rawkey(server)).decode()
            + "\nListenPort = "
            + str(PORT)
            + "\nS1 = 0\nS2 = 0\nS3 = 0\nS4 = 0\nH1 = 1\nH2 = 2\nH3 = 3\nH4 = 4\nRekeyAfterTime = 1000\nKeepaliveTimeout = 1000\nRekeyTimeout = 3\nRejectAfterTime = "
            + str(lifetime)
            + "\nRandomTrailers = off\nDisableCookies = on\n[Peer]\nPublicKey = "
            + base64.b64encode(pub(client)).decode()
            + "\nPresharedKey = "
            + base64.b64encode(psk).decode()
            + "\nAllowedIPs = 10.253.90.2/32\n"
        )
        result = subprocess.run(
            ["awg", "setconf", IFACE, "/dev/stdin"],
            input=config,
            text=True,
            capture_output=True,
        )
        assert result.returncode == 0, "Native regression configuration rejected"
        subprocess.run(
            ["ip", "addr", "add", "10.253.90.1/30", "dev", IFACE], check=True
        )
        subprocess.run(["ip", "link", "set", IFACE, "up"], check=True)
        s = Client(pub(server), client, psk)
        raw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

        def tx(seq):
            raw.sendto(icmp(8, seq), ("10.253.90.2", 0))
            return s.receive(8, seq)

        def rx(seq):
            s.send_ping(seq)
            return s.receive(0, seq)

        assert rx(1) and tx(2), "Early RX/TX did not work"
        middle = None
        if intermediate is not None:
            time.sleep(max(0, intermediate - (time.monotonic() - s.started)))
            middle = {"rx": rx(3), "tx": tx(4)}
            assert all(middle.values()), "Key expired earlier than configured"
        time.sleep(max(0, late - (time.monotonic() - s.started)))
        late_rx = rx(5)
        late_tx = tx(6)
        return {
            "rejectAfterTime": lifetime,
            "lateAgeSeconds": round(time.monotonic() - s.started, 2),
            "earlyRxTx": True,
            "intermediate": middle,
            "lateRx": late_rx,
            "lateTx": late_tx,
            "expiredAsConfigured": not late_rx and not late_tx,
        }
    finally:
        if s:
            s.sock.close()
        if raw:
            raw.close()
        subprocess.run(["ip", "link", "delete", IFACE], check=True)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--inner", action="store_true")
    p.add_argument("--expect", choices=["broken", "fixed"], required=True)
    p.add_argument("--long", action="store_true")
    a = p.parse_args()
    if not a.inner:
        existing = subprocess.check_output(["ip", "netns", "list"], text=True)
        assert NS not in existing.split(), "Regression namespace already exists"
        subprocess.run(["ip", "netns", "add", NS], check=True)
        try:
            subprocess.run(["ip", "-n", NS, "link", "set", "lo", "up"], check=True)
            q = subprocess.run(
                [
                    "ip",
                    "netns",
                    "exec",
                    NS,
                    sys.executable,
                    str(pathlib.Path(__file__).resolve()),
                    "--inner",
                    "--expect",
                    a.expect,
                ]
                + (["--long"] if a.long else []),
                timeout=265,
            )
            return q.returncode
        finally:
            subprocess.run(
                ["ip", "-n", NS, "link", "delete", IFACE], capture_output=True
            )
            subprocess.run(["ip", "netns", "delete", NS], check=True)
    tests = [case(4, 6)]
    assert tests[0]["expiredAsConfigured"] == (
        a.expect == "fixed"
    ), "RejectAfterTime regression verdict mismatch"
    if a.expect == "fixed":
        tests.append(case("4-8", 9))
        assert tests[-1]["expiredAsConfigured"]
    if a.long:
        assert a.expect == "fixed"
        tests.append(case("1-210", 212, intermediate=185))
        assert tests[-1]["expiredAsConfigured"]
    print(
        json.dumps(
            {
                "expected": a.expect,
                "passed": True,
                "cases": tests,
                "productionConfigurationUntouched": True,
            }
        ),
        flush=True,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
