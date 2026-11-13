# SPDX-License-Identifier: GPL-2.0
"""Destructive regression cases: run only inside a disposable debug-kernel VM."""
import errno
import os
import pathlib
import socket
import struct
import subprocess
import threading
import time
import unittest


def nla(kind, value):
    raw = struct.pack('HH', len(value) + 4, kind) + value
    return raw + bytes(-len(raw) % 4)


def attrs(raw):
    result = {}
    while len(raw) >= 4:
        length, kind = struct.unpack_from('HH', raw)
        if length < 4 or length > len(raw):
            raise ValueError('Invalid netlink attribute')
        result[kind & 0x3fff] = raw[4:length]
        raw = raw[(length + 3) & ~3:]
    return result


def u16(n):
    return struct.pack('H', n)


def u32(n):
    return struct.pack('I', n)


def interval(lo, hi):
    return u32(lo | (hi << 16))


class Netlink:
    def __init__(self, protocol=16):
        self.sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, protocol)
        self.sock.bind((0, 0))
        self.sock.settimeout(4)
        self.seq = 0

    def request(self, kind, payload, flags=5):
        self.seq += 1
        self.sock.send(struct.pack('IHHII', 16 + len(payload), kind, flags,
                                   self.seq, 0) + payload)
        result = []
        while True:
            raw = self.sock.recv(262144)
            while len(raw) >= 16:
                length, msgtype, _, sequence, _ = struct.unpack_from('IHHII', raw)
                body = raw[16:length]
                raw = raw[(length + 3) & ~3:]
                if sequence != self.seq:
                    continue
                if msgtype in (2, 3):
                    code = struct.unpack_from('i', body)[0] if len(body) >= 4 else 0
                    if code:
                        raise OSError(-code, os.strerror(-code))
                    return result
                result.append(body)
                if not flags & 4 and not flags & 0x300:
                    return result

    def close(self):
        self.sock.close()


class Device:
    # Attribute numbers follow src/uapi/wireguard.h.
    def __init__(self, name):
        self.name = name
        self.netlink = Netlink()
        family = self.netlink.request(16, b'\x03\x01\0\0' + nla(2, b'amneziawg\0'))
        self.family = struct.unpack('H', attrs(family[0][4:])[1])[0]
        route = Netlink(0)
        try:
            info = struct.pack('BBHiII', socket.AF_UNSPEC, 0, 0, 0, 0, 0)
            route.request(16, info + nla(3, name.encode() + b'\0') +
                          nla(18 | 0x8000, nla(1, b'amneziawg\0')), flags=0x605)
        finally:
            route.close()

    def set(self, *values):
        self.netlink.request(self.family, b'\x01\x03\0\0' +
                             nla(2, self.name.encode() + b'\0') + b''.join(values))

    def get(self):
        data = self.netlink.request(self.family, b'\x00\x03\0\0' +
                                    nla(2, self.name.encode() + b'\0'), flags=0x301)
        return attrs(data[0][4:])

    def close(self):
        subprocess.run(['ip', 'link', 'del', self.name], check=False, capture_output=True)
        self.netlink.close()


def command(*args):
    return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT)


class Hardening(unittest.TestCase):
    def setUp(self):
        self.device = Device('hard0')

    def tearDown(self):
        self.device.close()

    def rejected(self, *values):
        with self.assertRaises(OSError) as error:
            self.device.set(*values)
        self.assertIn(error.exception.errno, (errno.EINVAL, errno.EMSGSIZE))

    def test_01_reject_negative_and_oversized_cps(self):
        for text in ['<r -1>', '<rc -1>', '<rd -1>', '<r -1><b 0x4141>',
                     '<r 65508>', '<r 32754><r 32754>']:
            with self.subTest(text=text):
                self.rejected(nla(21, text.encode() + b'\0'))

    def test_02_ranges_and_partial_updates(self):
        self.device.set(nla(10, u16(10)), nla(11, u16(50)))
        self.rejected(nla(10, u16(51)))
        self.rejected(nla(11, u16(9)))
        self.assertEqual(self.device.get()[10], u16(10))
        self.assertEqual(self.device.get()[11], u16(50))
        for kind in range(27, 33):
            with self.subTest(kind=kind):
                self.rejected(nla(kind, interval(7, 3)))
                self.device.set(nla(kind, interval(0, 0)))
                self.device.set(nla(kind, interval(3, 7)))
        self.rejected(nla(14, struct.pack('Q', 9 | (3 << 32))))
        self.rejected(nla(8 | 0x8000, nla(1 | 0x8000,
            nla(1, bytes(range(32))) + nla(5, interval(35, 25)))))
        self.assertFalse(self.device.get().get(8, b''))

    def test_03_failed_cps_update_keeps_wire_packet(self):
        capture = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        capture.bind(('127.0.0.1', 0))
        capture.settimeout(8)
        try:
            self.device.set(nla(3, os.urandom(32)), nla(21, b'<b 0x4142>\0'))
            self.rejected(nla(21, b'<unknown>\0'))
            self.assertEqual(self.device.get()[21], b'<b 0x4142>\0')
            command('ip', 'link', 'set', 'hard0', 'up')
            endpoint = struct.pack('H', socket.AF_INET) + struct.pack('!H', capture.getsockname()[1]) + socket.inet_aton('127.0.0.1') + bytes(8)
            peer = nla(1, bytes(range(32))) + nla(4, endpoint) + nla(5, interval(1, 1))
            self.device.set(nla(8 | 0x8000, nla(1 | 0x8000, peer)))
            self.assertEqual(capture.recv(2048), b'AB')
        finally:
            capture.close()

    def test_04_header_protection_softirq_and_updates(self):
        key = os.urandom(32)
        self.device.set(*(nla(k, u16(12)) for k in (12, 13, 19, 20)),
                        nla(26, key), nla(6, u16(55188)))
        command('ip', 'link', 'set', 'hard0', 'up')
        before = command('dmesg')
        errors = []

        def writer():
            try:
                for _ in range(300):
                    self.device.set(nla(26, key))
            except Exception as e:
                errors.append(str(e))

        worker = threading.Thread(target=writer)
        worker.start()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            for _ in range(600):
                sock.sendto(bytes(96), ('127.0.0.1', 55188))
        worker.join(timeout=20)
        self.assertFalse(worker.is_alive())
        self.assertFalse(errors)
        time.sleep(0.1)
        new = command('dmesg')[len(before):]
        for marker in ('sleeping function called', 'scheduling while atomic',
                       'possible recursive locking', 'inconsistent lock state', 'KASAN:'):
            self.assertNotIn(marker, new)

    def test_05_legacy_and_awg31_traffic(self):
        for mode in ('wireguard', 'awg2', 'awg31'):
            with self.subTest(protocol=mode):
                other = Device('hard1')
                try:
                    self.device.set(nla(3, os.urandom(32)), nla(6, u16(55190)))
                    other.set(nla(3, os.urandom(32)), nla(6, u16(55191)))
                    if mode == 'awg2':
                        for dev in (self.device, other):
                            dev.set(nla(12, u16(17)), nla(13, u16(31)),
                                    *(nla(14 + n, struct.pack('Q', (12345 + n) * 0x100000001)) for n in range(4)))
                    if mode == 'awg31':
                        hpk = os.urandom(32)
                        for dev in (self.device, other):
                            dev.set(*(nla(k, u16(12)) for k in (12, 13, 19, 20)),
                                    nla(26, hpk), nla(33, b'\x01'), nla(34, b'\x01'),
                                    nla(9, u16(6)), nla(10, u16(10)), nla(11, u16(50)))
                    public = [self.device.get()[4], other.get()[4]]
                    psk = os.urandom(32)
                    for index, dev in enumerate((self.device, other)):
                        remote = 1 - index
                        ip = '10.99.0.' + str(remote + 1)
                        endpoint = struct.pack('H', socket.AF_INET) + struct.pack('!H', 55190 + remote) + socket.inet_aton('127.0.0.1') + bytes(8)
                        allowed = nla(1, u16(socket.AF_INET)) + nla(2, socket.inet_aton(ip)) + nla(3, b'\x20')
                        peer = nla(1, public[remote]) + nla(2, psk) + nla(4, endpoint) + nla(9 | 0x8000, nla(1 | 0x8000, allowed))
                        dev.set(nla(8 | 0x8000, nla(1 | 0x8000, peer)))
                        name = 'hard' + str(index)
                        namespace = 'awg-hardening-' + str(index)
                        command('ip', 'netns', 'add', namespace)
                        command('ip', 'link', 'set', name, 'netns', namespace)
                        command('ip', '-n', namespace, 'addr', 'add', '10.99.0.' + str(index + 1) + '/24', 'dev', name)
                        command('ip', '-n', namespace, 'link', 'set', name, 'up')
                        command('ip', '-n', namespace, 'link', 'set', 'lo', 'up')
                    for index in (0, 1):
                        output = command('ip', 'netns', 'exec', 'awg-hardening-' + str(index),
                                         'ping', '-c', '3', '-W', '3', '10.99.0.' + str(2 - index))
                        self.assertIn(', 0% packet loss', output)
                finally:
                    for index in (0, 1):
                        subprocess.run(['ip', 'netns', 'del', 'awg-hardening-' + str(index)], capture_output=True)
                    other.netlink.close()
                if mode != 'awg31':
                    self.device.netlink.close()
                    self.device = Device('hard0')

    def test_06_junk_allocation_failure_keeps_handshake(self):
        fault = pathlib.Path('/sys/kernel/debug/failslab')
        self.assertTrue(fault.exists(), 'Enable FAILSLAB in the lab kernel')
        symbols = [line.split() for line in pathlib.Path('/proc/kallsyms').read_text().splitlines()]
        index = next(i for i, row in enumerate(symbols)
                     if row[2:] == ['wg_packet_send_handshake_initiation', '[amneziawg]'])
        start = int(symbols[index][0], 16)
        end = next(int(row[0], 16) for row in symbols[index + 1:] if int(row[0], 16) > start)
        self.assertGreater(start, 0)
        self.device.set(nla(3, os.urandom(32)), nla(9, u16(6)),
                        nla(10, u16(10)), nla(11, u16(50)))
        command('ip', 'link', 'set', 'hard0', 'up')
        capture = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        capture.bind(('127.0.0.1', 0))
        capture.settimeout(8)
        before = command('dmesg')
        settings = {'probability': '0', 'interval': '1', 'times': '1', 'space': '0',
                    'verbose': '2', 'task-filter': '0', 'cache-filter': '0',
                    'ignore-gfp-wait': '0', 'stacktrace-depth': '32',
                    'require-start': hex(start), 'require-end': hex(end)}
        try:
            for name, value in settings.items():
                (fault / name).write_text(value)
            (fault / 'probability').write_text('100')
            endpoint = struct.pack('H', socket.AF_INET) + struct.pack('!H', capture.getsockname()[1]) + socket.inet_aton('127.0.0.1') + bytes(8)
            self.device.set(nla(8 | 0x8000, nla(1 | 0x8000,
                nla(1, bytes(range(32))) + nla(4, endpoint) + nla(5, interval(1, 1)))))
            for _ in range(6):
                self.assertIn(len(capture.recv(2048)), range(10, 51))
            self.assertEqual(len(capture.recv(2048)), 148)
            self.assertEqual((fault / 'times').read_text().strip(), '0')
        finally:
            (fault / 'probability').write_text('0')
            capture.close()
        new = command('dmesg')[len(before):]
        self.assertIn('FAULT_INJECTION: forcing a failure', new)
        self.assertIn('wg_packet_send_handshake_initiation', new)
        self.assertNotIn('Oops:', new)
        self.assertNotIn('KASAN:', new)


if __name__ == '__main__':
    if os.geteuid() != 0 or os.environ.get('AWG_DISPOSABLE_LAB') != '1':
        raise SystemExit('Use a disposable VM and explicitly set AWG_DISPOSABLE_LAB=1')
    unittest.main(verbosity=2)
