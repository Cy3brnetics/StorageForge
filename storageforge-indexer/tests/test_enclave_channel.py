"""The channel to the key enclave (roadmap section 14, "Layers"; enclave.py): a Noise handshake against the enclave's static key, pinned
the first time it is spoken to. The real enclave program on a socket file, and between it and the client a relay that reads, and in one
test changes, everything that crosses. What must hold: nothing that crosses can be read; a frame changed on the way is refused; what
shows another key than the one pinned is not spoken to at all, so the vault secret never reaches it; and what does not begin with
the handshake gets no answer."""
import base64
import io
import os
import socket
import stat
import struct
import subprocess
import threading
import time
import unittest
from unittest import mock

from storageforge_index import cli, enclave, vault
from test_enclave import SECRET, build
from test_enclave_stepup import Base


class Relay:
    """Something else on the host, sitting on the path between the web app and the enclave."""

    def __init__(self, path, target, change=None):
        self.path, self.target, self.change = str(path), str(target), change
        self.seen = {'out': bytearray(), 'back': bytearray()}
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener.bind(self.path)
        self.listener.listen(8)
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while True:
            try:
                client, _ = self.listener.accept()
            except OSError:
                return
            server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            server.connect(self.target)
            threading.Thread(target=self._pump, args=(client, server, 'out'), daemon=True).start()
            threading.Thread(target=self._pump, args=(server, client, 'back'), daemon=True).start()

    def _pump(self, src, dst, way):
        frames = 0
        try:
            while True:
                head = self._read(src, 4)
                body = self._read(src, struct.unpack('>I', head)[0])
                frames += 1
                if self.change:
                    body = self.change(way, frames, body)
                self.seen[way] += head + body
                dst.sendall(head + body)
        except (OSError, EOFError):
            pass
        finally:
            for s in (src, dst):
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    @staticmethod
    def _read(s, n):
        out = b''
        while len(out) < n:
            chunk = s.recv(n - len(out))
            if not chunk:
                raise EOFError
            out += chunk
        return out

    def close(self):
        self.listener.close()


class Channel(Base):
    def relay(self, change=None):
        r = Relay(self.tmp / 'relay.sock', self.path, change)
        self.addCleanup(r.close)
        return r, f'unix:{self.tmp}/relay.sock'

    def test_nothing_that_crosses_the_socket_can_be_read_and_the_same_request_never_looks_the_same(self):
        self.e.lock()
        relay, address = self.relay()
        with vault.Vault(self.db, self.conn, SECRET).unlock() as old:
            old.generate_key('k')
        through = enclave.Enclave(address)
        self.assertEqual(through.unlock(SECRET, self.meta())['state'], 'unlocked')
        self.assertTrue(through.sign(self.row('k'), b'what ssh asks an agent to sign')[0])
        first = len(relay.seen['out'])
        self.assertEqual(through.status()['state'], 'unlocked')
        again = len(relay.seen['out'])
        self.assertEqual(through.status()['state'], 'unlocked')
        crossed = bytes(relay.seen['out']) + bytes(relay.seen['back'])
        for plain in (SECRET, base64.b64encode(SECRET), b'unlock', b'"op"', b'"ok"', b'unlocked', b'signature', base64.b64encode(b'what ssh asks an agent to sign'), self.row('k')['key_uuid'].encode()):
            self.assertNotIn(plain, crossed, plain)
        one, two = bytes(relay.seen['out'][first:again]), bytes(relay.seen['out'][again:])
        self.assertEqual(len(one), len(two))
        self.assertNotEqual(one, two, 'each connection has keys of its own: the same question is other bytes every time')
        self.assertGreaterEqual(self.e.status()['channel']['handshakes'], 4)

    def test_a_frame_changed_on_the_way_is_refused_and_the_enclave_counts_it(self):
        def flip(way, frame, body):          # the first request after the handshake, one bit of it
            return body[:-1] + bytes([body[-1] ^ 1]) if way == 'out' and frame == 2 else body
        relay, address = self.relay(flip)
        self.refused('down', enclave.Enclave(address).status)
        self.assertEqual(self.e.status()['bad_requests'], 1)

        def answer(way, frame, body):        # and an answer changed on its way back is not believed
            return body[:-1] + bytes([body[-1] ^ 1]) if way == 'back' and frame == 2 else body
        relay.change = answer
        self.assertIn('stopped answering', self.refused('down', enclave.Enclave(address).status))
        self.assertEqual(self.e.status()['bad_requests'], 1, 'that one the enclave could not see')

    def test_what_shows_another_key_than_the_one_pinned_is_never_sent_the_secret(self):
        """Something takes the enclave's place at its address: here the same program started again, which has another key."""
        self.e.lock()
        self.assertEqual(base64.b64encode(enclave.pinned(self.address)).decode(), self.e.status()['channel']['key'])
        self.assertEqual(stat.S_IMODE(enclave.pin_file().stat().st_mode), 0o600)
        self.stop()
        self.proc = subprocess.Popen([str(build()), '--unix', str(self.path)], stderr=subprocess.PIPE)          # and nobody pins it
        until_up = enclave.Enclave(self.address, timeout=5)
        for _ in range(200):
            try:
                until_up.status()
            except enclave.EnclaveError as exc:
                if 'not the key enclave that was pinned' in str(exc):
                    break
                time.sleep(0.05)
        said = self.refused('down', self.e.unlock, SECRET, self.meta())
        self.assertIn('is not the key enclave that was pinned there', said)
        self.assertIn('Nothing was sent to it', said)
        os.environ['STORAGEFORGE_VAULT_SECRET'] = SECRET.decode()
        with self.assertRaises(vault.VaultLocked):                             # the vault does not open through it either
            vault.Vault(self.db, self.conn).unlock()
        enclave.forget_pin(self.address)                                       # looking at it afterwards: it was asked nothing
        st = self.e.status()
        self.assertEqual((st['state'], st['auth_failed'], st['bad_requests']), ('locked', 0, 0))
        with vault.Vault(self.db, self.conn).unlock() as v:                    # and pinned anew, as whoever restarted it would, it is the enclave again
            self.assertEqual(v.enclave, self.address)

    def test_the_key_can_be_named_and_another_one_is_refused_whatever_is_pinned(self):
        key = self.e.status()['channel']['key']
        with mock.patch.dict(os.environ, {enclave.KEY_ENV: key}):
            enclave.forget_pin(self.address)
            self.assertEqual(self.e.status()['state'], 'unlocked')
            self.assertIsNone(enclave._pins().get(self.address), 'a named key is not learnt from what answers')
        with mock.patch.dict(os.environ, {enclave.KEY_ENV: base64.b64encode(os.urandom(32)).decode()}):
            self.assertIn('not the key enclave that was pinned', self.refused('down', self.e.status))
        with mock.patch.dict(os.environ, {enclave.KEY_ENV: 'not a key'}):
            self.assertIn('is not a key', self.refused('down', self.e.status))

    def bare(self):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(8)
        s.connect(str(self.path))
        self.addCleanup(s.close)
        return s

    def gone(self, s):
        try:
            return s.recv(16) == b''
        except ConnectionResetError:
            return True

    def test_what_does_not_begin_with_the_handshake_gets_no_answer(self):
        frame = b'{"op":"status"}'                                             # as a client from before the channel spoke
        s = self.bare()
        s.sendall(struct.pack('>I', len(frame)) + frame)
        self.assertTrue(self.gone(s), 'it hangs up without a word')
        s = self.bare()
        s.sendall(struct.pack('>I', 32) + bytes(32))                           # a point of small order for a key: every secret it makes is zero
        self.assertTrue(self.gone(s))
        self.assertEqual(self.e.status()['bad_requests'], 2)
        s = self.bare()                                                        # the handshake done by hand, then a frame that is not encrypted
        probe = enclave.Enclave(self.address, timeout=8)
        probe._connect()
        self.addCleanup(probe.close)
        probe.sock.sendall(struct.pack('>I', len(frame) + 16) + frame + bytes(16))
        self.assertTrue(self.gone(probe.sock))
        self.assertEqual(self.e.status()['bad_requests'], 3)

    def test_the_command_shows_the_pinned_key_and_pins_anew_after_a_restart(self):
        def run(*args):
            out = io.StringIO()
            with mock.patch('sys.stdout', out), mock.patch('sys.stderr', out):
                return cli.main(['--db', self.db.url, 'vault', 'enclave-pin', *args]), out.getvalue()
        code, said = run()
        self.assertEqual((code, said.split()), (0, [self.address, self.e.status()['channel']['key']]))
        self.stop()
        self.proc = subprocess.Popen([str(build()), '--unix', str(self.path)], stderr=subprocess.PIPE)
        until = time.time() + 15
        while True:
            code, said = run()
            if 'not the key enclave that was pinned' in said or time.time() > until:
                break
            time.sleep(0.05)
        self.assertEqual(code, 1, said)
        code, said = run('--renew')
        self.assertEqual(code, 0, said)
        self.assertEqual(said.split()[1], self.e.status()['channel']['key'])
        with mock.patch.dict(os.environ):
            del os.environ['STORAGEFORGE_ENCLAVE']
            self.assertEqual(run()[0], 2)


if __name__ == '__main__':
    unittest.main()
