"""The key enclave (roadmap section 14): the real program (enclave/, built with cargo) on a socket file, against a vault the Python
code made. What must hold: it opens exactly the vault's own ciphertexts, so nothing stored changes; a signature made inside verifies
against the key's public half; a key made inside is one the vault can use; no request gets a private key or the KEK out; and its
limits are its own. Skipped where there is no cargo."""
import base64
import hashlib
import hmac
import json
import os
import shutil
import socket
import struct
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

import dbfactory
from storageforge_index import enclave, vault

ROOT = Path(__file__).resolve().parents[1]
SECRET = b's' * 48
BINARY = None


def build():
    """The enclave, built once for the run. None where it cannot be."""
    global BINARY
    if BINARY is None and shutil.which('cargo'):
        p = subprocess.run(['cargo', 'build', '--quiet', '--locked'], cwd=ROOT / 'enclave', capture_output=True, text=True)
        out = ROOT / 'enclave' / 'target' / 'debug' / 'storageforge-enclave'
        BINARY = out if p.returncode == 0 and out.exists() else False
        if not BINARY:
            raise AssertionError(f'cargo is here and the enclave does not build:\n{p.stderr[-2000:]}')
    return BINARY


def strings(blob):
    """The length-prefixed strings of an SSH wire blob."""
    out = []
    while blob:
        n = struct.unpack('>I', blob[:4])[0]
        out.append(blob[4:4 + n])
        blob = blob[4 + n:]
    return out


@unittest.skipUnless(shutil.which('cargo'), 'needs cargo to build the enclave (CI builds it)')
class Enclave(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.db = dbfactory.make(self, self.tmp / 'index.db')
        self.conn = self.db.connect()
        self.addCleanup(self.conn.close)
        self.db.migrate(self.conn)
        self.vault = vault.Vault(self.db, self.conn, SECRET)
        self.vault.init()
        self.vault.unlock()
        self.addCleanup(self.vault.close)
        self.path = self.tmp / 'enclave.sock'
        self.proc = subprocess.Popen([str(build()), '--unix', str(self.path)], stderr=subprocess.PIPE)
        self.addCleanup(self.stop)
        until = time.time() + 10
        while not self.path.exists() and time.time() < until:
            time.sleep(0.02)
        self.e = enclave.Enclave(f'unix:{self.path}')
        self.addCleanup(self.e.close)

    def stop(self):
        self.proc.kill()
        self.proc.wait()
        self.proc.stderr.close()

    def meta(self):
        cols = ('kdf_salt', 'kdf_time_cost', 'kdf_memory_kib', 'kdf_lanes', 'verifier_nonce', 'verifier', 'audit_key_nonce', 'audit_key_wrapped')
        row = self.conn.all(f'SELECT {", ".join(cols)} FROM vault_meta WHERE id = 1')[0]
        return {c: (bytes(v) if isinstance(v, (bytes, memoryview)) else v) for c, v in zip(cols, row)}

    def row(self, name):
        cols = ('key_uuid', 'dek_nonce', 'wrapped_dek', 'key_nonce', 'ciphertext', 'public_key', 'key_id')
        r = self.conn.all(f'SELECT {", ".join(cols)} FROM ssh_keys WHERE name = :n', {'n': name})[0]
        return {c: (bytes(v) if isinstance(v, (bytes, memoryview)) else v) for c, v in zip(cols, r)}

    def unlock(self):
        return self.e.unlock(SECRET, self.meta())

    def refused(self, code, fn, *a, **kw):
        with self.assertRaises(enclave.EnclaveError) as got:
            fn(*a, **kw)
        self.assertEqual(got.exception.code, code, str(got.exception))
        return str(got.exception)

    # ── unlock ──
    def test_it_starts_locked_and_the_vaults_own_secret_unlocks_it(self):
        st = self.e.status()
        self.assertEqual((st['state'], st['protocol']), ('locked', 1))
        self.vault.generate_key('k')
        self.refused('locked', self.e.sign, self.row('k'), b'x')
        self.assertEqual(self.unlock()['state'], 'unlocked')
        self.assertEqual(self.e.status()['state'], 'unlocked')
        self.assertEqual(self.e.lock()['state'], 'locked')
        self.refused('locked', self.e.mac, '0' * 64, 'p')

    def test_a_wrong_secret_or_a_changed_verifier_does_not_unlock(self):
        self.assertIn('wrong vault secret', self.refused('auth', self.e.unlock, b'w' * 48, self.meta()))
        tampered = {**self.meta(), 'verifier': bytes(b ^ 1 for b in self.meta()['verifier'])}
        self.refused('auth', self.e.unlock, SECRET, tampered)
        self.assertEqual(self.e.status()['state'], 'locked')

    def test_argon2_costs_that_would_stall_it_or_are_worth_nothing_are_refused(self):
        for change in ({'kdf_memory_kib': 64}, {'kdf_memory_kib': 64 * 1024 * 1024}, {'kdf_time_cost': 0}, {'kdf_time_cost': 1000}, {'kdf_lanes': 0}):
            with self.subTest(change):
                self.e.close()
                self.refused('bad-request', self.e.unlock, SECRET, {**self.meta(), **change})

    # ── signing ──
    def verified(self, public_line, signature, data):
        key = serialization.load_ssh_public_key(public_line.encode())
        algo, sig = strings(signature)
        if isinstance(key, ed25519.Ed25519PublicKey):
            key.verify(sig, data)
        elif isinstance(key, rsa.RSAPublicKey):
            key.verify(sig, data, padding.PKCS1v15(), {b'rsa-sha2-256': hashes.SHA256(), b'rsa-sha2-512': hashes.SHA512()}[algo])
        else:
            r, s = (int.from_bytes(x, 'big') for x in strings(sig))
            key.verify(encode_dss_signature(r, s), data, ec.ECDSA(hashes.SHA384() if key.curve.name == 'secp384r1' else hashes.SHA256()))
        return algo.decode()

    def test_a_signature_made_inside_verifies_against_the_keys_public_half(self):
        self.unlock()
        self.vault.generate_key('ed')
        row = self.row('ed')
        sig, public = self.e.sign(row, b'what ssh asks an agent to sign')
        self.assertEqual(self.verified(row['public_key'], sig, b'what ssh asks an agent to sign'), 'ssh-ed25519')
        self.assertEqual(public, base64.b64decode(row['public_key'].split()[1]), 'the public key it says it signed with is the row\'s')
        with self.assertRaises(InvalidSignature):
            self.verified(row['public_key'], sig, b'something else')

    def test_rsa_signs_with_the_hash_asked_for_and_never_sha1_and_ecdsa_signs(self):
        self.unlock()
        pem = rsa.generate_private_key(65537, 3072).private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, serialization.NoEncryption())
        self.vault.add_key('rsa', pem)
        row = self.row('rsa')
        for flags, want in ((0, 'rsa-sha2-512'), (2, 'rsa-sha2-256'), (4, 'rsa-sha2-512'), (6, 'rsa-sha2-512')):
            with self.subTest(flags=flags):
                self.assertEqual(self.verified(row['public_key'], self.e.sign(row, b'data', flags)[0], b'data'), want)
        # many of them: a library read about half of these wrongly, the ones whose secret number has its top bit clear
        seen = set()
        for i in range(400):            # until both curves have had a key of each kind: a dozen or so
            if len(seen) == 4 and i >= 12:
                break
            curve, want = ((ec.SECP256R1(), 'ecdsa-sha2-nistp256'), (ec.SECP384R1(), 'ecdsa-sha2-nistp384'))[i % 2]
            key = ec.generate_private_key(curve)
            seen.add((want, key.private_numbers().private_value.bit_length() == curve.key_size))
            self.vault.add_key(f'ec{i}', key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, serialization.NoEncryption()))
            row = self.row(f'ec{i}')
            self.assertEqual(self.verified(row['public_key'], self.e.sign(row, b'data')[0], b'data'), want, i)
        self.assertEqual(len(seen), 4, 'both curves, with the top bit set and clear')

    def test_a_ciphertext_moved_to_another_row_or_changed_does_not_open(self):
        self.unlock()
        self.vault.generate_key('a')
        self.vault.generate_key('b')
        a, b = self.row('a'), self.row('b')
        self.refused('auth', self.e.sign, {**a, 'key_uuid': b['key_uuid']}, b'x')
        self.refused('auth', self.e.sign, {**a, 'wrapped_dek': b['wrapped_dek'], 'dek_nonce': b['dek_nonce']}, b'x')
        self.refused('auth', self.e.sign, {**a, 'ciphertext': a['ciphertext'][:-1] + bytes([a['ciphertext'][-1] ^ 1])}, b'x')
        self.assertTrue(self.e.sign(a, b'x')[0], 'and the row as it is stored still signs')

    # ── keys made inside ──
    def test_a_key_made_inside_is_one_the_vault_stores_and_can_use(self):
        """Nothing stored changes format: the row the enclave fills is the row the Python vault reads, and the other way round."""
        self.unlock()
        uuid = 'ab' * 16
        made = self.e.generate(uuid, 'ed25519', 'storageforge:inside')
        self.assertTrue(made['public_key'].startswith('ssh-ed25519 '))
        self.assertTrue(made['public_key'].endswith(' storageforge:inside'))
        self.conn.execute("""INSERT INTO ssh_keys (key_uuid, name, key_type, public_key, fingerprint, comment, dek_nonce, wrapped_dek, key_nonce, ciphertext, created_at, origin)
                             VALUES (:u, 'inside', 'ssh-ed25519', :p, :f, 'c', :dn, :wd, :kn, :ct, 1, 'generated')""",
                          {'u': uuid, 'p': made['public_key'], 'f': vault.fingerprint(made['public_key']), 'dn': made['dek_nonce'], 'wd': made['wrapped_dek'], 'kn': made['key_nonce'], 'ct': made['ciphertext']})
        row = self.row('inside')
        with self.vault.decrypt_key(row['key_id']) as buf:           # the vault as it is today opens it
            key = serialization.load_ssh_private_key(bytes(buf.view()), None)
        line = key.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()
        self.assertEqual(line, ' '.join(made['public_key'].split()[:2]))
        self.assertEqual(self.verified(made['public_key'], self.e.sign(row, b'x')[0], b'x'), 'ssh-ed25519')
        self.refused('bad-request', self.e.generate, 'not-a-uuid', 'ed25519')

    # ── the audit chain's MAC ──
    def test_the_audit_mac_is_the_one_the_vault_computes(self):
        self.unlock()
        prev, payload = 'a' * 64, json.dumps([1, 'gabe', 'x', None, None, 'ok', '{}'], separators=(',', ':'))
        want = hmac.new(bytes(self.vault.audit_key.view()), prev.encode() + payload.encode(), hashlib.sha256).hexdigest()
        self.assertEqual(self.e.mac(prev, payload), want)
        self.assertTrue(self.e.mac_matches(prev, payload, want))
        self.assertFalse(self.e.mac_matches(prev, payload + ' ', want))

    # ── nothing gets a key out ──
    def test_no_request_returns_a_private_key_or_the_kek(self):
        self.unlock()
        self.vault.generate_key('k')
        row = self.row('k')
        with self.vault.decrypt_key(row['key_id']) as buf:
            private = bytes(buf.view())
        body = private.split(b'\n')[1]
        for op in ('status', 'sign', 'generate', 'mac'):
            self.e.close()
            got = self.e.raw(json.dumps({'op': op, 'data': base64.b64encode(b'x').decode(), 'kind': 'ed25519', 'prev': '0' * 64, 'payload': 'p', **{k: (v if k == 'uuid' else base64.b64encode(v).decode())
                                         for k, v in {'uuid': row['key_uuid'], 'dek_nonce': row['dek_nonce'], 'wrapped_dek': row['wrapped_dek'], 'key_nonce': row['key_nonce'], 'ciphertext': row['ciphertext']}.items()}}).encode())
            text = json.dumps(got)
            self.assertNotIn('PRIVATE KEY', text, op)
            self.assertNotIn(body.decode(), text, op)
        for op in ('export', 'decrypt', 'unwrap', 'key', 'kek', 'dump', 'shell', 'read'):
            self.e.close()
            self.assertEqual(self.e.raw(json.dumps({'op': op, **enclave.Enclave._key(row)}).encode())['error'], 'bad-request', op)
            self.e.close()
            if self.e.status()['state'] == 'lockdown':
                self.unlock()

    # ── its limits are its own ──
    def test_what_no_honest_client_sends_ends_the_connection_and_five_of_them_lock_it_down(self):
        self.unlock()
        self.vault.generate_key('k')
        for i, frame in enumerate((b'not json', b'[1, 2]', b'{"op": "nope"}', b'{"op": "sign", "uuid": "x"}', b'{}'), 1):
            got = self.e.raw(frame)
            self.assertEqual(got['error'], 'bad-request')
            with self.assertRaises(enclave.EnclaveError):                # it hung up
                self.e.raw(b'{"op": "status"}')
            self.e.close()
            self.assertEqual(self.e.status()['bad_requests'], i)
        self.assertEqual(self.e.status()['state'], 'lockdown')
        self.assertIn('unlock it again', self.refused('lockdown', self.e.sign, self.row('k'), b'x'))
        self.refused('lockdown', self.e.lock)
        self.unlock()                                                     # only someone with the secret lifts it
        self.assertEqual((self.e.status()['state'], self.e.status()['bad_requests']), ('unlocked', 0))
        self.assertTrue(self.e.sign(self.row('k'), b'x')[0])

    def test_a_frame_larger_than_it_takes_is_not_read(self):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect(str(self.path))
        s.sendall(struct.pack('>I', (1 << 20) + 1) + b'x' * 64)
        try:
            self.assertEqual(s.recv(16), b'', 'it hangs up without an answer')
        except ConnectionResetError:
            pass                    # hung up with what was sent still unread: the same answer
        s.close()
        self.assertEqual(self.e.status()['bad_requests'], 1)

    def test_unlock_attempts_are_limited_inside(self):
        codes = []
        for _ in range(8):
            try:
                self.e.unlock(b'w' * 48, self.meta())
            except enclave.EnclaveError as exc:
                codes.append(exc.code)
        self.assertEqual(codes, ['auth'] * 6 + ['rate'] * 2, 'six a minute, then it says wait: the web app cannot raise that')

    def test_it_holds_nothing_after_a_restart(self):
        self.unlock()
        self.stop()
        self.proc = subprocess.Popen([str(build()), '--unix', str(self.path)], stderr=subprocess.PIPE)
        until = time.time() + 10
        while time.time() < until:
            try:
                self.e.close()
                st = self.e.status()
                break
            except enclave.EnclaveError:
                time.sleep(0.05)
        self.assertEqual(st['state'], 'locked')

    def test_an_enclave_that_is_not_there_fails_closed(self):
        gone = enclave.Enclave(f'unix:{self.tmp}/nobody-home.sock')
        self.assertIn('does not answer', self.refused('down', gone.status))
        self.refused('down', enclave.Enclave('tcp:10.0.0.1:1').status)


if __name__ == '__main__':
    unittest.main()
