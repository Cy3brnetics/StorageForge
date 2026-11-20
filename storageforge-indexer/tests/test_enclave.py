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
import stat
import socket
import struct
import subprocess
import tempfile
import time
import unittest
from unittest import mock
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
class Harness(unittest.TestCase):
    """A vault the Python code made, and the enclave program beside it."""

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
        self.start()
        self.addCleanup(self.stop)
        self.e = enclave.Enclave(self.address)
        self.addCleanup(self.e.close)
        self.answering()

    def start(self):
        """The program on a socket file. EnclaveImage starts the micro VM here instead."""
        self.path = self.tmp / 'enclave.sock'
        self.address = f'unix:{self.path}'
        self.proc = subprocess.Popen([str(build()), '--unix', str(self.path)], stderr=subprocess.PIPE)

    def stop(self):
        self.proc.kill()
        self.proc.wait()
        self.proc.stderr.close()

    def answering(self):
        until = time.time() + 15
        while True:
            try:
                self.e.close()
                self.e.address = self.address          # a restarted VM is at a new address
                return self.e.status()
            except enclave.EnclaveError:
                if time.time() > until:
                    raise
                time.sleep(0.05)

    def wire(self):
        """A bare socket to it, for what the client would never send."""
        probe = enclave.Enclave(self.address, timeout=5)
        probe._connect()
        return probe.sock

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



class Enclave(Harness):
    # ── unlock ──
    def test_it_starts_locked_and_the_vaults_own_secret_unlocks_it(self):
        st = self.e.status()
        self.assertEqual((st['state'], st['protocol']), ('locked', 2))
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

    # ── keys brought in, secrets given back, the secret rotated ──
    def test_an_imported_key_signs_and_a_weak_or_unreadable_one_is_refused(self):
        self.unlock()
        key = ec.generate_private_key(ec.SECP384R1())
        pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, serialization.NoEncryption())
        made = self.e.import_key('cd' * 16, pem)
        line = key.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()
        self.assertEqual(made['public'], base64.b64decode(line.split()[1]))
        row = {'key_uuid': 'cd' * 16, **made}
        self.assertEqual(self.verified(line, self.e.sign(row, b'x')[0], b'x'), 'ecdsa-sha2-nistp384')
        weak = rsa.generate_private_key(65537, 2048).private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, serialization.NoEncryption())
        self.assertIn('too weak', self.refused('key', self.e.import_key, 'ce' * 16, weak))
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', 'a passphrase', '-f', str(self.tmp / 'locked')], check=True)
        locked = (self.tmp / 'locked').read_bytes()          # with a passphrase: the enclave is given keys already opened, and takes no other
        for junk in (b'not a key', locked, pem[:200]):
            self.refused('key', self.e.import_key, 'cf' * 16, junk)

    def test_a_secret_sealed_inside_is_released_counted_and_limited(self):
        self.unlock()
        row = self.e.seal('aa' * 16, b'{"password": "pw-123456"}')
        self.assertEqual(self.e.release('aa' * 16, row), b'{"password": "pw-123456"}')
        self.assertEqual(self.e.status()['released'], 1)
        self.refused('auth', self.e.release, 'bb' * 16, row)                       # another row's uuid
        self.refused('auth', self.e.release, 'aa' * 16, {**row, 'ciphertext': bytes(b ^ 1 for b in row['ciphertext'])})
        self.e.close()
        self.refused('bad-request', self.e.seal, 'aa' * 16, b'x', purpose='key')
        self.e.close()
        self.refused('bad-request', self.e.seal, 'aa' * 16, b'')
        self.e.close()
        self.unlock()
        codes = []
        for _ in range(70):
            try:
                self.e.release('aa' * 16, row)
                codes.append('ok')
            except enclave.EnclaveError as exc:
                codes.append(exc.code)
        self.assertEqual(codes[:55], ['ok'] * 55)
        self.assertEqual(codes[-1], 'rate', 'sixty a minute for one secret, and the web app cannot raise it')
        self.assertEqual(self.e.release('ab' * 16, self.e.seal('ab' * 16, b'other')), b'other', 'another secret has its own count')

    def test_a_private_key_cannot_be_asked_for_as_a_secret(self):
        """release gives plaintext back, so it must never open what was sealed as a key."""
        self.unlock()
        self.vault.generate_key('k')
        row = self.row('k')
        as_secret = {'dek_nonce': row['dek_nonce'], 'wrapped_dek': row['wrapped_dek'], 'nonce': row['key_nonce'], 'ciphertext': row['ciphertext']}
        self.refused('auth', self.e.release, row['key_uuid'], as_secret)
        self.e.close()
        self.refused('bad-request', self.e.release, row['key_uuid'], as_secret, purpose='key')
        self.e.close()
        self.unlock()
        self.assertEqual(self.e.status()['released'], 0)

    def test_the_secret_is_rotated_inside_and_nothing_moves_until_it_is_committed(self):
        self.unlock()
        self.vault.generate_key('k')
        row = self.row('k')
        self.refused('state', self.e.rewrap, row['key_uuid'], row['dek_nonce'], row['wrapped_dek'])
        self.refused('state', self.e.rotate_commit)
        new, salt = b'n' * 48, b's' * 16
        meta = self.e.rotate_begin(new, salt, 1, 8192, 1)
        self.assertTrue(self.e.status()['rotating'])
        dn, wd = self.e.rewrap(row['key_uuid'], row['dek_nonce'], row['wrapped_dek'])
        self.assertTrue(self.e.sign(row, b'x')[0], 'until the commit the old rows are the ones that open')
        self.refused('auth', self.e.sign, {**row, 'dek_nonce': dn, 'wrapped_dek': wd}, b'x')
        self.assertEqual(self.e.rotate_abort()['rotated'], False)
        self.assertTrue(self.e.sign(row, b'x')[0])
        meta = self.e.rotate_begin(new, salt, 1, 8192, 1)
        dn, wd = self.e.rewrap(row['key_uuid'], row['dek_nonce'], row['wrapped_dek'])
        self.assertEqual(self.e.rotate_commit()['rotated'], True)
        self.assertTrue(self.e.sign({**row, 'dek_nonce': dn, 'wrapped_dek': wd}, b'x')[0])
        self.refused('auth', self.e.sign, row, b'x')
        self.e.lock()
        stored = {'kdf_salt': salt, 'kdf_time_cost': 1, 'kdf_memory_kib': 8192, 'kdf_lanes': 1, **meta}
        self.assertEqual(self.e.unlock(new, stored)['state'], 'unlocked', 'what it handed back is what unlocks it with the new secret')
        self.e.lock()
        self.refused('auth', self.e.unlock, SECRET, stored)

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
        for op in ('status', 'sign', 'generate', 'mac', 'import', 'seal', 'rewrap', 'rotate-begin'):
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
        s = self.wire()
        s.sendall(struct.pack('>I', (1 << 20) + 1) + b'x' * 64)
        try:
            self.assertEqual(s.recv(16), b'', 'it hangs up without an answer')
        except ConnectionResetError:
            pass                    # hung up with what was sent still unread: the same answer
        s.close()
        self.assertEqual(self.e.status()['bad_requests'], 1)

    def test_a_connection_that_goes_quiet_does_not_hold_the_others_out(self):
        """One connection is served at a time. A client that opens one and says nothing is dropped after a few seconds."""
        idle = self.wire()
        self.addCleanup(idle.close)
        started = time.time()
        self.assertEqual(self.e.status()['state'], 'locked')
        self.assertLess(time.time() - started, 9)
        self.assertEqual(self.e.status()['bad_requests'], 0, 'being slow is not being hostile')

    def test_unlock_attempts_are_limited_inside(self):
        codes, started = [], time.time()
        for _ in range(9):
            try:
                self.e.unlock(b'w' * 48, self.meta())
            except enclave.EnclaveError as exc:
                codes.append(exc.code)
        earned = int((time.time() - started) / 10) + 1       # one more every ten seconds, and a slow machine takes that long
        self.assertEqual(codes[:6], ['auth'] * 6)
        self.assertLessEqual(codes.count('auth'), 6 + earned, 'six a minute, then it says wait: the web app cannot raise that')
        self.assertEqual(codes[-1], 'rate')

    def test_it_holds_nothing_after_a_restart(self):
        self.unlock()
        self.stop()
        self.start()
        self.assertEqual(self.answering()['state'], 'locked')

    # ── ssh, with the key inside ──
    def test_ssh_signs_through_an_agent_that_has_no_key_to_load(self):
        """The real ssh-add and ssh-keygen talk to the socket: the key is listed, a signature made through it verifies, and what an
        agent can be asked besides those two is refused. The private key was never on this side."""
        self.unlock()
        self.vault.generate_key('k')
        row = self.row('k')
        with enclave.agent(self.address, row, ttl=60, base=str(self.tmp)) as sock:
            env = {'PATH': os.environ['PATH'], 'SSH_AUTH_SOCK': sock}
            listed = subprocess.run(['ssh-add', '-L'], env=env, capture_output=True, text=True)
            self.assertEqual(listed.stdout.split()[:2], row['public_key'].split()[:2], listed.stderr)
            pub = self.tmp / 'k.pub'
            pub.write_text(row['public_key'] + '\n')
            self.assertEqual(subprocess.run(['ssh-add', '-T', str(pub)], env=env, capture_output=True, text=True).returncode, 0, 'ssh-add -T signs with it and checks the signature')
            (self.tmp / 'msg').write_text('a message')
            made = subprocess.run(['ssh-keygen', '-Y', 'sign', '-f', str(pub), '-n', 'file', str(self.tmp / 'msg')], env=env, capture_output=True, text=True)
            self.assertEqual(made.returncode, 0, made.stderr)
            (self.tmp / 'allowed').write_text(f'gabe {row["public_key"]}\n')
            checked = subprocess.run(['ssh-keygen', '-Y', 'verify', '-f', str(self.tmp / 'allowed'), '-I', 'gabe', '-n', 'file', '-s', str(self.tmp / 'msg.sig')],
                                     input=(self.tmp / 'msg').read_text(), capture_output=True, text=True)
            self.assertEqual(checked.returncode, 0, checked.stderr + checked.stdout)
            for flag in ('-D', '-x'):                                    # remove every key, lock the agent: not this agent's to do
                self.assertNotEqual(subprocess.run(['ssh-add', flag], env=env, input='pw\npw\n', capture_output=True, text=True).returncode, 0, flag)
            self.assertEqual(subprocess.run(['ssh-add', '-L'], env=env, capture_output=True, text=True).stdout.split()[:2], row['public_key'].split()[:2], 'and the key is still there')
            self.assertEqual(os.stat(sock).st_mode & 0o777, 0o600)
        self.assertFalse(os.path.exists(sock), 'the socket is gone with the task')

    def test_the_agent_answers_for_its_one_key_and_nothing_else(self):
        blob, other = b'\x00\x00\x00\x0bssh-ed25519' + b'\x00\x00\x00\x20' + b'k' * 32, b'\x00\x00\x00\x0bssh-ed25519' + b'\x00\x00\x00\x20' + b'o' * 32
        asked = []
        sign = lambda data, flags: asked.append((data, flags)) or b'SIG'
        s = lambda b: struct.pack('>I', len(b)) + b
        self.assertEqual(enclave.agent_reply(bytes([11]), blob, b'c', sign), bytes([12]) + struct.pack('>I', 1) + s(blob) + s(b'c'))
        self.assertEqual(enclave.agent_reply(bytes([13]) + s(blob) + s(b'data') + struct.pack('>I', 2), blob, b'c', sign), bytes([14]) + s(b'SIG'))
        self.assertEqual(asked, [(b'data', 2)])
        for bad in (b'', bytes([13]) + s(other) + s(b'data') + struct.pack('>I', 0), bytes([13]) + s(blob) + s(b'data'), bytes([13]) + s(blob) + s(b'data') + struct.pack('>I', 0) + b'x',
                    bytes([13]) + struct.pack('>I', 1 << 30) + b'x', bytes([11]) + b'x', bytes([17]) + s(blob), bytes([18]), bytes([19]), bytes([22]) + s(b'pw'), bytes([27]) + s(b'ext')):
            self.assertEqual(enclave.agent_reply(bad, blob, b'c', sign), bytes([5]), bad[:12])
        self.assertEqual(len(asked), 1, 'none of those reached the enclave')

        def down(data, flags):
            raise enclave.EnclaveError('locked', 'the enclave is locked')
        self.assertEqual(enclave.agent_reply(bytes([13]) + s(blob) + s(b'data') + struct.pack('>I', 0), blob, b'c', down), bytes([5]), 'a locked enclave is a failure to ssh, not a hang')

    def test_an_enclave_that_is_not_there_fails_closed(self):
        gone = enclave.Enclave(f'unix:{self.tmp}/nobody-home.sock')
        self.assertIn('does not answer', self.refused('down', gone.status))
        self.refused('down', enclave.Enclave('tcp:10.0.0.1:1').status)


class VaultThroughEnclave(Harness):
    """The vault with STORAGEFORGE_ENCLAVE set (roadmap section 14): what the rest of the program calls is unchanged, and the KEK,
    the private keys and the audit key are not in this process."""

    def setUp(self):
        super().setUp()
        self.vault.close()                                   # the vault that held the secret did its part: it made the vault
        env = mock.patch.dict(os.environ, {'STORAGEFORGE_ENCLAVE': self.address, 'STORAGEFORGE_VAULT_SECRET': SECRET.decode(), 'XDG_RUNTIME_DIR': str(self.tmp)})
        env.start()
        self.addCleanup(env.stop)
        os.environ.pop('STORAGEFORGE_VAULT_SECRET_FILE', None)

    def forget_the_secret(self):
        os.environ.pop('STORAGEFORGE_VAULT_SECRET')

    def test_the_first_unlock_hands_the_secret_over_and_after_that_none_is_needed_here(self):
        with vault.Vault(self.db, self.conn).unlock() as v:
            self.assertEqual(v.enclave, self.address)
            self.assertIsNone(v._kek, 'the KEK was not derived here')
        self.assertEqual(self.e.status()['state'], 'unlocked')
        self.forget_the_secret()
        with vault.Vault(self.db, self.conn).unlock() as v:
            made = v.generate_key('inside')
            key = v.decrypt_key(self.row('inside')['key_id'])
            self.assertIsInstance(key, vault.EnclaveKey)
            with self.assertRaises(vault.VaultError):
                key.view()
            self.assertIsNone(v._kek)
        self.assertTrue(made['public_key'].startswith('ssh-ed25519 '))
        with vault.Vault(self.db, self.conn, SECRET).unlock() as old:      # whoever holds the secret still opens what was made inside
            with old.decrypt_key(self.row('inside')['key_id']) as buf:
                private = serialization.load_ssh_private_key(bytes(buf.view()), None)
        line = private.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()
        self.assertEqual(line, ' '.join(made['public_key'].split()[:2]))

    def test_a_locked_enclave_and_no_secret_is_a_locked_vault_and_so_is_one_that_is_gone(self):
        self.forget_the_secret()
        with self.assertRaises(vault.VaultLocked) as got:
            vault.Vault(self.db, self.conn).unlock()
        self.assertIn('enclave is locked', str(got.exception))
        os.environ['STORAGEFORGE_VAULT_SECRET'] = SECRET.decode()
        self.stop()
        with self.assertRaises(vault.VaultLocked) as got:                  # fails closed: it does not quietly open the vault here
            vault.Vault(self.db, self.conn).unlock()
        self.assertIn('does not answer', str(got.exception))

    def test_the_notification_center_says_when_it_is_locked_locked_down_or_gone(self):
        from storageforge_index import alerts, notifications
        self.assertEqual(enclave.problems()['security-enclave'][4], 'warn')
        with vault.Vault(self.db, self.conn).unlock():
            pass
        self.assertEqual(enclave.problems(), {})
        for _ in range(5):
            self.e.raw(b'not json')
            self.e.close()
        kind, ref, title, detail, level = enclave.problems()['security-enclave']
        self.assertEqual((kind, level, title), ('security-enclave', 'crit', 'The key enclave has locked itself down'))
        self.assertFalse(notifications.ignorable(kind, 'warn'), 'it cannot be muted or snoozed at any level')
        self.stop()
        gone = alerts.problems(self.conn)['security-enclave']
        self.assertEqual((gone[2], gone[4]), ('The key enclave does not answer', 'crit'))
        with mock.patch.dict(os.environ):
            del os.environ['STORAGEFORGE_ENCLAVE']
            self.assertEqual(enclave.problems(), {}, 'a site that does not use it is told nothing')

    def test_the_wrong_secret_in_the_environment_does_not_unlock_it(self):
        os.environ['STORAGEFORGE_VAULT_SECRET'] = 'w' * 48
        with self.assertRaises(vault.VaultLocked):
            vault.Vault(self.db, self.conn).unlock()
        self.assertEqual(self.e.status()['state'], 'locked')

    def test_ssh_uses_a_vault_key_through_the_agent_helper_every_task_calls(self):
        from storageforge_index import runner
        with vault.Vault(self.db, self.conn).unlock() as v:
            v.generate_key('k')
            row = self.row('k')
            with runner.ephemeral_agent(v.decrypt_key(row['key_id']), ttl=30) as sock:
                env = {'PATH': os.environ['PATH'], 'SSH_AUTH_SOCK': sock}
                listed = subprocess.run(['ssh-add', '-L'], env=env, capture_output=True, text=True)
                self.assertEqual(listed.stdout.split()[:2], row['public_key'].split()[:2], listed.stderr)
                pub = self.tmp / 'k.pub'
                pub.write_text(row['public_key'] + '\n')
                (self.tmp / 'msg').write_text('a task\n')
                made = subprocess.run(['ssh-keygen', '-Y', 'sign', '-f', str(pub), '-n', 'file', str(self.tmp / 'msg')], env=env, capture_output=True, text=True)
                self.assertEqual(made.returncode, 0, made.stderr)
            self.assertFalse(Path(sock).exists(), 'the socket goes with the task')
        self.assertEqual(self.e.status()['signed'], 1)

    def test_a_deploy_request_is_signed_inside_and_verifies_as_before(self):
        from storageforge_index import deploy
        with vault.Vault(self.db, self.conn).unlock() as v:
            deploy.ensure_keys(v)
            signer = deploy._signer(v)
            self.assertIsInstance(signer, vault.EnclaveKey)
            armored = deploy.sshsig(signer, b'run this', namespace='storageforge-test')
            public = v.public_key(deploy.SIGNING_KEY)
        (self.tmp / 'signers').write_text(f'storageforge namespaces="storageforge-test" {public}\n')
        (self.tmp / 'sig').write_text(armored)
        checked = subprocess.run(['ssh-keygen', '-Y', 'verify', '-f', str(self.tmp / 'signers'), '-I', 'storageforge', '-n', 'storageforge-test', '-s', str(self.tmp / 'sig')],
                                 input='run this', capture_output=True, text=True)
        self.assertEqual(checked.returncode, 0, checked.stderr + checked.stdout)
        tampered = subprocess.run(['ssh-keygen', '-Y', 'verify', '-f', str(self.tmp / 'signers'), '-I', 'storageforge', '-n', 'storageforge-test', '-s', str(self.tmp / 'sig')],
                                  input='run that', capture_output=True, text=True)
        self.assertNotEqual(tampered.returncode, 0)

    def test_the_audit_chain_is_one_chain_whoever_computes_the_mac(self):
        with vault.Vault(self.db, self.conn, SECRET).unlock() as old:
            vault.AuditLog(self.db, self.conn, old.audit_key).append('gabe', 'before.enclave', 'ok')
        with vault.Vault(self.db, self.conn).unlock() as v:
            self.assertIsInstance(v.audit_key, vault.EnclaveMacKey)
            log = vault.AuditLog(self.db, self.conn, v.audit_key)
            log.append('gabe', 'through.enclave', 'ok', 'host1', None, {'n': 1})
            self.assertEqual(log.verify()[:2], (True, 2), 'the enclave verifies what the vault wrote')
        with vault.Vault(self.db, self.conn, SECRET).unlock() as old:
            self.assertEqual(vault.AuditLog(self.db, self.conn, old.audit_key).verify()[:2], (True, 2), 'and the vault what the enclave wrote')

    def test_importing_a_key_device_passwords_and_an_rsa_key_need_no_secret_here(self):
        pem = ed25519.Ed25519PrivateKey.generate().private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, serialization.NoEncryption())
        with vault.Vault(self.db, self.conn).unlock():
            pass
        self.forget_the_secret()
        with vault.Vault(self.db, self.conn).unlock() as v:
            v.add_key('imported', pem)
            v.store_credential('switch', 'admin', 'pw-123456', 'enable-9')
            self.assertEqual(v.credential('switch'), {'username': 'admin', 'password': 'pw-123456', 'enable': 'enable-9'})
            made = v.generate_key('rsa', kind='rsa')
            self.assertTrue(made['public_key'].startswith('ssh-rsa '))
            self.assertIsNone(v._kek, 'none of it opened the KEK here')
            with self.assertRaises(vault.VaultError):
                v._need_kek()
            for name in ('imported', 'rsa'):
                self.assertTrue(self.e.sign(self.row(name), b'x')[0], f'{name} signs inside like any other')
        self.assertEqual(self.e.status()['released'], 1)
        with vault.Vault(self.db, self.conn, SECRET).unlock() as old:          # and whoever holds the secret reads all of it without the enclave
            self.assertEqual(old.credential('switch')['password'], 'pw-123456')
            with old.decrypt_key(self.row('imported')['key_id']) as buf:
                opened = serialization.load_ssh_private_key(bytes(buf.view()), None)
            raw = (serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
            self.assertEqual(opened.private_bytes(*raw), serialization.load_ssh_private_key(pem, None).private_bytes(*raw))

    def test_rotating_the_secret_happens_inside_and_the_old_secret_stops_working(self):
        new = b'n' * 48
        with vault.Vault(self.db, self.conn).unlock() as v:
            v.generate_key('k')
            v.store_credential('switch', 'admin', 'pw-123456')
            before = self.row('k')
            vault.AuditLog(self.db, self.conn, v.audit_key).append('gabe', 'before', 'ok')
            self.assertEqual(v.rotate_secret(new), 1)
            after = self.row('k')
            self.assertNotEqual(before['wrapped_dek'], after['wrapped_dek'])
            self.assertEqual(before['ciphertext'], after['ciphertext'], 'the key itself is not re-encrypted: only its DEK is rewrapped')
            self.assertTrue(self.e.sign(after, b'x')[0], 'the enclave switched with the rows')
            self.refused('auth', self.e.sign, before, b'x')
            self.assertEqual(v.credential('switch')['password'], 'pw-123456')
            log = vault.AuditLog(self.db, self.conn, v.audit_key)
            log.append('gabe', 'after', 'ok')
            self.assertEqual(log.verify()[:2], (True, 2), 'the audit key is the same key under the new KEK')
        self.assertFalse(self.e.status()['rotating'])
        with self.assertRaises(vault.VaultLocked):
            vault.Vault(self.db, self.conn, SECRET).unlock()
        with vault.Vault(self.db, self.conn, new).unlock() as fresh:
            self.assertEqual(fresh.credential('switch')['password'], 'pw-123456')
        self.e.lock()                                                           # a restart: only the new secret opens it
        self.refused('auth', self.e.unlock, SECRET, self.meta())
        self.assertEqual(self.e.unlock(new, self.meta())['state'], 'unlocked')

    def test_a_rotation_that_fails_part_way_changes_nothing(self):
        with vault.Vault(self.db, self.conn).unlock() as v:
            v.generate_key('a')
            v.generate_key('b')
            before = (self.row('a'), self.row('b'), self.meta())
            real, calls = enclave.Enclave.rewrap, []

            def fails_on_the_second(e, *a):
                calls.append(a)
                if len(calls) == 2:
                    raise enclave.EnclaveError('down', 'the enclave went away')
                return real(e, *a)
            with mock.patch.object(enclave.Enclave, 'rewrap', fails_on_the_second), self.assertRaises(vault.VaultLocked):
                v.rotate_secret(b'n' * 48)
            self.assertEqual((self.row('a'), self.row('b'), self.meta()), before, 'no row was left rewrapped')
            self.assertFalse(self.e.status()['rotating'], 'and the enclave forgot the new KEK')
            self.assertTrue(self.e.sign(self.row('a'), b'x')[0])


IMAGE = ROOT / 'enclave' / 'image' / 'out'
CIDS = iter(range(20000 + os.getpid() % 20000 * 100, 1 << 31))


def image_reason():
    """Why the image cannot be booted here, or None."""
    if not all((IMAGE / f).exists() for f in ('bzImage', 'initramfs.cpio.gz')):
        return 'needs the enclave image (enclave/image/build.sh)'
    if not shutil.which('qemu-system-x86_64'):
        return 'needs qemu-system-x86_64'
    if not all(os.access(d, os.R_OK | os.W_OK) for d in ('/dev/kvm', '/dev/vhost-vsock')):
        return 'needs /dev/kvm and /dev/vhost-vsock'
    return None


@unittest.skipIf(image_reason(), image_reason() or '')
class EnclaveImage(Enclave):
    """Every test above again, against the image as it ships: the kernel and the initramfs in a micro VM whose one device is the
    vsock socket. Then what only the VM can show."""

    def start(self):
        self.serial = self.tmp / 'serial.log'
        cid = next(CIDS)
        self.address = f'vsock:{cid}:7000'
        self.proc = subprocess.Popen(
            ['qemu-system-x86_64', '-M', 'microvm,rtc=off,pit=off,pic=off,acpi=off', '-enable-kvm', '-cpu', 'host', '-m', '128', '-smp', '1', '-nodefaults',
             '-no-user-config', '-display', 'none', '-no-reboot', '-kernel', str(IMAGE / 'bzImage'), '-initrd', str(IMAGE / 'initramfs.cpio.gz'),
             '-append', 'console=ttyS0 panic=-1 quiet', '-serial', f'file:{self.serial}', '-device', f'vhost-vsock-device,guest-cid={cid}'],
            stdin=subprocess.DEVNULL, stderr=subprocess.PIPE)

    def test_in_its_vm_it_is_the_only_program_and_its_memory_is_locked(self):
        st = self.e.status()
        self.assertEqual((st['pid1'], st['memory_locked'], st['state']), (True, True, 'locked'))
        self.unlock()
        self.assertEqual(self.serial.read_text(), '', 'it has nothing to say on the console, and never the secret')

    def test_the_vm_has_no_device_but_the_socket(self):
        """The kernel is built without an IP stack, block devices or modules, and QEMU is given no device but vsock: asked for a
        network card or a disk, this kernel would have no driver. What is checked here is the configuration the build recorded."""
        config = (IMAGE / 'kernel.config.full').read_text().splitlines()
        on = {line.split('=')[0] for line in config if line.startswith('CONFIG_') and line.endswith('=y')}
        self.assertTrue({'CONFIG_VIRTIO_VSOCKETS', 'CONFIG_SECURITY_LOCKDOWN_LSM', 'CONFIG_LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY'} <= on)
        self.assertFalse(on & {'CONFIG_INET', 'CONFIG_BLOCK', 'CONFIG_MODULES', 'CONFIG_PROC_FS', 'CONFIG_DEVMEM', 'CONFIG_BPF_SYSCALL', 'CONFIG_IO_URING',
                               'CONFIG_USB_SUPPORT', 'CONFIG_SWAP', 'CONFIG_COREDUMP', 'CONFIG_VIRTIO_NET', 'CONFIG_VIRTIO_BLK', 'CONFIG_PCI'})


@unittest.skipIf(image_reason(), image_reason() or '')
class Supervised(unittest.TestCase):
    """The VM started and watched as the server will (enclave_vm.py). What must hold: only the image that was built and pinned is
    started; a VM that stops is noticed, nothing answers in between, and what comes back holds no key."""

    VMM = 'qemu'

    def setUp(self):
        from storageforge_index import enclave_vm
        self.vm = enclave_vm
        env = mock.patch.dict(os.environ, {enclave_vm.VMM_ENV: self.VMM})
        env.start()
        self.addCleanup(env.stop)
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.events = []
        self.sup = None

    def start(self, image=IMAGE, **kw):
        self.sup = self.vm.Supervisor(image, on_event=lambda kind, detail: self.events.append((kind, detail)), runtime_dir=self.tmp, **kw)
        self.addCleanup(self.sup.stop)
        return self.sup.start()

    def wait_for(self, kind, count=1, seconds=30):
        until = time.time() + seconds
        while time.time() < until:
            if sum(1 for k, _ in self.events if k == kind) >= count:
                return
            time.sleep(0.05)
        self.fail(f'no {count} {kind!r} in {self.events}')

    def test_it_starts_the_pinned_image_and_what_answers_is_the_enclave(self):
        address = self.start(expect=self.vm.image_digest(IMAGE))
        with enclave.Enclave(address) as e:
            st = e.status()
        self.assertEqual((st['pid1'], st['memory_locked'], st['state']), (True, True, 'locked'))
        self.assertEqual(self.events[0][0], 'up')
        self.assertEqual(self.events[0][1]['image'], self.vm.image_digest(IMAGE))
        self.given_nothing_but_vsock()

    def given_nothing_but_vsock(self):
        argv = ' '.join(self.sup._argv(5))
        for never in ('-netdev', '-nic', '-drive', '-virtfs', '-fsdev', 'virtio-net', 'virtio-blk', 'balloon', '-qmp', '-chardev'):
            self.assertNotIn(never, argv)
        self.assertIn('-sandbox on', argv)
        self.assertEqual((self.tmp / 'enclave-console.log').read_text(), '')

    def test_an_image_that_was_changed_or_is_not_the_one_pinned_is_not_started(self):
        copy = self.tmp / 'image'
        shutil.copytree(IMAGE, copy)
        with self.assertRaises(self.vm.EnclaveVMError) as got:
            self.start(copy, expect='0' * 64)
        self.assertIn('not the one pinned', str(got.exception))
        with open(copy / 'initramfs.cpio.gz', 'ab') as f:
            f.write(b'x')
        with self.assertRaises(self.vm.EnclaveVMError) as got:
            self.start(copy)
        self.assertIn('changed after it was built', str(got.exception))
        (copy / 'SHA256SUMS').unlink()
        with self.assertRaises(self.vm.EnclaveVMError):
            self.start(copy)
        self.assertEqual(self.events, [], 'nothing was started')

    def test_a_vm_that_stops_is_noticed_and_comes_back_at_the_same_address_holding_nothing(self):
        db_dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, db_dir, True)
        db = dbfactory.make(self, db_dir / 'index.db')
        conn = db.connect()
        self.addCleanup(conn.close)
        db.migrate(conn)
        with vault.Vault(db, conn, SECRET) as made:
            made.init()
        address = self.start()
        env = mock.patch.dict(os.environ, {'STORAGEFORGE_ENCLAVE': address, 'STORAGEFORGE_VAULT_SECRET': SECRET.decode()})
        env.start()
        self.addCleanup(env.stop)
        os.environ.pop('STORAGEFORGE_VAULT_SECRET_FILE', None)
        with vault.Vault(db, conn).unlock() as v:
            v.generate_key('k')
        with enclave.Enclave(address) as e:
            self.assertEqual(e.status()['state'], 'unlocked')
        self.sup.proc.kill()                                                       # the VM dies
        self.wait_for('down')
        self.wait_for('up', 2)
        self.assertEqual((self.sup.address, self.sup.restarts), (address, 1))
        with enclave.Enclave(address) as e:
            self.assertEqual(e.status()['state'], 'locked', 'it came back with no key')
        with vault.Vault(db, conn).unlock() as v:                                  # the next use hands it the secret again
            self.assertIsInstance(v.decrypt_key(conn.scalar('SELECT key_id FROM ssh_keys')), vault.EnclaveKey)
        self.sup.stop()
        with self.assertRaises(vault.VaultLocked):                                 # stopped for good: the vault is locked, not opened here
            vault.Vault(db, conn).unlock()
        self.assertFalse(self.sup.running())

    def test_the_server_starts_it_when_asked_and_only_then(self):
        with mock.patch.dict(os.environ, {'XDG_RUNTIME_DIR': str(self.tmp)}):
            os.environ.pop('STORAGEFORGE_ENCLAVE', None)
            self.assertIsNone(self.vm.from_env())
            os.environ['STORAGEFORGE_ENCLAVE'] = 'unix:/somewhere'
            self.assertIsNone(self.vm.from_env(), 'an address is somebody else\'s enclave to run')
            os.environ['STORAGEFORGE_ENCLAVE'] = 'vm'
            with self.assertRaises(self.vm.EnclaveVMError):
                self.vm.from_env()                                      # no image folder named
            os.environ.update({'STORAGEFORGE_ENCLAVE': 'vm', 'STORAGEFORGE_ENCLAVE_IMAGE_DIR': str(IMAGE), 'STORAGEFORGE_ENCLAVE_IMAGE': '0' * 64})
            with self.assertRaises(self.vm.EnclaveVMError):
                self.vm.from_env()
            self.assertNotEqual(os.environ['STORAGEFORGE_ENCLAVE'], 'vm', 'a failed start does not leave the vault free to open here')
            with self.assertRaises(enclave.EnclaveError):
                enclave.Enclave(os.environ['STORAGEFORGE_ENCLAVE']).status()
            os.environ.update({'STORAGEFORGE_ENCLAVE': 'vm', 'STORAGEFORGE_ENCLAVE_IMAGE': self.vm.image_digest(IMAGE)})
            sup = self.vm.from_env(lambda kind, detail: self.events.append((kind, detail)))
            self.addCleanup(sup.stop)
            self.assertEqual(os.environ['STORAGEFORGE_ENCLAVE'], sup.address)
            with enclave.Enclave(sup.address) as e:
                self.assertTrue(e.status()['pid1'])

    def test_where_no_vm_can_run_it_says_why(self):
        with mock.patch.object(self.vm.shutil, 'which', lambda name: None):
            self.assertIn('not installed', self.vm.missing())
            with self.assertRaises(self.vm.EnclaveVMError):
                self.vm.Supervisor(IMAGE).start()


    def test_a_command_that_needs_a_key_starts_its_own_and_one_that_does_not_starts_none(self):
        db_dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, db_dir, True)
        db = dbfactory.make(self, db_dir / 'index.db')
        conn = db.connect()
        self.addCleanup(conn.close)
        db.migrate(conn)
        env = {'STORAGEFORGE_ENCLAVE': 'vm', 'STORAGEFORGE_ENCLAVE_IMAGE_DIR': str(IMAGE), 'STORAGEFORGE_ENCLAVE_IMAGE': self.vm.image_digest(IMAGE),
               'STORAGEFORGE_VAULT_SECRET': SECRET.decode(), 'XDG_RUNTIME_DIR': str(self.tmp)}
        with mock.patch.dict(os.environ, env), mock.patch.object(self.vm, '_own', None):
            os.environ.pop('STORAGEFORGE_VAULT_SECRET_FILE', None)
            self.assertEqual(enclave.problems(), {}, 'looking for problems starts nothing')
            self.assertEqual(os.environ['STORAGEFORGE_ENCLAVE'], 'vm')
            with vault.Vault(db, conn, SECRET) as made:
                made.init()
            with vault.Vault(db, conn).unlock() as v:
                v.generate_key('k')
            own = self.vm._own
            self.addCleanup(own.stop)
            self.assertEqual(os.environ['STORAGEFORGE_ENCLAVE'], own.address)
            self.assertNotEqual(own.runtime, self.tmp, 'a folder of its own: it cannot take a running server\'s socket')
            self.assertEqual(self.vm.on_demand(), own.address, 'one for the process, not one per use')
            own.stop()
            self.assertFalse(own.runtime.exists())
        with mock.patch.dict(os.environ, env | {'STORAGEFORGE_ENCLAVE_IMAGE': '0' * 64}), mock.patch.object(self.vm, '_own', None):
            with self.assertRaises(vault.VaultLocked):
                vault.Vault(db, conn).unlock()
            self.assertEqual(os.environ['STORAGEFORGE_ENCLAVE'], 'vm:starting', 'and it stays closed')


@unittest.skipIf(image_reason(), image_reason() or '')
@unittest.skipUnless(shutil.which('firecracker'), 'needs firecracker (the shipped image has it)')
class SupervisedByFirecracker(Supervised):
    """The same, with the program the shipped image runs the VM by. It needs no /dev/vhost-vsock: the guest's vsock is a socket
    file in the runtime folder, and whoever can open that file can talk to the enclave."""
    VMM = 'firecracker'

    def given_nothing_but_vsock(self):
        self.assertTrue(self.sup.address.startswith(f'fc:{self.tmp}/enclave-vsock.sock:'))
        conf = json.loads((self.tmp / 'enclave-vm.json').read_text())
        self.assertEqual((conf['drives'], conf['network-interfaces'], sorted(conf)), ([], [], ['boot-source', 'drives', 'machine-config', 'network-interfaces', 'vsock']))
        argv = self.sup.proc.args
        self.assertIn('--no-api', argv, 'nothing can configure it after it has started')
        self.assertNotIn('--no-seccomp', argv)
        self.assertEqual(stat.S_IMODE(self.tmp.stat().st_mode), 0o700, 'the folder the socket is in')

    def test_it_is_the_one_chosen_where_it_is_installed(self):
        with mock.patch.dict(os.environ, {self.vm.VMM_ENV: ''}):
            self.assertEqual(self.vm.vmm(), 'firecracker')
        with mock.patch.dict(os.environ, {self.vm.VMM_ENV: 'bhyve'}), self.assertRaises(self.vm.EnclaveVMError):
            self.vm.vmm()


if __name__ == '__main__':
    unittest.main()
