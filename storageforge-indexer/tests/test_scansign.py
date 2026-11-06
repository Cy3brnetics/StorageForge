"""Signed scan payloads (scansign.py): every byte a host sends a scan is signed on the host and checked before it is used.

These run the real wrapper with a real ssh-keygen, through a transport that behaves as a remote one does (signing on, ssh's exit
codes) but runs sh on this machine, so nothing here needs a second host. A second transport changes a byte on the way, the way
someone between the hosts would."""
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import dbfactory
from storageforge_index import access, scansign
from storageforge_index.remote import RemoteError, Transport
from storageforge_index.scanner import ScanOptions, scan_host
from storageforge_index.scansign import BadSignature, HashingReader, Signing

HAVE_SIGN = shutil.which('ssh-keygen') and subprocess.run(['ssh-keygen', '-Y', 'sign'], capture_output=True).returncode != 127


class Here(Transport):
    """Signing on and remote rules, but the command runs here."""
    tamper = None                       # a sed expression run over stdout after the host signed it: the bytes changed on the way

    def argv(self, script):
        if self.tamper:
            return ['/bin/sh', '-c', f'( {script}\n) | sed -e {self.tamper!r}']
        return ['/bin/sh', '-c', script]

    def host_keys(self):
        return ['test-host-key']

    def close(self):
        pass


@unittest.skipUnless(HAVE_SIGN, 'needs ssh-keygen with -Y sign (OpenSSH 8.0 or later)')
class Signed(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='sfsig-test-'))
        self.key = self.tmp / 'scan-sign'
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(self.key)], check=True)
        self.pub = ' '.join(self.key.with_suffix('.pub').read_text().split()[:2])
        self.other = self.tmp / 'other'
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(self.other)], check=True)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def t(self, pinned=None, require=False, keys=None, tamper=None, pin=None):
        t = Here('box')
        t.tamper = tamper
        t.signing = Signing([], pinned=pinned, require=require, pin=pin, key_paths=keys or [str(self.key)])
        return t

    def test_a_signed_payload_from_the_pinned_key_is_used(self):
        t = self.t(pinned=self.pub)
        self.assertEqual(t.run('printf "hello\\n"; printf "oops\\n" >&2'), 'hello\n')
        self.assertEqual(t.signing.summary()['state'], 'signed')
        self.assertEqual(t.signing.summary()['keys'], [scansign.fingerprint(self.pub)])

    def test_a_host_key_already_pinned_in_known_hosts_signs_too(self):
        t = Here('box')
        t.signing = Signing(lambda: [self.pub], key_paths=[str(self.key)])         # as when the scan logs in as root
        self.assertEqual(t.run('echo x'), 'x\n')
        self.assertIsNone(t.signing.pinned)                                      # nothing new pinned: it was a host key

    def test_the_first_signature_from_an_unpinned_host_is_pinned(self):
        pinned = []
        t = self.t(pin=pinned.append)
        t.run('echo first')
        self.assertEqual(pinned, [self.pub])
        t.run('echo second')                                                     # and from then on it is the key
        self.assertEqual(t.signing.signed, 2)

    def test_another_key_after_one_is_pinned_is_refused(self):
        t = self.t(pinned=self.pub, keys=[str(self.other)])
        with self.assertRaisesRegex(BadSignature, 'not pinned for this host'):
            t.run('echo forged')

    def test_bytes_changed_on_the_way_are_refused(self):
        t = self.t(pinned=self.pub, tamper='s/secure/broken/')
        with self.assertRaisesRegex(BadSignature, 'changed on the way'):
            t.run('echo secure')
        self.assertIsInstance(BadSignature('x'), RemoteError)                     # so every scan path treats it as a failed command

    def test_a_signature_cannot_be_played_again(self):
        t = self.t(pinned=self.pub)
        captured = {}
        real = t.signing.check

        def keep(nonce, digest, tail, what='x'):
            captured.update(digest=digest, tail=list(tail))
            return real(nonce, digest, tail, what)
        t.signing.check = keep
        t.run('echo once')
        with self.assertRaisesRegex(BadSignature, 'does not verify'):
            real('0' * 32, captured['digest'], captured['tail'])                  # a new request, an old signature

    def test_a_host_that_cannot_sign_is_unsigned_or_refused(self):
        t = self.t(keys=[str(self.tmp / 'missing')])
        self.assertEqual(t.run('echo plain'), 'plain\n')
        self.assertEqual(t.signing.summary()['state'], 'unsigned')
        self.assertIn('no signing key', t.signing.summary()['reasons'][0])
        with self.assertRaisesRegex(BadSignature, 'requires signed scans'):
            self.t(keys=[str(self.tmp / 'missing')], require=True).run('echo plain')

    def test_a_truncated_signature_is_a_bad_signature_not_a_bare_error(self):
        """SF-75"""
        import base64
        for body in (b'SSHSIG', b'SSHSIG\x00\x00\x00\x01\x00\x00', b'SSHSIG\x00\x00\x00\x01\x00\x00\x00\x05ab', b'SSHSIG\x00\x00\x00\x01\x00\x00\x00\x01a\x00\x00\x00\x09ab'):
            arm = '-----BEGIN SSH SIGNATURE-----\n' + base64.b64encode(body).decode() + '\n-----END SSH SIGNATURE-----\n'
            mark = 'SFSIG1 ' + 'd' * 64 + ' ' + base64.b64encode(arm.encode()).decode()
            with self.assertRaisesRegex(BadSignature, 'cannot be read'):
                Signing([], pinned=self.pub).check('n', 'd' * 64, [mark])
            with self.assertRaises(ValueError):
                scansign.signer_key(arm)

    def test_no_signature_at_all_is_not_taken_for_a_signed_one(self):
        s = Signing([], pinned=self.pub, require=True)
        with self.assertRaisesRegex(BadSignature, 'no signature came back'):
            s.check('n', 'd' * 64, ['some other line'])

    def test_a_stream_keeps_its_stdin_and_its_exit_status_and_is_checked(self):
        t = self.t(pinned=self.pub)
        proc = t.stream('cat; exit 3', stdin=True)
        proc.stdin.write(b'abc\0def\0')
        proc.stdin.close()
        from storageforge_index.remote import StderrTail
        err = StderrTail(proc.stderr)
        r = HashingReader(proc.stdout.raw)
        data = b''.join(iter(lambda: r.read(4096), b''))
        self.assertEqual(proc.wait(), 3)
        err.join(5)
        self.assertEqual(data, b'abc\0def\0')
        t.check_stream(proc, r.digest(), err.tail, 'cat')
        self.assertEqual(t.signing.signed, 1)

    def test_the_key_inside_a_signature_is_read_as_ssh_keygen_writes_it(self):
        msg = self.tmp / 'm'
        msg.write_bytes(b'x')
        subprocess.run(['ssh-keygen', '-Y', 'sign', '-n', scansign.NAMESPACE, '-f', str(self.key), str(msg)], check=True, capture_output=True)
        self.assertEqual(scansign.signer_key((self.tmp / 'm.sig').read_text()), self.pub)


@unittest.skipUnless(HAVE_SIGN, 'needs ssh-keygen with -Y sign (OpenSSH 8.0 or later)')
class SignedScan(unittest.TestCase):
    """A whole scan of a folder, with every payload signed, and one walk changed on the way."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='sfsig-scan-'))
        self.tree = self.tmp / 'tree'
        (self.tree / 'a').mkdir(parents=True)
        for i in range(30):
            (self.tree / 'a' / f'f{i}.txt').write_text(str(i))
        self.key = self.tmp / 'scan-sign'
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(self.key)], check=True)
        self.db = dbfactory.make(self, self.tmp / 'idx.db')
        conn = self.db.connect()
        self.db.migrate(conn)
        conn.close()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def scan(self, tamper=None):
        conn = self.db.connect()
        try:
            t = Here('box')
            t.tamper = tamper
            t.signing = scansign.for_scan(conn, 'box', 22, None)
            t.signing.key_paths = (str(self.key),)
            opts = ScanOptions(roots=[str(self.tree)], include_tmpfs=True, include_fstypes=['overlay'])
            return scan_host(self.db, t, opts, log=lambda m: None), conn
        except Exception:
            conn.close()
            raise

    def test_every_payload_of_a_scan_is_signed_and_the_key_is_pinned(self):
        result, conn = self.scan()
        try:
            self.assertEqual(result['status'], 'ok')
            self.assertEqual(result['signed']['state'], 'signed')
            self.assertEqual(result['signed']['unsigned'], 0)
            self.assertGreaterEqual(result['signed']['signed'], 2)             # the inventory, the walk, and what else ran
            self.assertEqual(scansign.pinned_key(conn, 'box', 22).split()[0], 'ssh-ed25519')
            self.assertEqual(scansign.status(conn)[0]['state'], 'signed')
        finally:
            conn.close()

    def test_a_walk_changed_on_the_way_is_not_used(self):
        (self.tree / 'a' / 'needle-file.txt').write_text('n')
        first, conn = self.scan()
        conn.close()
        self.assertEqual(first['status'], 'ok')
        result, conn = self.scan(tamper='s/needle-file/zzzzzz-file/')            # only the walk carries this name
        try:
            self.assertEqual((result['status'], result['failed']), ('failed', 1))   # the walk was refused, so its mount was not touched
            names = {r[0] for r in conn.all('SELECT filename FROM file_records')}
            self.assertIn('needle-file.txt', names)
            self.assertNotIn('zzzzzz-file.txt', names)
        finally:
            conn.close()

    def test_a_changed_inventory_stops_the_scan_before_anything_is_taken_from_it(self):
        with self.assertRaisesRegex(BadSignature, 'changed on the way'):
            self.scan(tamper='s/^/x/')                                              # every payload changes; the inventory is the first


class Setup(unittest.TestCase):
    def test_the_scan_access_setup_makes_the_signing_key_and_prints_its_public_half(self):
        s = access.setup_script('scanuser')
        self.assertIn('ssh-keygen -q -t ed25519', s)
        self.assertIn('chmod 0640 "$D/scan-sign"', s)
        self.assertIn('echo "SFSIGNKEY', s)
        self.assertLess(s.index('SFSIGNKEY'), s.index('read-only scan access is ready'))
        self.assertIn(os.path.dirname(scansign.SIGNING_KEY), s.replace('%s', ''))

    def test_the_wrapper_is_posix_sh(self):
        if not shutil.which('dash'):
            self.skipTest('no dash here')
        p = subprocess.run(['dash', '-n'], input=scansign.wrap('echo x', 'ab'), text=True, capture_output=True)
        self.assertEqual(p.returncode, 0, p.stderr)


class Records(unittest.TestCase):
    def test_pin_forget_and_status(self):
        tmp = Path(tempfile.mkdtemp(prefix='sfsig-db-'))
        try:
            db = dbfactory.make(self, tmp / 'idx.db')
            conn = db.connect()
            db.migrate(conn)
            key = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEw1bmk3t2sT4o4l6c8X3f4l4m7q8r9s0t1u2v3w4x5y'
            scansign.pin(conn, 'nas', 2222, key, 'test')
            self.assertEqual(scansign.pinned_key(conn, 'nas', 2222), key)
            self.assertIsNone(scansign.pinned_key(conn, 'nas', 22))
            s = Signing([])
            s.unsigned, s.reasons = 2, ['old OpenSSH']
            scansign.record(conn, 'nas', s)
            self.assertEqual(scansign.status(conn, 'nas')[0]['reason'], 'old OpenSSH')
            self.assertTrue(scansign.forget(conn, 'nas', 2222))
            self.assertFalse(scansign.forget(conn, 'nas', 2222))
            conn.close()
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == '__main__':
    unittest.main()


class Routes(unittest.TestCase):
    """What a person sees and changes: an operator reads the state, and only keys.manage (an admin) requires signatures or forgets a key."""

    def setUp(self):
        from storageforge_index import server, users
        from storageforge_index.db import Database
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = Database(f'sqlite:///{self.tmp.name}/idx.db')
        self.conn = self.db.connect()
        self.addCleanup(self.conn.close)
        self.db.migrate(self.conn)
        self.pw = 'correct horse battery staple 9'
        users.create(self.conn, 'root', self.pw, 'admin')
        users.create(self.conn, 'op', self.pw, 'operator')
        self.web = server.create_app(server.App(self.db), 's' * 48)

    def client(self, name):
        c = self.web.test_client()
        self.assertEqual(c.post('/api/login', json={'username': name, 'password': self.pw}).status_code, 200)
        return c

    def test_the_state_is_read_and_the_policy_set_by_whom_it_should_be(self):
        key = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEw1bmk3t2sT4o4l6c8X3f4l4m7q8r9s0t1u2v3w4x5y'
        scansign.pin(self.conn, 'nas', 22, key, 'test')
        op, root = self.client('op'), self.client('root')
        got = op.get('/api/scans/signing').get_json()
        self.assertEqual((got['require'], got['pinned'][0]['address']), (False, 'nas'))
        self.assertEqual(op.put('/api/scans/signing', json={'require': True}).status_code, 403)       # an operator cannot loosen or tighten it
        self.assertEqual(op.delete('/api/scans/signing/nas').status_code, 403)
        r = root.put('/api/scans/signing', json={'require': True})
        if r.status_code == 403 and (r.get_json() or {}).get('reauth'):                              # a security policy may want the password again
            root.post('/api/reauth', json={'password': self.pw})
            r = root.put('/api/scans/signing', json={'require': True})
        self.assertEqual(r.get_json(), {'require': True})
        self.assertTrue(scansign.required(self.conn))
        for text, want in (('false', False), ('0', False), ('Off', False), ('true', True), ('on', True), (False, False)):         # SF-75: text is read, not taken as on
            r = root.put('/api/scans/signing', json={'require': text})
            self.assertEqual((r.status_code, r.get_json()), (200, {'require': want}), text)
            self.assertEqual(scansign.required(self.conn), want)
        scansign_before = scansign.required(self.conn)
        for bad in ('maybe', '', 'tru', 2, None, [], {}):
            self.assertEqual(root.put('/api/scans/signing', json={'require': bad}).status_code, 400, repr(bad))
        self.assertEqual(root.put('/api/scans/signing', json={}).status_code, 400)
        self.assertEqual(scansign.required(self.conn), scansign_before)
        root.put('/api/scans/signing', json={'require': True})
        gone = root.delete('/api/scans/signing/nas')
        self.assertEqual(gone.status_code, 200)                                                       # the password was just confirmed
        self.assertEqual(gone.get_json(), {'forgotten': True})
        self.assertIsNone(scansign.pinned_key(self.conn, 'nas', 22))
