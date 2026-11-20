"""The second lock on the KEK (roadmap section 14, "Layers"; lock2.py): a share in a file on the machine, mixed into the key the vault
secret derives. What must hold: with it on, the secret alone opens nothing, here or on another machine, with the enclave or without;
no key's ciphertext changes when it is turned on or off; the recovery share writes the host share again; and the enclave mixes it
exactly as today's vault does."""
import base64
import io
import os
import stat
import unittest
from unittest import mock

from storageforge_index import cli, enclave_start, lock2, vault
from test_enclave import SECRET
from test_enclave_stepup import PW, Base


class SecondLock(Base):
    def setUp(self):
        super().setUp()
        self.share_file = self.tmp / 'host' / 'host_share'
        os.environ[lock2.SHARE_ENV] = str(self.share_file)
        with vault.Vault(self.db, self.conn, SECRET).unlock() as v:          # a vault with something in it, made before the lock
            v.generate_key('k')
            v.store_credential('switch', 'admin', 'pw-123456')
        self.before = self.rows()

    def rows(self):
        return [tuple(bytes(x) for x in r) for r in self.conn.all('SELECT ciphertext, key_nonce FROM ssh_keys ORDER BY key_id')] + \
               [tuple(bytes(x) for x in r) for r in self.conn.all('SELECT ciphertext, nonce FROM device_credentials ORDER BY credential_id')]

    def run_cli(self, *args, stdin='', secret=SECRET.decode()):
        out = io.StringIO()
        env = {'STORAGEFORGE_VAULT_SECRET': secret} if secret else {}
        with mock.patch.dict(os.environ, env), mock.patch('sys.stdin', io.StringIO(stdin)), mock.patch('sys.stdout', out), mock.patch('sys.stderr', out):
            if not secret:
                os.environ.pop('STORAGEFORGE_VAULT_SECRET', None)
            return cli.main(['--db', self.db.url, 'vault', 'second-lock', *args]), out.getvalue()

    def turn_on(self):
        """Through the command, as a person would. Returns the recovery share it printed."""
        with mock.patch.dict(os.environ):
            os.environ.pop('STORAGEFORGE_ENCLAVE', None)                       # the command of whoever holds the secret, with no enclave
            code, said = self.run_cli('on')
        self.assertEqual(code, 0, said)
        return next(line.strip() for line in said.splitlines() if line.startswith('    ') and '-' in line)

    def without_enclave(self):
        env = mock.patch.dict(os.environ)
        env.start()
        self.addCleanup(env.stop)
        del os.environ['STORAGEFORGE_ENCLAVE']

    # ── without the enclave: today's vault ──
    def test_with_the_lock_on_the_secret_alone_opens_nothing_and_no_ciphertext_changed(self):
        self.without_enclave()
        self.assertIn('second lock: off', self.run_cli('status')[1])
        recovery = self.turn_on()
        self.assertEqual(len(recovery.replace('-', '')), 32)
        self.assertEqual(stat.S_IMODE(self.share_file.stat().st_mode), 0o600)
        self.assertEqual(self.rows(), self.before, 'the lock is a rotation: each DEK is rewrapped and no key or secret is encrypted again')
        self.assertIn('second lock: on', self.run_cli('status')[1])
        self.assertIn('TPM: not used', self.run_cli('status')[1])
        with vault.Vault(self.db, self.conn, SECRET).unlock() as v:           # the secret and the share: it opens
            self.assertEqual(v.credential('switch')['password'], 'pw-123456')
            with v.decrypt_key(self.conn.scalar('SELECT key_id FROM ssh_keys')) as buf:
                self.assertIn(b'OPENSSH PRIVATE KEY', bytes(buf.view()))
        held = self.share_file.read_text()
        self.share_file.unlink()                                               # the database and the secret on another machine
        with self.assertRaises(vault.VaultLocked) as got:
            vault.Vault(self.db, self.conn, SECRET).unlock()
        self.assertIn('opens only on the machine that holds the share', str(got.exception))
        self.share_file.write_text(base64.b64encode(os.urandom(32)).decode() + '\n')          # or with a share that is not this vault's
        self.share_file.chmod(0o600)
        with self.assertRaises(vault.VaultLocked) as got:
            vault.Vault(self.db, self.conn, SECRET).unlock()
        self.assertIn('not the one this vault is locked to', str(got.exception))
        self.share_file.write_text(held)
        self.share_file.chmod(0o644)                                           # a share others can read is not a share
        with self.assertRaises(vault.VaultError) as got:
            vault.Vault(self.db, self.conn, SECRET).unlock()
        self.assertIn('chmod 600', str(got.exception))

    def test_the_key_the_secret_alone_derives_is_not_the_vaults_key(self):
        """What the lock is for, shown directly: the KEK as 0.5.4 derives it authenticates nothing that is stored."""
        self.without_enclave()
        self.turn_on()
        salt, t, m, lanes, vn, verifier = self.conn.all('SELECT kdf_salt, kdf_time_cost, kdf_memory_kib, kdf_lanes, verifier_nonce, verifier FROM vault_meta')[0]
        alone = vault.derive_kek(SECRET, bytes(salt), {'time_cost': t, 'memory_kib': m, 'lanes': lanes})
        with self.assertRaises(vault.VaultError):
            vault.open_into(alone.view(), bytes(vn), bytes(verifier), b'storageforge:verifier')
        share = lock2.read_share()
        with vault.open_into(lock2.mix(alone.view(), share), bytes(vn), bytes(verifier), b'storageforge:verifier') as check:
            self.assertEqual(bytes(check.view()), vault.VERIFIER)

    def test_the_recovery_share_writes_the_host_share_again_and_a_wrong_one_does_not(self):
        self.without_enclave()
        recovery = self.turn_on()
        was = self.share_file.read_text()
        self.share_file.unlink()
        code, said = self.run_cli('recover', stdin='AAAA-BBBB-CCCC-DDDD-EEEE-FFFF-GGGG-HHHH\n')
        self.assertEqual(code, 1)
        self.assertIn('not the recovery share', said)
        self.assertFalse(self.share_file.exists())
        code, said = self.run_cli('recover', stdin=recovery.lower().replace('-', ' ') + '\n')          # typed back by hand
        self.assertEqual(code, 0, said)
        self.assertEqual(self.share_file.read_text(), was)
        with vault.Vault(self.db, self.conn, SECRET).unlock() as v:
            self.assertEqual(v.credential('switch')['password'], 'pw-123456')
        self.assertEqual(self.run_cli('recover', stdin=recovery + '\n')[0], 1, 'a share that is there is never overwritten')
        marker = self.conn.scalar('SELECT second_lock FROM vault_meta')
        self.assertNotIn(base64.b64decode(was.strip()).hex(), marker)
        self.assertNotIn(was.strip(), marker)

    def test_turning_it_off_is_the_way_back_and_rotating_the_secret_keeps_it(self):
        self.without_enclave()
        self.turn_on()
        new = 'n' * 48
        with mock.patch.dict(os.environ, {'STORAGEFORGE_VAULT_SECRET': SECRET.decode(), 'STORAGEFORGE_VAULT_NEW_SECRET': new}):
            out = io.StringIO()
            with mock.patch('sys.stdout', out), mock.patch('sys.stderr', out):
                self.assertEqual(cli.main(['--db', self.db.url, 'vault', 'rotate-secret']), 0, out.getvalue())
        self.assertIsNotNone(self.conn.scalar('SELECT second_lock FROM vault_meta'), 'a rotation of the secret leaves the lock on')
        with vault.Vault(self.db, self.conn, new.encode()).unlock() as v:
            self.assertEqual(v.credential('switch')['password'], 'pw-123456')
        self.assertEqual(self.run_cli('on', secret=new)[0], 1)
        code, said = self.run_cli('off', secret=new)
        self.assertEqual(code, 0, said)
        self.assertIsNone(self.conn.scalar('SELECT second_lock FROM vault_meta'))
        self.share_file.unlink()
        with vault.Vault(self.db, self.conn, new.encode()).unlock() as v:      # the vault as 0.5.4 opens it: the secret alone
            self.assertEqual(v.credential('switch')['password'], 'pw-123456')
        self.assertEqual(self.rows(), self.before)
        self.assertEqual(self.run_cli('off', secret=new)[0], 1)
        self.assertEqual(self.run_cli('on', secret='w' * 48)[0], 1, 'and only whoever holds the secret turns it on')
        self.assertFalse(self.share_file.exists(), 'a share written for a lock that did not take is removed')

    # ── with the enclave ──
    def test_the_enclave_mixes_the_share_as_the_vault_does_and_without_it_the_secret_does_not_unlock(self):
        self.turn_on()
        self.e.lock()
        self.assertIn('not the share of the machine', self.refused('auth', self.e.unlock, SECRET, {**self.meta(), 'share': os.urandom(32)}))
        self.assertIn('wrong vault secret', self.refused('auth', self.e.unlock, SECRET, self.meta()))          # the secret alone
        self.assertEqual(self.e.status()['state'], 'locked')
        os.environ['STORAGEFORGE_VAULT_SECRET'] = SECRET.decode()
        with vault.Vault(self.db, self.conn).unlock() as v:                    # the vault reads the share and hands both over
            self.assertEqual(v.enclave, self.address)
            self.assertTrue(self.e.status()['second_lock'])
            self.assertTrue(self.e.sign(self.row('k'), b'x')[0], 'a key made before the lock signs inside under it')
            self.assertEqual(v.credential('switch')['password'], 'pw-123456')
            v.generate_key('made-inside')
        self.without_enclave()
        with vault.Vault(self.db, self.conn, SECRET).unlock() as old:          # and what the enclave sealed, today's vault opens with the share
            with old.decrypt_key(self.conn.scalar("SELECT key_id FROM ssh_keys WHERE name = 'made-inside'")) as buf:
                self.assertIn(b'OPENSSH PRIVATE KEY', bytes(buf.view()))

    def test_the_starter_reads_the_share_and_on_a_machine_without_it_unlocks_nothing(self):
        self.turn_on()
        self.e.lock()
        secret_file = self.tmp / 'vault_secret'
        secret_file.write_text(SECRET.decode())
        os.environ['STORAGEFORGE_VAULT_SECRET_FILE'] = str(secret_file)
        said = []
        self.assertEqual(enclave_start.starter(self.db, self.address, wait=10, say=said.append), 0, said)
        self.assertEqual(self.e.status()['state'], 'unlocked')
        self.e.lock()
        self.share_file.rename(self.share_file.with_name('elsewhere'))
        self.assertEqual(enclave_start.starter(self.db, self.address, wait=5, say=said.append), 1)
        self.assertIn('host share', said[-1])
        self.assertEqual(self.e.status()['state'], 'locked')

    def test_the_lock_is_turned_on_and_off_inside_the_enclave_too(self):
        """A command with an enclave of its own: the new KEK is derived and mixed inside, and each DEK rewrapped there."""
        os.environ['STORAGEFORGE_VAULT_SECRET'] = SECRET.decode()
        code, said = self.run_cli('on')
        self.assertEqual(code, 0, said)
        self.assertEqual(self.rows(), self.before)
        self.assertTrue(self.e.status()['second_lock'], 'the enclave switched with the rows, and holds the share now')
        self.assertTrue(self.e.sign(self.row('k'), b'x')[0])
        self.e.lock()
        self.refused('auth', self.e.unlock, SECRET, self.meta())
        self.assertEqual(self.e.unlock(SECRET, {**self.meta(), 'share': lock2.read_share()})['state'], 'unlocked')
        code, said = self.run_cli('off')
        self.assertEqual(code, 0, said)
        self.assertFalse(self.e.status()['second_lock'])
        self.e.lock()
        self.assertEqual(self.unlock()['state'], 'unlocked')
        self.assertTrue(self.e.sign(self.row('k'), b'x')[0])

    def test_step_up_by_the_vault_secret_needs_the_share_as_well(self):
        from storageforge_index import enclave_stepup
        self.turn_on()
        self.e.lock()
        os.environ['STORAGEFORGE_VAULT_SECRET'] = SECRET.decode()
        with vault.Vault(self.db, self.conn).unlock() as v:
            enclave_stepup.enroll(self.conn, self.address, 'gabe', PW)
            self.assertTrue(v.generate_key('by-command'), 'the command holds the secret and reads the share: that is its step-up')
            self.refused('auth', self.e.stepup_secret, SECRET, self.meta())          # the secret without the share proves nothing


if __name__ == '__main__':
    unittest.main()
