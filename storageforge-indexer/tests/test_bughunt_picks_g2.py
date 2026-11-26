"""Vault fixes: a rotation marks itself so nothing is sealed under the KEK that is going, and the environment's secret is stripped."""
import os
import shutil
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import dbfactory
from storageforge_index import vault
from storageforge_index.vault import Vault, VaultError, VaultLocked

SECRET = 's' * 40
NEW = 'n' * 40


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        env = mock.patch.dict(os.environ)
        env.start()
        self.addCleanup(env.stop)
        for name in ('STORAGEFORGE_ENCLAVE', 'STORAGEFORGE_VAULT_SECRET', 'STORAGEFORGE_VAULT_SECRET_FILE'):
            os.environ.pop(name, None)
        self.db = dbfactory.make(self, self.tmp / 'index.db')
        self.conn = self.db.connect()
        self.addCleanup(self.conn.close)
        self.db.migrate(self.conn)

    def mark(self, since):
        self.conn.execute('DELETE FROM settings WHERE key = :k', {'k': vault.ROTATING_KEY})
        self.conn.execute("INSERT INTO settings (key, value_json, updated_at, updated_by) VALUES (:k, :v, 0, 't')",
                          {'k': vault.ROTATING_KEY, 'v': str(int(since))})


class RotationMark(Base):
    def setUp(self):
        super().setUp()
        Vault(self.db, self.conn, SECRET.encode()).init()
        self.v = Vault(self.db, self.conn, SECRET.encode()).unlock()
        self.addCleanup(self.v.close)

    def marked(self):
        return bool(self.conn.scalar('SELECT count(*) FROM settings WHERE key = :k', {'k': vault.ROTATING_KEY}))

    def test_every_seal_path_refuses_while_a_rotation_is_marked(self):
        self.mark(time.time())
        for call in (lambda: self.v.store_credential('c', 'u', 'pw'), lambda: self.v.generate_key('k')):
            with self.assertRaisesRegex(VaultError, 'rotation is under way'):
                call()
        self.assertEqual(self.conn.scalar('SELECT count(*) FROM device_credentials'), 0)
        self.assertEqual(self.conn.scalar('SELECT count(*) FROM ssh_keys'), 0)

    def test_a_mark_older_than_an_hour_is_ignored(self):
        self.mark(time.time() - 3601)
        self.v.store_credential('c', 'u', 'pw')

    def test_the_rotation_marks_itself_and_clears_the_mark_on_commit_and_on_failure(self):
        self.v.store_credential('c', 'u', 'pw')
        seen = []
        real = vault.open_into

        def spy(*a, **kw):
            seen.append(self.marked())
            return real(*a, **kw)
        with mock.patch.object(vault, 'open_into', spy):
            self.v.rotate_secret(NEW.encode())
        self.assertTrue(seen and all(seen))
        self.assertFalse(self.marked())
        with mock.patch.object(vault, 'open_into', side_effect=VaultError('boom')):
            with self.assertRaises(VaultError):
                self.v.rotate_secret(SECRET.encode())
        self.assertFalse(self.marked())
        self.v.store_credential('d', 'u', 'pw')          # sealing works again

    def test_a_second_rotation_refuses_and_leaves_the_first_mark(self):
        self.mark(time.time())
        with self.assertRaisesRegex(VaultError, 'rotation is under way'):
            self.v.rotate_secret(NEW.encode())
        self.assertTrue(self.marked())

    def test_a_credential_sealed_before_the_rotation_still_opens_after_it(self):
        self.v.store_credential('c', 'u', 'pw')
        self.v.rotate_secret(NEW.encode())
        with Vault(self.db, self.conn, NEW.encode()).unlock() as v2:
            self.assertEqual(v2.credential('c')['password'], 'pw')


class StrippedSecret(Base):
    def test_the_environment_secret_is_stripped(self):
        os.environ['STORAGEFORGE_VAULT_SECRET'] = f'  {SECRET}\n'
        self.assertEqual(vault.secret_from_env(), SECRET.encode())

    def test_a_secret_file_is_stripped_too(self):
        f = self.tmp / 'secret'
        f.write_text(f'{SECRET}\n')
        os.environ['STORAGEFORGE_VAULT_SECRET_FILE'] = str(f)
        self.assertEqual(vault.secret_from_env(), SECRET.encode())

    def test_a_vault_initialised_with_whitespace_still_opens(self):
        padded = f'{SECRET}\n'
        Vault(self.db, self.conn, padded.encode()).init()
        os.environ['STORAGEFORGE_VAULT_SECRET'] = padded
        with Vault(self.db, self.conn).unlock() as v:
            self.assertIsNotNone(v._kek)

    def test_a_stripped_vault_opens_from_a_padded_value_and_a_wrong_one_does_not(self):
        Vault(self.db, self.conn, SECRET.encode()).init()
        os.environ['STORAGEFORGE_VAULT_SECRET'] = f' {SECRET}\n'
        Vault(self.db, self.conn).unlock().close()
        os.environ['STORAGEFORGE_VAULT_SECRET'] = f' {NEW}\n'
        with self.assertRaises(VaultLocked) as cm:
            Vault(self.db, self.conn).unlock()
        self.assertNotIn(NEW, str(cm.exception))


if __name__ == '__main__':
    unittest.main()
