"""One database is one site: identity, keys that cannot be shared between clients, and starting a new environment."""
import json
import os
import shutil
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

try:
    import dbfactory
except ImportError:      # run as tests.test_x from the project folder
    from tests import dbfactory
from storageforge_index import backup, cli, reset, site, users
from storageforge_index.db import Database
from storageforge_index.vault import AuditLog, Vault, VaultError

OLD = 'old-secret-' + 'o' * 40


def private_pem():
    return ed25519.Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, serialization.NoEncryption())


@unittest.skipIf(dbfactory.PG, 'sites and restores here are SQLite files (PostgreSQL: pg_dump)')
class Sites(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.data, self.secrets, self.archive = self.tmp / 'data', self.tmp / 'secrets', self.tmp / 'archive'
        for d in (self.data, self.secrets, self.archive):
            d.mkdir()
        self.secret_file = self.secrets / 'vault_secret'
        self.secret_file.write_text(OLD)
        self.secret_file.chmod(0o400)
        self.secrets.chmod(0o500)      # as init-volumes.sh leaves it
        env = {'STORAGEFORGE_DATA_DIR': str(self.data), 'STORAGEFORGE_BACKUP_DIR': str(self.data / 'backups'),
               'STORAGEFORGE_VAULT_SECRET_FILE': str(self.secret_file), 'STORAGEFORGE_IMPORT_DIR': str(self.tmp / 'keys')}
        patcher = mock.patch.dict(os.environ, env)
        patcher.start()
        self.addCleanup(patcher.stop)
        for k in ('STORAGEFORGE_VAULT_SECRET', 'STORAGEFORGE_VAULT_NEW_SECRET'):
            os.environ.pop(k, None)
        self.path = self.data / 'index.db'
        self.db = Database(str(self.path))
        conn = self.db.connect()
        self.db.migrate(conn)
        Vault(self.db, conn, OLD.encode()).init()
        with Vault(self.db, conn, OLD.encode()).unlock() as v:
            v.add_key('client-a', private_pem())
            v.bind('client-a', 'nas-*', 'root')
        site.ensure(conn)
        site.rename(conn, 'Client A', 'test')
        conn.close()
        (self.data / 'ssh').mkdir()
        (self.data / 'ssh' / 'known_hosts').write_text('nas-1 ssh-ed25519 AAAA\n')

    def tearDown(self):
        self.secrets.chmod(0o700)
        shutil.rmtree(self.tmp)

    def run_reset(self, abandon=False, archive=None):
        return reset.run(Database(str(self.path)), 'Client B', str(archive or self.archive), abandon)

    def sql(self, *a):
        conn = self.db.connect()
        try:
            return conn.execute(*a)
        finally:
            conn.close()

    # keys
    def test_generate_only_refuses_imports_and_records_origin(self):
        conn = self.db.connect()
        with Vault(self.db, conn, OLD.encode()).unlock() as v:
            self.assertEqual(v.key_policy(), 'open')
            site.set_setting(conn, 'vault.policy', 'generate-only', 'test')
            with self.assertRaises(VaultError):
                v.add_key('reused', private_pem())
            v.generate_key('fresh')
            origin = {k['name']: k['origin'] for k in v.list_keys()}
        conn.close()
        self.assertEqual(origin, {'client-a': 'imported', 'fresh': 'generated'})

    def test_import_dir_takes_nothing_under_generate_only(self):
        conn = self.db.connect()
        site.set_setting(conn, 'vault.policy', 'generate-only', 'test')
        conn.close()
        folder = self.tmp / 'import'
        folder.mkdir()
        (folder / 'reused').write_bytes(private_pem())
        self.assertEqual(cli.main(['--db', str(self.path), 'vault', 'import-dir', str(folder)]), 0)
        conn = self.db.connect()
        self.assertIsNone(conn.scalar("SELECT 1 FROM ssh_keys WHERE name = 'reused'"))
        conn.close()

    # restore
    def other_site(self, named='Client Z', with_id=True):
        path = self.tmp / 'other.db'
        other = Database(str(path))
        conn = other.connect()
        other.migrate(conn)
        if with_id:
            site.ensure(conn)
            site.rename(conn, named, 'test')
        conn.close()
        return path

    def test_restore_refuses_another_sites_backup(self):
        with self.assertRaisesRegex(SystemExit, 'Client Z'):
            backup.restore(self.db, str(self.other_site()))
        conn = self.db.connect()
        self.assertEqual(site.name(conn), 'Client A')
        conn.close()

    def test_restore_takes_its_own_backup(self):
        made = backup.create(self.db, 'full', self.tmp)
        self.assertIsNone(backup.restore(self.db, made['path'])['warning'])

    def test_restore_onto_a_blank_or_missing_database_is_a_rebuild(self):
        made = backup.create(self.db, 'full', self.tmp)
        blank = self.tmp / 'blank.db'
        other = Database(str(blank))
        conn = other.connect()
        other.migrate(conn)
        site.ensure(conn)
        conn.close()
        self.assertEqual(backup.restore(other, made['path'])['keys'], 1)
        self.assertEqual(backup.restore(Database(str(self.tmp / 'missing.db')), made['path'])['keys'], 1)

    def test_a_backup_naming_no_site_only_warns_on_an_open_site(self):
        self.assertIn('no site', backup.restore(self.db, str(self.other_site(with_id=False)))['warning'])

    def test_a_backup_naming_no_site_is_refused_under_generate_only(self):
        conn = self.db.connect()
        site.set_setting(conn, 'vault.policy', 'generate-only', 'test')
        conn.close()
        with self.assertRaisesRegex(SystemExit, 'generated in its own vault'):
            backup.restore(self.db, str(self.other_site(with_id=False)))

    # reset
    def test_reset_archives_the_old_site_and_starts_clean(self):
        backups = self.data / 'backups'
        backups.mkdir()
        (backups / 'storageforge-essentials-20260101-030000.db').write_bytes(b'old backup')
        (self.data / 'index.db.pre-restore-20260101-030000').write_bytes(b'older')
        old = site.read_file(self.path)['id']

        r = self.run_reset()

        # the new site
        fresh = Database(str(self.path))
        conn = fresh.connect()
        new_secret = self.secret_file.read_text()
        self.assertNotEqual(new_secret, OLD)
        self.assertEqual(stat.S_IMODE(self.secret_file.stat().st_mode), 0o400)
        self.assertEqual(stat.S_IMODE(self.secrets.stat().st_mode), 0o500)
        with Vault(fresh, conn, new_secret.encode()).unlock() as v:
            self.assertEqual(v.key_policy(), 'generate-only')
            self.assertEqual(v.list_keys(), [])
            self.assertEqual(AuditLog(fresh, conn, v.audit_key).verify()[0], True)
        self.assertEqual(site.name(conn), 'Client B')
        self.assertNotEqual(site.site_id(conn), old)
        self.assertEqual(users.open_invite(conn, r['token'])['role'], 'admin')
        conn.close()

        # nothing of the old one in reach
        self.assertEqual(list(backups.iterdir()), [])
        self.assertFalse((self.data / 'ssh' / 'known_hosts').exists())
        self.assertEqual(list(self.data.glob('index.db.pre-restore-*')), [])
        self.assertEqual(list(self.data.glob('index.db.new*')), [])

        # the old one, whole, in the archive
        out = Path(r['archive'])
        self.assertTrue(out.name.startswith('client-a-'))
        self.assertEqual(stat.S_IMODE(out.stat().st_mode), 0o700)
        self.assertEqual((out / 'vault_secret').read_text(), OLD)
        self.assertEqual(stat.S_IMODE((out / 'vault_secret').stat().st_mode), 0o600)
        self.assertEqual((out / 'data' / 'ssh' / 'known_hosts').read_text(), 'nas-1 ssh-ed25519 AAAA\n')
        self.assertTrue((out / 'backups' / 'storageforge-essentials-20260101-030000.db').exists())
        self.assertTrue((out / 'data' / 'index.db.pre-restore-20260101-030000').exists())
        left = json.loads((out / 'left-behind.json').read_text())
        self.assertEqual(left['keys_on_hosts'][0]['host'], 'nas-*')
        kept = Database(str(next((out / 'database').glob('storageforge-full-*'))))
        conn = kept.connect()
        with Vault(kept, conn, OLD.encode()).unlock() as v:
            self.assertEqual([k['name'] for k in v.list_keys()], ['client-a'])
            self.assertEqual(AuditLog(kept, conn, v.audit_key).verify()[0], True)
        self.assertEqual(conn.scalar("SELECT count(*) FROM audit_log WHERE action = 'site.reset'"), 1)
        conn.close()

    def untouched(self):
        self.assertEqual(self.secret_file.read_text(), OLD)
        self.assertEqual(site.read_file(self.path)['name'], 'Client A')
        self.assertEqual(list(self.archive.iterdir()), [])

    def test_reset_refuses_while_a_server_runs(self):
        lock = reset.hold_server_lock(self.db)
        try:
            with self.assertRaisesRegex(SystemExit, 'server is running'):
                self.run_reset()
        finally:
            lock.close()
        self.untouched()

    def test_reset_refuses_an_archive_the_new_site_could_read(self):
        inside = self.data / 'archive'
        inside.mkdir()
        with self.assertRaisesRegex(SystemExit, 'inside'):
            self.run_reset(archive=inside)
        self.untouched()

    def test_reset_refuses_while_deployed_unless_abandoned(self):
        self.sql("INSERT INTO deploy_access (host, state, updated_at) VALUES ('nas-1', 'ok', 1)")
        with self.assertRaisesRegex(SystemExit, 'nas-1'):
            self.run_reset()
        self.untouched()
        self.assertEqual(self.run_reset(abandon=True)['abandoned'], 1)

    def test_reset_refuses_old_keys_waiting_for_import(self):
        keys = self.tmp / 'keys'
        keys.mkdir()
        (keys / 'client-a').write_bytes(b'x')
        with self.assertRaisesRegex(SystemExit, 'client-a'):
            self.run_reset()
        self.untouched()

    def test_reset_refuses_the_wrong_secret(self):
        self.secrets.chmod(0o700)
        self.secret_file.chmod(0o600)
        self.secret_file.write_text('w' * 40)
        with self.assertRaises(VaultError):
            self.run_reset()
        self.assertEqual(list(self.archive.iterdir()), [])

    def test_secret_from_the_environment_needs_a_new_one(self):
        with mock.patch.dict(os.environ, {'STORAGEFORGE_VAULT_SECRET': OLD}):
            with self.assertRaisesRegex(SystemExit, 'NEW_SECRET'):
                self.run_reset()
            with mock.patch.dict(os.environ, {'STORAGEFORGE_VAULT_NEW_SECRET': OLD}):
                with self.assertRaisesRegex(SystemExit, 'old secret'):
                    self.run_reset()
            self.untouched()
            with mock.patch.dict(os.environ, {'STORAGEFORGE_VAULT_NEW_SECRET': 'n' * 40}):
                self.assertFalse(self.run_reset()['secret_installed'])
        self.assertEqual(self.secret_file.read_text(), OLD)
        fresh = Database(str(self.path))
        conn = fresh.connect()
        Vault(fresh, conn, b'n' * 40).unlock().close()
        conn.close()

    def test_export_dir_is_per_named_site(self):
        conn = self.db.connect()
        self.assertEqual(site.export_dir(conn, '/mnt/x'), '/mnt/x/client-a')
        conn.close()
