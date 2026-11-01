"""One database is one site: identity, keys that cannot be shared between clients, and starting a new environment."""
import json
import os
import shutil
import stat
import subprocess
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
from storageforge_index import alerts, backup, cli, reset, site, users
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

    # sites sharing a machine
    def foreign_file(self, *lines):
        path = self.tmp / 'foreign'
        path.write_text(''.join(f'{x}\n' for x in lines))
        patcher = mock.patch.dict(os.environ, {'STORAGEFORGE_FOREIGN_FILE': str(path)})
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_a_key_another_site_uses_is_refused(self):
        pem = private_pem()
        conn = self.db.connect()
        with Vault(self.db, conn, OLD.encode()).unlock() as v:
            fp = v.add_key('here', pem)['fingerprint']
            v.remove_key('here')
            self.foreign_file(f'key {fp}')
            with self.assertRaisesRegex(VaultError, 'Another site'):
                v.add_key('again', pem)
            v.add_key('different', private_pem())
        conn.close()

    def test_no_foreign_file_refuses_nothing(self):
        with mock.patch.dict(os.environ, {'STORAGEFORGE_FOREIGN_FILE': str(self.tmp / 'none')}):
            self.assertEqual(site.foreign(), {'key': set(), 'host': set()})

    def test_shared_keys_and_machines_raise_alerts(self):
        conn = self.db.connect()
        fp = conn.scalar('SELECT fingerprint FROM ssh_keys')
        conn.execute("""INSERT INTO hosts (hostname, host_keys)
                        VALUES ('nas-1', :k)""", {'k': json.dumps(['SHA256:machine', 'local'])})
        self.assertEqual(site.shared_problems(conn), {})
        self.foreign_file(f'key {fp}', 'host SHA256:machine')
        found = site.shared_problems(conn)
        self.assertEqual(found['shared-key:client-a'][4], 'crit')
        self.assertEqual(found['shared-host:nas-1'][4], 'warn')
        self.assertIn('shared-host:nas-1', alerts.problems(conn))
        rows = sorted(r[0] for r in site.fingerprints(conn))
        self.assertEqual(rows, ['host', 'key'])      # 'local' is not a machine to compare
        conn.close()

    def test_site_init_names_it_and_refuses_imports(self):
        path = self.tmp / 'new.db'
        fresh = Database(str(path))
        conn = fresh.connect()
        fresh.migrate(conn)
        Vault(fresh, conn, OLD.encode()).init()
        conn.close()
        self.assertEqual(cli.main(['--db', str(path), 'site', 'init', '--name', 'Acme']), 0)
        info = site.read_file(path)
        self.assertEqual((info['name'], info['policy']), ('Acme', 'generate-only'))
        self.assertTrue(info['id'])
        with self.assertRaisesRegex(SystemExit, 'already Acme'):
            cli.main(['--db', str(path), 'site', 'init', '--name', 'Other'])

    def test_site_archive_changes_nothing(self):
        r = reset.archive(Database(str(self.path)), str(self.archive))
        self.assertEqual((Path(r['archive']) / 'vault_secret').read_text(), OLD)
        self.assertTrue((Path(r['archive']) / 'data' / 'ssh' / 'known_hosts').exists())
        self.assertEqual(self.secret_file.read_text(), OLD)
        self.assertEqual(site.read_file(self.path)['name'], 'Client A')
        self.assertTrue((self.data / 'ssh' / 'known_hosts').exists())

    def test_session_cookie_is_per_site(self):
        from storageforge_index.server import session_cookie_name
        self.assertEqual(session_cookie_name(True), '__Host-sf_session')
        self.assertEqual(session_cookie_name(False), 'sf_session')
        with mock.patch.dict(os.environ, {'STORAGEFORGE_COOKIE_SUFFIX': 'acme'}):
            self.assertEqual(session_cookie_name(True), '__Host-sf_session_acme')
        with mock.patch.dict(os.environ, {'STORAGEFORGE_COOKIE_SUFFIX': 'a;b=c'}), self.assertRaises(SystemExit):
            session_cookie_name(True)


class SfSiteScript(unittest.TestCase):
    """docker/sf-site against a stand-in for docker: which ports and bridges it picks, and what it will not remove."""
    SCRIPT = Path(__file__).resolve().parents[1] / 'docker' / 'sf-site'

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)
        (self.tmp / 'bin').mkdir()
        fake = self.tmp / 'bin' / 'docker'
        fake.write_text(f'#!/bin/sh\necho "$*" >>{self.tmp}/calls\ncase "$*" in *fingerprints*) cat {self.tmp}/fp-"$3" 2>/dev/null ;; esac\nexit 0\n')
        fake.chmod(0o755)

    def sf(self, *args, stdin=''):
        env = {**os.environ, 'PATH': f'{self.tmp}/bin:/usr/bin:/bin', 'SF_SITES_DIR': str(self.tmp / 'sites'),
               'SF_NO_DEFAULT': '1', 'SF_FIRST_PORT': '48444'}
        return subprocess.run(['bash', str(self.SCRIPT), *args], env=env, input=stdin, capture_output=True, text=True, timeout=30)

    def env_of(self, slug):
        return dict(x.split('=', 1) for x in (self.tmp / 'sites' / slug / 'site.env').read_text().splitlines())

    def test_new_sites_get_their_own_port_bridge_and_cookie(self):
        self.assertEqual(self.sf('new', 'acme', '--name', 'Acme Ltd').returncode, 0)
        self.assertEqual(self.sf('new', 'beta', '--name', 'Beta').returncode, 0)
        a, b = self.env_of('acme'), self.env_of('beta')
        self.assertNotEqual(a['STORAGEFORGE_HTTPS_PORT'], b['STORAGEFORGE_HTTPS_PORT'])
        self.assertNotEqual(a['STORAGEFORGE_BRIDGE'], b['STORAGEFORGE_BRIDGE'])
        self.assertEqual(b['STORAGEFORGE_COOKIE_SUFFIX'], 'beta')
        self.assertLessEqual(len(a['STORAGEFORGE_BRIDGE']), 15)
        self.assertIn('site init --name Acme Ltd', (self.tmp / 'calls').read_text())

    def test_new_refuses_bad_names_and_duplicates(self):
        self.assertNotEqual(self.sf('new', 'Bad/name', '--name', 'x').returncode, 0)
        self.assertNotEqual(self.sf('new', 'default', '--name', 'x').returncode, 0)
        self.assertNotEqual(self.sf('new', 'noname').returncode, 0)
        self.sf('new', 'acme', '--name', 'A')
        self.assertNotEqual(self.sf('new', 'acme', '--name', 'B').returncode, 0)

    def test_remove_needs_an_archive_and_the_typed_name(self):
        self.sf('new', 'acme', '--name', 'A')
        self.assertIn('archive it first', self.sf('remove', 'acme', stdin='acme\n').stderr)
        self.assertEqual(self.sf('archive', 'acme').returncode, 0)
        self.assertNotEqual(self.sf('remove', 'acme', stdin='nope\n').returncode, 0)
        self.assertNotIn('down -v', (self.tmp / 'calls').read_text())
        self.assertEqual(self.sf('remove', 'acme', stdin='acme\n').returncode, 0)
        self.assertIn('-p sf-acme', [x for x in (self.tmp / 'calls').read_text().splitlines() if 'down -v' in x][0])
        self.assertFalse((self.tmp / 'sites' / 'acme').exists())
        self.assertEqual(len(list((self.tmp / 'sites' / '.removed').iterdir())), 1)

    def test_audit_and_sync_compare_sites(self):
        self.sf('new', 'acme', '--name', 'A')
        self.sf('new', 'beta', '--name', 'B')
        self.assertEqual(self.sf('audit').returncode, 0)
        (self.tmp / 'fp-sf-acme').write_text('key\tSHA256:same\tk1\nhost\tSHA256:box\tnas\n')
        (self.tmp / 'fp-sf-beta').write_text('key\tSHA256:same\tk2\n')
        r = self.sf('audit')
        self.assertEqual(r.returncode, 1)
        self.assertIn('key SHA256:same', r.stdout)
        self.assertNotIn('SHA256:box', r.stdout)
        self.assertEqual(self.sf('sync').returncode, 0)
        self.assertEqual((self.tmp / 'sites' / 'beta' / 'foreign').read_text(), 'host SHA256:box\nkey SHA256:same\n')
        self.assertEqual((self.tmp / 'sites' / 'acme' / 'foreign').read_text(), 'key SHA256:same\n')
