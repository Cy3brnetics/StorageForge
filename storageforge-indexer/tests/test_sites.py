"""One database is one site: identity, keys that cannot be shared between clients, and starting a new environment."""
import json
import os
import re
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
from storageforge_index import alerts, authkeys, backup, changes, cli, moves, scheduler, shares, tasks, reset, site, users
from storageforge_index.db import Database
from storageforge_index.remote import INVENTORY_SCRIPT
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

    def test_reset_refuses_while_a_remote_node_dials_in(self):
        self.sql("""INSERT INTO remote_nodes (name, public_key, created_at, expires_at) VALUES ('branch', 'k', 1, 2)""")
        with self.assertRaisesRegex(SystemExit, 'remote node branch'):
            self.run_reset()
        self.untouched()

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

    def test_a_given_secret_goes_in_a_file_this_command_can_write(self):
        with mock.patch.dict(os.environ, {'STORAGEFORGE_VAULT_NEW_SECRET': 'n' * 40}):
            self.assertTrue(self.run_reset()['secret_installed'])
        self.assertEqual(self.secret_file.read_text(), 'n' * 40)

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

    # generated scripts
    def test_scripts_name_their_site(self):
        conn = self.db.connect()
        self.assertEqual(site.stamp(conn, '#!/bin/sh\necho hi\n'), '#!/bin/sh\n# Site: Client A\necho hi\n')
        site.set_setting(conn, 'site.name', 'Bad\nrm -rf /', 'test')      # however it got there, it stays a comment
        self.assertEqual(site.stamp(conn, '#!/bin/sh\n').count('\n'), 2)
        conn.execute("DELETE FROM settings WHERE key = 'site.name'")
        self.assertEqual(site.stamp(conn, '#!/bin/sh\n'), '#!/bin/sh\n')       # unchanged for an unnamed site
        conn.close()
        for fn in (moves.script, changes.script, shares.script, tasks.script, scheduler.generate_install_script):
            self.assertTrue(hasattr(fn, '__wrapped__'), fn)

    def test_a_real_generator_is_stamped(self):
        conn = self.db.connect()
        text = changes.script(conn, {'name': 'p', 'tasks': []})
        conn.close()
        self.assertEqual(text.splitlines()[1], '# Site: Client A')

    # authorized_keys
    KEY = 'AAAAC3NzaC1lZDI1NTE5AAAAIGJ1dCBpdCBpcyBub3QgYSByZWFsIGtleSBhdCBhbGw='

    def test_parse_authkeys(self):
        got = authkeys.parse(f'root\t{self.KEY}\t me@laptop\n!\tbob\nroot\tnot base64!\t\nnoise\n')
        self.assertEqual(got['unreadable'], ['bob'])
        self.assertEqual([k['comment'] for k in got['keys']], ['me@laptop'])
        self.assertTrue(got['keys'][0]['fingerprint'].startswith('SHA256:'))

    @unittest.skipUnless(shutil.which('sh'), 'needs sh')
    def test_inventory_section_reads_authorized_keys(self):
        home, locked = self.tmp / 'home', self.tmp / 'locked'
        (home / '.ssh').mkdir(parents=True)
        (home / '.ssh' / 'authorized_keys').write_text(
            f'# a comment\nno-pty,command="x y" ssh-ed25519 {self.KEY} me@laptop\nssh-rsa AAAA\n')
        (locked / '.ssh').mkdir(parents=True)
        (locked / '.ssh').chmod(0o000)
        (self.tmp / 'bin').mkdir()
        (self.tmp / 'bin' / 'getent').write_text(
            f'#!/bin/sh\necho "amy:x:1000:1000::{home}:/bin/sh"\necho "lee:x:1001:1001::{locked}:/bin/sh"\n'
            f'echo "daemon:x:2:2::{home}:/bin/sh"\necho "gone:x:1002:1002::/nonexistent:/bin/sh"\n')
        (self.tmp / 'bin' / 'getent').chmod(0o755)
        section = re.search(r"(echo '@@authkeys'.*?)echo '@@accounts'", INVENTORY_SCRIPT, re.S).group(1)
        try:
            out = subprocess.run(['sh', '-c', section], env={'PATH': f'{self.tmp}/bin:/usr/bin:/bin'},
                                 capture_output=True, text=True, timeout=30)
        finally:
            (locked / '.ssh').chmod(0o700)
        self.assertEqual(out.stderr, '')
        got = authkeys.parse(out.stdout)
        self.assertEqual(sorted(k['user'] for k in got['keys']), ['amy', 'amy'])     # not daemon: a system account
        self.assertIn('me@laptop', [k['comment'] for k in got['keys']])
        if os.geteuid():
            self.assertEqual(got['unreadable'], ['lee'])

    def host_with_keys(self, conn, **seen):
        conn.execute("INSERT INTO hosts (hostname, inventory_json) VALUES ('nas-1', :i)",
                     {'i': json.dumps({'authkeys': {'unreadable': [], **seen}})})

    def test_unknown_keys_alert_only_on_generate_only_sites(self):
        conn = self.db.connect()
        vault_fp = conn.scalar('SELECT fingerprint FROM ssh_keys')
        stranger = 'SHA256:' + 'A' * 43
        self.host_with_keys(conn, keys=[{'user': 'root', 'fingerprint': vault_fp, 'comment': ''},
                                        {'user': 'root', 'fingerprint': stranger, 'comment': 'me@laptop'}])
        self.assertEqual(authkeys.problems(conn), {})
        self.assertEqual([k['known'] for k in authkeys.report(conn)[0]['keys']], ['vault', None])
        site.set_setting(conn, 'vault.policy', 'generate-only', 'test')
        found = alerts.problems(conn)['unknown-key:nas-1']
        self.assertIn(stranger, found[3])
        self.assertNotIn(vault_fp, found[3])
        authkeys.allow(conn, stranger, 'the on-call admin', 'test')
        self.assertEqual(authkeys.problems(conn), {})
        authkeys.disallow(conn, stranger, 'test')
        self.assertIn('unknown-key:nas-1', authkeys.problems(conn))
        with self.assertRaises(SystemExit):
            authkeys.allow(conn, 'nonsense', '', 'test')
        conn.close()

    def test_a_scan_from_before_this_is_not_reported_clean(self):
        conn = self.db.connect()
        conn.execute("INSERT INTO hosts (hostname, inventory_json) VALUES ('old', '{}')")
        self.assertEqual(authkeys.report(conn), [])
        conn.close()

    def test_reset_marks_the_secret_for_init_volumes(self):
        self.run_reset()
        self.assertTrue((self.secrets / 'reset_at').exists())

    def test_status_is_what_an_overview_shows(self):
        conn = self.db.connect()
        st = site.status(conn)
        conn.close()
        self.assertEqual((st['name'], st['hosts'], st['alerts'], st['last_scan']), ('Client A', 0, 0, '-'))


class SfSiteScript(unittest.TestCase):
    """docker/sf-site against a stand-in for docker: which ports and bridges it picks, and what it will not remove."""
    SCRIPT = Path(__file__).resolve().parents[1] / 'docker' / 'sf-site'

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)
        (self.tmp / 'bin').mkdir()
        fake = self.tmp / 'bin' / 'docker'
        fake.write_text(f'#!/bin/sh\necho "$*" >>{self.tmp}/calls\ncase "$*" in *fingerprints*) cat {self.tmp}/fp-"$3" 2>/dev/null ;; *"site status"*) printf "<b>Acme\\t2\\t-\\t1\\t-\\n" ;; esac\nexit 0\n')
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

    def test_overview_lists_sites_and_escapes_html(self):
        self.sf('new', 'acme', '--name', 'A')
        page = self.tmp / 'o.html'
        r = self.sf('overview', '--html', str(page))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('<b>Acme', r.stdout)
        text = page.read_text()
        self.assertIn('&lt;b&gt;Acme', text)
        self.assertNotIn('<b>Acme', text)
        self.assertEqual(stat.S_IMODE(page.stat().st_mode), 0o600)
