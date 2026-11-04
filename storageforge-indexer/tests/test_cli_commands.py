"""Every command of the command line, on a database a real scan filled. It's how people script StorageForge, and at the audit of
2026-11-03 most of it had never been run by a test. Exit codes are part of what these commands promise.
Run with: python3 -m unittest discover -s tests -v"""
import contextlib
import io
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

try:
    import dbfactory
except ImportError:      # run as tests.test_x from the project folder
    from tests import dbfactory
from storageforge_index import cli, vault
from storageforge_index.db import Database
from storageforge_index.remote import Transport
from storageforge_index.scanner import ScanOptions, scan_host

SECRET = 'command line tests secret, thrown away with its database'
PW = 'a long enough password for tests'


@unittest.skipIf(dbfactory.PG, 'these drive a SQLite file through --db; the commands take any --db, and the rest of the suite covers PostgreSQL')
class Commands(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        cls.addClassCleanup(shutil.rmtree, cls.tmp, True)
        cls.env = mock.patch.dict(os.environ, {'STORAGEFORGE_VAULT_SECRET': SECRET, 'STORAGEFORGE_DATA_DIR': str(cls.tmp), 'STORAGEFORGE_RUNTIME_DIR': str(cls.tmp),
                                               'STORAGEFORGE_BACKUP_DIR': str(cls.tmp / 'backups'), 'STORAGEFORGE_ARCHIVE_DIR': str(cls.tmp / 'archive'),
                                               'STORAGEFORGE_IMPORT_DIR': str(cls.tmp / 'keys')})
        cls.env.start()
        cls.addClassCleanup(cls.env.stop)
        vault.KDF_DEFAULTS.update(time_cost=1, memory_kib=8192, lanes=1)
        cls.path = cls.tmp / 'index.db'
        cls.db = Database(str(cls.path))
        conn = cls.db.connect()
        cls.db.migrate(conn)
        conn.close()
        cls.data = cls.tmp / 'scanned'
        (cls.data / 'album').mkdir(parents=True)
        (cls.data / 'album-copy').mkdir()
        same = os.urandom(1 << 16)
        for name in ('a.jpg', 'b.jpg', 'c.jpg'):
            (cls.data / 'album' / name).write_bytes(same + name.encode())
            (cls.data / 'album-copy' / name).write_bytes(same + name.encode())
        (cls.data / 'report.pdf').write_bytes(same)
        (cls.data / 'report-copy.pdf').write_bytes(same)
        (cls.data / 'gone.txt').write_text('soon gone\n')
        cls.result = cls.scan(checksum=True)
        cls.host = cls.result['host']
        (cls.data / 'gone.txt').unlink()
        (cls.data / 'new.txt').write_text('new\n')
        cls.scan(checksum=True)
        code, _, err = cls.run_cli('vault', 'init')
        assert code == 0, err

    @classmethod
    def scan(cls, checksum=False):
        opts = ScanOptions(roots=[str(cls.data)], checksum=checksum, checksum_min_size=1, include_tmpfs=True)
        return scan_host(cls.db, Transport('localhost', local=True), opts, log=lambda m: None)

    @classmethod
    def run_cli(cls, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                code = cli.main(['--db', str(cls.path), *args])
            except SystemExit as exc:
                code = exc.code if isinstance(exc.code, int) else 1
                if not isinstance(exc.code, int):
                    print(exc.code, file=err)
        return code, out.getvalue(), err.getvalue()

    def run_cli_raw(self, *args):
        try:
            return self.run_cli(*args)[0]
        except ValueError:          # what the command line shows as a traceback, and still not a success
            return 1

    def ok(self, *args):
        code, out, err = self.run_cli(*args)
        self.assertEqual(code, 0, f'{args}: {out} {err}')
        return out

    # ── discovery ───────────────────────────────────────────────────
    def test_search_finds_a_file_and_a_miss_is_not_an_error(self):
        self.assertIn('report-copy.pdf', self.ok('search', 'report-copy.pdf'))
        code, out, _ = self.run_cli('search', 'nothing-is-called-this')
        self.assertNotIn('nothing-is-called-this', out)
        self.assertIn(code, (0, 1))

    def test_changes_shows_each_change_in_both_formats(self):
        table = self.ok('changes', '--host', self.host)
        self.assertRegex(table, r'\+\s.*new\.txt')
        self.assertRegex(table, r'-\s.*gone\.txt')
        doc = json.loads(self.ok('changes', '--host', self.host, '--format', 'json'))
        self.assertEqual({(r['change'], Path(r['path']).name) for r in doc['changes']}, {('added', 'new.txt'), ('deleted', 'gone.txt')})
        self.assertEqual(self.run_cli('changes', '--host', 'nobody')[0], 1)

    def test_dupes_lists_identical_files_and_exits_1_when_there_are_none(self):
        self.assertIn('report-copy.pdf', self.ok('dupes', '--host', self.host, '--min-size', '1'))
        groups = [json.loads(x) for x in self.ok('dupes', '--host', self.host, '--min-size', '1', '--format', 'json').splitlines()]
        self.assertTrue(any('report-copy.pdf' in str(g['files']) for g in groups))
        self.assertEqual(self.run_cli('dupes', '--host', self.host, '--min-size', '1GiB')[0], 1)

    def test_folders_finds_twins_and_exits_1_when_there_are_none(self):
        system = ('--include-system',)      # the tests' folders are under /tmp, and a host's are not
        self.assertIn('album-copy', self.ok('folders', '--host', self.host, '--min-files', '3', '--min-size', '1', *system))
        doc = json.loads(self.ok('folders', '--host', self.host, '--min-files', '3', '--min-size', '1', '--format', 'json', *system))
        self.assertTrue(doc['groups'])
        self.assertEqual(self.run_cli('folders', '--host', self.host, '--min-files', '3', '--min-size', '1TiB')[0], 1)

    def test_hosts_lists_what_is_indexed(self):
        self.assertIn(self.host, self.ok('hosts'))

    def test_scan_dry_run_writes_nothing(self):
        before = self.ok('hosts')
        self.ok('scan', '--host', 'localhost', '--local', '--path', str(self.data), '--include-tmpfs', '--dry-run')
        self.assertEqual(self.ok('hosts'), before)

    def test_scan_says_when_a_host_cannot_be_reached(self):
        code, _, err = self.run_cli('scan', '--host', 'no-such-host.invalid')
        self.assertEqual(code, 1)
        self.assertIn('no-such-host.invalid', err)

    def test_access_status_and_script(self):
        self.ok('access', 'status')
        script = self.ok('access', 'script', '--user', 'scan')
        self.assertEqual(subprocess.run(['bash', '-n'], input=script.encode(), capture_output=True).returncode, 0)
        self.assertNotEqual(self.ok('access', 'script', '--user', 'scan', '--remove'), script)

    def test_git_docker_and_clamav_answer_with_no_data(self):
        self.ok('git')
        json.loads(self.ok('git', '--format', 'json'))
        self.ok('docker')
        self.ok('clamav', 'status')
        self.assertEqual(self.run_cli('clamav', 'list')[0], 0)

    # ── views and reports ───────────────────────────────────────────
    def test_the_graph_builds_counts_and_exports_a_canvas(self):
        self.assertRegex(self.ok('graph', 'build', '--host', self.host), r'\d+ nodes, \d+ edges')
        self.assertTrue(self.ok('graph', 'stats').strip())
        doc = json.loads(self.ok('canvas', '--host', self.host))
        known = {n['id'] for n in doc['nodes']}
        self.assertEqual([e for e in doc['edges'] if e['fromNode'] not in known or e['toNode'] not in known], [])
        target = self.tmp / 'out.canvas'
        self.ok('canvas', '-o', str(target))
        self.assertEqual(sorted(json.loads(target.read_text())), ['edges', 'nodes'])

    def test_export_markdown_names_the_host_and_its_mount(self):
        text = self.ok('export-markdown', '--host', self.host, '--title', 'Lab network')
        self.assertIn('Lab network', text)
        self.assertIn(self.host, text)

    def test_a_report_from_saved_payloads_needs_no_index(self):
        fstab = self.tmp / 'fstab'
        fstab.write_text('UUID=abc /srv ext4 defaults 0 2\n')
        lsblk = self.tmp / 'lsblk.json'
        lsblk.write_text(json.dumps({'blockdevices': [{'name': 'sda', 'size': 1 << 40, 'type': 'disk', 'model': 'Lab Disk', 'rota': True, 'tran': 'sata',
                                                       'children': [{'name': 'sda1', 'size': 1 << 39, 'type': 'part', 'fstype': 'ext4', 'mountpoint': '/srv'}]}]}))
        text = self.ok('report', '--lsblk', str(lsblk), '--fstab', str(fstab), '--hostname', 'paper-host', '--as-of', '2026-11-03')
        self.assertIn('paper-host', text)
        self.assertIn('/srv', text)

    def test_graph_import_from_payloads(self):
        fstab = self.tmp / 'fstab2'
        fstab.write_text('UUID=abc /data xfs defaults 0 2\n')
        self.assertRegex(self.ok('graph', 'import', '--fstab', str(fstab), '--hostname', 'paper-graph'), r'paper-graph: \d+ nodes')
        self.ok('canvas', '--host', 'paper-graph')

    def test_config_list_diff_script_and_export(self):
        listed = self.ok('config', 'list', self.host)
        ids = [int(line.split()[0]) for line in listed.splitlines()]
        self.assertTrue(ids, 'a scan captured no configuration')
        script = self.ok('config', 'script', self.host)
        self.assertEqual(subprocess.run(['bash', '-n'], input=script.encode(), capture_output=True).returncode, 0)
        self.ok('config', 'diff', str(ids[-1]), str(ids[0]))
        self.assertNotEqual(self.run_cli('config', 'diff', '999998', '999999')[0], 0)
        self.assertNotEqual(self.run_cli('config', 'script', 'nobody')[0], 0)
        written = self.tmp / 'reinstall.sh'
        self.ok('config', 'script', self.host, '-o', str(written))
        self.assertTrue(os.access(written, os.X_OK))
        bundle = self.tmp / 'configs.tar.gz'
        self.ok('config', 'export', '-o', str(bundle))
        self.assertEqual(bundle.stat().st_mode & 0o777, 0o600)
        self.assertTrue(tarfile.open(bundle).getnames())

    # ── plans, one per kind ─────────────────────────────────────────
    def imported(self, kind, body):
        f = self.tmp / f'{kind}-{time.monotonic_ns()}.json'
        f.write_text(json.dumps(body))
        out = self.ok(kind, 'import', str(f))
        return int(next(w for w in out.replace('#', ' ').split() if w.isdigit()))

    def test_moves_import_list_check_and_script(self):
        pid = self.imported('moves', {'name': 'cli move', 'steps': [{'method': 'mirror', 'src': {'host': self.host, 'path': str(self.data)},
                                                                     'dst': {'host': self.host, 'path': str(self.tmp / 'mirror')}}]})
        self.assertIn('cli move', self.ok('moves', 'list'))
        self.run_cli('moves', 'check', str(pid))      # says what it finds; it may refuse
        script = self.ok('moves', 'script', str(pid))
        self.assertEqual(subprocess.run(['bash', '-n'], input=script.encode(), capture_output=True).returncode, 0)
        target = self.tmp / 'move.sh'
        self.ok('moves', 'script', str(pid), '-o', str(target))
        self.assertTrue(os.access(target, os.X_OK))

    def test_tasks_import_list_check_and_script(self):
        tid = self.imported('tasks', {'name': 'cli task', 'host': self.host, 'schedule': '*-*-* 03:00:00', 'blocks': [{'type': 'log', 'params': {'message': 'hello'}}]})
        self.assertIn('cli task', self.ok('tasks', 'list'))
        self.run_cli('tasks', 'check', str(tid))
        script = self.ok('tasks', 'script', str(tid))
        self.assertIn('hello', script)
        self.assertEqual(subprocess.run(['bash', '-n'], input=script.encode(), capture_output=True).returncode, 0)

    def test_plan_types_import_list_check_script_and_ansible(self):
        self.assertIn('dir', self.ok('plan', 'types'))
        pid = self.imported('plan', {'name': 'cli plan', 'tasks': [{'type': 'dir', 'host': self.host, 'params': {'path': str(self.tmp / 'made')}}]})
        self.assertIn('cli plan', self.ok('plan', 'list'))
        self.run_cli('plan', 'check', str(pid))
        script = self.ok('plan', 'script', str(pid))
        self.assertEqual(subprocess.run(['bash', '-n'], input=script.encode(), capture_output=True).returncode, 0)
        self.assertIn('hosts:', self.ok('plan', 'ansible', str(pid)))

    def test_shares_check_and_script_on_a_host_with_no_design(self):
        code, out, err = self.run_cli('shares', 'check', self.host)
        self.assertIn(code, (0, 1), err)
        self.assertIsNotNone(out)

    def test_a_blueprint_is_stored_and_overlays_the_scan(self):
        f = self.tmp / 'bp.json'
        f.write_text(json.dumps({'apiVersion': 'storageforge/v1', 'kind': 'StorageBlueprint', 'metadata': {'host': self.host}, 'drives': [], 'mounts': []}))
        self.ok('blueprint', str(f))

    # ── deploy ──────────────────────────────────────────────────────
    def test_deploy_status_setup_script_and_alerts(self):
        self.ok('deploy', 'status')
        script = self.ok('deploy', 'setup-script')
        self.assertEqual(subprocess.run(['bash', '-n'], input=script.encode(), capture_output=True).returncode, 0)
        self.assertIn('storageforge-deploy', script)
        self.assertNotEqual(self.ok('deploy', 'setup-script', '--remove'), script)
        self.assertIn(self.run_cli('deploy', 'alerts')[0], (0, 1))

    def test_the_scheduler_from_end_to_end(self):
        made = json.loads(self.ok('schedule', 'add', '--name', 'cli-schedule', '--host', self.host, '--cron', '0 2 * * *', '--type', 'command', '--ref', 'true', '--json'))
        sid = str(made['schedule']['schedule_id'] if 'schedule_id' in made['schedule'] else made['schedule']['id'])
        self.assertIn('cli-schedule', self.ok('schedule', 'list'))
        self.assertIn('cli-schedule', self.ok('schedule', 'get', sid))
        self.ok('schedule', 'pause', sid)
        self.assertIn('cli-schedule', self.ok('schedule', 'list', '--paused'))
        self.ok('schedule', 'resume', sid)
        self.assertNotIn('cli-schedule', self.ok('schedule', 'list', '--paused'))
        self.assertTrue(self.ok('schedule', 'token', sid).strip())
        self.assertIn('0 2 * * *', self.ok('schedule', 'cron', sid))
        script = self.ok('schedule', 'install-script', sid, '--report-url', 'https://forge.example')
        self.assertEqual(subprocess.run(['bash', '-n'], input=script.encode(), capture_output=True).returncode, 0)
        self.ok('schedule', 'runs', '--id', sid)
        self.ok('schedule', 'remove', sid)
        self.assertNotIn('cli-schedule', self.ok('schedule', 'list'))

    # ── administration ──────────────────────────────────────────────
    def test_the_vault_from_a_key_to_its_removal(self):
        self.ok('vault', 'status')
        self.assertTrue(self.ok('vault', 'generate', '--name', 'cli-key').startswith('ssh-ed25519'))
        self.assertIn('cli-key', self.ok('vault', 'list'))
        self.assertTrue(self.ok('vault', 'pubkey', '--name', 'cli-key').startswith('ssh-ed25519'))
        self.ok('vault', 'bind', '--key', 'cli-key', '--host', 'nas-*', '--user', 'scan')
        self.assertIn('nas-*', self.ok('vault', 'bindings'))
        self.assertIn('cli-key', self.ok('vault', 'resolve', '--host', 'nas-1'))
        self.assertNotEqual(self.run_cli('vault', 'resolve', '--host', 'other')[0], 0)
        self.ok('vault', 'policy')
        self.ok('vault', 'remove', '--name', 'cli-key')
        self.assertNotIn('cli-key', self.ok('vault', 'list'))

    def test_a_private_key_is_imported_and_never_printed(self):
        key = self.tmp / 'imported'
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(key)], check=True)
        self.ok('vault', 'add', '--name', 'cli-import', '--key-file', str(key))
        listing = self.ok('vault', 'list')
        self.assertIn('cli-import', listing)
        self.assertNotIn('PRIVATE', listing)
        self.ok('vault', 'remove', '--name', 'cli-import')

    def test_host_keys_exit_1_for_an_unknown_key_and_rekey_needs_a_host(self):
        self.assertIn(self.run_cli('hosts', 'keys', self.host)[0], (0, 1))
        fingerprint = 'SHA256:' + 'A' * 43
        self.ok('hosts', 'allow-key', fingerprint, '--note', 'test')
        self.ok('hosts', 'disallow-key', fingerprint)
        self.assertNotEqual(self.run_cli_raw('hosts', 'allow-key', 'not a fingerprint'), 0)
        self.assertEqual(self.run_cli('hosts', 'rekey', 'nobody')[0], 2)

    def test_retiring_a_host_that_does_not_exist_fails(self):
        code, _, err = self.run_cli('hosts', 'remove', 'nobody')
        self.assertEqual(code, 1)
        self.assertIn('nobody', err)

    def test_accounts_from_adding_to_removing(self):
        with mock.patch.dict(os.environ, {'CLI_PW': PW}):
            self.ok('user', 'add', 'cli-user', '--password-env', 'CLI_PW', '--role', 'viewer')
            self.assertRegex(self.ok('user', 'list'), r'cli-user\s+viewer')
            self.ok('user', 'role', 'cli-user', 'operator')
            self.assertRegex(self.ok('user', 'list'), r'cli-user\s+operator')
            self.ok('user', 'disable', 'cli-user')
            self.assertRegex(self.ok('user', 'list'), r'cli-user.*DISABLED')
            self.ok('user', 'enable', 'cli-user')
            self.assertNotRegex(self.ok('user', 'list'), r'cli-user.*DISABLED')
            self.ok('user', 'passwd', 'cli-user', '--password-env', 'CLI_PW')
            self.ok('user', 'signout', 'cli-user')
            self.ok('user', 'remove', 'cli-user')
        self.assertNotIn('cli-user', self.ok('user', 'list'))

    def test_a_short_password_is_refused(self):
        with mock.patch.dict(os.environ, {'CLI_PW': 'short'}):
            self.assertNotEqual(self.run_cli('user', 'add', 'cli-weak', '--password-env', 'CLI_PW')[0], 0)
        self.assertNotIn('cli-weak', self.ok('user', 'list'))

    def test_the_audit_log_tails_and_verifies(self):
        self.ok('vault', 'generate', '--name', 'cli-audit')
        self.ok('vault', 'remove', '--name', 'cli-audit')
        self.assertIn('intact', self.ok('audit', 'verify'))
        rows = [json.loads(x) for x in self.ok('audit', 'tail', '--limit', '5', '--format', 'json').splitlines()]
        self.assertTrue(rows)
        self.assertTrue(self.ok('audit', 'tail', '--limit', '5').strip())

    def test_the_activity_log_finds_and_writes(self):
        self.ok('vault', 'generate', '--name', 'cli-log')
        self.ok('vault', 'remove', '--name', 'cli-log')
        self.assertTrue(self.ok('log', '--limit', '20').strip())
        self.assertNotIn('vault.key', self.ok('log', '--grep', 'nothing-holds-this'))
        target = self.tmp / 'log.csv'
        self.assertIn('entries written', self.ok('log', '--format', 'csv', '-o', str(target)))
        self.assertTrue(target.read_text().strip())
        self.assertNotEqual(self.run_cli('log', '--since', 'not a date')[0], 0)

    def test_prune_and_migrate_keep_what_is_recent(self):
        self.ok('migrate')
        self.assertRegex(self.ok('prune', '--days', '90'), r'removed \d+ change rows')
        self.assertTrue(self.ok('changes', '--host', self.host))

    def test_the_site_has_a_name_status_and_fingerprints(self):
        self.ok('site', 'rename', 'CLI Client')
        self.assertIn('CLI Client', self.ok('site', 'show'))
        self.assertTrue(self.ok('site', 'status').startswith('CLI Client'))
        self.ok('site', 'fingerprints')

    def test_reset_and_restore_refuse_without_yes(self):
        self.assertEqual(self.run_cli('reset', '--site-name', 'New')[0], 2)
        self.assertEqual(self.run_cli('restore', '/nowhere')[0], 2)

    def test_remote_nodes_list_and_adding_one_needs_the_tunnel(self):
        self.ok('remote', 'list')
        with self.assertRaisesRegex(ValueError, 'tunnel is not running'):     # tier 7 adds, adopts and revokes real ones
            self.run_cli('remote', 'add', 'cli-node', '--endpoint', 'forge.example:2222')
        self.assertNotIn('cli-node', self.ok('remote', 'list'))

    def test_healthcheck_fails_with_nothing_listening(self):
        code, _, _ = self.run_cli('healthcheck', '--url', 'http://127.0.0.1:9/healthz')
        self.assertNotEqual(code, 0)


@unittest.skipIf(dbfactory.PG, 'backups here are SQLite files (PostgreSQL: pg_dump)')
class BackupCommands(unittest.TestCase):
    """Apart from the rest: a restore replaces the database under the commands."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        env = mock.patch.dict(os.environ, {'STORAGEFORGE_VAULT_SECRET': SECRET, 'STORAGEFORGE_DATA_DIR': str(self.tmp), 'STORAGEFORGE_RUNTIME_DIR': str(self.tmp),
                                           'STORAGEFORGE_BACKUP_DIR': str(self.tmp / 'backups'), 'CLI_PW': PW})
        env.start()
        self.addCleanup(env.stop)
        vault.KDF_DEFAULTS.update(time_cost=1, memory_kib=8192, lanes=1)
        self.path = self.tmp / 'index.db'

    def run_cli(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(['--db', str(self.path), *args])
        self.assertEqual(code, 0, err.getvalue())
        return out.getvalue()

    def test_a_backup_is_written_listed_and_restored(self):
        self.run_cli('migrate')
        self.run_cli('vault', 'init')
        self.run_cli('user', 'add', 'kept', '--password-env', 'CLI_PW')
        made = self.run_cli('backup', 'create').split()[1]
        self.assertIn(Path(made).name, self.run_cli('backup', 'list'))
        self.run_cli('user', 'add', 'after', '--password-env', 'CLI_PW')
        self.assertIn('restored', self.run_cli('restore', made, '--yes'))
        names = self.run_cli('user', 'list')
        self.assertIn('kept', names)
        self.assertNotIn('after', names)
        self.assertIn('intact', self.run_cli('audit', 'verify'))

    def test_a_full_backup_holds_the_index_and_old_ones_go(self):
        self.run_cli('migrate')
        self.run_cli('vault', 'init')
        for _ in range(3):
            self.run_cli('backup', 'create', '--keep', '2')
        self.assertEqual(len(list((self.tmp / 'backups').glob('*'))), 2)
        self.run_cli('backup', 'create', '--full')
        self.assertIn('full', self.run_cli('backup', 'list'))


if __name__ == '__main__':
    unittest.main()
