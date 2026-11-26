"""Bug hunt, rest E: scheduler, tasks, snapshot jobs, deploy output, search, folders, exports and small fixes.
Run with: python3 -m unittest test_bughunt_rest_e -v"""
import collections
import json
import shlex
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

try:
    import dbfactory
except ImportError:      # run as tests.test_x from the project folder
    from tests import dbfactory
from storageforge_index import deploy, jobs, mapexport, remote, remotes, scheduler, search, site, snapfind, snapjobs, tasks, wlcapture, wlexport
from storageforge_index import tbadapters, tbadapters_b  # noqa: F401
from storageforge_index.db import Database

try:
    from test_scheduler import SchedulerBaseTest
    from test_tasks import Fleet
except ImportError:
    from tests.test_scheduler import SchedulerBaseTest
    from tests.test_tasks import Fleet


class SchedulerE(SchedulerBaseTest):
    def make(self, **cfg):
        self.n = getattr(self, 'n', 0) + 1
        s, _ = scheduler.create_schedule(self.conn, {'name': f's{self.n}', 'host': 'nas', 'cron_expr': '0 3 * * *', 'task_type': 'command',
                                                     'task_ref': 'true', 'config': cfg}, 'test')
        return s

    def test_reverify_of_a_silent_direct_run_keeps_its_patterns(self):
        s = self.make(verify_rules={'output_must_match': 'DONE'})
        now = int(time.time())
        res = scheduler.ingest_report(self.conn, {'schedule_id': s['schedule_id'], 'exit_code': 0, 'output': '', 'started_at': now - 9, 'finished_at': now - 5}, 'direct')
        run = self.conn.scalar('SELECT run_id FROM schedule_runs WHERE schedule_id = :s', {'s': s['schedule_id']})
        out = scheduler.reverify_run(self.conn, run)
        self.assertFalse(out['verify_result']['passed'] if 'verify_result' in out else out.get('verified') == 1)
        self.assertNotEqual(self.conn.scalar('SELECT status FROM schedule_runs WHERE run_id = :r', {'r': run}), 'verified')

    def test_notifications_can_be_turned_off(self):
        s = self.make(notify_on=[])
        self.assertEqual(scheduler.get_schedule(self.conn, s['schedule_id'])['config']['notify_on'], [])
        s = self.make(notify_on=['failure', 'bogus'])
        self.assertEqual(scheduler.get_schedule(self.conn, s['schedule_id'])['config']['notify_on'], ['failure'])
        s = self.make()
        self.assertEqual(scheduler.get_schedule(self.conn, s['schedule_id'])['config']['notify_on'], ['failure', 'verify_failure'])

    def test_finished_at_cannot_park_the_next_run(self):
        s = self.make()
        now = int(time.time())
        scheduler.ingest_report(self.conn, {'schedule_id': s['schedule_id'], 'exit_code': 0, 'output': 'x', 'started_at': now - 5,
                                            'finished_at': now + 5 * 365 * 86400}, 'direct')
        nxt = scheduler.get_schedule(self.conn, s['schedule_id'])['next_run_at']
        self.assertLess(nxt, now + 3 * 86400)

    def test_a_paused_schedule_whose_task_is_gone_can_still_be_paused_on_its_host(self):
        s = self.make()
        sid = s['schedule_id']
        self.conn.execute("UPDATE schedules SET task_type = 'change', task_ref = '999', paused = 1 WHERE schedule_id = :s", {'s': sid})
        sched = scheduler.get_schedule(self.conn, sid)
        self.conn.execute("INSERT INTO deployed (host, kind, ref, deploy_hash, deployed_at, detail_json) VALUES ('nas', 'schedules', :r, 'h', 1, '{}')", {'r': str(sid)})
        items = scheduler.deploy_items(self.db, self.conn, sched, 'apply', None, 'test')
        install = [i for i in items if i['args'] == ['--install']]
        self.assertEqual(len(install), 1)
        self.assertIn('PAUSED=1', install[0]['script'])
        sched['paused'] = False
        with self.assertRaises(LookupError):                  # resuming has nothing to run
            scheduler.deploy_items(self.db, self.conn, sched, 'apply', None, 'test')


class TaskIdentity(Fleet):
    def mk(self, name='nightly'):
        return {'name': name, 'host': 'nas', 'schedule': 'daily',
                'blocks': [{'type': 'rotate', 'params': {'src_host': 'pc', 'src': '/home', 'dst': '/mnt/backup/pc', 'keep': 3}}]}

    def test_units_are_named_by_id_and_retire_the_old_slug(self):
        tid = tasks.save_task(self.conn, self.mk(), 'test')
        text = tasks.script(self.conn, tasks.get_task(self.conn, tid), retired=['nightly', 'old name', '5-before-rename'])
        self.assertIn(f"TASK_KEY={tid}-nightly\n", text)
        self.assertIn("RETIRED=(nightly 5-before-rename)", text)       # a name that is no slug is left out
        self.assertIn('UNIT=sf-task-$TASK_KEY', text)
        sh = Path(self.tmp) / 't.sh'
        sh.write_text(text)
        self.assertEqual(subprocess.run(['bash', '-n', str(sh)], capture_output=True).returncode, 0)
        self.assertIn('TASK_KEY=nightly\n', tasks.script(self.conn, self.mk()))      # unsaved: the slug alone

    def test_install_after_a_rename_takes_the_old_unit_off(self):
        tid = tasks.save_task(self.conn, self.mk(), 'test')
        # installed by the version before: slug-only ref, and one by id under the name from before a rename
        self.conn.execute("INSERT INTO deployed (host, kind, ref, deploy_hash, deployed_at, detail_json) VALUES ('nas', 'tasks', 'nightly', 'h', 1, '{}')")
        self.conn.execute("INSERT INTO deployed (host, kind, ref, deploy_hash, deployed_at, detail_json) VALUES ('nas', 'tasks', :r, 'h', 1, :d)",
                          {'r': f'{tid}-first-name', 'd': json.dumps({'id': tid})})
        items = tasks.deploy_items(self.db, self.conn, tasks.get_task(self.conn, tid), 'apply', 'test')
        self.assertEqual([i['ref'] for i in items], [f'{tid}-nightly'])
        self.assertIn(f"RETIRED=({tid}-first-name nightly)", items[0]['script'])
        items[0]['on_ok']({'status': 'ok'})
        refs = sorted(r[0] for r in self.conn.all("SELECT ref FROM deployed WHERE kind = 'tasks'"))
        self.assertEqual(refs, [f'{tid}-nightly'])
        # the list the page reads is keyed by the slug the task has now
        self.assertEqual(list(tasks.installed(self.conn)), ['nightly'])
        self.conn.execute("UPDATE storage_tasks SET body_json = :b WHERE task_id = :i",
                          {'b': json.dumps({**self.mk('renamed'), 'timeout_min': 0, 'on_fail': [], 'description': ''}), 'i': tid})
        self.assertEqual(list(tasks.installed(self.conn)), ['renamed'])
        # uninstalling removes the rows for every name
        gone = tasks.deploy_items(self.db, self.conn, tasks.get_task(self.conn, tid), 'apply', 'test', remove=True)
        gone[0]['on_ok']({'status': 'ok'})
        self.assertEqual(self.conn.scalar("SELECT count(*) FROM deployed WHERE kind = 'tasks'"), 0)


class SnapshotJobs(unittest.TestCase):
    CONF = '/etc/rsnapshot.conf'

    def parsed(self, *lines):
        base = [f'R\t{self.CONF}\tsnapshot_root\t/snap/', f'R\t{self.CONF}\tretain\tdaily\t7', f'R\t{self.CONF}\tbackup\t/etc/\tlocalhost/',
                f'M\t{self.CONF}\text4\t/\t1']
        return snapfind.parse('\n'.join(base + [f'R\t{self.CONF}\t{x}' for x in lines]))[0]

    def test_the_layout_is_recorded_at_import(self):
        self.assertIs(self.parsed()['relative'], True)                                           # rsnapshot's default has --relative
        self.assertIs(self.parsed('rsync_long_args\t--stats --delete --numeric-ids')['relative'], False)
        self.assertIs(self.parsed('rsync_long_args\t--delete --relative --stats')['relative'], True)
        self.assertIs(snapjobs._spec(self.parsed('rsync_long_args\t--delete'))['relative'], False)

    def spec(self, relative):
        return {'tool': 'rsnapshot', 'relative': relative, 'backups': [{'src': '/etc/', 'dst': 'localhost/'}]}

    def test_original_of_follows_the_recorded_layout(self):
        self.assertEqual(snapjobs.original_of(self.spec(True), 'localhost/etc/hosts'), '/etc/hosts')
        self.assertEqual(snapjobs.original_of(self.spec(False), 'localhost/etc/hosts'), '/etc/etc/hosts')    # no --relative: dst holds the source's content
        self.assertEqual(snapjobs.original_of(self.spec(False), 'localhost/hosts'), '/etc/hosts')
        with self.assertRaises(ValueError):
            snapjobs.original_of(self.spec(True), 'localhost/hosts')
        self.assertEqual(snapjobs.original_of(self.spec(None), 'localhost/hosts'), '/etc/hosts')              # from before: the guess

    def job(self):
        return {'id': 'p1-a', 'runner': 'nas', 'spec': {**self.spec(True), 'config': '/etc/rsnapshot.conf', 'root': '/snap', 'logfile': '/etc/shadow',
                                                       'lowest': 'daily', 'levels': {'daily': 7}}}

    def test_the_log_is_followed_only_for_a_config_root_owns(self):
        text = snapjobs.script(self.job(), 'log')
        self.assertIn('(conf_ok /etc/rsnapshot.conf) && [[ -r /etc/shadow ]]', text)
        self.assertIn('conf_ok()', text)
        self.assertIn('0 "?????-??-?', snapfind.SNAPFIND.replace('"0 "', '0 "'))

    def test_retention_matches_tab_runs_and_fails_when_nothing_matched(self):
        captured = {}

        def run(db, host, body, **kw):
            captured['body'] = body
            return {'status': 'failed', 'output': ''}
        with mock.patch.object(snapjobs.deploy, 'run', run), mock.patch.object(jobs, 'get', lambda c, j: self.job()), \
                mock.patch.object(snapjobs, 'is_imported', lambda j: True):
            snapjobs.retention(None, None, 'p1-a', {'daily': 30}, 'test')
        body = captured.get('body')
        self.assertIn("-F'\\t+'", body)
        self.assertIn('exit !hit', body)
        self.assertRegex(body, r'die .*no retain line for daily')
        sh = shutil.which('awk')
        with tempfile.TemporaryDirectory() as d:
            conf = Path(d) / 'c.conf'
            conf.write_text('retain\t\tdaily\t7\nretain\tweekly\t4\n')
            awk = body.split('awk ', 1)[1].split(f" /etc/rsnapshot.conf", 1)[0]
            prog = shlex.split(awk)
            for level, rc in (('daily', 0), ('monthly', 1)):
                r = subprocess.run([sh, *prog[:]] + [str(conf)], env={'LEVEL': level, 'KEEP': '30'}, capture_output=True, text=True)
                self.assertEqual(r.returncode, rc, level)
            self.assertIn('retain\tdaily\t30', subprocess.run([sh, *prog, str(conf)], env={'LEVEL': 'daily', 'KEEP': '30'}, capture_output=True, text=True).stdout)


class SmallFixes(unittest.TestCase):
    def test_grype_negligible_is_low(self):
        src = Path(tbadapters_b.__file__).read_text()
        self.assertLess(src.index("if sev == 'NEGLIGIBLE'"), src.index("if sev not in SEVERITIES"))

    def test_wlexport_skips_a_port_target_that_is_not_a_number(self):
        compose = "services:\n  a:\n    image: x\n    ports:\n      - '8080:${APP_PORT}'\n      - '9090:80'\n      - '7070:80-81'\n"
        out = wlexport.model({'name': 'p', 'tasks': [{'type': 'stack', 'host': 'nas', 'params': {'runtime': 'docker', 'name': 'wiki', 'compose': compose}}]})
        ports = [p for o in out for s in o.get('services', []) for p in s['ports']]
        self.assertEqual([p['external'] for p in ports], [9090])

    def test_netbox_prefixes_come_from_the_subnet_label_and_scope_prop(self):
        graph = {'nodes': [{'id': 'subnet:10.0.0.0/24', 'kind': 'Subnet', 'label': '10.0.0.0/24', 'props': {}},
                           {'id': 'dhcp:x', 'kind': 'DHCPScope', 'label': 'lan', 'props': {'subnet': '10.0.1.0/24'}},
                           {'id': 'r', 'kind': 'Subnet', 'label': '10.0.0.1-10.0.0.9', 'props': {}}], 'edges': []}
        prefixes = {p['prefix'] for p in json.loads(mapexport.netbox(graph))['prefixes']}
        self.assertEqual(prefixes, {'10.0.0.0/24', '10.0.1.0/24'})

    def test_path_contains_escapes_wildcards(self):
        self.assertEqual(search.like_escape('my_backup'), 'my\\_backup')
        src = Path(search.__file__).read_text()
        self.assertIn("like_escape(q.path_contains)", src)
        self.assertIn("like_escape(h) + '.%'", src)

    def test_site_file_with_a_hash_in_its_name_is_read(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'site#2?x.db'
            import sqlite3
            con = sqlite3.connect(p)
            con.execute('CREATE TABLE settings (key TEXT, value_json TEXT)')
            con.execute('CREATE TABLE hosts (a)')
            con.commit()
            con.close()
            self.assertIsNotNone(site.read_file(p))

    def test_remote_node_known_hosts_uses_the_bare_name_for_port_22(self):
        self.assertEqual(remote.known_hosts_name('forge.example.com', 22), 'forge.example.com')
        src = Path(remotes.__file__).read_text()
        self.assertIn("known = f'{known_hosts_name(host, port)} {tunnel_host_key}'", src)

    def test_a_malformed_run_line_does_not_stop_job_ingestion(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp)
        db = dbfactory.make(self, f'{tmp}/t.db')
        conn = db.connect()
        db.migrate(conn)
        conn.execute("INSERT INTO hosts (hostname, ssh_host, ssh_user, inventory_json) VALUES ('nas', '10.0.0.5', 'scan', '{}')")
        text = '\n'.join(['{"job": []}', '{"job": {"a": 1}}', '{"job": "p1-a", "run": "%s", "start": 1e999}' % ('0' * 8 + '-0000-4000-8000-' + '0' * 12)])
        self.assertEqual(jobs.ingest_scan(conn, 'nas', text), 0)

    def test_a_folder_row_without_its_directory_is_skipped(self):
        src = Path(__import__('storageforge_index.folders', fromlist=['x']).__file__).read_text()
        self.assertIn('d = dirs.get(dir_id)', src)

    def test_capture_of_an_unread_workload_is_refused(self):
        with self.assertRaisesRegex(ValueError, 'scan the host again'):
            wlcapture.render({'host': 'h', 'runtime': 'docker', 'name': 'x', 'detail': False})

    def test_deploy_keeps_the_end_of_a_long_output_and_sees_a_late_missing_line(self):
        self.assertTrue(deploy.UNFINISHED.search('ok\n  missing: a step\n'))
        src = Path(deploy.__file__).read_text()
        self.assertIn('tail.append(s)', src)
        self.assertIn('unfinished[0] = True', src)


class Migrations(unittest.TestCase):
    def test_a_failing_sqlite_migration_leaves_nothing_and_a_done_one_is_skipped(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp)
        db = dbfactory.make(self, f'{tmp}/t.db')
        if db.dialect != 'sqlite':
            self.skipTest('sqlite only')
        conn = db.connect()
        db.migrate(conn)
        mig = Path(tmp) / '900_bad.sql'
        mig.write_text('CREATE TABLE half_done (a INT);\nINSERT INTO nope VALUES (1);\n')
        with self.assertRaises(Exception):
            db._migrate_atomic(conn, mig, mig.read_text())
        self.assertIsNone(conn.scalar("SELECT name FROM sqlite_master WHERE name = 'half_done'"))
        self.assertFalse(conn.raw.in_transaction)
        ok = Path(tmp) / '901_ok.sql'
        ok.write_text("CREATE TABLE fine (a INT);\nINSERT INTO schema_version (version, name, applied_at) VALUES (901, 'ok', 1);\n")
        self.assertTrue(db._migrate_atomic(conn, ok, ok.read_text()))
        self.assertFalse(db._migrate_atomic(conn, ok, ok.read_text()))      # applied: found done once the lock is held


if __name__ == '__main__':
    unittest.main()
