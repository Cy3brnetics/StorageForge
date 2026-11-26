"""Bugs found in the plan, share, scheduler, snapshot-job and toolbox code: each test fails on the code as it was."""
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

try:
    import dbfactory
except ImportError:      # run as tests.test_x from the project folder
    from tests import dbfactory
from storageforge_index import deploy, moves, scheduler, shares, snapjobs, tbadapters, toolbox
from storageforge_index.stream import to_row

try:
    from test_toolbox import Base
except ImportError:
    from tests.test_toolbox import Base


class Scan(unittest.TestCase):
    def test_two_path_roots_on_one_mount_log_each_add_once(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        db = dbfactory.make(self, tmp / 'index.db')
        conn = db.connect()
        self.addCleanup(conn.close)
        db.migrate(conn)
        hid = conn.scalar("INSERT INTO hosts (hostname, ssh_host, inventory_json) VALUES ('nas', 'nas', '{}') RETURNING host_id")
        mid = conn.scalar("INSERT INTO mounts (host_id, mount_point, filesystem_type, scan_state) VALUES (:h, '/', 'ext4', 'indexed') RETURNING mount_id", {'h': hid})

        def walk(scan, root, names, full=False):
            rows = [to_row([b'f', b'10', b'644', b'0', b'0', b'1000000000', b'', n.encode()]) for n in names]
            db.stage_create(conn, 1)
            db.stage_insert(conn, 1, rows)
            stats = db.apply_diff(conn, scan, 1, mid, root, full)
            db.stage_drop(conn, 1)
            return stats
        first = db.begin_scan(conn, hid)
        walk(first, '/', ['/old/x.txt'], True)
        db.finish_scan(conn, first, hid, dict(entries=1, bytes=1, added=1, modified=0, deleted=0, read_errors=0), 'ok', 0.1)
        scan = db.begin_scan(conn, hid)
        walk(scan, '/a', ['/a/1.txt', '/a/2.txt'])
        walk(scan, '/b', ['/b/1.txt'])
        added = conn.all("SELECT parent_path, filename FROM file_changes WHERE scan_id = :s AND change_type = 'added'", {'s': scan})
        self.assertEqual(sorted(tuple(r) for r in added), [('/a', '1.txt'), ('/a', '2.txt'), ('/b', '1.txt')])


class Moves(unittest.TestCase):
    def test_subtree_matches_by_prefix_not_by_collation_range(self):
        where, p = moves._subtree_sql('/data/photos', '/data')
        self.assertNotIn('<', where)
        self.assertEqual((p['lo'], p['n']), ('/data/photos/', len('/data/photos') + 1))

    def test_git_verify_ignores_peeled_tag_lines(self):
        fn = next(l for l in moves.SCRIPT_BODY.splitlines() if l.startswith('git_refs()'))
        refs = 'aaa\tHEAD\nbbb\trefs/tags/v1\nccc\trefs/tags/v1^{}\nddd\trefs/heads/main\n'
        out = subprocess.run(['bash', '-c', fn + '\ngit_refs'], input=refs, capture_output=True, text=True).stdout
        self.assertEqual(out.split('\n')[:-1], ['bbb\trefs/tags/v1', 'ddd\trefs/heads/main'])


CONFIG = """# rsnapshot
snapshot_root\t/mnt/s/
retain\thourly\t6
retain\tdaily\t7
backup\t/home/\tlocalhost/\tone_fs=1
backup\t/etc/\tlocalhost/
"""


class Snap(unittest.TestCase):
    def edit(self, retain, backups, text=CONFIG):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        conf = Path(d) / 'c.conf'
        conf.write_text(text)
        env = {**os.environ, 'SF_ROOT': '/mnt/s/', 'SF_RETAIN': retain, 'SF_BACKUPS': backups, 'SF_EXCLUDES': '', 'SF_SET_EXCLUDES': '0'}
        return subprocess.run(['awk', snapjobs._RSNAPSHOT_EDIT_AWK, str(conf), str(conf)], capture_output=True, text=True, env=env).stdout

    def test_edit_keeps_backup_options_and_untouched_levels(self):
        out = self.edit('daily\t14', '/home/\tlocalhost/\n/etc/\tlocalhost/')
        self.assertIn('retain\thourly\t6\n', out)
        self.assertIn('retain\tdaily\t14\n', out)
        self.assertNotIn('daily\t7', out)
        self.assertIn('backup\t/home/\tlocalhost/\tone_fs=1\n', out)
        self.assertIn('backup\t/etc/\tlocalhost/\n', out)

    def test_edit_adds_a_new_level_after_the_last_one(self):
        out = self.edit('weekly\t4', '/home/\tlocalhost/')
        self.assertLess(out.index('retain\tdaily\t7'), out.index('retain\tweekly\t4'))

    def test_restore_of_a_relative_layout_and_longest_destination(self):
        spec = {'tool': 'rsnapshot', 'backups': [{'src': '/home/', 'dst': 'localhost/'}, {'src': '/etc/', 'dst': 'localhost/'}]}
        self.assertEqual(snapjobs.original_of(spec, 'localhost/etc/fstab'), '/etc/fstab')
        self.assertEqual(snapjobs.original_of(spec, 'localhost/home/a/b'), '/home/a/b')
        spec = {'tool': 'rsnapshot', 'backups': [{'src': '/a/', 'dst': 'x/'}, {'src': '/b/', 'dst': 'x/y/'}]}
        self.assertEqual(snapjobs.original_of(spec, 'x/y/f'), '/b/f')


class Toolbox(Base):
    def test_quadlet_quotes_an_environment_value_with_spaces(self):
        e = toolbox.find(self.conn, 'uptime-kuma')['entry']
        m = e['methods'][0]
        r = toolbox.resolve(e, m, {}, '', '')
        r['env'] = {'A': 'two words', 'B': 'plain'}
        text = toolbox.quadlet_text(e, m, r, True)
        self.assertIn('Environment="A=two words"\n', text)
        self.assertIn('Environment=B=plain\n', text)

    def test_port_overrides_by_container_port_reach_the_link_and_the_health_check(self):
        e = toolbox.find(self.conn, 'vaultwarden')['entry']
        m = next(x for x in e['methods'] if x.get('ports'))
        p = m['ports'][0]
        self.assertNotEqual(p['host'], p['container'], 'the entry maps a host port to another container port')
        self.assertEqual(tbadapters._host_port(e, m['kind'], {p['container']: 9000}, p['host']), 9000)
        self.assertEqual(tbadapters._host_port(e, m['kind'], {}, p['host']), p['host'])
        self.assertEqual(tbadapters._host_port(e, m['kind'], {p['host']: 9000}, p['host']), p['host'], 'a host-port key is not an override')


class Sched(unittest.TestCase):
    def test_removal_of_a_schedule_whose_task_is_gone_goes_the_orphan_way(self):
        sched = {'schedule_id': 7, 'task_type': 'task', 'task_ref': '99', 'host': 'nas', 'name': 's', 'paused': 0, 'cron_expr': '0 3 * * *', 'config': {}}
        with mock.patch.object(scheduler, 'generate_task_script', side_effect=LookupError('gone')), \
                mock.patch.object(scheduler, 'orphan_items', return_value=['orphan']) as orphan:
            self.assertEqual(scheduler.deploy_items(None, None, sched, 'apply', None, 'me', remove=True), ['orphan'])
        orphan.assert_called_once_with(None, None, 7, 'apply', 'me')


class Shares(Base):
    def test_a_design_is_deployed_only_when_the_clients_ran_too(self):
        self.host('pc', 'apt', [])
        shares.save_export(self.db, self.conn, 'nas', {'protocol': 'NFS', 'path': '/mnt/pool/photos', 'clients': '10.0.0.0/24'}, None, 'test')
        prev = {'clients': ['pc']}
        deploy.mark_deployed(self.conn, 'nas', 'shares', 'nas', 'old', prev, 'test')
        items = shares.deploy_items(self.db, self.conn, 'nas', 'apply', 'test')
        self.assertEqual([i['host'] for i in items], ['nas', 'pc'])
        sha = __import__('hashlib').sha256(items[0]['script'].encode()).hexdigest()[:16]

        def ran(host, status):          # what deploy.run records before the engine calls the item's hook
            self.conn.execute("""INSERT INTO deploy_runs (group_id, host, kind, ref, mode, status, script_sha, started_at)
                                 VALUES ('g', :h, 'shares', 'nas', 'apply', :s, :sha, 1)""", {'h': host, 's': status, 'sha': sha})
        ran('nas', 'ok')
        items[0]['on_ok']({'status': 'ok'})
        self.assertEqual(deploy.deployed(self.conn, kind='shares')[0]['hash'], 'old', 'the client has not run')
        ran('pc', 'failed')
        self.assertEqual(deploy.deployed(self.conn, kind='shares')[0]['hash'], 'old', 'the client failed')
        ran('pc', 'ok')                 # a retry runs only the host that was left, and that completes it
        items[1]['on_ok']({'status': 'ok'})
        self.assertNotEqual(deploy.deployed(self.conn, kind='shares')[0]['hash'], 'old')


if __name__ == '__main__':
    unittest.main()
