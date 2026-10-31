"""Storage tasks (blocks → Bash), the share wizard's checks and the file system browser.
Run with: python3 -m unittest discover -s tests -v"""
import json
import os
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

try:
    import dbfactory
except ImportError:      # run as tests.test_x from the project folder
    from tests import dbfactory
from storageforge_index import fsmap, jobs, moves, scriptkit, shares, tasks
from storageforge_index.db import Database, dir_id


class Fleet(unittest.TestCase):
    """nas: / on ext4, /mnt/pool on btrfs with photos/, /mnt/backup on ext4. pc: / and an empty /mnt/share, and
    /mnt/media already an NFS mount from elsewhere."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='sftask-')
        self.db = dbfactory.make(self, f'{self.tmp}/t.db')
        self.conn = self.db.connect()
        self.db.migrate(self.conn)
        mounts = {'nas': (('/', '/dev/sda1', 'ext4'), ('/mnt/pool', '/dev/sdb1[/@pool]', 'btrfs'),
                          ('/mnt/backup', '/dev/sdc1', 'ext4')),
                  'pc': (('/', '/dev/nvme0n1p2', 'ext4'), ('/mnt/media', 'other:/media', 'nfs4'))}
        for host, ms in mounts.items():
            self.conn.execute("INSERT INTO hosts (hostname, ssh_host, ssh_user, inventory_json) VALUES (:h, :a, 'scan', '{}')",
                              {'h': host, 'a': '10.0.0.5' if host == 'nas' else '10.0.0.9'})
            hid = self.conn.scalar('SELECT host_id FROM hosts WHERE hostname = :h', {'h': host})
            for mp, src, fs in ms:
                self.conn.execute("INSERT INTO mounts (host_id, mount_point, source, filesystem_type, total_bytes, used_bytes, "
                                  "scan_state, mount_options) VALUES (:h, :m, :s, :f, :t, 1, 'indexed', 'rw')",
                                  {'h': hid, 'm': mp, 's': src, 'f': fs, 't': 10 * 2**40})
        pool = self.conn.scalar("SELECT mount_id FROM mounts WHERE mount_point = '/mnt/pool'")
        root_pc = self.conn.scalar("SELECT m.mount_id FROM mounts m JOIN hosts h USING (host_id) WHERE h.hostname = 'pc' AND m.mount_point = '/'")
        rows = [(pool, '/mnt/pool', 'photos', 1, 0), (pool, '/mnt/pool/photos', 'a.jpg', 0, 2048),
                (pool, '/mnt/pool', 'readme.txt', 0, 10),
                (root_pc, '/', 'mnt', 1, 0), (root_pc, '/mnt', 'share', 1, 0), (root_pc, '/mnt', 'docs', 1, 0),
                (root_pc, '/mnt/docs', 'cv.pdf', 0, 99)]
        for m, parent, name, d, size in rows:
            self.conn.execute("INSERT INTO file_records (mount_id, dir_id, filename, is_directory, file_size_bytes, modified_at) "
                              f"VALUES (:m, :p, :n, :d, :s, {self.db.ts('0')})",
                              {'m': m, 'p': dir_id(self.conn, m, parent), 'n': name, 'd': bool(d), 's': size})

    def tearDown(self):
        self.conn.close()
        shutil.rmtree(self.tmp, ignore_errors=True)


class Browse(Fleet):
    def test_folders_files_and_mounts(self):
        r = fsmap.browse(self.conn, 'nas', '/mnt')
        dirs = {d['name']: d for d in r['dirs']}
        self.assertEqual(dirs['pool']['mount']['fstype'], 'btrfs')
        self.assertEqual(dirs['backup']['mount']['kind'], 'local')
        r = fsmap.browse(self.conn, 'nas', '/mnt/pool')
        self.assertEqual([f['name'] for f in r['files']], ['readme.txt'])
        self.assertEqual(r['here']['mount']['target'], '/mnt/pool')
        self.assertEqual([c['path'] for c in r['crumbs']], ['/', '/mnt', '/mnt/pool'])
        self.assertEqual(r['crumbs'][-1]['mount'], 'local')
        r = fsmap.browse(self.conn, 'pc', '/mnt')
        media = next(d for d in r['dirs'] if d['name'] == 'media')
        self.assertEqual(media['mount']['kind'], 'nfs')
        self.assertEqual(media['mount']['remote'], {'server': 'other', 'path': '/media'})
        with self.assertRaises(LookupError):
            fsmap.browse(self.conn, 'nope', '/')


class ShareChecks(Fleet):
    def levels(self, export, index=None):
        r = shares.validate(self.conn, 'nas', export, index)
        return r, [(x['level'], x['text']) for x in r['items']]

    def has(self, items, level, words):
        return any(lv == level and words in t for lv, t in items)

    def test_good_share(self):
        r, items = self.levels({'protocol': 'NFSv4.2', 'path': '/mnt/pool/photos',
                                'rules': [{'clients': '10.0.0.0/24', 'options': 'rw'}],
                                'mounts': [{'host': 'pc', 'path': '/mnt/photos'}]})
        self.assertEqual(r['crit'], 0, items)
        self.assertTrue(self.has(items, 'ok', 'on /mnt/pool (btrfs'))
        self.assertTrue(self.has(items, 'ok', 'mounts on pc:/mnt/photos'))

    def test_says_what_a_deploy_would_install(self):
        def scanned(host, packages):
            self.conn.execute('UPDATE hosts SET inventory_json = :i WHERE hostname = :h',
                              {'i': json.dumps({'packages': packages}), 'h': host})
        nfs = {'protocol': 'NFS', 'path': '/mnt/pool/photos', 'rules': [{'clients': '10.0.0.0/24', 'options': 'rw'}],
               'mounts': [{'host': 'pc', 'path': '/mnt/photos'}]}
        _, items = self.levels(nfs)                                     # scanned before scans looked
        self.assertTrue(self.has(items, 'note', 'rescan nas to see'))
        scanned('nas', 'pm apt-get\nhave mount.nfs')                    # the client programs are not the server
        scanned('pc', 'pm pacman')
        _, items = self.levels(nfs)
        self.assertTrue(self.has(items, 'note', 'the deploy installs nfs-kernel-server with apt-get'))
        self.assertTrue(self.has(items, 'note', 'the deploy installs nfs-utils with pacman'))
        scanned('nas', 'pm dnf\nhave exportfs')
        scanned('pc', 'pm zypper\nhave mount.nfs')
        r, items = self.levels(nfs)
        self.assertTrue(self.has(items, 'ok', 'NFS server is installed on nas'))
        self.assertTrue(self.has(items, 'ok', 'NFS client is installed on pc'))
        self.assertEqual(r['crit'], 0, items)
        scanned('nas', 'have exportfs')
        r, items = self.levels({'protocol': 'SMB3', 'name': 'photos', 'path': '/mnt/pool/photos', 'clients': 'gabe'})
        self.assertTrue(self.has(items, 'crit', 'no package manager'))

    def test_script_packages_match_the_check(self):
        for what in ('NFS server', 'Samba', 'NFS client', 'SMB client'):
            self.assertIn(scriptkit.need_line(what).strip() + ' ||', shares.SHARES_BODY_3)
        shares.save_export(self.db, self.conn, 'nas', {'protocol': 'NFS', 'path': '/mnt/pool/photos',
                                                       'rules': [{'clients': 'pc', 'options': 'rw'}]}, None, 'test')
        text = shares.script(self.conn, 'nas')
        self.assertIn('install_pkg() {', text)
        self.assertNotIn('@@PACKAGES@@', text)

    def test_jobs_get_rsync_and_rsnapshot(self):
        def scanned(host, packages):
            self.conn.execute('UPDATE hosts SET inventory_json = :i WHERE hostname = :h',
                              {'i': json.dumps({'packages': packages}), 'h': host})

        def plan(method):
            return moves.normalize({'name': 'p', 'steps': [{'id': 1, 'method': method, 'src': {'host': 'pc', 'path': '/mnt/docs'},
                                                            'dst': {'host': 'nas', 'path': '/mnt/backup/docs'}}]})

        def texts(method):
            return [(x['level'], x['text']) for x in moves.check(self.conn, plan(method))['steps'][0]['items']]
        scanned('nas', 'pm dnf\nhave rsync')
        scanned('pc', 'pm apt-get')
        items = texts('rsnapshot')
        self.assertTrue(self.has(items, 'ok', 'rsync is installed on nas'))
        self.assertTrue(self.has(items, 'note', 'rsync is not installed on pc: the deploy installs rsync with apt-get'))
        self.assertTrue(self.has(items, 'note', 'installs rsnapshot with dnf (from EPEL'))
        self.assertFalse(self.has(texts('copy'), 'note', 'rsnapshot'))
        self.assertFalse(self.has(texts('git'), 'note', 'rsync is'))
        p = {**plan('rsnapshot'), 'id': 1}
        sp = jobs.specs(self.conn, p)
        runner, source = jobs.host_script(p, 'nas', sp, [], None), jobs.host_script(p, 'pc', [], sp, None)
        self.assertIn('need_cmd rsnapshot "rsnapshot" rsnapshot', runner)
        self.assertIn('install_pkg() {', runner)
        self.assertIn('need_cmd rsync "rsync" rsync', source)
        self.assertNotIn('need_cmd rsnapshot', source)
        check = subprocess.run(['bash', '-n'], input=runner, text=True, capture_output=True)
        self.assertEqual(check.returncode, 0, check.stderr)

    def test_bad_mount_points_and_paths(self):
        _, items = self.levels({'protocol': 'NFS', 'path': '/mnt/pool/photos', 'rules': [{'clients': '*', 'options': 'rw'}],
                                'mounts': [{'host': 'pc', 'path': '/mnt/media'}, {'host': 'pc', 'path': '/mnt/docs'},
                                           {'host': 'pc', 'path': '/etc'}, {'host': 'ghost', 'path': '/x'}]})
        self.assertTrue(self.has(items, 'crit', 'already mounts other:/media'))
        self.assertTrue(self.has(items, 'warn', 'hidden while the share'))
        self.assertTrue(self.has(items, 'crit', 'system folder'))
        self.assertTrue(self.has(items, 'crit', 'ghost has not been scanned'))
        self.assertTrue(self.has(items, 'warn', 'every host'))
        _, items = self.levels({'protocol': 'NFS', 'path': '/mnt/pool/nothere', 'rules': [{'clients': 'pc', 'options': 'rw,bogus'}]})
        self.assertTrue(self.has(items, 'warn', 'not in the index'))
        self.assertTrue(self.has(items, 'crit', 'unknown NFS export option'))
        _, items = self.levels({'protocol': 'NFS', 'path': '/mnt', 'rules': [{'clients': 'pc', 'options': 'ro'}]})
        self.assertTrue(self.has(items, 'warn', 'separate filesystems'))
        with self.assertRaises(ValueError):
            shares.normalize_export({'protocol': 'NFS', 'path': 'relative'})

    def test_save_then_duplicate_and_clash(self):
        e = {'protocol': 'SMB3', 'name': 'photos', 'path': '/mnt/pool/photos', 'clients': 'gabe',
             'mounts': [{'host': 'pc', 'path': '/mnt/share'}]}
        res = shares.save_export(self.db, self.conn, 'nas', e, None, 'test')
        self.assertEqual(res['export']['name'], 'photos')
        self.assertEqual(shares.check(self.conn, 'nas')['crit'], 0)
        _, items = self.levels({**e, 'path': '/mnt/backup', 'mounts': []})
        self.assertTrue(self.has(items, 'crit', 'already called photos'))
        _, items = self.levels({**e, 'index': None}, res['index'])            # editing itself is no duplicate
        self.assertFalse(self.has(items, 'crit', 'already called'))
        b = fsmap.browse(self.conn, 'pc', '/mnt')
        self.assertEqual(next(d for d in b['dirs'] if d['name'] == 'share')['planned_mounts'][0]['server'], 'nas')
        shares.remove_export(self.db, self.conn, 'nas', res['index'])
        self.assertEqual(shares.design_exports(self.conn, 'nas'), [])


class MoveExtras(Fleet):
    def plan(self):
        return moves.save_plan(self.conn, {'name': 'Media', 'steps': [
            {'method': 'copy', 'src': {'host': 'pc', 'path': '/mnt/share'}, 'dst': {'host': 'nas', 'path': '/mnt/backup/a'}},
            {'method': 'move', 'src': {'host': 'pc', 'path': '/mnt/share'}, 'dst': {'host': 'nas', 'path': '/mnt/backup/b'}}]}, 'test')

    def test_progress_from_a_scan(self):
        pid = self.plan()
        self.assertEqual(moves.get_plan(self.conn, pid)['progress'], [{'copied': None, 'cutover': None}] * 2)
        inv = {'moves': 'media/0.done\t2026-10-30 10:00:00\nmedia/1.done\t2026-10-30 11:00:00\nmedia/1.cutover\t2026-10-31 09:00:00 · source kept\nother/0.done\tx'}
        self.conn.execute("UPDATE hosts SET inventory_json = :i WHERE hostname = 'nas'", {'i': json.dumps(inv)})
        self.assertEqual(moves.get_plan(self.conn, pid)['progress'], [
            {'copied': '2026-10-30 10:00:00', 'cutover': None},
            {'copied': '2026-10-30 11:00:00', 'cutover': '2026-10-31 09:00:00 · source kept'}])

    def test_copy(self):
        pid = self.plan()
        first = moves.copy_plan(self.conn, pid, 'test')
        second = moves.copy_plan(self.conn, pid, 'test')
        self.assertEqual(moves.get_plan(self.conn, first)['name'], 'Media (copy)')
        self.assertEqual(moves.get_plan(self.conn, second)['name'], 'Media (copy 2)')
        self.assertEqual(len(moves.get_plan(self.conn, second)['steps']), 2)

    def test_git_ignore(self):
        from storageforge_index import gitrepos
        self.assertTrue(gitrepos.is_noise('/home/a/.cache/x'))
        self.assertFalse(gitrepos.is_noise('/home/a/.cache/x', ['!/.cache/x']))
        self.assertTrue(gitrepos.is_noise('/scratch/x', ['/scratch/']))
        hid = self.conn.scalar("SELECT host_id FROM hosts WHERE hostname = 'nas'")
        self.conn.execute("INSERT INTO git_repos (host_id, path, bare, refs) VALUES (:h, '/scratch/x', 0, 1)", {'h': hid})
        self.assertEqual(len(gitrepos.listing(self.conn)['repos']), 1)
        gitrepos.save_ignore(self.conn, 'nas', ['/scratch/'], 'test')
        got = gitrepos.listing(self.conn)
        self.assertEqual((got['repos'], got['hidden']), ([], 1))
        gitrepos.save_ignore(self.conn, 'nas', [], 'test')
        self.assertEqual(len(gitrepos.listing(self.conn)['repos']), 1)


class DeployedProtection(Fleet):
    ROWS = [{'node': 'a', 'dataset': 'pool', 'path': '/mnt/pool', 'sync': {'state': 'None'},
             'snapshots': {'enabled': False}, 'backup': {'target': 'typed', 'enc': 'gpg', 'ratio': 2, 'last': '2020-01-01', 'offsite': False}},
            {'node': 'b', 'dataset': 'root', 'path': '/', 'sync': {'state': 'None'}, 'snapshots': {'enabled': False}, 'backup': {'target': 'by hand'}}]

    def job(self, **kw):
        return {'id': 'j1', 'name': 'Photos', 'method': 'rsnapshot', 'runner': 'pc', 'source': 'nas', 'src': '/mnt/pool/photos', 'dst': '/mnt/share/p',
                'schedule': 'daily', 'state': 'ok', 'last_ok': {'end': 1793000000}, **kw}

    def overlay(self, *jobs_):
        from unittest import mock
        from storageforge_index import protection
        with mock.patch('storageforge_index.jobs.overview', return_value=list(jobs_)):
            return protection.overlay(self.conn, 'nas', self.ROWS)

    def test_a_job_fills_its_dataset_and_a_typed_row_stays(self):
        import datetime as dt
        pool, root = self.overlay(self.job())
        self.assertEqual(pool['backup']['target'], 'pc:/mnt/share/p')
        self.assertEqual(pool['backup']['last'], dt.date.fromtimestamp(1793000000).isoformat())
        self.assertEqual((pool['backup']['enc'], pool['backup']['offsite']), ('gpg', False))
        self.assertEqual(pool['deployed'], ['job Photos'])
        self.assertEqual(root, self.ROWS[1])

    def test_offsite_and_removed_jobs(self):
        from storageforge_index import protection
        protection.set_offsite(self.conn, 'pc', True, 'test')
        pool = self.overlay(self.job())[0]
        self.assertTrue(pool['backup']['offsite'])
        protection.set_offsite(self.conn, 'pc', False, 'test')
        from unittest import mock
        with mock.patch('storageforge_index.jobs.overview', return_value=[]):      # saved with the job's values, then it went away
            again = protection.overlay(self.conn, 'nas', [pool])
        self.assertEqual(again[0]['backup'], self.ROWS[0]['backup'])
        self.assertNotIn('deployed', again[0])

    def test_a_failing_mirror_is_lagging(self):
        pool = self.overlay(self.job(method='mirror', state='failed', last_ok=None))[0]
        self.assertEqual((pool['sync']['state'], pool['sync']['lag']), ('Lagging', 'last run failed'))
        self.assertIsNone(pool['backup']['last'])

    def test_other_hosts_jobs_do_not_count(self):
        self.assertEqual(self.overlay(self.job(source='other')), self.ROWS)

    def test_a_scheduled_task_counts(self):
        from storageforge_index import protection
        task = {'name': 'Snaps', 'host': 'nas', 'schedule': 'hourly', 'blocks': [
            {'type': 'btrfs_snapshot', 'params': {'subvol': '/mnt/pool'}},
            {'type': 'rsync', 'params': {'src': '/mnt/pool/photos', 'dst': '/mnt/share/x', 'dst_host': 'pc'}}]}
        tasks.save_task(self.conn, task, 'test')
        self.conn.execute("""INSERT INTO deployed (host, kind, ref, deploy_hash, deployed_at, deployed_by, detail_json)
                             VALUES ('nas', 'tasks', 'snaps', 'x', 1, 't', '{}')""")
        self.conn.execute("INSERT INTO task_runs (host, task, started_at, finished_at, exit_code, via, received_at) VALUES ('nas', 'snaps', 1793000000, 1793000100, 0, 'scan', 1793000100)")
        pool = protection.overlay(self.conn, 'nas', self.ROWS)[0]
        self.assertEqual(pool['snapshots']['tool'], 'btrfs')
        self.assertEqual(pool['backup']['target'], 'pc:/mnt/share/x')
        self.assertIsNotNone(pool['backup']['last'])


class Retire(Fleet):
    def test_a_retired_host_leaves_everything(self):
        from storageforge_index import retire
        hit = lambda: self.conn.scalar("SELECT count(*) FROM file_fts WHERE filename LIKE '%readme%'")   # noqa: E731
        if self.db.dialect == 'sqlite':       # as apply_diff does for a real scan
            self.conn.execute('INSERT INTO file_fts (rowid, filename) SELECT file_id, filename FROM file_records')
        before = hit() if self.db.dialect == 'sqlite' else 0
        self.conn.execute("INSERT INTO scan_jobs (host, requested_by, queued_at, status) VALUES ('nas', 't', 1, 'ok')")
        self.conn.execute("INSERT INTO graph_nodes (node_id, kind, label, host, updated_at) VALUES ('host:nas', 'Host', 'nas', 'nas', 1)")
        self.conn.execute("INSERT INTO blueprints (hostname, body_json, imported_at) VALUES ('nas', '{}', 1)")
        retire.retire(self.conn, 'nas')
        for sql in ("SELECT count(*) FROM hosts WHERE hostname = 'nas'", "SELECT count(*) FROM scan_jobs",
                    "SELECT count(*) FROM graph_nodes WHERE host = 'nas'", "SELECT count(*) FROM blueprints"):
            self.assertEqual(self.conn.scalar(sql), 0, sql)
        self.assertEqual(self.conn.scalar("SELECT count(*) FROM mounts m LEFT JOIN hosts h ON h.host_id = m.host_id WHERE h.host_id IS NULL"), 0)
        if self.db.dialect == 'sqlite':
            self.assertGreater(before, 0)
            self.assertEqual(hit(), 0)
        self.assertEqual(self.conn.scalar("SELECT count(*) FROM hosts WHERE hostname = 'pc'"), 1)

    def test_refused_while_in_use_or_unknown(self):
        from storageforge_index import retire
        self.conn.execute("""INSERT INTO deployed (host, kind, ref, deploy_hash, deployed_at, detail_json) VALUES ('nas', 'tasks', 'x', 'h', 1, '{}')""")
        with self.assertRaisesRegex(ValueError, 'tasks x is deployed'):
            retire.retire(self.conn, 'nas')
        with self.assertRaises(LookupError):
            retire.retire(self.conn, 'nope')


class History(Fleet):
    def test_forecast(self):
        from storageforge_index.capacity import forecast
        day, g = 86400, 2**30
        self.assertEqual(forecast([(i * day, (100 + 10 * i) * g) for i in range(10)], 1000 * g), 81)     # 190 GiB used, 10 a day
        self.assertIsNone(forecast([(i * day, 100 * g) for i in range(10)], 1000 * g))                   # flat
        self.assertIsNone(forecast([(i * day, (100 - i) * g) for i in range(10)], 1000 * g))             # shrinking
        self.assertIsNone(forecast([(0, g), (3600, 2 * g)], 1000 * g))                                   # under a day of history
        self.assertEqual(forecast([(0, 100 * g), (day, 2000 * g)], 1000 * g), 0)                         # already over

    def test_a_scan_records_usage_and_old_rows_thin_out(self):
        from storageforge_index.capacity import trends
        hid = self.conn.scalar("SELECT host_id FROM hosts WHERE hostname = 'nas'")
        self.conn.execute("UPDATE mounts SET total_bytes = 1000, used_bytes = 10 WHERE host_id = :h", {'h': hid})
        sid = self.db.begin_scan(self.conn, hid)
        self.db.finish_scan(self.conn, sid, hid, dict(entries=0, bytes=0, added=0, modified=0, deleted=0, read_errors=0), 'ok', 1)
        got = trends(self.conn, 'nas')
        self.assertTrue(got and got[0]['used'] == 10)
        old = int(time.time()) - 200 * 86400
        day_start = old - old % 86400
        for i in range(3):
            self.conn.execute("INSERT INTO mount_usage (host_id, mount_point, at, used_bytes, total_bytes) VALUES (:h, '/old', :t, 1, 2)", {'h': hid, 't': day_start + i})
        self.db.prune(self.conn)
        self.assertEqual(self.conn.scalar("SELECT count(*) FROM mount_usage WHERE mount_point = '/old'"), 1)

    def test_the_report_names_every_job_and_alert(self):
        from unittest import mock
        from storageforge_index import reportextra
        job = {'name': 'photos-nightly', 'method': 'mirror', 'source': 'nas', 'runner': 'pc', 'state': 'ok', 'last': {'end': 1793000000}, 'last_ok': {'end': 1793000000}}
        self.conn.execute("""INSERT INTO alerts (alert_key, kind, ref, title, state, first_at, last_at) VALUES ('k', 'x', 'y', 'Disk on fire', 'open', 1, 1)""")
        with mock.patch('storageforge_index.jobs.overview', return_value=[job]):
            text = '\n'.join(reportextra.sections(self.conn, []))
        self.assertIn('photos-nightly', text)
        self.assertIn('Disk on fire', text)
        self.assertNotIn('could not be built', text)


class Health(Fleet):
    SMART = json.dumps({'smart_status': {'passed': True}, 'temperature': {'current': 34}, 'power_on_time': {'hours': 900},
                        'ata_smart_attributes': {'table': [{'id': 5, 'raw': {'value': 8}}, {'id': 197, 'raw': {'value': 0}}]}})
    REPORT = f"""## at
1793000000
## smart sda
{SMART}
## smart sdb
{{"smart_status": {{"passed": false}}}}
## smart sdc

## stats /mnt/pool
[/dev/sdb1].write_io_errs    3
[/dev/sdb1].read_io_errs     0
## scrub /mnt/pool
Scrub started:    Sun Oct  4 01:00:00 2026
Status:           finished
Error summary:    no errors found
## snaps /mnt/pool
12
"""

    def test_the_report_parses(self):
        from storageforge_index import health
        r = health.parse_report(self.REPORT)
        self.assertEqual(r['at'], 1793000000)
        self.assertEqual((r['disks']['sda']['smart'], r['disks']['sda']['reallocated'], r['disks']['sda']['temp']), ('warn', 8, 34))
        self.assertEqual(r['disks']['sdb']['smart'], 'fail')
        self.assertNotIn('sdc', r['disks'])
        self.assertEqual(r['btrfs']['/mnt/pool'], {'errors': 3, 'last_scrub': 'Sun Oct  4 01:00:00 2026', 'scrub_errors': 0, 'snapshots': 12})
        self.assertIsNone(health.parse_report(''))

    def test_problems(self):
        from storageforge_index import health
        import datetime as dt
        r = health.parse_report(self.REPORT)
        node = {'hostname': 'nas', 'disks': [{'dev': 'sda'}, {'dev': 'sdb'}], 'mounts': [{'target': '/mnt/pool', 'source': '/dev/sdb1'}],
                'pools': [{'name': 'pool', 'type': 'btrfs', 'members': ['sdb1']},
                          {'name': 'tank', 'type': 'zfs', 'scan': 'scrub repaired 0B in 01:00:00 with 0 errors on Sun Jan  4 01:00:00 2026'}]}
        health.apply_report(node, r)
        self.assertEqual(node['pools'][0]['last_scrub'], '2026-10-04')
        self.assertEqual(node['pools'][1]['last_scrub'], '2026-01-04')
        got = {k: (lv, t) for lv, k, t, _ in health.problems(node, dt.date(2026, 10, 20))}
        self.assertEqual(got['smart:sda'][0], 'warn')
        self.assertEqual(got['smart:sdb'][0], 'crit')
        self.assertEqual(got['pool-errors:pool'][0], 'crit')
        self.assertIn('scrub:tank', got)
        self.assertNotIn('scrub:pool', got)

    def test_the_setup_script_is_valid_and_grants_nothing_new(self):
        from storageforge_index import access
        text = access.setup_script('scanner')
        self.assertNotIn('sudoers', text)
        self.assertIn('sf-health.timer', text)
        self.assertEqual(subprocess.run(['sh', '-n'], input=text, text=True).returncode, 0)
        self.assertEqual(subprocess.run(['sh', '-n'], input=access.remove_script('scanner'), text=True).returncode, 0)
        self.assertIn('rm -rf /var/lib/storageforge/health', access.remove_script('scanner'))

    def test_detected_backups_and_snapshots(self):
        from storageforge_index import protection
        m = self.conn.scalar("SELECT m.mount_id FROM mounts m JOIN hosts h ON h.host_id = m.host_id WHERE h.hostname = 'nas' AND m.mount_point = '/mnt/backup'")
        repo = dir_id(self.conn, m, '/mnt/backup/restic')
        for n in ('keys', 'snapshots', 'index', 'data', 'config'):
            self.conn.execute(f"INSERT INTO file_records (mount_id, dir_id, filename, is_directory, file_size_bytes, modified_at) VALUES (:m, :d, :n, false, 1, {self.db.ts('1793000000')})", {'m': m, 'd': repo, 'n': n})
        self.conn.execute("UPDATE hosts SET inventory_json = :i WHERE hostname = 'nas'", {'i': json.dumps({'snapshots': {'zfs': {'tank/media': {'count': 9, 'newest': 1793000000}}}})})
        rows = [{'node': 'a', 'dataset': 'pool', 'path': '/mnt/pool', 'sync': {'state': 'None'}, 'snapshots': {'enabled': False}, 'backup': {}},
                {'node': 'b', 'dataset': 'backup', 'path': '/mnt/backup', 'sync': {'state': 'None'}, 'snapshots': {'enabled': False}, 'backup': {}},
                {'node': 'ds:tank/media', 'dataset': 'tank/media', 'path': '/srv/media', 'sync': {'state': 'None'}, 'snapshots': {'enabled': False}, 'backup': {'target': 'typed'}}]
        pool, backup, media = protection.overlay(self.conn, 'nas', rows)
        self.assertIn('restic /mnt/backup/restic', pool['backup']['target'])
        self.assertFalse(pool['backup']['offsite'])
        self.assertFalse(backup['backup'].get('target'))                       # a repo doesn't back up the disk it is on
        self.assertEqual(media['backup']['target'], 'typed')                   # what is typed stays
        self.assertEqual((media['snapshots']['tool'], media['snapshots']['count']), ('zfs', 9))


class Tasks(Fleet):
    def task(self, *blocks, **kw):
        return {'name': kw.pop('name', 'Nightly'), 'host': 'nas', 'schedule': kw.pop('schedule', 'hourly'), 'blocks': list(blocks), **kw}

    def test_running_containers_are_warned_about(self):
        hid = self.conn.scalar("SELECT host_id FROM hosts WHERE hostname = 'nas'")
        c = {'name': 'immich', 'labels': {}, 'state': 'running', 'mounts': [{'type': 'bind', 'source': '/mnt/pool/photos', 'rw': True}]}
        self.conn.execute("""INSERT INTO docker_hosts (host_id, engine, access, root_dir, containers_json, volumes_json, compose_json)
                             VALUES (:h, 'docker', 'direct', '/var/lib/docker', :c, '[]', '[]')""", {'h': hid, 'c': json.dumps([c])})
        block = {'type': 'rsync', 'params': {'src': '/mnt/pool/photos', 'dst': '/mnt/backup/photos'}}
        got = [x['text'] for x in tasks.check(self.conn, self.task(block))['blocks'][0]['items'] if x['level'] == 'warn']
        self.assertTrue(any('running container(s) use the source: immich' in x for x in got), got)
        block['params']['src'] = '/mnt/pool/other'
        got = [x['text'] for x in tasks.check(self.conn, self.task(block))['blocks'][0]['items']]
        self.assertFalse(any('running container' in x for x in got), got)

    def test_cli(self):
        import contextlib
        import io
        from storageforge_index import cli
        path = Path(self.tmp) / 'task.json'
        path.write_text(json.dumps(self.task({'type': 'mkdir', 'params': {'path': '/mnt/backup/x'}})))
        base = ['--db', self.db.url, 'tasks']

        def run(*a):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                rc = cli.main([*base, *a])
            return rc, out.getvalue()
        self.assertIn('saved storage task #', run('import', str(path))[1])
        self.assertIn('Nightly', run('list')[1])
        tid = tasks.list_tasks(self.conn)[0]['id']
        self.assertEqual(run('check', str(tid))[0] or 0, 0)
        self.assertIn('#!/', run('script', str(tid))[1])

    def test_checks_suggest_guards(self):
        t = self.task({'type': 'rsync', 'params': {'src': '/mnt/pool/photos', 'dst': '/mnt/backup/photos', 'mode': 'mirror'}})
        c = tasks.check(self.conn, t)
        items = c['blocks'][0]['items']
        fixes = [x['fix']['params']['path'] for x in items if x.get('fix')]
        self.assertEqual(sorted(fixes), ['/mnt/backup', '/mnt/pool'])
        guarded = self.task({'type': 'require_mounted', 'params': {'path': '/mnt/backup'}},
                            {'type': 'if', 'params': {'cond': 'mounted', 'arg': '/mnt/pool'},
                             'slots': {'then': [{'type': 'rsync', 'params': {'src': '/mnt/pool/photos', 'dst': '/mnt/backup/p',
                                                                              'mode': 'mirror'}}]}})
        c = tasks.check(self.conn, guarded)
        self.assertFalse([x for b in c['blocks'] for x in b['items'] if x.get('fix')])
        self.assertEqual(c['blocks'][2]['path'], [1, 'then', 0])
        c = tasks.check(self.conn, self.task({'type': 'btrfs_snapshot', 'params': {'subvol': '/mnt/backup'}},
                                             {'type': 'rsync', 'params': {'src': '/mnt/pool', 'dst': '/mnt/pool/x'}}))
        self.assertTrue(any('not btrfs' in x['text'] for x in c['blocks'][0]['items']))
        self.assertTrue(any('overlap' in x['text'] for x in c['blocks'][1]['items']))

    def test_shares_apply_with_steps_left_is_not_marked_deployed(self):
        from storageforge_index import deploy
        shares.save_export(self.db, self.conn, 'nas', {'protocol': 'NFS', 'path': '/mnt/pool/photos', 'clients': '10.0.0.0/24'}, None, 'test')
        hook = shares.deploy_items(self.db, self.conn, 'nas', 'apply', 'test')[0]['on_ok']
        hook({'status': 'incomplete'})
        self.assertEqual(deploy.deployed(self.conn, kind='shares'), [])
        hook({'status': 'ok'})
        self.assertEqual(len(deploy.deployed(self.conn, kind='shares')), 1)

    def test_normalize_refuses_bad_input(self):
        for bad in ({'type': 'nope'}, {'type': 'rsync', 'params': {'src': 'rel', 'dst': '/x'}},
                    {'type': 'zfs_snapshot', 'params': {'dataset': 'tank; rm -rf /'}},
                    {'type': 'rsync', 'params': {'src_host': 'pc', 'dst_host': 'nas', 'src': '/a', 'dst': '/b'}}):
            with self.assertRaises(ValueError):
                tasks.normalize(self.task(bad))
        with self.assertRaises(ValueError):
            tasks.normalize(self.task(schedule='daily\nExecStart=/bin/sh'))
        deep = {'type': 'log', 'params': {'message': 'x'}}
        for _ in range(8):
            deep = {'type': 'try', 'slots': {'do': [deep]}}
        with self.assertRaises(ValueError):
            tasks.normalize(self.task(deep))

    def test_templates_compile(self):
        fill = {'path': '/mnt/pool', 'src': '/mnt/pool/photos', 'dst': '/mnt/backup/p', 'subvol': '/mnt/pool', 'into': '/mnt/pool/.s',
                'dataset': 'tank/x', 'project': 'immich', 'host': 'pc', 'arg': '/mnt/pool'}

        def filled(blocks):
            return [{**b, 'params': {k: v or fill.get(k, v) for k, v in b['params'].items()},
                     'slots': {s: filled(k) for s, k in (b.get('slots') or {}).items()}} for b in blocks]
        for t in tasks.TEMPLATES:
            with self.assertRaises(ValueError):           # templates come with blanks to fill in
                tasks.script(self.conn, {'name': t['name'], 'host': 'nas', 'blocks': t['blocks']})
            text = tasks.script(self.conn, {'name': t['name'], 'host': 'nas', 'schedule': t['schedule'], 'blocks': filled(t['blocks'])})
            sh = Path(self.tmp) / 'x.sh'
            sh.write_text(text)
            self.assertEqual(subprocess.run(['bash', '-n', str(sh)], capture_output=True).returncode, 0, t['name'])

    def test_storage_and_remote_side(self):
        t = self.task({'type': 'rotate', 'params': {'src_host': 'pc', 'src': '/home', 'dst': '/mnt/backup/pc', 'keep': 3}})
        tid = tasks.save_task(self.conn, t, 'test')
        self.assertEqual(tasks.list_tasks(self.conn)[0]['blocks'], 1)
        with self.assertRaises(ValueError):
            tasks.save_task(self.conn, {**t, 'name': 'nightly'}, 'test')
        text = tasks.script(self.conn, tasks.get_task(self.conn, tid))
        self.assertIn("scan@10.0.0.9:/home/", text)
        self.assertIn("'--rsync-path=sudo rsync'", text)
        items = tasks.deploy_items(self.db, self.conn, tasks.get_task(self.conn, tid), 'apply', 'test')
        self.assertEqual([(i['host'], i['args']) for i in items], [('nas', ['--install'])])
        self.assertEqual(tasks.deploy_items(self.db, self.conn, t, 'report', 'test', run_now=True)[0]['args'], ['--run'])


@unittest.skipUnless(subprocess.run(['which', 'rsync'], capture_output=True).returncode == 0, 'needs rsync')
@unittest.skipIf(os.geteuid() == 0, 'as root the task script ignores the test paths and uses /var/lib/storageforge')
class TaskRuns(Fleet):
    """Run generated scripts for real on a temporary tree (not as root: STORAGEFORGE_TASK_STATE)."""

    def run_task(self, blocks, mode='--run', on_fail=()):
        text = tasks.script(self.conn, {'name': 'T', 'host': '', 'blocks': blocks, 'on_fail': list(on_fail)})
        sh = Path(self.tmp) / 't.sh'
        sh.write_text(text)
        env = {**os.environ, 'STORAGEFORGE_TASK_STATE': f'{self.tmp}/state'}
        return subprocess.run(['bash', str(sh)] + ([mode] if mode else []), capture_output=True, text=True, env=env, timeout=60)

    def test_copy_rotate_conditions_and_failure(self):
        src, dst = Path(self.tmp) / 'src', Path(self.tmp) / 'dst'
        (src / 'sub').mkdir(parents=True)
        (src / 'sub' / 'f.txt').write_text('hello')
        copy = {'type': 'rsync', 'params': {'src': str(src), 'dst': str(dst / 'copy'), 'one_fs': False}}
        r = self.run_task([copy], mode='')                                     # the report changes nothing
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn('would run: rsync', r.stdout)
        self.assertFalse(dst.exists())
        r = self.run_task([copy, {'type': 'rotate', 'params': {'src': str(src), 'dst': str(dst / 'snaps'), 'keep': 2, 'one_fs': False}}])
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual((dst / 'copy' / 'sub' / 'f.txt').read_text(), 'hello')
        snaps = list((dst / 'snaps').iterdir())
        self.assertEqual(len(snaps), 1)
        self.assertEqual((snaps[0] / 'sub' / 'f.txt').read_text(), 'hello')
        r = self.run_task([
            {'type': 'if', 'params': {'cond': 'exists', 'arg': str(Path(self.tmp) / 'missing')},
             'slots': {'then': [{'type': 'command', 'params': {'cmd': 'echo THEN'}}],
                       'else': [{'type': 'command', 'params': {'cmd': 'echo ELSE'}}]}},
            {'type': 'try', 'slots': {'do': [{'type': 'command', 'params': {'cmd': 'exit 3'}}],
                                      'fallback': [{'type': 'command', 'params': {'cmd': 'echo FALLBACK'}}]}},
            {'type': 'require_mounted', 'params': {'path': str(src)}},
            {'type': 'command', 'params': {'cmd': 'echo NEVER'}}],
            on_fail=[{'type': 'command', 'params': {'cmd': 'echo ONFAIL'}}])
        self.assertEqual(r.returncode, 1)
        out = r.stdout
        self.assertTrue('ELSE' in out and 'THEN' not in out.replace('then', '').split('ELSE')[0].split('echo')[-1])
        self.assertIn('FALLBACK', out)
        self.assertIn('not met', out)
        self.assertNotIn('\nNEVER', out)
        self.assertIn('ONFAIL', out)
        last = json.loads((Path(self.tmp) / 'state' / 't.last').read_text())
        self.assertEqual(last['rc'], 1)
        r = self.run_task([{'type': 'stop', 'params': {'outcome': 'ok', 'message': 'done early'}},
                           {'type': 'command', 'params': {'cmd': 'echo NEVER'}}])
        self.assertEqual(r.returncode, 0)
        self.assertNotIn('\nNEVER', r.stdout)


    def test_deployed_task_runs_as_its_own_executable(self):
        """A deploy installs $0 (the signed script, runner refresh first) as the unit's ExecStart: systemd execs it
        directly, so it must start with #! (GM-03)."""
        from storageforge_index import deploy
        text = tasks.script(self.conn, {'name': 'T', 'host': '', 'blocks': [
            {'type': 'command', 'params': {'cmd': 'echo FROM-SYSTEMD'}}]})
        sh = Path(self.tmp) / 'installed.sh'
        sh.write_text(deploy.RUNNER_UPDATE + text)
        sh.chmod(0o750)
        r = subprocess.run([str(sh), '--run'], capture_output=True, text=True, timeout=60,
                           env={**os.environ, 'STORAGEFORGE_TASK_STATE': f'{self.tmp}/state'})
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn('FROM-SYSTEMD', r.stdout)

if __name__ == '__main__':
    unittest.main()
