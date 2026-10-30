"""Storage tasks (blocks → Bash), the share wizard's checks and the file system browser.
Run with: python3 -m unittest discover -s tests -v"""
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from storageforge_index import fsmap, shares, tasks
from storageforge_index.db import Database, dir_id


class Fleet(unittest.TestCase):
    """nas: / on ext4, /mnt/pool on btrfs with photos/, /mnt/backup on ext4. pc: / and an empty /mnt/share, and
    /mnt/media already an NFS mount from elsewhere."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='sftask-')
        self.db = Database(f'{self.tmp}/t.db')
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
                              "VALUES (:m, :p, :n, :d, :s, 0)", {'m': m, 'p': dir_id(self.conn, m, parent), 'n': name, 'd': d, 's': size})

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


class Tasks(Fleet):
    def task(self, *blocks, **kw):
        return {'name': kw.pop('name', 'Nightly'), 'host': 'nas', 'schedule': kw.pop('schedule', 'hourly'), 'blocks': list(blocks), **kw}

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


if __name__ == '__main__':
    unittest.main()
