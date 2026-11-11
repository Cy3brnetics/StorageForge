"""Graph view file map: duplicate sets, ignore rules, and broken-link flags that respect them.
Run with: python3 -m unittest discover -s tests -v"""
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
from storageforge_index import filemap, folders, fsmap, graph, moves


class FileMap(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db = dbfactory.make(self, Path(self.tmp) / 'index.db')
        self.conn = self.db.connect()
        self.db.migrate(self.conn)
        self.mounts = {}

    def tearDown(self):
        self.conn.close()
        shutil.rmtree(self.tmp)

    def file(self, host, path, sha, size=5 << 20, mount='/'):
        c = self.conn
        if not c.scalar('SELECT 1 FROM hosts WHERE hostname = :h', {'h': host}):
            c.execute("INSERT INTO hosts (hostname) VALUES (:h)", {'h': host})
        key = (host, mount)
        if key not in self.mounts:
            hid = c.scalar('SELECT host_id FROM hosts WHERE hostname = :h', {'h': host})
            c.execute("INSERT INTO mounts (host_id, mount_point, filesystem_type, scan_state) VALUES (:i, :m, 'ext4', 'indexed')", {'i': hid, 'm': mount})
            self.mounts[key] = c.scalar('SELECT mount_id FROM mounts WHERE host_id = :i AND mount_point = :m', {'i': hid, 'm': mount})
        mid = self.mounts[key]
        parent, name = path.rsplit('/', 1)
        parent = parent or '/'
        if not c.scalar('SELECT 1 FROM directories WHERE mount_id = :m AND path = :p', {'m': mid, 'p': parent}):
            c.execute('INSERT INTO directories (mount_id, path) VALUES (:m, :p)', {'m': mid, 'p': parent})
        did = c.scalar('SELECT dir_id FROM directories WHERE mount_id = :m AND path = :p', {'m': mid, 'p': parent})
        c.execute(f"""INSERT INTO file_records (mount_id, dir_id, filename, file_size_bytes, modified_at, checksum_hash)
                      VALUES (:m, :d, :n, :s, {self.db.ts(':t')}, :c)""", {'m': mid, 'd': did, 'n': name, 's': size, 't': int(time.time()), 'c': sha})

    def test_ignore_rules(self):
        lists = {'*': ['Thumbs.db'], 'nas': ['/srv/junk', '!/usr/local/keep']}
        self.assertTrue(folders.is_ignored('nas', '/srv/junk/a', lists))
        self.assertFalse(folders.is_ignored('nas', '/srv/junkyard', lists))
        self.assertFalse(folders.is_ignored('pc', '/srv/junk/a', lists))
        self.assertTrue(folders.is_ignored('pc', '/data/Thumbs.db', lists))
        self.assertTrue(folders.is_ignored('nas', '/usr/lib/x', lists))
        self.assertFalse(folders.is_ignored('nas', '/usr/local/keep/x', lists))
        self.assertFalse(folders.is_ignored('nas', '/usr/lib/x', lists, system=False))
        self.assertTrue(folders.is_ignored('nas', '/data/.storageforge-trash/2026-01-01/x', lists))
        self.assertTrue(folders.is_ignored('nas', '/mnt/ssd/rsnapshot/daily.0/localhost/data/x', lists))
        self.assertTrue(folders.is_ignored('nas', '/mnt/ssd/docker/overlay2/abc/etc/mtab', lists))
        self.assertTrue(folders.is_ignored('nas', '/mnt/c/io.containerd.snapshotter.v1.overlayfs/snapshots/1/fs/x', lists))
        self.assertFalse(folders.is_ignored('nas', '/data/daily.notes/x', lists))

    def test_system_copies_are_hidden_and_folders_joined(self):
        self.file('nas', '/data/a/x.iso', 'aa')
        self.file('nas', '/data/b/x.iso', 'aa')
        self.file('nas', '/usr/lib/one.so', 'bb')
        self.file('nas', '/usr/lib64/one.so', 'bb')
        self.file('nas', '/opt/app-a/two.so', 'cc')
        self.file('nas', '/opt/app-b/two.so', 'cc')
        m = filemap.build(self.conn, None, 1 << 20)
        self.assertEqual([g['sha256'] for g in m['groups']], ['aa'])
        self.assertEqual(m['hidden']['groups'], 2)
        self.assertEqual(m['reclaimable'], 5 << 20)
        self.assertEqual({f['path'] for f in m['folders']}, {'/data/a', '/data/b'})
        self.assertEqual(len(m['links']), 1)
        self.assertEqual(m['links'][0]['scope'], 'same host')
        self.assertEqual(len(filemap.build(self.conn, None, 1 << 20, system=True)['groups']), 3)

    def test_a_host_filter_still_finds_the_copy_on_another_host(self):
        """Bug report 2026-11-10: with a host picked, the count ran on that host alone, so a file whose only copy was elsewhere
        was no duplicate at all."""
        from storageforge_index.search import run_dupes
        self.file('nas', '/data/x.iso', 'aa')
        self.file('pc', '/backup/x.iso', 'aa')
        self.file('pc', '/other/y.iso', 'bb')
        self.file('tv', '/other/y.iso', 'bb')
        for host in (None, 'nas', 'pc'):
            groups, _ = filemap.file_groups(self.conn, host, 1 << 20, {}, False)
            self.assertIn('aa', [g['sha256'] for g in groups], host)
        groups, _ = filemap.file_groups(self.conn, 'nas', 1 << 20, {}, False)
        self.assertEqual([(g['sha256'], g['scope'], sorted(c['host'] for c in g['copies'])) for g in groups], [('aa', 'across hosts', ['nas', 'pc'])])
        self.assertEqual([(g['sha256'], g['files']) for g in run_dupes(self.conn, 'nas', 1 << 20, 10)], [('aa', ['nas:/data/x.iso', 'pc:/backup/x.iso'])])
        self.assertEqual(sorted(g['sha256'] for g in run_dupes(self.conn, 'pc', 1 << 20, 10)), ['aa', 'bb'])

    def folder_of(self, host, root, n=3, sha=None):
        for i in range(n):
            self.file(host, f'{root}/f{i}.bin', sha, size=(i + 1) << 20)

    def test_folder_copies_across_hosts_are_not_crowded_out(self):
        """The live fleet had 313 same-host folder copies and 46 across hosts, sorted same-host first and cut at 100 (200 in the
        graph): not one across hosts showed."""
        for i in range(5):
            self.folder_of('nas', f'/a/set{i}', n=3 + i)
            self.folder_of('nas', f'/b/set{i}', n=3 + i)
        self.folder_of('nas', '/music/band', n=9)
        self.folder_of('pc', '/media/band', n=9)
        r = folders.duplicate_folders(self.conn, None, limit=2)
        self.assertEqual((r['same_host_groups'], r['across_hosts_groups']), (5, 1))
        self.assertEqual([g['scope'] for g in r['groups']], ['same host', 'same host', 'across hosts'])
        mine = folders.duplicate_folders(self.conn, 'pc', limit=2)          # the host's copy, with the one it matches elsewhere
        self.assertEqual([sorted((c['host'], c['path']) for c in g['copies']) for g in mine['groups']],
                         [[('nas', '/music/band'), ('pc', '/media/band')]])

    def test_checksum_catch_up_picks_the_copies_the_first_pass_could_not_see(self):
        """nas was hashed before the file was copied to pc: then it had no twin, so nas's copy was never hashed."""
        self.file('nas', '/data/x.iso', None, size=7 << 20)
        self.file('nas', '/data/lonely.iso', None, size=9 << 20)
        self.file('pc', '/in/x.iso', 'aa', size=7 << 20)
        hid = lambda h: self.conn.scalar('SELECT host_id FROM hosts WHERE hostname = :h', {'h': h})  # noqa: E731
        self.assertEqual([h for _, h in self.db.checksum_catchup_hosts(self.conn, hid('pc'), 1 << 20)], ['nas'])
        self.assertEqual([r[2] for r in self.db.checksum_candidates(self.conn, hid('nas'), 1 << 20, like_host=hid('pc'))], ['x.iso'])
        self.assertEqual(self.db.checksum_catchup_hosts(self.conn, hid('nas'), 1 << 20), [])      # nothing hashed on nas yet

    def test_copy_on_another_host_counts_as_backup_not_waste(self):
        self.file('nas', '/data/x.iso', 'aa')
        self.file('pc', '/data/x.iso', 'aa')
        m = filemap.build(self.conn, None, 1 << 20)
        self.assertEqual(m['reclaimable'], 0)
        self.assertEqual(m['links'][0]['scope'], 'across hosts')

    def test_user_ignore_hides_a_folder(self):
        self.file('nas', '/data/a/x.iso', 'aa')
        self.file('nas', '/data/b/x.iso', 'aa')
        folders.save_ignore(self.conn, 'nas', ['/data/b'], 'test')
        m = filemap.build(self.conn, 'nas', 1 << 20)
        self.assertEqual(m['groups'], [])
        self.assertEqual(m['hidden']['groups'], 1)

    def test_files_inside_a_folder_copy_are_not_listed_twice(self):
        self.file('nas', '/data/a/x.iso', 'aa')
        self.file('nas', '/data/b/x.iso', 'aa')
        twins = {'groups': [{'files': 3, 'bytes': 15 << 20, 'count': 2, 'reclaimable': 15 << 20, 'same_name': False, 'scope': 'same host',
                             'copies': [{'host': 'nas', 'mount': '/', 'path': '/data/a'}, {'host': 'nas', 'mount': '/', 'path': '/data/b'}]}]}
        m = filemap.build(self.conn, None, 1 << 20, twins=twins)
        self.assertEqual(m['groups'], [])
        self.assertEqual(m['reclaimable'], 15 << 20)
        self.assertEqual(m['links'][0]['kind'], 'folder')

    def test_a_file_also_inside_a_folder_copy_is_not_counted_twice(self):
        self.file('nas', '/data/a/x.iso', 'aa')
        self.file('nas', '/data/b/x.iso', 'aa')
        self.file('pc', '/dl/x.iso', 'aa')
        twins = {'groups': [{'files': 1, 'bytes': 5 << 20, 'count': 2, 'reclaimable': 5 << 20, 'same_name': False, 'scope': 'same host',
                             'copies': [{'host': 'nas', 'mount': '/', 'path': '/data/a'}, {'host': 'nas', 'mount': '/', 'path': '/data/b'}]}]}
        m = filemap.build(self.conn, None, 1 << 20, twins=twins)
        self.assertEqual(len(m['groups']), 1)
        self.assertEqual(m['reclaimable'], 5 << 20)
        self.assertEqual({f['path']: f['bytes'] for f in m['folders']}, {'/data/a': 5 << 20, '/data/b': 5 << 20, '/dl': 5 << 20})
        twin = next(l for l in m['links'] if l['kind'] == 'folder')
        self.assertEqual(twin['bytes'], 5 << 20)

    def test_a_copy_step_can_take_chosen_files(self):
        self.file('nas', '/data/a/x.iso', 'aa')
        self.file('nas', '/data/a/y.iso', 'bb', size=1 << 20)
        self.file('nas', '/data/a/skip.iso', 'cc')
        step = {'method': 'copy', 'src': {'host': 'nas', 'path': '/data/a'}, 'dst': {'host': 'nas', 'path': '/data/b'}, 'only': ['x.iso', 'y.iso', 'gone.iso']}
        plan = moves.normalize({'name': 'pick', 'steps': [step]})
        self.assertEqual(plan['steps'][0]['only'], ['gone.iso', 'x.iso', 'y.iso'])
        info = moves.check(self.conn, plan)['steps'][0]
        self.assertEqual(info['src']['bytes'], 6 << 20)
        self.assertEqual(info['src']['files'], 2)
        self.assertIn('--include=/x.iso', moves.script(self.conn, plan))
        self.assertEqual(moves.only_filters(['a*b[1].iso']), [r'--include=/a\*b\[1].iso', '--exclude=*'])

    @unittest.skipUnless(shutil.which('rsync'), 'needs rsync')
    def test_rsync_sends_exactly_the_chosen_files(self):
        src, dst = Path(self.tmp) / 'src', Path(self.tmp) / 'dst'
        (src / 'sub').mkdir(parents=True)
        dst.mkdir()
        wanted = ['keep.iso', 'a*b[1].iso', 'back\\slash.iso', 'both\\*.iso', 'with space.iso']
        for name in [*wanted, 'skip.iso', 'ab1.iso', 'sub/deep.iso']:
            (src / name).touch()
        subprocess.run(['rsync', '-a', '--protect-args', *moves.only_filters(wanted), f'{src}/', f'{dst}/'], check=True)
        self.assertEqual(sorted(p.name for p in dst.iterdir()), sorted(wanted))

    def test_chosen_files_are_plain_names_on_a_copy(self):
        base = {'src': {'host': 'nas', 'path': '/a'}, 'dst': {'host': 'nas', 'path': '/b'}}
        with self.assertRaises(ValueError):
            moves.normalize({'name': 'x', 'steps': [{**base, 'method': 'move', 'only': ['f']}]})
        for bad in ('../f', 'a/b', '..', 'a\nb'):
            with self.assertRaises(ValueError):
                moves.normalize({'name': 'x', 'steps': [{**base, 'method': 'copy', 'only': [bad]}]})
        self.assertNotIn('only', moves.normalize({'name': 'x', 'steps': [{**base, 'method': 'copy'}]})['steps'][0])

    def test_relations_list_what_joins_folders(self):
        c = self.conn
        self.file('nas', '/data/x', 'aa')
        self.file('pc', '/data/x', 'aa')
        for nid, kind, label, host, props in (
                ('link:nas:/srv/l', 'Symlink', '/srv/l', 'nas', '{}'), ('link:nas:/etc/l', 'Symlink', '/etc/l', 'nas', '{}'),
                ('mnt:nas:/data', 'MountPoint', '/data', 'nas', '{}'), ('mnt:pc:/nfs', 'MountPoint', '/nfs', 'pc', '{}'),
                ('mnt:nas:/bound', 'MountPoint', '/bound', 'nas', '{}'), ('fs:nas:d', 'Filesystem', 'ext4', 'nas', '{}'), ('host:B2', 'Host', 'B2', None, '{}')):
            c.execute('INSERT INTO graph_nodes (node_id, kind, label, host, health, props_json, updated_at) VALUES (:i, :k, :l, :h, :he, :p, 1)',
                      {'i': nid, 'k': kind, 'l': label, 'h': host, 'he': 'unknown', 'p': props})
        for src, dst, rel, props in (
                ('link:nas:/srv/l', 'mnt:nas:/data', 'SYMLINK_TO', '{"target": "/data/x"}'), ('link:nas:/etc/l', 'mnt:nas:/data', 'SYMLINK_TO', '{"target": "/data/y"}'),
                ('mnt:nas:/data', 'mnt:pc:/nfs', 'MOUNTED_AT', '{"remote": true, "server": "nas", "path": "/data/share"}'),
                ('mnt:nas:/data', 'mnt:nas:/bound', 'MOUNTED_AT', '{"bind": true, "source": "/data/b"}'),
                ('fs:nas:d', 'mnt:nas:/data', 'MOUNTED_AT', '{}'), ('fs:nas:d', 'host:B2', 'REPLICATES_TO', '{"detail": "restic -> B2"}')):
            c.execute('INSERT INTO graph_edges (src, dst, rel, props_json) VALUES (:s, :d, :r, :p)', {'s': src, 'd': dst, 'r': rel, 'p': props})
        got = {r['kind']: r for r in filemap.build(c, None, 1 << 20)['relations']}
        self.assertEqual(got['symlink']['src']['path'], '/srv/l')       # the one in /etc is a system link
        self.assertEqual(got['symlink']['dst'], {'host': 'nas', 'path': '/data/x'})
        self.assertEqual((got['share']['src'], got['share']['dst']), ({'host': 'nas', 'path': '/data/share'}, {'host': 'pc', 'path': '/nfs'}))
        self.assertEqual(got['bind']['src']['path'], '/data/b')
        self.assertIsNone(got['backup']['dst']['host'])
        self.assertEqual(got['backup']['src']['path'], '/data')

    def test_ignored_broken_link_does_not_turn_the_host_red(self):
        node = {'hostname': 'nas', 'links': [{'kind': 'symlink', 'path': '/etc/old', 'target': '/gone', 'state': 'crit', 'note': 'x'},
                                             {'kind': 'symlink', 'path': '/srv/mine', 'target': '/gone', 'state': 'crit', 'note': 'x'}],
                'remotes': [], 'protection': [], 'pools': [], 'mounts': [], 'exports': [], 'jobs': []}
        nodes, _ = graph.build({**node, 'link_ignore': {}})
        self.assertNotIn('link:nas:/etc/old', nodes)
        self.assertEqual(nodes['link:nas:/srv/mine']['health'], 'broken')
        nodes, _ = graph.build({**node, 'link_ignore': {'nas': ['/srv/mine']}})
        self.assertNotIn('link:nas:/srv/mine', nodes)
        self.assertEqual(nodes['host:nas']['health'], 'unknown')

    def test_kept_folder_index_lists_what_the_tables_do(self):
        for path in ('/data/a/one', '/data/a/two', '/data/a/sub/three', '/data/a-b/four', '/data/a0/five', '/data/z/deep/er/six', '/top'):
            self.file('nas', path, None, size=7)
        index = folders.dir_index(self.conn)
        for path in ('/', '/data', '/data/a', '/data/z', '/data/a-b', '/nothing'):
            kept, read = fsmap.listing(self.conn, 'nas', path, index), fsmap.browse(self.conn, 'nas', path)
            self.assertEqual(kept['dirs'], read['dirs'], path)
            self.assertEqual(kept['files'], read['files'], path)
        self.assertEqual({d['name']: (d['bytes'], d['entries']) for d in fsmap.listing(self.conn, 'nas', '/data', index)['dirs']},
                         {'a': (21, 3), 'a-b': (7, 1), 'a0': (7, 1), 'z': (7, 1)})

    def test_folder_comparison_is_the_same_from_a_kept_index(self):
        for root in ('/data/one', '/data/two', '/other/three'):
            for name in ('a', 'b', 'sub/c'):
                self.file('nas' if root != '/other/three' else 'pc', f'{root}/{name}', None)
        everywhere = folders.dir_index(self.conn)
        for host in (None, 'nas', 'pc'):
            built, kept = (folders.duplicate_folders(self.conn, host, 3, 1, include_system=True, index=i) for i in (None, everywhere))
            self.assertEqual(built['groups'], kept['groups'], host)
        # pc has one copy, and it matches the two on nas: the group, with every copy (it used to be compared on pc alone)
        self.assertEqual({c['path'] for c in kept['groups'][0]['copies']}, {'/data/one', '/data/two', '/other/three'})
        both = folders.duplicate_folders(self.conn, None, 3, 1, include_system=True, index=everywhere)['groups']
        self.assertEqual({c['path'] for c in both[0]['copies']}, {'/data/one', '/data/two', '/other/three'})

    def test_an_index_of_some_mounts_is_that_part_of_the_whole(self):
        for path in ('/data/a/one', '/data/a/two', '/data/b/three'):
            self.file('nas', path, None, size=9)
        for path in ('/srv/x/one', '/srv/x/two'):
            self.file('nas', path, None, size=3, mount='/srv')
        self.file('pc', '/home/me/notes', None, size=4)
        whole = folders.dir_index(self.conn)
        nas = self.mounts[('nas', '/')]
        part = folders.dir_index(self.conn, None, [nas])
        self.assertEqual(set(part), {nas})
        for attr in ('paths', 'prints'):
            self.assertEqual(getattr(part[nas], attr), getattr(whole[nas], attr))
        for attr in ('bytes', 'entries', 'fp', 'files', 'size'):
            self.assertEqual(list(getattr(part[nas], attr)), list(getattr(whole[nas], attr)))
        self.assertEqual(folders.dir_index(self.conn, None, []), {})
        self.assertEqual(set(folders.mount_marks(self.conn, 'pc')), {self.mounts[('pc', '/')]})

    def test_the_server_rebuilds_only_the_mounts_a_scan_changed(self):
        from unittest import mock
        from storageforge_index import server, users
        for root in ('/data/one', '/data/two'):
            for name in ('a', 'b', 'c'):
                self.file('nas', f'{root}/{name}', None)
        self.file('pc', '/home/me/a', None)
        users.create(self.conn, 'admin', 'a long enough password', 'admin')
        client = server.create_app(server.App(self.db), 's' * 48).test_client()
        self.assertEqual(client.post('/api/login', json={'username': 'admin', 'password': 'a long enough password'}).status_code, 200)
        built, real = [], folders.dir_index

        def counting(conn, host=None, mounts=None):
            built.append(sorted(mounts) if mounts is not None else None)
            return real(conn, host, mounts)

        nas, pc = self.mounts[('nas', '/')], self.mounts[('pc', '/')]
        get = lambda: client.get('/api/filemap?folders=1&min_size=1')
        scan = lambda host, status: self.conn.scalar(
            "INSERT INTO scans (host_id, started_at, status) SELECT host_id, 1, :s FROM hosts WHERE hostname = :h RETURNING scan_id", {'s': status, 'h': host})
        mark = lambda mount, sid: self.conn.execute('UPDATE mounts SET last_scan_id = :s WHERE mount_id = :m', {'s': sid, 'm': mount})
        with mock.patch.object(folders, 'dir_index', counting):
            first = get().get_json()
            self.assertEqual(built, [sorted([nas, pc])])
            self.assertEqual({c['path'] for c in first['folder_copies'][0]['copies']} if first['folder_copies'] else set(), {'/data/one', '/data/two'})
            mark(pc, scan('pc', 'ok'))              # pc was scanned: only its mount is read again
            built.clear(); get()
            self.assertEqual(built, [[pc]])
            mark(nas, scan('nas', 'running'))       # nas is being scanned: its mount serves the request and is not kept
            built.clear(); get(); get()
            self.assertEqual(built, [[nas], [nas]])
            self.conn.execute("UPDATE scans SET status = 'ok' WHERE status = 'running'")
            built.clear(); last = get().get_json()
            self.assertEqual(built, [[nas]])
            built.clear(); get()
            self.assertEqual(built, [])
        self.assertEqual(last['folder_copies'], first['folder_copies'])


if __name__ == '__main__':
    unittest.main()
