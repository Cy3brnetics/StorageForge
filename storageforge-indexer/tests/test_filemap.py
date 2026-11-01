"""Graph view file map: duplicate sets, ignore rules, and broken-link flags that respect them.
Run with: python3 -m unittest discover -s tests -v"""
import shutil
import tempfile
import time
import unittest
from pathlib import Path

try:
    import dbfactory
except ImportError:      # run as tests.test_x from the project folder
    from tests import dbfactory
from storageforge_index import filemap, folders, graph


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


if __name__ == '__main__':
    unittest.main()
