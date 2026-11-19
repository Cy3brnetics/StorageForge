"""Copies on other hosts as possible backups (the owner's request of 2026-11-19): what a plan's trash tasks would leave of each
content, duplicates across hosts as a class of their own, keeping a pair in sync, and the suggestions.
Run with: python3 -m unittest discover -s tests -v"""
import random
import shutil
import tempfile
import time
import unittest
from pathlib import Path

try:
    import dbfactory
except ImportError:      # run as tests.test_x from the project folder
    from tests import dbfactory
from storageforge_index import changes, copies, folders, moves

MIB = 1 << 20


class Builder:
    """Writes an index as scans leave it: a row for every file and for every folder on the way to it. test_browser_copies.py uses it too."""

    def start(self, db, conn):
        self.db, self.conn = db, conn
        self.mounts, self.dirs, self.made = {}, {}, set()
        return self

    def mount(self, host, mount='/', state='indexed'):
        c = self.conn
        if (host, mount) not in self.mounts:
            if not c.scalar('SELECT 1 FROM hosts WHERE hostname = :h', {'h': host}):
                c.execute("INSERT INTO hosts (hostname, ssh_host, ssh_user, inventory_json) VALUES (:h, :h, 'scan', '{}')", {'h': host})
            hid = c.scalar('SELECT host_id FROM hosts WHERE hostname = :h', {'h': host})
            c.execute("""INSERT INTO mounts (host_id, mount_point, filesystem_type, scan_state, total_bytes, used_bytes)
                         VALUES (:i, :m, 'ext4', :s, :t, :u)""", {'i': hid, 'm': mount, 's': state, 't': 1 << 40, 'u': 1 << 30})
            self.mounts[(host, mount)] = c.scalar('SELECT mount_id FROM mounts WHERE host_id = :i AND mount_point = :m', {'i': hid, 'm': mount})
        return self.mounts[(host, mount)]

    def _dir(self, mid, path):
        if (mid, path) not in self.dirs:
            self.conn.execute('INSERT INTO directories (mount_id, path) VALUES (:m, :p)', {'m': mid, 'p': path})
            self.dirs[(mid, path)] = self.conn.scalar('SELECT dir_id FROM directories WHERE mount_id = :m AND path = :p', {'m': mid, 'p': path})
        return self.dirs[(mid, path)]

    def _row(self, mid, parent, name, size, sha, is_dir, mtime):
        if (mid, parent, name) in self.made:
            return
        self.made.add((mid, parent, name))
        self.conn.execute(f"""INSERT INTO file_records (mount_id, dir_id, filename, file_size_bytes, is_directory, modified_at, checksum_hash)
                              VALUES (:m, :d, :n, :s, :dir, {self.db.ts(':t')}, :c)""",
                          {'m': mid, 'd': self._dir(mid, parent), 'n': name, 's': size, 'dir': bool(is_dir), 't': int(mtime), 'c': sha})

    def folder(self, host, path, mount='/', mtime=None):
        """The folder's own row, and one for each folder above it up to the mount."""
        mid = self.mount(host, mount)
        while path not in ('/', mount):
            parent, name = path.rsplit('/', 1)
            self._row(mid, parent or '/', name, 4096, None, True, mtime or 1_700_000_000)
            path = parent or '/'

    def file(self, host, path, sha=None, size=5 * MIB, mount='/', mtime=None):
        mid = self.mount(host, mount)
        parent, name = path.rsplit('/', 1)
        self.folder(host, parent or '/', mount)
        self._row(mid, parent or '/', name, size, sha, False, mtime or 1_700_000_000)

    def tree(self, host, root, files=3, sha=None, mount='/', mtime=None):
        """A folder of files. files: a count, or {relative path: size}. sha: a prefix for a checksum per file, or none."""
        names = {f'f{i}.bin': (i + 1) * MIB for i in range(files)} if isinstance(files, int) else files
        for rel, size in names.items():
            self.file(host, f'{root}/{rel}', f'{sha}-{rel}' if sha else None, size, mount, mtime)


class Index(Builder, unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db = dbfactory.make(self, Path(self.tmp) / 'index.db')
        self.start(self.db, self.db.connect())
        self.db.migrate(self.conn)

    def tearDown(self):
        self.conn.close()
        shutil.rmtree(self.tmp)

    def trash(self, *where):
        return changes.normalize({'name': 'cleanup', 'tasks': [{'type': 'trash', 'host': h, 'params': {'path': p}} for h, p in where]})

    def found(self, *where):
        """What the check says about copies, per task: [(task, level, code, text)]."""
        r = changes.check(self.conn, self.trash(*where))
        return [(t['task'], it['level'], it['code'], it['text']) for t in r['tasks'] for it in t['items'] if it.get('code')]


class TrashCheck(Index):
    def test_two_tasks_that_trash_both_copies_of_a_file_are_the_last_copy(self):
        self.file('nas', '/data/a/x.iso', 'aa')
        self.file('nas', '/data/b/x.iso', 'aa')
        got = self.found(('nas', '/data/a/x.iso'), ('nas', '/data/b/x.iso'))
        self.assertEqual([(t, lv, code) for t, lv, code, _ in got], [(2, 'crit', 'last-copy')])
        text = got[0][3]
        self.assertTrue(text.startswith('the last copy of a file'), text)
        for said in ('this and task 1', 'nas:/data/a/x.iso', 'nas:/data/b/x.iso', 'Keep one copy'):
            self.assertIn(said, text)
        r = changes.check(self.conn, self.trash(('nas', '/data/a/x.iso'), ('nas', '/data/b/x.iso')))
        self.assertEqual((r['crit'], r['warn'], r['all_done']), (1, 0, False))

    def test_trashing_one_of_two_copies_on_one_host_says_nothing(self):
        """Cleaning up a duplicate within a host is what the view is for: as before."""
        self.file('nas', '/data/a/x.iso', 'aa')
        self.file('nas', '/data/b/x.iso', 'aa')
        self.assertEqual(self.found(('nas', '/data/b/x.iso')), [])
        r = changes.check(self.conn, self.trash(('nas', '/data/b/x.iso')))
        self.assertEqual((r['crit'], r['warn']), (0, 0))

    def test_one_side_of_a_pair_across_hosts_leaves_the_only_copy_on_the_other(self):
        self.file('nas', '/data/x.iso', 'aa')
        self.file('pc', '/backup/x.iso', 'aa')
        got = self.found(('nas', '/data/x.iso'))
        self.assertEqual([(t, lv, code) for t, lv, code, _ in got], [(1, 'warn', 'only-copy-left')])
        self.assertIn('the copy on pc would be the only one left of a file', got[0][3])
        self.assertIn('pc:/backup/x.iso', got[0][3])
        self.assertIn('A copy on another host may be its backup', got[0][3])

    def test_three_copies_two_hosts(self):
        self.file('nas', '/data/a/x.iso', 'aa')
        self.file('nas', '/data/b/x.iso', 'aa')
        self.file('pc', '/backup/x.iso', 'aa')
        self.assertEqual(self.found(('nas', '/data/b/x.iso')), [], 'a copy stays on each host')
        both = self.found(('nas', '/data/a/x.iso'), ('nas', '/data/b/x.iso'))
        self.assertEqual([(t, lv, code) for t, lv, code, _ in both], [(2, 'warn', 'only-copy-left')])
        self.assertIn('the copy on pc would be the only one left', both[0][3])
        away = self.found(('pc', '/backup/x.iso'))
        self.assertEqual([(t, lv, code) for t, lv, code, _ in away], [(1, 'warn', 'only-copy-left')])
        self.assertIn('the 2 copies on nas would be the only ones left of a file', away[0][3])
        self.assertIn('nas:/data/a/x.iso, nas:/data/b/x.iso', away[0][3])
        every = self.found(('nas', '/data/a/x.iso'), ('pc', '/backup/x.iso'), ('nas', '/data/b/x.iso'))
        self.assertEqual([(t, lv, code) for t, lv, code, _ in every], [(3, 'crit', 'last-copy')])
        self.assertIn('this and tasks 1, 2', every[0][3])

    def test_one_task_that_holds_both_copies_is_a_folder_being_trashed_not_a_cleanup(self):
        self.file('nas', '/data/old/a/x.iso', 'aa')
        self.file('nas', '/data/old/b/x.iso', 'aa')
        self.assertEqual(self.found(('nas', '/data/old')), [])

    def test_many_files_are_one_line_with_their_count(self):
        for i in range(40):
            self.file('nas', f'/data/a/f{i}.bin', f's{i}', size=2 * MIB)
            self.file('nas', f'/data/b/sub/g{i}.bin', f's{i}', size=2 * MIB)       # other names, another layout: copies by checksum only
        got = self.found(('nas', '/data/a'), ('nas', '/data/b'))
        self.assertEqual([(t, lv, code) for t, lv, code, _ in got], [(2, 'crit', 'last-copy')])
        self.assertIn('the last copy of 40 files (80.0 MiB)', got[0][3])
        self.assertIn('such as', got[0][3])

    def test_both_copies_of_a_folder_alike_by_name_and_size_with_no_checksums(self):
        """What the owner's plan did: the duplicates view showed two folders as copies, and the plan trashed both."""
        self.tree('nas', '/photos/2019', {'a.jpg': 2 * MIB, 'b.jpg': 3 * MIB, 'raw/c.dng': 9 * MIB})
        self.tree('nas', '/old/2019-copy', {'a.jpg': 2 * MIB, 'b.jpg': 3 * MIB, 'raw/c.dng': 9 * MIB})
        self.tree('nas', '/photos/2020', {'a.jpg': 2 * MIB, 'b.jpg': 3 * MIB, 'raw/d.dng': 9 * MIB})        # nearly: one name differs
        got = self.found(('nas', '/photos/2019'), ('nas', '/old/2019-copy'))
        self.assertEqual([(t, lv, code) for t, lv, code, _ in got], [(2, 'crit', 'last-copy')])
        for said in ('the last copy: this and task 1', 'one folder', '3 files, 14.0 MiB', 'nas:/old/2019-copy', 'nas:/photos/2019', 'Keep one of them'):
            self.assertIn(said, got[0][3])
        self.assertEqual(self.found(('nas', '/old/2019-copy')), [], 'one of two on a host: a cleanup')
        self.assertEqual(self.found(('nas', '/photos/2019'), ('nas', '/photos/2020')), [], 'not copies of each other')

    def test_a_folder_whose_copy_is_on_another_host(self):
        self.tree('nas', '/photos/2019', 4)
        self.tree('pc', '/backup/2019', 4)
        got = self.found(('nas', '/photos/2019'))
        self.assertEqual([(t, lv, code) for t, lv, code, _ in got], [(1, 'warn', 'only-copy-left')])
        self.assertIn('the copy on pc would be the only one left of a folder (4 files, 10.0 MiB): pc:/backup/2019', got[0][3])
        both = self.found(('pc', '/backup/2019'), ('nas', '/photos/2019'))
        self.assertEqual([(t, lv, code) for t, lv, code, _ in both], [(2, 'crit', 'last-copy')])

    def test_copies_inside_the_folders_a_plan_trashes_are_found(self):
        """Neither trashed folder is a copy of the other, but each holds one of the two copies of an album."""
        self.tree('nas', '/data/old/album', 5)
        self.tree('nas', '/data/old/notes', {'n.txt': 10})
        self.tree('nas', '/data/new/things/album', 5)
        self.tree('nas', '/data/new/other', {'o.bin': 7 * MIB})
        got = self.found(('nas', '/data/old'), ('nas', '/data/new'))
        self.assertEqual([(t, lv, code) for t, lv, code, _ in got], [(2, 'crit', 'last-copy')])
        self.assertIn('nas:/data/new/things/album, nas:/data/old/album', got[0][3])

    def test_hashed_files_inside_a_pair_of_folders_are_not_said_again(self):
        self.tree('nas', '/photos/2019', 4, sha='p')
        self.tree('nas', '/old/2019', 4, sha='p')
        got = self.found(('nas', '/photos/2019'), ('nas', '/old/2019'))
        self.assertEqual(len(got), 1, got)
        self.assertIn('one folder', got[0][3])
        self.file('pc', '/dl/f0.bin', 'p-f0.bin', size=MIB)         # one of those files has a third copy elsewhere: that is its own line
        got = self.found(('nas', '/photos/2019'), ('nas', '/old/2019'))
        self.assertEqual(sorted((lv, code) for _, lv, code, _ in got), [('crit', 'last-copy'), ('warn', 'only-copy-left')])
        self.assertIn('pc:/dl/f0.bin', next(text for _, lv, _, text in got if lv == 'warn'))

    def test_a_copy_in_the_trash_is_nobodys_copy(self):
        self.file('nas', '/data/a/x.iso', 'aa')
        self.file('nas', '/data/c/x.iso', 'aa')
        self.file('nas', '/data/.storageforge-trash/2026-11-01/b/x.iso', 'aa')
        got = self.found(('nas', '/data/a/x.iso'), ('nas', '/data/c/x.iso'))
        self.assertEqual([(t, lv, code) for t, lv, code, _ in got], [(2, 'crit', 'last-copy')])
        self.assertNotIn('storageforge-trash', got[0][3])
        self.tree('nas', '/photos/2019', 4)
        self.tree('nas', '/old/2019', 4)
        self.tree('nas', '/photos/.storageforge-trash/2026-11-01/2019', 4)
        self.assertEqual([code for *_, code, _ in self.found(('nas', '/photos/2019'), ('nas', '/old/2019'))], ['last-copy'])

    def test_a_copy_on_a_mount_that_is_gone_is_not_counted_on(self):
        self.file('nas', '/data/a/x.iso', 'aa')
        self.file('nas', '/data/b/x.iso', 'aa')
        self.mount('pc', '/', state='gone')
        self.file('pc', '/backup/x.iso', 'aa')
        got = self.found(('nas', '/data/a/x.iso'), ('nas', '/data/b/x.iso'))
        self.assertEqual([(lv, code) for _, lv, code, _ in got], [('crit', 'last-copy')])

    def test_a_plan_with_no_trash_task_and_a_path_the_index_does_not_hold(self):
        self.file('nas', '/data/a/x.iso', 'aa')
        plan = changes.normalize({'name': 'p', 'tasks': [{'type': 'dir', 'host': 'nas', 'params': {'path': '/data/new'}}]})
        self.assertEqual(copies.trash_findings(self.conn, moves.hosts(self.conn), plan['tasks']), [])
        self.assertEqual(self.found(('nas', '/data/nothing'), ('ghost', '/data/a/x.iso')), [])

    def test_the_script_names_what_was_flagged_in_its_header(self):
        self.file('nas', '/data/a/x.iso', 'aa')
        self.file('nas', '/data/b/x.iso', 'aa')
        self.file('nas', '/data/y.iso', 'bb')
        self.file('pc', '/backup/y.iso', 'bb')
        text = changes.script(self.conn, self.trash(('nas', '/data/a/x.iso'), ('nas', '/data/b/x.iso'), ('nas', '/data/y.iso')))
        head = text.split('set -euo pipefail')[0]
        self.assertIn('#   task 2: CRIT: the last copy of a file', head)
        self.assertIn('#   task 3: WARN: the copy on pc would be the only one left of a file', head)
        self.assertTrue(all(line.startswith('#') for line in head.strip().splitlines()), 'a path cannot end the comment')

    def test_more_findings_than_are_named_are_counted(self):
        for i in range(copies.MAX_SAID + 3):
            self.tree('nas', f'/a/set{i}', 3 + i)
            self.tree('nas', f'/b/set{i}', 3 + i)
        where = [('nas', f'/a/set{i}') for i in range(copies.MAX_SAID + 3)] + [('nas', '/b')]
        got = self.found(*where)
        self.assertEqual({t for t, *_ in got}, {len(where)})
        self.assertEqual(len(got), copies.MAX_SAID + 1)
        self.assertEqual(got[-1][3], 'and 3 more like the lines above')

    def test_the_check_route_answers_with_the_code(self):
        from storageforge_index import server, users
        self.file('nas', '/data/x.iso', 'aa')
        self.file('pc', '/backup/x.iso', 'aa')
        users.create(self.conn, 'admin', 'a long enough password', 'admin')
        client = server.create_app(server.App(self.db), 's' * 48).test_client()
        self.assertEqual(client.post('/api/login', json={'username': 'admin', 'password': 'a long enough password'}).status_code, 200)
        r = client.post('/api/changes/check', json={'name': 'check', 'tasks': [{'type': 'trash', 'host': 'nas', 'params': {'path': '/data/x.iso'}}]}).get_json()
        self.assertEqual([(it['level'], it['code']) for it in r['tasks'][0]['items'] if it.get('code')], [('warn', 'only-copy-left')])
        self.assertEqual(r['warn'], 1)


class AcrossHosts(Index):
    """A copy on another host is a class of its own: a possible backup, never counted as space to free."""

    def seed(self):
        self.file('nas', '/data/a/same.iso', 'ss', size=8 * MIB)          # twice on one host: a duplicate there
        self.file('nas', '/data/b/same.iso', 'ss', size=8 * MIB)
        self.file('nas', '/data/x.iso', 'xx', size=20 * MIB)              # once on each of two hosts: a possible backup
        self.file('pc', '/backup/x.iso', 'xx', size=20 * MIB)
        self.file('nas', '/data/a/mix.iso', 'mm', size=3 * MIB)           # twice here and once there: both
        self.file('nas', '/data/b/mix.iso', 'mm', size=3 * MIB)
        self.file('pc', '/backup/mix.iso', 'mm', size=3 * MIB)

    def test_identical_files_are_two_classes(self):
        from storageforge_index.search import dupes_totals, run_dupes
        self.seed()
        got = {g['sha256']: g for g in run_dupes(self.conn, None, MIB, 50)}
        self.assertEqual({k: (g['scope'], g['hosts'], g['copies'], g['reclaimable'], g['elsewhere']) for k, g in got.items()},
                         {'ss': ('same host', 1, 2, 8 * MIB, 0), 'xx': ('across hosts', 2, 2, 0, 20 * MIB), 'mm': ('across hosts', 2, 3, 3 * MIB, 3 * MIB)})
        self.assertEqual(dupes_totals(self.conn, None, MIB),
                         {'total_groups': 3, 'reclaimable': 11 * MIB, 'across_hosts': {'groups': 2, 'bytes': 23 * MIB}})
        self.assertEqual(dupes_totals(self.conn, 'pc', MIB)['total_groups'], 2, 'with a host: the groups with a copy on it')
        self.assertEqual(dupes_totals(self.conn, None, 1 << 40), {'total_groups': 0, 'reclaimable': 0, 'across_hosts': {'groups': 0, 'bytes': 0}})

    def test_neither_class_crowds_the_other_out_of_a_short_list(self):
        from storageforge_index.search import run_dupes
        for i in range(6):
            self.file('nas', f'/data/a/s{i}', f's{i}', size=(50 + i) * MIB)
            self.file('nas', f'/data/b/s{i}', f's{i}', size=(50 + i) * MIB)
            self.file('nas', f'/data/x{i}', f'x{i}', size=(i + 1) * MIB)
            self.file('pc', f'/backup/x{i}', f'x{i}', size=(i + 1) * MIB)
        got = run_dupes(self.conn, None, MIB, 4)
        self.assertEqual([g['sha256'] for g in got], ['s5', 's4', 'x5', 'x4'], 'the largest of each')
        self.assertEqual(len(run_dupes(self.conn, None, MIB, 100)), 12)
        self.assertEqual([g['scope'] for g in run_dupes(self.conn, None, MIB, 8)], ['same host'] * 4 + ['across hosts'] * 4)
        self.file('tv', '/only/one', 'q1', size=MIB)
        self.file('pc', '/only/one', 'q1', size=MIB)
        short = run_dupes(self.conn, 'tv', MIB, 4)
        self.assertEqual([g['sha256'] for g in short], ['q1'], 'one class alone gets the whole list')

    def test_folder_copies_across_hosts_free_nothing(self):
        self.tree('nas', '/photos/2019', 4)
        self.tree('pc', '/backup/2019-copy', 4)            # across hosts only (another name, or the folders above them would be the pair)
        self.tree('nas', '/music/a', 5)
        self.tree('nas', '/music/b', 5)                    # on one host
        self.tree('nas', '/docs/a', 3)
        self.tree('nas', '/docs/b', 3)
        self.tree('pc', '/docs', 3)                        # both
        r = folders.duplicate_folders(self.conn, None, 3, MIB)
        got = {g['copies'][0]['path']: (g['scope'], g['hosts'], g['reclaimable'], g['elsewhere']) for g in r['groups']}
        self.assertEqual(got, {'/music/a': ('same host', 1, 15 * MIB, 0), '/photos/2019': ('across hosts', 2, 0, 10 * MIB), '/docs/a': ('across hosts', 2, 6 * MIB, 6 * MIB)})
        self.assertEqual((r['reclaimable_same_host'], r['elsewhere_across_hosts'], r['same_host_groups'], r['across_hosts_groups']), (21 * MIB, 16 * MIB, 1, 2))
        self.assertEqual([g['copies'][0]['path'] for g in r['groups']], ['/music/a', '/docs/a', '/photos/2019'], 'what can be freed first, then the largest')

    def test_the_file_map_counts_them_apart(self):
        from storageforge_index import filemap
        self.seed()
        self.tree('nas', '/photos/2019', 4)
        self.tree('pc', '/backup/2019', 4)
        twins = folders.duplicate_folders(self.conn, None, 3, MIB)
        m = filemap.build(self.conn, None, MIB, twins=twins)
        self.assertEqual(m['reclaimable'], 11 * MIB)
        self.assertEqual(m['across_hosts'], {'sets': 3, 'bytes': 33 * MIB})
        self.assertEqual({g['sha256']: (g['hosts'], g['elsewhere']) for g in m['groups']}, {'ss': (1, 0), 'xx': (2, 20 * MIB), 'mm': (2, 3 * MIB)})
        self.assertEqual([(t['scope'], t['hosts'], t['reclaimable'], t['elsewhere']) for t in m['folder_copies']], [('across hosts', 2, 0, 10 * MIB)])

    def test_the_routes_say_both_figures(self):
        from storageforge_index import server, users
        self.seed()
        self.tree('nas', '/photos/2019', 4)
        self.tree('pc', '/backup/2019', 4)
        users.create(self.conn, 'admin', 'a long enough password', 'admin')
        client = server.create_app(server.App(self.db), 's' * 48).test_client()
        self.assertEqual(client.post('/api/login', json={'username': 'admin', 'password': 'a long enough password'}).status_code, 200)
        r = client.get('/api/dupes').get_json()
        self.assertEqual((r['reclaimable'], r['across_hosts'], r['total_groups']), (11 * MIB, {'groups': 2, 'bytes': 23 * MIB}, 3))
        self.assertEqual({g['sha256']: g['scope'] for g in r['groups']}, {'ss': 'same host', 'xx': 'across hosts', 'mm': 'across hosts'})
        f = client.get('/api/folders/duplicates').get_json()
        self.assertEqual([(g['scope'], g['reclaimable'], g['elsewhere']) for g in f['groups']], [('across hosts', 0, 10 * MIB)])
        self.assertEqual((f['reclaimable_same_host'], f['elsewhere_across_hosts']), (0, 10 * MIB))
        fm = client.get('/api/filemap?folders=1').get_json()
        self.assertEqual((fm['reclaimable'], fm['across_hosts']), (11 * MIB, {'sets': 3, 'bytes': 33 * MIB}))

    def cli(self, *args):
        import contextlib
        import io
        from storageforge_index import cli
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(['--db', self.db.url, *args])
        return code, out.getvalue(), err.getvalue()

    def test_the_command_line_says_which_is_which(self):
        self.seed()
        self.tree('nas', '/photos/2019', 4)
        self.tree('pc', '/backup/2019', 4)
        self.tree('nas', '/music/a', 5)
        self.tree('nas', '/music/b', 5)
        self.conn.raw.commit()
        code, out, err = self.cli('dupes')
        self.assertEqual(code, 0, err)
        lines = [l for l in out.splitlines() if not l.startswith('    ')]
        self.assertEqual(lines, ['2× 8.00 MiB  reclaim 8.00 MiB  sha256 ss…',
                                 '3× 3.00 MiB  reclaim 3.00 MiB  on 2 hosts: a copy on another host, a possible backup  sha256 mm…',
                                 '2× 20.00 MiB  on 2 hosts: a copy on another host, a possible backup  sha256 xx…'])
        self.assertIn('3 group(s); 11.00 MiB reclaimable within hosts; 2 group(s) with a copy on another host (23.00 MiB), possible backups, not counted', err)
        code, out, err = self.cli('folders')
        self.assertEqual(code, 0, err)
        heads = [l for l in out.splitlines() if not l.startswith('    ')]
        self.assertEqual(heads, ['2× 5 files 15.00 MiB  same host  reclaim 15.00 MiB', '2× 4 files 10.00 MiB  across hosts  a copy on another host: a possible backup'])
        self.assertIn('15.00 MiB reclaimable within hosts; 1 group(s) with a copy on another host (10.00 MiB), possible backups, not counted', err)
        code, out, _ = self.cli('dupes', '--format', 'json')
        import json
        self.assertEqual({json.loads(l)['sha256']: json.loads(l)['scope'] for l in out.splitlines()}, {'ss': 'same host', 'mm': 'across hosts', 'xx': 'across hosts'})

    def test_a_report_counts_what_another_host_holds_apart(self):
        from storageforge_index import payloads, report
        self.seed()
        hid = self.conn.scalar("SELECT host_id FROM hosts WHERE hostname = 'nas'")
        ix = payloads._index_stats(self.conn, hid)
        self.assertEqual((ix['dup_groups'], ix['dup_reclaimable'], ix['dup_elsewhere'], ix['dup_elsewhere_bytes']), (2, 11 * MIB, 2, 23 * MIB))
        pc = payloads._index_stats(self.conn, self.conn.scalar("SELECT host_id FROM hosts WHERE hostname = 'pc'"))
        self.assertEqual((pc['dup_groups'], pc['dup_reclaimable'], pc['dup_elsewhere']), (0, 0, 2))
        text = report.render_report([payloads.node_from_index(self.conn, 'nas')])
        self.assertIn('Duplicates on this host: 2 groups of identical files', text)
        self.assertIn('Copies on other hosts: 2 files here', text)
        self.assertIn('are also on another host. Those are possible backups: they are not counted as reclaimable.', text)


class FolderCopiesFound(Index):
    """The check looks one folder up in the rest of the index. It must find what comparing every folder with every other finds."""

    def model(self, rng):
        shapes = [{f'f{i}': (i + 1) * MIB for i in range(n)} for n in (3, 4)] + [{'a': MIB, 'b': MIB, 'sub/c': 2 * MIB}, {'a': MIB, 'b': MIB, 'sub/d': 2 * MIB},
                                                                                {'a': MIB, 'b': MIB, 'c': 2 * MIB}, {'big': 4 * MIB, 'x/y/z': MIB, 'x/w': MIB}]
        placed = {}
        for host in ('nas', 'pc', 'tv'):
            for n, base in enumerate(('/data', '/srv/in', '/home/me/keep', '/data/deep/er')):       # so that no folder above the ones compared is itself a copy
                self.file(host, f'{base}/only-on-{host}', size=(n + 2) * 1000)
            for n in range(rng.randint(2, 5)):
                root = rng.choice(['/data', '/srv/in', '/home/me/keep', '/data/deep/er']) + f'/d{n}'
                shape = rng.choice(shapes)
                placed[(host, root)] = shape
                self.tree(host, root, shape)
                if rng.random() < 0.3:          # an empty folder inside makes it another layout
                    self.folder(host, f'{root}/empty')
                    placed[(host, root)] = {**shape, 'empty/': 0}
        return placed

    def test_the_same_copies_as_comparing_everything(self):
        rng = random.Random(20261119)
        placed = self.model(rng)
        finder = copies.Finder(self.conn)
        hs = moves.hosts(self.conn)
        by_fleet = {}
        for g in folders.duplicate_folders(self.conn, None, 3, 1, limit=10_000, include_system=True)['groups']:
            for c in g['copies']:
                by_fleet[(c['host'], c['path'])] = {(o['host'], o['path']) for o in g['copies']} - {(c['host'], c['path'])}
        some = 0
        for (host, root), shape in placed.items():
            m = moves.mount_of(hs[host], root)
            prints, _, best = copies.tree_prints(copies._rows_under(self.conn, m['id'], m['target'], root), root)
            got, more = finder.copies(host, root, prints[root], best[root])
            truth = {k for k, other in placed.items() if other == shape and k != (host, root)}
            self.assertEqual({(c['host'], c['path']) for c in got}, truth, (host, root))
            self.assertFalse(more)
            self.assertEqual(by_fleet.get((host, root), set()), truth, 'and the duplicates view has the same')
            some += bool(truth)
        self.assertGreater(some, 3, 'the model made copies to find')

    def test_a_folder_print_is_the_one_the_folder_index_makes(self):
        self.tree('nas', '/data/one', {'a': MIB, 'sub/b': 2 * MIB, 'sub/deep/c': 3 * MIB})
        self.folder('nas', '/data/one/empty')
        mid = self.mounts[('nas', '/')]
        whole = folders.dir_index(self.conn)[mid]
        prints, kids, best = copies.tree_prints(copies._rows_under(self.conn, mid, '/', '/data/one'), '/data/one')
        for i, path in enumerate(whole.prints):
            if path.startswith('/data/one'):
                self.assertEqual(prints[path], (whole.fp[i], whole.files[i], whole.size[i]), path)
        self.assertEqual(sorted(kids['/data/one']), ['/data/one/empty', '/data/one/sub'])
        self.assertEqual(best['/data/one'], (3 * MIB, '/data/one/sub/deep', 'c'))

    def test_a_file_in_many_places_is_compared_with_a_few_and_said(self):
        self.tree('nas', '/data/a', 3)
        for i in range(copies.MAX_CANDIDATES + 2):
            self.file('pc', f'/junk/j{i}/f2.bin', size=3 * MIB)
        self.tree('nas', '/data/b', 3)
        plan = changes.normalize({'name': 'p', 'tasks': [{'type': 'trash', 'host': 'nas', 'params': {'path': '/data/a'}}]})
        items = changes.check(self.conn, plan)['tasks'][0]['items']
        self.assertTrue(any(it['level'] == 'note' and 'more than' in it['text'] for it in items), items)

    def test_only_so_many_folders_of_a_plan_are_looked_up(self):
        from unittest import mock
        for i in range(6):
            self.tree('nas', f'/data/top/s{i}', 3 + i)
        with mock.patch.object(copies, 'MAX_LOOKUPS', 3):
            plan = changes.normalize({'name': 'p', 'tasks': [{'type': 'trash', 'host': 'nas', 'params': {'path': '/data/top'}}]})
            items = changes.check(self.conn, plan)['tasks'][0]['items']
        self.assertTrue(any(it['level'] == 'note' and 'only the 3 largest folders' in it['text'] and '4 smaller ones' in it['text'] for it in items), items)


if __name__ == '__main__':
    unittest.main()
