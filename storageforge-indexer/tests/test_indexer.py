"""Run with: python3 -m unittest discover -s tests -v"""
import io
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from storageforge_index.capacity import TiB, parse_size, pool_capacity
from storageforge_index.db import Database, MassDeleteRefused
from storageforge_index.payloads import (apply_df, apply_fstab, apply_zpool_status, load_structured, node_from_blueprint,
                                         parse_df, parse_fstab, parse_zpool_status)
from storageforge_index.remote import MountInfo, Transport, find_command
from storageforge_index.report import render_report
from storageforge_index.scanner import ScanOptions, build_jobs, plan_mounts, scan_host
from storageforge_index.search import SearchQuery, classify, glob_to_like, glob_to_regex, run_search
from storageforge_index.stream import TruncatedStream, extension, iter_rows, split_path

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / 'examples' / 'atlas'


class Units(unittest.TestCase):
    def test_parse_size(self):
        self.assertEqual(parse_size('100MB'), 100_000_000)
        self.assertEqual(parse_size('100MiB'), 100 * 2**20)
        self.assertEqual(parse_size('1.9T'), int(1.9 * 2**40))
        self.assertEqual(parse_size('4096'), 4096)
        with self.assertRaises(ValueError):
            parse_size('lots')

    def test_split_and_extension(self):
        self.assertEqual(split_path('/'), ('', '/'))
        self.assertEqual(split_path('/etc'), ('/', 'etc'))
        self.assertEqual(split_path('/etc/fstab'), ('/etc', 'fstab'))
        self.assertEqual(extension('IMG_1.CR2', False), 'cr2')
        self.assertEqual(extension('.bashrc', False), '')
        self.assertEqual(extension('dir.d', True), '')


class Stream(unittest.TestCase):
    def rec(self, path, t='f', size=10, target=''):
        return b'\0'.join([t.encode(), str(size).encode(), b'-rw-r--r--', b'1000', b'1000', b'1700000000.75',
                           target.encode(), path.encode()]) + b'\0'

    def test_newlines_and_spaces_in_names(self):
        data = self.rec('/srv/a b/new\nline.txt') + self.rec('/srv/l', 'l', 3, '../x')
        rows = list(iter_rows(io.BytesIO(data)))
        self.assertEqual(rows[0][:4], ('/srv/a b', 'new\nline.txt', 'txt', 10))
        self.assertEqual(rows[0][-1], 1700000000)
        self.assertTrue(rows[1][5])
        self.assertEqual(rows[1][6], '../x')

    def test_truncated_stream_is_an_error(self):
        data = self.rec('/a')[:-7]
        with self.assertRaises(TruncatedStream):
            list(iter_rows(io.BytesIO(data)))

    def test_small_reads_span_record_boundaries(self):
        class Trickle(io.BytesIO):
            def read1(self, n=-1):
                return super().read(3)
        rows = list(iter_rows(Trickle(self.rec('/x/y') * 50)))
        self.assertEqual(len(rows), 50)


class Patterns(unittest.TestCase):
    def test_classify(self):
        self.assertEqual(classify('*.cr2'), ('ext', 'cr2'))
        self.assertEqual(classify('report.pdf'), ('exact', 'report.pdf'))
        self.assertEqual(classify('IMG_*'), ('prefix', 'IMG_'))
        self.assertEqual(classify('*2019*raw*')[0], 'glob')

    def test_translations(self):
        self.assertEqual(glob_to_like('IMG_?[0-9]*.cr2'), 'IMG___%.cr2')
        self.assertEqual(glob_to_regex('a?[!x]*.c'), '^a.[^x].*\\.c$')


class Capacity(unittest.TestCase):
    def test_tank_matches_dashboard(self):
        r = pool_capacity('zfs', 'raidz2', [20000588955648] * 6)
        self.assertAlmostEqual(r['usable'] / TiB, 72.64, places=2)
        self.assertEqual(r['tolerance'], 2)

    def test_md_raid1_ext4(self):
        r = pool_capacity('md', 'raid1', [8001563222016 - 2**20] * 2, fs='ext4')
        self.assertAlmostEqual(r['usable'] / TiB, 6.80, places=2)

    def test_btrfs_raid1_mixed(self):
        r = pool_capacity('btrfs', 'raid1', [16e12, 4e12])
        self.assertAlmostEqual(r['usable'] / 1e12, 4.0, delta=0.1)   # limited by the small device
        self.assertGreater(r['waste'], 11e12)


class Planning(unittest.TestCase):
    def test_plan_skips_and_bind_alias(self):
        mounts = [MountInfo('/', '/dev/sda2', 'ext4', majmin='8:2', fsroot='/'),
                  MountInfo('/proc', 'proc', 'proc'),
                  MountInfo('/mnt/data', '/dev/sdb1', 'xfs', majmin='8:17', fsroot='/'),
                  MountInfo('/srv/data', '/dev/sdb1', 'xfs', majmin='8:17', fsroot='/shares'),
                  MountInfo('/mnt/nas', 'nas:/x', 'nfs4', majmin='0:55'),
                  MountInfo('/home', '/dev/sdc1', 'btrfs', majmin='0:40', fsroot='/@home'),
                  MountInfo('/var', '/dev/sdc1', 'btrfs', majmin='0:40', fsroot='/@var')]
        plans = {p.info.target: p for p in plan_mounts(mounts, ScanOptions())}
        self.assertEqual(plans['/proc'].action, 'skip')
        self.assertEqual(plans['/mnt/nas'].action, 'skip')
        self.assertEqual(plans['/srv/data'].action, 'alias')
        self.assertIs(plans['/srv/data'].alias_of, plans['/mnt/data'])
        self.assertEqual(plans['/home'].action, 'scan')   # sibling btrfs subvolumes are distinct trees
        self.assertEqual(plans['/var'].action, 'scan')
        jobs = {j.root: j for j in build_jobs(list(plans.values()), ScanOptions())}
        self.assertIn('/mnt/data', jobs['/'].prune)       # nested mounts are pruned from the parent walk
        self.assertIn('/proc', jobs['/'].prune)
        self.assertNotIn('/srv/data', jobs)

    def test_root_on_skipped_mount_is_refused(self):
        mounts = [MountInfo('/', '/dev/sda2', 'ext4', majmin='8:2'), MountInfo('/mnt/nas', 'nas:/x', 'nfs4')]
        with self.assertRaises(ValueError):
            build_jobs(plan_mounts(mounts, ScanOptions()), ScanOptions(roots=['/mnt/nas/photos']))

    def test_find_command_quotes_and_prunes(self):
        cmd = find_command("/srv/it's here", ['/srv/it\'s here/[x]'], ['.git'], nice=False)
        self.assertIn("'/srv/it'\"'\"'s here'", cmd)
        self.assertIn('\\[x\\]', cmd)
        self.assertIn('-xdev', cmd)


class Payloads(unittest.TestCase):
    def test_zpool_status(self):
        st = parse_zpool_status((EXAMPLES / 'zpool-status.txt').read_text())[0]
        self.assertEqual((st['name'], st['state'], st['level'], st['width']), ('tank', 'ONLINE', 'raidz2', 6))
        self.assertEqual(len(st['log']), 1)
        self.assertEqual(len(st['cache']), 1)
        self.assertEqual(st['device_errors'][0]['cksum'], 2)
        self.assertIn('unrecoverable error', st['status'])

    def test_df_wrapped_lines(self):
        rows = {r['target']: r for r in parse_df((EXAMPLES / 'df-h.txt').read_text())}
        self.assertEqual(rows['/mnt/remote_nfs']['source'], 'nas-02.tail4c2e.ts.net:/export/archive')
        self.assertEqual(rows['/mnt/legacy']['avail'], parse_size('191G'))

    def test_fstab(self):
        e = {x['target']: x for x in parse_fstab((EXAMPLES / 'fstab').read_text())}
        self.assertIn('subvol=@home', e['/home']['options'])
        self.assertIn('bind', e['/var/lib/docker']['options'])

    def test_atlas_report(self):
        node = node_from_blueprint(load_structured(str(EXAMPLES / 'blueprint.json')))
        apply_zpool_status(node, parse_zpool_status((EXAMPLES / 'zpool-status.txt').read_text()))
        apply_fstab(node, parse_fstab((EXAMPLES / 'fstab').read_text()))
        apply_df(node, parse_df((EXAMPLES / 'df-h.txt').read_text()))
        import datetime as dt
        md = render_report([node], as_of=dt.date(2026, 10, 26))
        for heading in ('## 1. Executive Summary', '## 2. Node & Disk Inventory', '## 3. Symbolic Link',
                        '## 4. Resilience', '## 5. Storage Economics'):
            self.assertIn(heading, md)
        self.assertIn('Circular symlink', md)
        self.assertIn('protection: {protected: 4, local_only: 2, critical: 3, excluded: 1}', md)
        self.assertIn('72.64 TiB', md)


class EndToEnd(unittest.TestCase):
    """Real local scans into a temporary SQLite index."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='sfidx-test-'))
        self.tree = self.tmp / 'tree'
        (self.tree / 'a').mkdir(parents=True)
        (self.tree / 'b').mkdir()
        for i in range(1200):
            (self.tree / 'a' / f'IMG_{i:04d}.CR2').write_text(str(i))
        (self.tree / 'b' / 'notes.txt').write_text('hi')
        (self.tree / 'b' / '.git').mkdir()
        (self.tree / 'b' / '.git' / 'HEAD').write_text('x')
        self.db = Database(str(self.tmp / 'idx.db'))
        conn = self.db.connect()
        self.db.migrate(conn)
        conn.close()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def scan(self, root=None, **kw):
        opts = ScanOptions(roots=[str(root or self.tree)], include_tmpfs=True, include_fstypes=['overlay'], **kw)
        return scan_host(self.db, Transport('localhost', local=True), opts, log=lambda m: None)

    def search(self, **kw):
        conn = self.db.connect()
        try:
            return run_search(self.db, conn, SearchQuery(limit=5000, **kw))
        finally:
            conn.close()

    def test_scan_search_and_incremental_diff(self):
        first = self.scan()
        self.assertEqual(first['status'], 'ok')
        self.assertEqual(first['entries'], 1 + 2 + 1200 + 1)       # root, a, b, images, notes (.git pruned)
        self.assertEqual(len(self.search(pattern='*.cr2')), 1200)
        self.assertEqual(len(self.search(pattern='*_00?5.CR2')), 10)
        self.assertEqual(len(self.search(pattern='notes.TXT')), 1)
        self.assertEqual(self.search(pattern='HEAD'), [])

        (self.tree / 'a' / 'IMG_0000.CR2').unlink()
        (self.tree / 'b' / 'notes.txt').write_text('longer text')
        (self.tree / 'b' / 'new.md').write_text('n')
        second = self.scan()
        self.assertEqual((second['added'], second['deleted']), (1, 1))
        self.assertGreaterEqual(second['modified'], 1)
        self.assertEqual(self.search(pattern='IMG_0000.CR2'), [])
        self.assertEqual(len(self.search(pattern='*0000*')), 0)       # FTS row removed too
        self.assertEqual(self.search(pattern='notes.txt')[0]['size'], 11)

    def test_subtree_scan_does_not_delete_siblings(self):
        self.scan()
        result = self.scan(self.tree / 'b')
        self.assertEqual(result['deleted'], 0)
        self.assertEqual(len(self.search(pattern='*.cr2')), 1200)

    def test_mass_delete_guard(self):
        self.scan()
        for f in (self.tree / 'a').iterdir():
            f.unlink()
        result = self.scan()
        self.assertEqual(result['status'], 'failed')
        self.assertEqual(len(self.search(pattern='*.cr2')), 1200)     # index left untouched
        result = self.scan(max_delete_ratio=1.0)
        self.assertEqual(result['deleted'], 1200)


if __name__ == '__main__':
    unittest.main()
