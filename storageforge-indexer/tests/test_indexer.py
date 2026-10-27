"""Run with: python3 -m unittest discover -s tests -v"""
import io
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from storageforge_index.capacity import TiB, parse_size, pool_capacity
from storageforge_index.db import Database, MassDeleteRefused
from storageforge_index.payloads import (apply_df, apply_fstab, apply_lvs, apply_zpool_status, load_structured, lvm_level,
                                         node_from_blueprint, node_from_lsblk, parse_df, parse_fstab, parse_zpool_status)
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

    def test_denied_lines_and_readonly_tools(self):
        from storageforge_index.remote import DENIED
        self.assertEqual(DENIED.match("find: '/srv/it's': Permission denied").group(1), "/srv/it's")
        self.assertEqual(DENIED.match('find: ‘/root’: Permission denied').group(1), '/root')
        self.assertIsNone(DENIED.match("find: '/x': No such file or directory"))
        cmd = find_command('/srv', [], [], nice=False)
        self.assertIn('/usr/local/lib/storageforge/find / -maxdepth 0', cmd)   # used only when it actually runs
        self.assertIn('|| echo find', cmd)

    def test_access_scripts(self):
        from storageforge_index import access
        s = access.setup_script('scan')
        self.assertIn('setcap cap_dac_read_search+ep', s)
        self.assertIn('-m 0750', s)
        self.assertIn('runuser -u "$U"', s)
        self.assertIn('rm -rf "$D"', s)                                      # a setup that cannot work leaves nothing
        with self.assertRaises(ValueError):
            access.setup_script('x; rm -rf /')
        self.assertIn('groupdel storageforge-scan', access.remove_script('scan'))

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


class Shares(unittest.TestCase):
    def test_nfs_exports_and_etab(self):
        from storageforge_index.payloads import parse_nfs_exports
        e = parse_nfs_exports('# comment\n/srv/media  10.42.0.0/24(rw,sync) 100.64.0.0/10(ro)\n'
                              '"/srv/with space" *(ro)\n/srv/long \\\n    host1(rw)\n')
        self.assertEqual([(x['path'], x['clients'], x['options']) for x in e],
                         [('/srv/media', '10.42.0.0/24 100.64.0.0/10', 'rw,sync'), ('/srv/with space', '*', 'ro'),
                          ('/srv/long', 'host1', 'rw')])
        etab = parse_nfs_exports('/mnt/ssd/shared\t10.42.0.11(rw,sync,wdelay)\n/mnt/ssd/shared\t10.42.0.12(rw,sync)\n')
        self.assertEqual([(x['path'], x['clients']) for x in etab], [('/mnt/ssd/shared', '10.42.0.11 10.42.0.12')])

    def test_smb_conf(self):
        from storageforge_index.payloads import parse_smb_conf
        s = parse_smb_conf('[global]\n  workgroup = HOME\n[homes]\n  browseable = no\n'
                           '[Photos]\n  path = /mnt/photos/\n  read only = yes\n  valid users = @family\n'
                           '; [old]\n[printers]\n  path = /var/spool\n[nopath]\n  comment = x\n')
        self.assertEqual(s, [{'protocol': 'SMB', 'name': 'Photos', 'path': '/mnt/photos', 'clients': '@family', 'options': 'ro'}])


class LvmRaid(unittest.TestCase):
    """thinkingrock01: an LVM raid5 LV across three whole disks, plus plain LVs on the boot NVMe."""
    G = 931.5 * 2**30

    def lsblk(self):
        lv = {'name': 'vg_data-lv_data01', 'type': 'lvm', 'size': int(2 * self.G), 'fstype': 'ext4', 'mountpoint': '/mnt/data01'}
        def leg(disk, i):
            return {'name': disk, 'type': 'disk', 'size': int(self.G + 4 * 2**20), 'rota': True, 'children': [
                {'name': f'vg_data-lv_data01_rmeta_{i}', 'type': 'lvm', 'size': 4 * 2**20, 'children': [lv]},
                {'name': f'vg_data-lv_data01_rimage_{i}', 'type': 'lvm', 'size': int(self.G), 'children': [lv]}]}
        nvme = {'name': 'nvme0n1', 'type': 'disk', 'tran': 'nvme', 'size': 500 * 10**9, 'children': [
            {'name': 'nvme0n1p3', 'type': 'part', 'size': 498 * 10**9, 'fstype': 'LVM2_member', 'children': [
                {'name': 'rl-root', 'type': 'lvm', 'size': 70 * 2**30, 'fstype': 'xfs', 'mountpoint': '/'},
                {'name': 'rl-swap', 'type': 'lvm', 'size': 16 * 2**30, 'fstype': 'swap', 'mountpoint': '[SWAP]'},
                {'name': 'rl-home', 'type': 'lvm', 'size': 378 * 2**30, 'fstype': 'xfs', 'mountpoint': '/home'}]}]}
        return {'blockdevices': [leg('sdd', 0), leg('sde', 1), leg('sdf', 2), nvme]}

    def test_lsblk_legs_become_a_raid5_pool(self):
        node = node_from_lsblk(self.lsblk(), 'thinkingrock01')
        pool = node['pools'][0]
        self.assertEqual((pool['name'], pool['type'], pool['level'], pool['vg'], pool['lv']),
                         ('vg_data-lv_data01', 'lvm', 'raid5', 'vg_data', 'lv_data01'))
        self.assertEqual(pool['members'], ['sdd', 'sde', 'sdf'])
        self.assertEqual((pool['mount'], pool['fs']), ('/mnt/data01', 'ext4'))
        self.assertIn('mapper/vg_data-lv_data01', pool['aliases'])
        self.assertEqual(pool['cap']['tolerance'], 1)
        self.assertAlmostEqual(pool['cap']['usable'] + pool['cap']['fs_reserve'], 2 * self.G, delta=2**20)
        self.assertEqual({d['dev']: d['member'] for d in node['disks']},
                         {'sdd': 'vg_data-lv_data01', 'sde': 'vg_data-lv_data01', 'sdf': 'vg_data-lv_data01', 'nvme0n1': None})

    def test_plain_lvs_group_into_their_volume_group(self):
        node = node_from_lsblk(self.lsblk(), 'thinkingrock01')
        vg = next(p for p in node['pools'] if p['name'] == 'rl')
        self.assertEqual((vg['type'], vg['level'], vg['lv'], vg['members']), ('lvm', 'linear', None, ['nvme0n1p3']))
        self.assertEqual([(d['name'], d['mount'], d['props']['fs']) for d in vg['datasets']],
                         [('rl/root', '/', 'xfs'), ('rl/home', '/home', 'xfs'), ('rl/swap', None, 'swap')])
        self.assertIn('mapper/rl-home', vg['aliases'])
        self.assertEqual(node['disks'][3]['parts'][0]['member'], 'rl')
        self.assertEqual(len(node['pools']), 2)                     # the raid LV is not counted again as a plain LV

    def test_level_from_leg_count(self):
        G = self.G
        self.assertEqual(lvm_level(2, G, G)[0], 'raid1')
        self.assertEqual(lvm_level(3, G, 3 * G)[0], 'raid0')
        self.assertEqual(lvm_level(5, G, 3 * G)[0], 'raid6')
        self.assertEqual(lvm_level(6, G, 3 * G)[0], 'raid10')
        self.assertIn('raid6', lvm_level(4, G, 2 * G)[1])          # ambiguous, and it says so

    def test_lvs_overrides_the_guess(self):
        node = node_from_lsblk(self.lsblk(), 'thinkingrock01')
        apply_lvs(node, '{"report": [{"lv": [{"vg_name": "vg_data", "lv_name": "lv_data01", "segtype": "raid4", '
                        '"lv_health_status": "partial", "copy_percent": "41.50"}]}]}')
        pool = node['pools'][0]
        self.assertEqual((pool['level'], pool['health'], pool['scan']), ('raid4', 'partial', 'resyncing 41.50%'))


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

    @unittest.skipIf(os.geteuid() == 0, 'root reads every folder')
    def test_unreadable_folders_and_duplicate_folders(self):
        from storageforge_index import access
        from storageforge_index.folders import duplicate_folders
        locked = self.tree / 'locked'
        (locked / 'inner').mkdir(parents=True)
        for root in (self.tree / 'photos' / '2019', self.tree / 'backup' / '2019 copy'):   # a renamed copy
            (root / 'raw').mkdir(parents=True)
            for i, n in enumerate(('a.jpg', 'b.jpg', 'c.jpg')):
                (root / n).write_bytes(b'x' * (1000 + i))
            (root / 'raw' / 'a.cr2').write_bytes(b'y' * 5000)
        (self.tree / 'photos' / '2020').mkdir()
        (self.tree / 'photos' / '2020' / 'a.jpg').write_bytes(b'x' * 1000)          # same name, different set
        locked.chmod(0)
        try:
            r = self.scan()
        finally:
            locked.chmod(0o755)
        self.assertEqual(r['status'], 'ok')                                       # unreadable is partial, not failed
        conn = self.db.connect()
        try:
            [st] = access.status(conn)
            self.assertEqual([d['path'] for d in st['denied']], [str(locked)])
            self.assertEqual((st['denied_total'], st['access']), (1, 'user'))
            dup = duplicate_folders(conn, min_files=3, min_bytes=0, include_system=True)   # the tree is under /tmp
        finally:
            conn.close()
        [g] = dup['groups']                                                       # raw/ is not listed again
        self.assertEqual(sorted(c['path'] for c in g['copies']),
                         [str(self.tree / 'backup' / '2019 copy'), str(self.tree / 'photos' / '2019')])
        self.assertEqual((g['files'], g['bytes'], g['same_name'], g['scope']), (4, 3003 + 5000, False, 'same host'))

    def test_second_scan_of_a_host_is_refused_while_one_runs(self):
        from storageforge_index.db import ScanBusy
        self.scan()
        conn = self.db.connect()
        try:
            host_id = conn.scalar('SELECT host_id FROM hosts')
            self.db.begin_scan(conn, host_id)                         # a scan left "running"
            with self.assertRaises(ScanBusy):
                self.scan()
            self.assertIsInstance(self.db.begin_scan(conn, host_id, stale_after=-1), int)   # a dead run expires
        finally:
            conn.close()

    def test_move_plan_check_and_script(self):
        import subprocess
        from storageforge_index import moves
        self.scan()
        conn = self.db.connect()
        try:
            host = conn.scalar('SELECT hostname FROM hosts')
            br = moves.browse(conn, host, str(self.tree))
            self.assertEqual({d['name'] for d in br['dirs']}, {'a', 'b'})
            self.assertEqual(next(d for d in br['dirs'] if d['name'] == 'a')['entries'], 1200)
            plan = moves.normalize({'name': 'Test plan', 'steps': [
                {'method': 'copy', 'src': {'host': host, 'path': str(self.tree / 'a')}, 'dst': {'host': host, 'path': str(self.tree / 'c')}},
                {'method': 'copy', 'src': {'host': host, 'path': str(self.tree)}, 'dst': {'host': host, 'path': str(self.tree / 'inside')}},
                {'method': 'move', 'src': {'host': 'nowhere', 'path': '/x'}, 'dst': {'host': host, 'path': '/y'}}]})
            c = moves.check(conn, plan)
            texts = [[(it['level'], it['text']) for it in st['items']] for st in c['steps']]
            self.assertIn(('ok', '1,200 files, 3.6 KiB to transfer'), texts[0])
            self.assertTrue(any(l == 'crit' and 'overlap' in t for l, t in texts[1]))
            self.assertTrue(any(l == 'crit' and 'nowhere' in t for l, t in texts[2]))
            sh = self.tmp / 'plan.sh'
            sh.write_text(moves.script(conn, plan))
            self.assertEqual(subprocess.run(['bash', '-n', str(sh)]).returncode, 0)
            pid = moves.save_plan(conn, plan, 'test')
            self.assertEqual(moves.get_plan(conn, pid)['steps'][0]['src']['path'], str(self.tree / 'a'))
            with self.assertRaises(ValueError):
                moves.save_plan(conn, {'name': 'test PLAN', 'steps': []}, 'test')        # names are unique
        finally:
            conn.close()
        for bad in ({'name': ''}, {'name': 'x', 'steps': [{'src': {'host': 'h', 'path': 'rel/path'}, 'dst': {'host': 'h', 'path': '/d'}}]},
                    {'name': 'x', 'steps': [{'src': {'host': 'h', 'path': '/a/../b'}, 'dst': {'host': 'h', 'path': '/d'}}]},
                    {'name': 'x', 'steps': [{'method': 'wipe', 'src': {'host': 'h', 'path': '/a'}, 'dst': {'host': 'h', 'path': '/d'}}]}):
            with self.assertRaises(ValueError):
                moves.normalize(bad)

    @unittest.skipUnless(shutil.which('git'), 'needs git')
    def test_git_repositories_and_copies(self):
        import subprocess
        from storageforge_index import gitrepos
        g = lambda *a, cwd=None, when='2026-10-01T10:00:00': subprocess.run(
            ['git', *a], cwd=cwd, check=True, capture_output=True,
            env={**os.environ, 'GIT_AUTHOR_NAME': 't', 'GIT_AUTHOR_EMAIL': 't@x', 'GIT_COMMITTER_NAME': 't',
                 'GIT_COMMITTER_EMAIL': 't@x', 'GIT_COMMITTER_DATE': when, 'GIT_AUTHOR_DATE': when})
        shutil.rmtree(self.tree / 'b' / '.git')
        work = self.tree / 'proj'
        work.mkdir()
        g('init', '-q', '-b', 'main', cwd=work)
        (work / 'x.txt').write_text('1')
        g('add', '.', cwd=work); g('commit', '-qm', 'first', cwd=work)
        g('clone', '-q', '--mirror', str(work), str(self.tree / 'archive' / 'proj.git'))
        (work / 'x.txt').write_text('2')
        g('commit', '-qam', 'second', cwd=work, when='2026-10-02T10:00:00')   # the archive is now a commit behind
        (work / 'x.txt').write_text('3')                            # and there is an uncommitted change
        other = self.tree / 'other'
        other.mkdir(); g('init', '-q', cwd=other)                   # no commits: no root, a single copy
        r = self.scan()
        self.assertEqual(r['status'], 'ok')
        conn = self.db.connect()
        try:
            repos = {x['path'].replace(str(self.tree), ''): x for x in gitrepos.listing(conn)['repos']}
        finally:
            conn.close()
        self.assertEqual(set(repos), {'/proj', '/archive/proj.git', '/other'})
        w, a = repos['/proj'], repos['/archive/proj.git']
        self.assertEqual((w['bare'], w['branch'], w['dirty'], w['head_subject']), (False, 'main', 1, 'second'))
        self.assertEqual((a['bare'], a['head_subject'], a['name']), (True, 'first', 'proj'))
        self.assertEqual(w['root_commit'], a['root_commit'])
        self.assertEqual([c['path'] for c in w['copies']], [str(self.tree / 'archive' / 'proj.git')])
        self.assertEqual((w['state'], a['state']), ('uncommitted', 'behind'))
        self.assertEqual(repos['/other']['state'], 'single copy')

    def test_cold_folders(self):
        import time
        from storageforge_index.folders import cold_folders
        old = time.time() - 3 * 365 * 86400
        (self.tree / 'archive' / 'inner').mkdir(parents=True)
        for i in range(3):
            f = self.tree / 'archive' / 'inner' / f'f{i}.bin'
            f.write_bytes(b'x' * 1000)
            os.utime(f, (old, old))
        self.scan()
        conn = self.db.connect()
        try:
            r = cold_folders(conn, min_bytes=0, include_system=True)   # the tree is under /tmp
        finally:
            conn.close()
        self.assertEqual([f['path'] for f in r['folders']], [str(self.tree / 'archive')])   # outermost cold folder only
        self.assertEqual((r['folders'][0]['files'], r['folders'][0]['bytes']), (3, 3000))

    def test_scan_search_and_incremental_diff(self):
        first = self.scan()
        self.assertEqual(first['status'], 'ok')
        self.assertEqual(first['entries'], 1 + 2 + 1200 + 1 + 1)   # root, a, b, images, notes, b/.git (its contents pruned)
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

    def test_symlinks_resolve_through_symlinked_parents(self):
        from storageforge_index.db import Database as _D
        from storageforge_index.payloads import node_from_index
        t = self.tree
        (t / 'usr' / 'lib').mkdir(parents=True)
        (t / 'usr' / 'lib' / 'thing.so').write_text('x')
        os.symlink('usr/lib', t / 'lib')                                 # usr-merge style parent link
        os.symlink(str(t / 'lib' / 'thing.so'), t / 'via-parent')        # resolves only through /lib → usr/lib
        os.symlink(str(t / 'lib' / 'missing.so'), t / 'dead')
        os.symlink('loop-b', t / 'loop-a')
        os.symlink('loop-a', t / 'loop-b')
        res = self.scan()
        conn = self.db.connect()
        try:
            node = node_from_index(conn, res['host'])
        finally:
            conn.close()
        listed = {l['path']: l for l in node['links'] if l.get('from_index')}
        self.assertNotIn(str(t / 'via-parent'), listed)                 # healthy, same mount: not reported
        self.assertNotIn(str(t / 'lib'), listed)
        self.assertIs(listed[str(t / 'dead')]['exists'], False)
        self.assertEqual(listed[str(t / 'loop-a')].get('note'), 'ELOOP')

    def test_canonical_and_system_links(self):
        from storageforge_index.payloads import canonical, is_system_link
        links = {'/lib': ('usr/lib', '/'), '/etc/alternatives/editor': ('/usr/bin/vim', '/'), '/a': ('b', '/'), '/b': ('/a', '/')}
        self.assertEqual(canonical('/lib/systemd/system/x.service', links), ('/usr/lib/systemd/system/x.service', False))
        self.assertEqual(canonical('/etc/alternatives/editor', links), ('/usr/bin/vim', False))
        self.assertEqual(canonical('/usr/lib/../share', links), ('/usr/share', False))
        self.assertTrue(canonical('/a', links)[1])
        for p in ('/etc/alternatives/editor', '/etc/systemd/system/multi-user.target.wants/ssh.service',
                  '/lib', '/usr/bin/python3', '/etc/localtime'):
            self.assertTrue(is_system_link(p), p)
        for p in ('/var/media', '/home/ops/Archive', '/srv/vm-images', '/etc-data/x'):
            self.assertFalse(is_system_link(p), p)

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
