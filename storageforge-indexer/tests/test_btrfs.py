"""btrfs beyond what df shows: nested subvolumes in scans, chunk allocation and device health from the scan and the
collector, and the upkeep tasks, run against a stand-in for btrfs. One test uses a real filesystem when it is on one."""
import datetime as dt
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from storageforge_index import changes, health, payloads, report
from storageforge_index.remote import MountInfo, find_command
from storageforge_index.scanner import ScanOptions, build_jobs, plan_mounts

from test_indexer import bash_fn
from test_tasks import Fleet

GIB = 2**30


def fs_node(line: str, mounts=None, parts=2):
    """A node with one btrfs filesystem, on one partition or as a pool of two."""
    disk = {'dev': 'sda', 'parts': [{'dev': 'sda1', 'fs': 'btrfs', 'uuid': 'u1', 'label': None, 'mount': '/data'}]}
    node = {'hostname': 'nas', 'disks': [disk], 'mounts': mounts or [], 'pools': []}
    if parts == 2:
        node['pools'].append({'name': 'pool', 'type': 'btrfs', 'uuid': 'u1', 'members': ['sda1', 'sdb1'], 'member_sizes': [GIB, GIB], 'mount': '/data'})
    payloads.apply_btrfs(node, line)
    return node


def usage(dev=1000, alloc=500, datat=450, datau=400, metat=40, metau=10, rsv=0.5, missing=0, op='none'):
    n = {k: int(v * GIB) for k, v in dict(dev=dev, alloc=alloc, datat=datat, datau=datau, metat=metat, metau=metau, rsv=rsv).items()}
    return ' '.join(f'{k}={v}' for k, v in n.items()) + f' missing={missing} op={op}'


class Walk(unittest.TestCase):
    def test_only_btrfs_crosses_subvolumes(self):
        self.assertIn('-xdev', find_command('/srv', [], [], nice=False))
        cmd = find_command('/srv', [], [], nice=False, btrfs=True)
        self.assertNotIn('-xdev', cmd)
        self.assertIn('-inum 256', cmd)
        self.assertIn('docker/btrfs', cmd)

    def test_subvolume_with_its_own_mount_is_not_walked_twice(self):
        mounts = [MountInfo('/mnt/top', '/dev/sdb1', 'btrfs', 'subvolid=5', '0:40', '/'),
                  MountInfo('/home', '/dev/sdb1[/@home]', 'btrfs', 'subvolid=257', '0:40', '/@home'),
                  MountInfo('/mnt/other', '/dev/sdc1', 'btrfs', 'subvolid=5', '0:41', '/')]
        jobs = {j.root: j for j in build_jobs(plan_mounts(mounts, ScanOptions()), ScanOptions())}
        self.assertEqual(set(jobs), {'/mnt/top', '/home', '/mnt/other'})
        self.assertIn('/mnt/top/@home', jobs['/mnt/top'].prune)
        self.assertNotIn('/mnt/top/@home', jobs['/mnt/other'].prune)

    def test_on_a_real_filesystem(self):
        here = Path(__file__).parent
        if shutil.which('btrfs') is None or subprocess.run(['stat', '-f', '-c', '%T', str(here)], capture_output=True, text=True).stdout.strip() != 'btrfs':
            self.skipTest('not on btrfs')
        top = Path(tempfile.mkdtemp(dir=here, prefix='.btrfs-walk-'))

        def b(*args):
            return subprocess.run(['btrfs', *args], capture_output=True).returncode == 0
        nested, snap = top / 'nested', top / 'snap'
        try:
            if not b('subvolume', 'create', str(nested)):
                self.skipTest('cannot create a subvolume here')
            (nested / 'kept').write_text('x')
            self.assertTrue(b('subvolume', 'snapshot', '-r', str(nested), str(snap)))
            out = subprocess.run(['bash', '-c', find_command(str(top), [], [], nice=False, btrfs=True)], capture_output=True).stdout
            names = {x.decode().removeprefix(str(top)) for x in out.split(b'\0') if x.startswith(str(top).encode())}
            self.assertIn('/nested/kept', names)
            self.assertNotIn('/snap/kept', names)
        finally:
            b('property', 'set', '-ts', str(snap), 'ro', 'false')
            for leftover in (snap / 'kept', nested / 'kept'):
                leftover.unlink(missing_ok=True)
            for sub in (snap, nested):
                if sub.exists():
                    os.rmdir(sub)
            shutil.rmtree(top)


class Sysfs(unittest.TestCase):
    def test_single_device_filesystem_is_tracked(self):
        node = fs_node(f'u1\tsingle,size_classes\tdup,size_classes\tdata\t{usage()}', parts=1)
        fs = node['btrfs_fs'][0]
        self.assertEqual((fs['name'], fs['pool'], fs['datas'], fs['metas']), ('data', None, ['single'], ['dup']))
        self.assertEqual(health.unallocated(fs), 500 * GIB)
        self.assertEqual(node['disks'][0]['parts'][0]['btrfs_profile'], 'single/dup')

    def test_a_scan_from_before_this_still_parses(self):
        fs = fs_node('u1\traid1\traid1\t')['btrfs_fs'][0]
        self.assertIsNone(health.unallocated(fs))
        self.assertEqual(health.problems(fs_node('u1\traid1\traid1\t'), dt.date(2026, 1, 1)), [])


class Problems(unittest.TestCase):
    def keys(self, extra, data='raid1', meta='raid1', mounts=None):
        node = fs_node(f'u1\t{data}\t{meta}\t\t{extra}', mounts)
        return {k: (lv, detail) for lv, k, _, detail in health.problems(node, dt.date(2026, 1, 1))}

    def test_healthy_says_nothing(self):
        self.assertEqual(self.keys(usage()), {})

    def test_missing_device(self):
        got = self.keys(usage(missing=1, dev=500, alloc=500))
        self.assertEqual(got['btrfs-missing:pool'][0], 'crit')
        self.assertNotIn('btrfs-unallocated:pool', got)       # its size is unknown, so free space can't be worked out

    def test_mixed_profiles_and_parity_metadata(self):
        got = self.keys(usage(), data='raid1,single', meta='raid6')
        self.assertEqual(got['btrfs-mixed:pool'][0], 'warn')
        self.assertIn('btrfs-meta-parity:pool', got)

    def test_no_unallocated_with_metadata_left_points_at_reclaim(self):
        lv, detail = self.keys(usage(alloc=999.5, datat=950, datau=500))['btrfs-unallocated:pool']
        self.assertEqual(lv, 'warn')
        self.assertIn('450.0 GiB is stuck', detail)

    def test_no_unallocated_and_no_metadata_is_critical(self):
        lv, detail = self.keys(usage(alloc=999.5, datat=950, datau=945, metat=10, metau=9.8))['btrfs-metadata:pool']
        self.assertEqual(lv, 'crit')
        self.assertIn('no space', detail)

    def test_quiet_while_a_balance_runs(self):
        self.assertEqual(self.keys(usage(alloc=999.5, op='balance')), {})

    def test_read_only_only_when_every_mount_is(self):
        rw = {'target': '/var', 'source': '/dev/sda1[/@var]', 'fstype': 'btrfs', 'options': 'rw,noatime'}
        ro = {'target': '/', 'source': '/dev/sda1[/@]', 'fstype': 'btrfs', 'options': 'ro,noatime'}
        self.assertNotIn('btrfs-ro:pool', self.keys(usage(), mounts=[ro, rw]))
        self.assertEqual(self.keys(usage(), mounts=[ro])['btrfs-ro:pool'][0], 'warn')


class Collector(unittest.TestCase):
    REPORT = """## at
1793000000
## stats /data
[/dev/sda1].write_io_errs    2
[/dev/sda1].read_io_errs     0
[/dev/sda1].corruption_errs  1
[devid:2].write_io_errs      4
## scrub /data
Scrub started:    Sun Oct  4 01:00:00 2026
Error summary:    no errors found
## snaps /data
2
## snaplist /data
288 2026-10-01 10:00:00
289 2026-10-30 10:00:00
## qgroup /data
Qgroupid    Referenced    Exclusive
--------    ----------    ---------
0/5              16384        16384
0/288          1048576         4096
0/289          1048576         8192
0/300         99999999     99999999
## compsize /data
TOTAL       50%      1000      2000      2000
"""

    def test_report(self):
        b = health.parse_report(self.REPORT)['btrfs']['/data']
        self.assertEqual(b['error_devices'], {'sda1': {'write': 2, 'corruption': 1}, 'devid:2': {'write': 4}})
        self.assertEqual(b['errors'], 7)
        self.assertEqual(b['newest_snapshot'], '2026-10-30 10:00:00')
        self.assertEqual(b['snapshot_exclusive'], 12288)
        self.assertEqual((b['disk_bytes'], b['uncompressed_bytes']), (1000, 2000))

    def test_repaired_and_unrepaired_scrubs_say_so(self):
        text = '## scrub /data\nScrub started:    Sun Oct  4 01:00:00 2026\nError summary:    csum=9\n  Corrected:      {}\n  Uncorrectable:  {}\n'
        node = fs_node(f'u1\tsingle\tdup\tdata\t{usage()}', [{'target': '/data', 'source': '/dev/sda1', 'fstype': 'btrfs', 'options': 'rw'}], parts=1)
        health.apply_report(node, health.parse_report(text.format(9, 0)))
        self.assertIn('all repaired', {k: d for _, k, _, d in health.problems(node, dt.date(2026, 10, 20))}['pool-errors:data'])
        health.apply_report(node, health.parse_report(text.format(7, 2)))
        self.assertIn('2 could not be repaired', {k: d for _, k, _, d in health.problems(node, dt.date(2026, 10, 20))}['pool-errors:data'])

    def test_a_single_device_gets_scrub_and_errors_too(self):
        node = fs_node(f'u1\tsingle\tdup\tdata\t{usage()}', [{'target': '/data', 'source': '/dev/sda1', 'fstype': 'btrfs', 'options': 'rw'}], parts=1)
        health.apply_report(node, health.parse_report(self.REPORT))
        got = {k: (lv, d) for lv, k, _, d in health.problems(node, dt.date(2026, 10, 20))}
        self.assertEqual(got['pool-errors:data'][0], 'crit')
        self.assertIn('sda1: 1 corruption, 2 write', got['pool-errors:data'][1])
        self.assertNotIn('scrub:data', got)

    def test_collector_is_valid_sh(self):
        self.assertEqual(subprocess.run(['sh', '-n'], input=health.COLLECTOR, text=True).returncode, 0)

    def test_report_table(self):
        node = fs_node(f'u1\tsingle\tdup\tdata\t{usage()}', [{'target': '/data', 'source': '/dev/sda1', 'fstype': 'btrfs', 'options': 'rw'}], parts=1)
        health.apply_report(node, health.parse_report(self.REPORT))
        text = '\n'.join(report._btrfs_section([node]))
        self.assertIn('500', text)
        self.assertIn('50%', text)
        self.assertIn('2 (', text)


class Upkeep(Fleet):
    def plan(self, kind, **params):
        return {'name': 'p', 'tasks': [{'type': kind, 'host': 'nas', 'params': params}]}

    def test_bad_device_names_are_refused(self):
        with self.assertRaises(ValueError):
            changes.normalize(self.plan('btrfs-replace', target='/mnt/pool', old='x; rm', device='/dev/sdz', confirm='/dev/sdz'))
        with self.assertRaises(ValueError):
            changes.normalize(self.plan('btrfs-remove', target='/mnt/pool', device='/dev/sdz', confirm='/dev/sdy'))

    def test_percent_over_100_fails_the_check(self):
        items = changes.check(self.conn, changes.normalize(self.plan('btrfs-reclaim', target='/', dusage='150')))['tasks'][0]['items']
        self.assertTrue(any(i['level'] == 'crit' and 'percentage' in i['text'] for i in items))


class Scripts(unittest.TestCase):
    PRELUDE = r"""
ok() { echo "ok: $*"; }; info() { echo "info: $*"; }; conflict() { echo "conflict: $*"; }; later() { echo "later: $*"; }
try() { "$@"; }; need() { :; }; act() { ((APPLY)) || { echo "would: $*"; return 1; }; }
dev_guard() { :; }; mountpoint() { [[ -e $MOUNTED ]]; }; stat() { echo btrfs; }; blkid() { :; }
"""
    BTRFS = r"""#!/bin/bash
echo "btrfs $*" >>"$LOG"
case "$1 $2" in
  "subvolume show") [ -d "${@: -1}" ] ;;
  "subvolume snapshot") cp -a "${@: -2:1}" "${@: -1}" ;;
  "subvolume list") cat "$NESTED" 2>/dev/null ;;
  "filesystem show") cat "$SHOW" 2>/dev/null ;;
  "qgroup show") [ -e "$QUOTA" ] ;;
esac
"""

    def setUp(self):
        self.t = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.t)
        (self.t / 'btrfs').write_text(self.BTRFS)
        (self.t / 'btrfs').chmod(0o755)
        self.source = Path(changes.__file__).read_text()
        self.log = self.t / 'log'

    def run_fn(self, name, *args, apply=True, **env):
        body = self.PRELUDE + bash_fn(self.source, name)
        call = ' '.join(f'"${i + 1}"' for i in range(len(args)))
        r = subprocess.run(['bash', '-c', f'{body}\n{name} {call} "" "" "" ""', 'x', *args], capture_output=True, text=True, env={
            **os.environ, 'PATH': f'{self.t}:{os.environ["PATH"]}', 'LOG': str(self.log), 'STATE': str(self.t / 'state'),
            'STAMP': '20260101-000000', 'APPLY': '1' if apply else '0', 'MOUNTED': str(self.t / 'mounted'), 'NESTED': str(self.t / 'nested'),
            'SHOW': str(self.t / 'show'), 'QUOTA': str(self.t / 'quota'), **env})
        self.assertEqual(r.stderr, '')
        return r.stdout

    def calls(self):
        return self.log.read_text() if self.log.exists() else ''

    def test_reclaim_only_once_and_never_when_running(self):
        (self.t / 'mounted').touch()
        self.assertIn('would: btrfs balance start --bg -dusage=50 -musage=30', self.run_fn('t_btrfs_reclaim', '/data', '', '', apply=False))
        self.assertNotIn('balance start', self.calls())
        self.run_fn('t_btrfs_reclaim', '/data', '20', '10')
        self.assertIn('balance start --bg -dusage=20 -musage=10 -- /data', self.calls())
        self.assertIn('started', self.run_fn('t_btrfs_reclaim', '/data', '20', '10'))
        self.assertEqual(self.calls().count('balance start'), 1)

    def test_replace(self):
        (self.t / 'mounted').touch()
        self.run_fn('t_btrfs_replace', '/data', '2', '/dev/sdz', '1')
        self.assertIn('replace start -f -- 2 /dev/sdz /data', self.calls())
        (self.t / 'show').write_text('\tdevid    2 size 1 used 1 path /dev/sdz\n')
        self.assertIn('is in the pool', self.run_fn('t_btrfs_replace', '/data', '2', '/dev/sdz', '1'))
        self.assertEqual(self.calls().count('replace start'), 1)

    def test_remove_looks_first(self):
        (self.t / 'mounted').touch()
        self.assertIn('is not in the pool', self.run_fn('t_btrfs_remove', '/data', '/dev/sdz'))
        self.assertIn('no device is missing', self.run_fn('t_btrfs_remove', '/data', 'missing'))
        self.assertNotIn('device remove', self.calls())
        (self.t / 'show').write_text('\tdevid    2 size 1 used 1 path /dev/sdz\n')
        self.run_fn('t_btrfs_remove', '/data', '2')
        self.run_fn('t_btrfs_remove', '/data', '/dev/sdz')
        self.assertIn('device remove -- 2 /data', self.calls())
        self.assertIn('device remove -- /dev/sdz /data', self.calls())

    def test_restore_keeps_the_current_copy(self):
        snap, live = self.t / 'snap', self.t / 'live'
        snap.mkdir()
        (snap / 'f').write_text('old')
        live.mkdir()
        (live / 'f').write_text('new')
        self.assertIn('would: restore', self.run_fn('t_subvolume_restore', str(snap), str(live), apply=False))
        self.assertEqual((live / 'f').read_text(), 'new')
        self.assertIn('restored', self.run_fn('t_subvolume_restore', str(snap), str(live)))
        self.assertEqual((live / 'f').read_text(), 'old')
        self.assertEqual((self.t / 'live.before-restore-20260101-000000/f').read_text(), 'new')
        self.assertEqual((snap / 'f').read_text(), 'old')
        (live / 'f').write_text('changed since')
        self.assertIn('ok: restored', self.run_fn('t_subvolume_restore', str(snap), str(live)))
        self.assertEqual((live / 'f').read_text(), 'changed since')

    def test_restore_refuses_mount_points_and_nested_subvolumes(self):
        snap, live = self.t / 'snap', self.t / 'live'
        snap.mkdir()
        live.mkdir()
        (self.t / 'mounted').touch()
        self.assertIn('conflict: ', self.run_fn('t_subvolume_restore', str(snap), str(live)))
        (self.t / 'mounted').unlink()
        (self.t / 'nested').write_text('ID 300 path x\n')
        self.assertIn('other subvolumes', self.run_fn('t_subvolume_restore', str(snap), str(live)))
        self.assertTrue(live.is_dir())
        self.assertFalse((self.t / 'live.restoring').exists())

    def test_quota_and_resize(self):
        (self.t / 'mounted').touch()
        self.run_fn('t_btrfs_quota', '/data')
        self.assertIn('quota enable -- /data', self.calls())
        (self.t / 'quota').touch()
        self.assertIn('quotas are on', self.run_fn('t_btrfs_quota', '/data'))
        self.run_fn('t_btrfs_resize', '/data', '2')
        self.assertIn('filesystem resize 2:max /data', self.calls())


del Fleet
if __name__ == '__main__':
    unittest.main()
