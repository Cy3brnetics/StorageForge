"""What a disaster drill found: losing two hosts, rebuilding them on new disks, and what the survivors have to cope with."""
import io
import json
import os
import shutil
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

try:
    import dbfactory
except ImportError:      # run as tests.test_x from the project folder
    from tests import dbfactory
from storageforge_index import blueprint, changes, fromdesign, hostconfig, jobs, jobscript, protection, reinstall, remote, scanner, shares, server, users


class Case(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db = dbfactory.make(self, Path(self.tmp) / 'index.db')
        self.conn = self.db.connect()
        self.db.migrate(self.conn)
        self.addCleanup(shutil.rmtree, self.tmp)
        self.addCleanup(self.conn.close)
        self.conn.execute("INSERT INTO hosts (hostname, ssh_host, ssh_user, inventory_json) VALUES ('nas', 'nas', 'scan', '{}')")


class RebuildVersion(Case):
    FULL = 'UUID=r / ext4 defaults 0 1\nUUID=a /data ext4 nofail 0 0\n10.0.0.2:/x /mnt/x nfs4 _netdev 0 0\n'
    BLANK = 'UUID=r / ext4 defaults 0 1\n'

    def scan(self, fstab, machine):
        self.conn.execute("UPDATE hosts SET machine_id = :m, inventory_json = :i WHERE hostname = 'nas'", {'m': machine, 'i': json.dumps({
            'collected_at': '2026-11-02T00:00:00+00:00', 'configs': {'files': {'/etc/fstab': fstab}, 'unreadable': []}})})
        return hostconfig.capture(self.conn, 'nas')['config_id']

    def test_a_scan_of_the_blank_install_is_not_what_a_rebuild_uses(self):
        old = self.scan(self.FULL, 'a' * 32)
        new = self.scan(self.BLANK, 'b' * 32)
        v = hostconfig.for_rebuild(self.conn, 'nas')
        self.assertEqual((v['config_id'], v['instead_of']['config_id']), (old, new))
        self.assertIn('from before the reinstall', reinstall.script(v))

    def test_part_way_through_a_rebuild_still_uses_the_old_version(self):
        old = self.scan(self.FULL, 'a' * 32)
        self.scan(self.BLANK + 'UUID=a /data ext4 nofail 0 0\n', 'b' * 32)
        self.assertEqual(hostconfig.for_rebuild(self.conn, 'nas')['config_id'], old)

    def test_a_finished_rebuild_is_the_newest_again(self):
        self.scan(self.FULL, 'a' * 32)
        new = self.scan(self.FULL.replace('UUID=a', 'UUID=c'), 'b' * 32)
        v = hostconfig.for_rebuild(self.conn, 'nas')
        self.assertEqual(v['config_id'], new)
        self.assertNotIn('instead_of', v)

    def test_removing_a_disk_on_the_same_machine_is_not_a_reinstall(self):
        self.scan(self.FULL, 'a' * 32)
        new = self.scan(self.FULL.replace('UUID=a /data ext4 nofail 0 0\n', ''), 'a' * 32)
        self.assertEqual(hostconfig.for_rebuild(self.conn, 'nas')['config_id'], new)


class DeadServer(unittest.TestCase):
    def test_the_scan_bounds_what_can_block_on_a_dead_mount(self):
        script = next(v for k, v in vars(remote).items() if isinstance(v, str) and "echo '@@findmnt'" in v)
        self.assertIn('bounded findmnt -J -b -l -o TARGET,SOURCE,FSTYPE,SIZE,USED', script)
        self.assertRegex(script, r'\|\| findmnt -J -b -l -o TARGET,SOURCE,FSTYPE,OPTIONS')    # no statfs in the fallback
        self.assertIn('bounded df -B1 -P 2>/dev/null || df -B1 -P -l', script)

    def test_local_sizes_come_from_df_when_findmnt_skipped_them(self):
        mounts = remote.parse_findmnt(json.dumps({'filesystems': [{'target': '/data', 'source': '/dev/sdb', 'fstype': 'ext4'},
                                                                  {'target': '/mnt/x', 'source': 'h:/x', 'fstype': 'nfs4'}]}))
        remote.fill_sizes(mounts, 'Filesystem 1-blocks Used Available Capacity Mounted on\n/dev/sdb 100 40 60 40% /data\n')
        self.assertEqual([(m.total, m.used) for m in mounts], [(100, 40), (None, None)])


class StalledWalk(unittest.TestCase):
    def test_a_silent_host_is_stopped_with_a_reason(self):
        job = mock.Mock(root='/', prune=[], plan=mock.Mock(mount_id=1, info=mock.Mock(fstype='ext4')), id=1, full=True)
        pool, opts = mock.Mock(), mock.Mock(exclude_names=[], nice=False, batch_size=10)
        # the sleep outlives the kill and keeps the pipe open, as an ssh master does
        t = mock.Mock(stream=lambda _: subprocess.Popen(['sh', '-c', 'sleep 40 & wait'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL))
        started = time.time()
        with mock.patch.dict('os.environ', {'STORAGEFORGE_SCAN_STALL_SECS': '5'}):
            res = scanner.stream_job(t, job, pool, opts)
        self.assertLess(time.time() - started, 30)
        self.assertIn('network mount', str(res.error))
        self.assertEqual(pool.send.call_args_list[-1].args[1][0], 'abort')       # nothing may be deleted

    def test_data_that_arrives_late_is_not_a_stall(self):
        r, w = os.pipe()
        self.addCleanup(os.close, w)
        killed = []
        guard = scanner.StallGuard(io.FileIO(r), lambda: killed.append(1), 5)
        threading.Timer(1, os.write, (w, b'x' * 10)).start()
        self.assertEqual(guard.read(10), b'x' * 10)
        self.assertEqual(killed, [])

    def test_waiting_on_a_silent_host_is_a_stall_though_the_pipe_stays_open(self):
        r, w = os.pipe()
        self.addCleanup(os.close, w)
        killed = []
        guard = scanner.StallGuard(io.FileIO(r), lambda: killed.append(1), 1)
        self.assertEqual(guard.read(10), b'')
        self.assertTrue(guard.stalled and killed)


class Clients(unittest.TestCase):
    def test_a_stale_mount_is_let_go_and_only_a_stale_one(self):
        text = next(v for k, v in vars(shares).items() if isinstance(v, str) and 'mount_share()' in v)
        body = text[text.index('mount_share()'):text.index('client_mount()')]
        self.assertIn('[[ $err == *[Ss]tale* ]] || return 1', body)
        self.assertLess(body.index('[[ $err =='), body.index('umount -l'))

    def test_automounts_let_go_when_idle_unless_the_design_says_otherwise(self):
        text = next(v for k, v in vars(shares).items() if isinstance(v, str) and 'mount_share()' in v)
        self.assertIn('$extra != *x-systemd.idle-timeout=*', text)


class Restore(unittest.TestCase):
    def test_a_sparse_file_stays_sparse(self):
        self.assertIn('--sparse -cf -', jobscript.SCRIPT if hasattr(jobscript, 'SCRIPT') else
                      next(v for v in vars(jobscript).values() if isinstance(v, str) and 'pack()' in v))


DISK = {'bus': 'VIRTIO', 'table': None, 'sizeBytes': 2 << 30}


class Designs(Case):
    def plan(self, design, have=None):
        with mock.patch.object(fromdesign, 'hosts', return_value=[{'name': 'nas', 'mounts': []}]), \
                mock.patch.object(fromdesign, 'find_host', return_value={'name': 'nas', 'mounts': []}), \
                mock.patch.object(fromdesign.blueprint, 'from_index', return_value=have or {
                    'devices': [{'dev': '/dev/vdb', 'sizeBytes': 2 << 30, 'partitions': []}, {'dev': '/dev/vdc', 'sizeBytes': 2 << 30, 'partitions': []}],
                    'pools': [], 'remotes': [], 'links': []}):
            return fromdesign.plan(self.conn, design)

    def raid1(self):
        subvols = [{'name': '@media', 'mount': '/data/media'}, {'name': '@snaps', 'mount': None}]
        return {'metadata': {'host': 'nas'}, 'links': [], 'remotes': [],
                'devices': [{**DISK, 'dev': '/dev/vdb', 'partitions': [{'id': 'vdb', 'fs': 'btrfs', 'label': 'sfdata', 'subvolumes': subvols,
                                                                        'options': ['compress=zstd', 'noatime', 'subvol=@media', 'subvolid=256']}]},
                            {**DISK, 'dev': '/dev/vdc', 'partitions': [{'id': 'vdc', 'fs': 'btrfs', 'label': 'sfdata'}]}],
                'pools': [{'name': 'sfdata', 'type': 'btrfs', 'level': 'raid1', 'metaLevel': 'raid1', 'members': ['vdb', 'vdc'], 'datasets': []}]}

    def test_a_multi_device_btrfs_is_built_in_order_as_one_filesystem(self):
        r = self.plan(self.raid1())
        self.assertEqual([t['type'] for t in r['tasks']], ['format', 'mount', 'btrfs-add', 'btrfs-balance', 'subvolume', 'subvolume', 'mount', 'unmount'])
        self.assertEqual(r['manual'], [])
        p = [t['params'] for t in r['tasks']]
        self.assertEqual((p[0]['device'], p[0]['label'], p[0]['confirm']), ('/dev/vdb', 'sfdata', ''))
        self.assertEqual((p[2]['device'], p[3]['data'], p[3]['metadata']), ('/dev/vdc', 'raid1', 'raid1'))
        self.assertEqual((p[6]['source'], p[6]['subvol'], p[6]['target']), ('LABEL=sfdata', '@media', '/data/media'))
        self.assertIn('compress=zstd', p[1]['options'])          # the first mount sets it for the whole filesystem

    def test_a_pool_that_exists_is_not_built_again(self):
        have = {'devices': [{'dev': '/dev/vdb', 'partitions': [{'id': 'vdb', 'fs': 'btrfs'}]}, {'dev': '/dev/vdc', 'partitions': [{'id': 'vdc', 'fs': 'btrfs'}]}],
                'pools': [{'name': 'sfdata', 'type': 'btrfs', 'level': 'raid1', 'metaLevel': 'raid1', 'members': ['vdb', 'vdc'], 'mount': None}], 'remotes': [], 'links': []}
        d = self.raid1()
        d['devices'][0]['partitions'][0]['subvolumes'] = []
        self.assertNotIn('format', [t['type'] for t in self.plan(d, have)['tasks']])

    def test_what_the_kernel_says_of_one_nfs_mount_is_no_setting(self):
        d = {'metadata': {'host': 'nas'}, 'devices': [], 'pools': [], 'links': [],
             'remotes': [{'protocol': 'NFSv4.2', 'endpoint': 'h:/x', 'mount': '/mnt/x', 'options': ['hard', 'clientaddr=10.0.0.1', 'addr=10.0.0.2']}]}
        self.assertEqual(self.plan(d)['tasks'][0]['params']['options'], 'hard,_netdev,nofail')

    def test_a_scan_records_zfs_properties_and_a_plan_restores_them(self):
        self.conn.execute("UPDATE hosts SET inventory_json = :i WHERE hostname = 'nas'", {'i': json.dumps({
            'zfs_props': 'tank\tcompression\tlz4\ntank\tatime\toff\ntank/media\trecordsize\t1M'})})
        bp = {'pools': [{'name': 'tank', 'type': 'zfs', 'datasets': [{'name': 'media', 'mount': '/tank/media'}]}]}
        got = blueprint._with_zfs_props(self.conn, 'nas', bp)['pools'][0]
        self.assertEqual((got['fsProperties'], got['datasets'][0]['recordsize']), ('atime=off,compression=lz4', '1M'))
        got.update(level='mirror', members=['vdb', 'vdc'], mount='/tank')
        r = self.plan({'metadata': {'host': 'nas'}, 'devices': [], 'remotes': [], 'links': [], 'pools': [got]})
        tasks = {t['type']: t['params'] for t in r['tasks']}
        self.assertEqual(tasks['zfs-pool']['fs_props'], 'atime=off,compression=lz4')
        self.assertEqual(tasks['zfs-dataset']['options'], 'recordsize=1M')


class PlanChecks(Case):
    def check(self, *tasks):
        lsblk = {'blockdevices': [{'name': n, 'path': f'/dev/{n}', 'type': 'disk', 'size': 2 << 30} for n in ('vda', 'vdb', 'vdc', 'vdd')]}
        self.conn.execute("UPDATE hosts SET inventory_json = :i WHERE hostname = 'nas'", {'i': json.dumps({'lsblk': lsblk})})
        plan = changes.normalize({'name': 't', 'tasks': [{'host': 'nas', 'type': k, 'params': p} for k, p in tasks]})
        with mock.patch.object(changes, 'hosts', return_value={'nas': {'name': 'nas', 'mounts': [], 'id': 1, 'inventory': {'lsblk': lsblk}}}):
            out = changes.check(self.conn, plan)
        return [i['text'] for t in out['tasks'] for i in t['items'] if i['level'] in ('crit', 'warn') and 'sdX names' not in i['text']]

    def test_a_pool_may_use_partitions_made_earlier_in_the_plan(self):
        add = {'name': 'z', 'size': '1G', 'fstype': '', 'label': '', 'flag': '', 'mkfs': ''}
        self.assertEqual(self.check(('partition-add', {**add, 'disk': '/dev/vdb', 'confirm': '/dev/vdb'}),
                                    ('partition-add', {**add, 'disk': '/dev/vdc', 'confirm': '/dev/vdc'}),
                                    ('zfs-pool', {'pool': 'tank', 'level': 'mirror', 'devices': '/dev/vdb1 /dev/vdc1', 'mountpoint': '/tank', 'confirm': '/dev/vdb1 /dev/vdc1',
                                                  'wipe': False, 'ashift': '12', 'pool_props': '', 'fs_props': ''})), [])

    def test_a_partition_nobody_makes_is_still_refused(self):
        got = self.check(('zfs-pool', {'pool': 'tank', 'level': 'stripe', 'devices': '/dev/vdb1', 'mountpoint': '', 'confirm': '/dev/vdb1', 'wipe': False, 'ashift': '12', 'pool_props': '', 'fs_props': ''}))
        self.assertIn('/dev/vdb1 was not seen by the last scan of nas', got)

    def test_a_balance_counts_a_device_added_earlier_in_the_plan(self):
        common = [('format', {'device': '/dev/vdb', 'fstype': 'btrfs', 'label': 'p', 'wipe': False, 'confirm': '/dev/vdb', 'mkfs': ''}),
                  ('mount', {'source': 'LABEL=p', 'subvol': '', 'target': '/mnt/p', 'fstype': 'btrfs', 'options': 'noatime,nofail', 'fsck_pass': ''})]
        balance = ('btrfs-balance', {'target': '/mnt/p', 'data': 'raid1', 'metadata': 'raid1'})
        self.assertIn('raid1 needs 2 devices; this filesystem has 1', self.check(*common, balance))
        self.assertEqual(self.check(*common, ('btrfs-add', {'device': '/dev/vdc', 'target': '/mnt/p', 'wipe': False, 'confirm': '/dev/vdc'}), balance), [])


class ReloadGuard(unittest.TestCase):
    def run_guard(self, stat_rc, fstype='nfs4'):
        from storageforge_index.scriptkit import HELPERS
        with tempfile.NamedTemporaryFile('w', suffix='.mounts') as f:
            f.write(f'h:/x /mnt/my\\040share {fstype} rw 0 0\n')
            f.flush()
            fn = HELPERS[HELPERS.index('reload_systemd()'):].split('\n}\n')[0].replace('/proc/self/mounts', f.name) + '\n}\n'
            script = (f'conflict() {{ echo "conflict $*"; }}; timeout() {{ echo "probed ${{@: -1}}"; return {stat_rc}; }}; '
                      f'systemctl() {{ echo "reloaded"; }}\n{fn}reload_systemd; echo rc=$?')
            return subprocess.run(['bash', '-c', script], capture_output=True, text=True).stdout

    def test_a_dead_mount_stops_the_reload_and_says_why(self):
        out = self.run_guard(124)
        self.assertIn('conflict /mnt/my share is not answering', out)
        self.assertNotIn('reloaded', out)
        self.assertIn('rc=1', out)

    def test_a_stale_or_healthy_mount_lets_it_reload(self):
        for rc in (0, 1):
            self.assertIn('reloaded', self.run_guard(rc))

    def test_local_filesystems_are_not_probed(self):
        out = self.run_guard(124, 'xfs')
        self.assertNotIn('probed', out)
        self.assertIn('reloaded', out)


class OwnFile(unittest.TestCase):
    """A share's config file reported as deployed came back empty when the server lost power 40 seconds later."""
    def run_it(self, path, content, stubs=''):
        body = shares.SHARES_BODY_3
        fn = body[body.index('own_file()'):].split('\n}\n')[0] + '\n}\n'
        script = (f'APPLY=1; STAMP=x; ok() {{ echo "ok $*"; }}; doing() {{ echo "doing $*"; }}; conflict() {{ echo "conflict $*"; }}; missing() {{ echo "missing $*"; }}\n'
                  f'backup() {{ :; }}; durable() {{ echo "durable $*"; }}\n{stubs}\n{fn}own_file "$1" "$2"; echo rc=$?')
        return subprocess.run(['bash', '-c', script, 'x', str(path), content], capture_output=True, text=True).stdout

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.path = Path(self.tmp) / 'a.exports'

    def test_it_reaches_the_disk_before_it_takes_the_old_files_place(self):
        out = self.run_it(self.path, 'new')
        self.assertLess(out.index('durable ' + str(self.path) + '.storageforge-new'), out.index('durable ' + self.tmp + '\n'))
        self.assertEqual(self.path.read_text(), 'new\n')
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o644)
        self.assertEqual([x.name for x in Path(self.tmp).iterdir()], ['a.exports'])
        self.assertIn('rc=0', out)

    def test_a_failed_write_keeps_the_old_file_and_says_so(self):
        self.path.write_text('old\n')
        out = self.run_it(self.path, 'new', 'mv() { return 1; }')
        self.assertEqual(self.path.read_text(), 'old\n')
        self.assertIn('conflict could not write', out)
        self.assertIn('rc=1', out)
        self.assertEqual([x.name for x in Path(self.tmp).iterdir()], ['a.exports'])

    def test_the_helper_is_in_every_script_that_uses_it(self):
        from storageforge_index.scriptkit import HELPERS
        self.assertIn('durable()', HELPERS)
        self.assertIn('durable "$p"', jobs.HOST_FUNCS)


class PlanScript(unittest.TestCase):
    def report(self, *call):
        head = next(v for v in vars(changes).values() if isinstance(v, str) and 'dev_guard()' in v)
        funcs = head[head.index('dev_guard()'):].split('\n}\n')[0] + '\n}\n'
        script = ('APPLY=0; later() { echo "later $*"; }; conflict() { echo "conflict $*"; }; lsblk() { :; }\n' + funcs
                  + 'PLANNED_PARTS=" /dev/nope1"\n' + ' ; '.join(call))
        return subprocess.run(['bash', '-c', script], capture_output=True, text=True).stdout

    def test_a_report_accepts_only_partitions_an_earlier_task_makes(self):
        self.assertIn('later /dev/nope1 is made by an earlier task', self.report('dev_guard /dev/nope1'))
        self.assertIn('conflict /dev/nope2 is not a block device', self.report('dev_guard /dev/nope2'))


class SaveDesign(Case):
    def test_a_design_as_loaded_can_be_saved_with_jobs_deployed(self):
        users.create(self.conn, 'alice', 'a long enough password')
        client = server.create_app(server.App(self.db), 's' * 48).test_client()
        client.post('/api/login', json={'username': 'alice', 'password': 'a long enough password'})
        design = {'apiVersion': 'storageforge/v1', 'kind': 'StorageBlueprint', 'metadata': {'host': 'nas'}, 'devices': [], 'pools': [],
                  'protection': [{'node': 'n', 'dataset': 'd', 'sync': 'typed', 'hand': {'sync': 'typed'},
                                  'deployed': ['rsnapshot nas:/a -> b:/c'], 'backup': {'target': 'job'}}]}
        r = client.put('/api/planner/design', json=design)
        self.assertEqual(r.status_code, 200, r.json)
        saved = client.get('/api/planner/design?host=nas&source=saved').json['blueprint']['protection'][0]
        self.assertEqual(saved['sync'], 'typed')
        self.assertNotIn('->', json.dumps(protection.as_typed([saved])))


if __name__ == '__main__':
    unittest.main()
