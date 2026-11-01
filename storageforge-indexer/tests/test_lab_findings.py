"""Bugs the KVM lab found: each script is run against stand-ins for the commands it calls."""
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from storageforge_index import alerts, changes, jobscript, reinstall, scriptkit, shares
from storageforge_index.remote import MountInfo, apply_mergerfs
from storageforge_index.scanner import ScanOptions, plan_mounts, skip_reason

from test_tasks import Fleet

KIT = r"""
APPLY=${APPLY:-1} CUR_DESTRUCTIVE=0 DESTRUCTIVE=0
ok() { echo "ok $*"; }; missing() { echo "missing $*"; }; conflict() { echo "conflict $*"; }; doing() { echo "doing $*"; }; later() { echo "later $*"; }
need() { :; }; try() { "$@" || { conflict "failed: $*"; return 1; }; }
act() { if ((!APPLY)); then missing "would: $*"; return 1; fi; doing "$*"; }
pm() { echo "${STUB_PM:-apt-get}"; }; install_pkg() { echo "$2" >>"$STUB_DIR/installed"; }
"""


def functions(text, *names):
    return ''.join(re.search(rf'^{n}\(\) .*?^}}\n|^{n}\(\) .*\}}\n', text, re.M | re.S).group(0) for n in names)


class Scripted(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir)
        self.bin = self.dir / 'bin'
        self.bin.mkdir()

    def stub(self, name, body):
        (self.bin / name).write_text(f'#!/bin/bash\n{body}\n')
        (self.bin / name).chmod(0o755)

    def run_bash(self, code, **env):
        return subprocess.run(['bash', '-c', 'set -euo pipefail\n' + KIT + code], capture_output=True, text=True, timeout=30,
                              env={**os.environ, 'PATH': f'{self.bin}:{os.environ["PATH"]}', 'STUB_DIR': str(self.dir), **env})

    def log(self):
        p = self.dir / 'log'
        return p.read_text() if p.exists() else ''


class Convert(Scripted):
    GIB = 2**30

    def usage(self, *free):
        return ''.join(f'/dev/vd{i}, ID: {i}\n   Device size: {2 * self.GIB}\n   Device slack: 0\n   Unallocated: {f}\n' for i, f in enumerate(free))

    def btrfs(self, before, after=None):
        """before: device usage until a reclaim has run, then after."""
        (self.dir / 'before').write_text(before)
        (self.dir / 'after').write_text(after or before)
        self.stub('btrfs', r'''echo "$*" >>"$STUB_DIR/log"
case "$1 $2" in
  "filesystem df") echo 'Data, raid1c3: total=1G, used=1G'; echo 'Metadata, raid1c3: total=1G, used=1G' ;;
  "device usage") if grep -q dusage "$STUB_DIR/log"; then cat "$STUB_DIR/after"; else cat "$STUB_DIR/before"; fi ;;
  "balance status") echo 'No balance found' ;;
esac''')

    def convert(self, **env):
        body = functions(changes.CHANGE_BODY_3, 'btrfs_room', 'profile_devices', 't_btrfs_balance')
        return self.run_bash(body + 't_btrfs_balance /mnt/p raid1 raid1 || echo "rc=$?"\n', **env)

    def test_refuses_when_reclaiming_frees_too_little(self):
        self.btrfs(self.usage(1024, 1024, 1024))
        r = self.convert()
        self.assertIn('not converted', r.stdout)
        self.assertIn('rc=1', r.stdout)
        self.assertNotIn('dconvert', self.log())

    def test_reclaims_first_when_that_makes_room(self):
        self.btrfs(self.usage(1024, 1024, 1024), self.usage(self.GIB, self.GIB, 1024))
        r = self.convert()
        self.assertNotIn('not converted', r.stdout)
        log = self.log()
        self.assertLess(log.index('dusage'), log.index('dconvert=raid1'))

    def test_counts_only_devices_with_room(self):
        self.btrfs(self.usage(self.GIB, 1024, 1024))        # raid1 needs two
        self.assertIn('not converted', self.convert().stdout)

    def test_room_goes_straight_to_converting(self):
        self.btrfs(self.usage(self.GIB, self.GIB, self.GIB))
        self.convert()
        self.assertNotIn('dusage', self.log())
        self.assertIn('-dconvert=raid1 -mconvert=raid1 -- /mnt/p', self.log())

    def test_report_mode_changes_nothing(self):
        self.btrfs(self.usage(1024, 1024, 1024))
        r = self.convert(APPLY='0')
        self.assertIn('would: reclaim', r.stdout)
        self.assertNotIn('balance start', self.log())

    def test_an_old_btrfs_that_says_nothing_is_not_refused(self):
        self.btrfs('')
        self.convert()
        self.assertIn('dconvert', self.log())

    def test_the_ansible_step_refuses_with_the_same_count(self):
        self.assertIn(changes.BTRFS_ROOM_AWK, changes.CHANGE_BODY_3)
        step = changes._ansible_task({'type': 'btrfs-balance', 'title': 't', 'params': {'target': '/mnt/my pool', 'data': 'raid1', 'metadata': 'raid1'}}, None)
        cmd = step['ansible.builtin.shell']['cmd']
        self.btrfs(self.usage(1024, 1024, 1024))
        r = subprocess.run(['bash', '-c', cmd], capture_output=True, text=True, env={**os.environ, 'PATH': f'{self.bin}:{os.environ["PATH"]}', 'STUB_DIR': str(self.dir)})
        self.assertEqual(r.returncode, 1)
        self.assertIn('not converted', r.stderr)
        self.assertNotIn('dconvert', self.log())
        self.btrfs(self.usage(self.GIB, self.GIB, self.GIB))
        r = subprocess.run(['bash', '-c', cmd], capture_output=True, text=True, env={**os.environ, 'PATH': f'{self.bin}:{os.environ["PATH"]}', 'STUB_DIR': str(self.dir)})
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('-dconvert=raid1 -mconvert=raid1 -- /mnt/my pool', self.log())


class ConvertCheck(unittest.TestCase):
    def test_unallocated_comes_from_the_scan(self):
        host = changes.Host.__new__(changes.Host)
        host.mounted = {'/mnt/p': {'source': '/dev/vdb'}}
        host.node = {'btrfs_fs': [{'name': 'p', 'members': ['vdb', 'vdc'], 'dev': 4 * 2**30, 'alloc': 4 * 2**30 - 1024, 'missing': 0}]}
        self.assertEqual(host.unallocated('/mnt/p'), 1024)
        host.mounted = {}
        self.assertIsNone(host.unallocated('/mnt/p'))


class ShareScript(Fleet):
    def test_a_share_script_defines_the_module_install(self):
        shares.save_export(self.db, self.conn, 'nas', {'protocol': 'NFS', 'path': '/mnt/pool/photos',
                                                       'rules': [{'clients': 'pc', 'options': 'rw'}]}, None, 'test')
        text = shares.script(self.conn, 'nas')
        self.assertEqual(text.count('cifs_kernel() {'), 1)
        self.assertEqual(subprocess.run(['bash', '-n'], input=text, text=True).returncode, 0)


class DiskAlerts(Fleet):
    def test_btrfs_raid_is_as_full_as_df_says(self):
        """df: 850 used, 8 available, 99%. Against the raw total of 1000 that reads 85%."""
        gib = 2**30
        self.conn.execute('UPDATE mounts SET used_bytes = :u, total_bytes = :t WHERE mount_point = :m', {'u': 850 * gib, 't': 1000 * gib, 'm': '/mnt/backup'})
        df = f'Filesystem 1-blocks Used Available Capacity Mounted on\n/dev/vdb {1000 * gib} {850 * gib} {8 * gib} 99% /mnt/backup\n'
        self.conn.execute("UPDATE hosts SET inventory_json = :i WHERE hostname = 'nas'", {'i': json.dumps({'df': df})})
        now = alerts.scan_problems(self.conn)
        self.assertIn('99%', now['disk-crit:nas:/mnt/backup'][2])
        self.assertIn('8.0 GiB free', now['disk-crit:nas:/mnt/backup'][3])


class ZfsSet(Scripted):
    def test_set_passes_no_double_dash(self):
        """Before OpenZFS 2.2, zfs set takes -- for the dataset: cannot open '--'."""
        self.stub('zfs', r'''echo "$*" >>"$STUB_DIR/log"
if [ "$1" = set ]; then [ "$3" != -- ] || { echo "cannot open '--'" >&2; exit 1; }; fi
if [ "$1" = list ]; then exit 0; fi
if [ "$1" = get ]; then echo old; fi''')
        body = functions(changes.CHANGE_BODY_3, 't_zfs_dataset')
        r = self.run_bash('zfs_exists() { return 0; }\n' + body + 't_zfs_dataset tank/a "" compression=zstd\n')
        self.assertNotIn('conflict', r.stdout, r.stderr)
        self.assertIn('set compression=zstd tank/a', self.log())
        r = self.run_bash('zfs_exists() { return 0; }\n' + body + 't_zfs_dataset -x "" compression=zstd || echo "rc=$?"\n')
        self.assertIn('not a dataset name', r.stdout)


class SmbKernel(Scripted):
    def run_it(self, **env):
        return self.run_bash(functions(scriptkit.CIFS_KERNEL, 'cifs_kernel') + 'cifs_kernel || echo "rc=$?"\n', **env)

    def modprobe(self):
        self.stub('modprobe', 'name=$2; [ -e "$STUB_DIR/installed" ] && exit 0; [ "$name" = cifs ]')
        self.stub('uname', 'echo 6.8.0-cloud')

    def test_a_kernel_with_both_needs_nothing(self):
        self.stub('modprobe', 'exit 0')
        r = self.run_it()
        self.assertIn('ok kernel has', r.stdout)
        self.assertFalse((self.dir / 'installed').exists())

    def test_installs_the_package_for_the_running_kernel(self):
        self.modprobe()
        for pm, pkg in (('apt-get', 'linux-modules-extra-6.8.0-cloud'), ('dnf', 'kernel-modules-6.8.0-cloud'), ('zypper', 'kernel-default-optional')):
            (self.dir / 'installed').unlink(missing_ok=True)
            r = self.run_it(STUB_PM=pm)
            self.assertIn('ok kernel has', r.stdout)
            self.assertEqual((self.dir / 'installed').read_text().strip(), pkg)

    def test_report_mode_installs_nothing(self):
        self.modprobe()
        r = self.run_it(APPLY='0')
        self.assertIn('would install linux-modules-extra', r.stdout)
        self.assertFalse((self.dir / 'installed').exists())

    def test_stops_when_the_package_does_not_help(self):
        self.stub('modprobe', 'exit 1')
        self.stub('uname', 'echo 6.8.0-cloud')
        r = self.run_it(STUB_PM='dnf')
        self.assertEqual((self.dir / 'installed').read_text().split(), ['kernel-modules-6.8.0-cloud', 'kernel-modules-extra-6.8.0-cloud'])
        self.assertIn('still has no cifs', r.stdout)
        self.assertIn('rc=1', r.stdout)

    def test_client_mount_asks_for_it(self):
        self.assertIn('cifs-utils || return 0\n    cifs_kernel || return 0\n', shares.SHARES_BODY_3)

    def reinstall_script(self, fstypes):
        return reinstall.script({'host': 'nas', 'config_id': 1, 'captured_at': 0, 'body': {'fstypes': fstypes, 'mounts': []}})

    def test_reinstalling_a_host_with_smb_mounts_gets_the_modules(self):
        text = self.reinstall_script(['cifs', 'smb3'])
        self.assertIn('cifs_kernel() {', text)
        tools = text[text.index('section "Tools"'):]
        self.assertEqual(tools.count('\n  cifs_kernel\n'), 1)
        self.assertLess(tools.index('need_cmd mount.cifs'), tools.index('\n  cifs_kernel\n'))
        self.assertEqual(subprocess.run(['bash', '-n'], input=text, text=True).returncode, 0)

    def test_reinstalling_a_host_without_them_asks_for_nothing(self):
        self.assertNotIn('\n  cifs_kernel\n', self.reinstall_script(['ext4']))


class SelinuxParents(Scripted):
    def ls(self):
        # /srv/btrfs has no label until restorecon or chcon gives it one
        self.stub('ls', r'''p=${@: -1}
if [ "$p" = /srv/btrfs ] && [ ! -e "$STUB_DIR/labelled" ]; then echo "system_u:object_r:unlabeled_t:s0 $p"; else echo "system_u:object_r:var_t:s0 $p"; fi''')

    def run_it(self, **env):
        return self.run_bash(functions(shares.SHARES_BODY_3, 'selinux_parents') + 'selinux_parents /srv/btrfs/home\n', **env)

    def test_restorecon_labels_only_the_folder_above(self):
        self.ls()
        self.stub('restorecon', 'echo "restorecon $*" >>"$STUB_DIR/log"; touch "$STUB_DIR/labelled"')
        self.stub('chcon', 'echo "chcon $*" >>"$STUB_DIR/log"')
        r = self.run_it()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.log(), 'restorecon /srv/btrfs\n')       # not -R: what is below it isn't ours

    def test_a_subvolume_root_shows_no_label_as_a_question_mark(self):
        self.stub('ls', r'''p=${@: -1}
if [ "$p" = /srv/btrfs ] && [ ! -e "$STUB_DIR/labelled" ]; then echo "    ? $p"; else echo "system_u:object_r:var_t:s0 $p"; fi''')
        self.stub('restorecon', 'echo "restorecon $*" >>"$STUB_DIR/log"; touch "$STUB_DIR/labelled"')
        self.assertEqual(self.run_it().returncode, 0)
        self.assertEqual(self.log(), 'restorecon /srv/btrfs\n')

    def test_chcon_when_policy_leaves_it_unlabelled(self):
        self.ls()
        self.stub('restorecon', 'exit 0')
        self.stub('chcon', 'echo "chcon $*" >>"$STUB_DIR/log"; touch "$STUB_DIR/labelled"')
        self.run_it()
        self.assertEqual(self.log(), 'chcon -t samba_share_t /srv/btrfs\n')

    def test_report_mode_only_says_so(self):
        self.ls()
        self.stub('restorecon', 'echo "restorecon $*" >>"$STUB_DIR/log"')
        self.assertIn('missing SELinux would block Samba from walking through /srv/btrfs', self.run_it(APPLY='0').stdout)
        self.assertEqual(self.log(), '')

    def test_labelled_parents_are_left_alone(self):
        self.ls()
        (self.dir / 'labelled').touch()
        self.stub('restorecon', 'echo "restorecon $*" >>"$STUB_DIR/log"')
        self.assertEqual(self.run_it().returncode, 0)
        self.assertEqual(self.log(), '')

    def test_runs_even_when_the_share_itself_is_labelled(self):
        self.assertLess(shares.SHARES_BODY_3.index('selinux_parents "${E_PATH[$i]}"'), shares.SHARES_BODY_3.index('is samba_share_t"'))


class VerifyOutput(Scripted):
    """verify_job with rsync standing in: what counts as a differing file."""

    def verify(self, rsync):
        self.stub('rsync', rsync)
        code = functions(jobscript.JOB_SCRIPT, 'verify_job')
        return self.run_bash(r'''set +e
LOCKS=$STUB_DIR ID=j METHOD=copy SRC=/s DST=/d FLAGS= TRANSPORT=rsync
load() { :; }; dst_guard() { :; }; volume_lock() { :; }; resolve_route() { :; }; die() { echo "die $*"; exit 9; }
report() { echo "report $1 $2"; }
rsync_cmd() { RS=(rsync); }
''' + code + 'verify_job j; echo "rc=$?"\n')

    WARNING = 'echo "** WARNING: connection is not using a post-quantum key exchange algorithm." >&2; '

    def test_ssh_warnings_are_not_files(self):
        r = self.verify(self.WARNING + 'exit 0')
        self.assertIn('report 0 every file matches', r.stdout)

    def test_only_real_differences_count(self):
        r = self.verify(self.WARNING + "echo '>fcsT...... a.txt'; echo '.d..t...... dir/'; exit 0")
        self.assertIn('report 1 1 file(s) differ', r.stdout)
        self.assertIn('a.txt', r.stdout)

    def test_rsync_failing_is_never_a_match(self):
        r = self.verify(self.WARNING + "echo 'ssh: connect to host x port 22: Connection refused' >&2; exit 255")
        self.assertIn('report 1 could not compare with the source (rsync exit 255)', r.stdout)
        self.assertIn('Connection refused', r.stdout)
        self.assertNotIn('every file matches', r.stdout)


class ContainerLayers(unittest.TestCase):
    def test_podman_overlay_folder_is_skipped_not_failed(self):
        for target in ('/var/lib/containers/storage/overlay', '/home/a/.local/share/containers/storage/overlay'):
            self.assertIn('image layers', skip_reason(MountInfo(target, '/dev/vda1[x]', 'xfs'), ScanOptions()))
        self.assertIsNone(skip_reason(MountInfo('/srv/overlay', '/dev/vdb', 'xfs'), ScanOptions()))
        plans = plan_mounts([MountInfo('/', '/dev/vda1', 'xfs', majmin='8:1'),
                             MountInfo('/var/lib/containers/storage/overlay', '/dev/vda1[/var/lib/containers/storage/overlay]', 'xfs', majmin='8:1',
                                       fsroot='/var/lib/containers/storage/overlay')], ScanOptions())
        self.assertEqual({p.info.target: p.action for p in plans}, {'/': 'scan', '/var/lib/containers/storage/overlay': 'skip'})


class Mergerfs(unittest.TestCase):
    def test_source_is_the_branches_not_the_kernels_1_2(self):
        m = [MountInfo('/mnt/pool', '1:2', 'fuse.mergerfs'), MountInfo('/mnt/two', '1:2', 'fuse.mergerfs'), MountInfo('/mnt/my pool', '1:2', 'fuse.mergerfs'),
             MountInfo('/mnt/none', '1:2', 'fuse.mergerfs'), MountInfo('/mnt/pool2', '/dev/vdb', 'ext4')]
        apply_mergerfs(m, 'mergerfs -o cache.files=off /mnt/a:/mnt/b /mnt/two\n/mnt/disk1:/mnt/disk2 /mnt/pool\n/mnt/x /mnt/my\\040pool\n/mnt/old /mnt/two\n/mnt/z /mnt/pool2\n')
        self.assertEqual([x.source for x in m], ['/mnt/disk1:/mnt/disk2', '/mnt/a:/mnt/b', '/mnt/x', '1:2', '/dev/vdb'])


if __name__ == '__main__':
    unittest.main()
