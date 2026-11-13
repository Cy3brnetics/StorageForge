"""mdadm arrays and services on a copy of a host: the scan of a whole-disk array, the md-array and services steps
(run as Bash against stand-in mdadm and systemctl), what the copy plans, and the fixes the lab run found."""
import base64
import json
import os
import shlex
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

try:
    from test_clone import Db, blk
except ImportError:      # run as tests.test_x from the project folder
    from tests.test_clone import Db, blk
from storageforge_index import changes, clone, fromdesign, payloads, pkglist, steps_md, steps_services

HARNESS = r'''
set -u
ok() { echo "ok: $*"; }; missing() { echo "missing: $*"; }; conflict() { echo "conflict: $*"; PROBLEMS=$((PROBLEMS + 1)); }
info() { echo "info: $*"; }; doing() { echo "doing: $*"; }; skip() { echo "skip: $*"; }; later() { echo "later: $*"; }
act() { if ((APPLY)); then echo "doing: $*"; return 0; else echo "would: $*"; return 1; fi; }
try() { "$@" || { conflict "failed: $*"; return 1; }; }
need() { command -v "$1" >/dev/null || { conflict "$1 is not installed"; return 1; }; }
PROBLEMS=0 STAMP=20261107-120000
'''


def stub(d: Path, name: str, body: str):
    p = d / name
    p.write_text('#!/bin/bash\n' + body + '\n')
    p.chmod(0o755)


def md_lsblk():
    """What lsblk printed for sf-suse: the whole disks vdb and vdc in md0, with the array straight under each disk."""
    md0 = {'name': 'md0', 'path': '/dev/md0', 'type': 'raid1', 'fstype': 'ext4', 'mountpoint': '/mnt/raid', 'uuid': '5ba851d3', 'size': 2144337920}
    return {'blockdevices': [
        {'name': 'vda', 'type': 'disk', 'size': 10 * 2**30, 'children': [{'name': 'vda1', 'type': 'part', 'fstype': 'xfs', 'mountpoint': '/', 'uuid': 'r', 'size': 10 * 2**30}]},
        *({'name': n, 'path': f'/dev/{n}', 'type': 'disk', 'fstype': 'linux_raid_member', 'label': 'sf-suse:0', 'uuid': 'fb69', 'serial': s,
           'size': 2 * 2**30, 'children': [md0]} for n, s in (('vdb', 'D1'), ('vdc', 'D2')))]}


class Scan(unittest.TestCase):
    def test_a_whole_disk_md_member_is_seen(self):
        node = payloads.node_from_lsblk(md_lsblk(), 'sf-suse')
        pool = next(p for p in node['pools'] if p['type'] == 'mdadm')
        self.assertEqual((pool['name'], pool['level'], pool['members'], pool['mount'], pool['fs']), ('md0', 'raid1', ['vdb', 'vdc'], '/mnt/raid', 'ext4'))

    def test_the_services_section(self):
        sv = steps_services.parse('init systemd\ne\tchronyd.service\tenabled\ne\tfstrim.timer\tdisabled\ne\t$(id).service\tx\ne\tbad name\t\n')
        self.assertEqual(sv, {'init': 'systemd', 'enabled': [{'unit': 'chronyd.service', 'preset': 'enabled'}, {'unit': 'fstrim.timer', 'preset': 'disabled'}]})
        rc = steps_services.parse('init openrc\no\tchronyd\tdefault\no\tdevfs\tsysinit\no\t;rm\tdefault\n')
        self.assertEqual([e['unit'] for e in rc['enabled']], ['chronyd', 'devfs'])
        self.assertIsNone(steps_services.parse('e\tx.service\t\n'))       # no init line: neither


class Choose(unittest.TestCase):
    SV = {'init': 'systemd', 'enabled': [{'unit': u} for u in (
        'chronyd.service', 'nfs-server.service', 'fstrim.timer', 'borgmatic.service', 'postfix.service', 'cloud-init.service',
        'NetworkManager.service', 'qemu-guest-agent.service', 'sf-job-media.timer', 'ufw.service', 'grub-common.service',
        'snap.lxd.daemon.service', 'systemd-resolved.service')]}

    def test_a_test_copy_starts_what_the_host_does_and_nothing_that_reaches_out(self):
        take, left = steps_services.choose(self.SV, timers=False)
        self.assertEqual([e['unit'] for e in take], ['chronyd.service', 'nfs-server.service'])
        why = dict(left)
        self.assertIn('timer', why['fstrim.timer'])
        self.assertIn('sends data off', why['borgmatic.service'])
        self.assertIn('sends data off', why['postfix.service'])
        self.assertIn('shut out SSH', why['ufw.service'])          # a firewall with none of its rules
        self.assertIn('StorageForge', why['sf-job-media.timer'])

    def test_a_migration_takes_timers_backups_and_mail_too(self):
        take, _ = steps_services.choose(self.SV, timers=True)
        self.assertEqual({e['unit'] for e in take}, {'chronyd.service', 'nfs-server.service', 'fstrim.timer', 'borgmatic.service', 'postfix.service'})

    def test_openrc_base_runlevels_stay_behind(self):
        take, left = steps_services.choose({'init': 'openrc', 'enabled': [{'unit': 'devfs', 'runlevel': 'sysinit'}, {'unit': 'chronyd', 'runlevel': 'default'},
                                                                         {'unit': 'networking', 'runlevel': 'boot'}]}, False)
        self.assertEqual([e['unit'] for e in take], ['chronyd'])


class Bash(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.d)
        self.bin = self.d / 'bin'
        self.bin.mkdir()
        self.fake = self.d / 'fake'
        self.fake.mkdir()

    def run_bash(self, body, call, apply):
        script = HARNESS + f'APPLY={int(apply)}\n' + body + '\n' + call + '\nexit $((PROBLEMS > 0))\n'
        return subprocess.run(['bash', '-c', script], capture_output=True, text=True, timeout=60,
                              env={**os.environ, 'PATH': f'{self.bin}:{os.environ["PATH"]}', 'FAKE': str(self.fake), 'LOG': str(self.d / 'log')})

    def log(self):
        return (self.d / 'log').read_text() if (self.d / 'log').exists() else ''

    # ── md-array ──
    def md(self, apply, fs='ext4', kernel_has_md=True):
        stub(self.bin, 'mdadm', 'echo "mdadm $*" >>"$LOG"; case "$*" in *--create*) touch "$FAKE/md" ;; '
             '*--export*) [[ -e $FAKE/md ]] && echo MD_UUID=d5af489f ;; *--brief*) echo "ARRAY /dev/md/data metadata=1.2 UUID=d5af489f" ;; '
             '*--detail*) [[ -e $FAKE/md ]] || exit 1; echo "     Raid Level : raid1"; echo "          State : clean" ;; esac')
        stub(self.bin, 'modinfo', 'exit 0' if kernel_has_md else 'exit 1')
        stub(self.bin, 'blkid', 'cat "$FAKE/fs" 2>/dev/null; true')
        # the change script's own helpers, stood in for: the devices are free, mkfs writes the type, mdadm.conf is here
        extra = ('devs_guard() { echo "guard $*" >>"$LOG"; }\nmkfs_dev() { echo "mkfs $*" >>"$LOG"; echo "$2" >"$FAKE/fs"; }\n'
                 'md_conf() { echo "$FAKE/mdadm.conf"; }\n')
        call = f't_md_array data raid1 {shlex.quote("/dev/vdb /dev/vdc")} "" {fs} mnt-raid ""'
        # the kernel check reads /sys/module/md_mod and /proc/mdstat too: on a host with md loaded, only modinfo is stood in
        body = steps_md.BASH.replace('[[ ! -d /sys/module/md_mod ]]', '[[ ! -d $FAKE/no-such ]]').replace('/proc/mdstat', '"$FAKE/mdstat"')
        return self.run_bash(body + extra, call, apply)

    def test_md_report_changes_nothing(self):
        out = self.md(False)
        self.assertEqual(out.returncode, 0, out.stdout)
        self.assertIn('would: mdadm --create /dev/md/data --level=raid1 --raid-devices=2 /dev/vdb /dev/vdc, then mkfs.ext4', out.stdout)
        self.assertNotIn('--create', self.log())

    def test_md_apply_creates_writes_mdadm_conf_and_formats_then_finds_it_all_again(self):
        out = self.md(True)
        self.assertEqual(out.returncode, 0, out.stdout)
        create = next(l for l in self.log().splitlines() if '--create' in l)
        # mdadm takes no -- before the devices: with one it saw no devices at all (the lab run)
        self.assertEqual(create, 'mdadm --create /dev/md/data --run --level=raid1 --raid-devices=2 --metadata=1.2 --name=data /dev/vdb /dev/vdc')
        self.assertNotIn(' -- ', self.log())
        self.assertEqual((self.fake / 'mdadm.conf').read_text(), 'ARRAY /dev/md/data metadata=1.2 UUID=d5af489f\n')
        self.assertIn('mkfs /dev/md/data ext4 mnt-raid', self.log())

    def test_md_says_when_the_kernel_has_no_md_driver(self):
        out = self.md(False, kernel_has_md=False)
        self.assertIn('has no md driver (md_mod)', out.stdout)
        self.assertNotIn('guard', self.log())        # before any device is looked at

    # ── services ──
    def services(self, apply, units, states, timers=''):
        stub(self.bin, 'systemctl', 'echo "systemctl $*" >>"$LOG"; u=${@: -1}; case $1 in '
             'is-enabled) cat "$FAKE/state-$u" 2>/dev/null || exit 1 ;; enable) echo enabled >"$FAKE/state-$u" ;; '
             'start) [[ $u != broken.service ]] ;; esac')
        stub(self.bin, 'journalctl', 'echo "Failed to start: no config"')
        for u, st in states.items():
            (self.fake / f'state-{u}').write_text(st + '\n')
        want = base64.b64encode(('\n'.join(units) + '\n').encode()).decode()
        left = base64.b64encode(b'fstrim.timer\ta timer: on a test copy, timers stay off\n').decode()
        body = steps_services.BASH.replace('[[ -d /run/systemd/system ]]', 'true')
        return self.run_bash(body, f't_services web-01 "{timers}" systemd {want} {left}', apply)

    def test_services_report_then_apply(self):
        units = ['chronyd.service', 'nfs-server.service', 'gone.service', 'masked.service', 'broken.service']
        states = {'chronyd.service': 'enabled', 'nfs-server.service': 'disabled', 'masked.service': 'masked', 'broken.service': 'disabled'}
        report = self.services(False, units, states)
        self.assertIn('would: systemctl enable nfs-server.service, and start it', report.stdout)
        self.assertIn('skip: fstrim.timer: a timer', report.stdout)
        self.assertNotIn('systemctl enable', self.log())
        out = self.services(True, units, states)
        self.assertIn('ok: nfs-server.service enabled and started', out.stdout)
        self.assertIn('masked here: left as it is', out.stdout)                       # never unmasked
        self.assertIn('missing: gone.service is not here', out.stdout)                 # never installed
        self.assertIn('broken.service is enabled, and did not start: Failed to start: no config', out.stdout)
        self.assertIn('ok: 1 of 5 already enabled', out.stdout)
        self.assertNotIn('disable', self.log())
        self.assertNotIn('unmask', self.log())

    def test_services_refuse_another_init_system(self):
        body = steps_services.BASH.replace('[[ -d /run/systemd/system ]]', 'false').replace('command -v rc-update >/dev/null', 'true')
        out = self.run_bash(body, 't_services web-01 "" systemd "" ""', True)
        self.assertIn('starts its services with systemd and this host with openrc: nothing is enabled', out.stdout)

    # ── a subvolume on a btrfs an earlier task mounts, in a report ──
    def test_a_report_sees_a_btrfs_mount_made_earlier_in_the_plan(self):
        body = changes.CHANGE_BODY_2 if 't_subvolume()' in changes.CHANGE_BODY_2 else next(
            b for b in (changes.CHANGE_BODY_1, changes.CHANGE_BODY_2, changes.CHANGE_BODY_3) if 't_subvolume()' in b)
        fn = body[body.index('t_subvolume()'):]
        fn = fn[:fn.index('\n}\n') + 3]
        stub(self.bin, 'btrfs', 'exit 1')
        out = self.run_bash(fn, f'PLANNED_MOUNTS=" {self.d}/top:btrfs"; t_subvolume {self.d}/top/@data', False)
        self.assertIn('later: ', out.stdout)
        self.assertIn('mounted by an earlier task', out.stdout)
        self.assertNotIn('conflict', out.stdout)


class Packages(unittest.TestCase):
    def test_the_kernel_and_bootloader_are_left_to_the_base_install(self):
        d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d)
        # bare metal, whatever runs the test: GitHub's runners are Azure VMs, where the script rightly leaves the firmware out
        for name, body in (('zypper', 'true'), ('rpm', 'true'), ('systemd-detect-virt', 'echo none')):
            stub(d, name, body)
        pk = pkglist.parse('distro\topensuse-leap\t16.0\npm zypper\na\tkernel-default\na\tgrub2\na\tshim\na\tvim\na\tlinux-firmware\ncomplete')
        path = d / 'p.sh'
        path.write_text(pkglist.script(pk, 'sf-suse', 'now').replace('here_pm() {', 'here_pm() { echo zypper; return; '))
        out = subprocess.run(['bash', str(path)], capture_output=True, text=True, timeout=60, env={**os.environ, 'PATH': f'{d}:{os.environ["PATH"]}'})
        self.assertIn('3 kernel or boot package(s) left to the base install here, which the copy never changes: grub2 kernel-default shim', out.stdout)
        self.assertIn('2 to install with zypper: linux-firmware vim', out.stdout)


class Copy(Db):
    def test_an_md_array_comes_across_as_one_step_and_a_mount_by_label(self):
        self.add('suse', {'collected_at': '2026-11-07T00:00:00+00:00', 'lsblk': md_lsblk()},
                 [('/', 'xfs', '/dev/vda1', 3, 'rw'), ('/mnt/raid', 'ext4', '/dev/md0', 1, 'rw,relatime')])
        got = clone.build(self.conn, 'suse', 'web-copy', packages=False, accounts=False, services=False)
        tasks = got['plans']['changes']['tasks']
        md = next(t['params'] for t in tasks if t['type'] == 'md-array')
        self.assertEqual((md['name'], md['level'], md['devices'], md['fstype'], md['confirm']), ('md0', 'raid1', '/dev/vdb /dev/vdc', 'ext4', '/dev/vdb /dev/vdc'))
        self.assertFalse([t for t in tasks if t['type'] in ('partition', 'partition-add', 'format')])     # whole disks: nothing partitioned
        mount = next(t['params'] for t in tasks if t['type'] == 'mount')
        self.assertEqual((mount['source'], mount['target'], mount['fstype']), (f'LABEL={md["label"]}', '/mnt/raid', 'ext4'))
        self.assertFalse(any('mdadm' in n for n in got['not_carried']))
        changes.normalize(got['plans']['changes'])

    def test_services_join_the_copy_with_timers_only_for_a_migration(self):
        hid = self.conn.scalar("SELECT host_id FROM hosts WHERE hostname = 'web-01'")
        inv = self.conn.scalar('SELECT inventory_json FROM hosts WHERE host_id = :h', {'h': hid})
        inv = json.loads(inv) if isinstance(inv, str) else inv           # PostgreSQL hands back jsonb as a dict
        inv['services'] = {'init': 'systemd', 'enabled': [{'unit': 'chronyd.service'}, {'unit': 'fstrim.timer'}]}
        self.conn.execute(f"UPDATE hosts SET inventory_json = {self.db.jsonp(':i')} WHERE host_id = :h", {'i': json.dumps(inv), 'h': hid})
        test = next(t for t in clone.build(self.conn, 'web-01', 'web-copy')['plans']['changes']['tasks'] if t['type'] == 'services')
        mig = next(t for t in clone.build(self.conn, 'web-01', 'web-copy', mode='migrate')['plans']['changes']['tasks'] if t['type'] == 'services')
        self.assertEqual((test['params']['timers'], mig['params']['timers']), (False, True))
        self.assertNotIn('services', [t['type'] for t in clone.build(self.conn, 'web-01', 'web-copy', services=False)['plans']['changes']['tasks']])
        script = changes.script(self.conn, {**clone.build(self.conn, 'web-01', 'web-copy')['plans']['changes']})
        self.assertIn('t_services', script)

    def test_a_source_scanned_before_services_were_read_says_so(self):
        self.assertTrue(any(n.startswith('services:') for n in clone.build(self.conn, 'web-01', 'web-copy')['not_carried']))


class Design(unittest.TestCase):
    def test_the_md_step_comes_before_formatting_and_lvm(self):
        order = fromdesign.ORDER
        self.assertLess(order.index('md-array'), order.index('format'))
        self.assertLess(order.index('md-array'), order.index('lvm-vg'))


if __name__ == '__main__':
    unittest.main()
