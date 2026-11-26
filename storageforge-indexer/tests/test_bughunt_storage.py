"""Regressions found by the storage and steps bug hunt: each test fails on the code as it was and passes on the fix."""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import test_archive as ta
from storageforge_index import changes, payloads, steps_clone, steps_infra, steps_overlay, steps_storage, steps_workloads


def bash(script, env=None, timeout=60):
    return subprocess.run(['bash', '-c', script], capture_output=True, text=True, timeout=timeout, env={**os.environ, **(env or {})})


def func(text, name):
    return re.search(rf'^{name}\(\) \{{.*?^\}}$', text, re.M | re.S)[0]


def plan_task(kind, **params):
    return changes.normalize({'name': 'p', 'tasks': [{'type': kind, 'host': 'nas', 'params': params}]})['tasks'][0]


class Stubs(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='sf-bh-'))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.bin = self.tmp / 'bin'
        self.bin.mkdir()
        self.log = self.tmp / 'log'
        self.log.write_text('')

    def stub(self, name, body):
        p = self.bin / name
        p.write_text('#!/bin/bash\n' + body + '\n')
        p.chmod(0o755)

    def env(self):
        return {'PATH': f'{self.bin}:{os.environ["PATH"]}', 'STUB_LOG': str(self.log)}


class AnsibleExport(Stubs):
    def test_drive_tune_and_partition_add_render_without_a_vg(self):
        for t in (plan_task('drive-tune', device='/dev/sdb', spindown='20'),
                  plan_task('partition-add', disk='/dev/sdb', name='x', size='1G', confirm='/dev/sdb')):
            self.assertTrue(changes._ansible_task(t, None, None)['name'])

    def test_drive_wipe_and_partition_delete_keep_the_device_guard(self):
        for kind, params, dev in (('drive-wipe', dict(device='/dev/null', confirm='/dev/null'), '/dev/null'),
                                  ('partition-delete', dict(disk='/dev/sdb', partition='/dev/null', confirm='/dev/null'), '/dev/null')):
            for name in ('shred', 'wipefs', 'parted', 'sgdisk', 'partprobe', 'udevadm', 'blkdiscard'):
                self.stub(name, 'echo "$0" >>"$STUB_LOG"')
            cmd = changes._ansible_task(plan_task(kind, **params), None, None)['ansible.builtin.shell']['cmd']
            self.assertIn('dev_guard', cmd)
            self.log.write_text('')
            r = bash(cmd, self.env())
            # /dev/null is not a block device: a drive-wipe must stop at the guard before any tool runs
            if kind == 'drive-wipe':
                self.assertNotEqual(r.returncode, 0)
                self.assertIn('not a block device', r.stderr)
                self.assertEqual(self.log.read_text(), '')

    def secure_delete(self, path, method='unlink'):
        # built by hand: the plan check already refuses a system path, and the playbook has to refuse it on its own too
        t = {'type': 'secure-delete', 'host': 'nas', 'params': {'path': path, 'method': method}}
        return bash(steps_storage._ansible_secure_delete(t)['ansible.builtin.shell']['cmd'])

    def test_secure_delete_refuses_system_paths_and_links(self):
        for p in ('/etc', '/etc/', '//usr', '/./var'):
            r = self.secure_delete(p)
            self.assertNotEqual(r.returncode, 0, p)
            self.assertIn('system path', r.stderr)
        target = self.tmp / 'real'
        target.write_text('x')
        link = self.tmp / 'link'
        link.symlink_to(target)
        r = self.secure_delete(str(link))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('symbolic link', r.stderr)
        self.assertTrue(target.exists())

    def test_secure_delete_still_deletes_an_ordinary_file(self):
        f = self.tmp / 'plain'
        f.write_text('x')
        self.assertEqual(self.secure_delete(str(f)).returncode, 0)
        self.assertFalse(f.exists())
        self.assertIn('unchanged', self.secure_delete(str(f)).stdout)

    def test_network_steps_carry_their_helpers_and_refuse_a_rollback(self):
        if not Path('/sys/class/net/lo/mtu').exists():
            self.skipTest('no lo')
        self.stub('ip', 'echo "ip $*" >>"$STUB_LOG"')
        cmd = changes._ansible_task(plan_task('net-mtu', iface='lo', mtu='1400', rollback='5'), None, None)['ansible.builtin.shell']['cmd']
        self.assertIn('net_guard() {', cmd)
        self.assertIn('net_manager() {', cmd)
        r = bash(cmd, self.env())
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('rollback timer is not available', r.stderr)
        self.assertEqual(self.log.read_text(), '', 'nothing was changed before the refusal')

    def test_wg_forward_export_installs_the_firewall_helper(self):
        tasks = changes._ansible_task(plan_task('wg-forward', iface='sf0', range='10.1.0.0/24'), None, None)
        self.assertIsInstance(tasks, list)
        self.assertEqual(tasks[0]['name'], 'storageforge-fwrules')


class Parsing(unittest.TestCase):
    def test_nfs_exports_with_a_tab_after_the_path(self):
        got = payloads.parse_nfs_exports('/srv/a\t10.0.0.1(rw) 10.0.0.2(ro)\n/srv/b 10.0.0.3(rw)\n')
        self.assertEqual([e['path'] for e in got], ['/srv/a', '/srv/b'])
        self.assertEqual(got[0]['clients'], '10.0.0.1 10.0.0.2')


class Archive(unittest.TestCase):
    setUp = ta.ArchiveStepsAndOffloadTests.setUp
    tearDown = ta.ArchiveStepsAndOffloadTests.tearDown
    _run_change_script = ta.ArchiveStepsAndOffloadTests._run_change_script

    @unittest.skipUnless(shutil.which('zstd') and shutil.which('tar'), 'needs tar and zstd')
    def test_extract_into_an_existing_folder_keeps_its_mode(self):
        src = ta._make_sample_tree(self.tmp)
        arc = self.tmp / 'a.tar.zst'
        dest = self.tmp / 'dest'
        dest.mkdir()
        os.chmod(dest, 0o2775)
        os.chmod(dest, 0o750)
        plan = {'name': 'x', 'tasks': [
            {'type': 'archive', 'host': ta.ME, 'params': {'path': str(src), 'dest': str(arc), 'codec': 'zstd-high', 'verify': True}},
            {'type': 'archive-extract', 'host': ta.ME, 'params': {'archive': str(arc), 'dest': str(dest), 'verify_checksum': True}}]}
        res = self._run_change_script(changes.script(self.conn, plan), '--apply')
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertTrue((dest / 'dataset' / 'alpha.txt').exists())
        self.assertEqual(oct(dest.stat().st_mode & 0o7777), '0o750')


class DiskImage(Stubs):
    def run_fn(self, extra=''):
        fn = func(steps_clone.PHASE7_BASH, 't_disk_image')
        dest = self.tmp / 'out.qcow2'
        script = ('APPLY=1; STAMP=S; ok() { echo "ok: $*"; }; conflict() { echo "conflict: $*"; }; missing() { :; }; info() { :; }; act() { :; }\n'
                  'try() { "$@" || { conflict "failed: $*"; return 1; }; }\n' + fn + f'\nt_disk_image /dev/vg0/data {dest} qcow2 0\n')
        return bash(script, self.env()), dest

    def test_a_failed_convert_leaves_no_image_and_says_so(self):
        self.stub('qemu-img', 'echo "qemu-img $*" >>"$STUB_LOG"; echo partial >"${@: -1}"; exit 1')
        self.stub('lvs', 'echo "  vg0 data"')
        self.stub('lvcreate', 'echo "lvcreate $*" >>"$STUB_LOG"')
        self.stub('lvremove', 'echo "lvremove $*" >>"$STUB_LOG"')
        r, dest = self.run_fn()
        self.assertNotIn('ok: wrote', r.stdout)
        self.assertFalse(dest.exists())
        self.assertFalse(Path(f'{dest}.sf-part').exists())
        self.assertIn('lvremove -f -- /dev/vg0/data-sf-img-S', self.log.read_text())

    def test_a_failed_snapshot_stops_before_the_copy(self):
        self.stub('qemu-img', 'echo "qemu-img $*" >>"$STUB_LOG"')
        self.stub('lvs', 'echo "  vg0 data"')
        self.stub('lvcreate', 'exit 5')
        r, dest = self.run_fn()
        self.assertNotIn('ok: wrote', r.stdout)
        self.assertNotIn('qemu-img', self.log.read_text())

    def test_a_good_copy_is_moved_into_place(self):
        self.stub('qemu-img', 'echo img >"${@: -1}"')
        self.stub('lvs', 'exit 1')
        r, dest = self.run_fn()
        self.assertIn('ok: wrote', r.stdout)
        self.assertTrue(dest.exists())
        self.assertFalse(Path(f'{dest}.sf-part').exists())


class FwRules(Stubs):
    def test_arm_with_a_timer_already_pending_still_prints_the_marker(self):
        script = self.tmp / 'fw'
        script.write_text(steps_infra.FWRULES)
        self.stub('systemctl', 'echo "sf-fw-rollback.timer  n/a n/a n/a n/a"')
        self.stub('systemd-run', 'echo "run" >>"$STUB_LOG"')
        r = bash(f'bash {script} arm 7', {**self.env(), 'SF_FW_DIR': str(self.tmp / 'fw.d')})
        self.assertIn('FW-ROLLBACK armed 7', r.stdout)
        self.assertEqual(self.log.read_text(), '', 'a second timer is not started')

    def test_wg_forward_asks_the_fwrules_program_for_the_backend(self):
        fwp = self.tmp / 'fwp'
        fwp.write_text('#!/bin/bash\n[ "$1" = backend ] && echo iptables\n')
        fwp.chmod(0o755)
        self.stub('sysctl', 'if [ "$1" = -n ]; then echo 0; exit 0; fi')
        self.stub('iptables', 'echo "iptables $*" >>"$STUB_LOG"; case " $* " in *" -C "*) exit 1;; esac')
        fn = func(steps_infra.BASH, 't_wg_forward')
        script = (f'fw_tool() {{ FW={fwp}; }}; ok() {{ echo "ok: $*"; }}; act() {{ :; }}; conflict() {{ echo "conflict: $*"; }}; durable() {{ :; }}; try() {{ "$@"; }}\n'
                  + fn + '\nt_wg_forward sf0 10.1.0.0/24 present\n')
        r = bash(script, {**self.env(), 'SF_SYSCTL_DIR': str(self.tmp / 'sysctl.d')})
        self.assertIn('iptables -I FORWARD 1 -i sf0 -o sf0 -j ACCEPT', self.log.read_text(), r.stdout + r.stderr)


class Nebula(Stubs):
    def run_absent(self, conf_name, with_unit):
        d = self.tmp / 'neb'
        d.mkdir()
        units = self.tmp / 'units'
        units.mkdir()
        for f in ('host.key', 'host.crt', 'ca.crt'):
            (d / f).write_text('x')
        (d / conf_name).write_text('pki: {}\n')
        if with_unit:
            (units / 'storageforge-nebula.service').write_text('x')
        script = ('APPLY=1; ok() { echo "ok: $*"; }; conflict() { echo "conflict: $*"; }; act() { :; }; tun_unit_stop() { :; }\n'
                  + func(steps_overlay.BASH, 'nebula_ours') + '\n' + func(steps_overlay.BASH, 't_nebula') + "\nt_nebula ca '' '' '' '' absent\n")
        r = bash(script, {'SF_NEBULA_DIR': str(d), 'SF_UNIT_DIR': str(units)})
        return r, d

    def test_hand_made_nebula_with_other_config_name_is_left_alone(self):
        r, d = self.run_absent('other.yml', with_unit=False)
        self.assertIn('conflict:', r.stdout)
        self.assertTrue((d / 'host.key').exists())

    def test_our_unit_with_no_config_is_still_removed(self):
        r, d = self.run_absent('other.yml', with_unit=True)
        self.assertFalse((d / 'host.key').exists(), r.stdout)


class Workloads(Stubs):
    def test_wl_wait_with_no_containers_is_not_healthy(self):
        r = bash(func(steps_workloads.BASH, 'wl_health') + '\n' + func(steps_workloads.BASH, 'wl_wait') + '\nwl_wait docker 5; echo "rc=$? why=$WL_WHY"', self.env())
        self.assertIn('rc=1 why=no container', r.stdout)

    def test_a_port_the_fence_cannot_number_is_a_crit(self):
        said = []
        ports = [{'bind': '0.0.0.0', 'published': '${WEB:-8080}', 'target': '80', 'proto': 'tcp'}]
        with mock.patch('storageforge_index.netfacts.reading', return_value={}):
            steps_workloads._published_check(None, {'name': 'h'}, ports, '10.0.0.0/24', lambda lvl, msg: said.append(lvl), 'a fence')
        self.assertIn('crit', said)
        said.clear()
        ports[0]['published'] = '8080'
        with mock.patch('storageforge_index.netfacts.reading', return_value={}):
            steps_workloads._published_check(None, {'name': 'h'}, ports, '10.0.0.0/24', lambda lvl, msg: said.append(lvl), 'a fence')
        self.assertNotIn('crit', said)


if __name__ == '__main__':
    unittest.main()
