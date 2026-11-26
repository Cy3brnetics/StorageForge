"""Regressions of the last bug-hunt round (changes, confirm, design versions, steps, toolbox, what-if): each fails on the code as it was."""
from __future__ import annotations

import json
import os
import re
import stat
import subprocess
import time
import unittest
from unittest import mock

import test_design_versions as tdv
import test_platform_more as tpm
from test_bughunt_storage import Stubs, bash, func, plan_task
from storageforge_index import (changes, confirm, design_versions as dv, fromdesign, reinstall, steps_infra, steps_osinstall, steps_pools,
                                steps_restoretest, steps_secretfile, steps_toolbox, steps_toolbox_b, toolbox, whatif)

HARNESS = ('APPLY=1; ok() { echo "ok: $*"; }; missing() { echo "missing: $*"; }; conflict() { echo "conflict: $*"; }; info() { echo "info: $*"; }\n'
           'act() { echo "act: $*"; return 0; }; doing() { echo "doing: $*"; }; try() { "$@" || { conflict "failed: $*"; return 1; }; }; durable() { :; }\n')


class Changes(Stubs):
    def test_an_fstab_lookup_finds_a_mount_point_with_a_space(self):
        fstab = self.tmp / 'fstab'
        fstab.write_text('/dev/sdb1 /mnt/my\\040disk ext4 defaults 0 2\n')
        text = changes.CHANGE_BODY_3.replace('/etc/fstab', str(fstab))
        one = lambda name: re.search(rf'^{name}\(\) \{{.*$', text, re.M)[0]  # noqa: E731  (one-line functions)
        r = bash(one('esc') + '\n' + one('fstab_line') + '\nfstab_line "/mnt/my disk"', self.env())
        self.assertIn('/dev/sdb1', r.stdout, r.stderr)

    def test_the_drive_tune_rule_has_a_valid_match(self):
        self.stub('udevadm', 'if [ "$1" = info ]; then echo ID_SERIAL=${SERIAL:-}; fi')
        cmd = changes._ansible_task(plan_task('drive-tune', device='/dev/sdb', scheduler='bfq'), None, None)['ansible.builtin.shell']['cmd']
        rules = self.tmp / 'rules'
        rules.mkdir()
        cmd = cmd.replace('/etc/udev/rules.d', str(rules))
        for serial, want in (('WD123', 'ENV{ID_SERIAL}=="WD123"'), ('', 'KERNEL=="sdb"')):
            r = bash(cmd, {**self.env(), 'SERIAL': serial})
            self.assertEqual(r.returncode, 0, r.stderr)
            body = (rules / '90-storageforge-sdb.rules').read_text()
            self.assertIn(f'ENV{{DEVTYPE}}=="disk", {want}, ATTR{{queue/scheduler}}="bfq"', body)
            (rules / '90-storageforge-sdb.rules').unlink()


class Confirm(unittest.TestCase):
    def test_one_bad_line_in_runs_does_not_stop_the_rest(self):
        import dbfactory
        import shutil
        import tempfile
        from pathlib import Path
        tmp = Path(tempfile.mkdtemp(prefix='sf-conf-'))
        self.addCleanup(shutil.rmtree, tmp, True)
        db = dbfactory.make(self, tmp / 'idx.db')
        conn = db.connect()
        self.addCleanup(conn.close)
        db.migrate(conn)
        now = int(time.time())
        nonce = 'ab' * 16
        conn.execute("""INSERT INTO deploy_runs (group_id, host, kind, ref, mode, status, nonce, started_at)
                        VALUES ('g1', 'h1', 'changes', '1', 'apply', 'running', :n, :t)""", {'n': nonce, 't': now - 60})
        text = '{"nonce":"cd","rc":null}\n{"nonce":"ef","rc":"x"}\n' + json.dumps({'nonce': nonce, 'rc': 0, 'finished': now - 5}) + '\n'
        got = confirm.ingest_runs(conn, 'h1', text)
        self.assertEqual([g['status'] for g in got], ['ok'])


class DesignVersions(tdv.Base):
    def test_a_version_is_for_the_host_its_design_names(self):
        with self.assertRaisesRegex(ValueError, 'not nas-01'):
            dv.save(self.conn, 'nas-01', tdv.design('nas-02'), 'ann')
        self.assertEqual(dv.list_versions(self.conn, 'nas-01'), [])
        self.assertEqual(dv.save(self.conn, 'nas-01', tdv.design('nas-01'), 'ann')['host'], 'nas-01')

    def test_a_restore_does_not_write_another_hosts_design(self):
        body = json.dumps(tdv.design('nas-02'))
        vid = self.conn.scalar("""INSERT INTO design_versions (host, name, note, author, auto, body_json, size_bytes, created_at)
                                  VALUES ('nas-01', 'odd', '', 'ann', 0, :b, :s, 1) RETURNING id""", {'b': body, 's': len(body)})
        with self.assertRaisesRegex(ValueError, 'not nas-01'):
            dv.restore(self.db, self.conn, vid, 'ann')
        ok = dv.save(self.conn, 'nas-01', tdv.design('nas-01'), 'ann')
        with self.assertRaisesRegex(ValueError, 'not nas-01'):
            dv.restore(self.db, self.conn, ok['id'], 'ann', current=tdv.design('nas-02'))


class Steps(Stubs):
    def test_an_ansible_fence_removal_is_unchanged_when_the_fence_is_gone(self):
        task = plan_task('fw-fence', name='gone-fence', service='smb', clients='10.0.0.0/8', state='absent')
        cmd = steps_infra._ansible_fw_fence(task)[-1]['ansible.builtin.shell']['cmd']
        r = bash(cmd, self.env())
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn('changed', r.stdout)

    def test_an_os_install_name_is_cut_to_what_a_partition_name_holds(self):
        longest = 'a' * steps_osinstall.NAME_MAX
        self.assertEqual(steps_osinstall.NAME_MAX, 28)
        said = []
        base = {'image': 'custom', 'image_url': 'u', 'image_sha': 's', 'user': 'adm'}
        steps_osinstall._check_install(None, None, None, {**base, 'name': longest}, lambda lvl, t: said.append(lvl))
        self.assertNotIn('crit', said)
        steps_osinstall._check_install(None, None, None, {**base, 'name': longest + 'b'}, lambda lvl, t: said.append(lvl))
        self.assertIn('crit', said)
        fn = func(steps_osinstall.bash(), 't_os_install')
        r = bash(HARNESS + fn + f'\nt_os_install {longest}b x y z /dev/null', self.env())
        self.assertIn('conflict: the name', r.stdout)
        self.assertIn('longer than 28', r.stdout)

    def test_a_file_directly_under_the_root_has_a_folder(self):
        if os.geteuid() == 0:
            self.skipTest('would write to /')
        src = self.tmp / 'secrets'
        src.mkdir()
        (src / 'tok').write_text('x')
        r = bash(HARNESS + steps_secretfile.BASH + f'\nt_secret_file tok /sf-test-token {os.environ.get("USER", "root")} "" 0600 present', {**self.env(), 'SF_SECRET_DIR': str(src)})
        self.assertNotIn('the folder  does not exist', r.stdout)
        self.assertNotIn('does not exist', r.stdout)

    def test_a_secret_file_can_make_its_folder_and_wait_for_the_account(self):
        src = self.tmp / 'secrets'
        src.mkdir()
        (src / 'tok').write_text('x')
        self.stub('chown', 'echo "chown $*" >>"$STUB_LOG"')
        dest = self.tmp / 'srv' / 'tool' / 'secrets'
        call = f'\nt_secret_file tok {dest}/tok sf-no-such-account "" 0600 present %s\n'
        env = {**self.env(), 'SF_SECRET_DIR': str(src)}
        r = bash(HARNESS + steps_secretfile.BASH + call % '', env)
        self.assertIn('conflict: there is no account sf-no-such-account', r.stdout)
        self.assertFalse(dest.exists())
        r = bash(HARNESS + steps_secretfile.BASH + call % '1', env)
        self.assertNotIn('conflict', r.stdout)
        self.assertEqual((dest / 'tok').read_text(), 'x')
        self.assertEqual(stat.S_IMODE(dest.stat().st_mode), 0o750)
        self.assertIn(f'chown root:root {dest}', self.log.read_text(), 'until the install makes the account, the folder is root\'s')

    def test_a_secret_file_owner_may_be_a_user_id_with_no_account(self):
        src = self.tmp / 'secrets'
        src.mkdir()
        (src / 'tok').write_text('x')
        self.stub('chown', 'echo "chown $*" >>"$STUB_LOG"')
        r = bash(HARNESS + steps_secretfile.BASH + f'\nt_secret_file tok {self.tmp}/tok 54321 "" 0600 present', {**self.env(), 'SF_SECRET_DIR': str(src)})
        self.assertNotIn('no account', r.stdout)
        self.assertIn('chown 54321:54321', self.log.read_text())

    def test_the_install_hands_over_what_secret_file_made_before_the_account(self):
        d = self.tmp / 'secrets'
        d.mkdir()
        (d / 'tok').write_text('x')
        self.stub('chown', 'echo "chown $*" >>"$STUB_LOG"')
        r = bash(HARNESS + func(steps_toolbox.BASH, 'tb_hand_over') + f'\ntb_hand_over {d} sf-someone', self.env())
        self.assertEqual(r.returncode, 0, r.stderr)
        log = self.log.read_text()
        self.assertIn(f'chown sf-someone:sf-someone -- {d}', log)
        self.assertIn(f'chown sf-someone:sf-someone -- {d}/tok', log)
        self.assertIn('tb_hand_over "/srv/toolbox/$tool/secrets" "$owner"', steps_toolbox.BASH)

    def test_a_service_that_fails_to_start_is_a_conflict(self):
        self.stub('systemctl', 'case "$1" in cat) exit 0 ;; is-active|is-enabled) exit 3 ;; enable) echo "Job failed"; exit 1 ;; esac')
        fn = func(reinstall.BODY, 'service_on')
        r = bash(HARNESS + fn + '\nservice_on nfs-server', self.env())
        self.assertIn('conflict: nfs-server did not start', r.stdout)

    def test_a_restore_test_leaves_the_mode_of_the_scratch_folder_the_operator_named(self):
        scratch = self.tmp / 'scratch'
        scratch.mkdir()
        scratch.chmod(0o775)
        key, source = self.tmp / 'key', self.tmp / 'source'
        key.write_text('k')
        source.mkdir()
        self.stub('restic', 'exit 0')
        text = steps_restoretest.BASH
        script = (HARNESS + 'rt_done() { echo "done: $*"; }\n' + func(text, 'rt_restore_test') +
                  f'\nrt_restore_test n restic repo {key} {source} {scratch} 5')
        r = bash(script, self.env())
        self.assertIn('done: failed no snapshot', r.stdout, r.stderr)
        self.assertEqual(stat.S_IMODE(scratch.stat().st_mode), 0o775)

    def test_a_partition_is_not_in_the_pool_because_its_number_starts_another(self):
        fn = func(steps_pools.BASH, 'zp_find')
        for want, leaf, found in (('/dev/sda1', '/dev/sda11', False), ('/dev/nvme0n1p1', '/dev/nvme0n1p10', False), ('/dev/sda', '/dev/sda1', True),
                                  ('/dev/nvme0n1', '/dev/nvme0n1p1', True), ('/dev/sda1', '/dev/sda1', True)):
            r = bash(f'zp_leaves() {{ echo "disk {leaf}"; }}\n{fn}\nzp_find tank {want} && echo FOUND', self.env())
            self.assertEqual('FOUND' in r.stdout, found, (want, leaf, r.stdout, r.stderr))

    def test_a_scan_report_of_an_image_that_no_longer_runs_is_pruned(self):
        scans = self.tmp / 'scans'
        scans.mkdir()
        old = scans / 'trivy-old.tsv'
        old.write_text('i\told/img:1\t1\ttrivy\nv\tCVE-1\n')
        other = scans / 'grype-old.tsv'
        other.write_text('i\told/img:1\t1\tgrype\n')
        self.stub('trivy', 'printf "v\\tCVE-2\\n"')
        fn = func(steps_toolbox_b.BASH.replace(steps_toolbox_b.SCANS, str(scans)), 't_trivy_scan')
        pre = HARNESS + 'tb_scan_refs() { echo new/img:2; }\n' + fn
        r = bash(pre + '\nt_trivy_scan images "old/img:1" trivy ok why', self.env())
        self.assertTrue(old.exists(), r.stdout + r.stderr)
        r = bash(pre + '\nt_trivy_scan running "" trivy ok why', self.env())
        self.assertFalse(old.exists(), r.stdout + r.stderr)
        self.assertTrue(other.exists(), 'another scanner\'s reports are not this one\'s to prune')
        self.assertEqual(len(list(scans.glob('trivy-*.tsv'))), 1)


class ToolboxEntry(unittest.TestCase):
    def test_a_list_or_mapping_where_a_name_belongs_is_a_problem_not_a_crash(self):
        for y in ('risk: [[x]]', 'labels: [{a: 1}]', 'inputs: [{name: a, kind: [1]}]', 'gui: {panel: {adapter: [1]}}', 'gui: {panel: {api: [1]}}'):
            e, problems = toolbox.load_entry(f'format: 1\nid: ab\n{y}\n')
            self.assertTrue(problems, y)

    def test_an_override_bind_is_one_ipv4_address(self):
        ovr, problems = toolbox.load_override('bind: 192.168.1.5\n')
        self.assertEqual((ovr.get('bind'), problems), ('192.168.1.5', []))
        ovr, problems = toolbox.load_override('bind: fd00::5\n')
        self.assertNotIn('bind', ovr)
        self.assertTrue(any('bind' in p for p in problems))


class PlannerAndWhatIf(tpm.Base):
    facts = tpm.WhatIf.facts

    def test_a_task_naming_its_host_by_another_case_still_touches_the_interface_ssh_comes_in_on(self):
        self.facts(tpm.ufw_fw())
        with mock.patch.object(tpm.security, '_controller_ips', return_value=['192.168.1.5']):
            got = whatif.run(self.conn, {'tasks': [{'host': 'NAS', 'type': 'net-bridge', 'params': {'name': 'br1', 'ports': 'eth0'}}]})
        self.assertTrue(got['blocked'], got['conflicts'])
        with mock.patch.object(tpm.security, '_controller_ips', return_value=['192.168.1.5']):
            got = whatif.run(self.conn, {'tasks': [{'host': 'NAS', 'type': 'net-bridge', 'params': {'name': 'br1', 'ports': 'eth0', 'rollback': '5'}}]})
        self.assertFalse(got['blocked'], got['conflicts'])


class ZfsDesign(unittest.TestCase):
    def plan(self, **changed):
        pool = {'name': 'tank', 'type': 'zfs', 'level': 'mirror', 'members': ['sdb1', 'sdc1'], 'datasets': []}
        have = {'devices': [], 'pools': [pool], 'remotes': [], 'links': [], 'exports': [], 'mounts': [], 'protection': []}
        design = json.loads(json.dumps(have))
        design['metadata'] = {'host': 'nas'}
        design['pools'][0].update(changed)
        h = {'name': 'nas', 'mounts': [], 'ssh_host': 'nas', 'id': 1}
        with mock.patch.object(fromdesign, 'hosts', return_value={'nas': h}), mock.patch.object(fromdesign.blueprint, 'from_index', return_value=have):
            return fromdesign.plan(None, design)

    def test_a_design_that_matches_the_pool_says_nothing(self):
        r = self.plan()
        self.assertEqual((r['tasks'], r['manual']), ([], []))
        self.assertEqual(self.plan(members=['sdb', 'sdc'])['manual'], [], 'the scan lists partitions, the design disks')

    def test_a_device_or_level_the_design_changes_is_listed_by_hand(self):
        r = self.plan(members=['sdb', 'sdc', 'sdd', 'sde'])
        self.assertEqual([m['what'] for m in r['manual']], ['Add /dev/sdd to tank', 'Add /dev/sde to tank'])
        r = self.plan(level='raidz1')
        self.assertIn('Reshape zfs tank from mirror to raidz1', [m['what'] for m in r['manual']])


if __name__ == '__main__':
    unittest.main()
