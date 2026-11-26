"""The Proxmox VE action and remove steps: checked against the reading, run as a report and as an Ansible export with stubbed qm and pct."""
import hashlib
import os
import shlex
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

import yaml

try:
    from test_tasks import Fleet
except ImportError:      # run as tests.test_x from the project folder
    from tests.test_tasks import Fleet
from storageforge_index import changes, security, steps_proxmox

GUESTS = [{'kind': 'qemu', 'vmid': '101', 'name': 'web', 'state': 'running', 'cores': 2, 'memory_mib': 1024, 'disks': [], 'nics': []},
          {'kind': 'lxc', 'vmid': '102', 'name': 'dns', 'state': 'stopped', 'disks': [], 'nics': [], 'unprivileged': True}]
BASE = {'pve-action': {'kind': 'qemu', 'vmid': '101', 'name': 'web', 'action': 'start'},
        'pve-remove': {'kind': 'qemu', 'vmid': '101', 'name': 'web', 'confirm': 'web'}}


def plan(step, host='nas', **over):
    return {'name': 'pve', 'tasks': [{'type': step, 'host': host, 'params': {**BASE[step], **over}}]}


class Loader(yaml.SafeLoader):
    """A playbook marks its commands !unsafe."""


Loader.add_constructor('!unsafe', lambda loader, node: loader.construct_scalar(node))


class Steps(Fleet):
    def make_node(self, host='nas'):
        security._save_measurement(self.conn, host, 'infra', int(time.time()), 'test', {'tools': ['qm', 'pct'], 'proxmox': GUESTS})

    def items(self, step, host='nas', **over):
        p = changes.normalize(changes.prepare(self.conn, plan(step, host, **over)))
        return [(i['level'], i['text']) for i in changes.check(self.conn, p)['tasks'][0]['items']]

    def stubs(self, state='running', name='web'):
        tmp = Path(tempfile.mkdtemp(dir=self.tmp))
        log = tmp / 'argv.log'
        for tool, key in (('qm', 'name'), ('pct', 'hostname')):
            (tmp / tool).write_text(f'#!/bin/sh\necho "$0 $*" >> {log}\ncase "$1" in status) echo "status: {state}" ;; config) echo "{key}: {name}" ;; esac\n')
            (tmp / tool).chmod(0o755)
        (tmp / 'uname').write_text('#!/bin/sh\necho nas\n')
        (tmp / 'uname').chmod(0o755)
        return tmp, log

    def run_report(self, step, **over):
        text = changes.script(self.conn, changes.normalize(plan(step, **over)))
        self.assertEqual(subprocess.run(['bash', '-n'], input=text, text=True, capture_output=True).returncode, 0)
        tmp, _ = self.stubs()
        r = subprocess.run(['bash', '-s', '--', '--report'], input=text, env={**os.environ, 'PATH': f'{tmp}:{os.environ["PATH"]}'}, capture_output=True, text=True, timeout=120)
        return r.stdout + r.stderr

    def run_export(self, step, state='running', stub_name=None, **over):
        p = changes.normalize(plan(step, **over))
        doc = yaml.load(changes.ansible(self.conn, p), Loader)
        cmds = [t['ansible.builtin.shell']['cmd'] for play in doc for t in play['tasks'] if 'ansible.builtin.shell' in t]
        cmd = next(c for c in cmds if 't_pve_' in c)
        self.assertEqual(subprocess.run(['bash', '-n'], input=cmd, text=True, capture_output=True).returncode, 0)
        tmp, log = self.stubs(state, stub_name or over.get('name', 'web'))
        r = subprocess.run(['bash', '-c', cmd], env={**os.environ, 'PATH': f'{tmp}:{os.environ["PATH"]}'}, capture_output=True, text=True, timeout=60)
        return r, (log.read_text() if log.exists() else '')


class Check(Steps):
    def test_both_kinds_are_in_the_proxmox_group(self):
        for kind in ('pve-action', 'pve-remove'):
            self.assertEqual(changes.TYPES[kind]['group'], 'Proxmox VE')
        self.assertTrue(changes.TYPES['pve-remove']['destructive'])
        self.assertEqual(changes.TYPES['pve-remove']['confirm_of'], 'name')

    def test_a_plain_host_is_not_a_node(self):
        for kind in ('pve-action', 'pve-remove'):
            self.assertTrue(any(lv == 'crit' and 'not a Proxmox VE node' in t for lv, t in self.items(kind, 'pc')), kind)

    def test_a_running_guest_started_is_already_running(self):
        self.make_node()
        self.assertTrue(any(lv == 'ok' and 'already running' in t for lv, t in self.items('pve-action')))

    def test_a_vmid_not_in_the_reading_is_looked_up_when_the_script_runs(self):
        self.make_node()
        items = self.items('pve-action', vmid='555')
        self.assertTrue(any(lv == 'note' and 'looks when it runs' in t for lv, t in items))
        self.assertFalse(any(lv == 'crit' for lv, _ in items))

    def test_a_snapshot_needs_a_name(self):
        self.make_node()
        self.assertTrue(any(lv == 'crit' and 'name the snapshot' in t for lv, t in self.items('pve-action', action='snapshot')))
        self.assertFalse(any(lv == 'crit' for lv, _ in self.items('pve-action', action='snapshot', snapshot='before-upgrade')))

    def test_removing_a_running_guest_says_stop_it_first(self):
        self.make_node()
        self.assertTrue(any(lv == 'crit' and 'stop it first' in t for lv, t in self.items('pve-remove')))

    def test_removing_a_stopped_guest_is_clean(self):
        self.make_node()
        self.assertFalse(any(lv == 'crit' for lv, _ in self.items('pve-remove', kind='lxc', vmid='102', name='dns', confirm='dns')))

    def test_a_name_that_is_not_the_guests_is_a_crit(self):
        self.make_node()
        for kind in ('pve-action', 'pve-remove'):
            self.assertTrue(any(lv == 'crit' and 'named web' in t for lv, t in self.items(kind, name='other', confirm='other')), kind)

    def test_the_vmid_and_kind_are_held_to_their_range(self):
        for bad in ('99', '1000000000', '0101', 'x'):
            with self.assertRaises(ValueError):
                changes.normalize(plan('pve-action', vmid=bad))
        self.make_node()
        self.assertTrue(any(lv == 'crit' and 'a container' in t for lv, t in self.items('pve-action', vmid='102', name='dns', kind='qemu')))


class Run(Steps):
    def test_the_report_says_what_it_would_do_and_changes_nothing(self):
        out = self.run_report('pve-action', action='shutdown')
        self.assertRegex(out, r'missing.*would: shutdown web \(101\)')
        self.assertNotIn('command not found', out)

    def test_the_report_of_a_remove_is_stopped_by_a_running_guest(self):
        self.assertIn('stop it first', self.run_report('pve-remove'))

    def test_an_export_acts_through_qm(self):
        r, log = self.run_export('pve-action', action='shutdown')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('qm shutdown 101', log)
        self.assertNotIn('command not found', r.stderr)

    def test_an_export_snapshots_a_container_through_pct(self):
        r, log = self.run_export('pve-action', name='dns', kind='lxc', vmid='102', action='snapshot', snapshot='snap1')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('pct snapshot 102 snap1', log)

    def test_a_remove_whose_name_differs_never_reaches_destroy(self):
        r, log = self.run_export('pve-remove', state='stopped', stub_name='other')
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('named other, not web', r.stderr)
        self.assertNotIn('destroy', log)

    def test_a_remove_of_a_running_guest_never_reaches_destroy(self):
        r, log = self.run_export('pve-remove')
        self.assertIn('stop it first', r.stderr)
        self.assertNotIn('destroy', log)

    def test_a_remove_of_the_right_stopped_guest_destroys_it_with_purge(self):
        r, log = self.run_export('pve-remove', state='stopped', purge=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('qm destroy 101 --purge', log)
        r, log = self.run_export('pve-remove', state='stopped', purge=False)
        self.assertTrue(log.strip().endswith('qm destroy 101'), log)

    def test_the_export_of_a_remove_is_marked_destructive(self):
        doc = yaml.load(changes.ansible(self.conn, changes.normalize(plan('pve-remove'))), Loader)
        task = next(t for play in doc for t in play['tasks'] if 't_pve_remove' in str(t))
        self.assertEqual(task['tags'], ['destructive'])


NODE = {'storages': [{'name': 'local', 'type': 'dir', 'active': True, 'content': ['iso', 'vztmpl', 'backup']},
                      {'name': 'local-lvm', 'type': 'lvmthin', 'active': True, 'content': ['images', 'rootdir']},
                      {'name': 'tank', 'type': 'zfspool', 'active': True, 'content': ['images']}],
        'isos': [], 'templates': [{'storage': 'local', 'volid': 'local:vztmpl/debian-13.tar.zst', 'size': 1}]}
CT = {'hostname': 'web-01', 'template': 'local:vztmpl/debian-13.tar.zst', 'storage': 'local-lvm', 'vmid': '105'}
BASE['pve-ct'] = CT
KEY = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl ops@laptop'
PASSWORD = 'S3cret-pass_word,42'


class Container(Steps):
    def make_node(self, node=NODE, host='nas'):
        security._save_measurement(self.conn, host, 'infra', int(time.time()), 'test', {'tools': ['qm', 'pct', 'pvesm'], 'proxmox': GUESTS, 'proxmox_node': node})

    def says(self, **over):
        return self.items('pve-ct', **over)

    def test_it_is_in_the_proxmox_group_and_asks_for_the_vault_secret(self):
        from storageforge_index import secretstore
        self.assertEqual(changes.TYPES['pve-ct']['group'], 'Proxmox VE')
        self.assertEqual(secretstore.secret_fields(changes.TYPES['pve-ct']), ['password_secret'])

    def test_a_good_container_checks_clean(self):
        self.make_node()
        self.assertFalse(any(lv == 'crit' for lv, _ in self.says()), self.says())

    def test_a_storage_the_node_lacks_is_named_with_the_ones_it_has(self):
        self.make_node()
        self.assertTrue(any(lv == 'crit' and 'no storage nope' in t and 'local-lvm' in t for lv, t in self.says(storage='nope')))

    def test_a_storage_without_rootdir_is_refused(self):
        self.make_node()
        self.assertTrue(any(lv == 'crit' and 'tank does not hold container disks' in t for lv, t in self.says(storage='tank')))

    def test_a_bare_template_is_downloaded_and_a_volid_on_the_wrong_storage_is_refused(self):
        self.make_node()
        self.assertTrue(any(lv == 'warn' and 'downloaded with pveam' in t for lv, t in self.says(template='debian-12.tar.zst')))
        self.assertTrue(any(lv == 'crit' and 'local-lvm does not hold container templates' in t for lv, t in self.says(template='local-lvm:vztmpl/x.tar.zst')))
        self.assertTrue(any(lv == 'ok' for lv, t in self.says(template='debian-13.tar.zst')))

    def test_an_old_scan_without_the_node_data_only_notes_it(self):
        security._save_measurement(self.conn, 'nas', 'infra', int(time.time()), 'test', {'tools': ['qm', 'pct']})
        items = self.says()
        self.assertTrue(any(lv == 'note' and 'not read yet' in t for lv, t in items))
        self.assertFalse(any(lv == 'crit' for lv, _ in items))

    def test_a_fixed_address_wants_a_gateway_and_nonsense_is_refused(self):
        self.make_node()
        self.assertTrue(any(lv == 'warn' and 'no gateway' in t for lv, t in self.says(ip='10.0.0.5/24')))
        self.assertFalse(any('gateway' in t for _, t in self.says(ip='10.0.0.5/24', gateway='10.0.0.1')))
        with self.assertRaises(ValueError):
            changes.normalize(plan('pve-ct', ip='nonsense'))

    def test_a_plain_host_and_an_existing_vmid_are_refused(self):
        self.assertTrue(any(lv == 'crit' and 'not a Proxmox VE node' in t for lv, t in self.says(host='pc')))
        self.make_node()
        self.assertTrue(any(lv == 'crit' and 'already web' in t for lv, t in self.says(vmid='101')))

    def test_the_secret_is_delivered_by_name_and_the_script_holds_only_the_name(self):
        from storageforge_index import secretstore
        p = plan('pve-ct', password_secret='ct-root')
        self.assertEqual(secretstore.plan_secrets(self.conn, p), {'nas': [('ct-root', 'pve-ct')]})
        text = changes.script(self.conn, changes.normalize(p))
        self.assertIn('ct-root', text)
        self.assertNotIn(PASSWORD, text)


class CtRun(Steps):
    def ct_stubs(self, exists=False, downloaded=True):
        tmp, log = self.stubs()
        (tmp / 'pct').write_text('#!/bin/sh\necho "$0 $*" >> %s\ncase "$1" in status) %s ;; exec) cat >> %s.stdin ;; esac\n'
                                 % (log, 'echo "status: running"; exit 0' if exists else 'exit 2', log))
        (tmp / 'pvesh').write_text('#!/bin/sh\necho 105\n')
        (tmp / 'pvesm').write_text('#!/bin/sh\necho "Name Type Status Total Used Avail %"\necho "local dir active 1 1 1 1%"\n')
        (tmp / 'pveam').write_text('#!/bin/sh\necho "$0 $*" >> %s\n[ "$1" = list ] && %s\nexit 0\n'
                                   % (log, 'echo "local:vztmpl/debian-13.tar.zst 1 1"' if downloaded else 'true'))
        (tmp / 'sleep').write_text('#!/bin/sh\nexit 0\n')
        for n in ('pct', 'pvesh', 'pvesm', 'pveam', 'sleep'):
            (tmp / n).chmod(0o755)
        (tmp / 'secrets').mkdir()
        (tmp / 'secrets' / 'ct-root').write_text(PASSWORD)
        return tmp, log

    def env(self, tmp):
        return {**os.environ, 'PATH': f'{tmp}:{os.environ["PATH"]}', 'SF_SECRET_DIR': str(tmp / 'secrets')}

    def export_cmd(self, **over):
        doc = yaml.load(changes.ansible(self.conn, changes.normalize(plan('pve-ct', **over))), Loader)
        cmd = next(t['ansible.builtin.shell']['cmd'] for play in doc for t in play['tasks'] if 'ansible.builtin.shell' in t and 't_pve_ct' in t['ansible.builtin.shell']['cmd'])
        self.assertEqual(subprocess.run(['bash', '-n'], input=cmd, text=True, capture_output=True).returncode, 0)
        return cmd

    def test_the_script_is_valid_bash_and_the_report_would_create(self):
        text = changes.script(self.conn, changes.normalize(plan('pve-ct', vmid='')))
        self.assertEqual(subprocess.run(['bash', '-n'], input=text, text=True, capture_output=True).returncode, 0)
        tmp, log = self.ct_stubs()
        r = subprocess.run(['bash', '-s', '--', '--report'], input=text, env=self.env(tmp), capture_output=True, text=True, timeout=120)
        out = r.stdout + r.stderr
        self.assertIn('would: create container 105', out)
        self.assertNotIn('command not found', out)
        self.assertNotIn(' create ', log.read_text().replace('status', ''))

    def test_a_vmid_that_exists_is_a_conflict_and_pct_create_is_never_called(self):
        tmp, log = self.ct_stubs(exists=True)
        r = subprocess.run(['bash', '-c', self.export_cmd()], env=self.env(tmp), capture_output=True, text=True, timeout=60)
        self.assertIn('already a guest', r.stderr)
        self.assertNotIn('create', log.read_text())

    def test_an_apply_creates_with_the_key_in_a_temp_file_and_the_password_on_stdin_only(self):
        tmp, log = self.ct_stubs()
        r = subprocess.run(['bash', '-c', self.export_cmd(password_secret='ct-root', ssh_key=KEY, onboot=True, ip='10.0.0.5/24', gateway='10.0.0.1')],
                           env=self.env(tmp), capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        argv = log.read_text()
        self.assertRegex(argv, r'pct create 105 local:vztmpl/debian-13.tar.zst --hostname web-01 --storage local-lvm --rootfs local-lvm:8 --cores 1 --memory 512 '
                               r'--net0 name=eth0,bridge=vmbr0,ip=10.0.0.5/24,gw=10.0.0.1 --unprivileged 1 --onboot 1 --ssh-public-keys /')
        self.assertNotIn(PASSWORD, argv)
        self.assertNotIn(PASSWORD, r.stdout + r.stderr)
        self.assertIn('pct start 105', argv)
        self.assertIn('pct shutdown 105', argv, 'not asked to start: stopped again')
        self.assertEqual((tmp / 'argv.log.stdin').read_text(), f'root:{PASSWORD}\n')
        keyfile = argv.split('--ssh-public-keys ')[1].split()[0]
        self.assertFalse(os.path.exists(keyfile), 'the temporary key file is removed')

    def test_start_keeps_it_running_and_a_bare_template_is_downloaded(self):
        tmp, log = self.ct_stubs(downloaded=False)
        r = subprocess.run(['bash', '-c', self.export_cmd(password_secret='ct-root', start=True, template='debian-13.tar.zst')], env=self.env(tmp), capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        argv = log.read_text()
        self.assertIn('pveam download local debian-13.tar.zst', argv)
        self.assertNotIn('pct shutdown', argv)

    def test_the_secret_missing_on_the_host_is_a_conflict_before_anything_is_created(self):
        tmp, log = self.ct_stubs()
        (tmp / 'secrets' / 'ct-root').unlink()
        r = subprocess.run(['bash', '-c', self.export_cmd(password_secret='ct-root')], env=self.env(tmp), capture_output=True, text=True, timeout=60)
        self.assertIn('is not on this host', r.stderr)
        self.assertNotIn('create', log.read_text())


VM = {'name': 'app-01', 'source': 'iso', 'iso': 'local:iso/debian-13.iso', 'storage': 'local-lvm', 'vmid': '106'}
BASE['pve-vm'] = VM
SHA = 'a' * 64


class Vm(CtRun):
    def make_node(self, node=NODE):
        security._save_measurement(self.conn, 'nas', 'infra', int(time.time()), 'test', {'tools': ['qm', 'pct', 'pvesm'], 'proxmox': GUESTS,
                                                                                       'proxmox_node': {**node, 'isos': [{'storage': 'local', 'volid': 'local:iso/debian-13.iso', 'size': 1}]}})

    def says(self, **over):
        return self.items('pve-vm', **over)

    def prepared(self, **over):
        return changes.normalize(changes.prepare(self.conn, plan('pve-vm', **over)))

    def vm_stubs(self, exists=False, match=True):
        tmp, log = self.ct_stubs()
        (tmp / 'qm').write_text('#!/bin/sh\necho "$0 $*" >> %s\ncase "$1" in status) %s ;; help) echo "--scsi0 import-from" ;; esac\n'
                                % (log, 'echo "status: stopped"; exit 0' if exists else 'exit 2'))
        # the stub curl serves an image of known content, and a checksum list that matches it or does not
        (tmp / 'curl').write_text('#!/bin/sh\necho "$0 $*" >> %s\nout=\nwhile [ $# -gt 0 ]; do [ "$1" = -o ] && out=$2; last=$1; shift; done\n'
                                  'case "$last" in *SUMS) echo "%s  debian-13-genericcloud-amd64.qcow2" ;; *) if [ -n "$out" ]; then echo image > "$out"; fi ;; esac\n'
                                  % (log, hashlib.sha256(b'image\n').hexdigest() if match else SHA))
        (tmp / 'curl').chmod(0o755)
        (tmp / 'qm').chmod(0o755)
        (tmp / 'tmpdir').mkdir()
        return tmp, log

    def vm_export_cmd(self, **over):
        doc = yaml.load(changes.ansible(self.conn, self.prepared(**over)), Loader)
        cmd = next(t['ansible.builtin.shell']['cmd'] for play in doc for t in play['tasks'] if 'ansible.builtin.shell' in t and 't_pve_vm' in t['ansible.builtin.shell']['cmd'])
        self.assertEqual(subprocess.run(['bash', '-n'], input=cmd, text=True, capture_output=True).returncode, 0)
        return cmd

    def run_vm(self, tmp, **over):
        env = {**self.env(tmp), 'TMPDIR': str(tmp / 'tmpdir')}
        return subprocess.run(['bash', '-c', self.vm_export_cmd(**over)], env=env, capture_output=True, text=True, timeout=60)

    def test_an_image_import_gets_the_long_timeout_and_an_iso_vm_does_not(self):
        from storageforge_index import receiving

        def timeout(**over):
            return next(i for i in changes.deploy_items(self.db, self.conn, self.prepared(**over), 'apply', 'tester') if i['kind'] == 'changes').get('timeout')
        self.assertEqual(timeout(source='image', iso='', image='debian13'), receiving.LONG_RUN)
        self.assertIsNone(timeout())

    def test_a_source_brings_its_own_field_and_not_the_others(self):
        for over in ({'iso': ''}, {'image': 'debian13'}, {'source': 'image', 'iso': '', 'image': ''}, {'source': 'image', 'image': 'debian13'}):
            with self.subTest(over):
                with self.assertRaises(ValueError):
                    self.prepared(**over)
        self.prepared()
        self.prepared(source='image', iso='', image='debian13')

    def test_storage_iso_and_ssh_key_are_checked(self):
        self.make_node()
        self.assertFalse(any(lv == 'crit' for lv, _ in self.says()), self.says())
        self.assertTrue(any(lv == 'crit' and 'does not hold VM disks' in t for lv, t in self.says(storage='local')))
        self.assertTrue(any(lv == 'crit' and 'no storage nope' in t for lv, t in self.says(storage='nope')))
        self.assertTrue(any(lv == 'crit' and 'not among the ISO images' in t for lv, t in self.says(iso='local:iso/other.iso')))
        self.assertTrue(any(lv == 'warn' and 'no way to log in' in t for lv, t in self.says(source='image', iso='', image='debian13')))
        self.assertFalse(any(lv == 'warn' for lv, _ in self.says(source='image', iso='', image='debian13', ssh_key=KEY)))
        self.assertTrue(any(lv == 'crit' and 'not a Proxmox VE node' in t for lv, t in self.says(host='pc')))

    def test_the_report_would_create_from_the_image_and_the_script_is_valid_bash(self):
        text = changes.script(self.conn, self.prepared(source='image', iso='', image='debian13', vmid=''))
        self.assertEqual(subprocess.run(['bash', '-n'], input=text, text=True, capture_output=True).returncode, 0)
        tmp, log = self.vm_stubs()
        r = subprocess.run(['bash', '-s', '--', '--report'], input=text, env=self.env(tmp), capture_output=True, text=True, timeout=120)
        self.assertIn('would: create VM 105 (app-01) from debian13', r.stdout + r.stderr)
        self.assertNotIn('command not found', r.stdout + r.stderr)
        self.assertNotIn('create', log.read_text().replace('status', ''))

    def test_a_vmid_that_exists_is_a_conflict_and_qm_create_is_never_called(self):
        tmp, log = self.vm_stubs(exists=True)
        r = self.run_vm(tmp)
        self.assertIn('already a guest', r.stderr)
        self.assertNotIn('create', log.read_text())

    def test_an_iso_vm_is_made_with_the_cdrom_and_boot_order(self):
        tmp, log = self.vm_stubs()
        r = self.run_vm(tmp, onboot=True, start=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("qm create 106 --name app-01 --memory 2048 --cores 2 --net0 virtio,bridge=vmbr0 --scsihw virtio-scsi-single --ostype l26 --agent 1 --onboot 1 "
                      "--scsi0 local-lvm:32 --ide2 local:iso/debian-13.iso,media=cdrom --boot order=scsi0;ide2", log.read_text())
        self.assertIn('qm start 106', log.read_text())

    def test_an_image_vm_is_downloaded_checked_imported_and_the_temp_folder_is_gone(self):
        tmp, log = self.vm_stubs()
        r = self.run_vm(tmp, source='image', iso='', image='debian13', ssh_key=KEY)
        self.assertEqual(r.returncode, 0, r.stderr)
        argv = log.read_text()
        self.assertRegex(argv, r'qm create 106 .* --boot order=scsi0 --scsi0 local-lvm:0,import-from=/.*/debian-13-genericcloud-amd64\.qcow2')
        for want in ('qm resize 106 scsi0 32G', '--ide2 local-lvm:cloudinit --ciuser admin --ipconfig0 ip=dhcp --serial0 socket --vga serial0', 'qm set 106 --sshkeys /'):
            self.assertIn(want, argv)
        self.assertEqual(list((tmp / 'tmpdir').iterdir()), [], 'the temporary folder is removed')

    def test_a_download_that_does_not_match_its_checksum_stops_everything(self):
        tmp, log = self.vm_stubs(match=False)
        r = self.run_vm(tmp, source='image', iso='', image='debian13', ssh_key=KEY)
        self.assertIn('does not match its checksum', r.stderr)
        lines = log.read_text().splitlines()
        self.assertTrue(lines[-1].startswith(str(tmp / 'curl')) and ' -o ' in lines[-1], lines)     # the last thing run was the image download
        self.assertFalse(any('create' in l or 'importdisk' in l for l in lines))
        self.assertEqual(list((tmp / 'tmpdir').iterdir()), [], 'the temporary folder is removed on this way out too')

    def failing_qm(self, tmp, verb, name='app-01'):
        (tmp / 'qm').write_text((tmp / 'qm').read_text().replace('esac', f'  config) echo "name: {name}" ;;\n  {verb}) exit 1 ;;\nesac'))

    def test_a_failure_after_qm_create_removes_the_vm_this_run_made(self):
        for verb, over in (('resize', {'source': 'image', 'iso': '', 'image': 'debian13'}), ('set', {'source': 'image', 'iso': '', 'image': 'debian13'})):
            with self.subTest(verb):
                tmp, log = self.vm_stubs()
                self.failing_qm(tmp, verb)
                r = self.run_vm(tmp, **over)
                self.assertNotEqual(r.returncode, 0)
                lines = log.read_text().splitlines()
                self.assertIn(f'{tmp}/qm destroy 106 --purge', lines)
                self.assertLess(next(i for i, x in enumerate(lines) if ' create ' in x), lines.index(f'{tmp}/qm destroy 106 --purge'))
                self.assertIn('removed the half-made VM 106 (app-01)', r.stdout)
                self.assertEqual(list((tmp / 'tmpdir').iterdir()), [])

    def test_the_undo_leaves_a_vm_that_is_not_named_as_the_step_says(self):
        tmp, log = self.vm_stubs()
        self.failing_qm(tmp, 'resize', name='someone-else')
        r = self.run_vm(tmp, source='image', iso='', image='debian13')
        self.assertNotEqual(r.returncode, 0)
        self.assertNotIn('destroy', log.read_text())

    def test_a_failure_before_qm_create_destroys_nothing(self):
        tmp, log = self.vm_stubs(match=False)
        self.failing_qm(tmp, 'resize')
        self.run_vm(tmp, source='image', iso='', image='debian13')
        self.assertNotIn('destroy', log.read_text())

    def test_a_vm_that_was_made_and_started_is_not_destroyed(self):
        tmp, log = self.vm_stubs()
        self.failing_qm(tmp, 'start')
        self.run_vm(tmp, start=True)
        self.assertNotIn('destroy', log.read_text())

    def with_trap(self, tmp, cmd):
        return f"trap 'echo ran > {tmp}/marker' EXIT\n" + cmd

    def test_a_trap_of_the_script_around_it_still_runs_after_a_checksum_mismatch(self):
        tmp, log = self.vm_stubs(match=False)
        env = {**self.env(tmp), 'TMPDIR': str(tmp / 'tmpdir')}
        r = subprocess.run(['bash', '-c', self.with_trap(tmp, self.vm_export_cmd(source='image', iso='', image='debian13'))], env=env, capture_output=True, text=True, timeout=60)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('does not match its checksum', r.stderr)
        self.assertTrue((tmp / 'marker').exists(), 'the existing EXIT trap ran')
        self.assertEqual(list((tmp / 'tmpdir').iterdir()), [])

    def test_a_trap_of_the_script_around_it_runs_at_the_end_after_a_good_run(self):
        tmp, log = self.vm_stubs()
        env = {**self.env(tmp), 'TMPDIR': str(tmp / 'tmpdir')}
        r = subprocess.run(['bash', '-c', self.with_trap(tmp, self.vm_export_cmd(source='image', iso='', image='debian13'))], env=env, capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue((tmp / 'marker').exists())
        self.assertEqual(list((tmp / 'tmpdir').iterdir()), [])

    def test_in_a_script_a_failed_download_counts_a_problem_and_keeps_the_trap(self):
        tmp, log = self.vm_stubs(match=False)
        head = ('APPLY=1; PROBLEMS=0; ok() { echo "ok: $*"; }; missing() { echo "missing: $*"; }; info() { :; }; doing() { :; }; later() { conflict "$*"; }\n'
                'conflict() { echo "conflict: $*" >&2; PROBLEMS=$((PROBLEMS + 1)); }; act() { echo "changed: $*"; }; try() { "$@" || { conflict "failed: $*"; return 1; }; }\n')
        call = ' '.join(shlex.quote(w) for w in ('106', 'app-01', 'image', '', 'debian13', 'local-lvm', '32', '2', '2048', 'vmbr0', 'l26', 'admin', '', '', ''))
        script = self.with_trap(tmp, head + steps_proxmox._vm_helpers() + steps_proxmox.BASH + f'\nt_pve_vm {call}\necho "problems: $PROBLEMS"\n')
        env = {**self.env(tmp), 'TMPDIR': str(tmp / 'tmpdir')}
        r = subprocess.run(['bash', '-c', script], env=env, capture_output=True, text=True, timeout=60)
        self.assertIn('problems: 1', r.stdout)      # counted in the script, not lost with the subshell
        self.assertIn('does not match its checksum', r.stderr)
        self.assertTrue((tmp / 'marker').exists())
        self.assertEqual(list((tmp / 'tmpdir').iterdir()), [])
        self.assertFalse(any('create' in l for l in log.read_text().splitlines()))

    def plan_style(self, tmp, call):
        head = ('APPLY=1; PROBLEMS=0; ok() { echo "ok: $*"; }; missing() { echo "missing: $*"; }; info() { :; }; doing() { :; }; later() { conflict "$*"; }\n'
                'conflict() { echo "conflict: $*" >&2; PROBLEMS=$((PROBLEMS + 1)); }; act() { echo "changed: $*"; }; try() { "$@" || { conflict "failed: $*"; return 1; }; }\n')
        script = head + steps_proxmox._vm_helpers() + steps_proxmox.BASH + f'\nt_pve_vm {call}\necho "problems: $PROBLEMS"\n'
        return subprocess.run(['bash', '-c', script], env={**self.env(tmp), 'TMPDIR': str(tmp / 'tmpdir')}, capture_output=True, text=True, timeout=60)

    def test_in_a_script_a_failed_start_counts_a_problem_and_the_step_is_not_done(self):
        tmp, log = self.vm_stubs()
        (tmp / 'qm').write_text((tmp / 'qm').read_text().replace('esac', '  start) exit 1 ;;\nesac'))
        call = ' '.join(shlex.quote(w) for w in ('106', 'app-01', 'iso', 'local:iso/debian-13.iso', '', 'local-lvm', '32', '2', '2048', 'vmbr0', 'l26', 'admin', '', '', '1'))
        r = self.plan_style(tmp, call)
        self.assertIn('problems: 1', r.stdout)
        self.assertIn('failed: qm start 106', r.stderr)
        self.assertNotIn('started 106', r.stdout)
        self.assertIn('qm create 106', log.read_text())

    def test_an_export_carries_the_catalog_and_the_fetch_function(self):
        cmd = self.vm_export_cmd(source='image', iso='', image='debian13')
        self.assertIn('sf_vm_image()', cmd)
        self.assertIn('sf_vm_fetch()', cmd)


class CtPassword(CtRun):
    def test_a_failing_chpasswd_stops_the_container_before_the_conflict_and_shows_the_real_error(self):
        tmp, log = self.ct_stubs()
        (tmp / 'pct').write_text('#!/bin/sh\necho "$0 $*" >> %s\ncase "$1" in status) exit 2 ;; exec) cat >/dev/null; echo "chpasswd: PAM failure" >&2; exit 1 ;; esac\n' % log)
        r = subprocess.run(['bash', '-c', self.export_cmd(password_secret='ct-root')], env=self.env(tmp), capture_output=True, text=True, timeout=60)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('could not set the root password of 105: chpasswd: PAM failure', r.stderr)
        self.assertNotIn(PASSWORD, r.stdout + r.stderr + log.read_text())
        self.assertIn('pct shutdown 105', log.read_text())


if __name__ == '__main__':
    unittest.main()
