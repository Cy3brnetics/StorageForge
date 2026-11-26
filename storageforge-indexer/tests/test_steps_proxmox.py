"""The Proxmox VE action and remove steps: checked against the reading, run as a report and as an Ansible export with stubbed qm and pct."""
import os
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
from storageforge_index import changes, security

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


if __name__ == '__main__':
    unittest.main()
