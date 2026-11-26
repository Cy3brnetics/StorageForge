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
        for kind in BASE:
            self.assertEqual(changes.TYPES[kind]['group'], 'Proxmox VE')
        self.assertTrue(changes.TYPES['pve-remove']['destructive'])
        self.assertEqual(changes.TYPES['pve-remove']['confirm_of'], 'name')

    def test_a_plain_host_is_not_a_node(self):
        for kind in BASE:
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
        for kind in BASE:
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


if __name__ == '__main__':
    unittest.main()
