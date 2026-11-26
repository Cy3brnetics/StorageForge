"""The generic VM and LXC steps refuse a Proxmox VE node, and plain LXC can be started, stopped and snapshotted."""
import json
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
from storageforge_index import changes, security, steps_infra

NODE = 'Proxmox VE node'
KEY = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl ops@laptop'
STEPS = {
    'vm-create': {'name': 'web', 'image': 'debian13', 'ssh_key': KEY},
    'vm-iso': {'name': 'web', 'iso': 'custom', 'iso_url': 'https://example.org/a.iso', 'iso_sha': 'a' * 64},
    'vm': {'name': 'web', 'disk': '/var/lib/libvirt/images/web.qcow2'},
    'vm-define': {'name': 'web', 'folder': '/var/lib/libvirt/images', 'disks': 'vda:virtio:qcow2:web-vda.qcow2', 'vcpus': '2', 'memory_mib': '2048'},
    'lxc': {'name': 'web', 'distro': 'debian', 'release': 'trixie'},
    'incus': {'name': 'web'},
    'workload-action': {'runtime': 'lxc', 'name': 'web', 'action': 'stop'},
    'managed-workload-remove': {'runtime': 'lxc', 'name': 'web', 'confirm': 'web'},
}


def plan(kind, host, **over):
    return {'name': 'pve guards', 'tasks': [{'type': kind, 'host': host, 'params': {**STEPS[kind], **over}}]}


class Guards(Fleet):
    def items(self, kind, host, **over):
        p = changes.normalize(changes.prepare(self.conn, plan(kind, host, **over)))
        return [(i['level'], i['text']) for i in changes.check(self.conn, p)['tasks'][0]['items']]

    def make_node(self, host):
        security._save_measurement(self.conn, host, 'infra', int(time.time()), 'test', {'tools': ['qm', 'pct']})

    def test_every_generic_step_refuses_a_node(self):
        self.make_node('nas')
        for kind in STEPS:
            with self.subTest(kind):
                self.assertTrue(any(lv == 'crit' and NODE in t for lv, t in self.items(kind, 'nas')), kind)

    def test_the_scan_platform_line_is_enough(self):
        self.conn.execute("UPDATE hosts SET inventory_json = :i WHERE hostname = 'pc'", {'i': json.dumps({'packages': 'platform proxmox 9.1'})})
        self.assertTrue(any(NODE in t for _, t in self.items('lxc', 'pc')))

    def test_a_plain_host_gets_no_such_crit(self):
        for kind in STEPS:
            with self.subTest(kind):
                self.assertFalse(any(NODE in t for _, t in self.items(kind, 'pc')), kind)

    def test_the_other_runtimes_are_not_refused_on_a_node(self):
        self.make_node('nas')
        self.assertFalse(any(NODE in t for _, t in self.items('workload-action', 'nas', runtime='docker')))
        self.assertFalse(any(NODE in t for _, t in self.items('managed-workload-remove', 'nas', runtime='docker')))

    def test_remove_does_not_offer_lxc_and_names_are_checked(self):
        self.assertEqual(steps_infra.REMOVE_RUNTIMES, ['docker', 'podman', 'libvirt', 'incus'])
        self.assertIn('lxc', steps_infra.ACTION_RUNTIMES)
        with self.assertRaises(ValueError):
            changes.normalize({'name': 'x', 'tasks': [{'type': 'workload-remove', 'host': 'nas', 'params': {'runtime': 'lxc', 'name': 'web'}}]})
        with self.assertRaises(ValueError):
            changes.normalize(plan('workload-action', 'nas', name='a;rm -rf /'))


class Report(Fleet):
    def run_report(self, kind, pve_dir, **over):
        p = changes.normalize(plan(kind, 'nas', **over))
        text = changes.script(self.conn, p)
        self.assertEqual(subprocess.run(['bash', '-n'], input=text, text=True, capture_output=True).returncode, 0)
        tmp = Path(tempfile.mkdtemp(dir=self.tmp))
        for name, body in (('uname', 'echo nas'), ('lxc-info', 'echo "State:          RUNNING"')):
            (tmp / name).write_text(f'#!/bin/sh\n{body}\n')
            (tmp / name).chmod(0o755)
        env = {**os.environ, 'PATH': f'{tmp}:{os.environ["PATH"]}', 'SF_PVE_DIR': pve_dir}
        r = subprocess.run(['bash', '-s', '--', '--report'], input=text, env=env, capture_output=True, text=True, timeout=120)
        return r.stdout + r.stderr

    def test_a_plain_lxc_stop_would_stop_it(self):
        out = self.run_report('workload-action', str(Path(self.tmp) / 'no-pve'))
        self.assertRegex(out, r'(?i)missing.*stop web')
        self.assertNotIn('command not found', out)
        self.assertNotIn('Proxmox', out)

    def test_on_a_node_the_script_says_so_and_changes_nothing(self):
        out = self.run_report('workload-action', self.tmp)
        self.assertIn('this is a Proxmox VE node', out)
        self.assertNotRegex(out, r'(?i)missing.*stop web')

    def test_the_other_generic_scripts_say_so_on_a_node(self):
        for kind in ('vm-create', 'lxc', 'incus', 'vm', 'vm-iso', 'managed-workload-remove'):
            with self.subTest(kind):
                out = self.run_report(kind, self.tmp)
                self.assertIn('this is a Proxmox VE node', out)
                self.assertNotIn('command not found', out)


class Loader(yaml.SafeLoader):
    """A playbook marks its commands !unsafe."""


Loader.add_constructor('!unsafe', lambda loader, node: loader.construct_scalar(node))


def shell_cmds(node):
    if isinstance(node, dict):
        found = [node['ansible.builtin.shell']['cmd']] if isinstance(node.get('ansible.builtin.shell'), dict) else []
        return found + [c for v in node.values() for c in shell_cmds(v)]
    return [c for v in node for c in shell_cmds(v)] if isinstance(node, list) else []


class Ansible(Fleet):
    def guarded(self, kind, **over):
        p = changes.normalize(changes.prepare(self.conn, plan(kind, 'nas', **over)))
        return [c for c in shell_cmds(yaml.load(changes.ansible(self.conn, p), Loader)) if 'not_on_pve ||' in c]

    def test_every_guarded_export_defines_the_guard_and_is_valid_bash(self):
        for kind in STEPS:
            with self.subTest(kind):
                cmds = self.guarded(kind)
                self.assertTrue(cmds, kind)
                for c in cmds:
                    self.assertIn('not_on_pve()', c)
                    self.assertEqual(subprocess.run(['bash', '-n'], input=c, text=True, capture_output=True).returncode, 0)

    def test_the_guard_in_an_export_stops_on_a_node(self):
        for kind in ('lxc', 'vm'):
            with self.subTest(kind):
                r = subprocess.run(['bash', '-c', self.guarded(kind)[0]], env={**os.environ, 'SF_PVE_DIR': self.tmp}, capture_output=True, text=True, timeout=60)
                self.assertNotEqual(r.returncode, 0)
                self.assertIn('this is a Proxmox VE node', r.stderr)
                self.assertNotIn('command not found', r.stderr)


if __name__ == '__main__':
    unittest.main()
