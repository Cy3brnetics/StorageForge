"""Monitoring-only hosts (roadmap section 11.5, "Hosts by mode"; agentmonitor.py): a host the controller has no SSH scan key or deploy
access for, set up by hand with the same setup script, adopted with the line it prints, its agent enrolled through the real
storageforge-agentctl, and refused, with the reason, everything that acts over SSH as root.

What is real: the setup script in bash, storageforge-agentctl and the agent built by cargo, the requests the controller signs, ssh-keygen
for the host key, the database on SQLite and PostgreSQL, deploy.run's refusal. What stands in: the host's root (a folder) and its
runtime, as in test_agent."""
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import dbfactory
import test_agent
from storageforge_index import agentmonitor, deploy, sfagent
from storageforge_index.remote import known_host_keys
from storageforge_index.runner import known_hosts_path


class Adopt(test_agent.Base):
    def setUp(self):
        super().setUp()
        # nas is not a host StorageForge scans or deploys to: no deploy access, no inventory but what the admin said
        self.conn.execute("DELETE FROM deploy_access WHERE host = 'nas'")
        self.conn.execute("DELETE FROM hosts WHERE hostname = 'nas'")
        agentmonitor.register(self.conn, 'nas', '10.0.0.3', 22, 'x86_64', 'test')
        key = self.host.root / 'etc/ssh/ssh_host_ed25519_key'
        key.unlink()
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(key)], check=True)
        self.host_key = (self.host.root / 'etc/ssh/ssh_host_ed25519_key.pub').read_text().split()[1]

    def test_a_host_set_up_by_hand_is_adopted_with_the_line_its_setup_printed(self):
        self.assertTrue(agentmonitor.monitoring_only(self.conn, 'nas'))
        bundle = agentmonitor.setup(self.db, 'nas')
        self.assertEqual(bundle['program_size'], len(self.program))
        self.assertNotIn('PRIVATE', bundle['script'])
        p = self.host.run_setup(bundle['script'], self.program)
        self.assertEqual(p.returncode, 0, p.stderr.decode())
        line = next(l for l in p.stdout.decode().splitlines() if l.startswith('storageforge-agent-adopt '))
        self.assertEqual(line, f'storageforge-agent-adopt {test_agent.MACHINE} ssh-ed25519 {self.host_key}')
        got = agentmonitor.adopt(self.db, 'nas', line, 'test')
        self.assertEqual((got['state'], got['mode']), ('running', 'monitoring'))
        row = sfagent.get(self.conn, 'nas')
        self.assertEqual((row['mode'], row['state'], row['host_key']), ('monitoring', 'running', f'ssh-ed25519 {self.host_key}'))
        self.assertEqual(row['public_key'], (self.host.root / 'var/lib/storageforge-agent/state/agent_key.pub').read_text().strip())
        self.assertEqual(self.conn.scalar("SELECT machine_id FROM hosts WHERE hostname = 'nas'"), test_agent.MACHINE)
        # the host key is pinned as a key a person compared: the controller's SSH to storageforge-agentctl checks it from now on
        self.assertEqual(known_host_keys('10.0.0.3', 22, str(known_hosts_path())), [got['host_key']])
        self.assertEqual(self.conn.scalar("SELECT confirmed_by FROM host_key_confirmations WHERE address = '10.0.0.3'"), 'test')
        self.assertFalse(deploy.ready(self.conn, 'nas'), 'no deploy access was set up')
        self.assertIn(('agent.enroll', 'ok'), self.audit())

    def test_a_line_that_is_not_the_setups_or_another_host_key_is_refused(self):
        for bad in ('', 'storageforge-agent-adopt none none', f'storageforge-agent-adopt {test_agent.MACHINE} ssh-rsa AAAA', 'rm -rf /'):
            with self.assertRaises(agentmonitor.MonitoringError):
                agentmonitor.adopt(self.db, 'nas', bad, 'test')
        known_hosts_path().write_text('10.0.0.3 ssh-ed25519 ' + 'A' * 68 + '\n')
        with self.assertRaises(agentmonitor.MonitoringError) as e:
            agentmonitor.adopt(self.db, 'nas', f'storageforge-agent-adopt {test_agent.MACHINE} ssh-ed25519 {self.host_key}', 'test')
        self.assertIn('another host key', str(e.exception))
        self.assertEqual(sfagent.get(self.conn, 'nas')['state'], 'on', 'nothing was enrolled')

    def test_a_host_storageforge_has_already_is_not_registered_again(self):
        with self.assertRaises(agentmonitor.MonitoringError):
            agentmonitor.register(self.conn, 'nas', '10.0.0.9', 22, 'x86_64', 'test')
        with self.assertRaises(agentmonitor.MonitoringError):
            agentmonitor.register(self.conn, 'other', '10.0.0.3', 22, 'x86_64', 'test')
        with self.assertRaises(agentmonitor.MonitoringError):
            agentmonitor.register(self.conn, 'bad name;', '10.0.0.8', 22, 'x86_64', 'test')

    def test_windows_monitoring_host_generates_native_service_powershell_setup(self):
        agentmonitor.register(self.conn, 'winbox', '10.0.0.44', 22, 'x86_64', 'test', os_family='windows')
        self.assertEqual(agentmonitor.host_os(self.conn, 'winbox'), 'windows')
        self.assertEqual(sfagent.host_arch(self.conn, 'winbox'), 'x86_64')
        bundle = agentmonitor.setup(self.db, 'winbox')
        self.assertEqual((bundle['platform'], bundle['service']), ('windows', 'StorageForgeAgent'))
        self.assertIn('sc.exe create StorageForgeAgent', bundle['script'])
        self.assertIn('administrators_authorized_keys', bundle['script'])
        self.assertIn('storageforge-agent-adopt', bundle['script'])
        with self.assertRaises(agentmonitor.MonitoringError):
            agentmonitor.register(self.conn, 'bad-os', '10.0.0.45', 22, 'x86_64', 'test', os_family='solaris')


class Features(unittest.TestCase):
    """What a monitoring-only host does not get is refused with the reason, before anything reaches it."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.db = dbfactory.make(self, self.tmp / 'index.db')
        self.conn = self.db.connect()
        self.addCleanup(self.conn.close)
        self.db.migrate(self.conn)
        agentmonitor.register(self.conn, 'quiet', '10.0.0.7', 22, 'arm64', 'test')

    def test_deploys_and_everything_over_ssh_as_root_are_refused_with_the_reason(self):
        got = deploy.run(self.db, 'quiet', 'echo hello', kind='nfs', mode='apply', actor='test', require_ready=False)
        self.assertEqual(got['status'], 'failed')
        self.assertIn('quiet is monitoring only', got['output'])
        self.assertIn('Set up SSH access to the host to have it', got['output'])
        with self.assertRaises(deploy.DeployError):
            with deploy.raw(self.db, 'quiet', 'tar c .', kind='send', actor='test'):
                pass
        self.assertIsNone(agentmonitor.refusal(self.conn, 'elsewhere', 'deploys'))
        self.assertEqual(sfagent.host_arch(self.conn, 'quiet'), 'aarch64')
        listed = {a['host']: a for a in sfagent.view(self.conn)}
        self.assertEqual(listed['quiet']['mode'], 'monitoring')


if __name__ == '__main__':
    unittest.main()
