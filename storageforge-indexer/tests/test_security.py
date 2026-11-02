"""Unit tests for Ransomware Defense & Host Security backend engine."""
import hashlib
import json
import shutil
import tempfile
import time
import unittest
from pathlib import Path

from storageforge_index import backup, permissions, security, server, users
from storageforge_index.db import Database

PW = 'a very secure password for tests'


class TestSecurityEngine(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db = Database(f'sqlite:///{self.tmp}/test.db')
        self.conn = self.db.connect()
        self.db.migrate(self.conn)
        users.create(self.conn, 'admin1', PW, 'admin')
        users.create(self.conn, 'admin2', PW, 'admin')
        self.app = server.App(self.db)
        self.web = server.create_app(self.app, 's' * 48)
        self.client = self.web.test_client()

    def tearDown(self):
        self.conn.close()
        shutil.rmtree(self.tmp)

    def _login(self, username='admin1'):
        r = self.client.post('/api/login', json={'username': username, 'password': PW})
        self.assertEqual(r.status_code, 200)

    def test_shannon_entropy_calculation(self):
        self.assertEqual(security.calculate_shannon_entropy(b''), 0.0)
        # Low entropy plaintext
        plain = b'A' * 1000
        self.assertEqual(security.calculate_shannon_entropy(plain), 0.0)
        # Structured English plaintext (typically 3.0 - 5.0)
        text = b'StorageForge provides immutable WORM snapshot retention and ransomware defense.' * 50
        e_text = security.calculate_shannon_entropy(text)
        self.assertTrue(3.5 < e_text < 5.0)
        # High entropy pseudo-random/ciphertext (typically > 7.5)
        crypto = bytes(range(256)) * 4
        e_crypto = security.calculate_shannon_entropy(crypto)
        self.assertAlmostEqual(e_crypto, 8.0, delta=0.1)

    def test_adaptive_quorum_and_worm_holds(self):
        self._login('admin1')
        # Apply WORM hold
        r = self.client.post('/api/security/worm/hold', json={
            'host': 'nas-01',
            'dataset': 'tank/shares',
            'snapshot': 'tank/shares@daily-20261102',
            'retention_days': 14,
            'legal_hold': False,
        })
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertTrue(data['ok'])
        hold_id = data['hold_id']

        # Request release (should trigger Dual-Admin Quorum or timelock)
        r2 = self.client.post('/api/security/worm/release', json={'hold_id': hold_id})
        self.assertEqual(r2.status_code, 200)
        rel_data = r2.get_json()
        self.assertTrue(rel_data['ok'])
        timelock_id = rel_data['timelock_id']

        # Same admin cannot approve their own quorum in multi-admin mode
        r3 = self.client.post('/api/security/worm/quorum/approve', json={'timelock_id': timelock_id})
        self.assertEqual(r3.status_code, 409)

        # Login as second admin and approve
        self._login('admin2')
        r4 = self.client.post('/api/security/worm/quorum/approve', json={'timelock_id': timelock_id})
        self.assertEqual(r4.status_code, 200)
        self.assertTrue(r4.get_json()['ok'])

    def test_break_glass_recovery_key(self):
        # Generate break-glass key
        self._login('admin1')
        gen_res = security.break_glass_worm(self.conn, {'action': 'generate'}, 'admin1')
        self.assertTrue(gen_res['ok'])
        bg_key = gen_res['break_glass_key']
        self.assertEqual(len(bg_key), 64)

        # Apply hold & request release
        apply_res = security.apply_worm_hold(self.conn, {'host': 'nas-01', 'snapshot': 'tank@test-bg'}, 'admin1')
        rel_res = security.request_worm_release(self.conn, {'hold_id': apply_res['hold_id']}, 'admin1')
        tid = rel_res['timelock_id']

        # Bypass with break-glass key
        r = self.client.post('/api/security/worm/break-glass', json={'timelock_id': tid, 'break_glass_key': bg_key})
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.get_json()['break_glass_used'])

    def test_clock_guard_forward_jump_tripwire(self):
        # Forward jump of 30 days (>60s) triggers emergency freeze
        jump_res = security.check_clock_jump(self.conn, 'nas-01', 30 * 86400, 'test_attacker')
        self.assertTrue(jump_res['tripped'])
        status = security.clock_guard_status(self.conn)
        self.assertTrue(status['emergency_freeze'])

        # Attempting hold release while clock is frozen is rejected
        rel_res = security.request_worm_release(self.conn, {'snapshot': 'tank@snap'}, 'admin1')
        self.assertFalse(rel_res['ok'])
        self.assertIn('freeze', rel_res['error'].lower())

    def test_canary_deployment_and_testing(self):
        self._login('admin1')
        r = self.client.post('/api/security/canaries/deploy', json={
            'host': 'nas-01',
            'shares': ['/srv/shares/accounting', '/srv/shares/legal'],
            'enable_vss_trap': True,
        })
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertTrue(data['ok'])
        self.assertGreaterEqual(data['count'], 6)

        # Test canary list
        r2 = self.client.get('/api/security/canaries?host=nas-01')
        self.assertEqual(r2.status_code, 200)
        canaries_data = r2.get_json()
        self.assertEqual(canaries_data['summary']['total_canaries'], data['count'])
        self.assertGreater(canaries_data['summary']['vss_traps'], 0)

        # Non-destructive test
        r3 = self.client.post('/api/security/canaries/test', json={'host': 'nas-01', 'simulate_trip': False})
        self.assertEqual(r3.status_code, 200)
        self.assertTrue(r3.get_json()['ok'])

    def test_firewall_quarantine_and_airgap(self):
        self._login('admin1')
        # Quarantine an attacker IP
        r = self.client.post('/api/security/firewall/quarantine', json={
            'host': 'nas-01',
            'ip_address': '192.168.1.184',
            'reason': 'Canary tripped',
            'duration_minutes': 60,
        })
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.get_json()['ok'])

        # Attempting to quarantine loopback is blocked
        r_vip = self.client.post('/api/security/firewall/quarantine', json={'host': 'nas-01', 'ip_address': '127.0.0.1'})
        self.assertEqual(r_vip.status_code, 409)

        # Test airgap trigger
        r_air = self.client.post('/api/security/firewall/airgap', json={'host': 'nas-01', 'enabled': True})
        self.assertEqual(r_air.status_code, 200)
        self.assertTrue(r_air.get_json()['airgap_enabled'])

        # Release quarantine
        r_del = self.client.delete('/api/security/firewall/quarantine/192.168.1.184?host=nas-01')
        self.assertEqual(r_del.status_code, 200)
        self.assertTrue(r_del.get_json()['ok'])

    def test_emergency_brake_orchestration(self):
        self._login('admin1')
        r = self.client.post('/api/security/incident/brake', json={
            'host': 'nas-01',
            'client_ip': '10.0.1.42',
            'share_path': '/srv/shares/finance',
            'dataset': 'tank/shares/finance',
            'pid': 14201,
            'reason': 'Mass rename detected on canary',
        })
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertTrue(data['ok'])
        self.assertIn('volatile_ram_triage_dump', data['steps_executed'])
        self.assertIn('ip_quarantined', data['steps_executed'])
        self.assertIn('filesystem_remounted_ro', data['steps_executed'])
        self.assertIn('immutable_snapshot_locked', data['steps_executed'])

    def test_compliance_standards_and_init_script_generator(self):
        self._login('admin1')
        r = self.client.get('/api/security/compliance/standards')
        self.assertEqual(r.status_code, 200)
        stds = r.get_json()['standards']
        self.assertTrue(any(s['id'] == 'cis-l2' for s in stds))
        self.assertTrue(any(s['id'] == 'nist-800-53' for s in stds))

        # Stage compliance init
        r2 = self.client.post('/api/security/compliance/init', json={
            'host': 'nas-01',
            'profile': 'cis-l2',
            'waivers': ['CIS-1.1.1.8'],
        })
        self.assertEqual(r2.status_code, 200)
        data = r2.get_json()
        self.assertTrue(data['ok'])
        self.assertIn('sf_install_security_prereqs', data['script'])
        self.assertIn('sf_harden_sysctl_and_umask', data['script'])


if __name__ == '__main__':
    unittest.main()
