"""Hub forwarding, dual-stack IPv6 literal endpoints and signed head/route directory (roadmap section 2.1 / 0.5.14)."""
import json
import os
import re
import shlex
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import dbfactory
from storageforge_index import alerts, changes, deploy, server, sfcontroller, sfnet, sfnetwork, steps_infra, users, vault
from test_sfnet import key

PW = 'correct horse battery staple 9'


class RoamingAndHub(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.db = dbfactory.make(self, f'{self.tmp}/t.db')
        self.conn = self.db.connect()
        self.addCleanup(self.conn.close)
        self.db.migrate(self.conn)
        for name, address in (('hub', '2001:db8::10'), ('nas', '10.42.0.10'), ('pi', '10.42.0.20')):
            self.conn.execute('INSERT INTO hosts (hostname, ip_address, ssh_host) VALUES (:h, :a, :a)', {'h': name, 'a': address})

    def test_ipv6_endpoints_are_formatted_with_brackets_everywhere(self):
        self.assertEqual(sfnet.format_endpoint('2001:db8::1', 51903), '[2001:db8::1]:51903')
        self.assertEqual(sfnet.format_endpoint('[2001:db8::1]', 51903), '[2001:db8::1]:51903')
        self.assertEqual(sfnet.format_endpoint('10.42.0.2', 51903), '10.42.0.2:51903')

        sfnetwork.create(self.conn, 'gabe', topology='hub')
        m_hub = sfnetwork.join(self.conn, 'hub', 'gabe', endpoint='[2001:db8::10]', hub=True)
        self.assertEqual(m_hub['endpoint'], '2001:db8::10')
        with self.assertRaises(sfnet.NetworkError):
            sfnetwork.join(self.conn, 'nas', 'gabe', endpoint='fe80::1')
        sfnetwork.join(self.conn, 'nas', 'gabe', reachable=False)

        net = sfnetwork.load(self.conn)
        sfnet.set_key(net, 'hub', key(1))
        sfnet.set_key(net, 'nas', key(2))
        peers = sfnet.desired_peers(net, 'nas')
        self.assertEqual(peers[0]['endpoint'], '[2001:db8::10]:51903')
        self.assertEqual(peers[0]['keepalive'], sfnet.KEEPALIVE)

        # sfcontroller accepts [IPv6]:port want lines too
        want = sfcontroller.want(net, sfnet.member(net, 'nas'), peers)
        self.assertIn('[2001:db8::10]:51903', want)

    def test_hub_topology_emits_and_runs_wg_forward_step(self):
        sfnetwork.create(self.conn, 'gabe', topology='hub')
        sfnetwork.join(self.conn, 'hub', 'gabe', endpoint='[2001:db8::10]', hub=True)
        sfnetwork.join(self.conn, 'pi', 'gabe', reachable=False)
        for i, h in enumerate(('hub', 'pi'), 1):
            self.conn.execute("INSERT INTO security_measurements (host, kind, measured_at, via, data_json) VALUES (:h, 'infra', :t, 'controller', :d)",
                              {'h': h, 't': int(time.time()), 'd': json.dumps({'access': {'wireguard': [{'name': 'sf0', 'public_key': key(i), 'listen_port': 51903, 'peers': []}]}})})
        sfnetwork.observe(self.conn)
        tasks = sfnetwork.tasks(self.conn)
        fwd = [t for t in tasks if t['type'] == 'wg-forward']
        self.assertEqual(len(fwd), 1)
        self.assertEqual(fwd[0]['host'], 'hub')
        self.assertEqual(fwd[0]['params'], {'iface': 'sf0', 'range': '10.203.0.0/20', 'state': 'present'})

        # Execute t_wg_forward against a stand-in sysctl + tempdir
        bin_dir = self.tmp / 'bin'
        bin_dir.mkdir()
        sys_dir = self.tmp / 'sysctl.d'
        sysctl_log = self.tmp / 'sysctl.log'
        (bin_dir / 'sysctl').write_text(f"""#!/bin/bash
if [ "$1" = "-n" ]; then echo 0; exit 0; fi
printf '%s\\n' "$*" >> {sysctl_log}
""")
        (bin_dir / 'sysctl').chmod(0o755)
        fn = re.search(r'^t_wg_forward\(\) \{.*?^\}$', steps_infra.BASH, re.M | re.S)[0]
        backend_stub = 'backend() { echo none; }; ok() { echo "ok: $*"; }; act() { echo "act: $*"; }; conflict() { echo "conflict: $*"; }; durable() { :; }; try() { "$@"; }\n'
        script = f'export SF_SYSCTL_DIR={shlex.quote(str(sys_dir))} PATH={shlex.quote(str(bin_dir))}:$PATH\n' + backend_stub + fn + '\nt_wg_forward sf0 10.203.0.0/20 present\n'
        ran = subprocess.run(['bash', '-c', script], capture_output=True, text=True)
        self.assertEqual(ran.stderr, '')
        self.assertIn('net.ipv4.ip_forward = 1', (sys_dir / '90-storageforge-sf0.conf').read_text())
        self.assertIn('-w net.ipv4.ip_forward=1', sysctl_log.read_text())

    def test_signed_head_directory_verifies_rejects_tamper_expiry_and_rollback(self):
        sfnetwork.create(self.conn, 'gabe', topology='hub')
        sfnetwork.join(self.conn, 'hub', 'gabe', endpoint='2001:db8::10', hub=True)
        sfnetwork.join(self.conn, 'nas', 'gabe', endpoint='10.42.0.10')
        for i, h in enumerate(('hub', 'nas'), 1):
            self.conn.execute("INSERT INTO security_measurements (host, kind, measured_at, via, data_json) VALUES (:h, 'infra', :t, 'controller', :d)",
                              {'h': h, 't': int(time.time()), 'd': json.dumps({'access': {'wireguard': [{'name': 'sf0', 'public_key': key(i), 'listen_port': 51903, 'peers': []}]}})})
        sfnetwork.observe(self.conn)

        with mock.patch.dict(os.environ, {'STORAGEFORGE_VAULT_SECRET': 'vault-pass-phrase-for-test-only'}):
            v = vault.Vault(self.db, self.conn, secret=b'vault-pass-phrase-for-test-only')
            v.init()
            with v.unlock():
                sign_pub, _ = deploy.ensure_keys(v)
                rec1 = sfnetwork.sign_directory(self.conn, deploy._signer(v), sign_pub, ttl=600, now=1000, actor='gabe')
                self.assertEqual(rec1['directory']['seq'], 1)
                self.assertEqual(rec1['directory']['head']['endpoint'], '[2001:db8::10]:51903')

                verified = sfnet.verify_directory(rec1['directory_json'], rec1['signature'], [sign_pub], min_seq=1, now=1200)
                self.assertEqual(verified['head']['public_key'], key(1))

                # Tampered endpoint rejected
                tampered = rec1['directory_json'].replace('2001:db8::10', '2001:db8::99')
                with self.assertRaisesRegex(sfnet.NetworkError, 'verification failed'):
                    sfnet.verify_directory(tampered, rec1['signature'], [sign_pub], min_seq=1, now=1200)

                # Expired rejected
                with self.assertRaisesRegex(sfnet.NetworkError, 'expired'):
                    sfnet.verify_directory(rec1['directory_json'], rec1['signature'], [sign_pub], min_seq=1, now=2000)

                # Monotonic sequence rollback rejected once seq 2 is known
                rec2 = sfnetwork.sign_directory(self.conn, deploy._signer(v), sign_pub, ttl=600, now=1200, actor='gabe')
                self.assertEqual(rec2['directory']['seq'], 2)
                with self.assertRaisesRegex(sfnet.NetworkError, 'stale'):
                    sfnet.verify_directory(rec1['directory_json'], rec1['signature'], [sign_pub], min_seq=2, now=1200)

        # HTTP route serves cached signed directory
        users.create(self.conn, 'admin', PW, 'admin')
        web = server.create_app(server.App(self.db), 's' * 48)
        c = web.test_client()
        self.assertEqual(c.post('/api/login', json={'username': 'admin', 'password': PW}).status_code, 200)
        got = c.get('/api/sfnet/directory')
        self.assertEqual(got.status_code, 200)
        self.assertTrue(got.get_json()['signed'])
        self.assertEqual(got.get_json()['directory']['seq'], 2)
