"""Setting up deploy access on a host (deploy.enroll): a password goes to the host once, through access.sudo_run, so everything that can be
refused is refused before it does, and what happened is in the audit log either way. sudo_run and the signed probe are replaced here; the
vault, the bindings and the audit chain are real."""
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import dbfactory
from storageforge_index import access, deploy, vault
from storageforge_index.remote import RemoteError

SECRET = b'correct horse battery staple, but longer than 32'


class Enroll(unittest.TestCase):
    def setUp(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        p = mock.patch.dict(os.environ, {'STORAGEFORGE_VAULT_SECRET': SECRET.decode(), 'STORAGEFORGE_DATA_DIR': str(tmp / 'data')})
        p.start()
        self.addCleanup(p.stop)
        self.db = dbfactory.make(self, tmp / 'index.db')
        self.conn = self.db.connect()
        self.addCleanup(self.conn.close)
        self.db.migrate(self.conn)
        vault.Vault(self.db, self.conn, SECRET).init()
        self.host('nas', 'pm apt-get\ninit systemd\nprobed 1\nhave bash\nhave sudo\n')
        self.sudo, self.probe = [], {'status': 'ok', 'output': 'signed runs work on nas'}

    def host(self, name, packages):
        self.conn.execute("INSERT INTO hosts (hostname, ssh_host, ssh_port, inventory_json) VALUES (:h, :a, 2222, :i)",
                          {'h': name, 'a': f'10.0.0.{len(name)}', 'i': json.dumps({'packages': packages})})

    def fake_sudo(self, db, conn, addr, make_script, password, admin_user=None, admin_key=None):
        self.sudo.append({'addr': addr, 'script': make_script('admin'), 'password': password})
        return {'output': 'set up', 'port': 22, 'via': 'password'}

    def enroll(self, host='nas', **kw):
        with mock.patch.object(access, 'sudo_run', self.fake_sudo), mock.patch.object(deploy, 'run', return_value=self.probe):
            return deploy.enroll(self.db, self.conn, host, 'hunter2', actor='test', **kw)

    def bindings(self):
        with vault.Vault(self.db, self.conn, SECRET).unlock() as v:
            return [b for b in v.bindings() if b['key'] == deploy.DEPLOY_KEY]

    def audit(self):
        return [(a, o) for a, o in self.conn.all("SELECT action, outcome FROM audit_log WHERE action LIKE 'deploy.%' ORDER BY audit_id")]

    def test_a_host_set_up_is_bound_once_audited_and_proved_by_a_signed_run(self):
        r = self.enroll()
        self.assertEqual(r['state'], 'ready')
        self.assertEqual(len(self.sudo), 1)
        self.assertEqual(self.sudo[0]['addr'], '10.0.0.3')
        self.assertIn('storageforge-deploy', self.sudo[0]['script'])
        self.assertNotIn('hunter2', self.sudo[0]['script'], 'the password is sudo_run\'s, never in the script')
        b = self.bindings()
        self.assertEqual([(x['pattern'], x['user'], x['port']) for x in b], [('10.0.0.3', deploy.DEPLOY_USER, 2222)], 'the port the host is scanned on')
        self.enroll()
        self.assertEqual(len(self.bindings()), 1, 'a second set-up binds nothing new')
        self.assertEqual(self.audit(), [('deploy.setup', 'ok'), ('deploy.setup', 'ok')])
        self.assertTrue(deploy.ready(self.conn, 'nas'))

    def test_a_probe_that_fails_leaves_the_host_failed_not_ready(self):
        self.probe = {'status': 'failed', 'output': 'storageforge-run: not found'}
        r = self.enroll()
        self.assertEqual(r['state'], 'failed')
        self.assertIn('not found', r['output'])
        self.assertFalse(deploy.ready(self.conn, 'nas'))

    def test_a_host_deploys_cannot_run_on_is_refused_before_the_password_goes_anywhere(self):
        self.host('rc', 'pm apk\ninit openrc\n')
        with self.assertRaisesRegex(RemoteError, 'rc cannot run deploys: no systemd'):
            self.enroll('rc')
        self.conn.execute("INSERT INTO network_devices (name, platform, address, port, created_at) VALUES ('nas', 'routeros', '10.0.0.3', 22, 1)")
        with self.assertRaisesRegex(deploy.DeployError, 'network device'):
            self.enroll('nas')
        self.assertEqual(self.sudo, [], 'sudo_run was never called')
        self.assertEqual(self.bindings(), [])

    def test_a_set_up_that_fails_on_the_host_is_audited_and_binds_nothing(self):
        def refused(*_a, **_k):
            raise RemoteError('sudo: 1 incorrect password attempt')
        with mock.patch.object(access, 'sudo_run', refused), self.assertRaisesRegex(RemoteError, 'incorrect password'):
            deploy.enroll(self.db, self.conn, 'nas', 'wrong', actor='test')
        self.assertEqual(self.audit(), [('deploy.setup', 'failed')])
        self.assertEqual(self.bindings(), [])

    def test_removing_access_unbinds_the_key_and_says_removed(self):
        self.enroll()
        r = self.enroll(remove=True)
        self.assertEqual(r['state'], 'removed')
        self.assertEqual(self.bindings(), [])
        self.assertFalse(deploy.ready(self.conn, 'nas'))
        self.assertEqual(self.audit()[-1], ('deploy.remove', 'ok'))
        self.assertIn('remove', self.sudo[-1]['script'].lower())

    def test_removing_runs_even_where_deploys_could_not(self):
        """A host that later lost systemd must still be able to have deploy access taken off."""
        self.enroll()
        self.conn.execute("UPDATE hosts SET inventory_json = :i WHERE hostname = 'nas'", {'i': json.dumps({'packages': 'init openrc\n'})})
        self.assertEqual(self.enroll(remove=True)['state'], 'removed')


if __name__ == '__main__':
    unittest.main()
