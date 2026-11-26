"""SFTP shares through the share wizard's code (netshares.py, share_sftp.py): saved and checked like NFS and SMB, the generated script
pins the server's host keys and carries the client's private key only as a vault secret on stdin, and runs as a report on both sides."""
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from test_tasks import Fleet

from storageforge_index import netshares, shares

KEY = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl backup@pc'
SHARE = {'protocol': 'SFTP', 'name': 'photos', 'path': '/mnt/pool/photos', 'clients': 'backup alice', 'settings': {'readonly': False, 'umask': '002'},
         'mounts': [{'host': 'pc', 'path': '/mnt/photos', 'settings': {'user': 'backup', 'key_secret': 'pc-sftp-key', 'public_key': KEY}}]}


class SftpShare(Fleet):
    def setUp(self):
        super().setUp()
        self.conn.execute("UPDATE hosts SET host_keys = :k WHERE hostname = 'nas'", {'k': json.dumps(['ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBASE64'])})

    def items(self, export):
        r = shares.validate(self.conn, 'nas', export)
        return r, [(x['level'], x['text']) for x in r['items']]

    def test_it_is_offered_with_its_fields(self):
        self.assertIn('SFTP', shares.protocols())
        pub = netshares.DRIVERS['SFTP'].public()
        self.assertEqual([f['name'] for f in pub['mount_fields']], ['user', 'key_secret', 'public_key'])

    def test_a_good_share_checks_clean_and_saves_with_its_settings(self):
        r, items = self.items(SHARE)
        self.assertEqual(r['crit'], 0, items)
        self.assertTrue(any('chrooted to photos' in t for _, t in items))
        saved = shares.save_export(self.db, self.conn, 'nas', SHARE, None, 'test')['export']
        self.assertEqual((saved['protocol'], saved['settings'], saved['mounts'][0]['settings']['user']), ('SFTP', {'umask': '002'}, 'backup'))
        self.assertEqual([e['proto'] for e in shares.design_exports(self.conn, 'nas')], ['SFTP'])

    def test_what_cannot_work_is_refused(self):
        _, items = self.items({**SHARE, 'clients': 'root'})
        self.assertTrue(any(lv == 'crit' and 'root cannot be chrooted' in t for lv, t in items))
        bad_mount = {**SHARE, 'mounts': [{'host': 'pc', 'path': '/mnt/photos', 'settings': {'user': 'mallory', 'key_secret': 'k'}}]}
        _, items = self.items(bad_mount)
        self.assertTrue(any(lv == 'crit' and 'mallory is not one of the accounts' in t for lv, t in items))
        with self.assertRaises(ValueError):
            shares.normalize_export({**SHARE, 'mounts': [{'host': 'pc', 'path': '/mnt/p', 'settings': {'public_key': 'not a key'}}]})

    def test_the_script_pins_host_keys_and_never_holds_the_private_key(self):
        shares.save_export(self.db, self.conn, 'nas', SHARE, None, 'test')
        text = shares.script(self.conn, 'nas')
        self.assertIn('server_sftp()', text)
        self.assertIn('known_hosts=10.0.0.5 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBASE64', text)
        self.assertIn('key_secret=pc-sftp-key', text)
        self.assertNotIn('PRIVATE KEY', text)
        self.assertEqual(subprocess.run(['bash', '-n'], input=text, text=True, capture_output=True).returncode, 0)

    def test_an_apply_brings_the_client_its_key_from_the_vault_and_the_server_nothing(self):
        shares.save_export(self.db, self.conn, 'nas', SHARE, None, 'test')
        self.assertEqual(shares.share_secrets(self.conn, shares.check(self.conn, 'nas')), {'pc': [('pc-sftp-key', 'share-sftp')]})
        items = {i['host']: i for i in shares.deploy_items(self.db, self.conn, 'nas', 'apply', 'test')}
        self.assertIn('--secrets-stdin', items['pc']['args'])
        self.assertIn('data', items['pc'])
        self.assertNotIn('--secrets-stdin', items['nas']['args'])
        report = {i['host']: i for i in shares.deploy_items(self.db, self.conn, 'nas', 'report', 'test')}
        self.assertNotIn('data', report['pc'], 'a report carries no secret')

    def run_report(self, as_host):
        shares.save_export(self.db, self.conn, 'nas', SHARE, None, 'test')
        text = shares.script(self.conn, 'nas')
        tmp = Path(tempfile.mkdtemp(dir=self.tmp))
        (tmp / 'uname').write_text(f'#!/bin/sh\necho {as_host}\n')
        (tmp / 'uname').chmod(0o755)
        env = {**os.environ, 'PATH': f'{tmp}:{os.environ["PATH"]}', 'SF_SFTP_ROOT': str(tmp / 'chroots'), 'SF_SFTP_CONF': str(tmp / 'sftp.conf')}
        r = subprocess.run(['bash', '-s', '--', '--report'], input=text, env=env, capture_output=True, text=True, timeout=120)
        return r.stdout + r.stderr

    def test_the_report_runs_on_the_server_and_changes_nothing(self):
        out = self.run_report('nas')
        self.assertIn('SFTP server', out)
        self.assertNotIn('unbound variable', out)
        self.assertNotIn('command not found', out)

    def test_the_report_runs_on_the_client(self):
        out = self.run_report('pc')
        self.assertIn('sshfs', out)
        self.assertNotIn('unbound variable', out)
        self.assertNotIn('command not found', out)


class ProtocolsApi(unittest.TestCase):
    def test_the_wizard_gets_every_protocol_with_its_fields(self):
        import test_security as T
        base = T.Base('run')
        base.setUp()
        self.addCleanup(base.doCleanups)
        r = base.client.get('/api/shares/protocols')
        self.assertEqual(r.status_code, 200)
        got = {p['key']: p for p in r.get_json()['protocols']}
        self.assertIn('SFTP', got)
        self.assertEqual(got['SFTP']['clients_label'], 'Accounts on the server that may connect')


if __name__ == '__main__':
    unittest.main()
