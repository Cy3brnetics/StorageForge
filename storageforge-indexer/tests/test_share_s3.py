"""S3 shares through the share wizard's code (netshares.py, share_s3.py): saved and checked like the other protocols, the script serves the
folder with rclone and keeps the keys out of itself, an apply brings each side only its own vault secrets, and the report runs on both."""
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from test_tasks import Fleet

from storageforge_index import netshares, shares

SHARE = {'protocol': 'S3', 'name': 'photos', 'path': '/mnt/pool/photos', 'clients': '10.0.0.0/24', 'settings': {'secret': 'nas-s3-keys'},
         'mounts': [{'host': 'pc', 'path': '/mnt/photos', 'settings': {'secret': 'pc-s3-keys', 'crypt': True, 'crypt_secret': 'pc-s3-crypt'}}]}


class S3Share(Fleet):
    def items(self, export):
        r = shares.validate(self.conn, 'nas', export)
        return r, [(x['level'], x['text']) for x in r['items']]

    def test_it_is_offered_with_its_fields(self):
        self.assertIn('S3', shares.protocols())
        pub = netshares.DRIVERS['S3'].public()
        self.assertEqual([f['name'] for f in pub['fields']], ['port', 'secret', 'tls', 'cert_file', 'key_file'])
        self.assertEqual([f['name'] for f in pub['mount_fields']], ['secret', 'crypt', 'crypt_secret'])

    def test_a_good_share_checks_and_saves_with_its_settings(self):
        r, items = self.items(SHARE)
        self.assertEqual(r['crit'], 0, items)
        self.assertTrue(any(lv == 'warn' and 'plain HTTP' in t for lv, t in items))
        self.assertTrue(any('MinIO or Garage' in t for _, t in items))
        tls = {**SHARE, 'settings': {'secret': 'nas-s3-keys', 'port': 9443, 'tls': True, 'cert_file': '/etc/ssl/sf.pem', 'key_file': '/etc/ssl/sf.key'}}
        r, items = self.items(tls)
        self.assertEqual(r['crit'], 0, items)
        self.assertFalse(any('plain HTTP' in t for _, t in items))
        saved = shares.save_export(self.db, self.conn, 'nas', tls, None, 'test')['export']
        self.assertEqual((saved['protocol'], saved['settings']['port'], saved['settings']['tls']), ('S3', 9443, True))
        self.assertEqual(saved['mounts'][0]['settings'], SHARE['mounts'][0]['settings'])
        self.assertEqual([e['proto'] for e in shares.design_exports(self.conn, 'nas')], ['S3'])

    def test_what_cannot_work_is_refused(self):
        for name in ('ab', 'Photos', 'my_photos', '-photos', 'photos-', 'x' * 64):
            _, items = self.items({**SHARE, 'name': name})
            self.assertTrue(any(lv == 'crit' and 'bucket' in t for lv, t in items), name)
        _, items = self.items({**SHARE, 'settings': {'secret': 'k', 'tls': True}})
        self.assertTrue(any(lv == 'crit' and 'TLS needs' in t for lv, t in items))
        for bad in ({'secret': 'k', 'port': 80}, {'secret': 'k', 'port': 70000}, {}, {'secret': 'k', 'tls': True, 'cert_file': '/a b', 'key_file': '/k'},
                    {'secret': 'k', 'cert_file': 'relative.pem'}):
            with self.assertRaises(ValueError, msg=bad):
                shares.normalize_export({**SHARE, 'settings': bad})
        _, items = self.items({**SHARE, 'mounts': [{'host': 'pc', 'path': '/mnt/p', 'settings': {'secret': 'k', 'crypt': True}}]})
        self.assertTrue(any(lv == 'crit' and 'encryption needs a vault secret' in t for lv, t in items))

    def test_the_script_has_its_functions_and_params_and_no_keys(self):
        shares.save_export(self.db, self.conn, 'nas', SHARE, None, 'test')
        text = shares.script(self.conn, 'nas')
        for want in ('server_s3()', 'client_s3()', 'cleanup_s3()', 'port=9000', 'secret=nas-s3-keys', 'secret=pc-s3-keys', 'crypt=1',
                     'crypt_secret=pc-s3-crypt', 'endpoint=http://10.0.0.5:9000', 'rc_install()'):
            self.assertIn(want, text)
        self.assertNotIn('access_key_id=', text)
        self.assertEqual(subprocess.run(['bash', '-n'], input=text, text=True, capture_output=True).returncode, 0)

    def test_an_apply_brings_each_side_its_own_secrets(self):
        shares.save_export(self.db, self.conn, 'nas', SHARE, None, 'test')
        self.assertEqual(shares.share_secrets(self.conn, shares.check(self.conn, 'nas')),
                         {'nas': [('nas-s3-keys', 'share-s3')], 'pc': [('pc-s3-keys', 'share-s3'), ('pc-s3-crypt', 'share-s3')]})
        items = {i['host']: i for i in shares.deploy_items(self.db, self.conn, 'nas', 'apply', 'test')}
        self.assertIn('--secrets-stdin', items['pc']['args'])
        self.assertIn('--secrets-stdin', items['nas']['args'])
        self.assertIn('data', items['nas'])
        report = {i['host']: i for i in shares.deploy_items(self.db, self.conn, 'nas', 'report', 'test')}
        self.assertNotIn('data', report['pc'], 'a report carries no secret')

    def run_report(self, as_host, share=SHARE):
        shares.save_export(self.db, self.conn, 'nas', share, None, 'test')
        text = shares.script(self.conn, 'nas')
        tmp = Path(tempfile.mkdtemp(dir=self.tmp))
        (tmp / 'uname').write_text(f'#!/bin/sh\necho {as_host}\n')
        (tmp / 'uname').chmod(0o755)
        env = {**os.environ, 'PATH': f'{tmp}:{os.environ["PATH"]}', 'SF_S3_DIR': str(tmp / 's3'), 'SF_RCLONE_DIR': str(tmp / 'rclone'),
               'SF_UNIT_DIR': str(tmp / 'units')}
        r = subprocess.run(['bash', '-s', '--', '--report'], input=text, env=env, capture_output=True, text=True, timeout=120)
        self.assertFalse((tmp / 's3').exists() or (tmp / 'rclone').exists(), 'a report changes nothing')
        return r.stdout + r.stderr

    def test_the_report_runs_on_the_server(self):
        out = self.run_report('nas')
        self.assertIn('S3 server', out)
        self.assertNotIn('unbound variable', out)
        self.assertNotIn('command not found', out)

    def test_the_report_runs_on_the_client(self):
        out = self.run_report('pc')
        self.assertIn('rclone, S3', out)
        self.assertNotIn('unbound variable', out)
        self.assertNotIn('command not found', out)


if __name__ == '__main__':
    unittest.main()
