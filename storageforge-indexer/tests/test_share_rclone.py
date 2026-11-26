"""rclone serve shares through the share wizard's code (netshares.py, share_rclone.py): saved and checked like the others, the script
holds only vault secret names, an apply brings each side exactly its secrets, and the report runs on both sides."""
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from test_tasks import Fleet

from storageforge_index import netshares, shares

SHARE = {'protocol': 'RCLONE', 'name': 'gdrive', 'path': '/mnt/pool/gdrive-cache', 'clients': '10.0.0.0/24',
         'settings': {'backend': 'drive', 'remote_path': 'Backups/nas', 'options': 'scope=drive', 'secret': 'gd-rclone', 'crypt': True,
                      'crypt_secret': 'gd-crypt', 'serve_as': 'webdav', 'port': 8089, 'access_secret': 'gd-login'},
         'mounts': [{'host': 'pc', 'path': '/mnt/gdrive', 'settings': {'secret': 'pc-gd-login'}}]}


class RcloneShare(Fleet):
    def items(self, export):
        r = shares.validate(self.conn, 'nas', export)
        return r, [(x['level'], x['text']) for x in r['items']]

    def test_it_is_offered_with_its_fields(self):
        self.assertIn('RCLONE', shares.protocols())
        pub = netshares.DRIVERS['RCLONE'].public()
        self.assertEqual([f['name'] for f in pub['mount_fields']], ['secret', 'cache'])
        self.assertIn('serve_as', [f['name'] for f in pub['fields']])

    def test_a_good_share_checks_clean_and_saves_with_its_settings(self):
        r, items = self.items(SHARE)
        self.assertEqual(r['crit'], 0, items)
        self.assertTrue(any(lv == 'warn' and 'plain HTTP' in t for lv, t in items))
        saved = shares.save_export(self.db, self.conn, 'nas', SHARE, None, 'test')['export']
        self.assertEqual(saved['protocol'], 'RCLONE')
        self.assertEqual((saved['settings']['remote_path'], saved['settings']['crypt'], saved['settings']['access_secret']), ('Backups/nas', True, 'gd-login'))
        self.assertNotIn('port', saved['settings'], 'the default is not kept')
        self.assertEqual([e['proto'] for e in shares.design_exports(self.conn, 'nas')], ['RCLONE'])

    def test_what_cannot_work_is_refused(self):
        no_crypt = {**SHARE, 'settings': {**SHARE['settings'], 'crypt_secret': ''}}
        _, items = self.items(no_crypt)
        self.assertTrue(any(lv == 'crit' and 'vault secret with its passwords' in t for lv, t in items))
        no_login = {**SHARE, 'settings': {**SHARE['settings'], 'access_secret': ''}}
        with self.assertRaises(ValueError):
            shares.normalize_export(no_login)
        for bad in ({'options': 'token=abc'}, {'options': 'a b'}, {'remote_path': 'x"y'}, {'serve_as': 'ftp'}, {'port': 0}):
            with self.assertRaises(ValueError, msg=bad):
                shares.normalize_export({**SHARE, 'settings': {**SHARE['settings'], **bad}})
        _, items = self.items({**SHARE, 'path': '/mnt/pool/a"b'})
        self.assertTrue(any(lv == 'crit' for lv, _ in items))
        _, items = self.items({**SHARE, 'name': 'a b'})
        self.assertTrue(any(lv == 'crit' and 'letters, digits' in t for lv, t in items))

    def test_http_is_read_only(self):
        http = {**SHARE, 'settings': {**SHARE['settings'], 'serve_as': 'http'}}
        _, items = self.items(http)
        self.assertTrue(any('read only' in t for _, t in items))

    def test_the_script_has_its_functions_and_params_and_no_secret_value(self):
        shares.save_export(self.db, self.conn, 'nas', SHARE, None, 'test')
        text = shares.script(self.conn, 'nas')
        for fn in ('server_rclone()', 'client_rclone()', 'cleanup_rclone()'):
            self.assertIn(fn, text)
        for want in ('serve_as=webdav', 'access_secret=gd-login', 'crypt_secret=gd-crypt', 'secret=pc-gd-login', 'remote_path=Backups/nas'):
            self.assertIn(want, text)
        self.assertEqual(subprocess.run(['bash', '-n'], input=text, text=True, capture_output=True).returncode, 0)

    def test_an_apply_brings_each_side_exactly_its_secrets(self):
        shares.save_export(self.db, self.conn, 'nas', SHARE, None, 'test')
        got = shares.share_secrets(self.conn, shares.check(self.conn, 'nas'))
        self.assertEqual(got, {'nas': [('gd-rclone', 'share-rclone'), ('gd-crypt', 'share-rclone'), ('gd-login', 'share-rclone')],
                               'pc': [('pc-gd-login', 'share-rclone')]})
        items = {i['host']: i for i in shares.deploy_items(self.db, self.conn, 'nas', 'apply', 'test')}
        self.assertIn('--secrets-stdin', items['nas']['args'])
        self.assertIn('--secrets-stdin', items['pc']['args'])
        report = {i['host']: i for i in shares.deploy_items(self.db, self.conn, 'nas', 'report', 'test')}
        self.assertNotIn('data', report['pc'], 'a report carries no secret')

    def run_report(self, as_host):
        shares.save_export(self.db, self.conn, 'nas', SHARE, None, 'test')
        text = shares.script(self.conn, 'nas')
        tmp = Path(tempfile.mkdtemp(dir=self.tmp))
        (tmp / 'uname').write_text(f'#!/bin/sh\necho {as_host}\n')
        (tmp / 'uname').chmod(0o755)
        env = {**os.environ, 'PATH': f'{tmp}:{os.environ["PATH"]}', 'SF_RCLONE_DIR': str(tmp / 'rclone'), 'SF_UNIT_DIR': str(tmp / 'units'),
               'SF_SECRET_DIR': str(tmp / 'secrets')}
        r = subprocess.run(['bash', '-s', '--', '--report'], input=text, env=env, capture_output=True, text=True, timeout=120)
        return r.stdout + r.stderr

    def test_the_report_runs_on_the_server_and_changes_nothing(self):
        out = self.run_report('nas')
        self.assertIn('rclone serve webdav', out)
        self.assertNotIn('unbound variable', out)
        self.assertNotIn('command not found', out)

    def test_the_report_runs_on_the_client(self):
        out = self.run_report('pc')
        self.assertIn('rclone, webdav', out)
        self.assertNotIn('unbound variable', out)
        self.assertNotIn('command not found', out)


if __name__ == '__main__':
    unittest.main()
