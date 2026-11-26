"""WebDAV shares through the share wizard's code (netshares.py, share_webdav.py): saved and checked like NFS and SMB, the script serves
with rclone from an htpasswd vault secret and mounts with rclone on the clients, and runs as a report on both sides."""
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from test_tasks import Fleet

from storageforge_index import netshares, shares
from storageforge_index.share_webdav import BASH

SHARE = {'protocol': 'WEBDAV', 'name': 'docs', 'path': '/mnt/pool/docs', 'clients': '10.0.0.0/24',
         'settings': {'users_secret': 'nas-webdav-users', 'readonly': True, 'tls_cert': '/etc/ssl/nas.pem', 'tls_key': '/etc/ssl/nas.key'},
         'mounts': [{'host': 'pc', 'path': '/mnt/docs', 'settings': {'login_secret': 'pc-webdav-login', 'crypt': True, 'crypt_secret': 'pc-webdav-crypt'}}]}


class WebdavShare(Fleet):
    def items(self, export):
        r = shares.validate(self.conn, 'nas', export)
        return r, [(x['level'], x['text']) for x in r['items']]

    def test_it_is_offered_with_its_fields(self):
        self.assertIn('WEBDAV', shares.protocols())
        pub = netshares.DRIVERS['WEBDAV'].public()
        self.assertEqual([f['name'] for f in pub['fields']], ['users_secret', 'port', 'readonly', 'tls_cert', 'tls_key'])
        self.assertEqual([f['name'] for f in pub['mount_fields']], ['login_secret', 'crypt', 'crypt_secret'])

    def test_a_good_share_checks_clean_and_saves_with_its_settings(self):
        r, items = self.items(SHARE)
        self.assertEqual(r['crit'], 0, items)
        self.assertTrue(any('Nextcloud' in t for _, t in items))
        saved = shares.save_export(self.db, self.conn, 'nas', {**SHARE, 'settings': {**SHARE['settings'], 'port': 9443}}, None, 'test')['export']
        self.assertEqual((saved['protocol'], saved['settings']['port'], saved['settings']['readonly'], saved['mounts'][0]['settings']['crypt']),
                         ('WEBDAV', 9443, True, True))
        self.assertEqual([e['proto'] for e in shares.design_exports(self.conn, 'nas')], ['WEBDAV'])

    def test_plain_http_is_warned_about(self):
        _, items = self.items({**SHARE, 'settings': {'users_secret': 'u'}})
        self.assertTrue(any(lv == 'warn' and 'plain HTTP' in t for lv, t in items))
        _, items = self.items(SHARE)
        self.assertFalse(any('plain HTTP' in t for _, t in items))

    def test_what_cannot_work_is_refused(self):
        for port in (80, 70000, 'x'):
            with self.assertRaises(ValueError, msg=port):
                shares.normalize_export({**SHARE, 'settings': {**SHARE['settings'], 'port': port}})
        with self.assertRaises(ValueError):
            shares.normalize_export({**SHARE, 'settings': {'tls_cert': '/a', 'tls_key': '/b'}})   # no users secret
        with self.assertRaises(ValueError):
            shares.normalize_export({**SHARE, 'settings': {**SHARE['settings'], 'tls_cert': '/etc/ssl/a b$.pem'}})
        _, items = self.items({**SHARE, 'settings': {'users_secret': 'u', 'tls_cert': '/etc/ssl/nas.pem'}})
        self.assertTrue(any(lv == 'crit' and 'both a certificate' in t for lv, t in items))
        _, items = self.items({**SHARE, 'path': '/mnt/pool/a%b'})
        self.assertTrue(any(lv == 'crit' and 'cannot hold' in t for lv, t in items))
        bad = {**SHARE, 'mounts': [{'host': 'pc', 'path': '/mnt/docs', 'settings': {'login_secret': 'l', 'crypt': True}}]}
        _, items = self.items(bad)
        self.assertTrue(any(lv == 'crit' and 'encryption needs' in t for lv, t in items))

    def test_the_script_serves_and_mounts_with_rclone_and_passes_bash_n(self):
        shares.save_export(self.db, self.conn, 'nas', SHARE, None, 'test')
        text = shares.script(self.conn, 'nas')
        for want in ('server_webdav()', 'client_webdav()', 'cleanup_webdav()', 'rc_mount_unit()', 'users_secret=nas-webdav-users',
                     'scheme=https', 'login_secret=pc-webdav-login', 'crypt=1', 'crypt_secret=pc-webdav-crypt', 'port=8088'):
            self.assertIn(want, text)
        self.assertEqual(subprocess.run(['bash', '-n'], input=text, text=True, capture_output=True).returncode, 0)

    def test_an_apply_brings_each_side_exactly_its_secrets(self):
        shares.save_export(self.db, self.conn, 'nas', SHARE, None, 'test')
        got = shares.share_secrets(self.conn, shares.check(self.conn, 'nas'))
        self.assertEqual(got, {'nas': [('nas-webdav-users', 'share-webdav')],
                               'pc': [('pc-webdav-login', 'share-webdav'), ('pc-webdav-crypt', 'share-webdav')]})
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
        env = {**os.environ, 'PATH': f'{tmp}:{os.environ["PATH"]}', 'SF_WEBDAV_DIR': str(tmp / 'webdav'), 'SF_RCLONE_DIR': str(tmp / 'rclone'),
               'SF_UNIT_DIR': str(tmp / 'units')}
        r = subprocess.run(['bash', '-s', '--', '--report'], input=text, env=env, capture_output=True, text=True, timeout=120)
        return r.stdout + r.stderr

    def test_the_report_runs_on_the_server_and_changes_nothing(self):
        out = self.run_report('nas')
        self.assertIn('WebDAV server', out)
        self.assertIn('storageforge-webdav-docs', out)
        self.assertNotIn('unbound variable', out)
        self.assertNotIn('command not found', out)

    def test_the_report_runs_on_the_client(self):
        out = self.run_report('pc')
        self.assertIn('WebDAV', out)
        self.assertIn('would mount', out)
        self.assertNotIn('unbound variable', out)
        self.assertNotIn('command not found', out)

    def test_the_password_is_obscured_from_a_pipe_into_the_remote_section(self):
        tmp = Path(tempfile.mkdtemp(dir=self.tmp))
        (tmp / 'rclone').write_text('#!/bin/sh\n[ "$1" = obscure ] && [ "$2" = - ] && printf "OBSCURED(%s)" "$(cat)"\n')
        (tmp / 'rclone').chmod(0o755)
        conf = tmp / 'c.conf'
        conf.write_text('[r]\ntype = webdav\nurl = http://h:1/\n\n[r-crypt]\ntype = crypt\npassword = x\n')
        script = BASH.split('webdav_pass()')[1].split('client_webdav()')[0]
        r = subprocess.run(['bash', '-c', 'rc_bin() { echo %s/rclone; }; durable() { :; }\nwebdav_pass()%s\nset -e; webdav_pass %s s3cret'
                            % (tmp, script, conf)], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(conf.read_text().splitlines()[:3], ['[r]', 'type = webdav', 'pass = OBSCURED(s3cret)'])
        self.assertEqual(conf.read_text().count('pass = '), 1)


if __name__ == '__main__':
    unittest.main()
