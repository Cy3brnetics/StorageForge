"""NBD shares through the share wizard's code (netshares.py, share_nbd.py): saved and checked like the others, one client only, the
allow-list built from the mounts' addresses, and a generated script that parses and runs as a report on both sides."""
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from test_tasks import Fleet

from storageforge_index import netshares, shares

SHARE = {'protocol': 'NBD', 'name': 'vol1', 'path': '/mnt/pool/photos', 'clients': '', 'settings': {'size_gb': 50},
         'mounts': [{'host': 'pc', 'path': '/mnt/vol1', 'settings': {'format': 'xfs'}}]}
TLS = {'size_gb': 50, 'tls_cert': '/etc/ssl/nbd.crt', 'tls_key': '/etc/ssl/nbd.key', 'tls_ca': '/etc/ssl/ca.crt'}


class NbdShare(Fleet):
    def items(self, export):
        r = shares.validate(self.conn, 'nas', export)
        return r, [(x['level'], x['text']) for x in r['items']]

    def test_it_is_offered_with_its_fields(self):
        self.assertIn('NBD', shares.protocols())
        pub = netshares.DRIVERS['NBD'].public()
        self.assertEqual([f['name'] for f in pub['fields']], ['size_gb', 'tls_cert', 'tls_key', 'tls_ca'])
        self.assertEqual([f['name'] for f in pub['mount_fields']], ['format', 'tls_ca', 'tls_cert', 'tls_key'])

    def test_a_good_share_checks_clean_saves_and_warns_without_tls(self):
        r, items = self.items(SHARE)
        self.assertEqual(r['crit'], 0, items)
        self.assertTrue(any(lv == 'warn' and 'no TLS' in t for lv, t in items))
        self.assertTrue(any('no user authentication' in t and '10.0.0.9' in t for _, t in items))
        saved = shares.save_export(self.db, self.conn, 'nas', SHARE, None, 'test')['export']
        self.assertEqual((saved['protocol'], saved['settings'], saved['mounts'][0]['settings']), ('NBD', {'size_gb': 50}, {'format': 'xfs'}))
        self.assertNotIn('_nbd_allow', saved)

    def test_tls_clears_the_warning(self):
        r, items = self.items({**SHARE, 'settings': TLS, 'mounts': [{'host': 'pc', 'path': '/mnt/vol1',
                                                                    'settings': {'tls_ca': '/etc/ca.crt', 'tls_cert': '/etc/c.crt', 'tls_key': '/etc/c.key'}}]})
        self.assertEqual(r['crit'], 0, items)
        self.assertFalse(any(lv == 'warn' and 'no TLS' in t for lv, t in items))

    def test_more_than_one_client_is_refused(self):
        two = {**SHARE, 'mounts': SHARE['mounts'] + [{'host': 'nas', 'path': '/mnt/vol2'}]}
        _, items = self.items(two)
        self.assertTrue(any(lv == 'crit' and 'one writer' in t for lv, t in items))
        _, items = self.items({**SHARE, 'mounts': [{'host': 'pc', 'path': '/mnt/a'}, {'host': 'pc', 'path': '/mnt/b'}]})
        self.assertTrue(any(lv == 'crit' and 'one writer' in t for lv, t in items))

    def test_what_cannot_work_is_refused(self):
        _, items = self.items({**SHARE, 'name': 'bad.name'})
        self.assertTrue(any(lv == 'crit' and 'needs a name' in t for lv, t in items))
        _, items = self.items({**SHARE, 'clients': 'pc-host'})
        self.assertTrue(any(lv == 'crit' and 'not an IP address' in t for lv, t in items))
        _, items = self.items({**SHARE, 'mounts': [], 'clients': ''})
        self.assertTrue(any(lv == 'crit' and 'address of the client' in t for lv, t in items))
        _, items = self.items({**SHARE, 'settings': {**TLS}, 'mounts': [{'host': 'pc', 'path': '/mnt/v', 'settings': {}}]})
        self.assertTrue(any(lv == 'crit' and 'client certificate' in t for lv, t in items))
        for bad in ({}, {'size_gb': 0}, {'size_gb': 5, 'tls_cert': '/c'}, {'size_gb': 5, 'tls_ca': '/ca'},
                    {'size_gb': 5, 'tls_cert': '/c', 'tls_key': '/k with space'}, {'size_gb': 5, 'tls_cert': 'rel', 'tls_key': '/k'}):
            with self.assertRaises(ValueError, msg=bad):
                shares.normalize_export({**SHARE, 'settings': bad})
        with self.assertRaises(ValueError):
            shares.normalize_export({**SHARE, 'mounts': [{'host': 'pc', 'path': '/m', 'settings': {'format': 'ntfs'}}]})

    def test_the_script_has_the_functions_and_params_and_parses(self):
        shares.save_export(self.db, self.conn, 'nas', {**SHARE, 'clients': '192.168.7.0/24'}, None, 'test')
        text = shares.script(self.conn, 'nas')
        for fn in ('server_nbd()', 'client_nbd()', 'cleanup_nbd()'):
            self.assertIn(fn, text)
        self.assertIn('allow=10.0.0.9 192.168.7.0/24', text)
        self.assertIn('size_gb=50', text)
        self.assertIn('format=xfs', text)
        self.assertEqual(subprocess.run(['bash', '-n'], input=text, text=True, capture_output=True).returncode, 0)

    def test_an_apply_needs_no_secrets_on_either_side(self):
        shares.save_export(self.db, self.conn, 'nas', SHARE, None, 'test')
        self.assertEqual(shares.share_secrets(self.conn, shares.check(self.conn, 'nas')), {})
        items = {i['host']: i for i in shares.deploy_items(self.db, self.conn, 'nas', 'apply', 'test')}
        for h in ('nas', 'pc'):
            self.assertNotIn('--secrets-stdin', items[h]['args'])

    def run_report(self, as_host):
        shares.save_export(self.db, self.conn, 'nas', SHARE, None, 'test')
        text = shares.script(self.conn, 'nas')
        tmp = Path(tempfile.mkdtemp(dir=self.tmp))
        (tmp / 'uname').write_text(f'#!/bin/sh\necho {as_host}\n')
        (tmp / 'uname').chmod(0o755)
        env = {**os.environ, 'PATH': f'{tmp}:{os.environ["PATH"]}', 'SF_NBD_DIR': str(tmp / 'nbd-server'), 'SF_NBD_CLIENT_DIR': str(tmp / 'client'),
               'SF_NBD_STATE': str(tmp / 'state'), 'SF_NBD_MODLOAD': str(tmp / 'nbd.conf')}
        r = subprocess.run(['bash', '-s', '--', '--report'], input=text, env=env, capture_output=True, text=True, timeout=120)
        self.assertFalse((tmp / 'nbd-server').exists() or (tmp / 'client').exists() or (tmp / 'state').exists(), 'a report changes nothing')
        return r.stdout + r.stderr

    def test_the_report_runs_on_the_server_and_changes_nothing(self):
        out = self.run_report('nas')
        self.assertIn('NBD server', out)
        self.assertNotIn('unbound variable', out)
        self.assertNotIn('command not found', out)

    def test_the_report_runs_on_the_client(self):
        out = self.run_report('pc')
        self.assertIn('(NBD)', out)
        self.assertNotIn('unbound variable', out)
        self.assertNotIn('command not found', out)


if __name__ == '__main__':
    unittest.main()
