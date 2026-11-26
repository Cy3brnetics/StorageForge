"""iSCSI shares through the share wizard's code (netshares.py, share_iscsi.py): saved and checked like the other protocols, one client
at most, the CHAP secret reaches both sides only as a vault secret on stdin, and the script runs as a report on both sides."""
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from test_tasks import Fleet

from storageforge_index import netshares, shares

SHARE = {'protocol': 'ISCSI', 'name': 'vault', 'path': '/mnt/pool/vault', 'clients': '',
         'settings': {'size_gb': 50, 'chap_user': 'sfuser', 'chap_secret': 'pc-iscsi-chap'},
         'mounts': [{'host': 'pc', 'path': '/mnt/vault', 'settings': {'format': 'ext4'}}]}


class IscsiShare(Fleet):
    def items(self, export):
        r = shares.validate(self.conn, 'nas', export)
        return r, [(x['level'], x['text']) for x in r['items']]

    def test_it_is_offered_with_its_fields(self):
        self.assertIn('ISCSI', shares.protocols())
        pub = netshares.DRIVERS['ISCSI'].public()
        self.assertEqual([f['name'] for f in pub['fields']], ['size_gb', 'chap_user', 'chap_secret'])
        self.assertEqual([f['name'] for f in pub['mount_fields']], ['format'])

    def test_a_good_share_checks_clean_and_saves_with_its_settings(self):
        r, items = self.items(SHARE)
        self.assertEqual(r['crit'], 0, items)
        self.assertTrue(any('iqn.2026-11.org.storageforge:nas.vault' in t for _, t in items))
        self.assertTrue(any(lv == 'warn' and 'crash-consistent' in t for lv, t in items))
        saved = shares.save_export(self.db, self.conn, 'nas', SHARE, None, 'test')['export']
        self.assertEqual(saved['protocol'], 'ISCSI')
        self.assertEqual(saved['settings'], {'size_gb': 50, 'chap_user': 'sfuser', 'chap_secret': 'pc-iscsi-chap'})
        self.assertEqual(saved['mounts'][0]['settings'], {'format': 'ext4'})
        self.assertEqual([e['proto'] for e in shares.design_exports(self.conn, 'nas')], ['ISCSI'])

    def test_what_cannot_work_is_refused(self):
        two = {**SHARE, 'mounts': SHARE['mounts'] + [{'host': 'nas', 'path': '/mnt/v2', 'settings': {}}]}
        _, items = self.items(two)
        self.assertTrue(any(lv == 'crit' and 'two hosts' in t for lv, t in items), items)
        _, items = self.items({**SHARE, 'settings': {'size_gb': 50, 'chap_user': 'sfuser'}})
        self.assertTrue(any(lv == 'crit' and 'CHAP password' in t for lv, t in items))
        _, items = self.items({**SHARE, 'name': 'Vault_1'})
        self.assertTrue(any(lv == 'crit' and 'lower-case' in t for lv, t in items))
        for bad in ({'chap_secret': 'x'}, {'size_gb': 0, 'chap_secret': 'x'}, {'size_gb': 70000}, {'size_gb': 5, 'chap_user': 'bad user'}):
            with self.assertRaises(ValueError, msg=bad):
                shares.normalize_export({**SHARE, 'settings': bad})
        with self.assertRaises(ValueError):
            shares.normalize_export({**SHARE, 'mounts': [{'host': 'pc', 'path': '/mnt/v', 'settings': {'format': 'ntfs'}}]})

    def test_the_script_has_its_functions_and_params_and_no_secret(self):
        shares.save_export(self.db, self.conn, 'nas', SHARE, None, 'test')
        text = shares.script(self.conn, 'nas')
        for fn in ('server_iscsi()', 'client_iscsi()', 'cleanup_iscsi()'):
            self.assertIn(fn, text)
        self.assertIn('iqn=iqn.2026-11.org.storageforge:nas.vault', text)
        self.assertIn('initiators=iqn.2026-11.org.storageforge:pc', text)
        self.assertIn('initiator=iqn.2026-11.org.storageforge:pc', text)
        self.assertIn('chap_secret=pc-iscsi-chap', text)
        self.assertIn('size_gb=50', text)
        self.assertIn('addrs=10.0.0.9', text)
        self.assertEqual(subprocess.run(['bash', '-n'], input=text, text=True, capture_output=True).returncode, 0)

    def test_an_apply_brings_both_sides_the_chap_secret_and_nothing_else(self):
        shares.save_export(self.db, self.conn, 'nas', SHARE, None, 'test')
        self.assertEqual(shares.share_secrets(self.conn, shares.check(self.conn, 'nas')),
                         {'nas': [('pc-iscsi-chap', 'share-iscsi')], 'pc': [('pc-iscsi-chap', 'share-iscsi')]})
        items = {i['host']: i for i in shares.deploy_items(self.db, self.conn, 'nas', 'apply', 'test')}
        for h in ('nas', 'pc'):
            self.assertIn('--secrets-stdin', items[h]['args'])
            self.assertIn('data', items[h])
        report = {i['host']: i for i in shares.deploy_items(self.db, self.conn, 'nas', 'report', 'test')}
        for h in ('nas', 'pc'):
            self.assertNotIn('data', report[h], 'a report carries no secret')

    def run_report(self, as_host):
        shares.save_export(self.db, self.conn, 'nas', SHARE, None, 'test')
        text = shares.script(self.conn, 'nas')
        tmp = Path(tempfile.mkdtemp(dir=self.tmp))
        (tmp / 'uname').write_text(f'#!/bin/sh\necho {as_host}\n')
        (tmp / 'uname').chmod(0o755)
        env = {**os.environ, 'PATH': f'{tmp}:{os.environ["PATH"]}', 'SF_ISCSI_NODES': str(tmp / 'nodes'), 'SF_ISCSI_BYPATH': str(tmp / 'by-path'),
               'SF_ISCSI_NAMEFILE': str(tmp / 'initiatorname.iscsi')}
        r = subprocess.run(['bash', '-s', '--', '--report'], input=text, env=env, capture_output=True, text=True, timeout=120)
        return r.stdout + r.stderr

    def test_the_report_runs_on_the_server_and_changes_nothing(self):
        out = self.run_report('nas')
        self.assertIn('iSCSI target', out)
        self.assertNotIn('unbound variable', out)
        self.assertNotIn('command not found', out)

    def test_the_report_runs_on_the_client(self):
        out = self.run_report('pc')
        self.assertIn('(iSCSI)', out)
        self.assertNotIn('unbound variable', out)
        self.assertNotIn('command not found', out)

    def test_the_client_side_with_the_tools_stubbed(self):
        """A stub iscsiadm that has the target, a node record, no session: the report says what an apply would do and writes nothing."""
        shares.save_export(self.db, self.conn, 'nas', SHARE, None, 'test')
        text = shares.script(self.conn, 'nas')
        tmp = Path(tempfile.mkdtemp(dir=self.tmp))
        for name, body in (('uname', 'echo pc'), ('iscsiadm', 'exit 21'), ('blkid', 'exit 2'), ('systemctl', 'exit 3')):
            (tmp / name).write_text(f'#!/bin/sh\n{body}\n')
            (tmp / name).chmod(0o755)
        names = tmp / 'initiatorname.iscsi'
        names.write_text('InitiatorName=iqn.1993-08.org.debian:01:0123456789ab\n')
        env = {**os.environ, 'PATH': f'{tmp}:{os.environ["PATH"]}', 'SF_ISCSI_NODES': str(tmp / 'nodes'), 'SF_ISCSI_BYPATH': str(tmp / 'by-path'),
               'SF_ISCSI_NAMEFILE': str(names)}
        r = subprocess.run(['bash', '-s', '--', '--report'], input=text, env=env, capture_output=True, text=True, timeout=120)
        out = r.stdout + r.stderr
        self.assertNotIn('unbound variable', out)
        self.assertNotIn('command not found', out)
        self.assertIn('discover', out)
        self.assertIn('iqn.2026-11.org.storageforge:pc', out)     # the file would be rewritten: it held a distribution default
        self.assertIn('InitiatorName=iqn.1993-08', names.read_text())
        names.write_text('InitiatorName=iqn.2001-04.com.example:mine\n')
        r = subprocess.run(['bash', '-s', '--', '--report'], input=text, env=env, capture_output=True, text=True, timeout=120)
        self.assertIn('not a distribution default', r.stdout + r.stderr)


if __name__ == '__main__':
    unittest.main()
