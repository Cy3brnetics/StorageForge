"""GlusterFS shares through the share wizard's code (netshares.py, share_gluster.py): checked and saved like the others, the volume is made
by the server after its peers have run their part, a design that does not fit is refused, and the script runs as a report on every side."""
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from test_tasks import Fleet

from storageforge_index import netshares, shares

SHARE = {'protocol': 'GLUSTER', 'name': 'vol1', 'path': '/mnt/pool/vol1', 'clients': '10.0.0.0/24 10.1.*',
         'settings': {'peers': 'pc', 'replica': 2},
         'mounts': [{'host': 'pc', 'path': '/mnt/vol1', 'settings': {}}]}
SOLO = {**SHARE, 'settings': {}, 'clients': '10.0.0.0/24'}


class GlusterShare(Fleet):
    def items(self, export):
        r = shares.validate(self.conn, 'nas', export)
        return r, [(x['level'], x['text']) for x in r['items']]

    def test_it_is_offered_with_its_fields(self):
        self.assertIn('GLUSTER', shares.protocols())
        pub = netshares.DRIVERS['GLUSTER'].public()
        self.assertEqual(pub['label'], 'GlusterFS')
        self.assertEqual([f['name'] for f in pub['fields']], ['peers', 'replica'])
        self.assertEqual(pub['mount_fields'], [])

    def test_a_good_share_checks_clean_and_saves_with_its_settings(self):
        r, items = self.items(SHARE)
        self.assertEqual(r['crit'], 0, items)
        self.assertTrue(any(lv == 'warn' and 'split-brain' in t for lv, t in items))
        saved = shares.save_export(self.db, self.conn, 'nas', SHARE, None, 'test')['export']
        self.assertEqual((saved['protocol'], saved['settings']), ('GLUSTER', {'peers': 'pc', 'replica': '2'}))
        self.assertEqual([e['proto'] for e in shares.design_exports(self.conn, 'nas')], ['GLUSTER'])
        r, items = self.items({**SHARE, 'settings': {'peers': 'pc', 'replica': 3}})
        self.assertTrue(any(lv == 'crit' and 'replica 3 needs 3 bricks' in t for lv, t in items), items)

    def test_what_cannot_work_is_refused(self):
        _, items = self.items({**SHARE, 'name': 'bad name!'})
        self.assertTrue(any(lv == 'crit' and 'volume name' in t for lv, t in items))
        _, items = self.items({**SHARE, 'settings': {'peers': 'nas', 'replica': 2}})
        self.assertTrue(any(lv == 'crit' and 'this server' in t for lv, t in items), items)
        _, items = self.items({**SHARE, 'settings': {'peers': 'ghost', 'replica': 2}})
        self.assertTrue(any(lv == 'crit' and 'has not been scanned' in t for lv, t in items))
        _, items = self.items({**SOLO, 'settings': {'replica': 2}})
        self.assertTrue(any(lv == 'crit' and 'replica 2 needs 2 bricks' in t for lv, t in items))
        _, items = self.items({**SHARE, 'clients': 'bad;rm'})
        self.assertTrue(any(lv == 'crit' for lv, t in items))
        for bad in ({'peers': 'pc; rm -rf /'}, {'peers': '-x'}, {'replica': 4}, {'replica': 'many'}):
            with self.assertRaises(ValueError):
                shares.normalize_export({**SHARE, 'settings': bad})
        _, items = self.items({**SHARE, 'path': '/mnt/pool/vol1', 'settings': {'peers': 'pc', 'replica': 2}})
        self.assertTrue(any(lv == 'warn' and 'system disk of pc' in t for lv, t in items), items)

    def test_the_script_has_both_sides_and_the_peers_addresses(self):
        shares.save_export(self.db, self.conn, 'nas', SHARE, None, 'test')
        text = shares.script(self.conn, 'nas')
        for fn in ('server_gluster()', 'client_gluster()', 'cleanup_gluster()', 'peer_gluster()'):
            self.assertIn(fn, text)
        self.assertIn('peer_addrs=10.0.0.9', text)
        self.assertIn('replica=2', text)
        self.assertIn("P_HOST=(pc)", text)
        self.assertEqual(subprocess.run(['bash', '-n'], input=text, text=True, capture_output=True).returncode, 0)

    def test_a_peer_that_moved_is_reached_at_its_new_address(self):
        shares.save_export(self.db, self.conn, 'nas', SHARE, None, 'test')
        self.assertIn('peer_addrs=10.0.0.9', shares.script(self.conn, 'nas'))
        self.conn.execute("UPDATE hosts SET ssh_host = '10.0.0.77' WHERE hostname = 'pc'")
        text = shares.script(self.conn, 'nas')
        self.assertIn('peer_addrs=10.0.0.77', text)
        self.assertNotIn('10.0.0.9', text)

    def test_an_apply_runs_the_peer_first_and_brings_no_secrets(self):
        shares.save_export(self.db, self.conn, 'nas', SHARE, None, 'test')
        self.assertEqual(shares.share_secrets(self.conn, shares.check(self.conn, 'nas')), {})
        items = shares.deploy_items(self.db, self.conn, 'nas', 'apply', 'test')
        self.assertEqual([(i['host'], i['phase']) for i in items], [('pc', -1), ('nas', 0), ('pc', 1)])
        self.assertTrue(all('--secrets-stdin' not in i['args'] and 'data' not in i for i in items))

    def run_report(self, as_host, export):
        shares.save_export(self.db, self.conn, 'nas', export, None, 'test')
        text = shares.script(self.conn, 'nas')
        tmp = Path(tempfile.mkdtemp(dir=self.tmp))
        (tmp / 'uname').write_text(f'#!/bin/sh\necho {as_host}\n')
        (tmp / 'uname').chmod(0o755)
        env = {**os.environ, 'PATH': f'{tmp}:{os.environ["PATH"]}'}
        r = subprocess.run(['bash', '-s', '--', '--report'], input=text, env=env, capture_output=True, text=True, timeout=120)
        return r.stdout + r.stderr

    def clean(self, out):
        self.assertNotIn('unbound variable', out)
        self.assertNotIn('command not found', out)
        self.assertNotIn('syntax error', out)

    def test_the_report_runs_on_the_server_and_changes_nothing(self):
        out = self.run_report('nas', SHARE)
        self.assertIn('GlusterFS volume vol1', out)
        self.assertIn('/mnt/pool/vol1/brick', out)
        self.clean(out)

    def test_the_report_runs_on_a_peer(self):
        out = self.run_report('pc', {**SHARE, 'mounts': []})
        self.assertIn('GlusterFS brick for vol1 (a peer of nas)', out)
        self.clean(out)

    def test_the_report_runs_on_a_client_and_names_the_backup_servers(self):
        out = self.run_report('pc', SHARE)
        self.assertIn('(GlusterFS)', out)
        self.clean(out)

    def test_a_client_that_is_no_peer_only_mounts(self):
        out = self.run_report('pc', SOLO)
        self.assertNotIn('GlusterFS brick for', out)
        self.assertIn('(GlusterFS)', out)
        self.clean(out)


if __name__ == '__main__':
    unittest.main()
