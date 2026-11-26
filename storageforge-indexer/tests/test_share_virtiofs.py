"""virtiofs shares through the share wizard's code (netshares.py, share_virtiofs.py): saved and checked like the other drivers, the script
carries the domain and tag of each mount, the domain XML editor adds and takes out only StorageForge's devices, and the report runs on the
KVM host (with a stub virsh) and on a VM."""
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from test_tasks import Fleet

from storageforge_index import netshares, share_virtiofs, shares

SHARE = {'protocol': 'VIRTIOFS', 'name': 'photos', 'path': '/mnt/pool/photos', 'clients': '',
         'mounts': [{'host': 'pc', 'path': '/mnt/photos', 'settings': {'domain': 'pc-vm'}}]}

XML = """<domain type='kvm'>
  <name>pc-vm</name>
  <memory unit='KiB'>2097152</memory>
  <vcpu>2</vcpu>
  <os><type arch='x86_64'>hvm</type></os>
  <devices>
    <filesystem type='mount' accessmode='passthrough'><driver type='virtiofs'/><source dir='/old'/><target dir='sf-old'/></filesystem>
    <filesystem type='mount' accessmode='mapped'><driver type='path'/><source dir='/x'/><target dir='mine'/></filesystem>
    <graphics type='vnc' passwd='secret'/>
  </devices>
</domain>
"""


def editor(mode, xml_path, *want):
    return subprocess.run([sys.executable, '-I', '-', mode, str(xml_path), *want], input=share_virtiofs.PY, text=True, capture_output=True)


class VirtiofsShare(Fleet):
    def items(self, export):
        r = shares.validate(self.conn, 'nas', export)
        return r, [(x['level'], x['text']) for x in r['items']]

    def test_it_is_offered_with_its_fields(self):
        self.assertIn('VIRTIOFS', shares.protocols())
        pub = netshares.DRIVERS['VIRTIOFS'].public()
        self.assertEqual([f['name'] for f in pub['mount_fields']], ['domain'])
        self.assertEqual(pub['label'], 'virtiofs (KVM host to its VMs)')

    def test_a_good_share_checks_clean_and_saves_with_its_domain(self):
        r, items = self.items(SHARE)
        self.assertEqual(r['crit'], 0, items)
        self.assertTrue(any('power cycle' in t for _, t in items))
        saved = shares.save_export(self.db, self.conn, 'nas', SHARE, None, 'test')['export']
        self.assertEqual((saved['protocol'], saved['mounts'][0]['settings']), ('VIRTIOFS', {'domain': 'pc-vm'}))
        self.assertEqual([e['proto'] for e in shares.design_exports(self.conn, 'nas')], ['VIRTIOFS'])

    def test_what_cannot_work_is_refused(self):
        for bad in ('a b', 'vm;rm', 'x' * 65):
            with self.assertRaises(ValueError):
                shares.normalize_export({**SHARE, 'mounts': [{'host': 'pc', 'path': '/mnt/p', 'settings': {'domain': bad}}]})
        with self.assertRaises(ValueError):
            shares.normalize_export({**SHARE, 'mounts': [{'host': 'pc', 'path': '/mnt/p', 'settings': {}}]})
        _, items = self.items({**SHARE, 'name': 'n' * 34})
        self.assertTrue(any(lv == 'crit' and 'at most 33' in t for lv, t in items))
        _, items = self.items({**SHARE, 'mounts': [*SHARE['mounts'], {'host': 'pc', 'path': '/mnt/p2', 'settings': {'domain': 'other'}}]})
        self.assertTrue(any(lv == 'crit' and 'more than one libvirt domain' in t for lv, t in items))

    def test_the_script_has_its_functions_and_params_and_parses(self):
        shares.save_export(self.db, self.conn, 'nas', SHARE, None, 'test')
        text = shares.script(self.conn, 'nas')
        for fn in ('server_virtiofs()', 'client_virtiofs()', 'cleanup_virtiofs()'):
            self.assertIn(fn, text)
        self.assertIn('domain=pc-vm', text)
        self.assertIn('tag=sf-photos', text)
        self.assertEqual(subprocess.run(['bash', '-n'], input=text, text=True, capture_output=True).returncode, 0)

    def test_an_apply_brings_nobody_a_secret(self):
        shares.save_export(self.db, self.conn, 'nas', SHARE, None, 'test')
        self.assertEqual(shares.share_secrets(self.conn, shares.check(self.conn, 'nas')), {})
        for i in shares.deploy_items(self.db, self.conn, 'nas', 'apply', 'test'):
            self.assertNotIn('--secrets-stdin', i['args'])

    def test_the_editor_adds_what_is_missing_and_drops_only_storageforge_devices(self):
        f = Path(tempfile.mkdtemp(dir=self.tmp)) / 'd.xml'
        f.write_text(XML)
        r = editor('check', f, 'sf-photos=/mnt/pool/photos')
        self.assertEqual(r.stdout.split('\n')[:3], ['mem', 'add sf-photos', 'drop sf-old'], r.stderr)
        self.assertEqual(editor('edit', f, 'sf-photos=/mnt/pool/photos').returncode, 0)
        out = f.read_text()
        self.assertIn('memfd', out)
        self.assertIn('mode="shared"', out)
        self.assertIn('dir="sf-photos"', out)
        self.assertNotIn('sf-old', out)
        self.assertIn('dir="mine"', out)
        self.assertIn('passwd="secret"', out)
        self.assertEqual(editor('check', f, 'sf-photos=/mnt/pool/photos').stdout.strip(), '')
        self.assertEqual(editor('check', f, 'sf-photos=/elsewhere').stdout.strip(), 'fix sf-photos')

    def run_report(self, as_host):
        shares.save_export(self.db, self.conn, 'nas', SHARE, None, 'test')
        text = shares.script(self.conn, 'nas')
        tmp = Path(tempfile.mkdtemp(dir=self.tmp))
        (tmp / 'bin').mkdir()
        (tmp / 'sys').mkdir()
        (tmp / 'dom.xml').write_text(XML)
        for name, body in (('uname', f'echo {as_host}'),
                           ('virsh', 'case $1 in list) echo pc-vm;; --version) echo 10.0;; dumpxml) cat "' + str(tmp / 'dom.xml') + '";; domstate) echo running;; esac')):
            (tmp / 'bin' / name).write_text(f'#!/bin/sh\n{body}\n')
            (tmp / 'bin' / name).chmod(0o755)
        env = {**os.environ, 'PATH': f'{tmp / "bin"}:{os.environ["PATH"]}', 'SF_VFS_SYS': str(tmp / 'sys'), 'SF_VIRTIOFSD': '/nonexistent'}
        r = subprocess.run(['bash', '-s', '--', '--report'], input=text, env=env, capture_output=True, text=True, timeout=120)
        return r.stdout + r.stderr

    def test_the_report_runs_on_the_kvm_host_and_changes_nothing(self):
        out = self.run_report('nas')
        self.assertIn('virtiofs server', out)
        self.assertIn('virtiofsd', out)
        self.assertIn('pc-vm: virtiofs device sf-photos', out)
        self.assertIn('power cycle', out)
        self.assertNotIn('unbound variable', out)
        self.assertNotIn('command not found', out)

    def test_the_report_runs_on_the_vm(self):
        out = self.run_report('pc')
        self.assertIn('virtiofs', out)
        self.assertIn('power cycle', out)
        self.assertNotIn('unbound variable', out)
        self.assertNotIn('command not found', out)


if __name__ == '__main__':
    unittest.main()
