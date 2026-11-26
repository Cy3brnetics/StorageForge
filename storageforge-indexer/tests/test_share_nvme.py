"""NVMe over TCP shares through the share wizard's code (netshares.py, share_nvme.py): saved and checked like the other drivers, exactly
one client mount, the script carries no secret, and runs as a report on the server and on the client."""
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from test_tasks import Fleet

from storageforge_index import netshares, shares

SHARE = {'protocol': 'NVME', 'name': 'vault', 'path': '/mnt/pool/vault', 'clients': '10.0.0.0/24', 'settings': {'size_gb': 50},
         'mounts': [{'host': 'pc', 'path': '/mnt/vault', 'settings': {'format': 'ext4'}}]}


class NvmeShare(Fleet):
    def items(self, export):
        r = shares.validate(self.conn, 'nas', export)
        return r, [(x['level'], x['text']) for x in r['items']]

    def test_it_is_offered_with_its_fields(self):
        self.assertIn('NVME', shares.protocols())
        pub = netshares.DRIVERS['NVME'].public()
        self.assertEqual(pub['label'], 'NVMe over TCP')
        self.assertEqual([f['name'] for f in pub['fields']], ['size_gb', 'device', 'port'])
        self.assertEqual([f['name'] for f in pub['mount_fields']], ['format'])

    def test_a_good_share_checks_clean_and_saves_with_its_settings(self):
        r, items = self.items(SHARE)
        self.assertEqual(r['crit'], 0, items)
        self.assertTrue(any(lv == 'warn' and 'no password' in t for lv, t in items))
        saved = shares.save_export(self.db, self.conn, 'nas', SHARE, None, 'test')['export']
        self.assertEqual((saved['protocol'], saved['settings'], saved['mounts'][0]['settings']), ('NVME', {'size_gb': 50}, {'format': 'ext4'}))
        self.assertEqual([e['proto'] for e in shares.design_exports(self.conn, 'nas')], ['NVME'])

    def test_a_block_device_instead_of_a_size_is_fine(self):
        r, items = self.items({**SHARE, 'settings': {'device': '/dev/vg0/nvme', 'port': 4421}})
        self.assertEqual(r['crit'], 0, items)

    def test_what_cannot_work_is_refused(self):
        _, items = self.items({**SHARE, 'settings': {}})
        self.assertTrue(any(lv == 'crit' and 'size of the disk' in t for lv, t in items))
        two = {**SHARE, 'mounts': SHARE['mounts'] + [{'host': 'nas2', 'path': '/mnt/vault'}]}
        _, items = self.items(two)
        self.assertTrue(any(lv == 'crit' and 'one client at a time' in t for lv, t in items))
        _, items = self.items({**SHARE, 'mounts': []})
        self.assertTrue(any(lv == 'crit' and 'one client' in t for lv, t in items))
        _, items = self.items({**SHARE, 'name': 'Vault Two'})
        self.assertTrue(any(lv == 'crit' and 'lowercase' in t for lv, t in items))
        for bad in ({'device': 'sdb'}, {'device': '/dev/../etc/passwd'}, {'device': '/dev/sdb; reboot'}, {'device': '/dev/sdb', 'size_gb': 5},
                    {'size_gb': 0}, {'size_gb': 5, 'port': 70000}):
            with self.assertRaises(ValueError, msg=bad):
                shares.normalize_export({**SHARE, 'settings': bad})
        with self.assertRaises(ValueError):
            shares.normalize_export({**SHARE, 'mounts': [{'host': 'pc', 'path': '/mnt/v', 'settings': {'format': 'ntfs'}}]})

    def test_the_script_has_the_functions_and_its_params_and_holds_no_secret(self):
        shares.save_export(self.db, self.conn, 'nas', SHARE, None, 'test')
        text = shares.script(self.conn, 'nas')
        for fn in ('server_nvme()', 'client_nvme()', 'cleanup_nvme()', 'nvmet_up()', 'nvmet_teardown()'):
            self.assertIn(fn, text)
        self.assertIn('size_gb=50', text)
        self.assertIn('format=ext4', text)
        self.assertEqual(subprocess.run(['bash', '-n'], input=text, text=True, capture_output=True).returncode, 0)

    def test_an_apply_brings_nobody_a_secret(self):
        shares.save_export(self.db, self.conn, 'nas', SHARE, None, 'test')
        self.assertEqual(shares.share_secrets(self.conn, shares.check(self.conn, 'nas')), {})
        items = {i['host']: i for i in shares.deploy_items(self.db, self.conn, 'nas', 'apply', 'test')}
        self.assertNotIn('--secrets-stdin', items['pc']['args'])
        self.assertNotIn('--secrets-stdin', items['nas']['args'])

    def run_report(self, as_host, setup=None):
        shares.save_export(self.db, self.conn, 'nas', SHARE, None, 'test')
        text = shares.script(self.conn, 'nas')
        tmp = Path(tempfile.mkdtemp(dir=self.tmp))
        (tmp / 'uname').write_text(f'#!/bin/sh\necho {as_host}\n')
        (tmp / 'uname').chmod(0o755)
        root = tmp / 'nvmet'
        if setup:
            setup(root)
        env = {**os.environ, 'PATH': f'{tmp}:{os.environ["PATH"]}', 'SF_NVMET_ROOT': str(root), 'SF_NVMET_DIR': str(tmp / 'nvmet-sh'),
               'SF_NVMET_MODLOAD': str(tmp / 'nvmet.conf'), 'SF_NVME_DIR': str(tmp / 'nvme-sh'), 'SF_NVME_ETC': str(tmp / 'etc-nvme'),
               'SF_NVME_MODLOAD': str(tmp / 'nvme-tcp.conf'), 'SF_NVME_SYS': str(tmp / 'sys-nvme')}
        r = subprocess.run(['bash', '-s', '--', '--report'], input=text, env=env, capture_output=True, text=True, timeout=120)
        return r.stdout + r.stderr, tmp

    def test_the_report_runs_on_the_server_and_changes_nothing(self):
        out, tmp = self.run_report('nas')
        self.assertIn('NVMe over TCP server', out)
        self.assertIn('vault.img', out)
        self.assertNotIn('unbound variable', out)
        self.assertNotIn('command not found', out)
        self.assertEqual(list(tmp.glob('nvmet-sh*')), [])
        self.assertFalse((tmp / 'nvmet.conf').exists())

    def test_the_report_says_what_it_would_remove_and_leaves_other_subsystems_alone(self):
        def setup(root):
            for n in ('nqn.2026-11.org.storageforge:nas.old', 'nqn.2014-08.org.nvmexpress:uuid:abc'):
                (root / 'subsystems' / n).mkdir(parents=True)
        out, _ = self.run_report('nas', setup)
        self.assertIn('would remove the subsystem nqn.2026-11.org.storageforge:nas.old', out)
        self.assertNotIn('nvmexpress', out)
        self.assertNotIn('unbound variable', out)

    def test_the_report_runs_on_the_client(self):
        out, tmp = self.run_report('pc')
        self.assertIn('NVMe over TCP', out)
        self.assertIn('NVMe tools', out)
        self.assertIn('nqn.2026-11.org.storageforge:host:pc', out)
        self.assertNotIn('unbound variable', out)
        self.assertNotIn('command not found', out)
        self.assertFalse((tmp / 'etc-nvme').exists())

    def test_a_hostnqn_that_is_not_ours_is_a_conflict(self):
        shares.save_export(self.db, self.conn, 'nas', SHARE, None, 'test')
        text = shares.script(self.conn, 'nas')
        tmp = Path(tempfile.mkdtemp(dir=self.tmp))
        (tmp / 'uname').write_text('#!/bin/sh\necho pc\n')
        (tmp / 'uname').chmod(0o755)
        (tmp / 'nvme').write_text('#!/bin/sh\n')
        (tmp / 'nvme').chmod(0o755)
        (tmp / 'etc-nvme').mkdir()
        (tmp / 'etc-nvme' / 'hostnqn').write_text('nqn.2014-08.org.nvmexpress:uuid:1234\n')
        env = {**os.environ, 'PATH': f'{tmp}:{os.environ["PATH"]}', 'SF_NVME_ETC': str(tmp / 'etc-nvme'), 'SF_NVME_DIR': str(tmp / 's'),
               'SF_NVME_MODLOAD': str(tmp / 'm.conf'), 'SF_NVME_SYS': str(tmp / 'sys')}
        r = subprocess.run(['bash', '-s', '--', '--report'], input=text, env=env, capture_output=True, text=True, timeout=120)
        self.assertIn('did not write', r.stdout)
        self.assertNotIn('command not found', r.stdout + r.stderr)

    def run_start(self, blkid_rc, fmt='ext4'):
        """The client helper's start, as the unit runs it, against stand-ins: blkid's bare probe ends with blkid_rc. Returns
        (exit status, stderr, the stand-ins that were called). PATH holds the stand-ins only, so no real tool can run."""
        if not hasattr(self, 'script_text'):
            shares.save_export(self.db, self.conn, 'nas', SHARE, None, 'test')
            self.script_text = shares.script(self.conn, 'nas')
        m = re.search(r'^nvme_client_sh\(\) \{[^\n]*\n  cat <<"EOF"\n(.*?)\nEOF\n', self.script_text, re.S | re.M)
        self.assertTrue(m, 'the client helper is not in the script')
        body = m.group(1)
        # the namespace is a plain file here, never a disk of the machine the test runs on
        self.assertEqual(body.count('[[ -b $dev ]]'), 1)
        body = body.replace('[[ -b $dev ]]', '[[ -e $dev ]]')
        self.assertEqual(body.count('\ncase ${1:-} in'), 1)
        body = body.replace('\ncase ${1:-} in', '\ndev_of() { echo "$DEV"; }\ncase ${1:-} in')
        tmp = Path(tempfile.mkdtemp(dir=self.tmp))
        bin_ = tmp / 'bin'
        bin_.mkdir()
        (tmp / 'disk').write_text('')
        stubs = {
            'blkid': 'case "$*" in *UUID*) if [ -e "$T/formatted" ] || [ "$BLKID_RC" = 0 ]; then echo 1b2c-3d4e; fi; exit 0 ;; esac\n'
                     '[ "$BLKID_RC" = 0 ] && echo "$2: TYPE=\\"ext4\\""\nexit "$BLKID_RC"',
            'mkfs.ext4': ': >"$T/formatted"', 'mkfs.xfs': ': >"$T/formatted"', 'mount': ': >"$T/mounted"', 'mountpoint': 'exit 1',
            'seq': 'echo 1', 'mkdir': ':', 'modprobe': ':', 'udevadm': ':', 'nvme': ':', 'sleep': ':'}
        for name, sh in stubs.items():
            (bin_ / name).write_text(f'#!/bin/sh\necho {name} >>"$T/calls"\n{sh}\n')
            (bin_ / name).chmod(0o755)
        helper = f'set -u\nNQN=nqn.test\nADDR=10.0.0.1\nPORT=4420\nFORMAT={fmt}\nTARGET={tmp}/mnt\nOPTS=\nDEV={tmp}/disk\n{body}\n'
        self.assertEqual(subprocess.run(['bash', '-n'], input=helper, text=True, capture_output=True).returncode, 0)
        env = {'PATH': str(bin_), 'T': str(tmp), 'BLKID_RC': str(blkid_rc)}
        r = subprocess.run([shutil.which('bash'), '-s', '--', 'start'], input=helper, env=env, capture_output=True, text=True, timeout=60)
        calls = (tmp / 'calls').read_text().split() if (tmp / 'calls').exists() else []
        return r.returncode, r.stderr, calls

    def test_a_disk_blkid_could_not_read_is_never_formatted(self):
        # 8 is an ambivalent probe (conflicting signatures), 4 a usage or read error: blkid prints nothing for either, as for a blank disk
        for rc in (8, 4):
            code, err, calls = self.run_start(rc)
            self.assertNotIn('mkfs.ext4', calls, f'blkid status {rc}')
            self.assertNotIn('mount', calls, f'blkid status {rc}')
            self.assertNotEqual(code, 0, f'blkid status {rc}')
            self.assertIn(f'status {rc}', err)
            self.assertIn('not formatting', err)

    def test_a_blank_disk_is_formatted_and_one_with_a_filesystem_is_mounted_as_it_is(self):
        code, err, calls = self.run_start(2)
        self.assertEqual((code, 'mkfs.ext4' in calls, 'mount' in calls), (0, True, True), err)
        code, err, calls = self.run_start(0)
        self.assertEqual((code, 'mkfs.ext4' in calls, 'mount' in calls), (0, False, True), err)
        code, err, calls = self.run_start(2, fmt='none')
        self.assertEqual((code != 0, 'mount' in calls), (True, False), err)
        self.assertFalse([c for c in calls if c.startswith('mkfs')])
        self.assertIn('holds no filesystem', err)


if __name__ == '__main__':
    unittest.main()
