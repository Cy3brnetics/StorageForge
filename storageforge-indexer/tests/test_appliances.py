"""Hosts that are appliances: Proxmox, TrueNAS, XCP-ng. tests/lab/tiers.py (tier 8) runs the same paths on the real systems.
Run with: python3 -m unittest discover -s tests -v"""
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from storageforge_index import preflight
from storageforge_index.remote import INVENTORY_SCRIPT, PLATFORM, PVE_ENTERPRISE, MountInfo
from storageforge_index.scanner import ScanOptions, plan_mounts

LAB = Path(__file__).resolve().parents[1] / 'examples' / 'lab'


def detect(files):
    """PLATFORM's answer on a machine holding these files, with its absolute paths moved under a folder of stand-ins."""
    with tempfile.TemporaryDirectory() as root:
        for path, text in files.items():
            full = Path(root + path)
            full.parent.mkdir(parents=True, exist_ok=True)
            full.write_text(text)
            full.chmod(0o755)
        script = PLATFORM
        for path in ('/usr/bin/pveversion', '/usr/bin/midclt', '/etc/version', '/etc/xensource-inventory', '/etc/os-release'):
            script = script.replace(path, root + path)
        env = {**os.environ, 'PATH': f'{root}/usr/bin:{os.environ["PATH"]}'}
        return subprocess.run(['sh', '-c', script + '\necho "$platform"'], capture_output=True, text=True, env=env).stdout.strip()


class Detection(unittest.TestCase):
    def test_proxmox(self):
        got = detect({'/usr/bin/pveversion': '#!/bin/sh\necho "pve-manager/9.2.2/abcd (running kernel: 7.0.2-6-pve)"\n'})
        self.assertEqual(got, 'proxmox 9.2.2')

    def test_truenas(self):
        self.assertEqual(detect({'/usr/bin/midclt': '#!/bin/sh\n', '/etc/version': '25.10.7\n'}), 'truenas 25.10.7')

    def test_xcp_ng_says_xenenterprise_as_its_id(self):   # as XCP-ng 8.3 really does
        got = detect({'/etc/xensource-inventory': '', '/etc/os-release': 'NAME="XCP-ng"\nVERSION_ID="8.3.0"\nID="xenenterprise"\n'})
        self.assertEqual(got, 'xcp-ng 8.3.0')

    def test_xenserver(self):
        got = detect({'/etc/xensource-inventory': '', '/etc/os-release': 'NAME="XenServer"\nVERSION_ID="8.4"\nID="xenenterprise"\n'})
        self.assertEqual(got, 'xenserver 8.4')

    def test_an_ordinary_host_is_no_platform(self):
        self.assertEqual(detect({'/etc/os-release': 'NAME="Debian GNU/Linux"\n'}), '')

    def test_debian_style_paths_reach_zpool(self):
        self.assertLess(INVENTORY_SCRIPT.index('/usr/sbin:/sbin'), INVENTORY_SCRIPT.index("zpool status"))

    def test_the_paid_proxmox_repository(self):
        def on(text):
            with tempfile.TemporaryDirectory() as d:
                Path(d, 'pve-enterprise.sources').write_text(text)
                script = PVE_ENTERPRISE.replace('/etc/apt/sources.list.d', d)
                return subprocess.run(['sh', '-c', script]).returncode == 0
        uri = 'URIs: https://enterprise.proxmox.com/debian/pve\n'
        self.assertTrue(on(uri))
        self.assertFalse(on(uri + 'Enabled: no\n'))
        self.assertFalse(on('URIs: http://download.proxmox.com/debian/pve\n'))


class Verdicts(unittest.TestCase):
    def levels(self, **facts):
        return [i['level'] for i in preflight.findings(facts)]

    def test_appliances_refuse_deploys_and_say_scans_still_work(self):
        for name in ('truenas 25.10.7', 'xcp-ng 8.3.0', 'xenserver 8.4'):
            with self.subTest(name):
                text = [i['text'] for i in preflight.findings({'platform': name}) if i['level'] == 'crit']
                self.assertEqual(len(text), 1)
                self.assertIn('Scans still work', text[0])

    def test_proxmox_can_be_deployed_to(self):
        self.assertEqual(self.levels(platform='proxmox 9.2.2'), [])

    def test_the_paid_repository_warns(self):
        self.assertEqual(self.levels(platform='proxmox 9.2.2', pve_enterprise='yes'), ['warn'])

    def test_a_probe_reports_the_platform(self):
        facts = preflight.parse_probe('platform=truenas 25.10.7\npve_enterprise=yes\n')
        self.assertEqual((facts['platform'], facts['pve_enterprise']), ('truenas 25.10.7', 'yes'))

    def test_a_scan_reports_the_platform(self):
        text = 'pm apt-get\nhave bash\nprobed 1\ninit systemd\nplatform truenas 25.10.7\npve_enterprise yes'
        conn = type('C', (), {'all': lambda self, *_a: [(f'{{"packages": {text!r}}}'.replace("'", '"').replace('\n', '\\n'),)]})()
        facts = preflight.facts_from_scan(conn, 'nas')
        self.assertEqual((facts['platform'], facts['pve_enterprise']), ('truenas 25.10.7', 'yes'))


class Scripts(unittest.TestCase):
    def test_the_probe_exits_0_with_no_paid_repository(self):      # any ordinary host: a last test that fails would fail the probe
        self.assertEqual(subprocess.run(['bash', '-c', preflight.PROBE], capture_output=True).returncode, 0)

    def test_setup_scripts_stop_on_an_appliance_before_changing_anything(self):
        from storageforge_index import deploy
        script = deploy.setup_script('ssh-ed25519 AAAA signer', 'ssh-ed25519 AAAA deploy')
        self.assertLess(script.index('nothing can be deployed'), script.index('useradd'))

    def test_scan_access_says_why_not_on_truenas(self):
        from storageforge_index import access
        script = access.setup_script('scan')
        self.assertLess(script.index('TrueNAS keeps its system read-only'), script.index('setcap'))


class Mounts(unittest.TestCase):
    def plan(self, target, fstype):
        return plan_mounts([MountInfo(target, '/dev/x', fstype, majmin='8:1')], ScanOptions())[0]

    def test_a_xen_storage_repository_is_scanned_though_under_run(self):
        self.assertEqual(self.plan('/run/sr-mount/c4afb01d', 'ext4').action, 'scan')

    def test_the_rest_of_run_is_still_excluded(self):
        self.assertEqual(self.plan('/run/media/x', 'ext4').action, 'skip')

    def test_the_proxmox_cluster_filesystem_is_skipped(self):
        self.assertEqual(self.plan('/etc/pve', 'fuse').action, 'skip')


class LabPool(unittest.TestCase):
    def test_random_builds_never_pick_an_appliance(self):
        sys.path.insert(0, str(LAB))
        try:
            import roles
            for seed in range(50):
                self.assertFalse({'sf-pve', 'sf-truenas', 'sf-xcp'} & set(roles.pick(seed)), seed)
        finally:
            sys.path.remove(str(LAB))


if __name__ == '__main__':
    unittest.main()
