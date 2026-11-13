"""Hardware differences in a copy (phase 3c): what of a package list belongs on the machine it lands on (a VM or
hardware, its CPU vendor and graphics, a Raspberry Pi or not, its architecture and x86-64 level), the services that
follow the same rule, and the checks made when a plan is checked."""
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

try:
    from test_clone import Db
    from test_md_services import HARNESS, stub
except ImportError:      # run as tests.test_x from the project folder
    from tests.test_clone import Db
    from tests.test_md_services import HARNESS, stub
from storageforge_index import changes, clone, pkglist, steps_services, steps_vm

# what one CachyOS desktop with an NVIDIA card listed (the lab run of 2026-11-07), and a Raspberry Pi
DESKTOP = ['linux-cachyos', 'linux-cachyos-nvidia-open', 'limine', 'amd-ucode', 'linux-firmware', 'sof-firmware', 'nvidia-utils',
           'lib32-nvidia-utils', 'vulkan-radeon', 'smartmontools', 'rpi-imager', 'sddm', 'firefox', 'linux-api-headers']
PI = ['raspberrypi-kernel', 'raspberrypi-bootloader', 'rpi-eeprom', 'raspi-config', 'libraspberrypi0', 'pi-bluetooth',
      'firmware-brcm80211', 'python3-rpi-lgpio', 'nginx', 'libc6:arm64', 'samba']


class Script(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.d)
        for name in ('pacman', 'apt-get', 'dpkg-query', 'apt-cache'):
            stub(self.d, name, 'if [ "$1" = policy ]; then shift; for p; do printf "%s:\\n  Candidate: 1.0\\n" "$p"; done; fi; true')

    def run_for(self, pkgs, pm='pacman', *, virt='', vendor='AuthenticAMD', gpus='', rpi='', arch='amd64', level='3',
                src_arch='amd64', needs=None, distro='cachyos', version=''):
        pk = pkglist.parse(f'distro\t{distro}\t{version}\npm {pm}\n' + ''.join(f'm\t{p}\n' for p in pkgs) + f'arch\t{src_arch}\ncomplete')
        if needs:
            pk['needs_level'] = needs
        text = (pkglist.script(pk, 'src', 'now')
                .replace('here_pm() {', f'here_pm() {{ echo {pm}; return; ')
                .replace('VIRT=$(systemd-detect-virt 2>/dev/null || true); [[ $VIRT == none ]] && VIRT=', f'VIRT={virt}')
                .replace('VENDOR=$(awk -F": " "/^vendor_id/ {print \\$2; exit}" /proc/cpuinfo 2>/dev/null || true)', f'VENDOR={vendor}')
                .replace('HERE_RPI=; grep -qs "Raspberry Pi" /proc/device-tree/model && HERE_RPI=1', f'HERE_RPI={rpi}')
                .replace('GPUS=; gpu_has 0x10de && GPUS+=" nvidia"; gpu_has 0x1002 && GPUS+=" amd"; gpu_has 0x8086 && GPUS+=" intel"', f'GPUS="{gpus}"')
                .replace('. /etc/os-release 2>/dev/null || true', f'ID={distro} VERSION_ID={version}')
                .replace('case $(uname -m) in x86_64) HERE_ARCH=amd64', f'case {arch} in amd64) HERE_ARCH=amd64')
                .replace('  lvl=$(here_level)', f'  lvl={level}'))
        for want in (f'VIRT={virt}', f'VENDOR={vendor}', f'HERE_RPI={rpi}', f'  lvl={level}', f'GPUS="{gpus}"', f'ID={distro} VERSION_ID={version}'):
            self.assertIn(want, text, 'a detection line of the script changed: change the test with it')
        path = self.d / 'p.sh'
        path.write_text(text)
        return subprocess.run(['bash', str(path)], capture_output=True, text=True, timeout=60, env={**os.environ, 'PATH': f'{self.d}:{os.environ["PATH"]}'}).stdout

    def left(self, out, why):
        m = re.search(rf'left out, {re.escape(why)}:(.*)', out)
        return sorted(m.group(1).split()) if m else []

    def test_hardware_to_a_vm(self):
        out = self.run_for(DESKTOP, virt='kvm')
        self.assertIn('this host: a kvm VM, amd64, AuthenticAMD', out)
        boots = re.search(r'kernel or boot package\(s\) left to the base install here, which the copy never changes: (.*)', out).group(1).split()
        self.assertEqual(sorted(boots), ['limine', 'linux-cachyos', 'linux-cachyos-nvidia-open'])
        self.assertEqual(self.left(out, 'for an NVIDIA GPU, which this machine lacks'), ['lib32-nvidia-utils', 'nvidia-utils'])
        self.assertEqual(self.left(out, 'for an AMD GPU, which this machine lacks'), ['vulkan-radeon'])
        self.assertEqual(self.left(out, 'firmware for hardware a VM does not have'), ['linux-firmware', 'sof-firmware'])
        self.assertEqual(self.left(out, 'CPU microcode: the host of the VM loads it'), ['amd-ucode'])
        self.assertEqual(self.left(out, 'a hardware tool, with no hardware to look after on a VM'), ['smartmontools'])
        self.assertIn('added for this kvm VM: qemu-guest-agent', out)
        self.assertIn('added for this kvm VM: spice-vdagent', out)          # sddm: a desktop
        want = re.search(r'to install with pacman: (.*)', out).group(1).split()
        self.assertEqual(sorted(want), ['firefox', 'linux-api-headers', 'qemu-guest-agent', 'rpi-imager', 'sddm', 'spice-vdagent'])

    def test_hardware_to_other_hardware_keeps_what_it_has_hardware_for(self):
        out = self.run_for(DESKTOP + ['qemu-guest-agent', 'intel-ucode'], vendor='GenuineIntel', gpus=' nvidia')
        want = re.search(r'to install with pacman: (.*)', out).group(1).split()
        for p in ('nvidia-utils', 'linux-firmware', 'smartmontools', 'intel-ucode'):
            self.assertIn(p, want)
        self.assertEqual(self.left(out, 'microcode for AMD, and this CPU is GenuineIntel'), ['amd-ucode'])
        self.assertEqual(self.left(out, 'a guest tool, and this is real hardware'), ['qemu-guest-agent'])
        self.assertNotIn('added for', out)

    def test_a_raspberry_pi_to_an_x86_vm(self):
        out = self.run_for(PI, pm='apt-get', virt='kvm', src_arch='aarch64', distro='debian', version='12')
        self.assertIn('src is arm64 and this host amd64', out)
        boots = re.search(r'never changes: (.*)', out).group(1).split()
        self.assertEqual(sorted(boots), ['raspberrypi-bootloader', 'raspberrypi-kernel', 'rpi-eeprom'])
        self.assertEqual(self.left(out, 'made for a Raspberry Pi, and this is not one'), ['libraspberrypi0', 'pi-bluetooth', 'python3-rpi-lgpio', 'raspi-config'])
        self.assertEqual(self.left(out, 'firmware for hardware a VM does not have'), ['firmware-brcm80211'])
        want = re.search(r'to install with apt-get: (.*)', out).group(1).split()
        self.assertEqual(sorted(want), ['libc6', 'nginx', 'qemu-guest-agent', 'samba'])      # :arm64 dropped: built for this host

    def test_a_pi_to_a_pi_keeps_the_pi_packages(self):
        out = self.run_for(PI, pm='apt-get', rpi='1', arch='arm64', src_arch='aarch64', distro='debian', version='12')
        self.assertNotIn('made for a Raspberry Pi', out)
        self.assertIn('raspi-config', re.search(r'to install with apt-get: (.*)', out).group(1))

    def test_packages_built_for_a_newer_cpu_are_refused_before_anything(self):
        out = self.run_for(['firefox'], virt='kvm', level='2', needs=3)
        self.assertIn('built for x86-64-v3, and this CPU runs x86-64-v2: they would not start', out)
        self.assertNotIn('to install', out)
        self.assertIn('this CPU runs x86-64-v3, as the packages of src need (v3)', self.run_for(['firefox'], virt='kvm', level='3', needs=3))
        self.assertNotIn('x86-64', self.run_for(['firefox'], virt='kvm', arch='arm64', level='', needs=3))     # an Arm target: no x86 level


class Parse(unittest.TestCase):
    def test_arch_cpu_level_and_the_level_the_packages_need(self):
        pk = pkglist.parse('pm pacman\nm\tvim\nr\tcachyos-v3\t/etc/pacman.d/cachyos-v3-mirrorlist\nr\tcore\t/etc/pacman.d/mirrorlist\narch\tx86_64\ncpu\t3\ncomplete')
        self.assertEqual((pk['arch'], pk['cpu_level'], pk['needs_level']), ('amd64', 3, 3))
        self.assertEqual(pkglist.parse('pm apt-get\narch\taarch64\ncpu\t$(id)\n')['arch'], 'arm64')
        self.assertIsNone(pkglist.parse('pm apt-get\narch\taarch64\ncpu\t$(id)\n')['cpu_level'])
        self.assertEqual(pkglist.parse('pm apt-get\narch\tarmv7l\n')['arch'], 'armhf')
        self.assertIsNone(pkglist.parse('pm pacman\nr\tcore\t/etc/pacman.d/mirrorlist\n')['needs_level'])
        self.assertEqual(pkglist.needs_level([{'where': 'cachyos-znver4', 'url': ''}]), 4)

    def test_the_scan_reads_both(self):
        from storageforge_index import remote
        self.assertIn("printf 'arch\\t%s\\n' \"$(uname -m)\"", remote.INVENTORY_SCRIPT)
        self.assertIn('ld-linux-x86-64.so.2', remote.INVENTORY_SCRIPT)

    def test_raspberry_pi_os_starts_from_debian(self):
        self.assertEqual(steps_vm.image_for('raspbian', '12'), steps_vm.image_for('debian', '12'))
        self.assertIsNotNone(steps_vm.image_for('raspbian', '12'))


class Services(unittest.TestCase):
    def test_hardware_nvidia_and_pi_services_stay_off_where_there_is_none(self):
        d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d)
        stub(d, 'systemctl', 'echo disabled')
        stub(d, 'systemd-detect-virt', 'echo kvm')
        import base64
        want = base64.b64encode(b'smartd.service\nnvidia-persistenced.service\nrpi-eeprom-update.service\nnginx.service\n').decode()
        body = steps_services.BASH.replace('[[ -d /run/systemd/system ]]', 'true').replace('/sys/bus/pci/devices/*', '/nonexistent/*')
        out = subprocess.run(['bash', '-c', HARNESS + 'APPLY=0\n' + body + f'\nt_services src "" systemd {want} ""\n'],
                             capture_output=True, text=True, timeout=60, env={**os.environ, 'PATH': f'{d}:{os.environ["PATH"]}'}).stdout
        self.assertIn('skip: smartd.service: a hardware service, and this is a kvm VM', out)
        self.assertIn('skip: nvidia-persistenced.service: for an NVIDIA GPU, which this machine lacks', out)
        self.assertIn('skip: rpi-eeprom-update.service: made for a Raspberry Pi, and this is not one', out)
        self.assertIn('would: systemctl enable nginx.service, and start it', out)


class Plans(Db):
    def set_pk(self, host, **kw):
        hid = self.conn.scalar('SELECT host_id FROM hosts WHERE hostname = :n', {'n': host})
        inv = self.conn.scalar('SELECT inventory_json FROM hosts WHERE host_id = :h', {'h': hid})
        inv = json.loads(inv) if isinstance(inv, str) else inv           # PostgreSQL hands back jsonb as a dict
        inv['pkglist'] = {**(inv.get('pkglist') or pkglist.parse('pm apt-get\ncomplete')), **kw}
        self.conn.execute(f"UPDATE hosts SET inventory_json = {self.db.jsonp(':i')} WHERE host_id = :h", {'i': json.dumps(inv), 'h': hid})

    def check(self):
        pid = clone.save(self.conn, clone.build(self.conn, 'web-01', 'web-copy'), 'test')['changes']
        return [i for t in changes.check(self.conn, changes.get_plan(self.conn, pid))['tasks'] if t['title'] == 'Packages of web-01' for i in t['items']]

    def test_an_architecture_change_is_a_risk_and_a_warning(self):
        self.set_pk('web-01', arch='arm64')
        self.set_pk('web-copy', arch='amd64')
        got = clone.build(self.conn, 'web-01', 'web-copy')
        self.assertIn('arch-change', [r['id'] for r in got['risks'] if r['level'] == 'warn'])
        self.assertTrue(any(i['level'] == 'warn' and 'web-01 is arm64 and web-copy amd64' in i['text'] for i in self.check()))

    def test_a_cpu_older_than_the_packages_is_critical_when_the_plan_is_checked(self):
        self.set_pk('web-01', needs_level=3)
        self.set_pk('web-copy', arch='amd64', cpu_level=2)
        self.assertTrue(any(i['level'] == 'crit' and 'x86-64-v3' in i['text'] for i in self.check()))


if __name__ == '__main__':
    unittest.main()
