"""A second system installed beside the running one (steps_osinstall.py). The install itself is proven in the KVM lab, where
there is a firmware and a disk; here: what the change engine takes and refuses, and the parts of the script that decide
something without a disk, run for real against stand-ins."""
import json
import os
import re
import shlex
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from storageforge_index import changes, steps_osinstall

KEY = 'ssh-ed25519 ' + 'A' * 68 + ' me@laptop'
PRELUDE = ('set -euo pipefail; ok() { echo "ok: $*"; }; conflict() { echo "conflict: $*"; }; info() { echo "info: $*"; }; later() { echo "later: $*"; }\n'
           'act() { if [[ ${APPLY:-1} == 1 ]]; then echo "changed: $*"; else echo "would: $*"; return 1; fi; }; try() { "$@"; }; doing() { :; }\n')


def install(**params):
    return {'type': 'os-install', 'host': 'nas', 'params': {'name': 'nas-fedora', 'image': 'fedora44', 'disk': '/dev/nvme0n1', 'confirm': '/dev/nvme0n1', 'user': 'gabe', 'ssh_key': KEY} | params}


class ThePlan(unittest.TestCase):
    def test_the_engine_takes_the_three_steps_and_fills_the_safe_defaults(self):
        plan = changes.normalize({'name': 'p', 'tasks': [install(), {'type': 'os-boot', 'host': 'nas', 'params': {'name': 'nas-fedora'}}, {'type': 'os-remove', 'host': 'nas', 'params': {'name': 'nas-fedora'}}]})
        first, boot, _ = (t['params'] for t in plan['tasks'])
        self.assertEqual((first['host_keys'], first['network'], first['carry'], first['sudo']), ('same', 'same', 'mount', 'nopasswd'))
        self.assertEqual((boot['when'], boot['restart']), ('once', 'no'), 'by default: once, and no restart nobody asked for')
        self.assertEqual([changes.title(t) for t in plan['tasks']], ['Install nas-fedora (Fedora 44) on /dev/nvme0n1', 'Start nas-fedora once', 'Remove the system nas-fedora'])
        self.assertTrue(changes.TYPES['os-install'].get('destructive') and changes.TYPES['os-remove'].get('destructive'))

    def test_what_is_refused_before_any_script_is_written(self):
        for why, params in (('the disk not typed again', {'confirm': ''}), ('the wrong disk typed again', {'confirm': '/dev/sda'}), ('no login key', {'ssh_key': ''}), ('a key with a command in it', {'ssh_key': KEY + '"; reboot'}),
                            ('a name with a space', {'name': 'my os'}), ('a name with a quote', {'name': 'a"b'}), ('an image not in the catalog', {'image': 'templeos'}),
                            ('an image over http', {'image': 'custom', 'image_url': 'http://example.com/a.qcow2', 'image_sha': 'a' * 64}), ('a disk that is a path elsewhere', {'disk': '/etc/passwd', 'confirm': '/etc/passwd'}),
                            ('a size that is not a number', {'size_gb': '5G'}), ('a third kind of host key', {'host_keys': 'copy'})):
            with self.subTest(why), self.assertRaises(ValueError):
                changes.normalize({'name': 'p', 'tasks': [install(**params)]})

    def test_the_check_says_what_matters(self):
        def said(fn, **params):
            out = []
            fn(None, None, {'name': 'nas'}, {'name': 'x', 'image': 'fedora44', 'user': 'gabe', 'host_keys': 'same'} | params, lambda level, text: out.append((level, text)))
            return out
        self.assertIn('crit', [lv for lv, _ in said(steps_osinstall._check_install, image='custom')])
        self.assertIn('crit', [lv for lv, _ in said(steps_osinstall._check_install, user='root')])
        self.assertIn('crit', [lv for lv, _ in said(steps_osinstall._check_install, size_gb='1')])
        self.assertTrue(any(lv == 'warn' and 'warn' in text for lv, text in said(steps_osinstall._check_install, host_keys='new')))
        self.assertEqual([lv for lv, _ in said(steps_osinstall._check_install)], ['note', 'note', 'note'])
        self.assertEqual([lv for lv, _ in said(steps_osinstall._check_boot, when='always', restart='yes')], ['warn', 'warn'])
        self.assertEqual(said(steps_osinstall._check_boot, when='once', restart='no'), [])

    def test_the_catalog_has_only_images_that_start_by_uefi(self):
        self.assertFalse([k for k in steps_osinstall.IMAGES if k.startswith('alpine')])
        self.assertIn('debian13', steps_osinstall.IMAGES)

    def test_the_script_is_bash_and_is_in_every_plan_script(self):
        ran = subprocess.run(['bash', '-n'], input=steps_osinstall.bash(), capture_output=True, text=True)
        self.assertEqual((ran.returncode, ran.stderr), (0, ''))
        self.assertIn(steps_osinstall.bash(), changes.EXTRA_BASH)
        self.assertNotIn('@', re.sub(r'"\$@"|\$\{made\[@\]\}|\$\{parts\[@\]\}|\$\{[a-z_]+\[@\]\}|[A-Za-z]@[a-z]', '', re.sub(r'#.*', '', steps_osinstall.bash())).replace('${@', ''), 'a placeholder was left in')


class TheScript(unittest.TestCase):
    """The parts that decide something, run for real: the script's own functions, with stand-ins for the tools they call."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.bin = self.tmp / 'bin'
        self.bin.mkdir()
        self.env = {'PATH': f'{self.bin}:{os.environ["PATH"]}', 'SF_FSTAB': str(self.tmp / 'fstab'), 'T': str(self.tmp)}

    def tool(self, name, body):
        (self.bin / name).write_text('#!/bin/bash\n' + body + '\n')
        (self.bin / name).chmod(0o755)

    def run_bash(self, code, apply=True):
        ran = subprocess.run(['bash', '-c', PRELUDE + steps_osinstall.bash() + '\n' + code], capture_output=True, text=True, env=self.env | {'APPLY': '1' if apply else '0'})
        self.assertEqual(ran.stderr, '')
        return ran.stdout

    def test_a_private_key_reaches_the_seed_byte_for_byte(self):
        """The first trial lost the newline a key file ends in, and sshd would not start: 'no hostkeys available'."""
        key = self.tmp / 'ssh_host_ed25519_key'
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', 'a "quoted" \\ comment', '-f', str(key)], check=True)
        for path in (key, Path(f'{key}.pub')):
            self.assertEqual(json.loads(self.run_bash(f'sf_os_json {shlex.quote(str(path))}')), path.read_text())

    def test_partitions_are_named_as_the_kernel_names_them(self):
        self.assertEqual(self.run_bash('sf_os_part /dev/sda 3; sf_os_part /dev/nvme0n1 3; sf_os_part /dev/mmcblk0 12; sf_os_part /dev/vdb 1').split(), ['/dev/sda3', '/dev/nvme0n1p3', '/dev/mmcblk0p12', '/dev/vdb1'])

    def test_only_data_filesystems_named_for_good_are_carried(self):
        (self.tmp / 'fstab').write_text('''# a comment
UUID=1111-root / ext4 defaults 0 1
UUID=2222-efi /boot/efi vfat umask=0077 0 2
UUID=3333-home /home ext4 defaults,noatime 0 2
LABEL=tank /srv/tank xfs defaults,nofail 0 2
/dev/sdb1 /mnt/by-letter ext4 defaults 0 2
/dev/mapper/vg-data /data ext4 defaults 0 2
UUID=4444-swap none swap sw 0 0
nas:/export /mnt/nfs nfs defaults 0 0
/dev/disk/by-id/ata-X-part1 /srv/b"ad btrfs subvol=@data 0 0
tmpfs /tmp tmpfs defaults 0 0
''')
        mounts = json.loads('[' + self.run_bash('sf_os_mounts') + ']')
        self.assertEqual(mounts, [['UUID=3333-home', '/home', 'ext4', 'defaults,noatime,nofail', '0', '2'], ['LABEL=tank', '/srv/tank', 'xfs', 'defaults,nofail', '0', '2'],
                                  ['/dev/disk/by-id/ata-X-part1', '/srv/bad', 'btrfs', 'subvol=@data,nofail', '0', '2']],
                         'not the old root, boot or swap; not a device letter, which may be another disk in the new system; nofail on each, so a missing one does not stop the boot')

    def network(self, addr_line, route='default via 10.0.0.1 dev eth9 proto static', how='same'):
        self.tool('ip', f'''case "$*" in
  "-4 route show default") echo "{route}";;
  "-o -4 addr show dev eth9 scope global") echo "{addr_line}";;
esac''')
        # a card: the script asks /sys whether the interface is one. This machine has none called eth9, so point it at one that is
        card = next((p.name for p in Path('/sys/class/net').iterdir() if (p / 'device').exists()), None)
        if card is None:
            self.skipTest('no network card here to stand for one')
        code = steps_osinstall.bash().replace('eth9', card)
        self.tool('ip', (self.bin / 'ip').read_text().split('\n', 1)[1].replace('eth9', card))
        ran = subprocess.run(['bash', '-c', PRELUDE + code + f'\nsf_os_network {how} || echo NONE'], capture_output=True, text=True, env=self.env)
        self.assertEqual(ran.stderr, '')
        return ran.stdout.strip(), Path(f'/sys/class/net/{card}/address').read_text().strip()

    def test_the_network_is_what_the_running_system_has(self):
        out, mac = self.network('2: eth9    inet 10.0.0.5/24 brd 10.0.0.255 scope global eth9')
        got = json.loads(out)['ethernets']['lan']
        self.assertEqual((got['match'], got['addresses'], got['routes']), ({'macaddress': mac}, ['10.0.0.5/24'], [{'to': '0.0.0.0/0', 'via': '10.0.0.1'}]))
        out, _ = self.network('2: eth9    inet 10.0.0.77/24 brd 10.0.0.255 scope global dynamic eth9')
        self.assertEqual(json.loads(out)['ethernets']['lan'], {'match': {'macaddress': mac}, 'dhcp4': True}, 'an address DHCP gave is asked for again')
        out, _ = self.network('2: eth9    inet 10.0.0.77/24 brd 10.0.0.255 scope global dynamic eth9', how='fixed')
        self.assertEqual(json.loads(out)['ethernets']['lan']['addresses'], ['10.0.0.77/24'], 'unless it is to be kept')
        self.assertEqual(self.network('', route='')[0], 'NONE', 'no default route: nothing is guessed')
        self.assertEqual(self.network('2: eth9    inet 10.0.0.5/24; reboot scope global eth9')[0].count('reboot'), 0)

    def firmware(self, order='0002,0000', next_=''):
        (self.tmp / 'order').write_text(order)
        (self.tmp / 'next').write_text(next_)
        self.tool('efibootmgr', '''set -- "${@/-q/}"; args=($*)
case "${args[0]:-}" in
  "") [ -s $T/next ] && echo "BootNext: $(cat $T/next)"; echo "BootCurrent: 0002"; echo "BootOrder: $(cat $T/order)"
      printf 'Boot0000* Firmware Setup\\tFvVol(x)\\nBoot0002* debian\\tHD(15,GPT,a)/File(\\\\EFI\\\\debian\\\\shimx64.efi)\\nBoot0004* sf-fedora\\tHD(1,GPT,b)/File(\\\\EFI\\\\fedora\\\\shimx64.efi)\\nBoot0005* sf-fedora-old\\tHD(9,GPT,c)\\n';;
  -n) echo "${args[1]}" > $T/next;;
  -N) : > $T/next;;
  -o) echo "${args[1]}" > $T/order;;
esac''')
        self.tool('systemd-run', 'echo "$*" >> $T/restarts')

    def state(self):
        return (self.tmp / 'order').read_text().strip(), (self.tmp / 'next').read_text().strip()

    def test_once_sets_only_the_next_start_and_leaves_the_order(self):
        self.firmware()
        out = self.run_bash('t_os_boot fedora once no')
        self.assertIn('ok: fedora starts at the next restart; the one after that follows the boot order (0002,0000)', out)
        self.assertEqual(self.state(), ('0002,0000', '0004'), 'entry 0004 is sf-fedora, not sf-fedora-old')
        self.assertIn('ok: fedora starts at the next restart, once', self.run_bash('t_os_boot fedora once no'))
        self.assertFalse((self.tmp / 'restarts').exists(), 'nothing restarts unless asked')

    def test_always_and_never_and_a_report_that_changes_nothing(self):
        self.firmware()
        self.assertIn('would: put fedora first', self.run_bash('t_os_boot fedora always yes', apply=False))
        self.assertEqual((self.state(), (self.tmp / 'restarts').exists()), (('0002,0000', ''), False))
        self.run_bash('t_os_boot fedora always no')
        self.assertEqual(self.state(), ('0004,0002,0000', ''))
        self.assertIn('ok: fedora is first in the boot order', self.run_bash('t_os_boot fedora always no'))
        (self.tmp / 'next').write_text('0004')
        self.run_bash('t_os_boot fedora never no')
        self.assertEqual(self.state(), ('0002,0000', ''), 'out of the order, and not the next start either')
        self.assertIn('ok: fedora is not in the boot order', self.run_bash('t_os_boot fedora never no'))

    def test_a_restart_is_a_minute_away_so_the_run_can_report(self):
        self.firmware()
        Path('/run/systemd/system').exists() or self.skipTest('no systemd here')
        out = self.run_bash('t_os_boot fedora once yes')
        self.assertIn('ok: restarting in one minute', out)
        self.assertEqual((self.tmp / 'restarts').read_text().strip(), '--quiet --on-active=60 systemctl reboot')

    def test_a_system_that_was_never_installed_cannot_be_started(self):
        self.firmware()
        self.assertIn('later: there is no boot entry sf-nixos', self.run_bash('t_os_boot nixos once yes'))
        self.assertEqual(self.state(), ('0002,0000', ''))

    def test_the_running_system_is_never_removed(self):
        self.firmware()
        self.tool('lsblk', '''case "$*" in
  "-rno PATH,PARTLABEL") printf '/dev/vda1 \\n/dev/vdb1 sf-fedora-2\\n/dev/vdb2 sf-fedora-root\\n/dev/vdb3 sf-fedora-old-root\\n';;
  *MOUNTPOINT*) :;;
esac''')
        self.tool('findmnt', 'echo "/dev/vdb2[/root]"')
        self.tool('sgdisk', 'echo "sgdisk $*" >> $T/deleted')
        self.tool('wipefs', 'echo "wipefs $*" >> $T/deleted')
        self.assertIn('conflict: fedora is the system that is running', self.run_bash('t_os_remove fedora'))
        self.assertFalse((self.tmp / 'deleted').exists())
        self.assertIn('ok: there is no system named arch here', self.run_bash('t_os_remove arch'))


if __name__ == '__main__':
    unittest.main()
