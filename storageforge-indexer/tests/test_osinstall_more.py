"""More of the second system (steps_osinstall.py): an address set by hand on the running system, Secure Boot, and a machine
started by BIOS. Run for real where that can be done without a disk or a firmware:

    the network   the script reads `ip` itself, in a network namespace of this user's own, with addresses and routes put there
                  by the real `ip`. No stand-in prints what `ip` is thought to print.
    Secure Boot   the firmware's variables are files, so a folder stands for them; a loader is a PE file, and the ones looked
                  at are systemd-boot as this machine has it (unsigned), a shim as a distribution ships it where one is
                  installed, and PE files built here with and without a signature table.
"""
import json
import os
import shlex
import shutil
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path

from storageforge_index import changes, steps_osinstall

PRELUDE = ('set -euo pipefail; ok() { echo "ok: $*"; }; conflict() { echo "conflict: $*"; }; info() { echo "info: $*"; }; later() { echo "later: $*"; }\n'
           'act() { if [[ ${APPLY:-1} == 1 ]]; then echo "changed: $*"; else echo "would: $*"; return 1; fi; }; try() { "$@"; }; doing() { :; }\n')
SECUREBOOT = 'SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c'
DB = 'db-d719b2cb-3d3a-4596-a3bc-dad00e67656f'
CA_2011, CA_2023 = 'Microsoft Corporation UEFI CA 2011', 'Microsoft UEFI CA 2023'
CARD = next((p.name for p in sorted(Path('/sys/class/net').iterdir()) if (p / 'device').exists()), None) if Path('/sys/class/net').is_dir() else None


def own_namespace() -> bool:
    """Can this user make a network namespace of its own and put an interface in it?"""
    if not (CARD and shutil.which('unshare') and shutil.which('ip')):
        return False
    return subprocess.run(['unshare', '-Urn', 'ip', 'link', 'add', CARD, 'type', 'dummy'], capture_output=True).returncode == 0


def pe_file(path: Path, signature: bytes = b'', bits: int = 64) -> Path:
    """A PE file as a loader is one: the DOS header, the PE header, an optional header with its directories, and, with a
    signature, a certificate table at the end that the fifth directory points at."""
    optional = bytearray(240 if bits == 64 else 224)
    struct.pack_into('<H', optional, 0, 0x20b if bits == 64 else 0x10b)
    body = bytearray(b'MZ' + bytes(58) + struct.pack('<I', 64) + b'PE\0\0' + bytes(20)) + optional + bytes(64)
    if signature:
        table = struct.pack('<IHH', 8 + len(signature), 0x200, 2) + signature
        struct.pack_into('<II', body, 64 + 24 + (112 if bits == 64 else 96) + 32, len(body), len(table))
        body += table
    path.write_bytes(bytes(body))
    return path


class Bash(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.bin = self.tmp / 'bin'
        self.bin.mkdir()
        self.fw = self.tmp / 'efi'
        (self.fw / 'efivars').mkdir(parents=True)
        self.env = {'PATH': f'{self.bin}:{os.environ["PATH"]}', 'SF_FIRMWARE': str(self.fw), 'SF_RESOLV': str(self.tmp / 'resolv.conf'), 'T': str(self.tmp)}

    def tool(self, name, body):
        (self.bin / name).write_text('#!/bin/bash\n' + body + '\n')
        (self.bin / name).chmod(0o755)

    def run_bash(self, code, apply=True, **env):
        ran = subprocess.run(['bash', '-c', PRELUDE + steps_osinstall.bash() + '\n' + code], capture_output=True, text=True, env=self.env | {'APPLY': '1' if apply else '0'} | env)
        self.assertEqual(ran.stderr, '')
        return ran.stdout


@unittest.skipUnless(own_namespace(), 'needs a network card, and a user who may make a network namespace (unshare -Urn)')
class AnAddressSetByHand(Bash):
    """`network: same` on a system whose address nobody handed out. The interface has the name of a card of this machine, so
    /sys says it is one; its addresses and routes are in a namespace where they change nothing."""

    def network(self, setup: list[str], how='same', resolv='nameserver 10.0.0.2\n'):
        (self.tmp / 'resolv.conf').write_text(resolv)
        lines = [f'ip link add {CARD} type dummy', f'ip link set {CARD} up'] + [x.replace('DEV', CARD) for x in setup]
        script = self.tmp / 'run.sh'
        script.write_text(PRELUDE + steps_osinstall.bash() + '\n' + '\n'.join(lines) + f'\nsf_os_network {how} || echo NONE\n')
        ran = subprocess.run(['unshare', '-Urn', 'bash', str(script)], capture_output=True, text=True, env=self.env)
        self.assertEqual(ran.stderr, '')
        out = ran.stdout.strip()
        return out if out == 'NONE' else json.loads(out)['ethernets']['lan']

    def mac(self):
        return Path(f'/sys/class/net/{CARD}/address').read_text().strip()

    def test_one_address_with_its_gateway_and_its_name_servers(self):
        got = self.network(['ip addr add 10.0.0.5/24 dev DEV', 'ip route add default via 10.0.0.1 dev DEV'],
                           resolv='# by hand\nnameserver 127.0.0.53\nnameserver 10.0.0.2\nnameserver 2001:db8::53\nnameserver fe80::1%eth0\nsearch lan example.org lan\noptions edns0\n')
        self.assertEqual(got, {'match': {'macaddress': self.mac()}, 'addresses': ['10.0.0.5/24'], 'routes': [{'to': '0.0.0.0/0', 'via': '10.0.0.1'}],
                               'nameservers': {'addresses': ['10.0.0.2', '2001:db8::53'], 'search': ['lan', 'example.org']}},
                         'the address as it is; not the resolver of this system itself, and not a name server with a zone in it')

    def test_every_address_of_the_interface_and_the_ipv6_ones_set_by_hand(self):
        got = self.network(['ip addr add 10.0.0.5/24 dev DEV', 'ip addr add 10.0.0.6/24 dev DEV', 'ip addr add 192.168.7.5/25 dev DEV', 'ip -6 addr add 2001:db8::5/64 dev DEV',
                            'ip -6 addr add 2001:db8::99/64 dev DEV valid_lft 3600 preferred_lft 3600',      # as a router advertisement gives one: not ours to write down
                            'ip route add default via 10.0.0.1 dev DEV', 'ip -6 route add default via fe80::1 dev DEV'])
        self.assertEqual(got['addresses'], ['10.0.0.5/24', '192.168.7.5/25', '10.0.0.6/24', '2001:db8::5/64'], 'in the order the kernel has them: the first of each network, then a second one in a network')
        self.assertEqual(got['routes'], [{'to': '0.0.0.0/0', 'via': '10.0.0.1'}, {'to': '::/0', 'via': 'fe80::1'}])
        self.assertNotIn('dhcp4', got)

    def test_a_gateway_outside_the_network_of_the_address_is_on_the_link(self):
        got = self.network(['ip addr add 203.0.113.7/32 dev DEV', 'ip route add default via 172.31.1.1 dev DEV onlink'])
        self.assertEqual((got['addresses'], got['routes']), (['203.0.113.7/32'], [{'to': '0.0.0.0/0', 'via': '172.31.1.1', 'on-link': True}]))

    def test_an_address_dhcp_gave_is_asked_for_again_unless_it_is_to_be_kept(self):
        leased = ['ip addr add 10.0.0.77/24 dev DEV valid_lft 3600 preferred_lft 3600', 'ip route add default via 10.0.0.1 dev DEV']
        self.assertEqual(self.network(leased), {'match': {'macaddress': self.mac()}, 'dhcp4': True})
        kept = self.network(leased, how='fixed')
        self.assertEqual((kept['addresses'], kept['routes'], 'dhcp4' in kept), (['10.0.0.77/24'], [{'to': '0.0.0.0/0', 'via': '10.0.0.1'}], False))
        both = self.network(leased + ['ip addr add 10.0.0.9/24 dev DEV'])
        self.assertEqual(both, {'match': {'macaddress': self.mac()}, 'dhcp4': True, 'addresses': ['10.0.0.9/24']}, 'one of each: DHCP gives the route, the other is kept beside it')

    def test_no_name_server_to_read_is_none_written_and_no_route_is_nothing_guessed(self):
        got = self.network(['ip addr add 10.0.0.5/24 dev DEV', 'ip route add default via 10.0.0.1 dev DEV'], resolv='nameserver 127.0.0.53\nnameserver ::1\n')
        self.assertNotIn('nameservers', got)
        self.assertEqual(self.network(['ip addr add 10.0.0.5/24 dev DEV']), 'NONE')
        self.assertEqual(self.network(['ip route add default dev DEV']), 'NONE', 'a route and no address')
        self.assertEqual(self.network(['ip addr add 10.0.0.5/24 dev DEV', 'ip route add default dev DEV']), 'NONE', 'an address by hand and no gateway to write beside it')


class Networks(Bash):
    def test_which_network_an_address_is_in(self):
        code = '; '.join(f'sf_os_in_net {a} {n} && echo yes || echo no' for a, n in (('10.0.0.1', '10.0.0.5/24'), ('10.0.1.1', '10.0.0.5/24'), ('10.0.1.1', '10.0.0.5/23'), ('172.31.1.1', '203.0.113.7/32'),
                                                                                 ('203.0.113.7', '203.0.113.7/32'), ('8.8.8.8', '0.0.0.0/0'), ('010.008.000.009', '10.8.0.1/24'), ('1.2.3.4', '1.2.3.4/33')))
        self.assertEqual(self.run_bash(code).split(), ['yes', 'no', 'yes', 'no', 'yes', 'yes', 'yes', 'no'])


class SecureBoot(Bash):
    def variable(self, value: int | None):
        path = self.fw / 'efivars' / SECUREBOOT
        path.unlink(missing_ok=True)
        if value is not None:
            path.write_bytes(struct.pack('<IB', 6, value))          # the attributes, then one byte

    def trusted_keys(self, *names):
        (self.fw / 'efivars' / DB).write_bytes(b'\xa1\x59\xc0\xa5' + b''.join(b'\x30\x82' + n.encode() + b'\x00\x01' for n in names))

    def test_the_firmware_says_whether_it_is_on(self):
        self.tool('mokutil', 'echo "SecureBoot enabled"')
        self.variable(1)
        self.assertEqual(self.run_bash('sf_os_secureboot').strip(), 'on')
        self.variable(0)
        self.assertEqual(self.run_bash('sf_os_secureboot').strip(), 'off', 'the variable of the firmware is asked first')
        self.variable(None)
        self.assertEqual(self.run_bash('sf_os_secureboot').strip(), 'on', 'mokutil where the variable cannot be read')
        self.tool('mokutil', 'echo "SecureBoot disabled"; echo "Platform is in Setup Mode"')
        self.assertEqual(self.run_bash('sf_os_secureboot').strip(), 'off')
        self.tool('mokutil', 'echo "EFI variables are not supported on this system" >&2; exit 1')
        self.assertEqual(self.run_bash('sf_os_secureboot').strip(), 'unknown', 'and nothing is guessed')

    @unittest.skipUnless(Path('/sys/firmware/efi/efivars', SECUREBOOT).exists(), 'this machine was not started by UEFI')
    def test_the_variable_of_this_machine_is_read(self):
        value = Path('/sys/firmware/efi/efivars', SECUREBOOT).read_bytes()[4]
        self.assertEqual(self.run_bash('sf_os_secureboot', SF_FIRMWARE='/sys/firmware/efi').strip(), {0: 'off', 1: 'on'}[value])

    def test_a_loader_carries_a_signature_or_does_not(self):
        signed, plain, small = pe_file(self.tmp / 'shim.efi', b'\x30\x82' + CA_2011.encode()), pe_file(self.tmp / 'grub.efi'), pe_file(self.tmp / 'ia32.efi', b'x' * 9, bits=32)
        (self.tmp / 'text').write_text('MZ is how a loader starts, and this is not one\n' * 9)
        out = self.run_bash(''.join(f'sf_os_signed {shlex.quote(str(p))} && echo yes || echo no; ' for p in (signed, plain, small, self.tmp / 'text', self.tmp / 'missing')))
        self.assertEqual(out.split(), ['yes', 'no', 'yes', 'no', 'no'])

    @unittest.skipUnless(Path('/usr/lib/systemd/boot/efi/systemd-bootx64.efi').exists(), 'needs systemd-boot as a distribution installs it')
    def test_systemd_boot_as_it_is_installed_here_has_none(self):
        self.assertEqual(self.run_bash('sf_os_signed /usr/lib/systemd/boot/efi/systemd-bootx64.efi && echo yes || echo no').strip(), 'no')

    @unittest.skipUnless(Path('/usr/lib/shim/shimx64.efi.signed').exists(), 'needs a shim as Debian and Ubuntu ship it (shim-signed)')
    def test_a_shim_as_a_distribution_ships_it_has_one_and_names_who_signed_it(self):
        self.trusted_keys(CA_2011, CA_2023)
        out = self.run_bash('f=/usr/lib/shim/shimx64.efi.signed; sf_os_signed $f && echo signed; sf_os_trusted $f')
        self.assertRegex(out, r'^signed\nyes Microsoft (Corporation )?UEFI CA 20(11|23)\n$')

    def test_the_key_that_signed_it_is_looked_for_in_the_list_of_the_firmware(self):
        old, new, both = (pe_file(self.tmp / f'{n}.efi', b''.join(b'\x30\x82' + c.encode() + b'\x00' for c in cas)) for n, cas in (('old', [CA_2011]), ('new', [CA_2023]), ('both', [CA_2011, CA_2023])))
        other = pe_file(self.tmp / 'other.efi', b'\x30\x82Somebody Else Secure Boot CA')
        named_elsewhere = pe_file(self.tmp / 'named.efi', b'\x30\x82Somebody Else')
        named_elsewhere.write_bytes(named_elsewhere.read_bytes().replace(bytes(64), CA_2011.encode().ljust(64, b'\0'), 1))      # the name in its code, not in its signature
        ask = lambda *files: self.run_bash(''.join(f'sf_os_trusted {shlex.quote(str(f))}; ' for f in files)).splitlines()      # noqa: E731
        self.trusted_keys(CA_2011)
        self.assertEqual(ask(old, new, both, other, named_elsewhere), [f'yes {CA_2011}', f'no {CA_2023}', f'yes {CA_2011}', 'unknown', 'unknown'])
        self.trusted_keys(CA_2023)
        self.assertEqual(ask(old, new, both), [f'no {CA_2011}', f'yes {CA_2023}', f'yes {CA_2023}'], 'a machine that ships with only the newer key')
        self.trusted_keys()
        self.assertEqual(ask(both), [f'no {CA_2011} or {CA_2023}'], 'the key for other systems turned off, as some machines ship')
        (self.fw / 'efivars' / DB).unlink()
        self.assertEqual(ask(old), ['unknown'], 'a list that cannot be read is not read as empty')

    def test_what_is_known_not_to_start_is_refused_and_the_rest_is_said_as_far_as_it_is_known(self):
        shim, unsigned = pe_file(self.tmp / 'shimx64.efi', b'\x30\x82' + CA_2011.encode()), pe_file(self.tmp / 'grubx64.efi')
        other = pe_file(self.tmp / 'other.efi', b'\x30\x82Somebody Else Secure Boot CA')
        say = lambda sb, f: self.run_bash(f'sf_os_boots {sb} {shlex.quote(str(f))} /EFI/x/{f.name}').strip()      # noqa: E731
        self.trusted_keys(CA_2011)
        for sb in ('off', 'unknown'):
            self.assertEqual(say(sb, unsigned), '', 'nothing is refused where Secure Boot is not known to be on')
        self.assertRegex(say('on', unsigned), r'^no Secure Boot is on and the loader of this image \(/EFI/x/grubx64.efi\) carries no signature: this firmware would refuse it\. Not installed')
        got = say('on', shim)
        self.assertRegex(got, rf'^yes Secure Boot is on: /EFI/x/shimx64.efi is signed with {CA_2011}, and this firmware lists that key\. Not checked: the revocation list')
        self.assertIn('some stop at a message until a key is pressed at the machine', got, 'what a refused loader costs is not promised')
        self.assertRegex(say('on', other), r'^yes Secure Boot is on: /EFI/x/other.efi carries a signature, and whether this firmware trusts it could not be read')
        self.trusted_keys(CA_2023)
        self.assertRegex(say('on', shim), rf'^no Secure Boot is on, the loader of this image \(/EFI/x/shimx64.efi\) is signed with {CA_2011}, and the list of keys this firmware trusts \(db\) names none of them')

    def test_the_plan_says_it_before_anything_runs(self):
        plan = changes.normalize({'name': 'p', 'tasks': [{'type': 'os-install', 'host': 'nas', 'params': {'name': 'nas-fedora', 'image': 'fedora44', 'disk': '/dev/sdb', 'confirm': '/dev/sdb',
                                                                                                              'user': 'gabe', 'ssh_key': 'ssh-ed25519 ' + 'A' * 68}}]})
        said = []
        steps_osinstall._check_install(None, None, {'name': 'nas'}, plan['tasks'][0]['params'], lambda level, text: said.append(text))
        self.assertTrue(any('Secure Boot' in t and 'not installed' in t for t in said), said)
        self.assertTrue(any('started by BIOS is refused' in t for t in said), said)


class StartedByBios(Bash):
    """A machine with no /sys/firmware/efi: every step says why it does nothing, and does nothing."""

    def setUp(self):
        super().setUp()
        self.env['SF_FIRMWARE'] = str(self.tmp / 'not-there')
        for name in ('efibootmgr', 'sgdisk', 'wipefs', 'qemu-img', 'curl', 'sfdisk', 'partx', 'dd'):
            self.tool(name, f'echo "{name} $*" >> $T/ran')

    def test_nothing_is_installed_and_the_message_says_what_a_bios_machine_is(self):
        out = self.run_bash('t_os_install nas-fedora fedora44 "" "" /dev/sdb "" gabe key')
        self.assertRegex(out, r'^conflict: this machine was started by BIOS, not UEFI \(there is no /sys/firmware/efi\): a second system beside the first needs the boot entries of UEFI, and is not installed here\.')
        for part in ('A BIOS disk has one boot sector, it belongs to the running system', 'legacy (CSM) mode', 'Nothing was changed'):
            self.assertIn(part, out)
        self.assertEqual(out.count('\n'), 1, 'one line, and nothing after it')
        self.assertFalse((self.tmp / 'ran').exists(), 'no tool was run')

    def test_there_is_nothing_to_choose_between(self):
        for when in ('once', 'always', 'never'):
            out = self.run_bash(f't_os_boot nas-fedora {when} yes')
            self.assertIn('conflict: this machine was started by BIOS, not UEFI (there is no /sys/firmware/efi): it has no boot entries to choose between.', out)
            self.assertNotIn('restart', out)
        self.assertFalse((self.tmp / 'ran').exists(), 'the boot entries were not asked for, and nothing restarts')


if __name__ == '__main__':
    unittest.main()
