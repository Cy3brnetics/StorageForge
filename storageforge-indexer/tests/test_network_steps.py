"""Bonds, addresses, routes and DHCP (steps_network.py), written in netplan, NetworkManager, systemd-networkd or ifupdown, whichever the
host uses. The Bash runs against stand-ins for ip, netplan, nmcli, networkctl and ifup that keep their state in files, so each test
can look at what was written, run the way back the rollback timer would run, and run the step again to see it finds its own work."""
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

try:
    from test_clone import Db, blk
except ImportError:      # run as tests.test_x from the project folder
    from tests.test_clone import Db, blk
from storageforge_index import changes, steps_infra, steps_network

HARNESS = r'''
set -u
ok() { echo "ok: $*"; }; missing() { echo "missing: $*"; }; conflict() { echo "conflict: $*"; PROBLEMS=$((PROBLEMS + 1)); }
info() { echo "info: $*"; }; doing() { echo "doing: $*"; }; later() { echo "later: $*"; }
act() { if ((APPLY)); then echo "doing: $*"; return 0; else echo "would: $*"; return 1; fi; }
try() { "$@" || { conflict "failed: $*"; return 1; }; }
durable() { :; }
PROBLEMS=0 STAMP=20261120-120000
'''
# the timer, stood in for: what fw_arm journals is what the timer would run
FW_STANDIN = 'fw_tool() { :; }\nfw_arm() { [[ -n $1 ]] || return 0; printf "%s\\n" "$2" >>"$FAKE/journal"; echo "FW-ROLLBACK armed $1"; }\n'

IP = r'''echo "ip $*" >>"$LOG"
a=("$@"); last=${a[-1]}
case " $* " in
  *" link show "*) [[ -e $FAKE/link-$last ]] || exit 1; [[ $1 == -o ]] && cat "$FAKE/link-$last"; exit 0 ;;
  *" addr show dev "*) cat "$FAKE/addr-$last" 2>/dev/null; exit 0 ;;
  *" addr add "*) echo "2: $5    inet $3 scope global $5" >>"$FAKE/addr-$5" ;;
  *" addr del "*) grep -vF " $3 " "$FAKE/addr-$5" >"$FAKE/x" || true; mv "$FAKE/x" "$FAKE/addr-$5" ;;
  *" route get "*) echo "$last dev ${ROUTE_DEV:-eth0} src 10.0.0.2 uid 0" ;;
  *" route show to exact "*) grep -F "$last " "$FAKE/routes" 2>/dev/null; exit 0 ;;
  *" route replace "*) shift 3; echo "$1 via $3 dev $5 proto static" >>"$FAKE/routes" ;;
  *" route del "*) shift 3; grep -vF "$1 via $3 " "$FAKE/routes" >"$FAKE/x" || true; mv "$FAKE/x" "$FAKE/routes" ;;
esac
exit 0'''

NMCLI = r'''echo "nmcli $*" >>"$LOG"
n=$FAKE/nm
case "$*" in
  "-t -f RUNNING general") [[ -e $FAKE/nm-running ]] && echo running ;;
  "-g GENERAL.CONNECTION device show "*) cat "$n/dev-$5" 2>/dev/null ;;
  "-g "*" connection show "*) cat "$n/con-$5/$2" 2>/dev/null ;;
  "connection modify "*) con=$3; shift 3; mkdir -p "$n/con-$con"
    while (($#)); do k=$1 v=$2; shift 2; f=$n/con-$con/${k#[+-]}; have=$(cat "$f" 2>/dev/null)
      case $k in
        +*) if [[ -n $have ]]; then echo "$have, $v" >"$f"; else echo "$v" >"$f"; fi ;;
        -*) echo "$have" | sed "s/\(, \)\{0,1\}$v//; s/^, //" >"$f" ;;
        *) echo "$v" >"$f" ;;
      esac
    done ;;
esac
exit 0'''

NETWORKCTL = r'''echo "networkctl $*" >>"$LOG"
[[ $1 == status ]] && [[ -e $FAKE/network/10-$2.network ]] && echo "   Network File: $FAKE/network/10-$2.network"
exit 0'''

STUBS = {'ip': IP, 'nmcli': NMCLI, 'networkctl': NETWORKCTL,
         'netplan': 'echo "netplan $*" >>"$LOG"; case $1 in get) echo null ;; generate) [[ -e $FAKE/np-bad ]] && { echo "Error in network definition: bad" >&2; exit 1; } ;; esac; exit 0',
         'systemctl': 'echo "systemctl $*" >>"$LOG"; [[ "$*" == "is-active -q systemd-networkd" ]] && { [[ -e $FAKE/networkd ]]; exit; }; exit 0',
         'ifup': 'echo "ifup $*" >>"$LOG"', 'ifdown': 'echo "ifdown $*" >>"$LOG"'}


def stub(d: Path, name: str, body: str):
    p = d / name
    p.write_text('#!/bin/bash\n' + body + '\n')
    p.chmod(0o755)


class Bash(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.d)
        self.bin, self.fake = self.d / 'bin', self.d / 'fake'
        self.bin.mkdir()
        self.fake.mkdir()
        for name, body in STUBS.items():
            stub(self.bin, name, body)
        for sub in ('netplan', 'network', 'interfaces.d', 'run', 'nm'):
            (self.fake / sub).mkdir()
        for iface in ('eth0', 'eth1', 'eth2'):
            (self.fake / f'link-{iface}').write_text(f'3: {iface}: <BROADCAST,UP> mtu 1500 state UP\n')
        (self.fake / 'addr-eth0').write_text('2: eth0    inet 10.0.0.2/24 brd 10.0.0.255 scope global eth0\n')
        self.env = {}

    def body(self):
        guards = ''.join(re.search(rf'^{n}\(\) \{{.*?^\}}$', steps_infra.BASH, re.M | re.S)[0] + '\n' for n in ('net_is_ssh_path', 'net_guard'))
        text = steps_network.BASH
        for a, b in (('/etc/netplan', '$FAKE/netplan'), ('/etc/systemd/network', '$FAKE/network'), ('/etc/network/interfaces.d', '$FAKE/interfaces.d'),
                     ('/etc/network/interfaces', '$FAKE/interfaces'), ('/etc/network/if-up.d', '$FAKE/if-up.d'), ('/etc/network/if-pre-up.d', '$FAKE/if-pre-up.d'),
                     ('/etc/storageforge/net', '$FAKE/sfnet'), ('/run/sf-undo', '$FAKE/run/sf-undo')):
            text = text.replace(a, b)
        return guards + text

    def run_bash(self, call, apply=True, timer=True):
        script = HARNESS + f'APPLY={int(apply)}\n' + (FW_STANDIN if timer else '') + self.body() + '\n' + call + '\nexit $((PROBLEMS > 0))\n'
        return subprocess.run(['bash', '-c', script], capture_output=True, text=True, timeout=60,
                              env={**os.environ, 'PATH': f'{self.bin}:{os.environ["PATH"]}', 'FAKE': str(self.fake), 'LOG': str(self.d / 'log'), **self.env})

    def log(self):
        return (self.d / 'log').read_text() if (self.d / 'log').exists() else ''

    def undo(self):
        """What the rollback timer runs when it fires: each journalled line, last first."""
        lines = (self.fake / 'journal').read_text().splitlines()
        for line in reversed(lines):
            subprocess.run(['bash', '-c', line], capture_output=True, text=True, timeout=30,
                           env={**os.environ, 'PATH': f'{self.bin}:{os.environ["PATH"]}', 'FAKE': str(self.fake), 'LOG': str(self.d / 'log')})
        (self.fake / 'journal').unlink()

    def netplan(self):
        (self.fake / 'netplan' / '50-cloud-init.yaml').write_text('network:\n  version: 2\n  ethernets:\n    eth0:\n      dhcp4: true\n')

    def nm(self, con='Wired connection 1'):
        (self.fake / 'nm-running').touch()
        for iface in ('eth0', 'eth1'):
            (self.fake / 'nm' / f'dev-{iface}').write_text(f'{con}\n')
        c = self.fake / 'nm' / f'con-{con}'
        c.mkdir()
        (c / 'ipv4.method').write_text('auto\n')
        (c / 'ipv6.method').write_text('auto\n')
        (c / 'ipv4.addresses').write_text('\n')
        (c / 'ipv6.addresses').write_text('\n')

    def networkd(self):
        (self.fake / 'networkd').touch()
        (self.fake / 'network' / '10-eth0.network').write_text('[Match]\nName=eth0\n[Network]\nDHCP=ipv4\n')

    def ifupdown(self, sourced=True):
        (self.fake / 'interfaces').write_text('auto lo\niface lo inet loopback\n' + (f'source {self.fake}/interfaces.d/*\n' if sourced else '') + 'auto eth0\niface eth0 inet dhcp\n')

    # ── which one ──
    def test_the_host_says_which_system_keeps_its_network(self):
        for setup, want in ((self.netplan, 'netplan'), (self.nm, 'nm'), (self.networkd, 'networkd'), (self.ifupdown, 'ifupdown'), (lambda: None, 'none')):
            with self.subTest(want):
                self.setUp()
                setup()
                self.assertEqual(self.run_bash('nw_backend').stdout.strip(), want)

    def test_with_nothing_to_keep_it_the_step_says_so(self):
        out = self.run_bash('t_net_address eth0 10.0.5.2/24 present ""')
        self.assertIn('nothing on this host keeps network settings across a reboot', out.stdout)
        self.assertNotIn('addr add', self.log())

    # ── netplan ──
    def test_netplan_address_report_apply_rerun_and_the_way_back(self):
        self.netplan()
        out = self.run_bash('t_net_address eth0 10.0.5.2/24 present ""', apply=False)
        self.assertIn('would: give eth0 10.0.5.2/24, with netplan', out.stdout)
        self.assertEqual(sorted(p.name for p in (self.fake / 'netplan').iterdir()), ['50-cloud-init.yaml'])
        out = self.run_bash('t_net_address eth0 10.0.5.2/24 present 10')
        self.assertEqual(out.returncode, 0, out.stdout)
        f = self.fake / 'netplan' / '90-storageforge-addr-eth0-10.0.5.2-24.yaml'
        self.assertEqual(yaml.safe_load(f.read_text()), {'network': {'version': 2, 'ethernets': {'eth0': {'addresses': ['10.0.5.2/24']}}}})
        self.assertEqual(stat.S_IMODE(f.stat().st_mode), 0o600, 'netplan warns about a file others can read')
        self.assertLess(self.log().index('netplan generate'), self.log().index('netplan apply'))
        self.assertIn('FW-ROLLBACK armed 10', out.stdout)
        out = self.run_bash('t_net_address eth0 10.0.5.2/24 present 10')
        self.assertIn('ok: eth0 has 10.0.5.2/24, and netplan keeps it', out.stdout)
        self.undo()
        self.assertFalse(f.exists(), 'the timer takes the file away again')

    def test_netplan_refusing_the_file_takes_it_out_again(self):
        self.netplan()
        (self.fake / 'np-bad').touch()
        out = self.run_bash('t_net_address eth0 10.0.5.2/24 present ""')
        self.assertIn('netplan generate refused it, so it is taken out again: Error in network definition: bad', out.stdout)
        self.assertEqual(sorted(p.name for p in (self.fake / 'netplan').iterdir()), ['50-cloud-init.yaml'])
        self.assertNotIn('netplan apply', self.log())

    def test_an_address_another_file_sets_is_left_to_a_person(self):
        self.netplan()
        (self.fake / 'netplan' / '60-static.yaml').write_text('network:\n  version: 2\n  ethernets:\n    eth1:\n      addresses: [10.0.9.9/24]\n')
        (self.fake / 'addr-eth1').write_text('3: eth1    inet 10.0.9.9/24 scope global eth1\n')
        out = self.run_bash('t_net_address eth1 10.0.9.9/24 absent ""')
        self.assertIn('10.0.9.9/24 on eth1 says so in', out.stdout)
        self.assertIn('60-static.yaml, which is not a file of StorageForge: change it there by hand', out.stdout)
        self.assertNotIn('addr del', self.log())

    def test_netplan_route_dhcp_and_bond(self):
        self.netplan()
        out = self.run_bash('t_net_route 0.0.0.0/0 10.0.0.1 eth0 100 present 5')
        self.assertEqual(out.returncode, 0, out.stdout)
        doc = yaml.safe_load((self.fake / 'netplan' / '90-storageforge-route-eth0-0.0.0.0-0-10.0.0.1.yaml').read_text())
        self.assertEqual(doc['network']['ethernets']['eth0']['routes'], [{'to': 'default', 'via': '10.0.0.1', 'metric': 100}])
        self.assertIn('ip -4 route replace 0.0.0.0/0 via 10.0.0.1 dev eth0 metric 100', self.log())
        out = self.run_bash('t_net_dhcp eth1 both on ""')
        doc = yaml.safe_load((self.fake / 'netplan' / '90-storageforge-dhcp-eth1.yaml').read_text())
        self.assertEqual(doc['network']['ethernets']['eth1'], {'dhcp4': True, 'dhcp6': True})
        out = self.run_bash('t_net_dhcp eth1 both on ""')
        self.assertIn('ok: netplan has DHCP on for both on eth1', out.stdout)
        out = self.run_bash('t_net_bond bond0 eth1,eth2 802.3ad 10.0.7.2/24 "" ""')
        self.assertEqual(out.returncode, 0, out.stdout)
        doc = yaml.safe_load((self.fake / 'netplan' / '90-storageforge-bond-bond0.yaml').read_text())['network']
        self.assertEqual(doc['bonds']['bond0'], {'interfaces': ['eth1', 'eth2'], 'parameters': {'mode': '802.3ad', 'mii-monitor-interval': 100}, 'addresses': ['10.0.7.2/24']})
        self.assertEqual(doc['ethernets']['eth2'], {'dhcp4': False, 'dhcp6': False})

    # ── NetworkManager ──
    def test_nm_address_goes_in_the_connection_and_the_way_back_takes_it_out(self):
        self.nm()
        out = self.run_bash('t_net_address eth0 10.0.5.2/24 present 10')
        self.assertEqual(out.returncode, 0, out.stdout)
        self.assertIn('nmcli connection modify Wired connection 1 +ipv4.addresses 10.0.5.2/24', self.log())
        self.assertIn('nmcli device reapply eth0', self.log())
        con = self.fake / 'nm' / 'con-Wired connection 1'
        self.assertEqual((con / 'ipv4.addresses').read_text().strip(), '10.0.5.2/24')
        out = self.run_bash('t_net_address eth0 10.0.5.2/24 present 10')
        self.assertIn('ok: eth0 has 10.0.5.2/24, and NetworkManager keeps it', out.stdout)
        self.undo()
        self.assertEqual((con / 'ipv4.addresses').read_text().strip(), '')

    def test_nm_dhcp_off_keeps_an_interface_with_addresses_manual(self):
        self.nm()
        con = self.fake / 'nm' / 'con-Wired connection 1'
        (con / 'ipv4.addresses').write_text('10.0.0.2/24\n')
        out = self.run_bash('t_net_dhcp eth1 ipv4 off ""')
        self.assertEqual(out.returncode, 0, out.stdout)
        self.assertEqual((con / 'ipv4.method').read_text().strip(), 'manual')
        self.assertEqual((con / 'ipv6.method').read_text().strip(), 'auto', 'only the family asked for')

    def test_nm_bond(self):
        self.nm()
        out = self.run_bash('t_net_bond bond0 eth1,eth2 active-backup "" 1 ""')
        self.assertEqual(out.returncode, 0, out.stdout)
        self.assertIn('nmcli connection add type bond ifname bond0 con-name sf-bond0 bond.options mode=active-backup,miimon=100 ipv4.method auto ipv6.method disabled', self.log())
        self.assertIn('nmcli connection add type bond-slave ifname eth2 master bond0 con-name sf-bond0-eth2', self.log())

    # ── systemd-networkd ──
    def test_networkd_drop_ins_beside_the_file_that_manages_it(self):
        self.networkd()
        out = self.run_bash('t_net_address eth0 10.0.5.2/24 present ""')
        self.assertEqual(out.returncode, 0, out.stdout)
        d = self.fake / 'network' / '10-eth0.network.d'
        self.assertEqual((d / 'sf-address-eth0-10.0.5.2-24.conf').read_text(), '[Network]\nAddress=10.0.5.2/24\n')
        self.assertIn('networkctl reconfigure eth0', self.log())
        out = self.run_bash('t_net_route 10.9.0.0/16 10.0.0.1 "" "" present ""')
        self.assertEqual((d / 'sf-route-eth0-10.9.0.0-16-10.0.0.1.conf').read_text(), '[Route]\nDestination=10.9.0.0/16\nGateway=10.0.0.1\n')
        out = self.run_bash('t_net_dhcp eth0 both on ""')
        self.assertEqual((d / 'sf-dhcp.conf').read_text(), '[Network]\nDHCP=yes\n')
        out = self.run_bash('t_net_dhcp eth0 both on ""')
        self.assertIn('ok: systemd-networkd has DHCP=yes on eth0', out.stdout)
        out = self.run_bash('t_net_address eth0 10.0.5.2/24 absent ""')
        self.assertFalse((d / 'sf-address-eth0-10.0.5.2-24.conf').exists())
        self.assertIn('ip addr del 10.0.5.2/24 dev eth0', self.log())

    def test_networkd_bond_and_its_way_back(self):
        self.networkd()
        out = self.run_bash('t_net_bond bond0 eth1,eth2 balance-alb "" 1 15')
        self.assertEqual(out.returncode, 0, out.stdout)
        n = self.fake / 'network'
        self.assertEqual((n / '05-sf-bond0.netdev').read_text(), '[NetDev]\nName=bond0\nKind=bond\n[Bond]\nMode=balance-alb\nMIIMonitorSec=100ms\n')
        self.assertEqual((n / '05-sf-bond0-eth1.network').read_text(), '[Match]\nName=eth1\n[Network]\nBond=bond0\n')
        self.undo()
        self.assertEqual(sorted(p.name for p in n.iterdir()), ['10-eth0.network'])

    # ── ifupdown ──
    def test_ifupdown_address_needs_interfaces_d_read(self):
        self.ifupdown(sourced=False)
        out = self.run_bash('t_net_address eth1 10.0.5.2/24 present ""')
        self.assertIn('does not read', out.stdout)
        self.ifupdown()
        out = self.run_bash('t_net_address eth1 10.0.5.2/24 present ""')
        self.assertEqual(out.returncode, 0, out.stdout)
        self.assertEqual((self.fake / 'interfaces.d' / 'sf-addr-eth1-10.0.5.2-24').read_text(), 'iface eth1 inet static\n    address 10.0.5.2/24\n')

    def test_ifupdown_routes_come_back_through_a_hook(self):
        self.ifupdown()
        out = self.run_bash('t_net_route 10.9.0.0/16 10.0.0.1 eth0 "" present ""')
        self.assertEqual(out.returncode, 0, out.stdout)
        self.assertEqual((self.fake / 'sfnet' / 'routes').read_text(), 'eth0 10.9.0.0/16 10.0.0.1\n')
        self.assertTrue(os.access(self.fake / 'if-up.d' / 'storageforge-routes', os.X_OK))
        out = self.run_bash('t_net_route 10.9.0.0/16 10.0.0.1 eth0 "" present ""')
        self.assertIn('ok: the route to 10.9.0.0/16 via 10.0.0.1 is there, and ifupdown keeps it', out.stdout)

    def test_ifupdown_dhcp_set_in_another_file_and_a_bond_without_ifenslave(self):
        self.ifupdown()
        out = self.run_bash('t_net_dhcp eth0 ipv4 off ""')
        self.assertIn('how eth0 gets its address says so in', out.stdout)
        out = self.run_bash('t_net_bond bond0 eth1,eth2 active-backup "" 1 ""')
        self.assertIn('ifenslave, which is not installed', out.stdout)

    # ── the path StorageForge comes in on ──
    def test_a_change_on_the_ssh_interface_needs_a_timer(self):
        self.networkd()
        self.env = {'SSH_CONNECTION': '10.0.0.9 50000 10.0.0.2 22'}
        out = self.run_bash('t_net_dhcp eth0 ipv4 off ""')
        self.assertIn('this session comes in through eth0: stage a rollback timer', out.stdout)
        self.assertFalse((self.fake / 'network' / '10-eth0.network.d').exists())
        out = self.run_bash('t_net_bond bond0 eth0,eth1 active-backup "" 1 ""')
        self.assertIn('this session comes in through eth0', out.stdout)
        out = self.run_bash('t_net_dhcp eth0 ipv4 off 10')
        self.assertEqual(out.returncode, 0, out.stdout)
        self.assertIn('FW-ROLLBACK armed 10', out.stdout)

    def test_a_route_that_covers_where_the_session_comes_from_needs_a_timer(self):
        self.networkd()
        self.env = {'SSH_CONNECTION': '192.168.7.20 50000 10.0.0.2 22'}
        out = self.run_bash('t_net_route 192.168.0.0/16 10.0.0.254 eth0 "" present ""')
        self.assertIn('this session comes from 192.168.7.20, inside 192.168.0.0/16: stage a rollback timer', out.stdout)
        out = self.run_bash('t_net_route 172.16.0.0/12 10.0.0.254 eth0 "" present ""')
        self.assertEqual(out.returncode, 0, out.stdout)
        out = self.run_bash('nw_covers 0.0.0.0/0 1.2.3.4 && echo in; nw_covers 10.0.0.0/8 11.0.0.1 || echo out; nw_covers 10.1.2.3/32 10.1.2.3 && echo in')
        self.assertEqual(out.stdout.split(), ['in', 'out', 'in'])

    def test_a_bridge_port_file_comes_before_the_one_netplan_writes(self):
        """networkd takes the first .network file in name order that matches: netplan writes 10-netplan-<port>.network, and a bridge port
        written as 10-sf-... came after it, so on a netplan host the port never joined the bridge."""
        self.networkd()
        fns = ''.join(re.search(rf'^{n}\(\) \{{.*?^\}}$', steps_infra.BASH, re.M | re.S)[0] + '\n' for n in ('net_manager', 't_net_bridge'))
        out = self.run_bash(fns.replace('/etc/systemd/network', '$FAKE/network') + 't_net_bridge br0 eth1 "" 5')
        self.assertEqual(out.returncode, 0, out.stdout)
        port = self.fake / 'network' / '05-sf-br0-eth1.network'
        self.assertEqual(port.read_text(), '[Match]\nName=eth1\n[Network]\nBridge=br0\n')
        self.assertLess('05-sf-br0-eth1.network', '10-netplan-eth1.network')
        self.assertIn('networkctl reconfigure eth1', self.log())
        self.undo()
        self.assertFalse(port.exists())

    def test_the_real_rollback_journal_undoes_a_bond(self):
        """storageforge-fwrules itself: the step journals with note, and revert (what the timer runs) puts the files back."""
        self.networkd()
        fw = self.d / 'fwrules'
        text = steps_infra.FWRULES.replace('export LC_ALL=C PATH=/usr/local/sbin', 'export LC_ALL=C PATH=$PATH:/usr/local/sbin')
        self.assertNotEqual(text, steps_infra.FWRULES, 'the stand-ins must come first: the real systemd-run must never be reached from a test')
        fw.write_text(text)
        fw.chmod(0o755)
        stub(self.bin, 'systemd-run', 'echo "systemd-run $*" >>"$LOG"')
        self.env = {'SF_FW_DIR': str(self.d / 'fwdir'), 'FW': str(fw)}
        arm = re.search(r'^fw_arm\(\) \{.*?\}$', steps_infra.BASH, re.M)[0]
        call = 'fw_tool() { :; }\n' + arm + '\nt_net_bond bond0 eth1,eth2 active-backup 10.0.7.2/24 "" 7'
        out = self.run_bash(call, timer=False)
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertIn('FW-ROLLBACK armed 7', out.stdout)
        self.assertIn('--on-active=7min', self.log())
        self.assertTrue((self.fake / 'network' / '05-sf-bond0.netdev').exists())
        r = subprocess.run([str(fw), 'revert'], capture_output=True, text=True, timeout=30,
                           env={**os.environ, 'PATH': f'{self.bin}:{os.environ["PATH"]}', 'FAKE': str(self.fake), 'LOG': str(self.d / 'log'), 'SF_FW_DIR': str(self.d / 'fwdir')})
        self.assertIn('FW-ROLLBACK reverted', r.stdout)
        self.assertEqual(sorted(p.name for p in (self.fake / 'network').iterdir()), ['10-eth0.network'])


class Checks(Db):
    """What the plan check says from the last scan of the network."""

    def setUp(self):
        super().setUp()
        self.add('nas', {'collected_at': '2026-11-20T00:00:00+00:00', 'lsblk': blk(('sda', 'S1', 'ext4', 'r'))}, [('/', 'ext4', '/dev/sda1', 3, 'rw')])
        self.conn.execute("UPDATE hosts SET ssh_host = '10.0.0.2' WHERE hostname = 'nas'")
        hid = self.conn.scalar("SELECT host_id FROM hosts WHERE hostname = 'nas'")
        net = {'interfaces': [{'name': 'eth0', 'kind': 'ethernet', 'addresses': [{'ip': '10.0.0.2', 'prefix': 24, 'scope': 'global'}], 'master': None},
                              {'name': 'eth1', 'kind': 'ethernet', 'addresses': [], 'master': None}, {'name': 'br0', 'kind': 'bridge', 'addresses': [], 'master': None}],
               'routes': [{'dst': 'default', 'via': '10.0.0.1', 'dev': 'eth0', 'metric': None, 'family': 4}],
               'config': {'manager': 'netplan', 'interfaces': {'eth0': {'source': '/etc/netplan/50-cloud-init.yaml', 'dhcp4': True, 'addresses': []}}}}
        self.conn.execute('INSERT INTO host_network (host_id, data_json, scan_id, updated_at) VALUES (:h, :d, NULL, 1)', {'h': hid, 'd': json.dumps(net)})

    def said(self, kind, **params):
        spec = changes.TYPES[kind]
        p = {f['name']: (False if f['kind'] == 'bool' else f.get('default', '')) for f in spec['fields']}
        p.update(params)
        r = changes.check(self.conn, changes.normalize({'name': 'p', 'tasks': [{'type': kind, 'host': 'nas', 'params': p}]}))
        return [(i['level'], i['text']) for i in r['tasks'][0]['items']]

    def test_a_bond_over_the_ssh_interface_needs_a_timer(self):
        got = self.said('net-bond', name='bond0', ports='eth0,eth1', address='10.0.0.2/24')
        self.assertIn(('crit', 'eth0 carries the address StorageForge reaches this host on: stage a rollback timer'), got)
        got = self.said('net-bond', name='bond0', ports='eth0,eth1', address='10.0.7.2/24', rollback='10')
        self.assertFalse([t for lv, t in got if lv == 'crit'], got)
        self.assertIn(('crit', 'br0 exists and is not a bond'), self.said('net-bond', name='br0', ports='eth1'))
        self.assertIn(('crit', 'eth9 is not an interface on nas at the last scan'), self.said('net-bond', name='bond0', ports='eth9'))

    def test_addresses(self):
        self.assertIn(('ok', 'eth1 does not have 10.0.5.2/24: nothing to do'), self.said('net-address', iface='eth1', address='10.0.5.2/24', state='absent'))
        self.assertIn(('crit', 'StorageForge reaches nas on 10.0.0.2: stage a rollback timer'), self.said('net-address', iface='eth0', address='10.0.0.2/24', state='absent'))
        self.assertIn(('crit', '10.0.5.2 is not an address with its prefix, such as 10.0.5.2/24'), self.said('net-address', iface='eth1', address='10.0.5.2'))
        got = self.said('net-address', iface='eth0', address='10.0.5.2/24')
        self.assertIn(('note', 'eth0 is set up in /etc/netplan/50-cloud-init.yaml (netplan); the step writes a file of its own beside it'), got)

    def test_routes(self):
        self.assertIn(('ok', 'the route to 0.0.0.0/0 via 10.0.0.1 is there already: the script checks it is kept across a reboot'), self.said('net-route', dst='0.0.0.0/0', via='10.0.0.1'))
        self.assertIn(('crit', 'the network and the gateway are not of the same IP version'), self.said('net-route', dst='fd00::/8', via='10.0.0.1'))
        self.assertIn(('crit', '10.0.0.1/24 is not a gateway address'), self.said('net-route', dst='10.9.0.0/16', via='10.0.0.1/24'))

    def test_dhcp(self):
        got = self.said('net-dhcp', iface='eth0', state='off')
        self.assertIn(('crit', 'eth0 carries the address StorageForge reaches this host on: stage a rollback timer'), got)
        self.assertIn(('warn', 'eth1 has no other address at the last scan: with DHCP off it has none'), self.said('net-dhcp', iface='eth1', state='off'))

    def test_what_if_draws_the_bond_and_blocks_one_over_the_ssh_interface(self):
        from storageforge_index import whatif
        got = whatif.run(self.conn, {'tasks': [{'type': 'net-bond', 'host': 'nas', 'params': {'name': 'bond0', 'ports': 'eth0,eth1', 'address': '10.0.7.2/24'}}]})
        self.assertTrue(got['blocked'], got['conflicts'])
        self.assertIn('nic:nas:bond0', [n['id'] for n in got['ghost']['add']])
        got = whatif.run(self.conn, {'tasks': [{'type': 'net-bond', 'host': 'nas', 'params': {'name': 'bond0', 'ports': 'eth0,eth1', 'address': '10.0.7.2/24', 'rollback': '5'}}]})
        self.assertFalse(got['blocked'], got['conflicts'])
        got = whatif.run(self.conn, {'tasks': [{'type': 'net-dhcp', 'host': 'nas', 'params': {'iface': 'eth1', 'state': 'on'}},
                                               {'type': 'net-address', 'host': 'nas', 'params': {'iface': 'eth1', 'address': '10.0.5.2/24'}}]})
        self.assertFalse(got['blocked'], got['conflicts'])
        self.assertIn('adds 10.0.5.2/24', [c['what'] for c in got['ghost']['changed']])

    def test_a_script_of_every_kind_passes_bash_and_shellcheck(self):
        plan = {'name': 'p', 'tasks': [{'type': 'net-bond', 'host': 'nas', 'params': {'name': 'bond0', 'ports': 'eth1', 'rollback': '5'}},
                                       {'type': 'net-address', 'host': 'nas', 'params': {'iface': 'eth1', 'address': '10.0.5.2/24'}},
                                       {'type': 'net-route', 'host': 'nas', 'params': {'dst': '10.9.0.0/16', 'via': '10.0.0.1', 'metric': '50'}},
                                       {'type': 'net-dhcp', 'host': 'nas', 'params': {'iface': 'eth1', 'family': 'both'}}]}
        script = changes.script(self.conn, plan)
        self.assertEqual(subprocess.run(['bash', '-n'], input=script, capture_output=True, text=True).returncode, 0)
        sc = shutil.which('shellcheck') or shutil.which('shellcheck', path=str(Path(os.sys.executable).parent))
        if sc:
            r = subprocess.run([sc, '--severity=error', '-s', 'bash', '-'], input=script, capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stdout)
        cmd = yaml.load(changes.ansible(self.conn, plan), Loader=_Loader)[0]['tasks'][1]['ansible.builtin.shell']['cmd']
        self.assertIn('t_net_address eth1 10.0.5.2/24 present', cmd)
        self.assertEqual(subprocess.run(['bash', '-n'], input=cmd, capture_output=True, text=True).returncode, 0)


class AnsibleTask(unittest.TestCase):
    """The one builder of the Ansible task that runs a step's Bash function (changes.shell_task, words_of, bash_fn)."""

    def test_words_of_turns_parameters_into_the_words_of_the_bash_function(self):
        p = {'on': True, 'off': False, 'zero': '0', 'spaced': 'a b', 'empty': ''}
        self.assertEqual(changes.words_of(p, ('on', 'off', 'zero', 'spaced', 'empty', 'not_saved')), ['1', '', '0', 'a b', '', ''])

    def test_bash_fn_cuts_whole_functions_and_refuses_a_missing_one(self):
        text = 'one() { echo 1; }\ntwo() {\n  echo 2\n}\nthree() { echo 3; }\n'
        self.assertEqual(changes.bash_fn(text, 'one', 'two'), 'one() { echo 1; }\ntwo() {\n  echo 2\n}\n')
        with self.assertRaises(ValueError):
            changes.bash_fn(text, 'four')

    def test_shell_task_registers_the_output_and_counts_the_changed_word(self):
        self.assertEqual(changes.shell_task('n', 'true', changed='installed'),
                         {'name': 'n', 'ansible.builtin.shell': {'cmd': 'true', 'executable': '/bin/bash'}, 'register': 'sf_out',
                          'changed_when': "'installed' in sf_out.stdout"})

    def test_steps_built_on_ansible_head_start_with_the_head_they_had(self):
        # the text each of these modules wrote out by hand before changes.ansible_head; their exports must still begin with it
        head = ('APPLY=1; ok() { echo "ok: $*"; }; missing() { echo "missing: $*"; }; conflict() { echo "conflict: $*" >&2; exit 1; }; info() { :; }\n')
        act, try_ = 'act() { echo "changed: $*"; }; ', 'try() { "$@" || { conflict "failed: $*"; return 1; }; }; '
        self.assertEqual(changes.ansible_head(), head)
        for kind, second in (
                ('tailscale', act + try_[:-2] + '\n'),
                ('vm-mac', act + try_ + 'later() { conflict "$*"; }\n'),
                ('secret-file', act + try_ + 'durable() { sync; }\n'),
                ('dux-install', 'doing() { :; }; ' + act + try_ + 'later() { conflict "$*"; }\n'),
                ('os-install', 'doing() { :; }; ' + act + try_ + 'later() { conflict "$*"; }\n'),
                ('rclone-mount', act + 'durable() { sync; }; reload_systemd() { systemctl daemon-reload; }\n'),
                ('netconsole', act + 'durable() { sync; }\n'),
                ('runtime-install', 'doing() { echo "changed: $*"; }; ' + act + try_ + 'durable() { sync; }\n')):
            params = {f['name']: '' for f in changes.TYPES[kind]['fields']}
            params.update({'target': '10.0.0.9', 'runtime': 'docker', 'path': '/srv/x', 'name': 'x', 'remote': 'r:', 'os': 'debian-12'})
            cmd = changes._ansible_task({'id': 't1', 'type': kind, 'host': 'nas', 'params': params}, None)['ansible.builtin.shell']['cmd']
            self.assertTrue(cmd.startswith(head + second), kind)

    def test_an_exported_network_step_carries_its_helpers_once(self):
        # net-bridge is built from steps_infra, net-address from steps_network: both cut their helpers out of steps_infra.BASH
        for kind, params, fn, helpers in (
                ('net-bridge', {'name': 'br0', 'ports': 'eth1', 'address': '', 'rollback': ''}, 't_net_bridge', {'net_manager', 'net_is_ssh_path', 'net_guard', 'fw_arm', 'fw_tool'}),
                ('net-address', {'iface': 'eth1', 'address': '10.0.5.2/24', 'state': 'present', 'rollback': ''}, 't_net_address', {'net_is_ssh_path', 'net_guard', 'fw_arm', 'fw_tool'})):
            cmd = changes._ansible_task({'id': 't1', 'type': kind, 'host': 'nas', 'params': params}, None)['ansible.builtin.shell']['cmd']
            defined = re.findall(r'(?:^|[;{] *)(\w+)\(\) \{', cmd, re.M)
            self.assertEqual(defined.count('net_guard'), 1, kind)
            self.assertIn(fn, defined, kind)
            if kind == 'net-bridge':    # steps_infra cuts out the one function it runs (steps_network carries its own whole BASH)
                self.assertEqual([d for d in defined if d.startswith('t_')], [fn])
            self.assertLessEqual(helpers, set(defined), kind)
            self.assertEqual(subprocess.run(['bash', '-n'], input=cmd, capture_output=True, text=True).returncode, 0, kind)


class _Loader(yaml.SafeLoader):
    pass


_Loader.add_constructor('!unsafe', lambda loader, node: loader.construct_scalar(node))


if __name__ == '__main__':
    unittest.main()
