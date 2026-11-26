"""Fixes from the second bug hunt over the network modules: each test failed before its fix."""
import os
import shutil
import subprocess
import tempfile
import threading
import unittest
from unittest import mock

import dbfactory
from test_network_steps import Bash as StepsBash
from test_sfnetwork import Kept
from storageforge_index import confread, inframeasure, netconsole, netdevice, netscan, rostranspiler, sfnet, sfnetwork, tunnels, traffic


class Redaction(unittest.TestCase):
    """The value of a credential line is blanked and the line stays, in the three places that share the rule."""
    TEXT = 'tunnel: abc\ntoken: SECRETVALUE\ningress:\n  - hostname: photos.example.com\nauth.token = "SECRETVALUE"\n'

    def test_tunnels_keep_the_name_and_blank_the_value(self):
        out = tunnels.scrub(self.TEXT)
        self.assertNotIn('SECRET', out)
        self.assertIn('token: "***"', out)
        self.assertIn('auth.token = "***"', out)
        self.assertIn('  - hostname: photos.example.com', out)

    def test_the_host_awk_and_the_server_agree(self):
        got = subprocess.run(['awk', '-v', f're={tunnels.SECRET_LINE}', tunnels.TUNNEL_AWK], input=self.TEXT, capture_output=True, text=True).stdout
        self.assertEqual(got.splitlines(), tunnels.scrub(self.TEXT).splitlines())
        self.assertNotIn("'", tunnels.TUNNEL_AWK)

    def test_the_masked_file_still_parses_as_toml_and_yaml(self):
        got = tunnels.frp('serverAddr = "frp.example.net"\nauth.token = "SECRET"\n[[proxies]]\nname = "web"\ntype = "http"\nlocalPort = 80\ncustomDomains = ["a.example.net"]\n')
        self.assertEqual([p['public'] for p in got['published']], ['http://a.example.net'])
        got = tunnels.cloudflared('tunnel: x\ntoken: SECRET\ningress:\n  - hostname: a.example.com\n    service: http://localhost:80\n  - service: http_status:404\n')
        self.assertEqual([p['public'] for p in got['published']], ['https://a.example.com'])

    def test_the_collector_script_uses_the_awk(self):
        self.assertNotIn('@TUNNEL_AWK@', inframeasure.BODY)
        self.assertNotIn('@SECRET_LINE@', inframeasure.BODY)
        self.assertIn('awk -v re=', inframeasure.BODY)

    def test_the_wider_rule_keeps_the_name_and_still_drops_the_block(self):
        text = 'a: 1\nsigning_key: |\n  LS0tSECRET\n  moreSECRET\nb: 2\n'
        out = confread.scrub(text)
        self.assertEqual(out.splitlines(), ['a: 1', 'signing_key: "***"', 'b: 2'])
        awk = subprocess.run(['awk', '-v', f're={confread.SECRET_LINE}', confread.SCRUB_AWK], input=text, capture_output=True, text=True).stdout
        self.assertEqual(awk.splitlines(), out.splitlines())
        self.assertEqual(confread.scrub(out), out, 'doing it again changes nothing')


class FrpDomains(unittest.TestCase):
    def test_a_domain_list_that_is_not_a_list_does_not_raise(self):
        text = 'serverAddr = "s"\n[[proxies]]\nname = "w"\ntype = "http"\nlocalPort = 80\ncustomDomains = 5\n'
        self.assertEqual(tunnels.frp(text)['published'], [])

    def test_one_unreadable_tunnel_does_not_end_the_reading(self):
        with mock.patch.dict(tunnels.READERS, {'frp': mock.Mock(side_effect=TypeError('x'))}):
            got = inframeasure.parse_tunnels({'frp': ['a = 1']})
        self.assertEqual(got[0]['error'], 'could not be read')


class Netscan(unittest.TestCase):
    def test_the_module_has_os_for_the_check_after_a_scan(self):
        self.assertTrue(hasattr(netscan, 'os'))

    def test_a_connection_that_cannot_be_opened_still_frees_the_scanner(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        db = dbfactory.make(self, f'{tmp}/t.db')
        conn = db.connect()
        self.addCleanup(conn.close)
        db.migrate(conn)
        netscan.save_settings(conn, {'enabled': True, 'ranges': ['10.9.0.0/24']}, 'test')
        real = db.connect
        calls = []

        def flaky():
            calls.append(1)
            if len(calls) > 0 and threading.current_thread() is not threading.main_thread():
                raise OSError('database is locked')
            return real()
        with mock.patch.object(db, 'connect', flaky), mock.patch('storageforge_index.errlog.trace'):
            netscan.run(db, conn, None, 'test', wait=True, runner=lambda argv: '<nmaprun></nmaprun>')
        self.assertTrue(netscan._running.acquire(blocking=False), 'the lock was left held')
        netscan._running.release()


class Devices(unittest.TestCase):
    def test_removing_a_device_removes_its_traffic(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        db = dbfactory.make(self, f'{tmp}/t.db')
        conn = db.connect()
        self.addCleanup(conn.close)
        db.migrate(conn)
        netdevice.add(conn, {'name': 'gw', 'platform': 'routeros', 'address': '10.0.0.1', 'credential': None}, 'a')
        traffic.set_enabled(conn, True, 'a')
        traffic.record(conn, 'gw', [{'iface': 'e', 'rx_bytes': 1, 'tx_bytes': 1, 'rx_drop': 0, 'tx_drop': 0, 'rx_error': 0, 'tx_error': 0}], 100)
        netdevice.remove(conn, 'gw')
        self.assertEqual(conn.scalar("SELECT count(*) FROM traffic_samples WHERE host = 'gw'"), 0)


class Netconsole(unittest.TestCase):
    def test_lines_are_kept_when_a_flush_fails(self):
        db = mock.Mock()
        db.connect.side_effect = OSError('locked')
        r = netconsole.Receiver(db)
        r.pending = {'a': ['x', 'y']}
        r.counted = {'a': [2, 1]}
        with self.assertRaises(OSError):
            r.flush(10.0)
        self.assertEqual((r.pending, r.counted), ({'a': ['x', 'y']}, {'a': [2, 1]}))

    def test_one_host_failing_does_not_drop_the_others(self):
        db = mock.Mock()
        r = netconsole.Receiver(db)
        r.pending = {'a': ['x'], 'b': ['y']}

        def store(conn, host, *a, **k):
            if host == 'a':
                raise OSError('locked')
            return 1
        with mock.patch.object(netconsole.hostlogs, 'store', store):
            with self.assertRaises(OSError):
                r.flush(10.0)
        self.assertEqual(r.pending, {'a': ['x']}, 'b was stored, a is kept for the next flush')


class Rejoin(Kept):
    def test_a_host_that_rejoins_before_its_old_interface_is_gone_gets_it_made_again(self):
        self.up()
        self.read('ctl', 1, {2: ['10.203.0.2/32'], 3: ['10.203.0.3/32']})
        self.read('nas', 2, {1: ['10.203.0.1/32'], 3: ['10.203.0.3/32']})
        self.read('pi', 3, {1: ['10.203.0.1/32'], 2: ['10.203.0.2/32']})
        sfnetwork.leave(self.conn, 'pi', 'gabe')
        sfnetwork.join(self.conn, 'pi', 'gabe')
        mine = [(t['type'], t['params'].get('state')) for t in sfnetwork.tasks(self.conn) if t['host'] == 'pi' and t['type'] == 'wg-interface']
        self.assertEqual(mine, [('wg-interface', 'absent'), ('wg-interface', 'present')])

    def test_observe_does_not_save_over_a_change_made_after_it_read(self):
        self.up()
        sfnetwork.leave(self.conn, 'pi', 'gabe')
        sfnetwork.join(self.conn, 'pi', 'gabe')            # pending again
        self.read('pi', 9)                                 # a new key: observe takes it
        real = sfnetwork.seen

        def seen_then_a_leave(conn, network):
            got = real(conn, network)
            sfnetwork.leave(conn, 'nas', 'gabe')            # committed between the first read and the save
            return got
        with mock.patch.object(sfnetwork, 'seen', seen_then_a_leave):
            self.assertEqual(sfnetwork.observe(self.conn), ['pi'])
        states = {m['host']: m['state'] for m in sfnetwork.load(self.conn)['members']}
        self.assertEqual(states['pi'], 'active')
        self.assertEqual(states['nas'], 'revoked', 'the leave is still there')


class Rules(unittest.TestCase):
    def test_firewalld_lists_what_a_rich_rule_cannot_say(self):
        for text in ('/ip firewall filter add chain=input action=accept in-interface=eth1 protocol=tcp dst-port=22',
                     '/ip firewall filter add chain=input action=accept dst-address-list=x protocol=tcp dst-port=22',
                     '/ip firewall filter add chain=input action=accept protocol=tcp src-port=1000 dst-port=22',
                     '/ip firewall filter add chain=input action=accept protocol=tcp dst-port=22,80'):
            got = rostranspiler.emit(rostranspiler.parse(text), 'firewalld')
            self.assertTrue(got['unsupported'], text)
            self.assertNotIn('add-rich-rule', got['text'])

    def test_openwrt_names_with_a_slash_do_not_break_the_sed(self):
        got = rostranspiler.emit(rostranspiler.parse('/ip firewall address-list add list=lan/guests address=10.0.0.0/24\n/interface bridge port add bridge=br/x interface=eth1'), 'openwrt')['text']
        self.assertNotIn("name='lan/guests'$/", got)
        self.assertIn("s#^firewall", got)
        out = subprocess.run(['bash', '-c', 'printf "firewall.cfg1.name=\'lan/guests\'\\n" | sed -n "s#^firewall\\.\\(.*\\)\\.name=\'lan/guests\'\\$#\\1#p"'], capture_output=True, text=True)
        self.assertEqual(out.stdout.strip(), 'cfg1')
        self.assertIn('\\$#', got)


class OpenWrtZones(unittest.TestCase):
    FACTS = {'identity': 'ap', 'zones': [{'name': 'lan', 'networks': ['lan']}, {'name': 'wan', 'networks': ['wan', 'wan6']}],
             'config': "network.lan=interface\nnetwork.lan.device='br-lan'\nnetwork.wan=interface\nnetwork.wan.device='eth0.2'\nnetwork.guest=interface\nnetwork.guest.device='br-lan'\n"
                       "network.@device[0]=device\nnetwork.@device[0].name='br-lan'\nnetwork.@device[0].ports='eth1' 'eth2'\n"}

    def stmts(self, text):
        return rostranspiler.parse(text)

    def test_a_device_name_becomes_the_zone_of_its_network(self):
        facts = {**self.FACTS, 'config': self.FACTS['config'].replace("network.guest=interface\nnetwork.guest.device='br-lan'\n", '')}
        got = netdevice._openwrt_zones(facts, self.stmts('/ip firewall filter add chain=forward in-interface=eth1 out-interface=eth0.2 action=accept'))
        self.assertEqual(got, {'eth1': 'lan', 'eth0.2': 'wan'})

    def test_a_network_name_is_still_accepted(self):
        got = netdevice._openwrt_zones(self.FACTS, self.stmts('/ip firewall filter add chain=input in-interface=wan action=drop'))
        self.assertEqual(got, {'wan': 'wan'})

    def test_a_name_that_carries_two_networks_or_none_is_refused(self):
        with self.assertRaisesRegex(netdevice.DeviceError, 'carries guest, lan'):
            netdevice._openwrt_zones(self.FACTS, self.stmts('/ip firewall filter add chain=input in-interface=br-lan action=drop'))
        with self.assertRaisesRegex(netdevice.DeviceError, 'carries none'):
            netdevice._openwrt_zones(self.FACTS, self.stmts('/ip firewall filter add chain=input in-interface=eth9 action=drop'))

    def test_a_network_in_no_zone_is_refused(self):
        with self.assertRaisesRegex(netdevice.DeviceError, 'in no firewall zone'):
            netdevice._openwrt_zones(self.FACTS, self.stmts('/ip firewall filter add chain=input in-interface=guest action=drop'))


class Mirror(unittest.TestCase):
    def test_the_roaming_script_verifies_the_text_that_was_signed(self):
        script = sfnet.mirror_pull_script(['https://sf.example.com/api/sfnet/directory'], ['ssh-ed25519 AAAA'])
        self.assertIn('resp.get("directory_json")', script)
        self.assertNotIn('resp.get("payload")', script)
        self.assertIn('then exit 0; fi', script, 'a mirror that fails leaves the next one to be tried')
        self.assertEqual(subprocess.run(['bash', '-n'], input=script, capture_output=True, text=True).returncode, 0)


class Route(StepsBash):
    """net-route decides ownership by destination and gateway, not by any file that mentions the gateway."""

    def test_a_default_route_through_the_gateway_does_not_own_a_route_to_another_network(self):
        self.netplan()
        (self.fake / 'netplan' / '50-cloud-init.yaml').write_text('network:\n  version: 2\n  ethernets:\n    eth0:\n      routes:\n        - to: default\n          via: 10.0.0.1\n')
        out = self.run_bash('t_net_route 10.9.0.0/16 10.0.0.1 eth0 "" present ""')
        self.assertEqual(out.returncode, 0, out.stdout)
        self.assertTrue((self.fake / 'netplan' / '90-storageforge-route-eth0-10.9.0.0-16-10.0.0.1.yaml').exists(), 'persisted by a file of our own')

    def test_the_same_route_in_another_file_is_still_left_to_that_file(self):
        self.netplan()
        (self.fake / 'netplan' / '50-cloud-init.yaml').write_text('network:\n  version: 2\n  ethernets:\n    eth0:\n      routes:\n        - to: 10.9.0.0/16\n          via: 10.0.0.1\n')
        out = self.run_bash('t_net_route 10.9.0.0/16 10.0.0.1 eth0 "" present ""')
        self.assertFalse((self.fake / 'netplan' / '90-storageforge-route-eth0-10.9.0.0-16-10.0.0.1.yaml').exists())
        self.assertIn('ok: route to', out.stdout)

    def test_networkd_the_same_way(self):
        self.networkd()
        (self.fake / 'network' / '10-eth0.network').write_text('[Match]\nName=eth0\n[Route]\nGateway=10.0.0.1\n')
        out = self.run_bash('t_net_route 10.9.0.0/16 10.0.0.1 eth0 "" present ""')
        self.assertTrue((self.fake / 'network' / '10-eth0.network.d' / 'sf-route-eth0-10.9.0.0-16-10.0.0.1.conf').exists(), out.stdout)
        self.setUp()
        self.networkd()
        (self.fake / 'network' / '10-eth0.network').write_text('[Match]\nName=eth0\n[Route]\nDestination=10.9.0.0/16\nGateway=10.0.0.1\n')
        out = self.run_bash('t_net_route 10.9.0.0/16 10.0.0.1 eth0 "" present ""')
        self.assertFalse((self.fake / 'network' / '10-eth0.network.d').exists())


# The step tests of the module this one borrows from are its own: they run there.
for _name in [n for n in dir(StepsBash) if n.startswith('test')]:
    if _name not in Route.__dict__:
        setattr(Route, _name, None)
for _name in [n for n in dir(Kept) if n.startswith('test')]:
    if _name not in Rejoin.__dict__:
        setattr(Rejoin, _name, None)


if __name__ == '__main__':
    unittest.main()
