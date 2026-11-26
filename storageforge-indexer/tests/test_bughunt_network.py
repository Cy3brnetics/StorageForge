"""Regression tests for the network-module bug hunt: each one failed before its fix."""
import sqlite3
import time
import unittest
from unittest import mock
from xml.etree import ElementTree

from storageforge_index import exposure, mapdesign, netconsole, netdevice, pfsense, qrsvg, reach, rostranspiler

NET = {'interfaces': [{'name': 'eth0', 'kind': 'ethernet', 'state': 'up', 'addresses': [{'ip': '192.168.1.10', 'prefix': 24}]}], 'listeners': []}


def _fw(rules, policy='drop'):
    base = {'backend': 'nft', 'table': 'inet f', 'chain': 'input', 'action': None, 'proto': None, 'dports': [], 'saddr': None, 'daddr': None,
            'iif': None, 'oif': None, 'not_iif': None, 'not_oif': None, 'ct': None, 'comment': None, 'unmodelled': []}
    return {'readable': True, 'backends': ['nft'], 'policies': {'input': policy},
            'chains': [{'backend': 'nft', 'table': 'inet f', 'name': 'input', 'hook': 'input', 'prio': 0, 'policy': policy, 'family': 'inet'}],
            'rules': [{**base, 'order': i, **r} for i, r in enumerate(rules, 1)], 'nat': [], 'zones': [], 'notes': []}


class Exposure(unittest.TestCase):
    def test_an_accept_for_everyone_but_some_sources_is_doubt_not_blocked(self):
        fw = _fw([{'action': 'accept', 'proto': 'tcp', 'dports': [8000], 'not_saddr': '10.9.9.9'}])
        item = exposure.listener_item({'proto': 'tcp', 'addr': '0.0.0.0', 'port': 8000, 'scope': 'any'}, NET, fw)
        self.assertEqual(item['level'], 'unknown')

    def test_a_dual_stack_wildcard_is_judged_on_ipv6_as_well(self):
        fw = _fw([{'action': 'accept', 'proto': 'tcp', 'dports': [8000], 'family': 'ip6'}])
        item = exposure.listener_item({'proto': 'tcp', 'addr': '*', 'port': 8000, 'scope': 'any'}, NET, fw)
        self.assertNotEqual(item['level'], 'blocked')

    def test_a_tcp_udp_forward_is_one_forward_for_each_protocol(self):
        fw = {**_fw([], 'accept'), 'chains': [], 'nat': [{'action': 'dnat', 'to_addr': '192.168.1.5', 'to_port': 80, 'proto': 'tcp,udp', 'dports': [8080], 'iif': None}]}
        got = exposure.forwards_of('gw', fw, [], NET)
        self.assertEqual(sorted(f['proto'] for f in got), ['tcp', 'udp'])


class PfSense(unittest.TestCase):
    def test_a_tcp_udp_port_forward_is_the_pair(self):
        root = ElementTree.fromstring('<pfsense><nat><rule><protocol>TCP/UDP</protocol><interface>wan</interface><target>192.168.1.5</target><local-port>80</local-port>'
                                      '<destination><port>8080</port></destination></rule></nat></pfsense>')
        out = pfsense.firewall(root, {'wan': {'if': 'em0'}})
        self.assertEqual(out['nat'][0]['proto'], 'tcp,udp')


class Reach(unittest.TestCase):
    def test_a_destination_with_no_addresses_read_is_unknown(self):
        fleet = reach.Fleet({'a': {'net': NET, 'infra': None, 'containers': []}, 'b': {'net': {'interfaces': []}, 'infra': None, 'containers': []}})
        got = reach.query(fleet, 'a', 'b', 22)
        self.assertEqual(got['verdict'], 'unknown')


class MapDesign(unittest.TestCase):
    def test_a_designed_port_range_is_recognised(self):
        rule = {'action': 'allow', 'proto': 'tcp', 'port': '8000-8100', 'source': '10.0.0.0/8'}
        scanned = [{'action': 'accept', 'proto': 'tcp', 'dports': [[8000, 8100]], 'saddr': '10.0.0.0/8'}]
        self.assertTrue(mapdesign._rule_there(scanned, rule))
        self.assertFalse(mapdesign._rule_there([{**scanned[0], 'dports': [[8000, 8050]]}], rule))
        self.assertTrue(mapdesign._rule_there([{**scanned[0], 'dports': [22]}], {**rule, 'port': '22'}))


class NetConsole(unittest.TestCase):
    def test_a_database_error_does_not_end_the_receiver(self):
        class Db:
            def connect(self):
                raise sqlite3.OperationalError('database is locked')
        r = netconsole.Receiver(Db())
        with mock.patch.object(netconsole.errlog, 'trace'):
            got = r.take(b'<6>hello', ('10.0.0.1', 514), time.time())
        self.assertEqual(got, 'unknown')


class QrSvg(unittest.TestCase):
    def test_a_peer_sized_text_gets_a_whole_code_and_a_huge_one_gets_none(self):
        text = 'x' * 286
        ver, _ = qrsvg._encode_codewords(text.encode())
        self.assertGreaterEqual(ver, 11)
        self.assertTrue(qrsvg.svg(text).startswith('<svg'))
        self.assertEqual(qrsvg.svg('x' * 600), '')


class Cisco(unittest.TestCase):
    def test_one_accept_does_not_deny_everything_else(self):
        stmts = rostranspiler.parse('/ip firewall filter add chain=input in-interface=Gi0/1 protocol=tcp dst-port=22 action=accept')
        out = rostranspiler.emit(stmts, 'cisco')
        self.assertIn(' permit ip any any', out['text'].splitlines())
        self.assertTrue(any('access-group' in n for n in out['notes']))


class OpenWrtRefusal(unittest.TestCase):
    def test_a_refused_apply_drops_what_uci_staged(self):
        calls = []

        def run(cmd, timeout=None):
            calls.append(cmd)
            return 'uci: Parse error'
        with self.assertRaises(netdevice.DeviceError):
            netdevice.OpenWrtApply(7).apply(run, {'text': 'uci set firewall.x=rule\nuci commit firewall\nuci commit network'})
        self.assertIn('uci revert firewall', calls)
        self.assertIn('uci revert network', calls)


class LateConfirm(unittest.TestCase):
    def test_a_confirm_after_the_timer_is_refused(self):
        change = {'status': 'unconfirmed', 'rollback_at': int(time.time()) - 5, 'device': 'gw'}
        with mock.patch.object(netdevice, 'change', return_value=change), mock.patch.object(netdevice, '_set') as put, \
                mock.patch.object(netdevice, 'session') as session:
            with self.assertRaisesRegex(netdevice.DeviceError, 'timer'):
                netdevice.confirm(None, None, 1)
        session.assert_not_called()
        self.assertEqual(put.call_args.kwargs['status'], 'rolling-back')


class CutsOff(unittest.TestCase):
    def test_new_rules_land_in_the_chain_the_device_really_walks(self):
        fw = {'readable': True, 'backends': ['cisco_acl'], 'policies': {'input': 'accept'}, 'rules': [], 'nat': [], 'zones': [], 'notes': [],
              'chains': [{'backend': 'cisco_acl', 'table': 'acl', 'name': 'input', 'hook': 'input', 'prio': 0, 'policy': 'accept', 'family': 'ip'}]}
        net = {'interfaces': [{'name': 'Gi0/1', 'kind': 'ethernet', 'state': 'up', 'addresses': [{'ip': '10.0.0.2', 'prefix': 24}]}]}
        d = {'name': 'sw', 'address': '10.0.0.2', 'port': 22, 'platform': 'cisco'}
        stmts = rostranspiler.parse('/ip firewall filter add chain=input protocol=tcp dst-port=22 action=drop')
        from storageforge_index import inframeasure, netfacts
        with mock.patch.object(inframeasure, 'reading', return_value={'firewall': fw}), mock.patch.object(netfacts, 'reading', return_value=net), \
                mock.patch.object(netdevice, '_controller_ips', return_value=['10.0.0.9']):
            got = netdevice.cuts_off(None, d, stmts)
        self.assertTrue(got['cuts'])


if __name__ == '__main__':
    unittest.main()
