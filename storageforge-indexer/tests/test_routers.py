"""Routers, switches and firewalls: real output of RouterOS 7.25 and OpenWrt 25.12, captured from the lab's VMs in tests/fixtures, and written-to-format samples for pfSense and IOS, which the lab has no free image of."""
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from storageforge_index import changes, cisco, deploy, exposure, netdevice, netscan, openwrt, permissions, pfsense, reach, routeros, rostranspiler as ros, security, traffic, vault
from storageforge_index.db import Database
from storageforge_index.nettransport import DirectTransport
from test_security import Base

FIX = Path(__file__).parent / 'fixtures'
ROS_FILES = {'address': 'ip_address', 'interface': 'interface', 'route': 'ip_route', 'filter': 'ip_firewall_filter', 'nat': 'ip_firewall_nat', 'neighbor': 'ip_neighbor', 'bridge_port': 'interface_bridge_port', 'bridge_vlan': 'interface_bridge_vlan', 'vlan': 'interface_vlan',
             'bonding': 'interface_bonding', 'lease': 'ip_dhcp-server_lease', 'arp': 'ip_arp', 'address_list': 'ip_firewall_address-list', 'service': 'ip_service', 'iface_list': 'interface_list_member', 'address6': 'ipv6_address', 'route6': 'ipv6_route'}


def ros_tables():
    return {k: routeros.parse_table((FIX / 'routeros' / f'{v}.json').read_text()) for k, v in ROS_FILES.items()}


def ros_host():
    t = ros_tables()
    return {'net': routeros.network(t), 'infra': {'firewall': routeros.firewall(t), 'device': 'routeros', 'listeners': routeros.network(t)['listeners']}, 'containers': []}


def linux(ip, prefix, gateways, listeners=()):
    """A Linux host behind the router with no firewall of its own."""
    routes = [{'dst': str(__import__('ipaddress').ip_interface(f'{ip}/{prefix}').network), 'via': None, 'dev': 'eth1', 'metric': 0, 'family': 4}] + [{'dst': d, 'via': v, 'dev': 'eth1', 'metric': 1, 'family': 4} for d, v in gateways]
    return {'net': {'interfaces': [{'name': 'eth1', 'kind': 'ethernet', 'state': 'up', 'addresses': [{'ip': ip, 'prefix': prefix, 'scope': 'global'}], 'master': None}], 'routes': routes, 'listeners': list(listeners), 'unreadable': []},
            'infra': {'firewall': {'readable': True, 'backends': [], 'rules': [], 'nat': [], 'chains': [], 'policies': {}}, 'listeners': list(listeners)}, 'containers': []}


def web_listener(port):
    return {'proto': 'tcp', 'addr': '0.0.0.0', 'port': port, 'scope': 'any', 'process': ['httpd']}


def lab_fleet(host=None):
    return reach.Fleet({'sf-mikrotik': host or ros_host(),
                        'client': linux('10.77.10.50', 24, [('10.77.20.0/24', '10.77.10.1'), ('198.51.100.0/24', '10.77.10.1')]),
                        'server': linux('10.77.20.80', 24, [('10.77.10.0/24', '10.77.20.1')], [web_listener(80), web_listener(443), web_listener(22)]),
                        'outside': linux('198.51.100.50', 24, [])})


class RouterOsReading(unittest.TestCase):
    def test_serialized_tables_become_the_record_a_host_has(self):
        net = routeros.network(ros_tables())
        by = {i['name']: i for i in net['interfaces']}
        self.assertEqual(by['ether3']['addresses'][0]['ip'], '10.77.10.1')
        self.assertEqual(by['ether1']['kind'], 'ethernet')
        self.assertEqual(by['br-test']['kind'], 'bridge')
        self.assertEqual((by['vlan20']['kind'], by['vlan20']['vlan_id'], by['vlan20']['parent']), ('vlan', 20, 'br-test'))
        self.assertEqual(net['gateways'], ['10.77.0.1'])
        default = next(r for r in net['routes'] if r['dst'] == 'default')
        self.assertEqual((default['via'], default['dev']), ('10.77.0.1', 'ether1'))
        self.assertEqual(net['dns'], {'nameservers': [], 'search': []})
        self.assertEqual(net['unreadable'], [])

    def test_a_service_turned_off_or_listed_twice_is_one_or_none(self):
        ports = [x['port'] for x in routeros.network(ros_tables())['listeners']]
        self.assertEqual(ports.count(22), 1)
        self.assertIn(8291, ports)

    def test_a_port_that_came_as_a_float_is_a_port(self):
        self.assertIn('80.000000', (FIX / 'routeros' / 'ip_firewall_filter.json').read_text(), 'the fixture is what RouterOS really sends')
        rules = routeros.firewall(ros_tables())['rules']
        self.assertEqual(next(r for r in rules if r['comment'] == 'lan-to-dmz-web')['dports'], [80])

    def test_a_refusal_is_unreadable_and_never_an_empty_table(self):
        self.assertIsNone(routeros.parse_table('not enough permissions (9)'))
        self.assertIsNone(routeros.parse_table('bad command name serialize'))
        self.assertEqual(routeros.parse_table('[]'), [])
        fw = routeros.firewall({'filter': None, 'nat': []})
        self.assertFalse(fw['readable'])
        self.assertEqual(fw['backends'], [])

    def test_collect_refuses_when_what_must_be_read_was_not(self):
        def run(cmd):
            return 'not enough permissions' if 'firewall/filter' in cmd else '[]'
        with self.assertRaisesRegex(ValueError, 'firewall/filter'):
            routeros.collect(run)

    def test_a_terse_listing_from_an_older_routeros(self):
        rows = routeros.parse_terse((FIX / 'routeros' / 'filter.terse').read_text())
        self.assertEqual(rows[1]['in-interface'], 'ether1')
        self.assertEqual(rows[1]['comment'], 'management')
        got = routeros.parse_terse(' 0 X  comment=two words here chain=input action=drop\n 1 D  chain=forward action=accept')
        self.assertTrue(got[0]['disabled'])
        self.assertEqual(got[0]['comment'], 'two words here')
        self.assertTrue(got[1]['dynamic'])
        self.assertIsNone(routeros.parse_terse('bad command name print'))

    def test_a_device_without_serialize_is_asked_in_the_older_format(self):
        asked = []

        def run(cmd):
            asked.append(cmd)
            if ':serialize' in cmd:
                return 'bad command name serialize (line 1 column 8)'
            if cmd.startswith('/system resource'):
                return 'version: 6.49.10 (long-term)'
            if cmd.startswith('/system identity'):
                return 'name: old-router'
            if cmd.startswith('/ip address'):
                return ' 0   address=10.1.1.1/24 network=10.1.1.0 interface=ether1'
            if cmd.startswith('/interface print'):
                return ' 0  R name=ether1 type=ether mtu=1500 mac-address=AA:BB:CC:00:11:22'
            return ''
        got = routeros.collect(run)
        self.assertEqual(got['os'], 'RouterOS 6.49.10')
        self.assertIn('/ip firewall filter print terse without-paging', asked)
        self.assertEqual(got['net']['interfaces'][0]['state'], 'up')
        self.assertEqual(got['net']['interfaces'][0]['addresses'][0]['ip'], '10.1.1.1')

    def test_a_match_with_no_field_is_kept_and_marked(self):
        rows = [{'chain': 'forward', 'action': 'accept', 'src-mac-address': 'AA:BB:CC:00:11:22', 'layer7-protocol': 'x'}]
        r = routeros.firewall({'filter': rows, 'nat': []})['rules'][0]
        self.assertEqual(len(r['unmodelled']), 2)

    def test_address_lists_and_interface_lists_are_resolved(self):
        t = {'filter': [{'chain': 'input', 'action': 'accept', 'src-address-list': 'admins', 'in-interface-list': 'LAN'}, {'chain': 'input', 'action': 'drop', 'src-address-list': 'nothing-here'}, {'chain': 'input', 'action': 'drop', 'in-interface-list': '!LAN'}],
             'nat': [], 'address_list': [{'list': 'admins', 'address': '10.0.0.0/8'}, {'list': 'admins', 'address': '192.168.0.0/16'}], 'iface_list': [{'list': 'LAN', 'interface': 'ether2'}, {'list': 'LAN', 'interface': 'bridge'}]}
        rules = routeros.firewall(t)['rules']
        self.assertEqual(rules[0]['saddr'], '10.0.0.0/8,192.168.0.0/16')
        self.assertEqual(rules[0]['iif'], 'ether2,bridge')
        self.assertTrue(rules[1]['unmodelled'], 'an empty list says nothing of what it would match')
        self.assertEqual(rules[2]['not_iif'], 'ether2,bridge')

    def test_a_disabled_rule_is_not_a_rule(self):
        t = {'filter': [{'chain': 'input', 'action': 'drop', 'disabled': True}, {'chain': 'input', 'action': 'drop', 'disabled': 'true'}], 'nat': [{'chain': 'dstnat', 'action': 'dst-nat', 'disabled': True, 'to-addresses': '1.2.3.4'}]}
        fw = routeros.firewall(t)
        self.assertEqual((fw['rules'], fw['nat']), ([], []))

    def test_only_active_routes_in_the_main_table_are_followed(self):
        t = {'route': [{'dst-address': '0.0.0.0/0', 'gateway': '1.1.1.1', 'active': False}, {'dst-address': '10.9.0.0/16', 'gateway': '10.0.0.2', 'routing-table': 'dmz'}], 'interface': [], 'address': [], 'arp': [], 'service': []}
        net = routeros.network(t)
        self.assertEqual(len(net['routes']), 1)
        self.assertIsNone(reach.route_to(net, '10.9.0.1'), 'a policy table is not what plain traffic follows')


class ThroughTheRouter(unittest.TestCase):
    def test_allowed_across_the_router_names_the_rule(self):
        got = reach.query(lab_fleet(), '10.77.10.50', '10.77.20.80', 80)
        self.assertEqual(got['verdict'], 'allowed')
        hop = next(h for h in got['hops'] if h['at'] == 'sf-mikrotik')
        self.assertEqual(hop['verdict'], 'accept')
        self.assertIn('forward', hop['what'])
        self.assertIn('ether3 to ether4', hop['what'])

    def test_blocked_across_the_router_names_the_rule_that_drops_it(self):
        got = reach.query(lab_fleet(), '10.77.10.50', '10.77.20.80', 22)
        self.assertEqual(got['verdict'], 'blocked')
        self.assertIn('sf-mikrotik', got['decided_by'])
        self.assertIn('forward drop', got['decided_by'])

    def test_a_router_rule_flips_the_answer(self):
        host = ros_host()
        host['infra']['firewall']['rules'] = [r for r in host['infra']['firewall']['rules'] if r['comment'] != 'lan-to-dmz-web']
        self.assertEqual(reach.query(lab_fleet(host), '10.77.10.50', '10.77.20.80', 80)['verdict'], 'blocked')

    def test_through_two_routers(self):
        edge = {'net': {'interfaces': [{'name': 'a', 'kind': 'ethernet', 'state': 'up', 'addresses': [{'ip': '10.1.0.1', 'prefix': 24}], 'master': None}, {'name': 'b', 'kind': 'ethernet', 'state': 'up', 'addresses': [{'ip': '10.2.0.1', 'prefix': 24}], 'master': None}],
                        'routes': [{'dst': '10.1.0.0/24', 'via': None, 'dev': 'a', 'family': 4}, {'dst': '10.2.0.0/24', 'via': None, 'dev': 'b', 'family': 4}, {'dst': '10.3.0.0/24', 'via': '10.2.0.2', 'dev': 'b', 'family': 4}]},
                'infra': {'device': 'routeros', 'firewall': {'readable': True, 'backends': ['routeros'], 'rules': [], 'nat': [], 'chains': [{'backend': 'routeros', 'table': 'filter', 'name': 'forward', 'hook': 'forward', 'policy': 'accept'}], 'policies': {}}}, 'containers': []}
        core = {'net': {'interfaces': [{'name': 'c', 'kind': 'ethernet', 'state': 'up', 'addresses': [{'ip': '10.2.0.2', 'prefix': 24}], 'master': None}, {'name': 'd', 'kind': 'ethernet', 'state': 'up', 'addresses': [{'ip': '10.3.0.1', 'prefix': 24}], 'master': None}],
                        'routes': [{'dst': '10.2.0.0/24', 'via': None, 'dev': 'c', 'family': 4}, {'dst': '10.3.0.0/24', 'via': None, 'dev': 'd', 'family': 4}]},
                'infra': {'device': 'routeros', 'firewall': {'readable': True, 'backends': ['routeros'], 'rules': [], 'nat': [], 'chains': [{'backend': 'routeros', 'table': 'filter', 'name': 'forward', 'hook': 'forward', 'policy': 'accept'}], 'policies': {}}}, 'containers': []}
        fleet = reach.Fleet({'edge': edge, 'core': core, 'a': linux('10.1.0.5', 24, [('default', '10.1.0.1')]), 'b': linux('10.3.0.5', 24, [('default', '10.3.0.1')], [web_listener(80)])})
        got = reach.query(fleet, 'a', 'b', 80)
        self.assertEqual(got['verdict'], 'allowed')
        self.assertEqual([h['at'] for h in got['hops'] if 'forward' in h['what']], ['edge', 'core'])
        # a rule further along, on the second router
        core['infra']['firewall']['rules'] = [routeros._row_to_rule({'chain': 'forward', 'action': 'drop', 'dst-port': 80.0, 'protocol': 'tcp'}, 'filter', 1, {}, {})]
        self.assertIn('core', reach.query(reach.Fleet(fleet.hosts), 'a', 'b', 80)['decided_by'])

    def test_a_routing_loop_is_an_answer(self):
        def router(ip, other):
            return {'net': {'interfaces': [{'name': 'a', 'kind': 'ethernet', 'state': 'up', 'addresses': [{'ip': ip, 'prefix': 24}], 'master': None}], 'routes': [{'dst': 'default', 'via': other, 'dev': 'a', 'family': 4}]}, 'infra': {'device': 'routeros', 'firewall': {'readable': True, 'backends': [], 'rules': [], 'nat': [], 'chains': [], 'policies': {}}}, 'containers': []}
        fleet = reach.Fleet({'r1': router('10.0.0.1', '10.0.0.2'), 'r2': router('10.0.0.2', '10.0.0.1'), 'a': linux('10.0.0.5', 24, [('default', '10.0.0.1')])})
        self.assertIn('routing loop', reach.query(fleet, 'a', '10.9.9.9', 80)['decided_by'])

    def test_a_port_forward_from_the_wan_lands_on_the_server(self):
        got = reach.query(lab_fleet(), '198.51.100.50', '198.51.100.1', 443)
        self.assertEqual(got['verdict'], 'allowed')
        self.assertEqual(got['forwarded_to'], '10.77.20.80:443')
        self.assertEqual(got['to_host'], 'server')

    def test_a_port_with_no_forward_stops_at_the_router(self):
        self.assertEqual(reach.query(lab_fleet(), '198.51.100.50', '198.51.100.1', 8443)['verdict'], 'blocked')

    def test_an_unread_router_is_a_blind_spot_and_never_a_yes(self):
        host = ros_host()
        host['infra']['firewall'] = {'readable': False, 'backends': [], 'rules': [], 'nat': [], 'notes': []}
        got = reach.query(lab_fleet(host), '10.77.10.50', '10.77.20.80', 80)
        self.assertTrue(any('has not been read' in s for s in got['blind_spots']))


class WanExposure(unittest.TestCase):
    def forwards(self):
        h = ros_host()
        return exposure.forwards_of('sf-mikrotik', h['infra']['firewall'], ['ether2'], h['net'])

    def test_each_forward_says_where_it_lands_and_whether_rules_let_it(self):
        f = self.forwards()
        self.assertEqual(len(f), 1)
        self.assertEqual((f[0]['to_addr'], f[0]['to_port'], f[0]['from_wan'], f[0]['verdict']), ('10.77.20.80', 443, True, 'accept'))

    def test_a_forwarded_service_is_exposed_to_any_address_and_an_unforwarded_one_stays_lan(self):
        h = linux('10.77.20.80', 24, [], [web_listener(443), web_listener(8080)])
        rep = exposure.host_report(h['net'], h['infra'], [], 'server', self.forwards())
        by = {i['port']: i for i in rep['items']}
        self.assertEqual(by[443]['level'], 'any')
        self.assertIn('sf-mikrotik', by[443]['rule'])
        self.assertEqual(by[8080]['level'], 'lan')

    def test_a_forward_the_routers_own_rules_drop_exposes_nothing(self):
        h = ros_host()
        fw = h['infra']['firewall']
        fw['rules'] = [r for r in fw['rules'] if r['comment'] != 'wan-to-dmz-https']
        forwards = exposure.forwards_of('r', fw, ['ether2'], h['net'])
        self.assertEqual(forwards[0]['verdict'], 'drop')
        s = linux('10.77.20.80', 24, [], [web_listener(443)])
        self.assertEqual(exposure.host_report(s['net'], s['infra'], [], 's', forwards)['items'][0]['level'], 'lan')

    def test_a_forward_only_widens(self):
        s = linux('10.77.20.80', 24, [], [{'proto': 'tcp', 'addr': '127.0.0.1', 'port': 443, 'scope': 'loopback'}])
        self.assertEqual(exposure.host_report(s['net'], s['infra'], [], 's', self.forwards())['items'][0]['level'], 'loopback')


class OpenWrtReading(unittest.TestCase):
    def setUp(self):
        self.d = openwrt.parse((FIX / 'openwrt' / 'reading.txt').read_text())

    def test_its_own_reading(self):
        d = self.d
        self.assertEqual(d['identity'], 'sf-openwrt')
        self.assertTrue(d['os'].startswith('OpenWrt 25.12'))
        self.assertEqual(d['facts']['wan'], ['eth1'])
        self.assertEqual({i['name']: i['addresses'][0]['ip'] for i in d['net']['interfaces'] if i['addresses']}['eth2'], '10.77.10.2')
        self.assertEqual(next(r for r in d['net']['routes'] if r['dst'] == 'default')['via'], '10.77.0.1')

    def test_fw4_decides_as_it_does_on_the_router(self):
        fw = self.d['firewall']
        self.assertTrue(fw['readable'])
        flow = {'proto': 'tcp', 'daddr': '10.77.20.80', 'saddr': '10.77.10.50', 'iif': 'eth2', 'oif': 'eth3', 'family': 'ip'}
        self.assertEqual(exposure.kernel_path(fw, 'forward', {**flow, 'port': 80})['verdict'], 'accept')
        self.assertEqual(exposure.kernel_path(fw, 'forward', {**flow, 'port': 22})['verdict'], 'drop')

    def test_a_redirect_applies_to_its_zones_devices(self):
        nat = next(n for n in self.d['firewall']['nat'] if n['action'] == 'dnat')
        self.assertEqual((nat['iif'], nat['to_addr'], nat['comment']), ('eth1', '10.77.20.80', 'dmz-https'))

    def test_a_forward_gets_through_fw4s_own_rule_for_forwards(self):
        fw = self.d['firewall']
        forwards = exposure.forwards_of('sf-openwrt', fw, ['eth1'], self.d['net'])
        wan = next(f for f in forwards if f['iif'] == 'eth1')
        self.assertEqual((wan['verdict'], wan['from_wan']), ('accept', True))
        self.assertEqual(exposure.kernel_path(fw, 'forward', {'proto': 'tcp', 'port': 443, 'iif': 'eth1', 'oif': 'eth3', 'daddr': '10.77.20.80', 'family': 'ip'})['verdict'], 'drop', 'the same packet with no forward behind it')

    def test_leases_and_uci(self):
        self.assertEqual(openwrt.parse_leases('1800000000 AA:BB:CC:00:11:22 10.0.0.9 phone 01:aa\n0 AA:BB:CC:00:11:33 10.0.0.10 * *')[1], {'ip': '10.0.0.10', 'mac': 'aa:bb:cc:00:11:33', 'name': None, 'expires': 0, 'static': True})
        uci = openwrt.parse_uci("firewall.@zone[0]=zone\nfirewall.@zone[0].name='wan'\nfirewall.@zone[0].network='wan' 'wan6'\nfirewall.@zone[0].masq='1'")
        self.assertEqual(openwrt.zones(uci)[0]['networks'], ['wan', 'wan6'])

    def test_cut_short_is_refused(self):
        with self.assertRaises(ValueError):
            openwrt.parse('@@link\n[]')


class PfSenseReading(unittest.TestCase):
    def setUp(self):
        self.xml = (FIX / 'pfsense' / 'config.xml').read_text()
        self.d = pfsense.parse('@@config\n' + self.xml + '\n@@hostname\npf1\n@@end\n')

    def test_rules_from_config_xml(self):
        fw = self.d['firewall']
        self.assertEqual(fw['backends'], ['pf'])
        self.assertEqual(fw['policies']['forward'], 'drop')
        rule = next(r for r in fw['rules'] if r['comment'] == 'lan to web')
        self.assertEqual((rule['saddr'], rule['daddr'], rule['dports'], rule['iif']), ('10.77.10.0/24', '10.77.20.80', [80, 443], 'vtnet2'))
        self.assertFalse(any(r['comment'] == 'off' for r in fw['rules']))

    def test_an_alias_it_does_not_know_stays_unmodelled(self):
        rule = next(r for r in self.d['firewall']['rules'] if r['comment'] == 'an alias not known here')
        self.assertTrue(rule['unmodelled'])

    def test_aliases_expand_through_each_other(self):
        self.assertEqual(pfsense.aliases(pfsense.load_xml(self.xml))['admins'], '10.0.0.0/8,192.168.5.5')

    def test_a_forward_and_what_decides_it(self):
        fw = self.d['firewall']
        self.assertEqual((fw['nat'][0]['to_addr'], fw['nat'][0]['to_port'], fw['nat'][0]['iif'], fw['nat'][0]['dports']), ('10.77.20.80', 443, 'vtnet1', [443]))
        flow = {'proto': 'tcp', 'daddr': '10.77.20.80', 'saddr': '10.77.10.9', 'iif': 'vtnet2', 'family': 'ip'}
        self.assertEqual(exposure.kernel_path(fw, 'forward', {**flow, 'port': 80})['verdict'], 'accept')
        self.assertEqual(exposure.kernel_path(fw, 'forward', {**flow, 'port': 22})['verdict'], 'drop')
        self.assertEqual(exposure.kernel_path(fw, 'forward', {**flow, 'port': 9000})['verdict'], 'drop', 'pf blocks what no rule passes')

    def test_no_secret_from_config_xml_gets_out(self):
        self.assertNotIn('secret-hash', json.dumps(self.d))

    def test_a_document_declaring_an_entity_is_refused(self):
        with self.assertRaisesRegex(ValueError, 'entity'):
            pfsense.load_xml('<!DOCTYPE x [<!ENTITY a "aaaa">]><pfsense>&a;</pfsense>')

    def test_kernel_readings(self):
        got = pfsense.parse_sockstat('USER COMMAND PID FD PROTO LOCAL FOREIGN\nroot sshd 1 3 tcp4 *:22 *:*\nroot unbound 2 4 udp4 127.0.0.1:53 *:*')
        self.assertEqual([(g['port'], g['scope']) for g in got], [(22, 'any'), (53, 'loopback')])
        self.assertEqual(pfsense.parse_arp('? (10.0.0.1) at aa:bb:cc:00:11:22 on vtnet1 expires in 1 seconds')[0]['dev'], 'vtnet1')
        routes = pfsense.parse_netstat('Internet:\nDestination Gateway Flags Netif\ndefault 198.51.100.254 UGS vtnet1\n10.0.0.0/24 link#2 U vtnet2')
        self.assertEqual((routes[0]['dst'], routes[0]['via'], routes[1]['via']), ('default', '198.51.100.254', None))

    def test_a_change_goes_into_its_section_and_leaves_the_rest_alone(self):
        got = ros.emit(ros.parse('/ip firewall filter add chain=forward in-interface=lan protocol=tcp dst-port=25 action=drop comment="no mail"'), 'pfsense')
        merged = netdevice.merge_config(self.xml, got['files'])
        root = pfsense.load_xml(merged)
        self.assertEqual(len(root.findall('filter/rule')), 5)
        self.assertEqual(root.find('system/password').text, '$2y$secret-hash')


class CiscoReading(unittest.TestCase):
    def texts(self):
        return {'brief': (FIX / 'cisco' / 'brief.txt').read_text(), 'running': (FIX / 'cisco' / 'running.txt').read_text(), 'route': (FIX / 'cisco' / 'route.txt').read_text(), 'acl': (FIX / 'cisco' / 'acl.txt').read_text(),
                'version': 'Cisco IOS Software, Version 15.9(3)M4, RELEASE', 'arp': 'Protocol  Address  Age (min)  Hardware Addr   Type   Interface\nInternet  10.77.10.9  3  5254.00aa.bbcc  ARPA  GigabitEthernet0/1\nInternet 10.77.10.8 0 Incomplete ARPA', 'cdp': '-------------------------\nDevice ID: sw1\nEntry address(es):\n  IP address: 10.77.10.7\nPlatform: cisco WS-C2960, Capabilities: Switch\nInterface: GigabitEthernet0/1,  Port ID (outgoing port): FastEthernet0/24\n', 'lldp': '', 'vlan': '10   users   active   Fa1/0, Fa1/1\n', 'counters': 'GigabitEthernet0/1 is up, line protocol is up\n     12 packets input, 3400 bytes\n     5 packets output, 800 bytes\n     2 input errors, 0 CRC'}

    def test_the_record(self):
        d = cisco.model(self.texts())
        self.assertEqual((d['identity'], d['os']), ('R1', 'Cisco IOS 15.9(3)M4'))
        by = {i['name']: i for i in d['net']['interfaces']}
        self.assertEqual(by['GigabitEthernet0/1']['addresses'][0], {'ip': '10.77.10.4', 'prefix': 24, 'scope': 'global'})
        self.assertEqual(by['GigabitEthernet0/2']['state'], 'down')
        self.assertEqual((by['FastEthernet1/0']['bridge_vlans'], by['FastEthernet1/0']['master'], by['FastEthernet1/0']['switchport']), ([10, 20, 21, 22], 'Port-channel3', 'trunk'))
        routes = {r['dst']: r for r in d['net']['routes']}
        self.assertEqual(routes['default']['via'], '198.51.100.254')
        self.assertEqual(routes['10.77.10.0/24']['dev'], 'GigabitEthernet0/1')
        self.assertNotIn('10.77.10.4/32', routes)
        self.assertEqual(d['net']['neighbours'][0]['mac'], '52:54:00:aa:bb:cc')
        self.assertEqual(len(d['net']['neighbours']), 1)
        self.assertEqual(d['facts']['discovered'][0], {'name': 'sw1', 'ip': '10.77.10.7', 'platform': 'cisco WS-C2960', 'via': 'GigabitEthernet0/1', 'remote_port': 'FastEthernet0/24', 'protocol': 'cdp'})
        self.assertEqual(d['facts']['counters'][0]['rx_error'], 2)

    def test_acls_decide_on_the_interface_they_are_bound_to(self):
        fw = cisco.model(self.texts())['firewall']
        flow = {'proto': 'tcp', 'daddr': '10.77.20.80', 'saddr': '10.77.10.50', 'iif': 'GigabitEthernet0/1', 'family': 'ip'}
        self.assertEqual(exposure.kernel_path(fw, 'forward', {**flow, 'port': 80})['verdict'], 'accept')
        self.assertEqual(exposure.kernel_path(fw, 'forward', {**flow, 'port': 22})['verdict'], 'drop')
        out = exposure.kernel_path(fw, 'forward', {'proto': 'tcp', 'daddr': '10.77.20.80', 'saddr': '8.8.8.8', 'iif': 'GigabitEthernet0/0', 'port': 25, 'family': 'ip'})
        self.assertEqual(out['verdict'], 'drop', 'deny ip any any, then the end of the ACL')

    def test_an_acl_ends_in_an_implicit_deny(self):
        texts = self.texts()
        texts['acl'] = 'Extended IP access list 110\n    10 permit tcp any any eq 80\nExtended IP access list OUTSIDE_IN\n    10 permit tcp any any eq 443'
        fw = cisco.model(texts)['firewall']
        got = exposure.kernel_path(fw, 'forward', {'proto': 'tcp', 'daddr': '1.2.3.4', 'saddr': '1.1.1.1', 'iif': 'GigabitEthernet0/1', 'port': 22, 'family': 'ip'})
        self.assertEqual(got['verdict'], 'drop')
        self.assertIn('implicit', [r for r in fw['rules'] if r.get('comment')][0]['comment'])

    def test_a_wildcard_with_holes_is_not_a_prefix(self):
        self.assertEqual(cisco.wildcard_to_cidr('10.0.0.0', '0.0.0.255'), '10.0.0.0/24')
        self.assertEqual(cisco.wildcard_to_cidr('10.0.0.0', '0.255.255.255'), '10.0.0.0/8')
        self.assertIsNone(cisco.wildcard_to_cidr('10.0.0.0', '0.255.0.255'))
        rule = next(r for r in cisco.parse_acls((FIX / 'cisco' / 'acl.txt').read_text())['OUTSIDE_IN'] if r['order'] == 30)
        self.assertTrue(rule['unmodelled'])

    def test_a_static_forward(self):
        nat = cisco.model(self.texts())['firewall']['nat'][0]
        self.assertEqual((nat['to_addr'], nat['to_port'], nat['dports'], nat['iif']), ('10.77.20.80', 443, [443], 'GigabitEthernet0/0'))

    def test_secrets_stay_out_of_the_saved_config(self):
        cfg = cisco.model(self.texts())['config']
        for secret in ('$1$abcd', '$1$xyz', 'public RO'):
            self.assertNotIn(secret, cfg)
        self.assertIn('hostname R1', cfg)

    def test_a_refused_show_is_an_error(self):
        t = self.texts()
        t['running'] = "% Invalid input detected at '^' marker."
        with self.assertRaisesRegex(ValueError, 'enable mode'):
            cisco.model(t)


class Language(unittest.TestCase):
    TEXT = '''/interface bridge add name=br-lan vlan-filtering=yes
/interface bridge port add bridge=br-lan interface=eth1 pvid=10
/interface vlan add name=vlan10 vlan-id=10 interface=br-lan
/interface bonding add name=bond0 slaves=eth2,eth3 mode=802.3ad
/ip address add address=192.168.10.1/24 interface=vlan10 comment="the gateway"
/ip route add dst-address=172.16.0.0/16 gateway=192.168.10.254 distance=5
/ip dns set servers=1.1.1.1,8.8.8.8
/ip firewall address-list add list=admins address=10.0.0.0/8
/ip firewall filter add chain=input protocol=tcp dst-port=22 src-address=10.0.0.0/8 action=accept comment="ssh in"
/ip firewall filter add chain=forward in-interface=eth1 out-interface=eth2 protocol=tcp dst-port=80,443 action=accept
/ip firewall filter add chain=input protocol=tcp dst-port=23 action=drop
/ip firewall nat add chain=dstnat protocol=tcp dst-port=443 in-interface=wan action=dst-nat to-addresses=10.77.20.80 to-ports=8443 comment="web in"
/ip/firewall/nat/add chain=srcnat out-interface=wan action=masquerade
'''

    def test_every_way_of_writing_a_path(self):
        for text in ('/ip firewall filter add chain=input action=drop', '/ip/firewall/filter/add chain=input action=drop', '/ip firewall filter\nadd chain=input action=drop', '/ip firewall filter add \\\n  chain=input \\\n  action=drop'):
            got = ros.parse(text)
            self.assertEqual((got[0].path, got[0]['chain']), (('ip', 'firewall', 'filter'), 'input'), text)

    def test_anything_a_target_could_be_told_to_run_is_refused(self):
        for bad in ('/ip firewall filter add chain=input action=accept comment="x; reboot"', '/ip firewall filter add chain=$(reboot) action=accept', '/ip firewall filter add chain=input action=accept comment="`id`"', '/ip firewall filter add chain=input action=accept comment="<x>"',
                    '/ip address add address=1.1.1.1/24 interface="eth0 && id"', '/ip firewall filter add chain=input action=accept dst-port=22;id', '/interface vlan add name=a vlan-id=$(id) interface=b', '/ip firewall filter add chain=input action=accept src-address=1.1.1.1/24;drop', '/ip dns set servers=1.1.1.1\x01'):
            with self.assertRaises(ros.DslError, msg=bad):
                ros.parse(bad)

    def test_a_comment_can_not_be_a_command_to_routeros(self):
        for bad in ('/ip firewall filter add chain=input action=accept comment=[/system/reboot]', '/ip firewall filter add chain=input action=accept comment="[/system/reset-configuration]"', '/ip firewall filter add chain=input action=accept comment={x}'):
            with self.assertRaises(ros.DslError, msg=bad):
                ros.parse(bad)
        self.assertIn('comment="plain"', ros.parse('/ip firewall filter add chain=input action=accept comment=plain')[0].text())

    def test_a_comment_can_not_hold_a_character_that_changes_how_it_reads(self):
        # SF-53: a text-direction or zero-width character in a comment reorders or hides what a person reads in the emitted text, the review screen and a device's own log
        for char in ('\u202e', '\u2066', '\u200b', '\u200f', '\u2060', '\ufeff'):
            with self.assertRaisesRegex(ros.DslError, 'text-direction or zero-width', msg=repr(char)):
                ros.parse(f'/ip firewall filter add chain=input action=accept comment="ok{char}allow"')
        with self.assertRaises(ros.DslError):      # a line separator cuts the statement in two before the comment is read, which is refused for another reason
            ros.parse('/ip firewall filter add chain=input action=accept comment="ok\u2028allow"')
        for fine in ('caf\u00e9 in', '\u05e9\u05dc\u05d5\u05dd', '\u0645\u0631\u062d\u0628\u0627'):      # letters of other scripts are fine; it is the controls that are refused
            self.assertIn(fine, ros.parse(f'/ip firewall filter add chain=input action=accept comment="{fine}"')[0].text())

    def test_it_says_what_is_wrong_and_where(self):
        with self.assertRaisesRegex(ros.DslError, 'line 2: /ip firewall filter has no bogus'):
            ros.parse('/ip firewall filter add chain=input action=drop\n/ip firewall filter add chain=input action=drop bogus=1')
        for bad, why in (('/nonsense add a=1', 'no path'), ('add chain=input', 'no path has been set'), ('/ip firewall filter add action=drop', 'needs chain'), ('/ip firewall filter set chain=input action=drop', 'takes add'), ('/ip firewall filter add chain=input action=jump', 'jump-target'), ('/ip firewall nat add chain=dstnat action=dst-nat', 'to-addresses')):
            with self.assertRaisesRegex(ros.DslError, why):
                ros.parse(bad)

    def test_every_target_says_what_it_left_out(self):
        stmts = ros.parse(self.TEXT)
        for t in ros.TARGETS:
            got = ros.emit(stmts, t)
            written = got['text'] + ' '.join(got['files'].values())
            for u in got['unsupported']:
                self.assertTrue(u['why'], t)
            self.assertTrue(written.strip() or got['unsupported'], t)
        self.assertEqual(ros.emit(stmts, 'routeros')['unsupported'], [])

    @unittest.skipUnless(shutil.which('nft'), 'needs nft')
    def test_nft_itself_takes_what_is_written_for_it(self):
        got = ros.emit(ros.parse(self.TEXT), 'nftables')
        lines = got['text'].splitlines()
        # `delete` only makes sense on a machine that has the table: the syntax check is of the rest
        body = '\n'.join(x for x in lines if not x.startswith(('delete table', 'table inet storageforge_dsl\n')) and x not in ('table inet storageforge_dsl', 'table ip storageforge_dsl_nat'))
        with tempfile.NamedTemporaryFile('w', suffix='.nft') as f:
            f.write(body)
            f.flush()
            p = subprocess.run(['nft', '-c', '-f', f.name], capture_output=True, text=True)
        if 'Operation not permitted' in p.stderr:
            self.skipTest('nft -c needs CAP_NET_ADMIN here: the lab checks it for real')
        self.assertEqual(p.returncode, 0, p.stderr)

    def test_the_iptables_form(self):
        text = ros.emit(ros.parse(self.TEXT), 'iptables')['text']
        self.assertIn('-A INPUT -p tcp -s 10.0.0.0/8 --dport 22 -m comment --comment "ssh in" -j ACCEPT', text)
        self.assertIn('-m multiport --dports 80,443', text)
        self.assertIn('-A PREROUTING -i wan -p tcp --dport 443 -m comment --comment "web in" -j DNAT --to-destination 10.77.20.80:8443', text)
        self.assertIn('-A POSTROUTING -o wan -j MASQUERADE', text)
        self.assertLess(text.index('*filter'), text.index('COMMIT'))

    def test_a_port_needs_a_protocol_everywhere(self):
        stmts = ros.parse('/ip firewall filter add chain=input in-interface=e0 dst-port=22 action=accept')
        for t in ('nftables', 'iptables', 'firewalld', 'ufw', 'cisco'):
            self.assertTrue(ros.emit(stmts, t)['unsupported'], t)

    def test_firewalld_and_ufw(self):
        self.assertIn('''--add-rich-rule='rule family="ipv4" source address="10.0.0.0/8" port port="22" protocol="tcp" accept\'''', ros.emit(ros.parse(self.TEXT), 'firewalld')['text'])
        self.assertIn('ufw allow proto tcp from 10.0.0.0/8 to any port 22 comment', ros.emit(ros.parse(self.TEXT), 'ufw')['text'])
        self.assertIn('--add-forward-port=port=443:proto=tcp:toaddr=10.77.20.80:toport=8443', ros.emit(ros.parse(self.TEXT), 'firewalld')['text'])

    def test_openwrt_rules_speak_in_zones(self):
        text = ros.emit(ros.parse(self.TEXT), 'openwrt', zones={'eth1': 'lan', 'eth2': 'dmz', 'wan': 'wan'})['text']
        self.assertIn('uci set firewall.$r.src=lan', text)
        self.assertIn('uci set firewall.$r.dest=dmz', text)
        self.assertIn('uci set firewall.$r.target=DNAT', text)
        self.assertIn('uci commit firewall', text)

    def test_pfsense_writes_xml_that_parses_and_escapes(self):
        got = ros.emit(ros.parse('/ip firewall filter add chain=forward in-interface=lan protocol=tcp dst-port=80 action=accept comment="a b"'), 'pfsense')
        from xml.etree import ElementTree
        rule = ElementTree.fromstring(f'<x>{got["files"]["filter"]}</x>')[0]
        self.assertEqual((rule.find('type').text, rule.find('destination/port').text, rule.find('descr').text), ('pass', '80', 'a b'))

    def test_cisco_acls_and_wildcards(self):
        text = ros.emit(ros.parse('/ip firewall filter add chain=forward in-interface=Gi0/1 protocol=tcp src-address=10.0.0.0/24 dst-address=1.2.3.4 dst-port=80-90 action=accept comment="x y"\n/ip route add dst-address=172.16.0.0/16 gateway=10.0.0.1'), 'cisco')['text']
        self.assertIn('ip access-list extended SF_GI0_1_IN', text)
        self.assertIn('permit tcp 10.0.0.0 0.0.0.255 host 1.2.3.4 range 80 90', text)
        self.assertIn('ip access-group SF_GI0_1_IN in', text)
        self.assertIn('ip route 172.16.0.0 255.255.0.0 10.0.0.1', text)
        self.assertEqual(len(cisco.parse_acls('Extended IP access list X\n    permit tcp 10.0.0.0 0.0.0.255 host 1.2.3.4 range 80 90')['X']), 1)

    def test_linux_network_files(self):
        got = ros.emit(ros.parse(self.TEXT), 'networkd')
        self.assertIn('Kind=bridge', got['files']['50-br-lan.netdev'])
        self.assertIn('VLANFiltering=yes', got['files']['50-br-lan.netdev'])
        self.assertIn('Address=192.168.10.1/24', got['files']['50-vlan10.network'])
        self.assertIn('Destination=172.16.0.0/16', got['files']['50-vlan10.network'])
        self.assertIn('Bond=bond0', got['files']['50-eth2.network'])
        self.assertTrue(any('firewall statement' in u['why'] for u in got['unsupported']))

    def test_what_a_secret_looks_like_when_shown(self):
        key = 'A' * 43 + '='
        s = ros.parse(f'/interface wireguard add name=wg0 listen-port=51820 private-key="{key}"')[0]
        self.assertNotIn(key, s.text())
        self.assertIn(key, s.text(redact=False))

    def test_any_firewall_reads_back_in_the_one_syntax_and_parses(self):
        for net, fw in ((ros_host()['net'], ros_host()['infra']['firewall']),
                        (openwrt.parse((FIX / 'openwrt' / 'reading.txt').read_text())['net'], None)):
            text = ros.from_model(net, fw)
            self.assertIn('/ip address add', text)
            kept = [line.split('  # also:')[0] for line in text.splitlines() if 'interface vlan add' not in line and 'chain=dstnat' not in line or 'to-addresses' in line]
            ros.parse('\n'.join(kept))
        self.assertIn('chain=forward action=accept protocol=tcp dst-address=10.77.20.80 in-interface=ether3 out-interface=ether4 dst-port=80', ros.from_model(None, ros_host()['infra']['firewall']))
        self.assertIn('/ip firewall nat add chain=dstnat action=dst-nat protocol=tcp in-interface=ether2 dst-port=443 to-addresses=10.77.20.80 to-ports=443', ros.from_model(None, ros_host()['infra']['firewall']))

    def test_a_what_if_uses_the_rules_as_they_would_be(self):
        added = ros.to_model_rules(ros.parse('/ip firewall filter add chain=forward protocol=tcp dst-port=80 action=drop'))
        fw = routeros.firewall({'filter': [], 'nat': []})
        fw['rules'] += added['rules']
        self.assertEqual(exposure.kernel_path(fw, 'forward', {'proto': 'tcp', 'port': 80, 'family': 'ip'})['verdict'], 'drop')
        self.assertEqual(exposure.kernel_path(fw, 'forward', {'proto': 'tcp', 'port': 81, 'family': 'ip'})['verdict'], 'accept')


class Scanner(unittest.TestCase):
    XML = '''<?xml version="1.0"?><!DOCTYPE nmaprun><nmaprun><host><status state="up"/><address addr="10.0.0.5" addrtype="ipv4"/><address addr="AA:BB:CC:00:11:22" addrtype="mac" vendor="Acme"/><hostnames><hostname name="printer"/></hostnames><ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port><port protocol="tcp" portid="80"><state state="closed"/></port></ports></host>
<host><status state="down"/><address addr="10.0.0.6" addrtype="ipv4"/></host></nmaprun>'''

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Database(f'sqlite:///{self.tmp.name}/t.db')
        self.conn = self.db.connect()
        self.db.migrate(self.conn)

    def tearDown(self):
        self.conn.close()
        self.tmp.cleanup()

    def test_it_starts_off_and_refuses_to_run(self):
        self.assertFalse(netscan.settings(self.conn)['enabled'])
        with self.assertRaisesRegex(netscan.ScanRefused, 'off'):
            netscan.run(self.db, self.conn, '10.0.0.0/24', 'a')
        self.assertEqual(netscan.tick(self.db), 0)

    def test_only_private_networks_of_a_sane_size(self):
        for bad in ('8.8.8.0/24', '10.0.0.0/8', 'fd00::/64', '10.0.0.0/24; rm -rf /', '--script=evil', '-iL /etc/passwd'):
            with self.assertRaises(netscan.ScanRefused, msg=bad):
                netscan.check_range(bad)
        self.assertEqual(netscan.check_range('10.0.0.9/24'), '10.0.0.0/24')

    def test_the_command_is_an_unprivileged_connect_scan_of_that_network_only(self):
        argv = netscan.command('10.0.0.0/24', 100)
        self.assertIn('-sT', argv)
        self.assertEqual(argv[-2:], ['--', '10.0.0.0/24'])
        self.assertNotIn('-sS', argv)
        self.assertNotIn('-O', argv)

    def test_a_network_not_named_in_the_settings_is_refused(self):
        netscan.save_settings(self.conn, {'enabled': True, 'ranges': ['10.0.0.0/24']}, 'a')
        with self.assertRaisesRegex(netscan.ScanRefused, 'not one of the ranges'):
            netscan.run(self.db, self.conn, '192.168.1.0/24', 'a')

    def test_results_link_back_to_what_stoageforge_manages(self):
        self.conn.execute("INSERT INTO hosts (hostname, ip_address, ssh_host) VALUES ('nas', '10.0.0.5', '10.0.0.5')")
        netdevice.add(self.conn, {'name': 'gw', 'platform': 'routeros', 'address': '10.0.0.1', 'credential': None}, 'a')
        self.conn.execute("INSERT INTO hosts (hostname, ip_address, ssh_host) VALUES ('gw', '10.0.0.1', '10.0.0.1')")
        netscan.save_settings(self.conn, {'enabled': True, 'ranges': ['10.0.0.0/24']}, 'a')
        xml = self.XML.replace('</nmaprun>', '<host><status state="up"/><address addr="10.0.0.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="22"><state state="open"/></port></ports></host><host><status state="up"/><address addr="10.0.0.77" addrtype="ipv4"/><ports><port protocol="tcp" portid="22"><state state="open"/></port></ports></host></nmaprun>')
        got = netscan.run(self.db, self.conn, None, 'a', wait=True, runner=lambda argv: xml)
        res = netscan.results(self.conn, got['scan_id'])
        by = {h['ip']: h for h in res['hosts']}
        self.assertEqual(set(by), {'10.0.0.1', '10.0.0.5', '10.0.0.77'})
        self.assertEqual([p['port'] for p in by['10.0.0.5']['ports']], [22])
        self.assertEqual((by['10.0.0.5']['vendor'], by['10.0.0.5']['name']), ('Acme', 'printer'))
        self.assertIn({'label': 'Config', 'url': '/#host=nas&tab=rebuild'}, by['10.0.0.5']['link']['links'])
        self.assertIn({'label': 'Device', 'url': '/manage#device=gw'}, by['10.0.0.1']['link']['links'])
        self.assertFalse(by['10.0.0.77']['link']['managed'])
        self.assertTrue(by['10.0.0.77']['link']['ssh'])
        self.assertIn('10.0.0.77', by['10.0.0.77']['link']['links'][1]['url'])
        self.assertEqual(netscan.graph(self.conn, got['scan_id'])['networks'][0]['network'], '10.0.0.0/24')

    def test_what_is_new_or_gone_since_the_last_scan(self):
        netscan.save_settings(self.conn, {'enabled': True, 'ranges': ['10.0.0.0/24']}, 'a')
        netscan.run(self.db, self.conn, None, 'a', wait=True, runner=lambda argv: self.XML)
        second = self.XML.replace('addr="10.0.0.5"', 'addr="10.0.0.9"')
        got = netscan.run(self.db, self.conn, None, 'a', wait=True, runner=lambda argv: second)
        res = netscan.results(self.conn, got['scan_id'])
        self.assertTrue(res['hosts'][0]['new'])
        self.assertEqual(res['gone'], ['10.0.0.5'])

    @staticmethod
    def found(ip):
        return f'<host><status state="up"/><address addr="{ip}" addrtype="ipv4"/><ports><port protocol="tcp" portid="22"><state state="open"/></port></ports></host>'

    def test_results_are_grouped_by_the_ranges_that_were_scanned(self):            # UX-29
        """The page put every address in an assumed /24, which is wrong for a /20, a /22 or a /25."""
        netscan.save_settings(self.conn, {'enabled': True, 'ranges': ['10.20.0.0/20', '192.168.7.0/25', '10.30.0.0/24']}, 'a')
        answers = {'10.20.0.0/20': ['10.20.5.9', '10.20.15.1'], '192.168.7.0/25': ['192.168.7.9', '172.16.0.4'], '10.30.0.0/24': []}    # the second sends one back from outside its range
        got = netscan.run(self.db, self.conn, None, 'a', wait=True, runner=lambda argv: '<nmaprun>' + ''.join(self.found(ip) for ip in answers[argv[-1]]) + '</nmaprun>')
        res = netscan.results(self.conn, got['scan_id'])
        self.assertEqual(res['ranges'], ['10.20.0.0/20', '192.168.7.0/25', '10.30.0.0/24'])
        self.assertEqual({h['ip']: h['range'] for h in res['hosts']},
                         {'10.20.5.9': '10.20.0.0/20', '10.20.15.1': '10.20.0.0/20', '192.168.7.9': '192.168.7.0/25', '172.16.0.4': None})
        nets = netscan.graph(self.conn, got['scan_id'])['networks']
        self.assertEqual([(n['network'], [h['ip'] for h in n['hosts']]) for n in nets],
                         [('10.20.0.0/20', ['10.20.5.9', '10.20.15.1']), ('192.168.7.0/25', ['192.168.7.9']), ('other', ['172.16.0.4'])])   # one /20, not two /24s, and the stray last

    def test_range_of_picks_the_narrowest_range_and_never_fails(self):             # UX-29
        r = ['10.0.0.0/8', '10.1.0.0/16', '192.168.1.0/24']
        self.assertEqual(netscan.range_of('10.1.2.3', r), '10.1.0.0/16')
        self.assertEqual(netscan.range_of('10.9.9.9', r), '10.0.0.0/8')
        self.assertIsNone(netscan.range_of('172.16.0.1', r))
        for odd in ('fd00::1', 'not an address', '', '10.0.0'):
            self.assertIsNone(netscan.range_of(odd, r), odd)
        self.assertIsNone(netscan.range_of('10.1.2.3', ['junk', '']))
        self.assertEqual(netscan.range_of('fd00::5', ['fd00::/64']), 'fd00::/64')            # an address matches only a range of its own family
        self.assertEqual(sorted(['b', '10.0.0.10', 'fd00::1', '10.0.0.9'], key=netscan._address_order), ['10.0.0.9', '10.0.0.10', 'fd00::1', 'b'])

    def test_a_stored_address_that_is_not_ipv4_does_not_break_the_results(self):   # UX-29
        netscan.save_settings(self.conn, {'enabled': True, 'ranges': ['10.0.0.0/24']}, 'a')
        got = netscan.run(self.db, self.conn, None, 'a', wait=True, runner=lambda argv: self.XML)
        self.conn.execute("INSERT INTO network_scan_hosts (scan_id, ip, ports_json) VALUES (:s, 'fd00::7', '[]')", {'s': got['scan_id']})
        res = netscan.results(self.conn, got['scan_id'])
        self.assertEqual([h['ip'] for h in res['hosts']], ['10.0.0.5', 'fd00::7'])          # int() of an octet raised on this before
        self.assertIsNone(res['hosts'][1]['range'])
        self.assertEqual(netscan.graph(self.conn, got['scan_id'])['networks'][-1]['network'], 'other')

    def test_a_failed_scan_says_so(self):
        netscan.save_settings(self.conn, {'enabled': True, 'ranges': ['10.0.0.0/24']}, 'a')
        def boom(argv):
            raise RuntimeError('nmap fell over')
        got = netscan.run(self.db, self.conn, None, 'a', wait=True, runner=boom)
        scan = netscan.results(self.conn, got['scan_id'])['scan']
        self.assertEqual((scan['status'], scan['error']), ('failed', 'nmap fell over'))

    def test_a_document_with_entities_is_refused(self):
        with self.assertRaises(ValueError):
            netscan.parse_xml('<!DOCTYPE x [<!ENTITY a "b">]><nmaprun/>')


class Traffic(unittest.TestCase):
    def series(self, rate=1000, n=20, last=None):
        rows, total = [], 0
        for i in range(n):
            total += (last if last is not None and i == n - 1 else rate) * 300
            rows.append((i * 300, total, total, 0, 0, 0, 0))
        return rows

    def test_a_reboot_is_not_a_rate(self):
        got = traffic.rates([(0, 100, 100, 0, 0, 0, 0), (300, 10, 10, 0, 0, 0, 0), (600, 310, 310, 0, 0, 0, 0)])
        self.assertEqual([x['at'] for x in got], [600])
        self.assertEqual(got[0]['rx_rate'], 1)

    def test_far_above_its_normal_stands_out(self):
        found = traffic.judge(traffic.rates(self.series(rate=1 << 21, last=1 << 26)))
        self.assertEqual({a['kind'] for a in found}, {'rate'})

    def test_a_small_jump_is_nobodys_emergency(self):
        self.assertEqual(traffic.judge(traffic.rates(self.series(rate=100, last=9000))), [])

    def test_not_enough_history_says_nothing(self):
        self.assertEqual(traffic.judge(traffic.rates(self.series(rate=1 << 21, n=5, last=1 << 26))), [])

    def test_errors_where_there_were_none(self):
        rows = self.series()
        rows[-1] = (*rows[-1][:5], 7, 0)
        self.assertEqual([a['kind'] for a in traffic.judge(traffic.rates(rows))], ['errors'])

    def test_it_records_nothing_until_turned_on(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Database(f'sqlite:///{tmp}/t.db')
            conn = db.connect()
            db.migrate(conn)
            row = {'iface': 'e', 'rx_bytes': 1, 'tx_bytes': 1, 'rx_drop': 0, 'tx_drop': 0, 'rx_error': 0, 'tx_error': 0}
            self.assertEqual(traffic.record(conn, 'h', [row]), 0)
            traffic.set_enabled(conn, True, 'a')
            self.assertEqual(traffic.record(conn, 'h', [row], 100), 1)
            self.assertEqual(traffic.record(conn, 'h', [row], 200), 1)
            self.assertEqual(traffic.stats(conn, 'h')[0]['iface'], 'e')
            conn.close()


class Api(Base):
    """The routes, signed in as a real account would be."""

    def setUp(self):
        super().setUp()
        env = mock.patch.dict(os.environ, {'STORAGEFORGE_VAULT_SECRET': 'a routers test secret, thrown away with its database'})
        env.start()
        self.addCleanup(env.stop)
        vault.Vault(self.db, self.conn, vault.secret_from_env()).init()
        self.conn.execute("INSERT INTO hosts (hostname, ip_address, ssh_host) VALUES ('dmzbox', '10.77.20.80', '10.77.20.80')")
        hid = self.conn.scalar("SELECT host_id FROM hosts WHERE hostname = 'dmzbox'")
        net = linux('10.77.20.80', 24, [('10.77.10.0/24', '10.77.20.1')], [web_listener(80), web_listener(443)])
        self.conn.execute('INSERT INTO host_network (host_id, data_json, updated_at) VALUES (:h, :d, 1)', {'h': hid, 'd': json.dumps(net['net'])})
        security._save_measurement(self.conn, 'dmzbox', 'infra', 1, 'measure', net['infra'])
        t = ros_tables()
        res = self.client.post('/api/devices', json={'name': 'gw', 'platform': 'routeros', 'address': '10.77.0.30', 'wan': ['ether2']})
        self.assertEqual(res.status_code, 200, res.get_data(as_text=True))
        d = netdevice.get(self.conn, 'gw')
        netdevice.store(self.db, self.conn, d, {'net': routeros.network(t), 'firewall': routeros.firewall(t), 'facts': routeros.facts(t, {'version': '7.25.1'}), 'os': 'RouterOS 7.25.1', 'identity': 'gw', 'config': None})

    def test_the_management_planner_starts_from_every_machine(self):
        f = self.client.get('/api/fleet').get_json()
        names = {m['name']: m for m in f['machines']}
        self.assertEqual((names['gw']['kind'], names['gw']['target'], names['gw']['nat']), ('device', 'routeros', 2))
        self.assertEqual((names['dmzbox']['kind'], names['dmzbox']['exposed']), ('host', 1))
        self.assertEqual(f['forwards'][0]['to_addr'], '10.77.20.80')
        self.assertEqual(self.client.get('/manage').status_code, 200)

    def test_exposure_and_the_map_know_about_the_router(self):
        rep = self.client.get('/api/exposure?host=dmzbox').get_json()['hosts'][0]
        self.assertEqual({i['port']: i['level'] for i in rep['items']}[443], 'any')
        got = self.client.get('/api/map/exposure?host=dmzbox&scope=any').get_json()['hosts'][0]
        self.assertEqual([i['port'] for i in got['items']], [443])
        g = self.client.get('/api/map?layers=network').get_json()
        self.assertEqual(next(n for n in g['nodes'] if n['kind'] == 'Host' and n['label'] == 'gw')['props']['device'], 'routeros')

    def test_compiling_shows_each_target_and_no_secret(self):
        key = 'C' * 43 + '='
        got = self.client.post('/api/dsl/compile', json={'dsl': f'/interface wireguard add name=wg0 private-key="{key}"', 'targets': ['routeros', 'networkd']}).get_json()
        self.assertNotIn(key, json.dumps(got))
        self.assertEqual(self.client.post('/api/dsl/compile', json={'dsl': '/nonsense add a=1'}).status_code, 400)

    def test_a_what_if_flips_on_the_rule_it_was_given(self):
        got = self.client.post('/api/dsl/whatif', json={'host': 'gw', 'dsl': '/ip firewall filter add chain=input in-interface=ether2 protocol=tcp dst-port=8291 action=accept', 'from': '198.51.100.9', 'to': '198.51.100.1', 'port': 8291}).get_json()
        self.assertEqual((got['before']['verdict'], got['changed']), ('blocked', False), 'it goes after the final drop, where RouterOS would append it')
        got = self.client.post('/api/dsl/whatif', json={'host': 'dmzbox', 'dsl': '/ip firewall filter add chain=input protocol=tcp dst-port=80 action=drop', 'from': '10.77.20.80', 'to': '10.77.20.80', 'port': 80}).get_json()
        self.assertTrue(got['changed'])

    def test_a_linux_hosts_rules_become_steps_in_changes(self):
        got = self.client.post('/api/dsl/stage', json={'host': 'dmzbox', 'dsl': '/ip firewall filter add chain=input protocol=tcp dst-port=8080 src-address=10.0.0.0/8 action=accept\n/ip firewall nat add chain=srcnat out-interface=e0 action=masquerade'}).get_json()
        self.assertTrue(got['ok'], got)
        self.assertEqual(got['tasks'], 1)
        self.assertIn('masquerade', got['left'][0])
        plan = changes.get_plan(self.conn, got['plan_id'])
        self.assertEqual((plan['tasks'][0]['type'], plan['tasks'][0]['params']['source']), ('fw-rule', '10.0.0.0/8'))
        self.assertEqual(self.client.post('/api/dsl/stage', json={'host': 'gw', 'dsl': '/ip firewall filter add chain=input action=drop'}).status_code, 400)

    def test_a_key_bound_for_reading_a_device_does_not_get_it_scanned(self):
        with vault.Vault(self.db, self.conn).unlock() as v:
            v.generate_key('net')
            v.bind('net', '10.77.0.30', 'scan', actions='scan')
        self.assertNotIn('gw', self.app.bound_hosts())
        self.assertNotIn('10.77.0.30', self.app.bound_hosts())

    def test_a_long_script_reaches_the_language_and_a_longer_one_is_refused_by_it(self):
        line = '/ip firewall filter add chain=forward protocol=tcp dst-port=80 action=accept comment="a rule among many"\n'
        big = line * 200
        self.assertGreater(len(big), 16384)
        self.assertEqual(self.client.post('/api/dsl/compile', json={'dsl': big, 'targets': ['nftables']}).status_code, 200)
        self.assertEqual(self.client.post('/api/devices/gw/report', json={'dsl': big}).status_code, 200)
        self.assertEqual(self.client.post('/api/dsl/stage', json={'host': 'dmzbox', 'dsl': big}).status_code, 200)
        got = self.client.post('/api/dsl/compile', json={'dsl': line * 2100})
        self.assertEqual(got.status_code, 400)

    def test_the_dsl_of_a_machine(self):
        self.assertIn('lan-to-dmz-web', self.client.get('/api/dsl/of?host=gw').get_json()['dsl'])

    def test_a_device_answers_for_itself(self):
        got = self.client.get('/api/devices/gw').get_json()
        self.assertEqual(got['facts']['version'], '7.25.1')
        self.assertIn('/ip firewall', got['dsl'])
        self.assertEqual(self.client.get('/api/devices/nobody').status_code, 400)
        self.assertEqual(self.client.get('/api/devices').get_json()['platforms']['cisco'], 'Cisco IOS')

    def test_deploys_are_refused_on_a_device(self):
        with self.assertRaisesRegex(deploy.DeployError, 'network device'):
            deploy.enroll(self.db, self.conn, 'gw', 'pw')

    def test_credentials_are_sealed_and_never_come_back(self):
        got = self.client.post('/api/devices/credentials', json={'name': 'sw', 'username': 'admin', 'password': 'hunter2', 'enable': 'en-secret'})
        self.assertEqual(got.status_code, 200)
        self.assertNotIn('hunter2', got.get_data(as_text=True))
        listed = self.client.get('/api/devices/credentials').get_data(as_text=True)
        self.assertIn('sw', listed)
        self.assertNotIn('hunter2', listed)
        self.assertNotIn(b'hunter2', b''.join(bytes(x) for r in self.conn.all('SELECT ciphertext FROM device_credentials') for x in r))
        self.assertTrue(self.client.delete('/api/devices/credentials/sw').get_json()['ok'])

    def test_the_scanner_routes_start_off(self):
        self.assertFalse(self.client.get('/api/netscan').get_json()['settings']['enabled'])
        self.assertEqual(self.client.post('/api/netscan/run', json={}).status_code, 400)
        self.assertEqual(self.client.get('/api/netscan/graph').get_json()['networks'], [])
        saved = self.client.post('/api/netscan/settings', json={'enabled': True, 'ranges': ['10.77.0.0/24']}).get_json()
        self.assertTrue(saved['enabled'])
        self.assertEqual(self.client.post('/api/netscan/settings', json={'ranges': ['8.8.8.0/24']}).status_code, 400)

    def test_traffic_routes(self):
        self.assertFalse(self.client.get('/api/traffic').get_json()['enabled'])
        self.assertTrue(self.client.post('/api/traffic/settings', json={'enabled': True}).get_json()['enabled'])

    def test_who_may_do_what(self):
        viewer = permissions.BUILTIN['viewer'][1]
        for method, path in (('GET', '/api/fleet'), ('GET', '/api/devices/gw'), ('POST', '/api/dsl/compile'), ('GET', '/api/netscan'), ('GET', '/api/traffic')):
            self.assertTrue(permissions.allows(viewer, method, path), path)
        for method, path in (('POST', '/api/devices'), ('POST', '/api/devices/gw/read'), ('POST', '/api/devices/gw/report'), ('POST', '/api/devices/changes/1/apply'), ('POST', '/api/devices/changes/1/confirm'), ('POST', '/api/netscan/run'), ('POST', '/api/netscan/settings'), ('POST', '/api/traffic/settings'), ('DELETE', '/api/devices/gw'), ('POST', '/api/dsl/stage'), ('POST', '/api/devices/credentials')):
            self.assertFalse(permissions.allows(viewer, method, path), path)
        self.assertEqual(permissions.required('POST', '/api/devices/changes/1/apply'), 'devices.apply')
        self.assertIn('devices.apply', permissions.HIGH_RISK)
        self.assertIn('netscan.run', permissions.HIGH_RISK)


class Devices(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Database(f'sqlite:///{self.tmp.name}/t.db')
        self.conn = self.db.connect()
        self.db.migrate(self.conn)

    def tearDown(self):
        self.conn.close()
        self.tmp.cleanup()

    def reading(self):
        t = ros_tables()
        return {'net': routeros.network(t), 'firewall': routeros.firewall(t), 'facts': routeros.facts(t, {'version': '7.25.1', 'identity': 'x', 'counters': [{'iface': 'ether1', 'rx_bytes': 1, 'tx_bytes': 1, 'rx_drop': 0, 'tx_drop': 0, 'rx_error': 0, 'tx_error': 0}]}), 'os': 'RouterOS 7.25.1', 'identity': 'x', 'config': None}

    def stored(self):
        d = netdevice.add(self.conn, {'name': 'gw', 'platform': 'routeros', 'address': '10.77.0.30'}, 'a')
        return d, netdevice.store(self.db, self.conn, d, self.reading())

    def test_what_a_device_may_be_called_and_reached_by(self):
        for body in ({'name': 'a b', 'platform': 'routeros', 'address': '1.1.1.1'}, {'name': 'a', 'platform': 'junos', 'address': '1.1.1.1'}, {'name': 'a', 'platform': 'cisco', 'address': '-oProxyCommand=x'}, {'name': 'a', 'platform': 'cisco', 'address': '1.1.1.1', 'port': 70000},
                     {'name': 'a', 'platform': 'cisco', 'address': '1.1.1.1', 'transport': 'telnet'}, {'name': 'a', 'platform': 'cisco', 'address': '1.1.1.1', 'username': 'a;b'}):
            with self.assertRaises(netdevice.DeviceError, msg=str(body)):
                netdevice.add(self.conn, body, 'a')

    def test_a_scanned_hosts_name_is_taken(self):
        self.conn.execute("INSERT INTO hosts (hostname) VALUES ('nas')")
        with self.assertRaisesRegex(netdevice.DeviceError, 'already a scanned host'):
            netdevice.add(self.conn, {'name': 'nas', 'platform': 'routeros', 'address': '1.1.1.1'}, 'a')

    def test_telnet_and_old_ciphers_are_called_out(self):
        netdevice.add(self.conn, {'name': 'sw', 'platform': 'cisco', 'address': '1.1.1.1', 'transport': 'telnet', 'credential': 'c'}, 'a')
        netdevice.add(self.conn, {'name': 'old', 'platform': 'cisco', 'address': '1.1.1.2', 'legacy': True}, 'a')
        said = netdevice.warnings(self.conn)
        self.assertEqual({w['device'] for w in said}, {'sw', 'old'})
        self.assertIn('Telnet', next(w['text'] for w in said if w['device'] == 'sw'))
        self.assertFalse(netdevice.get(self.conn, 'sw')['encrypted'])
        self.assertEqual(netdevice.get(self.conn, 'sw')['port'], 23)

    def test_a_reading_lands_where_a_hosts_does(self):
        from storageforge_index import inframeasure, netfacts
        _, res = self.stored()
        self.assertTrue(res['ok'])
        self.assertEqual(self.conn.scalar("SELECT os_info FROM hosts WHERE hostname = 'gw'"), 'RouterOS 7.25.1')
        self.assertEqual(len(netfacts.reading(self.conn, 'gw')['interfaces']), 7)
        self.assertEqual(inframeasure.reading(self.conn, 'gw')['firewall']['backends'], ['routeros'])
        self.assertEqual(netdevice.facts_of(self.conn, 'gw')['version'], '7.25.1')
        kinds = {r[0] for r in self.conn.all("SELECT kind FROM graph_nodes WHERE host = 'gw'")}
        self.assertTrue({'NIC', 'Bridge', 'VLAN'} <= kinds, kinds)
        self.assertEqual(len(netdevice.forwards(self.conn)), 1)

    def test_wan_is_what_was_said_then_what_it_says_then_its_default_route(self):
        net = {'routes': [{'dst': 'default', 'dev': 'e9'}]}
        self.assertEqual(netdevice.wan_of(net, {'wan': ['e2']}, ['e1']), ['e1'])
        self.assertEqual(netdevice.wan_of(net, {'wan': ['e2']}), ['e2'])
        self.assertEqual(netdevice.wan_of(net, {}), ['e9'])

    def test_a_failed_read_says_so_and_keeps_what_was_read(self):
        d, _ = self.stored()

        class Fails:
            def __enter__(self):
                raise OSError('no route')

            def __exit__(self, *a):
                return False
        netdevice.session, keep = (lambda *a, **k: Fails()), netdevice.session
        try:
            got = netdevice.read(self.db, self.conn, 'gw')
        finally:
            netdevice.session = keep
        self.assertFalse(got['ok'])
        self.assertEqual(netdevice.get(self.conn, 'gw')['last_error'], 'no route')
        self.assertIsNotNone(netdevice.get(self.conn, 'gw')['last_read_at'])

    def test_a_device_raises_no_alarm_for_not_being_a_host(self):
        from storageforge_index import alerts
        self.stored()
        self.assertEqual([k for k in alerts.problems(self.conn) if 'gw' in k], [])

    def test_telnet_is_an_alert_the_security_side_sees(self):
        from storageforge_index import alerts
        netdevice.add(self.conn, {'name': 'sw', 'platform': 'cisco', 'address': '1.1.1.1', 'transport': 'telnet', 'credential': 'c'}, 'a')
        found = alerts.problems(self.conn)
        self.assertIn('device-telnet:sw', found)
        self.assertIn('Telnet', found['device-telnet:sw'][2])

    def test_a_device_is_not_scanned_as_a_host(self):
        from storageforge_index import runner
        from storageforge_index.scanner import ScanOptions
        self.stored()
        for name in ('gw', '10.77.0.30'):
            with self.assertRaisesRegex(ValueError, 'network device'):
                runner.scan_via_vault(self.db, name, ScanOptions(roots=['/']))

    def test_removing_takes_all_of_it(self):
        self.stored()
        netdevice.remove(self.conn, 'gw')
        self.assertEqual(self.conn.scalar("SELECT count(*) FROM hosts WHERE hostname = 'gw'"), 0)
        self.assertEqual(self.conn.scalar("SELECT count(*) FROM graph_nodes WHERE host = 'gw'"), 0)
        self.assertEqual(self.conn.scalar("SELECT count(*) FROM security_measurements WHERE host = 'gw'"), 0)

    def test_a_report_finds_what_would_cut_storageforge_off(self):
        self.stored()
        rep = netdevice.report(self.db, self.conn, 'gw', '/ip firewall filter add chain=input in-interface=ether1 protocol=tcp dst-port=22 action=drop', 'a')
        self.assertFalse(rep['cuts_off']['cuts'], 'RouterOS appends, and the accept before it still matches')
        self.conn.execute("UPDATE security_measurements SET data_json = :d WHERE host = 'gw' AND kind = 'infra'", {'d': json.dumps({'firewall': {'readable': True, 'backends': ['routeros'], 'rules': [], 'nat': [], 'chains': routeros.firewall({'filter': [], 'nat': []})['chains'], 'policies': {}}})})
        rep = netdevice.report(self.db, self.conn, 'gw', '/ip firewall filter add chain=input in-interface=ether1 protocol=tcp dst-port=22 action=drop', 'a')
        self.assertTrue(rep['cuts_off']['cuts'])

    def test_what_can_not_be_expressed_can_not_be_applied(self):
        netdevice.add(self.conn, {'name': 'sw', 'platform': 'cisco', 'address': '1.1.1.1'}, 'a')
        rep = netdevice.report(self.db, self.conn, 'sw', '/ip firewall filter add chain=input action=drop', 'a')
        self.assertFalse(rep['can_apply'])
        with self.assertRaisesRegex(netdevice.DeviceError, 'express'):
            netdevice.apply(self.db, self.conn, rep['id'], 'a')

    def test_a_private_key_is_never_written_down(self):
        d, _ = self.stored()
        key = 'B' * 43 + '='
        rep = netdevice.report(self.db, self.conn, 'gw', f'/interface wireguard add name=wg0 private-key="{key}"', 'a')
        rows = self.conn.all('SELECT dsl, source, report_json FROM network_changes WHERE change_id = :i', {'i': rep['id']})[0]
        self.assertNotIn(key, json.dumps([str(x) for x in rows]))
        self.assertNotIn(key, json.dumps(rep))
        netdevice._SOURCES.clear()
        with self.assertRaisesRegex(netdevice.DeviceError, 'held a secret'):
            netdevice.apply(self.db, self.conn, rep['id'], 'a')

    def test_the_way_back_goes_on_before_the_change(self):
        self.stored()
        calls = []

        class Fake:
            def __enter__(self):
                return lambda c, timeout=None: calls.append(c) or 'ok'

            def __exit__(self, *a):
                return False
        rep = netdevice.report(self.db, self.conn, 'gw', '/ip firewall filter add chain=forward action=drop', 'a')
        netdevice.session, keep = (lambda *a, **k: Fake()), netdevice.session
        try:
            got = netdevice.apply(self.db, self.conn, rep['id'], 'a', rollback=120, hold=True)
            self.assertEqual(got['status'], 'unconfirmed')
            self.assertIn('backup/save', calls[0])
            self.assertTrue(any('scheduler/add' in c and 'interval=120s' in c for c in calls[:3]))
            at = calls.index('/ip firewall filter add chain=forward action=drop')
            self.assertGreater(at, 1)
            netdevice.read, keep_read = (lambda *a, **k: {'ok': True}), netdevice.read
            try:
                netdevice.confirm(self.db, self.conn, rep['id'])
            finally:
                netdevice.read = keep_read
            self.assertTrue(any('scheduler/remove' in c for c in calls[at:]))
            self.assertEqual(netdevice.change(self.conn, rep['id'])['status'], 'confirmed')
            with self.assertRaisesRegex(netdevice.DeviceError, 'confirmed'):
                netdevice.apply(self.db, self.conn, rep['id'], 'a')
        finally:
            netdevice.session = keep

    def test_a_refusal_part_way_leaves_the_timer_to_put_it_back(self):
        self.stored()
        calls = []

        class Fake:
            def __enter__(self):
                def run(c, timeout=None):
                    calls.append(c)
                    return 'failure: bad thing' if 'firewall' in c else 'ok'
                return run

            def __exit__(self, *a):
                return False
        rep = netdevice.report(self.db, self.conn, 'gw', '/ip firewall filter add chain=forward action=drop', 'a')
        netdevice.session, keep = (lambda *a, **k: Fake()), netdevice.session
        try:
            got = netdevice.apply(self.db, self.conn, rep['id'], 'a', hold=True)
        finally:
            netdevice.session = keep
        self.assertEqual(got['status'], 'rolling-back')
        self.assertFalse(any('scheduler/remove' in c for c in calls[2:]), 'the timer stays')

    def test_the_timer_has_limits(self):
        self.stored()
        rep = netdevice.report(self.db, self.conn, 'gw', '/ip firewall filter add chain=forward action=drop', 'a')
        for bad in (10, 99999, 'soon'):
            with self.assertRaisesRegex(netdevice.DeviceError, 'rollback'):
                netdevice.apply(self.db, self.conn, rep['id'], 'a', rollback=bad)

    def test_each_platforms_way_back(self):
        calls = []

        def run(c, timeout=None):
            calls.append(c)
            return 'planted applied ok'
        o = netdevice.OpenWrtApply(7)
        o.plant(run, 180)
        self.assertIn('sleep 180', calls[0])
        self.assertIn('cp -a /etc/config/.', calls[0])
        o.apply(run, {'text': 'uci set firewall.x=rule'})
        self.assertIn('uci set firewall.x=rule', calls[1])
        o.confirm(run)
        self.assertIn('rm -rf /tmp/sf-7', calls[2])
        calls.clear()
        c = netdevice.CiscoApply(7)
        c.plant(run, 300)
        self.assertIn('configure terminal revert timer 5', calls)
        c.confirm(run)
        self.assertIn('configure confirm', calls)
        calls.clear()
        with self.assertRaisesRegex(netdevice.DeviceError, 'no revert timer'):
            c.plant(lambda x, timeout=None: "% Invalid input detected at '^' marker." if 'revert' in x else '', 300)

    def test_a_password_only_goes_to_a_pinned_key(self):
        with self.assertRaisesRegex(ValueError, 'strict'):
            DirectTransport(host='h', user='u', password='p')
        t = DirectTransport(host='h', user='u', password='hunter2', strict=True, known_hosts='/x')
        try:
            argv = t.argv('/ip/address/print')
            self.assertIn('StrictHostKeyChecking=yes', argv)
            self.assertNotIn('BatchMode=yes', argv)
            self.assertNotIn('hunter2', ' '.join(argv))
            self.assertEqual(argv[-1], '/ip/address/print')
            with mock.patch('storageforge_index.keyinstall.askpass_path', return_value='/x'):
                self.assertEqual(t.env()['STORAGEFORGE_ASKPASS_SECRET'], 'hunter2')
        finally:
            t.close()

    def test_a_shell_device_gets_a_script_and_a_command_line_device_does_not(self):
        t = DirectTransport(host='h', user='u', posix=True)
        d = DirectTransport(host='h', user='u')
        try:
            self.assertTrue(t.argv('a\nb')[-1].startswith('sh -c'))
            with self.assertRaises(ValueError):
                d.argv('a\nb')
        finally:
            t.close()
            d.close()


if __name__ == '__main__':
    unittest.main()
