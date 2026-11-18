"""Private networks (roadmap section 2): the naming, and each tool's status read into one shape. The texts here are what the tools
print, cut down. What must hold: a network is named for whose it is, never guessed as Tailscale; no reader raises on anything a host
could send; and no user or account name is kept."""
import json
import unittest

from storageforge_index import overlays

TAILSCALE = json.dumps({
    'Version': '1.82.0', 'BackendState': 'Running', 'MagicDNSSuffix': 'tail1234.ts.net',
    'Self': {'HostName': 'nas', 'DNSName': 'nas.tail1234.ts.net.', 'OS': 'linux', 'TailscaleIPs': ['100.101.1.1', 'fd7a:115c:a1e0::1'], 'PublicKey': 'nodekey:aa', 'Online': True,
             'UserID': 77, 'PrimaryRoutes': ['10.42.0.0/24']},
    'Peer': {
        'nodekey:bb': {'HostName': 'pi', 'OS': 'linux', 'TailscaleIPs': ['100.101.1.2'], 'PublicKey': 'nodekey:bb', 'Online': True, 'CurAddr': '10.42.0.9:41641', 'Relay': 'fra', 'UserID': 77},
        'nodekey:cc': {'HostName': 'laptop', 'OS': 'macOS', 'TailscaleIPs': ['100.101.1.3'], 'PublicKey': 'nodekey:cc', 'Online': True, 'CurAddr': '', 'Relay': 'fra', 'ExitNodeOption': True},
        'nodekey:dd': {'HostName': 'old', 'OS': 'windows', 'TailscaleIPs': ['100.101.1.4'], 'PublicKey': 'nodekey:dd', 'Online': False, 'LastSeen': '2026-10-01T10:00:00Z'}},
    'User': {'77': {'LoginName': 'gabe@example.com', 'DisplayName': 'Gabe'}}})

NETBIRD = 'Warning: daemon is newer than the client\n' + json.dumps({
    'peers': {'total': 2, 'connected': 1, 'details': [
        {'fqdn': 'pi.netbird.selfhosted', 'netbirdIp': '100.92.0.2', 'publicKey': 'pk-pi', 'status': 'Connected', 'connectionType': 'P2P', 'lastWireguardHandshake': '2026-11-18T01:00:00Z', 'networks': ['192.168.7.0/24']},
        {'fqdn': 'desk.netbird.selfhosted', 'netbirdIp': '100.92.0.3', 'publicKey': 'pk-desk', 'status': 'Disconnected', 'connectionType': ''}]},
    'management': {'url': 'https://netbird.lab:443', 'connected': True}, 'signal': {'url': 'https://netbird.lab:443', 'connected': True},
    'netbirdIp': '100.92.0.1/16', 'publicKey': 'pk-nas', 'fqdn': 'nas.netbird.selfhosted'})

ZT_INFO = json.dumps({'address': 'a1b2c3d4e5', 'online': True, 'version': '1.14.2'})
ZT_NETWORKS = json.dumps([{'nwid': '8056c2e21c000001', 'name': 'lab', 'status': 'OK', 'type': 'PRIVATE', 'portDeviceName': 'ztabcdef12', 'assignedAddresses': ['10.147.17.5/24', 'fd80::5/88'],
                           'routes': [{'target': '10.147.17.0/24', 'via': None}, {'target': '192.168.9.0/24', 'via': '10.147.17.1'}]}])
ZT_PEERS = json.dumps([{'address': 'ffeeddccbb', 'role': 'LEAF', 'latency': 4, 'paths': [{'active': True, 'address': '10.42.0.9/9993'}]},
                       {'address': '1122334455', 'role': 'LEAF', 'latency': -1, 'paths': []},
                       {'address': '778cde7190', 'role': 'PLANET', 'latency': 30, 'paths': [{'active': True, 'address': '103.195.103.66/9993'}]}])

HEADSCALE = json.dumps([{'id': 1, 'name': 'nas', 'given_name': 'nas', 'ip_addresses': ['100.64.0.1', 'fd7a:115c:a1e0::1'], 'node_key': 'nodekey:aa', 'online': True, 'user': {'name': 'gabe'}, 'approved_routes': ['10.42.0.0/24']},
                        {'id': 2, 'name': 'pi', 'given_name': 'pi', 'ip_addresses': ['100.64.0.2'], 'node_key': 'nodekey:bb', 'online': False, 'user': {'name': 'gabe'}}])

OPENVPN = """OpenVPN CLIENT LIST
Updated,2026-11-18 01:00:00
Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since
laptop,203.0.113.7:51820,12345,67890,2026-11-18 00:10:00
branch,198.51.100.4:1194,1,2,2026-11-17 09:00:00
ROUTING TABLE
Virtual Address,Common Name,Real Address,Last Ref
10.8.0.2,laptop,203.0.113.7:51820,2026-11-18 00:59:00
10.8.0.6,branch,198.51.100.4:1194,2026-11-18 00:59:00
192.168.50.0/24,branch,198.51.100.4:1194,2026-11-18 00:59:00
GLOBAL STATS
Max bcast/mcast queue length,0
END
"""


class Naming(unittest.TestCase):
    def test_an_interface_is_named_for_whose_it_is(self):
        for name, network in (('tailscale0', 'tailscale'), ('wt0', 'netbird'), ('ztabcdef12', 'zerotier'), ('nebula1', 'nebula'), ('nm-lab', 'netmaker'), ('wg0', 'wireguard'),
                              ('wg-site', 'wireguard'), ('sf0', 'storageforge'), ('tun0', 'openvpn'), ('ziti0', 'openziti'), ('vti1', 'ipsec'), ('eth0', None), ('br0', None), ('enp3s0', None), ('', None)):
            with self.subTest(name):
                self.assertEqual(overlays.network_of(name), network)

    def test_a_netbird_address_is_not_called_tailscale(self):
        """The bug this replaces: any address in 100.64.0.0/10 was Tailscale."""
        self.assertEqual(overlays.network_of('wt0', '100.92.0.1'), 'netbird')
        self.assertEqual(overlays.label('netbird'), 'NetBird')
        self.assertEqual(overlays.network_of('tailscale0', '100.101.1.1'), 'tailscale')
        self.assertEqual(overlays.network_of('eth9', '100.92.0.1/16'), 'overlay', 'an address in the shared range on an interface that says nothing is not guessed at')
        self.assertEqual(overlays.label('overlay'), 'a private network')
        self.assertIsNone(overlays.network_of('eth0', '10.42.0.5'))
        self.assertIsNone(overlays.network_of('eth0', 'not an address'))
        self.assertEqual(overlays.label('something new'), 'a private network')


class Readers(unittest.TestCase):
    def test_tailscale(self):
        got = overlays.tailscale(TAILSCALE)
        self.assertEqual((got['network'], got['state'], got['control']), ('tailscale', 'connected', 'tail1234.ts.net'))
        self.assertEqual(got['self'], {'name': 'nas', 'addresses': ['100.101.1.1', 'fd7a:115c:a1e0::1'], 'key': 'nodekey:aa'})
        self.assertEqual(got['routes'], ['10.42.0.0/24'])
        by = {p['name']: p for p in got['peers']}
        self.assertEqual((by['pi']['online'], by['pi']['direct']), (True, True))
        self.assertEqual((by['laptop']['online'], by['laptop']['direct'], by['laptop']['offers_exit']), (True, False, True), 'online with no address of its own: relayed')
        self.assertEqual((by['old']['online'], by['old']['direct'], by['old']['last_seen']), (False, None, '2026-10-01T10:00:00Z'))
        self.assertNotIn('gabe', json.dumps(got), 'who owns a peer is not kept')

    def test_netbird_with_a_warning_before_its_json(self):
        got = overlays.netbird(NETBIRD)
        self.assertEqual((got['network'], got['state'], got['control']), ('netbird', 'connected', 'https://netbird.lab:443'))
        self.assertEqual(got['self']['addresses'], ['100.92.0.1'], 'without the prefix length')
        pi, desk = got['peers']
        self.assertEqual((pi['name'], pi['addresses'], pi['online'], pi['direct'], pi['routes']), ('pi.netbird.selfhosted', ['100.92.0.2'], True, True, ['192.168.7.0/24']))
        self.assertEqual((desk['online'], desk['direct']), (False, None))

    def test_zerotier_keeps_this_sites_peers_and_not_the_root_servers(self):
        got = overlays.zerotier(ZT_INFO, ZT_NETWORKS, ZT_PEERS)
        self.assertEqual((got['state'], got['self']['name'], got['self']['addresses']), ('connected', 'a1b2c3d4e5', ['10.147.17.5', 'fd80::5']))
        self.assertEqual(got['routes'], ['10.147.17.0/24', '192.168.9.0/24'])
        self.assertEqual(got['networks'][0] | {'addresses': None}, {'id': '8056c2e21c000001', 'name': 'lab', 'status': 'OK', 'private': True, 'interface': 'ztabcdef12', 'addresses': None})
        self.assertEqual([(p['name'], p['online'], p['latency_ms']) for p in got['peers']], [('ffeeddccbb', True, 4), ('1122334455', False, None)])
        self.assertEqual(overlays.zerotier(ZT_INFO, '', '')['peers'], [], 'joined to nothing is still an answer')

    def test_headscale_lists_every_node_it_knows(self):
        got = overlays.headscale(HEADSCALE)
        self.assertEqual((got['network'], got['state'], got['control']), ('tailscale', 'control server', 'headscale'))
        self.assertEqual([(p['name'], p['addresses'][0], p['online']) for p in got['peers']], [('nas', '100.64.0.1', True), ('pi', '100.64.0.2', False)])
        self.assertEqual(got['peers'][0]['routes'], ['10.42.0.0/24'])
        self.assertNotIn('gabe', json.dumps(got))

    def test_openvpn_gives_each_client_its_address_and_the_network_behind_it(self):
        got = overlays.openvpn(OPENVPN)
        by = {p['name']: p for p in got['peers']}
        self.assertEqual((by['laptop']['addresses'], by['laptop']['routes']), (['10.8.0.2'], []))
        self.assertEqual((by['branch']['addresses'], by['branch']['routes']), (['10.8.0.6'], ['192.168.50.0/24']))
        self.assertNotIn('203.0.113.7', json.dumps(got), 'where a client connects from is not kept')

    def test_nothing_a_host_could_print_makes_a_reader_raise(self):
        junk = ['', None, 5, 'not json', '{', '[]', '{}', '[1, 2]', '{"Peer": [1], "Self": 3}', '{"peers": {"details": [1, "x", {"netbirdIp": 7}]}, "management": 4}',
                '[' * 100000, '{"Peer": {"k": {"TailscaleIPs": ["999.1.1.1", 5, null], "PrimaryRoutes": "x", "HostName": 9}}}', '[{"ip_addresses": "100.64.0.1"}, 4]',
                'OpenVPN CLIENT LIST\n,,,,\nROUTING TABLE\n,\n', json.dumps({'Peer': {str(i): {'HostName': 'h' * 5000} for i in range(3000)}})]
        for text in junk:
            for reader in (overlays.tailscale, overlays.netbird, overlays.headscale, overlays.openvpn, lambda t: overlays.zerotier(t, t, t)):
                got = reader(text)
                self.assertIsInstance(got, dict)
                self.assertIn('network', got)
                json.dumps(got)

    def test_what_is_read_is_cut_to_a_size(self):
        got = overlays.tailscale(json.dumps({'Peer': {str(i): {'HostName': 'h' * 300, 'TailscaleIPs': ['100.64.0.1'] * 70} for i in range(2100)}}))
        self.assertEqual(len(got['peers']), overlays.MAX_PEERS)
        self.assertEqual((len(got['peers'][0]['name']), len(got['peers'][0]['addresses'])), (overlays.MAX_TEXT, overlays.MAX_LIST))
        self.assertEqual(overlays.netbird('{' + ' ' * (overlays.MAX_INPUT + 1) + '}')['error'], 'more than it should ever print')


if __name__ == '__main__':
    unittest.main()
