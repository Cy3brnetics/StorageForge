"""What a host's network files say (netconfig.py): netplan, systemd-networkd, NetworkManager and ifupdown, read from the text the scan
prints, put together under the system that keeps the network, shown on the map beside what the kernel has, and read by the network steps."""
import json
import unittest

from props import HAVE, given, settings, scaled
from storageforge_index import changes, infragraph, netconfig, netfacts

try:
    from test_clone import Db, blk
    from test_props_parsers import holds, mutated
except ImportError:      # run as tests.test_x from the project folder
    from tests.test_clone import Db, blk
    from tests.test_props_parsers import holds, mutated

NETPLAN = '''@@>file /etc/netplan/50-cloud-init.yaml
network:
  version: 2
  ethernets:
    eth0:
      dhcp4: true
    eth1: {}
    eth2: {}
@@>file /etc/netplan/60-storage.yaml
network:
  version: 2
  renderer: networkd
  ethernets:
    eth0:
      addresses: [10.0.5.2/24]
      routes:
        - to: 10.9.0.0/16
          via: 10.0.5.1
          metric: 50
  bonds:
    bond0:
      interfaces: [eth1, eth2]
      parameters: {mode: 802.3ad, mii-monitor-interval: 100}
      addresses:
        - 10.0.7.2/24
  vlans:
    vlan20:
      id: 20
      link: bond0
      dhcp4: false
@@>unreadable /etc/netplan/01-closed.yaml
'''

NETWORKD = '''@@>file /run/systemd/network/10-netplan-eth0.network
[Match]
Name=eth0

[Network]
DHCP=ipv4
Address=10.0.5.2/24
VLAN=eth0.30

[Route]
Destination=10.9.0.0/16
Gateway=10.0.5.1
Metric=50

[Route]
Gateway=10.0.5.254
@@>file /etc/systemd/network/20-eth1.network
[Match]
Name=eth1 eth2

[Network]
Bond=bond0
@@>file /etc/systemd/network/30-eth1-late.network
[Match]
Name=eth1
[Network]
Address=192.168.99.1/24
@@>file /etc/systemd/network/20-eth1.network.d/sf-dhcp.conf
[Network]
DHCP=yes
@@>file /etc/systemd/network/05-sf-bond0.netdev
[NetDev]
Name=bond0
Kind=bond
[Bond]
Mode=active-backup
@@>file /etc/systemd/network/40-vlan.netdev
[NetDev]
Name=eth0.30
Kind=vlan
[VLAN]
Id=30
'''

NM = r'''@@>con 7b0c8a3e-1111-4c1e-9d55-000000000001
connection.id:Wired connection 1
connection.interface-name:eth0
connection.type:802-3-ethernet
connection.master:
ipv4.method:manual
ipv4.addresses:10.0.5.2/24,10.0.5.3/24
ipv4.gateway:10.0.5.1
ipv4.routes:{ ip = 10.9.0.0/16, nh = 10.0.5.1, mt = 50 }
ipv6.method:auto
ipv6.addresses:fd00\:\:2/64
ipv6.gateway:--
@@>con 7b0c8a3e-1111-4c1e-9d55-000000000002
connection.id:sf-bond0
connection.interface-name:bond0
connection.type:bond
ipv4.method:auto
bond.options:mode=802.3ad,miimon=100
@@>con 7b0c8a3e-1111-4c1e-9d55-000000000003
connection.id:sf-bond0-eth1
connection.interface-name:eth1
connection.type:802-3-ethernet
connection.master:bond0
connection.slave-type:bond
'''

IFUPDOWN = '''@@>file /etc/network/interfaces
auto lo
iface lo inet loopback
source /etc/network/interfaces.d/*

auto eth0
iface eth0 inet static
    address 10.0.5.2
    netmask 255.255.255.0
    gateway 10.0.5.1
    up ip route add 10.9.0.0/16 via 10.0.5.1 metric 50
iface eth0 inet6 auto
@@>file /etc/network/interfaces.d/sf-bond-bond0
auto bond0
iface bond0 inet dhcp
    bond-slaves eth1 eth2
    bond-mode 802.3ad
    bond-miimon 100
@@>file /etc/network/interfaces.d/sf-addr-eth0
iface eth0 inet static
    address 10.0.6.2/24
'''


class Parsers(unittest.TestCase):
    def test_netplan_files_merge_in_name_order(self):
        got = netconfig.parse_netplan(NETPLAN)
        eth0, bond, vlan = (got['interfaces'][n] for n in ('eth0', 'bond0', 'vlan20'))
        self.assertEqual((eth0['dhcp4'], eth0['addresses'], eth0['source']), (True, ['10.0.5.2/24'], '/etc/netplan/50-cloud-init.yaml'))
        self.assertEqual(eth0['routes'], [{'to': '10.9.0.0/16', 'via': '10.0.5.1', 'metric': 50}])
        self.assertEqual((bond['kind'], bond['members'], bond['mode'], bond['addresses']), ('bond', ['eth1', 'eth2'], '802.3ad', ['10.0.7.2/24']))
        self.assertEqual((vlan['parent'], vlan['vlan_id'], vlan['dhcp4']), ('bond0', 20, False))
        self.assertEqual((got['renderer'], got['unreadable']), ('networkd', ['/etc/netplan/01-closed.yaml']))

    def test_networkd_takes_the_first_file_that_matches_with_its_drop_ins(self):
        got = netconfig.parse_networkd(NETWORKD)['interfaces']
        self.assertEqual((got['eth0']['dhcp4'], got['eth0']['dhcp6'], got['eth0']['addresses']), (True, False, ['10.0.5.2/24']))
        self.assertEqual(got['eth0']['routes'], [{'to': '10.9.0.0/16', 'via': '10.0.5.1', 'metric': 50}, {'to': 'default', 'via': '10.0.5.254', 'metric': None}])
        self.assertEqual(got['eth1']['source'], '/etc/systemd/network/20-eth1.network')
        self.assertEqual(got['eth1']['addresses'], [], 'the later file that also matches eth1 is not used')
        self.assertEqual((got['eth1']['dhcp4'], got['eth1']['dhcp6']), (True, True), 'the drop-in counts')
        self.assertEqual((got['bond0']['kind'], got['bond0']['mode'], got['bond0']['members']), ('bond', 'active-backup', ['eth1', 'eth2']))
        self.assertEqual((got['eth0.30']['kind'], got['eth0.30']['vlan_id'], got['eth0.30']['parent']), ('vlan', 30, 'eth0'))

    def test_networkmanager_connections(self):
        got = netconfig.parse_nm(NM)['interfaces']
        eth0 = got['eth0']
        self.assertEqual((eth0['dhcp4'], eth0['dhcp6']), (False, True))
        self.assertEqual(eth0['addresses'], ['10.0.5.2/24', '10.0.5.3/24', 'fd00::2/64'])
        self.assertEqual((eth0['gateway'], eth0['routes']), (['10.0.5.1'], [{'to': '10.9.0.0/16', 'via': '10.0.5.1', 'metric': 50}]))
        self.assertEqual((got['bond0']['mode'], got['bond0']['members'], got['bond0']['dhcp4']), ('802.3ad', ['eth1'], True))
        self.assertEqual(eth0['source'], 'NetworkManager: Wired connection 1')
        self.assertEqual(netconfig._nm_routes('10.8.0.0/16 10.0.5.1 20'), [{'to': '10.8.0.0/16', 'via': '10.0.5.1', 'metric': 20}], 'the older plain form')

    def test_ifupdown_stanzas_all_apply(self):
        got = netconfig.parse_ifupdown(IFUPDOWN)['interfaces']
        eth0 = got['eth0']
        self.assertEqual(eth0['addresses'], ['10.0.5.2/24', '10.0.6.2/24'])
        self.assertEqual((eth0['dhcp4'], eth0['dhcp6'], eth0['gateway']), (False, True, ['10.0.5.1']))
        self.assertEqual(eth0['routes'], [{'to': '10.9.0.0/16', 'via': '10.0.5.1', 'metric': 50}])
        self.assertEqual((got['bond0']['kind'], got['bond0']['members'], got['bond0']['mode'], got['bond0']['dhcp4']), ('bond', ['eth1', 'eth2'], '802.3ad', True))

    def test_the_manager_decides_whose_word_counts(self):
        sections = {'manager': 'netplan=1\nnm=\nnetworkd=active\n', 'netplan': NETPLAN, 'networkd': NETWORKD, 'nm': '', 'ifupdown': ''}
        got = netconfig.read(sections)
        self.assertEqual(got['manager'], 'netplan')
        self.assertEqual(got['interfaces']['eth0']['managed_by'], 'netplan')
        self.assertEqual(got['interfaces']['eth0.30']['managed_by'], 'networkd', 'what netplan rendered fills in')
        self.assertIn('/etc/netplan/01-closed.yaml', got['unreadable'])
        self.assertEqual(netconfig.read({**sections, 'manager': 'nm=running\n'})['manager'], 'nm')
        self.assertEqual(netconfig.read({'manager': 'ifup=1\n', 'ifupdown': IFUPDOWN})['manager'], 'ifupdown')
        self.assertEqual(netconfig.read({'manager': ''})['manager'], 'none')
        self.assertIsNone(netconfig.read({}), 'a reading from before these were read says nothing, not none')

    def test_netfacts_carries_it_and_the_script_prints_it(self):
        text = '@@link\n[]\n@@addr\n[]\n@@route\n[]\n@@neigh\n[]\n@@listen\n@@manager\nnetplan=1\n@@netplan\n' + NETPLAN + '@@end\n'
        self.assertEqual(netfacts.parse(text)['config']['interfaces']['bond0']['members'], ['eth1', 'eth2'])
        self.assertIn("echo '@@netplan'", netfacts.SCRIPT)
        self.assertLess(netfacts.SCRIPT.index('@@ifupdown'), netfacts.SCRIPT.index("'@@end'"))

    def test_odd_input_is_read_as_far_as_it_goes(self):
        for fn in (netconfig.parse_netplan, netconfig.parse_networkd, netconfig.parse_ifupdown):
            with self.subTest(fn.__name__):
                for text in ('@@>file /a\n', '@@>file /a\n[\n', '@@>file /a\nnetwork: 3\n', '@@>file /a\nnetwork:\n  ethernets: [1, 2]\n',
                             '@@>file /a\nnetwork:\n  ethernets:\n    eth0:\n      addresses: [{}, 3, [1]]\n      routes: [1, {to: [1]}]\n', '@@>file /a\n- !!python/object:os.system x\n'):
                    self.assertIsInstance(fn(text)['interfaces'], dict)
        self.assertEqual(netconfig.parse_nm('@@>con x\nipv4.routes:{ ip = , nh }\n')['interfaces'], {})


@unittest.skipUnless(HAVE, 'needs hypothesis (pip install hypothesis; CI has it)')
class Damaged(unittest.TestCase):
    """The fixtures above, damaged the way output gets damaged: each parser reads what it can and never throws."""

    @settings(max_examples=scaled(30, 800))
    @given(mutated(NETPLAN))
    def test_netplan(self, text):
        holds(self, 'netconfig.parse_netplan', netconfig.parse_netplan, text, False)

    @settings(max_examples=scaled(30, 800))
    @given(mutated(NETWORKD))
    def test_networkd(self, text):
        holds(self, 'netconfig.parse_networkd', netconfig.parse_networkd, text, False)

    @settings(max_examples=scaled(30, 800))
    @given(mutated(NM))
    def test_nm(self, text):
        holds(self, 'netconfig.parse_nm', netconfig.parse_nm, text, False)

    @settings(max_examples=scaled(30, 800))
    @given(mutated(IFUPDOWN))
    def test_ifupdown(self, text):
        holds(self, 'netconfig.parse_ifupdown', netconfig.parse_ifupdown, text, False)


class OnTheMap(unittest.TestCase):
    def test_a_node_says_what_its_files_say_and_a_configured_interface_that_is_not_there_shows(self):
        net = {'interfaces': [{'name': 'eth0', 'kind': 'ethernet', 'state': 'up', 'addresses': [{'ip': '10.0.5.2', 'prefix': 24}], 'master': None, 'parent': None}],
               'routes': [], 'config': netconfig.read({'manager': 'netplan=1\n', 'netplan': NETPLAN})}
        nodes, _ = infragraph.build('nas', net, None, [], [], {}, set())
        eth0 = next(n for n in nodes.values() if n['id'] == 'nic:nas:eth0')
        self.assertEqual(eth0['props']['configured_in'], '/etc/netplan/50-cloud-init.yaml')
        self.assertEqual(eth0['props']['configured_dhcp'], 'IPv4')
        self.assertNotIn('not_live', eth0['props'])
        bond = nodes['nic:nas:bond0']
        self.assertEqual((bond['kind'], bond['confidence'], bond['props']['state']), ('Bond', 'inferred', 'configured, not present'))
        self.assertEqual(bond['props']['not_live'], ['10.0.7.2/24'])


class StepsReadIt(Db):
    def test_the_address_step_names_the_file_that_sets_the_interface_up(self):
        self.add('nas', {'collected_at': '2026-11-20T00:00:00+00:00', 'lsblk': blk(('sda', 'S1', 'ext4', 'r'))}, [('/', 'ext4', '/dev/sda1', 3, 'rw')])
        hid = self.conn.scalar("SELECT host_id FROM hosts WHERE hostname = 'nas'")
        net = netfacts.parse('@@link\n[{"ifname": "eth0", "link_type": "ether", "operstate": "UP"}]\n@@addr\n[]\n@@route\n[]\n@@neigh\n[]\n@@listen\n'
                             '@@manager\nifup=1\n@@ifupdown\n' + IFUPDOWN + '@@end\n')
        self.conn.execute('INSERT INTO host_network (host_id, data_json, scan_id, updated_at) VALUES (:h, :d, NULL, 1)', {'h': hid, 'd': json.dumps(net)})
        r = changes.check(self.conn, changes.normalize({'name': 'p', 'tasks': [{'type': 'net-address', 'host': 'nas', 'params': {'iface': 'eth0', 'address': '10.0.8.2/24'}}]}))
        self.assertIn(('note', 'eth0 is set up in /etc/network/interfaces (ifupdown); the step writes a file of its own beside it'),
                      [(i['level'], i['text']) for i in r['tasks'][0]['items']])


if __name__ == '__main__':
    unittest.main()
