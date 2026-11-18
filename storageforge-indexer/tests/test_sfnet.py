"""StorageForge's own network (roadmap section 2.1): the address plan, who peers with whom, and what a scan confirms. No host and no
database here. What must hold: the range meets nothing in use; an address is one host's for good; a peer is trusted for its own
address only; a revoked key comes off every member; and a key nobody put on record is seen."""
import base64
import unittest

from storageforge_index import sfnet


def key(n: int) -> str:
    return base64.b64encode(bytes([n]) * 32).decode()


def iface(own: int, peers: dict) -> list[dict]:
    """What a scan reads from `wg show sf0`."""
    return [{'name': 'wg0', 'public_key': key(200), 'peers': [{'public_key': key(201), 'allowed_ips': ['10.8.0.2/32']}]},
            {'name': 'sf0', 'public_key': key(own), 'listen_port': 51903, 'peers': [{'public_key': key(k), 'allowed_ips': a} for k, a in peers.items()]}]


class Range(unittest.TestCase):
    def test_the_first_range_that_meets_nothing_in_use(self):
        self.assertEqual(sfnet.pick_range([]), '10.203.0.0/20')
        self.assertEqual(sfnet.pick_range(['10.203.4.0/24', '192.168.1.0/24']), '10.87.64.0/20')
        self.assertEqual(sfnet.pick_range(['10.0.0.0/8']), '172.29.160.0/20', 'a site that uses all of 10/8')
        self.assertEqual(sfnet.pick_range(['10.203.1.7', 'garbage', '', None, 'fd00::/8', '0.0.0.0/0']), '10.87.64.0/20', 'a single address counts; a default route and junk do not')
        with self.assertRaises(sfnet.NetworkError):
            sfnet.pick_range(['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'])

    def test_a_range_given_by_hand_is_private_and_never_the_shared_one(self):
        self.assertEqual(sfnet.new(range_='10.55.0.0/24')['range'], '10.55.0.0/24')
        for bad in ('100.64.0.0/16', '100.100.0.0/24', '8.8.8.0/24', '10.0.0.0/8', '10.0.0.0/30', 'fd00::/64', 'x'):
            with self.subTest(bad), self.assertRaises(sfnet.NetworkError):
                sfnet.new(range_=bad)
        with self.assertRaises(sfnet.NetworkError):
            sfnet.new(topology='ring')


class Members(unittest.TestCase):
    def net(self, topology='mesh'):
        n = sfnet.new(topology=topology)
        for i, (host, endpoint, hub) in enumerate((('ctl', '10.42.0.2', True), ('nas', '10.42.0.10', False), ('pi', None, False)), 1):
            sfnet.join(n, host, endpoint, hub)
            sfnet.set_key(n, host, key(i))
        return n

    def test_addresses_are_given_in_order_and_never_to_a_second_host(self):
        n = self.net()
        self.assertEqual([m['address'] for m in n['members']], ['10.203.0.1', '10.203.0.2', '10.203.0.3'])
        self.assertEqual(sfnet.join(n, 'nas', '10.42.0.11')['address'], '10.203.0.2', 'joining again keeps the address')
        sfnet.revoke(n, 'nas')
        self.assertEqual(sfnet.join(n, 'new')['address'], '10.203.0.4', 'a revoked host\'s address is not handed on')
        back = sfnet.join(n, 'nas')
        self.assertEqual((back['address'], back['state'], back['public_key']), ('10.203.0.5', 'pending', None), 'and it comes back as a new member')
        self.assertIn(key(2), [m['public_key'] for m in n['members'] if m['state'] == 'revoked'], 'its old key stays on record as revoked')

    def test_a_small_range_runs_out_and_says_so(self):
        n = sfnet.new(range_='10.55.0.0/28')
        for i in range(14):
            sfnet.join(n, f'h{i}')
        with self.assertRaises(sfnet.NetworkError) as got:
            sfnet.join(n, 'one-too-many')
        self.assertIn('no address left', str(got.exception))

    def test_a_key_is_one_hosts_and_does_not_change_without_a_rotation(self):
        n = self.net()
        for bad in ('short', key(1)[:-1] + '!', None, key(1) + 'A'):
            with self.subTest(bad), self.assertRaises(sfnet.NetworkError):
                sfnet.set_key(n, 'pi', bad)
        sfnet.join(n, 'late')
        with self.assertRaises(sfnet.NetworkError):
            sfnet.set_key(n, 'late', key(2))                         # nas's key
        with self.assertRaises(sfnet.NetworkError):
            sfnet.set_key(n, 'nas', key(9))                          # a different key on an active member
        self.assertEqual(sfnet.set_key(n, 'nas', key(2))['state'], 'active', 'the same key again is nothing')
        with self.assertRaises(sfnet.NetworkError):
            sfnet.set_key(n, 'stranger', key(9))

    def test_in_a_mesh_every_peer_is_trusted_for_its_own_address_only(self):
        n = self.net()
        nas = sfnet.desired_peers(n, 'nas')
        self.assertEqual([(p['host'], p['allowed'], p['endpoint'], p['keepalive']) for p in nas],
                         [('ctl', ['10.203.0.1/32'], '10.42.0.2:51903', None), ('pi', ['10.203.0.3/32'], None, None)])
        pi = sfnet.desired_peers(n, 'pi')
        self.assertEqual([(p['host'], p['keepalive']) for p in pi], [('ctl', 25), ('nas', 25)], 'a host nobody can call keeps its own paths open')
        self.assertEqual(sfnet.desired_peers(n, 'nobody'), [])

    def test_in_a_hub_network_spokes_meet_at_the_hub(self):
        n = self.net('hub')
        self.assertEqual([(p['host'], p['allowed']) for p in sfnet.desired_peers(n, 'nas')], [('ctl', ['10.203.0.0/20'])])
        self.assertEqual([(p['host'], p['allowed']) for p in sfnet.desired_peers(n, 'ctl')], [('nas', ['10.203.0.2/32']), ('pi', ['10.203.0.3/32'])],
                         'the hub trusts each spoke for its own address, so a spoke cannot answer for another')


class Steps(unittest.TestCase):
    def setUp(self):
        self.n = Members.net(self)

    def test_a_new_host_gets_its_peers_and_a_settled_one_gets_nothing(self):
        got = sfnet.steps(self.n, 'nas', iface(2, {}))
        self.assertEqual([(s['kind'], s['params']['pubkey'], s['params']['allowed'], s['params']['endpoint'], s['params']['state']) for s in got],
                         [('wg-peer', key(1), '10.203.0.1/32', '10.42.0.2:51903', 'present'), ('wg-peer', key(3), '10.203.0.3/32', '', 'present')])
        self.assertTrue(all(s['params']['iface'] == 'sf0' for s in got))
        self.assertEqual(sfnet.steps(self.n, 'nas', iface(2, {1: ['10.203.0.1/32'], 3: ['10.203.0.3/32']})), [])
        self.assertEqual(len(sfnet.steps(self.n, 'nas', None)), 2, 'no scan yet: everything is to be written')

    def test_a_peer_trusted_for_more_than_its_address_is_put_right(self):
        got = sfnet.steps(self.n, 'nas', iface(2, {1: ['10.203.0.1/32'], 3: ['10.203.0.3/32', '10.42.0.0/24']}))
        self.assertEqual([(s['params']['pubkey'], s['params']['allowed'], s['params']['state']) for s in got], [(key(3), '10.203.0.3/32', 'present')])

    def test_a_revoked_host_comes_off_every_member_and_so_does_a_peer_nobody_asked_for(self):
        sfnet.revoke(self.n, 'pi')
        got = sfnet.steps(self.n, 'nas', iface(2, {1: ['10.203.0.1/32'], 3: ['10.203.0.3/32'], 77: ['0.0.0.0/0']}))
        self.assertEqual([(s['params']['pubkey'], s['params']['state'], s['why']) for s in got],
                         [(key(3), 'absent', 'pi is no longer on the network'), (key(77), 'absent', 'a peer nobody asked for')])
        self.assertEqual(sfnet.steps(self.n, 'pi', iface(3, {1: ['10.203.0.1/32']}))[0]['params']['state'], 'absent', 'and the revoked host loses its peers too')
        other = sfnet.steps(self.n, 'nas', iface(2, {1: ['10.203.0.1/32']}))
        self.assertEqual(other, [], 'wg0, which is not ours, is never touched')

    def test_a_rotation_adds_the_new_key_everywhere_before_the_old_one_goes(self):
        sfnet.rotate(self.n, 'ctl', key(11))
        during = sfnet.steps(self.n, 'nas', iface(2, {1: ['10.203.0.1/32'], 3: ['10.203.0.3/32']}))
        self.assertEqual([(s['params']['pubkey'], s['params']['allowed'], s['params']['state']) for s in during], [(key(11), '', 'present')], 'known, and carrying nothing yet')
        sfnet.rotated(self.n, 'ctl')
        after = sfnet.steps(self.n, 'nas', iface(2, {1: ['10.203.0.1/32'], 11: [], 3: ['10.203.0.3/32']}))
        self.assertEqual([(s['params']['pubkey'], s['params']['allowed'], s['params']['state']) for s in after], [(key(11), '10.203.0.1/32', 'present'), (key(1), '', 'absent')])
        with self.assertRaises(sfnet.NetworkError):
            sfnet.rotate(self.n, 'nas', key(3))                      # pi's key
        with self.assertRaises(sfnet.NetworkError):
            sfnet.rotated(self.n, 'nas')


class Confirm(unittest.TestCase):
    def setUp(self):
        self.n = Members.net(self)

    def test_peers_are_confirmed_by_key_and_address(self):
        got = sfnet.confirm(self.n, {'ctl': iface(1, {2: ['10.203.0.2/32'], 3: ['10.203.0.3/32']}), 'nas': iface(2, {1: ['10.203.0.1/32']}), 'pi': [{'name': 'wg0', 'public_key': key(200), 'peers': []}]})
        self.assertEqual(got['ctl'], {'state': 'ok', 'confirmed': ['nas', 'pi'], 'missing': [], 'unknown': [], 'key_changed': False})
        self.assertEqual((got['nas']['state'], got['nas']['confirmed'], got['nas']['missing']), ('differs', ['ctl'], ['pi']))
        self.assertEqual((got['pi']['state'], got['pi']['missing']), ('no interface', ['ctl', 'nas']))
        self.assertEqual(sfnet.confirm(self.n, {})['ctl']['state'], 'not scanned')

    def test_a_key_nobody_put_on_record_and_a_host_whose_own_key_changed_are_seen(self):
        got = sfnet.confirm(self.n, {'ctl': iface(1, {2: ['10.203.0.2/32'], 3: ['10.203.0.3/32'], 66: ['10.203.0.9/32']}), 'nas': iface(42, {1: ['10.203.0.1/32'], 3: ['10.203.0.3/32']})})
        self.assertEqual((got['ctl']['state'], got['ctl']['unknown']), ('differs', [key(66)]))
        self.assertEqual((got['nas']['state'], got['nas']['key_changed']), ('differs', True))
        sfnet.rotate(self.n, 'nas', key(42))
        self.assertFalse(sfnet.confirm(self.n, {'nas': iface(42, {1: ['10.203.0.1/32'], 3: ['10.203.0.3/32']})})['nas']['key_changed'], 'a planned rotation is not a finding')

    def test_a_peer_with_the_right_key_and_the_wrong_addresses_is_not_confirmed(self):
        got = sfnet.confirm(self.n, {'nas': iface(2, {1: ['10.203.0.0/20'], 3: ['10.203.0.3/32']})})
        self.assertEqual((got['nas']['confirmed'], got['nas']['missing']), (['pi'], ['ctl']))


if __name__ == '__main__':
    unittest.main()
