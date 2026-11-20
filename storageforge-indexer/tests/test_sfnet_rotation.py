"""A member's key rotated through plans (roadmap section 2.1), first against readings made up here, then with real WireGuard.

What must hold: a private key never leaves the host that made it, in no plan, script, output, reading or stored record; a key is
taken from a reading only when a host joins and when a person asked for a rotation, once each; any other new key is reported and
left; and a host switches only when every peer already knows the key it switches to.

RealWireGuard runs on the machines of wgworld.py: each host is a network namespace with a real `sf0`, on one LAN. The generated
step functions run there unchanged, the readings are taken with the lines a scan runs, and whether two hosts can talk is asked of
the kernel with a ping across the network.
"""
import json
import shutil
import tempfile
import time
import unittest

import dbfactory
import wgworld
from storageforge_index import alerts, changes, server, sfnet, sfnetwork, steps_infra, users
from test_sfnet import key

PW = 'correct horse battery staple 9'
HOSTS = (('ctl', '10.42.0.2'), ('nas', '10.42.0.10'), ('pi', '10.42.0.20'))


def store(conn, host, wireguard):
    conn.execute("DELETE FROM security_measurements WHERE host = :h AND kind = 'infra'", {'h': host})
    conn.execute("INSERT INTO security_measurements (host, kind, measured_at, via, data_json) VALUES (:h, 'infra', :t, 'controller', :d)",
                 {'h': host, 't': int(time.time()), 'd': json.dumps({'access': {'wireguard': wireguard}})})


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.db = dbfactory.make(self, f'{self.tmp}/t.db')
        self.conn = self.db.connect()
        self.addCleanup(self.conn.close)
        self.db.migrate(self.conn)
        for name, address in HOSTS:
            self.conn.execute('INSERT INTO hosts (hostname, ip_address, ssh_host) VALUES (:h, :a, :a)', {'h': name, 'a': address})

    def member(self, host):
        return sfnet.member(sfnetwork.load(self.conn), host)

    def row(self, host):
        return next(m for m in sfnetwork.status(self.conn)['members'] if m['host'] == host)


class Rotation(Base):
    """ctl is 10.203.0.1 with key 1, nas .2 with key 2, pi .3 with key 3, every peer in place. nas rotates to key 22."""
    ADDR = {1: '10.203.0.1/32', 2: '10.203.0.2/32', 3: '10.203.0.3/32'}

    def read(self, host, own, peers, waiting=None):
        iface = {'name': 'sf0', 'public_key': key(own), 'listen_port': 51903, 'peers': [{'public_key': key(k), 'allowed_ips': a} for k, a in peers.items()]}
        if waiting:
            iface['next_public_key'] = key(waiting)
        store(self.conn, host, [iface])

    def setUp(self):
        super().setUp()
        sfnetwork.create(self.conn, 'gabe')
        for i, (host, _) in enumerate(HOSTS, 1):
            sfnetwork.join(self.conn, host, 'gabe')
            self.read(host, i, {})
        sfnetwork.observe(self.conn)
        self.settled()

    def settled(self, nas=2):
        self.read('ctl', 1, {nas: [self.ADDR[2]], 3: [self.ADDR[3]]})
        self.read('nas', nas, {1: [self.ADDR[1]], 3: [self.ADDR[3]]})
        self.read('pi', 3, {1: [self.ADDR[1]], nas: [self.ADDR[2]]})

    def tasks(self):
        return [(t['host'], t['type'], t['params'].get('phase') or t['params'].get('state'), t['params'].get('pubkey'), t['params'].get('allowed')) for t in sfnetwork.tasks(self.conn)]

    def test_a_rotation_is_three_plans_and_the_host_switches_only_when_every_peer_knows_the_key(self):
        self.assertEqual(self.tasks(), [])
        sfnetwork.rotate(self.conn, 'NAS', 'gabe')
        self.assertEqual(self.tasks(), [('nas', 'wg-rotate', 'prepare', None, None)], 'first the host makes a second pair')
        self.assertEqual(self.row('nas')['rotation'], {'step': 'make the key', 'waiting': []})
        self.assertEqual(self.member('nas')['next_public_key'], None, 'nothing is trusted yet')

        self.read('nas', 2, {1: [self.ADDR[1]], 3: [self.ADDR[3]]}, waiting=22)
        self.assertEqual(sfnetwork.observe(self.conn), ['nas'])
        self.assertEqual((self.member('nas')['public_key'], self.member('nas')['next_public_key']), (key(2), key(22)))
        self.assertEqual(sorted(self.tasks()), [('ctl', 'wg-peer', 'present', key(22), None), ('pi', 'wg-peer', 'present', key(22), None)],
                         'every peer learns the key, with no address on it: the host has not switched')
        self.assertEqual(self.row('nas')['rotation'], {'step': 'tell the peers', 'waiting': ['ctl', 'pi']})

        self.read('ctl', 1, {2: [self.ADDR[2]], 3: [self.ADDR[3]], 22: []})
        self.assertEqual(self.row('nas')['rotation'], {'step': 'tell the peers', 'waiting': ['pi']})
        self.assertNotIn('wg-rotate', [t[1] for t in self.tasks()], 'pi does not know the key yet, so nas keeps the old one')
        self.read('pi', 3, {1: [self.ADDR[1]], 2: [self.ADDR[2]], 22: []})
        self.assertEqual(self.row('nas')['rotation'], {'step': 'switch', 'waiting': []})
        got = self.tasks()
        self.assertEqual(got[0], ('nas', 'wg-rotate', 'switch', key(22), None), 'the switch comes first, and names the key the peers were given')
        self.assertEqual(sorted(got[1:]), sorted([('ctl', 'wg-peer', 'present', key(22), self.ADDR[2]), ('ctl', 'wg-peer', 'absent', key(2), None),
                                                  ('pi', 'wg-peer', 'present', key(22), self.ADDR[2]), ('pi', 'wg-peer', 'absent', key(2), None)]),
                         'and in the same plan its address moves to the new key and the old key comes off')
        changes.normalize({'name': 'p', 'tasks': sfnetwork.tasks(self.conn)})
        self.assertEqual(self.member('nas')['public_key'], key(2), 'on record it is still the old key until a reading shows the switch')

        self.settled(nas=22)
        self.assertEqual(sfnetwork.observe(self.conn), ['nas'])
        m = self.member('nas')
        self.assertEqual((m['public_key'], m['next_public_key'], m['rotation']), (key(22), None, None))
        self.assertEqual((self.tasks(), self.row('nas')['state'], self.row('nas')['rotation'], sfnetwork.problems(self.conn)), ([], 'ok', None, {}))

    def test_a_switch_that_ran_while_a_peer_step_failed_is_finished_by_the_next_plan(self):
        sfnetwork.rotate(self.conn, 'nas', 'gabe')
        self.read('nas', 2, {1: [self.ADDR[1]], 3: [self.ADDR[3]]}, waiting=22)
        self.assertEqual(sfnetwork.observe(self.conn), ['nas'])
        self.read('ctl', 1, {2: [self.ADDR[2]], 3: [self.ADDR[3]], 22: []})
        self.read('pi', 3, {1: [self.ADDR[1]], 2: [self.ADDR[2]], 22: []})
        self.read('nas', 22, {1: [self.ADDR[1]], 3: [self.ADDR[3]]})          # nas switched; ctl moved; pi did not
        self.read('ctl', 1, {22: [self.ADDR[2]], 3: [self.ADDR[3]]})
        self.assertEqual(sorted(self.tasks()), [('pi', 'wg-peer', 'absent', key(2), None), ('pi', 'wg-peer', 'present', key(22), self.ADDR[2])])
        self.assertEqual(self.member('nas')['public_key'], key(22))

    def test_a_new_key_nobody_asked_for_is_never_taken(self):
        before = json.dumps(sfnetwork.load(self.conn), sort_keys=True)
        self.read('nas', 2, {1: [self.ADDR[1]], 3: [self.ADDR[3]]}, waiting=22)          # a second key waiting on the host
        self.assertEqual(sfnetwork.observe(self.conn), [])
        self.assertEqual(json.dumps(sfnetwork.load(self.conn), sort_keys=True), before)
        self.assertTrue(self.row('nas')['key_unasked'])
        self.assertEqual([(k, v[4]) for k, v in sfnetwork.problems(self.conn).items()], [('sfnet-key:nas', 'warn')])
        self.assertEqual(self.tasks(), [('nas', 'wg-rotate', 'cancel', None, None)], 'the plan removes it, and no peer hears of it')

        self.read('nas', 22, {1: [self.ADDR[1]], 3: [self.ADDR[3]]})                       # and then the host switched on its own
        self.assertEqual(sfnetwork.observe(self.conn), [])
        self.assertEqual(json.dumps(sfnetwork.load(self.conn), sort_keys=True), before, 'the key on record stays')
        self.assertTrue(self.row('nas')['key_changed'])
        self.assertEqual([(k, v[4]) for k, v in sfnetwork.problems(self.conn).items()], [('sfnet-key:nas', 'crit')])
        self.assertIn('sfnet-key:nas', alerts.problems(self.conn))
        self.assertNotIn(key(22), json.dumps(sfnetwork.tasks(self.conn)), 'no peer is told to trust it')

    def test_during_a_rotation_only_the_key_the_peers_were_given_is_taken(self):
        sfnetwork.rotate(self.conn, 'nas', 'gabe')
        self.read('nas', 2, {1: [self.ADDR[1]], 3: [self.ADDR[3]]}, waiting=22)
        sfnetwork.observe(self.conn)
        self.read('nas', 2, {1: [self.ADDR[1]], 3: [self.ADDR[3]]}, waiting=23)          # the host now shows another next key
        self.assertEqual(sfnetwork.observe(self.conn), [])
        self.assertEqual(self.member('nas')['next_public_key'], key(22), 'a next key is taken once')
        self.read('nas', 23, {1: [self.ADDR[1]], 3: [self.ADDR[3]]})                       # and switches to it
        self.assertEqual(sfnetwork.observe(self.conn), [])
        self.assertEqual(self.member('nas')['public_key'], key(2))
        self.assertTrue(self.row('nas')['key_changed'])
        self.assertNotIn(key(23), json.dumps(sfnetwork.tasks(self.conn)))

    def test_a_next_key_another_member_holds_is_refused(self):
        sfnetwork.rotate(self.conn, 'nas', 'gabe')
        self.read('nas', 2, {1: [self.ADDR[1]], 3: [self.ADDR[3]]}, waiting=3)           # pi's key
        self.assertEqual(sfnetwork.observe(self.conn), [])
        self.assertEqual((self.member('nas')['next_public_key'], self.row('nas')['rotation']['step']), (None, 'key refused'))

    def test_a_rotation_taken_back_comes_off_the_peers_and_the_host(self):
        sfnetwork.rotate(self.conn, 'nas', 'gabe')
        with self.assertRaises(sfnet.NetworkError):
            sfnetwork.rotate(self.conn, 'nas', 'gabe')
        self.read('nas', 2, {1: [self.ADDR[1]], 3: [self.ADDR[3]]}, waiting=22)
        sfnetwork.observe(self.conn)
        self.read('ctl', 1, {2: [self.ADDR[2]], 3: [self.ADDR[3]], 22: []})
        sfnetwork.rotate(self.conn, 'nas', 'gabe', cancel=True)
        self.assertEqual((self.member('nas')['next_public_key'], self.member('nas')['rotation']), (None, None))
        self.assertEqual(sorted(self.tasks()), [('ctl', 'wg-peer', 'absent', key(22), None), ('nas', 'wg-rotate', 'cancel', None, None)])
        for host in ('pi-is-pending', 'nobody'):
            with self.subTest(host), self.assertRaises(sfnet.NetworkError):
                sfnetwork.rotate(self.conn, host, 'gabe')
        with self.assertRaises(sfnet.NetworkError):
            sfnetwork.rotate(self.conn, 'pi', 'gabe', cancel=True)

    def test_a_revoked_member_has_no_rotation(self):
        sfnetwork.rotate(self.conn, 'nas', 'gabe')
        sfnetwork.leave(self.conn, 'nas', 'gabe')
        self.assertEqual(self.member('nas')['rotation'], None)
        self.assertNotIn('wg-rotate', [t[1] for t in self.tasks()])

    def test_the_step_is_checked_before_any_script_is_written(self):
        for params, want in (({'phase': 'switch'}, 'give the public key'), ({'phase': 'switch', 'pubkey': key(22)}, 'connections over sf0 stop'), ({'phase': 'prepare'}, 'stays there')):
            said = []
            steps_infra._check_wg_rotate(self.conn, None, {'name': 'nas'}, {'iface': 'sf0', 'pubkey': '', **params}, lambda level, text: said.append(text))
            with self.subTest(params):
                self.assertTrue(any(want in text for text in said), said)
        for bad in ({'phase': 'now'}, {'phase': 'switch', 'pubkey': 'not a key'}, {'phase': 'prepare', 'iface': 'sf0; id'}):
            with self.subTest(bad), self.assertRaises(ValueError):
                changes.normalize({'name': 'p', 'tasks': [{'type': 'wg-rotate', 'host': 'nas', 'params': {'iface': 'sf0', **bad}}]})

    def test_a_name_another_kind_of_interface_has_is_refused_by_the_check(self):
        # the machine that runs the StorageForge containers has a bridge called sf0 by default
        host_id = self.conn.all("SELECT host_id FROM hosts WHERE hostname = 'pi'")[0][0]
        self.conn.execute('INSERT INTO host_network (host_id, data_json, updated_at) VALUES (:i, :d, :t)',
                          {'i': host_id, 't': int(time.time()), 'd': json.dumps({'interfaces': [{'name': 'sf0', 'addresses': [{'ip': '172.30.0.1', 'prefix': 24}]}]})})
        store(self.conn, 'pi', [])
        said = []
        steps_infra._check_wg_interface(self.conn, None, {'name': 'pi'}, {'iface': 'sf0', 'address': '10.203.0.3/20', 'port': '51903', 'state': 'present'}, lambda level, text: said.append((level, text)))
        self.assertTrue(any(level == 'crit' and 'is not a WireGuard interface' in text and 'STORAGEFORGE_BRIDGE' in text for level, text in said), said)

    def test_the_route(self):
        users.create(self.conn, 'admin', PW, 'admin')
        users.create(self.conn, 'viewer', PW, 'viewer')
        app = server.create_app(server.App(self.db), 's' * 48)
        viewer, admin = app.test_client(), app.test_client()
        for client, name in ((viewer, 'viewer'), (admin, 'admin')):
            self.assertEqual(client.post('/api/login', json={'username': name, 'password': PW}).status_code, 200)
        self.assertEqual(viewer.post('/api/sfnet/members/rotate', json={'host': 'nas'}).status_code, 403)
        self.assertEqual(admin.post('/api/reauth', json={'password': PW}).status_code, 200)
        self.assertEqual(admin.post('/api/sfnet/members/rotate', json={'host': 'nobody'}).status_code, 400)
        asked = admin.post('/api/sfnet/members/rotate', json={'host': 'nas'})
        self.assertEqual((asked.status_code, asked.get_json()['rotation']), (200, 'asked'))
        self.assertEqual(admin.post('/api/sfnet/members/rotate', json={'host': 'nas'}).status_code, 400, 'one rotation at a time')
        seen = next(m for m in viewer.get('/api/sfnet').get_json()['members'] if m['host'] == 'nas')
        self.assertEqual(seen['rotation'], {'step': 'make the key', 'waiting': []})
        planned = admin.post('/api/sfnet/plan', json={}).get_json()
        plan = changes.get_plan(self.conn, planned['plan_id'])
        self.assertEqual([(t['type'], t['params']['phase']) for t in plan['tasks']], [('wg-rotate', 'prepare')])
        self.assertIn('t_wg_rotate', changes.script(self.conn, plan))
        self.assertEqual(admin.post('/api/sfnet/members/rotate', json={'host': 'nas', 'cancel': True}).get_json()['rotation'], None)
        actions = [r[0] for r in self.conn.all("SELECT action FROM audit_log WHERE action LIKE 'sfnet.%' ORDER BY audit_id")]
        self.assertEqual(actions, ['sfnet.rotate', 'sfnet.plan', 'sfnet.rotate.cancel'])


# ── real WireGuard ──
@unittest.skipUnless(wgworld.WORKS, wgworld.NEEDS)
class RealWireGuard(Base):
    ON = {'ctl': '10.203.0.1', 'nas': '10.203.0.2', 'pi': '10.203.0.3'}

    def setUp(self):
        super().setUp()
        self.m = wgworld.Machines(self, HOSTS)
        self.secrets = set()

    def read_all(self):
        for host, _ in HOSTS:
            store(self.conn, host, self.m.reading(host))
        self.secrets |= self.m.private_keys()

    def converge(self, limit=5) -> list[list]:
        """Plan, run every task where it belongs, read every host; again until there is nothing to do. Returns each plan's tasks."""
        plans = []
        while True:
            todo = sfnetwork.tasks(self.conn)
            if not todo:
                return plans
            self.assertLess(len(plans), limit, f'the plans do not settle: {todo}')
            plans.append([(t['host'], t['type'], t['params'].get('phase') or t['params'].get('state') or 'present') for t in todo])
            self.secrets |= self.m.private_keys()
            for t in todo:
                self.m.step(t)
            self.read_all()

    def show(self, host, what):
        return self.m.run(host, f'wg show sf0 {what}').stdout.strip()

    def peers(self, host) -> dict:
        return {line.split('\t')[0]: line.split('\t')[1] for line in self.show(host, 'allowed-ips').splitlines()}

    def reach(self) -> dict:
        """{(from, to): whether a ping crosses the StorageForge network}, for every pair."""
        return {(a, b): self.m.ping(a, self.ON[b]) for a in self.ON for b in self.ON if a != b}

    def test_a_network_is_made_a_key_rotated_and_a_host_revoked_and_no_private_key_is_ever_shown(self):
        sfnetwork.create(self.conn, 'gabe')
        for host, _ in HOSTS:
            sfnetwork.join(self.conn, host, 'gabe')
        self.read_all()
        plans = self.converge()
        self.assertEqual([sorted({kind for _, kind, _ in p}) for p in plans], [['wg-interface'], ['wg-peer']], 'the interfaces, a reading, then the peers')
        self.assertEqual([(m['host'], m['state']) for m in sfnetwork.status(self.conn)['members']], [(h, 'ok') for h, _ in HOSTS])
        made = {h: self.show(h, 'public-key') for h, _ in HOSTS}
        self.assertEqual(made, {m['host']: m['public_key'] for m in sfnetwork.load(self.conn)['members']}, 'on record is what each host made')
        self.assertEqual(self.peers('ctl'), {made['nas']: '10.203.0.2/32', made['pi']: '10.203.0.3/32'})
        self.assertEqual(self.m.run('nas', 'ip -o -4 addr show dev sf0').stdout.split()[3], '10.203.0.2/20')
        for host, _ in HOSTS:
            mode = (self.m.keys(host) / 'sf0.key').stat().st_mode & 0o777
            self.assertEqual(mode, 0o600, host)
        self.assertEqual(set(self.reach().values()), {True}, 'every host reaches every other across the network')
        conf = (self.m.keys('nas') / 'sf0.conf').read_text()
        self.assertEqual((conf.count('[Peer]'), 'PrivateKey' in conf), (2, False), 'the peers are kept for a restart, and the key stays in its own file')

        # the key of nas, rotated
        old_private = (self.m.keys('nas') / 'sf0.key').read_text().strip()
        sfnetwork.rotate(self.conn, 'nas', 'gabe')
        self.assertIn('would: make the next key pair', self.m.step(sfnetwork.tasks(self.conn)[0], apply=False), 'a report changes nothing')
        self.assertFalse((self.m.keys('nas') / 'sf0.key.next').exists())
        todo = sfnetwork.tasks(self.conn)
        self.assertEqual([(t['host'], t['type'], t['params']['phase']) for t in todo], [('nas', 'wg-rotate', 'prepare')])
        self.m.step(todo[0])
        self.read_all()
        todo = sfnetwork.tasks(self.conn)
        self.assertEqual(sorted((t['host'], t['type'], t['params'].get('allowed')) for t in todo), [('ctl', 'wg-peer', None), ('pi', 'wg-peer', None)])
        self.m.step(todo[0])
        self.assertEqual(set(self.reach().values()), {True}, 'between the halves nothing is lost: both keys are known, and the old one carries the address')
        self.read_all()
        self.assertNotIn('wg-rotate', [t['type'] for t in sfnetwork.tasks(self.conn)], 'one peer does not know the new key yet: nas keeps the old one')
        plans = self.converge()
        self.assertEqual([p[0] for p in plans], [('pi', 'wg-peer', 'present'), ('nas', 'wg-rotate', 'switch')])
        new = self.show('nas', 'public-key')
        self.assertNotEqual(new, made['nas'])
        self.assertEqual(sfnet.member(sfnetwork.load(self.conn), 'nas')['public_key'], new)
        self.assertEqual((self.peers('ctl'), self.peers('pi')), ({new: '10.203.0.2/32', made['pi']: '10.203.0.3/32'}, {made['ctl']: '10.203.0.1/32', new: '10.203.0.2/32'}),
                         'every peer holds the new key with the address, and the old key is gone')
        self.assertEqual(set(self.reach().values()), {True}, 'and every host still reaches every other, nas by its new key')
        self.assertEqual(sorted(f.name for f in self.m.keys('nas').iterdir()), ['sf0.conf', 'sf0.key', 'sf0.storageforge'])
        for f in self.m.keys('nas').iterdir():
            self.assertNotIn(old_private, f.read_text(), f'the old private key is gone from the host: {f.name}')
        self.assertEqual([(m['host'], m['state']) for m in sfnetwork.status(self.conn)['members']], [(h, 'ok') for h, _ in HOSTS])
        self.assertEqual(sfnetwork.problems(self.conn), {})
        # the interface taken down and brought up, as a restart does: the new key and the peers come back
        self.assertEqual(self.m.run('nas', 'wg-quick down sf0 && wg-quick up sf0').returncode, 0)
        self.assertEqual((self.show('nas', 'public-key'), self.peers('nas')), (new, {made['ctl']: '10.203.0.1/32', made['pi']: '10.203.0.3/32'}))
        # it calls first: the others still hold a session with the interface that is gone, and WireGuard takes seconds to give that up
        self.assertTrue(self.m.ping('nas', self.ON['ctl']) and self.m.ping('ctl', self.ON['nas']))

        # a switch to a key the peers were not given is refused on the host
        other = self.m.run('nas', 'umask 077; wg genkey > "$SF_WG_DIR/sf0.key.next"; wg pubkey < "$SF_WG_DIR/sf0.key.next"').stdout.strip()
        out = self.m.step({'type': 'wg-rotate', 'host': 'nas', 'params': {'iface': 'sf0', 'phase': 'switch', 'pubkey': made['pi']}})
        self.assertIn('conflict: the next key on this host is not the one its peers were given: nothing is switched', out)
        self.assertEqual(self.show('nas', 'public-key'), new)
        # and that key, which nobody asked for, is seen by the reading and not taken
        self.read_all()
        self.assertEqual(sfnetwork.observe(self.conn), [])
        self.assertEqual([k for k in sfnetwork.problems(self.conn)], ['sfnet-key:nas'])
        self.assertNotIn(other, json.dumps(sfnetwork.load(self.conn)))
        self.assertEqual(self.converge(), [[('nas', 'wg-rotate', 'cancel')]])

        # a key changed by hand on the host: nothing takes it, and the others stop talking to it
        self.m.run('nas', 'umask 077; wg genkey > "$SF_WG_DIR/by-hand"; wg set sf0 private-key "$SF_WG_DIR/by-hand"')
        by_hand = self.show('nas', 'public-key')
        self.read_all()
        self.assertEqual(sfnetwork.observe(self.conn), [])
        self.assertEqual(sfnet.member(sfnetwork.load(self.conn), 'nas')['public_key'], new, 'the key on record stays')
        self.assertEqual([(k, v[4]) for k, v in sfnetwork.problems(self.conn).items()], [('sfnet-key:nas', 'crit')])
        self.assertNotIn(by_hand, json.dumps(sfnetwork.tasks(self.conn)))
        self.assertNotIn(by_hand, self.peers('ctl'))
        got = self.reach()
        self.assertEqual((got['ctl', 'nas'], got['nas', 'pi'], got['ctl', 'pi']), (False, False, True), 'a machine with another key is not let in')

        # nas leaves: its key comes off the others, and its interface and key are removed
        sfnetwork.leave(self.conn, 'nas', 'gabe')
        plans = self.converge()
        self.assertEqual(sorted(plans[0]), [('ctl', 'wg-peer', 'absent'), ('nas', 'wg-interface', 'absent'), ('pi', 'wg-peer', 'absent')])
        self.assertEqual((self.peers('ctl'), self.peers('pi')), ({made['pi']: '10.203.0.3/32'}, {made['ctl']: '10.203.0.1/32'}))
        self.assertNotEqual(self.m.run('nas', 'wg show sf0').returncode, 0)
        self.assertFalse((self.m.keys('nas') / 'sf0.key').exists())
        self.assertTrue(self.m.ping('ctl', self.ON['pi']))

        # a machine where sf0 is something else, as the bridge of the StorageForge containers is: left as it is, and no key is made
        self.m.add('docker', '10.42.0.30')
        self.m.run('docker', 'ip link add sf0 type bridge')
        out = self.m.step({'type': 'wg-interface', 'host': 'docker', 'params': {'iface': 'sf0', 'address': '10.203.0.9/20', 'port': '51903'}})
        self.assertIn('conflict: sf0 is on this host and is not a WireGuard interface: it is left as it is', out)
        self.assertFalse(self.m.keys('docker').exists())
        self.assertIn('bridge', self.m.run('docker', 'ip -d link show dev sf0').stdout)

        # nothing that left a host, and nothing kept, holds a private key
        self.assertGreaterEqual(len(self.secrets), 6, 'three first keys, a rotated one, one nobody asked for and one made by hand')
        kept = json.dumps(alerts.get_setting(self.conn, sfnetwork.KEY)) + json.dumps([list(r) for r in self.conn.all('SELECT data_json FROM security_measurements')])
        shown = '\n'.join(self.m.said)
        for secret in self.secrets:
            self.assertNotIn(secret, shown, 'in what a step or a reading printed')
            self.assertNotIn(secret, kept, 'in the index')


if __name__ == '__main__':
    unittest.main()
