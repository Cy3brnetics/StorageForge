"""StorageForge's own SSH connections over its own network (roadmap section 2.1): sfnetwork.route, via and carry, the transport
that takes the path, and the console.

What must hold: the network carries a connection only where the controller and the host are active members that confirm each other
by the key on record; everything else goes to the normal address, at once; and the SSH host key checked is the one pinned for the
host itself whichever address carries the connection, so another machine answering on the network address is refused.

RealSsh makes real connections: the network's range is put in 127.0.0.0/8, where every address is this machine, a real sshd
listens on the host's network address only, and the host's normal address is one nothing answers at.
"""
import getpass
import json
import os
import shutil
import socket
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import dbfactory
from storageforge_index import console, infragraph, remote, sfcontroller, sfnet, sfnetwork
from test_sfnet import key
from test_sfnet_rotation import store

NAME = sfcontroller.NAME
SSHD = shutil.which('sshd') or '/usr/sbin/sshd'


class Base(unittest.TestCase):
    RANGE = None

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.db = dbfactory.make(self, f'{self.tmp}/t.db')
        self.conn = self.db.connect()
        self.addCleanup(self.conn.close)
        self.db.migrate(self.conn)
        self.want, self.state = self.tmp / 'want', self.tmp / 'state'
        self.want.mkdir()
        self.state.mkdir()
        env = mock.patch.dict(os.environ, {sfcontroller.WANT_ENV: str(self.want), sfcontroller.STATE_ENV: str(self.state),
                                           'STORAGEFORGE_DATA_DIR': str(self.tmp), 'STORAGEFORGE_RUNTIME_DIR': str(self.tmp)})
        env.start()
        self.addCleanup(env.stop)
        sfnetwork._UNREACHED.clear()
        self.addCleanup(setattr, remote, 'PATH_OF', remote.PATH_OF)

    def host(self, name, address, port=22):
        self.conn.execute('INSERT INTO hosts (hostname, ip_address, ssh_host, ssh_port) VALUES (:h, :a, :a, :p)', {'h': name, 'a': address, 'p': port})

    def link_says(self, own, peers):
        lines = [f't\t{int(time.time())}', f'i\tsf0\t{key(own)}\t51903'] + [f'a\tsf0\t{key(k)}\t{a}' for k, a in peers.items()]
        (self.state / 'sf0.state').write_text('\n'.join(lines) + '\n')

    def host_says(self, host, own, peers):
        store(self.conn, host, [{'name': 'sf0', 'public_key': key(own), 'listen_port': 51903, 'peers': [{'public_key': key(k), 'allowed_ips': [a]} for k, a in peers.items()]}])

    def up(self, prefix='10.203.0'):
        """nas (key 2) and pi (key 3) and the controller through its link (key 1), every peer confirmed."""
        sfnetwork.create(self.conn, 'gabe', self.RANGE)
        for i, host in ((2, 'nas'), (3, 'pi')):
            sfnetwork.join(self.conn, host, 'gabe')
            self.host_says(host, i, {})
        sfnetwork.join_controller(self.conn, 'gabe')
        self.link_says(1, {})
        sfnetwork.observe(self.conn)
        self.a = {'nas': f'{prefix}.1', 'pi': f'{prefix}.2', NAME: f'{prefix}.3'}
        self.settled()

    def settled(self):
        self.link_says(1, {2: self.a['nas'] + '/32', 3: self.a['pi'] + '/32'})
        self.host_says('nas', 2, {1: self.a[NAME] + '/32', 3: self.a['pi'] + '/32'})
        self.host_says('pi', 3, {1: self.a[NAME] + '/32', 2: self.a['nas'] + '/32'})


class Route(Base):
    def setUp(self):
        super().setUp()
        self.host('nas', '10.42.0.10')
        self.host('pi', '10.42.0.20', 2222)
        self.host('other', '10.42.0.30')

    def test_a_host_is_reached_over_the_network_only_when_both_ends_confirm_the_other_by_key(self):
        self.assertIsNone(sfnetwork.route(self.conn, 'nas'), 'no network')
        self.up()
        self.assertEqual((sfnetwork.route(self.conn, 'NAS'), sfnetwork.route(self.conn, 'pi')), ('10.203.0.1', '10.203.0.2'))
        self.assertEqual((sfnetwork.route(self.conn, '10.42.0.10', 22), sfnetwork.route(self.conn, '10.42.0.20', 2222)), ('10.203.0.1', '10.203.0.2'),
                         'by the address and port scans use, which is what a connection is made with')
        self.assertIsNone(sfnetwork.route(self.conn, '10.42.0.20', 22), 'another port is another host')
        self.assertIsNone(sfnetwork.route(self.conn, 'other'), 'not a member')
        self.assertIsNone(sfnetwork.route(self.conn, 'nowhere'))

        self.host_says('nas', 2, {3: '10.203.0.2/32'})
        self.assertIsNone(sfnetwork.route(self.conn, 'nas'), 'nas does not hold the controller as a peer')
        self.host_says('nas', 2, {1: '10.203.0.0/20', 3: '10.203.0.2/32'})
        self.assertIsNone(sfnetwork.route(self.conn, 'nas'), 'nor with the wrong addresses on its key')
        self.settled()
        self.link_says(1, {3: '10.203.0.2/32'})
        self.assertIsNone(sfnetwork.route(self.conn, 'nas'), 'the controller does not hold nas')
        self.assertEqual(sfnetwork.route(self.conn, 'pi'), '10.203.0.2')
        self.settled()
        self.assertEqual(sfnetwork.route(self.conn, 'nas'), '10.203.0.1')

    def test_a_changed_key_at_either_end_takes_the_path_away(self):
        self.up()
        self.host_says('nas', 99, {1: '10.203.0.3/32', 3: '10.203.0.2/32'})
        self.assertIsNone(sfnetwork.route(self.conn, 'nas'), 'nas shows a key that is not the one on record')
        self.assertEqual(sfnetwork.route(self.conn, 'pi'), '10.203.0.2')
        self.settled()
        self.link_says(98, {2: '10.203.0.1/32', 3: '10.203.0.2/32'})
        self.assertEqual((sfnetwork.route(self.conn, 'nas'), sfnetwork.route(self.conn, 'pi')), (None, None), 'the controller itself shows another key')
        self.settled()
        (self.state / 'sf0.state').write_text(f't\t{int(time.time()) - 600}\ni\tsf0\t{key(1)}\t51903\n')
        self.assertIsNone(sfnetwork.route(self.conn, 'nas'), 'the link stopped reporting')

    def test_a_revoked_or_pending_member_and_a_controller_that_is_no_member_have_no_path(self):
        self.up()
        sfnetwork.leave(self.conn, 'nas', 'gabe')
        self.assertIsNone(sfnetwork.route(self.conn, 'nas'))
        back = sfnetwork.join(self.conn, 'nas', 'gabe')
        self.assertEqual(back['state'], 'pending')
        self.assertIsNone(sfnetwork.route(self.conn, 'nas'))
        sfnetwork.leave(self.conn, NAME, 'gabe')
        self.assertIsNone(sfnetwork.route(self.conn, 'pi'), 'the controller left')

    def test_two_hosts_behind_one_address_and_port_are_never_guessed_between(self):
        self.up()
        self.conn.execute("UPDATE hosts SET ssh_host = '10.42.0.10', ssh_port = 22 WHERE hostname = 'other'")
        self.assertIsNone(sfnetwork.route(self.conn, '10.42.0.10', 22))
        self.assertEqual(sfnetwork.route(self.conn, 'nas'), '10.203.0.1', 'by name it is still one host')

    def test_a_controller_that_runs_on_a_member_reaches_the_others_through_that_host(self):
        sfnetwork.create(self.conn, 'gabe')
        for i, host in ((2, 'nas'), (3, 'pi')):
            sfnetwork.join(self.conn, host, 'gabe')
            self.host_says(host, i, {})
        sfnetwork.observe(self.conn)
        sfnetwork.controller_on(self.conn, 'nas', 'gabe')
        self.assertIsNone(sfnetwork.route(self.conn, 'pi'))
        self.host_says('nas', 2, {3: '10.203.0.2/32'})
        self.host_says('pi', 3, {2: '10.203.0.1/32'})
        self.assertEqual((sfnetwork.route(self.conn, 'pi'), sfnetwork.route(self.conn, 'nas')), ('10.203.0.2', None), 'and not itself')

    def test_a_network_that_does_not_answer_costs_one_wait_and_the_normal_address_is_used(self):
        self.up()
        asked = []

        def dead(address, port):
            asked.append((address, port))
            raise OSError('timed out')
        self.assertIsNone(sfnetwork.via(self.conn, 'pi', probe=dead))
        self.assertIsNone(sfnetwork.via(self.conn, '10.42.0.20', 2222, probe=dead))
        self.assertEqual(asked, [('10.203.0.2', 2222)], 'asked once, on the host\'s own SSH port, and not again for a minute')
        self.assertEqual(sfnetwork.via(self.conn, 'nas', probe=lambda *a: asked.append(a)), '10.203.0.1')
        sfnetwork._UNREACHED[('10.203.0.2', 2222)] -= sfnetwork.RETRY + 1
        self.assertEqual(sfnetwork.via(self.conn, 'pi', probe=lambda *a: None), '10.203.0.2', 'and tried again after that')
        with mock.patch.object(sfnetwork, 'route', side_effect=RuntimeError('anything')):
            self.assertIsNone(sfnetwork.via(self.conn, 'pi'), 'nothing about the network may stop a connection')

    def test_the_console_offers_it_by_what_the_index_confirms_and_not_by_an_interface_name(self):
        nas = self.conn.all("SELECT host_id FROM hosts WHERE hostname = 'nas'")[0][0]
        pi = self.conn.all("SELECT host_id FROM hosts WHERE hostname = 'pi'")[0][0]
        # nas has its sf0; pi, which runs the StorageForge containers in this story, has a bridge of that name
        for host_id, address in ((nas, '10.203.0.1'), (pi, '172.30.0.1')):
            self.conn.execute('INSERT INTO host_network (host_id, data_json, updated_at) VALUES (:i, :d, :t)',
                              {'i': host_id, 't': int(time.time()), 'd': json.dumps({'interfaces': [{'name': 'sf0', 'addresses': [{'ip': address}]}]})})
        self.assertEqual([r['route'] for r in console.routes(self.conn, 'nas')], ['lan'], 'no network on record: an interface called sf0 is not offered')
        self.up()
        self.assertEqual([(r['route'], r['label'], r['address'], r['port']) for r in console.routes(self.conn, 'nas')],
                         [('storageforge', 'the StorageForge network', '10.203.0.1', 22), ('lan', 'LAN', '10.42.0.10', 22)], 'first, so it is what a console uses')
        self.assertEqual([(r['route'], r['address'], r['port']) for r in console.routes(self.conn, 'pi')], [('storageforge', '10.203.0.2', 2222), ('lan', '10.42.0.20', 2222)],
                         'its address on record, never the bridge\'s')
        self.host_says('nas', 99, {1: '10.203.0.3/32'})
        self.assertEqual([r['route'] for r in console.routes(self.conn, 'nas')], ['lan'])

    def test_the_map_names_the_interface_as_the_storageforge_network(self):
        wg = [{'name': 'sf0', 'public_key': key(2), 'listen_port': 51903, 'peers': []}, {'name': 'wg0', 'public_key': key(5), 'listen_port': 51820, 'peers': []}]
        nodes, _ = infragraph.build('nas', None, {'access': {'wireguard': wg}}, [], [], {}, set())
        self.assertEqual({n['label']: n['props']['network'] for n in nodes.values() if n['kind'] == 'VPNNetwork'}, {'sf0': 'the StorageForge network', 'wg0': 'WireGuard'})


@unittest.skipUnless(os.path.exists(SSHD) and shutil.which('ssh-keygen'), 'needs sshd and ssh-keygen')
class RealSsh(Base):
    RANGE = '127.77.0.0/24'

    def setUp(self):
        super().setUp()
        with socket.socket() as s:
            s.bind(('127.77.0.1', 0))
            self.port = s.getsockname()[1]
        # the address scans know nas by is one nothing answers at (TEST-NET-1): only the network address reaches it
        self.host('nas', '192.0.2.10', self.port)
        self.host('pi', '192.0.2.20', self.port)
        self.up(prefix='127.77.0')
        self.kh = self.tmp / 'known_hosts'
        self.hostkey = self.serve('nas-host', self.a['nas'])
        self.user_key = self.tmp / 'user'
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(self.user_key)], check=True)
        (self.tmp / 'authorized_keys').write_text((self.tmp / 'user.pub').read_text())
        self.pin('192.0.2.10', self.hostkey)

    def serve(self, name, address) -> Path:
        """A real sshd on that address alone, with a host key of its own."""
        hostkey = self.tmp / name
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(hostkey)], check=True)
        conf = self.tmp / f'{name}.conf'
        conf.write_text(f'Port {self.port}\nListenAddress {address}\nHostKey {hostkey}\nAuthorizedKeysFile {self.tmp}/authorized_keys\nPidFile none\nUsePAM no\nStrictModes no\n'
                        'PasswordAuthentication no\nKbdInteractiveAuthentication no\nLogLevel ERROR\n')
        sshd = subprocess.Popen([SSHD, '-D', '-e', '-f', str(conf)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(sshd.wait)
        self.addCleanup(sshd.kill)
        for _ in range(100):
            with socket.socket() as s:
                if s.connect_ex((address, self.port)) == 0:
                    return hostkey
            time.sleep(0.05)
        self.skipTest('sshd would not start here')

    def pin(self, address, hostkey):
        """The line a first scan leaves in known_hosts: the host's key under the address and port scans reach it at."""
        self.kh.write_text(f'[{address}]:{self.port} ' + ' '.join(Path(f'{hostkey}.pub').read_text().split()[:2]) + '\n')

    def transport(self, host='192.0.2.10', **more):
        t = remote.Transport(host=host, user=getpass.getuser(), port=self.port, key=str(self.user_key), known_hosts=str(self.kh), isolated=True, connect_timeout=3, **more)
        self.addCleanup(shutil.rmtree, t._ctl_dir, True)
        return t

    def test_a_scan_connection_goes_over_the_network_and_checks_the_key_pinned_for_the_host(self):
        self.assertIsNone(self.transport().via, 'until the server says so, a connection is what it always was')
        sfnetwork.carry(self.db)
        t = self.transport()
        self.assertEqual(t.via, '127.77.0.1')
        argv = t.argv('true')
        self.assertEqual((argv[-2], f'HostName=127.77.0.1' in argv, f'HostKeyAlias=[192.0.2.10]:{self.port}' in argv, 'StrictHostKeyChecking=yes' in argv),
                         (f'{getpass.getuser()}@192.0.2.10', True, True, True))
        self.assertEqual(t.run('echo carried').strip(), 'carried', 'a real login, to an sshd that listens on the network address only')
        self.assertEqual(t.host_keys(), remote.known_host_keys('192.0.2.10', self.port, str(self.kh)), 'and the host is still known by its own address')
        self.assertEqual(len(self.kh.read_text().splitlines()), 1, 'nothing was added to known_hosts')

    def test_another_machine_answering_on_the_network_address_is_refused(self):
        sfnetwork.carry(self.db)
        other = self.tmp / 'not-the-host'
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(other)], check=True)
        self.pin('192.0.2.10', other)                      # the key on record for nas is not the one this sshd holds
        before = self.kh.read_text()
        t = self.transport()
        self.assertEqual(t.via, '127.77.0.1')
        with self.assertRaises(Exception) as seen:
            t.run('echo carried')
        self.assertIn('host key', str(seen.exception).lower())
        self.assertEqual(self.kh.read_text(), before, 'and its key is not taken')

    def test_a_host_whose_key_was_never_pinned_is_not_met_for_the_first_time_over_the_network(self):
        sfnetwork.carry(self.db)
        self.kh.write_text('')
        self.assertIsNone(self.transport().via)

    def test_where_the_network_does_not_answer_the_connection_is_made_as_before(self):
        sfnetwork.carry(self.db)
        t = self.transport(host='192.0.2.20')              # pi: a confirmed member, and nothing listens on its network address
        self.pin('192.0.2.20', self.hostkey)
        t = self.transport(host='192.0.2.20')
        self.assertIsNone(t.via)
        self.assertNotIn('HostKeyAlias', ' '.join(t.argv('true')))
        self.assertIn(('127.77.0.2', self.port), sfnetwork._UNREACHED)
        self.assertIsNone(self.transport(host='192.0.2.99').via, 'and a host that is no member is never asked about')

    def test_the_console_takes_the_network_when_it_answers_and_names_the_key_as_it_is_pinned(self):
        self.assertEqual(console.routes(self.conn, 'nas')[0]['route'], 'storageforge')
        self.assertEqual(sfnetwork.via(self.conn, 'nas'), '127.77.0.1')
        self.assertIsNone(sfnetwork.via(self.conn, 'pi'), 'nothing answers there: auto falls back to the LAN route')
        argv = console._ssh_argv('/run/agent.sock', 'admin', '127.77.0.1', self.port, remote.known_hosts_name('192.0.2.10', self.port))
        from storageforge_index.runner import known_hosts_path
        known_hosts_path().write_text(self.kh.read_text())
        i = argv.index('IdentityAgent=/run/agent.sock')
        argv = [a for n, a in enumerate(argv) if n not in (i - 1, i) and a != '-tt'] + ['true']
        ran = subprocess.run(argv, capture_output=True, text=True, timeout=20, env={**os.environ, 'SSH_AUTH_SOCK': ''})
        # no key is offered, so the login is refused, after the host key was accepted under the pinned name
        self.assertIn('Permission denied', ran.stderr)
        self.assertNotIn('Host key verification failed', ran.stderr)


if __name__ == '__main__':
    unittest.main()
