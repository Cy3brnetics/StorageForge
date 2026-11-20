"""The controller as a member of the StorageForge network (roadmap section 2.1): sfcontroller.py and its link.

What must hold: the controller's private key is made by the link and is never in the database, in the file the controller writes,
in the file the link reports, or in anything either prints; the link acts on nothing in the want file that is not an address, a
port or a WireGuard public key, and never on an interface other than its own; and a controller that is a member is planned and
confirmed by key like any host.

RealLink runs the link program itself, with real wg and ip, on the machines of wgworld.py: the controller is one network namespace
and each host another, and whether they can talk is asked of the kernel.
"""
import json
import os
import shutil
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import dbfactory
import wgworld
from storageforge_index import alerts, changes, cli, server, sfcontroller, sfnet, sfnetwork, users
from test_sfnet import key
from test_sfnet_rotation import store

PW = 'correct horse battery staple 9'
NAME = sfcontroller.NAME


class Base(unittest.TestCase):
    HOSTS = (('nas', '10.42.0.10'), ('pi', '10.42.0.20'))

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.db = dbfactory.make(self, f'{self.tmp}/t.db')
        self.conn = self.db.connect()
        self.addCleanup(self.conn.close)
        self.db.migrate(self.conn)
        for name, address in self.HOSTS:
            self.conn.execute('INSERT INTO hosts (hostname, ip_address, ssh_host) VALUES (:h, :a, :a)', {'h': name, 'a': address})
        self.want, self.state = self.tmp / 'want', self.tmp / 'state'
        self.want.mkdir()
        self.state.mkdir()
        env = mock.patch.dict(os.environ, {sfcontroller.WANT_ENV: str(self.want), sfcontroller.STATE_ENV: str(self.state)})
        env.start()
        self.addCleanup(env.stop)

    def said(self, *lines, age=0):
        """The link's report, written as the link writes it."""
        (self.state / 'sf0.state').write_text('\n'.join((f't\t{int(time.time()) - age}', *lines)) + '\n')

    def row(self, host):
        return next(m for m in sfnetwork.status(self.conn)['members'] if m['host'] == host)


class Controller(Base):
    """Against a link's report written here. nas has key 2 and pi key 3; the link, when it reports, has key 1."""

    def up(self):
        sfnetwork.create(self.conn, 'gabe')
        for i, (host, _) in enumerate(self.HOSTS, 2):
            sfnetwork.join(self.conn, host, 'gabe')
            store(self.conn, host, [{'name': 'sf0', 'public_key': key(i), 'listen_port': 51903, 'peers': []}])
        return sfnetwork.join_controller(self.conn, 'gabe')

    def test_a_controller_with_no_link_cannot_join_and_says_what_is_missing(self):
        sfnetwork.create(self.conn, 'gabe')
        with mock.patch.dict(os.environ, {sfcontroller.WANT_ENV: ''}):
            self.assertFalse(sfnetwork.status(self.conn)['controller']['configured'])
            with self.assertRaisesRegex(sfnet.NetworkError, 'not started with a link'):
                sfnetwork.join_controller(self.conn, 'gabe')
            with self.assertRaises(sfnet.NetworkError):
                sfcontroller.write('v\t1\n')

    def test_it_joins_pending_asks_its_link_and_takes_the_key_the_link_reports(self):
        me = self.up()
        self.assertEqual((me['host'], me['address'], me['state'], me['endpoint']), (NAME, '10.203.0.3', 'pending', None))
        got = sfnetwork.status(self.conn)['controller']
        self.assertEqual((got['member'], got['link'], got['running'], got['pending']), (NAME, True, False, True))
        self.assertEqual(self.row(NAME)['state'], 'not scanned', 'no link has reported')
        self.assertNotIn(NAME, [t['host'] for t in sfnetwork.tasks(self.conn)], 'the controller is in no plan: its link is asked')
        self.assertEqual(sfnetwork.apply_controller(self.conn, 'gabe'), {'changed': True, 'peers': 0})
        self.assertEqual((self.want / 'sf0.want').read_text(), 'v\t1\ni\tsf0\t10.203.0.3/20\t51903\n', 'nobody is its peer until it has a key')
        self.assertEqual((self.want / 'sf0.want').stat().st_mode & 0o777, 0o644, 'the link reads it as another user')
        self.assertEqual(sfnetwork.apply_controller(self.conn, 'gabe')['changed'], False)

        self.said(f'i\tsf0\t{key(1)}\t51903')
        self.assertEqual(self.row(NAME)['state'], 'differs', 'active, with the key the link made, and its peers still to come')
        self.assertEqual(sfnet.member(sfnetwork.load(self.conn), NAME)['public_key'], key(1))
        self.assertEqual(sorted((t['host'], t['params']['pubkey'], t['params'].get('endpoint')) for t in sfnetwork.tasks(self.conn) if t['params']['pubkey'] == key(1)),
                         [('nas', key(1), None), ('pi', key(1), None)], 'the hosts learn its key, and are not told to call it: it calls them')
        self.assertTrue(sfnetwork.status(self.conn)['controller']['pending'])
        self.assertEqual(sfnetwork.apply_controller(self.conn, 'gabe'), {'changed': True, 'peers': 2})
        self.assertEqual((self.want / 'sf0.want').read_text().splitlines()[2:],
                         [f'p\t{key(2)}\t10.203.0.1/32\t10.42.0.10:51903\t25', f'p\t{key(3)}\t10.203.0.2/32\t10.42.0.20:51903\t25'],
                         'each host by its key, for its one address, called where scans reach it, with the path kept open')

    def test_a_link_that_stopped_reporting_is_not_running_and_its_last_word_is_not_a_reading(self):
        self.up()
        self.said(f'i\tsf0\t{key(1)}\t51903', age=sfcontroller.STALE + 5)
        got = sfcontroller.report()
        self.assertEqual((got['running'], got['interfaces']), (False, None))
        self.assertEqual(sfnet.member(sfnetwork.load(self.conn), NAME)['state'], 'pending', 'an old report gives no key')
        self.said('x\tcould not make sf0')
        self.assertEqual(sfnetwork.status(self.conn)['controller']['error'], 'could not make sf0')

    def test_a_report_is_read_as_a_host_reading_is_and_nothing_else_in_it_is_kept(self):
        self.up()
        (self.state / 'sf0.state').write_text(f't\t{int(time.time())}\ni\tsf0\t{key(1)}\t51903\nPrivateKey = {key(9)}\ni\tsf0\tnot-a-key\t1\nq\tsf0\t{key(8)}\n')
        got = sfcontroller.reading()
        self.assertEqual(got, [{'name': 'sf0', 'public_key': key(1), 'listen_port': 51903, 'peers': []}])
        (self.state / 'sf0.state').write_text('t\t' + 'x' * (sfcontroller.MAX_STATE + 10))
        self.assertEqual((sfcontroller.report()['running'], sfcontroller.report()['error']), (False, 'the link wrote more than it ever should'))
        (self.state / 'sf0.state').write_text('t\tnever\n')
        self.assertFalse(sfcontroller.report()['running'])

    def test_a_different_key_from_the_link_is_a_finding_like_any_other(self):
        self.up()
        self.said(f'i\tsf0\t{key(1)}\t51903')
        sfnetwork.observe(self.conn)
        self.said(f'i\tsf0\t{key(77)}\t51903')
        self.assertEqual(sfnetwork.observe(self.conn), [])
        self.assertEqual(sfnet.member(sfnetwork.load(self.conn), NAME)['public_key'], key(1))
        self.assertEqual([(k, v[4]) for k, v in sfnetwork.problems(self.conn).items() if k.startswith('sfnet-key')], [(f'sfnet-key:{NAME}', 'crit')])
        self.assertNotIn(key(77), json.dumps(sfnetwork.tasks(self.conn)), 'no host is told to trust it')

    def test_what_is_written_for_the_link_is_checked_before_it_is_written(self):
        network = sfnet.new()
        me = sfnet.join(network, NAME)
        for peer in ({'public_key': 'not a key', 'allowed': ['10.203.0.2/32']}, {'public_key': key(2), 'allowed': ['10.203.0.2/32; id']},
                     {'public_key': key(2), 'allowed': ['10.203.0.2/32'], 'endpoint': 'nas:51903\tx'}, {'public_key': key(2), 'allowed': ['10.203.0.2/32'], 'endpoint': '$(id):1'},
                     {'public_key': key(2), 'allowed': ['10.203.0.2/32'], 'keepalive': '25; id'}):
            with self.subTest(peer), self.assertRaises(sfnet.NetworkError):
                sfcontroller.want(network, me, [{'host': 'nas', **peer}])
        for rotation in (('now', None), ('switch', None), ('switch', 'not a key')):
            with self.subTest(rotation), self.assertRaises(sfnet.NetworkError):
                sfcontroller.want(network, me, [], rotation)
        self.assertEqual(sfcontroller.want(network, {**me, 'state': 'revoked'}, []), 'v\t1\nx\tsf0\n')
        self.assertEqual(sfcontroller.want(network, None, []), 'v\t1\nx\tsf0\n')

    def test_a_controller_that_runs_on_a_member_uses_that_host_and_needs_no_link(self):
        sfnetwork.create(self.conn, 'gabe')
        sfnetwork.join(self.conn, 'nas', 'gabe')
        with self.assertRaisesRegex(sfnet.NetworkError, 'not a member'):
            sfnetwork.controller_on(self.conn, 'pi', 'gabe')
        self.assertEqual(sfnetwork.controller_on(self.conn, 'NAS', 'gabe')['host'], 'nas')
        got = sfnetwork.status(self.conn)
        self.assertEqual((got['controller']['member'], got['controller']['link'], got['controller']['pending']), ('nas', False, False))
        self.assertEqual([(m['host'], m['is_controller'], m['link']) for m in got['members']], [('nas', True, False)])
        self.assertEqual([(t['host'], t['type']) for t in sfnetwork.tasks(self.conn)], [('nas', 'wg-interface')], 'that host is planned like any other')
        with self.assertRaisesRegex(sfnet.NetworkError, 'not on the network through a link'):
            sfnetwork.apply_controller(self.conn, 'gabe')
        self.assertEqual(sfnetwork.controller_on(self.conn, None, 'gabe'), {'host': None})
        self.assertEqual(sfnetwork.status(self.conn)['controller']['member'], None)
        sfnetwork.join_controller(self.conn, 'gabe')
        with self.assertRaisesRegex(sfnet.NetworkError, 'through its link'):
            sfnetwork.controller_on(self.conn, 'nas', 'gabe')

    def test_the_routes(self):
        users.create(self.conn, 'admin', PW, 'admin')
        users.create(self.conn, 'viewer', PW, 'viewer')
        app = server.create_app(server.App(self.db), 's' * 48)
        viewer, admin = app.test_client(), app.test_client()
        for client, name in ((viewer, 'viewer'), (admin, 'admin')):
            self.assertEqual(client.post('/api/login', json={'username': name, 'password': PW}).status_code, 200)
        for path in ('/api/sfnet/controller', '/api/sfnet/controller/apply'):
            self.assertEqual(viewer.post(path, json={}).status_code, 403, path)
        self.assertEqual(admin.post('/api/reauth', json={'password': PW}).status_code, 200)
        self.assertEqual(admin.post('/api/sfnet/controller', json={}).status_code, 400, 'no network yet')
        admin.post('/api/sfnet', json={})
        self.assertEqual(admin.post('/api/sfnet/controller/apply', json={}).status_code, 400, 'not a member yet')
        self.assertEqual(admin.post('/api/sfnet/controller', json={'endpoint': 'ctl.lab:51903'}).status_code, 400, 'a place to call has no port')
        joined = admin.post('/api/sfnet/controller', json={'endpoint': 'ctl.lab'})
        self.assertEqual((joined.status_code, joined.get_json()['host'], joined.get_json()['endpoint']), (200, NAME, 'ctl.lab'))
        self.assertEqual(admin.post('/api/sfnet/controller/apply', json={}).get_json(), {'changed': True, 'peers': 0})
        seen = viewer.get('/api/sfnet').get_json()
        self.assertEqual((seen['controller']['member'], seen['controller']['configured'], seen['controller']['pending']), (NAME, True, False))
        admin.post('/api/sfnet/members', json={'host': 'nas'})
        self.assertEqual(admin.post('/api/sfnet/members/remove', json={'host': NAME}).get_json()['state'], 'revoked')
        self.assertEqual(admin.post('/api/sfnet/controller/apply', json={}).get_json()['changed'], True)
        self.assertEqual((self.want / 'sf0.want').read_text(), 'v\t1\nx\tsf0\n', 'a controller that left asks for its interface to be removed')
        self.assertEqual(admin.post('/api/sfnet/controller', json={'on': 'nas'}).get_json()['host'], 'nas')
        self.assertEqual(admin.post('/api/sfnet/controller', json={'on': None}).get_json(), {'host': None})
        actions = [r[0] for r in self.conn.all("SELECT action FROM audit_log WHERE action LIKE 'sfnet.%' ORDER BY audit_id")]
        self.assertEqual(actions, ['sfnet.create', 'sfnet.join', 'sfnet.controller.apply', 'sfnet.join', 'sfnet.leave', 'sfnet.controller.apply', 'sfnet.controller.on', 'sfnet.controller.on'])

    def test_the_command_prints_the_link_and_the_members(self):
        import contextlib
        import io
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(cli.main(['--db', self.db.url if hasattr(self.db, 'url') else f'{self.tmp}/t.db', 'sfnet', 'link']), 0)
        self.assertEqual(out.getvalue(), sfcontroller.LINK)
        self.up()
        self.said(f'i\tsf0\t{key(77)}\t51903')
        sfnetwork.observe(self.conn)
        self.said(f'i\tsf0\t{key(78)}\t51903')
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = cli.main(['--db', self.db.url if hasattr(self.db, 'url') else f'{self.tmp}/t.db', 'sfnet'])
        self.assertEqual(code, 1, 'a member with a key that is not on record')
        self.assertIn(f'{NAME}\t10.203.0.3\tdiffers\t{key(77)[:12]}', out.getvalue())
        self.assertIn('a different key than the one on record', out.getvalue())


class TheLinkAsText(unittest.TestCase):
    def test_it_parses_and_holds_no_apostrophe(self):
        import subprocess
        self.assertEqual(subprocess.run(['bash', '-n'], input=sfcontroller.LINK, text=True, capture_output=True).stderr, '')
        self.assertNotIn("'", sfcontroller.LINK)

    def test_it_never_asks_wg_for_a_private_key_and_never_prints_a_line_it_read(self):
        code = '\n'.join(line for line in sfcontroller.LINK.splitlines() if not line.lstrip().startswith('#'))
        for never in ('showconf', 'dump', 'show "$IFACE" private-key', 'cat "$KEY"', 'cat "$NEXT"', 'set -x'):
            self.assertNotIn(never, code)
        # every message is a fixed sentence: what stop and echo are given names no variable that came from the want file
        for line in code.splitlines():
            for said in __import__('re').findall(r'(?:stop|echo) "([^"]*)"', line):
                self.assertFalse(__import__('re').search(r'\$(?!IFACE\b)', said), line)

    def test_the_compose_file_gives_the_link_one_capability_and_the_server_none(self):
        text = (Path(__file__).resolve().parents[1] / 'docker-compose.sfnet.yml').read_text()
        link = text[text.index('\n  sfnet:'):text.index('\nvolumes:')]
        server_part = text[text.index('\n  storageforge:'):text.index('\n  sfnet:')]
        self.assertIn('cap_drop: [ALL]\n    cap_add: [NET_ADMIN]', link)
        self.assertIn('no-new-privileges:true', link)
        self.assertIn('read_only: true', link)
        self.assertIn('network_mode: "service:storageforge"', link)
        self.assertIn('sf-sfnet-want:/run/storageforge-sfnet/want:ro', link, 'the link only reads what the server wants')
        self.assertIn('sf-sfnet-state:/run/sf-sfnet-state:ro', server_part, 'the server only reads what the link reports')
        self.assertNotIn('sf-sfnet-keys', server_part, 'the server never mounts the folder of the private key')
        self.assertNotIn('cap_add', server_part)
        self.assertNotIn('privileged', text)


# ── the link itself, with real WireGuard ──
@unittest.skipUnless(wgworld.WORKS, wgworld.NEEDS)
class RealLink(Base):
    ON = {'nas': '10.203.0.1', 'pi': '10.203.0.2', NAME: '10.203.0.3'}

    def setUp(self):
        super().setUp()
        self.m = wgworld.Machines(self, (('controller', '10.42.0.2'), *self.HOSTS))
        self.program = self.tmp / 'storageforge-sfnet-link'
        self.program.write_text(sfcontroller.LINK)
        self.secrets = set()

    def link(self, how='once', **env):
        ran = self.m.run('controller', f'bash {self.program} {how}', SF_WG_WANT=str(self.want), SF_WG_STATE=str(self.state), **env)
        self.secrets |= self.m.private_keys()
        return ran

    def report(self) -> str:
        return (self.state / 'sf0.state').read_text()

    def read_all(self):
        for host, _ in self.HOSTS:
            store(self.conn, host, self.m.reading(host))
        self.secrets |= self.m.private_keys()

    def settle(self, limit=8) -> list:
        """Until nothing is left to do: hand the link what the controller wants and let it run a pass, run the hosts' plan, read
        every host. Returns what each round did."""
        rounds = []
        while True:
            asked = sfnetwork.apply_controller(self.conn, 'gabe')['changed']
            self.assertEqual(self.link().returncode, 0)
            todo = sfnetwork.tasks(self.conn)
            if not todo and not asked:
                return rounds
            self.assertLess(len(rounds), limit, f'it does not settle: {todo}')
            rounds.append((asked, sorted({(t['type'], t['params'].get('phase') or t['params'].get('state') or 'present') for t in todo})))
            for t in todo:
                self.m.step(t)
            self.read_all()

    def up(self):
        sfnetwork.create(self.conn, 'gabe')
        for host, _ in self.HOSTS:
            sfnetwork.join(self.conn, host, 'gabe')
        sfnetwork.join_controller(self.conn, 'gabe')
        self.read_all()
        return self.settle()

    def reaches(self, machine, address, within=12) -> bool:
        """A ping gets through, now or within seconds: a handshake that was sent before the other side knew this key is sent again
        by WireGuard five seconds later, and not sooner."""
        until = time.time() + within
        while not self.m.ping(machine, address):
            if time.time() > until:
                return False
        return True

    def show(self, machine, what):
        return self.m.run(machine, f'wg show sf0 {what}').stdout.strip()

    def test_the_controller_joins_reaches_the_hosts_rotates_its_key_and_leaves(self):
        self.assertEqual(self.link().returncode, 0, 'with nothing asked of it, it reports and does nothing')
        self.assertNotIn('i\t', self.report())
        self.assertNotEqual(self.m.run('controller', 'ip link show dev sf0').returncode, 0)
        self.up()
        got = sfnetwork.status(self.conn)
        self.assertEqual([(m['host'], m['state'], m['missing']) for m in got['members']], [('nas', 'ok', []), ('pi', 'ok', []), (NAME, 'ok', [])])
        self.assertEqual((got['controller']['running'], got['controller']['pending'], got['controller']['error']), (True, False, None))
        mine = self.show('controller', 'public-key')
        self.assertEqual(sfnet.member(sfnetwork.load(self.conn), NAME)['public_key'], mine, 'on record is the key the link made')
        self.assertEqual(self.m.run('controller', 'ip -o -4 addr show dev sf0').stdout.split()[3], '10.203.0.3/20')
        self.assertEqual(self.show('controller', 'listen-port'), '51903')
        self.assertEqual(((self.m.keys('controller') / 'sf0.key').stat().st_mode & 0o777, (self.m.keys('controller')).stat().st_mode & 0o777), (0o600, 0o700))
        # it calls the hosts, which were not told where it is, and then they answer it
        self.assertTrue(self.reaches('controller', self.ON['nas']) and self.reaches('controller', self.ON['pi']), 'the controller reaches each host across the network')
        self.assertTrue(self.reaches('nas', self.ON[NAME]), 'and a host reaches it, on the path the controller opened')
        self.assertEqual(self.link().returncode, 0)
        before = self.show('controller', 'latest-handshakes')
        self.assertEqual(self.link().returncode, 0, 'a pass with nothing to change')
        self.assertEqual(self.show('controller', 'latest-handshakes'), before, 'leaves the peers and their sessions as they are')

        # the key of the controller, rotated: the link makes the next pair, the hosts learn it, the link switches
        old_private = (self.m.keys('controller') / 'sf0.key').read_text().strip()
        sfnetwork.rotate(self.conn, NAME, 'gabe')
        self.assertTrue(sfnetwork.status(self.conn)['controller']['pending'])
        rounds = self.settle()
        self.assertEqual([r[1] for r in rounds], [[('wg-peer', 'present')], [('wg-peer', 'absent'), ('wg-peer', 'present')], []],
                         'the link makes a key and the hosts learn it; it switches and the hosts move its address and drop the old key; the last asks nothing new of a host')
        new = self.show('controller', 'public-key')
        self.assertNotEqual(new, mine)
        self.assertEqual(sfnet.member(sfnetwork.load(self.conn), NAME)['public_key'], new)
        self.assertEqual(sorted(f.name for f in self.m.keys('controller').iterdir()), ['sf0.key', 'sf0.storageforge'])
        self.assertNotEqual((self.m.keys('controller') / 'sf0.key').read_text().strip(), old_private, 'the old private key is gone')
        self.assertTrue(self.reaches('controller', self.ON['nas']) and self.reaches('controller', self.ON['pi']))
        self.assertEqual(sfnetwork.problems(self.conn), {})

        # the key of a host, rotated: that host does not switch until the controller's link holds the new key too
        sfnetwork.rotate(self.conn, 'nas', 'gabe')
        self.m.step(sfnetwork.tasks(self.conn)[0])
        self.read_all()
        for t in sfnetwork.tasks(self.conn):
            self.m.step(t)
        self.read_all()
        self.assertEqual(self.row('nas')['rotation'], {'step': 'tell the peers', 'waiting': [NAME]})
        self.assertNotIn('wg-rotate', [t['type'] for t in sfnetwork.tasks(self.conn)])
        self.settle()
        self.assertEqual((self.row('nas')['rotation'], self.row('nas')['state']), (None, 'ok'))
        self.assertIn(self.show('nas', 'public-key'), self.show('controller', 'peers'))
        self.assertTrue(self.reaches('controller', self.ON['nas']))

        # nothing the controller holds or was shown has a private key in it
        self.assertGreaterEqual(len(self.secrets), 5, 'three first keys and two rotated ones')
        kept = json.dumps(alerts.get_setting(self.conn, sfnetwork.KEY)) + json.dumps([list(r) for r in self.conn.all('SELECT data_json FROM security_measurements')])
        shown = '\n'.join(self.m.said) + self.report() + (self.want / 'sf0.want').read_text()
        for secret in self.secrets:
            self.assertNotIn(secret, kept, 'in the index')
            self.assertNotIn(secret, shown, 'in what the link printed or reported, or in what it was asked')

        # the controller leaves: its key comes off the hosts, and its interface and key are removed
        sfnetwork.leave(self.conn, NAME, 'gabe')
        self.settle()
        self.assertNotEqual(self.m.run('controller', 'ip link show dev sf0').returncode, 0)
        self.assertEqual(list(self.m.keys('controller').iterdir()), [])
        self.assertNotIn(new, self.show('nas', 'peers') + self.show('pi', 'peers'))
        self.assertNotIn('i\t', self.report())

    def test_a_want_file_that_is_not_what_the_controller_writes_changes_nothing(self):
        self.up()
        good = (self.want / 'sf0.want').read_text()
        peers, address = self.show('controller', 'allowed-ips'), self.m.run('controller', 'ip -o -4 addr show').stdout
        marker = self.tmp / 'ran'
        nas = sfnet.member(sfnetwork.load(self.conn), 'nas')['public_key']
        bad = {
            'a peer line is not a key': f'p\t$(touch {marker})\t-\t-\t-',
            'a peer line is not a key, addresses': f'p\t{nas}\t10.203.0.1/32;touch {marker}\t-\t-',
            'a peer line is not': f'p\t{nas}\t10.203.0.1/32\t`touch {marker}`:51903\t-',
            'a peer line': f'p\t{nas}\t10.203.0.1/32\t-\t25 --help',
            'the interface line is not an address and a port': f'i\tsf0\t10.203.0.3/20 dev eth0\t51903',
            'the interface line is not': 'i\teth0\t10.42.0.99/24\t51903',
            'only sf0 can be removed': 'x\teth0',
            'the want file has a line this link does not know': f'PostUp = touch {marker}',
            'the rotation line is not': f'r\tswitch\t$(touch {marker})',
            'the want file is of a version this link does not know': 'v\t2',
        }
        for want, line in bad.items():
            with self.subTest(line):
                (self.want / 'sf0.want').write_text(good + line + '\n')
                ran = self.link()
                self.assertNotEqual(ran.returncode, 0)
                said = self.report()
                self.assertIn(f'x\t{want}', said)
                self.assertNotIn('touch', said + ran.stdout + ran.stderr, 'no line of the want file is ever repeated')
                self.assertEqual((self.show('controller', 'allowed-ips'), self.m.run('controller', 'ip -o -4 addr show').stdout), (peers, address), 'and nothing is changed')
        self.assertFalse(marker.exists(), 'nothing in a want file is ever run')
        self.assertIn('eth0', self.m.run('controller', 'ip -o link show').stdout)
        # a want file that is a link to the private key: not read as a want file, and never repeated
        (self.want / 'sf0.want').unlink()
        (self.want / 'sf0.want').symlink_to(self.m.keys('controller') / 'sf0.key')
        ran = self.link()
        private = (self.m.keys('controller') / 'sf0.key').read_text().strip()
        self.assertNotIn(private, self.report() + ran.stdout + ran.stderr)
        self.assertEqual(self.show('controller', 'allowed-ips'), peers)
        # more than it should ever hold
        (self.want / 'sf0.want').unlink()
        (self.want / 'sf0.want').write_text('v\t1\n' + ''.join(f'p\t{nas}\t-\t-\t-\n' for _ in range(5001)))
        self.assertNotEqual(self.link().returncode, 0)
        self.assertIn('more lines than it ever should', self.report())
        (self.want / 'sf0.want').write_text(good)
        self.assertEqual(self.link().returncode, 0)
        self.assertEqual((self.show('controller', 'allowed-ips'), 'x\t' in self.report()), (peers, False), 'what the controller writes is taken again')

    def test_an_interface_the_link_did_not_make_is_left_alone(self):
        sfnetwork.create(self.conn, 'gabe')
        sfnetwork.join_controller(self.conn, 'gabe')
        sfnetwork.apply_controller(self.conn, 'gabe')
        self.m.run('controller', 'ip link add sf0 type wireguard && umask 077 && mkdir -p "$SF_WG_DIR" && wg genkey > "$SF_WG_DIR/theirs" && wg set sf0 private-key "$SF_WG_DIR/theirs"')
        theirs = self.show('controller', 'public-key')
        self.assertNotEqual(self.link().returncode, 0)
        self.assertIn('x\tsf0 is here and StorageForge did not make it: it is left as it is', self.report())
        self.assertNotIn('i\t', self.report(), 'and its key is not reported as the controller\'s')
        self.assertEqual((self.show('controller', 'public-key'), sfnet.member(sfnetwork.load(self.conn), NAME)['state']), (theirs, 'pending'))
        self.m.run('controller', 'ip link del sf0 && ip link add sf0 type bridge')
        self.assertNotEqual(self.link().returncode, 0)
        self.assertIn('x\tsf0 is here and is not a WireGuard interface: it is left as it is', self.report())
        self.assertFalse((self.m.keys('controller') / 'sf0.key').exists(), 'no key is made for an interface it will not make')

    def test_left_alone_in_a_network_that_is_gone_it_stops(self):
        # as when the server container restarts without it: only lo and its own interface remain
        self.assertEqual(self.link('once').returncode, 0)
        self.m.run('controller', 'ip link del eth0')
        ran = self.link('run', SF_WG_EVERY='1')
        self.assertEqual(ran.returncode, 1)
        self.assertIn('the network this was started in is gone', ran.stderr)


if __name__ == '__main__':
    unittest.main()
