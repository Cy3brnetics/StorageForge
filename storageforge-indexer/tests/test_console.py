"""The web console (console.py): a session on a pseudo-terminal of its own, its recording, its routes, and the API's
rules: who may open one, the password again for each, nobody else's session, and the console page's own policy."""
import base64
import json
import os
import shutil
import tempfile
import time
import unittest
from pathlib import Path

try:
    import dbfactory
except ImportError:      # run as tests.test_x from the project folder
    from tests import dbfactory
from storageforge_index import console, permissions, server, users

PW = 'a long enough password'


def until(fn, t=10):
    end = time.time() + t
    while time.time() < end:
        got = fn()
        if got:
            return got
        time.sleep(0.05)
    return None


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        os.environ['STORAGEFORGE_DATA_DIR'] = self.tmp
        self.addCleanup(os.environ.pop, 'STORAGEFORGE_DATA_DIR', None)
        self.db = dbfactory.make(self, Path(self.tmp) / 'index.db')
        self.conn = self.db.connect()
        self.db.migrate(self.conn)
        self.addCleanup(self.conn.close)
        self.addCleanup(console.close_all, 'test over')

    def shell(self, owner='alice', record=False):
        """A session on a real pseudo-terminal, with sh in it instead of ssh."""
        if record:
            console.save_settings(self.conn, {'record': True}, 'test')
        s = console.Session(owner, 'web-01', 'ssh', 'lan', '10.0.0.5', 80, 24)
        self.audit = []
        s._audit = lambda action, detail: self.audit.append((action, detail))
        s._start_recording(self.conn, 'web-01 (ssh, lan)')
        s.spawn(['/bin/sh', '-i'], {'PATH': os.environ['PATH'], 'PS1': '$ ', 'TERM': 'xterm-256color'})
        with console._LOCK:
            console._REGISTRY[s.id] = s
        return s

    def text(self, s, after=0):
        return s.read_after(after, wait=0.2)['data'].decode(errors='replace')


class Session(Base):
    def test_typed_in_shown_back_resized_and_closed(self):
        s = self.shell()
        s.write(b'echo SF-$((6*7))\n')
        self.assertTrue(until(lambda: 'SF-42' in self.text(s)))
        s.resize(132, 40)
        s.write(b'stty size\n')
        self.assertTrue(until(lambda: '40 132' in self.text(s)), self.text(s))
        s.write(b'exit\n')
        self.assertTrue(until(lambda: s.closed))
        self.assertEqual(self.audit[-1][0], 'console.close')
        d = self.audit[-1][1]
        self.assertEqual(d['reason'], 'ended')
        self.assertGreater(d['bytes_in'], 0)
        self.assertGreater(d['bytes_out'], 0)
        with self.assertRaises(console.ConsoleError):
            s.write(b'x')

    def test_a_reader_waits_for_output_and_learns_it_ended(self):
        s = self.shell()
        first = s.read_after(0, wait=2)['next']
        while s.read_after(first, wait=0.3)['next'] != first:      # until sh has printed all it will: its prompt can come late
            first = s.read_after(first, wait=0)['next']
        start = time.time()
        got = s.read_after(first, wait=0.5)
        self.assertGreaterEqual(time.time() - start, 0.45)      # nothing new: it waited
        self.assertEqual(got['data'], b'')
        s.close('closed in the browser')
        self.assertEqual(s.read_after(first, wait=5)['closed'], 'closed in the browser')

    def test_a_recording_holds_input_output_and_the_end(self):
        s = self.shell(record=True)
        s.write(b'echo RECORDED\n')
        until(lambda: 'RECORDED\r\n' in self.text(s))
        s.close('closed in the browser')
        p = console.recordings_dir() / s.rec_name
        self.assertEqual(p.stat().st_mode & 0o777, 0o600)
        lines = [json.loads(x) for x in p.read_text().splitlines()]
        self.assertEqual((lines[0]['version'], lines[0]['sf']['host'], lines[0]['sf']['user']), (2, 'web-01', 'alice'))
        self.assertEqual(''.join(e[2] for e in lines[1:] if e[1] == 'i'), 'echo RECORDED\n')
        self.assertTrue(any(e[1] == 'o' and 'RECORDED' in e[2] for e in lines[1:]))
        self.assertEqual(lines[-1][1:], ['x', 'closed in the browser'])
        self.assertEqual([r['name'] for r in console.recordings(self.conn)], [s.rec_name])
        with self.assertRaises(LookupError):
            console.recording_path('../index.db')

    def test_no_recording_unless_it_is_on(self):
        s = self.shell()
        self.assertIsNone(s.rec_name)
        self.assertEqual(list(console.recordings_dir().glob('*.cast')), [])

    def test_an_idle_session_is_closed(self):
        s = self.shell()
        s.active = time.time() - console.IDLE - 1
        console.reap()
        self.assertIn('idle', s.closed)

    def test_a_session_is_its_owners_alone(self):
        s = self.shell('alice')
        self.assertIs(console.get(s.id, 'alice'), s)
        with self.assertRaises(LookupError):
            console.get(s.id, 'bob')


class Routes(Base):
    def add(self, name, ssh_host, interfaces):
        self.conn.execute("INSERT INTO hosts (hostname, ssh_host, ssh_user) VALUES (:n, :a, 'scan')", {'n': name, 'a': ssh_host})
        hid = self.conn.scalar('SELECT host_id FROM hosts WHERE hostname = :n', {'n': name})
        self.conn.execute('INSERT INTO host_network (host_id, data_json, updated_at) VALUES (:h, :d, 0)',
                          {'h': hid, 'd': json.dumps({'interfaces': interfaces})})

    def test_lan_and_tailscale_from_the_scan(self):
        self.add('vm1', '10.77.0.121', [{'name': 'enp1s0', 'addresses': [{'ip': '10.77.0.121'}]},
                                        {'name': 'tailscale0', 'addresses': [{'ip': '100.120.104.24'}, {'ip': 'fd7a:115c:a1e0::1'}]}])
        self.assertEqual([(r['route'], r['address']) for r in console.routes(self.conn, 'vm1')],
                         [('lan', '10.77.0.121'), ('tailscale', '100.120.104.24')])
        self.add('vm2', '10.0.0.2', [{'name': 'eth0', 'addresses': [{'ip': '10.0.0.2'}]}])
        self.assertEqual([r['route'] for r in console.routes(self.conn, 'vm2')], ['lan'])
        with self.assertRaises(LookupError):
            console.routes(self.conn, 'nowhere')

    def test_ssh_takes_only_a_confirmed_host_key_and_carries_nothing_along(self):
        argv = console._ssh_argv('/run/agent.sock', 'rpi', '100.120.104.24', 22, '10.77.0.121')
        joined = ' '.join(argv)
        for want in ('StrictHostKeyChecking=yes', 'HostKeyAlias=10.77.0.121', 'ForwardAgent=no', 'ForwardX11=no',
                     'ClearAllForwardings=yes', 'PasswordAuthentication=no', '-tt'):
            self.assertIn(want, joined)
        self.assertEqual(argv[-2:], ['--', 'rpi@100.120.104.24'])

    def test_the_vault_allows_a_console_binding(self):
        import inspect
        from storageforge_index import vault
        self.assertIn("'deploy', 'console'}", inspect.getsource(vault.Vault.bind))     # a key bound for console, apart from scans


class Api(Base):
    def setUp(self):
        super().setUp()
        users.create(self.conn, 'alice', PW, 'admin')
        users.create(self.conn, 'olga', PW, 'operator')
        self.app = server.create_app(server.App(self.db), 's' * 48)

    def client(self, who):
        c = self.app.test_client()
        self.assertEqual(c.post('/api/login', json={'username': who, 'password': PW}).status_code, 200)
        return c

    def test_admins_only_by_default(self):
        self.assertIn('console.open', permissions.HIGH_RISK)
        self.assertNotIn('console.open', permissions.BUILTIN['operator'][1])
        self.assertEqual(self.client('olga').post('/api/console/sessions', json={'host': 'x'}).status_code, 403)
        page = self.client('olga').get('/console')
        self.assertEqual(page.status_code, 302)                 # no console page either

    def test_the_password_again_for_a_session(self):
        c = self.client('alice')
        with c.session_transaction() as sess:
            sess['auth_at'] = 0
        r = c.post('/api/console/sessions', json={'host': 'web-01'})
        self.assertEqual((r.status_code, r.json.get('reauth')), (403, True))

    def test_input_output_through_the_api_and_nobody_elses(self):
        c = self.client('alice')
        s = self.shell('alice')
        r = c.post(f'/api/console/sessions/{s.id}/input', json={'data': base64.b64encode(b'echo VIA-API\n').decode()})
        self.assertEqual(r.status_code, 200)
        seen = until(lambda: 'VIA-API' in base64.b64decode(c.get(f'/api/console/sessions/{s.id}/output?after=0&wait=1').json['data']).decode(errors='replace'))
        self.assertTrue(seen)
        bob = s.id
        users.create(self.conn, 'adam', PW, 'admin')         # another admin: still not his
        other = self.client('adam')
        self.assertEqual(other.get(f'/api/console/sessions/{bob}/output?after=0&wait=0').status_code, 404)
        self.assertEqual(other.post(f'/api/console/sessions/{bob}/input', json={'data': 'eA=='}).status_code, 404)
        too_big = base64.b64encode(b'x' * 70000).decode()
        self.assertEqual(c.post(f'/api/console/sessions/{s.id}/input', json={'data': too_big}).status_code, 413)
        self.assertEqual(c.delete(f'/api/console/sessions/{s.id}').status_code, 200)
        self.assertTrue(until(lambda: s.closed))

    def test_what_a_host_offers(self):
        self.conn.execute("INSERT INTO hosts (hostname, ssh_host, ssh_user) VALUES ('vm1', '10.77.0.121', 'scan')")
        hid = self.conn.scalar("SELECT host_id FROM hosts WHERE hostname = 'vm1'")
        self.conn.execute('INSERT INTO host_network (host_id, data_json, updated_at) VALUES (:h, :d, 0)',
                          {'h': hid, 'd': json.dumps({'interfaces': [{'name': 'tailscale0', 'addresses': [{'ip': '100.64.1.2'}]}]})})
        got = self.client('alice').get('/api/console/hosts/vm1').json
        self.assertEqual([r['route'] for r in got['routes']], ['lan', 'tailscale'])
        self.assertEqual((got['recording'], got['open']), (False, []))
        self.assertEqual(self.client('alice').get('/api/console/hosts/nowhere').status_code, 404)
        self.assertEqual(self.client('olga').get('/api/console/hosts/vm1').status_code, 403)

    def test_the_console_page_alone_allows_style_elements(self):
        c = self.client('alice')
        page = c.get('/console')
        self.assertEqual(page.status_code, 200)
        self.assertIn("style-src 'self' 'unsafe-inline'", page.headers['Content-Security-Policy'])
        self.assertIn("script-src 'self';", page.headers['Content-Security-Policy'])
        self.assertNotIn("'unsafe-inline'", c.get('/').headers['Content-Security-Policy'].split('style-src-attr')[0])
        self.assertEqual(c.get('/xterm.js').status_code, 200)

    def test_recording_is_set_by_settings_managers_and_logged(self):
        c = self.client('alice')
        self.assertEqual(c.put('/api/console/settings', json={'record': 'yes'}).status_code, 400)
        r = c.put('/api/console/settings', json={'record': True, 'keep_days': 30})
        self.assertEqual((r.status_code, r.json), (200, {'record': True, 'keep_days': 30}))
        self.assertTrue(self.conn.scalar("SELECT 1 FROM audit_log WHERE action = 'console.settings'"))
        self.assertEqual(self.client('olga').put('/api/console/settings', json={'record': False}).status_code, 403)
        self.assertEqual(c.get('/api/console/recordings/..%2Findex.db').status_code, 404)


if __name__ == '__main__':
    unittest.main()
