"""Remote nodes: the install script, the keys it may use, and the tunnel's lockdown against a real sshd running the
config the container ships. Reverse tunnels from real machines through the real container are lab tier 7."""
import os
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

try:
    import dbfactory
except ImportError:      # run as tests.test_x from the project folder
    from tests import dbfactory
from storageforge_index import moves, remotes, retire, server, users, vault

CONFIG = Path(__file__).resolve().parents[1] / 'docker' / 'tunnel' / 'sshd_config'
SECRET = 'x' * 48
PW = 'a long enough password'


def new_key(path: Path) -> str:
    k = ed25519.Ed25519PrivateKey.generate()
    path.write_bytes(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, serialization.NoEncryption()))
    path.chmod(0o600)
    return k.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='sf-remote-'))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        (self.tmp / 'keys').mkdir()
        (self.tmp / 'host').mkdir()
        (self.tmp / 'host' / 'ssh_host_ed25519_key.pub').write_text('ssh-ed25519 AAAATUNNELKEY storageforge-tunnel\n')
        env = {'STORAGEFORGE_TUNNEL_KEYS': str(self.tmp / 'keys'), 'STORAGEFORGE_TUNNEL_HOST': str(self.tmp / 'host'),
               'STORAGEFORGE_VAULT_SECRET': SECRET}
        patcher = mock.patch.dict(os.environ, env)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.db = dbfactory.make(self, self.tmp / 'idx.db')
        self.conn = self.db.connect()
        self.addCleanup(self.conn.close)
        self.db.migrate(self.conn)
        vault.Vault(self.db, self.conn, SECRET.encode()).init()

    def add(self, name='cabin', endpoint='forge.example.com:2222'):
        return remotes.add(self.db, self.conn, name, endpoint, 'tester')

    def authorized(self):
        return (self.tmp / 'keys' / 'authorized_keys').read_text()


class Nodes(Base):
    def test_a_node_gets_one_address_and_only_the_public_key_is_kept(self):
        a, b = self.add('cabin'), self.add('barn')
        self.assertNotEqual(a['address'], b['address'])
        self.assertTrue(a['address'].startswith('127.77.'))
        self.assertIn('BEGIN OPENSSH PRIVATE KEY', a['script'])
        self.assertNotIn('PRIVATE', ''.join(str(r) for r in self.conn.all('SELECT * FROM remote_nodes')))
        self.assertNotIn('PRIVATE', self.authorized())
        self.assertIn(f'permitlisten="{a["address"]}:{remotes.LISTEN_PORT}"', self.authorized())
        for line in self.authorized().splitlines():
            self.assertTrue(line.startswith('restrict,port-forwarding,permitlisten="'), line)
            self.assertIn('command="/bin/false"', line)

    def test_an_unused_key_expires_and_an_expired_one_is_not_offered(self):
        self.add()
        self.assertIn('expiry-time="', self.authorized())
        self.assertEqual(remotes.authorized_lines(self.conn, now=time.time() + 2 * remotes.INVITE_SECONDS), '')

    def test_adopting_needs_the_tunnel_up_and_lifts_the_expiry(self):
        node = self.add()
        with self.assertRaisesRegex(ValueError, 'not connected'):
            remotes.adopt(self.db, self.conn, node['id'], 't', lambda a: None)
        self.assertIn('expiry-time', self.authorized())
        queued = []
        with mock.patch.object(remotes, 'online', return_value=True):
            out = remotes.adopt(self.db, self.conn, node['id'], 't', queued.append)
        self.assertEqual((out['state'], queued), ('scanning', [node['address']]))
        self.assertNotIn('expiry-time', self.authorized())

    def test_revoking_removes_the_key_its_bindings_and_every_session(self):
        from storageforge_index.vault import Vault
        node = self.add()
        remotes.revoke(self.db, self.conn, node['id'], 't')
        self.assertEqual(self.authorized(), '')
        self.assertTrue((self.tmp / 'keys' / 'generation').read_text().strip())
        with Vault(self.db, self.conn).unlock() as v:
            self.assertFalse([b for b in v.bindings() if b['pattern'] == node['address']])
        again = self.add()                      # the name is free again, on an address nothing pinned
        self.assertNotEqual(again['address'], node['address'])

    def test_the_database_decides_what_the_tunnel_reads(self):
        self.add()
        (self.tmp / 'keys' / 'authorized_keys').write_text('ssh-ed25519 AAAASOMEONE planted\n')
        remotes.overview(self.conn)
        self.assertNotIn('planted', self.authorized())

    def test_looking_at_the_list_writes_nothing_when_nothing_changed(self):
        self.add()
        before = (self.tmp / 'keys' / 'authorized_keys').stat().st_ino
        remotes.overview(self.conn)
        self.assertEqual((self.tmp / 'keys' / 'authorized_keys').stat().st_ino, before)

    def test_nodes_are_probed_together(self):
        for name in ('a', 'b', 'c'):
            self.add(name)
        met = threading.Barrier(3, timeout=10)      # passes only if all three probes are out at once

        def probe(addr):
            met.wait()
            return False
        with mock.patch.object(remotes, 'online', probe):
            self.assertEqual(len(remotes.overview(self.conn)['nodes']), 3)

    def test_a_node_nobody_is_behind_answers_at_once(self):
        """The tunnel shares this network: no forward means a refusal, so only a hung node can use the timeout."""
        started = time.monotonic()
        self.assertFalse(remotes.online(remotes.address(60000)))
        self.assertLess(time.monotonic() - started, 1)

    def test_addresses_run_out_rather_than_wrap(self):
        self.assertEqual(remotes.address(remotes.MAX_NODE_ID), '127.77.255.255')
        self.conn.execute("""INSERT INTO remote_nodes (node_id, name, public_key, created_at, created_by, expires_at, revoked_at)
                             VALUES (:i, 'old', 'k', 1, 't', 1, 1)""", {'i': remotes.MAX_NODE_ID})
        with self.assertRaisesRegex(ValueError, 'every remote node address'):
            self.add()

    def retiring(self, name, node_address):
        self.conn.execute("INSERT INTO hosts (hostname, ssh_host, ssh_user, inventory_json) VALUES (:h, :a, 'sfscan', '{}')", {'h': name, 'a': node_address})
        return retire.retire(self.conn, name)

    def test_retiring_its_host_cuts_the_tunnel(self):
        """SF-40, EQ-06: the key stayed in authorized_keys, and the machine kept its address here for good."""
        node, other = self.add('cabin'), self.add('barn')
        self.assertEqual(self.retiring('cabin-host', node['address'])['remote_node'], 'cabin')
        self.assertNotIn('storageforge:node:cabin', self.authorized())
        self.assertIn('storageforge:node:barn', self.authorized())
        self.assertTrue((self.tmp / 'keys' / 'generation').read_text().strip())
        self.assertEqual([n['name'] for n in remotes.overview(self.conn)['nodes']], ['barn'])
        with vault.Vault(self.db, self.conn).unlock() as v:
            self.assertFalse([b for b in v.bindings() if b['pattern'] == node['address']])
            self.assertTrue([b for b in v.bindings() if b['pattern'] == other['address']])

    def test_retiring_any_other_host_leaves_the_nodes_alone(self):
        self.add()
        keys = self.authorized()
        self.assertNotIn('remote_node', self.retiring('lan-host', '10.0.0.9'))
        self.assertEqual(self.authorized(), keys)
        self.assertFalse((self.tmp / 'keys' / 'generation').exists())

    def test_bad_values_are_refused(self):
        for name in ('', '-x', 'a b', '$(id)', "a'b", 'a/b', 'x' * 64):
            with self.assertRaises(ValueError, msg=name):
                self.add(name)
        for endpoint in ('', 'a b', '$(id):22', '-oProxyCommand=x', 'a:99999', "a';id;'"):
            with self.assertRaises(ValueError, msg=endpoint):
                self.add('ok', endpoint)
        self.assertEqual(self.conn.scalar('SELECT count(*) FROM remote_nodes'), 0)

    def test_no_tunnel_says_so(self):
        (self.tmp / 'host' / 'ssh_host_ed25519_key.pub').unlink()
        with self.assertRaisesRegex(ValueError, 'docker-compose.remote.yml'):
            self.add()

    def test_a_job_cannot_pull_from_a_node_it_cannot_reach(self):
        for h, addr in (('nas', '127.77.0.5'), ('pc', '10.0.0.2')):
            self.conn.execute("INSERT INTO hosts (hostname, ssh_host, ssh_user, inventory_json) VALUES (:h, :a, 'scan', '{}')", {'h': h, 'a': addr})
            hid = self.conn.scalar('SELECT host_id FROM hosts WHERE hostname = :h', {'h': h})
            self.conn.execute("INSERT INTO mounts (host_id, mount_point, source, filesystem_type, total_bytes, used_bytes, scan_state, mount_options) "
                              "VALUES (:h, '/', '/dev/sda1', 'ext4', 1000, 1, 'indexed', 'rw')", {'h': hid})

        def texts(**o):
            plan = moves.normalize({'name': 'p', 'steps': [{'method': 'copy', 'src': {'host': 'nas', 'path': '/a'}, 'dst': {'host': 'pc', 'path': '/b'}, 'options': o}]})
            return [i['text'] for s in moves.check(self.conn, plan)['steps'] for i in s['items'] if i['level'] == 'crit']
        self.assertTrue(any('remote node' in t for t in texts()))
        self.assertFalse(any('remote node' in t for t in texts(routes=[{'via': 'mesh', 'address': '100.64.0.5'}])))


class Script(Base):
    def script(self):
        path = self.tmp / 'node.sh'
        path.write_text(self.add()['script'])
        return path

    def test_it_is_valid_bash_and_every_generated_part_is(self):
        p = subprocess.run(['bash', '-n', str(self.script())], capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)

    def test_it_pins_the_tunnel_and_binds_only_its_own_address(self):
        node = self.add('barn')
        text = node['script']
        self.assertIn('[forge.example.com]:2222 ssh-ed25519 AAAATUNNELKEY', text)
        self.assertIn('StrictHostKeyChecking=yes', text)
        self.assertNotIn('accept-new', text.split('@')[0])
        self.assertIn(f'LISTEN={node["address"]}:{remotes.LISTEN_PORT}', text)
        self.assertIn('sftunnel@$HOST', text)

    @unittest.skipIf(os.geteuid() == 0, 'as root it could only be read')
    def test_no_flags_only_reports(self):
        p = subprocess.run(['bash', str(self.script())], capture_output=True, text=True, timeout=60)
        self.assertNotIn('BEGIN OPENSSH', p.stdout + p.stderr)
        self.assertRegex(p.stdout, 'report only|problem')
        self.assertFalse(Path('/etc/storageforge/remote/key').exists() and os.access('/etc/storageforge/remote/key', os.W_OK))

    @unittest.skipIf(os.geteuid() == 0, 'as root it would change this machine')
    def test_changing_anything_takes_root(self):
        script = self.script()
        for flag in ('--apply', '--remove'):
            p = subprocess.run(['bash', str(script), flag], capture_output=True, text=True, timeout=30)
            self.assertEqual(p.returncode, 1)
            self.assertIn('run as root', p.stderr)

    def test_the_unit_runs_under_selinux(self):
        """The lab found this on Rocky 10: NoNewPrivileges stops the exec of ssh with Permission denied."""
        unit = self.add('unit')['script'].split('[Service]')[1].split('[Install]')[0]
        self.assertNotIn('NoNewPrivileges', unit)
        self.assertIn('CapabilityBoundingSet=', unit)
        self.assertIn('ExecStart=$BIN', unit)          # never ssh itself: systemd may not start ssh_exec_t programs
        self.assertIn('User=$RUNAS', unit)

    def test_unknown_flags_are_refused(self):
        self.assertEqual(subprocess.run(['bash', str(self.script()), '--nope'], capture_output=True).returncode, 2)


class Routes(Base):
    def setUp(self):
        super().setUp()
        users.create(self.conn, 'root', PW, 'admin')
        self.web = server.create_app(server.App(self.db), 's' * 48).test_client()

    def test_the_routes_need_a_session_and_a_fresh_password(self):
        self.assertEqual(self.web.post('/api/remote/nodes', json={'name': 'a'}).status_code, 401)
        self.assertEqual(self.web.post('/api/login', json={'username': 'root', 'password': PW}).status_code, 200)
        with self.web.session_transaction() as s:
            s['auth_at'] = 0
        self.assertTrue(self.web.post('/api/remote/nodes', json={'name': 'a'}).get_json().get('reauth'))
        self.assertEqual(self.conn.scalar('SELECT count(*) FROM remote_nodes'), 0)

    def test_add_list_and_revoke(self):
        self.web.post('/api/login', json={'username': 'root', 'password': PW})
        r = self.web.post('/api/remote/nodes', json={'name': 'cabin', 'endpoint': 'forge.example.com'})
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True))
        self.assertIn('--apply', r.get_json()['script'])
        got = self.web.get('/api/remote/nodes').get_json()
        self.assertEqual((got['endpoint'], got['nodes'][0]['state']), ('forge.example.com', 'waiting'))
        self.assertNotIn('PRIVATE', str(got))
        self.assertEqual(self.web.delete(f'/api/remote/nodes/{got["nodes"][0]["id"]}').status_code, 200)
        self.assertEqual(self.web.get('/api/remote/nodes').get_json()['nodes'], [])
        self.assertEqual(self.web.delete('/api/remote/nodes/9999').status_code, 404)


@unittest.skipUnless(shutil.which('sshd') and shutil.which('ssh'), 'needs OpenSSH')
@unittest.skipIf(os.geteuid() == 0, 'runs sshd as the test user, as the container does')
class Lockdown(unittest.TestCase):
    """The config the tunnel container ships, on a real sshd. What stands between a stolen key and this server."""
    ME = '127.77.9.1'

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='sf-tun-'))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.port, self.listen = self.free(), self.free()
        hostkey = self.tmp / 'host'
        new_key(hostkey)
        self.user = os.environ.get('USER') or subprocess.run(['id', '-un'], capture_output=True, text=True).stdout.strip()
        cfg = CONFIG.read_text()
        for a, b in ((r'Port 2222', f'Port {self.port}\nListenAddress 127.0.0.1'), ('/var/lib/sf-tunnel/ssh_host_ed25519_key', str(hostkey)),
                     ('/run/sf-tunnel-keys/authorized_keys', str(self.tmp / 'auth')), ('AllowUsers sftunnel', f'AllowUsers {self.user}')):
            self.assertIn(a, cfg)
            cfg = cfg.replace(a, b)
        (self.tmp / 'cfg').write_text(cfg)
        self.write_auth()
        self.sshd = subprocess.Popen([shutil.which('sshd'), '-D', '-e', '-f', str(self.tmp / 'cfg')], stdout=subprocess.DEVNULL, stderr=open(self.tmp / 'log', 'w'))
        self.addCleanup(self.sshd.wait)
        self.addCleanup(self.sshd.terminate)
        for _ in range(50):
            try:
                socket.create_connection(('127.0.0.1', self.port), 1).close()
                break
            except OSError:
                time.sleep(0.1)
        else:
            self.skipTest('sshd would not start here: ' + (self.tmp / 'log').read_text()[-200:])
        self.backend = socket.create_server(('127.0.0.1', 0))
        self.addCleanup(self.backend.close)
        threading.Thread(target=self.serve, daemon=True).start()

    @staticmethod
    def free():
        with socket.socket() as s:
            s.bind(('127.0.0.1', 0))
            return s.getsockname()[1]

    def serve(self):
        while True:
            try:
                c, _ = self.backend.accept()
                c.sendall(b'SSH-2.0-fake\r\n')
                c.close()
            except OSError:
                return

    def write_auth(self, expiry=''):
        pub = new_key(self.tmp / 'key')
        (self.tmp / 'auth').write_text(f'restrict,port-forwarding,permitlisten="{self.ME}:{self.listen}",command="/bin/false"{expiry} {pub}\n')

    def ssh(self, *args, timeout=8):
        return ['ssh', '-F', '/dev/null', '-i', str(self.tmp / 'key'), '-p', str(self.port), '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=no',
                '-o', f'UserKnownHostsFile={self.tmp}/kh', '-o', 'ExitOnForwardFailure=yes', '-o', 'IdentitiesOnly=yes', '-o', f'ConnectTimeout={timeout}', *args, f'{self.user}@127.0.0.1']

    def reverse(self, addr, port):
        """Starts a tunnel. Returns it if it stayed up."""
        p = subprocess.Popen(self.ssh('-N', '-T', '-R', f'{addr}:{port}:127.0.0.1:{self.backend.getsockname()[1]}'), stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        self.addCleanup(p.wait)
        self.addCleanup(p.terminate)
        for _ in range(30):
            if p.poll() is not None:
                return None
            try:
                with socket.create_connection((addr, port), 0.3) as s:
                    if s.recv(8).startswith(b'SSH-'):
                        return p
            except OSError:
                time.sleep(0.1)
        return None

    def test_a_key_can_offer_its_own_address(self):
        self.assertIsNotNone(self.reverse(self.ME, self.listen), (self.tmp / 'log').read_text()[-500:])
        with mock.patch.object(remotes, 'LISTEN_PORT', self.listen):
            self.assertTrue(remotes.online(self.ME))

    def test_and_no_other_address_or_port(self):
        for addr, port in (('127.77.9.2', self.listen), (self.ME, self.free()), ('0.0.0.0', self.free()), ('127.0.0.1', self.free())):
            self.assertIsNone(self.reverse(addr, port), (addr, port))

    def test_it_cannot_reach_out_through_the_server(self):
        p = subprocess.Popen(self.ssh('-N', '-T', '-L', f'127.0.0.1:{self.listen}:127.0.0.1:{self.backend.getsockname()[1]}'), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(p.wait)
        self.addCleanup(p.terminate)
        time.sleep(1.5)
        try:
            with socket.create_connection(('127.0.0.1', self.listen), 1) as s:
                s.settimeout(1.5)
                self.assertFalse(s.recv(8).startswith(b'SSH-'))
        except OSError:
            pass                       # refused at the first step is as good

    def test_it_gets_no_shell_and_no_command(self):
        for cmd in (['id'], ['-tt', 'sh'], ['-s', 'sftp']):
            extra, rest = (cmd[:-1], cmd[-1:]) if cmd[0].startswith('-') else ([], cmd)
            p = subprocess.run(self.ssh(*extra) + rest, capture_output=True, text=True, timeout=20)
            self.assertNotEqual(p.returncode, 0, cmd)
            self.assertNotIn('uid=', p.stdout)

    def test_passwords_are_off(self):
        p = subprocess.run(['ssh', '-F', '/dev/null', '-p', str(self.port), '-o', 'BatchMode=yes', '-o', 'PubkeyAuthentication=no', '-o', 'StrictHostKeyChecking=no',
                            '-o', f'UserKnownHostsFile={self.tmp}/kh', f'{self.user}@127.0.0.1', 'id'], capture_output=True, text=True, timeout=20)
        self.assertNotEqual(p.returncode, 0)
        self.assertIn('publickey', p.stderr)
        self.assertNotIn('password', p.stderr.split('Permission denied')[-1])

    def test_an_expired_invitation_gets_nothing(self):
        self.write_auth(',expiry-time="202001010000Z"')
        self.assertIsNone(self.reverse(self.ME, self.listen))


if __name__ == '__main__':
    unittest.main()
