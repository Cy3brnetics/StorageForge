"""The agent's tunnel from the controller's side (roadmap section 11.1, "Delivery"; agenttunnel.py, agent/src/tunnel.rs).

What is real here: the Noise handshake in Python against the one in Rust, byte for byte; the real storageforge-agent, built with a
release key of the run's, dialling a Python receiver over TCP on this machine, taking its manifest and a signed plugin through the
tunnel, starting itself again to load it, and sending what the plugin reported as a signed batch; the batch signature checked as the
receiver checks it; nft loading the agent's egress rule in a network namespace of its own, and that rule stopping a connection.

Skipped where there is no cargo."""
import base64
import hashlib
import json
import os
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ed25519

from storageforge_index import agenttunnel as t, deploy

import test_agent

RUST_VECTOR = (Path(__file__).resolve().parents[1] / 'wire/src/noise_vector.txt').read_text().strip()


class Fake:
    def __init__(self):
        self.out = b''

    def sendall(self, b):
        self.out += b

    def recv(self, _n):
        return b''


class Handshake(unittest.TestCase):
    def test_the_python_side_makes_the_bytes_the_rust_side_makes(self):
        f = Fake()
        with self.assertRaises(ConnectionError):
            t.initiate(f, bytes([1]) * 32, t.public_of(bytes([2]) * 32), b'hi', ephemeral=bytes([3]) * 32)
        self.assertEqual(hashlib.sha256(f.out).hexdigest(), RUST_VECTOR, 'wire/src/noise.rs, fixed_keys_give_fixed_bytes')

    def test_an_agent_key_is_its_ed25519_key_as_x25519(self):
        for seed in (bytes([7]) * 32, os.urandom(32)):
            pub = ed25519.Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes_raw()
            self.assertEqual(t.ed25519_to_x25519(pub), t.public_of(t.x25519_of_seed(seed)))
        for bad in (b'', b'\x01' + b'\0' * 31, b'\xff' * 32):
            with self.assertRaises(ValueError):
                t.ed25519_to_x25519(bad)

    def test_both_ends_in_python_and_a_key_not_admitted(self):
        agent, receiver = os.urandom(32), os.urandom(32)
        got = {}

        def serve(sock):
            try:
                s, _ = t.respond(sock, receiver, lambda k: k == t.public_of(agent), lambda k, p: b'{"last_counter":3}')
                got['msg'] = s.read(sock)
            except t.TunnelError as exc:
                got['error'] = str(exc)
            finally:
                sock.close()
        for key, works in ((agent, True), (os.urandom(32), False)):
            a, b = socket.socketpair()
            th = threading.Thread(target=serve, args=(b,))
            th.start()
            try:
                if works:
                    s, welcome = t.initiate(a, key, t.public_of(receiver))
                    s.write(a, b'hello')
                    th.join()
                    self.assertEqual((welcome, got['msg']), (b'{"last_counter":3}', b'hello'))
                else:
                    with self.assertRaises(ConnectionError):
                        t.initiate(a, key, t.public_of(receiver))
                    th.join()
                    self.assertIn('not the pinned key', got['error'])
            finally:
                a.close()

    def test_a_batch_signature_is_the_agents_and_for_batches_only(self):
        key = ed25519.Ed25519PrivateKey.generate()
        pub = key.public_key().public_bytes_raw()
        body = b'{"counter":1}'
        good = t.sign_batch(key, body)
        self.assertTrue(t.verify_batch(pub, body, good))
        self.assertFalse(t.verify_batch(pub, body + b' ', good), 'other bytes')
        self.assertFalse(t.verify_batch(ed25519.Ed25519PrivateKey.generate().public_key().public_bytes_raw(), body, good), 'another key')
        self.assertFalse(t.verify_batch(pub, body, deploy.sshsig(key, body, 'storageforge-agent-manifest')), 'made for another use')
        self.assertFalse(t.verify_batch(pub, body, 'not a signature'))

    def test_the_receiver_key_is_made_once_and_kept_private(self):
        d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d, True)
        secret = t.load_or_make_key(d / 'r')
        self.assertEqual(oct((d / 'r' / t.KEY_FILE).stat().st_mode & 0o777), '0o600')
        self.assertEqual(t.load_or_make_key(d / 'r'), secret)
        self.assertEqual(base64.b64decode(t.receiver_public(d / 'r')), t.public_of(secret))
        (d / 'r' / t.KEY_FILE).chmod(0o644)
        with self.assertRaises(t.TunnelError):
            t.load_or_make_key(d / 'r')


def nft_namespace():
    """Whether nft can load rules in a network namespace of this user's own (unshare -rn), which needs no root."""
    if not (shutil.which('nft') and shutil.which('unshare')):
        return False
    return subprocess.run(['unshare', '-rn', 'nft', 'list', 'ruleset'], capture_output=True).returncode == 0


@unittest.skipUnless(shutil.which('cargo'), 'needs cargo to build the agent (CI builds it)')
class EgressRule(unittest.TestCase):
    """The rule storageforge-agentctl writes, as the agent's runtime module makes it, loaded by the real nft."""

    def rules(self, uid, to):
        p = subprocess.run([str(test_agent.build() / 'examples' / 'egress'), str(uid), to], capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        return p.stdout

    @unittest.skipUnless(nft_namespace(), 'needs nft and unprivileged network namespaces')
    def test_the_agent_reaches_its_controller_and_nothing_else(self):
        rules = self.rules(0, '127.0.0.1:7843')
        script = ('set -e; ip link set lo up; nft -f "$1"; nft -f "$1"\n'          # twice: loading it again replaces it whole
                  'python3 -c "import socket,sys\nfor p in (7843, 22, 8443):\n'
                  '  s=socket.socket(); s.settimeout(1)\n  try: s.connect((\'127.0.0.1\', p)); r=\'open\'\n'
                  '  except ConnectionRefusedError: r=\'refused\'\n  except OSError: r=\'dropped\'\n  print(p, r)"\n'
                  'nft list table inet storageforge_agent | grep -c drop')
        with tempfile.NamedTemporaryFile('w', suffix='.nft') as f:
            f.write(rules)
            f.flush()
            p = subprocess.run(['unshare', '-rn', 'bash', '-c', script, 'x', f.name], capture_output=True, text=True, timeout=60)
        self.assertEqual(p.returncode, 0, p.stderr)
        lines = p.stdout.split('\n')
        # nothing listens in the namespace: the controller's port is refused (it got through to the stack), the others are dropped
        self.assertEqual(lines[:3], ['7843 refused', '22 dropped', '8443 dropped'], p.stdout)
        self.assertEqual(lines[3], '3', 'one drop per chain, and the table once')

    def test_the_rule_names_the_bridge_and_the_uid(self):
        rules = self.rules(987, '192.0.2.10:7843')
        self.assertIn('meta skuid 987 ip daddr 192.0.2.10 tcp dport 7843 accept', rules)
        self.assertIn('iifname "sfagent0" counter drop', rules)
        if shutil.which('nft') and nft_namespace():
            with tempfile.NamedTemporaryFile('w', suffix='.nft') as f:
                f.write(rules)
                f.flush()
                self.assertEqual(subprocess.run(['unshare', '-rn', 'nft', '-c', '-f', f.name], capture_output=True).returncode, 0)


@unittest.skipUnless(shutil.which('cargo'), 'needs cargo to build the agent (CI builds it)')
class RealAgent(unittest.TestCase):
    """The real agent dials a receiver written here with agenttunnel, takes a plugin through the tunnel, and reports through it."""

    def setUp(self):
        self.out = test_agent.build()
        self.dir = Path(tempfile.mkdtemp(prefix='sftunnel-'))
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.etc, self.manifest_dir, self.state = self.dir / 'etc', self.dir / 'manifest', self.dir / 'state'
        for d in (self.etc, self.manifest_dir, self.state):
            d.mkdir()
        self.controller = ed25519.Ed25519PrivateKey.generate()
        pub = self.controller.public_key().public_bytes_raw()
        line = 'ssh-ed25519 ' + base64.b64encode(deploy._s(b'ssh-ed25519') + deploy._s(pub)).decode()
        (self.etc / 'controller_signers').write_text(f'controller namespaces="storageforge-agentctl,storageforge-agent-manifest" {line}\n')
        self.receiver = os.urandom(32)
        self.listener = socket.socket()
        self.listener.bind(('127.0.0.1', 0))
        self.listener.listen(4)
        self.addCleanup(self.listener.close)
        self.port = self.listener.getsockname()[1]
        (self.etc / 'tunnel').write_text(json.dumps({'format': 1, 'endpoint': f'127.0.0.1:{self.port}', 'key': base64.b64encode(t.public_of(self.receiver)).decode()}))
        self.proc = None

    def start(self):
        self.log = open(self.dir / 'agent.log', 'wb')
        self.addCleanup(self.log.close)
        self.proc = subprocess.Popen([str(self.out / 'storageforge-agent'), 'run', '--etc', str(self.etc), '--manifest', str(self.manifest_dir), '--state', str(self.state)],
                                     stdout=subprocess.DEVNULL, stderr=self.log)
        self.addCleanup(self.stop)

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.kill()                 # the process this test started
            self.proc.wait()

    def agent_key(self):
        for _ in range(100):
            line = (self.state / 'agent_key.pub').read_text() if (self.state / 'agent_key.pub').exists() else ''
            if line:
                return t.ed25519_of_line(line)
            time.sleep(0.1)
        self.fail('the agent made no key')

    def manifest(self, agent_pub, entries):
        fp = 'SHA256:' + base64.b64encode(hashlib.sha256(deploy._s(b'ssh-ed25519') + deploy._s(agent_pub)).digest()).decode().rstrip('=')
        text = json.dumps({'format': 1, 'agent': fp, 'machine': test_agent.MACHINE, 'counter': 1, 'issued': int(time.time()),
                           'image': test_agent.IMAGE, 'plugins': entries}, separators=(',', ':'))
        return text, deploy.sshsig(self.controller, text.encode(), 'storageforge-agent-manifest')

    def accept(self, agent_pub):
        self.listener.settimeout(30)
        conn, _ = self.listener.accept()
        conn.settimeout(30)
        s, _ = t.respond(conn, self.receiver, lambda k: k == t.ed25519_to_x25519(agent_pub), lambda k, p: b'{"last_counter":0}')
        return conn, s

    def test_a_plugin_arrives_through_the_tunnel_loads_and_reports_back_signed(self):
        self.start()
        agent_pub = self.agent_key()
        program = (self.out / 'examples' / 'probe').read_bytes()
        descriptor = json.dumps({'format': 1, 'name': 'probe', 'version': '0.5.7', 'arch': os.uname().machine, 'sha256': hashlib.sha256(program).hexdigest(),
                                 'size': len(program), 'protocol': 1, 'needs': {}}, separators=(',', ':'))
        signature = test_agent.ssh_sign(test_agent.TARGET / 'release-key', 'storageforge-plugin', descriptor.encode())
        text, msig = self.manifest(agent_pub, [{'name': 'probe', 'descriptor': hashlib.sha256(descriptor.encode()).hexdigest(), 'signer': 'release', 'needs': {}}])
        # what storageforge-agentctl does over SSH: the manifest in force. The plugin files come through the tunnel
        (self.manifest_dir / 'manifest.json.sig').write_text(msig)
        (self.manifest_dir / 'manifest.json').write_text(text)
        plugins = self.dir / 'release'
        (plugins / os.uname().machine).mkdir(parents=True)
        shutil.copy(self.out / 'examples' / 'probe', plugins / os.uname().machine / 'probe.plugin')
        os.environ['STORAGEFORGE_AGENT_PLUGINS'] = str(plugins)
        self.addCleanup(os.environ.pop, 'STORAGEFORGE_AGENT_PLUGINS', None)
        delivery = {'manifest': text, 'signature': msig, 'plugins': [{'descriptor': descriptor, 'signature': signature}]}
        # the first session: hello, the delivery, and the agent leaves to load what came
        conn, s = self.accept(agent_pub)
        hello = json.loads(s.read(conn))
        self.assertEqual((hello['op'], hello['have'], hello['manifest']['counter']), ('hello', [], 1))
        for frame in t.delivery_frames(delivery, hello['have']):
            s.send_json(conn, frame)
        # the agent writes the files and starts itself again; whatever it says next comes on a new connection
        conn, s = self.accept(agent_pub)
        self.assertEqual((self.state / 'plugins' / 'probe.plugin').read_bytes(), program, (self.dir / 'agent.log').read_text())
        # the second session, after the agent started itself again: it has the plugin, and what it reported comes signed
        hello = json.loads(s.read(conn))
        self.assertEqual(hello['have'], ['probe'])
        for frame in t.delivery_frames(delivery, hello['have']):
            s.send_json(conn, frame)
        found = None
        for _ in range(5):
            batch = json.loads(s.read(conn))
            self.assertEqual(batch['op'], 'batch')
            self.assertTrue(t.verify_batch(agent_pub, batch['body'].encode(), batch['signature']))
            body = json.loads(batch['body'])
            s.send_json(conn, {'op': 'ack', 'counter': body['counter']})
            found = next((r for r in body['records'] if r['plugin'] == 'probe'), None)
            if found:
                break
        conn.close()
        self.assertIsNotNone(found, (self.dir / 'agent.log').read_text())
        self.assertEqual((found['kind'], found['body']['env'], found['body']['no_new_privs']), ('probe', 0, True))
        self.assertEqual(self.proc.poll(), None, 'the agent runs on')

    def test_an_agent_refuses_a_receiver_without_the_pinned_key(self):
        self.receiver, pinned = os.urandom(32), self.receiver
        self.start()
        agent_pub = self.agent_key()
        self.listener.settimeout(30)
        conn, _ = self.listener.accept()
        conn.settimeout(10)
        with self.assertRaises(t.TunnelError):
            t.respond(conn, self.receiver, lambda k: True, lambda k, p: b'{}')
        conn.close()
        self.assertNotEqual(pinned, self.receiver)
        self.assertIsNotNone(agent_pub)
