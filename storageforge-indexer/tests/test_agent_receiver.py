"""The agent receiver (roadmap section 11.2; agentreceiver.py): the hostile-input boundary where what agents say comes in.

What is real here: the receiver itself, listening on a port of this machine in a thread of its own, with its own database
connection; agents played by Python with real keys, real Noise sessions and real batch signatures, saying everything an agent that
was taken over might say; the database, SQLite and (with STORAGEFORGE_TEST_PG) PostgreSQL, where the receiver's own role is made
with the grants it prints and is shown to be unable to touch anything else. Through the real storageforge-agent, the receiver is met
in test_agent_tunnel.py and in Delivery below."""
import base64
import json
import os
import shutil
import socket
import tempfile
import threading
import time
import unittest
import uuid
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives.asymmetric import ed25519

import dbfactory
from storageforge_index import agentreceiver as ar, agenttunnel as t, deploy, sfagent, vault

import test_agent

MACHINE = '0123456789abcdef0123456789abcdef'


def key_line(pub: bytes) -> str:
    return 'ssh-ed25519 ' + base64.b64encode(deploy._s(b'ssh-ed25519') + deploy._s(pub)).decode() + ' storageforge-agent'


class Agent:
    """An agent, played here: its own key, enrolled for `host`, and the things it may send."""

    def __init__(self, case, host: str, enroll: bool = True):
        self.case, self.host = case, host
        self.seed = os.urandom(32)
        self.key = ed25519.Ed25519PrivateKey.from_private_bytes(self.seed)
        self.pub = self.key.public_key().public_bytes_raw()
        self.line = key_line(self.pub)
        self.fp = sfagent.fingerprint(self.line)
        self.run, self.seq, self.counter = 7, 0, 0
        if enroll:
            case.conn.execute("""INSERT INTO agents (host, enabled, state, public_key, fingerprint, counter, updated_at, updated_by)
                                 VALUES (:h, 1, 'running', :k, :f, 1, 0, 'test')""", {'h': host, 'k': self.line, 'f': self.fp})
            # the receiver reads the pins on its own schedule: on a slow machine the agent would open before it has read this one,
            # and be refused as a stranger. Wait for the receiver's own refresh to show the key, rather than for a time
            deadline = time.monotonic() + 10
            while not any(fp == self.fp for (_h, fp, _e) in list(case.r.pins.by_key.values())) and time.monotonic() < deadline:
                time.sleep(0.01)

    def open(self):
        sock = socket.create_connection(('127.0.0.1', self.case.port), timeout=10)
        self.case.addCleanup(sock.close)
        s, welcome = t.initiate(sock, t.x25519_of_seed(self.seed), self.case.receiver_pub)
        self.sock, self.s = sock, s
        return json.loads(welcome)

    def hello(self, **claims):
        self.s.send_json(self.sock, {'op': 'hello', 'version': '0.5.7', 'run': self.run, 'claims': claims, 'manifest': None, 'have': []})
        frames = []
        while True:
            frames.append(json.loads(self.s.read(self.sock)))
            if frames[-1]['op'] == 'ready':
                return frames

    def body(self, records=None, counter=None, dropped=0, **extra):
        if counter is None:
            self.counter += 1
            counter = self.counter
        recs = []
        for r in records if records is not None else [{'kind': 'reading', 'body': {'n': 1}}]:
            self.seq += 1
            recs.append({'seq': self.seq, 'at': int(time.time()), 'plugin': r.get('plugin', 'probe'), 'kind': r['kind'], 'body': r['body']})
        return json.dumps({'counter': counter, 'run': self.run, 'sent': int(time.time()), 'dropped': dropped, 'records': recs, **extra}).encode()

    def send(self, body: bytes, signature: str | None = None) -> dict:
        self.s.send_json(self.sock, {'op': 'batch', 'body': body.decode(), 'signature': signature or t.sign_batch(self.key, body)})
        return json.loads(self.s.read(self.sock))


class Base(unittest.TestCase):
    LIMITS = {}

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.db = dbfactory.make(self, self.tmp / 'index.db')
        self.conn = self.db.connect()
        self.addCleanup(self.conn.close)
        self.db.migrate(self.conn)
        for name in ('nas', 'web'):
            self.conn.execute("INSERT INTO hosts (hostname, ssh_host, ssh_port, machine_id) VALUES (:h, '10.0.0.3', 22, :m)",
                              {'h': name, 'm': MACHINE if name == 'nas' else 'f' * 32})
        p = mock.patch.object(ar, 'PIN_REFRESH', 0.2)
        p.start()
        self.addCleanup(p.stop)
        self.secret = os.urandom(32)
        self.receiver_pub = t.public_of(self.secret)
        self.lines = []
        self.r = ar.Receiver(self.db, self.secret, log=self.lines.append, **self.LIMITS)
        self.port = self.r.listen('127.0.0.1', 0)
        threading.Thread(target=self.r.serve_forever, daemon=True).start()
        self.addCleanup(self.r.stop)

    def records(self, host=None):
        q = 'SELECT host, fingerprint, source, plugin, kind, body_json FROM agent_records'
        return self.conn.all(q + (' WHERE host = :h' if host else '') + ' ORDER BY record_id', {'h': host} if host else {})

    def peer(self, fp):
        cols = ('host', 'last_counter', 'gaps', 'repeats', 'resent', 'malformed', 'over_quota', 'pruned', 'lost', 'claims_json', 'sessions')
        rows = self.conn.all(f'SELECT {", ".join(cols)} FROM agent_peers WHERE fingerprint = :f', {'f': fp})
        return dict(zip(cols, rows[0])) if rows else None

    def events(self, kind):
        return self.conn.all('SELECT host, count, detail FROM agent_events WHERE kind = :k ORDER BY event_id', {'k': kind})


class Identity(Base):
    def test_what_an_agent_says_is_kept_under_its_own_host_whatever_it_names(self):
        a = Agent(self, 'nas')
        Agent(self, 'web')
        welcome = a.open()
        self.assertEqual(welcome['last_counter'], 0)
        a.hello(machine='f' * 32, hostname='web', address='10.0.0.9')
        # a batch that names another host everywhere it can: in a record body, and with a field batches do not have
        got = a.send(a.body([{'kind': 'reading', 'body': {'host': 'web', 'hostname': 'web', 'machine_id': 'f' * 32}}]))
        self.assertEqual(got, {'op': 'ack', 'counter': 1})
        self.assertEqual([(h, f, s) for h, f, s, *_ in self.records()], [('nas', a.fp, 'agent')], 'the host its key belongs to, labelled as the agent\'s')
        self.assertEqual(json.loads(self.records()[0][5])['host'], 'web', 'what it said is kept as it said it: a claim')
        claims = json.loads(self.peer(a.fp)['claims_json'])
        self.assertEqual(claims['claims']['machine'], 'f' * 32, 'its claim about itself, stored as one')
        self.assertEqual(self.peer(a.fp)['host'], 'nas')
        got = a.send(a.body(host='web'))
        self.assertEqual(got['op'], 'refused', 'a field a batch does not have')
        self.assertEqual(len(self.records('web')), 0)

    def test_a_key_that_is_not_pinned_gets_no_session_and_is_counted_once(self):
        stranger = Agent(self, 'nas', enroll=False)
        for _ in range(3):
            with self.assertRaises((ConnectionError, t.TunnelError, OSError)):
                stranger.open()
        self.r._flush_unknown()
        self.assertEqual(sum(c for _h, c, _d in self.events('unknown-key')), 3)
        self.assertEqual(self.events('unknown-key')[0][0], None, 'about no host')
        self.assertEqual(self.records(), [])

    def test_a_removed_agent_loses_its_session_and_gets_no_other(self):
        a = Agent(self, 'nas')
        a.open()
        a.hello()
        self.assertEqual(a.send(a.body())['op'], 'ack')
        self.conn.execute("UPDATE agents SET state = 'removed', public_key = NULL, fingerprint = NULL WHERE host = 'nas'")
        time.sleep(1.0)
        with self.assertRaises((ConnectionError, OSError, t.TunnelError)):
            got = a.send(a.body())
            self.assertIn(got.get('op'), ('bye', None))
            a.send(a.body())
        with self.assertRaises((ConnectionError, OSError, t.TunnelError)):
            a.open()

    def test_words_never_become_code(self):
        a = Agent(self, 'nas')
        a.open()
        a.hello()
        nasty = {'sql': "x'); DROP TABLE agent_records; --", 'html': '<script>alert(1)</script>', 'shell': '$(reboot)', 'nul': 'a\u0000b'}
        self.assertEqual(a.send(a.body([{'kind': 'reading', 'body': nasty}]))['op'], 'ack')
        self.assertEqual(json.loads(self.records()[0][5]), nasty, 'kept byte for byte, as a parameter')
        for bad in ({'plugin': '<b>', 'kind': 'reading', 'body': {}}, {'kind': '../etc', 'body': {}}, {'kind': 'reading', 'body': 'text'}):
            self.assertEqual(a.send(a.body([bad]))['op'], 'refused', bad)
        self.assertEqual(len(self.records()), 1)


class Counted(Base):
    def test_a_resend_is_answered_a_replay_refused_and_a_gap_recorded(self):
        a, b = Agent(self, 'nas'), Agent(self, 'web')
        a.open()
        a.hello()
        first = a.body()
        self.assertEqual(a.send(first)['op'], 'ack')
        self.assertEqual(a.send(first)['op'], 'ack', 'the same bytes again: the agent did not hear the answer')
        self.assertEqual(len(self.records()), 1, 'and it is not stored twice')
        other = a.body(counter=1)
        self.assertEqual(a.send(other)['op'], 'refused', 'the same counter with other bytes')
        a.counter = 4
        self.assertEqual(a.send(a.body())['op'], 'ack')
        p = self.peer(a.fp)
        self.assertEqual((p['resent'], p['repeats'], p['gaps'], p['last_counter']), (1, 1, 3, 5))
        self.assertEqual([c for _h, c, _d in self.events('gap')], [3])
        self.assertEqual(len(self.events('repeat')), 1)
        # an agent that lost its own count is told where to go on from
        b.open()
        self.assertEqual(a.open()['last_counter'], 5)

    def test_records_the_agent_dropped_are_counted_as_lost(self):
        a = Agent(self, 'nas')
        a.open()
        a.hello()
        a.send(a.body())
        a.seq += 4                      # four records it never sent: the outbox numbers what it drops, so the gap and `dropped` are one loss
        a.send(a.body(dropped=4))
        self.assertEqual(self.peer(a.fp)['lost'], 4)

    def test_a_batch_not_signed_by_its_key_is_refused_and_five_end_the_session(self):
        a = Agent(self, 'nas')
        other = ed25519.Ed25519PrivateKey.generate()
        a.open()
        a.hello()
        for i in range(ar.MALFORMED_LIMIT):
            body = a.body()
            got = a.send(body, t.sign_batch(other, body))
            self.assertEqual(got['op'], 'refused')
        with self.assertRaises((ConnectionError, OSError, t.TunnelError)):
            a.send(a.body())
        self.assertEqual(self.peer(a.fp)['malformed'], ar.MALFORMED_LIMIT)
        with self.assertRaises((ConnectionError, OSError, t.TunnelError)):
            a.open()                    # and it waits before it may open another
        self.assertEqual(self.records(), [])


class Quotas(Base):
    LIMITS = {'rows_per_host': 10, 'batches_per_minute': 1000}

    def test_a_flood_costs_the_flooder_its_own_oldest_rows_and_nobody_else(self):
        quiet, loud = Agent(self, 'web'), Agent(self, 'nas')
        quiet.open()
        quiet.hello()
        quiet.send(quiet.body([{'kind': 'reading', 'body': {'n': n}} for n in range(5)]))
        loud.open()
        loud.hello()
        for _ in range(ar.PRUNE_EVERY):
            loud.send(loud.body([{'kind': 'reading', 'body': {'n': n}} for n in range(3)]))
        self.assertEqual(len(self.records('nas')), 10, 'its quota')
        self.assertEqual(len(self.records('web')), 5, 'the other agent keeps all of its rows')
        self.assertEqual(json.loads(self.records('nas')[-1][5]), {'n': 2}, 'the newest stay')
        self.assertEqual(self.peer(loud.fp)['pruned'], ar.PRUNE_EVERY * 3 - 10)
        self.assertTrue(self.events('pruned'))

    def test_what_is_too_large_or_too_deep_is_refused_before_it_is_kept(self):
        a = Agent(self, 'nas')
        a.open()
        a.hello()
        deep = {}
        cur = deep
        for _ in range(ar.MAX_DEPTH + 2):
            cur['x'] = {}
            cur = cur['x']
        self.assertEqual(a.send(a.body([{'kind': 'reading', 'body': deep}]))['op'], 'refused')
        self.assertEqual(a.send(a.body([{'kind': 'reading', 'body': {'x': 'y' * (ar.MAX_BODY + 1)}}]))['op'], 'refused')
        self.assertEqual(a.send(a.body([{'kind': 'reading', 'body': {}}] * (ar.MAX_RECORDS + 1)))['op'], 'refused')
        self.assertEqual(self.records(), [])
        # a frame larger than any frame ends the conversation, unread
        a.sock.sendall((t.MAX_FRAME + 1000).to_bytes(4, 'big') + b'x' * 100)
        with self.assertRaises((ConnectionError, OSError, t.TunnelError)):
            a.send(a.body())


class Rate(Base):
    LIMITS = {'batches_per_minute': 3}

    def test_more_batches_a_minute_than_allowed_are_refused_and_counted(self):
        a, b = Agent(self, 'nas'), Agent(self, 'web')
        a.open()
        a.hello()
        answers = [a.send(a.body())['op'] for _ in range(5)]
        self.assertEqual(answers[:3], ['ack'] * 3)
        self.assertEqual(answers[3:], ['refused'] * 2)
        self.assertEqual(self.peer(a.fp)['over_quota'], 2)
        b.open()
        b.hello()
        self.assertEqual(b.send(b.body())['op'], 'ack', 'another agent has its own rate')


class Sessions(Base):
    LIMITS = {'session_secs': 1}

    def test_a_session_ends_on_time_and_the_agent_opens_another(self):
        a = Agent(self, 'nas')
        a.open()
        a.hello()
        time.sleep(1.2)
        got = a.send(a.body())
        self.assertIn(got['op'], ('bye', 'ack'))
        if got['op'] == 'ack':
            got = json.loads(a.s.read(a.sock))
        self.assertEqual(got['op'], 'bye')
        a.open()
        a.hello()
        self.assertEqual(self.peer(a.fp)['sessions'], 2)


class OneAtATime(Base):
    LIMITS = {'handshakes_per_minute': 2}

    def test_handshakes_are_limited_per_address_before_any_key_is_known(self):
        a = Agent(self, 'nas')
        a.open()
        a.open()
        with self.assertRaises((ConnectionError, OSError, t.TunnelError)):
            a.open()


class DeliveryFrames(Base):
    def test_the_agent_gets_its_own_hosts_delivery_and_no_other(self):
        a, b = Agent(self, 'nas'), Agent(self, 'web')
        self.conn.execute("""INSERT INTO agent_deliveries (host, fingerprint, counter, manifest, signature, plugins_json, updated_at)
                             VALUES ('web', :f, 3, 'web manifest', 'sig', '[]', 0)""", {'f': b.fp})
        a.open()
        self.assertEqual(a.hello()[0], {'op': 'manifest', 'manifest': None, 'signature': None})
        b.open()
        self.assertEqual(b.hello()[0]['manifest'], 'web manifest')


class Role(unittest.TestCase):
    """The receiver's database connection can reach its own tables and nothing else."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.db = dbfactory.make(self, self.tmp / 'index.db')
        conn = self.db.connect()
        self.db.migrate(conn)
        conn.execute("INSERT INTO hosts (hostname, ssh_host, ssh_port) VALUES ('nas', '10.0.0.3', 22)")
        conn.execute("INSERT INTO agents (host, enabled, state, public_key, fingerprint, counter, updated_at, updated_by) VALUES ('nas', 1, 'running', 'k', 'f', 1, 0, 't')")
        conn.close()

    def receiver_db(self):
        if self.db.dialect == 'sqlite':
            return self.db
        import psycopg
        role = 'sf_recv_' + uuid.uuid4().hex[:8]
        password = uuid.uuid4().hex
        admin = self.db.connect()
        admin.raw.execute(f"CREATE ROLE {role} LOGIN PASSWORD '{password}'")
        self.addCleanup(lambda: _drop_role(self.db, role))
        for g in ar.grants(role):
            admin.raw.execute(g)
        admin.close()
        base = self.db.url.split('://', 1)[1].split('@', 1)[1]
        from storageforge_index.db import Database
        self.assertTrue(psycopg)
        return Database(f'postgresql://{role}:{password}@{base}')

    def test_it_writes_its_own_tables_reads_the_pins_and_nothing_else(self):
        conn = ar.connect(self.receiver_db())
        self.addCleanup(conn.close)
        store = ar.Store(self.db)
        store.peer(conn, 'f', 'nas')
        store.event(conn, 'nas', 'f', 'gap', 1, '')
        conn.execute("INSERT INTO agent_records (host, fingerprint, counter, seq, plugin, kind, received_at, body_json) VALUES ('nas', 'f', 1, 1, 'p', 'k', 0, '{}')")
        self.assertEqual(conn.scalar("SELECT host FROM agents WHERE fingerprint = 'f'"), 'nas')
        for sql in ("SELECT * FROM ssh_keys", "SELECT counter FROM agents", "SELECT * FROM hosts", "UPDATE agents SET public_key = 'x'",
                    "INSERT INTO hosts (hostname) VALUES ('evil')", "DELETE FROM audit_log", "SELECT * FROM users", "UPDATE agent_deliveries SET manifest = 'x'",
                    "INSERT INTO alerts (alert_key, kind, ref, title, message, state, first_at, last_at) VALUES ('a','k','r','t','m','open',0,0)"):
            with self.assertRaises(Exception, msg=sql):
                conn.execute(sql).fetchall()
            if conn.dialect == 'postgres':
                pass                       # autocommit: each statement stands alone

    def test_the_grants_name_its_tables_and_no_others(self):
        g = ' '.join(ar.grants('sf_receiver'))
        for table in ('agent_peers', 'agent_records', 'agent_events'):
            self.assertIn(f'ON {table} TO sf_receiver', g)
        self.assertIn('GRANT SELECT (host, enabled, state, public_key, fingerprint) ON agents', g)
        for never in ('ssh_keys', 'hosts', 'users', 'audit_log', 'ALL'):
            self.assertNotIn(never, g)
        with self.assertRaises(ValueError):
            ar.grants('x; DROP TABLE hosts')


def _drop_role(db, role):
    conn = db.connect()
    try:
        conn.raw.execute(f'DROP OWNED BY {role}')
        conn.raw.execute(f'DROP ROLE IF EXISTS {role}')
    finally:
        conn.close()


class Isolated(unittest.TestCase):
    def test_the_receiver_imports_nothing_that_reaches_the_vault_or_ssh(self):
        import subprocess
        import sys
        code = ('import sys, storageforge_index.agentreceiver; '
                'print(" ".join(sorted(m for m in sys.modules if m.startswith("storageforge_index"))))')
        out = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True, cwd=str(Path(__file__).resolve().parents[1]),
                             env={**os.environ, 'PYTHONPATH': str(Path(__file__).resolve().parents[1])}).stdout.split()
        self.assertIn('storageforge_index.agentreceiver', out)
        for never in ('vault', 'enclave', 'remote', 'runner', 'deploy', 'sfagent', 'server', 'scanner', 'changes'):
            self.assertNotIn(f'storageforge_index.{never}', out)

    def test_it_will_not_start_with_the_vault_secret(self):
        with mock.patch.dict(os.environ, {'STORAGEFORGE_AGENT_RECEIVER_DIR': tempfile.mkdtemp(), 'STORAGEFORGE_VAULT_SECRET': 'x' * 40,
                                          'STORAGEFORGE_AGENT_RECEIVER_DB': 'sqlite:///' + tempfile.mktemp()}):
            with self.assertRaises(SystemExit) as cm:
                ar.main(['--listen', '127.0.0.1:0'])
            self.assertIn('without the vault', str(cm.exception))


@unittest.skipUnless(shutil.which('cargo'), 'needs cargo to build the agent (CI builds it)')
class Delivery(test_agent.Base):
    """The whole road with the real programs: sfagent signs and names the receiver, the real storageforge-agentctl pins it and loads
    the egress rule (nft standing in), the real agent dials the real receiver, takes its plugin through the tunnel, and what the
    plugin reports is stored under the host the agent's key belongs to."""

    def setUp(self):
        super().setUp()
        for name in ('nft', 'systemctl'):
            test_agent.stub(self.host.bin, name, f'echo "{name} $*" >>{self.host.log}')
        (self.host.root / 'etc/systemd/system').mkdir(parents=True)
        self.recv_dir = self.tmp / 'receiver'
        self.secret = t.load_or_make_key(self.recv_dir)
        p = mock.patch.object(ar, 'PIN_REFRESH', 0.2)
        p.start()
        self.addCleanup(p.stop)
        self.r = ar.Receiver(self.db, self.secret, log=lambda line: None)
        port = self.r.listen('127.0.0.1', 0)
        threading.Thread(target=self.r.serve_forever, daemon=True).start()
        self.addCleanup(self.r.stop)
        release = self.tmp / 'release' / os.uname().machine
        release.mkdir(parents=True)
        shutil.copy(self.out / 'examples' / 'probe', release / 'probe.plugin')
        env = mock.patch.dict(os.environ, {'STORAGEFORGE_AGENT_RECEIVER_DIR': str(self.recv_dir), 'STORAGEFORGE_AGENT_ENDPOINT': f'127.0.0.1:{port}',
                                           'STORAGEFORGE_AGENT_PLUGINS': str(self.tmp / 'release')})
        env.start()
        self.addCleanup(env.stop)

    def wait_for(self, check, seconds=30):
        for _ in range(seconds * 10):
            got = check()
            if got:
                return got
            time.sleep(0.1)
        self.fail('waited in vain; the agent said:\n' + (self.host.agent_log.read_text() if self.host.agent_log.exists() else ''))

    def test_a_plugin_goes_through_the_tunnel_and_its_readings_come_back_under_the_senders_host(self):
        got = self.install()
        self.assertEqual(got['state'], 'running')
        row = sfagent.get(self.conn, 'nas')
        self.assertEqual((row['endpoint'], row['receiver_key']), (os.environ['STORAGEFORGE_AGENT_ENDPOINT'], t.receiver_public(self.recv_dir)))
        pinned = json.loads((self.host.root / 'etc/storageforge-agent/tunnel').read_text())
        self.assertEqual(pinned['key'], t.receiver_public(self.recv_dir), 'the host pinned the receiver it was told of')
        calls = self.host.calls()
        self.assertTrue(any(c.startswith('nft -f') for c in calls), 'the egress rule was loaded')
        egress = (self.host.root / 'var/lib/storageforge-agent/ctl/egress.nft').read_text()
        self.assertIn('ip daddr 127.0.0.1 tcp dport', egress)
        run = self.host.calls('docker run')[-1]
        self.assertIn('--network sfagent', run)
        self.assertLess(max(i for i, c in enumerate(calls) if c.startswith('nft -f')), max(i for i, c in enumerate(calls) if c.startswith('docker run')),
                        'the rule before the container')
        # a session comes at once: the agent said hello, under its own key's host
        self.wait_for(lambda: self.conn.scalar("SELECT sessions FROM agent_peers WHERE host = 'nas'"))
        # and now a plugin: its readings come back through the tunnel
        sfagent.apply(self.db, 'nas', [self.plugin()], actor='test')
        rows = self.wait_for(lambda: self.conn.all("SELECT host, fingerprint, source, kind, body_json FROM agent_records WHERE plugin = 'probe'"))
        host, fp, source, kind, body = rows[0]
        self.assertEqual((host, fp, source, kind), ('nas', row['fingerprint'], 'agent', 'probe'))
        self.assertEqual(json.loads(body)['env'], 0)
        self.assertEqual((self.host.root / 'var/lib/storageforge-agent/state/plugins/probe.plugin').read_bytes(), (self.out / 'examples' / 'probe').read_bytes())

    def test_a_receiver_key_that_changed_is_given_to_a_host_only_when_a_person_accepts_it(self):
        self.install()
        old = t.receiver_public(self.recv_dir)
        shutil.rmtree(self.recv_dir)
        t.load_or_make_key(self.recv_dir)           # the receiver was set up again, with a new key
        with self.assertRaises(sfagent.AgentError) as cm:
            sfagent.apply(self.db, 'nas', [], actor='test')
        self.assertEqual(cm.exception.code, 'tunnel-key')
        self.assertEqual(json.loads((self.host.root / 'etc/storageforge-agent/tunnel').read_text())['key'], old, 'the host was not asked')
        # the host refuses it too, whoever signs the request, unless it says a person accepted it
        rc, got = self.ask('apply', **self.apply_fields(accept=False))
        self.assertEqual((rc, got.get('error')), (97, 'tunnel-key'))
        sfagent.apply(self.db, 'nas', [], actor='test', accept_new_key=True)
        self.assertEqual(json.loads((self.host.root / 'etc/storageforge-agent/tunnel').read_text())['key'], t.receiver_public(self.recv_dir))

    def apply_fields(self, accept):
        with vault.Vault(self.db, self.conn, test_agent.SECRET).unlock() as v:
            row = sfagent.get(self.conn, 'nas')
            self.conn.execute("UPDATE agents SET counter = counter + 1 WHERE host = 'nas'")
            counter = sfagent.get(self.conn, 'nas')['counter']
            text, sig = sfagent.manifest(sfagent._signer(v), row['fingerprint'], MACHINE, counter, test_agent.IMAGE, [])
        return {'manifest': text, 'manifest_signature': sig, 'image_signature': (self.tmp / 'agentdir/image.sig').read_text(),
                'tunnel': sfagent.tunnel_for(self.conn, 'nas'), 'accept_new_tunnel_key': accept}
