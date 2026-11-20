"""The rows of roadmap section 11.2 that the tunnel and the receiver do not settle by themselves: what the web app makes of what agents
said (agentwatch.py: every reading labelled as the agent's claim, compared with what SSH read, silence and missing batches shown),
privilege that needs a person (POST /api/agents/<host>/plugins), and that nothing secret goes to an agent.

What is real: the database (SQLite, and PostgreSQL with STORAGEFORGE_TEST_PG), the web app through Flask's test client with real
accounts, roles and the password window, the audit chain. sfagent.apply is replaced where a route would reach a host: what it does
there is test_agent_receiver.Delivery's."""
import base64
import json
import os
import shutil
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import dbfactory
from storageforge_index import agenttunnel, agentwatch, alerts, notifications, server, sfagent, users, vault

PW = 'a long enough password'
SECRET = b'correct horse battery staple, but longer than 32'
MACHINE = '0123456789abcdef0123456789abcdef'


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        p = mock.patch.dict(os.environ, {'STORAGEFORGE_VAULT_SECRET': SECRET.decode(), 'STORAGEFORGE_DATA_DIR': str(self.tmp / 'data')})
        p.start()
        self.addCleanup(p.stop)
        self.db = dbfactory.make(self, self.tmp / 'index.db')
        self.conn = self.db.connect()
        self.addCleanup(self.conn.close)
        self.db.migrate(self.conn)
        self.conn.execute("INSERT INTO hosts (hostname, ssh_host, ssh_port, machine_id, inventory_json) VALUES ('nas', '10.0.0.3', 22, :m, :i)",
                          {'m': MACHINE, 'i': json.dumps({'packages': 'arch\tx86_64\n'})})

    def enroll(self, host='nas', endpoint='10.0.0.1:7843', updated=None, manifest='m' * 64):
        self.conn.execute("""INSERT INTO agents (host, enabled, state, public_key, fingerprint, counter, manifest_sha, endpoint, updated_at, updated_by)
                             VALUES (:h, 1, 'running', 'ssh-ed25519 AAAA', :f, 1, :m, :e, :t, 'test')""",
                          {'h': host, 'f': 'SHA256:' + host, 'm': manifest, 'e': endpoint, 't': int(updated or time.time())})
        return 'SHA256:' + host

    def peer(self, fp, host='nas', last_seen=None, claims=None):
        self.conn.execute('INSERT INTO agent_peers (fingerprint, host, last_seen, claims_json) VALUES (:f, :h, :s, :c)',
                          {'f': fp, 'h': host, 's': int(last_seen or time.time()), 'c': json.dumps(claims) if claims is not None else None})

    def event(self, kind, count=1, host='nas', at=None):
        self.conn.execute('INSERT INTO agent_events (host, fingerprint, at, kind, count) VALUES (:h, :f, :t, :k, :c)',
                          {'h': host, 'f': 'SHA256:' + host, 't': int(at or time.time()), 'k': kind, 'c': count})


class Watch(Base):
    def test_silence_is_shown_and_scans_go_on(self):
        self.enroll(updated=time.time() - 3600)
        got = agentwatch.problems(self.conn)
        self.assertEqual(got['agent-silent:nas'][0], 'agent-silent')
        self.assertIn('has not reported', got['agent-silent:nas'][2])
        self.peer('SHA256:nas', last_seen=time.time() - 3600)
        self.assertIn('went silent', agentwatch.problems(self.conn)['agent-silent:nas'][2])
        self.conn.execute('UPDATE agent_peers SET last_seen = :t', {'t': int(time.time())})
        self.assertNotIn('agent-silent:nas', agentwatch.problems(self.conn))

    def test_an_agent_without_a_tunnel_is_not_called_silent(self):
        self.enroll(endpoint=None, updated=time.time() - 3600)
        self.assertEqual(agentwatch.problems(self.conn), {})

    def test_missing_and_replayed_batches_are_shown_for_a_day(self):
        fp = self.enroll()
        self.peer(fp)
        self.event('gap', 3)
        self.event('repeat', 1)
        self.event('gap', 9, at=time.time() - 2 * 86400)          # older than a day: no longer counted
        got = agentwatch.problems(self.conn)['agent-gap:nas']
        self.assertIn('3 missing, 1 played again', got[3])
        self.event('malformed', 2)
        self.assertEqual(agentwatch.problems(self.conn)['agent-refused:nas'][4], 'info')

    def test_a_claim_that_disagrees_with_ssh_is_a_finding_that_cannot_be_ignored(self):
        fp = self.enroll()
        self.peer(fp, claims={'claims': {'machine': 'f' * 32}, 'manifest': {'counter': 1, 'sha256': 'm' * 64}})
        got = agentwatch.problems(self.conn)
        kind = got['security-agent-claim:nas'][0]
        self.assertFalse(notifications.ignorable(kind, 'warn'), 'a security finding leaves only when it is resolved')
        self.assertNotIn('agent-manifest:nas', got, 'the manifest it says it runs is the one given')
        self.conn.execute('UPDATE agent_peers SET claims_json = :c', {'c': json.dumps({'claims': {'machine': MACHINE}, 'manifest': {'sha256': 'o' * 64}})})
        got = agentwatch.problems(self.conn)
        self.assertNotIn('security-agent-claim:nas', got)
        self.assertIn('agent-manifest:nas', got)

    def test_the_notification_center_hears_of_it(self):
        self.enroll(updated=time.time() - 3600)
        self.assertIn('agent-silent:nas', alerts.problems(self.conn))

    def test_readings_go_out_labelled_as_the_agents_claim(self):
        fp = self.enroll()
        self.conn.execute("""INSERT INTO agent_records (host, fingerprint, counter, seq, plugin, kind, claimed_at, received_at, body_json)
                             VALUES ('nas', :f, 1, 1, 'health', 'load', 5, 6, :b)""", {'f': fp, 'b': json.dumps({'html': '<script>x</script>'})})
        got = agentwatch.records(self.conn, 'nas')
        self.assertEqual((got[0]['source'], got[0]['label'], got[0]['body']), ('agent', 'reported by agent', {'html': '<script>x</script>'}))
        self.assertEqual(agentwatch.records(self.conn, 'nas', plugin='other'), [])


class Routes(Base):
    def setUp(self):
        super().setUp()
        vault.Vault(self.db, self.conn, SECRET).init()
        users.create(self.conn, 'root', PW, 'admin')
        users.create(self.conn, 'viewer', PW, 'viewer')
        users.save_role(self.conn, 'keykeeper', 'keys, not privilege', ['keys.view', 'keys.manage', 'hosts.view'], 'test', True)
        users.create(self.conn, 'keeper', PW, 'keykeeper')
        self.web = server.create_app(server.App(self.db), 's' * 48)
        release = self.tmp / 'release' / 'x86_64'
        release.mkdir(parents=True)
        for name, needs in (('heartbeat', {}), ('disks', {'capabilities': ['SYS_RAWIO'], 'devices': ['disks']})):
            (release / f'{name}.plugin.json').write_text(json.dumps({'format': 1, 'name': name, 'needs': needs}))
            (release / f'{name}.plugin.sig').write_text('-----BEGIN SSH SIGNATURE-----\nAA==\n-----END SSH SIGNATURE-----\n')
        p = mock.patch.dict(os.environ, {'STORAGEFORGE_AGENT_PLUGINS': str(self.tmp / 'release')})
        p.start()
        self.addCleanup(p.stop)
        self.enroll()
        self.applied = []
        p = mock.patch.object(sfagent, 'apply', lambda db, host, plugins, actor=None, group_id=None, accept_new_key=False:
                              self.applied.append(([json.loads(d)['name'] for d, _s, _k in plugins], accept_new_key)) or {'host': host, 'state': 'running'})
        p.start()
        self.addCleanup(p.stop)

    def client(self, name):
        c = self.web.test_client()
        self.assertEqual(c.post('/api/login', json={'username': name, 'password': PW}).status_code, 200)
        return c

    def audit(self):
        return [(a, o) for a, o in self.conn.all("SELECT action, outcome FROM audit_log WHERE action = 'agent.plugins' ORDER BY audit_id")]

    def test_a_plugin_with_privileges_takes_an_admin(self):
        keeper = self.client('keeper')
        got = keeper.post('/api/agents/nas/plugins', json={'plugins': ['heartbeat']})
        self.assertEqual(got.status_code, 200, got.get_json())
        got = keeper.post('/api/agents/nas/plugins', json={'plugins': ['heartbeat', 'disks']})
        self.assertEqual((got.status_code, got.get_json()['code']), (403, 'privilege'))
        self.assertIn('disks declares privileges', got.get_json()['error'])
        got = keeper.post('/api/agents/nas/plugins', json={'plugins': ['heartbeat'], 'accept_new_key': True})
        self.assertEqual(got.status_code, 403, 'a new receiver key is a trust decision too')
        root = self.client('root')
        self.assertEqual(root.post('/api/agents/nas/plugins', json={'plugins': ['heartbeat', 'disks'], 'accept_new_key': True}).status_code, 200)
        self.assertEqual(self.applied, [(['heartbeat'], False), (['heartbeat', 'disks'], True)])
        self.assertEqual(self.audit(), [('agent.plugins', 'ok'), ('agent.plugins', 'denied'), ('agent.plugins', 'denied'), ('agent.plugins', 'ok')])

    def test_choosing_plugins_takes_keys_manage_and_a_fresh_password(self):
        self.assertEqual(self.client('viewer').post('/api/agents/nas/plugins', json={'plugins': ['heartbeat']}).status_code, 403)
        root = self.client('root')
        with root.session_transaction() as s:
            s['auth_at'] = 0
        got = root.post('/api/agents/nas/plugins', json={'plugins': ['heartbeat']})
        self.assertTrue(got.get_json().get('reauth'))
        self.assertEqual(self.applied, [])

    def test_a_plugin_the_release_does_not_have_is_refused(self):
        got = self.client('root').post('/api/agents/nas/plugins', json={'plugins': ['../../etc/passwd']})
        self.assertEqual(got.status_code, 409)
        got = self.client('root').post('/api/agents/nas/plugins', json={'plugins': ['files']})
        self.assertIn('no plugin files', got.get_json()['error'])

    def test_what_an_agent_reported_is_read_with_hosts_view_and_labelled(self):
        self.conn.execute("""INSERT INTO agent_records (host, fingerprint, counter, seq, plugin, kind, received_at, body_json)
                             VALUES ('nas', 'SHA256:nas', 1, 1, 'probe', 'reading', 1, '{"n":1}')""")
        got = self.client('viewer').get('/api/agents/nas/records').get_json()
        self.assertEqual((got['label'], got['records'][0]['source'], got['records'][0]['body']), ('reported by agent', 'agent', {'n': 1}))


class NoSecrets(Base):
    def test_an_agent_is_given_public_things_only(self):
        folder = self.tmp / 'receiver'
        secret = agenttunnel.load_or_make_key(folder)
        with mock.patch.dict(os.environ, {'STORAGEFORGE_AGENT_RECEIVER_DIR': str(folder), 'STORAGEFORGE_AGENT_ENDPOINT': '192.0.2.10:7843'}):
            got = sfagent.tunnel_for(self.conn, 'nas')
        self.assertEqual(set(got), {'endpoint', 'key'})
        self.assertEqual(base64.b64decode(got['key']), agenttunnel.public_of(secret), 'the public half')
        self.assertNotIn(secret.hex(), json.dumps(got))
        # a delivery holds the manifest and signed descriptors, which the controller signed or only carries
        self.enroll()
        sfagent.save_delivery(self.conn, 'nas', 'SHA256:nas', 2, '{"format":1}', 'sig', [(b'{"name":"x"}', 'sig', 'release')], tunnel=False)
        row = self.conn.all('SELECT manifest, signature, plugins_json FROM agent_deliveries')[0]
        self.assertEqual(json.loads(row[2]), [{'descriptor': '{"name":"x"}', 'signature': 'sig'}])
        for text in row:
            self.assertNotIn('PRIVATE', text)
