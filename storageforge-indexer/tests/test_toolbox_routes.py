"""The Toolbox API (routes_toolbox.py) through the real app: what each permission allows (a custom entry and an operator key take
hosts.command and a fresh password; staging takes plans.edit and saves a plan; accepting an unsigned entry asks for the password again),
the editor's validate and dry run, signing on the operator's machine with the controller only verifying, actions, overrides, updates and
exposure, and what lands in the audit log."""
import json
import time

try:
    from test_toolbox import CUSTOM, Base, keypair, sign
except ImportError:      # run as tests.test_x from the project folder
    from tests.test_toolbox import CUSTOM, Base, keypair, sign
from storageforge_index import security, server, users

PW = 'a long enough password'


class Routes(Base):
    def setUp(self):
        super().setUp()
        self.host('box', 'apt', ['podman', 'wg'])
        security._save_measurement(self.conn, 'box', 'infra', int(time.time()), 'measure',
                                   {'tools': ['podman', 'wg'], 'listeners': [{'proto': 'tcp', 'addr': '0.0.0.0', 'port': 3001, 'scope': 'any'}],
                                    'access': {'wireguard': [{'name': 'wg0', 'public_key': 'A' * 43 + '=', 'listen_port': 51820, 'peers': []}]}})
        users.create(self.conn, 'admin', PW, 'admin')
        users.create(self.conn, 'op', PW, 'operator')
        self.web = server.create_app(server.App(self.db), 's' * 48)

    def client(self, who='admin', fresh=True):
        c = self.web.test_client()
        self.assertEqual(c.post('/api/login', json={'username': who, 'password': PW}).status_code, 200)
        if not fresh:
            with c.session_transaction() as s:
                s['auth_at'] = 0
        return c

    def audited(self, action):
        return [json.loads(r[0] or '{}') for r in self.conn.all('SELECT detail_json FROM audit_log WHERE action = :a ORDER BY audit_id', {'a': action})]

    def test_the_catalog_and_an_entry(self):
        c = self.client('op')
        got = c.get('/api/toolbox/catalog').get_json()
        self.assertLessEqual({'cockpit', 'uptime-kuma', 'wireguard'}, {e['id'] for e in got['entries']})
        self.assertEqual(got['official']['state'], 'packaged')
        self.assertFalse(got['may_write'])
        e = c.get('/api/toolbox/catalog/uptime-kuma').get_json()
        self.assertIn('format: 1', e['text'])
        self.assertEqual(e['methods'], ['container', 'quadlet', 'compose'])
        self.assertEqual(c.get('/api/toolbox/catalog/nope').status_code, 404)

    def test_custom_entries_take_hosts_command_and_a_fresh_password(self):
        op = self.client('op')
        self.assertEqual(op.post('/api/toolbox/catalog/custom', json={'yaml': CUSTOM}).status_code, 403)
        stale = self.client('admin', fresh=False)
        self.assertTrue(stale.post('/api/toolbox/catalog/custom', json={'yaml': CUSTOM}).get_json().get('reauth'))
        c = self.client()
        v = c.post('/api/toolbox/catalog/validate', json={'yaml': CUSTOM}).get_json()
        self.assertTrue(v['ok'])
        self.assertIn('ssh-keygen -Y sign', v['sign'])
        self.assertEqual(v['signature']['state'], 'unsigned')
        self.assertFalse(c.post('/api/toolbox/catalog/validate', json={'yaml': CUSTOM.replace('format: 1', 'format: 9')}).get_json()['ok'])
        r = c.post('/api/toolbox/catalog/custom', json={'yaml': CUSTOM})
        self.assertEqual(r.status_code, 201, r.get_json())
        self.assertEqual(r.get_json()['state'], 'unsigned')
        self.assertEqual(self.audited('toolbox.custom.save')[0]['trust'], 'unsigned')
        # the operator's key: its public half here, the signature made where the private half is
        key, pub = keypair(self.tmp, 'alice')
        self.assertEqual(c.post('/api/toolbox/signers', json={'name': 'alice', 'public_key': pub}).status_code, 201)
        self.assertEqual(c.get('/api/toolbox/signers').get_json()['signers'][0]['name'], 'alice')
        stored = c.get('/api/toolbox/catalog/whoami').get_json()['text']
        r = c.post('/api/toolbox/catalog/sign', json={'id': 'whoami', 'signature': sign(key, stored + 'x', self.tmp)})
        self.assertEqual(r.status_code, 400)
        r = c.post('/api/toolbox/catalog/sign', json={'id': 'whoami', 'signature': sign(key, stored, self.tmp)})
        self.assertEqual(r.get_json()['state'], 'operator-signed')
        self.assertEqual(c.get('/api/toolbox/catalog/whoami').get_json()['signed_by'], 'alice')
        self.assertEqual(c.delete('/api/toolbox/signers/alice').status_code, 200)
        self.assertEqual(c.get('/api/toolbox/catalog/whoami').get_json()['trust'], 'refused', 'its signer is gone')
        self.assertEqual(c.delete('/api/toolbox/catalog/custom/whoami').status_code, 200)
        self.assertEqual(c.post('/api/toolbox/catalog/update', json={'manifest': '{}', 'signature': '', 'entries': {'x': 'y'}}).status_code, 400)

    def test_preview_and_stage(self):
        c = self.client('op')
        pv = c.post('/api/toolbox/preview', json={'host': 'box', 'tool': 'uptime-kuma'}).get_json()
        self.assertEqual(pv['method'], 'container')
        self.assertFalse(self.conn.scalar('SELECT COUNT(*) FROM change_plans'))
        r = c.post('/api/toolbox/stage', json={'host': 'box', 'tool': 'uptime-kuma'})
        self.assertEqual(r.status_code, 201, r.get_json())
        plan = c.get(f'/api/changes/{r.get_json()["plan_id"]}').get_json()
        self.assertEqual(plan['tasks'][0]['type'], 'tool-install')
        self.assertEqual(self.audited('toolbox.stage')[0]['tool'], 'uptime-kuma')
        inst = c.get('/api/toolbox/installed?host=box').get_json()
        self.assertEqual(inst['installs'][0]['status'], 'staged')
        self.assertIn('box', inst['hosts'])
        st = c.get('/api/toolbox/installed/box/uptime-kuma/status').get_json()
        self.assertEqual(st['links'][0]['tunnel'], 'ssh -L 3001:127.0.0.1:3001 box')
        ex = c.get('/api/toolbox/exposure').get_json()['exposure'][0]
        self.assertTrue(ex['wider_than_staged'], 'staged on loopback, and the reading saw 3001 on every address')
        r = c.post('/api/toolbox/stage', json={'host': 'box', 'tool': 'uptime-kuma', 'action': 'remove'})
        self.assertEqual(r.get_json()['kept'], ['/srv/toolbox/uptime-kuma/data'])
        self.assertEqual(c.post('/api/toolbox/stage', json={'host': 'nowhere', 'tool': 'cockpit'}).status_code, 404)
        self.assertEqual(self.client('admin').get('/api/toolbox/updates').get_json()['updates'], [])

    def test_a_custom_entry_and_an_unsigned_one_ask_for_more(self):
        self.client().post('/api/toolbox/catalog/custom', json={'yaml': CUSTOM})
        op = self.client('op')
        self.assertEqual(op.post('/api/toolbox/stage', json={'host': 'box', 'tool': 'whoami'}).status_code, 403)
        stale = self.client('admin', fresh=False)
        self.assertEqual(stale.post('/api/toolbox/stage', json={'host': 'box', 'tool': 'whoami'}).status_code, 400, 'not accepted: refused')
        self.assertTrue(stale.post('/api/toolbox/stage', json={'host': 'box', 'tool': 'whoami', 'accept_unsigned': True}).get_json().get('reauth'))
        r = self.client().post('/api/toolbox/stage', json={'host': 'box', 'tool': 'whoami', 'accept_unsigned': True})
        self.assertEqual(r.status_code, 201, r.get_json())
        self.assertTrue(self.audited('toolbox.stage')[-1]['unsigned_accepted'])
        dry = op.post('/api/toolbox/preview', json={'host': 'box', 'yaml': CUSTOM.replace('id: whoami', 'id: whoami-two')}).get_json()
        self.assertEqual(dry['tool'], 'whoami-two')
        self.assertEqual(dry['tasks'][0]['type'], 'tool-install')

    def test_a_tool_a_bundle_and_a_role_profile_pass_one_gate(self):
        from storageforge_index import tbbundles
        self.client().post('/api/toolbox/catalog/custom', json={'yaml': CUSTOM})
        tbbundles.save_bundle(self.conn, {'id': 'mine', 'name': 'Mine', 'entries': ['whoami']}, 'admin')
        tbbundles.set_role_profile(self.conn, 'edge', ['whoami'], {}, 'admin')
        tbbundles.set_host_role(self.conn, 'box', 'edge', [], 'admin')
        tries = [('/api/toolbox/stage', {'host': 'box', 'tool': 'whoami'}), ('/api/toolbox/bundles/stage', {'host': 'box', 'bundle_id': 'mine'}),
                 ('/api/toolbox/bundles/stage', {'host': 'box', 'entries': [' whoami']}), ('/api/toolbox/profiles/host/box/stage', {})]
        op, stale = self.client('op'), self.client('admin', fresh=False)
        for path, body in tries:
            with self.subTest(path=path, body=body):
                r = op.post(path, json=body)
                self.assertEqual(r.status_code, 403)
                self.assertIn('custom entry', r.get_json()['error'])
                self.assertEqual(op.post(path, json={**body, 'accept_unsigned': True}).status_code, 403)
                self.assertTrue(stale.post(path, json={**body, 'accept_unsigned': True}).get_json().get('reauth'))

    def test_accepting_unsigned_in_a_role_profile_is_refused_before_the_host_is_looked_up(self):
        op, stale = self.client('op'), self.client('admin', fresh=False)
        r = op.post('/api/toolbox/profiles/host/nosuchhost/stage', json={'accept_unsigned': True})
        self.assertEqual(r.status_code, 403)
        self.assertIn('unsigned', r.get_json()['error'])
        self.assertTrue(stale.post('/api/toolbox/profiles/host/nosuchhost/stage', json={'accept_unsigned': True}).get_json().get('reauth'))
        self.assertEqual(self.client().post('/api/toolbox/profiles/host/nosuchhost/stage', json={'accept_unsigned': True}).status_code, 404)

    def test_a_refused_staging_is_audited_for_a_tool_a_bundle_and_a_role_profile(self):
        from storageforge_index import tbbundles
        c = self.client()
        tbbundles.save_bundle(self.conn, {'id': 'mine', 'name': 'Mine', 'entries': ['cockpit']}, 'admin')
        tbbundles.set_role_profile(self.conn, 'edge', ['cockpit'], {}, 'admin')
        tbbundles.set_host_role(self.conn, 'box', 'edge', ['cockpit'], 'admin')
        self.assertEqual(c.post('/api/toolbox/stage', json={'host': 'box', 'tool': 'cockpit', 'method': 'nope'}).status_code, 400)
        self.assertEqual(c.post('/api/toolbox/bundles/remove', json={'host': 'box', 'bundle_id': 'mine'}).status_code, 400)
        self.assertEqual(c.post('/api/toolbox/profiles/host/box/stage', json={}).status_code, 400)
        self.assertEqual(len(self.audited('toolbox.stage')), 1)
        self.assertEqual(self.audited('toolbox.bundle.remove'), [{'bundle': 'mine', 'why': 'no StorageForge-managed tools from bundle Mine are installed on box'}])
        self.assertEqual(self.audited('toolbox.profile.stage'), [{'role': 'edge', 'why': 'all tools in role edge are excluded on box'}])

    def test_actions_and_overrides(self):
        c = self.client('op')
        acts = c.get('/api/toolbox/box/wireguard/actions').get_json()['actions']
        self.assertEqual(acts[0]['id'], 'add-peer')
        r = c.post('/api/toolbox/box/wireguard/actions/add-peer', json={'values': {'iface': 'wg0', 'pubkey': 'B' * 43 + '=', 'allowed': '10.8.0.2/32'}})
        self.assertEqual(r.status_code, 201, r.get_json())
        self.assertEqual(r.get_json()['tasks'][0]['type'], 'wg-peer')
        self.assertEqual(c.post('/api/toolbox/box/wireguard/actions/nope', json={}).status_code, 400)
        self.assertEqual(c.put('/api/toolbox/overrides/box/uptime-kuma', json={'yaml': 'ports: {3001: 3911}\n'}).status_code, 200)
        self.assertEqual(c.get('/api/toolbox/overrides/box/uptime-kuma').get_json()['override']['text'], 'ports: {3001: 3911}\n')
        img = 'image: docker.io/louislam/uptime-kuma:2.0.1@sha256:' + '6' * 64 + '\n'
        self.assertEqual(c.put('/api/toolbox/overrides/box/uptime-kuma', json={'yaml': img}).status_code, 403, 'another image runs other code')
        self.assertEqual(self.client().put('/api/toolbox/overrides/box/uptime-kuma', json={'yaml': img}).status_code, 200)
        self.assertEqual(c.put('/api/toolbox/overrides/box/uptime-kuma', json={'yaml': 'run: id\n'}).status_code, 400)
        self.assertEqual(self.audited('toolbox.override')[0]['keys'], ['ports'])
        viewer = self.web.test_client()
        users.create(self.conn, 'v', PW, 'viewer')
        viewer.post('/api/login', json={'username': 'v', 'password': PW})
        self.assertEqual(viewer.get('/api/toolbox/catalog').status_code, 200)
        self.assertEqual(viewer.post('/api/toolbox/stage', json={'host': 'box', 'tool': 'cockpit'}).status_code, 403)
