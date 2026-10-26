"""Vault, ephemeral agent, audit chain, graph, .canvas export and HTTP API.
Run with: python3 -m unittest discover -s tests -v"""
import datetime as dt
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from storageforge_index import blueprint, canvas, graph, vault
from storageforge_index.db import Database
from storageforge_index.payloads import (apply_df, apply_fstab, apply_zpool_status, load_structured, node_from_blueprint,
                                         parse_df, parse_fstab, parse_zpool_status)

EXAMPLES = Path(__file__).resolve().parents[1] / 'examples' / 'atlas'
SECRET = b'correct horse battery staple, but longer than 32'
vault.KDF_DEFAULTS = {'time_cost': 1, 'memory_kib': 8192, 'lanes': 1}   # fast Argon2id for tests


def atlas_node():
    node = node_from_blueprint(load_structured(str(EXAMPLES / 'blueprint.json')))
    apply_zpool_status(node, parse_zpool_status((EXAMPLES / 'zpool-status.txt').read_text()))
    apply_fstab(node, parse_fstab((EXAMPLES / 'fstab').read_text()))
    apply_df(node, parse_df((EXAMPLES / 'df-h.txt').read_text()))
    return node


def private_pem():
    k = ed25519.Ed25519PrivateKey.generate()
    return k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, serialization.NoEncryption())


class DBCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='sf-plat-'))
        self.db = Database(str(self.tmp / 'idx.db'))
        self.conn = self.db.connect()
        self.db.migrate(self.conn)

    def tearDown(self):
        self.conn.close()
        shutil.rmtree(self.tmp, ignore_errors=True)


class VaultTests(DBCase):
    def unlocked(self, secret=SECRET):
        v = vault.Vault(self.db, self.conn, secret)
        v.init()
        return v.unlock()

    def test_roundtrip_and_no_plaintext_at_rest(self):
        pem = private_pem()
        with self.unlocked() as v:
            info = v.add_key('nas', pem)
            kid = self.conn.scalar('SELECT key_id FROM ssh_keys')
            with v.decrypt_key(kid) as buf:
                got = bytes(buf.view())
            self.assertEqual(serialization.load_ssh_private_key(got, None).public_key().public_bytes(
                serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode(), info['public_key'].rsplit(' ', 1)[0])
        raw = Path(self.db.path).read_bytes()
        self.assertNotIn(b'OPENSSH PRIVATE KEY', raw)
        self.assertNotIn(pem[40:80], raw)

    def test_wrong_secret_is_refused(self):
        self.unlocked().close()
        with self.assertRaises(vault.VaultLocked):
            vault.Vault(self.db, self.conn, b'x' * 40).unlock()

    def test_tampered_or_swapped_ciphertext_fails(self):
        with self.unlocked() as v:
            v.add_key('a', private_pem())
            v.add_key('b', private_pem())
            (a_id, a_ct), (b_id, b_ct) = self.conn.all('SELECT key_id, ciphertext FROM ssh_keys ORDER BY key_id')
            self.conn.execute('UPDATE ssh_keys SET ciphertext = :c WHERE key_id = :k', {'c': b_ct, 'k': a_id})
            with self.assertRaises(vault.VaultError):
                v.decrypt_key(a_id)          # b's ciphertext is bound to b's UUID
            flipped = bytearray(bytes(b_ct))
            flipped[10] ^= 1
            self.conn.execute('UPDATE ssh_keys SET ciphertext = :c WHERE key_id = :k', {'c': bytes(flipped), 'k': b_id})
            with self.assertRaises(vault.VaultError):
                v.decrypt_key(b_id)

    def test_rotation_rewraps_without_reencrypting(self):
        with self.unlocked() as v:
            v.add_key('a', private_pem())
            before = self.conn.scalar('SELECT ciphertext FROM ssh_keys')
            v.rotate_secret(b'n' * 48)
        self.assertEqual(self.conn.scalar('SELECT ciphertext FROM ssh_keys'), before)
        with self.assertRaises(vault.VaultLocked):
            vault.Vault(self.db, self.conn, SECRET).unlock()
        with vault.Vault(self.db, self.conn, b'n' * 48).unlock() as v:
            v.decrypt_key(self.conn.scalar('SELECT key_id FROM ssh_keys')).wipe()

    def test_binding_specificity_and_actions(self):
        with self.unlocked() as v:
            v.add_key('fleet', private_pem())
            v.add_key('nas', private_pem())
            v.bind('fleet', '10.0.0.0/8', 'scan')
            v.bind('fleet', '10.0.20.0/24', 'ops')
            v.bind('nas', '10.0.20.5', 'root', 2222, 'scan,checksum')
            self.assertEqual(v.resolve('10.0.20.5').user, 'root')
            self.assertEqual(v.resolve('10.0.20.9').user, 'ops')
            self.assertEqual(v.resolve('10.9.9.9').user, 'scan')
            with self.assertRaises(vault.NoBinding):
                v.resolve('10.0.20.9', 'checksum')
            with self.assertRaises(vault.NoBinding):
                v.resolve('192.168.1.1')

    def test_audit_chain_detects_edits(self):
        with self.unlocked() as v:
            log = vault.AuditLog(self.db, self.conn, v.audit_key)
            for i in range(5):
                log.append('test', 'ssh.scan', 'ok', f'h{i}', None, {'i': i})
            self.assertEqual(log.verify(), (True, 5, None))
            with self.assertRaises(Exception):
                self.conn.execute("UPDATE audit_log SET outcome = 'failed'")
            self.conn.execute('DROP TRIGGER audit_log_no_update')
            self.conn.execute("UPDATE audit_log SET target_host = 'forged' WHERE audit_id = 3")
            self.assertEqual(log.verify()[0], False)
            self.assertEqual(log.verify()[2], 3)

    def test_ephemeral_agent_holds_key_only_in_memory(self):
        from storageforge_index import runner
        os.environ['STORAGEFORGE_RUNTIME_DIR'] = str(self.tmp)
        try:
            with self.unlocked() as v:
                info = v.add_key('k', private_pem())
                buf = v.decrypt_key(self.conn.scalar('SELECT key_id FROM ssh_keys'))
                with runner.ephemeral_agent(buf) as sock:
                    self.assertEqual(buf.length, 0)                     # plaintext wiped once loaded
                    listed = subprocess.run(['ssh-add', '-l'], env={'SSH_AUTH_SOCK': sock, 'PATH': os.environ['PATH']},
                                            capture_output=True, text=True).stdout
                    self.assertIn(info['fingerprint'], listed)
                    self.assertEqual(oct(os.stat(Path(sock).parent).st_mode & 0o777), '0o700')
                    files = [p for p in Path(sock).parent.iterdir()]
                    self.assertEqual([p.name for p in files], ['agent.sock'])  # no key file anywhere
                self.assertFalse(Path(sock).parent.exists())
        finally:
            del os.environ['STORAGEFORGE_RUNTIME_DIR']


class GraphTests(DBCase):
    def test_atlas_graph(self):
        nodes, edges = graph.build(atlas_node(), dt.date(2026, 10, 26))
        kinds = {n['kind'] for n in nodes.values()}
        self.assertEqual(kinds, set(graph.KINDS))
        rels = {e['rel'] for e in edges}
        self.assertEqual(rels, set(graph.RELS))
        self.assertEqual(nodes['mnt:atlas:/mnt/storage_array/vm']['health'], 'broken')
        self.assertEqual(nodes['mnt:atlas:/mnt/storage_array/photos']['health'], 'protected')
        self.assertEqual(nodes['mnt:atlas:/mnt/storage_array/media']['health'], 'local-only')
        loop = {(e['src'], e['dst']) for e in edges if e['rel'] == 'SYMLINK_TO' and e['src'].startswith('link:atlas:/opt')}
        self.assertEqual(loop, {('link:atlas:/opt/app/current', 'link:atlas:/opt/app/releases/live'),
                                ('link:atlas:/opt/app/releases/live', 'link:atlas:/opt/app/current')})
        self.assertIn('host:nas-02.tail4c2e.ts.net', {e['dst'] for e in edges if e['rel'] == 'REPLICATES_TO'})
        self.assertNotIn('host:nas-02 nightly 02:30', nodes)

    def test_save_load_and_canvas(self):
        nodes, edges = graph.build(atlas_node(), dt.date(2026, 10, 26))
        graph.save(self.db, self.conn, 'atlas', nodes, edges)
        graph.save(self.db, self.conn, 'atlas', nodes, edges)          # idempotent rebuild
        g = graph.load(self.conn)
        self.assertEqual(len(g['nodes']), len(nodes))
        c = canvas.to_canvas(g)
        ids = [n['id'] for n in c['nodes']]
        self.assertEqual(len(ids), len(set(ids)))
        for n in c['nodes']:
            self.assertIn(n['type'], ('text', 'group'))
            for k in ('x', 'y', 'width', 'height'):
                self.assertIsInstance(n[k], int)
        for e in c['edges']:
            self.assertIn(e['fromNode'], ids)
            self.assertIn(e['toNode'], ids)
            self.assertIn(e['fromSide'], ('left', 'right'))
        text_nodes = [n for n in c['nodes'] if n['type'] == 'text']
        boxes = [(n['x'], n['y'], n['x'] + n['width'], n['y'] + n['height']) for n in text_nodes]
        for i, a in enumerate(boxes):                                    # layout never overlaps cards
            for b in boxes[i + 1:]:
                self.assertFalse(a[0] < b[2] and b[0] < a[2] and a[1] < b[3] and b[1] < a[3], (a, b))
        json.loads(canvas.dumps(g))


class BlueprintTests(DBCase):
    def test_from_node_round_trips_through_the_indexer(self):
        bp = blueprint.from_node(atlas_node(), dt.date(2026, 10, 26))
        self.assertEqual((bp['apiVersion'], bp['metadata']['host']), ('storageforge/v1', 'atlas'))
        self.assertTrue(all(d['dev'].startswith('/dev/') for d in bp['devices']))
        pools = {p['name']: p for p in bp['pools']}
        self.assertEqual((pools['tank']['type'], pools['tank']['level']), ('zfs', 'raidz2'))
        nodes = {r['node'] for r in bp['protection']}
        self.assertIn('ds:tank/media', nodes)
        self.assertTrue(all(r['sync']['state'] == 'None' for r in bp['protection']))
        node = node_from_blueprint(json.loads(json.dumps(bp)))       # the graph/report side reads it back
        self.assertEqual({p['name'] for p in node['pools']}, set(pools))

    def test_merge_keeps_operator_intent(self):
        scanned = blueprint.from_node(atlas_node(), dt.date(2026, 10, 26))
        saved = json.loads(json.dumps(scanned))
        saved['devices'][0]['tier'] = 'remote'
        row = next(r for r in saved['protection'] if r['node'] == 'ds:tank/media')
        row['backup'] = {'target': 'restic → B2', 'enc': 'age', 'ratio': 1.2, 'last': '2026-10-20', 'offsite': True}
        saved['protection'].append({'node': 'ds:gone/x', 'dataset': 'gone/x', 'sync': {'state': 'None'}, 'backup': {}})
        saved['exports'] = [{'protocol': 'SMB3', 'name': 'photos', 'path': '/mnt/storage_array/photos'}]
        saved['links'].append({'kind': 'symlink', 'path': '/srv/planned', 'target': '/mnt/storage_array/media'})
        out = blueprint.merge_intent(scanned, saved)
        self.assertEqual(out['devices'][0]['tier'], 'remote')
        self.assertEqual(next(r for r in out['protection'] if r['node'] == 'ds:tank/media')['backup']['target'], 'restic → B2')
        self.assertIn('ds:gone/x', {r['node'] for r in out['protection']})
        self.assertEqual(out['exports'], saved['exports'])
        self.assertIn('/srv/planned', {l['path'] for l in out['links']})
        self.assertEqual(out['metadata']['source'], 'scan+design')


class ServerTests(DBCase):
    def setUp(self):
        super().setUp()
        from storageforge_index import server, users
        nodes, edges = graph.build(atlas_node(), dt.date(2026, 10, 26))
        graph.save(self.db, self.conn, 'atlas', nodes, edges)
        users.create(self.conn, 'alice', 'a long enough password')
        self.web = server.create_app(server.App(self.db), 's' * 48)
        self.client = self.web.test_client()

    def login(self, password='a long enough password', username='Alice'):
        return self.client.post('/api/login', json={'username': username, 'password': password})

    def test_health_auth_graph_canvas_ui(self):
        r = self.client.get('/healthz')
        self.assertEqual((r.status_code, r.json['status'], r.json['users']), (200, 'ok', 1))
        self.assertEqual(self.client.get('/api/graph').status_code, 401)
        self.assertEqual(self.login('wrong password!!').status_code, 401)
        self.assertEqual(self.login(username='nobody').status_code, 401)
        r = self.login()
        self.assertEqual((r.status_code, r.json['username']), (200, 'alice'))
        cookie = r.headers['Set-Cookie']
        self.assertIn('HttpOnly', cookie)
        self.assertIn('SameSite=Strict', cookie)
        self.assertEqual(self.client.get('/api/me').json['username'], 'alice')
        r = self.client.get('/api/graph?host=atlas')
        self.assertGreater(len(r.json['nodes']), 40)
        self.assertIn("default-src 'self'", r.headers['Content-Security-Policy'])
        r = self.client.get('/api/canvas')
        self.assertIn('attachment', r.headers['Content-Disposition'])
        self.assertIn('nodes', json.loads(r.data))
        self.assertIn(b'<canvas id="graph"', self.client.get('/').data)
        self.assertEqual(self.client.get('/app.js').status_code, 200)
        self.assertEqual(self.client.get('/server.py').status_code, 404)
        self.client.post('/api/logout')
        self.assertEqual(self.client.get('/api/me').status_code, 401)
        actions = [(e['action'], e['outcome']) for e in vault.AuditLog(self.db, self.conn, None).tail(10)]
        self.assertEqual(actions.count(('web.login', 'denied')), 2)
        self.assertIn(('web.login', 'ok'), actions)

    def test_password_change_and_disable_end_sessions(self):
        from storageforge_index import users
        self.login()
        users.set_password(self.conn, 'alice', 'another long password')
        self.assertEqual(self.client.get('/api/me').status_code, 401)
        self.assertEqual(self.login().status_code, 401)
        self.assertEqual(self.login('another long password').status_code, 200)
        users.set_disabled(self.conn, 'alice', True)
        self.assertEqual(self.client.get('/api/me').status_code, 401)
        self.assertEqual(self.login('another long password').status_code, 401)

    def test_scan_requires_json_and_session(self):
        self.assertEqual(self.client.post('/api/scan', json={'host': 'nas-02'}).status_code, 401)
        self.login()
        self.assertEqual(self.client.post('/api/scan', data='host=nas-02',
                                          content_type='application/x-www-form-urlencoded').status_code, 400)
        r = self.client.post('/api/scan', json={'host': 'nas-02'})
        self.assertEqual(r.status_code, 202)
        job = self.client.get('/api/jobs').json['jobs'][-1]
        self.assertEqual((job['job_id'], job['requested_by']), (r.json['job_id'], 'web:alice'))
        self.assertEqual(self.client.post('/api/scan', json={'host': 'x' * 5000}).status_code, 413)

    def test_failed_logins_are_rate_limited(self):
        from storageforge_index import users
        users.create(self.conn, 'bob', 'bob has a long password')
        for _ in range(4):
            self.assertEqual(self.login('wrong password!!').status_code, 401)
        self.assertEqual(self.login().status_code, 200)              # successes are not counted
        self.assertEqual(self.login('wrong password!!').status_code, 401)
        r = self.login()                                              # 5 failures for alice: locked even with the right one
        self.assertEqual(r.status_code, 429)
        self.assertIn('too many failed sign-ins', r.json['error'])
        self.assertIn('Retry-After', r.headers)
        for _ in range(4):                                            # bob is still open: 9 failures from this IP
            self.assertEqual(self.login('wrong password!!', 'bob').status_code, 401)
        self.assertEqual(self.login('wrong password!!', 'carol').status_code, 401)   # 10th
        self.assertEqual(self.login('bob has a long password', 'bob').status_code, 429)

    def test_key_generate_and_install_routes(self):
        from unittest import mock
        from storageforge_index import keyinstall
        os.environ['STORAGEFORGE_VAULT_SECRET'] = SECRET.decode()
        try:
            vault.Vault(self.db, self.conn, SECRET).init()
            self.login()
            r = self.client.post('/api/keys', json={'name': 'fleet', 'type': 'ed25519'})
            self.assertEqual(r.status_code, 201)
            self.assertTrue(r.json['public_key'].startswith('ssh-ed25519 '))
            self.assertEqual(self.client.post('/api/keys', json={'name': 'fleet'}).status_code, 400)
            self.assertEqual(self.client.post('/api/keys', json={'name': '../x'}).status_code, 400)
            body = {'key': 'fleet', 'host': 'nas-02', 'user': 'scan', 'port': 22, 'password': 'pw', 'bind': True}
            for bad in ({'host': '-oProxyCommand=sh'}, {'user': '-l'}, {'port': 70000}, {'key': 'missing'}):
                self.assertEqual(self.client.post('/api/keys/install', json=body | bad).status_code, 400, bad)
            calls = []
            def fake_install(public, host, user, password, port):
                calls.append((public, host, user, password, port))
                return {'host': host, 'user': user, 'port': port, 'keys_added': 1}
            works = iter([False, True, True])
            with mock.patch.object(keyinstall, 'install_public_key', fake_install), \
                 mock.patch.object(keyinstall, 'key_login_works', lambda *a: next(works)):
                r = self.client.post('/api/keys/install', json=body)
                self.assertEqual((r.status_code, r.json['verified'], r.json['keys_added']), (200, True, 1))
                bid = r.json['binding_id']
                r = self.client.post('/api/keys/install', json=body)         # key already works: no second copy
                self.assertEqual((r.json['keys_added'], r.json['binding_id']), (0, bid))
            self.assertEqual(len(calls), 1)
            self.assertTrue(calls[0][0].startswith('ssh-ed25519 '))           # only the public key goes to ssh-copy-id
            keys = self.client.get('/api/keys').json
            self.assertEqual([(b['pattern'], b['user'], b['actions']) for b in keys['bindings']], [('nas-02', 'scan', 'scan')])
            self.assertNotIn('ciphertext', json.dumps(keys))
            with mock.patch.object(keyinstall, 'key_login_works', lambda *a: False), \
                 mock.patch.object(keyinstall, 'install_public_key',
                                   mock.Mock(side_effect=keyinstall.InstallError('Permission denied'))):
                self.assertEqual(self.client.post('/api/keys/install', json=body).status_code, 502)
            audit = json.dumps(vault.AuditLog(self.db, self.conn, None).tail(20))
            self.assertIn('ssh.copy-id', audit)
            self.assertNotIn('"pw"', audit)
        finally:
            del os.environ['STORAGEFORGE_VAULT_SECRET']

    def test_askpass_answers_password_prompts_only(self):
        from storageforge_index import askpass
        from unittest import mock
        import io
        with mock.patch.dict(os.environ, {'STORAGEFORGE_ASKPASS_SECRET': 's3cret'}):
            for prompt, code, out in (("scan@nas's password: ", 0, 's3cret\n'), ('Password: ', 0, 's3cret\n'),
                                      ("Enter passphrase for key 'id': ", 1, ''),
                                      ('Are you sure you want to continue connecting (yes/no)? ', 1, '')):
                with mock.patch('sys.argv', ['askpass', prompt]), mock.patch('sys.stdout', io.StringIO()) as so:
                    self.assertEqual((askpass.main(), so.getvalue()), (code, out), prompt)

    def test_planner_page_and_designs(self):
        r = self.client.get('/planner')
        self.assertEqual(r.status_code, 200)
        self.assertIn(b'/planner.js', r.data)
        csp = r.headers['Content-Security-Policy']
        self.assertIn("script-src 'self'", csp)
        self.assertNotIn('unsafe-inline', csp.split('style-src-attr')[0])        # only style attributes are relaxed
        self.assertNotIn(b'<style', self.client.get('/planner.js').data)
        self.assertEqual(self.client.get('/api/planner/hosts').status_code, 401)
        self.login()
        self.assertEqual(self.client.get('/api/planner/design?host=nowhere').status_code, 404)
        bp = blueprint.from_node(atlas_node(), dt.date(2026, 10, 26))
        bp['metadata']['host'] = 'planned-01'
        bp['exports'] = [{'protocol': 'NFSv4.2', 'name': 'media', 'path': '/mnt/storage_array/media'}] * 40  # > 4 KiB
        r = self.client.put('/api/planner/design', json=bp)
        self.assertEqual(r.status_code, 200, r.json)
        self.assertGreater(r.json['graph']['nodes'], 10)
        self.assertIn('host:planned-01', {n['id'] for n in self.client.get('/api/graph?host=planned-01').json['nodes']})
        hosts = {h['host']: h for h in self.client.get('/api/planner/hosts').json['hosts']}
        self.assertTrue(hosts['planned-01']['saved'])
        self.assertFalse(hosts['planned-01']['scanned'])
        got = self.client.get('/api/planner/design?host=planned-01').json
        self.assertEqual((got['source'], len(got['blueprint']['exports'])), ('saved', 40))
        self.assertEqual(self.client.put('/api/planner/design', json={'kind': 'x'}).status_code, 400)
        self.assertEqual(self.client.post('/api/scan', json={'host': 'x' * 5000}).status_code, 413)   # other routes keep 4 KiB

    def test_user_rules(self):
        from storageforge_index import users
        with self.assertRaises(users.UserError):
            users.create(self.conn, 'ALICE', 'a long enough password')     # case-insensitive unique
        with self.assertRaises(users.UserError):
            users.create(self.conn, 'bob', 'short')
        with self.assertRaises(users.UserError):
            users.create(self.conn, 'bob smith', 'a long enough password')
        stored = self.conn.scalar("SELECT password_hash FROM users WHERE username = 'alice'")
        self.assertTrue(stored.startswith('scrypt:'))
        self.assertNotIn('a long enough password', stored)


if __name__ == '__main__':
    unittest.main()
