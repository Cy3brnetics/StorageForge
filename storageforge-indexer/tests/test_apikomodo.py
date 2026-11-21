"""Komodo through its API (apikomodo.py): reads as POST /read/NAME with the key and secret in X-Api-Key and X-Api-Secret, writes and
executes refused before they leave, a read-back from ListApiKeys, an admin-only probe and GetPermission, and the containers compared
with the SSH scan. Against the real client and apifake.py.

Where the samples come from: the Komodo Rust client, github.com/moghtech/komodo (client/core/rs), fetched 2026-11-20: entities/api_key.rs
(key, secret as a hash, user_id, name, created_at, expires 0 for never), entities/permission.rs (PermissionLevelAndSpecifics: level None,
Read, Execute, Write; specific Terminal, Attach, Inspect, Logs, Processes), entities/resource.rs (ResourceListItem: id, type, name,
template, tags, info), entities/server.rs (ServerListItemInfo: state, address, public_ip, version), entities/stack.rs
(StackListItemInfo: server_id, state, status, services [{service, image, update_available}]), entities/deployment.rs
(DeploymentListItemInfo: state, status, custom_name, image, server_id), entities/docker/container.rs (ContainerListItem: name, id,
image, state, status); api/read/user.rs (ListUsers is admin only), api/read/permission.rs (GetPermission factors in user groups)."""
import json

try:
    from test_apiconn import Base
except ImportError:      # run as tests.test_x from the project folder
    from tests.test_apiconn import Base
from storageforge_index import alerts, apiconn, apiguide, apikomodo, apiread, apiviews

KEY = 'K-7Qw2Er9Ty4Ui1Op6As3Df8Gh5Jk0Lz'
SECRET = 'S-4Mn7Bv2Cx9Za6Sd1Fg8Hj3Kl0Qw5Er'
NOW = 1_900_000_000


def body(req):
    return json.loads(req['body'] or '{}')


def routes(level='Read', specific=(), admin=False):
    perm = {'level': level, 'specific': list(specific)}
    return {
        '/read/ListApiKeys': [{'key': 'K-other', 'secret': '$argon2id$hash-not-the-secret', 'user_id': 'u1', 'name': 'old', 'created_at': 1, 'expires': 0},
                              {'key': KEY, 'secret': '$argon2id$hash-not-the-secret', 'user_id': 'u1', 'name': 'storageforge', 'created_at': 1, 'expires': NOW * 1000}],
        '/read/ListUsers': [{'id': 'u0', 'username': 'admin', 'admin': True}] if admin else (403, 'Forbidden', {'error': 'this method is admin only', 'trace': []}),
        '/read/ListServers': [{'id': 's1', 'type': 'Server', 'name': 'docker3', 'template': False, 'tags': [],
                               'info': {'state': 'Ok', 'address': 'https://10.9.3.3:8120', 'region': '', 'version': 'v2.3.1', 'public_ip': None}}],
        '/read/ListStacks': [{'id': 'st1', 'type': 'Stack', 'name': 'paperless', 'template': False, 'tags': [],
                              'info': {'server_id': 's1', 'server_name': 'docker3', 'state': 'running', 'status': 'Up', 'services': [{'service': 'web', 'image': 'paperless-ngx', 'update_available': False}]}}],
        '/read/ListDeployments': [{'id': 'd1', 'type': 'Deployment', 'name': 'uptime', 'template': False, 'tags': [],
                                   'info': {'state': 'exited', 'status': 'Exited', 'custom_name': '', 'image': 'louislam/uptime-kuma', 'update_available': True, 'server_id': 's1'}}],
        '/read/ListContainers': lambda req: [{'server_id': 's1', 'name': 'paperless-web-1', 'id': 'c1', 'image': 'paperless-ngx', 'state': 'running', 'status': 'Up'},
                                             {'server_id': 's1', 'name': 'uptime', 'id': 'c2', 'image': 'louislam/uptime-kuma', 'state': 'exited', 'status': 'Exited'}] if body(req).get('server') == 's1' else [],
        '/read/GetPermission': perm,
    }


class Read(Base):
    def setUp(self):
        super().setUp()
        self.fake.prefix, self.fake.wrap = '', False
        self.fake.routes.update(routes())
        self.conn.execute("INSERT INTO hosts (hostname, ssh_host, ip_address, ssh_user, inventory_json) VALUES ('docker3', 'docker3.lab', '10.9.3.3', 'scan', '{}')")
        row = apiconn.add(self.v, self.conn, 'komodo', 'komodo', self.fake.url, KEY, SECRET, 'gabe')
        self.row = apiconn.pin(self.conn, row['conn_id'], self.fake.fingerprint, 'gabe')

    def no_secret(self, *texts):
        for t in texts:
            self.assertNotIn(SECRET, str(t))
        self.assertNotIn(SECRET, self.stderr.getvalue())
        self.assertEqual(self.everywhere(SECRET), [])
        self.assertEqual(self.everywhere('hash-not-the-secret'), [])
        for r in self.fake.requests:
            self.assertNotIn(SECRET, r['path'] + r['body'])
            self.assertEqual((r['method'], r['headers']['X-Api-Key'], r['headers']['X-Api-Secret']), ('POST', KEY, SECRET))
            self.assertTrue(r['path'].startswith('/read/'))

    def test_a_read_only_group(self):
        got = apiread.read(self.db, self.conn, self.row)
        self.assertEqual(got['readback']['verdict'], 'exact')
        self.assertEqual(got['counts'], {'environment': 1, 'container': 2, 'stack': 1, 'deployment': 1})
        objs = {(o['kind'], o['ref']): o for o in apiread.objects(self.conn, self.row['conn_id'])}
        self.assertEqual(objs[('container', 's1/paperless-web-1')]['stack'], 'paperless')
        self.assertEqual(objs[('container', 's1/uptime')]['deployment'], 'uptime')
        targets = [body(r)['target'] for r in self.fake.requests if r['path'] == '/read/GetPermission']
        self.assertIn({'type': 'Server', 'id': 's1'}, targets)
        self.assertEqual(apiconn.get(self.conn, self.row['conn_id'])['token_expires_at'], NOW)
        self.no_secret(got)

    def test_an_admin_key_write_terminal_or_inspect_is_a_finding(self):
        self.fake.routes.update(routes(admin=True))
        rb = apiread.read(self.db, self.conn, self.row)['readback']
        self.assertEqual((rb['verdict'], rb['admin']), ('over', True))
        self.assertEqual(alerts.problems(self.conn)['security-api-token:komodo'][4], 'crit')
        self.fake.routes.update(routes(level='Write'))
        rb = apiread.read(self.db, self.conn, self.row)['readback']
        self.assertEqual(sorted(o['path'] for o in rb['over']), ['Deployment uptime', 'Server docker3', 'Stack paperless'])
        self.fake.routes.update(routes(specific=['Terminal', 'Logs']))
        rb = apiread.read(self.db, self.conn, self.row)['readback']
        self.assertTrue(rb['admin'])
        self.assertIn({'path': 'Server docker3', 'priv': 'Logs'}, rb['extra_read'])
        apiconn.set_actions(self.conn, self.row['conn_id'], ['redeploy'])
        self.fake.routes.update(routes(level='Execute'))
        rb = apiread.read(self.db, self.conn, apiconn.get(self.conn, self.row['conn_id']))['readback']
        self.assertEqual(sorted(o['path'] for o in rb['over']), ['Deployment uptime', 'Server docker3'], 'Execute is wanted on stacks only')
        self.no_secret()

    def test_a_write_or_an_execute_never_leaves(self):
        with apiconn.open_client(self.db, self.conn, self.row) as c:
            for path in ('/write/UpdateBuild', '/execute/DeployStack', '/read/../write/X', '/readx/Y'):
                with self.subTest(path), self.assertRaises(apiconn.ApiError):
                    c.request('POST', path, {'stack': 'paperless'})
        self.assertEqual(self.fake.requests, [])

    def test_containers_beside_the_scan(self):
        hid = self.conn.scalar("SELECT host_id FROM hosts WHERE hostname = 'docker3'")
        self.conn.execute("""INSERT INTO docker_hosts (host_id, engine, access, root_dir, containers_json, volumes_json, compose_json)
                             VALUES (:h, 'docker', 'direct', '/var/lib/docker', :c, '[]', '[]')""",
                          {'h': hid, 'c': json.dumps([{'name': 'paperless-web-1', 'state': 'running', 'mounts': [], 'labels': {'com.docker.compose.project': 'paperless'}}])})
        apiread.read(self.db, self.conn, self.row)
        cmp = {c['host']: c for c in apiviews.compare_connection(self.conn, apiconn.get(self.conn, self.row['conn_id']))['containers']}
        rows = {r['name']: r for r in cmp['docker3']['containers']}
        self.assertEqual((rows['paperless-web-1']['seen_by'], rows['uptime']['seen_by']), (['api', 'ssh'], ['api']))
        self.assertEqual(apiviews.managed_by(self.conn, 'docker3')['paperless-web-1']['stack'], 'paperless')

    def test_the_guide_and_answers_that_are_not_what_the_client_says(self):
        g = apiguide.guide('komodo')
        self.assertIn('all.Server = "Read"', g['steps'][1]['run'][0])
        self.assertNotIn('"Write"', json.dumps(g['steps']))
        for f in (apikomodo.parse_api_keys, apikomodo.parse_permission, apikomodo.parse_servers, apikomodo.parse_stacks, apikomodo.parse_deployments, apikomodo.parse_containers):
            for bad in ('', 'x', 'null', '{"level": "Root"}', '[null, {"id": 5}, {"id": "a", "name": "b", "info": []}]'):
                with self.subTest(f=f.__name__, bad=bad):
                    self.assertIsInstance(f(bad), dict)
        self.assertEqual(apikomodo.parse_permission('{"level": "Root", "specific": ["Logs", 3]}'), {'level': None, 'specific': ['Logs']})


if __name__ == '__main__':
    import unittest
    unittest.main()
