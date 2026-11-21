"""Dockhand through its API (apidockhand.py): a dh_ Bearer token, a read-back that says what Dockhand lets a token learn of itself and
plainly what it does not, environments with their containers and stacks, each container compared with the SSH scan's Docker reading,
and the hook section 6 uses to tell what a panel manages (apiviews.managed_by). Against the real client and apifake.py.

Where the samples come from: the @openapi blocks of Dockhand's own routes, github.com/Finsys/dockhand (1.0.58), fetched 2026-11-20:
    GET /api/license         the license status object (valid, active, payload {type: enterprise|smb}) and stored {name, activated_at},
                             with stored.key only for a caller holding license:manage (src/routes/api/license/+server.ts)
    GET /api/auth/tokens     [{id, name, tokenPrefix, lastUsed, expiresAt, createdAt}] (resp-200-example)
    GET /api/environments    [{id, name, connectionType, host, port, protocol, icon, publicIp, timezone, hasTlsKey, hasHawserToken}] (resp-200-example)
    GET /api/containers      [{id, name, image, state, status}] (resp-200-example)
    GET /api/stacks          the listComposeStacks entries (name, containers, status) with sourceType added from Dockhand's database
    GET /api/users           [{id, username, email, displayName, isAdmin, isActive, isSso, authProvider}] (needs users:view)"""
import json
import time

try:
    from test_apiconn import Base
except ImportError:      # run as tests.test_x from the project folder
    from tests.test_apiconn import Base
from storageforge_index import alerts, apiconn, apidockhand, apiguide, apiread, apiviews

TOKEN = 'dh_a1b2c3d4Q9wE8rT7yU6iO5pA4sD3fG2hJ1kL0zX9cVb'
NOW = int(time.time())
ENTERPRISE = {'valid': True, 'active': True, 'payload': {'name': 'Lab', 'host': 'dockhand', 'issued': '2026-01-01', 'expires': None, 'type': 'enterprise', 'v': 2},
              'stored': {'name': 'Lab', 'activated_at': '2026-01-02T00:00:00Z'}, 'hostname': 'dockhand'}


def routes(lic=ENTERPRISE):
    return {
        '/license': lic,
        '/auth/tokens': [{'id': 1, 'name': 'ci', 'tokenPrefix': 'zzzzzzzz', 'lastUsed': None, 'expiresAt': None, 'createdAt': '2026-06-01T10:00:00Z'},
                         {'id': 2, 'name': 'storageforge', 'tokenPrefix': 'a1b2c3d4', 'lastUsed': None, 'expiresAt': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(NOW + 300 * 86400)),
                          'createdAt': '2026-11-20T10:00:00Z'}],
        '/users': (403, 'Forbidden', {'error': 'Permission denied'}),
        '/environments': [{'id': 1, 'name': 'local', 'connectionType': 'socket', 'host': None, 'port': 2375, 'protocol': 'http', 'publicIp': None, 'hasTlsKey': False, 'hasHawserToken': False},
                          {'id': 2, 'name': 'docker2', 'connectionType': 'hawser-edge', 'host': None, 'port': 2375, 'protocol': 'http', 'publicIp': '203.0.113.10', 'hasTlsKey': False, 'hasHawserToken': True}],
        '/containers': lambda req: [{'id': 'a1b2c3d4e5f6', 'name': 'immich_server', 'image': 'ghcr.io/immich-app/immich-server:latest', 'state': 'running', 'status': 'Up 2 hours (healthy)'},
                                    {'id': 'b2c3d4e5f6a1', 'name': 'immich_redis', 'image': 'redis:7', 'state': 'exited', 'status': 'Exited (0)'}] if 'env=1' in req['path'] else
                                   [{'id': 'c3', 'name': 'edge-app', 'image': 'nginx', 'state': 'running', 'status': 'Up'}],
        '/stacks': lambda req: [{'name': 'immich', 'containers': ['immich_server', 'immich_redis'], 'containerDetails': [], 'status': 'partial', 'sourceType': 'internal'}] if 'env=1' in req['path'] else [],
    }


class Read(Base):
    def setUp(self):
        super().setUp()
        self.fake.prefix, self.fake.wrap = '/api', False
        self.fake.routes.update(routes())
        self.conn.execute("INSERT INTO hosts (hostname, ssh_host, ip_address, ssh_user, inventory_json) VALUES ('dock1', 'dock1.lab', '10.9.1.1', 'scan', '{}')")
        row = apiconn.add(self.v, self.conn, 'dockhand', 'dockhand', self.fake.url, 'storageforge', TOKEN, 'gabe', host='dock1')
        self.row = apiconn.pin(self.conn, row['conn_id'], self.fake.fingerprint, 'gabe')

    def no_secret(self, *texts):
        for t in texts:
            self.assertNotIn(TOKEN, str(t))
        self.assertNotIn(TOKEN, self.stderr.getvalue())
        self.assertEqual(self.everywhere(TOKEN), [])
        self.assertEqual(self.everywhere('LICENSE-KEY-NEVER-KEPT'), [])
        for r in self.fake.requests:
            self.assertNotIn(TOKEN, r['path'])
            self.assertEqual(r['headers']['Authorization'], f'Bearer {TOKEN}')

    def test_an_enterprise_read_with_what_cannot_be_known_said(self):
        got = apiread.read(self.db, self.conn, self.row)
        rb = got['readback']
        self.assertEqual(rb['verdict'], 'exact')
        self.assertTrue(any('no way to read its own permissions' in n for n in rb['notes']))
        self.assertEqual(got['counts'], {'environment': 2, 'container': 3, 'stack': 1})
        self.assertIn('images and volumes are not read yet', got['skipped'])
        row = apiconn.get(self.conn, self.row['conn_id'])
        self.assertEqual((row['expiry']['state'], row['expiry']['source']), ('ok', 'platform'), 'the expiry of the token whose prefix is in use')
        self.assertIn('api-panel-stopped:dockhand', alerts.problems(self.conn))
        self.no_secret(got)

    def test_the_free_edition_or_a_license_manager_is_a_critical_finding_and_the_key_is_dropped(self):
        self.fake.routes['/license'] = {'valid': False, 'active': False, 'hostname': 'dockhand'}
        rb = apiread.read(self.db, self.conn, self.row)['readback']
        self.assertEqual((rb['verdict'], rb['admin']), ('over', True))
        self.assertIn('every user has full access', rb['over'][0]['priv'])
        self.assertEqual(alerts.problems(self.conn)['security-api-token:dockhand'][4], 'crit')
        self.fake.routes['/license'] = {**ENTERPRISE, 'stored': {'name': 'Lab', 'key': 'LICENSE-KEY-NEVER-KEPT', 'activated_at': 'x'}}
        self.fake.routes['/users'] = [{'id': 1, 'username': 'admin', 'email': 'a@example.com', 'isAdmin': True}]
        rb = apiread.read(self.db, self.conn, self.row)['readback']
        self.assertEqual([o['priv'] for o in rb['over']], ['license:manage'])
        self.assertEqual([e['priv'] for e in rb['extra_read']], ['users:view (every account and its email)'])
        self.no_secret()

    def test_a_token_that_sees_no_environment_reads_nothing_and_says_what_to_add(self):
        self.fake.routes['/environments'] = (403, 'Forbidden', {'error': 'Permission denied'})
        got = apiread.read(self.db, self.conn, self.row)
        self.assertEqual(sorted(s['feature'] for s in got['readback']['short']), ['containers', 'environments', 'stacks'])
        self.assertEqual(got['counts'], {})

    def test_containers_beside_the_scan_and_the_hook_for_section_6(self):
        hid = self.conn.scalar("SELECT host_id FROM hosts WHERE hostname = 'dock1'")
        scanned = [{'name': 'immich_server', 'state': 'running', 'mounts': [], 'labels': {'com.docker.compose.project': 'immich'}},
                   {'name': 'immich_redis', 'state': 'running', 'mounts': [], 'labels': {'com.docker.compose.project': 'immich'}},
                   {'name': 'by-hand', 'state': 'running', 'mounts': [], 'labels': {}}]
        self.conn.execute("""INSERT INTO docker_hosts (host_id, engine, access, root_dir, containers_json, volumes_json, compose_json)
                             VALUES (:h, 'docker', 'direct', '/var/lib/docker', :c, '[]', '[]')""", {'h': hid, 'c': json.dumps(scanned)})
        apiread.read(self.db, self.conn, self.row)
        cmp = apiviews.compare_connection(self.conn, apiconn.get(self.conn, self.row['conn_id']))['containers']
        by_host = {c['host']: c for c in cmp}
        rows = {r['name']: r for r in by_host['dock1']['containers']}
        self.assertEqual(rows['immich_redis']['differs'], [{'field': 'state', 'api': 'exited', 'ssh': 'running'}])
        self.assertEqual(rows['by-hand']['seen_by'], ['ssh'])
        self.assertEqual(by_host[None]['containers'][0]['name'], 'edge-app', 'an edge environment that is no scanned host')
        managed = apiviews.managed_by(self.conn, 'dock1')
        self.assertEqual(managed['immich_server'], {'panel': 'dockhand', 'connection': 'dockhand', 'stack': 'immich', 'environment': 'local'})
        self.assertNotIn('by-hand', managed)
        g = apiviews.map_extra(self.conn, {'nodes': [{'id': 'host:dock1', 'kind': 'Host', 'label': 'dock1', 'layer': 'workloads', 'props': {}},
                                                     {'id': 'wl:dock1:docker::immich_server', 'kind': 'Container', 'label': 'immich_server', 'host': 'dock1', 'layer': 'workloads', 'props': {}}],
                                           'edges': []}, ('workloads',))
        nodes = {n['id']: n for n in g['nodes']}
        self.assertEqual(nodes['wl:dock1:docker::immich_server']['props']['api']['stack'], 'immich')
        self.assertIn('api:dockhand:ctr:2/edge-app', nodes)
        listing = apiviews.annotate_workloads(self.conn, {'workloads': [{'host': 'dock1', 'runtime': 'docker', 'name': 'immich_redis', 'state': 'running'}]})
        w = next(x for x in listing['workloads'] if x['name'] == 'immich_redis')
        self.assertEqual(w['api']['differs'], [{'field': 'state', 'api': 'exited', 'ssh': 'running'}])

    def test_the_guide_and_answers_that_are_not_what_the_routes_say(self):
        g = apiguide.guide('dockhand', scope='docker1')
        text = json.dumps(g)
        self.assertIn('enterprise key', g['least'])
        self.assertIn('Hawser', ' '.join(g['never']))
        self.assertNotIn('"Admin"', text)
        self.assertEqual(apidockhand.token_prefix(TOKEN), 'a1b2c3d4')
        self.assertIsNone(apidockhand.token_prefix('not-a-dockhand-token'))
        for f in (apidockhand.parse_license, apidockhand.parse_tokens, apidockhand.parse_environments, apidockhand.parse_containers, apidockhand.parse_stacks):
            for bad in ('', 'x', 'null', '{"stored": {"key": 5}}', '[null, {"id": "x", "name": 3}, {"name": "a", "containers": [1]}]'):
                with self.subTest(f=f.__name__, bad=bad):
                    self.assertIsInstance(f(bad), dict)


if __name__ == '__main__':
    import unittest
    unittest.main()
