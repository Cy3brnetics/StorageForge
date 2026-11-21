"""Portainer through its API (apiportainer.py): an access token in X-API-Key, a read-back from the user's role and its effective access
per environment, Docker environments read through Portainer's Docker proxy with GETs only, stacks without their variables, and the
containers compared with the SSH scan. Against the real client and apifake.py.

Where the samples come from: Portainer's Go sources (github.com/portainer/portainer, develop), fetched 2026-11-20: api/portainer.go
(User: Id, Username, Role 1 or 2; Endpoint: Id, Name, Type, URL, PublicURL, Status; Stack: Id, Name, Type, EndpointId, Env, Status),
api/http/handler/users/user_effective_access.go (endpointId, endpointName, roleId, roleName, accessLocation),
api/http/handler/system/version.go (ServerVersion, ServerEdition CE/EE). The proxied container list is Docker Engine's own
(Id, Names, Image, State, Status, Labels), as docs.docker.com documents GET /containers/json."""
import json

try:
    from test_apiconn import Base
except ImportError:      # run as tests.test_x from the project folder
    from tests.test_apiconn import Base
from storageforge_index import alerts, apiconn, apiguide, apiportainer, apiread, apiviews

TOKEN = 'ptr_Xq7w9ZbK2mN4pR6sT8vY0aC3dF5gH7jL9nQ1rS3uW5y='


def routes(role=2, edition='EE', access=None):
    return {
        '/users/me': {'Id': 5, 'Username': 'storageforge', 'Role': role, 'TokenIssueAt': 1, 'ThemeSettings': {}, 'UseCache': True},
        '/system/version': {'UpdateAvailable': False, 'LatestVersion': '2.33.0', 'ServerVersion': '2.33.0', 'VersionSupport': 'LTS', 'ServerEdition': edition, 'DatabaseVersion': '2.33.0'},
        '/users/5/effective-access': access if access is not None else [{'endpointId': 1, 'endpointName': 'local', 'roleId': 3, 'roleName': 'Read-only user', 'rolePriority': 4, 'accessLocation': 'user-endpoint'},
                                                                         {'endpointId': 2, 'endpointName': 'docker2', 'roleId': 3, 'roleName': 'Read-only user', 'rolePriority': 4, 'accessLocation': 'team-group'}],
        '/endpoints': [{'Id': 1, 'Name': 'local', 'Type': 1, 'ContainerEngine': 'docker', 'URL': 'unix:///var/run/docker.sock', 'GroupId': 1, 'PublicURL': '', 'Status': 1},
                       {'Id': 2, 'Name': 'docker2', 'Type': 2, 'ContainerEngine': 'docker', 'URL': 'tcp://10.9.2.2:9001', 'GroupId': 1, 'PublicURL': '10.9.2.2', 'Status': 1},
                       {'Id': 3, 'Name': 'k8s', 'Type': 6, 'URL': 'https://k8s:6443', 'Status': 1}],
        '/endpoints/1/docker/containers/json': [{'Id': 'aaa', 'Names': ['/nextcloud-app-1'], 'Image': 'nextcloud:29', 'State': 'running', 'Status': 'Up 3 days',
                                                 'Labels': {'com.docker.compose.project': 'nextcloud'}}],
        '/endpoints/2/docker/containers/json': [{'Id': 'bbb', 'Names': ['/grafana'], 'Image': 'grafana/grafana', 'State': 'exited', 'Status': 'Exited (1)', 'Labels': {}}],
        '/stacks': [{'Id': 1, 'Name': 'nextcloud', 'Type': 2, 'EndpointId': 1, 'EntryPoint': 'docker-compose.yml', 'Env': [{'name': 'DB_PASSWORD', 'value': 'STACK-SECRET-NEVER-KEPT'}], 'Status': 1}],
    }


class Read(Base):
    def setUp(self):
        super().setUp()
        self.fake.prefix, self.fake.wrap = '/api', False
        self.fake.routes.update(routes())
        self.conn.execute("INSERT INTO hosts (hostname, ssh_host, ip_address, ssh_user, inventory_json) VALUES ('docker2', 'docker2.lab', '10.9.2.2', 'scan', '{}')")
        row = apiconn.add(self.v, self.conn, 'portainer', 'portainer', self.fake.url, 'storageforge', TOKEN, 'gabe')
        self.row = apiconn.pin(self.conn, row['conn_id'], self.fake.fingerprint, 'gabe')

    def no_secret(self, *texts):
        for t in texts:
            self.assertNotIn(TOKEN, str(t))
        self.assertNotIn(TOKEN, self.stderr.getvalue())
        self.assertEqual(self.everywhere(TOKEN), [])
        self.assertEqual(self.everywhere('STACK-SECRET-NEVER-KEPT'), [], 'a stack variables are never kept')
        for r in self.fake.requests:
            self.assertNotIn(TOKEN, r['path'])
            self.assertEqual((r['method'], r['headers']['X-API-Key']), ('GET', TOKEN))
            self.assertNotIn('Authorization', r['headers'])

    def test_a_read_only_user_on_business_edition(self):
        got = apiread.read(self.db, self.conn, self.row)
        rb = got['readback']
        self.assertEqual(rb['verdict'], 'exact')
        self.assertTrue(any('no expiry date' in n for n in rb['notes']))
        self.assertEqual(got['counts'], {'platform': 1, 'environment': 3, 'container': 2, 'stack': 1})
        self.assertIn('k8s: only Docker environments are read', got['skipped'])
        objs = {(o['kind'], o['ref']): o for o in apiread.objects(self.conn, self.row['conn_id'])}
        self.assertEqual(objs[('container', '1/nextcloud-app-1')]['stack'], 'nextcloud')
        self.assertNotIn('Env', objs[('stack', '1/nextcloud')])
        self.assertEqual(apiconn.get(self.conn, self.row['conn_id'])['expiry']['state'], 'unknown', 'Portainer cannot say: a date given by a person is used instead')
        self.no_secret(got)

    def test_an_administrator_an_operator_or_community_edition_is_a_finding(self):
        self.fake.routes.update(routes(role=1))
        rb = apiread.read(self.db, self.conn, self.row)['readback']
        self.assertEqual((rb['verdict'], rb['admin']), ('over', True))
        self.assertEqual(alerts.problems(self.conn)['security-api-token:portainer'][4], 'crit')
        self.fake.routes.update(routes(access=[{'endpointId': 2, 'endpointName': 'docker2', 'roleName': 'Operator'}, {'endpointId': 1, 'endpointName': 'local', 'roleName': 'Environment administrator'}]))
        rb = apiread.read(self.db, self.conn, self.row)['readback']
        self.assertEqual(sorted((o['priv'], o['admin']) for o in rb['over']), [('Environment administrator', True), ('Operator', False)])
        self.fake.routes.update(routes(edition='CE'))
        self.fake.routes['/users/5/effective-access'] = (404, 'Not Found', {'message': 'not found'})
        rb = apiread.read(self.db, self.conn, self.row)['readback']
        self.assertEqual((rb['verdict'], rb['admin']), ('over', False))
        self.assertIn('Community Edition has no read-only role', rb['over'][0]['priv'])
        self.assertEqual(alerts.problems(self.conn)['security-api-token:portainer'][4], 'warn')
        apiconn.set_actions(self.conn, self.row['conn_id'], ['redeploy'])
        self.fake.routes.update(routes(access=[{'endpointId': 2, 'endpointName': 'docker2', 'roleName': 'Operator'}]))
        self.assertEqual(apiread.read(self.db, self.conn, apiconn.get(self.conn, self.row['conn_id']))['readback']['verdict'], 'exact')
        self.no_secret()

    def test_the_admin_user_is_refused_and_a_change_never_leaves(self):
        with self.assertRaisesRegex(apiconn.ConnError, 'administrator Portainer makes'):
            apiconn.add(self.v, self.conn, 'portainer', 'p2', self.fake.url, 'admin', TOKEN, 'gabe')
        with apiconn.open_client(self.db, self.conn, self.row) as c:
            with self.assertRaises(apiconn.ReadOnly):
                c.request('POST', '/endpoints/1/docker/containers/aaa/stop')
            with self.assertRaises(apiconn.ReadOnly):
                c.request('POST', '/stacks/1/redeploy', {}, action='redeploy')
        self.assertEqual(self.fake.requests, [])

    def test_containers_beside_the_scan(self):
        hid = self.conn.scalar("SELECT host_id FROM hosts WHERE hostname = 'docker2'")
        self.conn.execute("""INSERT INTO docker_hosts (host_id, engine, access, root_dir, containers_json, volumes_json, compose_json)
                             VALUES (:h, 'docker', 'direct', '/var/lib/docker', :c, '[]', '[]')""",
                          {'h': hid, 'c': json.dumps([{'name': 'grafana', 'state': 'running', 'mounts': [], 'labels': {}}])})
        apiread.read(self.db, self.conn, self.row)
        cmp = {c['host']: c for c in apiviews.compare_connection(self.conn, apiconn.get(self.conn, self.row['conn_id']))['containers']}
        self.assertEqual(cmp['docker2']['containers'][0]['differs'], [{'field': 'state', 'api': 'exited', 'ssh': 'running'}])
        self.assertFalse(cmp[None]['scanned'], 'the socket environment is the host Portainer runs on, which is not known here')
        self.assertEqual(apiviews.managed_by(self.conn, 'docker2')['grafana']['panel'], 'portainer')

    def test_the_guide_and_answers_that_are_not_what_the_sources_say(self):
        g = apiguide.guide('portainer')
        self.assertFalse(g['expiry']['allowed'])
        self.assertIn('Read-only user', g['least'])
        for f in (apiportainer.parse_me, apiportainer.parse_version, apiportainer.parse_access, apiportainer.parse_endpoints, apiportainer.parse_stacks, apiportainer.parse_containers):
            for bad in ('', 'x', 'null', '{}', '[null, {"Id": "x", "Name": 5}, {"Names": "notalist"}, {"Names": [3]}]'):
                with self.subTest(f=f.__name__, bad=bad):
                    self.assertIsInstance(f(bad), dict)


if __name__ == '__main__':
    import unittest
    unittest.main()
