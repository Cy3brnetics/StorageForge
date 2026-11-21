"""Pangolin through its Integration API (apipangolin.py): a key sent as Bearer KEYID.SECRET, the read-back from the key's own actions,
sites, resources and domains read page by page, and what is published fed to the exposure view, where the SSH scan saw a running
Newt and could not say what it carries (tunnels.py, inframeasure). Against the real client and apifake.py.

Where the samples come from: Pangolin's sources (github.com/fosrl/pangolin, main), fetched 2026-11-20, and its OpenAPI document
(api.pangolin.net/v1/openapi.json): every answer is {data, success, error, message, status}; listResources.ts maps each resource to
resourceId, niceId, name, ssl, fullDomain, passwordId, sso, pincodeId, whitelist, mtls, proxyPort, wildcard, mode, enabled, domainId,
headerAuthId, health, targets [{targetId, resourceId, siteId, ip, port, enabled, ...}], sites [{siteId, siteName, siteNiceId, online}],
with pagination {total, pageSize, page}; listSites.ts gives siteId, niceId, name, type, online, address, newtVersion, exitNodeName; the
OpenAPI schema of /org/{orgId}/domains gives domainId, baseDomain, verified, type, failed, tries, configManaged, certResolver,
preferWildcardCert, errorMessage; of /org/{orgId}/api-key/{apiKeyId}/actions, actions [{actionId}]. verifyApiKey.ts splits the Bearer
value at the dot into the key's ID and its secret."""
import json
import time

try:
    from test_apiconn import Base
except ImportError:      # run as tests.test_x from the project folder
    from tests.test_apiconn import Base
from storageforge_index import alerts, apiconn, apiguide, apipangolin, apiread, apiviews, exposure, infragraph, inframeasure

KEYID = 'k3y9ab12cd34ef56'
SECRET = 'q7Wm2Xp9Lr4Tz8Vb6Nc1Hd5Jf3Gs0Ka'
READ = ['listSites', 'listResources', 'listTargets', 'listOrgDomains', 'listApiKeyActions']


def wrap(data):
    return {'data': data, 'success': True, 'error': False, 'message': 'ok', 'status': 200}


def routes(actions=READ):
    return {
        f'/org/home/api-key/{KEYID}/actions': wrap({'actions': [{'actionId': a} for a in actions], 'pagination': {'total': len(actions), 'limit': 1000, 'offset': 0}}),
        '/org/home/sites': wrap({'sites': [{'siteId': 1, 'niceId': 'nas1', 'name': 'nas1', 'type': 'newt', 'online': True, 'address': '100.89.128.4', 'newtVersion': '1.6.0', 'exitNodeName': 'main'},
                                           {'siteId': 2, 'niceId': 'cabin', 'name': 'cabin', 'type': 'newt', 'online': False},
                                           {'siteId': 3, 'niceId': 'local', 'name': 'local', 'type': 'local', 'online': True}],
                                 'pagination': {'total': 3, 'pageSize': 1000, 'page': 1}}),
        '/org/home/resources': wrap({'resources': [
            {'resourceId': 10, 'niceId': 'jellyfin', 'name': 'Jellyfin', 'ssl': True, 'fullDomain': 'media.example.com', 'passwordId': None, 'sso': True, 'pincodeId': None,
             'whitelist': False, 'mtls': False, 'proxyPort': None, 'wildcard': False, 'mode': 'http', 'enabled': True, 'domainId': 'd1', 'headerAuthId': None, 'health': 'healthy',
             'targets': [{'targetId': 100, 'resourceId': 10, 'siteId': 1, 'ip': 'localhost', 'port': 8096, 'enabled': True}], 'sites': [{'siteId': 1, 'siteName': 'nas1', 'siteNiceId': 'nas1', 'online': True}], 'labels': []},
            {'resourceId': 11, 'niceId': 'files', 'name': 'Files', 'ssl': True, 'fullDomain': 'files.example.com', 'passwordId': None, 'sso': False, 'pincodeId': None,
             'whitelist': False, 'mtls': False, 'mode': 'http', 'enabled': True, 'headerAuthId': None,
             'targets': [{'targetId': 101, 'resourceId': 11, 'siteId': 1, 'ip': '192.168.1.20', 'port': 80, 'enabled': True}], 'sites': []},
            {'resourceId': 12, 'niceId': 'pin', 'name': 'Pinned', 'ssl': True, 'fullDomain': 'pin.example.com', 'passwordId': None, 'sso': False, 'pincodeId': 4,
             'whitelist': True, 'mtls': False, 'mode': 'http', 'enabled': True, 'headerAuthId': None, 'targets': [{'targetId': 102, 'siteId': 2, 'ip': 'localhost', 'port': 3000, 'enabled': True}]}],
            'pagination': {'total': 3, 'pageSize': 1000, 'page': 1}}),
        '/org/home/domains': wrap({'domains': [{'domainId': 'd1', 'baseDomain': 'example.com', 'verified': True, 'type': 'ns', 'failed': False, 'tries': 0, 'configManaged': False,
                                                'certResolver': None, 'preferWildcardCert': None, 'errorMessage': None}], 'pagination': {'total': 1, 'limit': 1000, 'offset': 0}}),
    }


class Read(Base):
    def setUp(self):
        super().setUp()
        self.fake.prefix, self.fake.wrap = '/v1', False
        self.fake.routes.update(routes())
        self.conn.execute("INSERT INTO hosts (hostname, ssh_host, ip_address, ssh_user, inventory_json) VALUES ('nas1', 'nas1.lab', '10.9.4.4', 'scan', '{}')")
        row = apiconn.add(self.v, self.conn, 'pangolin', 'pangolin', self.fake.url, f'{KEYID}@home', SECRET, 'gabe')
        self.row = apiconn.pin(self.conn, row['conn_id'], self.fake.fingerprint, 'gabe')

    def no_secret(self, *texts):
        for t in texts:
            self.assertNotIn(SECRET, str(t))
        self.assertNotIn(SECRET, self.stderr.getvalue())
        self.assertEqual(self.everywhere(SECRET), [])
        for r in self.fake.requests:
            self.assertNotIn(SECRET, r['path'])
            self.assertEqual((r['method'], r['headers']['Authorization']), ('GET', f'Bearer {KEYID}.{SECRET}'))

    def newt_on_nas1(self):
        infra = {'access': {'tunnels': [{'tool': 'newt', 'server': 'its Pangolin server', 'published': [], 'remote': True, 'running': True}]}, 'listeners': []}
        self.conn.execute("INSERT INTO security_measurements (host, kind, measured_at, via, data_json) VALUES ('nas1', 'infra', :t, 'deploy', :d)",
                          {'t': int(time.time()), 'd': json.dumps(infra)})

    def test_a_read_with_a_list_only_key(self):
        got = apiread.read(self.db, self.conn, self.row)
        self.assertEqual(got['readback']['verdict'], 'exact')
        self.assertEqual(got['counts'], {'site': 3, 'resource': 3, 'domain': 1})
        objs = {(o['kind'], o['ref']): o for o in apiread.objects(self.conn, self.row['conn_id'])}
        self.assertEqual(objs[('resource', '10')]['login'], ['Pangolin sign-in (SSO)'])
        self.assertEqual(objs[('resource', '12')]['login'], ['a PIN', 'an email whitelist'])
        found = alerts.problems(self.conn)
        self.assertIn('files.example.com', found['api-pangolin-open:pangolin'][3])
        self.assertIn('cabin', found['api-pangolin-site:pangolin'][3])
        self.no_secret(got)

    def test_a_key_that_can_change_pangolin_or_read_secrets_is_a_finding(self):
        self.fake.routes.update(routes(READ + ['createResource', 'listUsers']))
        rb = apiread.read(self.db, self.conn, self.row)['readback']
        self.assertEqual(([o['priv'] for o in rb['over']], rb['admin'], [e['priv'] for e in rb['extra_read']]), (['createResource'], False, ['listUsers']))
        self.fake.routes.update(routes(READ + ['setApiKeyActions', 'getVirtualApiKey']))
        rb = apiread.read(self.db, self.conn, self.row)['readback']
        self.assertEqual((rb['admin'], sorted(o['priv'] for o in rb['over'])), (True, ['getVirtualApiKey', 'setApiKeyActions']))
        self.assertEqual(alerts.problems(self.conn)['security-api-token:pangolin'][4], 'crit')
        self.no_secret()

    def test_a_key_without_list_api_key_actions_cannot_be_checked_and_says_so(self):
        self.fake.routes[f'/org/home/api-key/{KEYID}/actions'] = (403, 'Forbidden', wrap(None))
        rb = apiread.read(self.db, self.conn, self.row)['readback']
        self.assertEqual(rb['verdict'], 'exact')
        self.assertTrue(any('give it listApiKeyActions' in n for n in rb['notes']))
        self.fake.routes['/org/home/domains'] = (403, 'Forbidden', wrap(None))
        got = apiread.read(self.db, self.conn, self.row)
        self.assertEqual([s['feature'] for s in got['readback']['short']], ['domains'])
        self.assertIn('domains: the key lacks listOrgDomains', got['skipped'])

    def test_what_newt_carries_reaches_the_exposure_view_with_its_login(self):
        self.newt_on_nas1()
        before = exposure.tunnel_items(inframeasure.reading(self.conn, 'nas1'))
        self.assertEqual(before[0]['level'], 'unknown', 'before the API read, the scan only knows Newt runs')
        apiread.read(self.db, self.conn, self.row)
        items = exposure.tunnel_items(inframeasure.reading(self.conn, 'nas1'))
        by = {i['public']: i for i in items}
        self.assertEqual(sorted(by), ['https://files.example.com', 'https://media.example.com'], 'the cabin site is no scanned host')
        self.assertEqual((by['https://media.example.com']['level'], by['https://media.example.com']['login'], by['https://media.example.com']['target_port']),
                         ('any', 'Pangolin sign-in (SSO)', 8096))
        self.assertEqual(by['https://files.example.com']['login'], 'none')
        self.assertEqual(by['https://files.example.com']['target_host'], '192.168.1.20', 'carried to another machine, not to nas1 itself')
        stored = self.conn.scalar("SELECT data_json FROM security_measurements WHERE host = 'nas1'")
        self.assertEqual(json.loads(stored)['access']['tunnels'][0]['published'], [], 'nothing stored changes: the reading is filled when asked')
        cmp = {c['site']: c for c in apiviews.compare_connection(self.conn, apiconn.get(self.conn, self.row['conn_id']))['sites']}
        self.assertEqual((cmp['nas1']['host'], cmp['nas1']['seen_by']), ('nas1', ['api', 'ssh']))
        self.assertEqual(cmp['cabin']['why'], 'no scanned host has this site name')
        g = apiviews.map_extra(self.conn, {'nodes': [{'id': 'host:nas1', 'kind': 'Host', 'label': 'nas1', 'layer': 'access', 'props': {}},
                                                     {'id': 'tunnel:nas1:newt', 'kind': 'Tunnel', 'label': 'Pangolin', 'layer': 'access', 'host': 'nas1', 'props': {}}], 'edges': []}, ('access',))
        route = next(n for n in g['nodes'] if n['id'] == 'api:pangolin:res:10')
        self.assertEqual((route['kind'], route['props']['login']), ('ProxyRoute', 'Pangolin sign-in (SSO)'))
        self.assertTrue(any(e['src'] == 'api:pangolin:res:10' and e['dst'] == 'tunnel:nas1:newt' for e in g['edges']))
        self.assertIsInstance(infragraph, object)

    def test_the_guide_and_answers_that_are_not_what_the_sources_say(self):
        g = apiguide.guide('pangolin', scope='home')
        self.assertEqual(g['role'], ', '.join(READ))
        self.assertIn('KEYID@home', json.dumps(g['steps']))
        with self.assertRaises(apiguide.GuideError):
            apiguide.action_steps('pangolin', 'anything')
        with self.assertRaises(apiconn.ConnError):
            apiconn.add(self.v, self.conn, 'pangolin', 'p2', self.fake.url, KEYID, SECRET, 'gabe')      # no organization
        for f in (apipangolin.parse_actions, apipangolin.parse_sites, apipangolin.parse_resources, apipangolin.parse_domains):
            for bad in ('', 'x', 'null', '{"data": 3}', '{"data": {"sites": [null, {"siteId": "x"}], "resources": [{"resourceId": 1, "targets": "no"}], "actions": [{"actionId": 5}]}}'):
                with self.subTest(f=f.__name__, bad=bad):
                    self.assertIsInstance(f(bad), dict)


if __name__ == '__main__':
    import unittest
    unittest.main()
