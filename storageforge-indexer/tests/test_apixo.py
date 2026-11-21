"""Xen Orchestra through its REST API (apixo.py): the token in the authenticationToken cookie, the read-back from /users/me and its RBAC
privileges, the expiry of the token in use found in the list of the user's tokens without keeping any of it, and the read compared
with the SSH scan's mounts under /run/sr-mount. Against the real client and apifake.py's TLS server.

Where the samples come from: the REST API's OpenAPI examples in the Xen Orchestra sources, fetched 2026-11-20
(@xen-orchestra/rest-api/src/open-api/oa-examples): user.oa-example.mts (permission, name, id; authenticationTokens with id,
expiration in milliseconds), acl-privilege.oa-example.mts (action, effect, resource, roleId, id), vm.oa-example.mts (name_label,
power_state, CPUs.number, memory.size, $pool, $container, tags), host.oa-example.mts (name_label, address, power_state, memory, $pool),
pool.oa-example.mts (name_label, master), sr.oa-example.mts (name_label, SR_type, size, physical_usage, usage, shared, $pool, $container,
content_type), backup-job.oa-example.mts (name, mode, type, id) and backup-log.oa-example.mts (id, jobId, jobName, status, start,
end). The redirect of /users/me to /users/ID is what the RBAC page says ("me is a convenience alias: it is automatically redirected")."""
import json
import time

try:
    from test_apiconn import Base
except ImportError:      # run as tests.test_x from the project folder
    from tests.test_apiconn import Base
from storageforge_index import alerts, apiconn, apiguide, apiread, apiviews, apixo, notifications

TOKEN = 'UlTBEnFeL12XocK-7Qx-DKvOYbPn0eG7Z2oMvOniNjg'
OTHER = 'ktdlq-BX_GdS5N8MR0v7QIuoSymBw4Ys4EOxsOdqpnE'      # another token of the same user: a secret in the list, never kept
UID = '722d17b9-699b-49d2-8193-be1ac573d3de'
POOL, HOST1, HOST2 = 'b7569d99-30f8-178a-7d94-801de3e29b5b', 'b61a5c92-700e-4966-a13b-00633f03eea8', '438aca0f-429c-4ae6-accc-93c306e636a0'
SR_NFS, SR_LVM = 'c4284e12-37c9-7967-b9e8-83ef229c3e03', '8aa2fb4a-143e-c2bc-05d4-c68bbb101d41'
NOW = int(time.time())
GiB = 1 << 30
READS = [{'id': f'p{i}', 'resource': r, 'action': 'read', 'effect': 'allow', 'href': f'/rest/v0/acl-privileges/p{i}'} for i, r in enumerate(apixo.RESOURCES)]


def routes(privs=READS, permission='none'):
    return {
        '/users/me': (302, 'Found', '', {'Location': f'/rest/v0/users/{UID}'}),
        f'/users/{UID}': {'permission': permission, 'name': 'storageforge', 'id': UID, 'email': 'storageforge', 'groups': [], 'preferences': {}},
        '/users/me/acl-privileges': privs,
        '/users/me/authentication_tokens': [{'id': OTHER, 'expiration': (NOW + 3600) * 1000, 'href': 'x'}, {'id': TOKEN, 'expiration': (NOW + 150 * 86400) * 1000, 'href': 'y'}],
        '/pools': [{'id': POOL, 'name_label': 'XO Lab', 'master': HOST1, 'href': f'/rest/v0/pools/{POOL}'}],
        '/hosts': [{'id': HOST1, 'name_label': 'xcp1', 'address': '10.9.0.11', 'power_state': 'Running', '$pool': POOL, 'memory': {'usage': 3544047616, 'size': 34359738368}},
                   {'id': HOST2, 'name_label': 'xcp-unscanned', 'address': '10.9.0.12', 'power_state': 'Running', '$pool': POOL}],
        '/vms': [{'id': 'f07ab729-c0e8-721c-45ec-f11276377030', 'name_label': 'web', 'power_state': 'Running', '$pool': POOL, '$container': HOST1,
                  'memory': {'size': 4294967296, 'dynamic': [1, 2], 'static': [1, 2]}, 'CPUs': {'max': 2, 'number': 2}, 'tags': ['prod']},
                 {'id': '0fc14abc-ae7a-4209-79c4-d20ca1f0e567', 'name_label': 'FreeNAS', 'power_state': 'Halted', '$pool': POOL, '$container': POOL, 'memory': {'size': 2147483648}}],
        '/srs': [{'id': SR_NFS, 'uuid': SR_NFS, 'name_label': 'nfs-vms', 'SR_type': 'nfs', 'size': 1000 * GiB, 'physical_usage': 950 * GiB, 'usage': 980 * GiB, 'shared': True,
                  '$pool': POOL, '$container': POOL, 'content_type': 'user'},
                 {'id': SR_LVM, 'name_label': 'Local storage', 'SR_type': 'lvm', 'size': 70 * GiB, 'physical_usage': 10 * GiB, 'shared': False, '$pool': POOL, '$container': HOST1}],
        '/backup-jobs': [{'name': 'nightly', 'mode': 'delta', 'type': 'backup', 'id': 'd33f3dc1-92b4-469c-ad58-4c2a106a4721'}],
        '/backup-logs': [{'id': '1753776067468', 'jobId': 'd33f3dc1-92b4-469c-ad58-4c2a106a4721', 'jobName': 'nightly', 'status': 'success', 'start': (NOW - 2 * 86400) * 1000},
                         {'id': '1753776157641', 'jobId': 'd33f3dc1-92b4-469c-ad58-4c2a106a4721', 'jobName': 'nightly', 'status': 'failure', 'start': (NOW - 86400) * 1000,
                          'end': (NOW - 86000) * 1000}],
    }


class Read(Base):
    def setUp(self):
        super().setUp()
        self.fake.prefix, self.fake.wrap = '/rest/v0', False
        self.fake.routes.update(routes())
        row = apiconn.add(self.v, self.conn, 'xo', 'xo', self.fake.url, 'storageforge', TOKEN, 'gabe')
        self.row = apiconn.pin(self.conn, row['conn_id'], self.fake.fingerprint, 'gabe')

    def no_token_anywhere_xo(self, *texts):
        for secret in (TOKEN, OTHER):
            for t in texts:
                self.assertNotIn(secret, str(t))
            self.assertNotIn(secret, self.stderr.getvalue())
            self.assertEqual(self.everywhere(secret), [], 'neither the token nor the other token in its list is kept')
            for r in self.fake.requests:
                self.assertNotIn(secret, r['path'])
        self.assertTrue(all(r['headers'].get('Cookie') == f'authenticationToken={TOKEN}' for r in self.fake.requests))

    def test_a_read_with_a_read_only_role(self):
        got = apiread.read(self.db, self.conn, self.row)
        self.assertEqual(got['readback']['verdict'], 'exact')
        self.assertEqual(got['counts'], {'xo-pool': 1, 'xo-host': 2, 'vm': 2, 'sr': 2, 'backup-job': 1, 'backup-run': 1})
        paths = [r['path'] for r in self.fake.requests]
        self.assertIn(f'/rest/v0/users/{UID}', paths, 'the redirect of /users/me was followed on the same server')
        self.assertTrue(any(p.startswith('/rest/v0/vms?fields=') and '%24container' in p for p in paths))
        row = apiconn.get(self.conn, self.row['conn_id'])
        self.assertEqual((row['expiry']['source'], row['expiry']['state']), ('platform', 'ok'), 'the expiry of the token in use, not of the other one')
        objs = {(o['kind'], o['ref']): o for o in apiread.objects(self.conn, self.row['conn_id'])}
        self.assertEqual(objs[('backup-run', 'd33f3dc1-92b4-469c-ad58-4c2a106a4721')]['status'], 'failure', 'the latest run of each job')
        found = alerts.problems(self.conn)
        self.assertIn('api-xo-backup:xo', found)
        self.assertIn(f'api-xo-sr-full:xo:{SR_NFS}', found)
        self.assertTrue(all(r['method'] == 'GET' for r in self.fake.requests))
        self.no_token_anywhere_xo(got)

    def test_an_administrator_or_a_write_privilege_is_a_finding(self):
        self.fake.routes.update(routes(permission='admin'))
        rb = apiread.read(self.db, self.conn, self.row)['readback']
        self.assertEqual((rb['verdict'], rb['admin']), ('over', True))
        found = alerts.problems(self.conn)['security-api-token:xo']
        self.assertEqual(found[4], 'crit')
        self.assertFalse(notifications.ignorable(found[0], found[4]))
        self.fake.routes.update(routes(READS + [{'resource': 'vm', 'action': 'shutdown', 'effect': 'allow', 'selector': 'tags:qa'}]))
        rb = apiread.read(self.db, self.conn, self.row)['readback']
        self.assertEqual(([o['priv'] for o in rb['over']], rb['admin']), (['vm:shutdown'], False))
        self.fake.routes.update(routes(READS + [{'resource': 'acl-privilege', 'action': 'create', 'effect': 'allow'}]))
        self.assertTrue(apiread.read(self.db, self.conn, self.row)['readback']['admin'])
        self.fake.routes.update(routes(READS + [{'resource': 'vm', 'action': 'shutdown', 'effect': 'deny'}, {'resource': 'user', 'action': 'read', 'effect': 'allow'}]))
        rb = apiread.read(self.db, self.conn, self.row)['readback']
        self.assertEqual((rb['verdict'], [e['priv'] for e in rb['extra_read']]), ('exact', ['user:read']), 'a deny changes nothing; reading users is listed, not a finding')
        apiconn.set_actions(self.conn, self.row['conn_id'], ['snapshot'])
        self.fake.routes.update(routes(READS + [{'resource': 'vm', 'action': 'snapshot', 'effect': 'allow', 'selector': 'tags: storageforge'}]))
        self.assertEqual(apiread.read(self.db, self.conn, apiconn.get(self.conn, self.row['conn_id']))['readback']['verdict'], 'exact')
        self.no_token_anywhere_xo()

    def test_a_role_without_backup_logs_skips_them_and_says_what_to_add(self):
        self.fake.routes.update(routes([p for p in READS if p['resource'] != 'backup-log']))
        got = apiread.read(self.db, self.conn, self.row)
        self.assertEqual([s['feature'] for s in got['readback']['short']], ['backup-logs'])
        self.assertEqual(got['readback']['short'][0]['add'], 'read on backup-log in the StorageForge role')
        self.assertNotIn('backup-run', got['counts'])

    def test_a_redirect_to_another_server_is_not_followed_and_admin_at_install_is_refused(self):
        self.fake.routes['/users/me'] = (302, 'Found', '', {'Location': 'https://evil.example/rest/v0/users/x'})
        with self.assertRaisesRegex(apiconn.ApiError, 'another server'):
            apiread.read(self.db, self.conn, self.row)
        self.fake.routes['/users/me'] = (302, 'Found', '', {'Location': '/admin/secret'})
        with self.assertRaisesRegex(apiconn.ApiError, 'outside its API'):
            apiread.read(self.db, self.conn, self.row)
        self.assertEqual(len([r for r in self.fake.requests if 'evil' in r['headers'].get('Host', '')]), 0)
        with self.assertRaisesRegex(apiconn.ConnError, 'administrator Xen Orchestra makes'):
            apiconn.add(self.v, self.conn, 'xo', 'xo2', self.fake.url, 'admin@admin.net', TOKEN, 'gabe')
        self.no_token_anywhere_xo()

    def test_srs_beside_the_mounts_the_scan_read_and_vms_on_the_map(self):
        self.conn.execute("INSERT INTO hosts (hostname, ssh_host, ip_address, ssh_user, inventory_json) VALUES ('xcp1', 'xcp1.lab', '10.9.0.11', 'scan', '{}')")
        hid = self.conn.scalar("SELECT host_id FROM hosts WHERE hostname = 'xcp1'")
        for mp, total in ((f'/run/sr-mount/{SR_NFS}', 1000 * GiB), ('/run/sr-mount/0e1f2a3b-4c5d-6e7f-8091-a2b3c4d5e6f7', 10 * GiB)):
            self.conn.execute("""INSERT INTO mounts (host_id, mount_point, source, filesystem_type, total_bytes, used_bytes, scan_state)
                                 VALUES (:h, :m, 'nas:/vms', 'nfs4', :t, 0, 'indexed')""", {'h': hid, 'm': mp, 't': total})
        apiread.read(self.db, self.conn, self.row)
        cmp = {c['sr']: c for c in apiviews.compare_connection(self.conn, apiconn.get(self.conn, self.row['conn_id']))['srs']}
        self.assertEqual((cmp[SR_NFS]['seen_by'], cmp[SR_NFS]['mounted_on']), (['api', 'ssh'], ['xcp1']))
        self.assertEqual(cmp[SR_LVM]['seen_by'], ['api'])
        self.assertEqual(cmp['0e1f2a3b-4c5d-6e7f-8091-a2b3c4d5e6f7']['seen_by'], ['ssh'])
        g = apiviews.map_extra(self.conn, {'nodes': [{'id': 'host:xcp1', 'kind': 'Host', 'label': 'xcp1', 'layer': 'storage', 'props': {}},
                                                     {'id': f'mnt:xcp1:/run/sr-mount/{SR_NFS}', 'kind': 'MountPoint', 'label': f'/run/sr-mount/{SR_NFS}', 'host': 'xcp1', 'layer': 'storage', 'props': {}}],
                                           'edges': []}, ('storage', 'workloads'))
        nodes = {n['id']: n for n in g['nodes']}
        web = nodes['api:xo:vm:f07ab729-c0e8-721c-45ec-f11276377030']
        self.assertEqual((web['kind'], web['host'], web['props']['state']), ('VM', 'xcp1', 'running'))
        self.assertIn({'src': f'api:xo:sr:{SR_NFS}', 'dst': f'mnt:xcp1:/run/sr-mount/{SR_NFS}', 'rel': 'STORED_ON',
                       'props': {'confidence': 'certain', 'evidence': {'source': 'Xen Orchestra API: the SR mounted there'}}}, g['edges'])
        listing = apiviews.annotate_workloads(self.conn, {'workloads': []})
        self.assertEqual(sorted((w['name'], w['host'], w['runtime']) for w in listing['workloads']), [('FreeNAS', None, 'xen'), ('web', 'xcp1', 'xen')])

    def test_the_guide_and_answers_that_are_not_what_the_examples_say(self):
        g = apiguide.guide('xo', scope=POOL)
        runs = [r for s in g['steps'] for r in s['run']]
        self.assertTrue(all('"action": "read"' in r for r in runs if 'acl-privileges' in r and '-d' in r))
        self.assertTrue(any(f'$pool: {POOL}' in r for r in runs))
        self.assertFalse(any('Administrator' in r for r in runs))
        with self.assertRaises(apiguide.GuideError):
            apiguide.guide('xo', scope='not-a-uuid')
        for f in (apixo.parse_me, apixo.parse_privileges, apixo.parse_token_expiry, apixo.parse_pools, apixo.parse_hosts, apixo.parse_vms, apixo.parse_srs,
                  apixo.parse_backup_jobs, apixo.parse_backup_logs):
            for bad in ('', 'x', 'null', '{}', '[null, 3, {"id": ["x"]}, {"id": "a b"}]'):
                with self.subTest(f=f.__name__, bad=bad):
                    self.assertIsInstance(f(bad), dict)
        self.assertEqual(apixo.parse_token_expiry(json.dumps([{'id': 'a', 'expiration': 5000}]), 'b'), {'expire': None, 'found': False})


if __name__ == '__main__':
    import unittest
    unittest.main()
