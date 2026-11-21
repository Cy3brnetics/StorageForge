"""TrueNAS through its middleware API (apitruenas.py, apiconn.WsClient): JSON-RPC 2.0 over a WebSocket on the pinned TLS connection,
the key sent once in auth.login_ex, the read-back from auth.me and api_key.my_keys, and what the reader takes, compared with the SSH
scan's `zpool status`. Against apifake.py, a real TLS server that speaks RFC 6455 and answers each call from a table.

Where the samples come from: the TrueNAS API reference for v25.10.5 (api.truenas.com/v25.10, fetched 2026-11-20), which gives each
method's return fields and types and no whole answers, so each sample is built from those fields:
    auth.login_ex          AuthRespSuccess {response_type: "SUCCESS", user_info}, AuthRespAuthErr {response_type: "AUTH_ERR"}
    auth.me                pw_name, pw_uid, ..., privilege (an object; rbac.html: "including the full list of roles"), account_attributes
    api_key.my_keys        id, name, username, user_identifier, keyhash, created_at, expires_at (date-time or null), local, revoked, revoked_reason
    system.info            version, hostname, uptime_seconds, ...
    pool.query             id, name, guid, status, path, healthy, status_detail, size, allocated, free, ...
    pool.dataset.query     id, type, name, pool, encrypted, used/available ({parsed, rawvalue, value, source}), mountpoint
    pool.snapshottask.query  id, dataset, recursive, lifetime_value, lifetime_unit, enabled, state
    replication.query      id, name, direction, transport, ssh_credentials, source_datasets, target_dataset, enabled, state
    sharing.smb.query      id, name, path, enabled, readonly, guestok; sharing.nfs.query id, path, networks, hosts, ro, enabled
    app.query              name, id, state, upgrade_available, human_version, version, custom_app, active_workloads {containers, container_details}
    alert.list             uuid, klass, level, formatted, dismissed, datetime
The way a date-time crosses the wire ({"$date": ms}) is the middleware's JSON encoder, as midclt prints it; an ISO string is read too."""
import json
import time

try:
    from test_apiconn import Base
except ImportError:      # run as tests.test_x from the project folder
    from tests.test_apiconn import Base
from apifake import RpcFail
from storageforge_index import alerts, apiconn, apiguide, apiread, apitruenas, apiviews, notifications

KEY = '7-Zk3qPw9xLm2Vb8Nc4Rt6Yh1Ju5Fd0Sa7Ge3Wq9Er2Ty6Ui8Op4As1Df5Gh7Jk'
NOW = int(time.time())
GiB = 1 << 30
READ_ROLES = ['READONLY_ADMIN', 'POOL_READ', 'DATASET_READ', 'SNAPSHOT_TASK_READ', 'REPLICATION_TASK_READ', 'SHARING_READ', 'SHARING_SMB_READ',
              'SHARING_NFS_READ', 'APPS_READ', 'ACCOUNT_READ', 'ALERT_LIST_READ']


def me(roles, web_shell=False, user='storageforge'):
    return {'pw_name': user, 'pw_gecos': 'StorageForge: reads through the API', 'pw_dir': '/var/empty', 'pw_shell': '/usr/sbin/nologin', 'pw_uid': 3001, 'pw_gid': 3001,
            'grouplist': None, 'sid': None, 'source': 'LOCAL', 'local': True, 'attributes': {}, 'two_factor_config': {},
            'privilege': {'roles': {'$set': roles}, 'web_shell': web_shell}, 'account_attributes': ['LOCAL']}


def methods(roles=READ_ROLES):
    return {
        'auth.login_ex': lambda p: {'response_type': 'SUCCESS', 'user_info': me(roles)} if p[0].get('api_key') == KEY and p[0].get('username') == 'storageforge'
        else {'response_type': 'AUTH_ERR'},
        'auth.me': me(roles),
        'api_key.my_keys': [{'id': 7, 'name': 'storageforge', 'username': 'storageforge', 'user_identifier': 3001, 'keyhash': '********', 'created_at': {'$date': (NOW - 86400) * 1000},
                             'expires_at': {'$date': (NOW + 20 * 86400) * 1000}, 'local': False, 'revoked': False, 'revoked_reason': None},
                            {'id': 9, 'name': 'old', 'username': 'storageforge', 'user_identifier': 3001, 'keyhash': '********', 'created_at': {'$date': 1},
                             'expires_at': None, 'local': False, 'revoked': True, 'revoked_reason': 'sent over HTTP'}],
        'system.info': {'version': '25.10.5', 'hostname': 'nas1', 'uptime_seconds': 86400.5, 'physmem': 34359738368},
        'pool.query': [{'id': 1, 'name': 'tank', 'guid': '1234', 'status': 'DEGRADED', 'path': '/mnt/tank', 'healthy': False, 'warning': False,
                        'status_detail': 'One or more devices has been removed', 'size': 8000 * GiB, 'allocated': 3000 * GiB, 'free': 5000 * GiB, 'topology': {}},
                       {'id': 2, 'name': 'fast', 'guid': '5678', 'status': 'ONLINE', 'path': '/mnt/fast', 'healthy': True, 'size': 1000 * GiB, 'allocated': 10 * GiB, 'free': 990 * GiB}],
        'pool.dataset.query': [{'id': 'tank/media', 'type': 'FILESYSTEM', 'name': 'tank/media', 'pool': 'tank', 'encrypted': False, 'mountpoint': '/mnt/tank/media',
                                'used': {'parsed': 2000 * GiB, 'rawvalue': str(2000 * GiB), 'value': '1.95T', 'source': 'NONE'},
                                'available': {'parsed': 5000 * GiB, 'rawvalue': str(5000 * GiB), 'value': '4.88T', 'source': 'NONE'}, 'children': []},
                               {'id': 'tank/vm', 'type': 'VOLUME', 'name': 'tank/vm', 'pool': 'tank', 'encrypted': True, 'used': {'parsed': 50 * GiB}}],
        'pool.snapshottask.query': [{'id': 3, 'dataset': 'tank/media', 'recursive': True, 'lifetime_value': 2, 'lifetime_unit': 'WEEK', 'enabled': True,
                                     'state': {'state': 'FINISHED', 'datetime': {'$date': (NOW - 3600) * 1000}}}],
        'replication.query': [{'id': 4, 'name': 'media to backup', 'direction': 'PUSH', 'transport': 'SSH', 'source_datasets': ['tank/media'], 'target_dataset': 'backup/media',
                               'enabled': True, 'ssh_credentials': {'id': 1, 'name': 'backup', 'attributes': {'private_key': 'REDACTED-BUT-DROPPED-ANYWAY'}},
                               'state': {'state': 'ERROR', 'datetime': '2026-11-20T03:00:00Z', 'error': 'ssh: connect to host backup port 22: No route to host'}}],
        'sharing.smb.query': [{'id': 1, 'name': 'media', 'path': '/mnt/tank/media', 'enabled': True, 'readonly': False, 'guestok': False}],
        'sharing.nfs.query': [{'id': 1, 'path': '/mnt/tank/media', 'networks': ['192.168.1.0/24'], 'hosts': [], 'ro': True, 'enabled': True}],
        'app.query': [{'name': 'jellyfin', 'id': 'jellyfin', 'state': 'RUNNING', 'upgrade_available': True, 'human_version': '10.10.7_1.2.3', 'version': '1.2.3', 'custom_app': False,
                       'active_workloads': {'containers': 1, 'used_ports': [], 'container_details': [{'id': 'abc', 'service_name': 'jellyfin', 'image': 'jellyfin/jellyfin:10.10.7', 'state': 'running'}]}}],
        'alert.list': [{'uuid': 'a1', 'klass': 'ZpoolCapacityWarning', 'level': 'CRITICAL', 'formatted': 'Pool tank state is DEGRADED', 'dismissed': False, 'datetime': {'$date': NOW * 1000}},
                       {'uuid': 'a2', 'klass': 'Update', 'level': 'INFO', 'formatted': 'Update available', 'dismissed': False}],
    }


class Read(Base):
    def setUp(self):
        super().setUp()
        self.fake.prefix, self.fake.wrap = '/api/current', False
        self.fake.methods.update(methods())
        row = apiconn.add(self.v, self.conn, 'truenas', 'nas', self.fake.url, 'storageforge', KEY, 'gabe')
        self.row = apiconn.pin(self.conn, row['conn_id'], self.fake.fingerprint, 'gabe')

    def no_key_anywhere(self, *texts):
        for t in texts:
            self.assertNotIn(KEY, str(t))
        self.assertNotIn(KEY, self.stderr.getvalue())
        self.assertEqual(self.everywhere(KEY), [])
        self.assertEqual(self.everywhere('REDACTED-BUT-DROPPED-ANYWAY'), [], 'replication credentials are never kept')
        for r in self.fake.requests:
            self.assertNotIn(KEY, r['path'])
            self.assertNotIn(KEY, json.dumps(r['headers']))
        sent = [c for c in self.fake.calls if KEY in json.dumps(c)]
        self.assertTrue(all(c['method'] == 'auth.login_ex' for c in sent), 'the key is in the login call and nowhere else')

    def test_a_read_through_the_websocket(self):
        self.fake.notify_first = True               # an event before each answer is skipped, not taken for the answer
        got = apiread.read(self.db, self.conn, self.row)
        rb = got['readback']
        self.assertEqual((rb['verdict'], rb['admin']), ('exact', False))
        self.assertEqual(got['counts'], {'platform': 1, 'pool': 2, 'dataset': 2, 'snapshot-task': 1, 'replication': 1, 'share': 2, 'app': 1, 'alert': 2})
        self.assertEqual(self.fake.calls[0]['method'], 'auth.login_ex')
        self.assertEqual(self.fake.calls[0]['params'][0]['mechanism'], 'API_KEY_PLAIN')
        self.assertEqual(len(self.fake.requests), 1, 'one WebSocket for the whole read')
        objs = {(o['kind'], o['ref']): o for o in apiread.objects(self.conn, self.row['conn_id'])}
        self.assertEqual(objs[('dataset', 'tank/media')]['used'], 2000 * GiB)
        self.assertEqual(objs[('replication', '4')]['last']['state'], 'ERROR')
        self.assertNotIn('ssh_credentials', objs[('replication', '4')])
        row = apiconn.get(self.conn, self.row['conn_id'])
        self.assertEqual((row['expiry']['state'], row['expiry']['source']), ('soon', 'platform'), 'the expiry of key 7, not of the revoked key 9')
        found = alerts.problems(self.conn)
        for key in ('api-truenas-pool:nas:tank', 'api-truenas-task:nas:replication:4', 'api-truenas-alerts:nas', 'api-token-expiry:nas'):
            self.assertIn(key, found)
        self.assertEqual(found['api-truenas-pool:nas:tank'][4], 'crit')
        self.no_key_anywhere(got)

    def test_a_full_admin_key_or_the_web_shell_is_a_finding_that_cannot_be_muted(self):
        self.fake.methods['auth.me'] = me(READ_ROLES + ['FULL_ADMIN', 'ACCOUNT_WRITE'])
        rb = apiread.read(self.db, self.conn, self.row)['readback']
        self.assertEqual((rb['verdict'], rb['admin']), ('over', True))
        found = alerts.problems(self.conn)['security-api-token:nas']
        self.assertEqual(found[4], 'crit')
        self.assertFalse(notifications.ignorable(found[0], found[4]))
        self.fake.methods['auth.me'] = me(READ_ROLES, web_shell=True)
        rb = apiread.read(self.db, self.conn, self.row)['readback']
        self.assertEqual([o['priv'] for o in rb['over']], ['web shell'])
        self.fake.methods['auth.me'] = me(READ_ROLES + ['SHARING_ADMIN', 'DATASET_WRITE'])
        rb = apiread.read(self.db, self.conn, self.row)['readback']
        self.assertEqual((rb['verdict'], rb['admin']), ('over', False))
        self.fake.methods['auth.me'] = me(READ_ROLES)                      # narrowed on TrueNAS: the finding leaves
        apiread.read(self.db, self.conn, self.row)
        self.assertNotIn('security-api-token:nas', alerts.problems(self.conn))
        self.no_key_anywhere()

    def test_replication_admin_is_what_the_snapshot_action_allows_and_a_short_key_skips_its_features(self):
        apiconn.set_actions(self.conn, self.row['conn_id'], ['snapshot'])
        self.fake.methods['auth.me'] = me(READ_ROLES + apitruenas.REPLICATION_ADMIN)
        rb = apiread.read(self.db, self.conn, apiconn.get(self.conn, self.row['conn_id']))['readback']
        self.assertEqual(rb['verdict'], 'exact')
        self.fake.methods['auth.me'] = me(['POOL_READ', 'DATASET_READ'])
        got = apiread.read(self.db, self.conn, apiconn.get(self.conn, self.row['conn_id']))
        self.assertEqual(sorted(s['feature'] for s in got['readback']['short']), ['apps', 'replication', 'shares', 'snapshot-tasks'])
        self.assertNotIn('app', got['counts'])
        self.assertIn('apps: the key lacks APPS_READ', got['skipped'])

    def test_a_key_truenas_refuses_fails_the_read_and_a_change_is_refused_before_it_is_sent(self):
        self.fake.methods['auth.login_ex'] = {'response_type': 'AUTH_ERR'}
        with self.assertRaisesRegex(apiconn.Refused, 'wrong, or the key was revoked'):
            apiread.read(self.db, self.conn, self.row)
        self.assertEqual(apiconn.get(self.conn, self.row['conn_id'])['state'], 'failed')
        self.fake.methods.update(methods())
        self.fake.calls.clear()
        with apiconn.open_client(self.db, self.conn, apiconn.get(self.conn, self.row['conn_id'])) as c:
            with self.assertRaises(apiconn.ReadOnly):
                c.call('pool.dataset.delete', 'tank/media')
            with self.assertRaises(apiconn.ReadOnly):
                c.call('zfs.snapshot.create', {'dataset': 'tank', 'name': 'x'}, action='snapshot')
            self.fake.methods['pool.query'] = RpcFail(-32001, 'Not authorized', 'EACCES')
            with self.assertRaises(apiconn.Refused):
                c.call('pool.query')
        self.assertNotIn('pool.dataset.delete', [x['method'] for x in self.fake.calls])
        self.no_key_anywhere()

    def test_root_and_the_admin_accounts_are_refused(self):
        for user in ('root', 'truenas_admin', 'admin'):
            with self.subTest(user), self.assertRaisesRegex(apiconn.ConnError, 'FULL_ADMIN'):
                apiconn.add(self.v, self.conn, 'truenas', f'x{user[:3]}', self.fake.url, user, KEY, 'gabe')
        self.assertEqual(apiconn.normalize_url('nas.lab', 'truenas'), 'https://nas.lab:443')
        self.assertEqual(apiconn.normalize_url('https://nas.lab/api/current', 'truenas'), 'https://nas.lab:443')

    def test_pools_beside_zpool_status_and_on_the_map(self):
        zpool = '  pool: tank\n state: DEGRADED\nconfig:\n\n\tNAME        STATE     READ WRITE CKSUM\n\ttank        DEGRADED     0     0     0\n\n  pool: boot-pool\n state: ONLINE\n'
        self.conn.execute("INSERT INTO hosts (hostname, ssh_host, ip_address, ssh_user, inventory_json) VALUES ('nas1', 'nas1.lab', '10.9.9.9', 'scan', :i)",
                          {'i': json.dumps({'zpool_status': zpool})})
        self.conn.execute("UPDATE platform_connections SET host = 'nas1' WHERE conn_id = :i", {'i': self.row['conn_id']})
        apiread.read(self.db, self.conn, self.row)
        row = apiconn.get(self.conn, self.row['conn_id'])
        cmp = {c['pool']: c for c in apiviews.compare_connection(self.conn, row)['pools']}
        self.assertEqual((cmp['tank']['seen_by'], cmp['tank']['differs']), (['api', 'ssh'], []))
        self.assertEqual(cmp['fast']['seen_by'], ['api'])
        self.assertEqual(cmp['boot-pool']['seen_by'], ['ssh'])
        g = apiviews.map_extra(self.conn, {'nodes': [{'id': 'host:nas1', 'kind': 'Host', 'label': 'nas1', 'layer': 'storage', 'props': {}},
                                                     {'id': 'pool:nas1:tank', 'kind': 'StoragePool', 'label': 'tank', 'layer': 'storage', 'host': 'nas1', 'props': {}}], 'edges': []},
                               ('storage', 'workloads'))
        nodes = {n['id']: n for n in g['nodes']}
        self.assertEqual(nodes['pool:nas1:tank']['props']['api']['status'], 'DEGRADED', 'the scan draws tank: the API reading goes beside it')
        self.assertIn('api:nas:pool:fast', nodes)
        self.assertEqual(nodes['api:nas:app:jellyfin']['props']['runtime'], 'truenas-app')
        listing = apiviews.annotate_workloads(self.conn, {'workloads': []})
        self.assertEqual([(w['name'], w['source'], w['host']) for w in listing['workloads']], [('jellyfin', 'api', 'nas1')])

    def test_the_guide_and_answers_that_are_not_what_the_reference_says(self):
        g = apiguide.guide('truenas')
        self.assertEqual(g['role'], 'READONLY_ADMIN')
        self.assertTrue(any('api_key.create' in r and 'expires_at' in r for s in g['steps'] for r in s['run']))
        self.assertFalse(any('FULL_ADMIN' in r for s in g['steps'] for r in s['run']))
        for f in (apitruenas.parse_me, apitruenas.parse_keys, apitruenas.parse_pools, apitruenas.parse_datasets, apitruenas.parse_snapshot_tasks,
                  apitruenas.parse_replications, apitruenas.parse_shares, apitruenas.parse_apps, apitruenas.parse_alerts, apitruenas.parse_system):
            for bad in ('', 'x', 'null', '3', '[null, 1, {"name": 5}]', '{"privilege": {"roles": ["ok_lower", 5, "POOL_READ"]}}'):
                with self.subTest(f=f.__name__, bad=bad):
                    self.assertIsInstance(f(bad), dict)
        self.assertEqual(apitruenas.parse_me('{"privilege": {"roles": ["ok_lower", 5, "POOL_READ"]}}')['roles'], ['POOL_READ'])
        self.assertEqual(apitruenas.parse_keys('[{"id": 1, "expires_at": "2027-01-01T00:00:00Z"}]')['keys'][0]['expires_at'], 1798761600)
        self.assertEqual(apitruenas.key_number(KEY), 7)


if __name__ == '__main__':
    import unittest
    unittest.main()
