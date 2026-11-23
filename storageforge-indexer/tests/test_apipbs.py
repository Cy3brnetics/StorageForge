"""Proxmox Backup Server through its API (apipbs.py), read with the real client from a TLS server on 127.0.0.1 with recorded JSON.

Where the samples come from: the Backup Server API viewer, pbs.proxmox.com/docs/api-viewer/apidoc.js, fetched 2026-11-20, which gives
each answer's fields and types (no whole example answers), so each sample is built from those fields:
    /status/datastore-usage              store, total, used, avail, estimated-full-date, mount-status, backend-type, gc-status, history
    /config/datastore                    name, path, gc-schedule, verify-new, comment
    /admin/datastore/{store}/groups      backup-type (vm, ct, host), backup-id, backup-count, last-backup, owner, files, comment
    /admin/datastore/{store}/snapshots   backup-type, backup-id, backup-time, size, protected, owner, fingerprint, verification {state (ok,
                                         failed), upid}
    /admin/verify, /admin/prune          id, store, schedule, ignore-verified, outdated-after, keep-*, last-run-state, last-run-endtime,
                                         last-run-upid, next-run
    /access/permissions                  the map of ACL path to privilege to propagate bit"""
import json
import time

try:
    from test_apiconn import Base
except ImportError:      # run as tests.test_x from the project folder
    from tests.test_apiconn import Base
from storageforge_index import apiconn, apipbs, apiread, apiviews

GiB = 1 << 30
NOW = int(time.time())
TID = 'storageforge@pbs!storageforge'
USAGE = [{'store': 'store1', 'total': 1000 * GiB, 'used': 400 * GiB, 'avail': 600 * GiB, 'estimated-full-date': NOW + 20 * 86400, 'mount-status': 'nonremovable', 'backend-type': 'filesystem',
          'history': [0.3, 0.35, 0.4], 'history-start': NOW - 86400 * 30, 'history-delta': 86400},
         {'store': 'gone', 'error': 'datastore could not be looked up', 'mount-status': 'nonremovable', 'backend-type': 'filesystem'}]
CONFIG = [{'name': 'store1', 'path': '/mnt/datastore/store1', 'gc-schedule': 'daily', 'verify-new': True}, {'name': 'gone', 'path': '/mnt/gone'}]
GROUPS = [{'backup-type': 'vm', 'backup-id': '100', 'backup-count': 14, 'last-backup': NOW - 3600, 'owner': 'pve-sync@pbs!pve1', 'files': ['index.json.blob']},
          {'backup-type': 'ct', 'backup-id': '101', 'backup-count': 3, 'last-backup': NOW - 10 * 86400, 'owner': 'pve-sync@pbs!pve1'},
          {'backup-type': 'nas', 'backup-id': 'x'}]
SNAPS = [{'backup-type': 'vm', 'backup-id': '100', 'backup-time': NOW - 3600, 'size': 12 * GiB, 'protected': False, 'owner': 'pve-sync@pbs!pve1', 'verification': {'state': 'ok', 'upid': 'UPID:pbs:0000A:0000B:00000000673C0000:verify:store1:root@pam:'}},
         {'backup-type': 'ct', 'backup-id': '101', 'backup-time': NOW - 10 * 86400, 'size': GiB, 'fingerprint': 'aa:bb', 'verification': {'state': 'failed', 'upid': 'UPID:pbs:0000C:0000D:00000000673C0001:verify:store1:root@pam:'}},
         {'backup-type': 'vm', 'backup-id': '100', 'backup-time': NOW - 90000, 'size': 12 * GiB}]
VERIFY = [{'id': 'v-store1', 'store': 'store1', 'schedule': 'daily', 'ignore-verified': True, 'outdated-after': 30, 'last-run-state': 'ERROR: 1 snapshot(s) failed', 'last-run-endtime': NOW - 7200, 'next-run': NOW + 79200}]
PRUNE = [{'id': 'p-store1', 'store': 'store1', 'schedule': 'daily', 'keep-last': 3, 'keep-daily': 7, 'last-run-state': 'OK', 'last-run-endtime': NOW - 3000}]


def pbs_routes():
    return {'/version': {'version': '4.1', 'release': '2', 'repoid': '0123abcd'}, '/status/datastore-usage': USAGE, '/config/datastore': CONFIG,
            '/admin/datastore/store1/groups': GROUPS, '/admin/datastore/store1/snapshots': SNAPS, '/admin/datastore/gone/groups': (400, 'datastore not found', {'data': None}),
            '/admin/datastore/store1/namespace': [], '/admin/datastore/gone/namespace': [], '/admin/datastore/gone/snapshots': [],
            '/admin/verify': VERIFY, '/admin/prune': PRUNE, '/access/permissions': {'/datastore/store1': {'Datastore.Audit': True}},
            '/access/users/storageforge@pbs/token/storageforge': {'tokenid': TID, 'enable': True, 'expire': NOW + 86400 * 200, 'comment': 'StorageForge'}}


class Read(Base):
    def setUp(self):
        super().setUp()
        self.fake.routes.update(pbs_routes())
        row = apiconn.add(self.v, self.conn, 'pbs', 'backups', self.fake.url, TID, 'a6c8e0f2-1b3d-4e5f-8a9b-0c1d2e3f4a5b', 'gabe')
        self.row = apiconn.pin(self.conn, row['conn_id'], self.fake.fingerprint, 'gabe')

    def test_datastores_groups_snapshots_and_jobs(self):
        got = apiread.read(self.db, self.conn, self.row)
        self.assertEqual(got['readback']['verdict'], 'exact')
        self.assertEqual(got['counts'], {'platform': 1, 'datastore': 2, 'backup-group': 2, 'snapshot': 3, 'verify-job': 1, 'prune-job': 1})
        self.assertEqual(len(got['skipped']), 1)
        self.assertIn('gone', got['skipped'][0])
        objs = {(o['kind'], o['ref']): o for o in apiread.objects(self.conn, self.row['conn_id'])}
        self.assertEqual(objs[('datastore', 'store1')]['path'], '/mnt/datastore/store1')
        self.assertEqual(objs[('snapshot', f'store1/ct/101/{NOW - 10 * 86400}')]['verify'], 'failed')
        self.assertEqual(objs[('prune-job', 'p-store1')]['keep'], {'last': 3, 'daily': 7})
        found = apiread.problems(self.conn)
        self.assertEqual(sorted(found), ['api-backup-stale:backups', 'api-backup-verify:backups', 'api-datastore-full:backups:store1', 'api-verify-job:backups:v-store1'])
        self.assertIn('store1/ct/101', found['api-backup-stale:backups'][3])
        self.assertTrue(all(r['method'] == 'GET' for r in self.fake.requests))
        self.assertEqual(self.fake.requests[0]['headers']['Authorization'].split('=')[0], 'PBSAPIToken')

    def test_nonroot_namespaces_are_read_even_if_root_groups_are_denied(self):
        self.fake.routes['/admin/datastore/store1/namespace'] = [{'ns': ''}, {'ns': 'team/nas'}]
        self.fake.routes['/admin/datastore/store1/groups'] = lambda req: GROUPS if '?ns=team%2Fnas' in req['path'] else (403, 'Forbidden', None)
        got = apiread.read(self.db, self.conn, self.row)
        self.assertTrue(any('store1 groups:' in msg for msg in got['skipped']))
        objs = {(o['kind'], o['ref']): o for o in apiread.objects(self.conn, self.row['conn_id'])}
        self.assertEqual(objs[('backup-group', 'store1/team/nas/vm/100')]['ns'], 'team/nas')
        self.assertIn(('snapshot', f'store1/team/nas/ct/101/{NOW - 10 * 86400}'), objs)
        self.assertIn(('snapshot', f'store1/ct/101/{NOW - 10 * 86400}'), objs)

    def test_a_token_with_more_than_datastore_audit_is_found(self):
        self.fake.routes['/access/permissions'] = {'/datastore/store1': {'Datastore.Audit': True, 'Datastore.Modify': True, 'Datastore.Prune': True}}
        got = apiread.read(self.db, self.conn, self.row)
        self.assertEqual(got['readback']['verdict'], 'over')
        self.assertEqual(apiconn.problems(self.conn)['security-api-token:backups'][4], 'warn')

    def test_a_token_without_datastore_audit_reads_only_the_version(self):
        self.fake.routes['/access/permissions'] = {}
        got = apiread.read(self.db, self.conn, self.row)
        self.assertEqual((got['counts'], got['skipped']), ({'platform': 1}, ['datastores: the token lacks Datastore.Audit']))
        self.assertIn('api-token-short:backups', apiconn.problems(self.conn))

    def test_the_datastore_path_is_compared_with_the_mount_the_scan_read(self):
        self.conn.execute("INSERT INTO hosts (hostname, ssh_host, ssh_user, inventory_json) VALUES ('pbs1', 'pbs1.lab', 'scan', '{}')")
        hid = self.conn.scalar("SELECT host_id FROM hosts WHERE hostname = 'pbs1'")
        self.conn.execute("""INSERT INTO mounts (host_id, mount_point, source, filesystem_type, total_bytes, used_bytes, scan_state)
                             VALUES (:h, '/mnt/datastore', '/dev/sdb1', 'xfs', :t, :u, 'indexed')""", {'h': hid, 't': 800 * GiB, 'u': 400 * GiB})
        self.conn.execute("UPDATE platform_connections SET host = 'pbs1' WHERE conn_id = :i", {'i': self.row['conn_id']})
        apiread.read(self.db, self.conn, self.row)
        cmp = apiviews.compare_connection(self.conn, apiconn.get(self.conn, self.row['conn_id']))['datastores']
        by = {c['store']: c for c in cmp}
        self.assertEqual((by['store1']['mount'], by['store1']['fstype']), ('/mnt/datastore', 'xfs'))
        self.assertEqual(by['store1']['differs'], [{'field': 'total_bytes', 'api': 1000 * GiB, 'ssh': 800 * GiB}])
        self.assertIsNone(by['gone']['mount'])

    def test_answers_that_are_not_what_the_viewer_says(self):
        for f in (apipbs.parse_usage, apipbs.parse_groups, apipbs.parse_snapshots, apipbs.parse_jobs, apipbs.parse_config):
            for bad in ('', 'x', '{"data": 3}', json.dumps({'data': [None, {'store': 5}, {'backup-type': 'vm', 'backup-id': ['x']}]})):
                with self.subTest(f=f.__name__, bad=bad):
                    self.assertIsInstance(f(bad), dict)


if __name__ == '__main__':
    import unittest
    unittest.main()
