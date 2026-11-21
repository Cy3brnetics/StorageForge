"""The read-back (apireadback.py): what a token can really do, asked of the platform, compared with the permission guide. An
over-privileged token is a security finding that cannot be muted, and it leaves when the token is narrowed.

The answers are built from each API's own documentation, fetched 2026-11-20: GET /access/permissions returns "Map of path => (Map of
privilege => propagate boolean)" in Proxmox VE (pve-docs/api-viewer/apidoc.js, /access/permissions), "Map of ACL path to Map of
privilege to propagate bit" in Backup Server and Datacenter Manager (their api-viewer/apidoc.js); the token metadata GET
/access/users/{userid}/token/{tokenid} returns comment, expire and privsep in Proxmox VE and tokenid, enable, expire, comment in the
other two. The privilege names are those the user management pages list (pve-docs/chapter-pveum.html, pbs docs user-management.html,
pdm docs access-control.html)."""
import time

try:
    from test_apiconn import TOKEN, Base
except ImportError:      # run as tests.test_x from the project folder
    from tests.test_apiconn import TOKEN, Base
from storageforge_index import alerts, apiconn, apiread, apireadback, notifications, server, users

PVE_AUDITOR = {'Datastore.Audit': 1, 'Mapping.Audit': 1, 'Pool.Audit': 1, 'SDN.Audit': 1, 'Sys.Audit': 1, 'VM.Audit': 1, 'VM.GuestAgent.Audit': 1}
PVE_ADMIN = {**PVE_AUDITOR, 'Permissions.Modify': 1, 'Sys.Modify': 1, 'User.Modify': 1, 'VM.Allocate': 1, 'VM.PowerMgmt': 1, 'Datastore.Allocate': 1}
TOKEN_INFO = {'comment': 'StorageForge', 'expire': int(time.time()) + 86400 * 300, 'privsep': 1}
PW = 'a long enough password'


class Judge(Base):
    def test_a_pve_auditor_token_is_exactly_right(self):
        r = apireadback.judge('pve', {'/': PVE_AUDITOR}, [], {'expire': TOKEN_INFO['expire'], 'privsep': True})
        self.assertEqual((r['verdict'], r['over'], r['short'], r['notes']), ('exact', [], [], []))
        self.assertEqual({e['priv'] for e in r['extra_read']}, {'Mapping.Audit', 'Pool.Audit', 'SDN.Audit', 'VM.GuestAgent.Audit'})

    def test_one_privilege_too_few_fails_only_its_feature_and_says_what_to_add(self):
        r = apireadback.judge('pve', {'/vms': {'VM.Audit': 1}, '/storage': {'Datastore.Audit': 1}, '/nodes': {'Sys.Audit': 1}})
        self.assertEqual(r['verdict'], 'short')
        self.assertEqual([s['feature'] for s in r['short']], ['backup-jobs'])
        self.assertTrue(r['features']['guests']['ok'] and r['features']['storage']['ok'])
        self.assertIn('Sys.Audit (PVEAuditor) for the token and its user on /', r['short'][0]['add'])

    def test_an_admin_token_is_over_and_critical_and_an_action_turned_on_is_not_over(self):
        r = apireadback.judge('pve', {'/': PVE_ADMIN})
        self.assertEqual((r['verdict'], r['admin']), ('over', True))
        self.assertIn('Permissions.Modify', {o['priv'] for o in r['over']})
        snap = apireadback.judge('pve', {'/': PVE_AUDITOR, '/vms/100': {'VM.Snapshot': 1, 'VM.Audit': 1}}, ['snapshot'])
        self.assertEqual(snap['verdict'], 'exact')
        lacking = apireadback.judge('pve', {'/': PVE_AUDITOR}, ['snapshot'])
        self.assertEqual(lacking['short'][0]['feature'], 'action snapshot')
        power = apireadback.judge('pve', {'/': PVE_AUDITOR, '/vms/100': {'VM.PowerMgmt': 1}})
        self.assertEqual((power['verdict'], power['admin']), ('over', False))

    def test_backup_server_and_datacenter_manager(self):
        self.assertEqual(apireadback.judge('pbs', {'/datastore/store1': {'Datastore.Audit': 1}})['verdict'], 'exact')
        r = apireadback.judge('pbs', {'/datastore/store1': {'Datastore.Audit': 1, 'Datastore.Backup': 1, 'Datastore.Read': 1, 'Datastore.Verify': 1}})
        self.assertEqual({o['priv'] for o in r['over']}, {'Datastore.Backup', 'Datastore.Read', 'Datastore.Verify'})
        self.assertEqual(apireadback.judge('pbs', {'/datastore/store1': {'Datastore.Audit': 1, 'Datastore.Read': 1}}, ['restore-test'])['verdict'], 'exact')
        self.assertEqual(apireadback.judge('pbs', {})['short'][0]['feature'], 'datastores')
        self.assertEqual(apireadback.judge('pdm', {'/resource/pve-a': {'Resource.Audit': 1}})['verdict'], 'exact')
        admin = apireadback.judge('pdm', {'/': {'Resource.Audit': 1, 'Resource.Manage': 1, 'Resource.Migrate': 1, 'Access.Modify': 1, 'System.Modify': 1}})
        self.assertEqual((admin['verdict'], admin['admin']), ('over', True))

    def test_privilege_separation_off_no_expiry_and_an_expired_token_are_said(self):
        r = apireadback.judge('pve', {'/': PVE_AUDITOR}, [], {'privsep': False, 'expire': 0, 'enable': None})
        self.assertTrue(any('privilege separation is off' in n for n in r['notes']))
        self.assertTrue(any('no expiry' in n for n in r['notes']))
        self.assertTrue(any('expired' in n for n in apireadback.judge('pve', {}, [], {'expire': 5})['notes']))

    def test_answers_that_are_not_permission_lists(self):
        for text in ('', 'null', '{"data": null}', '{"data": [1,2]}', '<html>', '{"data": {"/": "x", "nopath": {}, "/a": {"P": "yes", "Q": 1}}}'):
            with self.subTest(text):
                got = apireadback.parse_permissions(text)
                self.assertIsInstance(got['paths'], dict)
        self.assertEqual(apireadback.parse_permissions('{"data": {"/a": {"P": "yes", "Q": 1}}}')['paths'], {'/a': {'Q': True}})
        self.assertEqual(apireadback.parse_token_info('{"data": {"expire": "soon", "privsep": 0}}'), {'expire': None, 'privsep': False, 'enable': None})


class AgainstThePlatform(Base):
    """A read through the real client to the TLS server, with the answers above."""

    def setUp(self):
        super().setUp()
        self.fake.routes['/access/permissions'] = {'/': PVE_AUDITOR}
        self.fake.routes['/access/users/storageforge@pve/token/storageforge'] = TOKEN_INFO
        self.row = self.pinned()

    def test_the_read_back_is_stored_and_an_admin_token_is_a_finding_that_leaves_when_narrowed(self):
        got = apiread.read(self.db, self.conn, self.row)
        self.assertEqual(got['readback']['verdict'], 'exact')
        self.assertEqual(apiconn.get(self.conn, self.row['conn_id'])['readback']['verdict'], 'exact')
        paths = [r['path'].split('?')[0] for r in self.fake.requests]
        self.assertIn('/api2/json/access/users/storageforge%40pve/token/storageforge', paths)
        self.assertNotIn('security-api-token:lab', alerts.problems(self.conn))
        self.fake.routes['/access/permissions'] = {'/': PVE_ADMIN}
        apiread.read(self.db, self.conn, self.row)
        found = alerts.problems(self.conn)['security-api-token:lab']
        self.assertEqual((found[0], found[4]), ('security-api-token', 'crit'))
        self.assertFalse(notifications.ignorable(found[0], found[4]))
        alerts.evaluate(self.db)
        key = next(r[0] for r in self.conn.all("SELECT alert_key FROM alerts WHERE kind = 'security-api-token'"))
        with self.assertRaises(ValueError):
            notifications.snooze(self.conn, key, 3600, 'gabe')
        self.fake.routes['/access/permissions'] = {'/': PVE_AUDITOR}       # the token narrowed on the platform
        apiread.read(self.db, self.conn, self.row)
        self.assertNotIn('security-api-token:lab', alerts.problems(self.conn))
        self.no_token_anywhere()

    def test_a_platform_that_will_not_say_what_the_token_can_do_fails_the_read(self):
        self.fake.routes['/access/permissions'] = (403, 'Permission check failed', {'data': None})
        with self.assertRaises(apiconn.Refused):
            apiread.read(self.db, self.conn, self.row)
        row = apiconn.get(self.conn, self.row['conn_id'])
        self.assertEqual(row['state'], 'failed')
        self.assertIn('api-read:lab', alerts.problems(self.conn))
        self.no_token_anywhere(row)

    def test_the_route_reads_back_and_a_viewer_cannot(self):
        users.create(self.conn, 'admin', PW, 'admin')
        users.create(self.conn, 'viewer', PW, 'viewer')
        app = server.create_app(server.App(self.db), 's' * 48)
        c, v = app.test_client(), app.test_client()
        c.post('/api/login', json={'username': 'admin', 'password': PW})
        v.post('/api/login', json={'username': 'viewer', 'password': PW})
        self.assertEqual(v.post(f'/api/keys/platforms/{self.row["conn_id"]}/read', json={}).status_code, 403)
        r = c.post(f'/api/keys/platforms/{self.row["conn_id"]}/read', json={})
        self.assertEqual(r.status_code, 200, r.get_json())
        self.assertEqual(r.get_json()['readback']['verdict'], 'exact')
        self.assertNotIn(TOKEN, r.get_data(as_text=True))
        self.assertEqual(v.get(f'/api/keys/platforms/{self.row["conn_id"]}').status_code, 200)


if __name__ == '__main__':
    import unittest
    unittest.main()
