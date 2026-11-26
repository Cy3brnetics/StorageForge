"""Expiry and rotation of platform API tokens (apiconn.rotate, apiconn.expiry_of; roadmap section 13): an expiry read back from the
platform or given by a person, a warning in the notification center before it lapses, and a new token taken without a gap, only once
the read-back found the platform takes it, it reads what the old one read and can do no more than StorageForge needs.

Against the real client and the TLS server of apifake.py. The platform here tells the two tokens apart by the Authorization header
each request carries, as a real one does: a route answers 401 to a token it does not know. The answers are those of
test_apireadback.py (Proxmox VE's /access/permissions and token metadata, from pve-docs/api-viewer/apidoc.js, fetched 2026-11-20)."""
import time

try:
    from test_apiconn import TOKEN, TOKEN_ID, Base
    from test_apireadback import PVE_ADMIN, PVE_AUDITOR
except ImportError:      # run as tests.test_x from the project folder
    from tests.test_apiconn import TOKEN, TOKEN_ID, Base
    from tests.test_apireadback import PVE_ADMIN, PVE_AUDITOR
from storageforge_index import alerts, apiconn, apiread, notifications, server, users, vault

NEW = '9b2e4d61-0c3a-4f5e-8d7c-1a2b3c4d5e6f'
NEW_ID = 'storageforge@pve!storageforge2'
PW = 'a long enough password'


class Expiry(Base):
    def test_a_given_date_warns_thirty_days_before_and_is_critical_in_the_last_week(self):
        now = time.time()
        row = self.add(expires_at=int(now + 20 * 86400))
        self.assertEqual((row['expiry']['state'], row['expiry']['source']), ('soon', 'given'))
        found = apiconn.problems(self.conn)['api-token-expiry:lab']
        self.assertEqual(found[4], 'warn')
        self.assertIn('the platform does not say', found[3])
        self.assertTrue(notifications.ignorable(found[0], found[4]), 'a warning about an expiry can be snoozed: it is not a security finding')
        self.conn.execute('UPDATE platform_connections SET token_expires_at = :e', {'e': int(now + 3 * 86400)})
        self.assertEqual(apiconn.problems(self.conn)['api-token-expiry:lab'][4], 'crit')
        self.conn.execute('UPDATE platform_connections SET token_expires_at = :e', {'e': int(now - 60)})
        self.assertIn('expired on', apiconn.problems(self.conn)['api-token-expiry:lab'][2])
        self.conn.execute('UPDATE platform_connections SET token_expires_at = :e', {'e': int(now + 200 * 86400)})
        self.assertNotIn('api-token-expiry:lab', apiconn.problems(self.conn))

    def test_dates_people_type(self):
        self.assertEqual(apiconn.check_expiry('2027-01-02'), int(time.mktime(time.strptime('2027-01-02', '%Y-%m-%d'))))
        self.assertEqual(apiconn.check_expiry('1800000000'), 1800000000)
        self.assertIsNone(apiconn.check_expiry(''))
        for bad in ('soon', '2027-13-45', True, -5, '99999999999999999'):
            with self.subTest(bad), self.assertRaises(apiconn.ConnError):
                apiconn.check_expiry(bad)

    def test_the_platform_s_word_replaces_the_given_one_and_never_is_said(self):
        row = self.add(expires_at='2030-01-01')
        row = apiconn.pin(self.conn, row['conn_id'], self.fake.fingerprint, 'gabe')
        lapse = int(time.time()) + 10 * 86400
        self.fake.routes.update({'/access/permissions': {'/': PVE_AUDITOR}, '/cluster/resources': [], '/cluster/backup': [],
                                 '/access/users/storageforge@pve/token/storageforge': {'expire': lapse, 'privsep': 1}})
        apiread.read(self.db, self.conn, row)
        got = apiconn.get(self.conn, row['conn_id'])
        self.assertEqual((got['token_expires_at'], got['expiry']['source'], got['expiry']['state']), (lapse, 'platform', 'soon'))
        self.fake.routes['/access/users/storageforge@pve/token/storageforge'] = {'expire': 0, 'privsep': 1}
        apiread.read(self.db, self.conn, row)
        got = apiconn.get(self.conn, row['conn_id'])
        self.assertEqual(got['expiry']['state'], 'never')
        self.assertTrue(any('no expiry' in n for n in got['readback']['notes']))
        self.no_token_anywhere()


class Rotation(Base):
    def setUp(self):
        super().setUp()
        self.known = {TOKEN: {'/': PVE_AUDITOR}, NEW: {'/': PVE_AUDITOR}}

        def perms(req):
            for secret, paths in self.known.items():
                if req['headers'].get('Authorization', '').endswith('=' + secret):
                    return paths
            return 401, 'authentication failure', {'data': None}
        self.fake.routes.update({'/access/permissions': perms, '/cluster/resources': [], '/cluster/backup': [],
                                 '/access/users/storageforge@pve/token/storageforge': {'expire': int(time.time()) + 86400 * 300, 'privsep': 1},
                                 '/access/users/storageforge@pve/token/storageforge2': {'expire': int(time.time()) + 86400 * 400, 'privsep': 1}})
        self.row = self.pinned()
        apiread.read(self.db, self.conn, self.row)
        self.row = apiconn.get(self.conn, self.row['conn_id'])

    def released(self):
        return self.v.credential('api-pve-lab', platform='pve:lab')

    def nothing_staged(self):
        self.assertEqual(self.conn.scalar("SELECT COUNT(*) FROM device_credentials WHERE name = 'api-pve-lab.next'"), 0)

    def no_secret_anywhere(self, *texts):
        self.no_token_anywhere(*texts)
        for t in texts:
            self.assertNotIn(NEW, str(t))
        self.assertNotIn(NEW, self.stderr.getvalue())
        for r in self.fake.requests:
            self.assertNotIn(NEW, r['path'])
        for found in self.everywhere(NEW):
            self.fail(f'the new token is readable in {found}')

    def test_a_new_token_the_platform_takes_replaces_the_old_one(self):
        got = apiconn.rotate(self.db, self.conn, self.row['conn_id'], NEW_ID, NEW, 'gabe')
        self.assertEqual(got['readback']['verdict'], 'exact')
        self.assertEqual((self.released()['password'], self.released()['username']), (NEW, NEW_ID))
        self.nothing_staged()
        row = got['connection']
        self.assertEqual((row['token_id'], row['token_previous'], row['expiry']['source']), (NEW_ID, TOKEN_ID, 'platform'))
        found = apiconn.problems(self.conn)['api-token-previous:lab']
        self.assertIn(TOKEN_ID, found[3])
        auths = [r['headers']['Authorization'] for r in self.fake.requests]
        self.assertTrue(any(a.endswith('=' + NEW) for a in auths), 'the new token was tried against the platform before it was taken')
        self.assertNotIn('api-token-previous:lab', apiconn.problems(self.conn) if apiconn.forget_previous(self.conn, self.row['conn_id']) else {})
        apiread.read(self.db, self.conn, apiconn.get(self.conn, self.row['conn_id']))
        self.assertTrue(self.fake.requests[-1]['headers']['Authorization'].endswith('=' + NEW))
        self.no_secret_anywhere(got)

    def test_a_token_the_platform_refuses_is_dropped_and_the_old_one_keeps_working(self):
        del self.known[NEW]
        with self.assertRaises(apiconn.RotationRefused) as caught:
            apiconn.rotate(self.db, self.conn, self.row['conn_id'], NEW_ID, NEW, 'gabe')
        self.assertIn('old token stays', str(caught.exception))
        self.assertEqual(self.released()['password'], TOKEN)
        self.assertEqual(apiconn.get(self.conn, self.row['conn_id'])['token_id'], TOKEN_ID)
        self.nothing_staged()
        apiread.read(self.db, self.conn, apiconn.get(self.conn, self.row['conn_id']))       # the old token still reads
        self.no_secret_anywhere(caught.exception)

    def test_a_certificate_that_changes_while_the_new_token_is_checked_refuses_the_rotation_and_is_recorded(self):
        path = '/access/permissions'        # the next call, for the new token's expiry, forgives an error
        answer, new = self.fake.routes[path], []

        def swap(req):
            new.append(self.fake.new_certificate())
            return answer
        self.fake.routes[path] = swap
        with self.assertRaises(apiconn.RotationRefused) as caught:
            apiconn.rotate(self.db, self.conn, self.row['conn_id'], NEW_ID, NEW, 'gabe')
        self.assertIn('old token stays', str(caught.exception))
        self.assertIn('certificate', str(caught.exception))
        self.assertEqual(self.released()['password'], TOKEN)
        self.nothing_staged()
        row = apiconn.get(self.conn, self.row['conn_id'])
        self.assertEqual((row['token_id'], row['state'], row['cert_offered']), (TOKEN_ID, 'certificate-changed', new[0]))
        self.assertIn('security-api-cert:lab', apiconn.problems(self.conn))
        self.no_secret_anywhere(caught.exception)

    def test_a_wider_token_or_one_that_reads_less_is_not_taken(self):
        self.known[NEW] = {'/': PVE_ADMIN}
        with self.assertRaisesRegex(apiconn.RotationRefused, 'more than StorageForge needs'):
            apiconn.rotate(self.db, self.conn, self.row['conn_id'], NEW_ID, NEW, 'gabe')
        self.known[NEW] = {'/vms': {'VM.Audit': 1}}
        with self.assertRaisesRegex(apiconn.RotationRefused, 'cannot read what the old one reads') as caught:
            apiconn.rotate(self.db, self.conn, self.row['conn_id'], NEW_ID, NEW, 'gabe')
        self.assertIn('backup-jobs', str(caught.exception))
        self.assertEqual(self.released()['password'], TOKEN)
        self.nothing_staged()
        self.no_secret_anywhere(caught.exception)

    def test_not_before_the_certificate_is_accepted_and_removal_takes_a_staged_token_too(self):
        other = self.add('other')
        with self.assertRaisesRegex(apiconn.ConnError, 'accept the platform certificate'):
            apiconn.rotate(self.db, self.conn, other['conn_id'], NEW_ID, NEW, 'gabe')
        self.v.store_credential('api-pve-lab.next', NEW_ID, NEW, policy={'platforms': ['pve:lab']})      # as if a rotation stopped half way
        apiconn.remove(self.conn, self.row['conn_id'])
        self.assertEqual(self.conn.scalar("SELECT COUNT(*) FROM device_credentials WHERE name LIKE 'api-pve-lab%'"), 0)

    def test_the_route_takes_a_new_token_in_the_audit_log_by_its_id_only(self):
        users.create(self.conn, 'admin', PW, 'admin')
        app = server.create_app(server.App(self.db), 's' * 48)
        c = app.test_client()
        c.post('/api/login', json={'username': 'admin', 'password': PW})
        del self.known[NEW]
        r = c.post(f'/api/keys/platforms/{self.row["conn_id"]}/token', json={'token_id': NEW_ID, 'token': NEW})
        self.assertEqual(r.status_code, 409, r.get_json())
        self.known[NEW] = {'/': PVE_AUDITOR}
        r = c.post(f'/api/keys/platforms/{self.row["conn_id"]}/token', json={'token_id': NEW_ID, 'token': NEW, 'expires_at': '2031-01-01'})
        self.assertEqual(r.status_code, 200, r.get_json())
        self.assertEqual(r.get_json()['connection']['token_id'], NEW_ID)
        self.assertEqual(r.headers['Cache-Control'], 'no-store')
        r = c.post(f'/api/keys/platforms/{self.row["conn_id"]}/token/previous', json={})
        self.assertIsNone(r.get_json()['connection']['token_previous'])
        actions = [a for (a,) in self.conn.all("SELECT action FROM audit_log WHERE action LIKE 'platform.token%' ORDER BY audit_id")]
        self.assertEqual(actions, ['platform.token', 'platform.token', 'platform.token_previous'])
        alerts.evaluate(self.db)
        self.no_secret_anywhere(r.get_data(as_text=True))


if __name__ == '__main__':
    import unittest
    unittest.main()
