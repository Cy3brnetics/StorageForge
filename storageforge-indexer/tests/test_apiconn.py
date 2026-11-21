"""The API connection kind (roadmap section 13; apiconn.py): an HTTPS client to a platform's own API with the certificate pinned once a
person accepted it, the token from the vault released for that one platform, timeouts, a rate limit, retries only where they help, and
read-only unless an action is turned on. Tested against a real TLS server on 127.0.0.1 (apifake.py) with certificates openssl made.

What must hold above all: the token is in no URL, no log line, no error message and no row of the database but its own ciphertext, and
nothing is sent with it to a server whose certificate a person did not accept."""
import contextlib
import io
import os
import shutil
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import dbfactory
from apifake import Platform
from storageforge_index import apiconn, notifications, vault

SECRET = 's' * 48
TOKEN = '3f1c9a52-7d0e-4b8f-9a61-2c5e8d4b7a10'
TOKEN_ID = 'storageforge@pve!storageforge'


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.db = dbfactory.make(self, self.tmp / 'index.db')
        self.conn = self.db.connect()
        self.addCleanup(self.conn.close)
        self.db.migrate(self.conn)
        env = mock.patch.dict(os.environ, {'STORAGEFORGE_VAULT_SECRET': SECRET})
        env.start()
        self.addCleanup(env.stop)
        for name in ('STORAGEFORGE_ENCLAVE', 'STORAGEFORGE_VAULT_SECRET_FILE'):
            os.environ.pop(name, None)
        vault.Vault(self.db, self.conn, SECRET.encode()).init()
        self.v = vault.Vault(self.db, self.conn).unlock()
        self.addCleanup(self.v.close)
        self.fake = Platform({'/version': {'version': '9.1.2', 'release': '9.1', 'repoid': 'abcdef12'}})
        self.addCleanup(self.fake.close)
        self.stderr = io.StringIO()
        cm = contextlib.redirect_stderr(self.stderr)
        cm.__enter__()
        self.addCleanup(cm.__exit__, None, None, None)

    def add(self, name='lab', kind='pve', **kw):
        return apiconn.add(self.v, self.conn, kind, name, self.fake.url, kw.pop('token_id', TOKEN_ID), kw.pop('secret', TOKEN), 'gabe', **kw)

    def pinned(self, name='lab'):
        row = self.add(name)
        return apiconn.pin(self.conn, row['conn_id'], self.fake.fingerprint, 'gabe')

    def everywhere(self, value: str) -> list[str]:
        if self.db.dialect == 'sqlite':
            tables = [r[0] for r in self.conn.all("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'")]
        else:
            tables = [r[0] for r in self.conn.all("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'")]
        found = []
        for t in tables:
            for row in self.conn.all(f'SELECT * FROM {t}'):
                for cell in row:
                    text = bytes(cell).decode('latin-1') if isinstance(cell, (bytes, bytearray, memoryview)) else str(cell)
                    if value in text:
                        found.append(t)
        return found

    def no_token_anywhere(self, *texts):
        for t in texts:
            self.assertNotIn(TOKEN, str(t))
        self.assertNotIn(TOKEN, self.stderr.getvalue())
        self.assertEqual(self.everywhere(TOKEN), [])
        for r in self.fake.requests:
            self.assertNotIn(TOKEN, r['path'])
            self.assertNotIn(TOKEN, r['body'])


class WhatAPersonGives(Base):
    def test_plain_http_a_password_in_the_url_and_a_path_are_refused(self):
        for url, why in (('http://pve.lab:8006', 'plain HTTP is refused'), ('https://root:pw@pve.lab', 'no user name or password'),
                         ('https://pve.lab/api2/json/nodes', 'only the scheme'), ('ftp://pve.lab', 'starts with https'), ('https://pve.lab?x=1', 'only the scheme')):
            with self.subTest(url), self.assertRaisesRegex(apiconn.ConnError, why):
                apiconn.normalize_url(url, 'pve')
        self.assertEqual(apiconn.normalize_url('pve.lab', 'pve'), 'https://pve.lab:8006')
        self.assertEqual(apiconn.normalize_url('https://10.0.0.5/', 'pbs'), 'https://10.0.0.5:8007')
        self.assertEqual(apiconn.normalize_url('pdm.lab', 'pdm'), 'https://pdm.lab:8443')
        self.assertEqual(apiconn.normalize_url('https://[fd00::5]:9000/api2/json', 'pve'), 'https://[fd00::5]:9000')

    def test_a_root_token_is_refused_with_the_reason(self):
        with self.assertRaisesRegex(apiconn.ConnError, 'root@pam is refused: root@pam can do everything'):
            self.add(token_id='root@pam!sf')
        self.assertEqual(apiconn.listing(self.conn), [])

    def test_a_secret_that_could_end_a_header_is_refused(self):
        for bad in ('short', 'has space inside it', 'line\r\nX-Evil: 1', 'tab\there12'):
            with self.subTest(bad), self.assertRaises(apiconn.ConnError):
                self.add(secret=bad)
        self.assertEqual(self.conn.scalar('SELECT COUNT(*) FROM device_credentials'), 0)

    def test_stored_sealed_with_a_policy_for_this_platform_alone(self):
        row = self.add()
        self.assertEqual((row['state'], row['secret_name'], row['token_id']), ('certificate-unaccepted', 'api-pve-lab', TOKEN_ID))
        self.assertEqual(self.v.list_credentials()[0]['policy'], {'hosts': [], 'platforms': ['pve:lab'], 'sensitive': False, 'steps': []})
        self.assertEqual(self.v.credential('api-pve-lab', platform='pve:lab')['password'], TOKEN)
        with self.assertRaises(vault.NotReleased):
            self.v.credential('api-pve-lab', platform='pve:other')
        with self.assertRaises(vault.NotReleased):
            self.v.credential('api-pve-lab', host='web', step='tailscale')
        self.assertEqual(self.fake.requests, [], 'adding a connection sends nothing')
        with self.assertRaisesRegex(apiconn.ConnError, 'already a connection'):
            self.add()
        self.no_token_anywhere()

    def test_linked_to_the_scanned_host_at_its_address(self):
        self.conn.execute("INSERT INTO hosts (hostname, ssh_host, ip_address, ssh_user, inventory_json) VALUES ('pve1', 'pve1.lab', '127.0.0.1', 'scan', '{}')")
        self.assertEqual(self.add()['host'], 'pve1')
        with self.assertRaisesRegex(apiconn.ConnError, 'no scanned host'):
            self.add('b', host='ghost')

    def test_removed_with_its_token_and_what_it_read(self):
        row = self.pinned()
        self.conn.execute("INSERT INTO platform_objects (conn_id, kind, ref, data_json, read_at) VALUES (:i, 'guest', '100', '{}', 1)", {'i': row['conn_id']})
        apiconn.remove(self.conn, row['conn_id'])
        self.assertEqual([self.conn.scalar(f'SELECT COUNT(*) FROM {t}') for t in ('platform_connections', 'platform_objects', 'device_credentials')], [0, 0, 0])


class Certificate(Base):
    def test_the_fingerprint_is_the_one_openssl_prints(self):
        got = apiconn.offered(self.fake.url)
        self.assertEqual(got['sha256'], self.fake.fingerprint)
        self.assertEqual((got['subject'], got['self_signed'], got['names']), ('CN=pve.lab', True, ['pve.lab']))
        self.assertEqual(self.fake.requests, [], 'fetching the certificate sends no request')

    def test_nothing_is_sent_and_the_token_not_released_before_a_person_accepts_it(self):
        row = self.add()
        with self.assertRaises(apiconn.NotPinned):
            apiconn.open_client(self.db, self.conn, row)
        with self.assertRaises(apiconn.NotPinned):
            apiconn.Client(row, TOKEN).get('/version')
        self.assertEqual(self.fake.requests, [])

    def test_a_fingerprint_the_server_does_not_present_is_not_pinned(self):
        row = self.add()
        with self.assertRaisesRegex(apiconn.ConnError, 'different certificate'):
            apiconn.pin(self.conn, row['conn_id'], ':'.join(['AB'] * 32), 'gabe')
        self.assertIsNone(apiconn.get(self.conn, row['conn_id'])['cert_sha256'])

    def test_a_changed_certificate_gets_nothing_and_is_a_finding_that_cannot_be_muted(self):
        row = self.pinned()
        with apiconn.open_client(self.db, self.conn, row) as c:
            self.assertIn('9.1.2', c.get('/version'))
        before = len(self.fake.requests)
        new = self.fake.new_certificate()
        with apiconn.open_client(self.db, self.conn, row) as c, self.assertRaises(apiconn.CertificateChanged) as caught:
            c.get('/version')
        self.assertEqual(len(self.fake.requests), before, 'the token never reached the server with the new certificate')
        self.assertIn(new, str(caught.exception))
        apiconn.record_failure(self.conn, row, caught.exception)
        row = apiconn.get(self.conn, row['conn_id'])
        self.assertEqual((row['state'], row['cert_offered']), ('certificate-changed', new))
        found = apiconn.problems(self.conn)['security-api-cert:lab']
        self.assertEqual(found[4], 'crit')
        self.assertFalse(notifications.ignorable(found[0], found[4]))
        apiconn.pin(self.conn, row['conn_id'], new, 'gabe')            # a person accepts the renewed one
        self.assertEqual(apiconn.problems(self.conn), {})
        with apiconn.open_client(self.db, self.conn, apiconn.get(self.conn, row['conn_id'])) as c:
            self.assertIn('9.1.2', c.get('/version'))
        self.no_token_anywhere(caught.exception)


class Requests(Base):
    def test_the_token_goes_in_the_header_only_in_each_platform_s_form(self):
        for kind, want in (('pve', f'PVEAPIToken={TOKEN_ID}={TOKEN}'), ('pbs', f'PBSAPIToken={TOKEN_ID}:{TOKEN}'), ('pdm', f'PDMAPIToken={TOKEN_ID}:{TOKEN}')):
            with self.subTest(kind):
                self.fake.requests.clear()
                row = self.add(f'x-{kind}', kind=kind)
                row = apiconn.pin(self.conn, row['conn_id'], self.fake.fingerprint, 'gabe')
                with apiconn.open_client(self.db, self.conn, row) as c:
                    c.get('/version', full=1)
                (r,) = self.fake.requests
                self.assertEqual((r['method'], r['path'], r['headers']['Authorization']), ('GET', '/api2/json/version?full=1', want))
        self.no_token_anywhere()

    def test_read_only_unless_the_action_is_turned_on(self):
        row = self.pinned()
        with apiconn.open_client(self.db, self.conn, row) as c:
            for method in ('POST', 'PUT', 'DELETE'):
                with self.subTest(method), self.assertRaisesRegex(apiconn.ReadOnly, 'is read-only'):
                    c.request(method, '/nodes/pve1/qemu/100/snapshot', {'snapname': 'x'})
            with self.assertRaises(apiconn.ReadOnly):
                c.request('POST', '/nodes/pve1/qemu/100/snapshot', {'snapname': 'x'}, action='snapshot')
        self.assertEqual(self.fake.requests, [])
        self.fake.routes['/nodes/pve1/qemu/100/snapshot'] = 'UPID:pve1:1'
        with apiconn.Client({**row, 'actions': ['snapshot']}, TOKEN) as c:
            c.request('POST', '/nodes/pve1/qemu/100/snapshot', {'snapname': 'x'}, action='snapshot')
        self.assertEqual([r['method'] for r in self.fake.requests], ['POST'])

    def test_a_platform_value_cannot_climb_out_of_its_path(self):
        row = self.pinned()
        with apiconn.Client(row, TOKEN) as c:
            self.assertEqual(c.seg('../../access?x=1'), '..%2F..%2Faccess%3Fx%3D1')
            for bad in ('/nodes/../access', 'nodes', '/nodes/a b', '/x?y=1'):
                with self.subTest(bad), self.assertRaises(apiconn.ApiError):
                    c.get(bad)
        self.assertEqual(self.fake.requests, [])

    def test_a_refused_token_is_not_retried_and_the_error_holds_no_token(self):
        row = self.pinned()
        self.fake.routes['/nodes'] = (401, f'invalid token {TOKEN}', {'data': None})
        with apiconn.open_client(self.db, self.conn, row) as c, self.assertRaises(apiconn.Refused) as caught:
            c.get('/nodes')
        self.assertEqual(len(self.fake.requests), 1)
        self.assertIn('[token]', str(caught.exception))
        apiconn.record_failure(self.conn, row, caught.exception)
        self.assertEqual(apiconn.get(self.conn, row['conn_id'])['state'], 'failed')
        self.no_token_anywhere(caught.exception, apiconn.problems(self.conn))

    def test_a_busy_server_is_retried_and_a_broken_one_is_not_retried_forever(self):
        row = self.pinned()
        answers = iter([(503, 'busy', {'data': None}), (200, 'OK', {'data': ['n']})])
        self.fake.routes['/nodes'] = lambda req: next(answers)
        with apiconn.Client(row, TOKEN) as c:
            self.assertIn('"n"', c.get('/nodes'))
        self.assertEqual(len(self.fake.requests), 2)
        self.fake.requests.clear()
        self.fake.routes['/nodes'] = (500, 'broken', {'data': None})
        with apiconn.Client(row, TOKEN) as c, self.assertRaisesRegex(apiconn.ApiError, '500 broken'):
            c.get('/nodes')
        self.assertEqual(len(self.fake.requests), 1, 'a 500 is not retried')
        self.fake.requests.clear()
        self.fake.routes['/nodes'] = (503, 'busy', {'data': None})
        with apiconn.Client(row, TOKEN) as c, self.assertRaises(apiconn.ApiError):
            c.get('/nodes')
        self.assertEqual(len(self.fake.requests), 1 + apiconn.RETRIES)

    def test_a_rate_limit_a_budget_and_a_timeout(self):
        row = self.pinned()
        start = time.monotonic()
        with apiconn.Client(row, TOKEN, rate=20) as c:
            for _ in range(6):
                c.get('/version')
        self.assertGreaterEqual(time.monotonic() - start, 5 / 20 - 0.01)
        with apiconn.Client(row, TOKEN, budget=2) as c:
            c.get('/version')
            c.get('/version')
            with self.assertRaisesRegex(apiconn.ApiError, 'limit of 2 requests'):
                c.get('/version')
        import socket
        quiet = socket.socket()
        quiet.bind(('127.0.0.1', 0))
        quiet.listen(1)              # accepts the connection and never says a word of TLS
        self.addCleanup(quiet.close)
        slow = {**row, 'base_url': f'https://127.0.0.1:{quiet.getsockname()[1]}'}
        start = time.monotonic()
        with apiconn.Client(slow, TOKEN, timeout=0.5) as c, self.assertRaisesRegex(apiconn.ApiError, 'did not answer'):
            c.get('/version')
        self.assertLess(time.monotonic() - start, 5)

    def test_a_closed_client_holds_no_token(self):
        row = self.pinned()
        c = apiconn.open_client(self.db, self.conn, row)
        c.close()
        self.assertNotIn(TOKEN, repr(vars(c)))
        with self.assertRaisesRegex(apiconn.ApiError, 'closed'):
            c.get('/version')


if __name__ == '__main__':
    unittest.main()
