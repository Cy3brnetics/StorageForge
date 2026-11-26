"""Sensitive routes that move (roadmap section 14, "Layers"; routecode.py). What must hold: a session that asked for it at sign-in has to
send the code of the moment on every request that changes keys, the enclave, deploys, consoles or host access; the code is for one
route, one method and one half minute; a session that did not ask is left as it was; a copied cookie gets no route key without the
password; and taking the code out of the path changes nothing about which rules a route falls under."""
import shutil
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import dbfactory
from storageforge_index import routecode, server, users

PW = 'a long enough password'


class RouteCodes(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.db = dbfactory.make(self, self.tmp / 'index.db')
        self.conn = self.db.connect()
        self.addCleanup(self.conn.close)
        self.db.migrate(self.conn)
        users.create(self.conn, 'root', PW, 'admin')
        users.create(self.conn, 'reader', PW, 'viewer')
        self.web = server.create_app(server.App(self.db), 's' * 48)

    def browser(self, name='root'):
        """A browser: the sign-in page asks for the route key."""
        c = self.web.test_client()
        r = c.post('/api/login', json={'username': name, 'password': PW, 'route_code': True})
        self.assertEqual(r.status_code, 200)
        got = r.get_json()
        self.assertLess(abs(got['now'] - time.time()), 5)
        return c, got['route_key']

    def coded(self, key, method, path, at=None):
        return f'/api/~{routecode.code(key, method, path, int((time.time() if at is None else at) // 30))}{path[4:]}'

    def test_a_browser_session_sends_the_code_of_the_moment_on_a_sensitive_request(self):
        c, key = self.browser()
        r = c.post('/api/bindings', json={})
        self.assertEqual((r.status_code, r.get_json()['routecode']), (403, True))
        self.assertLess(abs(r.get_json()['now'] - time.time()), 5, 'the refusal says what time the server has')
        self.assertNotEqual(c.post(self.coded(key, 'POST', '/api/bindings'), json={}).get_json().get('routecode'), True, 'with the code it reaches the route')
        self.assertEqual(c.post('/api/bindings', json={}, headers={'X-SF-Code': routecode.code(key, 'POST', '/api/bindings', int(time.time() // 30))}).get_json().get('routecode'), None,
                         'and in a header, for a client that cannot change its paths')
        self.assertEqual(c.get('/api/keys').status_code, 200, 'reading takes no code')
        self.assertNotEqual(c.post('/api/scan/all', json={}).get_json().get('routecode'), True, 'nor does a route that is not one of the sensitive ones')
        for path in ('/api/enclave/lock', '/api/deploy/start', '/api/console/sessions', '/api/access/grant', '/api/keys/install'):
            self.assertEqual(c.post(path, json={}).get_json().get('routecode'), True, path)
        self.assertEqual(c.delete('/api/keys/x').get_json().get('routecode'), True)

    def test_a_code_is_for_one_route_one_method_one_session_and_half_a_minute(self):
        c, key = self.browser()
        other, other_key = self.browser()
        self.assertNotEqual(key, other_key)
        now = time.time()
        wrong = {'another route': self.coded(key, 'POST', '/api/keys').replace('/keys', '/bindings'),
                 'another method': f'/api/~{routecode.code(key, "DELETE", "/api/bindings", int(now // 30))}/bindings',
                 'another session': self.coded(other_key, 'POST', '/api/bindings'),
                 'two minutes ago': self.coded(key, 'POST', '/api/bindings', now - 120),
                 'two minutes ahead': self.coded(key, 'POST', '/api/bindings', now + 120)}
        for why, path in wrong.items():
            self.assertEqual(c.post(path, json={}).get_json().get('routecode'), True, why)
        for why, at in (('the half minute before', now - 30), ('the half minute after', now + 30)):
            self.assertIsNone(c.post(self.coded(key, 'POST', '/api/bindings', at), json={}).get_json().get('routecode'), why)
        with mock.patch.object(routecode.time, 'time', lambda: now + 95):        # the same recorded URL, a minute and a half later
            self.assertEqual(c.post(self.coded(key, 'POST', '/api/bindings', now), json={}).get_json().get('routecode'), True, 'a recorded URL is dead')

    def test_a_session_that_did_not_ask_at_sign_in_is_left_as_it_was(self):
        c = self.web.test_client()
        got = c.post('/api/login', json={'username': 'root', 'password': PW}).get_json()
        self.assertEqual(got, {'username': 'root'})
        self.assertIsNone(c.post('/api/bindings', json={}).get_json().get('routecode'))
        got = c.post('/api/login', json={'username': 'root', 'password': PW, 'route_code': 'yes'}).get_json()
        self.assertNotIn('route_key', got, 'asked for with true, and nothing else')

    def test_a_copied_cookie_gets_no_route_key_without_the_password(self):
        c, key = self.browser()
        thief = self.web.test_client()
        cookie = c.get_cookie(self.web.config['SESSION_COOKIE_NAME'])
        thief.set_cookie(self.web.config['SESSION_COOKIE_NAME'], cookie.value)
        self.assertEqual(thief.get('/api/me').status_code, 200, 'the cookie is the session')
        self.assertEqual(thief.post('/api/keys', json={'name': 'stolen'}).get_json().get('routecode'), True, 'and it changes nothing on a sensitive route')
        self.assertNotIn('route_key', thief.get('/api/me').get_json())
        with thief.session_transaction() as s:
            s['auth_at'] = 0                                                    # the password was typed in the owner's browser, a while ago
        self.assertEqual(thief.post('/api/routecode', json={}).status_code, 403)
        self.assertEqual(thief.post('/api/routecode', json={'password': 'not the password'}).status_code, 403)
        self.assertEqual(self.conn.scalar("SELECT count(*) FROM ssh_keys WHERE name = 'stolen'"), 0)
        self.assertEqual(c.post('/api/routecode', json={'password': PW}).get_json()['route_key'], key)          # the owner, whose browser lost its key
        self.assertEqual(self.conn.scalar("SELECT count(*) FROM audit_log WHERE action = 'web.routecode'"), 3, 'two refusals and the owner\'s, each recorded')

    def test_the_mark_on_the_session_cannot_be_taken_off_and_asking_for_the_key_puts_it_on(self):
        c = self.web.test_client()
        self.assertEqual(c.post('/api/login', json={'username': 'root', 'password': PW}).status_code, 200)
        self.assertIsNone(c.post('/api/bindings', json={}).get_json().get('routecode'))
        key = c.post('/api/routecode', json={'password': PW}).get_json()['route_key']
        self.assertEqual(c.post('/api/bindings', json={}).get_json().get('routecode'), True, 'from then on this session sends codes')
        self.assertIsNone(c.post(self.coded(key, 'POST', '/api/bindings'), json={}).get_json().get('routecode'))

    def test_the_code_in_the_path_changes_nothing_about_the_rules_of_the_route(self):
        c, key = self.browser('reader')
        r = c.post(self.coded(key, 'POST', '/api/keys'), json={'name': 'k'})
        self.assertEqual(r.status_code, 403)
        self.assertIn('may not do this', r.get_json()['error'], 'a role that may not make keys still may not')
        admin, admin_key = self.browser()
        with admin.session_transaction() as s:
            s['auth_at'] = 0
        self.assertEqual(admin.post(self.coded(admin_key, 'POST', '/api/bindings'), json={}).get_json().get('reauth'), True, 'and the password is still asked for')
        self.assertEqual(admin.post('/api/~nothexat/keys', json={}).status_code, 404)
        self.assertEqual(admin.post('/api/~0123456/keys', json={}).status_code, 404)
        self.assertEqual(self.web.test_client().post('/api/~01234567/keys', json={}).status_code, 401, 'without a session it is the sign-in that is missing')

    def test_the_code_is_the_one_the_browser_computes(self):
        """The same numbers kernel.js gets (tests/test_browser_enclave.py runs that side): HMAC-SHA256, eight hex digits."""
        key = routecode.key_for('s' * 48, 'sid', 1700000000)
        self.assertEqual(len(key), 64)
        self.assertEqual(routecode.code(key, 'post', '/api/keys', 56666666), routecode.code(key, 'POST', '/api/keys', 56666666))
        self.assertRegex(routecode.code(key, 'POST', '/api/keys', 56666666), r'^[0-9a-f]{8}$')
        self.assertNotEqual(routecode.code(key, 'POST', '/api/keys', 56666666), routecode.code(key, 'POST', '/api/keys', 56666667))
        self.assertTrue(routecode.sensitive('POST', '/api/security/webauthn/register/begin'))
        self.assertFalse(routecode.sensitive('GET', '/api/keys'))
        self.assertFalse(routecode.sensitive('POST', '/api/reauth'), 'the way back to a route key is not itself behind one')


if __name__ == '__main__':
    unittest.main()
