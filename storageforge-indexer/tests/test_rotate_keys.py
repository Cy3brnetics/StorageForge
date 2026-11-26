"""Keys that rotate by themselves (roadmap section 14, "Layers"; rotate_keys.py). What must hold: the session-signing key changes on
its schedule without signing anyone out, an old one checks cookies only for as long as a session can last, and it is made from two
things neither of which signs alone; the vault key is derived again and every DEK rewrapped on its schedule, inside the key enclave
with no secret handed over, and no key's ciphertext changes; a rotation that fails says so until one succeeds."""
import json
import os
import shutil
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import dbfactory
from storageforge_index import alerts, enclave_stepup, lock2, rotate_keys, server, users, vault
from test_enclave import SECRET
from test_enclave_stepup import PW, Base

MASTER = 'm' * 48
DAY = 86400


class SessionKeys(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.db = dbfactory.make(self, self.tmp / 'index.db')
        self.conn = self.db.connect()
        self.addCleanup(self.conn.close)
        self.db.migrate(self.conn)
        users.create(self.conn, 'root', PW, 'admin')
        env = mock.patch.dict(os.environ)
        env.start()
        self.addCleanup(env.stop)
        for name in ('STORAGEFORGE_ENCLAVE', 'STORAGEFORGE_VAULT_SECRET', 'STORAGEFORGE_VAULT_SECRET_FILE', rotate_keys.SESSION_HOURS_ENV, rotate_keys.KEK_DAYS_ENV):
            os.environ.pop(name, None)
        self.web = server.create_app(server.App(self.db), MASTER)
        self.audited = []
        self.t0 = time.time()

    def tick(self, after=0.0):
        return rotate_keys.tick(self.db, self.web, MASTER, lambda c, action, outcome, detail: self.audited.append((action, outcome)), now=self.t0 + after)

    def signed_in(self):
        c = self.web.test_client()
        self.assertEqual(c.post('/api/login', json={'username': 'root', 'password': PW}).status_code, 200)
        return c

    def cookie_of(self, client):
        return client.get_cookie(self.web.config['SESSION_COOKIE_NAME']).value

    def with_cookie(self, value):
        c = self.web.test_client()
        c.set_cookie(self.web.config['SESSION_COOKIE_NAME'], value)
        return c.get('/api/me').status_code

    def test_a_new_key_signs_after_a_day_and_nobody_is_signed_out_by_it(self):
        self.assertEqual(self.tick(), {'session': True})
        first = self.web.config['SECRET_KEY']
        self.assertNotEqual(first, MASTER, 'the session secret itself signs nothing any more')
        self.assertEqual(self.tick(23 * 3600), {}, 'not yet')
        c = self.signed_in()
        kept = self.cookie_of(c)
        self.assertEqual(self.tick(25 * 3600), {'session': True})
        self.assertEqual((self.web.config['SECRET_KEY'] != first, self.web.config['SECRET_KEY_FALLBACKS']), (True, [first]))
        self.assertEqual(c.get('/api/me').status_code, 200, 'the cookie the old key signed is still good')
        self.assertEqual(self.with_cookie(kept), 200)
        self.assertEqual(self.signed_in().get('/api/me').status_code, 200)
        self.assertEqual(self.audited, [('session.key.rotate', 'ok')] * 2)

    def test_a_key_that_stopped_signing_checks_cookies_only_for_as_long_as_a_session_lasts(self):
        self.tick()
        kept = self.cookie_of(self.signed_in())
        self.tick(25 * 3600)                                                   # it stops signing here
        self.assertEqual(self.with_cookie(kept), 200)
        self.tick(25 * 3600 + 7 * 3600)
        self.assertEqual(self.with_cookie(kept), 200, 'seven hours on: a session may last eight')
        self.tick(50 * 3600)                                                   # the next rotation, more than eight hours after
        self.assertEqual(len(self.web.config['SECRET_KEY_FALLBACKS']), 1, 'the first key is forgotten, the second still checks')
        self.assertEqual(self.with_cookie(kept), 401, 'a cookie signed with a forgotten key is no cookie')

    def test_the_key_is_made_from_the_secret_and_the_database_and_neither_alone_gives_it(self):
        self.tick()
        key = self.web.config['SECRET_KEY']
        ring = alerts.get_setting(self.conn, rotate_keys.RING)
        self.assertEqual(len(ring), 1)
        self.assertNotIn(key, json.dumps(ring))                                # whoever reads the database
        self.assertNotIn(MASTER, json.dumps(ring))
        self.assertNotEqual(rotate_keys.session_keys(self.conn, 'x' * 48, self.t0), [key], 'and with the ring, another secret makes another key')
        self.assertEqual(rotate_keys.session_keys(self.conn, MASTER, self.t0), [key], 'a restarted server finds the same key: sessions outlive it')
        again = server.create_app(server.App(self.db), MASTER)
        rotate_keys.tick(self.db, again, MASTER, now=self.t0)
        c = self.signed_in()
        c2 = again.test_client()
        c2.set_cookie(again.config['SESSION_COOKIE_NAME'], self.cookie_of(c))
        self.assertEqual(c2.get('/api/me').status_code, 200)

    def test_with_the_period_at_zero_the_session_secret_signs_as_before(self):
        os.environ[rotate_keys.SESSION_HOURS_ENV] = '0'
        self.assertEqual(self.tick(), {})
        self.assertEqual((self.web.config['SECRET_KEY'], self.web.config['SECRET_KEY_FALLBACKS']), (MASTER, None))
        self.assertIsNone(alerts.get_setting(self.conn, rotate_keys.RING))

    # ── the vault key, without the enclave ──
    def old(self, days=31):
        self.conn.execute('UPDATE vault_meta SET created_at = :t, rotated_at = NULL', {'t': int(self.t0) - days * DAY})

    def test_the_vault_key_is_rewrapped_on_its_schedule_and_a_failure_is_a_notification_until_it_works(self):
        with vault.Vault(self.db, self.conn, SECRET) as v:
            v.init()
            v.unlock()
            v.generate_key('k')
        was = self.conn.all('SELECT kdf_salt, wrapped_dek, ciphertext FROM vault_meta, ssh_keys')[0]
        self.assertEqual(self.tick().get('kek'), None, 'a vault made today is not due')
        self.old()
        self.assertNotIn('kek', self.tick(), 'due, and this server has no secret to derive it from')
        got = rotate_keys.problems(self.conn)
        self.assertEqual(list(got), ['rotation-failed:kek'])
        self.assertIn('Rotating the vault key failed', got['rotation-failed:kek'][2])
        self.assertIn('rotation-failed:kek', alerts.problems(self.conn), 'it reaches the notification center')
        self.assertIn(('vault.rekey', 'failed'), self.audited)
        os.environ['STORAGEFORGE_VAULT_SECRET'] = SECRET.decode()
        self.assertEqual(self.tick()['kek'], 1)
        self.assertEqual(rotate_keys.problems(self.conn), {})
        now = self.conn.all('SELECT kdf_salt, wrapped_dek, ciphertext FROM vault_meta, ssh_keys')[0]
        self.assertNotEqual((bytes(now[0]), bytes(now[1])), (bytes(was[0]), bytes(was[1])))
        self.assertEqual(bytes(now[2]), bytes(was[2]), 'the key itself is not encrypted again')
        self.assertNotIn('kek', self.tick(), 'and it is not due again')
        with vault.Vault(self.db, self.conn, SECRET).unlock() as v:
            with v.decrypt_key(self.conn.scalar('SELECT key_id FROM ssh_keys')) as buf:
                self.assertIn(b'OPENSSH PRIVATE KEY', bytes(buf.view()))
        os.environ[rotate_keys.KEK_DAYS_ENV] = '0'
        self.old()
        self.assertNotIn('kek', self.tick(), 'turned off')


class Rewrap(Base):
    """The same schedule with the key enclave: the KEK is derived again inside, from the secret the enclave holds."""

    def setUp(self):
        super().setUp()
        self.v = vault.Vault(self.db, self.conn).unlock()
        self.addCleanup(self.v.close)
        self.v.generate_key('k')
        self.v.store_credential('switch', 'admin', 'pw-123456')
        os.environ.pop(rotate_keys.KEK_DAYS_ENV, None)

    def old(self):
        self.conn.execute('UPDATE vault_meta SET created_at = :t, rotated_at = NULL', {'t': int(time.time()) - 31 * DAY})

    def test_the_enclave_derives_the_key_again_and_nobody_hands_it_the_secret(self):
        self.assertNotIn('STORAGEFORGE_VAULT_SECRET', os.environ)
        before, meta = self.row('k'), self.meta()
        self.assertEqual(rotate_keys.tick(self.db), {})
        self.old()
        self.assertEqual(rotate_keys.tick(self.db), {'kek': 1})
        after = self.row('k')
        self.assertNotEqual(self.meta()['kdf_salt'], meta['kdf_salt'])
        self.assertNotEqual(after['wrapped_dek'], before['wrapped_dek'])
        self.assertEqual(after['ciphertext'], before['ciphertext'])
        self.assertTrue(self.e.sign(after, b'x')[0])
        self.refused('auth', self.e.sign, before, b'x')
        self.assertEqual(self.v.credential('switch', host='sw1')['password'], 'pw-123456')
        self.e.lock()
        self.e.unlock(SECRET, meta)                                            # the salt and verifier from before derive the key from before,
        self.refused('auth', self.e.sign, after, b'x')                         # which opens nothing that is stored now
        self.e.lock()
        self.assertEqual(self.unlock()['state'], 'unlocked', 'the same secret, under the new salt')
        self.assertTrue(self.e.sign(after, b'x')[0])
        with vault.Vault(self.db, self.conn, SECRET).unlock() as old:          # and today's vault opens it too
            self.assertEqual(old.credential('switch', host='sw1')['password'], 'pw-123456')

    def test_a_scheduled_rewrap_takes_no_step_up_and_a_new_secret_still_does(self):
        enclave_stepup.enroll(self.conn, self.address, 'gabe', PW)
        self.old()
        self.assertEqual(rotate_keys.tick(self.db), {'kek': 1}, 'it gives nobody anything: the vault opens with the same secret after')
        with self.assertRaises(vault.StepUpNeeded):
            self.v.rotate_secret(b'n' * 48, current=SECRET)
        self.assertTrue(enclave_stepup.check(self.conn, self.address, 'gabe', password=PW)['token'], 'the step-up record was rewrapped with the rest')

    def test_a_locked_enclave_makes_the_rewrap_fail_and_say_so(self):
        self.old()
        self.e.lock()
        self.assertEqual(rotate_keys.tick(self.db), {})
        self.assertIn('enclave is locked', rotate_keys.problems(self.conn)['rotation-failed:kek'][3])
        self.unlock()
        self.assertEqual(rotate_keys.tick(self.db), {'kek': 1})
        self.assertEqual(rotate_keys.problems(self.conn), {})

    def test_a_rewrap_keeps_the_second_lock(self):
        share_file = self.tmp / 'host_share'
        os.environ[lock2.SHARE_ENV] = str(share_file)
        share = os.urandom(32)
        lock2.write_share(share, share_file)
        os.environ['STORAGEFORGE_VAULT_SECRET'] = SECRET.decode()
        self.v.rotate_secret(SECRET, second_lock=(share, lock2.marker(share, lock2.recovery(share)[1])))
        del os.environ['STORAGEFORGE_VAULT_SECRET']
        self.old()
        self.assertEqual(rotate_keys.tick(self.db), {'kek': 1})
        self.assertIsNotNone(self.conn.scalar('SELECT second_lock FROM vault_meta'))
        self.assertTrue(self.e.status()['second_lock'])
        self.e.lock()
        self.refused('auth', self.e.unlock, SECRET, self.meta())               # still not by the secret alone
        self.assertEqual(self.e.unlock(SECRET, {**self.meta(), 'share': share})['state'], 'unlocked')
        self.assertTrue(self.e.sign(self.row('k'), b'x')[0])


if __name__ == '__main__':
    unittest.main()
