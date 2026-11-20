"""Step-up checked inside the key enclave (roadmap section 14; enclave_stepup.py): the real enclave program on a socket file. What must
hold: once someone has enrolled, a key is made, brought in or rotated only with a token the enclave gave for a proof it checked itself,
a password against a hash it holds or a FIDO2 assertion against a public key it holds and a challenge it made; the web app can neither
make a token nor use an assertion twice; tries are limited inside; a token runs out by itself; and a lock-down is lifted only by a person."""
import base64
import hashlib
import io
import json
import os
import subprocess
import time
from unittest import mock

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from storageforge_index import cli, enclave, enclave_start, enclave_stepup, server, users, vault
from test_enclave import SECRET, Harness, build

PW, ANN = 'a long enough password', 'another long password'
RP, ORIGIN = 'forge.example', 'https://forge.example:8443'


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b'=').decode()


class Base(Harness):
    ARGS = ()

    def start(self):
        self.path = self.tmp / 'enclave.sock'
        self.address = f'unix:{self.path}'
        enclave.forget_pin(self.address)
        self.proc = subprocess.Popen([str(build()), '--unix', str(self.path), *self.ARGS], stderr=subprocess.PIPE)

    def setUp(self):
        super().setUp()
        self.vault.close()
        env = mock.patch.dict(os.environ, {'STORAGEFORGE_ENCLAVE': self.address, 'XDG_RUNTIME_DIR': str(self.tmp), 'STORAGEFORGE_ENCLAVE_RUN_DIR': str(self.tmp)})
        env.start()
        self.addCleanup(env.stop)
        for name in (*enclave_start.SECRET_ENVS, enclave_stepup.STEPUP_ENV):
            os.environ.pop(name, None)
        self.addCleanup(vault.present_token, None)
        self.unlock()

    def stepup(self):
        return self.e.status()['stepup']

    def enroll(self, user='gabe', password=PW, **kw):
        return enclave_stepup.enroll(self.conn, self.address, user, password, RP, ORIGIN, **kw)

    def token(self, user='gabe', password=PW):
        return enclave_stepup.check(self.conn, self.address, user, password=password)['token']

    def make_key(self, name):
        with vault.Vault(self.db, self.conn).unlock() as v:
            return v.generate_key(name)

    def lock_down(self):
        for _ in range(5):
            self.e.raw(b'not json')
            self.e.close()
        self.assertEqual(self.e.status()['state'], 'lockdown')


class StepUp(Base):
    def test_until_someone_enrolls_keys_are_made_as_before_and_after_that_only_with_a_token(self):
        self.assertFalse(self.stepup()['required'])
        self.make_key('before')
        self.assertEqual(self.enroll(), {'username': 'gabe', 'security_keys': 0, 'replaced': False})
        self.assertTrue(self.stepup()['required'])
        with self.assertRaises(vault.StepUpNeeded) as got:
            self.make_key('refused')
        self.assertIn('step-up the enclave checks itself', str(got.exception))
        self.assertIn('wrong password', self.refused('auth', enclave_stepup.check, self.conn, self.address, 'gabe', password='not the password'))
        self.assertEqual((self.stepup()['failed'], self.stepup()['ok']), (1, 0))
        vault.present_token('0' * 64)                                      # a token the enclave did not give
        with self.assertRaises(vault.StepUpNeeded):
            self.make_key('refused')
        vault.present_token(self.token())
        self.assertTrue(self.make_key('made')['public_key'].startswith('ssh-ed25519 '))
        pem = ed25519.Ed25519PrivateKey.generate().private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, serialization.NoEncryption())
        with vault.Vault(self.db, self.conn).unlock() as v:
            v.add_key('imported', pem)
            self.assertTrue(self.e.sign(self.row('made'), b'x')[0], 'signing with a key there is takes no step-up: tasks run unattended')
        vault.present_token(None)
        with self.assertRaises(vault.StepUpNeeded):
            self.make_key('refused')
        self.assertEqual(self.conn.scalar("SELECT count(*) FROM ssh_keys WHERE name = 'refused'"), 0)

    def test_what_is_kept_is_sealed_and_holds_no_password(self):
        self.enroll()
        row = self.conn.all('SELECT rec_uuid, ciphertext, wrapped_dek FROM enclave_stepup')[0]
        self.assertNotIn(PW.encode(), bytes(row[1]))
        with vault.Vault(self.db, self.conn, SECRET).unlock() as old:          # whoever holds the secret can read it: a hash, not the password
            with vault.open_into(old._need_kek(), *[bytes(x) for x in self.conn.all('SELECT dek_nonce, wrapped_dek FROM enclave_stepup')[0]], f'storageforge:dek:{row[0]}'.encode()) as dek:
                with vault.open_into(dek.view(), *[bytes(x) for x in self.conn.all('SELECT nonce, ciphertext FROM enclave_stepup')[0]], f'storageforge:stepup:{row[0]}'.encode()) as plain:
                    record = json.loads(bytes(plain.view()))
        self.assertEqual((record['user'], record['rp'], record['origin'], record['fido']), ('gabe', RP, ORIGIN, []))
        self.assertEqual(len(base64.b64decode(record['hash'])), 32)
        self.assertNotIn(PW, json.dumps(record))

    def test_a_record_proves_one_person_and_a_changed_one_proves_nobody(self):
        self.enroll()
        self.enroll('ann', ANN, token=self.token())
        gabe, ann = enclave_stepup.record_of(self.conn, 'gabe'), enclave_stepup.record_of(self.conn, 'ann')
        self.refused('auth', self.e.stepup, 'gabe', ann, ANN)                 # ann's record, said to be gabe's
        self.refused('auth', self.e.stepup, 'ann', ann, PW)                   # gabe's password on ann's record
        self.refused('auth', self.e.stepup, 'gabe', {**gabe, 'ciphertext': bytes(b ^ 1 for b in gabe['ciphertext'])}, PW)
        self.refused('auth', self.e.stepup, 'gabe', {**gabe, 'uuid': ann['uuid']}, PW)
        self.assertEqual(self.e.stepup('ann', ann, ANN)['user'], 'ann')
        self.assertIn('no step-up record', self.refused('stepup', enclave_stepup.check, self.conn, self.address, 'nobody', password=PW))

    def test_tries_are_limited_for_each_person_inside(self):
        self.enroll()
        self.enroll('ann', ANN, token=self.token())
        codes = []
        for _ in range(8):
            try:
                enclave_stepup.check(self.conn, self.address, 'gabe', password='wrong, every time')
            except enclave.EnclaveError as exc:
                codes.append(exc.code)
        self.assertEqual((codes[:4], codes[-1]), (['auth'] * 4, 'rate'), 'five a minute for one person (one was the token above), and the web app cannot raise that')
        self.refused('rate', enclave_stepup.check, self.conn, self.address, 'gabe', password=PW)
        self.assertTrue(self.token('ann', ANN), 'another person has their own count')

    def test_enrolling_once_someone_is_enrolled_takes_a_token_or_the_vault_secret(self):
        self.enroll()
        self.refused('stepup', self.enroll, 'ann', ANN)
        self.assertIsNone(enclave_stepup.record_of(self.conn, 'ann'))
        self.assertEqual(self.enroll('ann', ANN, token=self.token())['replaced'], False)
        with vault.Vault(self.db, self.conn).unlock() as v:
            meta = v._meta()
        self.assertEqual(self.enroll('cy', PW, secret=SECRET, meta=meta)['username'], 'cy')
        self.refused('stepup', self.enroll, 'dee', PW, secret=b'w' * 48, meta=meta)
        self.assertIn('at least 12', self.refused('auth', self.enroll, 'gabe', 'short', token=self.token('ann', ANN)))
        self.assertEqual(self.enroll('gabe', ANN, token=self.token('ann', ANN))['replaced'], True)
        self.refused('auth', enclave_stepup.check, self.conn, self.address, 'gabe', password=PW)
        self.assertTrue(self.token('gabe', ANN), 'the record was replaced: the new password is the one checked')

    # ── a security key ──
    def security_key(self, user='gabe'):
        key = ec.generate_private_key(ec.SECP256R1())
        cred = b64u(os.urandom(32))
        public = b64u(key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint))
        self.conn.execute("INSERT INTO security_webauthn (username, credential_id, public_key, sign_count, name, created_at) VALUES (:u, :c, :p, 0, 'token', 1)", {'u': user, 'c': cred, 'p': public})
        return key, cred

    def assertion(self, key, cred, challenge, origin=ORIGIN, rp=RP, kind='webauthn.get'):
        client = json.dumps({'type': kind, 'challenge': challenge, 'origin': origin}).encode()
        auth = hashlib.sha256(rp.encode()).digest() + b'\x01' + (7).to_bytes(4, 'big')
        sig = key.sign(auth + hashlib.sha256(client).digest(), ec.ECDSA(hashes.SHA256()))
        return {'id': cred, 'authenticator_data': base64.b64encode(auth).decode(), 'client_data': base64.b64encode(client).decode(), 'signature': base64.b64encode(sig).decode()}

    def by_key(self, fido):
        return enclave_stepup.check(self.conn, self.address, 'gabe', fido=fido)

    def test_a_security_key_is_checked_inside_against_a_challenge_the_enclave_made(self):
        key, cred = self.security_key()
        self.assertEqual(self.enroll()['security_keys'], 1)
        for i in range(12):                                                   # many: a signature's two numbers come in every length
            answer = self.assertion(key, cred, self.e.challenge())
            self.assertEqual(self.by_key(answer)['user'], 'gabe', i)
            self.e.close()
            self.unlock_again_if_limited(i)
        vault.present_token(self.by_key(self.assertion(key, cred, self.e.challenge()))['token'])
        self.assertTrue(self.make_key('by-touch'))

    def unlock_again_if_limited(self, i):
        if i % 4 == 3:          # five step-ups a minute for one person: a restart is a new minute
            self.stop()
            self.start()
            self.answering()
            self.unlock()

    def test_an_answer_counts_once_and_only_to_a_challenge_from_the_enclave_for_this_site(self):
        key, cred = self.security_key()
        other = ec.generate_private_key(ec.SECP256R1())
        self.enroll()
        answer = self.assertion(key, cred, self.e.challenge())
        self.assertTrue(self.by_key(answer)['token'])
        self.refused('auth', self.by_key, answer)                             # the same answer again: its challenge is used up
        self.refused('auth', self.by_key, self.assertion(key, cred, b64u(os.urandom(32))))          # a challenge the web app made up
        self.refused('auth', self.by_key, self.assertion(key, cred, self.e.challenge(), origin='https://evil.example'))
        self.stop()
        self.start()
        self.answering()
        self.unlock()
        self.refused('auth', self.by_key, self.assertion(key, cred, self.e.challenge(), rp='evil.example'))
        self.refused('auth', self.by_key, self.assertion(key, cred, self.e.challenge(), kind='webauthn.create'))
        self.refused('auth', self.by_key, self.assertion(other, cred, self.e.challenge()))           # not the key the enclave holds
        self.refused('auth', self.by_key, self.assertion(key, b64u(b'another credential'), self.e.challenge()))
        self.assertTrue(self.by_key(self.assertion(key, cred, self.e.challenge()))['token'], 'and a right one still passes')

    def test_only_so_many_challenges_wait_for_an_answer(self):
        codes = []
        for _ in range(18):
            try:
                self.e.challenge()
                codes.append('ok')
            except enclave.EnclaveError as exc:
                codes.append(exc.code)
        self.assertEqual((codes.count('ok'), codes[-1]), (16, 'rate'))

    def test_a_security_key_added_later_is_not_in_the_record_until_enrolling_again(self):
        self.enroll()
        self.assertFalse(enclave_stepup.stale_keys(self.conn, 'gabe'))
        key, cred = self.security_key()
        self.assertTrue(enclave_stepup.stale_keys(self.conn, 'gabe'))
        self.refused('auth', self.by_key, self.assertion(key, cred, self.e.challenge()))
        self.assertEqual(self.enroll(token=self.token())['security_keys'], 1)
        self.assertFalse(enclave_stepup.stale_keys(self.conn, 'gabe'))
        self.assertTrue(self.by_key(self.assertion(key, cred, self.e.challenge()))['token'])

    # ── restarts, lock-downs, and whoever holds the secret ──
    def restart(self):
        self.stop()
        self.start()
        self.answering()

    def test_after_a_restart_a_record_shown_at_unlock_turns_it_on_again_and_it_can_be_insisted_on(self):
        self.enroll()
        self.restart()
        self.assertFalse(self.stepup()['required'], 'a restarted enclave knows nothing')
        os.environ['STORAGEFORGE_VAULT_SECRET'] = SECRET.decode()
        with vault.Vault(self.db, self.conn).unlock():
            pass
        self.assertTrue(self.stepup()['required'], 'the vault shows it the records, and one that opens turns step-up on')
        self.conn.execute('DELETE FROM enclave_stepup')                       # whoever can write the database removes every record
        self.restart()
        with vault.Vault(self.db, self.conn).unlock():
            pass
        self.assertFalse(self.stepup()['required'], 'which is the limit the docs name')
        self.restart()
        os.environ[enclave_stepup.STEPUP_ENV] = 'required'                  # and what closes it, set where the enclave is unlocked from
        with vault.Vault(self.db, self.conn).unlock():
            pass
        self.assertTrue(self.stepup()['required'])
        del os.environ['STORAGEFORGE_VAULT_SECRET']
        with self.assertRaises(vault.StepUpNeeded):
            self.make_key('refused')

    def test_a_lock_or_a_lock_down_does_not_turn_it_off_and_tokens_do_not_outlive_either(self):
        self.enroll()
        vault.present_token(self.token())
        self.make_key('a')
        self.e.lock()
        self.unlock()                                                          # by the secret alone, with no record shown
        self.assertTrue(self.stepup()['required'])
        with self.assertRaises(vault.StepUpNeeded):
            self.make_key('b')

    def test_a_lock_down_is_lifted_only_with_a_persons_own_proof_once_step_up_is_on(self):
        self.enroll()
        record = enclave_stepup.record_of(self.conn, 'gabe')
        self.lock_down()
        self.assertIn('locked down', self.refused('stepup', self.e.unlock, SECRET, self.meta()))
        self.refused('auth', self.e.unlock, SECRET, self.meta(), proof={'user': 'gabe', 'record': record, 'password': 'not the password'})
        self.refused('auth', self.e.unlock, b'w' * 48, self.meta(), proof={'user': 'gabe', 'record': record, 'password': PW})
        self.assertEqual(self.e.status()['state'], 'lockdown')
        os.environ['STORAGEFORGE_VAULT_SECRET_FILE'] = str(self.tmp / 'secret')
        (self.tmp / 'secret').write_text(SECRET.decode())
        said = []
        self.assertEqual(enclave_start.starter(self.db, self.address, wait=5, say=said.append), 1, 'a starter holds the secret and is no person')
        del os.environ['STORAGEFORGE_VAULT_SECRET_FILE']
        with self.assertRaises(vault.StepUpNeeded):
            enclave_start.typed(self.db, self.conn, SECRET.decode())
        self.assertEqual(enclave_start.typed(self.db, self.conn, SECRET.decode(), {'user': 'gabe', 'record': record, 'password': PW}), 'unlocked')

    def test_whoever_holds_the_vault_secret_needs_no_person_beside_them(self):
        self.enroll()
        os.environ['STORAGEFORGE_VAULT_SECRET'] = SECRET.decode()
        self.assertTrue(self.make_key('by-command'), 'a command run with the secret gets its own token with it')
        self.refused('auth', self.e.stepup_secret, b'w' * 48, self.meta())
        os.environ['STORAGEFORGE_VAULT_SECRET'] = 'w' * 48
        with self.assertRaises(vault.VaultError):
            self.make_key('refused')

    def test_rotating_the_vault_secret_takes_a_step_up_and_the_records_open_under_the_new_one(self):
        self.enroll()
        new = b'n' * 48
        with vault.Vault(self.db, self.conn).unlock() as v:
            with self.assertRaises(vault.StepUpNeeded):
                v.rotate_secret(new)
            self.assertFalse(self.e.status()['rotating'])
            vault.present_token(self.token())
            v.rotate_secret(new)
        self.assertTrue(self.token(), 'the record was rewrapped with the keys: the same password still proves gabe')
        self.e.lock()
        self.assertEqual(self.e.unlock(new, self.meta(), records=enclave_stepup.records(self.conn))['stepup'], True)
        with vault.Vault(self.db, self.conn, new).unlock() as fresh:          # and the vault without the enclave rewraps them too
            fresh.rotate_secret(SECRET)
        self.e.lock()
        self.unlock()
        self.assertTrue(self.token())

    # ── the web app ──
    def web(self, name='root', role='admin'):
        users.create(self.conn, name, PW, role)
        app = server.App(self.db)
        web = server.create_app(app, 's' * 48)
        return web, self.signed_in(web, name)

    def signed_in(self, web, name, password=PW):
        c = web.test_client()
        self.assertEqual(c.post('/api/login', json={'username': name, 'password': password}).status_code, 200)
        return c

    def audited(self, action):
        return [r[0] for r in self.conn.all('SELECT outcome FROM audit_log WHERE action = :a ORDER BY audit_id', {'a': action})]

    def test_the_page_is_asked_for_the_password_and_the_enclave_is_what_checks_it(self):
        web, c = self.web()
        self.assertEqual(c.post('/api/keys', json={'name': 'before'}).status_code, 201)
        self.assertEqual(c.post('/api/enclave/stepup/enroll', json={'password': 'not my password at all'}).status_code, 403)
        got = c.post('/api/enclave/stepup/enroll', json={'password': PW}).get_json()
        self.assertEqual((got['stepup']['required'], got['stepup']['enrolled'], got['stepup']['people'], got['stepup']['fresh']), (True, True, 1, False))
        r = c.post('/api/keys', json={'name': 'k'})
        self.assertEqual((r.status_code, r.get_json().get('stepup')), (403, True))
        r = c.post('/api/enclave/stepup', json={'password': 'not my password at all'})
        self.assertEqual((r.status_code, r.get_json().get('stepup')), (403, None), 'a wrong password is an answer, not a new question')
        self.assertEqual(c.post('/api/enclave/stepup', json={'password': PW}).status_code, 200)
        self.assertTrue(c.get('/api/enclave').get_json()['stepup']['fresh'])
        self.assertEqual(c.post('/api/keys', json={'name': 'k'}).status_code, 201)
        other = self.signed_in(web, 'root')                                   # the same account in another browser: its session has no token
        self.assertEqual(other.post('/api/keys', json={'name': 'k2'}).status_code, 403)
        self.assertEqual(self.audited('enclave.stepup'), ['denied', 'ok'])
        self.assertEqual(self.audited('enclave.stepup.enroll'), ['denied', 'ok'])
        self.assertNotIn(PW, ' '.join(str(r[0]) for r in self.conn.all('SELECT detail_json FROM audit_log')))
        with c.session_transaction() as s:
            self.assertNotIn('token', json.dumps({k: str(v) for k, v in s.items()}), 'the token is kept in the server, not in the cookie')

    def test_a_second_person_enrolls_on_their_own_step_up_or_the_vault_secret(self):
        web, c = self.web()
        users.create(self.conn, 'ann', ANN, 'admin')
        ann = self.signed_in(web, 'ann', ANN)
        self.assertEqual(c.post('/api/enclave/stepup/enroll', json={'password': PW}).status_code, 200)
        r = ann.post('/api/enclave/stepup/enroll', json={'password': ANN})
        self.assertEqual((r.status_code, r.get_json()['stepup']), (403, True))
        r = ann.post('/api/enclave/stepup', json={'password': ANN})
        self.assertEqual((r.status_code, r.get_json()['enroll']), (403, True), 'she has no record to step up with')
        self.assertEqual(ann.post('/api/enclave/stepup/enroll', json={'password': ANN, 'secret': 'w' * 48}).status_code, 403)
        self.assertEqual(ann.post('/api/enclave/stepup/enroll', json={'password': ANN, 'secret': SECRET.decode()}).status_code, 200)
        self.assertEqual(ann.post('/api/enclave/stepup', json={'password': ANN}).status_code, 200)
        self.assertEqual(ann.post('/api/keys', json={'name': 'anns'}).status_code, 201)

    def test_a_security_key_steps_up_through_the_page(self):
        users.create(self.conn, 'root', PW, 'admin')
        key, cred = self.security_key('root')
        c = server.create_app(server.App(self.db), 's' * 48).test_client()

        def post(path, body):          # as a browser at this site's own name, which is what the token signs for
            return c.post(path, json=body, base_url=ORIGIN)
        self.assertEqual(post('/api/login', {'username': 'root', 'password': PW}).status_code, 200)
        self.assertEqual(post('/api/enclave/stepup/enroll', {'password': PW}).get_json()['stepup']['security_keys'], 1)
        o = post('/api/enclave/stepup/begin', {}).get_json()
        self.assertEqual((o['rpId'], o['allowCredentials']), (RP, [{'type': 'public-key', 'id': cred}]))
        a = self.assertion(key, cred, o['challenge'])
        sent = {'id': cred, 'authenticatorData': b64u(base64.b64decode(a['authenticator_data'])), 'clientDataJSON': b64u(base64.b64decode(a['client_data'])), 'signature': b64u(base64.b64decode(a['signature']))}
        self.assertEqual(post('/api/enclave/stepup', {'fido': sent}).status_code, 200)
        self.assertEqual(post('/api/enclave/stepup', {'fido': sent}).status_code, 403, 'the same answer twice')
        self.assertEqual(post('/api/keys', {'name': 'k'}).status_code, 201)
        self.assertEqual(post('/api/enclave/stepup', {'fido': {'id': cred}}).status_code, 400)

    def test_changing_the_account_password_changes_the_one_the_enclave_checks(self):
        web, c = self.web()
        self.assertEqual(c.post('/api/enclave/stepup/enroll', json={'password': PW}).status_code, 200)
        self.assertEqual(c.post('/api/me/password', json={'password': PW, 'new_password': ANN}).status_code, 200)
        c = self.signed_in(web, 'root', ANN)
        self.assertEqual(c.post('/api/enclave/stepup', json={'password': PW}).status_code, 403)
        self.assertEqual(c.post('/api/enclave/stepup', json={'password': ANN}).status_code, 200)
        self.assertEqual(self.audited('enclave.stepup.enroll'), ['ok', 'ok'])

    def test_the_command_enrolls_an_account_from_stdin_and_forgets_one(self):
        users.create(self.conn, 'root', PW, 'admin')
        os.environ['STORAGEFORGE_VAULT_SECRET'] = SECRET.decode()
        url = self.db.url

        def run(*args, stdin=''):
            out = io.StringIO()
            with mock.patch('sys.stdin', io.StringIO(stdin)), mock.patch('sys.stdout', out), mock.patch('sys.stderr', out):
                return cli.main(['--db', url, 'vault', *args]), out.getvalue()
        self.assertEqual(run('stepup-enroll', 'root', stdin=PW + '\n')[0], 0)
        self.assertEqual(run('stepup-enroll', 'root', stdin=ANN + '\n')[0], 0, 'again, on the vault secret')
        self.assertEqual(run('stepup-enroll', 'nobody', stdin=PW + '\n')[0], 2)
        code, said = run('stepup-enroll', 'root', stdin='short\n')
        self.assertEqual(code, 1)
        self.assertIn('at least 12', said)
        self.assertTrue(self.token('root', ANN))
        self.assertEqual(run('stepup-forget', 'root')[0], 0)
        self.assertIsNone(enclave_stepup.record_of(self.conn, 'root'))


class ShortTokens(Base):
    """The same program with tokens that last one second, which it takes on a socket file only."""
    ARGS = ('--token-seconds', '1')

    def test_a_token_runs_out_by_itself(self):
        self.assertEqual(self.stepup()['token_seconds'], 1)
        self.enroll()
        vault.present_token(self.token())
        self.make_key('in-time')
        self.assertEqual(self.stepup()['tokens'], 1)
        time.sleep(1.3)
        with self.assertRaises(vault.StepUpNeeded):
            self.make_key('too-late')

    def test_the_web_app_forgets_its_copy_when_the_token_has_run_out(self):
        users.create(self.conn, 'root', PW, 'admin')
        web = server.create_app(server.App(self.db), 's' * 48)
        c = web.test_client()
        self.assertEqual(c.post('/api/login', json={'username': 'root', 'password': PW}).status_code, 200)
        self.assertEqual(c.post('/api/enclave/stepup/enroll', json={'password': PW}).status_code, 200)
        self.assertEqual(c.post('/api/enclave/stepup', json={'password': PW}).status_code, 200)
        time.sleep(1.3)
        self.assertFalse(c.get('/api/enclave').get_json()['stepup']['fresh'])
        self.assertEqual(c.post('/api/keys', json={'name': 'k'}).get_json().get('stepup'), True)
