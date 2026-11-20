"""Unlocking the key enclave (roadmap section 14, "Unlock"; enclave_start.py): the starter that reads the secret file once and hands
it over, a server that takes the secret out of its own environment, and a person typing it on the Keys page. The real enclave
program on a socket file, as test_enclave.py runs it. What must hold: after any of the three the web app works with no secret of its
own, a starter never lifts a lock-down, and a container told the secret is kept apart refuses to start with one."""
import os
import shutil
import subprocess
import sys
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from storageforge_index import enclave, enclave_start, server, users, vault
from test_enclave import ROOT, SECRET, Harness

PW = 'a long enough password'
ENTRYPOINT = ROOT / 'docker' / 'entrypoint.sh'


class Unlock(Harness):
    def setUp(self):
        super().setUp()
        self.vault.close()
        self.secret_file = self.tmp / 'vault_secret'
        self.secret_file.write_text(SECRET.decode() + '\n')
        env = mock.patch.dict(os.environ, {'STORAGEFORGE_ENCLAVE': self.address, 'XDG_RUNTIME_DIR': str(self.tmp), 'STORAGEFORGE_ENCLAVE_RUN_DIR': str(self.tmp)})
        env.start()
        self.addCleanup(env.stop)
        for name in enclave_start.SECRET_ENVS:
            os.environ.pop(name, None)
        self.said = []

    def state(self):
        return self.e.status()['state']

    def lock_down(self):
        for _ in range(5):
            self.e.raw(b'not json')
            self.e.close()
        self.assertEqual(self.state(), 'lockdown')

    # ── the starter, apart ──
    def test_the_starter_hands_the_secret_from_its_file_and_the_web_app_then_needs_none(self):
        os.environ['STORAGEFORGE_VAULT_SECRET_FILE'] = str(self.secret_file)
        self.assertEqual(enclave_start.starter(self.db, self.address, wait=10, say=self.said.append), 0)
        self.assertEqual(self.state(), 'unlocked')
        self.assertEqual(self.said, ['starter: the key enclave is unlocked'])
        del os.environ['STORAGEFORGE_VAULT_SECRET_FILE']          # the web app: no secret, and no file
        with vault.Vault(self.db, self.conn).unlock() as v:
            self.assertTrue(v.generate_key('k')['public_key'].startswith('ssh-ed25519 '))
            self.assertIsNone(v._kek)

    def test_the_starter_finds_the_enclave_where_the_server_published_it(self):
        os.environ['STORAGEFORGE_VAULT_SECRET_FILE'] = str(self.secret_file)
        self.assertIsNone(enclave_start.published())
        self.assertEqual(enclave_start.starter(self.db, None, wait=0.2, say=self.said.append, pause=0.05), 1)
        self.assertIn('has not published its address', self.said[-1])
        enclave_start.publish(self.address)
        self.assertEqual(os.stat(enclave_start.address_file()).st_mode & 0o777, 0o600)
        self.assertEqual(enclave_start.starter(self.db, None, wait=10, say=self.said.append), 0)
        self.assertEqual(self.state(), 'unlocked')

    def test_the_starter_with_no_secret_or_the_wrong_one_unlocks_nothing_and_says_so(self):
        self.assertEqual(enclave_start.starter(self.db, self.address, wait=5, say=self.said.append), 2)
        self.assertIn('no vault secret here', self.said[-1])
        self.secret_file.write_text('w' * 48)
        os.environ['STORAGEFORGE_VAULT_SECRET_FILE'] = str(self.secret_file)
        self.assertEqual(enclave_start.starter(self.db, self.address, wait=5, say=self.said.append), 1)
        self.assertIn('wrong vault secret', self.said[-1])
        self.secret_file.write_text('short')
        self.assertEqual(enclave_start.starter(self.db, self.address, wait=5, say=self.said.append), 1)
        os.environ['STORAGEFORGE_VAULT_SECRET_FILE'] = str(self.tmp / 'nowhere')
        self.assertEqual(enclave_start.starter(self.db, self.address, wait=5, say=self.said.append), 1)
        self.assertIn('cannot be read', self.said[-1])
        self.assertEqual(self.state(), 'locked')

    def test_a_starter_never_lifts_a_lock_down_and_a_person_does(self):
        os.environ['STORAGEFORGE_VAULT_SECRET_FILE'] = str(self.secret_file)
        self.lock_down()
        self.assertEqual(enclave_start.starter(self.db, self.address, wait=5, say=self.said.append), 1)
        self.assertIn('a person unlocks it', self.said[-1])
        self.assertEqual(self.state(), 'lockdown')
        self.assertEqual(enclave_start.typed(self.db, self.conn, SECRET.decode()), 'unlocked')

    def test_a_watching_starter_unlocks_it_again_after_a_restart_and_keeps_nothing_between(self):
        os.environ['STORAGEFORGE_VAULT_SECRET_FILE'] = str(self.secret_file)
        done = []
        thread = threading.Thread(target=lambda: done.append(enclave_start.starter(self.db, self.address, watch=True, say=self.said.append, pause=0.05, rounds=150)), daemon=True)
        thread.start()
        self.wait_for('unlocked')
        until = time.time() + 20
        while not self.said and time.time() < until:          # it looks once more after handing over, and then says so
            time.sleep(0.02)
        self.stop()
        self.start()
        self.answering()
        self.wait_for('unlocked')
        thread.join(60)
        self.assertEqual((self.said, done), (['starter: the key enclave is unlocked'] * 2, [0]))
        self.assertEqual(done, [0])

    def wait_for(self, state, seconds=20):
        until = time.time() + seconds
        while time.time() < until:
            try:
                if self.state() == state:
                    return
            except enclave.EnclaveError:
                pass
            time.sleep(0.05)
        self.fail(f'the enclave did not become {state}')

    def test_the_starter_makes_the_vault_where_the_database_has_none(self):
        self.conn.execute('DELETE FROM vault_meta')
        os.environ['STORAGEFORGE_VAULT_SECRET_FILE'] = str(self.secret_file)
        self.assertEqual(enclave_start.starter(self.db, self.address, wait=10, say=self.said.append), 0)
        self.assertEqual(self.conn.scalar('SELECT count(*) FROM vault_meta'), 1)
        self.assertEqual(self.state(), 'unlocked')

    # ── the starter, in place: a server that was given the secret ──
    def test_a_server_given_the_secret_hands_it_over_and_takes_it_out_of_its_environment(self):
        os.environ['STORAGEFORGE_VAULT_SECRET'] = SECRET.decode()
        os.environ['STORAGEFORGE_VAULT_SECRET_FILE'] = str(self.secret_file)
        self.assertEqual(enclave_start.at_server_start(self.db), 'unlocked')
        self.assertNotIn('STORAGEFORGE_VAULT_SECRET', os.environ)
        self.assertNotIn('STORAGEFORGE_VAULT_SECRET_FILE', os.environ)
        self.assertEqual(enclave_start.published(), self.address)
        with self.assertRaises(vault.VaultLocked):
            vault.secret_from_env()
        with vault.Vault(self.db, self.conn).unlock() as v:          # and it works all the same
            self.assertEqual(v.enclave, self.address)

    def test_a_server_given_no_secret_starts_with_the_enclave_locked(self):
        self.assertEqual(enclave_start.at_server_start(self.db), 'locked')
        self.assertEqual(self.state(), 'locked')
        with mock.patch.dict(os.environ):
            del os.environ['STORAGEFORGE_ENCLAVE']
            self.assertIsNone(enclave_start.at_server_start(self.db), 'an installation without the enclave is left as it was')

    def test_a_server_whose_secret_came_from_a_file_unlocks_its_enclave_again_after_a_restart(self):
        os.environ['STORAGEFORGE_VAULT_SECRET_FILE'] = str(self.secret_file)
        self.assertEqual(enclave_start.at_server_start(self.db), 'unlocked')
        self.stop()
        self.start()
        self.answering()
        self.assertEqual(self.state(), 'locked')
        self.assertEqual(enclave_start.after_restart(self.db, self.address), 'unlocked')
        self.assertNotIn('STORAGEFORGE_VAULT_SECRET_FILE', os.environ)

    def test_scrubbing_overwrites_the_variable_where_proc_shows_it(self):
        """Taking a variable out of os.environ leaves its bytes in the block /proc/PID/environ reads. A real process looks at its own."""
        code = ('import os\nfrom storageforge_index import enclave_start\n'
                'before = open("/proc/self/environ", "rb").read().count(b"q" * 40)\n'
                'enclave_start.scrub_env("STORAGEFORGE_VAULT_SECRET")\n'
                'print(before, open("/proc/self/environ", "rb").read().count(b"q" * 40), "STORAGEFORGE_VAULT_SECRET" in os.environ)\n')
        got = subprocess.run([sys.executable, '-c', code], env={'PATH': os.environ['PATH'], 'PYTHONPATH': str(ROOT), 'STORAGEFORGE_VAULT_SECRET': 'q' * 40},
                             capture_output=True, text=True, timeout=60)
        self.assertEqual(got.stdout.split(), ['1', '0', 'False'], got.stderr)

    # ── a person, on the Keys page ──
    def web(self):
        users.create(self.conn, 'root', PW, 'admin')
        app = server.App(self.db)
        client = server.create_app(app, 's' * 48).test_client()
        self.assertEqual(client.post('/api/login', json={'username': 'root', 'password': PW}).status_code, 200)
        return app, client

    def audited(self, action):
        return [(r[0], r[1]) for r in self.conn.all('SELECT outcome, hash_alg FROM audit_log WHERE action = :a ORDER BY audit_id', {'a': action})]

    def test_a_person_types_the_secret_and_the_wrong_one_is_refused_and_both_are_audited(self):
        app, c = self.web()
        got = c.get('/api/enclave').get_json()
        self.assertEqual((got['on'], got['state'], got['label']), (True, 'locked', 'Key enclave: locked'))
        r = c.post('/api/enclave/unlock', json={'secret': 'w' * 48})
        self.assertEqual(r.status_code, 403)
        self.assertIn('wrong vault secret', r.get_json()['error'])
        self.assertEqual(c.post('/api/enclave/unlock', json={'secret': 'short'}).status_code, 400)
        self.assertEqual(self.state(), 'locked')
        r = c.post('/api/enclave/unlock', json={'secret': SECRET.decode()})
        self.assertEqual((r.status_code, r.get_json()['state']), (200, 'unlocked'))
        self.assertEqual(self.audited('enclave.unlock'), [('denied', 'sha256'), ('failed', 'sha256'), ('ok', 'hmac-sha256')],
                         'the entry written once it is unlocked is keyed again, with the key the enclave holds')
        self.assertNotIn(SECRET.decode(), ' '.join(str(r) for r in self.conn.all('SELECT detail_json FROM audit_log')))
        self.assertEqual(c.post('/api/keys', json={'name': 'k'}).status_code, 201, 'the web app was never given the secret, and makes a key')

    def test_a_person_lifts_a_lock_down_and_can_lock_it_again(self):
        app, c = self.web()
        self.lock_down()
        self.assertEqual(c.get('/api/enclave').get_json()['label'], 'Key enclave: locked down')
        self.assertEqual(c.post('/api/enclave/unlock', json={'secret': SECRET.decode()}).get_json()['state'], 'unlocked')
        r = c.post('/api/enclave/lock', json={})
        self.assertEqual((r.status_code, r.get_json()['state']), (200, 'locked'))
        self.assertEqual(self.audited('enclave.lock'), [('ok', 'hmac-sha256')], 'said before it locks, while the entry can be keyed')
        r = c.post('/api/keys', json={'name': 'k'})
        self.assertEqual(r.status_code, 400)
        self.assertIn('enclave is locked', r.get_json()['error'])

    def test_unlocking_takes_a_fresh_password_and_the_permission_to_manage_keys(self):
        app, c = self.web()
        with c.session_transaction() as s:
            s['auth_at'] = 0
        self.assertTrue(c.post('/api/enclave/unlock', json={'secret': SECRET.decode()}).get_json()['reauth'])
        users.create(self.conn, 'reader', PW, 'viewer')
        viewer = server.create_app(app, 's' * 48).test_client()
        self.assertEqual(viewer.post('/api/login', json={'username': 'reader', 'password': PW}).status_code, 200)
        self.assertEqual(viewer.get('/api/enclave').status_code, 200)
        self.assertEqual(viewer.post('/api/enclave/unlock', json={'secret': SECRET.decode()}).status_code, 403)
        self.assertEqual(self.state(), 'locked')

    def test_an_installation_without_the_enclave_says_so_and_why(self):
        from storageforge_index import enclave_vm
        with mock.patch.dict(os.environ):
            del os.environ['STORAGEFORGE_ENCLAVE']
            with mock.patch.object(enclave_vm, 'missing', lambda which=None: '/dev/kvm is not here or not usable by this account'):
                got = enclave.describe()
            self.assertEqual((got['on'], got['state'], got['vm_possible']), (False, 'off', False))
            self.assertIn('the extra layer is not there', got['detail'])
            self.assertIn('/dev/kvm is not here', got['detail'])
            with mock.patch.object(enclave_vm, 'missing', lambda which=None: None):
                self.assertIn('can run the enclave', enclave.describe()['detail'])
            with self.assertRaises(vault.VaultError):
                enclave_start.typed(self.db, self.conn, SECRET.decode())


@unittest.skipUnless(shutil.which('sh'), 'needs sh')
@unittest.skipIf(os.geteuid() == 0, 'the entrypoint refuses root')
class Container(unittest.TestCase):
    """docker/entrypoint.sh with the secret kept apart: the real script, with a stand-in for the program it starts."""

    def setUp(self):
        import tempfile
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        (self.tmp / 'bin').mkdir()
        (self.tmp / 'bin' / 'storageforge-index').write_text(f'#!/bin/sh\necho "$*" >>{self.tmp}/calls\n')
        (self.tmp / 'bin' / 'storageforge-index').chmod(0o755)
        for d in ('data', 'run', 'keys'):
            (self.tmp / d).mkdir()
        (self.tmp / 'keys' / 'fleet').write_text('a key\n')

    def start(self, *args, **more):
        (self.tmp / 'calls').unlink(missing_ok=True)
        env = {'PATH': f'{self.tmp}/bin:/usr/bin:/bin', 'STORAGEFORGE_DATA_DIR': f'{self.tmp}/data', 'STORAGEFORGE_RUNTIME_DIR': f'{self.tmp}/run',
               'STORAGEFORGE_ALLOW_DISK_RUNTIME': '1', 'STORAGEFORGE_IMPORT_DIR': f'{self.tmp}/keys', 'STORAGEFORGE_SESSION_SECRET': 's' * 40, **more}
        p = subprocess.run(['sh', str(ENTRYPOINT), *args], env=env, capture_output=True, text=True, timeout=30)
        calls = (self.tmp / 'calls').read_text().splitlines() if (self.tmp / 'calls').exists() else []
        return p.returncode, calls, p.stderr

    def test_a_server_whose_secret_is_apart_starts_without_one_and_opens_no_vault(self):
        rc, calls, err = self.start(STORAGEFORGE_VAULT_SECRET_APART='1', STORAGEFORGE_ENCLAVE='vm')
        self.assertEqual((rc, calls), (0, ['migrate', 'serve']), err)
        self.assertIn('the starter hands it to the key enclave', err)
        rc, calls, err = self.start(STORAGEFORGE_VAULT_SECRET_APART='1', STORAGEFORGE_ENCLAVE='vm', STORAGEFORGE_VAULT_SECRET_FILE='')
        self.assertEqual((rc, calls), (0, ['migrate', 'serve']), 'an empty file name, as the compose file sets it, is no secret')

    def test_it_refuses_a_secret_it_was_told_it_would_not_get_and_apart_without_an_enclave(self):
        rc, calls, err = self.start(STORAGEFORGE_VAULT_SECRET_APART='1', STORAGEFORGE_ENCLAVE='vm', STORAGEFORGE_VAULT_SECRET='v' * 40)
        self.assertEqual((rc, calls), (64, []))
        self.assertIn('not given the vault secret, and it is', err)
        rc, calls, err = self.start(STORAGEFORGE_VAULT_SECRET_APART='1')
        self.assertEqual((rc, calls), (64, []))
        self.assertIn('needs the key enclave', err)
        rc, calls, err = self.start()
        self.assertEqual((rc, calls), (64, []), 'and without either it still insists on a secret')

    def test_the_starter_neither_migrates_nor_opens_the_vault_before_it_runs(self):
        rc, calls, err = self.start('vault', 'starter', '--watch', STORAGEFORGE_VAULT_SECRET='v' * 40)
        self.assertEqual((rc, calls), (0, ['vault starter --watch']), err)
        rc, calls, err = self.start('vault', 'list', STORAGEFORGE_VAULT_SECRET='v' * 40)
        self.assertEqual(calls[:2], ['migrate', 'vault init'], 'any other vault command is prepared for as before')


if __name__ == '__main__':
    unittest.main()
