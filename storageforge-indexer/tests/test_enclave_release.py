"""Secrets that leave the key enclave, and the audit log's head it keeps (roadmap section 14; vault.py). The real enclave program on a
socket file. What must hold: a secret with a policy is released only for the step, host or platform the policy names, and the policy
cannot be changed or left out in the database; a secret marked sensitive takes a step-up the enclave checks; every release is an entry
of the audit log that the enclave wrote and signed, which today's vault verifies byte for byte; a release that is not written, and a
log that was cut short, no longer end where the enclave says, and nothing is released into a cut log until a person accepts it."""
import io
import json
import os
from unittest import mock

from storageforge_index import cli, enclave, enclave_stepup, server, users, vault
from test_enclave import SECRET
from test_enclave_stepup import PW, Base


class Release(Base):
    def setUp(self):
        super().setUp()
        self.v = vault.Vault(self.db, self.conn).unlock()
        self.addCleanup(self.v.close)
        self.log = vault.AuditLog(self.db, self.conn, self.v.audit_key)

    def entries(self, action='enclave.release'):
        return [{'actor': r[0], 'outcome': r[1], 'host': r[2], 'alg': r[4], **json.loads(r[3])}
                for r in self.conn.all('SELECT actor, outcome, target_host, detail_json, hash_alg FROM audit_log WHERE action = :a ORDER BY audit_id', {'a': action})]

    def chain(self):
        return self.e.chain()

    def uuid_of(self, name):
        return self.conn.scalar('SELECT cred_uuid FROM device_credentials WHERE name = :n', {'n': name})

    def cut(self, keep):
        """What someone who holds the database does: the triggers off, and the log's last entries gone."""
        for trigger in ('audit_log_no_update', 'audit_log_no_delete') if self.db.dialect == 'sqlite' else ('audit_log_no_update',):
            self.conn.execute(f'DROP TRIGGER {trigger}' + ('' if self.db.dialect == 'sqlite' else ' ON audit_log'))
        ids = [r[0] for r in self.conn.all('SELECT audit_id FROM audit_log ORDER BY audit_id')]
        self.conn.execute('DELETE FROM audit_log WHERE audit_id > :k', {'k': ids[keep - 1]})

    # ── a release is for something named ──
    def test_a_secret_with_a_policy_is_released_only_for_what_it_names(self):
        made = self.v.store_credential('ts', 'secret', 'tskey-auth-123456', policy={'steps': ['tailscale'], 'hosts': ['nas2', 'nas1']})
        self.assertEqual(made['policy'], {'hosts': ['nas1', 'nas2'], 'platforms': [], 'sensitive': False, 'steps': ['tailscale']})
        self.assertEqual(self.v.credential('ts', host='nas1', step='tailscale')['password'], 'tskey-auth-123456')
        for named in ({'host': 'nas3', 'step': 'tailscale'}, {'host': 'nas1', 'step': 'netbird'}, {'host': 'nas1'}, {'step': 'tailscale'}, {}, {'platform': 'routeros'}):
            with self.assertRaises(vault.NotReleased, msg=named) as got:
                self.v.credential('ts', **named)
            self.assertIn('its policy names', str(got.exception))
        self.v.store_credential('router', 'admin', 'pw-123456', policy={'platforms': ['routeros']})
        self.assertEqual(self.v.credential('router', host='anything', platform='routeros')['password'], 'pw-123456')
        with self.assertRaises(vault.NotReleased):
            self.v.credential('router', host='anything', platform='openwrt')
        self.assertEqual(self.e.status()['released'], 2)
        self.assertEqual([c['policy'] and c['policy']['steps'] for c in self.v.list_credentials()], [[], ['tailscale']])

    def test_a_secret_without_a_policy_is_released_for_any_named_request_as_before(self):
        self.v.store_credential('old', 'admin', 'pw-123456')
        self.assertIsNone(self.conn.scalar("SELECT policy_json FROM device_credentials WHERE name = 'old'"))
        self.assertEqual(self.v.credential('old', host='sw1', platform='cisco')['password'], 'pw-123456')
        self.assertEqual(self.v.credential('old')['password'], 'pw-123456')
        self.assertEqual([e['for'] for e in self.entries()], [{'host': 'sw1', 'platform': 'cisco', 'step': ''}, {'host': '', 'platform': '', 'step': 'unnamed'}])
        row = self.conn.all("SELECT cred_uuid, dek_nonce, wrapped_dek, nonce, ciphertext FROM device_credentials WHERE name = 'old'")[0]
        sealed = {'dek_nonce': bytes(row[1]), 'wrapped_dek': bytes(row[2]), 'nonce': bytes(row[3]), 'ciphertext': bytes(row[4])}
        self.e.close()
        self.refused('bad-request', self.e.release, row[0], sealed, {}, 1, self.chain()['head'])                 # for nothing at all
        self.e.close()
        self.refused('bad-request', self.e.release, row[0], sealed, {'host': 'a host"with a quote'}, 1, '0' * 64)

    def test_the_policy_cannot_be_changed_or_left_out_in_the_database(self):
        self.v.store_credential('ts', 'secret', 'tskey-auth-123456', policy={'hosts': ['nas1'], 'sensitive': True})
        was = self.conn.scalar("SELECT policy_json FROM device_credentials WHERE name = 'ts'")
        for forged in (vault.policy_text({'hosts': ['evil'], 'sensitive': True}), vault.policy_text({'hosts': ['nas1']}), vault.policy_text({}), None):
            self.conn.execute("UPDATE device_credentials SET policy_json = :p WHERE name = 'ts'", {'p': forged})
            with self.assertRaises(vault.VaultLocked, msg=forged):                 # it does not open: the policy is in what was sealed
                self.v.credential('ts', host='evil' if forged and 'evil' in forged else 'nas1')
        self.conn.execute("UPDATE device_credentials SET policy_json = :p WHERE name = 'ts'", {'p': was.replace(',', ', ')})
        with self.assertRaises(vault.VaultLocked):                                 # the same policy written another way is not the text that was sealed
            self.v.credential('ts', host='nas1')
        self.assertEqual(self.e.status()['released'], 0)
        with self.assertRaises(vault.VaultError):
            self.v.store_credential('bad', 'x', 'pw-123456', policy={'hosts': ['a b']})
        with self.assertRaises(vault.VaultError):
            self.v.store_credential('bad', 'x', 'pw-123456', policy={'hosts': [], 'anything': 1})

    def test_a_sensitive_secret_takes_a_step_up_the_enclave_checks_and_the_entry_says_who(self):
        self.v.store_credential('token', 'secret', 'api-token-123456', policy={'platforms': ['pve'], 'sensitive': True})
        with self.assertRaises(vault.StepUpNeeded):                                # nobody is enrolled: the web app's word is not a step-up
            self.v.credential('token', platform='pve')
        enclave_stepup.enroll(self.conn, self.address, 'gabe', PW)
        with self.assertRaises(vault.StepUpNeeded):
            self.v.credential('token', platform='pve')
        vault.present_token(enclave_stepup.check(self.conn, self.address, 'gabe', password=PW)['token'])
        self.assertEqual(self.v.credential('token', platform='pve')['password'], 'api-token-123456')
        with self.assertRaises(vault.NotReleased):
            self.v.credential('token', platform='pbs')
        made = self.entries()
        self.assertEqual([(e['actor'], e['outcome'], e.get('who'), e.get('why')) for e in made],
                         [('vault', 'denied', None, 'step-up'), ('vault', 'denied', None, 'step-up'), ('enclave', 'ok', 'gabe', None), ('vault', 'denied', None, 'policy')])
        self.assertNotIn('api-token-123456', ' '.join(str(r[0]) for r in self.conn.all('SELECT detail_json FROM audit_log')))

    # ── each release is in the audit log, written from inside ──
    def test_the_enclave_writes_each_release_into_the_log_and_todays_vault_verifies_it(self):
        self.v.store_credential('ts', 'secret', 'tskey-auth-123456', policy={'hosts': ['nas1']})
        self.log.append('gabe', 'before', 'ok')
        for _ in range(3):
            self.v.credential('ts', host='nas1', step='tailscale')
        self.log.append('gabe', 'after', 'ok', 'nas1', None, {'n': 1})
        made = self.entries()
        self.assertEqual([(e['actor'], e['outcome'], e['host'], e['alg'], e['n'], e['sensitive'], e['secret']) for e in made],
                         [('enclave', 'ok', 'nas1', 'hmac-sha256', n, False, self.uuid_of('ts')) for n in (1, 2, 3)])
        self.assertEqual(made[0]['for'], {'host': 'nas1', 'platform': '', 'step': 'tailscale'})
        self.assertEqual(self.log.verify()[:2], (True, 5), 'the chain is one chain: the entries the enclave made follow and are followed')
        with vault.Vault(self.db, self.conn, SECRET).unlock() as old:           # and Python computes the same bytes the enclave signed
            self.assertEqual(vault.AuditLog(self.db, self.conn, old.audit_key).verify()[:2], (True, 5))
        self.assertEqual(self.log.head_check()['ok'], True)
        self.assertEqual((self.chain()['appended'], self.chain()['unwritten']), (5, 0))

    def test_a_release_that_is_not_written_to_the_log_is_noticed(self):
        """A web app that has been taken over asks the socket itself and keeps the entry to itself."""
        self.v.store_credential('ts', 'secret', 'tskey-auth-123456')
        self.log.append('gabe', 'before', 'ok')
        row = self.conn.all("SELECT cred_uuid, dek_nonce, wrapped_dek, nonce, ciphertext FROM device_credentials WHERE name = 'ts'")[0]
        sealed = {'dek_nonce': bytes(row[1]), 'wrapped_dek': bytes(row[2]), 'nonce': bytes(row[3]), 'ciphertext': bytes(row[4])}
        plain, entry = self.e.release(row[0], sealed, {'host': 'stolen'}, 1, self.chain()['head'])
        self.assertIn(b'tskey-auth-123456', plain)
        check = self.log.head_check()
        self.assertEqual(check['ok'], False)
        self.assertIn('released a secret and the entry it made for that is not in the log', check['why'])
        self.log.append('gabe', 'after', 'ok')                                    # the log goes on from the entry before
        self.assertEqual((self.chain()['unwritten'], self.chain()['releases_unwritten']), (1, 1), 'and the enclave has counted it, where the web app cannot reach')
        self.assertEqual(self.log.verify()[0], True)

    def test_an_entry_whose_write_failed_is_counted_and_is_not_a_cut(self):
        self.log.append('gabe', 'one', 'ok')
        real = self.conn.execute

        def fails(sql, *a, **kw):
            if 'INSERT INTO audit_log' in sql:
                raise RuntimeError('the disk is full')
            return real(sql, *a, **kw)
        with mock.patch.object(self.conn, 'execute', fails), self.assertRaises(RuntimeError):
            self.log.append('gabe', 'lost', 'ok')
        self.assertEqual(self.log.head_check()['ok'], True)
        self.assertIn('was not written', self.log.head_check()['why'])
        self.log.append('gabe', 'two', 'ok')
        self.assertEqual((self.chain()['unwritten'], self.chain()['releases_unwritten'], self.chain()['behind']), (1, 0, False))
        self.assertEqual(self.log.verify()[:2], (True, 2))

    # ── the head ──
    def test_a_log_cut_short_no_longer_ends_where_the_enclave_signed_it(self):
        self.v.store_credential('ts', 'secret', 'tskey-auth-123456')
        for i in range(6):
            self.log.append('gabe', f'entry{i}', 'ok')
        self.assertEqual(self.log.head_check()['ok'], True)
        self.cut(keep=3)
        self.assertEqual(self.log.verify()[:2], (True, 3), 'what is left is a chain that verifies: that is what a cut log looks like')
        check = self.log.head_check()
        self.assertEqual(check['ok'], False)
        self.assertIn('entries were removed', check['why'])
        self.log.append('gabe', 'afterwards', 'ok')                              # the log still takes entries, and keyed ones
        self.assertEqual(self.conn.scalar("SELECT hash_alg FROM audit_log WHERE action = 'afterwards'"), 'hmac-sha256')
        self.assertTrue(self.chain()['behind'])
        self.assertEqual(self.log.head_check()['ok'], False, 'writing more does not make the enclave forget')
        with self.assertRaises(vault.ChainBroken):                                # and no secret is released into a log that was cut
            self.v.credential('ts', host='nas1')
        self.assertEqual(self.e.status()['released'], 0)
        self.log.accept_head()                                                    # a person, after looking
        self.assertEqual((self.log.head_check()['ok'], self.chain()['behind']), (True, False))
        self.assertEqual(self.v.credential('ts', host='nas1')['password'], 'tskey-auth-123456')

    def test_cutting_one_entry_looks_like_a_write_that_failed_and_is_counted(self):
        for i in range(3):
            self.log.append('gabe', f'entry{i}', 'ok')
        self.cut(keep=2)
        self.assertIn('was not written', self.log.head_check()['why'])
        self.log.append('gabe', 'next', 'ok')
        self.assertEqual(self.chain()['unwritten'], 1)

    def test_entries_others_wrote_are_led_past_the_head_and_a_changed_one_is_not(self):
        self.log.append('gabe', 'through the enclave', 'ok')
        with vault.Vault(self.db, self.conn, SECRET).unlock() as old:           # a command that holds the secret, with the key in its own hands
            vault.AuditLog(self.db, self.conn, old.audit_key).append('cli:gabe', 'beside it', 'ok')
        vault.AuditLog(self.db, self.conn, None).append('system', 'while locked', 'ok')          # and one chained without the key
        self.log.append('gabe', 'through the enclave again', 'ok')
        self.assertEqual((self.chain()['taken_in'], self.chain()['appended'], self.chain()['behind']), (2, 2, False))
        self.assertEqual((self.log.verify()[:2], self.log.head_check()['ok']), ((True, 4), True))
        with vault.Vault(self.db, self.conn, SECRET).unlock() as old:
            vault.AuditLog(self.db, self.conn, old.audit_key).append('cli:gabe', 'to be changed', 'ok')
        self.conn.execute('DROP TRIGGER audit_log_no_update' + ('' if self.db.dialect == 'sqlite' else ' ON audit_log'))
        self.conn.execute("UPDATE audit_log SET actor = 'someone else' WHERE action = 'to be changed'")
        check = self.log.head_check()
        self.assertEqual(check['ok'], False)
        self.assertIn('does not follow the one before it', check['why'])

    def test_after_a_restart_the_enclave_takes_the_log_as_it_finds_it(self):
        """The limit the docs name: the head is in memory, and a restart forgets it."""
        self.log.append('gabe', 'one', 'ok')
        self.stop()
        self.start()
        self.answering()
        self.unlock()
        self.assertIsNone(self.chain()['head'])
        self.assertIn('takes the log as it finds it', self.log.head_check()['why'])
        self.log.append('gabe', 'two', 'ok')
        self.assertEqual(self.log.head_check()['ok'], True)

    # ── with and without the enclave, the same secrets ──
    def test_a_policy_sealed_without_the_enclave_holds_inside_it_and_the_other_way_round(self):
        with vault.Vault(self.db, self.conn, SECRET).unlock() as old:
            old.store_credential('here', 'secret', 'made-here-123456', policy={'hosts': ['nas1']})
            self.v.store_credential('inside', 'secret', 'made-inside-123456', policy={'hosts': ['nas1'], 'steps': ['tailscale']})
            self.assertEqual(old.credential('inside', host='nas1', step='tailscale')['password'], 'made-inside-123456')
            with self.assertRaises(vault.NotReleased):
                old.credential('inside', host='nas2', step='tailscale')
        self.assertEqual(self.v.credential('here', host='nas1')['password'], 'made-here-123456')
        with self.assertRaises(vault.NotReleased):
            self.v.credential('here', host='nas2')

    def test_the_command_stores_a_secret_with_a_policy_and_takes_it_off_again(self):
        os.environ['STORAGEFORGE_VAULT_SECRET'] = SECRET.decode()

        def run(*args, stdin=''):
            out = io.StringIO()
            with mock.patch('sys.stdin', io.StringIO(stdin)), mock.patch('sys.stdout', out), mock.patch('sys.stderr', out):
                return cli.main(['--db', self.db.url, 'vault', *args]), out.getvalue()
        self.assertEqual(run('secret-add', 'ts', '--step', 'tailscale', '--for-host', 'nas1', stdin='tskey-auth-123456\n')[0], 0)
        self.assertEqual(json.loads(run('secret-policy', 'ts')[1]), {'hosts': ['nas1'], 'platforms': [], 'sensitive': False, 'steps': ['tailscale']})
        with self.assertRaises(vault.NotReleased):
            self.v.credential('ts', host='nas2', step='tailscale')
        code, said = run('secret-policy', 'ts', '--none')
        self.assertEqual((code, said.strip()), (0, 'ts: no policy now'))
        self.assertIsNone(self.conn.scalar("SELECT policy_json FROM device_credentials WHERE name = 'ts'"))
        self.assertEqual(self.v.credential('ts', host='nas2')['password'], 'tskey-auth-123456', 'the way back: a secret as 0.5.4 stored it')
        self.assertEqual(run('secret-policy', 'ts', '--for-host', 'nas9', '--sensitive')[0], 0)
        self.assertTrue(self.v.list_credentials()[0]['policy']['sensitive'])
        self.assertEqual(run('secret-policy', 'nothing')[0], 1)

    # ── the web app ──
    def test_verifying_the_chain_says_whether_the_log_ends_where_the_enclave_signed_it(self):
        users.create(self.conn, 'root', PW, 'admin')
        c = server.create_app(server.App(self.db), 's' * 48).test_client()
        self.assertEqual(c.post('/api/login', json={'username': 'root', 'password': PW}).status_code, 200)
        for i in range(4):
            self.assertEqual(c.post('/api/keys', json={'name': f'k{i}'}).status_code, 201)          # each is an entry the server wrote through the enclave
        got = c.get('/api/audit/verify').get_json()
        self.assertEqual((got['valid'], got['head']['enclave'], got['head']['ok']), (True, True, True))
        n = self.conn.scalar('SELECT count(*) FROM audit_log')
        self.assertGreaterEqual(n, 5)
        self.cut(keep=n - 2)
        got = c.get('/api/audit/verify').get_json()
        self.assertEqual((got['valid'], got['first_bad_id'], got['head']['ok']), (False, None, False))
        self.assertTrue(c.get('/api/enclave').get_json()['chain']['behind'])
        r = c.post('/api/enclave/chain/accept', json={})
        self.assertEqual((r.status_code, r.get_json()['head']['ok']), (200, True))
        self.assertEqual(self.conn.scalar("SELECT count(*) FROM audit_log WHERE action = 'audit.head.accept'"), 1)
        self.assertEqual(c.get('/api/audit/verify').get_json()['valid'], True)
