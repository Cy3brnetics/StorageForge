"""The key enclave's own limits and counts (roadmap section 14, "Its own limits"): the real enclave program on a socket file. What
must hold: each kind of task has an allowance of its own, on top of the one per key, and a count; secrets leave at most so often for
one kind of task; and the notification center opens on what the enclave itself counted, where the web app cannot change it, and
closes an hour after the count last moved."""
import os
import subprocess
import time
from unittest import mock

from storageforge_index import enclave, notifications, runner, vault
from test_enclave_stepup import Base


class Counts(Base):
    def setUp(self):
        super().setUp()
        enclave._looks.clear()
        self.addCleanup(enclave._looks.clear)
        self.v = vault.Vault(self.db, self.conn).unlock()
        self.addCleanup(self.v.close)

    def tasks(self):
        return self.e.status()['tasks']

    def test_each_kind_of_task_has_an_allowance_and_a_count_of_its_own(self):
        self.v.generate_key('k')
        row = self.row('k')
        codes, started = [], time.time()
        for _ in range(400):
            try:
                self.e.sign(row, b'x', 0, 'console')
                codes.append('ok')
            except enclave.EnclaveError as exc:
                codes.append(exc.code)
                self.assertIn('console tasks have signed as often', str(exc))
                break
        earned = int((time.time() - started) * 2) + 1          # two more a second, and a slow machine takes a few seconds over this
        self.assertEqual(codes[-1], 'rate', '120 a minute for consoles, and the web app cannot raise it')
        self.assertTrue(118 <= codes.count('ok') <= 120 + earned, codes.count('ok'))
        self.assertTrue(self.e.sign(row, b'x', 0, 'scan')[0], 'what consoles used up is not taken from scans, with the same key')
        self.assertTrue(self.e.sign(row, b'x', 0, 'a kind nobody listed')[0])
        self.assertTrue(self.e.sign(row, b'x')[0])
        got = self.tasks()
        self.assertEqual(got['console']['signed'], codes.count('ok'))
        self.assertEqual(got['console']['refused'], codes.count('rate'))
        self.assertEqual((got['scan'], got['other']), ({'signed': 1, 'refused': 0}, {'signed': 2, 'refused': 0}))
        limits = self.e.status()['limits']
        self.assertEqual((limits['sign_per_task_per_minute']['console'], limits['sign_per_task_per_minute']['scan'], limits['releases_per_hour']), (120.0, 1200.0, 600.0))

    def test_a_task_signs_as_its_own_kind_through_the_agent_socket(self):
        self.v.generate_key('k')
        row = self.row('k')
        pub = self.tmp / 'k.pub'
        pub.write_text(row['public_key'] + '\n')
        for key in (self.v.decrypt_key(row['key_id'], 'deploy'), runner._for_scans(self.v.decrypt_key(row['key_id'])), self.v.decrypt_key(row['key_id'])):
            with runner.ephemeral_agent(key, ttl=30) as sock:
                done = subprocess.run(['ssh-add', '-T', str(pub)], env={'PATH': os.environ['PATH'], 'SSH_AUTH_SOCK': sock}, capture_output=True, text=True)
                self.assertEqual(done.returncode, 0, done.stderr)
        got = self.tasks()
        self.assertEqual(sorted(got), ['deploy', 'other', 'scan'])
        self.assertTrue(all(t['signed'] >= 1 for t in got.values()))

    def test_secrets_leave_only_so_often_for_one_kind_of_task(self):
        for name in ('a', 'b', 'c', 'd'):          # four, so that no one of them reaches its own sixty a minute first
            self.v.store_credential(name, 'secret', f'secret-{name}-123456')
        codes, started = [], time.time()
        for i in range(400):
            try:
                self.v.credential('abcd'[i % 4], host=f'nas{i}', step='tailscale')
                codes.append('ok')
            except vault.VaultLocked as exc:
                codes.append('rate')
                self.assertIn('that kind of task', str(exc))
                break
        earned = int((time.time() - started) * 2) + 1
        self.assertEqual(codes[-1], 'rate', '120 a minute for one kind of step, however many secrets it is spread over')
        self.assertTrue(118 <= codes.count('ok') <= 120 + earned, codes.count('ok'))
        self.assertEqual(self.v.credential('a', host='nas1', step='netbird')['password'], 'secret-a-123456', 'another kind of step has its own')
        self.assertGreaterEqual(self.e.status()['refused'], 1)

    def test_the_notification_center_opens_on_what_the_enclave_counted_and_none_of_it_can_be_muted(self):
        self.assertEqual(enclave.problems(), {})
        self.v.generate_key('k')
        row = self.row('k')
        self.v.store_credential('ts', 'secret', 'tskey-auth-123456', policy={'hosts': ['nas1']})
        with self.assertRaises(vault.NotReleased):
            self.v.credential('ts', host='nas9')
        for _ in range(3):                                                    # ciphertexts that were changed: someone trying things
            self.refused('auth', self.e.sign, {**row, 'ciphertext': bytes(b ^ 1 for b in row['ciphertext'])}, b'x')
        self.e.raw(b'not json')
        self.e.close()
        got = enclave.problems()
        self.assertEqual(sorted(got), ['security-enclave-malformed', 'security-enclave-policy', 'security-enclave-probed'])
        kind, ref, title, detail, level = got['security-enclave-probed']
        self.assertEqual((ref, level), ('enclave', 'warn'))
        self.assertIn('3 in the last hour did not authenticate', detail)
        self.assertIn('1 of the 5', got['security-enclave-malformed'][3])
        for kind, entry in got.items():
            self.assertEqual(kind, entry[0])
            self.assertFalse(notifications.ignorable(kind, entry[4]), kind)
        for _ in range(17):
            self.refused('auth', self.e.sign, {**row, 'ciphertext': bytes(b ^ 1 for b in row['ciphertext'])}, b'x')
        self.assertEqual(enclave.problems()['security-enclave-probed'][4], 'crit', 'twenty in an hour is critical')

    def test_a_count_that_stopped_moving_leaves_after_an_hour_and_a_restart_starts_again(self):
        self.v.store_credential('ts', 'secret', 'tskey-auth-123456', policy={'hosts': ['nas1']})
        with self.assertRaises(vault.NotReleased):
            self.v.credential('ts', host='nas9')
        self.assertIn('security-enclave-policy', enclave.problems())
        now = time.time()
        with mock.patch.object(enclave.time, 'time', lambda: now + 1800):
            self.assertIn('security-enclave-policy', enclave.problems(), 'half an hour on it is still within the hour')
        with mock.patch.object(enclave.time, 'time', lambda: now + 3700):
            self.assertEqual(enclave.problems(), {}, 'nothing moved for an hour')
            with self.assertRaises(vault.NotReleased):
                self.v.credential('ts', host='nas9')
            self.assertIn('1 in the last hour', enclave.problems()['security-enclave-policy'][3])
        self.stop()
        self.start()
        self.answering()
        self.unlock()
        self.assertEqual(enclave.problems(), {}, 'a restarted enclave counts from nothing, and so does what is remembered of it')

    def test_an_enclave_that_has_run_for_longer_than_an_hour_is_counted_from_the_first_look(self):
        status = {**self.e.status(), 'uptime': 90000, 'refused': 40, 'released': 5000}
        self.assertEqual(enclave.risen('unix:elsewhere', status)['refused'], 0)
        self.assertEqual(enclave.risen('unix:elsewhere', {**status, 'refused': 42})['refused'], 2)

    def test_a_cut_audit_log_and_a_release_that_was_not_written_are_notifications(self):
        log = vault.AuditLog(self.db, self.conn, self.v.audit_key)
        self.v.store_credential('ts', 'secret', 'tskey-auth-123456')
        log.append('gabe', 'one', 'ok')
        row = self.conn.all("SELECT cred_uuid, dek_nonce, wrapped_dek, nonce, ciphertext FROM device_credentials WHERE name = 'ts'")[0]
        sealed = {'dek_nonce': bytes(row[1]), 'wrapped_dek': bytes(row[2]), 'nonce': bytes(row[3]), 'ciphertext': bytes(row[4])}
        self.e.release(row[0], sealed, {'host': 'stolen'}, 1, self.e.chain()['head'])          # released, and the entry kept back
        log.append('gabe', 'two', 'ok')
        got = enclave.problems()
        self.assertEqual(got['security-enclave-audit-release'][4], 'crit')
        self.assertEqual(got['security-enclave-audit-unwritten'][4], 'warn')
        for i in range(3):
            log.append('gabe', f'more{i}', 'ok')
        for trigger in ('audit_log_no_update', 'audit_log_no_delete') if self.db.dialect == 'sqlite' else ('audit_log_no_update',):
            self.conn.execute(f'DROP TRIGGER {trigger}' + ('' if self.db.dialect == 'sqlite' else ' ON audit_log'))
        first = self.conn.scalar('SELECT min(audit_id) FROM audit_log')
        self.conn.execute('DELETE FROM audit_log WHERE audit_id > :k', {'k': first})
        log.append('gabe', 'after the cut', 'ok')
        self.assertEqual(enclave.problems()['security-enclave-audit'][4], 'crit')
