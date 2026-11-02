"""Small fixes from the 2026-11-01 code audit that have no better home."""
import os
import socket
import subprocess
import tempfile
import time
import unittest
from unittest import mock

from storageforge_index import (alerts, changes, confirm, deploy, fromdesign, gitrepos, jobs, logbook, moves, preflight, reset, retire,
                                scheduler, server, shares)
from storageforge_index.db import Database
from storageforge_index.stream import decode


class Locks(unittest.TestCase):
    def test_no_lock_in_a_folder_anyone_can_write(self):
        for module in (changes, moves):
            with open(module.__file__) as f:
                self.assertNotIn('exec 9>"/tmp/', f.read())


class Period(unittest.TestCase):
    def test_a_calendar_it_cannot_read_counts_as_daily(self):
        for odd in ('*-*-* *:5/x:00', '*-*-* 1/y:00:00'):
            self.assertTrue(moves.CALENDAR_RE.fullmatch(odd))
            self.assertEqual(jobs.period(odd), jobs.DAY)
        self.assertEqual(jobs.period('*-*-* *:5/15:00'), 900)


class Cache(unittest.TestCase):
    def test_only_the_oldest_goes(self):
        cache = {}
        for i in range(9):
            server.remember(cache, (i, 7), i, 7, keep=8)
        self.assertEqual(sorted(k[0] for k in cache), list(range(1, 9)))

    def test_a_new_scan_clears_the_old(self):
        cache = {('a', 7): 1}
        server.remember(cache, ('b', 8), 2, 8)
        self.assertEqual(cache, {('b', 8): 2})


class HostLogFilter(unittest.TestCase):
    def test_a_rare_outcome_is_found_behind_newer_rows(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Database(f'sqlite:///{tmp}/t.db')
            conn = db.connect()
            db.migrate(conn)
            insert = "INSERT INTO host_logs (log_key, host, kind, ref, reason, state, found_at) VALUES (:k, 'h', 'deploy', 'r', 'x', :s, :t)"
            conn.execute(insert, {'k': 'old', 's': 'failed', 't': 1})
            for i in range(5):
                conn.execute(insert, {'k': f'n{i}', 's': 'fetched', 't': 100 + i})
            f = logbook.clean_filter(sources='hostlog', outcomes='failed')
            self.assertEqual([e['id'] for e in logbook.entries(conn, f, limit=2)], ['hostlog:old'])
            conn.close()


class MoveFailures(unittest.TestCase):
    """The generated move script, run for real, with only the root check and its folders changed."""

    def run_script(self, method='copy', args=('--run',), source='missing', prepare=None):
        with tempfile.TemporaryDirectory() as tmp:
            db = Database(f'sqlite:///{tmp}/t.db')
            conn = db.connect()
            db.migrate(conn)
            me = moves.host_slug(socket.gethostname())
            conn.execute("INSERT INTO hosts (hostname, ssh_host, inventory_json) VALUES (:h, '127.0.0.1', '{}')", {'h': me})
            os.mkdir(f'{tmp}/dst')
            if prepare:
                prepare(tmp)
            text = moves.script(conn, {'name': 'p', 'steps': [{'method': method, 'src': {'host': me, 'path': f'{tmp}/{source}'},
                                                               'dst': {'host': me, 'path': f'{tmp}/dst'}, 'options': {'one_fs': False, 'link_back': False}}]})
            conn.close()
            text = (text.replace('$EUID -ne 0', '1 -eq 0').replace('LOG_DIR=/var/log/storageforge', f'LOG_DIR={tmp}/log')
                    .replace('STATE=/var/lib/storageforge/moves/$PLAN', f'STATE={tmp}/state').replace('/run/lock/', f'{tmp}/'))
            with open(f'{tmp}/m.sh', 'w') as f:
                f.write(text)
            p = subprocess.run(['bash', f'{tmp}/m.sh', *args], capture_output=True, text=True, timeout=60)
            return p, os.path.exists(f'{tmp}/state/0.done')

    def test_a_failed_copy_is_not_reported_as_copied(self):
        p, done = self.run_script()
        self.assertEqual(p.returncode, 1, p.stdout)
        self.assertIn('rsync failed', p.stdout)         # what a schedule's verification looks for
        self.assertNotIn('ok        copied', p.stdout)
        self.assertFalse(done)

    def test_a_good_copy_still_is(self):
        def prepare(tmp):
            os.mkdir(f'{tmp}/src')
            with open(f'{tmp}/src/a', 'w') as f:
                f.write('x')
        p, done = self.run_script(source='src', prepare=prepare)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertTrue(done)

    def test_a_failed_git_step_is_not_reported(self):
        p, done = self.run_script(method='git')
        self.assertEqual(p.returncode, 1, p.stdout)
        self.assertFalse(done)


class Db(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = Database(f'sqlite:///{self.tmp.name}/t.db')
        self.conn = self.db.connect()
        self.addCleanup(self.conn.close)
        self.db.migrate(self.conn)
        self.conn.execute("INSERT INTO hosts (hostname, ssh_host, ip_address, inventory_json) VALUES ('nas', '10.0.0.5', '192.168.1.10', '{}')")

    def run_row(self, status='running', kind='jobs', nonce='a' * 32, started=None):
        return self.conn.scalar("""INSERT INTO deploy_runs (group_id, host, kind, ref, mode, status, actor, started_at, nonce)
                                   VALUES ('g', 'nas', :k, 'r', 'apply', :s, 'a', :t, :n) RETURNING run_id""",
                                {'k': kind, 's': status, 't': started or int(time.time()), 'n': nonce})

    def test_a_saved_check_does_not_block_deploys_later(self):
        now = int(time.time())
        facts = preflight.parse_probe(f'clock={now}\ninit=systemd\nbash=5\nopenssh=9.6\nsudo=1\n')
        preflight.save(self.conn, 'nas', 'probe', facts, [], 't')
        with mock.patch('time.time', return_value=now + 3600):
            self.assertEqual(preflight.blockers(self.conn, ['nas'], 'jobs'), [])

    def test_a_clock_that_was_off_when_checked_still_blocks(self):
        now = int(time.time())
        preflight.save(self.conn, 'nas', 'probe', preflight.parse_probe(f'clock={now - 900}\n'), [], 't')
        self.assertTrue(preflight.blockers(self.conn, ['nas'], 'jobs'))

    def test_a_run_under_way_is_not_marked_absent(self):
        self.run_row(started=int(time.time()) - 900)
        with deploy._track('a' * 32):
            self.assertEqual(confirm.ingest_runs(self.conn, 'nas', '{"nonce":"%s","rc":0}' % ('b' * 32)), [])
        self.assertEqual(len(confirm.ingest_runs(self.conn, 'nas', '{"nonce":"%s","rc":0}' % ('b' * 32))), 1)    # one that really vanished

    def test_failed_log_fetches_make_no_more_of_themselves(self):
        self.conn.execute("INSERT INTO deploy_access (host, state, detail, updated_at, updated_by) VALUES ('nas', 'ready', '', 1, 'a')")
        self.run_row('failed')
        made = []

        def failing(db, host, script, **kw):
            made.append(self.run_row('failed', kw['kind'], f'{len(made) + 1:032x}'))
            return {'run_id': made[-1], 'status': 'failed', 'output': 'refused'}
        with mock.patch.object(deploy, 'run', failing):
            for _ in range(4):
                confirm.fetch_problem_logs(self.db, self.conn, 'nas', [])
        self.assertEqual(len(made), 1)

    def bind(self, pattern):
        key = self.conn.scalar("""INSERT INTO ssh_keys (key_uuid, name, key_type, public_key, fingerprint, dek_nonce, wrapped_dek, key_nonce, ciphertext, created_at, origin)
                                  VALUES (:p, :p, 'ssh-ed25519', 'p', :p, x'00', x'00', x'00', x'00', 1, 'generated') RETURNING key_id""", {'p': pattern})
        self.conn.execute("""INSERT INTO key_bindings (key_id, host_pattern, pattern_kind, ssh_user, ssh_port, allowed_actions, priority, created_at)
                             VALUES (:k, :p, 'host', 'scan', 22, 'scan', 100, 1)""", {'k': key, 'p': pattern})

    def test_retiring_keeps_the_binding_of_an_address_it_only_reported(self):
        self.bind('192.168.1.10')
        self.bind('10.0.0.5')
        retire.retire(self.conn, 'nas')
        self.assertEqual([r[0] for r in self.conn.all('SELECT host_pattern FROM key_bindings')], ['192.168.1.10'])

    def test_retiring_says_what_stays_and_does_not_block_reset(self):
        self.conn.execute("INSERT INTO deploy_access (host, state, detail, updated_at, updated_by) VALUES ('nas', 'ready', '', 1, 'a')")
        self.assertIn('still_on_host', retire.retire(self.conn, 'nas'))
        self.assertEqual(reset._blocking(reset.left_behind(self.conn)), [])

    def test_a_mistyped_scan_stops_alerting(self):
        insert = "INSERT INTO scan_jobs (host, requested_by, queued_at, status, result_json) VALUES (:h, 'a', :t, 'failed', '{}')"
        now = int(time.time())
        self.conn.execute(insert, {'h': 'old-typo', 't': now - 8 * 86400})
        self.conn.execute(insert, {'h': 'new-typo', 't': now})
        self.conn.execute(insert, {'h': 'nas', 't': now - 8 * 86400})
        found = [k for k in alerts.scan_problems(self.conn) if k.startswith('scan-failed')]
        self.assertEqual(sorted(found), ['scan-failed:nas', 'scan-failed:new-typo'])

    def test_a_volume_sized_in_bytes_can_be_staged(self):
        plan = fromdesign.plan(self.conn, {'metadata': {'host': 'nas'}, 'devices': [], 'pools': [
            {'name': 'vg0', 'type': 'lvm', 'vg': 'vg0', 'members': ['/dev/sdb'], 'datasets': [{'name': 'data', 'sizeBytes': 1 << 30}]}]})
        task = next(t for t in plan['tasks'] if t['type'] == 'lvm-lv')
        self.assertEqual(task['params']['size'], '1024M')
        changes.normalize({'name': 'x', 'tasks': [task]})

    def test_options_are_read_whole(self):
        said = shares.id_check(self.conn, {'id': 1, 'name': 'nas', 'mounts': []}, {'path': '/x', 'rules': [{'clients': '*', 'options': 'rw,no_all_squash'}]}, [])
        self.assertNotIn('all_squash)', ' '.join(t for _, t in said))
        self.assertIn('[[ ,${E_OPTS[$i]}, == *,ro,* ]]', shares.SHARES_BODY_3)


class Periods(unittest.TestCase):
    def test_cron_uses_the_longest_wait(self):
        day = 86400
        for expr, want in (('0 9 * * 1-5', 3 * day), ('0 3 * * 1,2', 6 * day), ('0 8,9 * * *', 23 * 3600), ('* * * * *', 60), ('0 3 1 * *', 31 * day),
                           ('0 3 1 1,7 *', 184 * day), ('* * * 1 *', 335 * day + 60)):
            self.assertEqual(scheduler.period(expr), want, expr)
        self.assertEqual(scheduler.period('not cron'), day)

    def test_calendars_use_the_longest_wait(self):
        day = jobs.DAY
        for cal, want in (('Sun *-*-01..07 04:00:00', 35 * day), ('Mon..Fri 02:00', 3 * day), ('Mon,Tue *-*-* 02:00:00', 6 * day), ('*-*-01,15 02:00:00', 17 * day),
                          ('*-*-* 08,09:00:00', 23 * 3600), ('*-*-* 00/6:00:00', 6 * 3600), ('Sun *-*-* 03:00:00', 7 * day), ('*-*-01 04:00:00', 31 * day),
                          ('hourly', 3600), ('*-01-01 02:00', 366 * day), ('*-02-29 02:00', 1461 * day)):
            self.assertEqual(jobs.period(cal), want, cal)


class ScheduleScripts(unittest.TestCase):
    def test_a_command_is_readable_only_by_who_runs_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Database(f'sqlite:///{tmp}/t.db')
            conn = db.connect()
            db.migrate(conn)
            s, _ = scheduler.create_schedule(conn, {'name': 'a', 'host': 'nas', 'cron_expr': '0 3 * * *', 'task_type': 'command', 'task_ref': 'true'}, 't')
            self.assertIn('chmod 0700 "$TASK_SH"', scheduler.generate_install_script(conn, s, None, ''))
            s, _ = scheduler.create_schedule(conn, {'name': 'b', 'host': 'nas', 'cron_expr': '0 3 * * *', 'task_type': 'command', 'task_ref': 'true', 'config': {'user': 'bob'}}, 't')
            text = scheduler.generate_install_script(conn, s, None, '')
            self.assertIn('chmod 0750 "$TASK_SH"', text)
            self.assertNotIn('chmod 0755 "$TASK_SH"', text)
            conn.close()


class OddRepoPaths(unittest.TestCase):
    def test_real_bytes_reach_the_shell(self):
        with tempfile.TemporaryDirectory() as tmp:
            real = os.fsencode(tmp) + b'/caf\xe9'
            os.mkdir(real)
            stored = decode(real)
            out = subprocess.run(['sh', '-c', f'[ -d {gitrepos._sh_path(stored)} ] && echo yes'], capture_output=True, text=True).stdout
            self.assertEqual(out.strip(), 'yes')
        self.assertEqual(gitrepos._sh_path('/plain path'), "'/plain path'")
