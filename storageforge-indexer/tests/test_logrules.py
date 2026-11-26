"""Log rules (logrules.py, roadmap 3 phase 1): which lines a rule means, how they are counted as they arrive, when a rule is an alert and
when it stops being one, the built-in rules against the lines real kernels and services write, and the web routes."""
import json
import shutil
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import dbfactory
from storageforge_index import alerts, hostlogs, logrules, notifications, server, users
from storageforge_index.db import Database

NOW = 2000000000.0
PW = 'correct horse battery staple'


def row(msg, at=NOW - 60, priority='4', unit='', ident='kernel', comm=None, n=[0]):
    n[0] += 1
    out = {'__CURSOR': f'c{n[0]}', '__REALTIME_TIMESTAMP': str(int(at * 1e6)), 'MESSAGE': msg, 'PRIORITY': priority, 'SYSLOG_IDENTIFIER': ident}
    if unit:
        out['_SYSTEMD_UNIT'] = unit
    if comm:
        out['_COMM'] = comm
    return out


def output(*rows):
    return '@@who 0 root\n@@important\n\n@@routine\n' + '\n'.join(json.dumps(r) for r in rows) + '\n@@end\n'


class Patterns(unittest.TestCase):
    def take(self, pattern, value):
        return logrules.matches(logrules.compile_pattern(pattern), value)

    def test_plain_text_stars_and_alternatives(self):
        for pattern, value, want in (('*I/O error*', 'blk: I/O error, dev sda', True), ('I/O error*', 'blk: I/O error', False), ('*error', 'an error', True),
                                     ('*error', 'an error.', False), ('sshd', 'SSHD', True), ('sshd', 'sshd-session', False), ('sshd*', 'sshd-session', True),
                                     ('*a*b*c*', 'xxaxxbxxcxx', True), ('*a*b*c*', 'cba', False), ('a*a', 'a', False), ('a*a', 'aa', True),
                                     ('*oom*|*killed process*', 'Out of memory: Killed process 4', True), ('one|two', 'three', False),
                                     ('*', '', True), ('', 'anything', True), ('*.*', 'a.b', True), ('*[a-z]+*', 'abc', False), ('*(x|y)*', 'x', False)):
            with self.subTest(pattern=pattern, value=value):
                self.assertEqual(self.take(pattern, value), want)

    def test_nothing_in_a_pattern_is_a_regular_expression(self):
        """SF-52: a pattern built to make a regex engine backtrack is only text here, and a long line costs what its length costs."""
        evil = '*' + 'a*' * 19 + 'b'
        started = time.time()
        self.assertFalse(self.take(evil, 'a' * 4000))
        self.assertFalse(self.take('*(a+)+$*', 'a' * 4000 + '!'))
        self.assertLess(time.time() - started, 0.5)

    def test_what_a_pattern_may_not_be(self):
        for bad, why in (('a||b', 'empty alternative'), ('|a', 'empty alternative'), ('x' * 601, 'at most 600'), ('|'.join('ab' for _ in range(21)), 'alternatives'), ('*a' * 21, 'stars')):
            with self.assertRaisesRegex(ValueError, why, msg=bad):
                logrules.compile_pattern(bad)


class Db(unittest.TestCase):
    def setUp(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        self.db = self.make(tmp)
        self.conn = self.db.connect()
        self.addCleanup(self.conn.close)
        self.db.migrate(self.conn)
        for host in ('nas', 'pc'):
            self.conn.execute(f"INSERT INTO hosts (hostname, ssh_host, ssh_user, inventory_json, last_scanned_at) VALUES (:h, :h, 'scan', '{{}}', {self.db.ts(':t')})", {'h': host, 't': 1600000000})

    def make(self, tmp):
        return dbfactory.make(self, tmp / 'index.db')

    def logged(self, *rows, host='nas', now=NOW):
        return hostlogs.store(self.conn, host, hostlogs.parse(output(*rows), now), now)

    def raised(self, now=NOW):
        return {k: v for k, v in logrules.problems(self.conn, now).items()}

    def rule(self, **body):
        return logrules.save(self.conn, {'name': 'mine', 'text': '*boom*', **body}, 'gabe')


class BuiltIn(Db):
    """Each built-in rule against lines as kernels and services really write them, and against lines that only look alike."""
    REAL = {
        'oom': ['Out of memory: Killed process 4242 (postgres) total-vm:8123456kB, anon-rss:7000000kB', 'postgres invoked oom-killer: gfp_mask=0x140cca, order=0'],
        'io-error': ['blk_update_request: I/O error, dev sdb, sector 123456 op 0x0:(READ) flags 0x0', 'Buffer I/O error on dev sdb1, logical block 1, async page read',
                     'sd 2:0:0:0: [sdb] tag#3 Sense Key : Medium Error [current]', 'nvme nvme0: I/O 12 QID 3 timeout, aborting'],
        'fs-error': ['EXT4-fs error (device sda1): ext4_lookup:1700: inode #2: comm ls: deleted inode referenced', 'XFS (sdb1): Metadata corruption detected at xfs_agf_verify',
                     'BTRFS error (device sdc): parent transid verify failed on 30408704', 'BTRFS critical (device sdc): corrupt leaf'],
        'pool-degraded': ['md/raid1:md0: Disk failure on sdb1, disabling device.', 'md/raid1:md0: Operation continuing on 1 devices.',
                          'The state of pool tank is DEGRADED', 'vdev state changed, pool_guid=1 vdev_guid=2 state=FAULTED',
                          "eid=45 class=statechange pool='tank' vdev=vdb1 vdev_state=OFFLINE", "eid=46 class=statechange pool='tank' vdev=vdc1 vdev_state=FAULTED"],
        'share-down': ['nfs: server nas-02 not responding, still trying', 'CIFS: VFS: \\\\nas\\share has not responded in 180 seconds. Reconnecting...'],
    }
    LOOKALIKE = ['I/O scheduler mq-deadline registered', 'EXT4-fs (sda1): mounted filesystem with ordered data mode', 'md0: detected capacity change from 0 to 100',
                 'BTRFS info (device sdc): using crc32c', 'nfs: server nas-02 OK', 'Memory cgroup stats for /system.slice', 'pool tank is ONLINE', "eid=47 class=statechange pool='tank' vdev=vdb1 vdev_state=ONLINE"]

    def test_each_storage_rule_takes_the_lines_it_is_for(self):
        for key, lines in self.REAL.items():
            for line in lines:
                with self.subTest(rule=key, line=line):
                    self.setUp()
                    self.logged(row(line))
                    got = self.raised()
                    names = {r['id']: r['builtin'] for r in logrules.rules(self.conn)}
                    self.assertEqual([names[int(k.split(':')[1])] for k in got], [key], f'{line!r} raised {list(got.values())}')
                    self.assertEqual(next(iter(got.values()))[4], 'crit' if key != 'share-down' else 'warn')

    def test_every_built_in_rule_is_one_the_matcher_takes(self):
        """A rule that does not compile matches nothing, quietly. One built-in rule grew past the pattern limit and stopped firing."""
        for key, _name, program, _lowest, text, *_ in logrules.BUILTIN:
            with self.subTest(rule=key):
                self.assertIsNotNone(logrules.compile_pattern(text))
                logrules.compile_pattern(program)

    def test_zed_says_a_state_change_at_notice_and_the_rule_hears_it(self):
        """The KVM lab: a disk taken offline was logged by zed at notice, the rule asked for warning or worse, and nothing was raised."""
        self.logged(row("eid=6 class=statechange pool='vault' vdev=vdc1 vdev_state=OFFLINE", priority='5', ident='zed'))
        got = self.raised()
        self.assertEqual([v[4] for v in got.values()], ['crit'])
        self.assertIn('A ZFS pool or an md array is degraded on nas', [v[2] for v in got.values()])

    def test_lines_that_only_look_alike_raise_nothing(self):
        self.logged(*[row(line) for line in self.LOOKALIKE])
        self.assertEqual(self.raised(), {})

    def test_failed_units_segfaults_and_a_full_disk_want_three_in_an_hour(self):
        for key, ident, lines in (('unit-failed', 'systemd', ['nginx.service: Failed with result \'exit-code\'.', 'Failed to start nginx.service - A web server.', 'smbd.service: Failed with result \'timeout\'.']),
                                  ('segfault', 'kernel', ['app[99]: segfault at 0 ip 00007f sp 00007f error 4 in libc.so'] * 3),
                                  ('disk-full', 'rsync', ['write failed: No space left on device (28)'] * 3)):
            with self.subTest(rule=key):
                self.setUp()
                unit = 'init.scope' if key == 'unit-failed' else ''          # systemd's own lines are written by pid 1, unit init.scope
                self.logged(*[row(line, ident=ident, unit=unit, at=NOW - 60 - i) for i, line in enumerate(lines[:2])])
                self.assertEqual(self.raised(), {}, 'two are not three')
                self.logged(row(lines[2], ident=ident, unit=unit, at=NOW - 5), now=NOW + 60)
                [(_, (kind, ref, title, message, level))] = self.raised(NOW + 60).items()
                self.assertEqual((kind, level, ref.split(':')[0]), ('log-rule', 'warn', 'nas'))
                self.assertIn('3 line(s) in the last 1 h', message)

    def test_failed_logins_are_off_until_someone_turns_them_on(self):
        lines = [row(f'Failed password for root from 203.0.113.9 port {i} ssh2', ident='sshd', unit='sshd.service', comm='sshd', priority='6') for i in range(25)]
        self.logged(*lines)
        self.assertEqual(self.raised(), {})
        ssh = next(r for r in logrules.rules(self.conn) if r['builtin'] == 'ssh-failed')
        self.assertFalse(ssh['enabled'])
        logrules.save(self.conn, {**ssh, 'enabled': True}, 'gabe', ssh['id'])
        self.logged(*[row(f'Failed password for admin from 203.0.113.9 port {i} ssh2', ident='sshd', unit='sshd.service', comm='sshd', priority='6') for i in range(25)], now=NOW + 30)
        self.assertEqual([v[2] for v in self.raised(NOW + 30).values()], ['A burst of failed SSH logins on nas'])

    def test_an_upgrade_brings_a_rules_new_text_and_keeps_what_the_operator_set(self):
        oom = next(r for r in logrules.rules(self.conn) if r['builtin'] == 'oom')
        logrules.save(self.conn, {**oom, 'threshold': 4, 'enabled': False, 'level': 'warn', 'text': '*mine*', 'name': 'renamed'}, 'gabe', oom['id'])
        self.conn.execute("UPDATE log_rules SET text = 'what an older release shipped' WHERE builtin = 'oom'")
        got = next(r for r in logrules.rules(self.conn) if r['builtin'] == 'oom')
        self.assertEqual((got['threshold'], got['enabled'], got['level']), (4, False, 'warn'), 'the operator\'s')
        self.assertEqual((got['text'], got['name']), (logrules.BUILTIN[0][4], logrules.BUILTIN[0][1]), 'the release\'s: a built-in rule\'s text and name are not the operator\'s to change')
        with self.assertRaisesRegex(ValueError, 'turned off, not deleted'):
            logrules.delete(self.conn, oom['id'])


class Matching(Db):
    def test_a_rule_means_its_host_unit_program_level_and_text(self):
        r = self.rule(host='na*', unit='smbd', program='smbd', min_level='err', text='*boom*')
        hit = dict(unit='smbd.service', ident='smbd', priority='3')
        self.logged(row('a boom', **hit))
        self.assertEqual(len(self.raised()), 1)
        for name, line in (('another host', None), ('another unit', row('a boom', **{**hit, 'unit': 'nmbd.service'})),
                           ('a lower level', row('a boom', **{**hit, 'priority': '4'})), ('other text', row('a bang', **hit))):
            with self.subTest(name):
                self.conn.execute('DELETE FROM log_rule_hits')
                if line is None:
                    self.logged(row('a boom', **hit), host='pc')
                else:
                    self.logged(line)
                self.assertEqual(self.raised(), {})
        self.assertEqual(r['min_level'], 'err')

    def test_a_program_is_who_journald_saw_and_not_the_name_on_the_line(self):
        """`logger -t sshd` is anyone. A rule about sshd counts what sshd wrote."""
        self.rule(program='sshd', text='*Accepted*', min_level='info')
        self.logged(row('Accepted password for root', ident='sshd', comm='logger', priority='6'))
        self.assertEqual(self.raised(), {})
        self.logged(row('Accepted password for root', ident='sshd', unit='sshd.service', comm='sshd', priority='6'), now=NOW + 5)
        self.assertEqual(len(self.raised(NOW + 5)), 1)
        self.conn.execute('DELETE FROM log_rule_hits')
        self.logged(row('Accepted publickey for gabe', ident='sshd', priority='6'), now=NOW + 9)
        self.assertEqual(len(self.raised(NOW + 9)), 1, 'a line from before journald\'s fields were kept goes by its own name')

    def test_a_flood_is_one_alert_per_rule_and_host_and_says_how_many(self):
        self.rule()
        self.logged(*[row(f'boom {i}') for i in range(500)])
        self.logged(row('boom on pc'), host='pc')
        got = self.raised()
        self.assertEqual(sorted(v[2] for v in got.values()), ['mine on nas', 'mine on pc'])
        self.assertIn('500 line(s)', next(v[3] for v in got.values() if v[2] == 'mine on nas'))
        self.assertIn('The last: boom', next(v[3] for v in got.values() if v[2] == 'mine on nas'))

    def test_a_line_read_twice_counts_once(self):
        self.rule(threshold=2)
        r = row('boom')
        self.logged(r)
        self.logged(r, now=NOW + 30)
        self.assertEqual(self.raised(NOW + 30), {})

    def test_a_line_over_the_hosts_rate_still_counts(self):
        keep = hostlogs.RATE_PER_DAY
        hostlogs.RATE_PER_DAY = 1
        self.addCleanup(setattr, hostlogs, 'RATE_PER_DAY', keep)
        self.rule(threshold=5)
        self.logged(*[row(f'boom {i}') for i in range(6)])
        self.assertEqual(self.conn.scalar('SELECT count(*) FROM host_log_lines'), 1)
        self.assertEqual(len(self.raised()), 1, 'a flood that is not stored is exactly when the rule should fire')

    def test_it_resolves_when_the_window_has_passed_and_a_hosts_clock_cannot_hold_it_open_or_shut(self):
        self.rule(window_secs=600)
        self.logged(row('boom', at=NOW + 80000))            # stamped far ahead: counted when it arrived
        self.assertEqual(len(self.raised()), 1)
        self.assertEqual(len(self.raised(NOW + 500)), 1)
        self.assertEqual(self.raised(NOW + 1300), {})
        self.logged(row('boom', at=NOW - 9 * 86400), now=NOW + 2000)    # stamped long ago: still new now
        self.assertEqual(len(self.raised(NOW + 2000)), 1)

    def test_a_rule_turned_off_or_deleted_stops_at_once(self):
        r = self.rule()
        self.logged(row('boom'))
        logrules.save(self.conn, {**r, 'enabled': False}, 'gabe', r['id'])
        self.assertEqual(self.raised(), {})
        logrules.save(self.conn, {**r, 'enabled': True}, 'gabe', r['id'])
        self.assertEqual(len(self.raised()), 1)
        logrules.delete(self.conn, r['id'])
        self.assertEqual(self.raised(), {})
        self.assertEqual(self.conn.scalar('SELECT count(*) FROM log_rule_hits'), 0)

    def test_what_a_rule_may_not_be(self):
        for body, why in (({'name': ''}, 'needs a name'), ({'text': '*'}, 'every line'), ({'text': 'a||b'}, 'empty alternative'), ({'threshold': 0}, 'threshold'),
                          ({'window_secs': 60}, '5 minutes to 7 days'), ({'level': 'loud'}, 'level is one of'), ({'min_level': 'chatty'}, 'lowest level'), ({'threshold': 'many'}, 'whole numbers')):
            with self.assertRaisesRegex(ValueError, why, msg=body):
                self.rule(**body)
        self.rule(text='*', min_level='err', name='every error')
        self.rule()
        with self.assertRaisesRegex(ValueError, 'that name already'):
            self.rule()

    def test_what_a_host_logs_reaches_the_alert_as_text_cut_to_size(self):
        self.rule()
        self.logged(row('boom <script>alert(1)</script> ' + 'x' * 5000))
        message = next(iter(self.raised().values()))[3]
        self.assertLess(len(message), 500)
        self.assertIn('<script>', message, 'kept as it was: the page shows it as text')


class AsNotifications(Db):
    def test_a_rule_opens_one_notification_ranked_by_its_level_and_it_resolves(self):
        sent = []
        with mock.patch.object(alerts, 'send', lambda cfg, title, message, level='warn', extra=None: sent.append((title, level)) or ['recorded']), \
                mock.patch.object(alerts, 'scan_problems', lambda conn: {}), mock.patch.object(alerts, 'backup_problems', lambda conn: {}), mock.patch.object(alerts, 'cert_problems', lambda: {}):
            self.logged(row('md/raid1:md0: Disk failure on sdb1, disabling device.'), now=time.time())
            self.logged(row('nfs: server nas-02 not responding, still trying'), host='pc', now=time.time())
            alerts.evaluate(self.db)
            c = notifications.center(self.conn)
            rows = [(g['level'], g['host'], g['kind'], g['count']) for g in c['groups'] if g['kind'] == 'log-rule']
            self.assertEqual(rows, [('crit', 'nas', 'log-rule', 1), ('warn', 'pc', 'log-rule', 1)])
            self.assertIn(('A ZFS pool or an md array is degraded on nas', 'crit'), sent)
            crit = next(x for g in c['groups'] for x in g['items'] if x['level'] == 'crit' and x['kind'] == 'log-rule')
            with self.assertRaisesRegex(ValueError, 'cannot be snoozed'):
                notifications.snooze(self.conn, crit['key'], 3600, 'gabe')
            self.conn.execute('DELETE FROM log_rule_hits')
            alerts.evaluate(self.db)
            self.assertEqual([g for g in notifications.center(self.conn)['groups'] if g['kind'] == 'log-rule'], [])
            self.assertIn(('Resolved: A ZFS pool or an md array is degraded on nas', 'ok'), sent)


class OverTheWeb(Db):
    def make(self, tmp):
        return Database(str(tmp / 'index.db'))

    def client(self, role):
        users.create(self.conn, role, PW, role)
        c = server.create_app(server.App(self.db), 's' * 48).test_client()
        self.assertEqual(c.post('/api/login', json={'username': role, 'password': PW}).status_code, 200)
        return c

    def test_an_operator_reads_makes_changes_and_deletes_a_rule_and_each_is_audited(self):
        c = self.client('operator')
        got = c.get('/api/hostlogs/rules').get_json()
        self.assertEqual(len(got['rules']), len(logrules.BUILTIN))
        self.assertEqual([r['builtin'] for r in got['rules'] if not r['enabled']], ['ssh-failed', 'sudo-failed'])
        made = c.post('/api/hostlogs/rules', json={'name': 'smbd panics', 'unit': 'smbd', 'text': '*PANIC*', 'threshold': 2, 'level': 'crit'})
        self.assertEqual((made.status_code, made.get_json()['unit'], made.get_json()['updated_by']), (200, 'smbd', 'web:operator'))
        rid = made.get_json()['id']
        self.assertEqual(c.put(f'/api/hostlogs/rules/{rid}', json={'name': 'smbd panics', 'unit': 'smbd', 'text': '*PANIC*', 'threshold': 5}).get_json()['threshold'], 5)
        self.assertEqual(c.post('/api/hostlogs/rules', json={'name': 'x', 'text': '*'}).status_code, 400)
        self.assertEqual(c.put('/api/hostlogs/rules/9999', json={'name': 'x', 'text': 'y'}).status_code, 404)
        builtin = got['rules'][0]['id']
        self.assertEqual(c.delete(f'/api/hostlogs/rules/{builtin}').status_code, 400)
        self.assertEqual(c.delete(f'/api/hostlogs/rules/{rid}').status_code, 200)
        self.assertEqual(c.delete(f'/api/hostlogs/rules/{rid}').status_code, 404)
        self.assertEqual([tuple(r) for r in self.conn.all("SELECT action, outcome FROM audit_log WHERE action LIKE 'logrule.%' ORDER BY rowid")],
                         [('logrule.save', 'ok'), ('logrule.save', 'ok'), ('logrule.delete', 'ok')])

    def test_a_viewer_reads_no_rules_and_someone_who_reads_logs_cannot_change_them(self):
        c = self.client('viewer')
        self.assertEqual(c.get('/api/hostlogs/rules').status_code, 403, 'a rule\'s text says what the hosts log')
        self.assertEqual(c.post('/api/hostlogs/rules', json={'name': 'x', 'text': 'y'}).status_code, 403)
        self.assertEqual(c.delete('/api/hostlogs/rules/1').status_code, 403)


if __name__ == '__main__':
    unittest.main()
