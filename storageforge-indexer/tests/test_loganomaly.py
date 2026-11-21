"""Anomalies in host logs (loganomaly.py, roadmap 3 phase 3): the kind of a line, volume against the same hour of the weeks before, new kinds
of line, and silence of a host and of a unit. The counts are real: lines are stored through hostlogs.store, a pickup at a time, over weeks of
fake time, and what the notification center makes of them is read through alerts.evaluate()."""
import json
import shutil
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import dbfactory
from storageforge_index import alerts, hostlogs, loganomaly, notifications

HOUR, DAY, WEEK = 3600, 86400, 7 * 86400
NOW = 2000000000.0 - 2000000000.0 % 300          # on a 5-minute edge, so an hour is twelve whole buckets


def output(rows):
    return '@@who 0 root\n@@important\n\n@@routine\n' + '\n'.join(json.dumps(r) for r in rows) + '\n@@end\n'


class Shapes(unittest.TestCase):
    def test_what_changes_from_line_to_line_is_blanked(self):
        same = ('Accepted publickey for gabe from 10.42.0.7 port 51234 ssh2: ED25519 SHA256:x',
                'Accepted publickey for gabe from 192.168.1.20 port 40022 ssh2: ED25519 SHA256:x')
        self.assertEqual(loganomaly.shape(same[0]), loganomaly.shape(same[1]))
        self.assertEqual(loganomaly.shape('Accepted publickey for gabe from 10.42.0.7 port 51234'), 'Accepted publickey for gabe from <ip> port #')
        for a, b in (('blk_update_request: I/O error, dev sdb, sector 123456', 'blk_update_request: I/O error, dev sdb, sector 99'),
                     ('mounted /srv/tank/media at 0x7ffd1234', 'mounted /home/gabe/x at 0xdeadbeef'),
                     ('job 3fa85f64-5717-4562-b3fc-2c963f66afa6 done', 'job 9b2e1c4a-0000-4000-8000-000000000001 done'),
                     ('link eth0 up, 52:54:00:12:34:56', 'link eth0 up, 52:54:00:ab:cd:ef'),
                     ('peer fe80::1:2 gone', 'peer 2001:db8::7 gone'),
                     ('commit a3f9c21e0b applied', 'commit 77e0d1f2c4 applied')):
            with self.subTest(a=a):
                self.assertEqual(loganomaly.shape(a), loganomaly.shape(b))
        self.assertNotEqual(loganomaly.shape('I/O error, dev sdb'), loganomaly.shape('I/O error, dev sdc'), 'a device name is the kind, not a number in it')
        self.assertNotEqual(loganomaly.shape('Started backup.service'), loganomaly.shape('Failed backup.service'))
        self.assertLessEqual(len(loganomaly.shape('x' * 4000)), loganomaly.SHAPE_CHARS)

    def test_the_program_is_part_of_the_kind(self):
        line = {'message': 'started', 'priority': 6}
        self.assertNotEqual(loganomaly.kind_of({**line, 'comm': 'smbd'})[0], loganomaly.kind_of({**line, 'comm': 'nfsd'})[0])
        self.assertEqual(loganomaly.kind_of({**line, 'comm': 'smbd', 'ident': 'liar'})[1], 'smbd', 'who journald saw, not the name on the line')

    def test_a_line_built_to_be_slow_is_not(self):
        """SF-52: every pattern reads a line once. 4,000 characters of each pattern's worst case take what their length takes."""
        started = time.time()
        for evil in ('0' * 4000, 'a1' * 2000, ':' * 4000, '1.' * 2000, '/' * 4000, 'f:' * 2000, '0x' * 2000, 'ab:' * 1333, ' ' * 4000, '-' * 4000):
            loganomaly.shape(evil)
        self.assertLess(time.time() - started, 0.5)


class Db(unittest.TestCase):
    def setUp(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        self.db = dbfactory.make(self, tmp / 'index.db')
        self.conn = self.db.connect()
        self.addCleanup(self.conn.close)
        self.db.migrate(self.conn)
        self.n = 0
        for host in ('nas', 'pc'):
            self.conn.execute(f"INSERT INTO hosts (hostname, ssh_host, ssh_user, inventory_json, last_scanned_at) VALUES (:h, :h, 'scan', '{{}}', {self.db.ts(':t')})", {'h': host, 't': 1600000000})

    def row(self, msg, at, unit='cron.service', priority=6, comm=None):
        self.n += 1
        out = {'__CURSOR': f'c{self.n}', '__REALTIME_TIMESTAMP': str(int(at * 1e6)), 'MESSAGE': msg, 'PRIORITY': str(priority), 'SYSLOG_IDENTIFIER': comm or unit.split('.')[0]}
        if unit:
            out['_SYSTEMD_UNIT'] = unit
        if comm:
            out['_COMM'] = comm
        return out

    def pickup(self, rows, now, host='nas', via=None):
        return hostlogs.store(self.conn, host, hostlogs.parse(output(rows), now), now, via=via)

    def hours(self, start, hours, per_hour, host='nas', unit='cron.service', via=None, msg='job {i} ran in {ms} ms', skew=0):
        """A host logging per_hour lines an hour of one kind, from start, picked up at the end of each hour. skew: its clock, against ours."""
        for h in range(hours):
            t0 = start + h * HOUR
            self.pickup([self.row(msg.format(i=i, ms=17 * i + h), t0 + skew + i * HOUR / max(per_hour, 1), unit) for i in range(per_hour)], t0 + HOUR, host, via)

    def weeks_of(self, weeks, window_hours, per_hour, host='nas', unit='cron.service', via=None, end=NOW):
        """The same few hours of the week, in each of the weeks before `end`: what the baseline reads."""
        for k in range(weeks, 0, -1):
            self.hours(end - k * WEEK - window_hours * HOUR, window_hours, per_hour, host, unit, via)

    def problems(self, now=NOW):
        return loganomaly.problems(self.conn, now)


class Volume(Db):
    def test_a_host_logging_ten_times_its_usual_hour_is_one_warning_naming_the_unit(self):
        self.weeks_of(3, 2, 20)
        self.weeks_of(3, 2, 4, unit='smbd.service')
        self.hours(NOW - 2 * HOUR, 1, 20)
        self.hours(NOW - HOUR, 1, 20)
        self.hours(NOW - HOUR, 1, 300, unit='smbd.service')
        p = self.problems()
        self.assertEqual(list(p), ['log-volume:nas'])
        kind, ref, title, message, level = p['log-volume:nas']
        self.assertEqual((kind, ref, level), ('log-volume', 'nas', 'warn'))
        self.assertIn('smbd.service: 300 lines, usually 4', message)
        self.assertNotIn('cron', message, 'a unit at its usual rate is not named')
        self.assertIn('last 3 weeks', message)

    def test_an_ordinary_hour_says_nothing_and_neither_does_a_quiet_unit_that_logs_a_little_more(self):
        self.weeks_of(3, 2, 20)
        self.weeks_of(3, 2, 1, unit='smartd.service')
        self.hours(NOW - HOUR, 1, 24)
        self.hours(NOW - HOUR, 1, 9, unit='smartd.service')
        self.assertEqual(self.problems(), {})
        a = loganomaly.assess(self.conn, 'nas', NOW)
        self.assertEqual((a['weeks'], a['hour'], a['usual']), (3, 33, 21))

    def test_nothing_is_said_until_two_weeks_of_counts_exist(self):
        self.weeks_of(1, 2, 20)
        self.hours(NOW - HOUR, 1, 500)
        self.assertEqual(self.problems(), {})
        a = loganomaly.assess(self.conn, 'nas', NOW)
        self.assertTrue(a['learning'])
        self.assertEqual(a['weeks'], 1)
        self.hours(NOW - 2 * WEEK - 2 * HOUR, 2, 20)       # and a week before that: two weeks of counts
        self.pickup([], NOW)
        self.assertIn('log-volume:nas', self.problems(), 'with two weeks before it, the same hour is loud')

    def test_the_spread_of_the_weeks_widens_what_is_usual(self):
        for k, n in ((3, 20), (2, 200), (1, 120)):
            self.hours(NOW - k * WEEK - 2 * HOUR, 2, n)
        self.hours(NOW - HOUR, 1, 380)
        self.assertEqual(self.problems(), {}, 'median 120, spread 119: 380 is within four spreads of it')
        self.hours(NOW - HOUR, 1, 600)
        self.assertIn('980 lines', self.problems()['log-volume:nas'][3])

    def test_lines_that_came_with_a_scan_long_ago_say_nothing_about_now(self):
        self.weeks_of(3, 2, 20)
        self.hours(NOW - HOUR, 1, 500)
        self.assertIn('log-volume:nas', self.problems(NOW))
        self.assertEqual(self.problems(NOW + loganomaly.STALE_SECS + 60), {}, 'the last scan was hours ago: nothing is known of the last hour')

    def test_lines_over_the_rate_are_counted_and_still_loud(self):
        self.weeks_of(3, 2, 20)
        with mock.patch.object(hostlogs, 'RATE_PER_DAY', 50):
            self.hours(NOW - HOUR, 1, 400)
        self.assertLess(self.conn.scalar('SELECT count(*) FROM host_log_lines WHERE collected_at = :t', {'t': int(NOW)}), 400)
        self.assertIn('400 lines', self.problems()['log-volume:nas'][3])


class Silence(Db):
    def test_a_host_whose_agent_pushes_and_that_stops_is_critical_and_cannot_be_snoozed(self):
        self.weeks_of(3, 4, 30, via='agent')
        self.hours(NOW - 4 * HOUR, 2, 30, via='agent')
        p = self.problems()
        self.assertEqual(list(p), ['log-silence:nas'])
        kind, ref, title, message, level = p['log-silence:nas']
        self.assertEqual((kind, level, title), ('log-silence', 'crit', 'nas has stopped logging'))
        self.assertIn('its agent pushes its lines as they are written, and none came', message)
        self.assertFalse(notifications.ignorable(kind, level))
        self.hours(NOW, 1, 3, via='agent')
        self.assertNotIn('log-silence:nas', self.problems(NOW + HOUR), 'it resolves when lines come again')

    def test_silence_from_scans_is_a_warning_and_not_said_of_a_host_that_is_quiet_at_this_time(self):
        self.weeks_of(3, 4, 30)
        self.hours(NOW - 4 * HOUR, 2, 30)
        self.pickup([], NOW)                    # the scan at NOW found nothing new since two hours ago
        self.assertEqual(self.problems()['log-silence:nas'][4], 'warn')
        self.assertIn('the scans since brought none', self.problems()['log-silence:nas'][3])
        # pc logs by day and is quiet at night: the same silence, at a time of the week it is always quiet, is nothing
        for k in (3, 2, 1):
            self.hours(NOW - k * WEEK - 12 * HOUR, 8, 30, host='pc')
        self.hours(NOW - 12 * HOUR, 8, 30, host='pc')
        self.pickup([], NOW, host='pc')
        self.assertNotIn('log-silence:pc', self.problems())

    def test_a_host_with_its_clock_two_hours_behind_is_not_silent(self):
        self.weeks_of(3, 4, 30, via='agent')
        self.hours(NOW - 4 * HOUR, 4, 30, via='agent', skew=-2 * HOUR)
        self.assertNotIn('log-silence:nas', self.problems())

    def test_a_failed_scan_says_nothing_of_silence_the_scan_says_it_failed(self):
        self.weeks_of(3, 4, 30)
        self.hours(NOW - 4 * HOUR, 2, 30)
        with self.conn.tx():
            hostlogs._set_status(self.conn, 'nas', int(NOW), 'failed', 0, False, None, 'ssh: connection timed out')
        self.assertEqual(self.problems(), {})

    def test_a_unit_that_stops_while_its_host_goes_on_is_named(self):
        for unit in ('cron.service', 'smbd.service'):
            self.weeks_of(3, 6, 12, unit=unit)
        self.hours(NOW - 6 * HOUR, 3, 12, unit='smbd.service')
        self.hours(NOW - 6 * HOUR, 6, 12)
        p = self.problems()
        self.assertEqual(list(p), ['log-unit-silence:nas'])
        self.assertIn('smbd.service since', p['log-unit-silence:nas'][3])
        self.assertNotIn('cron.service', p['log-unit-silence:nas'][3])
        self.assertEqual(p['log-unit-silence:nas'][4], 'warn')

    def test_a_unit_that_logs_only_some_weeks_is_not_missed(self):
        self.weeks_of(3, 6, 12)
        self.hours(NOW - 2 * WEEK - 6 * HOUR, 6, 12, unit='backup.service')
        self.hours(NOW - 6 * HOUR, 1, 12, unit='backup.service')
        self.hours(NOW - 6 * HOUR, 6, 12)
        self.assertEqual(self.problems(), {}, 'backup.service logged in one of three weeks: its quiet is usual')


class NewKinds(Db):
    def learn(self, host='nas', days=8):
        for d in range(days):
            self.pickup([self.row('job 1 ran in 20 ms', NOW - (days - d) * DAY), self.row('Started Daily apt upgrade.', NOW - (days - d) * DAY + 1, 'systemd', comm='systemd')],
                        NOW - (days - d) * DAY + 60, host)

    def test_a_kind_never_logged_before_is_said_once_the_host_is_learned(self):
        self.learn()
        self.pickup([self.row('job 7 ran in 31 ms', NOW - 100), self.row('Started Daily apt upgrade.', NOW - 90, 'systemd', comm='systemd')], NOW - 60)
        self.assertEqual(self.problems(), {}, 'other numbers in a known line are the same kind')
        self.pickup([self.row('ata3.00: failed command: READ FPDMA QUEUED', NOW - 50, '', 3, comm='kernel')], NOW - 30)
        p = self.problems()
        self.assertEqual(list(p), ['log-new-kind:nas'])
        kind, ref, title, message, level = p['log-new-kind:nas']
        self.assertEqual((kind, title, level), ('log-new-kind', 'nas logged 1 new kind(s) of line', 'warn'))
        self.assertIn('at err, from kernel: ata3.00: failed command: READ FPDMA QUEUED', message)
        self.assertTrue(notifications.ignorable(kind, level))
        self.assertEqual(self.problems(NOW + DAY), {}, 'a day later it is no longer new')

    def test_a_routine_new_kind_is_information(self):
        self.learn()
        self.pickup([self.row('Reloading nginx configuration', NOW - 50, 'nginx.service')], NOW - 30)
        self.assertEqual(self.problems()['log-new-kind:nas'][4], 'info')

    def test_nothing_is_new_while_a_host_is_being_learned(self):
        self.learn(days=3)
        self.pickup([self.row('something never seen', NOW - 50)], NOW - 30)
        self.assertEqual(self.problems(), {})
        self.assertTrue(loganomaly.new_kinds(self.conn, 'nas', NOW)['learning'])

    def test_a_flood_of_new_kinds_is_one_notification_and_a_host_keeps_only_so_many(self):
        self.learn()
        with mock.patch.object(loganomaly, 'KINDS_PER_HOST', 60):
            self.pickup([self.row(f'module{chr(97 + i % 26)}{chr(97 + i // 26)} loaded', NOW - 50, '', comm='kernel') for i in range(100)], NOW - 30)
        self.assertEqual(self.conn.scalar("SELECT count(*) FROM host_log_kinds WHERE host = 'nas'"), 60)
        p = self.problems()
        self.assertEqual(list(p), ['log-new-kind:nas'])
        self.assertIn('58 new kind(s)', p['log-new-kind:nas'][2])
        self.assertIn('42 more were not kept', p['log-new-kind:nas'][3])

    def test_when_a_kind_came_is_when_it_arrived_not_what_the_host_stamped(self):
        self.learn()
        self.pickup([self.row('a line stamped a year ago', NOW - 365 * DAY)], NOW - 30)
        self.assertIn('log-new-kind:nas', self.problems())


class AsNotifications(Db):
    def test_silence_crit_ranks_above_volume_and_new_kinds_and_only_it_cannot_be_snoozed(self):
        self.weeks_of(3, 4, 30, via='agent')
        self.hours(NOW - 4 * HOUR, 2, 30, via='agent')          # nas: silent for two hours
        self.weeks_of(3, 2, 20, host='pc')
        self.learn_pc()
        self.hours(NOW - 2 * HOUR, 2, 20, host='pc')
        self.hours(NOW - HOUR, 1, 600, host='pc', unit='smbd.service', msg='smbd {i} {ms}')    # pc: loud, and its kinds are new
        sent = []
        with mock.patch.object(alerts, 'send', lambda cfg, title, message, level='warn', extra=None: sent.append((title, level)) or ['recorded']), \
                mock.patch.object(alerts, 'scan_problems', lambda conn: {}), mock.patch.object(alerts, 'backup_problems', lambda conn: {}), \
                mock.patch.object(alerts, 'cert_problems', lambda: {}), mock.patch.object(loganomaly.time, 'time', lambda: NOW):
            alerts.evaluate(self.db)
            c = notifications.center(self.conn)
            rows = [(g['level'], g['host'], g['kind']) for g in c['groups'] if g['kind'].startswith('log-')]
            self.assertEqual(rows[0], ('crit', 'nas', 'log-silence'))
            self.assertEqual(sorted(rows[1:]), [('info', 'pc', 'log-new-kind'), ('warn', 'pc', 'log-volume')])
            self.assertLess(rows.index(('warn', 'pc', 'log-volume')), rows.index(('info', 'pc', 'log-new-kind')))
            with self.assertRaisesRegex(ValueError, 'cannot be snoozed'):
                notifications.snooze(self.conn, 'log-silence:nas', 3600, 'gabe')
            self.assertIsNotNone(notifications.snooze(self.conn, 'log-volume:pc', 3600, 'gabe')['snoozed_until'])
            self.assertIn(('nas has stopped logging', 'crit'), sent)

    def learn_pc(self):
        self.pickup([self.row('job 1 ran in 20 ms', NOW - 9 * DAY)], NOW - 9 * DAY + 60, 'pc')


if __name__ == '__main__':
    unittest.main()
