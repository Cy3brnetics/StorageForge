"""Host logs: what a scan picks up from the journal, what is stored of it, and finding it again.
The collection script runs for real against a stand-in journalctl. Run with: python3 -m unittest discover -s tests -v"""
import contextlib
import csv
import io
import json
import os
import shutil
import stat
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

try:
    import dbfactory
except ImportError:      # run as tests.test_x from the project folder
    from tests import dbfactory
from storageforge_index import access, cli, hostlogs, permissions, server, users
from storageforge_index.db import Database
from storageforge_index.remote import Transport, collect_inventory
from storageforge_index.scanner import ScanOptions, scan_host

NOW = 2000000000.0
PW = 'correct horse battery staple'


def row(msg='hello', at=NOW - 60, cursor=None, priority='6', unit='sshd.service', ident='sshd', pid='42'):
    return {'__CURSOR': cursor or f'c-{msg}-{at}', '__REALTIME_TIMESTAMP': str(int(at * 1e6)), 'MESSAGE': msg, 'PRIORITY': priority,
            '_SYSTEMD_UNIT': unit, 'SYSLOG_IDENTIFIER': ident, '_PID': pid}


def output(*rows, who='1000 scan systemd-journal', end=True):
    body = '\n'.join(json.dumps(r) for r in rows)
    return f'@@who {who}\n@@important\n\n@@routine\n{body}\n' + ('@@end\n' if end else '')


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.db = dbfactory.make(self, f'{self.tmp}/t.db')
        self.conn = self.db.connect()
        self.db.migrate(self.conn)


class Parsing(unittest.TestCase):
    def test_a_plain_line(self):
        got = hostlogs.parse(output(row('Accepted publickey for gabe', priority='6')), NOW)
        self.assertEqual(got['state'], 'ok')
        self.assertFalse(got['cut'])
        x = got['lines'][0]
        self.assertEqual((x['message'], x['priority'], x['unit'], x['ident'], x['pid']), ('Accepted publickey for gabe', 6, 'sshd.service', 'sshd', 42))

    def test_a_line_in_both_streams_counts_once(self):
        r = row('disk failing', priority='3')
        text = f'@@who 0 root\n@@important\n{json.dumps(r)}\n@@routine\n{json.dumps(r)}\n@@end\n'
        self.assertEqual(len(hostlogs.parse(text, NOW)['lines']), 1)

    def test_no_journal_and_no_access_are_said_and_store_nothing(self):
        self.assertEqual(hostlogs.parse('@@nojournal\n', NOW)['state'], 'no_journal')
        limited = hostlogs.parse(output(row(), who='1000 scan users'), NOW)
        self.assertEqual((limited['state'], limited['lines']), ('limited', []))
        for who in ('0 root', '1000 scan adm', '1000 scan wheel'):
            self.assertEqual(hostlogs.parse(output(row(), who=who), NOW)['state'], 'ok', who)

    def test_output_that_stops_early_says_so(self):
        got = hostlogs.parse(output(row(), end=False), NOW)
        self.assertEqual(got['state'], 'partial')
        self.assertTrue(got['cut'])
        self.assertEqual(len(got['lines']), 1)

    def test_reaching_a_limit_says_lines_were_left_behind(self):
        rows = [row(f'm{i}') for i in range(hostlogs.LINES_ROUTINE)]
        self.assertTrue(hostlogs.parse(output(*rows), NOW)['cut'])

    def test_junk_from_a_host_is_skipped(self):
        text = output(row('good')).replace('@@end', 'not json\n{"MESSAGE": "no time"}\n[1,2]\n{"__REALTIME_TIMESTAMP": "x"}\n@@end')
        got = hostlogs.parse(text, NOW)
        self.assertEqual([x['message'] for x in got['lines']], ['good'])
        self.assertTrue(got['cut'])

    def test_a_line_cant_fake_a_section(self):
        got = hostlogs.parse(output(row('@@nojournal'), row('@@end')), NOW)
        self.assertEqual(got['state'], 'ok')
        self.assertEqual(len(got['lines']), 2)

    def test_odd_journal_values(self):
        as_bytes = row(cursor='a'); as_bytes['MESSAGE'] = list(b'caf\xc3\xa9 \xff')
        twice = row(cursor='b', pid='x'); twice['MESSAGE'] = ['first', 'second']
        too_long = row(cursor='c'); too_long['MESSAGE'] = None
        surrogate = row('bad \ud800 char', cursor='d', priority='99')
        got = hostlogs.parse(output(as_bytes, twice, too_long, surrogate), NOW)['lines']
        self.assertEqual(got[0]['message'], 'café �')
        self.assertEqual((got[1]['message'], got[1]['pid']), ('first', None))
        self.assertIn('too long', got[2]['message'])
        got[3]['message'].encode('utf-8')
        self.assertEqual(got[3]['priority'], 6)

    def test_terminal_escapes_and_line_breaks_are_removed(self):
        x = hostlogs.parse(output(row('\x1b[2Jwiped\nfake line\u202e', unit='evil\x1b]0;x\x07')), NOW)['lines'][0]
        self.assertEqual(x['message'], '[2Jwiped fake line')
        self.assertNotIn('\x1b', x['unit'])

    def test_sizes_are_limited_here_too(self):
        x = hostlogs.parse(output(row('m' * 100000, unit='u' * 5000)), NOW)['lines'][0]
        self.assertEqual((len(x['message']), len(x['unit'])), (hostlogs.MESSAGE_CHARS, hostlogs.NAME_CHARS))

    def test_a_clock_far_ahead_is_held_back(self):
        x = hostlogs.parse(output(row(at=NOW + 10 * 86400)), NOW)['lines'][0]
        self.assertEqual(x['at_us'], int((NOW + hostlogs.FUTURE_SECS) * 1e6))


class Secrets(unittest.TestCase):
    def test_secret_shapes_go(self):
        for text in ('PASSWORD=hunter2', 'MYSQL_ROOT_PASSWORD=hunter2', 'password: hunter2', '"password":"hunter2"', "passwd='hunter2'",
                     'api_key=hunter2', 'Authorization: Bearer hunter2', 'Authorization: Basic hunter2', 'token=hunter2', 'client_secret=hunter2',
                     'mount --password hunter2', 'app --api-key=hunter2', 'sshpass -p hunter2 ssh x', 'sudo: gabe : COMMAND=/usr/bin/mysql -u root -phunter2',
                     'curl https://bob:hunter2@example.com/x', 'Bearer hunter2hunter2'):
            self.assertNotIn('hunter2', hostlogs.scrub(text), text)

    def test_token_shapes_go(self):
        for text in ('ghp_' + 'a' * 36, 'AKIA' + 'A' * 16, 'eyJhbGciOiJI.eyJzdWIiOiIx.abc123', 'xoxb-1234567890-abcdef', 'glpat-' + 'a' * 20):
            self.assertNotIn(text, hostlogs.scrub(f'x {text} y'), text)

    def test_a_long_line_cannot_hold_the_server(self):
        # SF-52: each of these cost between 0.7 seconds and 2.5 minutes at the real cap, with the GIL held, and a line is anything a machine's journal is told to hold.
        # They cost a few milliseconds now; the bound is a hundred times that so a slow machine passes and a pattern that reads on from every character does not.
        n = hostlogs.MESSAGE_CHARS
        for name, text in (('one long name', 'a' * (n - 3) + 'key'), ('flags', '--a' * (n // 3 - 2) + 'token'), ('token starts', 'eyJ-' * (n // 4)),
                           ('secret words', 'pwd' * (n // 3)), ('longer words', 'password' * (n // 8))):
            began = time.perf_counter()
            hostlogs.scrub(text)
            self.assertLess(time.perf_counter() - began, 0.1, name)

    def test_a_secret_stays_secret_in_a_long_name_and_in_odd_letters(self):
        # what the patterns match is the same as before the lookahead: the key's length either side of the word, a value inside a value, letters that only look like others
        for text in ('x_' + 'a' * 300 + '_PASSWORD=hunter2', 'password_for_the_database_of_the_billing_department_prod=hunter2', 'foo="a password=hunter2"',
                     'x --db-password hunter2', 'pa\u017f\u017fword=hunter2', 'COOK\u0130E=hunter2', 'to\u212aen=hunter2', 'a' * 3000 + ' api_key=hunter2'):
            self.assertNotIn('hunter2', hostlogs.scrub(text), text[:80])

    def test_a_private_key_takes_the_whole_line(self):
        self.assertEqual(hostlogs.scrub('leak -----BEGIN OPENSSH PRIVATE KEY----- abc'), '[redacted: this line held a private key]')

    def test_ordinary_lines_stay_readable(self):
        for text in ('Failed password for root from 10.0.0.1 port 22 ssh2', 'Accepted publickey for gabe from 10.0.0.1',
                     'pam_unix(sshd:session): session opened for user gabe', 'Started Daily apt download activities.',
                     'https://example.com:8443/path', 'authentication failure; logname= uid=0 rhost=10.0.0.1 user=gabe'):
            self.assertEqual(hostlogs.scrub(text), text)

    def test_nothing_secret_reaches_the_table(self):
        x = hostlogs.parse(output(row('login with password=hunter2')), NOW)['lines'][0]
        self.assertEqual(x['message'], 'login with password=[redacted]')

    def test_the_script_never_asks_for_the_command_line(self):
        self.assertNotIn('_CMDLINE', hostlogs.script(1))


class Storing(Base):
    def store(self, *rows, now=NOW, **kw):
        return hostlogs.store(self.conn, 'nas', hostlogs.parse(output(*rows, **kw), now), now)

    def test_reading_a_line_twice_stores_it_once(self):
        self.assertEqual(self.store(row('a'), row('b')), 2)
        self.assertEqual(self.store(row('b'), row('c')), 1)
        self.assertEqual(self.conn.scalar('SELECT count(*) FROM host_log_lines'), 3)

    def test_first_scan_reads_back_a_week_and_later_ones_from_where_it_stopped(self):
        self.assertEqual(hostlogs.since_for(self.conn, 'nas', NOW), int(NOW) - hostlogs.FIRST_DAYS * 86400)
        self.store(row(at=NOW - 3600))
        self.assertEqual(hostlogs.since_for(self.conn, 'nas', NOW), int(NOW) - 3600 - hostlogs.OVERLAP_SECS)

    def test_a_long_gap_reads_back_no_further_than_the_first_scan(self):
        self.store(row(at=NOW - 3600))
        later = NOW + 90 * 86400
        self.assertEqual(hostlogs.since_for(self.conn, 'nas', later), int(later) - hostlogs.FIRST_DAYS * 86400)

    def test_a_future_line_doesnt_move_where_the_next_scan_starts(self):
        self.store(row('now', at=NOW - 100), row('ahead', at=NOW + 3 * 86400))
        self.assertEqual(hostlogs.since_for(self.conn, 'nas', NOW), int(NOW) - 100 - hostlogs.OVERLAP_SECS)

    def test_no_access_keeps_the_start_so_access_later_reads_the_history(self):
        self.store(row(), who='1000 scan users')
        self.assertEqual(self.conn.scalar('SELECT count(*) FROM host_log_lines'), 0)
        self.assertEqual(hostlogs.since_for(self.conn, 'nas', NOW), int(NOW) - hostlogs.FIRST_DAYS * 86400)
        s = hostlogs.status(self.conn)[0]
        self.assertEqual(s['state'], 'limited')
        self.assertIn('access script', s['note'])

    def test_lines_go_by_when_they_arrived_not_by_the_time_stamped_on_them(self):
        """A line stamped older than the retention was deleted as it was stored (roadmap 3, phase 0): a host with a wrong clock kept nothing."""
        self.store(row('stamped long ago', at=NOW - (hostlogs.KEEP_DAYS + 1) * 86400), row('new'))
        self.assertEqual(sorted(r[0] for r in self.conn.all('SELECT message FROM host_log_lines')), ['new', 'stamped long ago'])
        later = NOW + (hostlogs.KEEP_DAYS + 1) * 86400
        hostlogs.store(self.conn, 'nas', hostlogs.parse(output(row('arrived later', at=NOW - 5)), later), later)
        self.assertEqual([r[0] for r in self.conn.all('SELECT message FROM host_log_lines')], ['arrived later'], 'what arrived more than KEEP_DAYS ago is gone, whatever its stamp')

    def test_a_host_is_held_to_its_row_limit(self):
        keep = hostlogs.KEEP_ROWS
        hostlogs.KEEP_ROWS = 2
        self.addCleanup(setattr, hostlogs, 'KEEP_ROWS', keep)
        self.store(row('a', at=NOW - 30), row('b', at=NOW - 20), row('c', at=NOW - 10))
        self.assertEqual(sorted(r[0] for r in self.conn.all('SELECT message FROM host_log_lines')), ['b', 'c'])

    def test_collect_survives_a_failing_host_and_says_so(self):
        class Dead:
            def run(self, script, timeout=120):
                raise OSError('connection lost')
        said = []
        got = hostlogs.collect(self.conn, Dead(), 'nas', log=said.append)
        self.assertEqual(got['state'], 'failed')
        self.assertIn('connection lost', said[0])
        self.assertIn('connection lost', hostlogs.status(self.conn)[0]['note'])

    def test_collect_can_be_turned_off(self):
        os.environ['STORAGEFORGE_HOST_LOGS'] = '0'
        self.addCleanup(os.environ.pop, 'STORAGEFORGE_HOST_LOGS')
        self.assertIsNone(hostlogs.collect(self.conn, None, 'nas'))


class Ingest(Base):
    """Roadmap 3, phase 0: the holes in what was stored. Arrival decides what is kept, a host has a rate, journald's own account of the
    writer is stored beside the writer's, and counts outlive the lines."""

    def store(self, *rows, now=NOW, host='nas'):
        return hostlogs.store(self.conn, host, hostlogs.parse(output(*rows), now), now)

    def limits(self, **values):
        for name, value in values.items():
            self.addCleanup(setattr, hostlogs, name, getattr(hostlogs, name))
            setattr(hostlogs, name, value)

    def messages(self, host='nas'):
        return sorted(r[0] for r in self.conn.all('SELECT message FROM host_log_lines WHERE host = :h', {'h': host}))

    def test_lines_stamped_ahead_cannot_push_real_lines_out(self):
        """A host could log 500,000 lines stamped a day ahead, and the row limit kept those as the newest and dropped the real ones."""
        self.limits(KEEP_ROWS=3, RATE_PER_DAY=100)
        self.store(row('real 1', at=NOW - 30), row('real 2', at=NOW - 20), now=NOW)
        self.store(row('real 3', at=NOW + 3600 - 10), now=NOW + 3600)
        ahead = [row(f'ahead {i}', at=NOW + 80000 + i) for i in range(2)]
        self.store(*ahead, now=NOW + 7200)
        self.assertEqual(self.messages(), ['ahead 0', 'ahead 1', 'real 3'], 'the three that arrived last, not the three stamped latest')

    def test_a_host_over_its_rate_keeps_its_older_lines_and_the_overflow_is_recorded(self):
        self.limits(RATE_PER_DAY=5)
        self.store(*[row(f'early {i}', at=NOW - 100 + i) for i in range(3)])
        new = self.store(*[row(f'flood {i}', at=NOW + i) for i in range(10)], now=NOW + 60)
        self.assertEqual(new, 2, 'three of a day\'s five were used, and a minute gives back almost nothing')
        self.assertEqual(sum(m.startswith('early') for m in self.messages()), 3, 'the flood did not cost the older lines')
        s = hostlogs.status(self.conn, 'nas')[0]
        self.assertEqual((s['over_rate'], s['over_total'], s['rate_per_day']), (8, 8, 5))
        self.assertIn('8 line(s) were over this host\'s rate of 5 a day', s['note'])

    def test_the_rate_takes_routine_lines_before_warnings(self):
        self.limits(RATE_PER_DAY=2)
        self.store(row('chatter 1'), row('chatter 2'), row('disk failing', priority='3'), row('chatter 3'), row('pool degraded', priority='4'))
        self.assertEqual(self.messages(), ['disk failing', 'pool degraded'])

    def test_the_allowance_comes_back_with_time_up_to_a_days_worth(self):
        self.limits(RATE_PER_DAY=4)
        self.assertEqual(self.store(*[row(f'a{i}') for i in range(6)]), 4)
        self.assertEqual(self.store(*[row(f'b{i}', at=NOW + 43100 + i) for i in range(6)], now=NOW + 43200), 2, 'half a day gives half the rate back')
        self.assertEqual(self.store(*[row(f'c{i}', at=NOW + 900000 + i) for i in range(9)], now=NOW + 900000), 4, 'and ten days give one day\'s worth, not ten')

    def test_a_line_read_twice_is_not_counted_as_over_the_rate(self):
        self.limits(RATE_PER_DAY=2)
        rows = [row('one'), row('two')]
        self.store(*rows)
        self.store(*rows, now=NOW + 10)          # the overlap: a scan reads the last five minutes again
        s = hostlogs.status(self.conn, 'nas')[0]
        self.assertEqual((s['over_rate'], s['over_total'], s['lines']), (0, 0, 2))

    def test_one_hosts_flood_is_its_own(self):
        self.limits(RATE_PER_DAY=2)
        self.store(*[row(f'flood {i}') for i in range(9)], host='loud')
        self.assertEqual(self.store(row('quiet'), host='nas'), 1)
        self.assertEqual(hostlogs.status(self.conn, 'nas')[0]['over_total'], 0)

    def test_what_journald_says_of_the_writer_is_kept_beside_what_the_writer_says(self):
        """SYSLOG_IDENTIFIER is the writer's own word: `logger -t sshd` is anyone. _UID, _COMM and _EXE are journald's."""
        r = {**row('Accepted password for root', ident='sshd'), '_UID': '1000', '_COMM': 'logger', '_EXE': '/usr/bin/logger', '__SEQNUM': '4711', '__SEQNUM_ID': 'ab' * 16}
        x = hostlogs.parse(output(r), NOW)['lines'][0]
        self.assertEqual((x['ident'], x['uid'], x['comm'], x['exe'], x['seqnum'], x['seqnum_id']), ('sshd', 1000, 'logger', '/usr/bin/logger', 4711, 'ab' * 16))
        self.store(r)
        got = hostlogs.page(self.conn, hostlogs.clean_filter())['entries'][0]
        self.assertEqual((got['ident'], got['uid'], got['comm'], got['exe'], got['arrived']), ('sshd', 1000, 'logger', '/usr/bin/logger', int(NOW)))
        self.assertEqual(self.conn.all('SELECT seqnum, seqnum_id FROM host_log_lines')[0][:2], (4711, 'ab' * 16))

    def test_a_host_sends_anything_in_those_fields(self):
        for bad in ('-1', '1e9', '٣', 'root', '', None, [1, 2], '99999999999999999999999999', {'a': 1}):
            r = {**row(f'odd {bad!r}'), '_UID': bad, '__SEQNUM': bad, '__SEQNUM_ID': bad, '_COMM': bad, '_EXE': bad}
            x = hostlogs.parse(output(r), NOW)['lines'][0]
            self.assertEqual((x['uid'], x['seqnum'], x['seqnum_id']), (None, None, None), bad)
            self.assertIn(type(x['comm']), (str, type(None)))
        x = hostlogs.parse(output({**row('esc'), '_COMM': 'a\x1b[31mb\nc', '_EXE': '/x' * 500, '__SEQNUM_ID': 'AB' * 16}), NOW)['lines'][0]
        self.assertEqual(x['comm'], 'a [31mb c')
        self.assertLessEqual(len(x['exe']), hostlogs.NAME_CHARS)
        self.assertIsNone(x['seqnum_id'], 'an ID is 32 lower-case hex digits, or it is not one')
        self.assertEqual(self.store({**row('a line from before these fields')}), 1)
        self.assertEqual(self.conn.all("SELECT uid, comm, seqnum FROM host_log_lines")[0][:3], (None, None, None))

    def counts(self, host='nas'):
        return {(r[0], r[1], r[2]): r[3] for r in self.conn.all('SELECT unit, priority, bucket, lines FROM host_log_counts WHERE host = :h', {'h': host})}

    def test_new_lines_are_counted_per_unit_level_and_five_minutes(self):
        b = int(NOW // 300)
        self.store(row('a', at=NOW - 10), row('b', at=NOW - 20), row('c', at=NOW - 10, priority='3'), row('d', at=NOW - 400), row('e', at=NOW - 5, unit='', ident='kernel'))
        at = lambda secs: int((NOW - secs) // 300)
        self.assertEqual(self.counts(), {('sshd.service', 6, at(10)): 2, ('sshd.service', 3, at(10)): 1, ('sshd.service', 6, at(400)): 1, ('', 6, at(5)): 1})
        self.assertEqual(at(10), b - 1 if NOW % 300 < 10 else b)
        self.store(row('a', at=NOW - 10), row('f', at=NOW - 12), now=NOW + 30)
        self.assertEqual(self.counts()[('sshd.service', 6, at(10))], 3, 'a line read again is counted once')

    def test_a_line_over_the_rate_is_counted_though_not_stored(self):
        self.limits(RATE_PER_DAY=1)
        self.store(*[row(f'flood {i}', at=NOW - 5) for i in range(6)])
        self.assertEqual(len(self.messages()), 1)
        self.assertEqual(sum(self.counts().values()), 6, 'how loud the host was is known, even where the lines are not kept')

    def test_a_clock_ahead_does_not_write_the_futures_counts(self):
        self.store(row('ahead', at=NOW + 50000))
        self.assertEqual(list(self.counts()), [('sshd.service', 6, int(NOW // 300))])

    def test_counts_outlive_the_lines_and_then_go_too(self):
        self.store(row('a', at=NOW - 10))
        later = NOW + (hostlogs.KEEP_DAYS + 5) * 86400
        self.store(row('b', at=later - 10), now=later)
        self.assertEqual(self.messages(), ['b'])
        self.assertEqual(sum(self.counts().values()), 2, 'the count of the line that is gone is still there')
        much = later + (hostlogs.COUNT_KEEP_DAYS + 5) * 86400
        self.store(row('c', at=much - 10), now=much)
        self.assertEqual(sum(self.counts().values()), 1)

    def test_the_newest_lines_of_a_pickup_are_the_ones_kept(self):
        """The journal is read newest first (the KVM lab: before systemd 254, --since with -n gave the oldest lines, and a busy host lost its
        newest for good). Whatever order they come in, the row limit and the rate both give up the older ones."""
        self.assertIn(' -r ', hostlogs.script(0))
        self.limits(KEEP_ROWS=2, RATE_PER_DAY=100)
        self.store(row('newest', at=NOW - 10), row('middle', at=NOW - 20), row('oldest', at=NOW - 30))
        self.assertEqual(self.messages(), ['middle', 'newest'])
        self.limits(KEEP_ROWS=100, RATE_PER_DAY=3)
        self.store(row('r new', at=NOW - 1), row('w old', at=NOW - 50, priority='3'), row('r old', at=NOW - 40), row('w new', at=NOW - 2, priority='4'), row('r mid', at=NOW - 20), host='pc')
        self.assertEqual(self.messages('pc'), ['r new', 'w new', 'w old'], 'the warnings, then the newest routine line')
        self.assertEqual(hostlogs.status(self.conn, 'pc')[0]['over_rate'], 2)

    def test_the_script_asks_for_journalds_own_fields_and_never_the_command_line(self):
        text = hostlogs.script(0)
        for field in ('_UID', '_COMM', '_EXE'):
            self.assertIn(field, text)
        self.assertNotIn('_CMDLINE', text)


class Searching(Base):
    def setUp(self):
        super().setUp()
        hostlogs.store(self.conn, 'nas', hostlogs.parse(output(
            row('disk read error', at=NOW - 30, priority='3', unit='smartd.service', ident='smartd'),
            row('Failed password for root', at=NOW - 20, priority='6'),
            row('=cmd|boom', at=NOW - 10, priority='4', unit=None, ident='cron')), NOW), NOW)
        hostlogs.store(self.conn, 'pc', hostlogs.parse(output(row('pc line', at=NOW - 5, cursor='pc')), NOW), NOW)

    def find(self, **kw):
        return [e['message'] for e in hostlogs.page(self.conn, hostlogs.clean_filter(**kw))['entries']]

    def test_newest_first_across_hosts(self):
        self.assertEqual(self.find(), ['pc line', '=cmd|boom', 'Failed password for root', 'disk read error'])

    def test_filters(self):
        self.assertEqual(self.find(host='pc'), ['pc line'])
        self.assertEqual(self.find(level='err'), ['disk read error'])
        self.assertEqual(self.find(level='warning'), ['=cmd|boom', 'disk read error'])
        self.assertEqual(self.find(unit='smartd'), ['disk read error'])
        self.assertEqual(self.find(unit='cron'), ['=cmd|boom'])
        self.assertEqual(self.find(q='FAILED pass'), ['Failed password for root'])
        self.assertEqual(self.find(since=NOW - 7), ['pc line'])
        self.assertEqual(self.find(until=NOW - 25), ['disk read error'])

    def test_search_text_is_text(self):
        self.assertEqual(self.find(q='%'), [])
        self.assertEqual(self.find(q="' OR 1=1 --"), [])

    def test_a_bad_filter_is_refused(self):
        with self.assertRaises(ValueError):
            hostlogs.clean_filter(level='loud')

    def test_paging(self):
        f = hostlogs.clean_filter()
        one = hostlogs.page(self.conn, f, limit=3)
        two = hostlogs.page(self.conn, f, limit=3, offset=3)
        self.assertTrue(one['more'])
        self.assertFalse(two['more'])
        self.assertEqual(len(one['entries'] + two['entries']), 4)

    def test_exports(self):
        f = hostlogs.clean_filter(host='nas')
        text, n = hostlogs.export(self.conn, f, 'csv')
        self.assertEqual(n, 3)
        rows = list(csv.reader(io.StringIO(text)))
        self.assertEqual(rows[0], list(hostlogs.COLUMNS))
        self.assertEqual(rows[1][6], "'=cmd|boom", 'a spreadsheet must not run a line as a formula')
        self.assertEqual(len(json.loads(hostlogs.export(self.conn, f, 'json')[0])), 3)
        self.assertIn(' nas warning cron[42]: =cmd|boom\n', hostlogs.export(self.conn, f, 'text')[0])
        with self.assertRaises(ValueError):
            hostlogs.export(self.conn, f, 'xml')


class Counting(Base):
    """The counts and the unit list behind the Logs view."""
    HOUR = 3600
    T0 = 1999998000.0                 # 2033-05-18T03:00:00Z, an exact UTC hour, so the buckets below are easy to read

    def setUp(self):
        super().setUp()
        t = self.T0
        self.assertEqual(int(t) % self.HOUR, 0)
        self.rows = [row('a', at=t + 10, priority='3', unit='smartd.service', cursor='1'),
                     row('b', at=t + 20, priority='3', unit='smartd.service', cursor='2'),
                     row('c', at=t + 30, priority='6', unit='sshd.service', cursor='3'),
                     row('d', at=t + self.HOUR - 1, priority='4', unit='sshd.service', cursor='4'),      # still the first hour
                     row('e', at=t + self.HOUR, priority='6', unit='sshd.service', cursor='5'),          # the next hour starts here
                     row('f', at=t + 3 * self.HOUR + 5, priority='0', unit=None, ident='kernel', cursor='6')]
        hostlogs.store(self.conn, 'nas', hostlogs.parse(output(*self.rows), NOW), NOW)
        hostlogs.store(self.conn, 'pc', hostlogs.parse(output(row('pc', at=t + 40, priority='6', unit='cron.service', cursor='7')), NOW), NOW)

    def counts(self, **kw):
        return hostlogs.counts(self.conn, hostlogs.range_filter(**kw))

    def test_by_level_and_by_hour(self):
        got = self.counts(host='nas')
        self.assertEqual(got['total'], 6)
        self.assertEqual(list(got['by_level']), list(hostlogs.LEVELS))
        self.assertEqual({k: v for k, v in got['by_level'].items() if v}, {'emerg': 1, 'err': 2, 'warning': 1, 'info': 2})
        self.assertEqual([(h['hour'], h['total'], h['levels']) for h in got['by_hour']], [
            ('2033-05-18T03:00:00Z', 4, {'err': 2, 'info': 1, 'warning': 1}),
            ('2033-05-18T04:00:00Z', 1, {'info': 1}),
            ('2033-05-18T06:00:00Z', 1, {'emerg': 1})])
        self.assertFalse(got['truncated'])

    def test_without_a_host_it_is_all_hosts(self):
        got = self.counts()
        self.assertEqual((got['total'], got['by_level']['info'], got['by_hour'][0]['total']), (7, 3, 5))

    def test_the_time_range_narrows_it(self):
        got = self.counts(host='nas', since=self.T0 + self.HOUR, until=self.T0 + self.HOUR + 1)
        self.assertEqual((got['total'], [h['hour'] for h in got['by_hour']]), (1, ['2033-05-18T04:00:00Z']))
        self.assertEqual(self.counts(host='nas', since=self.T0 + 7 * self.HOUR)['total'], 0)
        self.assertEqual(self.counts(host='nobody')['by_hour'], [])

    def test_a_range_that_ends_before_it_starts_or_isnt_a_time_is_refused(self):
        with self.assertRaises(ValueError):
            hostlogs.range_filter('nas', since=self.T0 + 5, until=self.T0)
        with self.assertRaises(ValueError):
            hostlogs.range_filter('nas', since='yesterday-ish')

    def test_the_answer_is_bounded(self):
        t = self.T0
        many = [row(f'm{i}', at=t - i * self.HOUR, priority='6', cursor=f'h{i}') for i in range(hostlogs.MAX_HOURS + 30)]
        for r in many:
            self.conn.execute("""INSERT INTO host_log_lines (host, line_key, at_us, priority, unit, ident, pid, message, collected_at)
                                 VALUES ('big', :k, :a, 6, 'u', 'u', 1, 'x', 0)""", {'k': r['__CURSOR'], 'a': int(r['__REALTIME_TIMESTAMP'])})
        got = self.counts(host='big')
        self.assertEqual(len(got['by_hour']), hostlogs.MAX_HOURS)
        self.assertTrue(got['truncated'])
        self.assertEqual(got['total'], hostlogs.MAX_HOURS + 30)       # the totals still say how much there is
        self.assertEqual(got['by_hour'][-1]['hour'], '2033-05-18T03:00:00Z')          # the newest are the ones kept

    def test_units_most_lines_first_and_per_host(self):
        self.assertEqual(hostlogs.units(self.conn, 'nas'), [{'unit': 'sshd.service', 'lines': 3}, {'unit': 'smartd.service', 'lines': 2}])
        self.assertEqual(hostlogs.units(self.conn, 'pc'), [{'unit': 'cron.service', 'lines': 1}])
        self.assertEqual(hostlogs.units(self.conn, 'nobody'), [])
        self.assertEqual([u['unit'] for u in hostlogs.units(self.conn)], ['sshd.service', 'smartd.service', 'cron.service'])

    def test_units_are_capped_and_a_name_is_only_a_value(self):
        for i in range(hostlogs.MAX_UNITS + 20):
            self.conn.execute("""INSERT INTO host_log_lines (host, line_key, at_us, priority, unit, ident, pid, message, collected_at)
                                 VALUES ('many', :k, 1, 6, :u, 'u', 1, 'x', 0)""", {'k': f'k{i}', 'u': f'u{i:04}.service'})
        self.assertEqual(len(hostlogs.units(self.conn, 'many')), hostlogs.MAX_UNITS)
        self.assertEqual(hostlogs.units(self.conn, "x' OR '1'='1"), [])


class TheScript(unittest.TestCase):
    """The real script, in the real shell, against a stand-in journalctl."""

    def run_it(self, journalctl: str | None, since=1234) -> tuple[str, str]:
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        for tool in ('sh', 'id', 'head'):
            (tmp / tool).symlink_to(shutil.which(tool))
        if journalctl is not None:
            f = tmp / 'journalctl'
            f.write_text(f'#!/bin/sh\necho "$*" >> {tmp}/calls\n{journalctl}\n')
            f.chmod(f.stat().st_mode | stat.S_IXUSR)
        p = subprocess.run([str(tmp / 'sh'), '-c', hostlogs.script(since).replace('PATH="$PATH:/usr/sbin:/sbin"', f'PATH={tmp}')],
                           capture_output=True, text=True, timeout=30)
        self.assertEqual(p.returncode, 0, p.stderr)
        calls = tmp / 'calls'
        return p.stdout, calls.read_text() if calls.exists() else ''

    def test_no_journalctl(self):
        self.assertEqual(self.run_it(None)[0], '@@nojournal\n')

    def test_reads_both_streams_from_the_given_time(self):
        line = json.dumps(row('from the stand-in'))
        out, calls = self.run_it(f"case \"$*\" in *'-n 0'*) ;; *) echo '{line}' ;; esac")
        self.assertIn('--since @1234', calls)
        self.assertIn('-p warning -n 2000', calls)
        self.assertIn('-p info -n 5000', calls)
        self.assertIn('--output-fields=', calls)
        got = hostlogs.parse(out.replace(out.splitlines()[0], '@@who 0 root'), NOW)
        self.assertEqual([x['message'] for x in got['lines']], ['from the stand-in'])
        self.assertEqual(got['state'], 'ok')

    def test_an_old_journalctl_without_output_fields_still_works(self):
        out, calls = self.run_it('case "$*" in *--output-fields*) exit 1 ;; esac')
        self.assertIn('@@end', out)
        self.assertNotIn('--output-fields=MESSAGE,', calls)

    def test_only_a_number_reaches_the_shell(self):
        with self.assertRaises((TypeError, ValueError)):
            hostlogs.script('1"; rm -rf /; "')


class Wiring(Base):
    def test_access_script_adds_and_removes_the_journal_group(self):
        self.assertIn('usermod -a -G systemd-journal', access.setup_script('scan'))
        self.assertIn('gpasswd -d scan systemd-journal', access.remove_script('scan'))

    def test_host_logs_are_not_for_viewers(self):
        self.assertEqual(permissions.required('GET', '/api/hostlogs'), 'hostlogs.view')
        self.assertEqual(permissions.required('GET', '/api/hostlogs/export'), 'hostlogs.view')
        self.assertNotIn('hostlogs.view', permissions.BUILTIN['viewer'][1])
        self.assertIn('hostlogs.view', permissions.BUILTIN['operator'][1])
        self.assertIn('hostlogs.view', permissions.BUILTIN['admin'][1])

    def test_status_counts_what_is_kept(self):
        now = time.time()
        hostlogs.store(self.conn, 'nas', hostlogs.parse(output(row(at=now - 9)), now), now)
        s = hostlogs.status(self.conn, 'nas')[0]
        self.assertEqual((s['lines'], s['new_lines'], s['state'], s['note']), (1, 1, 'ok', ''))


@unittest.skipIf(dbfactory.PG, 'these drive a SQLite file through --db and a local app')
class Entrances(unittest.TestCase):
    """The same lines through the web, the CLI and a real scan."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.path = f'{self.tmp}/t.db'
        self.db = Database(self.path)
        self.conn = self.db.connect()
        self.addCleanup(self.conn.close)
        self.db.migrate(self.conn)
        now = time.time()
        hostlogs.store(self.conn, 'nas', hostlogs.parse(output(row('=disk read error', at=now - 9, priority='3')), now), now)

    def client(self, role):
        users.create(self.conn, role, PW, role)
        c = server.create_app(server.App(self.db), 's' * 48).test_client()
        self.assertEqual(c.post('/api/login', json={'username': role, 'password': PW}).status_code, 200)
        return c

    def test_web(self):
        c = self.client('operator')
        self.assertEqual([e['message'] for e in c.get('/api/hostlogs?host=nas&level=err').get_json()['entries']], ['=disk read error'])
        self.assertEqual(c.get('/api/hostlogs/status').get_json()['hosts'][0]['host'], 'nas')
        got = c.get('/api/hostlogs/export?format=csv')
        self.assertIn("'=disk read error", got.get_data(as_text=True))
        self.assertIn('attachment', got.headers['Content-Disposition'])
        self.assertEqual(self.conn.scalar("SELECT count(*) FROM audit_log WHERE action = 'hostlogs.export'"), 1)
        self.assertEqual(c.get('/api/hostlogs?level=loud').status_code, 400)

    def test_a_viewer_is_turned_away(self):
        c = self.client('viewer')
        for path in ('/api/hostlogs', '/api/hostlogs/status', '/api/hostlogs/export'):
            self.assertEqual(c.get(path).status_code, 403, path)

    def test_counts_and_units_over_the_web(self):
        c = self.client('operator')
        got = c.get('/api/hostlogs/counts?host=nas').get_json()
        self.assertEqual((got['total'], got['by_level']['err'], len(got['by_hour'])), (1, 1, 1))
        self.assertRegex(got['by_hour'][0]['hour'], r'^\d{4}-\d\d-\d\dT\d\d:00:00Z$')
        self.assertEqual(c.get('/api/hostlogs/units?host=nas').get_json(), {'host': 'nas', 'units': [{'unit': 'sshd.service', 'lines': 1}]})
        self.assertEqual(c.get('/api/hostlogs/counts?host=nas&since=2000-01-01&until=1999-01-01').status_code, 400)
        self.assertEqual(c.get('/api/hostlogs/counts?since=never').status_code, 400)
        self.assertEqual(c.get('/api/hostlogs/counts?host=nas&since=0&until=1').get_json()['total'], 0)

    def test_a_viewer_is_turned_away_from_counts_and_units(self):
        c = self.client('viewer')
        for path in ('/api/hostlogs/counts', '/api/hostlogs/counts?host=nas', '/api/hostlogs/units', '/api/hostlogs/units?host=nas'):
            self.assertEqual(c.get(path).status_code, 403, path)
        self.assertEqual(permissions.required('GET', '/api/hostlogs/counts'), 'hostlogs.view')
        self.assertEqual(permissions.required('GET', '/api/hostlogs/units'), 'hostlogs.view')

    def run_cli(self, *args):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(cli.main(['--db', self.path, *args]), 0)
        return out.getvalue()

    def test_cli(self):
        self.assertIn('=disk read error', self.run_cli('hostlogs', '--host', 'nas', '--level', 'err'))
        self.assertIn('nas  ok', self.run_cli('hostlogs', '--status'))
        self.assertEqual(self.run_cli('hostlogs', '--grep', 'nothing like this'), '')
        with self.assertRaises(SystemExit):
            self.run_cli('hostlogs', '--level', 'loud')
        file = f'{self.tmp}/out.json'
        self.assertIn('1 lines written', self.run_cli('hostlogs', '--format', 'json', '-o', file))
        self.assertEqual(json.loads(Path(file).read_text())[0]['host'], 'nas')

    def test_a_scan_collects_and_a_failed_pickup_doesnt_cost_the_scan(self):
        root = Path(self.tmp) / 'tree'
        root.mkdir()
        (root / 'f').write_text('x')
        real = Transport(host='localhost', local=True)
        hostname = collect_inventory(real).hostname
        opts = ScanOptions(roots=[str(root)], include_tmpfs=True)

        class Journal(Transport):
            def run(inner, script, timeout=120):      # the inventory is real; the journal is ours
                return output(row('picked up by a scan', at=time.time() - 5)) if 'journalctl' in script and '@@important' in script else Transport.run(inner, script, timeout)
        self.assertIsNotNone(scan_host(self.db, Journal(host='localhost', local=True), opts, log=lambda _: None))
        self.assertEqual(self.conn.scalar('SELECT count(*) FROM host_log_lines WHERE host = :h', {'h': hostname}), 1)

        class Dropped(Transport):
            def run(inner, script, timeout=120):
                if 'journalctl' in script and '@@important' in script:
                    raise OSError('journal went away')
                return Transport.run(inner, script, timeout)
        self.assertIsNotNone(scan_host(self.db, Dropped(host='localhost', local=True), opts, log=lambda _: None))
        self.assertEqual(hostlogs.status(self.conn, hostname)[0]['state'], 'failed')
        self.assertEqual(self.conn.scalar("SELECT status FROM scans ORDER BY scan_id DESC LIMIT 1"), 'ok')


if __name__ == '__main__':
    unittest.main()
