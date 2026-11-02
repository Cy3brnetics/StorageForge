"""Small fixes from the 2026-11-01 code audit that have no better home."""
import tempfile
import unittest

from storageforge_index import changes, jobs, logbook, moves, server
from storageforge_index.db import Database


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
