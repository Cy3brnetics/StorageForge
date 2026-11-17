"""What the server does when it is asked for more than it can do at once, as tests/stress/hammer.py found it should. Each behaviour here was a
break under load before: eight people opening the file map built it eight times over; requests waiting for an analysis held every thread, so
a list of hosts took seconds; and each request's connection held 256 MiB of SQLite cache."""
import shutil
import sqlite3
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

import dbfactory
from storageforge_index import folders, server, users

PW = 'under-load-password-0123456789'


class Base(unittest.TestCase):
    """A server on a fresh database with one account: no tests of its own."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.db = dbfactory.make(self, self.tmp / 'index.db')
        conn = self.db.connect()
        self.db.migrate(conn)
        users.create(conn, 'admin', PW, 'admin')
        conn.execute("INSERT INTO hosts (hostname, ssh_host, inventory_json) VALUES ('nas', 'nas', '{}')")
        conn.close()
        self.web = server.create_app(server.App(self.db), 's' * 48)

    def client(self):
        c = self.web.test_client()
        self.assertEqual(c.post('/api/login', json={'username': 'admin', 'password': PW}).status_code, 200)
        return c


class Server(Base):
    def test_many_asking_for_one_analysis_build_it_once(self):
        calls, gate = [], threading.Event()

        def slow(conn, host, years, min_size, limit=200, **_):
            calls.append(host)
            gate.wait(5)
            return {'folders': [], 'total': 0, 'bytes': 0, 'cutoff': 0}
        answers = []
        with mock.patch.object(folders, 'cold_folders', slow):
            threads = [threading.Thread(target=lambda c=self.client(): answers.append(c.get('/api/folders/cold?host=nas&years=1&min_size=1').status_code)) for _ in range(6)]
            for t in threads:
                t.start()
            time.sleep(0.5)
            gate.set()
            for t in threads:
                t.join(10)
        self.assertEqual(len(calls), 1, 'six requests, one build')
        self.assertEqual(answers, [200] * 6)
        with mock.patch.object(folders, 'cold_folders', slow):
            self.assertEqual(self.client().get('/api/folders/cold?host=nas&years=1&min_size=1').status_code, 200)
        self.assertEqual(len(calls), 1, 'and the next is answered from what it made')

    def test_an_analysis_that_takes_too_long_is_asked_for_again_and_is_there_by_then(self):
        gate = threading.Event()

        def slow(*_a, **_k):
            gate.wait(5)
            return {'folders': [], 'total': 0, 'bytes': 0, 'cutoff': 0}
        c = self.client()
        with mock.patch.object(folders, 'cold_folders', slow), mock.patch.object(server, 'FOLDER_WAIT_HERE', 0.2):
            r = c.get('/api/folders/cold?host=nas&years=1&min_size=1')
            self.assertEqual(r.status_code, 503)
            self.assertEqual(r.headers['Retry-After'], str(server.FOLDER_RETRY))
            self.assertTrue(r.get_json()['busy'])
            gate.set()
            for _ in range(50):                       # the build went on without the request that started it
                r = c.get('/api/folders/cold?host=nas&years=1&min_size=1')
                if r.status_code == 200:
                    break
                time.sleep(0.1)
        self.assertEqual(r.status_code, 200)

    def test_past_so_many_builds_waiting_a_new_kind_of_request_is_asked_back(self):
        gate = threading.Event()

        def slow(*_a, **_k):
            gate.wait(5)
            return {'folders': [], 'total': 0, 'bytes': 0, 'cutoff': 0}
        c = self.client()
        with mock.patch.object(folders, 'cold_folders', slow), mock.patch.object(server, 'FOLDER_PENDING', 2), mock.patch.object(server, 'FOLDER_WAIT_HERE', 0.1):
            for years in (1, 2):
                self.assertEqual(c.get(f'/api/folders/cold?host=nas&years={years}&min_size=1').status_code, 503)
            r = c.get('/api/folders/cold?host=nas&years=3&min_size=1')
            self.assertEqual(r.status_code, 503)
            self.assertIn('many folder analyses are waiting', r.get_json()['error'])
            gate.set()

    def test_when_a_scan_lands_the_last_result_is_answered_while_the_new_one_is_built(self):
        """hammer.py --writer: a scan every 10 s emptied the cache each time, and at 64 clients the analyses never settled."""
        version, gate = [1], threading.Event()

        def made(*_a, **_k):
            if version[0] > 1:
                gate.wait(5)
            return {'folders': [], 'total': version[0], 'bytes': 0, 'cutoff': 0}
        c = self.client()
        url = '/api/folders/cold?host=nas&years=1&min_size=1'
        with mock.patch.object(folders, 'cold_folders', made), mock.patch.object(server, 'FOLDER_WAIT_HERE', 0.2):
            self.assertEqual(c.get(url).get_json()['total'], 1)
            conn = self.db.connect()
            conn.scalar(f"INSERT INTO scans (host_id, started_at, status) SELECT host_id, {self.db.ts('1')}, 'ok' FROM hosts RETURNING scan_id")
            version[0] = 2
            r = c.get(url).get_json()
            self.assertEqual((r.get('total'), r.get('stale')), (1, True), f'the last one, at once, marked: {r}')
            gate.set()
            for _ in range(50):
                r = c.get(url).get_json()
                if not r.get('stale'):
                    break
                time.sleep(0.1)
            self.assertEqual((r['total'], r.get('stale')), (2, None), 'and the new one when it is made')
            conn.execute(f"INSERT INTO scans (host_id, started_at, status) SELECT host_id, {self.db.ts('2')}, 'running' FROM hosts")   # a scan starts: a new id
            version[0] = 3
            r = c.get(url).get_json()
            self.assertTrue(r['stale'])
            self.assertEqual(r['total'], 2, 'while a scan runs the last one stands and nothing is built')
            conn.close()

    def test_a_build_that_fails_says_so_to_everyone_waiting_for_it(self):
        def broken(*_a, **_k):
            time.sleep(0.3)
            raise ValueError('that folder analysis cannot be made')
        answers = []
        with mock.patch.object(folders, 'cold_folders', broken):
            threads = [threading.Thread(target=lambda c=self.client(): answers.append(c.get('/api/folders/cold?host=nas&years=1&min_size=1').status_code)) for _ in range(3)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(10)
        self.assertEqual(answers, [400] * 3)

    def test_the_file_map_builds_its_folder_comparison_on_the_slot_it_holds(self):
        """Its twin folders are an analysis of their own: built on a thread of their own they waited for the one slot the file map held."""
        with mock.patch.object(server, 'FOLDER_PARALLEL', 1):
            web = server.create_app(server.App(self.db), 's' * 48)
            c = web.test_client()
            c.post('/api/login', json={'username': 'admin', 'password': PW})
            started = time.time()
            self.assertEqual(c.get('/api/filemap?folders=1&min_size=1').status_code, 200)
        self.assertLess(time.time() - started, 5)

    def test_past_four_searches_at_once_the_next_is_asked_for_again_in_a_second(self):
        c = self.client()
        held = []
        slots = None
        for cell in self.web.before_request_funcs[None]:
            if cell.__name__ == 'admit_expensive':
                slots = dict(zip(cell.__code__.co_freevars, (x.cell_contents for x in cell.__closure__)))['expensive_slots']
        self.assertIsNotNone(slots)
        for _ in range(server.EXPENSIVE_PARALLEL):
            self.assertTrue(slots.acquire(timeout=1))
            held.append(1)
        try:
            r = c.get('/api/search?q=*.jpg')
            self.assertEqual((r.status_code, r.headers.get('Retry-After')), (503, '1'))
            self.assertEqual(c.get('/api/hosts').status_code, 200, 'a light route is not held back')
        finally:
            for _ in held:
                slots.release()
        self.assertEqual(c.get('/api/search?q=*.jpg').status_code, 200)
        for _ in range(server.EXPENSIVE_PARALLEL + 2):          # each one gives its slot back, failed or not
            c.get('/api/search')
        self.assertEqual(c.get('/api/search?q=*.jpg').status_code, 200)

    @unittest.skipIf(dbfactory.PG, 'a SQLite page cache')
    def test_a_requests_connection_keeps_a_small_cache_and_a_scan_a_large_one(self):
        lean = self.db.lean().connect()
        full = self.db.connect()
        try:
            self.assertEqual(lean.scalar('PRAGMA cache_size'), -16384)
            self.assertEqual(full.scalar('PRAGMA cache_size'), -262144)
        finally:
            lean.close()
            full.close()


class DatabaseShort(Base):
    def test_a_database_out_of_resources_for_a_moment_is_asked_again_not_a_500(self):
        """PostgreSQL in Docker ran out of its 64 MiB /dev/shm under parallel searches: each such search was a 500."""
        class DiskFull(Exception):
            sqlstate = '53100'
        c = self.client()
        for exc in (DiskFull('could not resize shared memory segment'), sqlite3.OperationalError('database is locked')):
            with self.subTest(type(exc).__name__), mock.patch.object(server, 'run_search', side_effect=exc):
                r = c.get('/api/search?q=*.jpg')
                self.assertEqual((r.status_code, r.headers.get('Retry-After')), (503, '2'))
                self.assertTrue(r.get_json()['busy'])
        class Syntax(Exception):
            sqlstate = '42601'
        with mock.patch.object(server, 'run_search', side_effect=Syntax('a real fault')):
            self.assertEqual(c.get('/api/search?q=*.jpg').status_code, 500, 'a fault is still a fault')


class FleetComparison(unittest.TestCase):
    def index(self, fp):
        own = {'/d/a': [10, 3], '/d/b': [10, 3]}
        return folders.MountDirs(own, {'/d/a': (fp, 3, 2 << 20), '/d/b': (fp, 3, 2 << 20)})

    def test_every_hosts_view_shares_one_comparison_until_the_index_is_rebuilt(self):
        mounts = {1: ('nas', '/')}
        first = {1: self.index(7)}
        a = folders._fleet_groups(first, mounts, 3, 1, False)
        self.assertIs(folders._fleet_groups(dict(first), mounts, 3, 1, False), a, 'the same mount indexes, a new dict: the same comparison')
        rebuilt = {1: self.index(9)}
        b = folders._fleet_groups(rebuilt, mounts, 3, 1, False)
        self.assertIsNot(b, a, 'an index rebuilt after a scan is never taken for the old one')
        self.assertEqual(list(b[0]), [9])
        self.assertIsNot(folders._fleet_groups(rebuilt, mounts, 4, 1, False), b, 'other limits, another comparison')


if __name__ == '__main__':
    unittest.main()
