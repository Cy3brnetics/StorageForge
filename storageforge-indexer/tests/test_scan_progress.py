"""How far a running scan is (the progress bars in the web UI's Scans list). What must hold: a real scan names its stages in order
and its counters end at what the scan stored; the jobs list carries a running scan's progress and a waiting scan's place; and a
finished scan leaves nothing behind."""
import shutil
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import dbfactory
from storageforge_index import server
from storageforge_index.remote import Transport
from storageforge_index.scanner import Progress, ScanOptions, scan_host
from test_security import Base


class Watched(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='sfprog-'))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        for folder, n in (('a', 300), ('b', 40)):
            (self.tmp / 'tree' / folder).mkdir(parents=True)
            for i in range(n):
                (self.tmp / 'tree' / folder / f'f{i}').write_text('x' * 10)
        self.db = dbfactory.make(self, self.tmp / 'idx.db')
        conn = self.db.connect()
        self.db.migrate(conn)
        conn.close()

    def test_a_real_scan_names_its_stages_in_order_and_counts_what_it_stored(self):
        progress, seen = Progress(expected=100), []
        stage = progress.stage
        progress.stage = lambda name, jobs=None: (seen.append((name, progress.snapshot()['entries'])), stage(name, jobs))[1]
        opts = ScanOptions(roots=[str(self.tmp / 'tree' / 'a'), str(self.tmp / 'tree' / 'b')], include_tmpfs=True, include_fstypes=['overlay'], progress=progress)
        result = scan_host(self.db, Transport('localhost', local=True), opts, log=lambda m: None)
        names = [n for n, _ in seen]
        self.assertEqual(names, ['inventory', 'preparing', 'files', 'writing', 'surveys', 'finishing'])
        self.assertEqual([n for n in names if n not in Progress.STAGES], [])
        self.assertEqual(dict(seen)['files'], 0, 'nothing was read before the files stage')
        now = progress.snapshot()
        self.assertEqual((now['entries'], now['filesystems'], now['filesystems_done'], now['reading'], now['expected']), (result['entries'], 2, 2, [], 100))
        self.assertEqual(dict(seen)['writing'], result['entries'], 'every row had been counted by the time reading ended')
        self.assertGreater(now['bytes'], 0)

    def test_a_scan_nobody_watches_is_the_same_scan(self):
        opts = ScanOptions(roots=[str(self.tmp / 'tree')], include_tmpfs=True, include_fstypes=['overlay'])
        self.assertEqual(scan_host(self.db, Transport('localhost', local=True), opts, log=lambda m: None)['status'], 'ok')

    def test_a_filesystem_being_read_is_named_until_it_is_done(self):
        progress = Progress()
        progress.stage('files', 2)
        progress.live += [SimpleNamespace(entries=10, bytes=5, job=SimpleNamespace(id=1, root='/srv')), SimpleNamespace(entries=4, bytes=1, job=SimpleNamespace(id=2, root='/home'))]
        self.assertEqual((progress.snapshot()['reading'], progress.snapshot()['entries']), (['/srv', '/home'], 14))
        progress.finished.append(1)
        now = progress.snapshot()
        self.assertEqual((now['reading'], now['filesystems_done'], now['entries'], now['expected']), (['/home'], 1, 14, None))


class JobsList(Base):
    def test_a_running_scan_says_how_far_it_is_and_a_waiting_one_its_place(self):
        reading, done = threading.Event(), threading.Event()

        def scan(db, host, opts, actor=None, log=None):
            opts.progress.stage('files', 3)
            opts.progress.live.append(SimpleNamespace(entries=1234, bytes=99, job=SimpleNamespace(id=1, root='/srv')))
            reading.set()
            done.wait(20)
            return {'status': 'ok', 'host': host}
        self.conn.execute("INSERT INTO scans (host_id, started_at, finished_at, status, entries_seen) SELECT host_id, 1, 2, 'ok', 5000 FROM hosts WHERE hostname = 'nas'")
        with mock.patch.object(server, 'scan_via_vault', scan):
            jid = self.app.enqueue('nas', 'test')
            self.assertTrue(reading.wait(20))
            for n in (1, 2):                 # two more asked for, which no worker has taken
                self.conn.execute("INSERT INTO scan_jobs (host, requested_by, queued_at) VALUES (:h, 'test', :t)", {'h': f'later{n}', 't': int(time.time())})
            jobs = {j['host']: j for j in self.client.get('/api/jobs').get_json()['jobs']}
            got = jobs['nas']['progress']
            self.assertEqual((got['stage'], got['entries'], got['expected'], got['filesystems'], got['filesystems_done'], got['reading']), ('files', 1234, 5000, 3, 0, ['/srv']))
            self.assertEqual((jobs['later1']['ahead'], jobs['later2']['ahead']), (0, 1))
            self.assertNotIn('progress', jobs['later1'])
            done.set()
            for _ in range(200):
                if self.conn.scalar('SELECT status FROM scan_jobs WHERE job_id = :j', {'j': jid}) == 'ok':
                    break
                time.sleep(0.05)
        for _ in range(100):
            if jid not in self.app.progress:
                break
            time.sleep(0.05)
        self.assertNotIn(jid, self.app.progress, 'a finished scan leaves nothing behind')
        self.assertNotIn('progress', {j['host']: j for j in self.client.get('/api/jobs').get_json()['jobs']}['nas'])

    def test_a_first_scan_has_nothing_to_measure_against(self):
        reading, done = threading.Event(), threading.Event()

        def scan(db, host, opts, actor=None, log=None):
            reading.set()
            done.wait(20)
            return {'status': 'ok', 'host': host}
        with mock.patch.object(server, 'scan_via_vault', scan):
            self.app.enqueue('10.9.9.9', 'test')
            self.assertTrue(reading.wait(20))
            got = self.client.get('/api/jobs').get_json()['jobs'][0]['progress']
            done.set()
        self.assertEqual((got['stage'], got['expected'], got['entries']), ('connecting', None, 0))


if __name__ == '__main__':
    unittest.main()
