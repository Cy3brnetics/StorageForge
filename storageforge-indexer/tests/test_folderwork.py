"""serve()'s folder analysis worker (folderwork.py): a process of its own, so the analyses don't share the web's interpreter, and replaceable,
so a worker that dies costs one request an error and nothing more."""
import os
import shutil
import signal
import tempfile
import time
import unittest
from pathlib import Path

import dbfactory
from storageforge_index import folderwork
from storageforge_index.stream import to_row


class Worker(unittest.TestCase):
    def setUp(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        self.db = dbfactory.make(self, tmp / 'index.db')
        conn = self.db.connect()
        self.db.migrate(conn)
        hid = conn.scalar("INSERT INTO hosts (hostname, ssh_host, inventory_json) VALUES ('nas', 'nas', '{}') RETURNING host_id")
        mid = conn.scalar("INSERT INTO mounts (host_id, mount_point, filesystem_type, scan_state) VALUES (:h, '/', 'ext4', 'indexed') RETURNING mount_id", {'h': hid})
        scan = self.db.begin_scan(conn, hid)
        rows = [to_row([b'f', b'4096', b'644', b'0', b'0', b'1000000000', b'', f'/srv/{d}/f{i}.txt'.encode()]) for d in ('a', 'b') for i in range(5)]
        self.db.stage_create(conn, 1)
        self.db.stage_insert(conn, 1, rows)
        self.db.apply_diff(conn, scan, 1, mid, '/', True)
        self.db.stage_drop(conn, 1)
        conn.close()
        self.worker = folderwork.Worker()
        self.addCleanup(self.worker.stop)

    def test_the_worker_makes_what_this_process_would(self):
        for kind, args in (('cold', ('nas', 1.0, 1)), ('dupes', ('nas', 3, 1, False)), ('filemap', ('nas', 1, False, True))):
            with self.subTest(kind):
                there, here = self.worker.run(self.db.url, kind, args), folderwork.compute(self.db.url, kind, args)
                if kind == 'cold':
                    there.pop('cutoff'), here.pop('cutoff')          # now, in each process
                self.assertEqual(there, here)
        self.assertEqual(self.worker.run(self.db.url, 'dupes', ('nas', 3, 1, False))['total_groups'], 1, '/srv/a and /srv/b are twins')

    def test_a_worker_that_dies_costs_one_request_and_the_next_has_a_new_one(self):
        self.worker.run(self.db.url, 'index', ())
        os.kill(next(iter(self.worker.pool._processes)), signal.SIGKILL)
        time.sleep(0.3)
        with self.assertRaisesRegex(RuntimeError, 'worker stopped'):
            self.worker.run(self.db.url, 'cold', ('nas', 1.0, 1))
        self.assertEqual(self.worker.run(self.db.url, 'cold', ('nas', 1.0, 1))['total'], folderwork.compute(self.db.url, 'cold', ('nas', 1.0, 1))['total'])

    def test_an_analysis_it_does_not_know_is_refused(self):
        with self.assertRaisesRegex(ValueError, "no analysis 'nope'"):
            self.worker.run(self.db.url, 'nope', ())


if __name__ == '__main__':
    unittest.main()
