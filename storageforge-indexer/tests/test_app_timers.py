"""The server's timers (scheduler, nightly backup, alerts, security) run under serve() only. A test's App started them too, and they
outlived the test: two minutes on, the nightly backup made STORAGEFORGE_BACKUP_DIR of whichever test was running then (test_sites, on
GitHub's CI on 2026-11-13), and the alerts thread kept opening a database whose folder was gone."""
import inspect
import shutil
import tempfile
import threading
import unittest

try:
    import dbfactory
except ImportError:      # run as tests.test_x from the project folder
    from tests import dbfactory
from storageforge_index import server

TIMERS = {'scheduler', 'nightly', 'alerts', 'security'}


class AppTimers(unittest.TestCase):
    def test_an_app_a_test_makes_starts_no_timer(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        db = dbfactory.make(self, f'{d}/idx.db')
        conn = db.connect()
        db.migrate(conn)
        conn.close()
        before = {t.ident for t in threading.enumerate()}
        server.App(db)
        started = {t.name for t in threading.enumerate() if t.ident not in before}
        self.assertFalse(started & TIMERS, started)
        self.assertTrue(any(n.startswith('scan-worker-') for n in started), started)     # scans queued by a test still run

    def test_serve_turns_them_on(self):
        self.assertIn('timers=True', inspect.getsource(server.serve))


if __name__ == '__main__':
    unittest.main()
