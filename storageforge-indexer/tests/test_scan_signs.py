"""What a scan shows of an encryptor at work (security._scan_signs): names, and files renamed in place with an extension
put after the name. Found on 2026-11-08: the rename check joined every added file of a scan with every deleted one, and
one scan that moved a big folder (21 thousand added, 287 thousand deleted) held every web thread of a live server for
hours, as the security posture asked again each minute. It is a set lookup now, worked out once per scan."""
import shutil
import tempfile
import threading
import time
import unittest
from pathlib import Path

try:
    import dbfactory
except ImportError:      # run as tests.test_x from the project folder
    from tests import dbfactory
from storageforge_index import security


class Signs(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp)
        self.db = dbfactory.make(self, Path(tmp) / 'index.db')
        self.conn = self.db.connect()
        self.db.migrate(self.conn)
        self.addCleanup(self.conn.close)
        self.conn.execute("INSERT INTO hosts (hostname, ssh_host) VALUES ('h', 'h')")
        hid = self.conn.scalar("SELECT host_id FROM hosts WHERE hostname = 'h'")
        self.conn.execute("INSERT INTO mounts (host_id, mount_point, source, filesystem_type, scan_state) VALUES (:h, '/srv', 'x', 'ext4', 'indexed')", {'h': hid})
        self.mid = self.conn.scalar('SELECT mount_id FROM mounts')
        self.sid = self.conn.scalar(f"INSERT INTO scans (host_id, status, started_at) VALUES (:h, 'ok', {self.db.ts('0')}) RETURNING scan_id", {'h': hid})
        security._SIGNS.clear()

    def change(self, kind, parent, name, mount=None, is_dir=0):
        self.conn.execute("""INSERT INTO file_changes (scan_id, mount_id, change_type, parent_path, filename, is_directory)
                             VALUES (:s, :m, :k, :p, :f, :d)""", {'s': self.sid, 'm': mount or self.mid, 'k': kind, 'p': parent, 'f': name, 'd': bool(is_dir)})

    def test_a_rename_in_place_is_counted_per_name_it_extends(self):
        self.change('deleted', '/srv/docs', 'report.docx')
        self.change('added', '/srv/docs', 'report.docx.xyz')          # the encryptor's rename
        self.change('deleted', '/srv/docs', 'report')
        self.change('added', '/srv/docs', 'report.v2.final')            # extends report: one pair (report.docx.xyz made two, one per name)
        self.change('added', '/srv/other', 'report.docx.xyz')         # another folder: not a rename of that file
        self.change('added', '/srv/docs', 'reportxdocx')               # no dot after the name
        self.change('added', '/srv/docs', 'report.docx.d', is_dir=1)    # a folder
        self.change('added', '/srv/docs', 'README.txt')
        self.change('added', '/srv/docs', 'README.txt.locky')          # its README.txt was not deleted
        self.assertEqual(security._appended(self.conn, self.sid), 3)

    def test_signs_are_worked_out_once_per_scan(self):
        self.change('deleted', '/srv', 'a.txt')
        self.change('added', '/srv', 'a.txt.enc')
        calls = []
        real = security._scan_signs_now

        def slow(conn, sid):
            calls.append(sid)
            time.sleep(0.3)
            return real(conn, sid)
        security._scan_signs_now = slow
        self.addCleanup(setattr, security, '_scan_signs_now', real)
        got = []

        def ask():
            c = self.db.connect()
            try:
                got.append(security._scan_signs(c, self.sid))
            finally:
                c.close()
        threads = [threading.Thread(target=ask) for _ in range(5)]      # posture, the alert loop and the tick, all at once
        for t in threads:
            t.start()
        for t in threads:
            t.join(10)
        self.assertEqual(calls, [self.sid])
        self.assertEqual([g['appended_extensions'] for g in got], [1] * 5)
        got[0]['appended_extensions'] = 99                              # a caller's copy, not the kept one
        self.assertEqual(security._scan_signs(self.conn, self.sid)['appended_extensions'], 1)
        self.change('deleted', '/srv', 'b.txt')                         # the same scan id holding something else: worked out again
        self.change('added', '/srv', 'b.txt.enc')
        self.assertEqual(security._scan_signs(self.conn, self.sid)['appended_extensions'], 2)


if __name__ == '__main__':
    unittest.main()
