"""Regressions for the bug reports of 2026-11-10 (release 0.5.1)."""
import contextlib
import hashlib
import os
import shutil
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

try:
    import dbfactory
except ImportError:      # run as tests.test_x from the project folder
    from tests import dbfactory
from storageforge_index import runner
from storageforge_index.db import Database
from storageforge_index.remote import Transport
from storageforge_index.scanner import ScanOptions


class DatabaseOutOfReach(unittest.TestCase):
    @unittest.skipIf(os.geteuid() == 0, 'root reads past the mode')
    def test_a_folder_it_cannot_enter_says_how_to_run_it(self):
        """vault bind from a root shell in the container: /app is the app user's alone, and it gave a traceback."""
        d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d)
        (d / 'app').mkdir(mode=0o700)
        (d / 'app' / 'data').mkdir()
        os.chmod(d / 'app', 0)
        self.addCleanup(os.chmod, d / 'app', 0o700)
        with self.assertRaises(SystemExit) as got:
            Database(f'sqlite:///{d}/app/data/index.db')
        self.assertIn('docker compose exec storageforge storageforge-index', str(got.exception))
        self.assertIn(f'uid {os.getuid()}', str(got.exception))



class ChecksumCatchUp(unittest.TestCase):
    """nas was hashed before a file was copied to pc. pc's checksum pass hashed its copy, and nas's never was."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)
        self.db = dbfactory.make(self, self.tmp / 'index.db')
        self.conn = self.db.connect()
        self.addCleanup(self.conn.close)
        self.db.migrate(self.conn)
        self.data = self.tmp / 'data'
        self.data.mkdir()
        self.blob = os.urandom(2 << 20)
        (self.data / 'x.iso').write_bytes(self.blob)

    def row(self, host, name, size, sha):
        c = self.conn
        if not c.scalar('SELECT 1 FROM hosts WHERE hostname = :h', {'h': host}):
            c.execute('INSERT INTO hosts (hostname, ssh_host) VALUES (:h, :h)', {'h': host})
            hid = c.scalar('SELECT host_id FROM hosts WHERE hostname = :h', {'h': host})
            c.execute("INSERT INTO mounts (host_id, mount_point, filesystem_type, scan_state) VALUES (:i, '/', 'ext4', 'indexed')", {'i': hid})
        mid = c.scalar("SELECT m.mount_id FROM mounts m JOIN hosts h ON h.host_id = m.host_id WHERE h.hostname = :h", {'h': host})
        if not c.scalar('SELECT 1 FROM directories WHERE mount_id = :m AND path = :p', {'m': mid, 'p': str(self.data)}):
            c.execute('INSERT INTO directories (mount_id, path) VALUES (:m, :p)', {'m': mid, 'p': str(self.data)})
        did = c.scalar('SELECT dir_id FROM directories WHERE mount_id = :m AND path = :p', {'m': mid, 'p': str(self.data)})
        c.execute(f"""INSERT INTO file_records (mount_id, dir_id, filename, file_size_bytes, modified_at, checksum_hash)
                      VALUES (:m, :d, :n, :s, {self.db.ts(':t')}, :c)""", {'m': mid, 'd': did, 'n': name, 's': size, 't': int(time.time()), 'c': sha})
        return c.scalar('SELECT host_id FROM hosts WHERE hostname = :h', {'h': host})

    def catch_up(self, bound=True):
        sha = hashlib.sha256(self.blob).hexdigest()
        self.row('nas', 'x.iso', len(self.blob), None)
        pc = self.row('pc', 'x.iso', len(self.blob), sha)
        binding = SimpleNamespace(key_id=1, user='scan', port=22, fingerprint='SHA256:x')

        def resolve(host, action):
            if not bound:
                raise runner.NoBinding('no key is bound')
            return binding
        vault = SimpleNamespace(resolve=resolve, decrypt_key=lambda k: None, audit_key=None,
                                unlock=lambda: contextlib.nullcontext(vault))
        logged = []
        with mock.patch.object(runner, 'Vault', lambda db, conn: vault), \
             mock.patch.object(runner, 'ephemeral_agent', lambda key: contextlib.nullcontext('sock')), \
             mock.patch.object(runner, 'Transport', lambda **kw: Transport('localhost', local=True)), \
             mock.patch('storageforge_index.scansign.for_scan', lambda *a: None):
            done = runner.checksum_catchup(self.db, pc, 'pc', ScanOptions(checksum=True), 'test', logged.append)
        got = self.conn.scalar("""SELECT f.checksum_hash FROM file_records f JOIN mounts m ON m.mount_id = f.mount_id
                                  JOIN hosts h ON h.host_id = m.host_id WHERE h.hostname = 'nas'""")
        return done, got, sha, logged

    def test_the_other_hosts_copy_is_hashed_after(self):
        done, got, sha, logged = self.catch_up()
        self.assertEqual(done, {'nas': 1})
        self.assertEqual(got, sha)
        self.assertIn('copies across hosts show now', logged[0])
        self.assertEqual(self.conn.scalar("SELECT count(*) FROM audit_log WHERE action = 'ssh.checksum.catchup' AND outcome = 'ok'"), 1)

    def test_a_host_whose_binding_does_not_allow_checksums_is_named(self):
        done, got, _, logged = self.catch_up(bound=False)
        self.assertEqual((done, got), ({'nas': 'no binding allows checksums'}, None))
        self.assertIn('Checksums on', logged[0])


if __name__ == '__main__':
    unittest.main()
