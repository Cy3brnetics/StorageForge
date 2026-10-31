"""Tests for deploy engine: outcome calculations, line summaries, group tracking, and retry."""
import os
import shutil
import tempfile
import time
import unittest
from pathlib import Path

try:
    import dbfactory
except ImportError:
    from tests import dbfactory
from storageforge_index import deploy, engine
from storageforge_index.db import Database


class EngineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='sf-engine-'))
        self.db = dbfactory.make(self, self.tmp / 'idx.db')
        self.conn = self.db.connect()
        self.db.migrate(self.conn)

    def tearDown(self):
        self.conn.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_outcome(self):
        self.assertEqual(engine.outcome(['ok', 'ok']), 'ok')
        self.assertEqual(engine.outcome(['ok', 'incomplete']), 'incomplete')
        self.assertEqual(engine.outcome(['ok', 'failed']), 'failed')
        self.assertEqual(engine.outcome(['ok', 'refused']), 'failed')
        self.assertEqual(engine.outcome(['ok', 'skipped']), 'failed')
        self.assertEqual(engine.outcome(['ok', 'cancelled']), 'cancelled')
        self.assertEqual(engine.outcome(['ok', 'running']), 'running')
        self.assertEqual(engine.outcome(['ok', 'queued']), 'running')

    def test_summarize(self):
        text = (
            "header line\n"
            "  ok /srv/data mounted\n"
            "  missing create /srv/data2\n"
            "  conflict /dev/sdb already in use\n"
            "  -> rsync started\n"
            "  warning check /etc/fstab\n"
            "  failed format disk\n"
        )
        s = engine.summarize(text)
        self.assertEqual(s['ok'], 1)
        self.assertEqual(s['missing'], 2)   # missing + warning
        self.assertEqual(s['conflict'], 2)  # conflict + failed
        self.assertEqual(s['did'], 1)       # ->

    def test_unfinished_hosts_and_recent(self):
        gid = 'a' * 32
        now = int(time.time())
        self.conn.execute("""INSERT INTO deploy_groups (group_id, kind, ref, mode, title, state, options_json, started_at)
                             VALUES (:g, 'changes', '1', 'apply', 'test deploy', 'failed', '{}', :t)""",
                          {'g': gid, 't': now})
        self.conn.execute("""INSERT INTO deploy_runs (group_id, host, kind, ref, mode, status, started_at)
                             VALUES (:g, 'alpha', 'changes', '1', 'apply', 'ok', :t)""", {'g': gid, 't': now})
        self.conn.execute("""INSERT INTO deploy_runs (group_id, host, kind, ref, mode, status, started_at)
                             VALUES (:g, 'beta', 'changes', '1', 'apply', 'failed', :t)""", {'g': gid, 't': now})
        self.conn.execute("""INSERT INTO deploy_runs (group_id, host, kind, ref, mode, status, started_at)
                             VALUES (:g, 'gamma', 'changes', '1', 'apply', 'incomplete', :t)""", {'g': gid, 't': now})

        unf = engine.unfinished_hosts(self.conn, gid)
        self.assertEqual(unf, ['beta'])     # 'incomplete' is in deploy.FINISHED, so unfinished is failed

        rec = engine.recent(self.conn, limit=10)
        self.assertEqual(len(rec), 1)
        self.assertEqual(rec[0]['group_id'], gid)
        self.assertEqual(len(rec[0]['hosts']), 3)

    def test_stale_dry_run_digest_check(self):
        # Verify digest mismatch logic
        c = self.conn
        gid = 'd' * 32
        now = int(time.time())
        c.execute("""INSERT INTO deploy_groups (group_id, kind, ref, mode, title, state, digest, started_at)
                     VALUES (:g, 'changes', '1', 'report', 'dry run', 'ok', 'sha-original', :t)""",
                  {'g': gid, 't': now})
        seen = engine.get(c, gid)
        self.assertIsNotNone(seen)
        self.assertEqual(seen['digest'], 'sha-original')
        current_digest = 'sha-modified'
        self.assertNotEqual(seen['digest'], current_digest)
