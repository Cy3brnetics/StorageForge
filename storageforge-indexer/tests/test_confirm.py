"""Tests for script confirmation and automatic log fetching (confirm.py)."""
import json
import os
import shutil
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

try:
    import dbfactory
except ImportError:
    from tests import dbfactory
from storageforge_index import confirm, deploy
from storageforge_index.db import Database


class ConfirmTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='sf-conf-'))
        self.db = dbfactory.make(self, self.tmp / 'idx.db')
        self.conn = self.db.connect()
        self.db.migrate(self.conn)

    def tearDown(self):
        self.conn.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_ingest_tasks(self):
        tasks_text = (
            '{"task":"backup-db","rc":0,"started":1700000000,"finished":1700000010}\n'
            '{"task":"cleanup-scratch","rc":1,"started":1700000020,"finished":1700000025}\n'
        )
        n = confirm.ingest_tasks(self.conn, 'server01', tasks_text)
        self.assertEqual(n, 2)

        rows = self.conn.all("SELECT task, exit_code FROM task_runs WHERE host = 'server01' ORDER BY started_at")
        self.assertEqual(rows, [('backup-db', 0), ('cleanup-scratch', 1)])

        # Ingesting the same again does not duplicate
        n2 = confirm.ingest_tasks(self.conn, 'server01', tasks_text)
        self.assertEqual(n2, 0)
        self.assertEqual(self.conn.scalar("SELECT count(*) FROM task_runs WHERE host = 'server01'"), 2)

    def test_ingest_runs_confirms_deploy_run(self):
        now = int(time.time())
        nonce = '1234567890abcdef1234567890abcdef'
        self.conn.execute("""INSERT INTO deploy_runs (group_id, host, kind, ref, mode, status, nonce, started_at)
                             VALUES ('g1', 'server01', 'changes', '1', 'apply', 'running', :n, :t)""",
                          {'n': nonce, 't': now - 60})

        runs_text = f'{{"nonce":"{nonce}","rc":0,"started":{now - 60},"finished":{now - 10}}}\n'
        res = confirm.ingest_runs(self.conn, 'server01', runs_text)
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]['status'], 'ok')

        row = self.conn.all("SELECT status, host_state, host_exit, exit_code FROM deploy_runs WHERE nonce = :n", {'n': nonce})[0]
        self.assertEqual(row, ('ok', 'finished', 0, 0))

    def test_ingest_runs_keeps_an_incomplete_apply_incomplete(self):
        now = int(time.time())
        nonce = 'fedcba0987654321fedcba0987654321'
        self.conn.execute("""INSERT INTO deploy_runs (group_id, host, kind, ref, mode, status, nonce, started_at, output, exit_code)
                             VALUES ('g3', 'server01', 'shares', 'x', 'apply', 'incomplete', :n, :t, :o, NULL)""",
                          {'n': nonce, 't': now - 60, 'o': '  missing   not mounted\n'})
        runs_text = f'{{"nonce":"{nonce}","rc":0,"started":{now - 60},"finished":{now - 10}}}\n'
        self.assertEqual(confirm.ingest_runs(self.conn, 'server01', runs_text)[0]['status'], 'incomplete')
        self.assertEqual(self.conn.scalar('SELECT status FROM deploy_runs WHERE nonce = :n', {'n': nonce}), 'incomplete')

    def test_ingest_runs_confirms_failure(self):
        now = int(time.time())
        nonce = 'abcdef1234567890abcdef1234567890'
        self.conn.execute("""INSERT INTO deploy_runs (group_id, host, kind, ref, mode, status, nonce, started_at)
                             VALUES ('g2', 'server02', 'tasks', 't1', 'apply', 'running', :n, :t)""",
                          {'n': nonce, 't': now - 60})

        runs_text = f'{{"nonce":"{nonce}","rc":2,"started":{now - 60},"finished":{now - 10}}}\n'
        res = confirm.ingest_runs(self.conn, 'server02', runs_text)
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]['status'], 'failed')

        row = self.conn.all("SELECT status, host_state, host_exit, exit_code FROM deploy_runs WHERE nonce = :n", {'n': nonce})[0]
        self.assertEqual(row, ('failed', 'finished', 2, 2))

    def test_absent_run_marked(self):
        old_time = int(time.time()) - 1000
        nonce = '00000000000000000000000000000000'
        self.conn.execute("""INSERT INTO deploy_runs (group_id, host, kind, ref, mode, status, nonce, started_at)
                             VALUES ('g3', 'server03', 'changes', '1', 'apply', 'running', :n, :t)""",
                          {'n': nonce, 't': old_time})

        # Scan text has nothing for server03
        confirm.ingest_runs(self.conn, 'server03', '')
        row = self.conn.all("SELECT status, host_state FROM deploy_runs WHERE nonce = :n", {'n': nonce})[0]
        self.assertEqual(row, ('failed', 'absent'))

    def test_fetch_problem_logs(self):
        now = int(time.time())
        self.conn.execute("INSERT INTO deploy_access (host, state, detail, updated_at, updated_by) VALUES ('server01', 'ready', 'ok', :t, 'test')", {'t': now})
        self.conn.execute("""INSERT INTO deploy_runs (run_id, group_id, host, kind, ref, mode, status, nonce, exit_code, started_at)
                             VALUES (42, 'g4', 'server01', 'changes', '1', 'apply', 'failed', 'n42', 1, :t)""", {'t': now - 100})

        fake_output = "error: package conflict\nfailed to install nfs-kernel-server"
        with mock.patch.object(deploy, 'ready', lambda c, h: True), \
             mock.patch.object(deploy, 'run', lambda *a, **k: {'run_id': 99, 'status': 'ok', 'output': fake_output}):
            fetched = confirm.fetch_problem_logs(self.db, self.conn, 'server01', [{'run_id': 42, 'nonce': 'n42', 'rc': 1}])
            self.assertEqual(fetched, 1)

        # Check host_logs has record
        log_row = self.conn.all("SELECT state, output FROM host_logs WHERE log_key = 'deploy:42'")
        self.assertEqual(len(log_row), 1)
        self.assertEqual(log_row[0][0], 'fetched')
        self.assertIn("package conflict", log_row[0][1])

        # Check deploy_runs.output has the fetched log appended
        out = self.conn.scalar("SELECT output FROM deploy_runs WHERE run_id = 42")
        self.assertIn("host logs fetched by scan", out)
        self.assertIn("package conflict", out)
