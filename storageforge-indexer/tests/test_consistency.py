"""Lists kept by hand in two places stay in step: container entrypoint vs CLI subcommands, backup tables vs schema.
Run with: python3 -m unittest discover -s tests -v"""
import re
import shutil
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path

from storageforge_index import backup, cli
from storageforge_index.db import Database

ENTRYPOINT = Path(__file__).resolve().parents[1] / 'docker' / 'entrypoint.sh'


class Consistency(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db = Database(str(Path(self.tmp) / 'index.db'))
        self.conn = self.db.connect()
        self.db.migrate(self.conn)

    def tearDown(self):
        self.conn.close()
        shutil.rmtree(self.tmp)

    def test_entrypoint_knows_every_subcommand(self):
        # the first case arm before ") ;;" lists the names the entrypoint prepares the environment for
        arm = re.search(r'case "\$\{1:-serve\}" in\n(.*?)\) ;;', ENTRYPOINT.read_text(), re.S).group(1)
        known = {n.strip() for n in arm.replace('\\\n', '').split('|')} - {'-*'}
        sub = next(a for a in cli.build_parser()._actions if a.dest == 'cmd')
        self.assertEqual(set(sub.choices) - known, set(), 'add these to docker/entrypoint.sh')
        self.assertEqual(known - set(sub.choices), set(), 'not storageforge-index subcommands')

    def test_every_table_is_backed_up_or_rebuildable(self):
        tables = {r[0] for r in self.conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE 'file_fts_%'")}
        both = set(backup.ESSENTIAL) & set(backup.REBUILDABLE)
        self.assertEqual(both, set(), 'in both lists')
        self.assertEqual(tables - set(backup.ESSENTIAL) - set(backup.REBUILDABLE), set(),
                         'new table: add it to backup.ESSENTIAL or backup.REBUILDABLE')
        self.assertEqual((set(backup.ESSENTIAL) | set(backup.REBUILDABLE)) - tables, set(), 'no such table')

    def test_essentials_carry_plans_settings_and_deploy_state(self):
        now = int(time.time())
        for sql in ("INSERT INTO change_plans (name, body_json, created_at, updated_at) VALUES ('c', '{}', :t, :t)",
                    "INSERT INTO storage_tasks (name, body_json, created_at, updated_at) VALUES ('t', '{}', :t, :t)",
                    "INSERT INTO settings (key, value_json, updated_at) VALUES ('report_url', '\"https://sf\"', :t)",
                    "INSERT INTO deploy_access (host, state, updated_at) VALUES ('nas', 'ready', :t)",
                    "INSERT INTO deployed (host, kind, ref, deploy_hash, deployed_at) VALUES ('nas', 'jobs', '1', 'h', :t)",
                    "INSERT INTO jobs (job_id, name, method, runner_host, source_host, token_hash) "
                    "VALUES ('p1-s1', 'j', 'mirror', 'nas', 'nas', 'sha')",
                    "INSERT INTO host_key_confirmations (address, port, fingerprint, confirmed_by, confirmed_at) "
                    "VALUES ('nas', 22, 'SHA256:x', 'admin', :t)",
                    "INSERT INTO job_runs (run_uuid, job_id, kind, started_at, via, received_at) "
                    "VALUES ('r1', 'p1-s1', 'run', :t, 'report', :t)"):
            self.conn.execute(sql, {'t': now})
        dest = Path(self.tmp) / 'bk'
        dest.mkdir()
        out = backup.create(self.db, 'essentials', dest)['path']
        bk = sqlite3.connect(out)
        try:
            for t in ('change_plans', 'storage_tasks', 'settings', 'deploy_access', 'deployed', 'jobs',
                      'host_key_confirmations'):
                self.assertEqual(bk.execute(f'SELECT count(*) FROM {t}').fetchone()[0], 1, t)
            self.assertEqual(bk.execute('SELECT token_hash FROM jobs').fetchone()[0], 'sha')   # reports still verify
            self.assertEqual(bk.execute('SELECT count(*) FROM job_runs').fetchone()[0], 0)      # history stays behind
        finally:
            bk.close()


if __name__ == '__main__':
    unittest.main()
