import json
import shutil
import tempfile
import time
import unittest
from pathlib import Path

import dbfactory
from storageforge_index import agentguard, agentwatch


class Unchecked(unittest.TestCase):
    """'agent unchecked' needs a long silence, not one failed check."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.db = dbfactory.make(self, self.tmp / 'index.db')
        self.conn = self.db.connect()
        self.addCleanup(self.conn.close)
        self.db.migrate(self.conn)
        self.conn.execute("INSERT INTO hosts (hostname, ssh_host, ssh_user, ssh_port) VALUES ('nas', '10.0.0.3', 'x', 22)")
        self.conn.execute("INSERT INTO agents (host, enabled, state, fingerprint, enrolled_at, updated_at, updated_by) VALUES ('nas', 1, 'running', 'fp', :t, :t, 'test')",
                          {'t': int(time.time()) - 10 * agentguard.UNCHECKED_SECS})

    def flagged(self):
        return 'agent-unchecked:nas' in agentwatch.problems(self.conn)

    def test_a_failure_keeps_the_time_of_the_last_success(self):
        agentguard._store_check(self.conn, 'nas', {'ok': True, 'clean': True})
        ok_at = json.loads(self.conn.scalar("SELECT check_json FROM agents WHERE host = 'nas'"))['last_ok']
        agentguard._store_check(self.conn, 'nas', {'ok': False, 'error': 'down'})
        got = json.loads(self.conn.scalar("SELECT check_json FROM agents WHERE host = 'nas'"))
        self.assertEqual((got['ok'], got['last_ok']), (False, ok_at))
        self.assertFalse(self.flagged())

    def test_a_failure_with_no_success_since_enrolment_long_ago_is_flagged(self):
        agentguard._store_check(self.conn, 'nas', {'ok': False, 'error': 'down'})
        self.assertTrue(self.flagged())

    def test_failures_after_an_old_success_are_flagged(self):
        old = int(time.time()) - 2 * agentguard.UNCHECKED_SECS
        self.conn.execute("UPDATE agents SET checked_at = :t, check_json = :j WHERE host = 'nas'", {'t': old, 'j': json.dumps({'ok': True, 'last_ok': old})})
        agentguard._store_check(self.conn, 'nas', {'ok': False, 'error': 'down'})
        self.assertTrue(self.flagged())

    def test_a_check_that_has_not_run_for_long_is_flagged(self):
        old = int(time.time()) - 2 * agentguard.UNCHECKED_SECS
        self.conn.execute("UPDATE agents SET checked_at = :t, check_json = :j WHERE host = 'nas'", {'t': old, 'j': json.dumps({'ok': True, 'last_ok': old})})
        self.assertTrue(self.flagged())


if __name__ == '__main__':
    unittest.main()
