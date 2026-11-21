"""The console on a monitoring-only host (decision of 2026-11-16; agentconsole.py, agent/src/console.rs): SSH turned on for that session
through storageforge-agentctl and off again after, never a shell in the agent, and only as an account the host's own admin listed.

What is real: storageforge-agentctl built by cargo, taking the controller's signed console-open and console-close; the key made for the
session; the account's authorized_keys written as that account; the database on SQLite and PostgreSQL; the console's session, closed.
What stands in: the host's root, a folder, and its accounts (one of them this test's own, since only root can become another)."""
import os
import time
import unittest
from unittest import mock

import test_agent
import test_agent_monitoring
from storageforge_index import agentconsole, console, sfagent


class Grant(test_agent_monitoring.Adopt):
    test_a_host_set_up_by_hand_is_adopted_with_the_line_its_setup_printed = None
    test_a_line_that_is_not_the_setups_or_another_host_key_is_refused = None
    test_a_host_storageforge_has_already_is_not_registered_again = None

    def setUp(self):
        super().setUp()
        root = self.host.root
        with (root / 'etc/passwd').open('a') as f:
            f.write(f'me:x:{os.getuid()}:{os.getgid()}::/home/me:/bin/bash\n')
        (root / 'home/me/.ssh').mkdir(parents=True)
        (root / 'home/me/.ssh/authorized_keys').write_text('ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOwn me@laptop\n')
        p = self.host.run_setup(agentmonitor_setup(self), self.program)
        line = next(l for l in p.stdout.decode().splitlines() if l.startswith('storageforge-agent-adopt '))
        from storageforge_index import agentmonitor
        agentmonitor.adopt(self.db, 'nas', line, 'test')
        self.users = root / 'etc/storageforge-agent/console_users'
        self.keys = root / 'home/me/.ssh/authorized_keys'

    def test_ssh_is_turned_on_for_the_session_as_a_listed_account_and_off_again(self):
        self.users.write_text('# the accounts a console may log in as, by this host\'s admin\nme\nsfagent\n')
        gid, key = agentconsole.grant(self.db, 'nas', 'me', 'web:root')
        self.assertIn(b'OPENSSH PRIVATE KEY', bytes(key.view()), 'the session\'s own key, in memory')
        lines = self.keys.read_text().splitlines()
        self.assertEqual(lines[0], 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOwn me@laptop', 'the account\'s own keys are left as they are')
        self.assertRegex(lines[1], r'^restrict,pty,expiry-time="\d{12}Z" ssh-ed25519 [A-Za-z0-9+/]{68} storageforge-console:' + gid + '$')
        row = self.conn.all('SELECT user_name, opened_by, closed_at, expires_at - opened_at FROM agent_console_grants WHERE grant_id = :g', {'g': gid})[0]
        self.assertEqual(row, ('me', 'web:root', None, agentconsole.LOGIN_MINUTES * 60))
        self.assertTrue(agentconsole.close(self.db, 'nas', gid, 'the session ended'))
        self.assertEqual(self.keys.read_text(), 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOwn me@laptop\n')
        self.assertIsNotNone(self.conn.scalar('SELECT closed_at FROM agent_console_grants WHERE grant_id = :g', {'g': gid}))

    def test_without_the_hosts_own_list_or_off_it_there_is_no_console(self):
        with self.assertRaises(agentconsole.ConsoleGrantError) as e:
            agentconsole.grant(self.db, 'nas', 'me', 'web:root')
        self.assertIn('allows no console', str(e.exception))
        self.users.write_text('sfagent\nstorageforge-agentctl\nana\n')
        for who in ('me', 'sfagent', 'storageforge-agentctl', 'root'):
            with self.assertRaises(agentconsole.ConsoleGrantError, msg=who):
                agentconsole.grant(self.db, 'nas', who, 'web:root')
        self.assertNotIn('storageforge-console', self.keys.read_text())
        self.assertEqual(self.conn.scalar('SELECT count(*) FROM agent_console_grants WHERE closed_at IS NULL'), 0)

    def test_a_console_nobody_closed_is_closed_by_the_next_request(self):
        self.users.write_text('me\n')
        gid, _key = agentconsole.grant(self.db, 'nas', 'me', 'web:root')
        grant_file = self.host.root / 'var/lib/storageforge-agent/ctl/console' / gid
        self.assertTrue(grant_file.exists())
        grant_file.write_text(f'me {int(time.time()) - 3600}\n')          # its time is past
        got = sfagent.lifecycle(self.db, 'nas', 'status', 'test')
        self.assertTrue(got['running'] is not None)
        self.assertNotIn('storageforge-console', self.keys.read_text(), 'taken out by storageforge-agentctl itself, whatever was asked')
        self.assertFalse(grant_file.exists())

    def test_the_session_turns_ssh_off_again_when_it_closes(self):
        self.users.write_text('me\n')
        s = console.Session('root', 'nas', 'ssh', 'lan', '10.0.0.3', 80, 24)
        with self.assertRaises(console.ConsoleError) as e:
            console._monitoring_login(self.db, s, 'nas', None, 'root')
        self.assertIn('name the account', str(e.exception))
        s = console.Session('root', 'nas', 'ssh', 'lan', '10.0.0.3', 80, 24)
        b, cert, key = console._monitoring_login(self.db, s, 'nas', 'me', 'root')
        self.assertEqual((b.user, cert), ('me', None))
        self.assertIn('storageforge-console:', self.keys.read_text())
        with mock.patch('threading.Thread.start', lambda t: t.run()):
            s.close('ended')
        self.assertNotIn('storageforge-console:', self.keys.read_text())
        self.assertIn('the session ended', self.conn.scalar('SELECT close_detail FROM agent_console_grants'))


def agentmonitor_setup(case):
    from storageforge_index import agentmonitor
    return agentmonitor.setup(case.db, 'nas')['script']


if __name__ == '__main__':
    unittest.main()
