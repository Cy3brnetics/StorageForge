"""Regression tests for the security, agent and vault bug hunt (agent plugins, receiver, backup, CLI, secplus, secscripts, security, server, sfagent)."""
import argparse
import json
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import dbfactory
from storageforge_index import agentaction, agentplugins, agentreceiver, backup, cli, reset, secplus, secscripts, security, server, sfagent


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(subprocess.run, ['rm', '-rf', str(self.tmp)])
        self.db = dbfactory.make(self, self.tmp / 'index.db')
        self.conn = self.db.connect()
        self.addCleanup(self.conn.close)
        self.db.migrate(self.conn)


class Tripwire(Base):
    def test_an_agreed_drop_nobody_can_perform_is_not_recorded_as_done(self):
        self.conn.execute("INSERT INTO hosts (hostname, ssh_host, ssh_port) VALUES ('win-client', '10.0.0.55', 22)")
        self.conn.execute("""INSERT INTO agents (host, enabled, state, public_key, fingerprint, counter, updated_at, updated_by)
                             VALUES ('win-client', 1, 'running', 'ssh-ed25519 AAAA', 'SHA256:win', 1, 0, 'test')""")
        now = int(time.time())
        witness = agentaction.Witness('sentinel', 'nas', '10.0.0.55', now)
        with mock.patch.object(agentaction, 'recent_witnesses', return_value=[witness]):
            agentplugins.take_tripwire(self.conn, 'win-client', {'command': 'vssadmin delete shadows /all'}, now)
        act = agentaction.recent(self.conn, 'win-client')[0]
        self.assertEqual(act['outcome'], 'failed')


class Receiver(unittest.TestCase):
    def test_a_full_record_of_non_ascii_text_is_not_refused_for_its_escapes(self):
        text = 'ж' * (24 << 10)                 # 48 KiB of UTF-8, 144 KiB once escaped
        batch = {'counter': 1, 'run': 1, 'sent': 1, 'dropped': 0, 'records': [{'seq': 1, 'at': 1, 'plugin': 'logs', 'kind': 'lines', 'body': {'t': text}}]}
        got = agentreceiver.read_batch(json.dumps(batch, ensure_ascii=False).encode())
        self.assertEqual(len(got['records']), 1)
        batch['records'][0]['body']['t'] = 'ж' * (40 << 10)     # 80 KiB of UTF-8 is still too big
        with self.assertRaises(agentreceiver.Refused):
            agentreceiver.read_batch(json.dumps(batch, ensure_ascii=False).encode())


@unittest.skipIf(dbfactory.PG, 'backups are of SQLite databases (PostgreSQL: pg_dump)')
class Restore(Base):
    def test_restore_refuses_while_a_server_holds_the_lock(self):
        made = backup.create(self.db, 'essentials', self.tmp)
        lock = reset.hold_server_lock(self.db)
        try:
            with self.assertRaises(SystemExit) as cm:
                backup.restore(self.db, made['path'])
            self.assertIn('server is running', str(cm.exception))
        finally:
            lock.close()
        self.assertIn('restored', backup.restore(self.db, made['path']))


class BackupArgs(unittest.TestCase):
    def test_options_before_the_subcommand_are_kept(self):
        a = cli.build_parser().parse_args(['backup', '--full', '--keep', '3', '--dir', '/x', 'create'])
        self.assertEqual((a.full, a.keep, a.dir), (True, 3, '/x'))
        a = cli.build_parser().parse_args(['backup', 'create', '--keep', '2'])
        self.assertEqual((a.full, a.keep, a.dir), (False, 2, None))
        a = cli.build_parser().parse_args(['backup', '--dir', '/y', 'list'])
        self.assertEqual(a.dir, '/y')
        a = cli.build_parser().parse_args(['backup'])
        self.assertEqual((a.backup_cmd, a.full, a.keep, a.dir), ('create', False, None, None))


class CleanRoom(Base):
    def sweep(self, output):
        if not self.conn.scalar("SELECT count(*) FROM hosts WHERE hostname = 'nas'"):
            self.conn.execute("INSERT INTO hosts (hostname, ssh_host, ssh_port) VALUES ('nas', '10.0.0.5', 22)")
        res = {'status': 'ok', 'output': output, 'run_id': 1}
        with mock.patch.object(security, '_run', return_value=res), mock.patch.object(secplus, 'yara_text', return_value=''):
            return secplus.clean_room_sweep(self.db, self.conn, {'host': 'nas'}, 'test')

    def test_a_scanner_that_failed_is_not_a_clean_result(self):
        r = self.sweep('FILES 3\nCLAM rc=2\nYARA absent\nSWEEP done\n')
        self.assertFalse(r['clean'])
        self.assertEqual((r['ran'], r['failed']), ([], ['clam']))

    def test_scanners_that_ran_are_clean(self):
        r = self.sweep('FILES 3\nCLAM rc=0\nYARA rc=0\nSWEEP done\n')
        self.assertEqual((r['clean'], r['ran'], r['failed']), (True, ['clam', 'yara'], []))
        self.assertFalse(self.sweep('FILES 3\nCLAM rc=0\nYARA rc=1\nSWEEP done\n')['clean'])


class Cursor(Base):
    def test_events_past_a_full_batch_are_read_on_the_next_look(self):
        seen = []
        with mock.patch.object(secplus, 'fire', side_effect=lambda db, conn, kind, host, ev: seen.append(ev['id']) or []):
            secplus.process_events(self.db, self.conn)                        # the first look marks the place
            for i in range(503):
                security.record_event(self.conn, 'nas', 'canary_tripped', f'e{i}', '', 'test')
            secplus.process_events(self.db, self.conn)
            secplus.process_events(self.db, self.conn)
        self.assertEqual(len(seen), 503)
        self.assertEqual(len(set(seen)), 503)


class Aide(unittest.TestCase):
    def test_a_watch_path_is_one_argument(self):
        script = secscripts.tool_script('aide-check', ['/srv/my dir'])
        self.assertIn('extra+=("--before=$r")', script)
        self.assertIn('"${extra[@]}"', script)
        self.assertNotIn('tr "\\n" " "', script)


class Holds(Base):
    def test_holding_again_withdraws_a_pending_release(self):
        now = int(time.time())
        hid = security._record_hold(self.conn, 'nas', 'zfs', 'tank@a', 'sf-worm-30d', now + 86400, False, 'admin', now)
        self.conn.execute("UPDATE security_retention_holds SET status = 'release_pending' WHERE id = :i", {'i': hid})
        tid = self.conn.scalar("""INSERT INTO security_timelock_queue (action, target_ref, host, actor, mode, requested_at, executes_at, status, detail_json)
                                  VALUES ('worm_release', 'tank@a#sf-worm-30d', 'nas', 'admin', 'cool_off', :r, :r, 'pending', :d) RETURNING id""",
                              {'r': now, 'd': json.dumps({'hold_id': hid, 'snapshot': 'tank@a', 'hold_tag': 'sf-worm-30d'})})
        security._record_hold(self.conn, 'nas', 'zfs', 'tank@a', 'sf-worm-30d', now + 2 * 86400, False, 'admin', now)
        self.assertEqual(self.conn.scalar('SELECT status FROM security_timelock_queue WHERE id = :i', {'i': tid}), 'aborted')
        self.assertEqual(self.conn.scalar('SELECT status FROM security_retention_holds WHERE id = :i', {'i': hid}), 'locked')
        self.assertEqual(security._timelocks(self.conn), [])


class Nightly(unittest.TestCase):
    def test_the_config_export_runs_on_postgresql_too(self):
        conn = mock.MagicMock()
        db = mock.MagicMock(dialect='postgresql')
        db.connect.return_value = conn
        app = object.__new__(server.App)
        app.db = db
        app.audit = mock.MagicMock()
        with mock.patch.object(server, 'CONFIG_EXPORT_DIR', '/x'), mock.patch.object(server.site, 'export_dir', return_value='/x'), \
                mock.patch.object(server.hostconfig, 'export_to', return_value={'n': 1}) as exported, \
                mock.patch.object(backup, 'create', side_effect=AssertionError('no file backups on PostgreSQL')):
            out = app.nightly_once()
        exported.assert_called_once()
        self.assertEqual(out['hostconfigs'], {'n': 1})
        db.prune.assert_called_once()


class Switch(Base):
    def test_switching_on_keeps_the_state_of_an_enrolled_agent(self):
        self.conn.execute("INSERT INTO hosts (hostname, ssh_host, ssh_port) VALUES ('nas', '10.0.0.5', 22)")
        self.conn.execute("""INSERT INTO agents (host, enabled, state, public_key, fingerprint, counter, updated_at, updated_by)
                             VALUES ('nas', 1, 'wiped', 'ssh-ed25519 AAAA', 'SHA256:x', 1, 0, 'test')""")
        self.assertEqual(sfagent.switch(self.conn, 'nas', True, 'admin')['state'], 'wiped')
        self.conn.execute("UPDATE agents SET state = 'off', enabled = 0 WHERE host = 'nas'")
        self.assertEqual(sfagent.switch(self.conn, 'nas', True, 'admin')['state'], 'on')


if __name__ == '__main__':
    unittest.main()
