"""The agent's first plugins from the controller's side (roadmap section 11.4, and section 3 phase 2 for logs): where the receiver
says each plugin is up to, pushed journal lines into host logs (agentingest.py), what the notification center makes of heartbeats,
health and gaps (agentwatch.py), and the whole road with the real agent, the real plugins and the real receiver.

What is real: the receiver and its sessions (test_agent_receiver's played agents), the database on SQLite and PostgreSQL, hostlogs and
the log rules, and in LogsRoad the real storageforge-agentctl, storageforge-agent and the logs and heartbeat plugins, signed by a release
key made for the run, reading journal files systemd's own systemd-journal-remote wrote. What stands in: the host, a folder."""
import json
import os
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

import dbfactory
import test_agent
import test_agent_receiver
from storageforge_index import agentingest, agentwatch, hostlogs, logrules, sfagent

SEQ = '0123456789abcdef0123456789abcdef'
REMOTE = '/usr/lib/systemd/systemd-journal-remote'


def line(n, message, priority=6, at=None, skipped=0, **more):
    at = at if at is not None else time.time()
    return {'MESSAGE': message, 'PRIORITY': str(priority), '__SEQNUM': str(n), '__SEQNUM_ID': SEQ, '__REALTIME_TIMESTAMP': str(int(at * 1e6)),
            '__CURSOR': f's={SEQ};i={n:x};b=b;m=1;t=1;x=1', '_COMM': more.pop('comm', 'kernel'), 'skipped': skipped, **more}


class ReceiverResume(test_agent_receiver.Base):
    def deliver(self, agent, plugins=('heartbeat', 'logs')):
        manifest = json.dumps({'plugins': [{'name': n} for n in plugins]})
        self.conn.execute("""INSERT INTO agent_deliveries (host, fingerprint, counter, manifest, signature, plugins_json, updated_at)
                             VALUES (:h, :f, 1, :m, 'sig', '[]', 0)""", {'h': agent.host, 'f': agent.fp, 'm': manifest})

    def test_each_plugin_is_told_where_the_controller_has_its_readings_up_to(self):
        a, b = test_agent_receiver.Agent(self, 'nas'), test_agent_receiver.Agent(self, 'web')
        self.deliver(a)
        self.deliver(b)
        time.sleep(0.3)        # the receiver reads the pinned keys again
        a.open()
        frames = a.hello()
        self.assertEqual([f for f in frames if f['op'] == 'resume'], [{'op': 'resume', 'cursors': {'heartbeat': None, 'logs': None}}])
        cursor = {'s': SEQ, 'i': 41, 't': 1795000000000000}
        self.assertEqual(a.send(a.body([{'plugin': 'logs', 'kind': 'lines', 'body': {'lines': [], 'cursor': cursor}}]))['op'], 'ack')
        # a cursor too large to be one is not kept; nor one in a batch that was refused
        self.assertEqual(a.send(a.body([{'plugin': 'heartbeat', 'kind': 'beat', 'body': {'cursor': {'x': 'y' * 2000}}}]))['op'], 'ack')
        a.open()
        frames = a.hello()
        self.assertEqual([f['cursors'] for f in frames if f['op'] == 'resume'], [{'heartbeat': None, 'logs': cursor}])
        # another agent's cursor is its own
        b.open()
        self.assertEqual([f['cursors'] for f in b.hello() if f['op'] == 'resume'], [{'heartbeat': None, 'logs': None}])


class OverQuota(test_agent_receiver.Base):
    LIMITS = {'batches_per_minute': 2}

    def test_a_batch_over_the_quota_is_to_be_sent_again_later(self):
        a = test_agent_receiver.Agent(self, 'nas')
        a.open()
        a.hello()
        self.assertEqual([a.send(a.body())['op'] for _ in range(2)], ['ack', 'ack'])
        got = a.send(a.body())
        self.assertEqual((got['op'], got.get('retry')), ('refused', True), 'a burst waits, it is not lost')


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.db = dbfactory.make(self, self.tmp / 'index.db')
        self.conn = self.db.connect()
        self.addCleanup(self.conn.close)
        self.db.migrate(self.conn)
        self.conn.execute("INSERT INTO hosts (hostname, ssh_host, ssh_port, machine_id) VALUES ('nas', '10.0.0.3', 22, :m)", {'m': '0' * 32})
        self.conn.execute("""INSERT INTO agents (host, enabled, state, public_key, fingerprint, counter, endpoint, updated_at, updated_by)
                             VALUES ('nas', 1, 'running', 'ssh-ed25519 AAAA', 'SHA256:nas', 1, '10.0.0.1:7843', 0, 'test')""")

    def record(self, plugin, kind, body, received=None, host='nas'):
        self.conn.execute("""INSERT INTO agent_records (host, fingerprint, counter, seq, plugin, kind, received_at, body_json)
                             VALUES (:h, 'SHA256:nas', 1, 1, :p, :k, :r, :b)""",
                          {'h': host, 'p': plugin, 'k': kind, 'r': int(received or time.time()), 'b': json.dumps(body)})


class Ingest(Base):
    def stored(self):
        return self.conn.all('SELECT host, message, via, seqnum FROM host_log_lines ORDER BY seqnum')

    def test_pushed_lines_go_into_host_logs_signed_scrubbed_and_matched_as_they_arrive(self):
        now = time.time()
        self.record('logs', 'lines', {'lines': [line(1, 'Out of memory: Killed process 4242 (postgres)', 3, now - 2, _HOSTNAME='web'),
                                                line(2, 'login with password=hunter2', 6, now - 2)], 'cursor': {'s': SEQ, 'i': 2, 't': 1}}, received=now)
        got = agentingest.take_lines(self.db, now)
        self.assertEqual(got, {'nas': 2})
        rows = self.stored()
        self.assertEqual([(h, v) for h, _m, v, _s in rows], [('nas', 'agent'), ('nas', 'agent')], 'under the host the key belongs to, whatever a line names')
        self.assertIn('[redacted]', rows[1][1])
        self.assertNotIn('hunter2', rows[1][1])
        status = hostlogs.status(self.conn, 'nas')[0]
        self.assertEqual((status['via'], status['signed'], status['pushed_lines'], status['gaps']), ('agent', True, 2, 0))
        self.assertGreaterEqual(status['delay_ms'], 1000)
        # the built-in rule for out-of-memory kills fired as the line arrived
        oom = self.conn.scalar("SELECT rule_id FROM log_rules WHERE builtin = 'oom'")
        self.assertEqual(self.conn.scalar('SELECT sum(hits) FROM log_rule_hits WHERE rule_id = :r', {'r': oom}), 1)
        self.assertTrue(any(k.startswith(f'log-rule:{oom}:nas') for k in logrules.problems(self.conn)))
        self.assertEqual(self.conn.scalar("SELECT count(*) FROM agent_records WHERE plugin = 'logs'"), 0, 'taken once')
        # the lines are the host's on every page that shows lines, marked as signed
        self.assertTrue(all(e['signed'] for e in hostlogs.page(self.conn, hostlogs.clean_filter(host='nas'))['entries']))

    def test_numbers_missing_from_the_journal_are_gaps_and_left_out_debug_lines_are_not(self):
        now = time.time()
        self.record('logs', 'lines', {'lines': [line(1, 'a'), line(2, 'b')], 'cursor': {'s': SEQ, 'i': 3, 't': 1}})
        agentingest.take_lines(self.db, now)
        self.assertEqual(hostlogs.status(self.conn, 'nas')[0]['gaps'], 0, 'entry 3 was a debug line after the last: the cursor covers it')
        # 4 follows on; 6 says one debug line was left out before it (5); 9 comes after 7 and 8, which never came
        self.record('logs', 'lines', {'lines': [line(4, 'c'), line(6, 'd', skipped=1), line(9, 'e')], 'cursor': {'s': SEQ, 'i': 9, 't': 1}})
        agentingest.take_lines(self.db, now)
        status = hostlogs.status(self.conn, 'nas')[0]
        self.assertEqual(status['gaps'], 2)
        self.assertIn('log-gap:nas', agentwatch.problems(self.conn))
        # a line seen again, or out of order, is no gap and no second row
        self.record('logs', 'lines', {'lines': [line(9, 'e'), line(10, 'f')], 'cursor': {'s': SEQ, 'i': 10, 't': 1}})
        agentingest.take_lines(self.db, now)
        self.assertEqual(hostlogs.status(self.conn, 'nas')[0]['gaps'], 2)
        self.assertEqual(len(self.stored()), 6)

    def test_while_the_agent_pushes_the_scan_does_not_ask_again(self):
        self.record('logs', 'lines', {'lines': [line(1, 'a')], 'cursor': {'s': SEQ, 'i': 1, 't': 1}})
        agentingest.take_lines(self.db)

        class NoSsh:
            def run(self, *_a, **_k):
                raise AssertionError('the scan asked over SSH while the agent pushes')
        self.assertEqual(hostlogs.collect(self.conn, NoSsh(), 'nas')['state'], 'agent')
        # pushing stopped ten minutes ago: the scan collects again
        self.conn.execute("UPDATE host_log_status SET pushed_at = :t WHERE host = 'nas'", {'t': int(time.time()) - hostlogs.PUSH_FRESH_SECS - 1})
        self.assertFalse(hostlogs.pushing(self.conn, 'nas'))

    def test_what_is_not_a_line_is_dropped_and_the_rest_kept(self):
        self.record('logs', 'lines', {'lines': ['not an object', {'MESSAGE': 'no time'}, line(1, 'fine')], 'cursor': 'x'})
        self.record('logs', 'lines', 'not even an object')
        self.assertEqual(agentingest.take_lines(self.db), {'nas': 1})


class Watch(Base):
    def test_a_heartbeat_that_stops_is_silence_within_seconds(self):
        self.conn.execute("""INSERT INTO agent_deliveries (host, fingerprint, counter, manifest, signature, plugins_json, updated_at)
                             VALUES ('nas', 'SHA256:nas', 1, :m, 's', '[]', 0)""", {'m': json.dumps({'plugins': [{'name': 'heartbeat'}]})})
        self.conn.execute("INSERT INTO agent_peers (fingerprint, host, last_seen) VALUES ('SHA256:nas', 'nas', :t)", {'t': int(time.time())})
        self.assertEqual(agentwatch.silent_beats(self.conn), [])
        beats = agentingest.Beats()
        self.assertFalse(beats.changed(self.db))
        later = time.time() + agentwatch.BEAT_SILENT_SECS + 1
        self.assertEqual(agentwatch.silent_beats(self.conn, later), ['nas'])
        self.assertTrue(beats.changed(self.db, later), 'the notification center is woken')
        self.assertIn('heartbeat stopped', agentwatch.problems(self.conn, later)['agent-silent:nas'][3])

    def test_the_agent_says_ssh_is_down_while_it_goes_on_reporting(self):
        self.record('health', 'health', {'ssh': {'process': True, 'listening': [22, 80], 'read': True}})
        self.assertNotIn('agent-ssh-down:nas', agentwatch.problems(self.conn))
        self.record('health', 'ssh', {'process': False, 'listening': [80], 'read': True})
        got = agentwatch.problems(self.conn)['agent-ssh-down:nas']
        self.assertIn('nothing listens on port 22, and no sshd process runs', got[3])
        self.assertIn('reported by agent', got[3])
        # on another port, as the host's record says
        self.conn.execute("UPDATE hosts SET ssh_port = 80 WHERE hostname = 'nas'")
        self.assertNotIn('agent-ssh-down:nas', agentwatch.problems(self.conn))
        # an old reading says nothing about now
        self.conn.execute("UPDATE hosts SET ssh_port = 22 WHERE hostname = 'nas'")
        self.conn.execute('UPDATE agent_records SET received_at = :t', {'t': int(time.time()) - agentwatch.HEALTH_FRESH_SECS - 5})
        self.assertNotIn('agent-ssh-down:nas', agentwatch.problems(self.conn))


def write_journal(folder: Path, entries):
    text = ''
    for priority, message in entries:
        text += (f'__REALTIME_TIMESTAMP={int(time.time() * 1e6)}\n__MONOTONIC_TIMESTAMP=1\n_BOOT_ID={SEQ}\nPRIORITY={priority}\nMESSAGE={message}\n'
                 '_COMM=kernel\n_SYSTEMD_UNIT=kernel\n\n')
    src = folder.parent / 'in.export'
    src.write_text(text)
    p = subprocess.run([REMOTE, f'--output={folder / "system.journal"}', str(src)], capture_output=True, text=True)
    assert p.returncode == 0, p.stderr


@unittest.skipUnless(os.path.exists(REMOTE), 'needs systemd-journal-remote to write journal files')
class LogsRoad(test_agent_receiver.Delivery):
    """The whole road: the real agent runs the real logs and heartbeat plugins, signed by a release key made for the run, delivered
    through the tunnel; journal lines written now come back through the receiver into host logs, and after the agent starts again it
    resumes after the last line the controller has."""
    test_a_plugin_goes_through_the_tunnel_and_its_readings_come_back_under_the_senders_host = None
    test_a_receiver_key_that_changed_is_given_to_a_host_only_when_a_person_accepts_it = None

    def setUp(self):
        super().setUp()
        docker = self.host.bin / 'docker'
        var = self.host.root / 'var/lib/storageforge-agent'
        docker.write_text(docker.read_text().replace(f'--state {var}/state', f'--state {var}/state --host {self.host.root}'))
        self.journal = self.host.root / 'var/log/journal' / test_agent.MACHINE
        self.journal.mkdir(parents=True)
        arch = os.uname().machine
        script = Path(__file__).resolve().parents[1] / 'agent/plugins.sh'
        subprocess.run(['sh', str(script), 'lay', str(self.out), arch, str(self.tmp / 'release')], check=True)
        subprocess.run(['sh', str(script), 'sign', str(self.tmp / 'release'), str(test_agent.TARGET / 'release-key')], check=True, capture_output=True)

    def lines(self):
        agentingest.take_lines(self.db)
        return [m for (m,) in self.conn.all("SELECT message FROM host_log_lines WHERE host = 'nas' AND via = 'agent' ORDER BY seqnum")]

    def test_lines_written_now_are_pushed_and_after_a_restart_resumed_from_the_last_one_kept(self):
        self.install()
        self.wait_for(lambda: self.conn.scalar("SELECT sessions FROM agent_peers WHERE host = 'nas'"))
        write_journal(self.journal, [(6, 'before the plugin ran')])
        arch = os.uname().machine
        sfagent.apply(self.db, 'nas', [sfagent.release_plugin(arch, 'heartbeat'), sfagent.release_plugin(arch, 'logs')], actor='test')
        self.wait_for(lambda: self.conn.scalar("SELECT count(*) FROM agent_records WHERE plugin = 'heartbeat'"))
        time.sleep(2)          # the logs plugin has its word from the receiver: nothing yet, so from what is written now
        write_journal(self.journal, [(3, 'Out of memory: Killed process 77 (java)'), (7, 'chatter'), (6, 'after it')])
        self.assertEqual(self.wait_for(lambda: self.lines() if len(self.lines()) >= 2 else None), ['Out of memory: Killed process 77 (java)', 'after it'])
        status = hostlogs.status(self.conn, 'nas')[0]
        self.assertEqual((status['signed'], status['gaps']), (True, 0), 'the debug line was left out and said so: no gap')
        # the agent starts again (a reboot, say): lines written meanwhile come, and none twice
        sfagent.lifecycle(self.db, 'nas', 'restart', 'test')
        write_journal(self.journal, [(4, 'while it was away')])
        got = self.wait_for(lambda: self.lines() if len(self.lines()) >= 3 else None, seconds=60)
        self.assertEqual(got, ['Out of memory: Killed process 77 (java)', 'after it', 'while it was away'])
        self.assertIn('agent-silent', json.dumps(agentwatch.problems(self.conn, time.time() + 60)), 'and its heartbeat is how silence is seen')


if __name__ == '__main__':
    unittest.main()
