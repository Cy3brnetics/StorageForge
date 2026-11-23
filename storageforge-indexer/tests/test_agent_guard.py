"""Wipe and stop (roadmap section 11.3) and what an agent's report may cause (11.2: "its actions affect only itself", "anything wider
needs a second witness"), from the controller's side (agentguard.py, agentaction.py; the host's side is agent/src/outside.rs and
agent/src/wipe.rs, with their own Rust tests).

What is real: storageforge-agentctl and storageforge-agent, built with a release key made for the run; the controller's signed
requests; the database (SQLite, and PostgreSQL with STORAGEFORGE_TEST_PG), the vault and the audit chain; the receiver and the tunnel in
LastWord. What stands in: the host, as in test_agent. Its docker here is a small program that keeps the arguments the container was
made with and answers `inspect` and `diff` as Docker does for a container made so (the shape of Docker's answers is the real one, and
agent/src/outside.rs's tests hold it); RealDocker in test_agent runs the real Docker."""
import json
import os
import shutil
import time
import unittest
from pathlib import Path

import dbfactory
import test_agent
import test_agent_receiver
from storageforge_index import agentaction, agentguard, agentwatch, notifications, sfagent

# A stand-in for docker that remembers how the container was made and describes it as Docker would. It starts the real agent where
# Docker would start the container. Values are read from the arguments storageforge-agentctl gave; nothing here is a fixed answer.
DOCKER = r'''#!/usr/bin/python3
import json, os, signal, subprocess, sys
D = os.environ.get('SF_STUB_DIR') or os.path.dirname(os.path.dirname(os.path.abspath(sys.argv[0])))
a = sys.argv[1:]
open(os.path.join(D, 'log'), 'a').write('docker ' + ' '.join(a) + '\n')
made, pidf, diff = os.path.join(D, 'run.json'), os.path.join(D, 'agent.pid'), os.path.join(D, 'diff.txt')
def running():
    try:
        os.kill(int(open(pidf).read()), 0); return True
    except Exception:
        return False
def stop():
    try:
        os.kill(int(open(pidf).read()), signal.SIGTERM)
    except Exception:
        pass
    try: os.remove(pidf)
    except OSError: pass
if a[:1] == ['--version']:
    print('Docker version 29.1.0, build stand-in'); sys.exit(0)
if a[:1] == ['run']:
    json.dump(a[1:], open(made, 'w'))
    host = json.load(open(os.path.join(D, 'host.json')))
    p = subprocess.Popen([host['agent'], 'run', '--etc', host['etc'], '--manifest', host['manifest'], '--state', host['state']],
                         stdout=open(host['log'], 'a'), stderr=subprocess.STDOUT, start_new_session=True)
    open(pidf, 'w').write(str(p.pid)); sys.exit(0)
if a[:1] in (['stop'], ['kill']):
    stop(); sys.exit(0)
if a[:1] == ['rm']:
    stop()
    if os.path.exists(made): os.remove(made)
    sys.exit(0)
if a[:2] == ['image', 'inspect']:
    print('sha256:' + '1' * 64); sys.exit(0)
if a[:1] == ['diff']:
    if not os.path.exists(made): sys.exit(1)
    print(open(diff).read() if os.path.exists(diff) else '', end=''); sys.exit(0)
if a[:1] == ['inspect']:
    if not os.path.exists(made): sys.exit(1)
    args = json.load(open(made))
    if '--format' in a:
        print(('true' if running() else 'false') + ' sha256:' + '1' * 64); sys.exit(0)
    hc = {'Privileged': False, 'ReadonlyRootfs': False, 'CapAdd': [], 'CapDrop': [], 'SecurityOpt': [], 'NetworkMode': 'default', 'PidMode': '',
          'Devices': [], 'Tmpfs': {}}
    c = {'Image': 'sha256:' + '1' * 64, 'Config': {'Image': '', 'User': ''}, 'State': {'Running': running()}, 'HostConfig': hc, 'Mounts': []}
    i = 0
    while i < len(args):
        x = args[i]
        v = args[i + 1] if i + 1 < len(args) else ''
        if x in ('-d', '--read-only'):
            hc['ReadonlyRootfs'] = hc['ReadonlyRootfs'] or x == '--read-only'; i += 1; continue
        if not x.startswith('-'):
            c['Config']['Image'] = x; break
        if x == '--cap-add': hc['CapAdd'].append(v)
        elif x == '--cap-drop': hc['CapDrop'].append(v)
        elif x == '--security-opt': hc['SecurityOpt'].append(v)
        elif x == '--user': c['Config']['User'] = v
        elif x == '--network': hc['NetworkMode'] = v
        elif x == '--pid': hc['PidMode'] = v
        elif x == '--privileged': hc['Privileged'] = True; i += 1; continue
        elif x == '--device': hc['Devices'].append({'PathOnHost': v.split(':')[0]})
        elif x == '--tmpfs':
            dst, _, opts = v.partition(':'); hc['Tmpfs'][dst] = opts
        elif x == '--mount':
            o = dict(p.partition('=')[::2] for p in v.split(','))
            c['Mounts'].append({'Type': o.get('type'), 'Source': o.get('src'), 'Destination': o.get('dst'), 'RW': not ('ro' in o or 'readonly' in o)})
        i += 2
    print(json.dumps([c])); sys.exit(0)
sys.exit(0)
'''


class Gate(unittest.TestCase):
    """agentaction: the one road by which a report causes an action."""

    def setUp(self):
        import tempfile
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.db = dbfactory.make(self, self.tmp / 'index.db')
        self.conn = self.db.connect()
        self.addCleanup(self.conn.close)
        self.db.migrate(self.conn)

    def rows(self):
        return [(r['host'], r['action'], r['target'], r['outcome']) for r in reversed(agentaction.recent(self.conn))]

    def test_a_report_acts_only_on_the_agent_that_sent_it_whatever_it_names(self):
        hit = []
        got = agentaction.on_self(self.conn, 'nas', 'SHA256:nas', 'wipe-self', hit.append, named={'host': 'backup', 'address': '10.0.0.9'})
        self.assertEqual((got, hit), ('done', ['nas']), 'the reporter, never the host the message names')
        row = agentaction.recent(self.conn)[0]
        self.assertEqual((row['target'], row['named']['host']), ('nas', 'backup'))
        self.assertIn('an agent can accuse only itself', row['detail'])
        # an action that is not protective, or not about the reporter, is no action a report causes by itself
        for action in ('freeze-share', 'drop-client', 'run', 'wipe'):
            with self.assertRaises(agentaction.Refused):
                agentaction.on_self(self.conn, 'nas', 'SHA256:nas', action, hit.append)
        self.assertEqual(hit, ['nas'])
        with self.assertRaises(agentaction.Refused):
            agentaction.on_self(self.conn, '', None, 'wipe-self', hit.append)
        self.assertEqual([r[3] for r in self.rows()], ['done', 'refused', 'refused', 'refused', 'refused'])

    def test_anything_wider_waits_for_an_independent_witness_or_a_person(self):
        frozen = []
        now = time.time()
        W = agentaction.Witness
        # no witness, the reporter's own sentinel, another target, an old one, an agent: held, and a person is told
        for witnesses in ([], [W('sentinel', 'nas', 'share:/srv/a', now)], [W('scan', 'files', 'share:/srv/b', now)],
                          [W('decoy', 'files', 'share:/srv/a', now - 3600)], [W('agent', 'files', 'share:/srv/a', now)]):
            got = agentaction.wider(self.conn, 'nas', 'SHA256:nas', 'freeze-share', 'share:/srv/a', witnesses, frozen.append, now=now)
            self.assertEqual(got, 'held', witnesses)
        self.assertEqual(frozen, [])
        held = agentaction.problems(self.conn)
        self.assertEqual(held['agent-held:nas'][0], 'agent-held')
        self.assertIn('agent-held:nas', agentwatch.problems(self.conn), 'through the notification center')
        # the share host's own sentinel, or a scan over SSH, agreeing about the same share: done
        got = agentaction.wider(self.conn, 'nas', 'SHA256:nas', 'freeze-share', 'share:/srv/a', [W('sentinel', 'files', 'share:/srv/a', now)], frozen.append, now=now)
        self.assertEqual((got, frozen), ('done', ['share:/srv/a']))
        self.assertEqual(agentaction.recent(self.conn)[0]['witnesses'][0]['source'], 'sentinel')
        with self.assertRaises(agentaction.Refused):
            agentaction.wider(self.conn, 'nas', None, 'wipe-self', 'nas', [], frozen.append)

    def test_shadow_copy_tripwire_drops_pinned_address_only_and_requires_witness(self):
        from storageforge_index import agentplugins
        self.conn.execute("INSERT INTO hosts (hostname, ssh_host, ssh_port) VALUES ('win-client', '10.0.0.55', 22)")
        self.conn.execute("""INSERT INTO agents (host, enabled, state, public_key, fingerprint, counter, updated_at, updated_by)
                             VALUES ('win-client', 1, 'running', 'ssh-ed25519 AAAA', 'SHA256:win', 1, 0, 'test')""")
        # All 5 documented shadow-copy commands + vanished shadows match
        for cmd in ('vssadmin.exe delete shadows /all /quiet', 'wmic shadowcopy delete',
                    'powershell Get-WmiObject Win32_ShadowCopy | ForEach-Object { $_.Delete() }',
                    'wbadmin delete catalog -quiet', 'bcdedit /set {default} recoveryenabled no'):
            self.assertIsNotNone(agentaction.detect_shadow_copy_tamper({'command': cmd}), cmd)
        self.assertIsNotNone(agentaction.detect_shadow_copy_tamper({'before': 3, 'after': 0}))
        self.assertIsNone(agentaction.detect_shadow_copy_tamper({'command': 'vssadmin list shadows'}))

        # Ingested report naming another client IP ('10.0.0.99') only targets pinned '10.0.0.55' and holds without witness
        now = int(time.time())
        self.conn.execute("""INSERT INTO agent_records (host, fingerprint, counter, seq, plugin, kind, received_at, body_json)
                             VALUES ('win-client', 'SHA256:win', 1, 1, 'tripwire', 'shadow_copy', :t, :b)""",
                          {'t': now, 'b': json.dumps({'command': 'vssadmin delete shadows /all', 'client': '10.0.0.99', 'host': 'other-pc'})})
        self.assertEqual(agentplugins.take(self.db, now), {'tripwire': 1})
        act = agentaction.recent(self.conn, 'win-client')[0]
        self.assertEqual((act['action'], act['target'], act['outcome']), ('shadow-copy-tripwire', '10.0.0.55', 'held'))
        self.assertEqual(act['named']['client'], '10.0.0.99')
        self.assertIn('agent-held:win-client', agentwatch.problems(self.conn, now))
        self.assertEqual(self.conn.scalar("SELECT kind FROM security_events WHERE host = 'win-client'"), 'shadow_copy_tripwire')

        # With an independent witness (share host's own sentinel seeing 10.0.0.55), tripwire_drop executes against pinned address
        dropped = []
        witnesses = [agentaction.Witness('sentinel', 'nas', '10.0.0.55', now)]
        res = agentaction.tripwire_drop(self.conn, 'win-client', 'SHA256:win', {'command': 'wmic shadowcopy delete', 'address': '10.0.0.88'},
                                        witnesses=witnesses, perform=dropped.append, now=now)
        self.assertEqual((res['outcome'], res['target'], dropped), ('done', '10.0.0.55', ['10.0.0.55']))

        # Share freeze also routes cleanly through wider
        frozen = []
        self.assertEqual(agentaction.freeze_share(self.conn, 'win-client', 'SHA256:win', 'share:/srv/smb', witnesses=[], perform=frozen.append, now=now)['outcome'], 'held')
        self.assertEqual(frozen, [])
        self.assertEqual(agentaction.freeze_share(self.conn, 'win-client', 'SHA256:win', 'share:/srv/smb',
                                                witnesses=[agentaction.Witness('decoy', 'nas', 'share:/srv/smb', now)], perform=frozen.append, now=now)['outcome'], 'done')
        self.assertEqual(frozen, ['share:/srv/smb'])

    def test_a_failed_action_is_recorded_as_failed(self):
        def boom(_host):
            raise RuntimeError('the host could not be reached')
        self.assertEqual(agentaction.on_self(self.conn, 'nas', 'SHA256:nas', 'wipe-self', boom), 'failed')
        self.assertIn('could not be reached', agentaction.recent(self.conn)[0]['detail'])


class Outside(test_agent.Base):
    """The check from outside, over SSH, and the wipe that follows a finding."""

    def setUp(self):
        super().setUp()
        (self.host.bin / 'docker').unlink()
        (self.host.bin / 'docker').write_text(DOCKER)
        (self.host.bin / 'docker').chmod(0o755)
        var = self.host.root / 'var/lib/storageforge-agent'
        (self.host.dir / 'host.json').write_text(json.dumps({'agent': str(self.out / 'storageforge-agent'), 'etc': str(self.host.root / 'etc/storageforge-agent'),
                                                             'manifest': str(var / 'manifest'), 'state': str(var / 'state'), 'log': str(self.host.agent_log)}))
        self.state = var / 'state'

    def made(self):
        return json.loads((self.host.dir / 'run.json').read_text())

    def remake(self, args):
        (self.host.dir / 'run.json').write_text(json.dumps(args))

    def assert_wiped(self, says):
        row = sfagent.get(self.conn, 'nas')
        self.assertEqual(row['state'], 'wiped')
        self.assertIsNone(row['public_key'], 'the key is revoked here: the receiver no longer knows it')
        self.assertIn(says, row['detail'])
        self.assertFalse((self.state / 'agent_key').exists(), 'the key is gone from the host')
        self.assertTrue((self.state / 'wiped').exists())
        self.assertFalse((self.host.root / 'var/lib/storageforge-agent/ctl/agent.pub').exists())
        self.assertTrue(any(c == 'docker update --restart no storageforge-agent' for c in self.host.calls('docker')), 'left stopped whatever its restart policy')
        self.assertFalse((self.host.dir / 'agent.pid').exists(), 'the container is stopped')
        self.assertIn(('agent.wipe', 'ok'), self.audit())
        problem = agentwatch.problems(self.conn)['security-agent-wiped:nas']
        self.assertEqual(problem[4], 'crit')
        self.assertFalse(notifications.ignorable(problem[0], problem[4]), 'it cannot be snoozed or muted')
        # nothing starts it again but a new enrollment
        with self.assertRaises(sfagent.AgentError) as cm:
            sfagent.lifecycle(self.db, 'nas', 'start', 'test')
        self.assertEqual(cm.exception.code, 'wiped')
        with self.assertRaises(sfagent.AgentError):
            sfagent.apply(self.db, 'nas', [], actor='test')
        rc, got = self.ask('start')
        self.assertEqual((rc, got.get('error')), (97, 'not-enrolled'), 'the host refuses it too')

    def test_a_container_as_it_was_made_is_clean(self):
        self.install()
        got = agentguard.check(self.db, 'nas')
        self.assertEqual((got['checked'], got['clean'], got['findings']), (True, True, []), got)
        row = sfagent.get(self.conn, 'nas')
        self.assertEqual(row['state'], 'running')
        self.assertTrue(json.loads(row['check_json'])['ok'])
        self.assertIn('image, mounts, capabilities and devices', json.loads(row['check_json'])['checked'])
        self.assertEqual(agentguard.due(self.conn), [], 'checked just now')
        later = int(time.time()) + 5
        if self.conn.dialect != 'sqlite':          # a timestamp there, an epoch on SQLite
            import datetime
            later = datetime.datetime.fromtimestamp(later, datetime.timezone.utc)
        self.conn.execute("UPDATE hosts SET last_scanned_at = :t WHERE hostname = 'nas'", {'t': later})
        self.assertEqual(agentguard.due(self.conn), ['nas'], 'and again after the next scan')

    def test_a_file_changed_in_the_container_wipes_it(self):
        self.install()
        (self.host.dir / 'diff.txt').write_text('C /usr\nC /usr/bin\nA /usr/bin/sh\n')
        got = agentguard.check(self.db, 'nas')
        self.assertFalse(got['clean'])
        self.assertIn('/usr/bin/sh in the container was added', got['findings'])
        self.assert_wiped('/usr/bin/sh in the container was added')

    def test_a_container_given_more_than_its_plugins_declare_wipes_it(self):
        self.install()
        args = self.made()
        at = args.index('--read-only')
        self.remake(args[:at] + ['--cap-add', 'SYS_ADMIN', '--mount', 'type=bind,src=/var/run/docker.sock,dst=/run/docker.sock'] + args[at:])
        got = agentguard.check(self.db, 'nas')
        self.assertIn('the container holds SYS_ADMIN, which no plugin of the manifest declares', got['findings'])
        self.assertTrue(any('/run/docker.sock' in f for f in got['findings']), got['findings'])
        self.assert_wiped('SYS_ADMIN')

    def test_a_file_in_the_state_folder_the_agent_does_not_keep_wipes_it(self):
        self.install()
        (self.state / 'payload').write_text('#!/bin/sh\n')
        got = agentguard.check(self.db, 'nas')
        self.assertEqual(got['findings'], ["payload is in the agent's state folder and the agent keeps no such file"])
        self.assert_wiped('payload')

    def test_an_agent_that_found_tampering_itself_is_wiped_from_outside_too(self):
        self.install()
        plugins = self.state / 'plugins'
        plugins.mkdir(exist_ok=True)
        (plugins / 'dropped.plugin').write_bytes(b'\x7fELF')
        sfagent.lifecycle(self.db, 'nas', 'restart', 'test')
        for _ in range(100):
            if (self.state / 'wiped').exists():
                break
            time.sleep(0.1)
        self.assertIn('dropped.plugin is in the plugin folder', (self.state / 'wiped').read_text())
        got = agentguard.check(self.db, 'nas')
        self.assertTrue(any(f.startswith('the agent wiped itself: dropped.plugin') for f in got['findings']), got['findings'])
        self.assert_wiped('the agent wiped itself')

    def test_a_check_that_cannot_run_wipes_nothing(self):
        self.install()

        def unreachable(*_a):
            return 255, b'', b'ssh: connect to host 10.0.0.3 port 22: No route to host\n'
        from unittest import mock
        with mock.patch.object(sfagent, '_send', unreachable):
            got = agentguard.check(self.db, 'nas')
        self.assertFalse(got['checked'])
        row = sfagent.get(self.conn, 'nas')
        self.assertEqual(row['state'], 'running')
        self.assertFalse(json.loads(row['check_json'])['ok'])
        self.conn.execute("UPDATE agents SET enrolled_at = :t WHERE host = 'nas'", {'t': int(time.time()) - 2 * agentguard.UNCHECKED_SECS})
        self.assertIn('agent-unchecked:nas', agentwatch.problems(self.conn))

    def test_an_agent_is_enrolled_again_after_a_wipe(self):
        self.install()
        old = sfagent.get(self.conn, 'nas')['fingerprint']
        agentguard.wipe(self.db, 'nas', ['a test'], actor='test')
        self.host.kill_agent()
        got = sfagent.start_install(self.db, 'nas', 'admin')
        self.assertTrue(got)
        for _ in range(300):
            row = sfagent.get(self.conn, 'nas')
            if row['state'] in ('running', 'failed'):
                break
            time.sleep(0.1)
        self.assertEqual(row['state'], 'running', row['detail'])
        self.assertNotEqual(row['fingerprint'], old, 'another agent, with a key of its own')
        self.assertIsNone(row['wiped_at'])
        self.assertNotIn('security-agent-wiped:nas', agentwatch.problems(self.conn))
        self.assertEqual(agentguard.check(self.db, 'nas')['findings'], [])


class Reports(test_agent.Base):
    """An agent's last word, as the receiver stored it: it acts on that agent alone."""

    def test_a_last_word_wipes_the_agent_that_sent_it_and_no_other(self):
        self.install()
        fp = sfagent.get(self.conn, 'nas')['fingerprint']
        add = "INSERT INTO agent_records (host, fingerprint, counter, seq, plugin, kind, received_at, body_json) VALUES (:h, :f, 1, 1, :p, 'wipe', 1, :b)"
        # from a plugin, not the agent; from an earlier agent of the host: nothing happens
        self.conn.execute(add, {'h': 'nas', 'f': fp, 'p': 'probe', 'b': '{"why":["x"]}'})
        self.conn.execute(add, {'h': 'nas', 'f': 'SHA256:an-earlier-agent', 'p': 'agent', 'b': '{"why":["x"]}'})
        self.assertEqual(agentguard.take_reports(self.db), 0)
        self.assertEqual(sfagent.get(self.conn, 'nas')['state'], 'running')
        # the agent's own, naming another host as the culprit: the reporter is wiped, the other host is not touched
        self.conn.execute(add, {'h': 'nas', 'f': fp, 'p': 'agent', 'b': json.dumps({'why': ['plugin logs: its program is not the one that was signed'], 'host': 'backup'})})
        self.assertEqual(agentguard.take_reports(self.db), 1)
        self.assertEqual(sfagent.get(self.conn, 'nas')['state'], 'wiped')
        action = agentaction.recent(self.conn)[0]
        self.assertEqual((action['action'], action['host'], action['target'], action['outcome']), ('wipe-self', 'nas', 'nas', 'done'))
        self.assertIn('accuse only itself', action['detail'])
        self.assertEqual(self.conn.scalar("SELECT count(*) FROM agent_records WHERE plugin = 'agent'"), 0, 'each taken once')
        self.assertEqual(len(agentaction.recent(self.conn)), 1, 'and only the one from the agent pinned now acted')


class LastWord(test_agent_receiver.Delivery):
    """The whole road: the real agent finds a file nobody accounts for, wipes its key, says so through its tunnel to the real receiver,
    and the controller revokes it and stops it."""
    test_a_plugin_goes_through_the_tunnel_and_its_readings_come_back_under_the_senders_host = None
    test_a_receiver_key_that_changed_is_given_to_a_host_only_when_a_person_accepts_it = None

    def test_the_agents_last_word_reaches_the_controller_and_wipes_it(self):
        self.install()
        self.wait_for(lambda: self.conn.scalar("SELECT sessions FROM agent_peers WHERE host = 'nas'"))
        plugins = self.host.root / 'var/lib/storageforge-agent/state/plugins'
        plugins.mkdir(exist_ok=True)
        (plugins / 'dropped.plugin').write_bytes(b'\x7fELF')
        sfagent.lifecycle(self.db, 'nas', 'restart', 'test')
        rows = self.wait_for(lambda: self.conn.all("SELECT host, body_json FROM agent_records WHERE plugin = 'agent' AND kind = 'wipe'"))
        self.assertEqual(rows[0][0], 'nas')
        self.assertIn('dropped.plugin', rows[0][1])
        self.wait_for(lambda: 'the controller has the agent\'s last word' in self.host.agent_log.read_text())
        self.assertEqual(agentguard.take_reports(self.db), 1)
        self.assertEqual(sfagent.get(self.conn, 'nas')['state'], 'wiped')
        # its session ends within seconds, and its key opens no other
        self.wait_for(lambda: not self.r.sessions)


class ReceiverRole(test_agent_receiver.Role):
    """What an agent's report may cause, and pushed lines, are moved on the web app's side: the receiver's own role or authorizer
    cannot write what agents may cause, nor host logs, nor wipe an agent, nor read the cursors of anything but its own table."""
    test_it_writes_its_own_tables_reads_the_pins_and_nothing_else = None
    test_the_grants_name_its_tables_and_no_others = None

    def test_the_receiver_cannot_act_or_write_host_logs(self):
        from storageforge_index import agentreceiver as ar
        conn = ar.connect(self.receiver_db())
        self.addCleanup(conn.close)
        conn.execute("UPDATE agent_peers SET resume_json = '{}' WHERE fingerprint = 'none'")      # its own table, its own column
        for sql in ("INSERT INTO agent_actions (at, host, action, target, outcome) VALUES (0, 'nas', 'wipe-self', 'nas', 'done')",
                    "INSERT INTO host_log_lines (host, line_key, at_us, priority, message, collected_at) VALUES ('nas', 'k', 0, 3, 'm', 0)",
                    "UPDATE host_log_status SET seq_gaps = 0", "INSERT INTO log_rule_hits (rule_id, host, bucket, hits) VALUES (1, 'nas', 0, 1)",
                    "UPDATE agents SET state = 'wiped'", "SELECT check_json FROM agents"):
            with self.assertRaises(Exception, msg=sql):
                conn.execute(sql).fetchall()


if __name__ == '__main__':
    unittest.main()
