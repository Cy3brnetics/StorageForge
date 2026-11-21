"""The sentinel's events through the agent (roadmap section 11.4, "Sentinel reports"): the sentinel writes each event to the journal as
well (secscripts.py), the real sentinel plugin takes the lines only root could have written under the sentinel's name, and the controller
reads them as the host's claim through the same checks as the sentinel's own reports (security.ingest_events), marked as come through
the agent, which makes them no witness for an action on another host (agentaction.independent).

What is real: the plugin program, journal files written by systemd's own systemd-journal-remote, security.ingest_events and the
database on SQLite and PostgreSQL. What stands in: the host, a folder."""
import base64
import json
import os
import shutil
import struct
import subprocess
import tempfile
import time
import unittest
import uuid
from pathlib import Path

import test_agent
import test_agent_plugins
from storageforge_index import agentaction, agentplugins, secscripts, security

REMOTE = '/usr/lib/systemd/systemd-journal-remote'


def ev(kind='canary_tripped', summary='a decoy was written', detail='path_b64=' + base64.b64encode(b'/srv/share/.decoy.docx').decode()):
    b = lambda t: base64.b64encode(t.encode()).decode()
    return f'ev\t{uuid.uuid4()}\t{kind}\t{int(time.time())}\t{b(summary)}\t{b(detail)}'


def journal(folder: Path, entries):
    text = ''
    for i, (ident, uid, message) in enumerate(entries):
        text += (f'__REALTIME_TIMESTAMP={int(time.time() * 1e6) + i}\n__MONOTONIC_TIMESTAMP={1000 + i}\n_BOOT_ID={test_agent.MACHINE}\nPRIORITY=4\n'
                 f'SYSLOG_IDENTIFIER={ident}\n_UID={uid}\nMESSAGE={message}\n\n')
    src = folder / 'in.export'
    src.write_text(text)
    p = subprocess.run([REMOTE, f'--output={folder / "system.journal"}', str(src)], capture_output=True, text=True)
    src.unlink()
    assert p.returncode == 0, p.stderr


class Script(unittest.TestCase):
    def test_the_sentinel_writes_its_events_to_the_journal_as_root_only(self):
        self.assertIn('logger -t storageforge-sentinel -- "$line"', secscripts.SENTINEL_SCRIPT)
        line = next(l for l in secscripts.SENTINEL_SCRIPT.splitlines() if 'logger -t storageforge-sentinel' in l)
        self.assertIn('((EUID == 0))', line, 'the tests run the sentinel unprivileged, and this machine\'s journal is not theirs to write')


@unittest.skipUnless(shutil.which('cargo') and os.path.exists(REMOTE), 'needs cargo and systemd-journal-remote')
class Road(test_agent_plugins.Base):
    def setUp(self):
        super().setUp()
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, True)
        (self.root / 'etc').mkdir()
        (self.root / 'etc/machine-id').write_text(test_agent.MACHINE + '\n')
        self.dir = self.root / 'var/log/journal' / test_agent.MACHINE
        self.dir.mkdir(parents=True)
        journal(self.dir, [('storageforge-sentinel', '0', ev('sentinel_started', 'started', ''))])     # written before the plugin ran

    def plugin_lines(self, entries):
        p = subprocess.Popen([str(test_agent.build() / 'storageforge-plugin-sentinel')], stdin=subprocess.PIPE, stdout=subprocess.PIPE, env={})
        try:
            hello = json.dumps({'op': 'hello', 'protocol': 1, 'name': 'sentinel', 'host': str(self.root), 'resume': None}).encode()
            p.stdin.write(struct.pack('>I', len(hello)) + hello)
            p.stdin.flush()
            assert json.loads(p.stdout.read(struct.unpack('>I', p.stdout.read(4))[0]))['op'] == 'ready'
            time.sleep(1.5)
            journal(self.dir, entries)
            deadline = time.time() + 20
            while time.time() < deadline:
                m = json.loads(p.stdout.read(struct.unpack('>I', p.stdout.read(4))[0]))
                if m.get('kind') == 'events':
                    return m['body']
        finally:
            p.kill()
            p.wait()
        raise AssertionError('no events from the plugin')

    def test_root_s_sentinel_lines_come_through_and_are_the_hosts_claim(self):
        self.conn.execute("""INSERT INTO security_canaries (host, path, sha256, size, deployed_at, status) VALUES ('nas', '/srv/share/.decoy.docx', 'x', 1, 1, 'armed')""")
        real, forged = ev(), ev('brake_ran', 'forged', '')
        body = self.plugin_lines([('storageforge-sentinel', '0', real), ('storageforge-sentinel', '1000', forged), ('sshd', '0', ev())])
        self.assertEqual(body['lines'], [real], 'only what root wrote under the sentinel\'s name, and nothing written before the plugin ran')
        self.record('sentinel', 'events', body | {'host': 'web'})
        self.assertEqual(agentplugins.take(self.db), {'sentinel': 1})
        rows = self.conn.all('SELECT host, kind, via FROM security_events')
        self.assertEqual(rows, [('nas', 'canary_tripped', 'agent')], 'under the host the key belongs to')
        self.assertEqual(self.conn.scalar("SELECT status FROM security_canaries WHERE host = 'nas'"), 'tripped')
        # the same event by the sentinel's own report, or a scan, is one event
        self.assertEqual(security.ingest_events(self.conn, 'nas', real, 'scan'), 0)


class NoWitness(unittest.TestCase):
    def test_a_sentinel_event_an_agent_carried_is_no_witness(self):
        now = time.time()
        own = agentaction.Witness('sentinel', 'nas', '10.0.0.9', now)
        carried = agentaction.Witness('sentinel', 'nas', '10.0.0.9', now, via='agent')
        self.assertEqual(agentaction.independent('web', '10.0.0.9', [own, carried], now), [own])


if __name__ == '__main__':
    unittest.main()
