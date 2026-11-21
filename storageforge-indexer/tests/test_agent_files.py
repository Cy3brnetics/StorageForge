"""The agent's files plugin (roadmap sections 11.4 and 9, "Watchers"; agentfiles.py and agent/src/bin/plugin-files.rs): changes with
the process and account behind them, the file index updated as they come, hand edits to managed files, reads out of hours, the file
index from SSH and the agent checked against each other, and the plugin's privileges, root in effect, taking an admin.

What is real: the database on SQLite and PostgreSQL with its file index tables, the routes and the audit log, and in InDocker the real
plugin program with the real kernel's fanotify, in a container given the plugin's declared capabilities. What stands in: in the first
classes the readings are the plugin's form; the host's own processes, in InDocker, are this machine's."""
import json
import os
import queue
import shutil
import struct
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

import test_agent
import test_agent_plugins
import test_agent_trust
from storageforge_index import agentfiles, agentplugins, agentwatch, alerts, sfagent


class Base(test_agent_plugins.Base):
    def setUp(self):
        super().setUp()
        inv = {'accounts': 'u\tana\t1000\t1000\t/home/ana\t/bin/bash\nu\tben\t1001\t1001\t/home/ben\t/bin/bash',
               'managed': '## exports\n/etc/exports: OK\n/etc/storageforge-job.conf: OK'}
        self.conn.execute("UPDATE hosts SET inventory_json = :i WHERE hostname = 'nas'", {'i': json.dumps(inv)})
        self.host_id = self.conn.scalar("SELECT host_id FROM hosts WHERE hostname = 'nas'")
        self.mount = self.conn.scalar("""INSERT INTO mounts (host_id, mount_point, filesystem_type, scan_state) VALUES (:h, '/srv', 'ext4', 'indexed')
                                         RETURNING mount_id""", {'h': self.host_id})
        d = self.conn.scalar("INSERT INTO directories (mount_id, path) VALUES (:m, '/srv/share') RETURNING dir_id", {'m': self.mount})
        mtime = '1700000000' if self.conn.dialect == 'sqlite' else 'to_timestamp(1700000000)'
        self.conn.execute(f"""INSERT INTO file_records (mount_id, dir_id, filename, extension, file_size_bytes, is_directory, is_symlink, modified_at)
                              VALUES (:m, :d, 'old.txt', 'txt', 10, :f, :f, {mtime})""", {'m': self.mount, 'd': d, 'f': False if self.conn.dialect != 'sqlite' else 0})

    def change(self, path, action, at=None, stat=None, process='vim', uid=1000, pid=4242):
        c = {'at': int(at or time.time()), 'path': path, 'action': action, 'pid': pid, 'process': process, 'uid': uid, 'dir': False}
        if stat is not None:
            c['stat'] = stat
        return c

    def index(self):
        return {(p, n): s for p, n, s in self.conn.all("""SELECT d.path, r.filename, r.file_size_bytes FROM file_records r JOIN directories d ON d.dir_id = r.dir_id""")}


class Changes(Base):
    def test_changes_are_kept_with_who_made_them_and_the_index_updates_itself(self):
        now = int(time.time())
        st = {'size': 99, 'mtime': now, 'kind': 'file', 'uid': 1000, 'gid': 1000, 'mode': 0o644}
        self.record('files', 'changes', {'changes': [self.change('/srv/share/old.txt', 'write', stat=st),
                                                     self.change('/srv/share/new.pdf', 'create', stat=st | {'size': 5}),
                                                     self.change('/srv/share/gone.txt', 'delete'),
                                                     self.change('/home/ana/notes', 'write', stat=st),
                                                     self.change('relative/path', 'write'), self.change('/srv/x', 'chmod'), 'junk'],
                                         'left_out': 0, 'overflow': 0})
        self.assertEqual(agentplugins.take(self.db), {'files': 1})
        got = {e['path']: e for e in agentfiles.recent(self.conn, 'nas')}
        self.assertEqual(sorted(got), ['/home/ana/notes', '/srv/share/gone.txt', '/srv/share/new.pdf', '/srv/share/old.txt'], 'what is not a change is dropped')
        self.assertEqual((got['/srv/share/old.txt']['process'], got['/srv/share/old.txt']['user'], got['/srv/share/old.txt']['label']), ('vim', 'ana', 'reported by agent'))
        self.assertEqual({p: e['indexed'] for p, e in got.items()},
                         {'/srv/share/old.txt': 'updated', '/srv/share/new.pdf': 'added', '/srv/share/gone.txt': 'not in the index', '/home/ana/notes': 'no indexed mount'})
        self.assertEqual(self.index(), {('/srv/share', 'old.txt'): 99, ('/srv/share', 'new.pdf'): 5})
        if self.conn.dialect == 'sqlite':
            self.assertEqual(self.conn.scalar("SELECT count(*) FROM file_fts WHERE file_fts MATCH 'new'"), 1, 'found by name search at once')
        self.record('files', 'changes', {'changes': [self.change('/srv/share/new.pdf', 'moved_from')]})
        agentplugins.take(self.db)
        self.assertEqual(self.index(), {('/srv/share', 'old.txt'): 99})

    def test_a_managed_file_changed_while_no_deploy_ran_is_a_hand_edit_that_cannot_be_ignored(self):
        now = int(time.time())
        self.record('files', 'changes', {'changes': [self.change('/etc/exports', 'write', at=now - 60, process='nano', uid=0),
                                                     self.change('/etc/fstab', 'moved_to', at=now - 50, process='vi', uid=1001)]})
        agentplugins.take(self.db)
        p = agentwatch.problems(self.conn)
        self.assertEqual(p['agent-hand-edit:nas:/etc/exports'][0], 'drift')
        self.assertIn('nano as root', p['agent-hand-edit:nas:/etc/exports'][3])
        self.assertIn('vi as ben', p['agent-hand-edit:nas:/etc/fstab'][3], 'a config file StorageForge reads is managed too')
        from storageforge_index import notifications
        self.assertFalse(notifications.ignorable('drift', 'warn'))
        # a change made by a deploy is no hand edit
        self.conn.execute("""INSERT INTO deploy_runs (group_id, host, kind, ref, mode, status, actor, started_at, finished_at)
                             VALUES ('g', 'nas', 'nfs', 'x', 'apply', 'ok', 'test', :s, :f)""", {'s': now - 20, 'f': now - 5})
        self.record('files', 'changes', {'changes': [self.change('/etc/exports.d/a.exports', 'create', at=now - 10, process='install', uid=0)]})
        agentplugins.take(self.db)
        self.assertNotIn('agent-hand-edit:nas:/etc/exports.d/a.exports', agentwatch.problems(self.conn))
        # the deploy that finished after the edits settles them: the managed versions are back
        self.assertNotIn('agent-hand-edit:nas:/etc/exports', agentwatch.problems(self.conn))

    def test_reads_out_of_hours_above_the_limit_are_said(self):
        alerts.set_setting(self.conn, agentfiles.SETTINGS_KEY, {'work_days': [], 'offhours_reads_per_hour': 100}, 'test')
        minute = int(time.time()) // 60
        self.record('files', 'reads', {'minute': minute, 'accounts': [{'uid': 1001, 'reads': 150, 'folders': {'/srv/share/hr': 150}},
                                                                     {'uid': 1000, 'reads': 20, 'folders': {}}, {'uid': None, 'reads': 'x'}]})
        agentplugins.take(self.db)
        p = agentwatch.problems(self.conn)
        self.assertIn('ben read 150 files on nas out of working hours', p['agent-offhours:nas:ben'][2])
        self.assertNotIn('agent-offhours:nas:ana', p)
        # within working hours it is no notification
        alerts.set_setting(self.conn, agentfiles.SETTINGS_KEY, {'work_days': [0, 1, 2, 3, 4, 5, 6], 'work_start': 0, 'work_end': 24}, 'test')
        self.assertNotIn('agent-offhours:nas:ben', agentwatch.problems(self.conn))

    def test_a_filesystem_it_cannot_watch_and_dropped_events_are_said(self):
        self.record('files', 'watching', {'filesystems': [{'target': '/', 'fstype': 'ext4', 'how': 'whole'}],
                                          'refused': [{'target': '/data', 'fstype': 'btrfs', 'why': 'Invalid cross-device link'}]})
        self.record('files', 'changes', {'changes': [], 'left_out': 7, 'overflow': 1})
        agentplugins.take(self.db)
        got = agentwatch.problems(self.conn)['agent-files-blind:nas']
        self.assertIn('/data: Invalid cross-device link', got[3])
        self.assertIn('1 queue overflow(s) and 7 change(s) left out', got[3])


class FromBoth(Base):
    """The file index from SSH and the agent: each checks the other (decision of 2026-11-16)."""

    def scan(self, started, changes):
        ts = (lambda x: x) if self.conn.dialect == 'sqlite' else (lambda x: f'to_timestamp({x})')
        sid = self.conn.scalar(f"""INSERT INTO scans (host_id, started_at, finished_at, status) VALUES (:h, {ts(':s')}, {ts(':f')}, 'ok') RETURNING scan_id""",
                               {'h': self.host_id, 's': started, 'f': started + 10})
        for kind, parent, name in changes:
            self.conn.execute("""INSERT INTO file_changes (scan_id, mount_id, change_type, parent_path, filename, is_directory)
                                 VALUES (:s, :m, :k, :p, :n, :f)""", {'s': sid, 'm': self.mount, 'k': kind, 'p': parent, 'n': name, 'f': False if self.conn.dialect != 'sqlite' else 0})
        return sid

    def test_a_change_the_agent_never_reported_and_one_the_scan_contradicts_are_disagreements(self):
        now = int(time.time())
        self.scan(now - 7200, [])
        self.record('files', 'watching', {'filesystems': [{'target': '/srv', 'fstype': 'ext4'}], 'refused': []}, received=now - 7000)
        self.record('files', 'changes', {'changes': [self.change('/srv/share/old.txt', 'write', at=now - 3000, stat={'size': 1, 'mtime': now, 'kind': 'file'}),
                                                     self.change('/srv/share/fine.txt', 'create', at=now - 3000, stat={'size': 1, 'mtime': now, 'kind': 'file'})]}, received=now - 3000)
        agentplugins.take(self.db, now - 3000)
        # the scan finds old.txt other than the agent said, and report.docx changed while the agent said nothing (held back, say)
        sid = self.scan(now - 600, [('modified', '/srv/share', 'old.txt'), ('added', '/srv/share', 'report.docx')])
        got = agentfiles.after_scan(self.conn, 'nas', sid)
        self.assertEqual((got['unreported'], got['contradicted']), (1, 1))
        p = agentwatch.problems(self.conn)['agent-files-disagree:nas']
        self.assertIn('1 change(s) the agent never reported, and contradicted 1', p[3])
        rows = {e['path']: e for e in agentfiles.recent(self.conn, 'nas')}
        self.assertEqual(rows['/srv/share/report.docx']['label'], 'measured by scan')
        self.assertEqual(rows['/srv/share/old.txt']['checked'], 'contradicted by a scan')
        self.assertIsNone(rows['/srv/share/fine.txt']['checked'], 'what the scan agrees with is no disagreement')

    def test_without_the_files_plugin_a_scan_is_compared_with_nothing(self):
        sid = self.scan(int(time.time()) - 60, [('added', '/srv/share', 'a.txt')])
        self.assertEqual(agentfiles.after_scan(self.conn, 'nas', sid), {'unreported': 0, 'contradicted': 0})


class Privilege(test_agent_trust.Routes):
    """Switching the files plugin on: root on the host in effect, said where it is switched on, and only an admin can."""

    def setUp(self):
        super().setUp()
        release = self.tmp / 'release' / 'x86_64'
        needs = {'mounts': ['/proc'], 'capabilities': ['DAC_READ_SEARCH', 'SYS_ADMIN', 'SYS_PTRACE'], 'namespaces': ['pid']}
        (release / 'files.plugin.json').write_text(json.dumps({'format': 1, 'name': 'files', 'needs': needs}))
        (release / 'files.plugin.sig').write_text('-----BEGIN SSH SIGNATURE-----\nAA==\n-----END SSH SIGNATURE-----\n')

    test_a_plugin_the_release_does_not_have_is_refused = None

    def test_the_files_plugin_says_it_is_root_in_effect_and_takes_an_admin(self):
        listed = {p['name']: p for p in self.client('keeper').get('/api/agents').get_json()['plugins']}
        self.assertTrue(listed['files']['root_in_effect'] and listed['files']['privileged'])
        self.assertTrue(listed['files']['note'].startswith('ROOT ON THIS HOST IN EFFECT'))
        self.assertFalse(listed['heartbeat']['root_in_effect'])
        got = self.client('keeper').post('/api/agents/nas/plugins', json={'plugins': ['files']})
        self.assertEqual(got.status_code, 403)
        self.assertIn('root on the host in effect', got.get_json()['error'])
        got = self.client('root').post('/api/agents/nas/plugins', json={'plugins': ['heartbeat', 'files']})
        self.assertEqual(got.status_code, 200, got.get_json())
        self.assertIn('ROOT ON THIS HOST IN EFFECT', got.get_json()['warning'])
        detail = json.loads(self.conn.scalar("SELECT detail_json FROM audit_log WHERE action = 'agent.plugins' AND outcome = 'ok' ORDER BY audit_id DESC LIMIT 1"))
        self.assertEqual(detail['root_in_effect'], ['files'])

    def test_the_keys_page_says_so_before_it_can_be_ticked(self):
        js = (Path(sfagent.__file__).parent / 'static' / 'agentview.js').read_text()
        self.assertIn('Root on this host in effect', js)
        self.assertIn('confirmDialog', js)


@unittest.skipUnless(shutil.which('docker') and shutil.which('cargo'), 'needs Docker and cargo')
class InDocker(unittest.TestCase):
    """The real plugin program against the real kernel: in a container with the capabilities it declares, it marks the filesystem of
    a folder it is given and reports a file written into that folder from outside the container, with its size."""
    IMAGE = 'cgr.dev/chainguard/wolfi-base:latest'

    def setUp(self):
        if subprocess.run(['docker', 'image', 'inspect', self.IMAGE], capture_output=True).returncode != 0:
            self.skipTest(f'needs the {self.IMAGE} image here')
        self.program = test_agent.build() / 'storageforge-plugin-files'
        self.data = Path(tempfile.mkdtemp(dir=test_agent.TARGET))
        self.addCleanup(shutil.rmtree, self.data, True)
        self.name = f'sffiles-{os.getpid()}'
        self.addCleanup(lambda: subprocess.run(['docker', 'rm', '-f', self.name], capture_output=True))

    def test_a_file_written_from_outside_is_reported_with_its_path_and_size(self):
        # the debug build is linked against this machine's libc, so the container runs it with this machine's loader
        argv = ['docker', 'run', '--rm', '-i', '--name', self.name, '--cap-drop', 'ALL', '--cap-add', 'SYS_ADMIN', '--cap-add', 'DAC_READ_SEARCH',
                '--cap-add', 'SYS_PTRACE', '--security-opt', 'no-new-privileges', '-v', '/usr/lib:/hostlib:ro', '-v', f'{self.program}:/plugin:ro',
                '-v', f'{self.data}:/data', self.IMAGE, '/hostlib/ld-linux-x86-64.so.2', '--library-path', '/hostlib', '/plugin']
        if not Path('/usr/lib/ld-linux-x86-64.so.2').exists():
            self.skipTest('needs the loader at /usr/lib/ld-linux-x86-64.so.2')
        p = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        self.addCleanup(p.kill)
        got = queue.Queue()

        def reader():
            while (head := p.stdout.read(4)) and len(head) == 4:
                got.put(json.loads(p.stdout.read(struct.unpack('>I', head)[0])))
            got.put(None)
        threading.Thread(target=reader, daemon=True).start()
        hello = json.dumps({'op': 'hello', 'protocol': 1, 'name': 'files', 'host': '/', 'resume': None}).encode()
        p.stdin.write(struct.pack('>I', len(hello)) + hello)
        p.stdin.flush()
        self.assertEqual(got.get(timeout=20), {'op': 'ready'})
        watching = got.get(timeout=20)
        self.assertEqual(watching['kind'], 'watching', watching)
        self.assertEqual([f['target'] for f in watching['body']['filesystems']], ['/data'], watching)
        (self.data / 'report.docx').write_bytes(b'x' * 1234)
        deadline = time.time() + 30
        mine = []
        while time.time() < deadline and not mine:
            m = got.get(timeout=30)
            if m and m.get('kind') == 'changes':
                mine = [c for c in m['body']['changes'] if c['path'] == '/data/report.docx']
        self.assertTrue(mine, 'the write was reported')
        self.assertIn(mine[0]['action'], ('create', 'write'))
        self.assertEqual(mine[0]['stat']['size'], 1234)


if __name__ == '__main__':
    unittest.main()
