"""Quiesced snapshots of a stack (stack-snapshot, steps_workloads.py): the check against the index, and the script against stand-in
docker, findmnt, stat, zfs and btrfs. Stop, snapshot, start; the stack runs again even when a snapshot fails; the method is recorded."""
import json
import os
import shlex
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

try:
    import dbfactory
except ImportError:      # run as tests.test_x from the project folder
    from tests import dbfactory
from storageforge_index import changes, steps_workloads as wl
from test_workload_steps import HARNESS


def stub(d: Path, name: str, body: str):
    (d / name).write_text('#!/bin/bash\necho "' + name + ' $*" >>"$LOG"\n' + body + '\n')
    (d / name).chmod(0o755)


class Check(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.db = dbfactory.make(self, Path(self.tmp) / 'index.db')
        self.conn = self.db.connect()
        self.db.migrate(self.conn)
        self.addCleanup(self.conn.close)
        self.conn.execute("INSERT INTO hosts (hostname, ssh_host, ssh_user, inventory_json) VALUES ('nas', 'nas', 'scan', '{}')")
        hid = self.conn.scalar("SELECT host_id FROM hosts WHERE hostname = 'nas'")
        for point, src, fs in (('/', '/dev/sda1', 'ext4'), ('/tank', 'tank', 'zfs')):
            self.conn.execute("INSERT INTO mounts (host_id, mount_point, source, filesystem_type, total_bytes, used_bytes, scan_state) VALUES (:h, :p, :s, :f, 1, 0, 'indexed')",
                              {'h': hid, 'p': point, 's': src, 'f': fs})
        cs = [{'id': 'a', 'name': 'wiki-db-1', 'image': 'postgres:16', 'state': 'running', 'labels': {'com.docker.compose.project': 'wiki'},
               'mounts': [{'type': 'bind', 'source': '/tank/wiki/db', 'dest': '/var/lib/postgresql/data', 'rw': True}]},
              {'id': 'b', 'name': 'wiki-web-1', 'image': 'nginx:1.27', 'state': 'running', 'labels': {'com.docker.compose.project': 'wiki'},
               'mounts': [{'type': 'bind', 'source': '/etc/wiki', 'dest': '/etc/nginx', 'rw': False}]}]
        self.conn.execute("INSERT INTO docker_hosts (host_id, engine, access, root_dir, containers_json, volumes_json, compose_json, scan_id, updated_at) "
                          "VALUES (:h, 'docker', 'direct', '/var/lib/docker', :c, '[]', '[]', NULL, 1)", {'h': hid, 'c': json.dumps(cs)})

    def items(self, **p):
        plan = {'name': 's', 'tasks': [{'type': 'stack-snapshot', 'host': 'nas', 'params': {'runtime': 'docker', 'stack': 'wiki', **p}}]}
        return [(it['level'], it['text']) for it in changes.check(self.conn, changes.normalize(plan))['tasks'][0]['items']]

    def test_what_is_snapshotted_and_a_live_database(self):
        got = self.items()
        self.assertIn(('ok', 'snapshots of what it keeps: /tank/wiki/db (zfs)'), got)
        self.assertIn(('warn', 'not on ZFS or btrfs, so not snapshotted: /etc/wiki (ext4)'), got)
        self.assertTrue(any('stops for as long as the snapshots take' in t for _, t in got))
        self.assertTrue(any(l == 'warn' and 'wiki-db-1 is a database' in t for l, t in self.items(method='live')))
        self.assertTrue(any(l == 'warn' and 'no stack other' in t for l, t in self.items(stack='other')))


class Script(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.d)
        self.bin, self.fake = self.d / 'bin', self.d / 'fake'
        self.sub = self.d / 'pool/app'                 # a btrfs subvolume, its data in a folder under it
        for p in (self.bin, self.fake, self.sub / 'data'):
            p.mkdir(parents=True)
        mounts = {'a': ['/tank/wiki/db'], 'b': [str(self.sub / 'data'), '/etc/wiki', 'relative']}
        stub(self.bin, 'docker', f'''case $1 in
  ps) echo a; echo b ;;
  inspect) case ${{@: -1}} in a) printf "%s\\n" {' '.join(shlex.quote(x) for x in mounts['a'])} ;; b) printf "%s\\n" {' '.join(shlex.quote(x) for x in mounts['b'])} ;; esac ;;
esac''')
        stub(self.bin, 'findmnt', f'''case ${{@: -1}} in /tank/*) echo "zfs tank/wiki" ;; {self.d}/pool/*) echo "btrfs /dev/sdb[/app]" ;; *) echo "ext4 /dev/sda1" ;; esac''')
        stub(self.bin, 'stat', f'[[ ${{@: -1}} == {self.sub} ]] && echo 256 || echo 1234')
        stub(self.bin, 'zfs', '[[ -e $FAKE/zfs-fails ]] && exit 1; exit 0')
        stub(self.bin, 'btrfs', 'mkdir -p "${@: -1}"')

    def run_fn(self, apply, method=''):
        script = HARNESS + f'APPLY={int(apply)}\nWL_LOG={self.d}/quiesce.log\n' + wl.BASH + f'\nt_stack_snapshot docker wiki {shlex.quote(method)}\nexit $((PROBLEMS > 0))\n'
        return subprocess.run(['bash', '-c', script], capture_output=True, text=True, timeout=60,
                              env={**os.environ, 'PATH': f'{self.bin}:{os.environ["PATH"]}', 'LOG': str(self.d / 'log'), 'FAKE': str(self.fake)})

    def log(self):
        return (self.d / 'log').read_text() if (self.d / 'log').exists() else ''

    def test_report_then_stop_snapshot_start_with_the_method_recorded(self):
        out = self.run_fn(False)
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertIn(f'snapshots of zfs tank/wiki btrfs {self.sub}; method stop-snapshot-start', out.stdout)
        self.assertIn('not snapshotted, as their filesystem has no snapshots: /etc/wiki (ext4)', out.stdout)
        self.assertNotIn('docker stop', self.log())
        out = self.run_fn(True)
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        lines = [l for l in self.log().splitlines() if l.split()[0] in ('zfs', 'btrfs') or l.split()[1] in ('stop', 'start')]
        self.assertEqual([l.split()[0] + ' ' + l.split()[1] for l in lines], ['docker stop', 'zfs snapshot', 'btrfs subvolume', 'docker start'])
        self.assertIn('zfs snapshot -o storageforge:quiesce=stop tank/wiki@sf-wiki-20261120-120000', self.log())
        self.assertIn(f'btrfs subvolume snapshot -r -- {self.sub} {self.sub}/.storageforge-snapshots/wiki-20261120-120000', self.log())
        rec = (self.d / 'quiesce.log').read_text().split('\t')
        self.assertEqual(rec[:3], ['20261120-120000', 'wiki', 'stop-snapshot-start'])

    def test_a_failed_snapshot_still_starts_the_stack_and_pause_unpauses(self):
        (self.fake / 'zfs-fails').touch()
        out = self.run_fn(True)
        self.assertNotEqual(out.returncode, 0)
        self.assertIn('some snapshots of wiki failed', out.stdout)
        self.assertIn('docker start a b', self.log())
        out = self.run_fn(True, 'pause')
        self.assertIn('docker pause a b', self.log())
        self.assertIn('docker unpause a b', self.log())
        self.assertIn('the method is', self.run_fn(False, 'bogus').stdout)


if __name__ == '__main__':
    unittest.main()
