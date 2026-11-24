"""The agent's scan plugin (roadmap section 11.4; decision of 2026-11-16: scans on an agent host are scripts carried in the plugin):
the real plugin program runs its carried script against a folder that stands for a host's root, and what it writes is read by the
controller with the SSH scan's own parser (agentscan.py): the inventory and mounts of a monitoring-only host, and a comparison with the
SSH scan on a host that has both.

What is real: the plugin program, built by cargo, spoken to over its pipes as the agent speaks to it; agentplugins.take, remote.inventory_of
and the database on SQLite and PostgreSQL. What stands in: the host, a folder."""
import json
import shutil
import struct
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

import test_agent
import test_agent_plugins
from storageforge_index import agentplugins, agentscan, agentwatch
from storageforge_index.db import loads

MOUNTINFO = ('22 1 8:2 / / rw,relatime - ext4 /dev/sda2 rw\n'
             '23 22 0:5 / /proc rw - proc proc rw\n'
             '24 22 8:17 / /srv/data rw,noatime - xfs /dev/sdb1 rw\n')


def fake_host(root: Path):
    files = {
        'etc/os-release': 'NAME="Debian GNU/Linux"\nPRETTY_NAME="Debian GNU/Linux 13 (trixie)"\n',
        'etc/machine-id': test_agent.MACHINE + '\n',
        'etc/passwd': 'root:x:0:0:root:/root:/bin/bash\nana:x:1000:1000:Ana:/home/ana:/bin/bash\n',
        'etc/group': 'root:x:0:\nana:x:1000:\nsambashare:x:999:ana\n',
        'etc/exports': '/srv/data 10.0.0.0/24(rw,sync)\n',
        'etc/samba/smb.conf': '[data]\n   path = /srv/data\n',
        'etc/fstab': 'UUID=1 / ext4 defaults 0 1\n',
        'etc/systemd/system/multi-user.target.wants/nfs-server.service': '',
        'proc/1/mountinfo': MOUNTINFO,
        'proc/sys/kernel/hostname': 'quiet\n',
        'proc/sys/kernel/ostype': 'Linux\n',
        'proc/sys/kernel/osrelease': '6.12.0\n',
        'sys/block/sda/size': '2097152\n',
        'sys/block/sda/queue/rotational': '0\n',
        'sys/block/sda/sda2/size': '2000000\n',
        'sys/block/sda/sda2/partition': '2\n',
    }
    for path, text in files.items():
        p = root / path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    (root / 'etc/shadow').write_text('root:$6$secret:1:0:99999:7:::\n')


def run_plugin(program: Path, host: Path) -> list[dict]:
    p = subprocess.Popen([str(program)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, env={})
    try:
        hello = json.dumps({'op': 'hello', 'protocol': 1, 'name': 'scan', 'host': str(host), 'resume': None}).encode()
        p.stdin.write(struct.pack('>I', len(hello)) + hello)
        p.stdin.flush()
        out, deadline = [], time.time() + 20
        while time.time() < deadline:
            head = p.stdout.read(4)
            if len(head) < 4:
                break
            m = json.loads(p.stdout.read(struct.unpack('>I', head)[0]))
            if m.get('kind') == 'inventory':
                out.append(m['body'])
                if len(out) == m['body']['of']:
                    return out
        raise AssertionError(f'no whole inventory from the plugin: {out}')
    finally:
        p.kill()
        p.communicate()


@unittest.skipUnless(shutil.which('cargo'), 'needs cargo to build the plugin')
class Scan(test_agent_plugins.Base):
    def setUp(self):
        super().setUp()
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, True)
        fake_host(self.root)
        self.parts = run_plugin(test_agent.build() / 'storageforge-plugin-scan', self.root)

    def test_what_the_carried_script_writes_is_read_with_the_ssh_scans_parser(self):
        text = ''.join(p['text'] for p in self.parts)
        self.assertNotIn('$6$secret', text, 'nothing in the script reads the password file')
        self.conn.execute("UPDATE agents SET mode = 'monitoring' WHERE host = 'nas'")
        for part in self.parts:
            self.record('scan', 'inventory', part)
        self.assertEqual(agentplugins.take(self.db), {'scan': len(self.parts)})
        inv = loads(self.conn.scalar("SELECT inventory_json FROM hosts WHERE hostname = 'nas'"))
        self.assertIsNotNone(self.conn.scalar("SELECT last_scanned_at FROM hosts WHERE hostname = 'nas'"))
        self.assertEqual((inv['source'], inv['label']), ('agent', 'reported by agent'))
        self.assertEqual(sorted(m['target'] for m in inv['mounts']), ['/', '/proc', '/srv/data'])
        self.assertIn('/srv/data 10.0.0.0/24', inv['nfs'])
        self.assertIn('path = /srv/data', inv['smb'])
        self.assertIn('/etc/fstab', inv['configs']['files'] if 'files' in (inv['configs'] or {}) else inv['configs'])
        self.assertEqual(inv['lsblk']['blockdevices'][0]['children'][0]['name'], 'sda2')
        self.assertIn('u\tana\t1000', inv['accounts'])
        self.assertEqual(inv['services']['enabled'][0]['unit'], 'nfs-server.service')
        self.assertEqual(self.conn.scalar("SELECT os_info FROM hosts WHERE hostname = 'nas'"), 'Debian GNU/Linux 13 (trixie) · Linux 6.12.0 ' + __import__('platform').machine())
        mounts = dict(self.conn.all("""SELECT m.mount_point, m.scan_state FROM mounts m JOIN hosts h ON h.host_id = m.host_id WHERE h.hostname = 'nas'"""))
        self.assertEqual(mounts.get('/srv/data'), 'indexed', 'a monitoring-only host gets its file index through the agent')
        self.assertEqual(self.conn.scalar("SELECT machine_id FROM hosts WHERE hostname = 'nas'"), '0' * 32, 'its machine id is not taken from the agent')
        self.assertNotIn('agent-scan-disagree:nas', agentwatch.problems(self.conn))

    def test_on_a_host_with_ssh_the_two_scans_are_compared(self):
        ssh = {'mounts': [{'target': '/', 'fstype': 'ext4'}, {'target': '/srv/data', 'fstype': 'xfs'}, {'target': '/srv/backup', 'fstype': 'ext4'}]}
        self.conn.execute("UPDATE hosts SET inventory_json = :i, os_info = 'Debian GNU/Linux 13 (trixie) · Linux 6.12.0 x86_64' WHERE hostname = 'nas'", {'i': json.dumps(ssh)})
        for part in self.parts:
            self.record('scan', 'inventory', part)
        agentplugins.take(self.db)
        got = agentwatch.problems(self.conn)['agent-scan-disagree:nas']
        self.assertIn('only the scan saw /srv/backup', got[3])
        self.assertIn('reported by agent', got[3])
        self.assertEqual(loads(self.conn.scalar("SELECT inventory_json FROM hosts WHERE hostname = 'nas'")), ssh, 'the SSH scan\'s inventory is left as it was')

    def test_a_part_that_is_not_one_is_dropped(self):
        for bad in ({'script': 'other', 'run': 1, 'part': 0, 'of': 1, 'text': '@@hostname\nx'}, {'script': 'inventory', 'run': 1, 'part': 3, 'of': 2, 'text': ''},
                    {'script': 'inventory', 'run': 'x', 'part': 0, 'of': 1, 'text': ''}, {'script': 'inventory', 'run': 1, 'part': 0, 'of': 1, 'text': 'x' * (agentscan.MOST_PART + 1)}):
            self.record('scan', 'inventory', bad)
        agentplugins.take(self.db)
        self.assertIsNone(agentscan.view(self.conn, 'nas'))


if __name__ == '__main__':
    unittest.main()
