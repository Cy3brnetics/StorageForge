"""Tests for the Partition Manager, partition create/edit/delete, secure format/wipe and secure file delete."""
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml

try:
    import dbfactory
except ImportError:
    from tests import dbfactory

from storageforge_index import changes, permissions, server, steps_storage, users


def _lsblk_fixture():
    return {'blockdevices': [
        {'name': 'sda', 'path': '/dev/sda', 'type': 'disk', 'size': 100 << 30, 'pttype': 'gpt', 'model': 'OS SSD', 'rota': False, 'tran': 'sata',
         'children': [{'name': 'sda1', 'type': 'part', 'start': 2048, 'size': 99 << 30, 'fstype': 'ext4', 'label': 'root', 'uuid': 'u-os', 'mountpoint': '/'}]},
        {'name': 'sdb', 'path': '/dev/sdb', 'type': 'disk', 'size': 200 << 30, 'pttype': 'gpt', 'model': 'Data HDD', 'rota': True, 'tran': 'sata',
         'children': [
             {'name': 'sdb1', 'type': 'part', 'start': 2048, 'size': 80 << 30, 'fstype': 'ext4', 'partlabel': 'fast', 'label': 'fast', 'uuid': 'u-1', 'mountpoint': None},
             {'name': 'sdb2', 'type': 'part', 'start': (80 << 21) + 2048, 'size': 40 << 30, 'fstype': 'xfs', 'partlabel': 'logs', 'label': 'logs', 'uuid': 'u-2', 'mountpoint': '/mnt/logs'},
         ]},
        {'name': 'sdc', 'path': '/dev/sdc', 'type': 'disk', 'size': 50 << 30, 'pttype': 'dos', 'model': 'Legacy MBR', 'rota': False, 'tran': 'nvme',
         'children': [{'name': 'sdc1', 'type': 'part', 'start': 2048, 'size': 20 << 30, 'fstype': 'ext4', 'mountpoint': None}]},
    ]}


class PartitionManagerAndSecureErase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='sf-store-'))
        self.db = dbfactory.make(self, self.tmp / 'idx.db')
        self.conn = self.db.connect()
        self.db.migrate(self.conn)
        inv = {'lsblk': _lsblk_fixture()}
        with self.conn.tx():
            self.conn.execute("INSERT INTO hosts (hostname, ip_address, inventory_json, last_scanned_at) VALUES ('nas', '10.0.0.10', :i, 1)", {'i': json.dumps(inv)})
            hid = self.conn.scalar("SELECT host_id FROM hosts WHERE hostname = 'nas'")
            self.conn.execute("INSERT INTO mounts (host_id, mount_point, source, filesystem_type, scan_state) VALUES (:h, '/', '/dev/sda1', 'ext4', 'indexed')", {'h': hid})
            self.conn.execute("INSERT INTO mounts (host_id, mount_point, source, filesystem_type, scan_state) VALUES (:h, '/mnt/logs', '/dev/sdb2', 'xfs', 'indexed')", {'h': hid})
            self.conn.execute("INSERT INTO mounts (host_id, mount_point, source, filesystem_type, scan_state) VALUES (:h, '/mnt/data', '/dev/nvme0n1', 'btrfs', 'indexed')", {'h': hid})

    def tearDown(self):
        self.conn.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def check_items(self, *tasks):
        plan = changes.normalize({'name': 'p', 'tasks': [{'host': 'nas', 'type': k, 'params': p} for k, p in tasks]})
        r = changes.check(self.conn, plan)
        return r['tasks']

    def test_disks_api_and_permissions(self):
        users.create(self.conn, 'alice', 'a long enough password')
        client = server.create_app(server.App(self.db), 's' * 48).test_client()
        self.assertIn(client.get('/api/disks').status_code, (302, 401))
        client.post('/api/login', json={'username': 'alice', 'password': 'a long enough password'})
        got = client.get('/api/disks?host=nas').get_json()
        self.assertEqual(len(got['hosts']), 1)
        disks = {d['name']: d for d in got['hosts'][0]['disks']}
        self.assertEqual(disks['sdb']['table'], 'gpt')
        self.assertEqual(disks['sdb']['free_bytes'], 80 << 30)
        self.assertEqual([p['num'] for p in disks['sdb']['parts']], [1, 2])
        self.assertEqual(disks['sdb']['mounted'], ['/mnt/logs'])
        self.assertEqual(permissions.required('GET', '/api/disks'), 'hosts.view')

    def test_all_destructive_steps_require_confirm_and_flag(self):
        for kind, params in (
            ('partition-edit', {'disk': '/dev/sdb', 'partition': '/dev/sdb1', 'name': 'renamed'}),
            ('partition-delete', {'disk': '/dev/sdb', 'partition': '/dev/sdb1', 'method': 'zero'}),
            ('drive-wipe', {'device': '/dev/sdb', 'method': 'random-zero', 'wipe_table': True}),
            ('secure-delete', {'path': '/mnt/data/secret.key', 'method': 'random-zero'}),
        ):
            self.assertTrue(changes.TYPES[kind]['destructive'], kind)
            with self.assertRaisesRegex(ValueError, 'confirm'):
                changes.normalize({'name': 'p', 'tasks': [{'host': 'nas', 'type': kind, 'params': params}]})

    def test_partition_edit_delete_and_plan_reuse(self):
        # Cannot rename GPT partition on MBR disk, cannot shrink mounted partition
        bad = self.check_items(
            ('partition-edit', {'disk': '/dev/sdc', 'partition': '/dev/sdc1', 'name': 'nope', 'confirm': '/dev/sdc1'}),
            ('partition-edit', {'disk': '/dev/sdb', 'partition': '/dev/sdb2', 'size': '10G', 'confirm': '/dev/sdb2'}),
            ('partition-delete', {'disk': '/dev/sda', 'partition': '/dev/sda1', 'method': 'quick', 'confirm': '/dev/sda1'}),
        )
        self.assertTrue(any('GPT partition names' in i['text'] and i['level'] == 'crit' for i in bad[0]['items']))
        self.assertTrue(any('mounted at /mnt/logs' in i['text'] and i['level'] == 'crit' for i in bad[1]['items']))
        self.assertTrue(any('operating system partition' in i['text'] and i['level'] == 'crit' for i in bad[2]['items']))

        # Unmounting /mnt/logs and deleting sdb1 frees space so task 3 can add a new 150G partition on sdb
        ok_flow = self.check_items(
            ('unmount', {'target': '/mnt/logs'}),
            ('partition-delete', {'disk': '/dev/sdb', 'partition': '/dev/sdb1', 'method': 'zero', 'passes': '1', 'confirm': '/dev/sdb1'}),
            ('partition-add', {'disk': '/dev/sdb', 'name': 'replacement', 'size': '150G', 'fstype': 'ext4', 'confirm': '/dev/sdb'}),
        )
        self.assertFalse(any(i['level'] == 'crit' for t in ok_flow for i in t['items']), ok_flow)

    def test_drive_wipe_and_secure_delete_checks(self):
        got = self.check_items(
            ('drive-wipe', {'device': '/dev/sda', 'method': 'zero', 'wipe_table': True, 'confirm': '/dev/sda'}),
            ('drive-wipe', {'device': '/dev/sdb1', 'method': 'discard', 'wipe_table': False, 'confirm': '/dev/sdb1'}),
            ('secure-delete', {'path': '/etc', 'method': 'random-zero', 'passes': '1', 'confirm': '/etc'}),
            ('secure-delete', {'path': '/mnt/data', 'method': 'random-zero', 'passes': '1', 'confirm': '/mnt/data'}),
            ('secure-delete', {'path': '/mnt/data/secret.tar', 'method': 'random-zero', 'passes': '3', 'confirm': '/mnt/data/secret.tar'}),
        )
        self.assertTrue(any('operating system disk' in i['text'] and i['level'] == 'crit' for i in got[0]['items']))
        self.assertTrue(any('spinning HDD' in i['text'] and i['level'] == 'warn' for i in got[1]['items']))
        self.assertTrue(any('system directory' in i['text'] and i['level'] == 'crit' for i in got[2]['items']))
        self.assertTrue(any('mount point' in i['text'] and i['level'] == 'crit' for i in got[3]['items']))
        self.assertTrue(any('copy-on-write' in i['text'] and i['level'] == 'note' for i in got[4]['items']))

    def test_script_and_ansible_generation(self):
        # plan_hash for format/partition stays stable when secure_wipe is empty
        p_old = {'name': 'p', 'tasks': [{'host': 'nas', 'type': 'format', 'params': {'device': '/dev/sdb1', 'fstype': 'ext4', 'wipe': True, 'confirm': '/dev/sdb1'}}]}
        p_new = {'name': 'p', 'tasks': [{'host': 'nas', 'type': 'format', 'params': {'device': '/dev/sdb1', 'fstype': 'ext4', 'wipe': True, 'secure_wipe': '', 'confirm': '/dev/sdb1'}}]}
        self.assertEqual(changes.plan_hash(changes.normalize(p_old)), changes.plan_hash(changes.normalize(p_new)))

        plan = {
            'name': 'Erase and rebuild',
            'tasks': [
                {'host': 'nas', 'type': 'partition-edit', 'params': {'disk': '/dev/sdb', 'partition': '/dev/sdb1', 'name': 'fast2', 'size': '90G', 'flag': 'lvm', 'flag_state': 'on', 'confirm': '/dev/sdb1'}},
                {'host': 'nas', 'type': 'partition-delete', 'params': {'disk': '/dev/sdb', 'partition': '/dev/sdb1', 'method': 'zero', 'passes': '1', 'confirm': '/dev/sdb1'}},
                {'host': 'nas', 'type': 'drive-wipe', 'params': {'device': '/dev/sdb', 'method': 'random-zero', 'passes': '3', 'wipe_table': True, 'confirm': '/dev/sdb'}},
                {'host': 'nas', 'type': 'format', 'params': {'device': '/dev/sdb1', 'fstype': 'ext4', 'label': 'clean', 'wipe': True, 'secure_wipe': 'zero', 'confirm': '/dev/sdb1'}},
                {'host': 'nas', 'type': 'secure-delete', 'params': {'path': '/mnt/data/secret.key', 'method': 'random-zero', 'passes': '3', 'confirm': '/mnt/data/secret.key'}},
            ],
        }
        sh = changes.script(self.conn, plan)
        self.assertEqual(subprocess.run(['bash', '-n'], input=sh, capture_output=True, text=True).returncode, 0)
        for name in ('partition-edit', 'partition-delete', 'drive-wipe', 'secure-delete'):
            self.assertIn(name, sh.split('CUR_DESTRUCTIVE=1 ;; ')[1].split(')')[0])
        plays = yaml.safe_load(changes.ansible(self.conn, plan))
        self.assertEqual(len(plays[0]['tasks']), 6)       # 4 steps + 2 tasks (wipe + filesystem) for secure format
        for t in plays[0]['tasks']:
            self.assertEqual(t['when'], 'storageforge_destructive | default(false) | bool')

    def test_real_bash_secure_delete_and_wipe(self):
        secret = self.tmp / 'topsecret.txt'
        secret.write_bytes(b'CONFIDENTIAL-' * 200)
        folder = self.tmp / 'dir_to_wipe'
        folder.mkdir()
        (folder / 'a.bin').write_bytes(b'SECRET-A-' * 100)
        (folder / 'sub').mkdir()
        (folder / 'sub' / 'b.bin').write_bytes(b'SECRET-B-' * 100)
        link = self.tmp / 'sym'
        link.symlink_to(secret)
        img = self.tmp / 'disk.img'
        img.write_bytes(b'EXISTING-DATA-' * 2048)

        plan = changes.normalize({
            'name': 'real-del',
            'tasks': [
                {'host': os.uname().nodename, 'type': 'secure-delete', 'params': {'path': str(secret), 'method': 'random-zero', 'passes': '1', 'confirm': str(secret)}},
                {'host': os.uname().nodename, 'type': 'secure-delete', 'params': {'path': str(folder), 'method': 'zero', 'passes': '1', 'confirm': str(folder)}},
            ],
        })
        sh_text = changes.script(self.conn, plan)
        script_path = self.tmp / 'run.sh'
        script_path.write_text(sh_text)
        rep = subprocess.run(['bash', str(script_path)], capture_output=True, text=True)
        self.assertEqual(rep.returncode, 0, rep.stdout + rep.stderr)
        self.assertIn('would: securely delete', rep.stdout)
        self.assertTrue(secret.exists() and folder.exists())

        # Extract script helpers up to the first run() call, skipping the root/lock check for unprivileged temp tests
        head_only = sh_text.split('\nrun 1 ')[0]
        head_only = head_only.replace('if ((APPLY)) && [[ $EUID -ne 0 ]]', 'if false')
        head_only = head_only.replace('if ((APPLY)); then\n  exec 9>', 'if false; then\n  exec 9>')
        harness = f'''{head_only}
APPLY=1; DESTRUCTIVE=0; CUR_DESTRUCTIVE=1
t_secure_delete {str(secret)!r} random-zero 1
DESTRUCTIVE=1
t_secure_delete /etc random-zero 1
t_secure_delete {str(link)!r} random-zero 1
t_secure_delete {str(secret)!r} random-zero 1
t_secure_delete {str(folder)!r} zero 1
t_secure_delete {str(secret)!r} random-zero 1
wipe_dev {str(img)!r} zero 1
'''
        harness_path = self.tmp / 'harness.sh'
        harness_path.write_text(harness)
        res = subprocess.run(['bash', '-euo', 'pipefail', str(harness_path)], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertIn('destructive, skipped', res.stdout)
        self.assertIn('refusing to delete system path /etc', res.stdout)
        self.assertIn('is a symbolic link', res.stdout)
        self.assertIn('is deleted', res.stdout)
        self.assertFalse(secret.exists())
        self.assertFalse(folder.exists())
        self.assertEqual(img.read_bytes(), b'\x00' * len(b'EXISTING-DATA-' * 2048))


if __name__ == '__main__':
    unittest.main()
