"""Placement advice (placement.py): from what the index holds of a host, its disks, pools, ZFS properties and what protects a path, the
advice a plan check gives before a workload's data goes somewhere, and the API that gives it to a deploy form."""
import json
import shutil
import tempfile
import time
import unittest
from pathlib import Path

try:
    import dbfactory
except ImportError:      # run as tests.test_x from the project folder
    from tests import dbfactory
from storageforge_index import changes, placement
from storageforge_index.moves import find_host, hosts

LSBLK = {'blockdevices': [
    {'name': 'nvme0n1', 'type': 'disk', 'tran': 'nvme', 'rota': False, 'size': 512 * 2**30, 'children': [
        {'name': 'nvme0n1p1', 'type': 'part', 'fstype': 'ext4', 'mountpoint': '/', 'size': 200 * 2**30, 'start': 2048},
        {'name': 'nvme0n1p2', 'type': 'part', 'fstype': 'btrfs', 'mountpoint': '/data', 'size': 300 * 2**30, 'start': 4096}]},
    *[{'name': f'sd{x}', 'type': 'disk', 'tran': 'sata', 'rota': True, 'size': 4 * 2**40, 'children': [
        {'name': f'sd{x}1', 'type': 'part', 'fstype': 'zfs_member', 'label': 'tank', 'size': 4 * 2**40, 'start': 2048}]} for x in 'abc']]}


class Placement(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.db = dbfactory.make(self, Path(self.tmp) / 'index.db')
        self.conn = self.db.connect()
        self.db.migrate(self.conn)
        self.addCleanup(self.conn.close)
        inv = {'lsblk': LSBLK, 'zfs_props': 'tank/vm\trecordsize\t64K\ntank/media\trecordsize\t1M\ntank/db\trecordsize\t16K'}
        self.conn.execute("INSERT INTO hosts (hostname, ssh_host, ssh_user, inventory_json) VALUES ('nas', 'nas', 'scan', :i)", {'i': json.dumps(inv)})
        hid = self.conn.scalar("SELECT host_id FROM hosts WHERE hostname = 'nas'")
        for point, src, fs, opts in (('/', '/dev/nvme0n1p1', 'ext4', 'rw'), ('/data', '/dev/nvme0n1p2', 'btrfs', 'rw,noatime'), ('/tank', 'tank', 'zfs', 'rw'),
                                     ('/tank/vm', 'tank/vm', 'zfs', 'rw'), ('/tank/media', 'tank/media', 'zfs', 'rw'), ('/tank/db', 'tank/db', 'zfs', 'rw'),
                                     ('/mnt/nas', 'files:/export', 'nfs4', 'rw')):
            self.conn.execute("""INSERT INTO mounts (host_id, mount_point, source, filesystem_type, total_bytes, used_bytes, scan_state, mount_options)
                                 VALUES (:h, :p, :s, :f, :t, :u, 'indexed', :o)""", {'h': hid, 'p': point, 's': src, 'f': fs, 't': 2**40, 'u': 2**38, 'o': opts})

    def advise(self, path, use):
        h = find_host(hosts(self.conn), 'nas')
        return placement.advise(self.conn, changes.Host(self.conn, h), h, path, use)

    def test_vm_images_want_a_dataset_tuned_for_them(self):
        self.assertIn(('ok', 'tank/vm has recordsize=64K, which suits it'), self.advise('/tank/vm/images', 'vm'))
        got = self.advise('/tank/media/vms', 'vm')
        self.assertTrue(any(l == 'note' and 'recordsize=1M: 64K suits it better' in t for l, t in got), got)
        got = self.advise('/tank/other', 'vm')                          # no recordsize of its own or above it: the default
        self.assertTrue(any('recordsize=128K (the default): 64K suits it better' in t for _, t in got), got)
        got = self.advise('/data/vms', 'vm')
        self.assertTrue(any('btrfs with copy-on-write: VM images fragment' in t for _, t in got), got)

    def test_databases_are_kept_off_the_bulk_pool(self):
        got = self.advise('/tank/db/pg', 'database')
        self.assertTrue(any(l == 'warn' and 'a database on the bulk pool' in t and 'tank is on spinning disks' in t for l, t in got), got)
        self.assertIn(('ok', 'tank/db has recordsize=16K, which suits it'), got)
        self.assertFalse([t for _, t in self.advise('/var/lib/pg', 'database') if 'bulk pool' in t])     # the NVMe root
        self.assertFalse([t for _, t in self.advise('/tank/db/pg', 'data') if 'bulk pool' in t])         # only databases

    def test_bind_mounts_on_network_filesystems(self):
        got = self.advise('/mnt/nas/pg', 'database')
        self.assertTrue(any(l == 'warn' and 'network filesystem (nfs4 at /mnt/nas)' in t and 'corrupts or stalls' in t for l, t in got), got)
        got = self.advise('/mnt/nas/media', 'data')
        self.assertTrue(any('file locks on it are not reliable' in t for _, t in got))

    def test_data_no_hold_or_offsite_copy_reaches(self):
        self.assertTrue(any(l == 'warn' and 'no hold or offsite copy reaches /tank/db/pg' in t for l, t in self.advise('/tank/db/pg', 'data')))
        inv = self.conn.scalar("SELECT inventory_json FROM hosts WHERE hostname = 'nas'")
        inv = inv if isinstance(inv, dict) else json.loads(inv)      # PostgreSQL gives JSON back as a dict
        inv['snapshots'] = {'zfs': {'tank/db': {'count': 12, 'newest': int(time.time())}}}
        self.conn.execute("UPDATE hosts SET inventory_json = :i WHERE hostname = 'nas'", {'i': json.dumps(inv)})
        got = self.advise('/tank/db/pg', 'data')
        self.assertTrue(any(l == 'note' and 'is snapshotted (detected 12 ZFS snapshots), but no copy of it leaves nas' in t for l, t in got), got)
        self.assertFalse([t for _, t in got if 'no hold or offsite' in t])

    def test_a_stack_check_carries_the_advice_for_each_service(self):
        compose = 'services:\n  db:\n    image: postgres:16\n    volumes: ["/tank/db/pg:/var/lib/postgresql/data", "/mnt/nas/x:/x"]\n  web:\n    image: nginx:1.27\n'
        plan = {'name': 'p', 'tasks': [{'type': 'stack', 'host': 'nas', 'params': {'runtime': 'docker', 'name': 'app', 'compose': compose}}]}
        items = [(it['level'], it['text']) for it in changes.check(self.conn, changes.normalize(plan))['tasks'][0]['items']]
        self.assertTrue(any('a database on the bulk pool: db (/tank/db/pg)' in t for _, t in items), items)
        self.assertTrue(any('db (/mnt/nas/x) is on a network filesystem' in t for _, t in items), items)

    def test_the_api(self):
        from storageforge_index import server, users
        users.create(self.conn, 'root', 'a long enough password', 'admin')
        web = server.create_app(server.App(self.db), 's' * 48)
        c = web.test_client()
        self.assertEqual(c.post('/api/login', json={'username': 'root', 'password': 'a long enough password'}).status_code, 200)
        got = c.get('/api/workloads/placement?host=nas&path=/tank/db/pg&use=database').get_json()
        self.assertEqual(got['host'], 'nas')
        self.assertTrue(any('bulk pool' in a['text'] for a in got['advice']))
        self.assertEqual(c.get('/api/workloads/placement?host=nope&path=/x').status_code, 404)
        self.assertEqual(c.get('/api/workloads/placement?host=nas&path=/x&use=bogus').status_code, 400)


if __name__ == '__main__':
    unittest.main()
