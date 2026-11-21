"""Proxmox VE through its API (apipve.py), read with the real client from a TLS server on 127.0.0.1 that answers with recorded JSON.

Where the samples come from: the Proxmox VE API viewer, pve-docs/api-viewer/apidoc.js, fetched 2026-11-20. The documentation gives
each answer's fields with their types, not whole example answers, so each sample below is built from those fields alone, with the
names and types the viewer gives:
    /version                                       version, release, repoid
    /cluster/resources                             items with type (node, storage, qemu, lxc...), id, node, status, vmid, name, maxmem,
                                                   maxcpu, maxdisk, disk, content, plugintype, shared, pool, template...
    /cluster/backup                                items with id, enabled, schedule, storage, vmid, all, exclude, mode, next-run
    /nodes/{node}/storage/{storage}/content        items with volid, vmid, ctime, size, format, protected, verification {state, upid}
The SSH side of the comparison is the scan's own parser (runtimes/guests.parse_proxmox) on lines in the form the scan script prints."""
import time

try:
    from test_apiconn import TOKEN, Base
    from test_apireadback import PVE_AUDITOR, TOKEN_INFO
except ImportError:      # run as tests.test_x from the project folder
    from tests.test_apiconn import TOKEN, Base
    from tests.test_apireadback import PVE_AUDITOR, TOKEN_INFO
from storageforge_index import apipve, apiread, apiviews, security, server, users
from storageforge_index.runtimes import guests as guest_parsers

GiB = 1 << 30
RESOURCES = [
    {'id': 'node/pve1', 'type': 'node', 'node': 'pve1', 'status': 'online', 'cpu': 0.04, 'maxcpu': 8, 'mem': 6 * GiB, 'maxmem': 32 * GiB, 'uptime': 86400, 'level': ''},
    {'id': 'node/pve2', 'type': 'node', 'node': 'pve2', 'status': 'online', 'cpu': 0.10, 'maxcpu': 8, 'mem': 4 * GiB, 'maxmem': 32 * GiB, 'uptime': 3600, 'level': ''},
    {'id': 'qemu/100', 'type': 'qemu', 'vmid': 100, 'name': 'web', 'node': 'pve1', 'status': 'running', 'maxmem': 4 * GiB, 'maxcpu': 2, 'maxdisk': 32 * GiB, 'template': 0, 'uptime': 500},
    {'id': 'lxc/101', 'type': 'lxc', 'vmid': 101, 'name': 'dns', 'node': 'pve1', 'status': 'running', 'maxmem': 512 << 20, 'maxcpu': 1, 'maxdisk': 8 * GiB, 'template': 0},
    {'id': 'qemu/200', 'type': 'qemu', 'vmid': 200, 'name': 'db', 'node': 'pve2', 'status': 'stopped', 'maxmem': 8 * GiB, 'maxcpu': 4, 'pool': 'prod', 'template': 0},
    {'id': 'qemu/9000', 'type': 'qemu', 'vmid': 9000, 'name': 'debian-tpl', 'node': 'pve2', 'status': 'stopped', 'template': 1},
    {'id': 'storage/pve1/local', 'type': 'storage', 'storage': 'local', 'node': 'pve1', 'status': 'available', 'plugintype': 'dir', 'content': 'iso,vztmpl,backup', 'shared': 0, 'disk': 10 * GiB, 'maxdisk': 100 * GiB},
    {'id': 'storage/pve1/local-lvm', 'type': 'storage', 'storage': 'local-lvm', 'node': 'pve1', 'status': 'available', 'plugintype': 'lvmthin', 'content': 'images,rootdir', 'shared': 0, 'disk': 95 * GiB, 'maxdisk': 100 * GiB},
    {'id': 'storage/pve1/pbs-store', 'type': 'storage', 'storage': 'pbs-store', 'node': 'pve1', 'status': 'available', 'plugintype': 'pbs', 'content': 'backup', 'shared': 1, 'disk': 200 * GiB, 'maxdisk': 1000 * GiB},
    {'id': 'storage/pve2/pbs-store', 'type': 'storage', 'storage': 'pbs-store', 'node': 'pve2', 'status': 'available', 'plugintype': 'pbs', 'content': 'backup', 'shared': 1, 'disk': 200 * GiB, 'maxdisk': 1000 * GiB},
    {'id': 'sdn/pve1/localnetwork', 'type': 'sdn', 'sdn': 'localnetwork', 'node': 'pve1', 'status': 'ok'},
    {'type': 'qemu', 'name': 'no vmid'},
]
JOBS = [{'id': 'backup-0c1a2b3c-4d5e', 'enabled': 1, 'schedule': 'daily 02:00', 'storage': 'pbs-store', 'vmid': '100,101', 'mode': 'snapshot', 'next-run': 1795000000},
        {'id': 'backup-old', 'enabled': 0, 'schedule': 'sun 03:00', 'storage': 'local', 'all': 1}]
NOW = int(time.time())
PBS_BACKUPS = [
    {'volid': 'pbs-store:backup/vm/100/2026-11-19T02:00:00Z', 'vmid': 100, 'ctime': NOW - 86400, 'size': 12 * GiB, 'format': 'pbs-vm', 'protected': 0, 'verification': {'state': 'ok', 'upid': 'UPID:pbs:00001234:00005678:673C0000:verify:x:root@pam:'}},
    {'volid': 'pbs-store:backup/ct/101/2026-11-19T02:05:00Z', 'vmid': 101, 'ctime': NOW - 86000, 'size': GiB, 'format': 'pbs-ct', 'verification': {'state': 'failed', 'upid': 'UPID:pbs:00001235:00005679:673C0001:verify:y:root@pam:'}},
    {'volid': 'pbs-store:backup/vm/100/2026-11-20T02:00:00Z', 'vmid': 100, 'ctime': NOW - 600, 'size': 12 * GiB, 'format': 'pbs-vm'},
]
LOCAL_BACKUPS = [{'volid': 'local:backup/vzdump-qemu-200-2026_11_01-03_00_00.vma.zst', 'vmid': 200, 'ctime': NOW - 19 * 86400, 'size': 3 * GiB, 'format': 'vma.zst', 'protected': 1}]
SSH_LINES = ['g\tqemu\t100\tweb\trunning', 'c\tmemory: 4096', 'c\tcores: 2', 'g\tlxc\t101\tdns\tstopped', 'c\tmemory: 512', 'g\tqemu\t102\told\trunning']
PW = 'a long enough password'


def pve_routes():
    return {'/version': {'version': '9.1.2', 'release': '9.1', 'repoid': 'abcdef12'}, '/cluster/resources': RESOURCES, '/cluster/backup': JOBS,
            '/nodes/pve1/storage/pbs-store/content': PBS_BACKUPS, '/nodes/pve2/storage/pbs-store/content': PBS_BACKUPS,
            '/nodes/pve1/storage/local/content': LOCAL_BACKUPS, '/access/permissions': {'/': PVE_AUDITOR},
            '/access/users/storageforge@pve/token/storageforge': TOKEN_INFO}


class Parse(Base):
    def test_resources_jobs_and_backups(self):
        import json
        res = apipve.parse_resources(json.dumps({'data': RESOURCES}))
        self.assertEqual(([n['node'] for n in res['nodes']], [g['vmid'] for g in res['guests']], res['dropped']), (['pve1', 'pve2'], [100, 101, 200, 9000], 1))
        self.assertEqual(res['storage'][0]['content'], ['iso', 'vztmpl', 'backup'])
        jobs = apipve.parse_backup_jobs(json.dumps({'data': JOBS}))['jobs']
        self.assertEqual((jobs[0]['vmid'], jobs[0]['enabled'], jobs[1]['enabled'], jobs[1]['all']), (['100', '101'], True, False, True))
        b = apipve.parse_backups(json.dumps({'data': PBS_BACKUPS}))['backups']
        self.assertEqual([x['verify'] for x in b], ['ok', 'failed', None])
        for bad in ('', '{"data": {"a": 1}}', '{"data": [null, 5, {"type": "node", "node": ["x"]}]}', '[]'):
            self.assertEqual(apipve.parse_resources(bad)['nodes'], [])
            self.assertEqual(apipve.parse_backups(bad)['backups'], [])


class Read(Base):
    def setUp(self):
        super().setUp()
        self.fake.routes.update(pve_routes())
        self.row = self.pinned('cluster')

    def test_nodes_guests_storage_jobs_and_backups_are_read_and_a_shared_storage_once(self):
        got = apiread.read(self.db, self.conn, self.row)
        self.assertEqual(got['counts'], {'platform': 1, 'node': 2, 'guest': 4, 'storage': 4, 'backup-job': 2, 'backup': 4})
        self.assertEqual(got['skipped'], [])
        paths = [r['path'] for r in self.fake.requests]
        self.assertEqual(sum('/storage/pbs-store/content' in p for p in paths), 1, 'a shared storage is read once')
        self.assertIn('/api2/json/nodes/pve1/storage/local/content?content=backup', paths)
        self.assertFalse([p for p in paths if 'local-lvm' in p], 'a storage that holds no backups is not asked for them')
        self.assertTrue(all(r['method'] == 'GET' for r in self.fake.requests))
        found = apiread.problems(self.conn)
        self.assertIn('pbs-store:backup/ct/101', found['api-backup-verify:cluster'][3])
        self.assertIn('api-storage-full:cluster:pve1/local-lvm', found)
        unbacked = found['api-guest-unbacked:cluster']
        self.assertEqual((unbacked[3], unbacked[4]), ('200 db', 'info'))
        self.no_token_anywhere()

    def test_a_token_without_sys_audit_on_the_root_skips_the_jobs_and_says_so(self):
        self.fake.routes['/access/permissions'] = {'/vms': {'VM.Audit': 1}, '/storage': {'Datastore.Audit': 1}, '/nodes': {'Sys.Audit': 1}}
        got = apiread.read(self.db, self.conn, self.row)
        self.assertNotIn('backup-job', got['counts'])
        self.assertEqual(got['skipped'], ['backup jobs: the token lacks Sys.Audit on /'])
        self.assertFalse([r for r in self.fake.requests if r['path'].startswith('/api2/json/cluster/backup')])

    def test_compared_with_the_ssh_scan_not_merged(self):
        self.conn.execute("INSERT INTO hosts (hostname, ssh_host, ssh_user, inventory_json) VALUES ('pve1', 'pve1.lab', 'scan', '{}')")
        ssh = guest_parsers.parse_proxmox(SSH_LINES)
        security._save_measurement(self.conn, 'pve1', 'infra', NOW, 'test', {'proxmox': ssh, 'libvirt': [], 'incus': [], 'lxc': [], 'podman_rootless': []})
        apiread.read(self.db, self.conn, self.row)
        (c,) = apiviews.compare(self.conn)
        rows = {g['vmid']: g for g in c['guests']}
        self.assertEqual((c['host'], sorted(rows)), ('pve1', ['100', '101', '102']))
        self.assertEqual((rows['100']['seen_by'], rows['100']['differs']), (['api', 'ssh'], []))
        self.assertEqual(rows['101']['differs'], [{'field': 'state', 'api': 'running', 'ssh': 'stopped'}])
        self.assertEqual(rows['102']['seen_by'], ['ssh'])
        listing = apiviews.annotate_workloads(self.conn, {'workloads': [{'host': 'pve1', 'runtime': 'proxmox', 'name': 'dns', 'vmid': '101', 'state': 'stopped'}]})
        dns = listing['workloads'][0]
        self.assertEqual((dns['state'], dns['api']['status'], dns['api']['differs'][0]['field']), ('stopped', 'running', 'state'), 'the scan keeps its own state')
        added = {w['name']: w for w in listing['workloads'] if w.get('source') == 'api'}
        self.assertEqual(sorted(added), ['db', 'debian-tpl', 'web'])
        self.assertEqual((added['db']['host'], added['web']['host']), ('pve2', 'pve1'))

    def test_drawn_on_the_map_and_listed_in_workloads(self):
        self.conn.execute("INSERT INTO hosts (hostname, ssh_host, ssh_user, inventory_json) VALUES ('pve1', 'pve1.lab', 'scan', '{}')")
        self.conn.execute("INSERT INTO graph_nodes (node_id, kind, label, host, props_json, updated_at, layer, confidence, first_seen) VALUES ('host:pve1', 'Host', 'pve1', 'pve1', '{}', 1, 'storage', 'certain', 1)")
        apiread.read(self.db, self.conn, self.row)
        users.create(self.conn, 'admin', PW, 'admin')
        c = server.create_app(server.App(self.db), 's' * 48).test_client()
        c.post('/api/login', json={'username': 'admin', 'password': PW})
        g = c.get('/api/map').get_json()
        nodes = {n['id']: n for n in g['nodes']}
        web = nodes['api:cluster:guest::100']
        self.assertEqual((web['kind'], web['host'], web['props']['source']), ('VM', 'pve1', 'api'))
        self.assertEqual(nodes['api:cluster:guest::101']['kind'], 'Instance')
        self.assertIn({'src': 'api:cluster:guest::100', 'dst': 'host:pve1', 'rel': 'RUNS_ON'}, [{k: e[k] for k in ('src', 'dst', 'rel')} for e in g['edges']])
        self.assertIn('api:cluster:storage:pve1/pbs-store', nodes)
        self.assertEqual(nodes['api:cluster:guest::200']['host'], None)       # pve2 is not a scanned host: it hangs from the platform
        w = c.get('/api/workloads').get_json()
        self.assertEqual(sorted(x['name'] for x in w['workloads'] if x.get('source') == 'api'), ['db', 'debian-tpl', 'dns', 'web'])
        self.assertNotIn(TOKEN, c.get('/api/keys/platforms').get_data(as_text=True))


if __name__ == '__main__':
    import unittest
    unittest.main()
