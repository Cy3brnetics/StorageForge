"""Proxmox Datacenter Manager through its API (apipdm.py), read with the real client from a TLS server on 127.0.0.1 with recorded JSON.

Where the samples come from: the Datacenter Manager API viewer, pdm.proxmox.com/docs/api-viewer/apidoc.js, fetched 2026-11-20, which
gives fields and types (no whole example answers), so each sample is built from those:
    /remotes/remote                                   id, type (pve, pbs), nodes, authid, token ("The access token's secret."), web-url
    /resources/list                                   items {remote, error, resources}, each resource a oneOf by its "type" property:
                                                      pve-node, pve-qemu, pve-lxc, pve-storage, pve-network, pbs-node, pbs-datastore
    /pbs/remotes/{remote}/datastore/{d}/snapshots     as the Backup Server's own snapshot list
    /access/permissions                               the map of ACL path to privilege to propagate bit, paths /resource/{remote}..."""
import time

try:
    from test_apiconn import Base
    from test_apipve import pve_routes
except ImportError:      # run as tests.test_x from the project folder
    from tests.test_apiconn import Base
    from tests.test_apipve import pve_routes
from storageforge_index import apiconn, apipdm, apiread, apiviews, security
from storageforge_index.runtimes import guests as guest_parsers

GiB = 1 << 30
NOW = int(time.time())
TID = 'storageforge@pdm!storageforge'
REMOTE_SECRET = '9e8d7c6b-5a49-4382-a1b0-c9d8e7f6a5b4'
REMOTES = [{'id': 'pve-a', 'type': 'pve', 'nodes': [{'hostname': '10.0.0.11', 'fingerprint': 'AA:BB'}], 'authid': 'pdm-admin@pve!pdm', 'token': REMOTE_SECRET},
           {'id': 'pbs-b', 'type': 'pbs', 'nodes': ['10.0.0.20'], 'authid': 'pdm@pbs!pdm', 'token': REMOTE_SECRET, 'web-url': {'base-url': 'https://pbs.lab'}}]
RESOURCES = [
    {'remote': 'pve-a', 'resources': [
        {'type': 'pve-node', 'id': 'remote/pve-a/node/pve1', 'node': 'pve1', 'status': 'online', 'cpu': 0.1, 'maxcpu': 8, 'mem': GiB, 'maxmem': 32 * GiB, 'uptime': 99},
        {'type': 'pve-qemu', 'id': 'remote/pve-a/guest/100', 'vmid': 100, 'name': 'web', 'node': 'pve1', 'status': 'running', 'maxmem': 4 * GiB, 'maxcpu': 2, 'template': False, 'tags': ['prod']},
        {'type': 'pve-lxc', 'id': 'remote/pve-a/guest/101', 'vmid': 101, 'name': 'dns', 'node': 'pve1', 'status': 'stopped', 'maxmem': 512 << 20, 'template': False, 'tags': []},
        {'type': 'pve-storage', 'id': 'remote/pve-a/storage/pve1/local', 'storage': 'local', 'node': 'pve1', 'status': 'available', 'shared': False, 'disk': GiB, 'maxdisk': 100 * GiB},
        {'type': 'network', 'network_type': 'zone', 'id': 'remote/pve-a/sdn/x'}]},
    {'remote': 'pbs-b', 'resources': [
        {'type': 'pbs-node', 'id': 'remote/pbs-b/node/pbs', 'name': 'pbs', 'cpu': 0.01, 'maxcpu': 4, 'mem': GiB, 'maxmem': 8 * GiB, 'uptime': 9},
        {'type': 'pbs-datastore', 'id': 'remote/pbs-b/datastore/store1', 'name': 'store1', 'disk': 300 * GiB, 'maxdisk': 1000 * GiB, 'usage': 0.3, 'backend-type': 'filesystem'}]},
    {'remote': 'pve-down', 'error': 'connection refused', 'resources': []},
]
SNAPS = [{'backup-type': 'vm', 'backup-id': '100', 'backup-time': NOW - 3600, 'size': 9 * GiB, 'verification': {'state': 'failed', 'upid': 'UPID:pbs:0000A:0000B:00000000673C0000:verify:store1:root@pam:'}}]


def pdm_routes():
    return {'/version': {'version': '1.1.10', 'release': '1', 'repoid': 'aabbccdd'}, '/remotes/remote': REMOTES, '/resources/list': RESOURCES,
            '/pbs/remotes/pbs-b/datastore/store1/snapshots': SNAPS,
            '/access/permissions': {'/resource/pve-a': {'Resource.Audit': True}, '/resource/pbs-b': {'Resource.Audit': True}},
            '/access/users/storageforge@pdm/token/storageforge': {'tokenid': TID, 'enable': True, 'expire': NOW + 86400 * 100}}


class Read(Base):
    def setUp(self):
        super().setUp()
        self.fake.routes.update(pdm_routes())
        row = apiconn.add(self.v, self.conn, 'pdm', 'fleet', self.fake.url, TID, '0f1e2d3c-4b5a-4968-8776-a5b4c3d2e1f0', 'gabe')
        self.row = apiconn.pin(self.conn, row['conn_id'], self.fake.fingerprint, 'gabe')

    def test_remotes_and_their_resources_and_no_remote_token_is_kept(self):
        got = apiread.read(self.db, self.conn, self.row)
        self.assertEqual(got['readback']['verdict'], 'exact')
        self.assertEqual(got['counts'], {'platform': 1, 'remote': 2, 'node': 2, 'guest': 2, 'storage': 1, 'datastore': 1, 'snapshot': 1})
        self.assertEqual(got['skipped'], ['pve-down: PDM could not read it: connection refused'])
        remotes = {o['ref']: o for o in apiread.objects(self.conn, self.row['conn_id'], 'remote')}
        self.assertEqual((remotes['pve-a']['nodes'], remotes['pbs-b']['nodes']), (['10.0.0.11'], ['10.0.0.20']))
        self.assertEqual(self.everywhere(REMOTE_SECRET), [], "a remote's own token, which PDM lists, is never stored")
        self.assertIn('api-backup-verify:fleet', apiread.problems(self.conn))
        self.assertEqual(self.fake.requests[0]['headers']['Authorization'].split('=')[0], 'PDMAPIToken')

    def test_an_administrator_token_is_a_critical_finding(self):
        self.fake.routes['/access/permissions'] = {'/': {'Resource.Audit': True, 'Resource.Manage': True, 'Resource.Modify': True, 'Resource.Migrate': True,
                                                         'Access.Modify': True, 'System.Modify': True, 'Realm.Allocate': True}}
        apiread.read(self.db, self.conn, self.row)
        self.assertEqual(apiconn.problems(self.conn)['security-api-token:fleet'][4], 'crit')

    def test_its_guests_are_compared_with_the_scan_and_a_direct_connection_wins(self):
        self.conn.execute("INSERT INTO hosts (hostname, ssh_host, ssh_user, inventory_json) VALUES ('pve1', 'pve1.lab', 'scan', '{}')")
        ssh = guest_parsers.parse_proxmox(['g\tqemu\t100\tweb\trunning', 'g\tlxc\t101\tdns\tstopped'])
        security._save_measurement(self.conn, 'pve1', 'infra', NOW, 'test', {'proxmox': ssh, 'libvirt': [], 'incus': [], 'lxc': [], 'podman_rootless': []})
        apiread.read(self.db, self.conn, self.row)
        (c,) = apiviews.compare(self.conn)
        self.assertEqual([(g['vmid'], g['seen_by'], g['connection']) for g in c['guests']], [('100', ['api', 'ssh'], 'fleet'), ('101', ['api', 'ssh'], 'fleet')])
        # the same cluster connected directly as well: its reading is the one compared, and each guest is listed once
        self.fake.routes.update({k: v for k, v in pve_routes().items() if k not in ('/access/permissions', '/version')})
        self.fake.routes['/access/permissions'] = {'/': {'VM.Audit': 1, 'Sys.Audit': 1, 'Datastore.Audit': 1}}
        row = apiconn.add(self.v, self.conn, 'pve', 'cluster', self.fake.url, 'storageforge@pve!storageforge', '3f1c9a52-7d0e-4b8f-9a61-2c5e8d4b7a10', 'gabe')
        row = apiconn.pin(self.conn, row['conn_id'], self.fake.fingerprint, 'gabe')
        apiread.read(self.db, self.conn, row)
        (c,) = apiviews.compare(self.conn)
        self.assertEqual({g['vmid']: g.get('connection') for g in c['guests']}, {'100': 'cluster', '101': 'cluster'})
        listing = apiviews.annotate_workloads(self.conn, {'workloads': []})
        names = [w['name'] for w in listing['workloads']]
        self.assertEqual(sorted(names), sorted(set(names)), 'a guest seen twice is listed once')

    def test_answers_that_are_not_what_the_viewer_says(self):
        for bad in ('', '{"data": [{"remote": "x", "resources": [null, {"type": "pve-qemu", "vmid": "abc"}]}]}', '{"data": {"remote": 1}}'):
            self.assertIsInstance(apipdm.parse_resources(bad)['guests'], list)
        self.assertEqual(apipdm.parse_remotes('{"data": [{"id": "x", "type": "esxi"}]}')['remotes'], [])


if __name__ == '__main__':
    import unittest
    unittest.main()
