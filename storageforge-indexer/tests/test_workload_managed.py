"""Workloads something else manages (wlmanaged.py): told by labels, units, Proxmox, libvirt metadata and a panel with the engine socket,
and the warning a plan check gives before a step changes one."""
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
from storageforge_index import changes, inframeasure, security, wlmanaged, workloads
from storageforge_index.runtimes import guests


def c(name, image='nginx:1.27', **labels):
    return {'id': name, 'name': name, 'image': image, 'state': 'running', 'labels': labels, 'mounts': [], 'detail': True}


class Tell(unittest.TestCase):
    def test_labels_units_and_compose_folders(self):
        w = lambda **kw: {'name': 'x', 'labels': kw}       # noqa: E731
        self.assertEqual(wlmanaged.of_container(w(**{'komodo.stack': 'a'}), set())['by'], 'Komodo')
        self.assertEqual(wlmanaged.of_container(w(**{'app.kubernetes.io/managed-by': 'terraform'}), set())['by'], 'terraform')
        self.assertEqual(wlmanaged.of_container(w(PODMAN_SYSTEMD_UNIT='x.service'), set())['by'], 'systemd')
        self.assertEqual(wlmanaged.of_container({'name': 'web', 'labels': {}}, {'container-web.service'})['how'], 'the unit container-web.service runs it')
        got = wlmanaged.of_container(w(**{'com.docker.compose.project': 'p', 'com.docker.compose.project.working_dir': '/data/compose/3'}), set())
        self.assertEqual((got['by'], got['level']), ('Portainer', 'warn'))
        got = wlmanaged.of_container(w(**{'com.docker.compose.project': 'p', 'com.docker.compose.project.working_dir': '/srv/p'}), set())
        self.assertEqual((got['by'], got['level']), ('compose', 'note'))
        self.assertEqual(wlmanaged.of_container(w(**{'storageforge.managed': 'true'}), set())['level'], 'ok')
        self.assertIsNone(wlmanaged.of_container(w(), set()))

    def test_libvirt_metadata(self):
        dom = guests.parse_domain('<domain><name>a</name><metadata><o:vm xmlns:o="http://ovirt.org/vm/1.0"/>'
                                  '<l:libosinfo xmlns:l="http://libosinfo.org/xmlns/libvirt/domain/1.0"/></metadata></domain>')
        self.assertEqual(wlmanaged.of_vm(dom)['by'], 'oVirt')
        self.assertIsNone(wlmanaged.of_vm(guests.parse_domain('<domain><name>a</name></domain>')))
        other = wlmanaged.of_vm({'metadata_ns': ['https://example.org/mine']})
        self.assertEqual(other['by'], 'another tool')

    def test_the_units_section_is_read(self):
        got = inframeasure.parse('@@wl_units\ncontainer-web.service\npuppet.service\nmarker:pve\nnot a unit\n@@end\n')['wl_units']
        self.assertEqual(got, {'units': ['container-web.service', 'puppet.service'], 'markers': ['pve']})


class Listing(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.db = dbfactory.make(self, Path(self.tmp) / 'index.db')
        self.conn = self.db.connect()
        self.db.migrate(self.conn)
        self.addCleanup(self.conn.close)
        self.conn.execute("INSERT INTO hosts (hostname, ssh_host, ssh_user, inventory_json) VALUES ('nas', 'nas', 'scan', '{}')")
        hid = self.conn.scalar("SELECT host_id FROM hosts WHERE hostname = 'nas'")
        panel = dict(c('portainer', 'portainer/portainer-ce:2'), mounts=[{'type': 'bind', 'source': '/var/run/docker.sock', 'dest': '/var/run/docker.sock', 'rw': True}])
        cs = [panel, c('loose'), c('komodo-app', **{'komodo.stack': 'app'}), c('mine', **{'storageforge.managed': 'true', 'com.docker.compose.project': 'mine'})]
        self.conn.execute("INSERT INTO docker_hosts (host_id, engine, access, root_dir, containers_json, volumes_json, compose_json, scan_id, updated_at) "
                          "VALUES (:h, 'docker', 'direct', '/var/lib/docker', :c, '[]', '[]', NULL, 1)", {'h': hid, 'c': json.dumps(cs)})
        security._save_measurement(self.conn, 'nas', 'infra', int(time.time()), 'test',
                                   {'tools': ['virsh', 'lxc-ls', 'pct'], 'libvirt': [{'name': 'ov', 'state': 'running', 'metadata_ns': ['http://ovirt.org/vm/1.0']}],
                                    'lxc': [{'name': '101', 'state': 'running'}], 'wl_units': {'units': ['salt-minion.service'], 'markers': []}})

    def by_name(self):
        return {w['name']: w for w in workloads.listing(self.conn, 'nas')['workloads']}

    def test_what_the_listing_says(self):
        ws = self.by_name()
        self.assertEqual(ws['komodo-app']['managed']['by'], 'Komodo')
        self.assertIn('managed by Komodo: it carries Komodo labels', ws['komodo-app']['findings'])
        self.assertEqual(ws['loose']['managed']['by'], 'possibly Portainer')      # the panel has the socket
        self.assertEqual(ws['mine']['managed']['by'], 'Salt')                       # ours, but a config agent runs on the host
        self.assertEqual(ws['ov']['managed']['by'], 'oVirt')
        self.assertEqual(ws['101']['managed']['by'], 'Proxmox VE')

    def test_a_step_warns_before_it_changes_one(self):
        def items(kind, **p):
            plan = {'name': 'x', 'tasks': [{'type': kind, 'host': 'nas', 'params': p}]}
            return [(it['level'], it['text']) for it in changes.check(self.conn, changes.normalize(plan))['tasks'][0]['items']]
        got = items('workload-remove', runtime='docker', name='komodo-app')
        self.assertTrue(any(l == 'warn' and 'komodo-app is managed by Komodo' in t and 'Change it there, or adopt it first' in t for l, t in got), got)
        got = items('vm-snapshot', name='ov', action='create', snapshot='s1')
        self.assertTrue(any('ov is managed by oVirt' in t for _, t in got), got)
        self.assertFalse([t for _, t in items('workload-action', runtime='docker', name='nothing', action='start') if 'managed by' in t])


if __name__ == '__main__':
    unittest.main()
