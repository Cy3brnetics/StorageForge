"""The read side of workloads (wlread.py, wlcapture.py): Podman Quadlet units read and tied to their containers, adopting a workload by
capturing it as compose, a Quadlet unit, libvirt XML or Incus YAML, and drift against the capture. The compose capture is checked by the
real docker compose, and the libvirt one by the real virt-xml-validate; a container started by the real Docker is scanned and captured."""
import base64
import json
import os
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

import yaml

try:
    import dbfactory
except ImportError:      # run as tests.test_x from the project folder
    from tests import dbfactory
from storageforge_index import inframeasure, security, wlcapture, wlread, workloads
from storageforge_index.runtimes import docker


def b64(s):
    return base64.b64encode(s.encode()).decode()


CONTAINER = {'id': 'abc123', 'name': 'wiki', 'image': 'docker.io/library/nginx:1.27', 'state': 'running', 'restart': 'unless-stopped',
             'labels': {'com.docker.compose.project': 'x', 'team': 'web'}, 'mounts': [{'type': 'bind', 'source': '/srv/wiki', 'dest': '/usr/share/nginx/html', 'name': None, 'rw': False},
                                                                                       {'type': 'volume', 'source': '/var/lib/docker/volumes/wikidata/_data', 'dest': '/data', 'name': 'wikidata', 'rw': True}],
             'detail': True, 'digests': ['nginx@sha256:aaa'], 'privileged': False, 'network_mode': 'bridge', 'cap_add': ['NET_BIND_SERVICE'], 'cap_drop': [], 'security_opt': [],
             'readonly_root': False, 'ports': [{'host_ip': '127.0.0.1', 'host_port': 8080, 'port': 80, 'proto': 'tcp'}, {'host_ip': '0.0.0.0', 'host_port': 5353, 'port': 53, 'proto': 'udp'}],
             'networks': [{'name': 'bridge'}, {'name': 'front'}], 'health': None}
DOMAIN = {'name': 'web-01', 'state': 'running', 'vcpus': '2', 'memory_mib': 2048, 'firmware': 'uefi', 'tpm': True, 'machine': 'pc-q35-9.2', 'cpu_mode': 'host-passthrough',
          'agent': 'connected', 'serial': True, 'disks': [{'target': 'vda', 'device': 'disk', 'bus': 'virtio', 'format': 'qcow2', 'source': '/var/lib/libvirt/images/web-01.qcow2'},
                                                         {'target': 'sda', 'device': 'cdrom', 'bus': 'sata', 'format': 'raw', 'source': '/iso/x.iso', 'readonly': True}],
          'nics': [{'type': 'network', 'source': 'default', 'mac': '52:54:00:aa:bb:cc', 'model': 'virtio'}, {'type': 'bridge', 'source': 'br0', 'mac': '52:54:00:aa:bb:cd', 'model': 'virtio'}],
          'graphics': [{'type': 'spice', 'listen': '0.0.0.0'}], 'seclabel': {'type': 'dynamic'}}


class Quadlets(unittest.TestCase):
    def test_units_are_read_and_tied_to_their_containers(self):
        lines = [f'f\troot\t{b64("/etc/containers/systemd/wiki.container")}', 's\t[Container]', 'k\tImage\tdocker.io/library/nginx:1.27', 'k\tPublishPort\t8080:80',
                 'k\tLabel\tteam=web tier=front', 'k\tAutoUpdate\tregistry', f'f\talice\t{b64("/home/alice/.config/containers/systemd/db.container")}', 'k\tContainerName\tpg',
                 f'f\troot\t{b64("/etc/containers/systemd/data.volume")}', f'f\troot\t{b64("relative.container")}', 'k\tImage\tignored', 'junk line']
        q = wlread.quadlets(lines)
        self.assertEqual([(x['name'], x['unit'], x['user']) for x in q], [('wiki', 'wiki.service', 'root'), ('db', 'db.service', 'alice'), ('data', 'data-volume.service', 'root')])
        self.assertEqual((q[0]['image'], q[0]['publish'], q[0]['labels'], q[0]['auto_update']), ('docker.io/library/nginx:1.27', ['8080:80'], {'team': 'web', 'tier': 'front'}, 'registry'))
        ws = [{'host': 'h', 'runtime': 'podman', 'kind': 'container', 'name': 'systemd-wiki', 'labels': {'PODMAN_SYSTEMD_UNIT': 'wiki.service'}}]
        wlread.with_quadlets(ws, 'h', q)
        self.assertEqual(ws[0]['quadlet'], '/etc/containers/systemd/wiki.container')
        self.assertEqual([(w['name'], w['state'], w['user']) for w in ws[1:]], [('pg', 'defined', 'alice')])     # no container runs it
        s = inframeasure.script()
        self.assertIn('sec quadlet', s)
        self.assertNotIn('Environment', s.split('sec quadlet')[1].split('sec end')[0].replace('Never Environment', ''))
        self.assertEqual(inframeasure.parse('@@quadlet\n' + '\n'.join(lines) + '\n@@end\n')['quadlets'][0]['name'], 'wiki')

    @unittest.skipUnless(shutil.which('awk') and shutil.which('find'), 'needs awk and find')
    def test_the_reading_prints_only_the_keys_that_say_what_runs(self):
        d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d)
        (d / 'app.container').write_text('[Container]\nImage = nginx:1.27\nEnvironment=DB_PASSWORD=hunter2\nSecret=dbpass\nExec=--token=s3cret\nPublishPort=8080:80\n')
        body = wlread.BODY.split('sec quadlet\n')[1].split('for d in /etc')[0]
        out = subprocess.run(['bash', '-c', body + f'\nqfiles root {d}'], capture_output=True, text=True).stdout
        self.assertNotIn('hunter2', out)
        self.assertNotIn('s3cret', out)
        q = wlread.quadlets(out.splitlines())
        self.assertEqual((q[0]['image'], q[0]['publish']), ('nginx:1.27', ['8080:80']))


class Render(unittest.TestCase):
    def container(self):
        w = workloads._container('nas', 'docker', dict(CONTAINER), [], [{'name': 'wikidata', 'mountpoint': '/var/lib/docker/volumes/wikidata/_data'}])
        return w

    @unittest.skipUnless(shutil.which('docker') and subprocess.run(['docker', 'compose', 'version'], capture_output=True).returncode == 0, 'needs docker compose')
    def test_the_compose_capture_is_valid_compose(self):
        fmt, text = wlcapture.render(self.container())
        self.assertEqual(fmt, 'compose')
        self.assertIn('never reads environment values', text)
        doc = yaml.safe_load(text)
        svc = doc['services']['wiki']
        self.assertEqual(svc['ports'], ['127.0.0.1:8080:80', '5353:53/udp'])
        self.assertEqual(svc['volumes'], ['/srv/wiki:/usr/share/nginx/html:ro', 'wikidata:/data'])
        self.assertEqual(doc['volumes'], {'wikidata': {'external': True}})
        self.assertEqual(svc['labels'], {'team': 'web'})                    # not compose's own
        d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d)
        (d / 'compose.yaml').write_text(text)
        p = subprocess.run(['docker', 'compose', '-f', str(d / 'compose.yaml'), 'config', '-q'], capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)

    def test_the_quadlet_capture(self):
        fmt, text = wlcapture.render(self.container(), 'quadlet')
        self.assertIn('[Container]\nImage=docker.io/library/nginx:1.27\nContainerName=wiki\nPublishPort=127.0.0.1:8080:80\nPublishPort=5353:53/udp', text)
        self.assertIn('Volume=/srv/wiki:/usr/share/nginx/html:ro', text)
        self.assertIn('Network=front', text)
        self.assertIn('Restart=always', text)
        self.assertRaises(ValueError, wlcapture.render, self.container(), 'libvirt')

    def test_the_libvirt_capture_is_valid_and_never_widens_a_console(self):
        w = workloads.from_infra('kvm', {'libvirt': [DOMAIN]}, [])[0]
        fmt, text = wlcapture.render(w)
        self.assertEqual(fmt, 'libvirt')
        self.assertIn('listen="127.0.0.1"', text)
        self.assertNotIn('0.0.0.0', text)
        self.assertIn('<source file="/var/lib/libvirt/images/web-01.qcow2" />', text)
        self.assertIn('<os firmware="efi">', text)
        if shutil.which('virt-xml-validate'):
            d = Path(tempfile.mkdtemp())
            self.addCleanup(shutil.rmtree, d)
            (d / 'd.xml').write_text(text)
            p = subprocess.run(['virt-xml-validate', str(d / 'd.xml'), 'domain'], capture_output=True, text=True)
            self.assertEqual(p.returncode, 0, p.stdout + p.stderr)

    def test_the_incus_capture(self):
        dev = b64('root:\n  path: /\n  pool: default\n  type: disk\neth0:\n  network: incusbr0\n  type: nic\n')
        inst = __import__('storageforge_index.runtimes.guests', fromlist=['x']).parse_incus(['i\tc1,RUNNING,CONTAINER,default web,10.0.0.5 (eth0),0', f'd\tc1\t{dev}',
                                                                                            's\tc1\tsecurity.nesting\ttrue'])
        w = workloads.from_infra('h', {'incus': inst}, [])[0]
        doc = yaml.safe_load(wlcapture.render(w)[1])
        self.assertEqual(doc['profiles'], ['default', 'web'])
        self.assertEqual(doc['devices']['eth0'], {'network': 'incusbr0', 'type': 'nic'})
        self.assertEqual(doc['config'], {'security.nesting': 'true'})


class Adopt(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.db = dbfactory.make(self, Path(self.tmp) / 'index.db')
        self.conn = self.db.connect()
        self.db.migrate(self.conn)
        self.addCleanup(self.conn.close)
        self.conn.execute("INSERT INTO hosts (hostname, ssh_host, ssh_user, inventory_json) VALUES ('nas', 'nas', 'scan', '{}')")
        self.hid = self.conn.scalar("SELECT host_id FROM hosts WHERE hostname = 'nas'")
        self.set_containers([dict(CONTAINER)])
        security._save_measurement(self.conn, 'nas', 'infra', int(time.time()), 'test', {'tools': ['virsh'], 'libvirt': [DOMAIN]})

    def set_containers(self, cs):
        self.conn.execute('DELETE FROM docker_hosts WHERE host_id = :h', {'h': self.hid})
        self.conn.execute("INSERT INTO docker_hosts (host_id, engine, access, root_dir, containers_json, volumes_json, compose_json, scan_id, updated_at) "
                          "VALUES (:h, 'docker', 'direct', '/var/lib/docker', :c, '[]', '[]', NULL, 1)", {'h': self.hid, 'c': json.dumps(cs)})

    def test_drift_against_the_capture(self):
        got = wlcapture.adopt(self.conn, 'nas', 'docker', 'wiki', None, 'web:alice')
        self.assertEqual(got['format'], 'compose')
        self.assertEqual([c['state'] for c in wlcapture.captures(self.conn)], ['same'])
        changed = dict(CONTAINER, image='docker.io/library/nginx:1.28', ports=CONTAINER['ports'] + [{'host_ip': '0.0.0.0', 'host_port': 9000, 'port': 9000, 'proto': 'tcp'}])
        self.set_containers([changed])
        c = wlcapture.captures(self.conn)[0]
        self.assertEqual(c['state'], 'drifted')
        fields = {d['field']: d for d in c['drift']}
        self.assertEqual(fields['image']['now'], 'docker.io/library/nginx:1.28')
        self.assertEqual(fields['ports']['added'], ['0.0.0.0:9000->9000/tcp'])
        w = next(x for x in workloads.listing(self.conn, 'nas')['workloads'] if x['name'] == 'wiki')
        self.assertEqual(w['capture']['format'], 'compose')
        self.assertEqual(len(w['capture']['drift']), 2)
        self.set_containers([])
        self.assertEqual(wlcapture.captures(self.conn)[0]['state'], 'gone')

    def test_a_vm_capture_and_a_moved_nic(self):
        wlcapture.adopt(self.conn, 'nas', 'libvirt', 'web-01', None, 'cli')
        moved = dict(DOMAIN, nics=[dict(DOMAIN['nics'][0], source='isolated'), DOMAIN['nics'][1]])
        security._save_measurement(self.conn, 'nas', 'infra', int(time.time()), 'test', {'tools': ['virsh'], 'libvirt': [moved]})
        d = wlcapture.captures(self.conn)[0]['drift']
        self.assertEqual(d[0]['field'], 'nics')
        self.assertEqual(d[0]['added'], ['network:isolated:52:54:00:aa:bb:cc'])
        self.assertRaises(LookupError, wlcapture.adopt, self.conn, 'nas', 'libvirt', 'nope', None, 'cli')
        self.assertRaises(ValueError, wlcapture.adopt, self.conn, 'nas', 'docker', 'wiki', 'incus', 'cli')

    def test_the_routes(self):
        from storageforge_index import server, users
        users.create(self.conn, 'root', 'a long enough password', 'admin')
        c = server.create_app(server.App(self.db), 's' * 48).test_client()
        self.assertEqual(c.post('/api/login', json={'username': 'root', 'password': 'a long enough password'}).status_code, 200)
        prev = c.get('/api/workloads/capture?host=nas&runtime=docker&name=wiki&format=quadlet').get_json()
        self.assertEqual(prev['format'], 'quadlet')
        self.assertEqual(self.conn.scalar('SELECT count(*) FROM workload_captures'), 0)            # a preview saves nothing
        got = c.post('/api/workloads/captures', json={'host': 'nas', 'runtime': 'docker', 'name': 'wiki'}).get_json()
        self.assertIn('services:', c.get(f'/api/workloads/captures/{got["id"]}?raw=1').get_data(as_text=True))
        self.assertEqual(c.get('/api/workloads/captures').get_json()['captures'][0]['state'], 'same')
        self.assertEqual(self.conn.scalar("SELECT count(*) FROM audit_log WHERE action = 'workload.adopt'"), 1)
        self.assertEqual(c.post('/api/workloads/captures', json={'host': 'nas', 'runtime': 'docker', 'name': 'nope'}).status_code, 404)
        self.assertEqual(c.delete(f'/api/workloads/captures/{got["id"]}').status_code, 200)
        self.assertEqual(c.delete(f'/api/workloads/captures/{got["id"]}').status_code, 404)


@unittest.skipUnless(shutil.which('docker') and subprocess.run(['docker', 'image', 'inspect', 'busybox:latest'], capture_output=True).returncode == 0
                     and subprocess.run(['docker', 'compose', 'version'], capture_output=True).returncode == 0, 'needs Docker, compose and busybox')
class RealDockerCapture(unittest.TestCase):
    def test_a_running_container_is_scanned_captured_and_the_capture_is_valid(self):
        name = f'sfcap{os.getpid()}{int(time.time()) % 100000}'
        d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d, True)
        ran = subprocess.run(['docker', 'run', '-d', '--name', name, '-p', '127.0.0.1::80', '-v', f'{d}:/data:ro', '--label', 'team=test', '--label', 'io.containers.autoupdate=registry', '-e', 'TOKEN=hunter2',
                              '--restart', 'unless-stopped', 'busybox:latest', 'sleep', '120'], capture_output=True)
        if ran.returncode:
            self.skipTest('could not start a container here')
        self.addCleanup(subprocess.run, ['docker', 'rm', '-f', name], capture_output=True)
        c = next(x for x in docker.parse_engine(subprocess.run(['sh', '-c', docker.ENGINE], capture_output=True, text=True).stdout)['containers'] if x['name'] == name)
        fmt, text = wlcapture.render(workloads._container('here', 'docker', c, [], []))
        self.assertNotIn('hunter2', text)
        doc = yaml.safe_load(text)
        svc = doc['services'][name]
        self.assertEqual(svc['volumes'], [f'{d}:/data:ro'])
        self.assertEqual(svc['labels'], {'io.containers.autoupdate': 'registry'})      # the scan keeps only labels that say who runs it
        self.assertEqual(svc['restart'], 'unless-stopped')
        (d / 'compose.yaml').write_text(text)
        p = subprocess.run(['docker', 'compose', '-f', str(d / 'compose.yaml'), 'config', '-q'], capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)


if __name__ == '__main__':
    unittest.main()
