"""Workload exports (wlexport.py): a change plan's workload steps as Terraform or OpenTofu and as Puppet, read back and compared with the
plan they came from (the round trip), and checked by tofu, terraform and puppet where they are installed (here they are not, and those
checks skip). The readers below take the subset of HCL and of the Puppet language the exports write, and refuse anything else."""
import json
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

try:
    import dbfactory
except ImportError:      # run as tests.test_x from the project folder
    from tests import dbfactory
from storageforge_index import changes, wlexport

COMPOSE = 'services:\n  web:\n    image: docker.io/library/nginx:1.27\n    ports: ["127.0.0.1:8080:80"]\n    volumes: ["/srv/wiki:/usr/share/nginx/html:ro"]\n' \
          '    command: ["sh", "-c", "echo \'it\\\\s\' ${HOME}"]\n'
KEY = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl ops@laptop'
PLAN = {'name': 'web tier', 'tasks': [
    {'type': 'container', 'host': 'nas', 'params': {'runtime': 'docker', 'name': 'proxy', 'image': 'caddy:2', 'publish': '127.0.0.1:8443:443/tcp,80:80', 'binds': '/srv/caddy:/data:ro', 'restart': 'always'}},
    {'type': 'stack', 'host': 'nas', 'params': {'runtime': 'docker', 'name': 'wiki', 'compose': COMPOSE, 'labels': 'team=web', 'allow_from': '10.0.0.0/8'}},
    {'type': 'incus', 'host': 'nas', 'params': {'name': 'c1', 'image': 'images:debian/13', 'cpus': '2', 'memory_mb': '1024', 'publish': '8080:80', 'labels': 'team=web', 'pool': 'fast'}},
    {'type': 'vm-create', 'host': 'kvm', 'params': {'name': 'web-01', 'image': 'debian13', 'ssh_key': KEY, 'disk_gb': '30', 'ram_mb': '4096'}},
    {'type': 'vm-iso', 'host': 'kvm', 'params': {'name': 'pve', 'iso': 'custom', 'iso_url': 'https://x.example/pve.iso', 'iso_sha': 'a' * 64, 'bridge': 'br0'}},
    {'type': 'dir', 'host': 'nas', 'params': {'path': '/srv/wiki'}}]}


# ── a reader of the HCL the export writes ───────────────────────────
TOKEN = re.compile(r'\s*(?:(#[^\n]*)|("(?:[^"\\]|\\.)*")|(-?\d+)|([A-Za-z_][A-Za-z0-9_.\-]*)|(\S))')


def hcl_tokens(text):
    pos, out = 0, []
    while pos < len(text):
        m = TOKEN.match(text, pos)
        if not m or m.end() == pos:
            break
        pos = m.end()
        com, s, n, ident, sym = m.groups()
        if com:
            continue
        if s is not None:
            out.append(('str', json.loads(s).replace('$${', '${').replace('%%{', '%{')))
        elif n is not None:
            out.append(('num', int(n)))
        elif ident is not None:
            out.append(('id', ident))
        elif sym:
            out.append(('sym', sym))
    return out


def hcl_read(text):
    """[(block type, labels, body)] where body is {'attrs': {...}, 'blocks': [...]}."""
    toks = hcl_tokens(text)
    i = 0

    def value():
        nonlocal i
        kind, v = toks[i]
        i += 1
        if kind in ('str', 'num'):
            return v
        if kind == 'id':
            return {'true': True, 'false': False}.get(v, ('ref', v))
        if v == '[':
            out = []
            while toks[i] != ('sym', ']'):
                out.append(value())
                if toks[i] == ('sym', ','):
                    i += 1
            i += 1
            return out
        if v == '{':
            out = {}
            while toks[i] != ('sym', '}'):
                k = toks[i][1]
                i += 2                          # the key and '='
                out[k] = value()
            i += 1
            return out
        raise ValueError(f'not HCL the export writes: {v!r}')

    def body(end):
        nonlocal i
        b = {'attrs': {}, 'blocks': []}
        while i < len(toks) and toks[i] != end:
            name = toks[i][1]
            i += 1
            if toks[i] == ('sym', '='):
                i += 1
                b['attrs'][name] = value()
                continue
            labels = []
            while toks[i][0] == 'str':
                labels.append(toks[i][1])
                i += 1
            assert toks[i] == ('sym', '{'), toks[i]
            i += 1
            b['blocks'].append((name, labels, body(('sym', '}'))))
            i += 1
        return b
    return body(None)['blocks']


# ── a reader of the Puppet the export writes ────────────────────────
PTOKEN = re.compile(r"\s*(?:(#[^\n]*)|('(?:[^'\\]|\\.)*')|(-?\d+)|([A-Za-z_][A-Za-z0-9_:]*)|(=>|\S))")


def puppet_read(text):
    """{node: [(type, title, attrs)]}."""
    toks, pos = [], 0
    while pos < len(text):
        m = PTOKEN.match(text, pos)
        if not m or m.end() == pos:
            break
        pos = m.end()
        com, s, n, ident, sym = m.groups()
        if com:
            continue
        toks.append(('str', re.sub(r"\\(.)", r'\1', s[1:-1])) if s is not None else ('num', int(n)) if n is not None else ('id', ident) if ident else ('sym', sym))
    i, nodes = 0, {}

    def value():
        nonlocal i
        kind, v = toks[i]
        i += 1
        if kind in ('str', 'num'):
            return v
        if kind == 'id' and v in ('true', 'false'):
            return v == 'true'
        if v == '[':
            out = []
            while toks[i] != ('sym', ']'):
                out.append(value())
                if toks[i] == ('sym', ','):
                    i += 1
            i += 1
            return out
        raise ValueError(f'not Puppet the export writes: {v!r}')
    while i < len(toks):
        assert toks[i] == ('id', 'node'), toks[i]
        node = toks[i + 1][1]
        i += 3
        res = nodes.setdefault(node, [])
        while toks[i] != ('sym', '}'):
            rtype, title = toks[i][1], toks[i + 2][1]
            i += 4                              # type { 'title' :
            attrs = {}
            while toks[i] != ('sym', '}'):
                k = toks[i][1]
                i += 2                          # key =>
                attrs[k] = value()
                if toks[i] == ('sym', ','):
                    i += 1
            i += 1
            res.append((rtype, title, attrs))
        i += 1
    return nodes


class Export(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.db = dbfactory.make(self, Path(self.tmp) / 'index.db')
        self.conn = self.db.connect()
        self.db.migrate(self.conn)
        self.addCleanup(self.conn.close)

    def test_terraform_round_trip(self):
        name, text = wlexport.render(PLAN, 'terraform')
        self.assertEqual(name, 'workloads-web-tier.tf')
        blocks = hcl_read(text)
        res = {(lab[0], lab[1]): b for kind, lab, b in blocks if kind == 'resource'}
        providers = next(b for kind, _, b in blocks if kind == 'terraform')['blocks'][0][2]['attrs']
        self.assertEqual({k: v['source'] for k, v in providers.items()}, {'docker': 'kreuzwerker/docker', 'incus': 'lxc/incus', 'libvirt': 'dmacvicar/libvirt'})
        proxy = res[('docker_container', 'nas_proxy')]
        self.assertEqual(proxy['attrs']['image'], ('ref', 'docker_image.nas_proxy.image_id'))
        self.assertEqual(res[('docker_image', 'nas_proxy')]['attrs']['name'], 'caddy:2')
        ports = [(b['attrs']['ip'], b['attrs']['external'], b['attrs']['internal'], b['attrs']['protocol']) for k, _, b in proxy['blocks'] if k == 'ports']
        self.assertEqual(ports, [('127.0.0.1', 8443, 443, 'tcp'), ('0.0.0.0', 80, 80, 'tcp')])
        vols = [b['attrs'] for k, _, b in proxy['blocks'] if k == 'volumes']
        self.assertEqual(vols, [{'host_path': '/srv/caddy', 'container_path': '/data', 'read_only': True}])
        web = res[('docker_container', 'nas_wiki_web')]
        labels = {b['attrs']['label']: b['attrs']['value'] for k, _, b in web['blocks'] if k == 'labels'}
        self.assertEqual(labels, {'storageforge.managed': 'true', 'storageforge.stack': 'wiki', 'team': 'web', 'com.docker.compose.service': 'web'})
        c1 = res[('incus_instance', 'nas_c1')]['attrs']
        self.assertEqual((c1['image'], c1['config']['limits.cpu'], c1['config']['user.team']), ('images:debian/13', '2', 'web'))
        devs = {b['attrs']['name']: b['attrs']['properties'] for k, _, b in res[('incus_instance', 'nas_c1')]['blocks'] if k == 'device'}
        self.assertEqual(devs['sf-port-tcp-8080'], {'listen': 'tcp:0.0.0.0:8080', 'connect': 'tcp:127.0.0.1:80'})
        self.assertEqual(devs['root'], {'path': '/', 'pool': 'fast'})
        dom = res[('libvirt_domain', 'kvm_web_01')]
        self.assertEqual((dom['attrs']['memory'], dom['attrs']['cloudinit']), (4096, ('ref', 'libvirt_cloudinit_disk.kvm_web_01_seed.id')))
        g = next(b['attrs'] for k, _, b in dom['blocks'] if k == 'graphics')
        self.assertEqual(g['listen_address'], '127.0.0.1')
        seed = res[('libvirt_cloudinit_disk', 'kvm_web_01_seed')]['attrs']['user_data']
        self.assertEqual(json.loads(seed.split('\n', 1)[1])['users'][0]['ssh_authorized_keys'], [KEY])
        self.assertEqual(res[('libvirt_volume', 'kvm_web_01_root')]['attrs']['size'], 30 * 2**30)
        pve = res[('libvirt_domain', 'kvm_pve')]
        self.assertEqual(next(b['attrs'] for k, _, b in pve['blocks'] if k == 'network_interface'), {'bridge': 'br0'})
        self.assertIn([{'url': 'https://x.example/pve.iso'}], [[b['attrs']] for k, _, b in pve['blocks'] if k == 'disk'])
        self.assertIn('step dir on nas', text)                 # what has no counterpart is said, not dropped
        self.assertIn('only 10.0.0.0/8 may reach what it publishes', text)
        tofu = wlexport.render(PLAN, 'opentofu')[1]
        self.assertIn('tofu init', tofu)
        self.assertEqual(hcl_read(tofu), blocks)

    def test_puppet_round_trip(self):
        name, text = wlexport.render(PLAN, 'puppet')
        nodes = puppet_read(text)
        self.assertEqual(set(nodes), {'nas', 'kvm'})
        nas = {(t, title): a for t, title, a in nodes['nas']}
        run = nas[('docker::run', 'proxy')]
        self.assertEqual((run['image'], run['ports'], run['volumes'], run['restart']), ('caddy:2', ['127.0.0.1:8443:443/tcp', '0.0.0.0:80:80/tcp'], ['/srv/caddy:/data:ro'], 'always'))
        self.assertEqual(nas[('file', '/srv/stacks/wiki/compose.yaml')]['content'], changes.normalize(PLAN)['tasks'][1]['params']['compose'] + '\n')     # quotes and ${} kept
        self.assertEqual(nas[('docker_compose', 'wiki')]['compose_files'], ['/srv/stacks/wiki/compose.yaml', '/srv/stacks/wiki/storageforge.yaml'])
        self.assertEqual(json.loads(nas[('file', '/srv/stacks/wiki/storageforge.yaml')]['content'])['services']['web']['labels']['team'], 'web')
        inc = nas[('exec', 'incus c1')]
        self.assertEqual(inc['unless'], 'incus info c1')
        self.assertIn('-c limits.memory=1024MiB', inc['command'])
        kvm = {(t, title): a for t, title, a in nodes['kvm']}
        self.assertEqual(kvm[('exec', 'vm pve')]['unless'], 'virsh -c qemu:///system dominfo pve')
        self.assertIn('--network bridge=br0,model=virtio', kvm[('exec', 'vm pve')]['command'])
        self.assertIn('listen=127.0.0.1', kvm[('exec', 'vm web-01')]['command'])

    @unittest.skipUnless(shutil.which('tofu') or shutil.which('terraform'), 'needs tofu or terraform')
    def test_tofu_or_terraform_reads_it(self):
        tool = shutil.which('tofu') or shutil.which('terraform')
        p = subprocess.run([tool, 'fmt', '-'], input=wlexport.render(PLAN, 'opentofu')[1], capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)

    @unittest.skipUnless(shutil.which('puppet'), 'needs puppet')
    def test_puppet_parses_it(self):
        f = Path(self.tmp) / 'w.pp'
        f.write_text(wlexport.render(PLAN, 'puppet')[1])
        p = subprocess.run(['puppet', 'parser', 'validate', str(f)], capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)

    def test_the_route(self):
        from storageforge_index import server, users
        users.create(self.conn, 'root', 'a long enough password', 'admin')
        pid = changes.save_plan(self.conn, PLAN, 'root')
        c = server.create_app(server.App(self.db), 's' * 48).test_client()
        self.assertEqual(c.post('/api/login', json={'username': 'root', 'password': 'a long enough password'}).status_code, 200)
        r = c.get(f'/api/changes/{pid}/export/terraform')
        self.assertEqual(r.status_code, 200)
        self.assertIn('workloads-web-tier.tf', r.headers['Content-Disposition'])
        self.assertIn('resource "docker_container" "nas_proxy"', r.get_data(as_text=True))
        self.assertIn("docker::run { 'proxy':", c.get(f'/api/changes/{pid}/export/puppet').get_data(as_text=True))
        self.assertEqual(c.get('/api/changes/999/export/puppet').status_code, 404)
        self.assertEqual(self.conn.scalar("SELECT count(*) FROM audit_log WHERE action LIKE 'changes.export.%'"), 2)
        from storageforge_index import permissions
        self.assertEqual(permissions.required('GET', f'/api/changes/{pid}/export/opentofu'), 'plans.scripts')


if __name__ == '__main__':
    unittest.main()
