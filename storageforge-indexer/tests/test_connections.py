"""Connections on a scan and on the map (roadmap section 2): the collector's own lines run for real against stand-in tools, what
they print is read, and the map is built from it. What must hold: each private network's peers are drawn, a scanned host confirmed
and anything else a placeholder; a tunnel is drawn as public; and a tunnel's credential never leaves the host."""
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import json
import re

from storageforge_index import infragraph, inframeasure, overlays
from test_overlays import HEADSCALE, NETBIRD, OPENVPN, TAILSCALE, ZT_INFO, ZT_NETWORKS, ZT_PEERS
from test_tunnels import CLOUDFLARED, FRP_TOML
from test_accessproxies import BOUNDARY_CONTROLLER, BOUNDARY_TARGETS, POMERIUM, TCTL_NODES, TCTL_STATUS, TELEPORT_CONF, TSH_STATUS, ZITI
from test_overlay_readers import NEBULA_CONF, NETMAKER, REAL_NEBULA_CERT, SWAN_CONNS, SWAN_SAS, ZeroTierPeers


class Collected(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.bin = self.tmp / 'bin'
        self.bin.mkdir()
        # Only these and the stand-ins are on PATH: the machine running the tests may have a real tailscale, and its tailnet is not test data
        for real in ('bash', 'sh', 'cat', 'grep', 'head', 'timeout', 'sed', 'tr', 'base64', 'awk'):
            os.symlink(shutil.which(real), self.bin / real)

    def tool(self, name, body):
        (self.bin / name).write_text('#!/bin/sh\n' + body)
        (self.bin / name).chmod(0o755)

    def say(self, name, when, text):
        """A stand-in that prints text when its arguments are `when`, and nothing otherwise."""
        (self.tmp / f'{name}.out').write_text(text)
        self.tool(name, f'[ "$*" = "{when}" ] && cat {self.tmp}/{name}.out\nexit 0\n')

    def collect(self, running=()):
        """The collector's lines for private networks and tunnels, as the scan sends them, with the files they read moved under tmp."""
        body = inframeasure.BODY
        start, end = body.index('sec() {'), body.index('sec tools;')
        mine = body[body.index('# each private network'):body.index('# site names and upstreams')]
        for path in ('/etc/cloudflared/config.yml', '/etc/frp/frpc.toml', '/var/log/openvpn/openvpn-status.log'):
            self.assertIn(path, mine)
            mine = mine.replace(path, f'{self.tmp}{path}')
        self.tool('pgrep', 'case " ' + ' '.join(running) + ' " in *" $2 "*) exit 0;; esac\nexit 1\n')
        ran = subprocess.run([str(self.bin / 'bash'), '-c', 'set -u\n' + body[start:end] + mine + 'sec end\n'], capture_output=True, text=True, env={'PATH': str(self.bin)})
        self.assertEqual(ran.stderr, '')
        return ran.stdout

    def put(self, path, text):
        f = Path(f'{self.tmp}{path}')
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(text)

    def access(self, out):
        s = inframeasure._sections(out)
        self.assertIn('end', s)
        return inframeasure.parse_access(s, ['tailscale', 'netbird'])

    def test_every_network_a_host_is_on_is_read_from_its_own_tool(self):
        self.say('tailscale', 'status --json', TAILSCALE)
        self.say('netbird', 'status --json', NETBIRD)
        self.say('headscale', 'nodes list -o json', HEADSCALE)
        (self.tmp / 'zt').mkdir()
        for arg, text in (('info', ZT_INFO), ('listnetworks', ZT_NETWORKS), ('peers', ZT_PEERS)):
            (self.tmp / 'zt' / arg).write_text(text)
        self.tool('zerotier-cli', f'[ "$1" = -j ] && cat {self.tmp}/zt/$2\n')
        self.put('/var/log/openvpn/openvpn-status.log', OPENVPN)
        acc = self.access(self.collect())
        self.assertEqual(sorted((o['network'], o.get('state')) for o in acc['overlays']),
                         [('netbird', 'connected'), ('openvpn', 'server'), ('tailscale', 'connected'), ('tailscale', 'control server'), ('zerotier', 'connected')])
        self.assertEqual([(t['ip'], t['name'], t['active']) for t in acc['tailscale']], [('100.101.1.2', 'pi', True), ('100.101.1.3', 'laptop', True), ('100.101.1.4', 'old', False)],
                         'the peers the map already drew from the text now come from the JSON')

    def test_a_host_with_none_of_it_has_nothing_and_an_old_tailscale_is_still_read_from_its_text(self):
        acc = self.access(self.collect())
        self.assertEqual((acc['overlays'], acc['tunnels']), ([], []))
        s = {'tailscale': ['100.101.1.2   pi   gabe@   linux   active; direct 10.0.0.9:41641'], 'tailscale_json': ['unknown flag: --json']}
        acc = inframeasure.parse_access(s, ['tailscale'])
        self.assertEqual(acc['tailscale'], [{'ip': '100.101.1.2', 'name': 'pi', 'os': 'linux', 'active': True}])
        self.assertEqual(acc['overlays'][0]['error'], 'not the JSON this tool prints')

    def test_a_tunnels_routes_are_read_and_its_token_stays_on_the_host(self):
        self.put('/etc/cloudflared/config.yml', CLOUDFLARED)
        self.put('/etc/frp/frpc.toml', FRP_TOML)
        out = self.collect(running=('cloudflared', 'frpc', 'ngrok', 'newt'))
        self.assertNotIn('SECRET', out, 'no credential line is sent')
        self.assertIn('credentials-file: "***"', out, 'the line stays, with its value blanked')
        by = {t['tool']: t for t in self.access(out)['tunnels']}
        self.assertEqual([p['public'] for p in by['cloudflared']['published']], ['https://photos.example.com', 'https://git.example.com/api'])
        self.assertEqual([p['public'] for p in by['frp']['published']], ['frp.example.net:6000/tcp', 'http://www.example.net', 'http://example.net'])
        self.assertTrue(by['frp']['running'])
        self.assertEqual((by['ngrok']['published'], by['ngrok']['remote']), ([], True), 'running with nothing to read here is still a tunnel')
        self.assertEqual(by['newt']['server'], 'its Pangolin server')

    def test_the_map_draws_peers_and_tunnels(self):
        self.say('netbird', 'status --json', NETBIRD)
        self.put('/etc/cloudflared/config.yml', CLOUDFLARED)
        acc = self.access(self.collect(running=('cloudflared',)))
        nodes, edges = infragraph.build('nas', None, {'access': acc}, [], [], {'100.92.0.2': 'pi'}, set())
        peer_edges = {e['dst']: e['props'] for e in edges if e['rel'] == 'PEERS_WITH'}
        self.assertEqual(sorted(peer_edges), ['host:pi', 'ovnode:netbird:100.92.0.3'])
        self.assertEqual((peer_edges['host:pi']['confidence'], peer_edges['ovnode:netbird:100.92.0.3']['confidence']), ('confirmed', 'inferred'))
        self.assertEqual((peer_edges['host:pi']['network'], peer_edges['host:pi']['direct'], peer_edges['host:pi']['evidence']['source']), ('netbird', True, 'NetBird status'))
        placeholder = nodes['ovnode:netbird:100.92.0.3']
        self.assertEqual((placeholder['kind'], placeholder['label'], placeholder['props']['network']), ('Peer', 'desk.netbird.selfhosted', 'netbird'))
        tunnel = nodes['tunnel:nas:cloudflared']
        self.assertEqual((tunnel['kind'], tunnel['label'], tunnel['props']['exposure']), ('Tunnel', 'Cloudflare Tunnel', 'public'))
        self.assertEqual(tunnel['props']['published'], ['https://photos.example.com', 'https://git.example.com/api'])
        self.assertIn('Public through Cloudflare Tunnel', tunnel['props']['says'])

    def test_the_whole_script_is_still_one_bash_reads(self):
        script = inframeasure.script()
        self.assertEqual(subprocess.run(['bash', '-n'], input=script, text=True).returncode, 0)
        self.assertNotIn('@SECRET_LINE@', script)
        self.assertNotIn("'", inframeasure.tunnels.SECRET_LINE)


CA_CNF = """[ca]
default_ca = CA_default
[CA_default]
dir = .
database = $dir/index.txt
new_certs_dir = $dir/issued
serial = $dir/serial
crlnumber = $dir/crlnumber
default_md = sha256
policy = policy_any
default_days = 825
default_crl_days = 180
unique_subject = no
[policy_any]
organizationName = optional
commonName = supplied
emailAddress = optional
"""


def make_pki(pki: Path):
    """A CA as easy-rsa keeps one, made by the real `openssl ca`: a server, a client, a client that is revoked, one whose
    certificate ended in 2021 and is still marked valid in the index, and a CRL."""
    (pki / 'issued').mkdir(parents=True)
    (pki / 'index.txt').write_text('')
    (pki / 'serial').write_text('01\n')
    (pki / 'crlnumber').write_text('01\n')
    (pki / 'ca.cnf').write_text(CA_CNF)
    key = ['-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes']

    def run(*words):
        subprocess.run(['openssl', *words], cwd=pki, check=True, capture_output=True)
    ca = ['ca', '-batch', '-config', 'ca.cnf', '-cert', 'ca.crt', '-keyfile', 'ca.key']
    run('req', '-x509', *key, '-keyout', 'ca.key', '-out', 'ca.crt', '-subj', '/CN=Easy-RSA CA', '-days', '3650')
    for name, more in (('server', ()), ('laptop', ()), ('branch', ()), ('old', ('-startdate', '20200101000000Z', '-enddate', '20210101000000Z'))):
        run('req', *key, '-keyout', f'{name}.key', '-out', f'{name}.csr', '-subj', f'/O=Lab/CN={name}/emailAddress=gabe@example.com')
        run(*ca, '-in', f'{name}.csr', '-out', f'{name}.crt', '-notext', *more)
    run(*ca, '-revoke', 'branch.crt')
    run(*ca, '-gencrl', '-out', 'crl.pem')


@unittest.skipUnless(shutil.which('openssl') and shutil.which('awk'), 'needs openssl and awk')
class MoreCollected(Collected):
    """The same for the tools that came after: Nebula, Netmaker, strongSwan, OpenVPN's certificates and the four access proxies.
    The stand-ins print what the real tools print; awk, sed, grep and openssl are the real ones, so what is asserted of the
    output is what would leave a host."""
    PEOPLE = ('SECRET', 'gabe', 'carol', 'brien', 'mallory', 'steeeeve', 'strongswan.org')

    def setUp(self):
        super().setUp()
        for real in ('cut', 'openssl'):
            os.symlink(shutil.which(real), self.bin / real)

    def collect_all(self):
        body = inframeasure.BODY
        start, end = body.index('sec() {'), body.index('sec tools;')
        mine = body[body.index('# each private network'):body.index('# site names and upstreams')]
        mine = re.sub(r'(?<=[ "])/(etc|var/log|run|root|usr/share)/', lambda m: f'{self.tmp}/{m[1]}/', mine)
        self.assertNotIn(' /etc/', mine)
        self.tool('pgrep', 'exit 1\n')
        ran = subprocess.run([str(self.bin / 'bash'), '-c', 'set -u\n' + inframeasure.SCRUB_VARS + body[start:end] + mine + 'sec end\n'], capture_output=True, text=True, env={'PATH': str(self.bin)})
        self.assertEqual(ran.stderr, '')
        return ran.stdout

    def says(self, name, answers: dict):
        """A stand-in that prints one text for each set of arguments it knows, and fails on any other, as the real tools do."""
        cases = ''
        for i, (when, text) in enumerate(answers.items()):
            (self.tmp / f'{name}.{i}.out').write_text(text)
            cases += f'  "{when}") cat {self.tmp}/{name}.{i}.out;;\n'
        self.tool(name, f'case "$*" in\n{cases}  *) echo "unknown: $*" >&2; exit 1;;\nesac\n')

    def everything(self):
        self.put('/etc/nebula/config.yml', NEBULA_CONF.replace('/etc/nebula/host.crt', f'{self.tmp}/etc/nebula/host.crt'))
        if REAL_NEBULA_CERT:
            os.symlink(REAL_NEBULA_CERT, self.bin / 'nebula-cert')
            for words in (('ca', '-name', 'lab', '-duration', '48h'), ('sign', '-name', 'nas', '-ip', '192.168.100.7/24', '-subnets', '192.168.50.0/24', '-duration', '24h', '-out-crt', 'host.crt', '-out-key', 'host.key')):
                subprocess.run([REAL_NEBULA_CERT, *words], cwd=self.tmp / 'etc/nebula', check=True, capture_output=True)
        self.says('netclient', {'list -l': NETMAKER})
        self.says('swanctl', {'--list-sas': SWAN_SAS, '--list-conns': SWAN_CONNS})
        make_pki(self.tmp / 'etc/openvpn/easy-rsa/pki')
        (self.tmp / 'etc/openvpn/server').mkdir()
        shutil.copy(self.tmp / 'etc/openvpn/easy-rsa/pki/server.crt', self.tmp / 'etc/openvpn/server/server.crt')
        shutil.copy(self.tmp / 'etc/openvpn/easy-rsa/pki/server.key', self.tmp / 'etc/openvpn/server/server.key')
        (self.tmp / 'zt').mkdir()
        for arg, text in (('info', ZT_INFO), ('listnetworks', ZT_NETWORKS), ('peers', ZeroTierPeers.PEERS)):
            (self.tmp / 'zt' / arg).write_text(text)
        self.tool('zerotier-cli', f'[ "$1" = -j ] && cat {self.tmp}/zt/$2\n')
        self.says('ziti-edge-tunnel', {'tunnel_status': ZITI})
        self.says('tctl', {'status --format=json': TCTL_STATUS, 'status': 'Cluster: teleport.lab\nVersion: 18.2.1\nhost CA rotation: standby\n', 'get nodes --format=json': TCTL_NODES})
        self.says('tsh', {'status --format=json': TSH_STATUS})
        self.says('boundary', {'targets list -recursive -scope-id global -format json': BOUNDARY_TARGETS})
        self.put('/etc/teleport.yaml', TELEPORT_CONF)
        self.put('/etc/boundary.d/controller.hcl', BOUNDARY_CONTROLLER)
        self.put('/etc/pomerium/config.yaml', POMERIUM)
        return self.collect_all()

    def test_no_credential_and_no_person_leaves_the_host(self):
        out = self.everything()
        for word in self.PEOPLE + ('PRIVATE KEY', 'postgresql', 'Authorization', 'uname'):
            self.assertNotIn(word, out)
        s = inframeasure._sections(out)
        for section in ('nebula_conf', 'netmaker_json', 'swan_sas', 'swan_conns', 'openvpn_pki', 'ziti_status', 'tp_status', 'tp_nodes', 'tp_conf', 'tp_login', 'boundary_targets', 'boundary_conf', 'pomerium_conf'):
            self.assertTrue(s.get(section), f'{section} was collected')
        self.assertEqual(bool(s.get('nebula_cert')), bool(REAL_NEBULA_CERT))
        self.assertEqual([x for x in s['tp_status'] if x], ['"name": "teleport.lab"', '"version": "18.2.1"', 'Cluster: teleport.lab', 'Version: 18.2.1'])
        self.assertNotIn('ca.key', out, 'no key file is opened or named')

    def test_every_one_of_them_is_read(self):
        acc = self.access(self.everything())
        by = {(o['network'], o.get('state')): o for o in acc['overlays']}
        self.assertEqual(sorted(by), [('ipsec', 'connected'), ('nebula', 'configured'), ('netmaker', 'connected'), ('openvpn', 'server'), ('zerotier', 'connected')])
        self.assertFalse(any(o.get('error') for o in acc['overlays']))
        pki = by[('openvpn', 'server')]['pki']
        self.assertEqual(sorted((c['name'], c['state']) for c in pki['certificates']), [('branch', 'revoked'), ('laptop', 'valid'), ('old', 'valid'), ('server', 'valid')],
                         'the real index of the real openssl, with the common name alone')
        self.assertEqual(sorted(f['file'] for f in pki['files']), ['ca.crt', 'server.crt'])
        self.assertEqual((pki['crl']['revoked'], bool(pki['crl']['next'])), (1, True))
        import time
        counts = overlays.certificate_counts(pki, time.time())
        self.assertEqual((counts['valid'], counts['revoked'], counts['expired'], counts['crl_ended']), (4, 1, 1, False), 'the one that ended in 2021 is ended, whatever the index says')
        if REAL_NEBULA_CERT:
            self.assertEqual((by[('nebula', 'configured')]['self']['name'], by[('nebula', 'configured')]['self']['addresses'], by[('nebula', 'configured')]['routes']), ('nas', ['192.168.100.7'], ['192.168.50.0/24']))
        self.assertEqual(len(by[('ipsec', 'connected')]['peers']), 5)
        tools = {p['tool']: p for p in acc['proxies']}
        self.assertEqual(sorted(tools), ['boundary', 'openziti', 'pomerium', 'teleport'])
        self.assertFalse(any(p.get('error') for p in acc['proxies']))
        self.assertEqual((len(tools['openziti']['targets']), len(tools['teleport']['targets']), len(tools['boundary']['targets']), len(tools['pomerium']['targets'])), (3, 3, 3, 8))
        self.assertEqual((tools['teleport']['cluster'], tools['teleport']['roles'], tools['boundary']['roles']), ('teleport.lab', ['auth', 'proxy', 'node'], ['controller']))
        for word in self.PEOPLE:
            self.assertNotIn(word, json.dumps(acc))

    def test_a_tool_that_fails_or_prints_rubbish_costs_the_scan_nothing_else(self):
        self.says('netclient', {'list -l': 'panic: runtime error\n\ngoroutine 1 [running]:\n'})
        self.says('swanctl', {})                              # the daemon is down: nothing on stdout
        self.says('ziti-edge-tunnel', {'tunnel_status': '{"Success": fal'})
        self.says('tctl', {})
        self.put('/etc/pomerium/config.yaml', 'routes: [\n')
        self.put('/etc/nebula/config.yml', NEBULA_CONF)
        acc = self.access(self.collect_all())
        self.assertEqual(sorted((o['network'], o.get('error')) for o in acc['overlays']), [('nebula', None), ('netmaker', 'not the JSON this tool prints')])
        self.assertEqual(sorted((p['tool'], p.get('error')) for p in acc['proxies']), [('openziti', 'not the JSON this tool prints'), ('pomerium', 'not a Pomerium configuration')])
        nodes, _ = infragraph.build('nas', None, {'access': acc}, [], [], {}, set())
        self.assertEqual(nodes['ovnet:nas:netmaker:client']['props']['says'], 'Netmaker is here, and its status could not be read')
        self.assertTrue(nodes['proxy:nas:openziti']['props']['unread'])

    def test_the_map_draws_each_network_its_peers_and_what_is_behind_them(self):
        acc = self.access(self.everything())
        scanned = {'192.168.100.1': 'lh', '192.168.0.2': 'sun', '10.42.0.9': 'pi', '10.42.0.5': 'graf', '10.9.9.9': 'nas-01'}
        import time
        nodes, edges = infragraph.build('nas', None, {'access': acc}, [], [], scanned, set(), {'pk-pi=': ('pi', 'netmaker')}, None, {('zerotier', '1122334455'): 'desk'}, time.time())
        nets = {n['label']: n for n in nodes.values() if n['kind'] == 'VPNNetwork'}
        self.assertEqual(sorted(nets), ['IPsec', 'Nebula', 'Netmaker', 'OpenVPN', 'ZeroTier'])
        self.assertEqual((nets['Nebula']['props']['role'], nets['Nebula']['props']['interface'], nets['Nebula']['props']['listen_port']), ('host', 'nebula1', 4242))
        self.assertEqual(nets['OpenVPN']['props']['certificates'] | {'crl_next': None, 'ending': None}, {'valid': 4, 'revoked': 1, 'expired': 1, 'ending': None, 'crl_ended': False, 'crl_next': None})
        self.assertIn('Certificates: 4 valid, 1 revoked, 1 ended', nets['OpenVPN']['props']['says'])
        self.assertEqual(nets['IPsec']['props']['says'], 'IPsec: 2 of 4 site-to-site tunnel(s) up, and 1 client connection(s)')
        peer = {(e['props']['network'], e['dst']): e['props'] for e in edges if e['rel'] == 'PEERS_WITH'}
        # Nebula: a lighthouse a scanned host has the address of is that host; the other is a placeholder
        self.assertEqual((peer[('nebula', 'host:lh')]['confidence'], peer[('nebula', 'host:lh')]['lighthouse'], peer[('nebula', 'host:lh')]['relay']), ('confirmed', True, True))
        self.assertEqual((peer[('nebula', 'ovnode:nebula:192.168.100.2')]['confidence'], peer[('nebula', 'host:lh')]['evidence']['source']), ('inferred', 'Nebula configuration'))
        # strongSwan: the other end of a site-to-site tunnel, and a client by the address it was handed
        self.assertEqual((peer[('ipsec', 'host:sun')]['confidence'], peer[('ipsec', 'host:sun')]['active'], peer[('ipsec', 'host:sun')]['ike']), ('confirmed', True, 'IKEv2'))
        self.assertTrue(peer[('ipsec', 'ovnode:ipsec:10.9.0.1')]['client'])
        self.assertFalse(peer[('ipsec', 'ovnode:ipsec:198.51.100.20')]['active'], 'configured and down is drawn, and drawn as down')
        # Netmaker: a peer by its WireGuard key, which another scanned host holds
        self.assertEqual(peer[('netmaker', 'host:pi')]['confidence'], 'confirmed')
        self.assertIn('its key is the one pi said is its own', peer[('netmaker', 'host:pi')]['evidence']['source'])
        self.assertTrue(peer[('netmaker', 'ovnode:netmaker:10.20.0.1')]['gateway'])
        # ZeroTier: by node id where the other host was scanned as a node, and by where it is reached where it was not
        self.assertEqual((peer[('zerotier', 'host:desk')]['confidence'], peer[('zerotier', 'host:pi')]['confidence']), ('confirmed', 'inferred'))
        self.assertIn('node ffeeddccbb is reached at 10.42.0.9, an address of pi', peer[('zerotier', 'host:pi')]['evidence']['source'])
        via = {(e['props']['network'], e['dst']): e['props'] for e in edges if e['rel'] == 'ROUTES_VIA' and e['props'].get('network')}
        self.assertEqual((via[('ipsec', 'host:sun')]['networks'], via[('ipsec', 'host:sun')]['local_networks'], via[('ipsec', 'host:sun')]['confidence']), (['10.2.0.0/16', '10.3.0.0/24'], ['10.1.0.0/16'], 'confirmed'))
        self.assertEqual(via[('netmaker', 'ovnode:netmaker:10.20.0.1')]['networks'], ['192.168.40.0/24', '10.77.0.0/16'])
        self.assertEqual(sorted(e['props']['networks'][0] for e in edges if e['rel'] == 'ROUTES_VIA' and e['dst'] == 'host:lh'), ['192.168.87.0/24'], 'a network Nebula reaches through its lighthouse')
        self.assertEqual(nodes['ovnode:nebula:192.168.100.99']['confidence'], 'inferred', 'a gateway the configuration names and nothing else knows')
        for e in edges:
            self.assertTrue(e['props']['evidence']['source'], 'every line says why it is there')

    def test_the_map_draws_each_access_proxy_and_what_it_fronts(self):
        acc = self.access(self.everything())
        scanned = {'10.42.0.9': 'pi', '10.42.0.5': 'graf', '10.9.9.9': 'nas-01'}
        nodes, edges = infragraph.build('nas', None, {'access': acc}, [], [], scanned, set())
        proxies = {n['label']: n for n in nodes.values() if n['kind'] == 'AccessProxy'}
        self.assertEqual(sorted(proxies), ['Boundary', 'OpenZiti', 'Pomerium', 'Teleport'])
        self.assertEqual((proxies['Pomerium']['props']['exposure'], proxies['Pomerium']['props']['public_routes']), ('public', ['https://status.example.com', 'https://open.example.com']))
        self.assertNotIn('exposure', proxies['Teleport']['props'])
        self.assertEqual((proxies['Teleport']['props']['cluster'], proxies['Teleport']['props']['target_count'], proxies['OpenZiti']['props']['identities']), ('teleport.lab', 3, ['nas-01', 'backup']))
        fronts = {(e['src'], e['dst']): e['props'] for e in edges if e['rel'] == 'FRONTS'}
        self.assertEqual(fronts[('proxy:nas:teleport', 'host:pi')]['confidence'], 'confirmed', 'a node at an address a scanned host has')
        self.assertEqual((fronts[('proxy:nas:pomerium', 'host:graf')]['confidence'], fronts[('proxy:nas:pomerium', 'host:graf')]['access']), ('confirmed', 'by policy: domain, email'))
        self.assertEqual(fronts[('proxy:nas:pomerium', 'host:nas')]['public'], True, 'a route to localhost is to this host, and this one is public')
        self.assertEqual(fronts[('proxy:nas:pomerium', 'host:nas-01')]['confidence'], 'inferred', 'known by a name alone that a scanned host also has')
        self.assertEqual(fronts[('proxy:nas:boundary', 'host:graf')]['confidence'], 'confirmed')
        self.assertIn(('proxy:nas:openziti', 'host:nas'), fronts, 'the service this host is where it comes out')
        for word in self.PEOPLE:
            self.assertNotIn(word, json.dumps([nodes, edges]))


if __name__ == '__main__':
    unittest.main()
