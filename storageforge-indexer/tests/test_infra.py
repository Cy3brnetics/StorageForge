"""Networks, firewalls, workloads and exposure. Parsers meet real tools where this machine has them: real ip and ss, real nft and
iptables in a throwaway network namespace, real Docker. ufw and firewalld need a host running them, so those are samples of
their documented output until the lab runs them."""
import base64
import json
import shutil
import subprocess
import tempfile
import time
import unittest
from unittest import mock

from storageforge_index import exposure, firewall, inframeasure, netfacts, server, users, workloads
from storageforge_index.db import Database
from storageforge_index.runtimes import docker, guests

NS = ['unshare', '--user', '--map-root-user', '--net']
HAS_NS = bool(shutil.which('unshare') and subprocess.run(NS + ['true'], capture_output=True).returncode == 0)
PW = 'a long enough password'


def in_ns(script: str) -> str:
    r = subprocess.run(NS + ['bash', '-ec', script], capture_output=True, text=True, timeout=60)
    if r.returncode:
        raise AssertionError(r.stderr)
    return r.stdout


NET = {'interfaces': [
    {'name': 'lo', 'kind': 'loopback', 'state': 'unknown', 'addresses': [{'ip': '127.0.0.1', 'prefix': 8}]},
    {'name': 'eth0', 'kind': 'ethernet', 'state': 'up', 'addresses': [{'ip': '192.168.1.10', 'prefix': 24}]},
    {'name': 'docker0', 'kind': 'bridge', 'state': 'up', 'addresses': [{'ip': '172.17.0.1', 'prefix': 16}]},
    {'name': 'wg0', 'kind': 'wireguard', 'state': 'unknown', 'addresses': [{'ip': '10.8.0.1', 'prefix': 24}]},
], 'listeners': []}
LISTEN = {'proto': 'tcp', 'addr': '0.0.0.0', 'port': 8000, 'scope': 'any'}
DOCKER_RULES = """*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
:DOCKER - [0:0]
:DOCKER-USER - [0:0]
-A FORWARD -j DOCKER-USER
-A FORWARD -o docker0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A FORWARD -o docker0 -j DOCKER
-A DOCKER -d 172.17.0.2/32 ! -i docker0 -o docker0 -p tcp -m tcp --dport 80 -j ACCEPT
-A DOCKER ! -i docker0 -o docker0 -j DROP
-A DOCKER-USER -j RETURN
COMMIT
"""
UFW = """Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), deny (routed)
New profiles: skip

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW IN    Anywhere
445/tcp                    ALLOW IN    192.168.1.0/24
22/tcp (v6)                ALLOW IN    Anywhere (v6)
"""
CONTAINER = {'name': 'web', 'state': 'running', 'network_mode': 'bridge', 'ports': [{'host_ip': '0.0.0.0', 'host_port': 8080, 'port': 80, 'proto': 'tcp'}],
             'networks': [{'name': 'bridge', 'ip': '172.17.0.2', 'gateway': '172.17.0.1'}]}
FIREWALLD = """public (active)
  target: default
  icmp-block-inversion: no
  interfaces: eth0
  sources: 
  services: cockpit dhcpv6-client ssh
  ports: 8443/tcp
  rich rules: 
\trule family="ipv4" source address="10.0.0.0/8" service name="samba" accept
trusted
  target: ACCEPT
  interfaces: 
  sources: 
  services: 
  ports: 
  rich rules: 
"""


@unittest.skipUnless(shutil.which('ip') and shutil.which('ss'), 'needs ip and ss')
class Network(unittest.TestCase):
    def test_this_machine_for_real(self):
        data = netfacts.parse(subprocess.run(['sh', '-c', netfacts.SCRIPT], capture_output=True, text=True).stdout)
        self.assertTrue(data['complete'])
        self.assertEqual(data['unreadable'], [])
        self.assertIn('lo', [i['name'] for i in data['interfaces']])

    @unittest.skipUnless(HAS_NS, 'needs a user namespace')
    def test_bridge_vlan_and_listener_in_a_namespace(self):
        out = in_ns('''ip link set lo up; ip link add br0 type bridge; ip link add d0 type dummy; ip link set d0 master br0
                       ip link add link d0 name d0.20 type vlan id 20; ip addr add 10.5.0.1/24 dev br0; ip link set br0 up; ip route add 10.6.0.0/24 via 10.5.0.2 2>/dev/null
                       python3 -I -m http.server 18765 --bind 127.0.0.1 >/dev/null 2>&1 & p=$!; sleep 1
                       sh -c "$SCRIPT"; kill $p'''.replace('"$SCRIPT"', _quoted(netfacts.SCRIPT)))
        data = netfacts.parse(out)
        by = {i['name']: i for i in data['interfaces']}
        self.assertEqual(by['br0']['kind'], 'bridge')
        self.assertEqual(by['d0']['master'], 'br0')
        self.assertEqual(by['d0.20']['vlan_id'], 20)
        self.assertEqual(by['br0']['addresses'][0]['ip'], '10.5.0.1')
        self.assertIn({'proto': 'tcp', 'addr': '127.0.0.1', 'port': 18765, 'scope': 'loopback'}, data['listeners'])

    def test_a_tool_that_failed_is_not_an_empty_list(self):
        data = netfacts.parse('@@link\n\n@@addr\n\n@@route\n[]\n@@neigh\n[]\n@@listen\n\n@@end\n')
        self.assertIn('interfaces', data['unreadable'])
        self.assertNotIn('routes', data['unreadable'])

    def test_cut_short_keeps_the_old_reading(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        db = Database(f'sqlite:///{tmp.name}/x.db')
        conn = db.connect()
        self.addCleanup(conn.close)
        db.migrate(conn)
        conn.execute("INSERT INTO hosts (hostname, ssh_host, inventory_json) VALUES ('nas', 'nas', '{}')")
        hid = conn.scalar("SELECT host_id FROM hosts WHERE hostname = 'nas'")
        t = mock.Mock()
        t.run.return_value = '@@link\n[]\n@@addr\n[]\n@@route\n[]\n@@neigh\n[]\n@@listen\ntcp LISTEN 0 1 0.0.0.0:22 0.0.0.0:*\n@@end\n'
        netfacts.survey(conn, t, hid, 1)
        t.run.return_value = '@@link\n[]\n'
        self.assertIn('error', netfacts.survey(conn, t, hid, 2))
        self.assertEqual(netfacts.reading(conn, 'nas')['listeners'][0]['port'], 22)

    def test_ss_address_forms(self):
        text = 'tcp LISTEN 0 1 [::]:22 [::]:*\nudp UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:*\ntcp LISTEN 0 1 *:80 *:*\nudp UNCONN 0 0 [fe80::1]%eth0:546 [::]:*\n'
        got = {(x['addr'], x['port']): x['scope'] for x in netfacts.parse_listeners(text)}
        self.assertEqual(got, {('::', 22): 'any', ('127.0.0.53', 53): 'loopback', ('*', 80): 'any', ('fe80::1', 546): 'link'})


def _quoted(s):
    import shlex
    return shlex.quote(s)


@unittest.skipUnless(HAS_NS and shutil.which('nft'), 'needs nft and a user namespace')
class RealNft(unittest.TestCase):
    def read(self, rules):
        return firewall.parse_nft(in_ns(f"nft -f - <<'EOF'\n{rules}\nEOF\nnft -j list ruleset"))

    def test_ports_sources_policy_and_sets(self):
        fw = self.read('''table inet f {
          set admins { type ipv4_addr; elements = { 10.0.0.5 } }
          chain input { type filter hook input priority 0; policy drop;
            ct state established,related accept
            iifname "lo" accept
            tcp dport 22 accept
            tcp dport { 80, 443 } ip saddr 192.168.1.0/24 accept
            udp dport 5000-5010 accept
            ip saddr @admins tcp dport 9090 accept
            tcp dport 25 drop
          }
        }''')
        self.assertEqual(fw['policies']['input'], 'drop')
        rules = fw['rules']
        self.assertEqual(rules[2]['dports'], [22])
        self.assertEqual(rules[2]['action'], 'accept')
        self.assertEqual(sorted(rules[3]['dports']), [80, 443])
        self.assertEqual(rules[3]['saddr'], '192.168.1.0/24')
        self.assertEqual(rules[4]['dports'], [[5000, 5010]])
        self.assertEqual(rules[5]['saddr'], '@admins')
        self.assertEqual(rules[6]['action'], 'drop')

    def test_something_it_cannot_read_is_marked(self):
        fw = self.read('table inet f {\n chain input { type filter hook input priority 0; policy drop; tcp flags syn tcp option maxseg size 1000-2000 accept; }\n}')
        self.assertTrue(fw['rules'][0]['unmodelled'])
        item = exposure.listener_item(LISTEN, NET, _model(fw))
        self.assertEqual(item['level'], 'unknown')

    def test_exposure_against_a_real_ruleset(self):
        fw = _model(self.read('''table inet f {
          chain input { type filter hook input priority 0; policy drop;
            tcp dport 22 accept
            tcp dport 445 ip saddr 192.168.1.0/24 accept
            iifname "wg0" tcp dport 9000 accept; }
        }'''))
        level = lambda port: exposure.listener_item({**LISTEN, 'port': port}, NET, fw)['level']
        self.assertEqual(level(22), 'lan')          # open, but only private addresses here
        self.assertEqual(level(445), 'lan')
        self.assertEqual(level(9000), 'vpn')
        self.assertEqual(level(8000), 'blocked')


def _model(nft: dict) -> dict:
    return {'readable': True, 'backends': ['nftables'], 'zones': [], 'notes': [], 'nat': nft['nat'], 'rules': nft['rules'], 'chains': nft['chains'], 'policies': nft['policies']}


@unittest.skipUnless(HAS_NS and shutil.which('iptables-save') and shutil.which('iptables'), 'needs iptables and a user namespace')
class RealIptables(unittest.TestCase):
    def test_docker_shaped_rules_round_trip(self):
        out = in_ns('''iptables -P FORWARD DROP; iptables -N DOCKER; iptables -A FORWARD -o docker0 -j DOCKER
                       iptables -A DOCKER -d 172.17.0.2/32 ! -i docker0 -o docker0 -p tcp -m tcp --dport 80 -j ACCEPT
                       iptables -A DOCKER ! -i docker0 -o docker0 -j DROP; iptables-save''')
        fw = firewall.parse_iptables(out)
        self.assertEqual(fw['policies']['forward'], 'drop')
        rule = next(r for r in fw['rules'] if r['dports'])
        self.assertEqual((rule['daddr'], rule['not_iif'], rule['oif'], rule['dports'], rule['unmodelled']), ('172.17.0.2/32', 'docker0', 'docker0', [80], []))


class Exposure(unittest.TestCase):
    def fw(self, **sections):
        return firewall.model({'tools': ['iptables-save'] + (['ufw'] if 'ufw' in sections else []), **sections})

    def test_ufw_does_not_stop_a_published_port(self):
        """The reason this exists: ufw denies incoming and has no rule for 8080, and the port is open anyway."""
        fw = self.fw(iptables=DOCKER_RULES, ufw=UFW)
        self.assertEqual(exposure.listener_item({**LISTEN, 'port': 8080}, NET, fw)['level'], 'blocked')
        item = exposure.published_item(CONTAINER, CONTAINER['ports'][0], NET, fw, 'nas')
        self.assertEqual(item['level'], 'lan')
        self.assertTrue(item['bypasses_frontend'])
        self.assertIn('DOCKER', item['rule'])

    def test_a_docker_user_drop_does_stop_it(self):
        rules = DOCKER_RULES.replace('-A DOCKER-USER -j RETURN', '-A DOCKER-USER -p tcp -m tcp --dport 80 -j DROP')
        self.assertEqual(exposure.published_item(CONTAINER, CONTAINER['ports'][0], NET, self.fw(iptables=rules), 'nas')['level'], 'blocked')

    def test_published_on_loopback(self):
        port = {**CONTAINER['ports'][0], 'host_ip': '127.0.0.1'}
        self.assertEqual(exposure.published_item(CONTAINER, port, NET, None, 'nas')['level'], 'loopback')

    def test_nothing_read_is_unknown_never_closed(self):
        self.assertEqual(exposure.listener_item(LISTEN, NET, None)['level'], 'unknown')
        self.assertEqual(exposure.published_item(CONTAINER, CONTAINER['ports'][0], NET, None, 'nas')['level'], 'unknown')

    def test_an_unreadable_firewall_is_unknown(self):
        fw = firewall.model({'tools': ['nft'], 'nft': 'not json'})
        self.assertFalse(fw['readable'])
        self.assertEqual(exposure.listener_item(LISTEN, NET, fw)['level'], 'unknown')

    def test_a_loopback_bind_needs_no_firewall(self):
        self.assertEqual(exposure.listener_item({**LISTEN, 'addr': '127.0.0.1', 'scope': 'loopback'}, NET, None)['level'], 'loopback')

    def test_public_address_is_any(self):
        net = {'interfaces': [{'name': 'eth0', 'kind': 'ethernet', 'state': 'up', 'addresses': [{'ip': '8.8.8.8', 'prefix': 24}]}]}
        fw = firewall.model({'tools': ['nft'], 'nft': json.dumps({'nftables': []})})
        self.assertEqual(exposure.listener_item(LISTEN, net, fw)['level'], 'any')

    def test_ufw_source_limit_and_default(self):
        fw = self.fw(ufw=UFW)
        self.assertEqual(exposure.listener_item({**LISTEN, 'port': 445}, NET, fw)['level'], 'lan')
        self.assertEqual(exposure.listener_item({**LISTEN, 'port': 22}, NET, fw)['level'], 'lan')
        self.assertEqual(exposure.listener_item({**LISTEN, 'port': 9999}, NET, fw)['level'], 'blocked')

    def test_firewalld_zones(self):
        fw = firewall.model({'tools': ['firewall-cmd'], 'firewalld_state': 'running', 'firewalld': FIREWALLD})
        level = lambda port: exposure.listener_item({**LISTEN, 'port': port}, {'interfaces': NET['interfaces'][:2]}, fw)
        self.assertEqual(level(22)['level'], 'lan')
        self.assertEqual(level(8443)['level'], 'lan')
        self.assertEqual(level(9999)['level'], 'unknown')    # a rich rule it cannot read might allow it: not called closed

    def test_published_listener_is_not_listed_twice(self):
        net = {**NET, 'listeners': [{**LISTEN, 'port': 8080}, {**LISTEN, 'port': 22}], 'read_at': 1}
        report = exposure.host_report(net, {'firewall': self.fw(iptables=DOCKER_RULES, ufw=UFW)}, [CONTAINER], 'nas')
        self.assertEqual(sorted((i['kind'], i['port']) for i in report['items']), [('listener', 22), ('published', 8080)])

    def test_no_reading_says_so(self):
        self.assertFalse(exposure.host_report(None, None, [], 'nas')['read'])


class Parsers(unittest.TestCase):
    def test_hostile_text_never_raises(self):
        for fn in (firewall.parse_nft, firewall.parse_iptables, firewall.parse_ufw, firewall.parse_firewalld, netfacts.parse, netfacts.parse_listeners):
            for bad in ('', '{', '[1,2', '*filter\n-A\n', '-A X "unterminated', '\x00\xff', '{"nftables":[{"rule":{"expr":[{"match":{}}]}}]}'):
                try:
                    fn(bad)
                except (IndexError, AttributeError) as exc:
                    self.fail(f'{fn.__name__}({bad!r}): {exc}')

    def test_xml_with_entities_is_refused(self):
        bomb = '<!DOCTYPE d [<!ENTITY a "x">]><domain><name>&a;</name></domain>'
        self.assertIsNone(guests.parse_domain(bomb))
        self.assertEqual(guests.parse_libvirt([f'bad\trunning\tenable\t{base64.b64encode(bomb.encode()).decode()}'])[0]['unreadable'], True)

    def test_domain(self):
        xml = """<domain type='kvm'><name>web</name><uuid>u</uuid><memory unit='KiB'>2097152</memory><vcpu>2</vcpu><os firmware='efi'/>
          <seclabel type='none'/><devices>
          <disk type='file' device='disk'><driver type='qcow2'/><source file='/tank/vm/web.qcow2'/><target dev='vda' bus='virtio'/></disk>
          <disk type='file' device='cdrom'><source file='/iso/x.iso'/><target dev='sda' bus='sata'/><readonly/></disk>
          <interface type='bridge'><mac address='52:54:00:00:00:01'/><source bridge='br0'/><model type='virtio'/></interface>
          <graphics type='vnc' port='5900' listen='0.0.0.0' passwd='hunter2'/></devices></domain>"""
        vm = guests.parse_libvirt([f'web\trunning\tenable\t{base64.b64encode(xml.encode()).decode()}'])[0]
        self.assertEqual(vm['memory_mib'], 2048)
        self.assertEqual(vm['disks'][0]['source'], '/tank/vm/web.qcow2')
        self.assertNotIn('hunter2', json.dumps(vm))
        w = workloads.from_infra('nas', {'libvirt': [vm]}, [('/', 'ext4'), ('/tank', 'zfs')])[0]
        self.assertEqual(w['mounts'][0]['on'], {'mount': '/tank', 'filesystem': 'zfs'})
        self.assertEqual(len(w['mounts']), 1)     # the installer ISO is not where the VM lives
        joined = ' '.join(w['findings'])
        self.assertIn('0.0.0.0', joined)
        self.assertIn('unconfined', joined)
        self.assertIn('bridged', joined)

    def test_proxmox_and_incus(self):
        pve = guests.parse_proxmox(['g\tqemu\t100\tweb\trunning', 'c\tmemory: 4096', 'c\tcores: 2', 'c\tscsi0: local-lvm:vm-100-disk-0,size=32G', 'c\tnet0: virtio=AA:BB:CC:00:11:22,bridge=vmbr0,firewall=1',
                                    'g\tlxc\t101\tdb\tstopped', 'c\tunprivileged: 0'])
        self.assertEqual((pve[0]['memory_mib'], pve[0]['nics'][0]['source'], pve[0]['nics'][0]['mac']), (4096, 'vmbr0', 'AA:BB:CC:00:11:22'))
        w = workloads.from_infra('pve', {'proxmox': pve}, [])
        self.assertEqual(w[0]['managed_by'], 'proxmox')
        self.assertEqual(w[1]['findings'], ['privileged container'])
        dev = base64.b64encode(b'root:\n  path: /\n  pool: default\n  type: disk\n  secret: nope\n').decode()
        inc = guests.parse_incus(['i\tc1,RUNNING,CONTAINER,default,10.0.0.5 (eth0),0', f'd\tc1\t{dev}', 's\tc1\tsecurity.privileged\ttrue', 's\tc1\tother.key\tsecret'])
        self.assertEqual(inc[0]['devices']['root'], {'type': 'disk', 'path': '/', 'pool': 'default'})
        self.assertEqual(inc[0]['security'], {'security.privileged': 'true'})

    def test_the_measure_script_cannot_print_secrets(self):
        script = inframeasure.script()
        self.assertNotIn('.Config.Env', script)
        self.assertNotIn('--format json', script)
        self.assertNotIn('--security-info', script)
        self.assertEqual(subprocess.run(['bash', '-n'], input=script, text=True).returncode, 0)


@unittest.skipUnless(shutil.which('docker') and subprocess.run(['docker', 'info'], capture_output=True).returncode == 0, 'needs a Docker engine')
class RealDocker(unittest.TestCase):
    def test_container_with_no_healthcheck_keeps_its_details(self):
        """.State.Health is nil without a healthcheck, and that once lost the details of every such container."""
        name = f'sf-test-{int(time.time())}'
        ran = subprocess.run(['docker', 'run', '-d', '--rm', '--name', name, '-p', '127.0.0.1:0:80', '--cap-add', 'NET_ADMIN', '--read-only', '-e', 'SECRET_VALUE=hunter2', 'busybox', 'sleep', '60'], capture_output=True)
        if ran.returncode:
            self.skipTest('could not start a container here')
        self.addCleanup(subprocess.run, ['docker', 'rm', '-f', name], capture_output=True)
        out = subprocess.run(['sh', '-c', docker.ENGINE], capture_output=True, text=True).stdout
        self.assertNotIn('hunter2', out)
        c = next(x for x in docker.parse_engine(out)['containers'] if x['name'] == name)
        self.assertTrue(c['detail'])
        self.assertEqual(c['ports'][0]['host_ip'], '127.0.0.1')
        self.assertEqual(c['cap_add'], ['CAP_NET_ADMIN'] if 'CAP_NET_ADMIN' in c['cap_add'] else ['NET_ADMIN'])
        self.assertTrue(c['readonly_root'])
        self.assertEqual(c['networks'][0]['name'], 'bridge')
        self.assertIsNone(c['health'])


@unittest.skipUnless(HAS_NS and shutil.which('nft'), 'needs nft and a user namespace')
class ThroughTheRoutes(unittest.TestCase):
    """The measure script really runs, in a namespace with a real firewall. Only the signing and SSH are skipped: the lab has those."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = Database(f'sqlite:///{self.tmp.name}/x.db')
        self.conn = self.db.connect()
        self.addCleanup(self.conn.close)
        self.db.migrate(self.conn)
        users.create(self.conn, 'admin', PW, 'admin')
        self.conn.execute("INSERT INTO hosts (hostname, ssh_host, inventory_json) VALUES ('nas', 'nas', '{}')")
        hid = self.conn.scalar("SELECT host_id FROM hosts WHERE hostname = 'nas'")
        self.conn.execute("""INSERT INTO host_network (host_id, data_json, updated_at) VALUES (:h, :d, 1)""",
                          {'h': hid, 'd': json.dumps({**NET, 'listeners': [{**LISTEN, 'port': 22}, {**LISTEN, 'port': 8000}], 'unreadable': [], 'routes': [], 'neighbours': [], 'dns': {'nameservers': [], 'search': []}})})
        self.client = server.create_app(server.App(self.db), 's' * 48).test_client()
        self.assertEqual(self.client.post('/api/login', json={'username': 'admin', 'password': PW}).status_code, 200)

    def run_for_real(self, db, host, script, args, **kw):
        # ufw would refuse a namespace's fake root and make the reading unreadable, which is right on a real host
        stub = self.tmp.name + '/ufw'
        with open(stub, 'w') as f:
            f.write('#!/bin/sh\necho "Status: inactive"\n')
        subprocess.run(['chmod', '+x', stub])
        out = in_ns("nft -f - <<'EOF'\ntable inet f {\n chain input { type filter hook input priority 0; policy drop; tcp dport 22 accept; }\n}\nEOF\n"
                    + f'PATH={self.tmp.name}:$PATH bash -c {_quoted(script)}')
        return {'status': 'ok', 'output': out, 'run_id': 1}

    def test_measure_then_exposure(self):
        before = self.client.get('/api/exposure?host=nas').get_json()['hosts'][0]
        self.assertFalse(before['firewall_read'])
        self.assertEqual({i['level'] for i in before['items']}, {'unknown'})
        with mock.patch('storageforge_index.deploy.run', self.run_for_real):
            r = self.client.post('/api/infra/measure', json={'host': 'nas'})
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True))
        after = self.client.get('/api/exposure?host=nas').get_json()['hosts'][0]
        self.assertTrue(after['firewall_read'])
        self.assertEqual({i['port']: i['level'] for i in after['items']}, {22: 'lan', 8000: 'blocked'})
        fw = self.client.get('/api/firewall?host=nas').get_json()['firewall']
        self.assertIn('nftables', fw['backends'])
        self.assertEqual(self.client.get('/api/workloads?host=nas').get_json()['hosts'][0]['host'], 'nas')

    def test_a_failed_run_records_nothing(self):
        with mock.patch('storageforge_index.deploy.run', lambda *a, **k: {'status': 'failed', 'output': 'no', 'run_id': 2}):
            self.assertEqual(self.client.post('/api/infra/measure', json={'host': 'nas'}).status_code, 409)
        self.assertIsNone(inframeasure.reading(self.conn, 'nas'))
        with mock.patch('storageforge_index.deploy.run', lambda *a, **k: {'status': 'ok', 'output': '@@tools\nnft\n', 'run_id': 3}):
            self.assertEqual(self.client.post('/api/infra/measure', json={'host': 'nas'}).status_code, 409)
        self.assertIsNone(inframeasure.reading(self.conn, 'nas'))

    def test_tick_skips_hosts_turned_off_or_without_access(self):
        calls = []
        with mock.patch('storageforge_index.inframeasure.measure', lambda *a: calls.append(a[2]) or {'ok': True}):
            self.assertEqual(inframeasure.tick(self.db), 0)
            self.conn.execute("INSERT INTO deploy_access (host, state, updated_at) VALUES ('nas', 'ready', 1)")
            self.assertEqual(inframeasure.tick(self.db), 1)
            inframeasure.set_off(self.conn, 'nas', True, 'test')
            self.assertEqual(inframeasure.tick(self.db), 0)
        self.assertEqual(calls, ['nas'])

    def test_a_viewer_without_security_view_cannot_read_rules(self):
        users.save_role(self.conn, 'mapper', 'x', ['map.view', 'workloads.view'], 'test', True)
        users.create(self.conn, 'm', PW, 'mapper')
        c = server.create_app(server.App(self.db), 's' * 48).test_client()
        c.post('/api/login', json={'username': 'm', 'password': PW})
        self.assertEqual(c.get('/api/network?host=nas').status_code, 200)
        self.assertEqual(c.get('/api/firewall?host=nas').status_code, 403)
        self.assertEqual(c.get('/api/exposure').status_code, 403)


class TheMap(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = Database(f'sqlite:///{self.tmp.name}/x.db')
        self.conn = self.db.connect()
        self.addCleanup(self.conn.close)
        self.db.migrate(self.conn)
        users.create(self.conn, 'admin', PW, 'admin')
        for name, ip in (('nas-01', '192.168.1.10'), ('gw-01', '192.168.1.1')):
            self.conn.execute("INSERT INTO hosts (hostname, ssh_host, ip_address, inventory_json) VALUES (:n, :n, :i, '{}')", {'n': name, 'i': ip})
            self.conn.execute("""INSERT INTO graph_nodes (node_id, kind, label, host, updated_at) VALUES (:id, 'Host', :n, :n, 1)""", {'id': f'host:{name}', 'n': name})
        self.conn.execute("INSERT INTO graph_nodes (node_id, kind, label, host, updated_at) VALUES ('mnt:nas-01:/tank', 'MountPoint', '/tank', 'nas-01', 1)")
        self.conn.execute("INSERT INTO mounts (host_id, mount_point, filesystem_type) VALUES ((SELECT host_id FROM hosts WHERE hostname = 'nas-01'), '/tank', 'zfs')")
        self.net = {'interfaces': [
            {'name': 'lo', 'kind': 'loopback', 'state': 'unknown', 'addresses': [{'ip': '127.0.0.1', 'prefix': 8}]},
            {'name': 'eth0', 'kind': 'ethernet', 'state': 'up', 'mac': 'aa:bb:cc:dd:ee:01', 'master': 'br0', 'addresses': []},
            {'name': 'br0', 'kind': 'bridge', 'state': 'up', 'addresses': [{'ip': '192.168.1.10', 'prefix': 24}]},
            {'name': 'docker0', 'kind': 'bridge', 'state': 'up', 'addresses': [{'ip': '172.17.0.1', 'prefix': 16}]}],
            'routes': [], 'gateways': ['192.168.1.1'], 'neighbours': [{'ip': '192.168.1.50', 'mac': 'aa:bb:cc:dd:ee:02', 'dev': 'br0'}, {'ip': '172.17.0.2', 'mac': 'aa:bb:cc:dd:ee:03', 'dev': 'docker0'}],
            'listeners': [{'proto': 'tcp', 'addr': '0.0.0.0', 'port': 22, 'scope': 'any'}], 'dns': {'nameservers': ['192.168.1.1'], 'search': []}, 'unreadable': []}
        self.put_net()
        self.client = server.create_app(server.App(self.db), 's' * 48).test_client()
        self.assertEqual(self.client.post('/api/login', json={'username': 'admin', 'password': PW}).status_code, 200)

    def put_net(self):
        hid = self.conn.scalar("SELECT host_id FROM hosts WHERE hostname = 'nas-01'")
        self.conn.execute('DELETE FROM host_network WHERE host_id = :h', {'h': hid})
        self.conn.execute('INSERT INTO host_network (host_id, data_json, updated_at) VALUES (:h, :d, 1)', {'h': hid, 'd': json.dumps(self.net)})

    def rebuild(self):
        from storageforge_index import infragraph
        return infragraph.rebuild(self.conn, 'nas-01')

    def graph(self):
        return self.client.get('/api/map').get_json()

    def test_what_is_certain_confirmed_and_inferred(self):
        self.rebuild()
        g = self.graph()
        nodes = {n['id']: n for n in g['nodes']}
        self.assertEqual(nodes['nic:nas-01:br0']['confidence'], 'certain')
        self.assertEqual(nodes['subnet:192.168.1.0/24']['confidence'], 'inferred')
        self.assertTrue(nodes['ph:192.168.1.50']['props']['placeholder'])
        self.assertIsNone(nodes['ph:192.168.1.50']['host'])
        self.assertNotIn('subnet:172.17.0.0/16', nodes)       # every Docker host has this one, and it joins nothing
        self.assertNotIn('ph:172.17.0.2', nodes)              # a container on this machine is not a device nearby
        edges = {(e['src'], e['dst'], e['rel']): e for e in g['edges']}
        route = edges[('host:nas-01', 'host:gw-01', 'ROUTES_VIA')]
        self.assertEqual(route['props']['confidence'], 'confirmed')
        self.assertIn('192.168.1.1', route['props']['evidence']['source'])
        self.assertIn(('nic:nas-01:eth0', 'nic:nas-01:br0', 'MEMBER_OF'), edges)

    def test_storage_views_see_only_storage(self):
        self.rebuild()
        got = self.client.get('/api/graph').get_json()
        self.assertEqual({n['kind'] for n in got['nodes']}, {'Host', 'MountPoint'})
        self.assertNotIn('layer', got['nodes'][0])

    def test_rebuilding_storage_leaves_the_other_layers(self):
        from storageforge_index import graph
        self.rebuild()
        graph.save(self.db, self.conn, 'nas-01', {'host:nas-01': {'id': 'host:nas-01', 'kind': 'Host', 'label': 'nas-01', 'host': 'nas-01', 'health': 'unknown', 'props': {}}}, [])
        self.assertIn('nic:nas-01:br0', {n['id'] for n in self.graph()['nodes']})

    def test_a_change_is_noted_once_and_alerts(self):
        from storageforge_index import alerts, infragraph
        self.rebuild()
        self.rebuild()
        self.assertEqual(len(infragraph.timeline(self.conn, 'nas-01')), 1)
        self.net['listeners'].append({'proto': 'tcp', 'addr': '0.0.0.0', 'port': 2375, 'scope': 'any'})
        self.put_net()
        self.rebuild()
        changes = infragraph.timeline(self.conn, 'nas-01')
        self.assertEqual(changes[0]['added'], ['lsn:nas-01:tcp:2375'])
        self.assertEqual(self.client.get('/api/map/snapshots?host=nas-01').get_json()['changes'][0]['added'], ['lsn:nas-01:tcp:2375'])
        self.assertTrue(any('2375' in k for k in alerts.problems(self.conn)))

    def test_redaction_leaves_no_name_address_or_mac_in_any_format(self):
        self.rebuild()
        for fmt in ('json', 'mermaid', 'dot'):
            out = self.client.get(f'/api/map/export?format={fmt}&redact=1').get_data(as_text=True)
            for secret in ('nas-01', 'gw-01', '192.168', '172.17', 'aa:bb:cc'):
                self.assertNotIn(secret, out, fmt)
        out = self.client.get('/api/map/export?format=dot').get_data(as_text=True)
        self.assertIn('nas-01', out)
        self.assertEqual(self.conn.scalar("SELECT count(*) FROM audit_log WHERE action = 'map.export'"), 4)

    def test_hostile_labels_cannot_break_out_of_an_export(self):
        from storageforge_index import mapexport
        g = {'nodes': [{'id': 'a', 'kind': 'NIC', 'label': 'x"]; evil[" {}\n<script>'}], 'edges': []}
        self.assertNotIn('<script>', mapexport.mermaid(g))
        self.assertEqual(mapexport.dot(g).count('"'), 2)

    def test_views_are_kept_and_plain(self):
        self.assertEqual(self.client.post('/api/map/views', json={'name': 'mine', 'layers': ['network'], 'filter': 'x', 'other': 'dropped'}).status_code, 200)
        v = self.client.get('/api/map/views').get_json()['views'][0]
        self.assertEqual(v['body'], {'layers': ['network'], 'filter': 'x'})
        self.assertEqual(self.client.post('/api/map/views', json={'name': '<b>'}).status_code, 400)
        self.assertEqual(self.client.delete(f'/api/map/views/{v["id"]}').status_code, 200)

    def test_without_security_view_the_map_keeps_quiet(self):
        self.rebuild()
        users.save_role(self.conn, 'mapper', 'x', ['map.view'], 'test', True)
        users.create(self.conn, 'm', PW, 'mapper')
        c = server.create_app(server.App(self.db), 's' * 48).test_client()
        c.post('/api/login', json={'username': 'm', 'password': PW})
        g = c.get('/api/map').get_json()
        self.assertTrue(g['nodes'])
        self.assertFalse([n for n in g['nodes'] if n['kind'] == 'FirewallPolicy' or 'exposure' in n['props']])

    def test_retiring_a_host_takes_its_layers(self):
        self.rebuild()
        self.conn.execute("DELETE FROM graph_nodes WHERE lower(host) = lower('nas-01')")
        self.assertFalse([n for n in self.graph()['nodes'] if n['host'] == 'nas-01'])
