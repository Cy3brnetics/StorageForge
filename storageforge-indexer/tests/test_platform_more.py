"""Firewall writer, path queries, what-if, designs, and the operator's security policy. The writer runs for real against real nft and
iptables in a throwaway network namespace, a token's signatures are made with a real key, and evidence is checked with ssh-keygen."""
import base64
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import time
import unittest
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from storageforge_index import alerts, changes, deploy, exposure, firewall, infragraph, inframeasure, mapdesign, mapexport, netfacts, reach, secplus, security, steps_infra, webauthn, whatif
from test_security import PW, Base

NS = ['unshare', '--user', '--map-root-user', '--net']
HAS_NS = bool(shutil.which('unshare') and subprocess.run(NS + ['true'], capture_output=True).returncode == 0)
HAS_NFT = HAS_NS and bool(shutil.which('nft')) and subprocess.run(NS + ['nft', 'list', 'tables'], capture_output=True).returncode == 0
HAS_IPT = HAS_NS and bool(shutil.which('iptables')) and subprocess.run(NS + ['iptables', '-S'], capture_output=True).returncode == 0

NET = {'interfaces': [{'name': 'lo', 'kind': 'loopback', 'state': 'unknown', 'addresses': [{'ip': '127.0.0.1', 'prefix': 8}]},
                      {'name': 'eth0', 'kind': 'ethernet', 'state': 'up', 'addresses': [{'ip': '192.168.1.10', 'prefix': 24}]},
                      {'name': 'docker0', 'kind': 'bridge', 'state': 'up', 'addresses': [{'ip': '172.17.0.1', 'prefix': 16}]}],
       'routes': [{'dst': 'default', 'via': '192.168.1.1', 'dev': 'eth0', 'metric': 100, 'family': 4}, {'dst': '192.168.1.0/24', 'via': None, 'dev': 'eth0', 'metric': 100, 'family': 4}],
       'listeners': [{'proto': 'tcp', 'addr': '0.0.0.0', 'port': 22, 'scope': 'any'}, {'proto': 'tcp', 'addr': '0.0.0.0', 'port': 445, 'scope': 'any'}, {'proto': 'tcp', 'addr': '127.0.0.1', 'port': 5432, 'scope': 'loopback'}],
       'gateways': ['192.168.1.1'], 'dns': {'nameservers': []}, 'neighbours': [], 'unreadable': []}
UFW = """Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), disabled (routed)
New profiles: skip

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW IN    Anywhere
445/tcp                    ALLOW IN    10.0.20.0/24               # sf-rule-abc
"""


def ufw_fw():
    return firewall.model({'tools': ['ufw'], 'ufw': UFW})


def host(ip: str, fw=None, listeners=None, containers=None) -> dict:
    net = json.loads(json.dumps(NET))
    net['interfaces'][1]['addresses'][0]['ip'] = ip
    if listeners is not None:
        net['listeners'] = listeners
    return {'net': net, 'infra': {'firewall': fw} if fw else None, 'containers': containers or []}


@unittest.skipUnless(HAS_NFT, 'needs nft in a user namespace')
class WriterOnRealNftables(unittest.TestCase):
    """The program that goes on hosts, against the kernel. Each test is its own network namespace."""

    def run_ns(self, script: str) -> str:
        d = self.tmp
        (d / 'fw').write_text(steps_infra.FWRULES)
        (d / 'fw').chmod(0o755)
        r = subprocess.run(NS + ['bash', '-c', f'set -u; export SF_FW_DIR={d}/etc; FW={d}/fw\n' + script], capture_output=True, text=True, timeout=60, env={**os.environ, 'PATH': f'{os.environ["PATH"]}:/usr/sbin:/sbin'})
        return r.stdout + r.stderr

    def setUp(self):
        import pathlib
        import tempfile
        self.tmp = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def test_a_deny_goes_in_its_own_table_and_comes_back_out(self):
        out = self.run_ns("""$FW ensure a1 deny tcp 445 10.0.0.0/8 - input || echo FAIL
            $FW has a1 deny tcp 445 10.0.0.0/8 - input && echo HAS; nft list ruleset
            $FW remove a1 deny tcp 445 10.0.0.0/8 - input; $FW has a1 deny tcp 445 10.0.0.0/8 - input || echo GONE""")
        self.assertIn('HAS', out)
        self.assertIn('ip saddr 10.0.0.0/8 tcp dport 445 drop comment "sf-rule-a1"', out)
        self.assertIn('GONE', out)
        self.assertNotIn('FAIL', out)

    def test_an_allow_goes_in_the_chain_that_would_have_dropped_it(self):
        out = self.run_ns("""nft 'add table inet filter; add chain inet filter input { type filter hook input priority 0; policy drop; }'
            echo "backend $($FW backend)"
            $FW ensure b1 allow tcp 8443 10.0.0.0/24 - input || echo FAIL; nft list table inet filter
            $FW ensure b1 allow tcp 8443 10.0.0.0/24 - input; nft list table inet filter | grep -c sf-rule-b1
            $FW remove b1 allow tcp 8443 10.0.0.0/24 - input; nft list table inet filter | grep -c sf-rule-b1 || echo GONE""")
        self.assertIn('backend nftables', out)
        self.assertIn('ip saddr 10.0.0.0/24 tcp dport 8443 accept comment "sf-rule-b1"', out)
        self.assertRegex(out, r'\n1\n', 'a second ensure added a second rule')
        self.assertIn('GONE', out)

    def test_the_model_reads_what_the_writer_wrote(self):
        js = self.run_ns("""nft 'add table inet filter; add chain inet filter input { type filter hook input priority 0; policy drop; }'
            $FW ensure b1 allow tcp 8443 10.0.0.0/24 - input; nft -j list ruleset""")
        fw = firewall.model({'tools': ['nft'], 'nft': js[js.index('{'):]})
        got = exposure.kernel_path(fw, 'input', {'proto': 'tcp', 'port': 8443, 'iif': 'eth0', 'family': 'ip', 'saddr': '10.0.0.5'})
        self.assertEqual(got['verdict'], 'accept')
        self.assertEqual(exposure.kernel_path(fw, 'input', {'proto': 'tcp', 'port': 8443, 'iif': 'eth0', 'family': 'ip', 'saddr': '192.168.1.1'})['verdict'], 'drop')

    def test_a_fence_lets_in_only_its_clients_and_the_model_says_so(self):
        js = self.run_ns("""$FW fence-set finance 445,139 10.0.20.0/24,fd00::/64 - || echo FAIL; nft list table inet storageforge_shares; nft -j list ruleset
            """)
        self.assertNotIn('FAIL', js)
        self.assertIn('ip saddr != 10.0.20.0/24 drop', js)
        self.assertIn('ip6 saddr != fd00::/64 drop', js)
        fw = firewall.model({'tools': ['nft'], 'nft': js[js.index('{"nftables"'):]})
        net = {**NET}
        item = exposure.listener_item({'proto': 'tcp', 'addr': '0.0.0.0', 'port': 445, 'scope': 'any'}, net, fw)
        self.assertEqual(item['level'], 'lan')
        self.assertEqual(item['fenced_to'], ['10.0.20.0/24'])
        self.assertEqual(exposure.listener_item({'proto': 'tcp', 'addr': '0.0.0.0', 'port': 80, 'scope': 'any'}, net, fw)['level'], 'lan', 'it fences its own ports, and only those')

    def test_a_second_fence_replaces_nothing_and_the_last_takes_the_table(self):
        out = self.run_ns("""$FW fence-set a 445 10.0.0.0/8 -; $FW fence-set b 2049 192.168.0.0/16 eth1; nft list table inet storageforge_shares
            $FW fence-has a 445 10.0.0.0/8 - && echo HAS-A; $FW fence-has a 445 10.9.0.0/16 - || echo DIFFERENT
            $FW fence-del a; $FW fence-del b; nft list tables | grep -c storageforge_shares || echo TAKEN-DOWN""")
        self.assertIn('10.0.0.0/8', out)
        self.assertIn('iifname != "eth1"', out)
        self.assertIn('HAS-A', out)
        self.assertIn('DIFFERENT', out)
        self.assertIn('TAKEN-DOWN', out)

    def test_a_rejected_fence_changes_nothing(self):
        out = self.run_ns("""$FW fence-set a 445 10.0.0.0/8 -; $FW fence-set b 445 not-an-address - || echo REFUSED; nft list table inet storageforge_shares""")
        self.assertIn('REFUSED', out)
        self.assertIn('10.0.0.0/8', out)

    def test_the_rollback_journal_undoes_in_reverse(self):
        out = self.run_ns("""$FW note "echo first"; $FW note "echo second"; $FW revert; test -e $SF_FW_DIR/journal || echo CLEAN""")
        self.assertLess(out.index('second'), out.index('first'))
        self.assertIn('FW-ROLLBACK reverted', out)
        self.assertIn('CLEAN', out)


@unittest.skipUnless(HAS_IPT, 'needs iptables in a user namespace')
class WriterOnRealIptables(unittest.TestCase):
    def run_ns(self, script: str) -> str:
        import pathlib
        import tempfile
        d = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d, True)
        (d / 'fw').write_text(steps_infra.FWRULES)
        (d / 'fw').chmod(0o755)
        (d / 'bin').mkdir()
        (d / 'bin' / 'nft').write_text('#!/bin/sh\nexit 127\n')      # a host that has only iptables
        (d / 'bin' / 'nft').chmod(0o755)
        r = subprocess.run(NS + ['bash', '-c', f'set -u; export SF_FW_DIR={d}/etc; FW={d}/fw\n' + script], capture_output=True, text=True, timeout=60, env={**os.environ})
        return r.stdout + r.stderr

    def test_a_published_port_goes_through_docker_user_by_the_number_it_was_published_on(self):
        out = self.run_ns("""iptables -N DOCKER-USER; iptables -A FORWARD -j DOCKER-USER
            $FW ensure c1 deny tcp 8080 - - forward || echo FAIL; iptables-save
            $FW has c1 deny tcp 8080 - - forward && echo HAS; $FW remove c1 deny tcp 8080 - - forward; $FW has c1 deny tcp 8080 - - forward || echo GONE""")
        self.assertNotIn('FAIL', out)
        self.assertIn('--ctorigdstport 8080', out)
        self.assertIn('-j DROP', out)
        self.assertIn('HAS', out)
        self.assertIn('GONE', out)
        text = out[out.index('# Generated') if '# Generated' in out else 0:]
        rule = next(r for r in firewall.parse_iptables(text)['rules'] if r.get('orig_dports'))
        self.assertEqual(rule['orig_dports'], [8080])
        self.assertFalse(rule['unmodelled'], rule)


class ChangePlanSteps(unittest.TestCase):
    def test_every_step_has_all_of_what_a_step_needs(self):
        for kind in changes.EXTRA:
            self.assertIn(kind, changes.ARGS, kind)
            self.assertIn(f't_{kind.replace("-", "_")}()', steps_infra.BASH, kind)

    def test_the_whole_script_parses(self):
        p = subprocess.run(['bash', '-n'], input=steps_infra.BASH, text=True, capture_output=True)
        self.assertEqual(p.stderr, '')

    def test_bad_values_are_refused_before_any_script(self):
        for kind, params in (('fw-rule', {'action': 'allow', 'proto': 'tcp', 'port': '22; rm -rf /'}), ('fw-fence', {'name': 'a', 'service': 'smb', 'clients': '1.2.3.4/8 && id'}), ('sysctl-set', {'key': 'a b', 'value': '1'}),
                             ('wg-peer', {'iface': 'wg0', 'pubkey': 'notakey', 'allowed': '10.0.0.1/32'}), ('container', {'runtime': 'docker', 'name': 'a', 'image': 'x$(id)'})):
            with self.assertRaises(ValueError, msg=kind):
                changes.normalize({'name': 'p', 'tasks': [{'type': kind, 'host': 'nas', 'params': params}]})

    def test_the_rollback_comes_with_a_second_run_that_stops_it(self):
        self.assertIn('storageforge-fwrules confirm', steps_infra.CONFIRM_SCRIPT)
        self.assertIn('FW-ROLLBACK armed', steps_infra.FWRULES)

    # SF-65: the sshd-option and apparmor-local steps kept a tool's complaint in /tmp/sf-sshd.err and /tmp/sf-aa.err, names any local account could have made first
    OLD_NAMES = ('/tmp/sf-sshd.err', '/tmp/sf-aa.err')

    def run_step(self, fn, args, setup):
        """The step's own text, with the system folders pointed at a scratch one and stand-ins for the tools that reject the change. Returns (output, the text of what is left in its temp folder)."""
        import stat
        import tempfile
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            (root / 'bin').mkdir()
            (root / 'tmp').mkdir()
            for name in ('sshd', 'apparmor_parser'):
                tool = root / 'bin' / name
                tool.write_text('#!/bin/bash\n[[ $1 == -T ]] && exit 0\necho "STUBERR from ' + name + '" >&2\nexit 1\n')
                tool.chmod(tool.stat().st_mode | stat.S_IEXEC)
            setup(root)
            body = re.search(rf'^{fn}\(\) \{{.*?^\}}$', steps_infra.BASH, re.M | re.S)[0].replace('/etc/ssh', f'{root}/ssh').replace('/etc/apparmor.d', f'{root}/aa')
            script = ('STAMP=1; APPLY=1; ok() { echo "ok: $*"; }; conflict() { echo "conflict: $*"; }; act() { return 0; }; try() { "$@"; }; durable() { :; }; fw_tool() { :; }; fw_arm() { :; }\n'
                      + body + f'\n{fn} {args}\n')
            p = subprocess.run(['bash', '-c', script], capture_output=True, text=True, env={'PATH': f'{root}/bin:' + os.environ['PATH'], 'TMPDIR': str(root / 'tmp')}, timeout=30)
            return p.stdout + p.stderr, [x.read_text() for x in sorted((root / 'tmp').iterdir())]

    def test_no_step_names_a_fixed_file_in_tmp(self):
        for old in self.OLD_NAMES:
            self.assertNotIn(old, steps_infra.BASH)
        self.assertNotRegex(steps_infra.BASH, r'>\s*/tmp/sf-|2>\s*/tmp/sf-')

    def test_a_rejected_change_reports_the_tools_words_and_leaves_a_pre_made_file_alone(self):
        planted, made = {}, []
        for old in self.OLD_NAMES:
            path = Path(old)
            if not path.exists():
                path.write_text('PLANTED by another account\n')
                made.append(path)
                self.addCleanup(path.unlink, True)
            planted[old] = path.read_bytes()

        def ssh(root):
            (root / 'ssh').mkdir()
            (root / 'ssh' / 'sshd_config').write_text('Include /etc/ssh/sshd_config.d/*.conf\n')

        def aa(root):
            (root / 'aa' / 'local').mkdir(parents=True)
            (root / 'aa' / 'usr.sbin.test').write_text('profile test {}\n')
        out, left = self.run_step('t_sshd_option', 'AllowTcpForwarding no 10', ssh)
        self.assertIn('conflict: sshd -t rejected it, so it was put back: STUBERR from sshd', out)
        self.assertEqual(left, [], 'the error file is taken away again')
        out, left = self.run_step('t_apparmor_local', 'usr.sbin.test "/srv/** r,"', aa)
        self.assertIn('conflict: apparmor_parser rejected it, so it was put back: STUBERR from apparmor_parser', out)
        self.assertFalse([x for x in left if 'STUBERR' in x], 'the error file is taken away again (the step\'s own copy of the profile may stay)')
        for old, was in planted.items():
            self.assertEqual(Path(old).read_bytes(), was, f'{old} was written to')


class Reach(unittest.TestCase):
    def fleet(self, **hosts):
        return reach.Fleet(hosts)

    def test_a_listener_behind_ufw_is_decided_by_the_rule_that_decides_it(self):
        f = self.fleet(a=host('192.168.1.20', firewall.model({'tools': []})), b=host('192.168.1.10', ufw_fw()))
        self.assertEqual(reach.query(f, 'a', 'b', 22)['verdict'], 'allowed')
        no = reach.query(f, 'a', 'b', 8080)
        self.assertEqual(no['verdict'], 'blocked')
        self.assertIn('nothing listens', no['decided_by'])

    def test_a_named_source_gets_in_and_another_does_not(self):
        f = self.fleet(a=host('10.0.20.5', firewall.model({'tools': []})), c=host('10.0.30.5', firewall.model({'tools': []})), b=host('192.168.1.10', ufw_fw()))
        self.assertEqual(reach.query(f, '10.0.20.5', 'b', 445)['verdict'], 'allowed')
        self.assertEqual(reach.query(f, '10.0.30.5', 'b', 445)['verdict'], 'blocked')

    def test_a_router_nobody_scanned_is_a_blind_spot_not_a_yes(self):
        other = host('10.9.9.9', firewall.model({'tools': []}))
        f = self.fleet(a=host('192.168.1.20', firewall.model({'tools': []})), b=other)
        got = reach.query(f, 'a', '10.9.9.9', 22)
        self.assertTrue(any('192.168.1.1' in b for b in got['blind_spots']), got)

    def test_unread_rules_are_unknown_never_blocked(self):
        f = self.fleet(a=host('192.168.1.20'), b=host('192.168.1.10'))
        got = reach.query(f, 'a', 'b', 22)
        self.assertEqual(got['verdict'], 'unknown')
        self.assertTrue(got['blind_spots'])

    def test_an_unknown_name_says_so(self):
        self.assertEqual(reach.query(self.fleet(), 'a', 'nowhere', 22)['verdict'], 'unknown')

    def test_a_port_published_past_ufw_is_allowed_and_says_so(self):
        rules = """*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
:DOCKER - [0:0]
-A FORWARD -o docker0 -j DOCKER
-A DOCKER -d 172.17.0.2/32 ! -i docker0 -o docker0 -p tcp -m tcp --dport 80 -j ACCEPT
COMMIT
"""
        c = {'name': 'web', 'state': 'running', 'ports': [{'proto': 'tcp', 'host_ip': '0.0.0.0', 'host_port': 8080, 'port': 80}], 'networks': [{'ip': '172.17.0.2', 'gateway': '172.17.0.1'}]}
        fw = firewall.model({'tools': ['ufw', 'iptables'], 'ufw': UFW, 'iptables': rules})
        f = self.fleet(a=host('192.168.1.20', firewall.model({'tools': []})), b=host('192.168.1.10', fw, containers=[c]))
        got = reach.query(f, 'a', 'b', 8080)
        self.assertEqual(got['verdict'], 'allowed', got)
        self.assertTrue(got['bypasses_frontend'])
        self.assertEqual(reach.query(f, 'a', 'web', 80)['verdict'], 'allowed')


class AccessLayer(unittest.TestCase):
    KEY = 'A' * 43 + '='
    KEY2 = 'B' * 43 + '='

    def test_a_private_key_never_has_a_way_in(self):
        code = '\n'.join(line for line in inframeasure.BODY.splitlines() if not line.lstrip().startswith('#'))
        for word in ('" dump', 'showconf', 'preshared', 'private'):
            self.assertNotIn(word, code)
        got = inframeasure.parse_wireguard([f'i\twg0\t{self.KEY}\t51820', f'e\twg0\t{self.KEY2}\t1.2.3.4:51820', f'a\twg0\t{self.KEY2}\t10.8.0.2/32', f'h\twg0\t{self.KEY2}\t1700000000', 'i\twg1\tnot a key\t1'])
        self.assertEqual([i['name'] for i in got], ['wg0'])
        self.assertEqual(got[0]['peers'][0]['endpoint'], '1.2.3.4:51820')

    def test_proxy_files_give_up_only_sites_and_upstreams(self):
        got = inframeasure.parse_proxy_routes(['example.org {', '  reverse_proxy 127.0.0.1:8080'], ['  server_name a.example;', '  proxy_pass http://10.0.0.5:9000;'])
        self.assertEqual([r['upstream'] for r in got], ['127.0.0.1:8080', 'http://10.0.0.5:9000'])

    def test_a_peer_with_a_key_another_host_holds_is_confirmed_and_any_other_is_a_placeholder(self):
        infra = {'access': {'wireguard': [{'name': 'wg0', 'public_key': self.KEY, 'listen_port': 51820, 'peers': [{'public_key': self.KEY2, 'allowed_ips': ['10.8.0.2/32'], 'endpoint': None, 'handshake': None}, {'public_key': 'C' * 43 + '=', 'allowed_ips': [], 'endpoint': None, 'handshake': None}]}], 'tailscale': None, 'proxy_routes': [], 'units': []}, 'storage_clients': []}
        nodes, edges = infragraph.build('a', None, infra, [], [], {}, set(), {self.KEY2: ('b', 'wg0')})
        peers = [e for e in edges if e['rel'] == 'PEERS_WITH']
        self.assertTrue(any(e['dst'] == 'vpn:b:wg0' and e['props']['confidence'] == 'confirmed' for e in peers))
        unknown = next(n for n in nodes.values() if n['kind'] == 'Peer')
        self.assertTrue(unknown['props']['placeholder'])
        self.assertEqual(unknown['confidence'], 'inferred')

    def test_a_neighbour_says_who_made_it_when_that_is_known(self):
        net = {**NET, 'neighbours': [{'ip': '192.168.1.77', 'mac': '52:54:00:11:22:33', 'dev': 'eth0'}]}
        nodes, _ = infragraph.build('a', net, None, [], [], {}, set())
        self.assertEqual(nodes['ph:192.168.1.77']['props']['vendor'], 'QEMU/KVM')


class Exports(unittest.TestCase):
    G = {'nodes': [{'id': 'host:nas-01', 'kind': 'Host', 'label': 'nas-01', 'host': 'nas-01', 'confidence': 'certain', 'props': {}}, {'id': 'nic:nas-01:eth0', 'kind': 'NIC', 'label': 'eth0', 'host': 'nas-01', 'confidence': 'certain', 'props': {'addresses': ['192.168.1.10/24'], 'mac': '52:54:00:11:22:33'}},
                   {'id': 'ph:192.168.1.1', 'kind': 'Gateway', 'label': '192.168.1.1', 'host': None, 'confidence': 'inferred', 'props': {'placeholder': True, 'seen_as': 'default gateway of nas-01'}}],
         'edges': [{'src': 'nic:nas-01:eth0', 'dst': 'host:nas-01', 'rel': 'ATTACHED_TO', 'props': {'evidence': {'host': 'nas-01', 'source': 'ip link'}}}, {'src': 'host:nas-01', 'dst': 'ph:192.168.1.1', 'rel': 'ROUTES_VIA', 'props': {'confidence': 'inferred', 'evidence': {'source': 'ip route: default via 192.168.1.1'}}}]}

    def test_each_format_renders_and_a_redacted_one_gives_nothing_away(self):
        for fmt, (_, _, render) in mapexport.FORMATS.items():
            text = render(mapexport.redact(self.G))
            self.assertTrue(text.strip(), fmt)
            for leak in ('nas-01', '192.168.1', '52:54:00'):
                self.assertNotIn(leak, text, fmt)

    def test_the_xml_ones_are_xml_even_with_hostile_labels(self):
        g = {'nodes': [{'id': 'a', 'kind': 'Host', 'label': '<script>&"', 'host': 'a', 'props': {}}], 'edges': []}
        for render in (mapexport.svg, mapexport.drawio):
            ET.fromstring(render(g))


class Designs(Base):
    DOC = {'hosts': [{'name': 'nas', 'networks': [{'kind': 'bridge', 'name': 'br9', 'address': '10.0.5.1/24'}], 'workloads': [{'kind': 'container', 'runtime': 'docker', 'name': 'web', 'image': 'nginx:1.27', 'publish': '127.0.0.1:8080:80'}, {'kind': 'vm', 'name': 'db', 'disk': '/tank/db.qcow2'}],
                      'firewall': [{'action': 'allow', 'proto': 'tcp', 'port': '445', 'source': '10.0.20.0/24'}]}, {'name': 'not-yet', 'planned': True, 'workloads': [{'kind': 'container', 'runtime': 'podman', 'name': 'app', 'image': 'app:1'}]}]}

    def facts(self):
        hid = self.conn.scalar("SELECT host_id FROM hosts WHERE hostname = 'nas'")
        net = {**NET, 'interfaces': NET['interfaces'] + [{'name': 'br9', 'kind': 'bridge', 'state': 'up', 'addresses': [{'ip': '10.0.5.1', 'prefix': 24}]}]}
        self.conn.execute('INSERT INTO host_network (host_id, data_json, scan_id, updated_at) VALUES (:h, :d, 1, 1)', {'h': hid, 'd': json.dumps(net)})

    def test_half_deployed_lists_exactly_the_other_half(self):
        self.facts()
        got = mapdesign.compare(self.conn, mapdesign.normalize(self.DOC))
        missing = {(m['host'], m['kind'], m['what']) for m in got['missing']}
        self.assertIn(('nas', 'container', 'web'), missing)
        self.assertIn(('nas', 'vm', 'db'), missing)
        self.assertIn(('not-yet', 'host', 'not-yet'), missing)
        self.assertNotIn(('nas', 'bridge', 'br9'), missing)
        self.assertIn(('nas', 'bridge', 'br9'), {(m['host'], m['kind'], m['what']) for m in got['there']})
        self.assertEqual([u['kind'] for u in got['unknown']], ['rule'], 'an unread firewall is not known, and not missing')

    def test_what_is_staged_is_what_is_missing(self):
        self.facts()
        tasks = mapdesign.missing_tasks(self.conn, mapdesign.normalize(self.DOC))
        self.assertEqual(sorted(t['type'] for t in tasks), ['container', 'container', 'vm'])
        changes.normalize({'name': 'x', 'tasks': tasks})

    def test_a_bad_value_in_a_design_is_refused(self):
        with self.assertRaises(ValueError):
            mapdesign.normalize({'hosts': [{'name': 'nas', 'workloads': [{'kind': 'container', 'runtime': 'docker', 'name': 'a b', 'image': 'x'}]}]})

    def test_exports_hold_values_as_data(self):
        doc = mapdesign.normalize(self.DOC)
        doc['hosts'][0]['workloads'][0]['image'] = 'x${path.root}%{if}'
        tf = mapdesign.terraform(doc)
        self.assertIn('$${path.root}%%{if}', tf)
        self.assertIn('kreuzwerker/docker', tf)
        self.assertIn('Not here', tf)
        doc['hosts'][0]['workloads'][0]['image'] = "x'; exec { 'bad': }"
        pp = mapdesign.puppet(doc)
        self.assertIn("x\\'; exec", pp)

    def test_bash_and_ansible_come_from_the_same_plan(self):
        self.client.post('/api/map/designs', json={'name': 'd1', 'doc': self.DOC})
        did = self.conn.scalar("SELECT id FROM map_designs WHERE name = 'd1'")
        for target, word in (('bash', 't_net_bridge'), ('ansible', 'community.docker.docker_container'), ('terraform', 'docker_container'), ('puppet', 'docker::run')):
            r = self.client.get(f'/api/map/designs/{did}/export?target={target}')
            self.assertEqual(r.status_code, 200)
            self.assertIn(word, r.get_data(as_text=True), target)


class WhatIf(Base):
    def facts(self, fw):
        hid = self.conn.scalar("SELECT host_id FROM hosts WHERE hostname = 'nas'")
        self.conn.execute("UPDATE hosts SET ssh_host = '192.168.1.10', ip_address = '192.168.1.10' WHERE host_id = :h", {'h': hid})
        self.conn.execute('INSERT INTO host_network (host_id, data_json, scan_id, updated_at) VALUES (:h, :d, 1, 1)', {'h': hid, 'd': json.dumps(NET)})
        security._save_measurement(self.conn, 'nas', 'infra', int(time.time()), 'test', {'firewall': fw, 'listeners': NET['listeners'], 'storage_clients': [], 'libvirt': [], 'incus': [], 'lxc': [], 'proxmox': [], 'podman_rootless': []})

    def run_it(self, *tasks, **kw):
        with mock.patch.object(security, '_controller_ips', return_value=['192.168.1.5']):
            return whatif.run(self.conn, {'tasks': [{'host': 'nas', **t} for t in tasks], **kw})

    def test_cutting_ssh_is_blocked_unless_a_timer_is_staged(self):
        self.facts(ufw_fw())
        step = {'type': 'fw-rule', 'params': {'action': 'deny', 'proto': 'tcp', 'port': '22'}}
        got = self.run_it(step)
        self.assertTrue(got['blocked'], got['conflicts'])
        self.assertIn('how StorageForge reaches it', got['conflicts'][0]['text'])
        got = self.run_it({'type': 'fw-rule', 'params': {'action': 'deny', 'proto': 'tcp', 'port': '22', 'rollback': '10'}})
        self.assertFalse(got['blocked'])
        self.assertEqual(got['conflicts'][0]['level'], 'warn')

    def test_a_host_with_no_firewall_is_still_cut_by_a_deny(self):
        self.facts(firewall.model({'tools': []}))
        got = self.run_it({'type': 'fw-rule', 'params': {'action': 'deny', 'proto': 'tcp', 'port': '22'}})
        self.assertTrue(got['blocked'], got['conflicts'])

    def test_moving_the_interface_ssh_comes_in_on_is_blocked_unless_a_timer_is_staged(self):
        self.facts(ufw_fw())
        got = self.run_it({'type': 'net-bridge', 'params': {'name': 'br1', 'ports': 'eth0'}})
        self.assertTrue(got['blocked'], got['conflicts'])
        self.assertIn('how StorageForge reaches', got['conflicts'][0]['text'])
        got = self.run_it({'type': 'net-bridge', 'params': {'name': 'br1', 'ports': 'eth0', 'rollback': '5'}})
        self.assertFalse(got['blocked'], got['conflicts'])
        self.assertFalse(self.run_it({'type': 'net-bridge', 'params': {'name': 'br1', 'ports': 'eth9'}})['blocked'])

    def test_a_deny_elsewhere_is_no_conflict_and_shows_in_the_exposure_diff(self):
        self.facts(ufw_fw())
        got = self.run_it({'type': 'fw-rule', 'params': {'action': 'deny', 'proto': 'tcp', 'port': '445', 'source': ''}})
        self.assertEqual(got['conflicts'], [])
        self.assertEqual(got['exposure'][0]['changes'][0]['after'], 'blocked')

    def test_an_allow_widens_and_says_so(self):
        self.facts(ufw_fw())
        hid = self.conn.scalar("SELECT host_id FROM hosts WHERE hostname = 'nas'")
        extra = {**NET, 'listeners': NET['listeners'] + [{'proto': 'tcp', 'addr': '0.0.0.0', 'port': 9000, 'scope': 'any'}]}
        self.conn.execute('UPDATE host_network SET data_json = :d WHERE host_id = :h', {'d': json.dumps(extra), 'h': hid})
        security._save_measurement(self.conn, 'nas', 'infra', int(time.time()), 'test', {'firewall': ufw_fw(), 'listeners': extra['listeners'], 'storage_clients': []})
        got = self.run_it({'type': 'fw-rule', 'params': {'action': 'allow', 'proto': 'tcp', 'port': '9000'}})
        change = got['exposure'][0]['changes'][0]
        self.assertEqual((change['before'], change['after'], change['wider']), ('blocked', 'lan', True))

    def test_a_clashing_port_and_a_held_address_are_conflicts(self):
        self.facts(ufw_fw())
        got = self.run_it({'type': 'container', 'params': {'runtime': 'docker', 'name': 'x', 'image': 'y:1', 'publish': '445:80'}}, {'type': 'net-bridge', 'params': {'name': 'br1', 'address': '192.168.1.10/24'}})
        text = ' '.join(c['text'] for c in got['conflicts'])
        self.assertIn('445 is already in use', text)
        self.assertEqual({a['kind'] for a in got['ghost']['add']} >= {'Container', 'Bridge', 'Listener'}, True)

    def test_a_fence_shows_as_a_narrower_exposure(self):
        self.facts(ufw_fw())
        got = self.run_it({'type': 'fw-fence', 'params': {'name': 'f', 'service': 'smb', 'clients': '10.0.20.0/24'}})
        self.assertEqual(got['conflicts'], [])

    def test_with_nothing_read_it_says_it_cannot_tell(self):
        got = self.run_it({'type': 'fw-rule', 'params': {'action': 'allow', 'proto': 'tcp', 'port': '9000'}})
        self.assertTrue(got['not_modelled'])
        self.assertFalse(got['blocked'])

    def test_flows_are_compared_before_and_after(self):
        self.facts(ufw_fw())
        got = self.run_it({'type': 'fw-rule', 'params': {'action': 'deny', 'proto': 'tcp', 'port': '445'}}, flows=[{'from': '10.0.20.5', 'to': 'nas', 'port': 445}])
        self.assertEqual(got['flows'][0]['after'], 'blocked')


class MapRoutes(Base):
    def test_manual_nodes_are_marked_and_survive_a_rebuild(self):
        r = self.client.post('/api/map/manual', json={'kind': 'Switch', 'label': 'core-sw', 'url': 'https://inv/1', 'links': [{'to': 'host:nas'}]})
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True))
        self.conn.execute("INSERT INTO graph_nodes (node_id, kind, label, host, updated_at) VALUES ('host:nas', 'Host', 'nas', 'nas', 1)")
        infragraph.rebuild(self.conn, 'nas')
        g = self.client.get('/api/map?layers=manual').get_json()
        n = next(x for x in g['nodes'] if x['kind'] == 'Switch')
        self.assertEqual(n['confidence'], 'manual')
        self.assertTrue(any(e['src'] == n['id'] and e['dst'] == 'host:nas' for e in g['edges']))

    def test_a_link_must_be_a_web_address(self):
        self.assertEqual(self.client.post('/api/map/manual', json={'kind': 'Switch', 'label': 'x', 'url': 'javascript:alert(1)'}).status_code, 400)

    def test_the_timeline_draws_what_was_there_then(self):
        hid = self.conn.scalar("SELECT host_id FROM hosts WHERE hostname = 'nas'")
        self.conn.execute("INSERT INTO graph_nodes (node_id, kind, label, host, updated_at) VALUES ('host:nas', 'Host', 'nas', 'nas', 1)")
        self.conn.execute('INSERT INTO host_network (host_id, data_json, scan_id, updated_at) VALUES (:h, :d, 1, 1)', {'h': hid, 'd': json.dumps(NET)})
        infragraph.rebuild(self.conn, 'nas')
        then = self.conn.scalar("SELECT max(taken_at) FROM graph_snapshots WHERE host = 'nas'")
        self.conn.execute('UPDATE graph_snapshots SET taken_at = :t', {'t': then - 1000})
        extra = {**NET, 'listeners': NET['listeners'] + [{'proto': 'tcp', 'addr': '0.0.0.0', 'port': 9999, 'scope': 'any'}]}
        self.conn.execute('UPDATE host_network SET data_json = :d WHERE host_id = :h', {'d': json.dumps(extra), 'h': hid})
        infragraph.rebuild(self.conn, 'nas')
        now = {n['label'] for n in self.client.get('/api/map?layers=services').get_json()['nodes']}
        was = {n['label'] for n in self.client.get(f'/api/map?layers=services&at={then - 500}').get_json()['nodes']}
        self.assertIn('9999/tcp', now)
        self.assertNotIn('9999/tcp', was)
        self.assertIn('445/tcp', was)

    def test_firewall_detail_stays_behind_security_view(self):
        self.conn.execute("INSERT INTO graph_nodes (node_id, kind, label, host, updated_at, layer, props_json) VALUES ('lsn:nas:tcp:22', 'Listener', '22/tcp', 'nas', 1, 'services', '{\"exposure\": \"lan\", \"rule\": \"ufw\"}')")
        from storageforge_index import users
        users.create(self.conn, 'lookonly', PW, 'search')
        self.conn.execute("INSERT INTO roles (name, description, permissions, created_at, created_by) VALUES ('mapper', 'x', :p, 1, 'a')", {'p': json.dumps(['map.view', 'hosts.view'])})
        self.conn.execute("UPDATE users SET role = 'mapper' WHERE username = 'lookonly'")
        self.login('lookonly')
        self.assertEqual(self.client.get('/api/map/reach?from=a&to=b&port=22').status_code, 403)
        n = next(x for x in self.client.get('/api/map?layers=services').get_json()['nodes'] if x['kind'] == 'Listener')
        self.assertNotIn('exposure', n['props'])


class Policy(Base):
    def measured(self):
        self.measure()
        return security.measurement(self.conn, 'nas')

    def test_a_waived_check_still_shows_and_does_not_count(self):
        self.measured()
        before = security.compliance_status(self.conn, 'nas', 'cis-l1')
        failing = next(c for c in before['checks'] if c['result'] == 'fail')
        r = self.post('/api/security/waivers', host='nas', finding=failing['id'], reason='this kernel has no such setting', days=30)
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True))
        after = security.compliance_status(self.conn, 'nas', 'cis-l1')
        row = next(c for c in after['checks'] if c['id'] == failing['id'])
        self.assertEqual(row['result'], 'waived')
        self.assertIn('admin1', row['waiver']['approver'])
        self.assertEqual(after['waived'], 1)
        self.assertEqual(after['failed'], before['failed'] - 1)

    def test_a_waiver_needs_a_reason_and_an_end(self):
        self.assertEqual(self.post('/api/security/waivers', host='nas', finding='sysctl', reason='no', days=30).status_code, 400)
        self.assertEqual(self.post('/api/security/waivers', host='nas', finding='sysctl', reason='a good long reason').status_code, 400)

    def test_a_waiver_that_ended_counts_again(self):
        self.measured()
        failing = next(c for c in security.compliance_status(self.conn, 'nas', 'cis-l1')['checks'] if c['result'] == 'fail')
        secplus.save_waiver(self.conn, {'host': 'nas', 'finding': failing['id'], 'reason': 'for a while only', 'days': 1}, 'a')
        self.conn.execute('UPDATE security_waivers SET expires_at = 1')
        self.assertEqual(next(c for c in security.compliance_status(self.conn, 'nas', 'cis-l1')['checks'] if c['id'] == failing['id'])['result'], 'fail')

    def test_a_custom_profile_changes_the_numbers_and_says_they_are_not_the_standards(self):
        self.measured()
        r = self.post('/api/security/profiles', name='Ours', base='cis-l2', overrides={'target_lynis': 40, 'drop': ['aide'], 'add': ['malware']})
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True))
        got = security.compliance_status(self.conn, 'nas', 'custom:Ours')
        ids = {c['id'] for c in got['checks']}
        self.assertNotIn('aide', ids)
        self.assertIn('malware', ids)
        self.assertIn('no standard sets those numbers', security.compliance_standards(self.conn)['note'])

    def test_a_check_that_starts_failing_raises_a_drift_alert(self):
        m = self.measured()
        secplus.after_measure(self.conn, 'nas', m, int(time.time()))
        was = alerts.get_setting(self.conn, secplus.DRIFT + 'nas')
        passing = next((c for c in security.STANDARDS['cis-l1']['controls'] if c not in was['baseline']), None)
        self.assertTrue(passing)
        alerts.set_setting(self.conn, secplus.DRIFT + 'nas', {**was, 'baseline': []}, 'test')
        secplus.after_measure(self.conn, 'nas', m, int(time.time()))
        self.assertIn('security-drift:nas', secplus.problems(self.conn))

    def test_lynis_findings_become_steps_or_are_left_for_a_person(self):
        m = {'sysctl': {'fs.protected_hardlinks': '0'}, 'lynis': {'warnings': [], 'suggestions': [{'id': 'SSH-7408', 'text': 'Consider hardening SSH configuration', 'detail': 'AllowTcpForwarding (set YES to NO)'}, {'id': 'KRNL-6000', 'text': 'sysctl differ'}, {'id': 'AUTH-9328', 'text': 'umask'}, {'id': 'FILE-6310', 'text': 'partitions'}]}}
        tasks, by_hand = secplus.lynis_tasks('nas', m)
        types = {t['type']: t['params'] for t in tasks}
        self.assertEqual(types['sshd-option'], {'key': 'AllowTcpForwarding', 'value': 'no', 'rollback': '10'})
        self.assertEqual(types['sysctl-set']['key'], 'fs.protected_hardlinks')
        self.assertEqual(types['umask-set']['value'], '027')
        self.assertEqual([x['id'] for x in by_hand], ['FILE-6310'])
        changes.normalize({'name': 'x', 'tasks': tasks})

    def test_a_retention_policy_holds_the_newest_snapshot_and_only_when_it_ran(self):
        self.snap('tank/prod@a')
        self.snap('tank/prod@b')
        self.snap('tank/other@a')
        m = self.measured()
        security._save_measurement(self.conn, 'nas', 'host', m['measured_at'], 'test', {k: v for k, v in {**m, 'snapshots': ['tank/prod@a', 'tank/prod@b', 'tank/other@a']}.items() if k not in ('measured_at', 'stale', 'via')})
        self.post('/api/security/worm/policies', host='nas', pattern='tank/prod*', days=30)
        got = self.post('/api/security/worm/policies/apply', host='nas', mode='preview').get_json()
        self.assertEqual([t['snapshot'] for t in got['targets']], ['tank/prod@b'])
        self.assertEqual(self.conn.scalar('SELECT count(*) FROM security_retention_holds'), 0, 'previewing is not doing')
        r = self.post('/api/security/worm/policies/apply', host='nas', mode='apply')
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True))
        self.assertEqual(self.conn.scalar('SELECT snapshot FROM security_retention_holds'), 'tank/prod@b')
        self.assertIn('tank/prod@b', self.zstate.read_text() + self.log.read_text())

    def test_a_tier_goes_up_for_a_repeat_offender(self):
        secplus.record_ban(self.conn, 'nas', '10.0.0.9', 1, 'first')
        self.assertEqual(secplus.next_tier(self.conn, 'nas', '10.0.0.9', 1), 2)
        secplus.record_ban(self.conn, 'nas', '10.0.0.9', 2, 'second')
        self.assertEqual(secplus.next_tier(self.conn, 'nas', '10.0.0.9', 1), 3)
        self.assertEqual(secplus.next_tier(self.conn, 'nas', '10.0.0.8', 1), 1)

    def test_a_noise_rule_folds_noise_but_never_a_daemon_reaching_for_the_shadow_file(self):
        secplus.save_avc_noise(self.conn, {'rules': [{'daemon': 'smbd', 'path': '*'}]}, 'a')
        got = secplus.mark_avc(self.conn, [{'daemon': 'smbd', 'path': '/var/cache/x', 'storage': True}, {'daemon': 'smbd', 'path': '/etc/shadow', 'storage': True}])
        self.assertTrue(got[0]['noise'])
        self.assertFalse(got[1]['noise'])
        self.assertTrue(got[1]['lateral'])

    def test_a_folder_can_have_its_own_entropy_line(self):
        secplus.save_thresholds(self.conn, {'entropy': [{'prefix': '/srv/docs', 'threshold': 7.2}]}, 'a')
        self.assertEqual(secplus.entropy_limit(self.conn, '/srv/docs/a.txt'), 7.2)
        self.assertEqual(secplus.entropy_limit(self.conn, '/srv/media/a.mkv'), security.ENTROPY_FLAG)

    def test_a_tile_with_nothing_read_says_so(self):
        self.assertEqual(secplus.tile(self.conn, 'lynis', 'nas'), {'none': 'Not measured'})
        self.assertIn('none', secplus.tile(self.conn, 'decoys', None))
        with self.assertRaises(LookupError):
            secplus.tile(self.conn, 'made-up', None)

    def test_the_standalone_script_reports_first_and_has_no_certificate(self):
        r = self.client.get('/api/security/compliance/script?host=nas&profile=cis-l1')
        text = r.get_data(as_text=True)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(subprocess.run(['bash', '-n'], input=text, text=True, capture_output=True).stderr, '')
        out = subprocess.run(['bash', '-c', text, 'x', '--export-cert', '/tmp/x'], capture_output=True, text=True, env=self.env)
        self.assertEqual(out.returncode, 2)
        self.assertIn('only an auditor can attest', out.stderr)


class Evidence(Base):
    def test_it_verifies_with_ssh_keygen_and_says_what_it_is_not(self):
        if not shutil.which('ssh-keygen'):
            self.skipTest('needs ssh-keygen')
        from storageforge_index import vault
        from cryptography.hazmat.primitives.asymmetric import ed25519
        key = ed25519.Ed25519PrivateKey.generate()
        with mock.patch.object(vault.Vault, 'unlock'), mock.patch.object(deploy, '_signer', return_value=key):
            self.hold()
            r = secplus.evidence(self.db, self.conn, 'nas', None, None, 'a')
        doc = json.loads(r['document'])
        self.assertIn('not an attestation', doc['statement'])
        self.assertEqual(len(doc['holds']), 1)
        signers, sig = self.tmp / 'signers', self.tmp / 'e.sig'
        signers.write_text(f'storageforge namespaces="storageforge-evidence" {r["public_key"]}\n')
        sig.write_text(r['signature'])
        verify = ['ssh-keygen', '-Y', 'verify', '-f', str(signers), '-I', 'storageforge', '-n', 'storageforge-evidence', '-s', str(sig)]
        self.assertEqual(subprocess.run(verify, input=r['document'].encode(), capture_output=True).returncode, 0)
        self.assertNotEqual(subprocess.run(verify, input=r['document'].replace('nas', 'mas').encode(), capture_output=True).returncode, 0, 'a changed record must not verify')


class Identity(Base):
    SMB_B = 'Samba version 4.19\nPID Username Group Machine Protocol\n-----\n101 alice users 10.0.1.5 (ipv4:10.0.1.5:1) SMB3_11\n102 alice users 10.0.2.9 (ipv4:10.0.2.9:1) SMB3_11\n'
    SMB_S = 'Service pid Machine Connected\n-----\nfinance 101 10.0.1.5 Tue\nhr 101 10.0.1.5 Tue\nsales 102 10.0.2.9 Tue\nIPC$ 101 10.0.1.5 Tue\n'

    def test_the_sampler_flags_what_it_sees_once_and_reports_it(self):
        (self.bin / 'smbstatus').write_text(f"""#!/bin/bash\ncase $1 in -b) cat <<'E'\n{self.SMB_B}E\n;; -S) cat <<'E'\n{self.SMB_S}E\n;; esac\n""")
        (self.bin / 'smbstatus').chmod(0o755)
        root = self.tmp / 'identity'
        (root / 'c').mkdir(parents=True)
        (root / 's').mkdir()
        (root / 'c' / 'identity.conf').write_text('MAX_SHARES=2\nOFF_FROM=\nOFF_TO=\n')
        script = secplus.SESSIONS_SCRIPT.replace('CONF=/etc/storageforge/security STATE=/var/lib/storageforge/security', f'CONF={root}/c STATE={root}/s').replace('export LC_ALL=C PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin', 'export LC_ALL=C')
        for _ in range(2):
            r = subprocess.run(['bash', '-c', script], capture_output=True, text=True, env=self.env)
            self.assertEqual(r.returncode, 0, r.stderr)
        rows = (root / 's' / 'sessions.tsv').read_text().splitlines()
        self.assertTrue(any(line.endswith('\talice\t10.0.1.5\tfinance') for line in rows), rows)
        self.assertFalse(any('IPC$' in line for line in rows))
        events = (root / 's' / 'events.tsv').read_text().splitlines()
        kinds = [e.split('\t')[2] for e in events]
        self.assertEqual(sorted(kinds), ['identity_enumeration', 'identity_multi_subnet'], 'each once, for all the samples')
        self.assertEqual(security.ingest_events(self.conn, 'nas', '\n'.join(events), 'test'), 2)
        self.assertEqual(self.conn.scalar("SELECT severity FROM security_events WHERE kind = 'identity_enumeration'"), 'crit')

    def test_it_is_off_until_asked_and_the_report_changes_nothing(self):
        self.assertFalse(secplus.identity_config(self.conn, 'nas')['enabled'])
        (self.bin / 'smbstatus').write_text('#!/bin/sh\n')
        (self.bin / 'smbstatus').chmod(0o755)
        got = self.post('/api/security/mac/identity/deploy', host='nas', mode='report').get_json()
        self.assertIn('would sample', got['output'])
        self.assertFalse(secplus.identity_config(self.conn, 'nas')['enabled'])


class Falco(Base):
    def test_rules_are_checked_and_macros_come_from_the_index(self):
        secplus.check_falco_yaml(secplus.DEFAULT_FALCO)
        with self.assertRaises(ValueError):
            secplus.check_falco_yaml('not: [a list')
        with self.assertRaises(ValueError):
            secplus.check_falco_yaml('just: a mapping\n')
        rendered = secplus.render_falco(self.conn, 'nas', secplus.DEFAULT_FALCO)
        self.assertNotIn('$STORAGE', rendered)
        self.assertNotIn('$AUTHORIZED', rendered)

    def test_no_rule_claims_to_count(self):
        self.assertIn('cannot be said here', secplus.DEFAULT_FALCO)

    def test_only_named_fields_are_read_and_warnings_become_events(self):
        lines = ['a\tStorageForge disk destruction\tCritical\t2026-11-03T00:00:00Z\twipefs\t\troot', 'a\tSome rule\tNotice\t2026-11-03T00:00:01Z\tcat\t/etc/x\troot']
        parsed = secplus.parse_falco(lines)
        self.assertEqual(secplus.ingest_falco(self.conn, 'nas', parsed), 1)
        self.assertEqual(secplus.ingest_falco(self.conn, 'nas', parsed), 0, 'read twice, recorded once')
        self.assertEqual(self.conn.scalar("SELECT severity FROM security_events WHERE kind = 'falco_crit'"), 'crit')

    def test_the_measurement_prints_no_output_text(self):
        from storageforge_index import secscripts
        block = secscripts.MEASURE_BODY[secscripts.MEASURE_BODY.index('sec falco_alerts'):]
        self.assertNotIn('$(f output)', block)
        self.assertIn('f rule', block)

    def test_a_terminator_cannot_be_smuggled_in(self):
        with self.assertRaises(ValueError):
            secplus.falco_script('x\nSF_FALCO_RULES\nrm -rf /\n')


class Yara(Base):
    def yara_stub(self):
        (self.bin / 'yara').write_text("""#!/bin/bash
if [[ ${@: -1} == /dev/null ]]; then grep -q 'bad rule' "${@: -2:1}" && { echo "syntax error" >&2; exit 1; }; exit 0; fi
grep -q 'encrypted' "${@: -1}" && echo "Ransom_Note ${@: -1}"
exit 0
""")
        (self.bin / 'yara').chmod(0o755)

    def changed(self, *paths):
        hid = self.conn.scalar("SELECT host_id FROM hosts WHERE hostname = 'nas'")
        mid = self.conn.scalar("INSERT INTO mounts (host_id, mount_point, source, filesystem_type, scan_state) VALUES (:h, '/', '/dev/sda1', 'ext4', 'indexed') RETURNING mount_id", {'h': hid})
        sid = self.conn.scalar(f"INSERT INTO scans (host_id, status, started_at, finished_at) VALUES (:h, 'ok', {self.db.ts(':t')}, {self.db.ts(':t')}) RETURNING scan_id", {'h': hid, 't': 1700000000})
        for p in paths:
            d, n = os.path.split(p)
            self.conn.execute(f"INSERT INTO file_changes (scan_id, mount_id, parent_path, filename, change_type, is_directory, new_size) VALUES (:s, :m, :d, :n, 'added', {self.db.false if hasattr(self.db, 'false') else 'FALSE'}, 10)", {'s': sid, 'm': mid, 'd': d, 'n': n})

    def test_matches_join_the_list_and_a_test_records_nothing(self):
        self.yara_stub()
        bad, ok = self.root / 'note.txt', self.root / 'fine.txt'
        bad.write_text('your files have been encrypted')
        ok.write_text('hello')
        self.changed(str(bad), str(ok))
        dry = self.post('/api/security/behavior/yara', host='nas', dry=True, rules='rule x {condition: true}')
        self.assertEqual(dry.get_json()['hits'], 1, dry.get_data(as_text=True))
        self.assertEqual(self.conn.scalar('SELECT count(*) FROM clamav_detections'), 0)
        real = self.post('/api/security/behavior/yara', host='nas')
        self.assertEqual(real.get_json()['found'], 1, real.get_data(as_text=True))
        self.assertEqual(self.conn.scalar('SELECT signature FROM clamav_detections'), 'YARA:Ransom_Note')

    def test_a_bad_rule_is_refused_with_the_reason(self):
        self.yara_stub()
        (self.root / 'a').write_text('x')
        self.changed(str(self.root / 'a'))
        r = self.post('/api/security/behavior/yara', host='nas', dry=True, rules='bad rule')
        self.assertEqual(r.status_code, 409)
        self.assertIn('refused', r.get_json()['error'])

    def test_the_filter_skips_big_media_and_never_an_executable(self):
        self.changed('/a/film.mkv', '/a/run.exe', '/a/doc.txt')
        self.assertEqual(sorted(secplus.filtered_paths(self.conn, 'nas')), ['/a/doc.txt', '/a/run.exe'])


class Playbooks(Base):
    def save(self, **kw):
        r = self.post('/api/security/playbooks', **{'name': 'Canary response', 'trigger': 'canary_tripped', 'actions': ['snapshot', 'notify'], **kw})
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True))

    def fire(self, detail=''):
        security.record_event(self.conn, 'nas', 'canary_tripped', '/srv/a was changed', detail, 'test')
        return secplus.process_events(self.db, self.conn)

    def start(self):
        secplus.process_events(self.db, self.conn)      # the first look only marks the place

    def test_a_new_one_says_what_it_would_do_and_does_nothing(self):
        self.save()
        self.start()
        self.assertEqual(self.fire(), 1)
        run = secplus.playbook_runs(self.conn)[0]
        self.assertEqual(run['outcome'], 'would')
        self.assertEqual(self.calls, [])

    def test_history_fires_nothing(self):
        security.record_event(self.conn, 'nas', 'canary_tripped', 'long ago', '', 'test')
        self.save(mode='live')
        self.assertEqual(secplus.process_events(self.db, self.conn), 0)
        self.assertEqual(secplus.playbook_runs(self.conn), [])

    def test_a_live_one_runs_the_real_brake_and_says_how_it_went(self):
        self.save(mode='live')
        self.start()
        with mock.patch.object(alerts, 'send', return_value=['no channel is set up']) as sent:
            self.fire()
        run = secplus.playbook_runs(self.conn)[0]
        self.assertIn(run['outcome'], ('ran', 'failed'))
        self.assertTrue(any('brake' in c['ref'] for c in self.calls), 'the brake must really run')
        sent.assert_called_once()

    def test_asking_first_waits_for_a_person_and_alerts(self):
        self.save(mode='confirm')
        self.start()
        self.fire()
        pending = secplus.pending_runs(self.conn)
        self.assertEqual(len(pending), 1)
        self.assertEqual(self.calls, [])
        self.assertIn(f'security-playbook:{pending[0]["id"]}', secplus.problems(self.conn))
        r = self.post(f'/api/security/playbooks/runs/{pending[0]["id"]}', confirm=False)
        self.assertEqual(r.get_json()['outcome'], 'dismissed')
        self.assertEqual(self.calls, [])
        self.assertEqual(secplus.pending_runs(self.conn), [])

    def test_conditions_narrow_it(self):
        self.save(conditions={'host': 'other-*'})
        self.start()
        self.assertEqual(self.fire(), 0)

    def test_a_change_rate_above_usual_can_fire_one_once_for_each_scan(self):
        self.save(trigger='velocity')
        self.start()
        at = int(time.time())
        with mock.patch.object(security, 'velocity', return_value={'anomaly': True, 'latest': {'files_per_hour': 900, 'at': at}, 'baseline_median': 10}):
            secplus.note_velocity(self.conn)
            secplus.note_velocity(self.conn)
        self.assertEqual(secplus.process_events(self.db, self.conn), 1)
        self.assertEqual(self.conn.scalar("SELECT severity FROM security_events WHERE kind = 'velocity'"), 'warn')

    def test_a_trip_finds_its_client_from_the_event_that_names_one(self):
        path = base64.b64encode(b'/srv/a').decode()
        first = int(self.conn.scalar("INSERT INTO security_events (uuid, host, kind, severity, occurred_at, received_at, via, summary, detail) VALUES ('x', 'nas', 'canary_tripped', 'crit', 1, 1, 't', 's', :d) RETURNING event_id", {'d': f'path_b64={path};event=MODIFY'}))
        security.record_event(self.conn, 'nas', 'canary_source', 'from', f'path_b64={path};client=10.0.1.42;pid=9', 'test')
        self.assertEqual(secplus._client_of(self.conn, 'nas', first, secplus.event_fields(f'path_b64={path};event=MODIFY')), '10.0.1.42')


class FakeToken:
    """A FIDO2 token, with a real P-256 key. What a browser would hand over, without a browser."""

    def __init__(self, rp='nas.example', origin='https://nas.example'):
        self.key, self.rp, self.origin, self.count, self.cred = ec.generate_private_key(ec.SECP256R1()), rp, origin, 0, os.urandom(16)

    @staticmethod
    def cbor(v) -> bytes:
        def head(major, n):
            return bytes([major << 5 | n]) if n < 24 else bytes([major << 5 | 24, n]) if n < 256 else bytes([major << 5 | 25]) + struct.pack('>H', n)
        if isinstance(v, bool) or v is None:
            return bytes([0xf4 if v is False else 0xf5 if v else 0xf6])
        if isinstance(v, int):
            return head(0, v) if v >= 0 else head(1, -1 - v)
        if isinstance(v, bytes):
            return head(2, len(v)) + v
        if isinstance(v, str):
            return head(3, len(v.encode())) + v.encode()
        if isinstance(v, dict):
            return head(5, len(v)) + b''.join(FakeToken.cbor(k) + FakeToken.cbor(x) for k, x in v.items())
        raise TypeError(v)

    def client(self, kind, challenge, origin=None):
        return json.dumps({'type': kind, 'challenge': challenge, 'origin': origin or self.origin}).encode()

    def auth(self, flags=1, extra=b''):
        return hashlib.sha256(self.rp.encode()).digest() + bytes([flags]) + struct.pack('>I', self.count) + extra

    def register(self, challenge, origin=None):
        pub = self.key.public_key().public_numbers()
        cose = self.cbor({1: 2, 3: -7, -1: 1, -2: pub.x.to_bytes(32, 'big'), -3: pub.y.to_bytes(32, 'big')})
        auth = self.auth(0x41, uuid.uuid4().bytes + struct.pack('>H', len(self.cred)) + self.cred + cose)
        return {'clientDataJSON': webauthn.b64u(self.client('webauthn.create', challenge, origin)), 'attestationObject': webauthn.b64u(self.cbor({'fmt': 'none', 'attStmt': {}, 'authData': auth}))}

    def touch(self, challenge, origin=None, bump=True):
        if bump:
            self.count += 1
        auth, client = self.auth(), self.client('webauthn.get', challenge, origin)
        sig = self.key.sign(auth + hashlib.sha256(client).digest(), ec.ECDSA(hashes.SHA256()))
        return {'id': webauthn.b64u(self.cred), 'clientDataJSON': webauthn.b64u(client), 'authenticatorData': webauthn.b64u(auth), 'signature': webauthn.b64u(sig)}


class Webauthn(unittest.TestCase):
    RP, ORIGIN = 'nas.example', 'https://nas.example'

    def enrolled(self):
        t = FakeToken()
        return t, webauthn.register_finish(t.register('ch'), 'ch', self.ORIGIN, self.RP)

    def test_a_key_enrolls_and_its_touch_verifies(self):
        t, cred = self.enrolled()
        self.assertEqual(webauthn.assert_finish(t.touch('ch2'), 'ch2', self.ORIGIN, self.RP, cred['public_key'], 0), 1)

    def test_what_must_fail_fails(self):
        t, cred = self.enrolled()
        answer = t.touch('good')
        for args in (('other', self.ORIGIN, self.RP), ('good', 'https://evil.example', self.RP), ('good', self.ORIGIN, 'evil.example')):
            with self.assertRaises(ValueError, msg=args):
                webauthn.assert_finish(answer, *args, cred['public_key'], 0)
        with self.assertRaises(ValueError, msg='a counter that went backwards'):
            webauthn.assert_finish(answer, 'good', self.ORIGIN, self.RP, cred['public_key'], 5)
        other = FakeToken()
        with self.assertRaises(ValueError, msg='another key'):
            webauthn.assert_finish(other.touch('good'), 'good', self.ORIGIN, self.RP, cred['public_key'], 0)
        tampered = {**answer, 'signature': webauthn.b64u(webauthn.unb64u(answer['signature'])[:-1] + b'\x00')}
        with self.assertRaises((ValueError, Exception)):
            webauthn.assert_finish(tampered, 'good', self.ORIGIN, self.RP, cred['public_key'], 0)

    def test_no_touch_no_entry(self):
        t, cred = self.enrolled()
        auth = t.auth(flags=0)
        client = t.client('webauthn.get', 'c')
        sig = t.key.sign(auth + hashlib.sha256(client).digest(), ec.ECDSA(hashes.SHA256()))
        with self.assertRaises(ValueError):
            webauthn.assert_finish({'clientDataJSON': webauthn.b64u(client), 'authenticatorData': webauthn.b64u(auth), 'signature': webauthn.b64u(sig)}, 'c', self.ORIGIN, self.RP, cred['public_key'], 0)


class StepUp(Base):
    def test_a_release_asks_for_the_touch_once_a_key_is_enrolled(self):
        hid = self.hold()
        webauthn.add_key(self.conn, 'admin1', {'credential_id': 'abc', 'public_key': 'x', 'sign_count': 0}, 'key')
        r = self.post('/api/security/worm/release', hold_id=hid)
        self.assertEqual(r.status_code, 403)
        self.assertTrue(r.get_json()['webauthn'])
        self.assertEqual(self.hold_status(hid), 'locked')
        with self.client.session_transaction() as s:
            s['webauthn_at'] = time.time()
        self.assertEqual(self.post('/api/security/worm/release', hold_id=hid).status_code, 200)


class EveryRouteAnswers(Base):
    """A typo in a query or a field shows only when a route runs, so they all run, on a measured host with a design and a share."""

    def facts(self):
        hid = self.conn.scalar("SELECT host_id FROM hosts WHERE hostname = 'nas'")
        self.conn.execute('INSERT INTO host_network (host_id, data_json, scan_id, updated_at) VALUES (:h, :d, 1, 1)', {'h': hid, 'd': json.dumps(NET)})
        self.measure()
        security._save_measurement(self.conn, 'nas', 'infra', int(time.time()), 'test', {'firewall': ufw_fw(), 'listeners': NET['listeners'], 'storage_clients': [{'client': '10.0.20.5', 'port': 445, 'connections': 2}], 'libvirt': [], 'incus': [], 'lxc': [], 'proxmox': [], 'podman_rootless': [], 'access': {'wireguard': None, 'tailscale': None, 'proxy_routes': [], 'units': []}})
        self.conn.execute("INSERT INTO graph_nodes (node_id, kind, label, host, updated_at) VALUES ('host:nas', 'Host', 'nas', 'nas', 1)")
        infragraph.rebuild(self.conn, 'nas')
        self.assertEqual(self.client.post('/api/map/designs', json={'name': 'd', 'doc': {'hosts': [{'name': 'nas', 'firewall': [{'action': 'allow', 'proto': 'tcp', 'port': '445'}]}]}}).status_code, 200)
        self.hold()
        secplus.save_playbook(self.conn, {'name': 'p', 'trigger': 'canary_tripped', 'actions': ['notify']}, 'a')
        secplus.record_ban(self.conn, 'nas', '10.0.0.9', 1, 'x')
        security.record_event(self.conn, 'nas', 'canary_tripped', 'a decoy', 'client=10.0.0.9', 'test')

    def test_every_read_on_the_map_and_in_security(self):
        self.facts()
        did = self.conn.scalar("SELECT id FROM map_designs WHERE name = 'd'")
        node = 'lsn:nas:tcp:445'
        failed = []
        for rule in self.web.url_map.iter_rules():
            if 'GET' not in rule.methods or not rule.rule.startswith(('/api/map', '/api/security', '/api/workloads', '/api/network', '/api/firewall', '/api/exposure', '/api/infra')):
                continue
            path = rule.rule.replace('<int:design_id>', str(did)).replace('<path:node_id>', node).replace('<host>', 'nas').replace('<kind>', 'posture')
            if '<' in path:
                continue
            q = {'host': 'nas', 'from': 'nas', 'to': 'nas', 'port': '445', 'src': 'x', 'dst': 'y', 'rel': 'z'}
            if path.endswith('/api/security/evidence'):
                continue          # it unlocks the vault: Evidence tests it
            code = self.client.get(path, query_string=q).status_code
            if code not in (200, 404):
                failed.append((path, code))
        self.assertEqual(failed, [])

    def test_every_tile(self):
        self.facts()
        for kind in secplus.TILES:
            for host in ('nas', None):
                got = secplus.tile(self.conn, kind, host)
                self.assertIsInstance(got, dict, kind)
        self.assertEqual(self.client.post('/api/security/dash', json={'name': 'mine', 'layout': [{'kind': 'posture', 'w': 2, 'h': 1}]}).status_code, 200)
        self.assertEqual(self.client.get('/api/security/dash').get_json()['dashboards'][0]['layout'][0]['kind'], 'posture')

    def test_the_share_matrix_says_who_is_connected_against_what_is_allowed(self):
        self.facts()
        from storageforge_index import shares
        with mock.patch.object(shares, 'design_exports', return_value=[{'protocol': 'SMB3', 'name': 'finance', 'path': '/srv/f', 'clients': 'alice'}, {'protocol': 'NFSv4.2', 'name': 'b', 'path': '/srv/b', 'rules': [{'clients': '10.0.0.0/8'}]}]):
            got = secplus.share_matrix(self.conn, 'nas')
        smb = got['shares'][0]
        self.assertEqual(smb['protocol'], 'SMB')
        self.assertEqual(smb['connected'], [{'client': '10.0.20.5', 'port': 445, 'connections': 2}])
        self.assertEqual(got['shares'][1]['declared'], ['10.0.0.0/8'])

    def test_a_timeline_narrows_to_one_client(self):
        self.facts()
        rows = self.client.get('/api/security/timeline?client=10.0.0.9').get_json()['rows']
        self.assertTrue(rows)
        self.assertTrue(all('10.0.0.9' in r['text'] + r['detail'] for r in rows))
        self.assertEqual(self.client.get('/api/security/timeline?client=192.0.2.200').get_json()['rows'], [])

    def test_decoys_spread_where_the_index_says_with_names_that_fit(self):
        hid = self.conn.scalar("SELECT host_id FROM hosts WHERE hostname = 'nas'")
        mid = self.conn.scalar("INSERT INTO mounts (host_id, mount_point, source, filesystem_type, scan_state) VALUES (:h, '/srv', '/dev/sda1', 'ext4', 'indexed') RETURNING mount_id", {'h': hid})
        for d in ('/srv/shares', '/srv/shares/hr', '/srv/shares/hr/old', '/srv/shares/finance', '/srv/shares/.hidden'):
            self.conn.execute('INSERT INTO directories (mount_id, path) VALUES (:m, :p)', {'m': mid, 'p': d})
        top = security.spread_folders(self.conn, 'nas', ['/srv/shares'], 'top')
        self.assertEqual(top, ['/srv/shares', '/srv/shares/finance', '/srv/shares/hr'])
        r = self.client.post('/api/security/sentinel', json={'host': 'nas', 'folders': ['/srv/shares'], 'names': ['{Dept}_Salaries_{Year}.xlsx'], 'spread': 'top'})
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True))
        paths = security.decoy_paths(security.sentinel_config(self.conn, 'nas'))
        self.assertIn(f'/srv/shares/hr/Hr_Salaries_{time.strftime("%Y")}.xlsx', paths)
        self.assertEqual(self.client.post('/api/security/sentinel', json={'host': 'nas', 'folders': ['/srv/shares'], 'spread': 'everywhere'}).status_code, 400)

    def test_a_reconverge_stages_what_a_step_can_fix_and_lists_the_rest(self):
        self.measure()
        r = self.client.post('/api/security/compliance/reconverge', json={'host': 'nas', 'profile': 'cis-l2'})
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True))
        got = r.get_json()
        self.assertTrue(got['tasks'] or got['by_hand'])
        if got['plan_id']:
            changes.normalize(changes.get_plan(self.conn, got['plan_id']))

    def test_alert_routes_send_where_they_say_and_everywhere_if_none_match(self):
        cfg = {'routes': [{'level': 'crit', 'host': 'nas-*', 'channels': ['pagerduty']}]}
        self.assertEqual(alerts.routed(cfg, 'crit', 'nas-01'), {'pagerduty'})
        self.assertIsNone(alerts.routed(cfg, 'warn', 'nas-01'))
        self.assertIsNone(alerts.routed({}, 'crit', 'x'))
        with mock.patch.object(alerts, '_post') as post:
            alerts.send({'pagerduty': {'routing_key': 'k' * 32}, 'webhook': {'url': 'http://hook'}, **cfg}, 't', 'm', 'crit', {'ref': 'nas-01'})
        self.assertEqual(post.call_count, 1)
        self.assertIn('pagerduty', post.call_args[0][0])
        with self.assertRaises(ValueError):
            alerts.save_settings(self.conn, {'alerts': {'routes': [{'level': 'crit', 'host': '*', 'channels': ['nope']}]}}, 'a')


class Bash(unittest.TestCase):
    def test_what_goes_on_hosts_parses(self):
        from storageforge_index import secscripts
        for name, text in (('identity', secplus.identity_script(10, 22, 6)), ('falco', secplus.falco_script(secplus.DEFAULT_FALCO)), ('falco-off', secplus.falco_script('', True)), ('yara', secplus.YARA_SCAN), ('tree', secplus.YARA_TREE), ('sessions', secplus.SESSIONS_SCRIPT),
                           ('compliance', secscripts.compliance_script('cis-l1', 'nas')), ('aide', secscripts.tool_script('aide-check', ['/opt/x y'])), ('lynis', secscripts.tool_script('lynis')), ('airgap', secscripts.airgap_script(['10.0.0.1'])), ('quarantine', secscripts.quarantine_script('10.0.0.1', 60))):
            self.assertEqual(subprocess.run(['bash', '-n'], input=text, text=True, capture_output=True).stderr, '', name)


_ = (re, serialization, netfacts)
