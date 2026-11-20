"""The readers of roadmap section 2 that came after the first five: Nebula, Netmaker, strongSwan, OpenVPN's certificates and
ZeroTier's peers, and the scrubber that takes the credentials out of a configuration file before it leaves a host.

Each sample says where its format comes from. Where the real program is on this machine it is run (nebula-cert, openssl, awk);
the others are samples of what the tool's own source or documentation prints. What must hold everywhere: no reader raises, a
credential in a file is in nothing that comes back, and no person's name is kept."""
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from storageforge_index import confread, inframeasure, overlays


def _real(name):
    folder = os.environ.get('STORAGEFORGE_TEST_NEBULA') or str(Path.home() / '.cache/sfdev/dl/nebula-1.12.0')
    return shutil.which(name) or shutil.which(name, path=folder)


REAL_NEBULA_CERT = _real('nebula-cert')

# examples/config.yml of Nebula 1.12.0 (github.com/slackhq/nebula, tag v1.12.0) without its comments, with the options a lighthouse,
# a relay and a gateway set: static_host_map, lighthouse.hosts, relay.relays and tun.unsafe_routes in both of the forms the file
# documents (`via` as one address, and since 1.10 as a list of gateways). An inline key is what `pki.key` also takes.
NEBULA_CONF = """pki:
  ca: /etc/nebula/ca.crt
  cert: /etc/nebula/host.crt
  key: |
    -----BEGIN NEBULA X25519 PRIVATE KEY-----
    SECRETSECRETSECRETSECRETSECRETSECRETSECRETg=
    -----END NEBULA X25519 PRIVATE KEY-----
static_host_map:
  "192.168.100.1": ["100.64.22.11:4242"]
  "192.168.100.2": ["lh2.example.net:4242", "[2001:db8::2]:4242"]
lighthouse:
  am_lighthouse: false
  interval: 60
  hosts:
    - "192.168.100.1"
    - "192.168.100.2"
listen:
  host: "::"
  port: 4242
punchy:
  punch: true
relay:
  relays:
    - 192.168.100.1
  am_relay: false
  use_relays: true
tun:
  disabled: false
  dev: nebula1
  mtu: 1300
  unsafe_routes:
    - route: 172.16.1.0/24
      via: 192.168.100.99
      mtu: 1300
    - route: 192.168.87.0/24
      via:
        - gateway: 192.168.100.1
          weight: 10
        - gateway: 192.168.100.2
          weight: 5
sshd:
  enabled: true
  listen: 127.0.0.1:2222
  host_key: ./ssh_host_ed25519_key
  authorized_users:
    - user: steeeeve
      keys:
        - "ssh-ed25519 AAAASECRETSECRET steve@laptop"
firewall:
  outbound:
    - port: any
      proto: any
      host: any
  inbound:
    - port: 443
      proto: tcp
      groups:
        - laptop
        - home
"""

# `nebula-cert print -json -path host.crt`, printed by the real nebula-cert 1.12.0 on 2026-11-20 for a certificate made with
# `nebula-cert sign -name lighthouse1 -ip 10.99.0.1/24 -groups servers,lighthouse -subnets 192.168.50.0/24`. Since 1.10 it prints a
# list, with `networks` and `unsafeNetworks`; before that one object with `ips` and `subnets` (the second sample).
NEBULA_CERT = ('[{"curve":"CURVE25519","details":{"groups":["servers","lighthouse"],"isCa":false,"issuer":"f1b0fcb5cf64a2d822aa9cca1028b03fe0a5e4dcd4aff030225cbbb6715e243c",'
               '"name":"lighthouse1","networks":["10.99.0.1/24"],"notAfter":"2036-11-17T09:33:14-08:00","notBefore":"2026-11-20T09:33:15-08:00","unsafeNetworks":["192.168.50.0/24"]},'
               '"fingerprint":"939d3e0ff7316ca7533b4ca8d444069aa33aa87e5bd0804208d8bd8f8422d0b0","publicKey":"59f4b46d7531c455d1dacd7a8fe0828b2d9572a86f1229932f6fb192c8e18262",'
               '"signature":"9a3f9d41001364d795cc04bb1e133fc6ac0f56bc2bb8dc95aae7a3c4743c9577","version":2}]')
NEBULA_CERT_OLD = json.dumps({'details': {'groups': ['servers'], 'ips': ['10.99.0.7/24'], 'isCa': False, 'issuer': 'f1b0', 'name': 'old', 'notAfter': '2027-01-01T00:00:00Z',
                                          'notBefore': '2026-01-01T00:00:00Z', 'publicKey': '59f4', 'subnets': ['192.168.60.0/24']}, 'fingerprint': 'abcd', 'signature': '9a3f'})


def awk_scrub(text: str) -> str:
    """What the collector's awk leaves of a file: the rule as it runs on a host."""
    return subprocess.run(['awk', '-v', f're={confread.SECRET_LINE}', confread.SCRUB_AWK], input=text, capture_output=True, text=True, check=True).stdout


class Scrub(unittest.TestCase):
    """A credential goes with everything that belongs to it, on the host and again on the server."""
    FILES = {
        'nebula': NEBULA_CONF,
        'block under a name': 'a: 1\nsigning_key: |\n  LS0tSECRET\n  moreSECRET\nb: 2\n',
        'list of secrets': 'shared_secrets:\n- SECRETone\n- SECRETtwo\nroutes:\n- from: https://a.example.com\n',
        'a quoted value that runs on': 'cookie_secret: "SECRET\n  SECRET again\n  the end"\naddress: :443\n',
        'a pem block with no name': 'certs:\n  - -----BEGIN PRIVATE KEY-----\n    SECRET\n    -----END PRIVATE KEY-----\nname: x\n',
        'a password in an address': 'storage "postgres" {\n  url = "postgresql://boundary:SECRET@db.lab/boundary"\n}\nname = "c1"\n',
        'headers': 'routes:\n  - from: https://a.example.com\n    to: http://10.0.0.5:8080\n    set_request_headers:\n      Authorization: Basic SECRET\n      X-Other: SECRET\n    allow_any_authenticated_user: true\n',
    }

    def test_the_awk_on_the_host_and_the_rule_on_the_server_leave_the_same_text(self):
        for name, text in self.FILES.items():
            with self.subTest(name):
                self.assertEqual(awk_scrub(text).splitlines(), confread.scrub(text).splitlines())
                self.assertNotIn('SECRET', confread.scrub(text))

    def test_what_is_not_a_credential_stays(self):
        kept = confread.scrub(self.FILES['headers'])
        self.assertIn('to: http://10.0.0.5:8080', kept)
        self.assertIn('allow_any_authenticated_user: true', kept, 'the line after the block that was dropped')
        self.assertIn('name = "c1"', confread.scrub(self.FILES['a password in an address']))
        kept = confread.scrub(NEBULA_CONF)
        for line in ('cert: /etc/nebula/host.crt', 'am_lighthouse: false', '- route: 172.16.1.0/24', 'dev: nebula1'):
            self.assertIn(line, kept)
        self.assertNotIn('steve@laptop', kept, 'the keys of an account are its block, and go with it')

    def test_the_rule_can_stand_in_a_script(self):
        self.assertNotIn("'", confread.SECRET_LINE + confread.SCRUB_AWK)
        self.assertNotIn('\\', confread.SECRET_LINE)

    def test_any_text_is_scrubbed_the_same_way_twice(self):
        for text in ('', '\n\n', 'key', '-----BEGIN', '"', 'a: "\nb\n', '\t- token: x\n\t- y\n', 'x' * 5000, '- a\n- key: 1\n  b: 2\n- c\n'):
            self.assertEqual(awk_scrub(text).splitlines(), confread.scrub(text).splitlines(), text[:40])
            self.assertEqual(confread.scrub(confread.scrub(text)), confread.scrub(text))


class Nebula(unittest.TestCase):
    def test_a_host_with_two_lighthouses_a_relay_and_networks_behind_other_hosts(self):
        got = overlays.nebula(confread.scrub(NEBULA_CONF), NEBULA_CERT)
        self.assertEqual((got['network'], got['state'], got['role'], got['relay'], got['interface'], got['port']), ('nebula', 'configured', 'host', False, 'nebula1', 4242))
        self.assertEqual(got['self'], {'name': 'lighthouse1', 'addresses': ['10.99.0.1'], 'key': '939d3e0ff7316ca7533b4ca8d444069aa33aa87e5bd0804208d8bd8f8422d0b0'})
        self.assertEqual(got['routes'], ['192.168.50.0/24'], 'the networks its certificate lets it route for others')
        by = {p['addresses'][0]: p for p in got['peers']}
        self.assertEqual(sorted(by), ['192.168.100.1', '192.168.100.2'])
        self.assertEqual((by['192.168.100.1']['lighthouse'], by['192.168.100.1']['relay'], by['192.168.100.1']['endpoints']), (True, True, ['100.64.22.11:4242']))
        self.assertEqual((by['192.168.100.2']['relay'], by['192.168.100.2']['endpoints']), (False, ['lh2.example.net:4242', '[2001:db8::2]:4242']))
        self.assertIsNone(by['192.168.100.1']['online'], 'Nebula has no status command: nothing says a peer is up')
        self.assertEqual(got['uses_routes'], [{'route': '172.16.1.0/24', 'via': '192.168.100.99'}, {'route': '192.168.87.0/24', 'via': '192.168.100.1'}, {'route': '192.168.87.0/24', 'via': '192.168.100.2'}])
        self.assertEqual(got['certificate'], {'name': 'lighthouse1', 'groups': ['servers', 'lighthouse'], 'expires': '2036-11-17T09:33:14-08:00'})
        self.assertIn('names 2 lighthouse(s)', overlays.sentence(got))
        self.assertIn('which peers are up is not known', overlays.sentence(got))

    def test_a_lighthouse_says_so_and_the_file_is_read_without_its_certificate(self):
        conf = NEBULA_CONF.replace('am_lighthouse: false', 'am_lighthouse: true').replace('am_relay: false', 'am_relay: true')
        got = overlays.nebula(conf)
        self.assertEqual((got['role'], got['relay'], got['self'], got['certificate']), ('lighthouse', True, {'name': None, 'addresses': [], 'key': None}, None))
        self.assertIn('a lighthouse that also relays', overlays.sentence(got))
        self.assertEqual(overlays.nebula(NEBULA_CONF.replace('am_relay: false', 'am_relay: true'))['role'], 'relay')

    def test_the_key_in_the_file_is_in_nothing_that_comes_back(self):
        """The reader scrubs again what the host already scrubbed, so a file from a collector that did not is no worse."""
        for conf in (NEBULA_CONF, confread.scrub(NEBULA_CONF)):
            self.assertNotIn('SECRET', json.dumps(overlays.nebula(conf, NEBULA_CERT)))
            self.assertNotIn('steeeeve', json.dumps(overlays.nebula(conf, NEBULA_CERT)), 'an account that may use its debug shell is not kept')

    def test_a_certificate_as_nebula_printed_it_before_1_10(self):
        got = overlays.nebula(NEBULA_CONF, NEBULA_CERT_OLD)
        self.assertEqual((got['self']['name'], got['self']['addresses'], got['routes'], got['certificate']['expires']), ('old', ['10.99.0.7'], ['192.168.60.0/24'], '2027-01-01T00:00:00Z'))

    def test_the_ca_in_the_same_file_is_not_taken_for_the_host(self):
        ca = {'details': {'isCa': True, 'name': 'lab', 'networks': None, 'notAfter': '2036-11-17T09:33:15-08:00'}, 'fingerprint': 'f1b0'}
        got = overlays.nebula(NEBULA_CONF, json.dumps([ca] + json.loads(NEBULA_CERT)))
        self.assertEqual(got['self']['name'], 'lighthouse1')
        self.assertIsNone(overlays.nebula(NEBULA_CONF, json.dumps([ca]))['certificate'])

    @unittest.skipUnless(REAL_NEBULA_CERT, 'needs the real nebula-cert (in PATH, or in the folder STORAGEFORGE_TEST_NEBULA names)')
    def test_what_the_real_nebula_cert_prints_today(self):
        with tempfile.TemporaryDirectory() as d:
            def run(*words):
                return subprocess.run([REAL_NEBULA_CERT, *words], cwd=d, capture_output=True, text=True, check=True).stdout
            run('ca', '-name', 'lab', '-duration', '48h')
            run('sign', '-name', 'gw', '-ip', '10.99.0.9/24', '-groups', 'gateways', '-subnets', '192.168.70.0/24', '-duration', '24h')
            got = overlays.nebula(NEBULA_CONF, run('print', '-json', '-path', 'gw.crt'))
        self.assertEqual((got['self']['name'], got['self']['addresses'], got['routes'], got['certificate']['groups']), ('gw', ['10.99.0.9'], ['192.168.70.0/24'], ['gateways']))
        self.assertEqual(len(got['self']['key']), 64, 'the fingerprint of the certificate, which is public')
        self.assertTrue(got['certificate']['expires'])

    def test_its_interface_is_named_by_what_it_said_whatever_it_is_called(self):
        got = overlays.nebula(NEBULA_CONF.replace('dev: nebula1', 'dev: mesh0'), NEBULA_CERT)
        known = overlays.interfaces_of([got])
        self.assertEqual(overlays.network_of('mesh0', '10.99.0.1', known), 'nebula')
        self.assertEqual(overlays.network_of('eth5', '10.99.0.1/24', known), 'nebula', 'by the address its certificate gives it')
        self.assertIsNone(overlays.network_of('mesh0', '10.99.0.1'), 'and by nothing when the tool was not read')
        self.assertIsNone(overlays.network_of('eth0', '192.168.1.5', known))

    def test_nothing_a_host_could_send_makes_it_raise(self):
        junk = ['', None, 7, 'x', '- a', '{', 'pki: 5', 'pki: {}\nlighthouse: {hosts: 5}\nstatic_host_map: {1: 2, "x": [3]}\ntun: {unsafe_routes: [1, {route: 5, via: [1, {gateway: 7}]}], dev: 9}\nlisten: {port: true}',
                'a: &a [*a]', 'pki: {}\nrelay: {relays: {a: 1}}', '[' * 400, 'x' * (overlays.MAX_INPUT + 1), 'tun:\n  dev: ' + 'n' * 400, 'lighthouse:\n  hosts: ["' + '", "'.join(f'10.0.{i // 250}.{i % 250}' for i in range(3000)) + '"]']
        for conf in junk:
            for cert in junk[:9] + [NEBULA_CERT, '[1, {"details": 5}, {"details": {"groups": 5, "networks": "x", "name": 4}}]', '{"details": {"isCa": false, "groups": [1, null]}}']:
                got = overlays.nebula(conf, cert)
                self.assertEqual(got['network'], 'nebula')
                json.dumps(got)
                self.assertIsInstance(overlays.sentence(got, 1e9), str)
        self.assertEqual(overlays.nebula('routes: []\n')['error'], 'not a Nebula configuration')
        self.assertLessEqual(len(overlays.nebula(junk[-1])['peers']), overlays.MAX_LIST, 'a list is cut')
        self.assertEqual(len(overlays.nebula(junk[-2])['interface']), 15)

    def test_a_reader_that_fails_leaves_an_error_and_the_others_are_still_read(self):
        from unittest import mock
        s = {'nebula_conf': NEBULA_CONF.splitlines(), 'netmaker_json': NETMAKER.splitlines(), 'swan_conns': SWAN_CONNS.splitlines(), 'openvpn_pki': OPENVPN_PKI.splitlines()}
        with mock.patch.object(overlays, 'nebula', side_effect=RuntimeError('a bug')), mock.patch.object(overlays, 'openvpn_certificates', side_effect=RuntimeError('another')):
            got = inframeasure.parse_overlays(s)
        self.assertEqual([(o['network'], o.get('error')) for o in got], [('netmaker', None), ('nebula', 'could not be read'), ('ipsec', None), ('openvpn', None)])
        self.assertEqual(got[-1]['pki'], {'network': 'openvpn', 'error': 'could not be read'})
        self.assertEqual(overlays.sentence(got[1]), 'Nebula is here, and its status could not be read')
        self.assertEqual(overlays.sentence(got[-1], NOV_21_2026), 'OpenVPN server: 0 client(s) connected', 'certificates that could not be read are not counted as none')

    def test_through_the_scan(self):
        got = inframeasure.parse_overlays({'nebula_conf': confread.scrub(NEBULA_CONF).splitlines(), 'nebula_cert': [NEBULA_CERT]})
        self.assertEqual([(o['network'], o['self']['name']) for o in got], [('nebula', 'lighthouse1')])
        self.assertEqual(inframeasure.parse_overlays({'nebula_conf': [], 'nebula_cert': [NEBULA_CERT]}), [], 'a certificate with no configuration is not a Nebula host')


# `netclient list -l` of netclient 1.x (github.com/gravitl/netclient, functions/list.go): `json.MarshalIndent` of one `output` for
# each network the host is a node of, with the fields network, node_id, connected, ipv4_addr, ipv6_addr and, with -l, peers, each
# a public_key, an endpoint and allowed_ips. The log line before it is what netclient writes when its server is slow to answer.
NETMAKER = '[netclient] 2026-11-20 10:00:00 retrying the server\n' + json.dumps([
    {'network': 'lab', 'node_id': '0b6f5a3c-5d0b-4a5e-9a51-2f3f6d0c1a11', 'connected': True, 'ipv4_addr': '10.20.0.3/24', 'ipv6_addr': 'fd00:20::3/64', 'peers': [
        {'public_key': 'pk-gateway=', 'endpoint': '203.0.113.9:51821', 'allowed_ips': ['10.20.0.1/32', 'fd00:20::1/128', '192.168.40.0/24', '10.77.0.0/16']},
        {'public_key': 'pk-pi=', 'endpoint': '10.42.0.9:51821', 'allowed_ips': ['10.20.0.2/32']}]},
    {'network': 'backup', 'node_id': '7a0e4c1d-1111-4222-8333-944455556666', 'connected': False, 'ipv4_addr': '10.30.0.3/24', 'ipv6_addr': '', 'peers': [
        {'public_key': 'pk-gateway=', 'endpoint': '203.0.113.9:51821', 'allowed_ips': ['10.30.0.1/32']}]}], indent=' ')

# `swanctl --list-sas`: the first tunnel is the example of docs.strongswan.org/docs/latest/swanctl/swanctlListSas.html, word for
# word. The others follow the same format strings (strongSwan's src/swanctl/commands/list_sas.c): a site-to-site tunnel with two
# networks behind the other end, one of them with a protocol and port, a client that was handed a virtual address and signed in
# with EAP, and a tunnel still being set up.
SWAN_SAS = """home: #1, ESTABLISHED, IKEv2, 6fd55d95f66b4a67_i* cea64d4a303e0ca2_r
  local  'carol@strongswan.org' @ 192.168.0.100[4500]
  remote 'moon.strongswan.org' @ 192.168.0.1[4500]
  AES_CBC-128/HMAC_SHA2_256_128/PRF_HMAC_SHA2_256/CURVE_25519
  established 1s ago, rekeying in 14043s
  net: #1, reqid 1, INSTALLED, TUNNEL, ESP:AES_GCM_16-128
    installed 1s ago, rekeying in 3397s, expires in 3959s
    in  c8931e89,     84 bytes,     1 packets,     0s ago
    out cee78125,     84 bytes,     1 packets,     0s ago
    local  192.168.0.100/32
    remote 10.1.0.0/16
gw-gw: #2, ESTABLISHED, IKEv2, 1a2b3c4d5e6f7a8b_i* 9a8b7c6d5e4f3a2b_r
  local  'moon.strongswan.org' @ 192.168.0.100[500]
  remote 'C=CH, O=strongSwan Project, CN=sun.strongswan.org' @ 192.168.0.2[500]
  AES_CBC-128/HMAC_SHA2_256_128/PRF_HMAC_SHA2_256/CURVE_25519
  established 120s ago, rekeying in 13000s, reauth in 20000s
  net-net: #3, reqid 2, INSTALLED, TUNNEL, ESP:AES_GCM_16-128
    installed 120s ago, rekeying in 3200s, expires in 3840s
    in  c1a2b3c4,   1680 bytes,    20 packets,     5s ago
    out c5d6e7f8,   1680 bytes,    20 packets,     5s ago
    local  10.1.0.0/16
    remote 10.2.0.0/16 10.3.0.0/24[tcp/http]
rw: #5, ESTABLISHED, IKEv2, 0011223344556677_i 8899aabbccddeeff_r*
  local  'moon.strongswan.org' @ 192.168.0.100[4500]
  remote '192.168.7.44' @ 203.0.113.77[4500] EAP: 'carol o'brien' [10.9.0.1 fd09::1]
  AES_GCM_16-256/PRF_HMAC_SHA2_384/ECP_384
  established 60s ago, rekeying in 14000s
  rw: #9, reqid 3, cpu 2, INSTALLED, TUNNEL-in-UDP, ESP:AES_GCM_16-256
    installed 60s ago, rekeying in 3300s, expires in 3900s
    in  aa11bb22,      0 bytes,     0 packets
    out cc33dd44,      0 bytes,     0 packets
    local  10.1.0.0/16
    remote 10.9.0.1/32 fd09::1/128
branch: #6, CONNECTING, IKEv1, 1111111111111111_i* 0000000000000000_r
  local  '%any' @ 192.168.0.100[500]
  remote '%any' @ 198.51.100.4[500]
"""

# `swanctl --list-conns`: the first connection is the example of docs.strongswan.org/docs/latest/swanctl/swanctlListConns.html, word
# for word; the others follow list_conns.c, which prints one `remote:` line for each address a connection may be reached at.
SWAN_CONNS = """home: IKEv2, no reauthentication, rekeying every 14400s
  local:  192.168.0.100
  remote: 192.168.0.1
  local public key authentication:
    id: carol@strongswan.org
    certs: C=CH, O=strongSwan Project, OU=Research, CN=carol@strongswan.org
  remote public key authentication:
    id: moon.strongswan.org
  net: TUNNEL, rekeying every 3600s
    local:  dynamic
    remote: 10.1.0.0/16
dc: IKEv1/2, reauthentication every 10800s, dpd delay 30s
  local:  192.168.0.100[500]
  remote: 198.51.100.20[500]
  remote: dc.example.net[500]
  ppk: carol@strongswan.org, required
  local pre-shared key authentication:
    id: moon.strongswan.org
  remote pre-shared key authentication:
    id: dc.example.net
  dc-net: TUNNEL, rekeying every 3600s, dpd action is restart
    local:  10.1.0.0/16
    remote: 10.50.0.0/16
  dc-dmz: TUNNEL, rekeying every 3600s
    local:  10.1.0.0/16
    remote: 10.51.0.0/24
rw: IKEv2, no reauthentication, rekeying every 14400s
  local:  %any[500]
  remote: %any[500]
  local public key authentication:
    id: moon.strongswan.org
  remote EAP_MSCHAPV2 authentication:
    eap_id: %any
    groups: Research, Sales
  rw: TUNNEL, rekeying every 3600s
    local:  10.1.0.0/16
    remote: dynamic
"""

# What the collector prints of an OpenVPN server's PKI (inframeasure.py, `sec openvpn_pki`), from a CA that the real `openssl ca`
# of OpenSSL 4.1.0 made on 2026-11-20: its index.txt (the format of `openssl ca`, which is what easy-rsa keeps in pki/index.txt:
# flag, expiry, revocation, serial, file, subject, separated by tabs) through the collector's awk, and the dates as `openssl crl
# -lastupdate -nextupdate` and `openssl x509 -enddate` print them. tests/test_connections.py makes such a CA for real.
OPENVPN_PKI = ('i\tV\t290222173810Z\t\t01\tserver\n'
               'i\tV\t290222173810Z\t\t02\tlaptop\n'
               'i\tR\t290222173810Z\t261120173810Z\t03\tbranch\n'
               'i\tV\t210101000000Z\t\t04\told\n'
               'i\tV\t261205000000Z\t\t05\tphone\n'
               'i\tR\t290222173810Z\t261120173810Z,keyCompromise\t06\ttablet\n'
               'r\tNov 20 17:38:10 2026 GMT\tMay 19 17:38:10 2027 GMT\t2\n'
               'c\tserver.crt\tFeb 22 17:38:10 2029 GMT\tserver\n'
               'c\tca.crt\tNov 17 17:38:10 2036 GMT\tEasy-RSA CA\n')
NOV_21_2026 = 1795219200.0        # 2026-11-21T00:00:00Z


class Netmaker(unittest.TestCase):
    def test_each_network_its_address_and_the_gateways_among_its_peers(self):
        got = overlays.netmaker(NETMAKER)
        self.assertEqual((got['network'], got['state'], got['self']['addresses']), ('netmaker', 'connected', ['10.20.0.3', 'fd00:20::3', '10.30.0.3']))
        self.assertEqual([(n['name'], n['connected'], n['addresses']) for n in got['networks']], [('lab', True, ['10.20.0.3', 'fd00:20::3']), ('backup', False, ['10.30.0.3'])])
        gateway, pi = got['peers']
        self.assertEqual((gateway['key'], gateway['addresses'], gateway['routes'], gateway['gateway']), ('pk-gateway=', ['10.20.0.1', 'fd00:20::1', '10.30.0.1'], ['192.168.40.0/24', '10.77.0.0/16'], True),
                         'one peer in two networks is one peer, and what it is allowed beyond itself is what it is the gateway to')
        self.assertEqual((pi['addresses'], pi['routes'], pi['gateway'], pi['online']), (['10.20.0.2'], [], False, None), 'netclient does not say whether a peer is up')
        self.assertNotIn('203.0.113.9', json.dumps(got), 'where a peer connects from is not kept')
        self.assertIn('1 of them a gateway to other networks', overlays.sentence(got))
        self.assertEqual(overlays.network_of('netmaker', '10.20.0.3', overlays.interfaces_of([got])), 'netmaker')

    def test_a_node_with_no_peers_and_a_host_that_joined_nothing(self):
        got = overlays.netmaker(json.dumps([{'network': 'lab', 'node_id': 'x', 'connected': False, 'ipv4_addr': '10.20.0.3/24', 'ipv6_addr': ''}]))
        self.assertEqual((got['state'], got['peers']), ('not connected', []))
        self.assertEqual(overlays.netmaker('[]')['networks'], [])
        self.assertEqual(overlays.netmaker('\nno such network\n')['error'], 'not the JSON this tool prints')

    def test_nothing_a_host_could_print_makes_it_raise(self):
        for text in ('', None, 4, '{}', '[1, "x", null]', '[{"peers": 5}]', '[{"peers": [1, {"public_key": 5}, {"public_key": "k", "allowed_ips": [1, "x", "10.0.0.0/8", null]}], "ipv4_addr": 7}]',
                     '[' * 9000, '[x] [y] [z] [{"network": "lab"}]', json.dumps([{'network': 'n' * 900, 'peers': [{'public_key': f'k{i}', 'allowed_ips': ['10.0.0.1/32'] * 300} for i in range(2500)]}])):
            got = overlays.netmaker(text)
            self.assertEqual(got['network'], 'netmaker')
            json.dumps(got)
            self.assertIsInstance(overlays.sentence(got), str)
            self.assertLessEqual(len(got.get('peers') or []), overlays.MAX_PEERS)

    def test_through_the_scan(self):
        got = inframeasure.parse_overlays({'netmaker_json': NETMAKER.splitlines()})
        self.assertEqual([(o['network'], len(o['peers'])) for o in got], [('netmaker', 2)])


def as_collected(sas: str) -> str:
    """`swanctl --list-sas` as the collector sends it: its sed, run for real."""
    line = next(x for x in inframeasure.BODY.splitlines() if x.startswith('sec swan_sas;'))
    return subprocess.run(['bash', '-c', 'q=$(printf "\\047")\n' + line[line.index('sed -E'):line.index(' | capped')]], input=sas, capture_output=True, text=True, check=True).stdout


def conns_as_collected(conns: str) -> str:
    line = next(x for x in inframeasure.BODY.splitlines() if x.startswith('sec swan_conns;'))
    return subprocess.run(['bash', '-c', line[line.index('grep -avE'):line.index(' | capped')]], input=conns, capture_output=True, text=True).stdout


class StrongSwan(unittest.TestCase):
    def check(self, got):
        self.assertEqual((got['network'], got['state'], got['self']['addresses'], got['configured']), ('ipsec', 'connected', ['192.168.0.100'], 3))
        by = {p['name']: p for p in got['peers']}
        self.assertEqual(sorted(by), ['branch', 'dc', 'gw-gw', 'home', 'rw'])
        self.assertEqual((by['home']['addresses'], by['home']['online'], by['home']['routes'], by['home']['local_routes'], by['home']['ike'], by['home']['client']),
                         (['192.168.0.1'], True, ['10.1.0.0/16'], ['192.168.0.100/32'], 'IKEv2', False))
        self.assertEqual((by['gw-gw']['addresses'], by['gw-gw']['routes'], by['gw-gw']['local_routes']), (['192.168.0.2'], ['10.2.0.0/16', '10.3.0.0/24'], ['10.1.0.0/16']),
                         'a selector is read without its protocol and port')
        self.assertEqual((by['rw']['addresses'], by['rw']['client'], by['rw']['online'], by['rw']['routes']), (['10.9.0.1'], True, True, ['10.9.0.1/32', 'fd09::1/128']),
                         'a client is known by the address it was handed')
        self.assertEqual((by['branch']['online'], by['branch']['addresses'], by['branch']['ike']), (False, ['198.51.100.4'], 'IKEv1'), 'not yet established is not up')
        self.assertEqual((by['dc']['online'], by['dc']['addresses'], by['dc']['routes'], by['dc']['ike'], by['dc']['client']), (False, ['198.51.100.20'], ['10.50.0.0/16', '10.51.0.0/24'], 'IKEv1/2', False),
                         'configured and down: drawn from the list of connections')
        self.assertEqual(got['routes'], ['192.168.0.100/32', '10.1.0.0/16'], 'the networks at this end')
        said = json.dumps(got)
        for person in ('carol', 'brien', 'strongswan.org', 'Research', '203.0.113.77', 'sun.'):
            self.assertNotIn(person, said, 'no identity, and not where a client connects from')
        self.assertEqual(overlays.sentence(got), 'IPsec: 2 of 4 site-to-site tunnel(s) up, and 1 client connection(s)')

    def test_as_swanctl_prints_it(self):
        self.check(overlays.strongswan(SWAN_SAS, SWAN_CONNS))

    def test_as_the_collector_sends_it_without_any_identity(self):
        sas, conns = as_collected(SWAN_SAS), conns_as_collected(SWAN_CONNS)
        for person in ('carol', 'brien', 'moon', 'Research', 'sun.strongswan', 'dc.example.net\n'):
            self.assertNotIn(person, sas + conns.replace('remote: dc.example.net', ''), 'an identity does not leave the host')
        self.assertIn("  remote '-' @ 203.0.113.77[4500] EAP: '-' [10.9.0.1 fd09::1]", sas)
        self.assertIn('    remote 10.2.0.0/16 10.3.0.0/24[tcp/http]', sas, 'everything else is as it was')
        self.check(overlays.strongswan(sas, conns))

    def test_connections_alone_and_tunnels_alone(self):
        down = overlays.strongswan('', SWAN_CONNS)
        self.assertEqual((down['state'], [(p['name'], p['online']) for p in down['peers']]), ('not connected', [('home', False), ('dc', False), ('rw', False)]))
        self.assertTrue(down['peers'][2]['client'], 'a connection anyone may open from anywhere is for clients')
        self.assertEqual(overlays.sentence(down), 'IPsec: 0 of 2 site-to-site tunnel(s) up, and 1 client connection(s)')
        self.assertEqual(len(overlays.strongswan(SWAN_SAS)['peers']), 4)
        self.assertEqual(overlays.strongswan('', '')['error'], 'nothing read')
        self.assertEqual(overlays.strongswan('no files found matching \'/etc/swanctl/conf.d/*.conf\'\n', '')['peers'], [], 'swanctl with nothing loaded is an answer')
        self.assertEqual(overlays.strongswan('connecting to \'unix:///var/run/charon.vici\' failed: Connection refused', '')['error'], 'not what swanctl prints')

    def test_nothing_a_host_could_print_makes_it_raise(self):
        junk = ['', None, 3, 'x', 'a: #1, ESTABLISHED, IKEv2', "a: #1, X, IKEv9, y\n  remote '' @ [1]\n  remote 'x' @ nowhere[x] [\n  a: #1, reqid 1, A, B\n    remote \n    local  x y z\n    remote 999.0.0.0/8 /",
                SWAN_SAS * 3000, SWAN_SAS.replace('\n', '\r\n'), '\x00' * 50, 'a: IKEv2,\n  remote: [\n  b: TUNNEL\n    remote: ', SWAN_SAS[:700], SWAN_CONNS[:333]]
        for sas in junk:
            for conns in junk:
                got = overlays.strongswan(sas, conns)
                self.assertEqual(got['network'], 'ipsec')
                json.dumps(got)
                self.assertIsInstance(overlays.sentence(got), str)
                self.assertLessEqual(len(got.get('peers') or []), overlays.MAX_PEERS)

    def test_through_the_scan_a_host_with_connections_and_no_tunnel_up_is_still_read(self):
        got = inframeasure.parse_overlays({'swan_sas': [], 'swan_conns': SWAN_CONNS.splitlines()})
        self.assertEqual([(o['network'], o['state'], len(o['peers'])) for o in got], [('ipsec', 'not connected', 3)])
        known = overlays.interfaces_of(got + [overlays.strongswan(SWAN_SAS)])
        self.assertIsNone(overlays.network_of('eth0', '192.168.0.100', known), 'the local end of an IPsec tunnel is the address the host already has: its LAN is not renamed')


class OpenVpnCertificates(unittest.TestCase):
    def test_each_certificate_its_state_and_dates_and_the_crl(self):
        got = overlays.openvpn_certificates(OPENVPN_PKI)
        by = {c['name']: c for c in got['certificates']}
        self.assertEqual((by['laptop']['state'], by['laptop']['expires'], by['laptop']['revoked'], by['laptop']['serial']), ('valid', '2029-02-22T17:38:10Z', None, '02'))
        self.assertEqual((by['branch']['state'], by['branch']['revoked']), ('revoked', '2026-11-20T17:38:10Z'))
        self.assertEqual(by['tablet']['revoked'], '2026-11-20T17:38:10Z', 'the reason after the date is not part of the date')
        self.assertEqual(by['old']['expires'], '2021-01-01T00:00:00Z')
        self.assertEqual(got['crl'], {'updated': '2026-11-20T17:38:10Z', 'next': '2027-05-19T17:38:10Z', 'revoked': 2})
        self.assertEqual(got['files'], [{'file': 'server.crt', 'name': 'server', 'expires': '2029-02-22T17:38:10Z'}, {'file': 'ca.crt', 'name': 'Easy-RSA CA', 'expires': '2036-11-17T17:38:10Z'}])

    def test_how_it_stands_today_is_counted_when_it_is_drawn(self):
        pki = overlays.openvpn_certificates(OPENVPN_PKI)
        now = overlays.certificate_counts(pki, NOV_21_2026)
        self.assertEqual((now['valid'], now['revoked'], now['expired'], now['ending'], now['crl_ended'], now['crl_next']), (5, 2, 1, ['phone'], False, '2027-05-19T17:38:10Z'),
                         'still marked valid in the index, and past its date: ended. The CA and the server certificate are counted with the rest')
        later = overlays.certificate_counts(pki, NOV_21_2026 + 200 * 86400)
        self.assertEqual((later['valid'], later['expired'], later['ending'], later['crl_ended']), (4, 2, [], True))
        server = {'network': 'openvpn', 'state': 'server', 'self': None, 'peers': [], 'pki': pki}
        self.assertEqual(overlays.sentence(server, NOV_21_2026),
                         'OpenVPN server: 0 client(s) connected. Certificates: 5 valid, 2 revoked, 1 ended; ending within 30 days: phone. The CRL is good until 2027-05-19T17:38:10Z')
        self.assertIn('OpenVPN refuses every client until it is made again', overlays.sentence(server, NOV_21_2026 + 200 * 86400))
        self.assertEqual(overlays.sentence(server), 'OpenVPN server: 0 client(s) connected', 'with no time given nothing is said of dates')

    def test_the_index_alone_and_a_server_with_no_status_file(self):
        got = inframeasure.parse_overlays({'openvpn_pki': OPENVPN_PKI.splitlines()[:3]})
        self.assertEqual([(o['network'], o['state'], o['status_read'], len(o['pki']['certificates']), o['pki']['crl']) for o in got], [('openvpn', 'server', False, 3, None)])
        from test_overlays import OPENVPN
        both = inframeasure.parse_overlays({'openvpn_status': OPENVPN.splitlines(), 'openvpn_pki': OPENVPN_PKI.splitlines()})
        self.assertEqual([(o['network'], len(o['peers']), len(o['pki']['certificates'])) for o in both], [('openvpn', 2, 6)], 'the certificates belong to the server the status file is of')

    def test_nothing_a_host_could_print_makes_it_raise(self):
        for text in ('', None, 5, 'x', 'i\t', 'i\tV', 'i\tQ\t1\t2\t3\t4', 'i\tV\tnot a date\t\t\t', 'r\t\t\t', 'r\tx\ty\tz', 'c\t\t\t', 'c\ta/b/../c.crt\tJan  1 00:00:00 2030 GMT\t' + 'n' * 900,
                     'i\tR\t999999999999Z\t,,,\t' + 'f' * 900 + '\tx', OPENVPN_PKI * 900, 'r\tNov 20 17:38:10 2026 GMT\tMay 19 17:38:10 2027 GMT\t' + '9' * 40, '\t\t\t\t\t\t'):
            got = overlays.openvpn_certificates(text)
            self.assertEqual(got['network'], 'openvpn')
            json.dumps(got)
            json.dumps(overlays.certificate_counts(got, NOV_21_2026))
            self.assertLessEqual(len(got.get('certificates') or []), overlays.MAX_PEERS)
        got = overlays.openvpn_certificates('c\ta/b/../c.crt\tJan  1 00:00:00 2030 GMT\t' + 'n' * 900)
        self.assertEqual((got['files'][0]['file'], len(got['files'][0]['name']), got['files'][0]['expires']), ('c.crt', overlays.MAX_TEXT, '2030-01-01T00:00:00Z'))
        for odd in (None, 5, {}, {'certificates': 5, 'crl': 7, 'files': [3]}, {'certificates': [{'expires': 9}], 'crl': {'next': []}}):
            json.dumps(overlays.certificate_counts(odd, NOV_21_2026))


class ZeroTierPeers(unittest.TestCase):
    """`zerotier-cli -j peers` of ZeroTier 1.14 (github.com/zerotier/ZeroTierOne, one.cpp: the JSON of /peer): each peer has its
    ten-digit address, a role, a latency and its paths, each an `address` written ip/port with `active` and `preferred`."""
    PEERS = json.dumps([
        {'address': 'ffeeddccbb', 'isBonded': False, 'latency': 4, 'role': 'LEAF', 'version': '1.14.2', 'tunneled': False,
         'paths': [{'active': True, 'address': '10.42.0.9/9993', 'expired': False, 'lastReceive': 1795219000000, 'lastSend': 1795219000000, 'preferred': True, 'trustedPathId': 0},
                   {'active': True, 'address': '2001:db8::9/9993', 'expired': False, 'preferred': False}, {'active': False, 'address': '198.51.100.9/21001', 'expired': True, 'preferred': False}]},
        {'address': '1122334455', 'latency': -1, 'role': 'LEAF', 'paths': []},
        {'address': '778cde7190', 'latency': 30, 'role': 'PLANET', 'paths': [{'active': True, 'address': '103.195.103.66/9993', 'preferred': True}]}])

    def test_where_a_peer_is_reached_is_kept_without_its_port_and_only_for_a_path_in_use(self):
        from test_overlays import ZT_INFO, ZT_NETWORKS
        got = overlays.zerotier(ZT_INFO, ZT_NETWORKS, self.PEERS)
        self.assertEqual([(p['key'], p['online'], p['endpoints']) for p in got['peers']], [('ffeeddccbb', True, ['10.42.0.9', '2001:db8::9']), ('1122334455', False, [])])
        self.assertEqual(got['self']['key'], 'a1b2c3d4e5', 'its own node id, which is what another host sees it as')
        self.assertEqual(overlays.network_of('eth7', '10.147.17.5', overlays.interfaces_of([got])), 'zerotier')
        self.assertEqual(overlays.network_of('ztabcdef12'), 'zerotier')

    def test_odd_paths_do_not_make_it_raise(self):
        from test_overlays import ZT_INFO
        for paths in (5, [5, None, {'active': True}, {'active': True, 'address': 7}, {'active': True, 'address': 'nowhere/1'}, {'active': True, 'address': '/'}], [{'active': True, 'address': f'10.0.0.{i}/9993'} for i in range(200)]):
            got = overlays.zerotier(ZT_INFO, '[]', json.dumps([{'address': 'ffeeddccbb', 'role': 'LEAF', 'latency': True, 'paths': paths}]))
            self.assertLessEqual(len(got['peers'][0]['endpoints']), 4)
            self.assertIsNone(got['peers'][0]['latency_ms'])


if __name__ == '__main__':
    unittest.main()
