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
                'a: &a [*a]', 'pki: {}\nrelay: {relays: {a: 1}}', '[' * 5000, 'x' * (overlays.MAX_INPUT + 1), 'tun:\n  dev: ' + 'n' * 400, 'lighthouse:\n  hosts: ["' + '", "'.join(f'10.0.{i // 250}.{i % 250}' for i in range(3000)) + '"]']
        for conf in junk:
            for cert in junk[:9] + [NEBULA_CERT, '[1, {"details": 5}, {"details": {"groups": 5, "networks": "x", "name": 4}}]', '{"details": {"isCa": false, "groups": [1, null]}}']:
                got = overlays.nebula(conf, cert)
                self.assertEqual(got['network'], 'nebula')
                json.dumps(got)
                self.assertIsInstance(overlays.sentence(got, 1e9), str)
        self.assertEqual(overlays.nebula('routes: []\n')['error'], 'not a Nebula configuration')
        self.assertLessEqual(len(overlays.nebula(junk[-1])['peers']), overlays.MAX_LIST, 'a list is cut')
        self.assertEqual(len(overlays.nebula(junk[-2])['interface']), 15)

    def test_through_the_scan(self):
        got = inframeasure.parse_overlays({'nebula_conf': confread.scrub(NEBULA_CONF).splitlines(), 'nebula_cert': [NEBULA_CERT]})
        self.assertEqual([(o['network'], o['self']['name']) for o in got], [('nebula', 'lighthouse1')])
        self.assertEqual(inframeasure.parse_overlays({'nebula_conf': [], 'nebula_cert': [NEBULA_CERT]}), [], 'a certificate with no configuration is not a Nebula host')


if __name__ == '__main__':
    unittest.main()
