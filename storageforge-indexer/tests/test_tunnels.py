"""Tunnels that publish a service (roadmap section 2, exposure): Cloudflare Tunnel, frp and ngrok, read from their configuration.
What must hold: what is public is named; a credential in the file is in nothing that comes back; and no reader raises."""
import json
import re
import subprocess
import unittest

from storageforge_index import tunnels

CLOUDFLARED = """tunnel: 6ff42ae2-765d-4adf-8112-31c55c1551ef
credentials-file: /root/.cloudflared/6ff42ae2.json
token: eyJhIjoiSECRETSECRETSECRET
ingress:
  - hostname: photos.example.com
    service: http://localhost:2283
  - hostname: git.example.com
    path: /api
    service: https://127.0.0.1:3000
    originRequest:
      noTLSVerify: true
  - service: http_status:404
"""

FRP_TOML = """serverAddr = "frp.example.net"
serverPort = 7000
auth.method = "token"
auth.token = "SECRETSECRETSECRET"

[[proxies]]
name = "ssh"
type = "tcp"
localIP = "127.0.0.1"
localPort = 22
remotePort = 6000

[[proxies]]
name = "web"
type = "http"
localPort = 8080
customDomains = ["www.example.net", "example.net"]

[[proxies]]
name = "private"
type = "stcp"
secretKey = "SECRETSECRETSECRET"
localPort = 5432
"""

FRP_INI = """[common]
server_addr = frp.example.net
server_port = 7000
token = SECRETSECRETSECRET

[ssh]
type = tcp
local_ip = 127.0.0.1
local_port = 22
remote_port = 6000

[web]
type = https
local_port = 8443
custom_domains = a.example.net, b.example.net
"""

NGROK = """version: "3"
agent:
  authtoken: 2SECRETSECRETSECRET
tunnels:
  site:
    proto: http
    addr: 8080
    domain: site.example.ngrok.app
  db:
    proto: tcp
    addr: 5432
endpoints:
  - name: api
    url: https://api.example.ngrok.app
    upstream:
      url: http://localhost:9000
"""


class Readers(unittest.TestCase):
    def test_cloudflared_names_each_hostname_and_not_the_catch_all(self):
        got = tunnels.cloudflared(CLOUDFLARED)
        self.assertEqual(got['published'], [{'public': 'https://photos.example.com', 'local': 'localhost:2283', 'protocol': 'http'},
                                            {'public': 'https://git.example.com/api', 'local': '127.0.0.1:3000', 'protocol': 'https'}])
        self.assertEqual((got['tunnel'], got['remote']), ('6ff42ae2-765d-4adf-8112-31c55c1551ef', False))
        self.assertIn('Public through Cloudflare Tunnel: https://photos.example.com → localhost:2283', tunnels.sentence(got))

    def test_a_tunnel_run_from_a_token_alone_says_its_routes_are_elsewhere(self):
        got = tunnels.cloudflared('tunnel: abc\n')
        self.assertEqual((got['published'], got['remote']), ([], True))
        self.assertIn('cannot be read from this host', tunnels.sentence(got))

    def test_frp_in_both_forms(self):
        got = tunnels.frp(FRP_TOML)
        self.assertEqual([(p['name'], p['public'], p['local']) for p in got['published']],
                         [('ssh', 'frp.example.net:6000/tcp', '127.0.0.1:22'), ('web', 'http://www.example.net', '127.0.0.1:8080'), ('web', 'http://example.net', '127.0.0.1:8080')],
                         'the stcp proxy is not public: only a visitor with its key reaches it')
        old = tunnels.frp(FRP_INI)
        self.assertEqual([(p['name'], p['public'], p['local']) for p in old['published']],
                         [('ssh', 'frp.example.net:6000/tcp', '127.0.0.1:22'), ('web', 'https://a.example.net', '127.0.0.1:8443'), ('web', 'https://b.example.net', '127.0.0.1:8443')])

    def test_ngrok_tunnels_and_endpoints(self):
        got = tunnels.ngrok(NGROK)
        self.assertEqual([(p['name'], p['public'], p['local']) for p in got['published']],
                         [('site', 'https://site.example.ngrok.app', 'localhost:8080'), ('db', '(a random ngrok address)', 'localhost:5432'), ('api', 'https://api.example.ngrok.app', 'localhost:9000')])

    def test_no_credential_is_in_anything_that_comes_back(self):
        for reader, text in ((tunnels.cloudflared, CLOUDFLARED), (tunnels.frp, FRP_TOML), (tunnels.frp, FRP_INI), (tunnels.ngrok, NGROK)):
            self.assertNotIn('SECRET', json.dumps(reader(text)))
            self.assertNotIn('SECRET', tunnels.scrub(text))
            self.assertNotIn('/root/.cloudflared', tunnels.scrub(text), 'the value of a credential line is blanked, the name stays')

    def test_the_hosts_awk_blanks_the_same_values_scrub_does(self):
        """The collector runs awk with SECRET_LINE on the host, so the credential is not sent at all."""
        for text in (CLOUDFLARED, FRP_TOML, FRP_INI, NGROK):
            kept = subprocess.run(['awk', '-v', f're={tunnels.SECRET_LINE}', tunnels.TUNNEL_AWK], input=text, capture_output=True, text=True).stdout
            self.assertEqual(kept.strip().splitlines(), tunnels.scrub(text).strip().splitlines())
        self.assertTrue(re.fullmatch(r'[\w()|?]+', tunnels.SECRET_LINE), 'nothing in it a shell would read')

    def test_nothing_a_host_could_send_makes_a_reader_raise(self):
        junk = ['', None, 7, 'x', '- a\n- b', '{', 'ingress: 5', 'ingress: [1, {hostname: 9, service: [1]}]', 'tunnels: {a: 1, b: {addr: [1]}}\nendpoints: [3, {upstream: 4}]',
                '[[proxies]]\nname = 3\ntype = 5', '[common\nbroken', 'a: &a [*a]', '[' * 5000, 'x' * (tunnels.MAX_INPUT + 1), 'proxies = 4', '[s]\ntype = tcp\nremote_port = 1\n[s]\n']
        for text in junk:
            for reader in tunnels.READERS.values():
                got = reader(text)
                self.assertIn('tool', got)
                json.dumps(got)
                self.assertIsInstance(tunnels.sentence(got), str)

    def test_what_is_said_when_it_could_not_be_read(self):
        self.assertIn('could not be read', tunnels.sentence(tunnels.frp('x' * (tunnels.MAX_INPUT + 1))))
        self.assertEqual(tunnels.sentence(tunnels.ngrok('version: "3"\n')), 'ngrok is configured and publishes nothing')


if __name__ == '__main__':
    unittest.main()
