"""Connections on a scan and on the map (roadmap section 2): the collector's own lines run for real against stand-in tools, what
they print is read, and the map is built from it. What must hold: each private network's peers are drawn, a scanned host confirmed
and anything else a placeholder; a tunnel is drawn as public; and a tunnel's credential never leaves the host."""
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from storageforge_index import infragraph, inframeasure
from test_overlays import HEADSCALE, NETBIRD, OPENVPN, TAILSCALE, ZT_INFO, ZT_NETWORKS, ZT_PEERS
from test_tunnels import CLOUDFLARED, FRP_TOML


class Collected(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.bin = self.tmp / 'bin'
        self.bin.mkdir()
        # Only these and the stand-ins are on PATH: the machine running the tests may have a real tailscale, and its tailnet is not test data
        for real in ('bash', 'sh', 'cat', 'grep', 'head', 'timeout', 'sed', 'tr', 'base64'):
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
        self.assertNotIn('credentials-file', out)
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


if __name__ == '__main__':
    unittest.main()
