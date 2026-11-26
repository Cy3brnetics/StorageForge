"""Exposure through tunnels (roadmap section 2, part 4), and the two steps that start a tunnel from a secret in the vault.
What must hold: a service a running tunnel publishes is public in the exposure view and the security view although no port is
open; a tunnel whose routes cannot be read is unknown, never fine; and a token is in a file only its owner reads, on no command
line, in no output. cloudflared and Newt are not installed here, so the steps run against stand-ins that record what they were
started with; neither step has met the real program."""
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

import dbfactory
from storageforge_index import changes, exposure, inframeasure, security, steps_tunnels

TOKEN = 'eyJhIjoiTESTTESTTESTnotARealTunnelToken0000000000000000000000In0='
SITE_SECRET = 'q7testsecretnotarealone0000000000000000000000000000000000'
NET = {'interfaces': [{'name': 'eth0', 'kind': 'ethernet', 'state': 'up', 'addresses': [{'ip': '192.168.1.10', 'prefix': 24}]}], 'routes': [], 'listeners': []}
CLOUDFLARED = 'tunnel: 6ff42ae2\ningress:\n  - hostname: photos.example.com\n    service: http://localhost:2283\n  - hostname: nas.example.com\n    service: https://192.168.1.50\n  - service: http_status:404\n'


def lsn(addr, port, proto='tcp'):
    return {'proto': proto, 'addr': addr, 'port': port, 'scope': 'loopback' if addr.startswith('127.') else 'any', 'process': ['immich']}


def infra(sections, listeners):
    return {'firewall': None, 'listeners': listeners, 'access': {'tunnels': inframeasure.parse_tunnels(sections)}}


class Exposure(unittest.TestCase):
    def test_where_a_tunnel_sends_a_request(self):
        for local, protocol, want in (('localhost:2283', 'http', ('localhost', 2283)), ('127.0.0.1:3000', 'https', ('127.0.0.1', 3000)), ('[::1]:80', 'http', ('::1', 80)),
                                      ('localhost', 'http', ('localhost', 80)), ('192.168.1.50', 'https', ('192.168.1.50', 443)), ('localhost', 'ssh', ('localhost', 22)),
                                      ('8080', None, ('localhost', 8080)), ('http_status:404', None, (None, None)), ('unix:/run/app.sock', None, (None, None)),
                                      ('db.internal', 'tcp', ('db.internal', None)), (None, None, (None, None)), ('localhost:99999', 'tcp', ('localhost', None))):
            with self.subTest(local):
                self.assertEqual(exposure.tunnel_target(local, protocol), want)

    def test_a_loopback_service_a_running_tunnel_publishes_is_public(self):
        listeners = [lsn('127.0.0.1', 2283), lsn('127.0.0.1', 5432)]
        before = exposure.host_report(NET, infra({}, listeners), [], 'nas')
        self.assertEqual([(i['port'], i['level']) for i in before['items']], [(2283, 'loopback'), (5432, 'loopback')])
        self.assertEqual(before['tunnels'], [])
        rep = exposure.host_report(NET, infra({'cloudflared': CLOUDFLARED.splitlines(), 'tunnel_procs': ['cloudflared']}, listeners), [], 'nas')
        by_port = {i['port']: i for i in rep['items']}
        self.assertEqual((by_port[2283]['level'], by_port[2283]['tunnel']), ('any', 'https://photos.example.com'))
        self.assertIn('Cloudflare Tunnel publishes it at https://photos.example.com', by_port[2283]['rule'])
        self.assertIn('without the tunnel: loopback', by_port[2283]['why'][0])
        self.assertEqual(by_port[5432]['level'], 'loopback', 'what the tunnel does not name stays as it was')
        self.assertEqual(rep['items'][0]['port'], 2283, 'widest first')
        self.assertEqual([(t['public'], t['level'], t['target_host'], t['target_port']) for t in rep['tunnels']],
                         [('https://photos.example.com', 'any', 'localhost', 2283), ('https://nas.example.com', 'any', '192.168.1.50', 443)])
        self.assertIn('no open port and no firewall rule is involved', rep['tunnels'][0]['rule'])

    def test_a_firewall_that_blocks_the_port_does_not_stop_a_tunnel(self):
        fw = {'readable': True, 'backends': ['nftables'], 'rules': [], 'policies': {'input': 'drop'}, 'notes': [], 'tables': []}
        blocked = {'firewall': fw, 'listeners': [lsn('0.0.0.0', 2283)], 'access': {'tunnels': []}}
        was = exposure.host_report(NET, blocked, [], 'nas')['items'][0]['level']
        blocked['access']['tunnels'] = inframeasure.parse_tunnels({'cloudflared': CLOUDFLARED.splitlines(), 'tunnel_procs': ['cloudflared']})
        now = exposure.host_report(NET, blocked, [], 'nas')['items'][0]
        self.assertEqual(now['level'], 'any', f'it was {was} by the firewall alone')
        self.assertTrue(exposure.in_scope(now['level'], 'any'))

    def test_a_tunnel_to_another_machine_does_not_mark_this_ones_listener(self):
        rep = exposure.host_report(NET, infra({'cloudflared': CLOUDFLARED.splitlines(), 'tunnel_procs': ['cloudflared']}, [lsn('127.0.0.1', 443)]), [], 'nas')
        self.assertEqual(rep['items'][0]['level'], 'loopback', 'port 443 of 192.168.1.50 is published, not this host\'s')
        own = exposure.host_report(NET | {'interfaces': [{'name': 'eth0', 'kind': 'ethernet', 'state': 'up', 'addresses': [{'ip': '192.168.1.50', 'prefix': 24}]}]},
                                   infra({'cloudflared': CLOUDFLARED.splitlines(), 'tunnel_procs': ['cloudflared']}, [lsn('127.0.0.1', 443)]), [], 'nas')
        self.assertEqual(own['items'][0]['level'], 'any', 'the same address, when it is this host\'s own')

    def test_a_tunnel_that_is_not_running_or_cannot_be_read_is_unknown_and_never_fine(self):
        stopped = exposure.host_report(NET, infra({'cloudflared': CLOUDFLARED.splitlines()}, [lsn('127.0.0.1', 2283)]), [], 'nas')
        self.assertEqual(stopped['items'][0]['level'], 'loopback', 'nothing carries requests to it now')
        self.assertEqual({t['level'] for t in stopped['tunnels']}, {'unknown'})
        self.assertIn('public whenever it runs', stopped['tunnels'][0]['why'][0])
        for sections, says in (({'tunnel_procs': ['cloudflared']}, 'cannot be read from this host'), ({'tunnel_procs': ['newt']}, 'Pangolin runs with its routes kept at its Pangolin server'),
                               ({'frp': ['[common', 'broken'], 'tunnel_procs': ['frpc']}, 'could not be read')):
            with self.subTest(sections):
                rep = exposure.host_report(NET, infra(sections, []), [], 'nas')
                self.assertEqual([(t['level'], t['public']) for t in rep['tunnels']], [('unknown', None)])
                self.assertIn(says, rep['tunnels'][0]['rule'])
        self.assertEqual(exposure.host_report(NET, infra({'ngrok': ['version: "3"']}, []), [], 'nas')['tunnels'], [], 'configured, and publishes nothing')
        unscanned = exposure.host_report(None, infra({'tunnel_procs': ['cloudflared']}, []), [], 'nas')
        self.assertEqual((unscanned['read'], len(unscanned['tunnels'])), (False, 1), 'a tunnel is said even where the network was never read')

    def test_udp_and_frp(self):
        frp = 'serverAddr = "frp.example.net"\n[[proxies]]\nname = "game"\ntype = "udp"\nlocalPort = 27015\nremotePort = 7001\n[[proxies]]\nname = "ssh"\ntype = "tcp"\nlocalPort = 22\nremotePort = 6000\n'
        rep = exposure.host_report(NET, infra({'frp': frp.splitlines(), 'tunnel_procs': ['frpc']}, [lsn('0.0.0.0', 27015, 'udp'), lsn('0.0.0.0', 27015), lsn('127.0.0.1', 22)]), [], 'nas')
        got = {(i['port'], i['proto']): i.get('tunnel') for i in rep['items']}
        self.assertEqual(got, {(27015, 'udp'): 'frp.example.net:7001/udp', (27015, 'tcp'): None, (22, 'tcp'): 'frp.example.net:6000/tcp'})

    def test_the_security_view_says_what_is_public_and_a_token_on_a_command_line(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        db = dbfactory.make(self, f'{tmp}/t.db')
        conn = db.connect()
        self.addCleanup(conn.close)
        db.migrate(conn)
        conn.execute("INSERT INTO hosts (hostname, ssh_host) VALUES ('nas', '10.42.0.10')")
        self.assertEqual(security.host_coverage(conn, 'nas')['public'], [])
        got = infra({'cloudflared': CLOUDFLARED.splitlines(), 'tunnel_procs': ['cloudflared', 'newt'], 'tunnel_cmdline': ['cloudflared']}, [])
        security._save_measurement(conn, 'nas', 'infra', int(time.time()), 'test', got)
        before = security.host_coverage(conn, 'nas')
        self.assertEqual(len(before['public']), 2)
        self.assertIn('Public through Cloudflare Tunnel: https://photos.example.com → localhost:2283', before['public'][0])
        self.assertIn('Its token is on its command line, where every account on the host can read it', before['public'][0])
        self.assertIn('Pangolin runs with its routes kept at its Pangolin server', before['public'][1])
        self.assertEqual(security.posture(conn, 'nas')['hosts'][0]['public'], before['public'])
        security._save_measurement(conn, 'nas', 'infra', int(time.time()), 'test', infra({'cloudflared': CLOUDFLARED.splitlines()}, []))
        self.assertIn('(not running at the last reading)', security.host_coverage(conn, 'nas')['public'][0])

    @unittest.skipUnless(shutil.which('pgrep'), 'needs pgrep')
    def test_the_collector_sees_a_token_on_a_command_line_and_sends_only_the_name(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        for name in ('cloudflared', 'newt'):          # what pgrep -x goes by is the name of the program, which for a script is its file
            (tmp / name).write_text('#!/bin/bash\nsleep 30\n')
            (tmp / name).chmod(0o755)
        procs = [subprocess.Popen([str(tmp / 'cloudflared'), 'tunnel', 'run', '--token', TOKEN]), subprocess.Popen([str(tmp / 'newt'), '--id', 'abc', '--endpoint', 'https://p.example.com'])]
        self.addCleanup(lambda: [(p.kill(), p.wait()) for p in procs])
        time.sleep(0.3)
        lines = [line for line in inframeasure.BODY.splitlines() if line.startswith(('sec tunnel_procs;', 'sec tunnel_cmdline;'))]
        self.assertEqual(len(lines), 2)
        out = subprocess.run(['bash', '-c', 'sec() { printf "\\n@@%s\\n" "$1"; }\n' + '\n'.join(lines) + '\nsec end\n'], capture_output=True, text=True, timeout=30).stdout
        self.assertNotIn(TOKEN, out)
        s = inframeasure._sections(out)
        self.assertEqual((sorted(x for x in s['tunnel_procs'] if x), [x for x in s['tunnel_cmdline'] if x]), (['cloudflared', 'newt'], ['cloudflared']))
        got = {t['tool']: t.get('token_on_command_line', False) for t in inframeasure.parse_tunnels(s)}
        self.assertEqual(got, {'cloudflared': True, 'newt': False})


REAL_CLOUDFLARED = os.environ.get('STORAGEFORGE_TEST_CLOUDFLARED') or shutil.which('cloudflared')

HARNESS = r'''
set -euo pipefail
ok() { echo "ok: $*"; }; missing() { echo "missing: $*"; }; conflict() { echo "conflict: $*"; PROBLEMS=$((PROBLEMS + 1)); }
info() { echo "info: $*"; }; act() { if ((APPLY)); then echo "doing: $*"; return 0; else echo "would: $*"; return 1; fi; }
try() { "$@" || { conflict "failed: $*"; return 1; }; }
# the reload guard of scriptkit.HELPERS, as a stand-in: DEAD_MOUNT is a hard network mount whose server is gone
reload_systemd() { if [[ -n ${DEAD_MOUNT:-} ]]; then conflict "/mnt/dead is not answering: reloading systemd now would block logins"; return 1; fi; [[ -z ${RELOAD_FAILS:-} ]] && systemctl daemon-reload; }
PROBLEMS=0
'''


class Steps(unittest.TestCase):
    """t_cloudflare_tunnel and t_pangolin_site. systemctl is a stand-in that really starts what the unit's ExecStart names, with the
    unit's environment; cloudflared and newt are stand-ins that write down their own command line and what they read."""

    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.d, True)
        for name in ('bin', 'secrets', 'units', 'cf', 'newt', 'fake', 'run'):
            (self.d / name).mkdir()
        fake = self.d / 'fake'
        self.stub('cloudflared', f'''case "$*" in
  "tunnel run --help") echo "OPTIONS:"; echo "   --token value   The Tunnel token"; [ -e {fake}/old ] || echo "   --token-file value   Filepath at which to read the tunnel token" ;;
  "--version") echo "cloudflared version 2025.8.0 (stand-in)" ;;
  *) tr "\\0" " " </proc/$$/cmdline >{fake}/cloudflared.cmdline
     while [ $# -gt 0 ]; do [ "$1" = --token-file ] && cat "$2" >{fake}/cloudflared.read; shift; done
     [ "$(cat {fake}/cloudflared.read 2>/dev/null)" = "$(cat {fake}/accepts 2>/dev/null)" ] || exit 1 ;;
esac''')
        self.stub('newt', f'''tr "\\0" " " </proc/$$/cmdline >{fake}/newt.cmdline
env >{fake}/newt.env
python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print(d['id'], d['secret'], d['endpoint'], sorted(d))" "$CONFIG_FILE" >{fake}/newt.read || exit 1''')
        # start and restart run ExecStart once, with the unit's Environment: a program that exits 0 counts as running
        self.stub('systemctl', f'''echo "systemctl $*" >>{fake}/calls
unit="${{@: -1}}"; file={self.d}/units/$unit
case "$1" in
  cat) [ -e {fake}/other-$unit ] && cat {fake}/other-$unit || exit 1 ;;
  is-active) [ -e {fake}/active-$unit ] ;;
  start|restart) rm -f {fake}/active-$unit; [ -e "$file" ] || exit 5
     envs=$(sed -n "s/^Environment=//p" "$file"); cmd=$(sed -n "s/^ExecStart=//p" "$file")
     env $envs $cmd && touch {fake}/active-$unit ;;
  disable) rm -f {fake}/active-$unit ;;
esac''')

    def stub(self, name, body):
        p = self.d / 'bin' / name
        p.write_text('#!/bin/bash\n' + body + '\n')
        p.chmod(0o755)

    def step(self, apply, fn, *args, **more):
        call = fn + ' ' + ' '.join(f"'{a}'" for a in args)
        env = {**os.environ, **more, 'PATH': f'{self.d}/bin:{os.environ["PATH"]}', 'SF_SECRET_DIR': str(self.d / 'secrets'), 'SF_UNIT_DIR': str(self.d / 'units'), 'SF_CLOUDFLARED_DIR': str(self.d / 'cf'),
               'SF_NEWT_DIR': str(self.d / 'newt'), 'SF_SYSTEMD_RUN': str(self.d / 'run'), 'SF_TUNNEL_WAIT': '0'}
        got = subprocess.run(['bash', '-c', HARNESS + f'APPLY={int(apply)}\n' + steps_tunnels.BASH + '\n' + call + '\nexit $((PROBLEMS > 0))\n'], capture_output=True, text=True, timeout=60, env=env)
        return got.returncode, got.stdout + got.stderr

    def read(self, name):
        p = self.d / 'fake' / name
        return p.read_text() if p.exists() else ''

    def everything_written(self):
        """Every file the step left, but the two that are meant to hold the secret, and everything it said."""
        keep = {self.d / 'cf' / 'storageforge-token', self.d / 'newt' / 'storageforge.json', self.d / 'fake' / 'cloudflared.read', self.d / 'fake' / 'newt.read', self.d / 'fake' / 'accepts'}
        return '\n'.join(p.read_text(errors='replace') for p in self.d.rglob('*') if p.is_file() and p not in keep and p.parent.name != 'bin')

    # ── cloudflared ──
    def test_cloudflared_runs_from_a_token_file_and_the_token_is_on_no_command_line(self):
        (self.d / 'fake' / 'accepts').write_text(TOKEN)
        code, out = self.step(True, 't_cloudflare_tunnel', 'cf-token', 'present')
        self.assertEqual(code, 1)
        self.assertIn('no tunnel token at', out)
        self.assertIn('vault send-secret cf-token --host', out)
        self.assertNotIn('systemctl start', self.read('calls'))
        (self.d / 'secrets' / 'cf-token').write_text(TOKEN + '\n')
        code, out = self.step(False, 't_cloudflare_tunnel', 'cf-token', 'present')
        self.assertIn('would: keep the tunnel token in', out)
        self.assertEqual(list((self.d / 'cf').iterdir()) + list((self.d / 'units').iterdir()), [], 'a report writes nothing')
        code, out = self.step(True, 't_cloudflare_tunnel', 'cf-token', 'present')
        self.assertEqual(code, 0, out)
        self.assertIn('Its token is in', out)
        token_file = self.d / 'cf' / 'storageforge-token'
        self.assertEqual((token_file.read_text(), oct(token_file.stat().st_mode & 0o777)), (TOKEN, '0o600'))
        self.assertEqual(oct((self.d / 'cf').stat().st_mode & 0o777), '0o700')
        self.assertEqual(self.read('cloudflared.read'), TOKEN, 'cloudflared was handed the token, through the file')
        self.assertEqual(self.read('cloudflared.cmdline').split()[-5:], ['--no-autoupdate', 'tunnel', 'run', '--token-file', str(token_file)])
        unit = (self.d / 'units' / 'storageforge-cloudflared.service').read_text()
        self.assertIn(f'ExecStart={self.d}/bin/cloudflared --no-autoupdate tunnel run --token-file {token_file}\n', unit)
        self.assertNotIn(TOKEN, out + self.everything_written(), 'in no output, no unit, no command line and no log')
        self.assertFalse((self.d / 'secrets' / 'cf-token').exists(), 'the copy in memory is removed')
        code, out = self.step(True, 't_cloudflare_tunnel', 'cf-token', 'present')
        self.assertIn('ok: the tunnel runs as storageforge-cloudflared.service', out)
        self.assertEqual(self.read('calls').count('systemctl restart'), 1, 'a second run starts nothing')

    def test_a_new_token_replaces_the_old_one_and_restarts(self):
        (self.d / 'fake' / 'accepts').write_text(TOKEN)
        (self.d / 'secrets' / 'cf-token').write_text(TOKEN)
        self.assertEqual(self.step(True, 't_cloudflare_tunnel', 'cf-token', 'present')[0], 0)
        newer = TOKEN.replace('TEST', 'NEXT')
        (self.d / 'fake' / 'accepts').write_text(newer)
        (self.d / 'secrets' / 'cf-token').write_text(newer)
        code, out = self.step(True, 't_cloudflare_tunnel', 'cf-token', 'present')
        self.assertEqual(code, 0, out)
        self.assertEqual((self.read('cloudflared.read'), self.read('calls').count('systemctl restart')), (newer, 2))

    def test_an_old_cloudflared_is_refused_because_it_would_take_the_token_as_an_argument(self):
        (self.d / 'fake' / 'old').touch()
        (self.d / 'secrets' / 'cf-token').write_text(TOKEN)
        code, out = self.step(True, 't_cloudflare_tunnel', 'cf-token', 'present')
        self.assertEqual(code, 1)
        self.assertIn('cannot read its token from a file', out)
        self.assertEqual(list((self.d / 'cf').iterdir()) + list((self.d / 'units').iterdir()), [])
        self.assertTrue((self.d / 'secrets' / 'cf-token').exists())

    def test_a_token_cloudflare_refuses_and_a_file_that_is_no_token(self):
        (self.d / 'fake' / 'accepts').write_text('another token')
        (self.d / 'secrets' / 'cf-token').write_text(TOKEN)
        code, out = self.step(True, 't_cloudflare_tunnel', 'cf-token', 'present')
        self.assertEqual(code, 1)
        self.assertIn('cloudflared did not stay running', out)
        self.assertNotIn(TOKEN, out)
        self.assertTrue((self.d / 'secrets' / 'cf-token').exists(), 'kept for the next attempt')
        for bad in ('', 'two words here\nand two lines', 'x; rm -rf /', '$(id)'):
            (self.d / 'secrets' / 'cf-token').write_text(bad)
            (self.d / 'cf' / 'storageforge-token').unlink(missing_ok=True)
            code, out = self.step(True, 't_cloudflare_tunnel', 'cf-token', 'present')
            self.assertEqual(code, 1, bad)
            self.assertIn('does not hold a tunnel token', out)
            self.assertFalse((self.d / 'cf' / 'storageforge-token').exists(), bad)

    def test_the_unit_cloudflareds_own_installer_made_is_named_and_left_alone(self):
        (self.d / 'fake' / 'accepts').write_text(TOKEN)
        (self.d / 'fake' / 'other-cloudflared.service').write_text(f'[Service]\nExecStart=/usr/bin/cloudflared --no-autoupdate tunnel run --token {TOKEN}\n')
        (self.d / 'secrets' / 'cf-token').write_text(TOKEN)
        code, out = self.step(True, 't_cloudflare_tunnel', 'cf-token', 'present')
        self.assertEqual(code, 0, out)
        self.assertIn('has the token on its command line, where every account on this host can read it', out)
        self.assertNotIn(TOKEN, out)
        self.assertNotIn('disable --now cloudflared.service', self.read('calls'))

    def test_absent_stops_it_and_removes_the_token(self):
        self.assertIn('no Cloudflare Tunnel started by StorageForge is here', self.step(True, 't_cloudflare_tunnel', 'cf-token', 'absent')[1])
        (self.d / 'fake' / 'accepts').write_text(TOKEN)
        (self.d / 'secrets' / 'cf-token').write_text(TOKEN)
        self.step(True, 't_cloudflare_tunnel', 'cf-token', 'present')
        code, out = self.step(True, 't_cloudflare_tunnel', 'cf-token', 'absent')
        self.assertEqual(code, 0, out)
        self.assertEqual(list((self.d / 'cf').iterdir()) + list((self.d / 'units').iterdir()), [])
        self.assertIn('systemctl disable --now storageforge-cloudflared.service', self.read('calls'))

    def test_a_dead_network_mount_stops_the_tunnel_before_systemd_is_reloaded(self):
        """A plain daemon-reload waits on a hard NFS or CIFS mount whose server is gone, and every login then waits on systemd."""
        self.assertNotIn('systemctl daemon-reload', steps_tunnels.BASH, 'every reload goes through reload_systemd')
        (self.d / 'fake' / 'accepts').write_text(TOKEN)
        (self.d / 'secrets' / 'cf-token').write_text(TOKEN)
        code, out = self.step(True, 't_cloudflare_tunnel', 'cf-token', 'present', DEAD_MOUNT='1')
        self.assertEqual(code, 1, out)
        self.assertIn('conflict: /mnt/dead is not answering', out)
        self.assertNotIn('did not stay running', out, 'cloudflared was never started: the reload is the one thing that is said')
        self.assertEqual(out.count('conflict:'), 1, out)
        calls = self.read('calls')
        for word in ('daemon-reload', 'enable', 'start'):
            self.assertNotIn(f'systemctl {word}', calls)
        self.assertTrue((self.d / 'secrets' / 'cf-token').exists(), 'kept for the next attempt')
        code, out = self.step(True, 't_cloudflare_tunnel', 'cf-token', 'present')
        self.assertEqual(code, 0, out)
        self.assertIn('systemctl daemon-reload', self.read('calls'))
        # leaving: the unit is stopped and removed all the same, and the reload that was not made is said
        before = self.read('calls').count('systemctl daemon-reload')
        code, out = self.step(True, 't_cloudflare_tunnel', 'cf-token', 'absent', DEAD_MOUNT='1')
        self.assertEqual(code, 1, out)
        self.assertIn('conflict: /mnt/dead is not answering', out)
        self.assertIn('the tunnel no longer runs from here', out)
        self.assertEqual(list((self.d / 'cf').iterdir()) + list((self.d / 'units').iterdir()), [])
        self.assertEqual(self.read('calls').count('systemctl daemon-reload'), before)

    def test_a_reload_that_fails_for_another_reason_does_not_pass_for_a_running_tunnel(self):
        (self.d / 'fake' / 'accepts').write_text(TOKEN)
        (self.d / 'secrets' / 'cf-token').write_text(TOKEN)
        code, out = self.step(True, 't_cloudflare_tunnel', 'cf-token', 'present', RELOAD_FAILS='1')
        self.assertEqual((code, out.count('conflict:')), (1, 1), out)
        self.assertIn('conflict: cloudflared did not stay running', out)
        self.assertNotIn('systemctl enable', self.read('calls'))

    def test_a_dead_network_mount_stops_newt_too(self):
        (self.d / 'secrets' / 'pg-site').write_text(SITE_SECRET)
        code, out = self.step(True, 't_pangolin_site', 'pg-site', '2ix2t8xk22ubpfy', 'https://pangolin.example.com', 'present', DEAD_MOUNT='1')
        self.assertEqual((code, out.count('conflict:')), (1, 1), out)
        self.assertNotIn('systemctl enable', self.read('calls'))

    def test_the_ansible_task_carries_the_reload_guard(self):
        for kind, params in (('cloudflare-tunnel', {'secret': 'cf-token', 'state': 'present'}), ('pangolin-site', {'secret': 'pg-site', 'state': 'absent'})):
            cmd = changes.EXTRA[kind]['ansible']({'type': kind, 'host': 'nas', 'params': params})['ansible.builtin.shell']['cmd']
            self.assertIn('\nreload_systemd() {', cmd, 'a task that calls it without carrying it stops with: command not found')
            self.assertIn('timeout -k 1 5 stat', cmd, 'the guard itself, not a plain reload under its name')
            self.assertEqual(subprocess.run(['bash', '-n'], input=cmd, capture_output=True, text=True).stderr, '')

    # ── Newt ──
    def test_newt_reads_its_secret_from_a_configuration_file(self):
        args = ('pg-site', '2ix2t8xk22ubpfy', 'https://pangolin.example.com', 'present')
        code, out = self.step(False, 't_pangolin_site', *args)
        self.assertIn('missing: it needs the site secret at', out)
        (self.d / 'secrets' / 'pg-site').write_text(SITE_SECRET + '\n')
        self.assertIn('would: write site 2ix2t8xk22ubpfy of https://pangolin.example.com', self.step(False, 't_pangolin_site', *args)[1])
        self.assertEqual(list((self.d / 'newt').iterdir()), [])
        code, out = self.step(True, 't_pangolin_site', *args)
        self.assertEqual(code, 0, out)
        conf = self.d / 'newt' / 'storageforge.json'
        self.assertEqual(json.loads(conf.read_text()), {'id': '2ix2t8xk22ubpfy', 'secret': SITE_SECRET, 'endpoint': 'https://pangolin.example.com'})
        self.assertEqual((oct(conf.stat().st_mode & 0o777), sorted(p.name for p in (self.d / 'newt').iterdir())), ('0o600', ['storageforge.json']))
        self.assertEqual(self.read('newt.read').strip(), f"2ix2t8xk22ubpfy {SITE_SECRET} https://pangolin.example.com ['endpoint', 'id', 'secret']", 'Newt read all three from the file')
        self.assertEqual(self.read('newt.cmdline').split()[-1], f'{self.d}/bin/newt', 'started with no argument at all')
        self.assertIn('CONFIG_FILE=', self.read('newt.env'))
        self.assertNotIn(SITE_SECRET, self.read('newt.env'), 'and with no secret in its environment')
        unit = (self.d / 'units' / 'storageforge-newt.service').read_text()
        self.assertIn(f'Environment=CONFIG_FILE={conf}\nExecStart={self.d}/bin/newt\n', unit)
        self.assertNotIn(SITE_SECRET, out + self.everything_written())
        self.assertFalse((self.d / 'secrets' / 'pg-site').exists())
        self.assertIn('ok: Newt runs as storageforge-newt.service for site 2ix2t8xk22ubpfy', self.step(True, 't_pangolin_site', *args)[1])
        self.assertEqual(self.read('calls').count('systemctl restart'), 1)
        # another site: the secret is asked for again, and the one in place is not reused for it
        code, out = self.step(True, 't_pangolin_site', 'pg-site', 'othersite0000', 'https://pangolin.example.com', 'present')
        self.assertEqual(code, 1)
        self.assertIn('no site secret at', out)
        code, out = self.step(True, 't_pangolin_site', 'pg-site', '', '', 'absent')
        self.assertEqual(code, 0, out)
        self.assertEqual(list((self.d / 'newt').iterdir()) + list((self.d / 'units').iterdir()), [])

    def test_a_secret_file_that_is_not_one_and_a_newt_that_does_not_start(self):
        args = ('pg-site', '2ix2t8xk22ubpfy', 'https://pangolin.example.com', 'present')
        (self.d / 'secrets' / 'pg-site').write_text('a"b,"endpoint":"https://evil.example.com')
        code, out = self.step(True, 't_pangolin_site', *args)
        self.assertEqual(code, 1)
        self.assertIn('does not hold a site secret', out)
        self.assertEqual(list((self.d / 'newt').iterdir()), [], 'nothing that could change the file\'s other fields gets in')
        self.stub('newt', 'exit 1')
        (self.d / 'secrets' / 'pg-site').write_text(SITE_SECRET)
        code, out = self.step(True, 't_pangolin_site', *args)
        self.assertEqual(code, 1)
        self.assertIn('Newt did not stay running', out)
        self.assertNotIn(SITE_SECRET, out)

    def test_without_the_program_or_systemd_nothing_is_done(self):
        (self.d / 'bin' / 'cloudflared').unlink()
        (self.d / 'bin' / 'newt').unlink()
        self.assertIn('cloudflared is not installed', self.step(True, 't_cloudflare_tunnel', 'cf-token', 'present')[1])
        self.assertIn('newt is not installed', self.step(True, 't_pangolin_site', 'pg-site', 'abcd', 'https://p.example.com', 'present')[1])
        self.setUp()
        (self.d / 'run').rmdir()
        self.assertIn('systemd does not run this host', self.step(True, 't_cloudflare_tunnel', 'cf-token', 'present')[1])
        self.assertIn('systemd does not run this host', self.step(True, 't_pangolin_site', 'pg-site', 'abcd', 'https://p.example.com', 'present')[1])

    @unittest.skipUnless(REAL_CLOUDFLARED, 'needs a real cloudflared (in PATH, or named by STORAGEFORGE_TEST_CLOUDFLARED)')
    def test_the_real_cloudflared_reads_its_token_from_the_file_the_unit_names(self):
        """No tunnel is started: the file holds no token, and cloudflared says so before it connects anywhere."""
        helped = subprocess.run([REAL_CLOUDFLARED, 'tunnel', 'run', '--help'], capture_output=True, text=True, timeout=30)
        self.assertEqual(subprocess.run(['grep', '-q', '--', '--token-file'], input=helped.stdout + helped.stderr, text=True).returncode, 0, 'the check the step makes')
        (self.d / 'tok').write_text('notAToken0000')
        got = subprocess.run([REAL_CLOUDFLARED, '--no-autoupdate', 'tunnel', 'run', '--token-file', str(self.d / 'tok')], capture_output=True, text=True, timeout=30)
        self.assertIn('Provided Tunnel token is not valid', got.stdout + got.stderr, 'it read the file, in the place the unit puts the flag')
        gone = subprocess.run([REAL_CLOUDFLARED, '--no-autoupdate', 'tunnel', 'run', '--token-file', str(self.d / 'none')], capture_output=True, text=True, timeout=30)
        self.assertIn('Failed to read token file', gone.stdout + gone.stderr)

    # ── the plan ──
    def test_the_plan_holds_a_name_and_never_a_secret(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        db = dbfactory.make(self, f'{tmp}/t.db')
        conn = db.connect()
        self.addCleanup(conn.close)
        db.migrate(conn)
        conn.execute("INSERT INTO hosts (hostname, ssh_host, ssh_user, inventory_json) VALUES ('nas', '10.42.0.10', 'scan', '{}')")
        plan = changes.normalize({'name': 'tunnels', 'tasks': [
            {'type': 'cloudflare-tunnel', 'host': 'nas', 'params': {'secret': 'cf-token'}},
            {'type': 'pangolin-site', 'host': 'nas', 'params': {'secret': 'pg-site', 'site_id': '2ix2t8xk22ubpfy', 'endpoint': 'https://pangolin.example.com'}},
            {'type': 'pangolin-site', 'host': 'nas', 'params': {'secret': 'pg-site', 'state': 'absent'}}]})
        checked = changes.check(conn, plan)['tasks']
        self.assertFalse([i for t in checked for i in t['items'] if i['level'] == 'crit'], checked)
        for t in checked[:2]:
            texts = ' '.join(i['text'] for i in t['items'])
            self.assertIn('vault send-secret', texts)
            self.assertIn('public', texts)
            self.assertIn('Not lab-tested', texts)
        text = changes.script(conn, plan)
        self.assertIn("cloudflare-tunnel 'Run a Cloudflare Tunnel from a token in the vault' cf-token present", text)
        self.assertIn('pangolin-site', text)
        self.assertTrue(re.search(r'pg-site 2ix2t8xk22ubpfy https://pangolin.example.com present', text))
        bad = changes.normalize({'name': 'bad', 'tasks': [{'type': 'pangolin-site', 'host': 'nas', 'params': {'secret': 'pg-site', 'site_id': 'a"b', 'endpoint': 'http://plain.example.com'}}]})
        self.assertEqual([i['level'] for i in changes.check(conn, bad)['tasks'][0]['items']].count('crit'), 2)
        for spec in (changes.TYPES['cloudflare-tunnel'], changes.TYPES['pangolin-site']):
            self.assertIn('not lab-tested', spec['label'])


if __name__ == '__main__':
    unittest.main()
