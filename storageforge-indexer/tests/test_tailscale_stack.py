"""The stack's tailscale container (docker/tailscale/entrypoint.sh): it joins nothing without a key, joins without taking
routes, DNS or an exit node, keeps the tailnet away from everything but the web UI, and serves the UI through the proxy."""
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'docker' / 'tailscale' / 'entrypoint.sh'

STUBS = {
    # makes the control socket, then lives a moment so `wait` has something to wait for
    'tailscaled': '''#!/bin/sh
echo "tailscaled $*" >> "$LOG"
for a in "$@"; do case $a in --socket=*) sock=${a#--socket=} ;; esac; done
python3 -c "import socket,sys; s=socket.socket(socket.AF_UNIX); s.bind(sys.argv[1])" "$sock"
sleep 1
''',
    'tailscale': '''#!/bin/sh
echo "tailscale $*" >> "$LOG"
case " $* " in *" ip "*) echo 100.64.0.9 ;; esac
case " $* " in *" up "*) [ -z "${FAIL_UP:-}" ] || exit 1 ;; esac
exit 0
''',
    'iptables': '#!/bin/sh\necho "iptables $*" >> "$LOG"\ncase $1 in -C) exit 1 ;; esac\nexit 0\n',
    'ip6tables': '#!/bin/sh\necho "ip6tables $*" >> "$LOG"\ncase $1 in -C) exit 1 ;; esac\nexit 0\n',
    'mknod': '#!/bin/sh\nexit 1\n',
}


class Entrypoint(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.bin = self.tmp / 'bin'
        self.bin.mkdir()
        for name, body in STUBS.items():
            (self.bin / name).write_text(body)
            (self.bin / name).chmod(0o755)
        self.log = self.tmp / 'log'
        self.log.write_text('')
        (self.tmp / 'state').mkdir()

    def run_it(self, key='', keyfile='', idle_stops=True, **env):
        if idle_stops:          # the idle loop's sleep ends the script, so a test can see it got there
            (self.bin / 'sleep').write_text('#!/bin/sh\nif [ "$1" = 3600 ]; then kill -TERM $PPID; exit 0; fi\nexec /bin/sleep "$@"\n')
            (self.bin / 'sleep').chmod(0o755)
        kf = self.tmp / 'authkey'
        kf.write_text(keyfile)
        e = {'PATH': f'{self.bin}:{os.environ["PATH"]}', 'LOG': str(self.log), 'TS_STATE_DIR': str(self.tmp / 'state'),
             'TS_SOCKET': str(self.tmp / 'ts.sock'), 'TS_AUTHKEY_PATH': str(kf), 'STORAGEFORGE_TS_AUTHKEY': key, **env}
        r = subprocess.run(['sh', str(SCRIPT)], env=e, capture_output=True, text=True, timeout=30)
        return r, self.log.read_text()

    def test_without_a_key_it_joins_nothing(self):
        r, log = self.run_it()
        self.assertIn('not joining a tailnet', r.stdout)
        self.assertEqual(log, '', 'neither tailscaled nor any rule was started')

    def test_with_a_key_it_joins_without_routes_dns_or_firewall_takeover_and_serves_through_the_proxy(self):
        r, log = self.run_it(keyfile='tskey-auth-abc123\n')
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        up = next(line for line in log.splitlines() if ' up ' in f' {line} ')
        for flag in ('--accept-dns=false', '--accept-routes=false', '--netfilter-mode=off', '--hostname=storageforge', '--authkey=tskey-auth-abc123'):
            self.assertIn(flag, up)
        self.assertNotIn('exit-node', up)
        self.assertIn('serve --bg --https=443 https+insecure://proxy:8443', log)
        self.assertNotIn('tskey', r.stdout + r.stderr, 'the key is never printed')

    def test_only_the_web_ui_comes_in_from_the_tailnet(self):
        if not Path('/dev/net/tun').is_char_device():
            self.skipTest('no /dev/net/tun here: the userspace mode has no kernel interface to guard')
        _r, log = self.run_it(key='tskey-auth-x')
        rules = [line for line in log.splitlines() if line.startswith('iptables ')]
        self.assertIn('iptables -A SF-TAILNET -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT', rules)
        self.assertIn('iptables -A SF-TAILNET -p tcp --dport 443 -j ACCEPT', rules)
        self.assertIn('iptables -A SF-TAILNET -j DROP', rules)
        self.assertIn('iptables -I INPUT -i tailscale0 -j SF-TAILNET', rules)
        first_up = next(i for i, line in enumerate(log.splitlines()) if ' up ' in f' {line} ')
        last_rule = max(i for i, line in enumerate(log.splitlines()) if line.startswith(('iptables', 'ip6tables')))
        self.assertLess(last_rule, first_up, 'the chain is in place before the node is on the tailnet')

    def test_a_refused_key_stops_with_a_reason(self):
        r, _log = self.run_it(key='tskey-auth-old', FAIL_UP='1')
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('could not join the tailnet', r.stdout)

    def test_a_bad_host_name_is_refused(self):
        r, log = self.run_it(key='tskey-auth-x', STORAGEFORGE_TS_HOSTNAME='bad;name')
        self.assertEqual(r.returncode, 2)
        self.assertNotIn('tailscaled', log)


class Compose(unittest.TestCase):
    def test_the_service_shares_the_server_network_and_holds_the_only_extra_capabilities(self):
        d = yaml.safe_load((ROOT / 'docker-compose.yml').read_text())
        ts = d['services']['tailscale']
        self.assertEqual(ts['network_mode'], 'service:storageforge')
        self.assertEqual(set(ts['cap_add']), {'NET_ADMIN', 'NET_RAW', 'MKNOD'})
        self.assertNotIn('cap_add', d['services']['storageforge'], 'the server stays without capabilities')
        self.assertIn('sf-tailscale', d['volumes'])
        self.assertEqual(ts['image'].split(':')[1], d['services']['storageforge']['image'].split(':')[1])


if __name__ == '__main__':
    unittest.main()
