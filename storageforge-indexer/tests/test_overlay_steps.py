"""The steps that join a host to a private network and take it out again (steps_overlay.py): netbird, zerotier, nebula, openziti.
What must hold: a secret is named to its program as a file and is on no command line, in no plan, script or output; a second run
changes nothing; leaving is a step too; and a program that could only take its secret as an argument is refused.

netbird, zerotier-cli and ziti-edge-tunnel are not installed here, so those steps run against stand-ins that keep the state the
real program would and write down their own command line. Each script runs under `set -euo pipefail` on a PATH that holds the
stand-ins and the plain tools only. Nebula is different: its certificates are checked against the real nebula-cert and nebula
where they are found (in PATH, or in the folder STORAGEFORGE_TEST_NEBULA names), and against certificates the real nebula-cert
1.12.0 made, kept below, everywhere."""
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import dbfactory
from storageforge_index import changes, steps_overlay, steps_tunnels

SETUP_KEY = 'A1B2C3D4-TEST-4NOT-AREAL-SETUPKEY0000'
PRELUDE = r'''set -euo pipefail
ok() { echo "ok: $*"; }; missing() { echo "missing: $*"; }; conflict() { echo "conflict: $*"; PROBLEMS=$((PROBLEMS + 1)); }
info() { echo "info: $*"; }; act() { if ((APPLY)); then echo "doing: $*"; return 0; else echo "would: $*"; return 1; fi; }
try() { "$@" || { conflict "failed: $*"; return 1; }; }; durable() { :; }
PROBLEMS=0
'''
PLAIN = ('bash', 'sh', 'cat', 'grep', 'sed', 'tr', 'head', 'tail', 'awk', 'rm', 'mkdir', 'chmod', 'mv', 'cp', 'cmp', 'sleep', 'uname', 'mktemp', 'base64', 'touch', 'env', 'id', 'chown',
         'sha256sum', 'cut', 'date', 'ls', 'wc')


class Stage(unittest.TestCase):
    """A host as far as a step sees it: stand-ins first on a PATH with nothing else but the plain tools, and every folder a step
    writes moved under one temporary folder."""

    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.d, True)
        for name in ('bin', 'plain', 'secrets', 'units', 'fake', 'run'):
            (self.d / name).mkdir()
        self.fake = self.d / 'fake'
        for name in PLAIN:
            (self.d / 'plain' / name).symlink_to(shutil.which(name))
        # systemd as far as these steps ask: a unit is active once it was started, and a unit with a file runs its ExecStart once
        self.stub('systemctl', f'''echo "systemctl $*" >>{self.fake}/systemctl.calls
unit="${{@: -1}}"; unit=${{unit%.service}}; file={self.d}/units/$unit.service
case "$1" in
  is-active) [ -e {self.fake}/active-$unit ] ;;
  enable) [ "$2" = --now ] && {{ [ ! -e {self.fake}/broken-$unit ] || exit 1; touch {self.fake}/active-$unit; }}; exit 0 ;;
  start|restart) rm -f {self.fake}/active-$unit; [ -e "$file" ] || [ -e {self.fake}/packaged-$unit ] || exit 5
     if [ -e "$file" ]; then cmd=$(sed -n "s/^ExecStart=//p" "$file"); $cmd || exit 1; fi; touch {self.fake}/active-$unit ;;
  disable|stop) rm -f {self.fake}/active-$unit ;;
  cat) [ -e "$file" ] && cat "$file" || [ -e {self.fake}/packaged-$unit ] ;;
esac''')
        self.env = {'PATH': f'{self.d}/bin:{self.d}/plain', 'SF_SECRET_DIR': str(self.d / 'secrets'), 'SF_UNIT_DIR': str(self.d / 'units'), 'SF_SYSTEMD_RUN': str(self.d / 'run'),
                    'SF_TUNNEL_WAIT': '0', 'SF_OVERLAY_WAIT': '0', 'HOME': str(self.d)}

    def stub(self, name, body):
        p = self.d / 'bin' / name
        p.write_text('#!/bin/bash\n' + body + '\n')
        p.chmod(0o755)

    def step(self, apply, fn, *args, **env):
        call = fn + ' ' + ' '.join(f"'{a}'" for a in args)
        got = subprocess.run(['bash', '-c', PRELUDE + f'APPLY={int(apply)}\n' + steps_tunnels.BASH + steps_overlay.BASH + '\n' + call + '\nexit $((PROBLEMS > 0))\n'],
                             capture_output=True, text=True, timeout=60, env=self.env | env)
        self.assertEqual(got.stderr, '', 'nothing a step runs fails unseen, and nothing it needs is missing from the plain tools')
        return got.returncode, got.stdout

    def read(self, name):
        p = self.fake / name
        return p.read_text() if p.exists() else ''

    def secret(self, name, text):
        p = self.d / 'secrets' / name
        p.write_text(text + '\n')
        p.chmod(0o600)
        return p

    def everything_written(self, *keep):
        """Every file under the stage but the stand-ins and the ones named, which are where the secret is meant to be."""
        kept = {self.d / k for k in keep}
        return '\n'.join(p.read_text(errors='replace') for p in self.d.rglob('*') if p.is_file() and not p.is_symlink() and p not in kept and p.parent.name != 'bin')


class NetBird(Stage):
    """netbird as it behaves: a daemon that answers once its service runs, NeedsLogin until an up with a key the management server
    accepts, and a status in one line of JSON."""

    def setUp(self):
        super().setUp()
        f = self.fake
        (f / 'accepts').write_text(SETUP_KEY)
        (f / 'active-netbird').touch()
        self.stub('netbird', f'''case "$*" in
  "--help") echo "Available Commands:"; echo "  down        Disconnect from the NetBird network"; [ -e {f}/no-deregister ] || echo "  deregister  Deregister from the NetBird management service and delete this peer"; exit 0 ;;
  "up --help") echo "Flags:"; echo "  -k, --setup-key string   Setup key"; [ -e {f}/old ] || echo "      --setup-key-file string   The path to a setup key"; exit 0 ;;
  "version") echo 0.60.2; exit 0 ;;
esac
[ -e {f}/active-netbird ] || {{ echo "Error: failed to connect to daemon error: context deadline exceeded" >&2; exit 1; }}
url=$(cat {f}/url 2>/dev/null || echo https://api.netbird.io:443)
case "$1" in
  status)
    if [ "${{2:-}}" = --ipv4 ]; then [ -e {f}/up ] && echo 100.92.0.7; exit 0; fi
    if [ "${{2:-}}" = --json ]; then
      if [ -e {f}/up ]; then echo "{{\\"peers\\":{{\\"total\\":0,\\"connected\\":0,\\"details\\":[]}},\\"cliVersion\\":\\"0.60.2\\",\\"daemonStatus\\":\\"Connected\\",\\"management\\":{{\\"url\\":\\"$url\\",\\"connected\\":true,\\"error\\":\\"\\"}},\\"signal\\":{{\\"url\\":\\"$url\\",\\"connected\\":true,\\"error\\":\\"\\"}},\\"netbirdIp\\":\\"100.92.0.7/16\\",\\"fqdn\\":\\"web.netbird.selfhosted\\"}}"
      else echo "{{\\"peers\\":{{\\"total\\":0,\\"connected\\":0,\\"details\\":[]}},\\"cliVersion\\":\\"0.60.2\\",\\"daemonStatus\\":\\"Idle\\",\\"management\\":{{\\"url\\":\\"\\",\\"connected\\":false,\\"error\\":\\"\\"}},\\"signal\\":{{\\"url\\":\\"\\",\\"connected\\":false,\\"error\\":\\"\\"}},\\"netbirdIp\\":\\"\\"}}"; fi
      exit 0
    fi
    if [ ! -e {f}/registered ]; then echo "Daemon status: NeedsLogin"; echo; echo "Run UP command to log in with SSO (interactive login):"
    elif [ -e {f}/up ]; then echo "Management: Connected"; echo "NetBird IP: 100.92.0.7/16"
    else echo "Management: Disconnected"; fi ;;
  up) tr "\\0" " " </proc/$$/cmdline >>{f}/netbird.cmdline; echo >>{f}/netbird.cmdline
    for a in "$@"; do case $a in
      --setup-key-file=*) tr -d " \\n" <"${{a#*=}}" >{f}/netbird.read || exit 1
        [ "$(cat {f}/netbird.read)" = "$(cat {f}/accepts)" ] || {{ echo "Error: login failed: rpc error: code = PermissionDenied desc = setup key is invalid" >&2; exit 1; }}
        touch {f}/registered ;;
      --management-url=*) echo "${{a#*=}}:443" >{f}/url ;;
    esac; done
    [ -e {f}/registered ] || {{ echo "Error: login failed: no setup key and no SSO here" >&2; exit 1; }}
    [ -e {f}/stays-down ] || touch {f}/up; echo Connected ;;
  down) rm -f {f}/up; echo Disconnected ;;
  deregister) rm -f {f}/up {f}/registered {f}/url; echo "Deregistered successfully" ;;
esac''')

    def test_it_joins_from_the_key_file_and_the_key_is_on_no_command_line(self):
        rc, out = self.step(True, 't_netbird', 'nb-key', 'https://nb.example.com', 'web-1', 'present')
        self.assertEqual(rc, 1)
        self.assertIn(f'conflict: no setup key at {self.d}/secrets/nb-key: storageforge-index vault send-secret nb-key --host ', out)
        self.assertEqual(self.read('netbird.cmdline'), '', 'nothing was tried without the key')
        key = self.secret('nb-key', SETUP_KEY)
        rc, out = self.step(False, 't_netbird', 'nb-key', 'https://nb.example.com', 'web-1', 'present')
        self.assertIn(f'would: netbird up --setup-key-file={key} --management-url=https://nb.example.com --hostname=web-1', out)
        self.assertEqual(self.read('netbird.cmdline'), '', 'a report runs nothing')
        rc, out = self.step(True, 't_netbird', 'nb-key', 'https://nb.example.com', 'web-1', 'present')
        self.assertEqual(rc, 0, out)
        self.assertIn('ok: joined the NetBird network as 100.92.0.7; the setup key file is removed', out)
        self.assertEqual(self.read('netbird.cmdline').strip(), f'/bin/bash {self.d}/bin/netbird up --setup-key-file={key} --management-url=https://nb.example.com --hostname=web-1')
        self.assertEqual(self.read('netbird.read'), SETUP_KEY, 'netbird read the whole key from the file')
        self.assertFalse(key.exists(), 'the peer keeps a key of its own')
        self.assertNotIn(SETUP_KEY, out + self.everything_written('fake/netbird.read', 'fake/accepts'))

    def test_a_second_run_changes_nothing_and_removes_a_key_sent_again(self):
        self.secret('nb-key', SETUP_KEY)
        self.step(True, 't_netbird', 'nb-key', 'https://nb.example.com', '', 'present')
        before = self.read('netbird.cmdline')
        key = self.secret('nb-key', SETUP_KEY)
        for apply in (False, True):
            rc, out = self.step(apply, 't_netbird', 'nb-key', 'https://nb.example.com', '', 'present')
            self.assertEqual(rc, 0)
            self.assertIn('ok: on a NetBird network already, as 100.92.0.7, managed at https://nb.example.com:443', out)
            self.assertNotIn('doing:', out)
        self.assertEqual(self.read('netbird.cmdline'), before)
        self.assertFalse(key.exists())

    def test_a_host_on_another_management_server_is_left_there(self):
        self.secret('nb-key', SETUP_KEY)
        self.step(True, 't_netbird', 'nb-key', 'https://nb.example.com', '', 'present')
        key = self.secret('nb-key', SETUP_KEY)
        rc, out = self.step(True, 't_netbird', 'nb-key', 'https://other.example.org', '', 'present')
        self.assertEqual(rc, 1)
        self.assertIn('managed at https://nb.example.com:443 and not at https://other.example.org', out)
        self.assertTrue(key.exists(), 'the key is still needed once the host has left')

    def test_a_netbird_that_cannot_read_the_key_from_a_file_is_refused(self):
        (self.fake / 'old').touch()
        self.secret('nb-key', SETUP_KEY)
        rc, out = self.step(True, 't_netbird', 'nb-key', '', '', 'present')
        self.assertEqual(rc, 1)
        self.assertIn('cannot read its setup key from a file (--setup-key-file): with it the key would be on a command line, so nothing is done', out)
        self.assertEqual(self.read('netbird.cmdline'), '')

    def test_a_key_the_server_refuses_and_an_up_that_does_not_connect(self):
        key = self.secret('nb-key', 'WRONGKEY-0000-0000-0000-000000000000')
        rc, out = self.step(True, 't_netbird', 'nb-key', '', '', 'present')
        self.assertEqual(rc, 1)
        self.assertIn('conflict: netbird up failed:', out)
        self.assertIn('setup key is invalid', out)
        self.assertNotIn('WRONGKEY', out)
        self.assertTrue(key.exists(), 'a key that did not work is left for whoever looks into it')
        self.secret('nb-key', SETUP_KEY)
        (self.fake / 'stays-down').touch()
        rc, out = self.step(True, 't_netbird', 'nb-key', '', '', 'present')
        self.assertIn('the management server is not connected', out)

    def test_the_service_is_started_and_without_netbird_nothing_is_done(self):
        (self.fake / 'active-netbird').unlink()
        self.secret('nb-key', SETUP_KEY)
        rc, out = self.step(False, 't_netbird', 'nb-key', '', '', 'present')
        self.assertIn('would: systemctl enable --now netbird', out)
        rc, out = self.step(True, 't_netbird', 'nb-key', '', '', 'present')
        self.assertEqual(rc, 0, out)
        self.assertIn('systemctl enable --now netbird', self.read('systemctl.calls'))
        self.assertIn('joined the NetBird network', out)
        (self.d / 'bin' / 'netbird').unlink()
        rc, out = self.step(True, 't_netbird', 'nb-key', '', '', 'present')
        self.assertEqual(rc, 1)
        self.assertIn('netbird is not installed', out)
        self.assertEqual(self.step(True, 't_netbird', 'nb-key', '', '', 'absent'), (0, 'ok: NetBird is not installed\n'))

    def test_a_peer_that_is_registered_and_down_comes_up_without_a_key(self):
        (self.fake / 'registered').touch()
        rc, out = self.step(True, 't_netbird', 'nb-key', '', '', 'present')
        self.assertEqual(rc, 0, out)
        self.assertIn('doing: netbird up (registered already, and only disconnected)', out)
        self.assertEqual(self.read('netbird.cmdline').strip(), f'/bin/bash {self.d}/bin/netbird up')

    def test_absent_deregisters_once(self):
        self.secret('nb-key', SETUP_KEY)
        self.step(True, 't_netbird', 'nb-key', '', '', 'present')
        rc, out = self.step(False, 't_netbird', 'nb-key', '', '', 'absent')
        self.assertIn('would: netbird deregister', out)
        self.assertTrue((self.fake / 'registered').exists())
        rc, out = self.step(True, 't_netbird', 'nb-key', '', '', 'absent')
        self.assertEqual(rc, 0)
        self.assertIn('ok: left the NetBird network, and this peer is removed at the management server', out)
        self.assertFalse((self.fake / 'registered').exists())
        self.assertEqual(self.step(True, 't_netbird', 'nb-key', '', '', 'absent'), (0, 'ok: not registered with a NetBird management server\n'))

    def test_a_netbird_without_deregister_is_disconnected_and_says_what_stays(self):
        (self.fake / 'no-deregister').touch()
        self.secret('nb-key', SETUP_KEY)
        self.step(True, 't_netbird', 'nb-key', '', '', 'present')
        rc, out = self.step(True, 't_netbird', 'nb-key', '', '', 'absent')
        self.assertIn('the peer stays listed at the management server until it is removed there', out)
        self.assertIn('ok: disconnected from the NetBird network', out)
        self.assertFalse((self.fake / 'up').exists())
        rc, out = self.step(True, 't_netbird', 'nb-key', '', '', 'absent')
        self.assertIn('ok: not connected to a NetBird network', out)
        self.assertNotIn('doing:', out)


NET = '8056c2e21c000001'


class ZeroTier(Stage):
    """zerotier-cli as it behaves: nothing without its service, a network joined at once and let in only when its controller says."""

    def setUp(self):
        super().setUp()
        f = self.fake
        (f / 'nets').mkdir()
        (f / 'active-zerotier-one').touch()
        self.stub('zerotier-cli', f"""echo "zerotier-cli $*" >>{f}/zt.calls
[ -e {f}/active-zerotier-one ] || {{ echo "Error connecting to the ZeroTier service: "; echo; echo "Please check that the service is running and that TCP port 9993 can be contacted via 127.0.0.1."; exit 1; }}
case "$1" in
  info) echo "200 info 1a2b3c4d5e 1.14.2 ONLINE" ;;
  get) [ ${{#2}} -eq 16 ] || {{ echo "invalid format: must be a 16-digit (network) ID" >&2; exit 2; }}
       [ -e {f}/nets/$2 ] || {{ echo "unknown network ID, check that you are a member of the network" >&2; exit 0; }}
       case "$3" in status) cat {f}/nets/$2 ;; ip4) [ "$(cat {f}/nets/$2)" = OK ] && echo 10.147.17.5 ;; *) echo "error, unknown property name" ;; esac ;;
  join) [ ${{#2}} -eq 16 ] || {{ echo "invalid network id"; exit 2; }}
        [ ! -e {f}/join-fails ] || {{ echo "500 join internal error"; exit 1; }}
        cat {f}/controller-says >{f}/nets/$2 2>/dev/null || echo REQUESTING_CONFIGURATION >{f}/nets/$2; echo "200 join OK" ;;
  leave) rm -f {f}/nets/$2; echo "200 leave OK" ;;
esac""")

    def calls(self):
        return [line for line in self.read('zt.calls').splitlines() if ' join ' in line or ' leave ' in line]

    def test_it_joins_and_says_the_controller_has_to_let_the_node_in(self):
        (self.fake / 'controller-says').write_text('ACCESS_DENIED\n')
        rc, out = self.step(False, 't_zerotier', NET, 'present')
        self.assertIn(f'would: zerotier-cli join {NET} (the controller of a private network must then authorise this node: this step does not)', out)
        self.assertEqual(self.calls(), [])
        rc, out = self.step(True, 't_zerotier', NET, 'present')
        self.assertEqual(rc, 0, out)
        self.assertIn(f'info: joined ZeroTier network {NET}, and its controller has not authorised node 1a2b3c4d5e: that is done at the controller, not by this step', out)
        self.assertIn(f'ok: asked to join {NET} as node 1a2b3c4d5e', out)
        self.assertEqual(self.calls(), [f'zerotier-cli join {NET}'])
        # the controller authorises it: the next run says so, and joins nothing again
        (self.fake / 'nets' / NET).write_text('OK\n')
        for apply in (False, True):
            self.assertEqual(self.step(apply, 't_zerotier', NET, 'present'), (0, f'ok: on ZeroTier network {NET} as 10.147.17.5, node 1a2b3c4d5e\n'))
        self.assertEqual(self.calls(), [f'zerotier-cli join {NET}'])

    def test_a_network_nobody_answers_for_and_a_join_that_fails(self):
        (self.fake / 'controller-says').write_text('NOT_FOUND\n')
        rc, out = self.step(True, 't_zerotier', NET, 'present')
        self.assertEqual(rc, 1)
        self.assertIn(f'conflict: ZeroTier network {NET} is not found: no controller answers for that id', out)
        (self.fake / 'nets' / NET).unlink()
        (self.fake / 'join-fails').touch()
        rc, out = self.step(True, 't_zerotier', NET, 'present')
        self.assertIn('conflict: zerotier-cli join failed: 500 join internal error', out)

    def test_a_controller_that_has_not_answered_yet_is_said_and_is_no_failure(self):
        rc, out = self.step(True, 't_zerotier', NET, 'present')
        self.assertEqual(rc, 0)
        self.assertIn('the controller has not answered yet (REQUESTING_CONFIGURATION)', out)

    def test_absent_leaves_that_network_only_and_once(self):
        other = '8056c2e21c000002'
        for n in (NET, other):
            (self.fake / 'nets' / n).write_text('OK\n')
        rc, out = self.step(False, 't_zerotier', NET, 'absent')
        self.assertIn(f'would: zerotier-cli leave {NET}', out)
        rc, out = self.step(True, 't_zerotier', NET, 'absent')
        self.assertEqual(rc, 0)
        self.assertIn(f'ok: left ZeroTier network {NET}. Its controller still lists node 1a2b3c4d5e as a member: remove it there to forget it', out)
        self.assertEqual(sorted(p.name for p in (self.fake / 'nets').iterdir()), [other])
        self.assertEqual(self.step(True, 't_zerotier', NET, 'absent'), (0, f'ok: not on ZeroTier network {NET}\n'))
        self.assertEqual(self.calls(), [f'zerotier-cli leave {NET}'])

    def test_the_service_is_started_and_without_zerotier_nothing_is_done(self):
        (self.fake / 'active-zerotier-one').unlink()
        self.assertEqual(self.step(True, 't_zerotier', NET, 'absent'), (0, 'ok: the ZeroTier service does not run here: this host is on no ZeroTier network\n'))
        rc, out = self.step(False, 't_zerotier', NET, 'present')
        self.assertEqual(out, 'would: systemctl enable --now zerotier-one\n')
        (self.fake / 'broken-zerotier-one').touch()
        rc, out = self.step(True, 't_zerotier', NET, 'present')
        self.assertEqual(rc, 1)
        self.assertIn('conflict: could not start zerotier-one', out)
        (self.fake / 'broken-zerotier-one').unlink()
        rc, out = self.step(True, 't_zerotier', NET, 'present')
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.calls(), [f'zerotier-cli join {NET}'])
        (self.d / 'bin' / 'zerotier-cli').unlink()
        rc, out = self.step(True, 't_zerotier', NET, 'present')
        self.assertIn('conflict: zerotier-cli is not installed', out)
        self.assertEqual(self.step(True, 't_zerotier', NET, 'absent'), (0, 'ok: ZeroTier is not installed\n'))


def plan_db(case):
    tmp = tempfile.mkdtemp()
    case.addCleanup(shutil.rmtree, tmp, True)
    db = dbfactory.make(case, f'{tmp}/t.db')
    conn = db.connect()
    case.addCleanup(conn.close)
    db.migrate(conn)
    conn.execute("INSERT INTO hosts (hostname, ssh_host, ssh_user, inventory_json) VALUES ('nas', '10.42.0.10', 'scan', '{}')")
    return db, conn


class Plans(unittest.TestCase):
    """What a plan with these steps holds, says and writes: names, and never a secret."""

    def checked(self, conn, *tasks):
        plan = changes.normalize({'name': 'overlay', 'tasks': [{'type': kind, 'host': 'nas', 'params': params} for kind, params in tasks]})
        return plan, changes.check(conn, plan)['tasks']

    def crits(self, checked):
        return [i['text'] for t in checked for i in t['items'] if i['level'] == 'crit']

    def test_netbird_in_a_plan(self):
        db, conn = plan_db(self)
        plan, checked = self.checked(conn, ('netbird', {'secret': 'nb-key', 'management_url': 'https://nb.example.com', 'hostname': 'web-1'}), ('netbird', {'secret': 'nb-key', 'state': 'absent'}))
        self.assertEqual(self.crits(checked), [])
        said = ' '.join(i['text'] for i in checked[0]['items'])
        self.assertIn('storageforge-index vault send-secret nb-key --host nas', said)
        self.assertIn('on no command line', said)
        self.assertIn('Not lab-tested', said)
        self.assertIn('removed at the management server', checked[1]['items'][0]['text'])
        text = changes.script(conn, plan)
        self.assertIn("netbird 'Join the NetBird network at https://nb.example.com' nb-key https://nb.example.com web-1 present", text)
        self.assertIn("netbird 'Leave the NetBird network' nb-key '' '' absent", text)
        self.assertIn('t_netbird() {', text)
        _, bad = self.checked(conn, ('netbird', {'secret': 'nb-key', 'management_url': 'nb.example.com; id', 'hostname': 'Web_1'}))
        self.assertEqual(len(self.crits(bad)), 2)
        task = {'type': 'netbird', 'host': 'nas', 'params': plan['tasks'][0]['params']}
        cmd = changes.EXTRA['netbird']['ansible'](task)['ansible.builtin.shell']['cmd']
        self.assertIn('t_netbird nb-key https://nb.example.com web-1 present', cmd)
        self.assertIn('tun_secret_missing() {', cmd, 'the playbook carries the helpers the step calls')

    def test_zerotier_in_a_plan(self):
        db, conn = plan_db(self)
        plan, checked = self.checked(conn, ('zerotier', {'network': NET}), ('zerotier', {'network': NET, 'state': 'absent'}))
        self.assertEqual(self.crits(checked), [])
        said = ' '.join(i['text'] for i in checked[0]['items'])
        self.assertIn('No secret is involved', said)
        self.assertIn('This step does not authorise it', said)
        text = changes.script(conn, plan)
        self.assertIn(f"zerotier 'Join ZeroTier network {NET}' {NET} present", text)
        self.assertIn(f"zerotier 'Leave ZeroTier network {NET}' {NET} absent", text)
        for bad in ('8056C2E21C000001', '8056c2e21c00000', '8056c2e21c000001; id', 'all'):
            _, got = self.checked(conn, ('zerotier', {'network': bad}))
            self.assertEqual(len(self.crits(got)), 1, bad)


if __name__ == '__main__':
    unittest.main()
