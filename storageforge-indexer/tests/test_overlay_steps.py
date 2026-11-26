"""The steps that join a host to a private network and take it out again (steps_overlay.py): netbird, zerotier, nebula, openziti.
What must hold: a secret is named to its program as a file and is on no command line, in no plan, script or output; a second run
changes nothing; leaving is a step too; and a program that could only take its secret as an argument is refused.

netbird, zerotier-cli and ziti-edge-tunnel are not installed here, so those steps run against stand-ins that keep the state the
real program would and write down their own command line. Each script runs under `set -euo pipefail` on a PATH that holds the
stand-ins and the plain tools only. Nebula is different: its certificates are checked against the real nebula-cert and nebula
where they are found (in PATH, or in the folder STORAGEFORGE_TEST_NEBULA names), and against certificates the real nebula-cert
1.12.0 made, kept below, everywhere."""
import base64
import contextlib
import datetime as dt
import io
import json
import os
import shlex
import shutil
import subprocess
import tempfile
import unittest
import unittest.mock
from pathlib import Path

import dbfactory
from storageforge_index import changes, nebulaca, overlaykeys, overlays, secretstore, steps_overlay, steps_tailscale, steps_tunnels, vault

SETUP_KEY = 'A1B2C3D4-TEST-4NOT-AREAL-SETUPKEY0000'


def _real(name):
    folder = os.environ.get('STORAGEFORGE_TEST_NEBULA')
    found = shutil.which(name, path=folder) if folder else shutil.which(name)
    return str(Path(found).resolve()) if found else None


REAL_NEBULA, REAL_NEBULA_CERT = _real('nebula'), _real('nebula-cert')
NEEDS_NEBULA = unittest.skipUnless(REAL_NEBULA and REAL_NEBULA_CERT, 'needs the real nebula and nebula-cert (in PATH, or in the folder STORAGEFORGE_TEST_NEBULA names)')

# Made by the real nebula-cert 1.12.0 on 2026-11-20 (`nebula-cert ca -version 1 -name vector-ca -networks 10.9.0.0/24
# -unsafe-networks 192.168.7.0/24 -groups servers,web -duration 87600h`, then `sign -version 1 -name web-1 -networks 10.9.0.5/24
# -groups servers -unsafe-networks 192.168.7.0/24 -duration 8760h`), with what `nebula-cert print -json` said of each. The private
# keys were deleted: certificates are public.
VECTOR_CA = """-----BEGIN NEBULA CERTIFICATE-----
CmAKCXZlY3Rvci1jYRIJgICkUID+//8PGgqAjqCFDID+//8PIgdzZXJ2ZXJzIgN3
ZWIo2biA2AYw2b6w7gc6IJ97leuP+Dk9bBkHgy1StXXy1cavoCl7I48EVJh7Jpdc
QAESQIt/GSYWc0bfsXSU2+ccZX7f1EET7szYtn/YuS3KYHMP6CMmR2nl9Zdte7UZ
/n4F3SS6FG53800sRcmQA3aE5AM=
-----END NEBULA CERTIFICATE-----
"""
VECTOR_HOST = """-----BEGIN NEBULA CERTIFICATE-----
CncKBXdlYi0xEgmFgKRQgP7//w8aCoCOoIUMgP7//w8iB3NlcnZlcnMo2biA2AYw
2Z+F5wY6IAqVoNjG32qjPTyZc7Epg83sjP0lRubIAZn5O42AjTR/SiAr86QTZgN9
p/Oij4KnCuVwKwfdOYSTv+Lz+38M9r6XSBJAIJnfeeSlACCopwM67mdukYzFB/1D
Tnr9ctHM5DuKBPD3pn+UZTr832f9n6mef0NiLSpLAUjpvfsrJFlZuq8BDQ==
-----END NEBULA CERTIFICATE-----
"""
VECTOR_CA_SAID = {"details": {"curve": "CURVE25519", "groups": ["servers", "web"], "isCa": True, "issuer": "", "name": "vector-ca", "networks": ["10.9.0.0/24"],
                              "notAfter": "2036-11-17T02:09:29-08:00", "notBefore": "2026-11-20T02:09:29-08:00",
                              "publicKey": "9f7b95eb8ff8393d6c1907832d52b575f2d5c6afa0297b238f0454987b26975c", "unsafeNetworks": ["192.168.7.0/24"]},
                  "fingerprint": "2bf3a41366037da7f3a28f82a70ae5702b07dd398493bfe2f3fb7f0cf6be9748",
                  "signature": "8b7f1926167346dfb17494dbe71c657edfd44113eeccd8b67fd8b92dca60730fe823264769e5f5976d7bb519fe7e05dd24ba146e77f34d2c45c990037684e403", "version": 1}
VECTOR_HOST_SAID = {"details": {"curve": "CURVE25519", "groups": ["servers"], "isCa": False, "issuer": "2bf3a41366037da7f3a28f82a70ae5702b07dd398493bfe2f3fb7f0cf6be9748", "name": "web-1",
                                "networks": ["10.9.0.5/24"], "notAfter": "2027-11-20T02:09:29-08:00", "notBefore": "2026-11-20T02:09:29-08:00",
                                "publicKey": "0a95a0d8c6df6aa33d3c9973b12983cdec8cfd2546e6c80199f93b8d808d347f", "unsafeNetworks": ["192.168.7.0/24"]},
                    "fingerprint": "ebea5c5dc6c9767cee6991603a6b6ca6336dbbe39b1150b6c75cd3a11a8a24c4",
                    "signature": "2099df79e4a50020a8a7033aee676e918cc507fd434e7afd72d1cce43b8a04f0f7a67f94653afcdf67fd9fa99e7f43622d2a4b0148e9bdfb2b245959baaf010d", "version": 1}
PRELUDE = r'''set -euo pipefail
ok() { echo "ok: $*"; }; missing() { echo "missing: $*"; }; conflict() { echo "conflict: $*"; PROBLEMS=$((PROBLEMS + 1)); }
info() { echo "info: $*"; }; act() { if ((APPLY)); then echo "doing: $*"; return 0; else echo "would: $*"; return 1; fi; }
try() { "$@" || { conflict "failed: $*"; return 1; }; }; durable() { :; }
# the reload guard of scriptkit.HELPERS, as a stand-in: DEAD_MOUNT is a hard network mount whose server is gone
reload_systemd() { if [[ -n ${DEAD_MOUNT:-} ]]; then conflict "/mnt/dead is not answering: reloading systemd now would block logins"; return 1; fi; [[ -z ${RELOAD_FAILS:-} ]] && systemctl daemon-reload; }
PROBLEMS=0
'''
PLAIN = ('bash', 'sh', 'cat', 'grep', 'sed', 'tr', 'head', 'tail', 'awk', 'rm', 'mkdir', 'chmod', 'mv', 'cp', 'cmp', 'sleep', 'uname', 'mktemp', 'base64', 'touch', 'env', 'id', 'chown',
         'sha256sum', 'cut', 'date', 'ls', 'wc')

OWN_RUN = bool(shutil.which('unshare')) and subprocess.run(['unshare', '-Urm', 'mount', '-t', 'tmpfs', 'tmpfs', '/run'], capture_output=True).returncode == 0

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

    def step(self, apply, fn, *args, body=None, **env):
        call = fn + ' ' + ' '.join(f"'{a}'" for a in args)
        got = subprocess.run(['bash', '-c', PRELUDE + f'APPLY={int(apply)}\n' + (body or steps_tunnels.BASH + steps_overlay.BASH) + '\n' + call + '\nexit $((PROBLEMS > 0))\n'],
                             capture_output=True, text=True, timeout=60, env=self.env | env)
        self.assertEqual(got.stderr, '', 'nothing a step runs fails unseen, and nothing it needs is missing from the plain tools')
        return got.returncode, got.stdout

    def delivered_as_root(self, fn, name, value, *args):
        """What a signed run does as root, in a user namespace where this user is root and /run is its own: the plan's secret
        comes on stdin and is written by sf_secrets_in, then the step reports. SF_SECRET_DIR names an empty folder throughout."""
        call = fn + ' ' + ' '.join(f"'{a}'" for a in (name, *args))
        script = PRELUDE + 'APPLY=1 SECRETS_STDIN=1\n' + secretstore.BASH + 'APPLY=0\n' + steps_tunnels.BASH + steps_overlay.BASH + '\n' + call + '\n'
        got = subprocess.run([shutil.which('unshare'), '-Urm', 'bash', '-c', shutil.which('mount') + ' -t tmpfs tmpfs /run && exec bash -c "$0"', script], capture_output=True, text=True,
                             timeout=60, env=self.env, input=f'SF-SECRETS 1\n{name} {base64.b64encode(value.encode()).decode()}\nEND\n')
        out = got.stdout + got.stderr
        self.assertIn('info: 1 secret(s) from StorageForge written to /run/storageforge/secrets', out)
        self.assertNotIn('vault send-secret', out, 'the step found what the plan delivered')
        self.assertNotIn(str(self.d / 'secrets'), out, 'root reads the fixed folder')
        self.assertEqual(list((self.d / 'secrets').iterdir()), [])
        return out

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

    @unittest.skipUnless(OWN_RUN, 'needs a user who may make namespaces of its own (unshare -Urm)')
    def test_as_root_it_reads_the_folder_the_plan_delivered_to_whatever_SF_SECRET_DIR_says(self):
        out = self.delivered_as_root('t_netbird', 'nb-key', SETUP_KEY, 'https://nb.example.com', 'web-1', 'present')
        self.assertIn('would: netbird up --setup-key-file=/run/storageforge/secrets/nb-key ', out)

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
        for sent in (False, True):          # refused before the key is asked for, so nobody sends a key it cannot use
            if sent:
                self.secret('nb-key', SETUP_KEY)
            rc, out = self.step(True, 't_netbird', 'nb-key', '', '', 'present')
            self.assertEqual(rc, 1)
            self.assertIn('cannot read its setup key from a file (--setup-key-file): with it the key would be on a command line, so nothing is done', out)
        self.assertEqual(self.read('netbird.cmdline'), '')
        # one that somebody joined by hand is on its network all the same, and is said to be
        (self.fake / 'registered').touch()
        (self.fake / 'up').touch()
        rc, out = self.step(True, 't_netbird', 'nb-key', '', '', 'present')
        self.assertEqual(rc, 0, out)
        self.assertIn('ok: on a NetBird network already', out)

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
        for status, rc_want, text in (('PORT_ERROR', 1, 'ZeroTier on this host cannot use it (PORT_ERROR)'), ('AUTHENTICATION_REQUIRED', 0, 'wants a person to sign in before node 1a2b3c4d5e is let in')):
            (self.fake / 'nets' / NET).write_text(status + '\n')
            rc, out = self.step(True, 't_zerotier', NET, 'present')
            self.assertEqual(rc, rc_want, out)
            self.assertIn(text, out)

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


JWT = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL3ppdGkuZXhhbXBsZS5jb206MTI4MCIsImVtIjoib3R0IiwianRpIjoibm90LWEtcmVhbC10b2tlbiJ9.Tm90QVJlYWxTaWduYXR1cmVfLTAwMDAwMDAwMDAwMA'


class OpenZiti(Stage):
    """ziti-edge-tunnel as it enrolls: the token is a file it is named, it works once, the identity file must not be there yet,
    and what it writes holds a private key. When it fails it repeats the token it was given, which a real one may do in a log line."""

    def setUp(self):
        super().setUp()
        f = self.fake
        self.ids = self.d / 'identities'
        self.env['SF_ZITI_DIR'] = str(self.ids)
        (f / 'accepts').write_text(JWT)
        (f / 'packaged-ziti-edge-tunnel').touch()
        self.stub('ziti-edge-tunnel', f"""[ "$1" = enroll ] || exit 2
tr "\\0" " " </proc/$$/cmdline >>{f}/ziti.cmdline; echo >>{f}/ziti.cmdline
shift; while [ $# -gt 0 ]; do case $1 in --jwt) jwt=$2; shift ;; --identity) out=$2; shift ;; esac; shift; done
[ ! -e "$out" ] || {{ echo "ERROR failed to open file $out: File exists(17)" >&2; exit 1; }}
tok=$(tr -d "\\n" <"$jwt") || exit 1
if [ "$tok" != "$(cat {f}/accepts)" ] || [ -e {f}/used ]; then echo "ERROR enrollment failed: JWT validation failed for $tok" >&2; echo "ERROR controller said: ENROLLMENT_TOKEN_INVALID" >&2; exit 1; fi
touch {f}/used
echo "{{\\"ztAPI\\":\\"https://ziti.example.com:1280\\",\\"id\\":{{\\"cert\\":\\"pem:-----BEGIN CERTIFICATE-----\\",\\"key\\":\\"pem:-----BEGIN EC PRIVATE KEY-----STANDIN\\"}}}}" >"$out" """)

    def test_it_enrolls_from_the_token_file_and_the_token_is_on_no_command_line(self):
        rc, out = self.step(True, 't_openziti', 'ziti-web', 'web-1', 'present')
        self.assertEqual(rc, 1)
        self.assertIn(f'conflict: no enrollment token at {self.d}/secrets/ziti-web: storageforge-index vault send-secret ziti-web --host ', out)
        tok = self.secret('ziti-web', JWT)
        rc, out = self.step(False, 't_openziti', 'ziti-web', 'web-1', 'present')
        self.assertIn(f'would: ziti-edge-tunnel enroll --jwt {tok} --identity {self.ids}/web-1.json (the token works once)', out)
        self.assertEqual((self.read('ziti.cmdline'), self.ids.exists()), ('', False), 'a report runs and writes nothing')
        rc, out = self.step(True, 't_openziti', 'ziti-web', 'web-1', 'present')
        self.assertEqual(rc, 0, out)
        self.assertIn(f'ok: enrolled as web-1, and ziti-edge-tunnel.service loads {self.ids}/web-1.json. The token file is removed: it works once', out)
        self.assertEqual(self.read('ziti.cmdline').strip(), f'/bin/bash {self.d}/bin/ziti-edge-tunnel enroll --jwt {tok} --identity {self.ids}/web-1.json')
        identity = self.ids / 'web-1.json'
        self.assertEqual(identity.stat().st_mode & 0o777, 0o600, 'it holds a private key')
        self.assertFalse(tok.exists())
        self.assertIn('systemctl restart ziti-edge-tunnel.service', self.read('systemctl.calls'))
        self.assertNotIn(JWT, out + self.everything_written('fake/accepts'))
        self.assertNotIn('PRIVATE KEY', out + self.everything_written('identities/web-1.json'))

    @unittest.skipUnless(OWN_RUN, 'needs a user who may make namespaces of its own (unshare -Urm)')
    def test_as_root_it_reads_the_folder_the_plan_delivered_to_whatever_SF_SECRET_DIR_says(self):
        out = self.delivered_as_root('t_openziti', 'ziti-web', JWT, 'web-1', 'present')
        self.assertIn('would: ziti-edge-tunnel enroll --jwt /run/storageforge/secrets/ziti-web ', out)

    def test_a_second_run_changes_nothing_and_a_token_sent_again_is_removed(self):
        self.secret('ziti-web', JWT)
        self.step(True, 't_openziti', 'ziti-web', 'web-1', 'present')
        tok = self.secret('ziti-web', JWT)
        for apply in (False, True):
            rc, out = self.step(apply, 't_openziti', 'ziti-web', 'web-1', 'present')
            self.assertEqual(rc, 0)
            self.assertIn(f'ok: enrolled already as web-1: {self.ids}/web-1.json', out)
            self.assertNotIn('doing:', out)
        self.assertFalse(tok.exists())
        self.assertEqual(self.read('ziti.cmdline').count('\n'), 1)

    def test_the_group_of_the_packaged_service_reads_the_identity(self):
        self.stub('getent', '[ "$1 $2" = "group ziti" ] && echo "ziti:x:985:"')
        self.stub('chgrp', f'echo "chgrp $*" >>{self.fake}/chgrp.calls')
        self.secret('ziti-web', JWT)
        self.assertEqual(self.step(True, 't_openziti', 'ziti-web', 'web-1', 'present')[0], 0)
        self.assertEqual(self.read('chgrp.calls'), f'chgrp ziti {self.ids}/web-1.json\n')
        self.assertEqual((self.ids / 'web-1.json').stat().st_mode & 0o777, 0o640)

    def test_a_token_that_was_used_and_a_file_that_is_no_token(self):
        self.secret('ziti-web', JWT)
        (self.fake / 'used').touch()
        rc, out = self.step(True, 't_openziti', 'ziti-web', 'web-1', 'present')
        self.assertEqual(rc, 1)
        self.assertIn('conflict: the enrollment failed: ERROR enrollment failed: JWT validation failed for (the secret) ERROR controller said: ENROLLMENT_TOKEN_INVALID', out)
        self.assertIn('A token works once and for a limited time', out)
        self.assertNotIn(JWT, out, 'a program that repeats the token is not repeated')
        self.assertFalse((self.ids / 'web-1.json').exists())
        for text in ('not a token', JWT + '\n' + JWT, 'a.b', JWT + ' --identity /etc/passwd'):
            self.secret('ziti-web', text)
            rc, out = self.step(True, 't_openziti', 'ziti-web', 'web-1', 'present')
            self.assertIn('does not hold an enrollment token', out)
        self.assertEqual(self.read('ziti.cmdline').count('\n'), 1, 'what is not a token was never handed over')

    def test_without_the_service_it_says_how_the_identity_is_loaded_and_without_the_program_nothing_is_done(self):
        (self.fake / 'packaged-ziti-edge-tunnel').unlink()
        self.secret('ziti-web', JWT)
        rc, out = self.step(True, 't_openziti', 'ziti-web', 'web-1', 'present')
        self.assertEqual(rc, 0, out)
        self.assertIn(f'No ziti-edge-tunnel.service is here to load it: ziti-edge-tunnel run --identity-dir {self.ids} does', out)
        (self.d / 'bin' / 'ziti-edge-tunnel').unlink()
        rc, out = self.step(True, 't_openziti', 'ziti-web', 'web-2', 'present')
        self.assertIn('conflict: ziti-edge-tunnel is not installed', out)

    def test_absent_removes_the_identity_and_its_key(self):
        self.secret('ziti-web', JWT)
        self.step(True, 't_openziti', 'ziti-web', 'web-1', 'present')
        (self.ids / 'other.json').write_text('{}')
        rc, out = self.step(False, 't_openziti', 'ziti-web', 'web-1', 'absent')
        self.assertIn(f'would: remove {self.ids}/web-1.json', out)
        self.assertTrue((self.ids / 'web-1.json').exists())
        rc, out = self.step(True, 't_openziti', 'ziti-web', 'web-1', 'absent')
        self.assertEqual(rc, 0)
        self.assertIn('Delete it at the controller too', out)
        self.assertEqual([p.name for p in self.ids.iterdir()], ['other.json'])
        self.assertEqual(self.read('systemctl.calls').count('restart ziti-edge-tunnel.service'), 2)
        self.assertEqual(self.step(True, 't_openziti', 'ziti-web', 'web-1', 'absent'), (0, 'ok: no OpenZiti identity named web-1 is here\n'))


def _epoch(text):
    return int(dt.datetime.fromisoformat(text).timestamp())


def _as_nebula_cert_says(cert: dict) -> dict:
    """What nebulaca.read found, in the words of `nebula-cert print -json`, without the two times (compared as numbers)."""
    return {'details': {'curve': 'CURVE25519', 'groups': cert['groups'], 'isCa': cert['is_ca'], 'issuer': cert['issuer'], 'name': cert['name'], 'networks': cert['networks'],
                        'publicKey': cert['public_key'].hex(), 'unsafeNetworks': cert['unsafe_networks']},
            'fingerprint': cert['fingerprint'], 'signature': cert['signature'].hex(), 'version': 1}


def _without_times(said: dict) -> dict:
    return said | {'details': {k: v for k, v in said['details'].items() if k not in ('notBefore', 'notAfter')}}


def _key():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    key = Ed25519PrivateKey.generate()
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw), key.sign


class NebulaFormat(unittest.TestCase):
    """nebulaca.py against certificates the real nebula-cert made. No program is needed for these."""

    def test_it_reads_what_nebula_cert_wrote_as_nebula_cert_prints_it(self):
        for pem, said in ((VECTOR_CA, VECTOR_CA_SAID), (VECTOR_HOST, VECTOR_HOST_SAID)):
            cert = nebulaca.read(pem)
            self.assertEqual(_as_nebula_cert_says(cert), _without_times(said))
            self.assertEqual((cert['not_before'], cert['not_after']), (_epoch(said['details']['notBefore']), _epoch(said['details']['notAfter'])))

    def test_it_writes_the_same_bytes_nebula_cert_signed(self):
        """Nebula checks a signature over the details as it encodes them itself: a byte of difference and no host accepts the certificate."""
        import ipaddress
        for pem in (VECTOR_CA, VECTOR_HOST):
            c = nebulaca.read(pem)
            again = nebulaca._details(c['name'], [ipaddress.ip_interface(n) for n in c['networks']], [ipaddress.ip_interface(n) for n in c['unsafe_networks']], c['groups'],
                                      c['not_before'], c['not_after'], c['public_key'], c['is_ca'], bytes.fromhex(c['issuer']))
            self.assertEqual(again, c['signed'])
            self.assertEqual(nebulaca._pem(nebulaca.BANNER, nebulaca._field(1, 2, again) + nebulaca._field(2, 2, c['signature'])), pem)

    def test_the_signature_nebula_cert_made_verifies_and_a_changed_certificate_does_not(self):
        inside = _epoch('2027-01-01T00:00:00+00:00')
        self.assertEqual(nebulaca.verify(VECTOR_HOST, VECTOR_CA, inside)['name'], 'web-1')
        raw = bytearray(base64.b64decode(''.join(VECTOR_HOST.split('\n')[1:-2])))
        raw[4] ^= 1                                    # one letter of the name
        with self.assertRaisesRegex(nebulaca.CertificateError, 'signature'):
            nebulaca.verify(nebulaca._pem(nebulaca.BANNER, bytes(raw)), VECTOR_CA, inside)
        for when, why in ((_epoch('2026-01-01T00:00:00+00:00'), 'not valid yet'), (_epoch('2028-01-01T00:00:00+00:00'), 'the certificate has ended'), (_epoch('2037-01-01T00:00:00+00:00'), 'the CA certificate has ended')):
            with self.assertRaisesRegex(nebulaca.CertificateError, why):
                nebulaca.verify(VECTOR_HOST, VECTOR_CA, when)
        public, sign = _key()
        other = nebulaca.ca_certificate('other', public, sign, seconds=86400, now=inside)
        with self.assertRaisesRegex(nebulaca.CertificateError, 'did not issue'):
            nebulaca.verify(VECTOR_HOST, other, inside)
        with self.assertRaisesRegex(nebulaca.CertificateError, 'not a CA'):
            nebulaca.verify(VECTOR_HOST, VECTOR_HOST, inside)

    def test_what_a_ca_made_here_will_and_will_not_issue(self):
        public, sign = _key()
        host_public = bytes(range(32))
        ca = nebulaca.ca_certificate('home', public, sign, seconds=30 * 86400, networks=['10.9.0.0/24'], groups=['servers'], now=1_800_000_000)
        cert = nebulaca.host_certificate(ca, sign, name='web', address='10.9.0.5/24', public=host_public, groups=['servers'], now=1_800_000_000)
        said = nebulaca.verify(cert, ca, 1_800_000_100)
        self.assertEqual((said['networks'], said['groups'], said['is_ca'], said['issuer']), (['10.9.0.5/24'], ['servers'], False, nebulaca.fingerprint(ca)))
        self.assertEqual(said['not_after'], nebulaca.read(ca)['not_after'] - 1, 'with no length given it ends a second before its CA, as nebula-cert does')
        for kw, why in (({'address': '10.8.0.5/24'}, 'outside the networks this CA may issue for'), ({'address': '10.9.0.0/24'}, 'not a host address'), ({'address': '10.9.0.255/24'}, 'not a host address'),
                        ({'address': 'fd00::5/64'}, 'IPv4 only'), ({'address': '10.9.0.5'}, 'not a host address'), ({'groups': ['admins']}, 'issues only for the groups servers'),
                        ({'seconds': 31 * 86400}, 'cannot outlast its CA'), ({'seconds': 5}, 'at least a minute'), ({'name': 'web;id'}, 'needs a name'), ({'name': ''}, 'needs a name'),
                        ({'public': b'short'}, 'not an X25519 key'), ({'groups': ['a b']}, 'groups are names'), ({'now': 1_800_000_000 + 31 * 86400}, 'the CA certificate has ended')):
            with self.subTest(kw), self.assertRaisesRegex(nebulaca.CertificateError, why):
                nebulaca.host_certificate(ca, sign, **({'name': 'web', 'address': '10.9.0.5/24', 'public': host_public, 'now': 1_800_000_000} | kw))
        with self.assertRaisesRegex(nebulaca.CertificateError, 'not a CA'):
            nebulaca.host_certificate(cert, sign, name='x', address='10.9.0.6/24', public=host_public, now=1_800_000_000)
        with self.assertRaisesRegex(nebulaca.CertificateError, 'no Ed25519 signature'):
            nebulaca.host_certificate(ca, lambda data: b'', name='x', address='10.9.0.6/24', public=host_public, now=1_800_000_000)
        for kw, why in (({'seconds': 60}, 'between an hour and ten years'), ({'seconds': 11 * 366 * 86400}, 'between an hour and ten years'), ({'name': 'a b'}, 'needs a name'), ({'networks': ['10.9.0.0/33']}, 'not an address')):
            with self.subTest(kw), self.assertRaisesRegex(nebulaca.CertificateError, why):
                nebulaca.ca_certificate(**({'name': 'home', 'public': public, 'sign': sign, 'seconds': 86400} | kw))

    def test_nothing_that_is_not_a_certificate_makes_the_reader_do_anything_but_refuse(self):
        body = base64.b64decode(''.join(VECTOR_HOST.split('\n')[1:-2]))
        junk = ['', None, 7, 'x', VECTOR_HOST.replace('NEBULA CERTIFICATE', 'NEBULA CERTIFICATE V2'), '-----BEGIN NEBULA CERTIFICATE-----\n!!!\n-----END NEBULA CERTIFICATE-----\n',
                nebulaca._pem(nebulaca.BANNER, b''), nebulaca._pem(nebulaca.BANNER, b'\xff' * 40), nebulaca._pem(nebulaca.BANNER, body[:30]), nebulaca._pem(nebulaca.BANNER, b'\x0a\xff\xff\xff\xff\x0f'),
                nebulaca._pem(nebulaca.BANNER, nebulaca._field(1, 2, nebulaca._field(2, 2, b'\x01')) + nebulaca._field(2, 2, b'\0' * 64))]
        junk += [nebulaca._pem(nebulaca.BANNER, body[:i] + bytes([body[i] ^ 0x80]) + body[i + 1:]) for i in range(0, len(body), 7)]
        for text in junk:
            try:
                json.dumps({k: v.hex() if isinstance(v, bytes) else v for k, v in nebulaca.read(text).items()})
            except nebulaca.CertificateError:
                pass

    def test_the_configuration_takes_only_what_it_can_check(self):
        text = nebulaca.config(lighthouse=False, lighthouses_text='10.9.0.1=lh.example.org:4242, 10.9.0.2=198.51.100.7:4243', inbound_text='icmp, tcp/22, tcp/8000-8100@admins, any@web', blocklist=['ab' * 32])
        for line in ('pki:', '  ca: /etc/nebula/ca.crt', '  key: /etc/nebula/host.key', '    - ' + 'ab' * 32, '  "10.9.0.1": ["lh.example.org:4242"]', '  am_lighthouse: false', '    - "10.9.0.2"', '  port: 0',
                     '  dev: nebula1', '    - port: 8000-8100', '      group: "admins"', '    - port: 22'):
            self.assertIn(line + '\n', text)
        self.assertTrue(text.startswith('# Written by StorageForge'), 'the step knows its own file by this line')
        light = nebulaca.config(lighthouse=True, lighthouses_text='')
        self.assertIn('  am_lighthouse: true\n', light)
        self.assertIn('  hosts: []\n', light)
        self.assertIn('  port: 4242\n', light)
        for kw, why in (({'lighthouse': False, 'lighthouses_text': ''}, 'needs at least one lighthouse'), ({'lighthouses_text': 'lh.example.org:4242'}, 'a lighthouse is its Nebula address'),
                        ({'lighthouses_text': '10.9.0.1=lh.example.org'}, 'a name or address and a port'), ({'lighthouses_text': '10.9.0.1=lh.example.org:0'}, 'a name or address and a port'),
                        ({'lighthouses_text': '10.9.0.1=x:1"\n  evil: true'}, 'a name or address and a port'), ({'inbound_text': 'tcp'}, 'name the port'), ({'inbound_text': 'icmp/8'}, 'icmp has no port'),
                        ({'inbound_text': 'tcp/70000'}, 'ports are 1 to 65535'), ({'inbound_text': 'tcp/22@a b'}, 'an inbound rule is'), ({'inbound_text': 'tcp/22\n  - port: any'}, 'an inbound rule is'),
                        ({'lighthouse': True, 'port': 0}, 'a lighthouse listens on a port'), ({'port': 70000}, 'a lighthouse listens on a port'), ({'blocklist': ['zz']}, 'certificate fingerprints')):
            with self.subTest(kw), self.assertRaisesRegex(nebulaca.CertificateError, why):
                nebulaca.config(**({'lighthouse': False, 'lighthouses_text': '10.9.0.1=lh.example.org:4242'} | kw))


@NEEDS_NEBULA
class NebulaReal(unittest.TestCase):
    """The same module against the real programs: what is made here is accepted by nebula-cert and by nebula itself."""

    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.d, True)
        self.public, self.sign = _key()
        self.ca = nebulaca.ca_certificate('home', self.public, self.sign, seconds=365 * 86400, networks=['10.9.0.0/24'])
        (self.d / 'ca.crt').write_text(self.ca)
        subprocess.run([REAL_NEBULA_CERT, 'keygen', '-out-key', str(self.d / 'host.key'), '-out-pub', str(self.d / 'host.pub')], check=True)

    def cert(self, **kw):
        return nebulaca.host_certificate(self.ca, self.sign, **({'name': 'web', 'address': '10.9.0.5/24', 'public': nebulaca.public_key((self.d / 'host.pub').read_text())} | kw))

    def nebula_cert(self, *args):
        return subprocess.run([REAL_NEBULA_CERT, *args], capture_output=True, text=True, timeout=30)

    def test_nebula_cert_accepts_and_prints_what_was_made_here(self):
        (self.d / 'host.crt').write_text(self.cert(groups=['servers', 'web'], unsafe_networks=['192.168.7.0/24']))
        got = self.nebula_cert('verify', '-ca', str(self.d / 'ca.crt'), '-crt', str(self.d / 'host.crt'))
        self.assertEqual((got.returncode, got.stdout + got.stderr), (0, ''))
        for name in ('ca.crt', 'host.crt'):
            said = json.loads(self.nebula_cert('print', '-json', '-path', str(self.d / name)).stdout)[0]
            mine = nebulaca.read((self.d / name).read_text())
            self.assertEqual(_as_nebula_cert_says(mine), _without_times(said))
            self.assertEqual((mine['not_before'], mine['not_after']), (_epoch(said['details']['notBefore']), _epoch(said['details']['notAfter'])))

    def test_nebula_cert_refuses_another_ca_a_changed_certificate_and_one_that_ended(self):
        public, sign = _key()
        (self.d / 'other.crt').write_text(nebulaca.ca_certificate('other', public, sign, seconds=86400))
        (self.d / 'host.crt').write_text(self.cert())
        self.assertNotEqual(self.nebula_cert('verify', '-ca', str(self.d / 'other.crt'), '-crt', str(self.d / 'host.crt')).returncode, 0)
        forged = nebulaca._signed(nebulaca.read(self.cert())['signed'], sign)          # the same words, signed by a key that is not the CA
        (self.d / 'forged.crt').write_text(forged)
        self.assertNotEqual(self.nebula_cert('verify', '-ca', str(self.d / 'ca.crt'), '-crt', str(self.d / 'forged.crt')).returncode, 0)
        old = nebulaca.ca_certificate('home', self.public, self.sign, seconds=3600, now=1_700_000_000)
        (self.d / 'old-ca.crt').write_text(old)
        (self.d / 'old.crt').write_text(nebulaca.host_certificate(old, self.sign, name='web', address='10.9.0.5/24', public=bytes(32), now=1_700_000_000))
        self.assertNotEqual(self.nebula_cert('verify', '-ca', str(self.d / 'old-ca.crt'), '-crt', str(self.d / 'old.crt')).returncode, 0)

    def test_nebula_reads_the_configuration_with_the_certificate_and_the_hosts_own_key(self):
        (self.d / 'host.crt').write_text(self.cert(groups=['servers']))
        for kw in ({'lighthouse': False, 'lighthouses_text': '10.9.0.1=lh.example.org:4242, 10.9.0.2=198.51.100.7:4243', 'inbound_text': 'icmp, tcp/22, udp/53@servers, tcp/8000-8100, any@web'},
                   {'lighthouse': True, 'lighthouses_text': '10.9.0.2=198.51.100.7:4243', 'port': 4300, 'blocklist': ['ab' * 32, 'cd' * 32]}, {'lighthouse': True, 'lighthouses_text': '', 'inbound_text': ''}):
            (self.d / 'config.yml').write_text(nebulaca.config(directory=str(self.d), **kw))
            got = subprocess.run([REAL_NEBULA, '-test', '-config', str(self.d / 'config.yml')], capture_output=True, text=True, timeout=30)
            self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
        # a certificate for a key the host does not hold: nebula refuses to start with it
        (self.d / 'host.crt').write_text(self.cert(public=bytes(range(32))))
        got = subprocess.run([REAL_NEBULA, '-test', '-config', str(self.d / 'config.yml')], capture_output=True, text=True, timeout=30)
        self.assertNotEqual(got.returncode, 0)


def _namespaces():
    """Can this account make network namespaces of its own? Then two real Nebula nodes can run here without root."""
    if not all(shutil.which(x) for x in ('unshare', 'ip', 'ping')) or not os.path.exists('/dev/net/tun'):
        return False
    try:
        return subprocess.run(['unshare', '-Urnm', 'sh', '-c', 'mount -t tmpfs tmpfs /run && mkdir /run/netns && ip netns add probe && ip netns exec probe ip tuntap add dev t0 mode tun'],
                              capture_output=True, timeout=20).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


TWO_NODES = r"""set -eu
mount -t tmpfs tmpfs /run; mkdir /run/netns
ip netns add a; ip netns add b
ip link add va type veth peer name vb
ip link set va netns a; ip link set vb netns b
ip -n a addr add 192.0.2.1/24 dev va; ip -n a link set va up; ip -n a link set lo up
ip -n b addr add 192.0.2.2/24 dev vb; ip -n b link set vb up; ip -n b link set lo up
pids=
trap 'kill $pids 2>/dev/null || true' EXIT
start() { ip netns exec "$1" "$NEBULA" -config "$D/$1/$2" >>"$D/$1/log" 2>&1 & eval "pid_$1=$!"; pids="$pids $!"
  i=0; while ! ip -n "$1" -4 addr show nebula1 2>/dev/null | grep -q "inet 10.9.0."; do i=$((i + 1)); [ $i -lt 50 ] || { echo "nebula did not come up in $1"; cat "$D/$1/log"; exit 3; }; sleep 0.2; done; }
reach() { if ip netns exec b ping -c 1 -W 2 10.9.0.1 >/dev/null 2>&1 || ip netns exec b ping -c 1 -W 3 10.9.0.1 >/dev/null 2>&1; then echo "$1 reached"; else echo "$1 refused"; fi; }
start a config.yml; start b config.yml
reach first
kill $pid_a; wait $pid_a 2>/dev/null || true; start a config.yml
reach restarted
kill $pid_a; wait $pid_a 2>/dev/null || true; start a blocked.yml
reach blocked
"""


@NEEDS_NEBULA
@unittest.skipUnless(REAL_NEBULA and REAL_NEBULA_CERT and _namespaces(), 'needs network namespaces of its own (unshare -Urnm), ip, ping and /dev/net/tun')
class NebulaNetwork(unittest.TestCase):
    """Two real Nebula nodes, a lighthouse and a host, each in a network namespace of its own with one cable between them, started
    with certificates and configurations made here. No root is needed: the namespaces belong to this account."""

    def test_two_real_nodes_reach_each_other_until_one_certificate_is_on_the_blocklist(self):
        d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d, True)
        public, sign = _key()
        ca = nebulaca.ca_certificate('home', public, sign, seconds=86400, networks=['10.9.0.0/24'])
        certs = {}
        for name, address in (('a', '10.9.0.1/24'), ('b', '10.9.0.5/24')):
            (d / name).mkdir()
            subprocess.run([REAL_NEBULA_CERT, 'keygen', '-out-key', str(d / name / 'host.key'), '-out-pub', str(d / name / 'host.pub')], check=True)
            certs[name] = nebulaca.host_certificate(ca, sign, name=name, address=address, public=nebulaca.public_key((d / name / 'host.pub').read_text()))
            (d / name / 'host.crt').write_text(certs[name])
            (d / name / 'ca.crt').write_text(ca)
        (d / 'a' / 'config.yml').write_text(nebulaca.config(lighthouse=True, lighthouses_text='', directory=str(d / 'a')))
        (d / 'a' / 'blocked.yml').write_text(nebulaca.config(lighthouse=True, lighthouses_text='', directory=str(d / 'a'), blocklist=[nebulaca.fingerprint(certs['b'])]))
        (d / 'b' / 'config.yml').write_text(nebulaca.config(lighthouse=False, lighthouses_text='10.9.0.1=192.0.2.1:4242', directory=str(d / 'b')))
        got = subprocess.run(['unshare', '-Urnm', 'sh', '-c', TWO_NODES], capture_output=True, text=True, timeout=90, env={**os.environ, 'D': str(d), 'NEBULA': REAL_NEBULA})
        self.assertEqual(got.stdout.split('\n')[:3], ['first reached', 'restarted reached', 'blocked refused'], got.stdout + got.stderr + (d / 'a' / 'log').read_text()[-3000:])
        self.assertIn('block', (d / 'a' / 'log').read_text().lower(), 'the lighthouse says why it refused')


class Vaulted(Stage):
    """A stage with a database and a vault, and ssh replaced by running what it was given here: what `vault nebula-issue` and
    `vault headscale-key` send to a host runs under the stage's PATH, with /etc/nebula moved to a folder per host."""

    def setUp(self):
        super().setUp()
        self.db, self.conn = plan_db(self)
        secret = self.d / 'vault-secret'
        secret.write_text('s' * 48)
        os.environ['STORAGEFORGE_VAULT_SECRET_FILE'] = str(secret)
        self.addCleanup(os.environ.pop, 'STORAGEFORGE_VAULT_SECRET_FILE', None)
        self.ssh = []
        self.assertEqual(self.vault('init')[0], 0)

    def host_dir(self, host):
        return self.d / 'hosts' / host / 'nebula'

    def vault(self, *args, stdin=''):
        from storageforge_index import cli
        real = subprocess.run

        def over_ssh(argv, input=None, **kw):
            if argv[0] != 'ssh':
                return real(argv, input=input, **kw)
            target, remote = argv[-2].split('@')[-1], shlex.split(argv[-1])
            self.ssh.append((argv, input))
            if remote[:2] != ['sudo', '-n']:
                raise AssertionError(f'not run as root without a password: {argv[-1]}')
            script = remote[4].replace('/etc/nebula', str(self.host_dir(target))).replace('/run/storageforge/secrets', str(self.d / 'secrets')) if remote[2:4] == ['sh', '-c'] else None
            words = ['sh', '-c', script] if script else remote[2:]
            return real(words, input=input, capture_output=True, timeout=60, env={'PATH': self.env['PATH'], 'FAKE': str(self.fake)})
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), unittest.mock.patch('subprocess.run', over_ssh), unittest.mock.patch('sys.stdin', io.StringIO(stdin)):
            rc = cli.main(['--db', self.db.url, 'vault', *args])
        return rc, out.getvalue(), err.getvalue()

    def audited(self, like):
        return [(r[0], r[1]) for r in self.conn.all('SELECT action, outcome FROM audit_log WHERE action LIKE :l ORDER BY audit_id', {'l': like})]


HS_KEY = 'hskey-auth-TESTtestTEST-notARealPreAuthKey0000000000000000000000000000'
HS_NODES = [{'id': 1, 'given_name': 'router', 'name': 'router', 'ip_addresses': ['100.64.0.1', 'fd7a:115c:a1e0::1'], 'node_key': 'nodekey:aa', 'online': True, 'user': {'id': 1, 'name': 'gabe'},
             'approved_routes': ['10.42.0.0/24'], 'available_routes': ['10.42.0.0/24', '192.168.9.0/24'], 'subnet_routes': ['10.42.0.0/24']},
            {'id': 2, 'given_name': 'exit', 'ip_addresses': ['100.64.0.2'], 'online': False, 'approved_routes': ['0.0.0.0/0', '::/0'], 'available_routes': ['0.0.0.0/0', '::/0'], 'subnet_routes': []},
            {'id': 3, 'given_name': 'laptop', 'ip_addresses': ['100.64.0.3'], 'online': True}]


class HeadscaleRoutes(unittest.TestCase):
    def test_what_is_approved_what_waits_and_what_is_served(self):
        got = overlays.headscale('WRN a warning before the JSON\n' + json.dumps(HS_NODES))
        by = {p['name']: p for p in got['peers']}
        self.assertEqual((by['router']['routes'], by['router']['routes_waiting']), (['10.42.0.0/24'], ['192.168.9.0/24']), 'advertised and not approved carries nothing yet')
        self.assertEqual((by['exit']['routes'], by['exit']['routes_waiting']), (['0.0.0.0/0', '::/0'], []))
        self.assertEqual((by['laptop']['routes'], by['laptop']['routes_waiting']), ([], []))
        self.assertEqual(got['routes'], ['10.42.0.0/24'], 'what the tailnet serves now: the exit node is offline and serves nothing')
        self.assertNotIn('gabe', json.dumps(got))

    def test_the_next_release_spells_its_fields_differently_and_reads_the_same(self):
        """Headscale 0.29 prints ip_addresses and approved_routes; its main branch (2026-11-20) prints ipAddresses and approvedRoutes."""
        def camel(k):
            head, *rest = k.split('_')
            return head + ''.join(w.capitalize() for w in rest)
        newer = [{camel(k): v for k, v in n.items()} for n in HS_NODES]
        self.assertIn('ipAddresses', newer[0])
        self.assertEqual(overlays.headscale(json.dumps(newer)), overlays.headscale(json.dumps(HS_NODES)))

    def test_junk_in_the_route_lists_is_dropped(self):
        got = overlays.headscale(json.dumps([{'given_name': 'x', 'ip_addresses': ['100.64.0.9'], 'approved_routes': 'all', 'available_routes': [5, None, 'not a network', '10.1.0.0/16', {'a': 1}], 'subnet_routes': {'x': 1}}]))
        self.assertEqual((got['peers'][0]['routes'], got['peers'][0]['routes_waiting'], got['routes']), ([], ['10.1.0.0/16'], []))


class Headscale(Vaulted):
    """`vault headscale-key`: the key is made on the Headscale server, crosses inside ssh, and goes into the vault. headscale is a
    stand-in that answers as 0.29 does and writes down the words it was given."""

    def setUp(self):
        super().setUp()
        f = self.fake
        (f / 'answer').write_text(json.dumps({'user': {'id': 1, 'name': 'gabe'}, 'id': 7, 'key': HS_KEY, 'reusable': True, 'expiration': {'seconds': 1795200000, 'nanos': 0}, 'acl_tags': []}, indent='\t'))
        self.stub('headscale', f'echo "headscale $*" >>{f}/headscale.calls\n[ ! -e {f}/headscale-fails ] || {{ echo "Error: user not found" >&2; exit 1; }}\necho "WRN An updated version of Headscale has been found" >&2\ncat {f}/answer')
        self.stub('docker', f'echo "docker $*" >>{f}/docker.calls\n[ "$1" = exec ] && shift 2 && exec "$@"')

    def test_the_key_goes_from_the_server_into_the_vault_and_is_never_printed(self):
        rc, out, err = self.vault('headscale-key', 'hs-key', '--host', 'nas', '--hs-user', '1', '--reusable', '--expiration', '2h')
        self.assertEqual(rc, 0, err)
        self.assertEqual(self.read('headscale.calls'), 'headscale preauthkeys create --expiration 2h -o json --user 1 --reusable\n')
        self.assertIn('stored secret hs-key: a Headscale pre-auth key from nas, good until 2026-11-', out)
        self.assertIn('reusable', out)
        argv, sent = self.ssh[-1]
        self.assertEqual((argv[-2], sent), ('scan@nas', b''), 'nothing is sent to the server but the command')
        self.assertNotIn(HS_KEY, out + err + ' '.join(argv))
        rows = self.conn.all("SELECT action, outcome, detail_json FROM audit_log WHERE action = 'vault.secret_add'")
        self.assertEqual([(r[0], r[1]) for r in rows], [('vault.secret_add', 'ok')])
        self.assertNotIn(HS_KEY, str(rows))
        self.assertIn('headscale', str(rows))
        # and from the vault to a host, for the tailscale step, as any secret goes: on stdin
        rc, out, err = self.vault('send-secret', 'hs-key', '--host', 'nas')
        self.assertEqual(rc, 0, err)
        argv, sent = self.ssh[-1]
        self.assertEqual(sent, (HS_KEY + '\n').encode())
        self.assertNotIn(HS_KEY, ' '.join(argv) + out + err)
        self.assertEqual((self.d / 'secrets' / 'hs-key').read_text(), HS_KEY + '\n')

    def test_the_tailscale_step_joins_through_the_headscale_server_with_it(self):
        self.assertEqual(self.vault('headscale-key', 'hs-key', '--host', 'nas', '--tags', 'tag:server')[0], 0)
        self.assertEqual(self.read('headscale.calls'), 'headscale preauthkeys create --expiration 1h -o json --tags tag:server\n', 'a tagged key needs no user')
        self.assertEqual(self.vault('send-secret', 'hs-key', '--host', 'nas')[0], 0)
        f = self.fake
        self.stub('tailscale', f"""case $1 in
  status) if [ -e {f}/ts-up ]; then echo "  \\"BackendState\\": \\"Running\\","; else echo "  \\"BackendState\\": \\"NeedsLogin\\","; fi ;;
  up) tr "\\0" " " </proc/$$/cmdline >{f}/tailscale.cmdline
      for a in "$@"; do case $a in --auth-key=file:*) cat "${{a#--auth-key=file:}}" >{f}/tailscale.read || exit 1 ;; esac; done; touch {f}/ts-up ;;
  ip) echo 100.64.0.7 ;;
esac""")
        (f / 'active-tailscaled').touch()
        plan = changes.normalize({'name': 't', 'tasks': [{'type': 'tailscale', 'host': 'nas', 'params': {'secret': 'hs-key', 'login_server': 'https://hs.example.com'}}]})
        said = ' '.join(i['text'] for i in changes.check(self.conn, plan)['tasks'][0]['items'])
        self.assertIn('joins through the control server https://hs.example.com (Headscale)', said)
        self.assertIn('storageforge-index vault headscale-key', said)
        self.assertIn("hs-key '' '' '' '' present https://hs.example.com", changes.script(self.conn, plan))
        body = steps_tailscale.BASH.replace('/run/storageforge/secrets', str(self.d / 'secrets'))
        rc, out = self.step(True, 't_tailscale', 'hs-key', '', '', '', '', 'present', 'https://hs.example.com', body=body)
        self.assertEqual(rc, 0, out)
        self.assertIn('joined the tailnet as 100.64.0.7', out)
        self.assertEqual(self.read('tailscale.cmdline').strip(), f'/bin/bash {self.d}/bin/tailscale up --reset --auth-key=file:{self.d}/secrets/hs-key --login-server=https://hs.example.com --timeout=90s')
        self.assertEqual(self.read('tailscale.read'), HS_KEY + '\n')
        self.assertNotIn(HS_KEY, out + self.everything_written('fake/tailscale.read', 'fake/answer'))
        bad = changes.normalize({'name': 't', 'tasks': [{'type': 'tailscale', 'host': 'nas', 'params': {'secret': 'hs-key', 'login_server': 'hs.example.com --ssh'}}]})
        self.assertEqual([i['level'] for i in changes.check(self.conn, bad)['tasks'][0]['items']].count('crit'), 1)
        # a plan saved before the field was there is the same plan, and its playbook does not hand the step the word None
        old = changes.normalize({'name': 't', 'tasks': [{'type': 'tailscale', 'host': 'nas', 'params': {'secret': 'hs-key'}}]})
        before = {'tasks': [{**old['tasks'][0], 'params': {k: v for k, v in old['tasks'][0]['params'].items() if k != 'login_server'}}]}
        self.assertEqual(changes.plan_hash(old), changes.plan_hash(before))
        cmd = changes.EXTRA['tailscale']['ansible'](before['tasks'][0])['ansible.builtin.shell']['cmd']
        self.assertTrue(cmd.rstrip().endswith("t_tailscale hs-key '' '' '' '' present ''"), cmd[-80:])

    def test_headscale_in_a_container_and_the_words_it_is_given_are_checked(self):
        rc, out, err = self.vault('headscale-key', 'hs-key', '--host', 'nas', '--hs-user', 'gabe@example.com', '--container', 'headscale', '--ephemeral')
        self.assertEqual(rc, 0, err)
        self.assertEqual(self.read('docker.calls'), 'docker exec headscale headscale preauthkeys create --expiration 1h -o json --user gabe@example.com --ephemeral\n')
        before = len(self.ssh)
        for words, why in ((['--hs-user', '1; id'], 'the Headscale user is its number or its name'), (['--tags', 'server'], 'tags are tag:name'), ([], 'for a Headscale user (--hs-user) or for tags (--tags)'),
                           (['--hs-user', '1', '--expiration', '1 hour'], 'an expiration is a number and m, h or d'), (['--hs-user', '1', '--container', 'a b'], 'a container name'),
                           (['--hs-user', '1', '--user', 'Root; id'], 'is not a login name')):
            rc, out, err = self.vault('headscale-key', 'hs-key2', '--host', 'nas', *words)
            self.assertEqual((rc, why in err), (1, True), err)
        self.assertEqual(self.vault('headscale-key', 'bad name', '--host', 'nas', '--hs-user', '1')[0], 1)
        self.assertEqual(self.vault('headscale-key', 'hs-key2', '--host=-oProxyCommand=x', '--hs-user', '1')[0], 1)
        self.assertEqual(len(self.ssh), before, 'none of them reached ssh')

    def test_a_server_that_makes_no_key_stores_nothing_and_keeps_the_old_one(self):
        self.assertEqual(self.vault('headscale-key', 'hs-key', '--host', 'nas', '--hs-user', '1')[0], 0)
        (self.fake / 'headscale-fails').touch()
        rc, out, err = self.vault('headscale-key', 'hs-key', '--host', 'nas', '--hs-user', '9')
        self.assertEqual(rc, 1)
        self.assertIn('nas: headscale made no key: Error: user not found', err)
        (self.fake / 'headscale-fails').unlink()
        for answer in ('{}', 'not json', json.dumps({'key': 'short'}), json.dumps({'key': HS_KEY + ' and more'}), json.dumps([HS_KEY])):
            (self.fake / 'answer').write_text(answer)
            rc, out, err = self.vault('headscale-key', 'hs-key', '--host', 'nas', '--hs-user', '1')
            self.assertEqual((rc, err.strip()), (1, 'Headscale did not answer with a pre-auth key'))
        self.assertEqual(self.vault('send-secret', 'hs-key', '--host', 'nas')[0], 0)
        self.assertEqual(self.ssh[-1][1], (HS_KEY + '\n').encode(), 'the key that was there is still the one stored')
        outcomes = [r[0] for r in self.conn.all("SELECT outcome FROM audit_log WHERE action = 'vault.secret_add' ORDER BY audit_id")]
        self.assertEqual(outcomes, ['ok'] + ['failed'] * 6)

    def test_a_name_another_kind_of_credential_holds_is_refused_before_a_key_is_made(self):
        with vault.Vault(self.db, self.conn).unlock() as v:
            v.store_credential('sw', 'admin', 'device-password')
        before = len(self.ssh)
        rc, out, err = self.vault('headscale-key', 'sw', '--host', 'nas', '--hs-user', '1')
        self.assertEqual(rc, 1)
        self.assertIn('sw is a device credential', err)
        self.assertEqual(len(self.ssh), before, 'no key was made on the server for a name that cannot take it')
        with vault.Vault(self.db, self.conn).unlock() as v:
            self.assertEqual(v.credential('sw')['password'], 'device-password')

    def test_a_new_key_under_the_same_name_keeps_the_policy_of_the_secret(self):
        self.assertEqual(self.vault('secret-add', 'hs-key', '--step', 'tailscale', '--for-host', 'nas', stdin='an-older-key-123456\n')[0], 0)
        rc, out, err = self.vault('headscale-key', 'hs-key', '--host', 'nas', '--hs-user', '1')
        self.assertEqual(rc, 0, err)
        policy = self.conn.scalar("SELECT policy_json FROM device_credentials WHERE name = 'hs-key'")
        self.assertEqual((json.loads(policy)['steps'], json.loads(policy)['hosts']), (['tailscale'], ['nas']))
        with vault.Vault(self.db, self.conn).unlock() as v:
            self.assertEqual(v.credential('hs-key', host='nas', step='tailscale')['password'], HS_KEY)

    def test_the_answer_of_the_next_release(self):
        key, said = overlaykeys.headscale_answer(json.dumps({'aclTags': ['tag:server'], 'createdAt': '2026-11-20T10:00:00Z', 'ephemeral': False, 'expiration': '2026-11-20T11:00:00Z', 'id': '12', 'key': HS_KEY, 'reusable': False, 'used': False}))
        self.assertEqual((key, said), (HS_KEY, {'id': '12', 'reusable': False, 'ephemeral': False, 'expiration': '2026-11-20T11:00:00Z'}))


@NEEDS_NEBULA
class NebulaJoin(Vaulted):
    """The whole way with the real nebula-cert and nebula: a CA whose key is a vault key, a host that makes its own key, a
    certificate issued and written back, and the step that writes the configuration. Starting Nebula needs root and a tunnel
    device, so the unit's ExecStart is a stand-in that has the real nebula read (-test) what it was started with."""

    def setUp(self):
        super().setUp()
        (self.d / 'bin' / 'nebula-cert').symlink_to(REAL_NEBULA_CERT)
        self.stub('nebula', f'if [ "$1" = -test ]; then exec {REAL_NEBULA} "$@"; fi\necho "nebula $*" >>{self.fake}/nebula.started\nexec {REAL_NEBULA} -test "$@" >/dev/null 2>&1')
        self.dir = self.host_dir('nas')
        self.env['SF_NEBULA_DIR'] = str(self.dir)
        rc, self.ca_pem, err = self.vault('nebula-ca', 'home', '--networks', '10.9.0.0/24')
        self.assertEqual(rc, 0, err)

    def task(self, **params):
        return changes.normalize({'name': 'n', 'tasks': [{'type': 'nebula', 'host': 'nas', 'params': {'ca': 'home', 'lighthouses': '10.9.0.1=lh.example.org:4242', **params}}]})['tasks'][0]

    def words(self, **params):
        """What the plan script gives t_nebula, with /etc/nebula in the configuration moved to this host's folder."""
        t = self.task(**params)
        p = t['params']
        ca, conf = steps_overlay._nebula_args(self.conn, t)
        conf = base64.b64encode(base64.b64decode(conf).decode().replace('/etc/nebula', str(self.dir)).encode()).decode() if conf else ''
        return [p['ca'], '1' if p['lighthouse'] else '', p['lighthouses'], p['port'], p['inbound'], p['state'], ca, conf]

    def issue(self, host='nas', address='10.9.0.5/24', *more):
        return self.vault('nebula-issue', 'home', '--host', host, '--address', address, *more)

    def test_the_ca_key_is_a_vault_key_and_its_certificate_is_one_nebula_cert_reads(self):
        self.assertIn('nebula-ca-home', self.vault('list')[1])
        (self.d / 'ca.crt').write_text(self.ca_pem)
        said = json.loads(subprocess.run([REAL_NEBULA_CERT, 'print', '-json', '-path', str(self.d / 'ca.crt')], capture_output=True, text=True).stdout)[0]
        self.assertEqual((said['details']['name'], said['details']['isCa'], said['details']['networks']), ('home', True, ['10.9.0.0/24']))
        kept = json.dumps(overlaykeys.cas(self.conn))
        self.assertNotIn('PRIVATE', kept)
        self.assertEqual(overlaykeys.cas(self.conn)['home']['fingerprint'], said['fingerprint'])
        rc, _, err = self.vault('nebula-ca', 'home')
        self.assertEqual((rc, 'there is a Nebula CA named home already' in err), (1, True))
        self.assertEqual(self.audited('vault.nebula%'), [('vault.nebula_ca', 'ok')])

    def test_a_host_makes_its_own_key_gets_a_certificate_and_joins(self):
        rc, out = self.step(True, 't_nebula', *self.words())
        self.assertEqual(rc, 1)
        self.assertIn(f'conflict: no host certificate in {self.dir}: storageforge-index vault nebula-issue home --host ', out)
        rc, out, err = self.issue('nas', '10.9.0.5/24', '--groups', 'servers')
        self.assertEqual(rc, 0, err)
        self.assertIn('Its key was made on the host and stays there', out)
        key = (self.dir / 'host.key').read_text()
        self.assertEqual((self.dir / 'host.key').stat().st_mode & 0o777, 0o600)
        sent = ' '.join(' '.join(argv) + (data or b'').decode() for argv, data in self.ssh)
        self.assertIn('scan@nas', sent)
        self.assertNotIn(key.split('\n')[1], sent, 'the host key is in nothing that crossed')
        self.assertNotIn('PRIVATE', sent)
        got = subprocess.run([REAL_NEBULA_CERT, 'verify', '-ca', str(self.dir / 'ca.crt'), '-crt', str(self.dir / 'host.crt')], capture_output=True, text=True)
        self.assertEqual((got.returncode, got.stdout + got.stderr), (0, ''))
        said = nebulaca.verify((self.dir / 'host.crt').read_text(), self.ca_pem)
        self.assertEqual((said['name'], said['networks'], said['groups']), ('nas', ['10.9.0.5/24'], ['servers']))
        # the plan: it knows the certificate, carries nothing secret, and the step writes what nebula itself accepts
        plan = {'name': 'n', 'tasks': [self.task()]}
        checked = changes.check(self.conn, plan)['tasks'][0]['items']
        self.assertFalse([i for i in checked if i['level'] in ('crit', 'warn')], checked)
        self.assertTrue(any('nas has a certificate from CA home as nas at 10.9.0.5/24' in i['text'] for i in checked))
        text = changes.script(self.conn, plan)
        self.assertIn("nebula 'Join the Nebula network of CA home' home '' 10.9.0.1=lh.example.org:4242 '' '' present ", text)
        self.assertNotIn(key.split('\n')[1], text)
        for apply, want in ((False, 'would: write'), (True, 'doing: write')):
            rc, out = self.step(apply, 't_nebula', *self.words())
            self.assertEqual(rc, 0, out)
            self.assertIn(want, out)
        self.assertIn(f'ok: Nebula runs as storageforge-nebula.service from {self.dir}/config.yml', out)
        conf = (self.dir / 'config.yml').read_text()
        self.assertIn('"10.9.0.1": ["lh.example.org:4242"]', conf)
        unit = (self.d / 'units' / 'storageforge-nebula.service').read_text()
        self.assertIn(f'ExecStart={self.d}/bin/nebula -config {self.dir}/config.yml\n', unit)
        self.assertEqual(self.read('nebula.started'), f'nebula -config {self.dir}/config.yml\n')
        for apply in (False, True):
            rc, out = self.step(apply, 't_nebula', *self.words())
            self.assertEqual((rc, out), (0, f'ok: Nebula runs as storageforge-nebula.service from {self.dir}/config.yml, with a certificate CA home issued\n'))
        self.assertEqual(self.read('nebula.started').count('\n'), 1, 'a second run starts nothing again')
        # the same key is kept when a certificate is issued again, and an address belongs to one name
        self.assertEqual(self.issue('nas', '10.9.0.5/24')[0], 0)
        self.assertEqual((self.dir / 'host.key').read_text(), key)
        rc, _, err = self.issue('laptop', '10.9.0.5/24')
        self.assertEqual((rc, "10.9.0.5 is nas's on this network" in err), (1, True))
        rc, _, err = self.issue('laptop', '10.8.0.5/24')
        self.assertEqual((rc, 'outside the networks this CA may issue for' in err), (1, True))
        self.assertEqual(self.audited('vault.nebula_issue'), [('vault.nebula_issue', 'ok'), ('vault.nebula_issue', 'ok'), ('vault.nebula_issue', 'failed'), ('vault.nebula_issue', 'failed')])

    def test_a_lighthouse_does_not_name_itself_and_listens_on_its_port(self):
        self.assertEqual(self.issue('nas', '10.9.0.1/24')[0], 0)
        t = self.task(lighthouse=True, lighthouses='10.9.0.1=lh.example.org:4242, 10.9.0.2=lh2.example.org:4242')
        conf = base64.b64decode(steps_overlay._nebula_args(self.conn, t)[1]).decode()
        self.assertIn('  am_lighthouse: true\n', conf)
        self.assertIn('  port: 4242\n', conf)
        self.assertNotIn('"10.9.0.1"', conf, 'its own address is not in its own map')
        self.assertIn('"10.9.0.2": ["lh2.example.org:4242"]', conf)
        said = [i['text'] for i in changes.check(self.conn, {'name': 'n', 'tasks': [t]})['tasks'][0]['items']]
        self.assertTrue(any('a lighthouse listens on UDP port 4242' in x and 'opens no firewall' in x for x in said), said)
        rc, out = self.step(True, 't_nebula', *self.words(lighthouse=True, lighthouses='10.9.0.1=lh.example.org:4242'))
        self.assertEqual(rc, 0, out)
        self.assertIn('as a lighthouse: others must reach its UDP port', out)
        self.assertIn('static_host_map: {}', (self.dir / 'config.yml').read_text())

    def test_a_revoked_certificate_reaches_the_other_hosts_through_the_step(self):
        self.assertEqual(self.issue('nas', '10.9.0.5/24')[0], 0)
        self.assertEqual(self.issue('laptop', '10.9.0.9/24')[0], 0)
        self.assertEqual(self.step(True, 't_nebula', *self.words())[0], 0)
        gone = nebulaca.fingerprint((self.host_dir('laptop') / 'host.crt').read_text())
        rc, out, err = self.vault('nebula-revoke', 'home', 'laptop')
        self.assertEqual(rc, 0, err)
        self.assertEqual(overlaykeys.blocklist(self.conn, 'home'), [gone])
        said = ' '.join(i['text'] for i in changes.check(self.conn, {'name': 'n', 'tasks': [self.task()]})['tasks'][0]['items'])
        self.assertIn('with the 1 revoked certificate(s) this host must refuse', said)
        rc, out = self.step(True, 't_nebula', *self.words())
        self.assertEqual(rc, 0, out)
        self.assertIn('doing: write', out)
        self.assertIn(f'  blocklist:\n    - {gone}\n', (self.dir / 'config.yml').read_text())
        self.assertNotIn('blocklist', (self.dir / 'config.yml.sf-before').read_text(), 'what was there is kept beside it')
        self.assertEqual(self.read('nebula.started').count('\n'), 2, 'Nebula was restarted to read it')
        self.assertEqual(self.vault('nebula-revoke', 'home', 'laptop')[0], 1, 'nothing left to revoke')
        self.assertIn('laptop', self.vault('nebula-list')[1])
        self.assertIn('revoked', self.vault('nebula-list')[1])
        # the address is free again
        self.assertEqual(self.issue('tablet', '10.9.0.9/24')[0], 0)

    def test_what_is_not_storageforges_is_left_alone_and_a_bad_configuration_changes_nothing(self):
        self.assertEqual(self.issue()[0], 0)
        words = self.words()
        (self.dir / 'config.yml').write_text('pki:\n  ca: /etc/nebula/ca.crt\n')
        for state in ('present', 'absent'):
            rc, out = self.step(True, 't_nebula', *words[:5], state, *words[6:])
            self.assertEqual(rc, 1)
            self.assertIn('was not written by StorageForge: a Nebula somebody set up by hand is left alone', out)
        (self.dir / 'config.yml').unlink()
        (self.fake / 'active-nebula').touch()
        rc, out = self.step(True, 't_nebula', *words)
        self.assertIn('nebula.service runs a Nebula here that StorageForge did not start', out)
        (self.fake / 'active-nebula').unlink()
        self.assertEqual(self.step(True, 't_nebula', *words)[0], 0)
        before = (self.dir / 'config.yml').read_text()
        broken = base64.b64encode(b'# Written by StorageForge\npki: [\n').decode()
        rc, out = self.step(True, 't_nebula', *words[:7], broken)
        self.assertEqual(rc, 1)
        self.assertIn('conflict: nebula -test refuses the new configuration', out)
        self.assertEqual((self.dir / 'config.yml').read_text(), before)
        self.assertFalse((self.dir / '.sf-new-config.yml').exists())
        rc, out = self.step(True, 't_nebula', *words[:6], '', '')
        self.assertIn('there was no Nebula CA named home, or its configuration could not be made', out)
        # a certificate of another CA in the host's folder
        public, sign = _key()
        other = nebulaca.ca_certificate('other', public, sign, seconds=86400)
        (self.dir / 'host.crt').write_text(nebulaca.host_certificate(other, sign, name='nas', address='10.9.0.5/24', public=nebulaca.public_key((self.dir / 'host.pub').read_text())))
        rc, out = self.step(True, 't_nebula', *words)
        self.assertEqual(rc, 1)
        self.assertIn(f'conflict: the certificate in {self.dir}/host.crt is not a running one of CA home', out)

    def test_absent_stops_it_and_removes_the_key(self):
        self.assertEqual(self.issue()[0], 0)
        self.assertEqual(self.step(True, 't_nebula', *self.words())[0], 0)
        words = self.words(state='absent')
        self.assertEqual(words[6:], ['', ''], 'leaving needs nothing from the CA')
        rc, out = self.step(False, 't_nebula', *words)
        self.assertIn('would: stop storageforge-nebula.service and remove it', out)
        self.assertTrue((self.dir / 'host.key').exists())
        rc, out = self.step(True, 't_nebula', *words)
        self.assertEqual(rc, 0, out)
        self.assertIn('storageforge-index vault nebula-revoke home NAME', out)
        self.assertEqual(sorted(p.name for p in self.dir.iterdir()), [])
        self.assertFalse((self.d / 'units' / 'storageforge-nebula.service').exists())
        self.assertFalse((self.fake / 'active-storageforge-nebula').exists())
        self.assertEqual(self.step(True, 't_nebula', *words), (0, 'ok: no Nebula started by StorageForge is here\n'))

    def test_the_check_says_what_is_missing(self):
        def said(**params):
            return [(i['level'], i['text']) for i in changes.check(self.conn, {'name': 'n', 'tasks': [self.task(**params)]})['tasks'][0]['items']]
        got = said()
        self.assertTrue(any(lvl == 'warn' and 'no running certificate from CA home is on record for nas: storageforge-index vault nebula-issue home --host nas' in t for lvl, t in got), got)
        self.assertTrue(any('no secret travels' in t and 'nebula -test' in t for _, t in got))
        self.assertTrue(any('Not lab-tested' in t for _, t in got))
        self.assertEqual([lvl for lvl, _ in said(ca='nowhere')], ['crit'])
        self.assertTrue(any(lvl == 'crit' and 'needs at least one lighthouse' in t for lvl, t in said(lighthouses='')))
        self.assertTrue(any(lvl == 'crit' and 'an inbound rule is' in t for lvl, t in said(inbound='tcp/22; id')))
        self.assertTrue(any(lvl == 'crit' and 'a lighthouse listens on a port' in t for lvl, t in said(port='70000')))
        self.assertEqual(steps_overlay._nebula_args(self.conn, self.task(inbound='tcp/22; id')), ['', ''])
        cmd = changes.EXTRA['nebula']['ansible'](self.task(), self.conn)['ansible.builtin.shell']['cmd']
        self.assertIn('t_nebula home', cmd)
        self.assertIn('\nreload_systemd() {', cmd, 'tun_unit_start reloads through it: the task carries the guard')
        self.assertIn('timeout -k 1 5 stat', cmd)
        self.assertIn(base64.b64encode(self.ca_pem.encode()).decode(), cmd)


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

    def test_openziti_in_a_plan_and_no_step_for_netmaker(self):
        db, conn = plan_db(self)
        plan, checked = self.checked(conn, ('openziti', {'secret': 'ziti-web', 'identity': 'web-1'}), ('openziti', {'secret': 'ziti-web', 'identity': 'web-1', 'state': 'absent'}))
        self.assertEqual(self.crits(checked), [])
        said = ' '.join(i['text'] for i in checked[0]['items'])
        self.assertIn('storageforge-index vault send-secret ziti-web --host nas', said)
        self.assertIn('It works once', said)
        self.assertIn('100.64.0.0/10', said)
        text = changes.script(conn, plan)
        self.assertIn("openziti 'Enroll the OpenZiti identity web-1' ziti-web web-1 present", text)
        self.assertIn("openziti 'Remove the OpenZiti identity web-1' ziti-web web-1 absent", text)
        _, bad = self.checked(conn, ('openziti', {'secret': 'ziti-web', 'identity': 'web:1'}))
        self.assertEqual(len(self.crits(bad)), 1)
        # netclient takes its enrollment token as an argument only, so there is no step that would put one on a command line
        self.assertNotIn('netmaker', changes.TYPES)
        self.assertNotIn('netclient join', ''.join(changes.EXTRA_BASH))
        self.assertIn('NO STEP', steps_overlay.__doc__)

    def test_no_step_here_puts_a_secret_in_its_words(self):
        """The words a plan gives a step are in the script, the playbook and the logs: for these steps they are names, addresses and
        public certificates. A step whose field could hold the secret itself would show here."""
        for kind in ('netbird', 'zerotier', 'nebula', 'openziti'):
            fields = {f['name']: f for f in changes.TYPES[kind]['fields']}
            self.assertEqual(tuple(fields), changes.ARGS[kind])
            for name, f in fields.items():
                self.assertNotIn(name, ('key', 'token', 'jwt', 'password', 'setup_key'), kind)
                if 'vault secret' in f['label']:
                    self.assertEqual((f['kind'], name), ('name', 'secret'), 'a secret is named, and the name is checked as one')


if __name__ == '__main__':
    unittest.main()
