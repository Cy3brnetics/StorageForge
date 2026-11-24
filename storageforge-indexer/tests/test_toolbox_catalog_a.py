"""The Toolbox entries of 0.5.13 for panels, VPN and overlay servers, zero trust and identity (catalog/*.yaml, tbadapters_a.py), and
the engine parts they brought (toolbox.py, steps_toolbox.py): a container's command words, sidecars in a compose stack, an environment
variable that names a secret file, an override of a variable the entry sets, the rootless Podman socket of a panel's own account, the
uid an image runs as, and labels for licences and outside accounts.

Each entry passes the schema, is listed in the manifest, becomes a plan whose script is valid Bash for every method it has, and takes
its secrets from the vault as files. The adapters parse what the real tools print: the Headscale sample was printed by headscale 0.29.7
in a container with a Tailscale node joined to it (tests/fixtures/toolbox), and the probes run as Bash against stand-ins that print it."""
import json
import re
import shlex
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

try:
    from test_toolbox import CUSTOM, Base
    from test_toolbox_steps import Steps as StepsBase
except ImportError:      # run as tests.test_x from the project folder
    from tests.test_toolbox import CUSTOM, Base
    from tests.test_toolbox_steps import Steps as StepsBase
from storageforge_index import changes, inframeasure, security, steps_toolbox, tbadapters, tbadapters_a, toolbox

FIX = Path(__file__).resolve().parent / 'fixtures' / 'toolbox'
PANELS = ('dockge', 'portainer', 'komodo', 'dockhand', 'dokploy', 'incus-ui')
VPN = ('headscale', 'headscale-ui', 'zerotier', 'nebula-lighthouse', 'strongswan', 'netbird', 'netmaker', 'openvpn', 'pangolin')
ACCESS = ('cloudflared', 'ssh-ca', 'openziti', 'pomerium', 'teleport', 'boundary')
IDENTITY = ('authelia', 'authentik', 'keycloak', 'lldap', 'kanidm', 'samba-ad-dc', 'freeipa')
GROUPS = {'panel': PANELS, 'vpn': VPN, 'access': ACCESS, 'identity': IDENTITY}


def entry(tid):
    e, problems = toolbox.load_entry((toolbox.CATALOG_DIR / f'{tid}.yaml').read_text())
    assert not problems, (tid, problems)
    return e


class Entries(Base):
    def setUp(self):
        super().setUp()
        self.host('box', 'apt', ['podman'])
        self.host('fed', 'dnf', ['podman'])

    def test_each_entry_passes_and_is_in_the_manifest(self):
        man = json.loads((toolbox.CATALOG_DIR / 'catalog.json').read_text())['entries']
        for ids in GROUPS.values():
            for tid in ids:
                text = (toolbox.CATALOG_DIR / f'{tid}.yaml').read_text()
                e, problems = toolbox.load_entry(text)
                self.assertEqual(problems, [], tid)
                self.assertEqual(man.get(tid), toolbox.sha256(text), f'{tid}: python -m storageforge_index.toolbox manifest SERIAL writes the manifest again')
                for m in e['methods']:
                    for part in (m, *m.get('sidecars', [])):
                        if part.get('image'):
                            self.assertRegex(part['image'], r'@sha256:[0-9a-f]{64}$', tid)
                row = toolbox.find(self.conn, tid)
                self.assertEqual(row['trust'], 'packaged', tid)
                self.assertEqual(row['lab'], 'not lab-tested', tid)

    def test_each_method_of_each_entry_becomes_a_valid_plan(self):
        for ids in GROUPS.values():
            for tid in ids:
                e = entry(tid)
                for m in e['methods']:
                    host = 'box' if m['kind'] != 'package' or 'apt' in m['packages'] else 'fed'
                    kw = {'exposure': 'management', 'bind': '10.0.0.5'} if e['exposure']['default'] == 'management' else {}
                    pv = toolbox.preview(self.conn, host, tid, m['kind'], **kw)
                    t = next(x for x in pv['tasks'] if x['type'] == 'tool-install')
                    words = toolbox.install_words(self.conn, t)
                    self.assertEqual(words[0], 'ok', (tid, m['kind'], words[:2]))
                    for s in e['secrets']:
                        sf = next(x for x in pv['tasks'] if x['type'] == 'secret-file' and x['params']['secret'] == f'tool-{tid}-{s["name"]}')
                        self.assertEqual(sf['params']['mode'], '0600')
                    plan_id = changes.save_plan(self.conn, {'name': f'{tid} {m["kind"]}', 'tasks': pv['tasks']}, 'test')
                    text = changes.script(self.conn, changes.get_plan(self.conn, plan_id))
                    p = subprocess.run(['bash', '-n'], input=text, capture_output=True, text=True, timeout=30)
                    self.assertEqual(p.returncode, 0, (tid, m['kind'], p.stderr[-400:]))
                    for s in e['secrets']:
                        self.assertNotIn(f'tool-{tid}-{s["name"]}=', text)

    def test_panels(self):
        # a panel that manages containers holds the Podman socket of its own account, never root's, and the report says so
        for tid in ('dockge', 'portainer', 'dockhand'):
            pv = toolbox.preview(self.conn, 'box', tid)
            self.assertEqual(pv['method'], 'container', tid)
            self.assertIn('engine-socket', [r['label'] for r in pv['risks']])
            words = toolbox.install_words(self.conn, next(x for x in pv['tasks'] if x['type'] == 'tool-install'))
            self.assertIn('Volume=%t/podman/podman.sock:/var/run/docker.sock', words[2])
            self.assertNotIn('/run/docker.sock:', words[2].replace('%t/podman/podman.sock:/var/run/docker.sock', ''))
            self.assertEqual(words[7], '1')
        dockge = toolbox.install_words(self.conn, next(x for x in toolbox.preview(self.conn, 'box', 'dockge')['tasks'] if x['type'] == 'tool-install'))[2]
        self.assertIn('Volume=/srv/toolbox/dockge/stacks:/srv/toolbox/dockge/stacks:Z', dockge, 'a stack names its folders by their path on the host')
        self.assertEqual(toolbox.find(self.conn, 'portainer')['entry']['gui']['api'], 'portainer')
        self.assertEqual(toolbox.find(self.conn, 'dockhand')['labels'][0]['label'], 'source-available')
        # Komodo: Core and its MongoDB as one stack, secrets as files, the folders given to the uid MongoDB runs as
        pv = toolbox.preview(self.conn, 'box', 'komodo')
        self.assertEqual(pv['method'], 'compose')
        self.assertEqual([t['type'] for t in pv['tasks']], ['secret-file'] * 3 + ['tool-install'])
        self.assertEqual({t['params']['owner'] for t in pv['tasks'] if t['type'] == 'secret-file'}, {'999'})
        words = toolbox.install_words(self.conn, pv['tasks'][-1])
        compose = words[4]
        self.assertIn('container_name: sf-komodo-mongo', compose)
        self.assertIn('/srv/toolbox/komodo/secrets:/run/secrets/komodo:ro,z', compose, 'two services mount the secrets: shared label')
        self.assertIn('/srv/toolbox/komodo/mongo:/data/db:Z', compose)
        self.assertNotIn('27017:', compose, 'MongoDB publishes nothing')
        self.assertEqual(words[9], '999')


def reading(containers=(), access=None, health=None):
    return {'tools': ['podman'], 'listeners': [], 'podman_rootless': [{'user': 'sf-x', 'containers': list(containers)}],
            'toolbox': {'health': health or {}, 'access_a': access or {}}}


def box(name, image, state='running', tool=None, part=None):
    labels = {'storageforge.tool': tool} if tool else {}
    if part:
        labels['storageforge.part'] = part
    return {'name': name, 'image': image, 'state': state, 'labels': labels}


class Adapters(Base):
    def setUp(self):
        super().setUp()
        self.host('box', 'apt', ['podman'])

    def status(self, tid, r):
        a = tbadapters.ADAPTERS[tid]
        ctx = tbadapters.context(self.conn, 'box', r)
        found = a.detect(r, ctx)
        return found, (a.status(r, ctx, found) if found else None)

    def test_a_panel_in_its_container(self):
        r = reading([box('sf-dockge', 'docker.io/louislam/dockge:1.5.0@sha256:' + '3' * 64, tool='dockge')], health={'dockge': 200})
        found, st = self.status('dockge', r)
        self.assertTrue(found['managed'])
        self.assertEqual(st['version'], '1.5.0')
        self.assertEqual(st['health'], 'ok')
        found, st = self.status('dockge', reading([box('sf-dockge', 'docker.io/louislam/dockge:1.5.0', 'exited', tool='dockge')]))
        self.assertEqual(st['health'], 'down')
        self.assertIsNone(self.status('dockge', reading())[0])
        self.assertIsNone(tbadapters.ADAPTERS['ssh-ca'].detect(reading(), {}))


PROBE_STUBS = {
    'openvpn': '[[ $1 == --version ]] && echo "OpenVPN 2.6.12"',
    'id': 'if [[ $1 == -u && ($2 == sf-headscale || $2 == sf-zerotier) ]]; then echo 1001; exit 0; fi; exit 1',
    'runuser': 'shift 2; [[ $1 == -- ]] && shift; exec "$@"',
    'podman': r"""case "$*" in
  "exec sf-headscale headscale nodes list -o json-line") cat "$FIX/headscale-nodes.json" ;;
  "exec sf-zerotier zerotier-cli info") cat "$FIX/zerotier-info.txt" ;;
  *) exit 1 ;;
esac""",
    'swanctl': 'case $1 in --list-sas) cat "$FIX/swanctl-list-sas.txt" ;; --version) cat "$FIX/swanctl-version.txt" ;; esac',
    'systemctl': 'case $1 in cat) [[ $2 == strongswan.service ]] ;; is-active) echo active ;; is-enabled) echo enabled ;; esac',
}


class Probes(unittest.TestCase):
    """The tb_access section as Bash, with stand-ins for podman, runuser, swanctl and systemctl that print what the real tools printed."""

    def test_the_section_runs_and_reads_back(self):
        d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d, True)
        for name, body in PROBE_STUBS.items():
            (d / name).write_text('#!/bin/bash\n' + body + '\n')
            (d / name).chmod(0o755)
        script = 'sec() { printf "\\n@@%s\\n" "$1"; }\nhas() { command -v "$1" >/dev/null; }\n' + tbadapters_a.BODY
        p = subprocess.run(['bash', '-c', script], capture_output=True, text=True, timeout=30, env={'PATH': f'{d}:/usr/bin:/bin', 'FIX': str(FIX)})
        got = tbadapters.sections_of(inframeasure._sections(p.stdout))['access_a']
        self.assertEqual(got['headscale'], {'online': 1, 'nodes': 1})
        self.assertNotIn('hskey', p.stdout, 'the node list stays on the host: only its counts are printed')
        self.assertNotIn('mkey:', p.stdout)
        self.assertEqual(got['zerotier'], {'address': '8c38767c7b', 'version': '1.14.2', 'state': 'ONLINE'})
        self.assertEqual(got['units'], {'strongswan.service': {'active': 'active', 'enabled': 'enabled'}})
        self.assertEqual(got['versions'], {'strongswan': '6.0.1', 'openvpn': '2.6.12'})
        self.assertEqual(got['ike'], [{'name': 'site', 'id': 1, 'state': 'ESTABLISHED'}])
        self.assertEqual(got['child'], [{'name': 'net', 'id': 1, 'state': 'INSTALLED'}])
        self.assertNotIn('c767774a', p.stdout, 'SPIs and traffic lines are not read')

    def test_the_reading_script_carries_it_and_is_valid_bash(self):
        text = inframeasure.script(tbadapters.health_body([]))
        self.assertIn('sec tb_access', text)
        self.assertEqual(subprocess.run(['bash', '-n'], input=text, text=True, capture_output=True).returncode, 0)

    def test_what_a_host_prints_cannot_pass_for_more(self):
        got = tbadapters_a.read_access(['hs\t1; x\t2', 'zt\t200 info ../../x 1.0 ONLINE', 'u\tsshd.service\tactive\tenabled', 'v\tbash\t5.2',
                                         'ca\tSHA256:' + 'A' * 43 + '\t3', 'ca\tnot-a-fingerprint\t1', 's\t$(id): #1, ESTABLISHED'])
        self.assertEqual(got, {'units': {}, 'versions': {}, 'ike': [], 'child': [], 'sshca': {'fingerprint': 'SHA256:' + 'A' * 43, 'users': 3}})


class Vpn(Base):
    def setUp(self):
        super().setUp()
        self.host('box', 'apt', ['podman'])

    def test_headscale_runs_rootless_and_its_address_is_an_override(self):
        pv = toolbox.preview(self.conn, 'box', 'headscale')
        self.assertEqual(pv['method'], 'container')
        report = ' '.join(x['text'] for x in pv['report'])
        self.assertIn('public DERP servers of Tailscale', report, 'the outside service it uses is in the report')
        words = toolbox.install_words(self.conn, pv['tasks'][-1])
        self.assertIn('Exec=serve', words[2])
        self.assertIn('PublishPort=127.0.0.1:8080:8080/tcp', words[2])
        toolbox.set_override(self.conn, 'box', 'headscale', 'env: {HEADSCALE_SERVER_URL: "https://hs.example.org"}\nexposure: management\nbind: 10.0.0.5', 'test')
        pv = toolbox.preview(self.conn, 'box', 'headscale')
        words = toolbox.install_words(self.conn, pv['tasks'][-1])
        self.assertIn('Environment=HEADSCALE_SERVER_URL=https://hs.example.org', words[2])
        self.assertIn('PublishPort=10.0.0.5:8080:8080/tcp', words[2])

    def test_zerotier_is_never_a_default_and_its_folder_is_given_to_its_uid(self):
        row = toolbox.find(self.conn, 'zerotier')
        self.assertIn('not-a-default', [x['label'] for x in row['labels']])
        self.assertIn('1.16', row['entry']['notes'])
        self.assertEqual(row['app_version'], '1.14.2')
        words = toolbox.install_words(self.conn, toolbox.preview(self.conn, 'box', 'zerotier')['tasks'][-1])
        self.assertIn('Volume=/srv/toolbox/zerotier/data:/var/lib/zerotier-one:Z,U', words[2])
        self.assertIn('PublishPort=127.0.0.1:9993:9993/udp', words[2])

    def test_nebula_lighthouse_brings_its_nebula_step(self):
        pv = toolbox.preview(self.conn, 'box', 'nebula-lighthouse', inputs={'ca': 'lab', 'port': '4243'})
        self.assertEqual([t['type'] for t in pv['tasks']], ['tool-install', 'nebula'])
        neb = pv['tasks'][1]['params']
        self.assertEqual((neb['ca'], neb['lighthouse'], neb['port'], neb['inbound']), ('lab', 'true', '4243', 'icmp'))
        plan = changes.normalize({'name': 'n', 'tasks': pv['tasks']})
        self.assertIs(plan['tasks'][1]['params']['lighthouse'], True)
        self.assertEqual(pv['made']['packages'], {'apt': ['nebula'], 'dnf': ['nebula'], 'pacman': ['nebula']})
        self.assertEqual(pv['made']['units'], [], 'nebula.service of the package stays off: the step runs its own unit')

    def test_strongswan_from_the_distribution(self):
        pv = toolbox.preview(self.conn, 'box', 'strongswan')
        self.assertEqual(pv['made']['packages']['apt'], ['strongswan-swanctl', 'charon-systemd'])
        self.assertEqual(pv['made']['units'], ['strongswan.service'])
        self.assertIn('internet-listener', [r['label'] for r in pv['risks']])

    def test_adapters(self):
        sas = (FIX / 'swanctl-list-sas.txt').read_text().splitlines()
        access = tbadapters_a.read_access(['u\tstrongswan.service\tactive\tenabled', 'v\tstrongswan\tstrongSwan swanctl 6.0.1', 'hs\t1\t1',
                                           'zt\t' + (FIX / 'zerotier-info.txt').read_text().strip(), 'u\tstorageforge-nebula.service\tfailed\tenabled', 'v\tnebula\t1.9.6']
                                          + ['s\t' + x for x in sas if re.match(r'^(  )?[^ ]+: #', x)])
        r = reading([box('sf-headscale', 'docker.io/headscale/headscale:0.29.7@sha256:' + '1' * 64, tool='headscale'),
                     box('sf-zerotier', 'docker.io/zerotier/zerotier:1.14.2@sha256:' + '5' * 64, tool='zerotier')],
                    access=access, health={'headscale': 200})
        adapters = Adapters.status
        found, st = adapters(self, 'headscale', r)
        self.assertIn({'label': 'Nodes', 'value': '1 of 1 online', 'level': 'ok'}, st['tiles'])
        self.assertEqual(st['health'], 'ok')
        self.assertEqual(tbadapters.ADAPTERS['headscale'].metrics(r, tbadapters.context(self.conn, 'box', r))['nodes'], 1)
        found, st = adapters(self, 'zerotier', r)
        self.assertIn('node 8c38767c7b, online', [t['value'] for t in st['tiles']])
        found, st = adapters(self, 'strongswan', r)
        self.assertEqual(st['version'], '6.0.1')
        self.assertIn({'label': 'IKE SAs', 'value': '1 of 1 established', 'level': 'ok'}, st['tiles'])
        self.assertIn({'label': 'Tunnels', 'value': '1 installed', 'level': 'ok'}, st['tiles'])
        found, st = adapters(self, 'nebula-lighthouse', r)
        self.assertEqual(st['health'], 'down', 'its unit failed')
        security._save_measurement(self.conn, 'box', 'infra', int(time.time()), 'measure', r)
        got = tbadapters.refresh(self.conn, 'box', r)
        self.assertEqual({k: got[k] for k in ('headscale', 'zerotier', 'strongswan', 'nebula-lighthouse')},
                         {'headscale': 'ok', 'zerotier': 'ok', 'strongswan': 'ok', 'nebula-lighthouse': 'down'})


class Access(Base):
    def setUp(self):
        super().setUp()
        self.host('box', 'apt', ['podman'])

    def test_cloudflare_tunnel_is_the_publisher_binary_and_the_tunnel_step(self):
        pv = toolbox.preview(self.conn, 'box', 'cloudflared', inputs={'secret': 'cf-home'})
        self.assertEqual(pv['method'], 'binary', 'no package on Debian: the binary, checked by the SHA-256 Cloudflare publishes')
        self.assertEqual([t['type'] for t in pv['tasks']], ['tool-install', 'cloudflare-tunnel'])
        self.assertEqual(pv['tasks'][1]['params'], {'secret': 'cf-home', 'state': 'present'})
        report = ' '.join(x['text'] for x in pv['report'])
        self.assertIn('needs an account with an outside service, made by you there: a Cloudflare account', report)
        words = toolbox.install_words(self.conn, pv['tasks'][0])
        self.assertEqual(words[2:5], ['cloudflared', 'https://github.com/cloudflare/cloudflared/releases/download/2026.11.1/cloudflared-linux-amd64',
                                      '97bb3b02d23a5980fc9c15a1a270e692da1923f103f920d5b16d4931d5ab55e7'])
        self.host('arch', 'pacman', [])
        self.assertEqual(toolbox.preview(self.conn, 'arch', 'cloudflared')['method'], 'package')
        plan_id = changes.save_plan(self.conn, {'name': 'cf', 'tasks': pv['tasks']}, 'test')
        text = changes.script(self.conn, changes.get_plan(self.conn, plan_id))
        self.assertNotIn('--token ', text, 'the token is read from a file, never given on a command line')

    def test_ssh_ca_points_at_the_feature(self):
        pv = toolbox.preview(self.conn, 'box', 'ssh-ca', inputs={'users': 'root,backup'})
        self.assertEqual([t['type'] for t in pv['tasks']], ['tool-install', 'ssh-ca-trust'])
        self.assertEqual(pv['tasks'][1]['params'], {'users': 'root,backup', 'state': 'present'})
        self.assertEqual(pv['made']['units'], [], 'sshd is left as it is: only the trust step changes it')
        self.assertIn('Keys, SSH CA', toolbox.find(self.conn, 'ssh-ca')['entry']['notes'])

    def test_openziti_controller(self):
        words = toolbox.install_words(self.conn, toolbox.preview(self.conn, 'box', 'openziti')['tasks'][-1])
        self.assertIn('Exec=run config.yml', words[2])
        self.assertIn('Volume=/srv/toolbox/openziti/data:/ziti-controller:Z,U', words[2])
        self.assertIn('Environment=ZITI_CTRL_ADVERTISED_ADDRESS=127.0.0.1', words[2])

    def test_adapters(self):
        access = tbadapters_a.read_access(['u\tstorageforge-cloudflared.service\tactive\tenabled',
                                           'v\tcloudflared\tcloudflared version 2026.11.1 (built 2026-11-17-15:04 UTC)', 'ca\tSHA256:' + 'k' * 43 + '\t2'])
        r = reading([box('sf-openziti', 'docker.io/openziti/ziti-controller:2.0.9@sha256:' + '2' * 64, tool='openziti')], access=access, health={'openziti': 0})
        found, st = Adapters.status(self, 'cloudflared', r)
        self.assertEqual((st['health'], st['version']), ('ok', '2026.11.1'))
        found, st = Adapters.status(self, 'ssh-ca', r)
        self.assertEqual(st['tiles'][1]['value'], '2')
        found, st = Adapters.status(self, 'openziti', r)
        self.assertEqual(st['health'], 'down', 'its health check had no answer')


class Engine(Base):
    def setUp(self):
        super().setUp()
        self.host('box', 'apt', ['podman'])

    def problems(self, old, new, text=CUSTOM):
        changed = text.replace(old, new)
        self.assertNotEqual(changed, text, old)
        return ' '.join(toolbox.load_entry(changed)[1])

    def test_command_words_sidecars_and_secret_files(self):
        ports = '      ports: ["8099:80/tcp"]\n'
        self.assertEqual(self.problems(ports, ports + '      args: [serve, --port=80]\n'), '')
        self.assertIn('args are words', self.problems(ports, ports + '      args: ["a b"]\n'))
        self.assertIn('args are words', self.problems(ports, ports + '      args: ["$(id)"]\n'))
        self.assertIn('only for the rootless container method', self.problems('    - kind: container', '    - kind: quadlet\n      engine_socket: own'))
        self.assertIn('sidecars are for the compose method', self.problems(ports, ports + '      sidecars: [{name: db, image: "docker.io/library/postgres:16@sha256:' + '2' * 64 + '"}]\n'))
        compose = CUSTOM.replace('kind: container', 'kind: compose')
        side = ports + '      sidecars:\n        - {name: db, image: "docker.io/library/postgres:16@sha256:' + '2' * 64 + '"%s}\n'
        self.assertEqual(self.problems(ports, side % '', compose), '')
        self.assertIn('publishes no port', self.problems(ports, side % ', ports: ["5432:5432/tcp"]', compose))
        self.assertIn('privileged containers are refused', self.problems(ports, side % ', privileged: true', compose))
        self.assertIn('pinned by digest', self.problems(ports, side.replace('@sha256:' + '2' * 64, '') % '', compose))
        # a variable whose name looks like a secret only when its value is the file of a declared secret
        sec = 'secrets: [{name: db, kind: password}]\nrequires:'
        self.assertIn('looks like a secret', self.problems(ports, ports + '      env: {DB_PASSWORD_FILE: /run/secrets/whoami/other}\n'))
        both = CUSTOM.replace('requires:', sec)
        self.assertEqual(self.problems(ports, ports + '      env: {DB_PASSWORD_FILE: /run/secrets/whoami/db, X_KEY: "file:///run/secrets/whoami/db"}\n', both), '')
        self.assertIn('looks like a secret', self.problems(ports, ports + '      env: {DB_PASSWORD: hunter2}\n', both))

    def test_labels(self):
        self.assertIn('not a known label', self.problems('requires:', 'labels: [free-beer]\nrequires:'))
        self.assertIn('label it outside-account', self.problems('requires:', 'outside: a Cloudflare account\nrequires:'))
        e, _ = toolbox.load_entry(CUSTOM.replace('requires:', 'labels: [non-commercial]\nrequires:'))
        self.assertEqual(e['labels'], ['non-commercial', 'not-a-default'], 'a non-commercial licence is never a default')

    def test_an_override_changes_a_variable_the_entry_sets_and_no_other(self):
        text = CUSTOM.replace('      ports:', '      env: {SERVER_URL: "http://127.0.0.1:8099"}\n      ports:')
        toolbox.save_custom(self.conn, text, None, 'test')
        self.assertIn('never a secret', ' '.join(toolbox.load_override('env: {ADMIN_PASSWORD: x}')[1]))
        self.assertIn('never a secret', ' '.join(toolbox.load_override('env: {X: "%h"}')[1]))
        toolbox.set_override(self.conn, 'box', 'whoami', 'env: {SERVER_URL: "https://who.example.org", OTHER: x}', 'test')
        pv = toolbox.preview(self.conn, 'box', 'whoami')
        report = ' '.join(x['text'] for x in pv['report'])
        self.assertIn('the override sets env OTHER', report)
        self.assertIn('overridden on box: env', report)
        toolbox.stage(self.conn, 'box', 'whoami', 'test', accept_unsigned=True)
        words = toolbox.install_words(self.conn, next(x for x in pv['tasks'] if x['type'] == 'tool-install'))
        self.assertIn('Environment=SERVER_URL=https://who.example.org', words[2])
        self.assertNotIn('OTHER', words[2])

    def test_volume_owner(self):
        text = CUSTOM.replace('      ports:', '      volume_owner: "1000"\n      volumes: {data: /data}\n      ports:').replace('requires:\n', 'requires:\n  volumes: [data]\n')
        e, problems = toolbox.load_entry(text)
        self.assertEqual(problems, [])
        m = e['methods'][0]
        self.assertIn('Volume=/srv/toolbox/whoami/data:/data:Z,U', toolbox.quadlet_text(e, m, toolbox.resolve(e, m, {}, '', ''), True))
        self.assertIn('volume_owner', self.problems('      ports:', '      volume_owner: root\n      ports:'))


class Socket(StepsBase):
    # the stand-in host of test_toolbox_steps; its own tests are left to it (below)
    def test_a_panel_switches_on_the_socket_of_its_own_account(self):
        out = self.install(False, 'dockge')
        self.assertIn('would: switch on the Podman socket of sf-dockge', out)
        self.assertNotIn('enable --now podman.socket', self.log())
        out = self.install(True, 'dockge')
        self.assertIn('ok: dockge.service is running', out)
        self.assertIn('systemctl --user -M sf-dockge@ enable --now podman.socket', self.log())
        text = (self.tmp / 'home/dockge/.config/containers/systemd/dockge.container').read_text()
        self.assertIn('Volume=%t/podman/podman.sock:/var/run/docker.sock', text)
        (self.fake / 'log').unlink()
        out = self.install(True, 'dockge')
        self.assertIn('ok: the Podman socket of sf-dockge is on', out)


for _name in [n for n in vars(StepsBase) if n.startswith('test_')]:
    setattr(Socket, _name, None)

if __name__ == '__main__':
    unittest.main()
