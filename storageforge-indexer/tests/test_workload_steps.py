"""Workloads as plan steps (steps_workloads.py): compose stacks, LXC containers and Incus instances. What a compose file is read as, the
checks against the index, the scripts against stand-in lxc, incus, iptables and firewall tools, and a stack brought up by the real Docker
with the real compose plugin, in a folder of its own, and taken down again."""
import os
import shlex
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

try:
    import dbfactory
except ImportError:      # run as tests.test_x from the project folder
    from tests import dbfactory
from storageforge_index import changes, steps_infra, steps_workloads as wl

HARNESS = r'''
set -u
ok() { echo "ok: $*"; }; missing() { echo "missing: $*"; }; conflict() { echo "conflict: $*"; PROBLEMS=$((PROBLEMS + 1)); }
info() { echo "info: $*"; }; doing() { echo "doing: $*"; }; PROBLEMS=0; STAMP=20261120-120000
act() { if ((!APPLY)); then echo "would: $*"; return 1; fi; doing "$*"; }
try() { "$@" || { conflict "failed: $*"; return 1; }; }
later() { if ((APPLY)); then conflict "$*"; else missing "after the tasks before it: $*"; fi; }
not_on_pve() { return 0; }
fw_tool() { FW=$FAKE/fw; }; fw_need_nft() { :; }
fw_id() { printf '%s' "$*" | sha256sum | cut -c1-12; }
'''
# the firewall tool as the steps call it: has, ensure, fence-has, fence-set. What it was asked is in the log.
FW = r'''#!/bin/bash
echo "fw $*" >>"$LOG"
case $1 in
  has) [[ -e $FAKE/rule-$2 ]] ;;
  ensure) echo "$*" >"$FAKE/rule-$2" ;;
  fence-has) [[ -r $FAKE/fence-$2 && $(cat "$FAKE/fence-$2") == "$2 $3 $4 $5" ]] ;;
  fence-set) echo "$2 $3 $4 $5" >"$FAKE/fence-$2" ;;
esac
'''
COMPOSE = '''services:
  web:
    image: docker.io/library/nginx:1.27
    ports: ["8080:80", "127.0.0.1:9090:90", {target: 53, published: 5353, protocol: udp}]
    volumes: ["/srv/wiki/data:/data:Z", "cache:/cache"]
  db:
    image: postgres
    environment: {POSTGRES_PASSWORD: hunter2, POSTGRES_USER: wiki}
volumes:
  cache: {}
  shared: {external: true}
'''


def stub(d: Path, name: str, body: str):
    (d / name).write_text('#!/bin/bash\necho "' + name + ' $*" >>"$LOG"\n' + body + '\n')
    (d / name).chmod(0o755)


class Model(unittest.TestCase):
    def test_a_compose_file_is_read_for_what_the_checks_need(self):
        m = wl.compose_model(COMPOSE)
        self.assertIsNone(m['error'])
        web, db = m['services']['web'], m['services']['db']
        self.assertEqual([(p['bind'], p['published'], p['proto']) for p in web['ports']], [('0.0.0.0', '8080', 'tcp'), ('127.0.0.1', '9090', 'tcp'), ('0.0.0.0', '5353', 'udp')])
        self.assertEqual(web['binds'], [{'source': '/srv/wiki/data', 'target': '/data', 'options': 'Z'}])
        self.assertEqual(db['secret_env'], ['POSTGRES_PASSWORD'])
        self.assertEqual(m['volumes'], ['cache'])                       # an external volume is not made by compose
        self.assertEqual(wl.fenced_ports(web['ports']), '8080/tcp,5353/udp')   # loopback needs no rule

    def test_what_is_not_compose_says_so_and_never_raises(self):
        for text in ('', 'just text', '- a\n- list', 'services: []', ': : :', 'services:\n  web: 5'):
            m = wl.compose_model(text)
            self.assertIsInstance(m['services'], dict)
        self.assertIn('no services', wl.compose_model('version: "3"')['error'])
        self.assertIn('not YAML', wl.compose_model('a: [')['error'])

    def test_a_value_from_the_environment_is_not_a_secret_in_the_file(self):
        m = wl.compose_model('services:\n  db:\n    image: x:1\n    environment: ["DB_PASSWORD=${DB_PASSWORD}", "API_TOKEN", "PASSWORD_FILE=/run/secrets/p"]\n')
        self.assertEqual(m['services']['db']['secret_env'], [])

    def test_the_labels_file_quotes_every_value(self):
        text = wl.override('wiki', wl.compose_model(COMPOSE), {'team': 'web'})
        import yaml
        self.assertEqual(yaml.safe_load(text)['services']['db']['labels'], {'storageforge.managed': 'true', 'storageforge.stack': 'wiki', 'team': 'web'})

    def test_incus_ports_and_labels(self):
        ports, bad = wl.incus_ports('8080:80/tcp,127.0.0.1:5353:53/udp,[::1]:1:2,70000:1')
        self.assertEqual([(p['bind'], p['published'], p['target'], p['proto']) for p in ports], [('0.0.0.0', '8080', '80', 'tcp'), ('127.0.0.1', '5353', '53', 'udp')])
        self.assertEqual(bad, ['[::1]:1:2', '70000:1'])
        self.assertEqual(wl.fenced_ports(ports), '8080/tcp')
        self.assertEqual(wl.labels_of('team=web,bad label,x=')[0], {'team': 'web', 'x': ''})

    def test_the_ports_to_publish_are_read_once_for_the_what_if_the_exports_and_the_check(self):
        ports, bad = wl.parse_publish('8080:80/tcp,,127.0.0.1:5353:53/udp,[::1]:8443:443,::1:9000:90,80,127.0.0.1::81,ab:cd,0:1,70000:1,8080:80/ud,a.b:1:2,1.2.3.4:5:6:7,80:')
        self.assertEqual([(p['bind'], p['published'], p['target'], p['proto']) for p in ports],
                         [('0.0.0.0', '8080', '80', 'tcp'), ('127.0.0.1', '5353', '53', 'udp'), ('::1', '8443', '443', 'tcp'), ('::1', '9000', '90', 'tcp'),
                          ('0.0.0.0', '', '80', 'tcp'), ('127.0.0.1', '', '81', 'tcp')])
        self.assertEqual(bad, ['ab:cd', '0:1', '70000:1', '8080:80/ud', 'a.b:1:2', '1.2.3.4:5:6:7', '80:'])
        self.assertEqual(wl.parse_publish(None), ([], []))
        from storageforge_index import mapdesign, whatif, wlexport
        text = '127.0.0.1:8080:80/udp,443:443,80,ab:cd'      # what used to raise 'invalid literal for int()' in the what-if and the design exports
        self.assertEqual(whatif._publish_parts(text), [{'host_ip': '127.0.0.1', 'host_port': 8080, 'port': 80, 'proto': 'udp'}, {'host_ip': '0.0.0.0', 'host_port': 443, 'port': 443, 'proto': 'tcp'}])
        self.assertEqual(mapdesign._ports_tf(text), [('127.0.0.1', 8080, 80, 'udp'), ('0.0.0.0', 443, 443, 'tcp')])
        self.assertEqual(wlexport._publish(text), [{'ip': '127.0.0.1', 'external': 8080, 'internal': 80, 'protocol': 'udp'}, {'ip': '0.0.0.0', 'external': 443, 'internal': 443, 'protocol': 'tcp'}])


class Db(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.db = dbfactory.make(self, Path(self.tmp) / 'index.db')
        self.conn = self.db.connect()
        self.db.migrate(self.conn)
        self.addCleanup(self.conn.close)
        self.conn.execute("INSERT INTO hosts (hostname, ssh_host, ssh_user, inventory_json) VALUES ('nas', 'nas', 'scan', '{}')")
        hid = self.conn.scalar("SELECT host_id FROM hosts WHERE hostname = 'nas'")
        self.conn.execute("""INSERT INTO mounts (host_id, mount_point, source, filesystem_type, total_bytes, used_bytes, scan_state)
                             VALUES (:h, '/', '/dev/vda1', 'ext4', :t, :u, 'indexed')""", {'h': hid, 't': 100 * 2**30, 'u': 30 * 2**30})

    def items(self, kind, **p):
        plan = {'name': 'w', 'tasks': [{'type': kind, 'host': 'nas', 'params': p}]}
        return [(it['level'], it['text']) for it in changes.check(self.conn, changes.normalize(plan))['tasks'][0]['items']]


class Check(Db):
    def test_a_stack_check_says_what_matters(self):
        got = self.items('stack', runtime='docker', name='wiki', compose=COMPOSE, labels='team=web')
        crit = [t for l, t in got if l == 'crit']
        self.assertTrue(any('secret written into the compose file (POSTGRES_PASSWORD)' in t for t in crit), got)
        self.assertTrue(any(l == 'warn' and '8080/tcp, 5353/udp to every network' in t for l, t in got))
        self.assertTrue(any(l == 'note' and 'db runs postgres, with no version' in t for l, t in got))
        self.assertTrue(any('volumes compose makes' in t and 'cache' in t for _, t in got))
        self.assertIn(('note', 'labels: team=web'), got)
        fenced = self.items('stack', runtime='docker', name='wiki', compose=COMPOSE.replace('POSTGRES_PASSWORD: hunter2', 'POSTGRES_PASSWORD_FILE: /run/secrets/pw'), allow_from='192.168.1.0/24')
        self.assertFalse([t for l, t in fenced if l == 'crit'], fenced)
        self.assertTrue(any('only 192.168.1.0/24 may reach 8080/tcp, 5353/udp' in t for _, t in fenced))

    def test_a_stack_name_compose_refuses_and_a_built_image_are_refused(self):
        got = self.items('stack', runtime='docker', name='Wiki', compose='services:\n  app:\n    build: .\n', labels='storageforge.stack=x')
        crit = [t for l, t in got if l == 'crit']
        self.assertTrue(any('lower-case' in t for t in crit))
        self.assertTrue(any('built from source' in t for t in crit))
        self.assertTrue(any('set by StorageForge itself' in t for t in crit))
        self.assertIn('crit', [l for l, _ in self.items('stack', runtime='docker', name='x', compose='hello')])

    def test_lxc_and_incus_checks(self):
        got = self.items('lxc', name='b1', distro='debian', release='trixie', network='host', ports='8080')
        self.assertTrue(any(l == 'warn' and 'open to every network' in t for l, t in got))
        got = self.items('lxc', name='b1', distro='debian', release='trixie', network='bridge')
        self.assertIn('crit', [l for l, _ in got])
        got = self.items('incus', name='v1', type='vm', publish='8080:80', labels='user-data=x')
        crit = [t for l, t in got if l == 'crit']
        self.assertTrue(any('NAT mode' in t for t in crit))
        self.assertTrue(any('cloud-init' in t for t in crit))
        ok = self.items('incus', name='c1', publish='8080:80', allow_from='10.0.0.0/8', labels='team=web')
        self.assertFalse([t for l, t in ok if l == 'crit'], ok)
        self.assertTrue(any('a fence on input' in t for _, t in ok))

    def test_the_container_check_reads_the_ports_with_the_shared_parser(self):
        got = self.items('container', runtime='docker', name='web', image='nginx:1.27', publish='127.0.0.1:8080:80,8443:443,9000,ab:cd')
        warn = [t for l, t in got if l == 'warn']
        self.assertTrue(any(t.startswith('publishes 8443 to every network on nas') for t in warn), got)
        self.assertTrue(any(t.startswith('publishes container port 9000 on a host port the runtime picks to every network') for t in warn), got)
        self.assertTrue(any('(ab:cd is not), so it is not checked' in t for t in warn), got)
        self.assertFalse(any('8080' in t for t in warn), got)

    def test_managed_removal_needs_the_exact_name_and_destructive_permission(self):
        p = {'runtime': 'lxc', 'name': 'web', 'confirm': 'other'}
        with self.assertRaisesRegex(ValueError, 'type web again'):
            self.items('managed-workload-remove', **p)
        p['confirm'] = 'web'
        self.assertIn(('warn', 'destroying an LXC container deletes its root filesystem'), self.items('managed-workload-remove', **p))
        plan = {'name': 'remove', 'tasks': [{'type': 'managed-workload-remove', 'host': 'nas', 'params': p}]}
        self.assertIn('managed-workload-remove', changes.script(self.conn, plan))
        self.assertIn('storageforge_destructive | default(false) | bool', changes.ansible(self.conn, plan))

    def test_the_whole_script_is_valid_bash_and_ansible_renders(self):
        plan = {'name': 'w', 'tasks': [
            {'type': 'stack', 'host': 'nas', 'params': {'runtime': 'docker', 'name': 'wiki', 'compose': COMPOSE, 'allow_from': '10.0.0.0/8'}},
            {'type': 'lxc', 'host': 'nas', 'params': {'name': 'b1', 'distro': 'debian', 'release': 'trixie'}},
            {'type': 'incus', 'host': 'nas', 'params': {'name': 'c1', 'publish': '8080:80'}}]}
        text = changes.script(self.conn, plan)
        self.assertEqual(subprocess.run(['bash', '-n'], input=text, text=True).returncode, 0)
        self.assertEqual([l for l in wl.BASH.splitlines() if l.count("'") % 2], [])
        self.assertIn(' 8080/tcp,5353/udp forward', text)
        y = changes.ansible(self.conn, plan)
        for fn in ('t_stack', 't_lxc', 't_incus'):
            self.assertIn(fn, y)


class Scripts(unittest.TestCase):
    """The step functions against stand-ins."""
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.d)
        self.bin, self.fake, self.root = self.d / 'bin', self.d / 'fake', self.d / 'root'
        for p in (self.bin, self.fake, self.root / 'etc/lxc', self.root / 'sys/class/net/br0/bridge', self.d / 'lxc'):
            p.mkdir(parents=True)
        (self.fake / 'fw').write_text(FW)
        (self.fake / 'fw').chmod(0o755)

    def run_fn(self, fn, apply, *words, env=None):
        call = f'{fn} ' + ' '.join(shlex.quote(w) for w in words)
        script = HARNESS + f'APPLY={int(apply)}\n' + wl.BASH + f'\n{call}\nexit $((PROBLEMS > 0))\n'
        return subprocess.run(['bash', '-c', script], capture_output=True, text=True, timeout=60,
                              env={**os.environ, 'PATH': f'{self.bin}:{os.environ["PATH"]}', 'LOG': str(self.d / 'log'), 'FAKE': str(self.fake),
                                   'WL_ROOT': str(self.root), **(env or {})})

    def log(self):
        p = self.d / 'log'
        return p.read_text() if p.exists() else ''

    def lxc_stubs(self):
        stub(self.bin, 'lxc-config', f'echo {self.d}/lxc')
        stub(self.bin, 'lxc-info', '[[ -d $FAKE/c-$2 ]] || exit 1; [[ $3 == -sH ]] && cat "$FAKE/c-$2/state"; exit 0')
        stub(self.bin, 'lxc-create', f'''n=$2; mkdir -p "$FAKE/c-$n" "{self.d}/lxc/$n"; echo STOPPED >"$FAKE/c-$n/state"; cp "$4" "$FAKE/conf-$n"''')
        stub(self.bin, 'lxc-start', 'echo RUNNING >"$FAKE/c-$2/state"')

    def test_lxc_report_changes_nothing_and_apply_makes_it_unprivileged(self):
        self.lxc_stubs()
        (self.root / 'etc/subuid').write_text('alice:100000:65536\n')
        (self.root / 'etc/subgid').write_text('')
        (self.root / 'etc/lxc/default.conf').write_text('lxc.net.0.type = veth\n')
        words = ('b1', 'debian', 'trixie', 'amd64', '', '', '1', 'team=ci', '', '')
        out = self.run_fn('t_lxc', False, *words)
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertIn('would: create LXC container b1', out.stdout)
        self.assertIn('root has no subordinate ids', out.stdout)
        self.assertNotIn('lxc-create', self.log())
        self.assertEqual((self.root / 'etc/subuid').read_text(), 'alice:100000:65536\n')
        out = self.run_fn('t_lxc', True, *words)
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        conf = (self.fake / 'conf-b1').read_text()
        for want in ('lxc.include = /etc/lxc/default.conf', 'lxc.idmap = u 0 1000000 65536', 'lxc.idmap = g 0 1000000 65536', 'lxc.start.auto = 1'):
            self.assertIn(want, conf)
        self.assertIn('lxc-create -n b1 -f', self.log())
        self.assertIn('-t download -- --dist debian --release trixie --arch amd64', self.log())
        self.assertEqual((self.d / 'lxc/b1/storageforge.labels').read_text(), 'storageforge.managed=true\nteam=ci\n')
        self.assertIn('root:1000000:65536', (self.root / 'etc/subuid').read_text())
        again = self.run_fn('t_lxc', True, *words)
        self.assertIn('b1 exists, made by StorageForge, and runs', again.stdout)
        self.assertEqual(self.log().count('lxc-create'), 1)

    def test_lxc_someone_else_made_is_left_alone_and_the_host_network_is_fenced(self):
        self.lxc_stubs()
        (self.fake / 'c-old').mkdir()
        (self.fake / 'c-old/state').write_text('RUNNING\n')
        out = self.run_fn('t_lxc', True, 'old', 'debian', 'trixie', 'amd64', '', '', '', '', '', '')
        self.assertIn('StorageForge did not make it', out.stdout)
        (self.root / 'etc/subuid').write_text('root:200000:65536\n')
        (self.root / 'etc/subgid').write_text('root:200000:65536\n')
        out = self.run_fn('t_lxc', True, 'web', 'debian', 'trixie', 'amd64', 'host', '', '', '', '8080,8443', '10.0.0.0/8')
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertIn('lxc.net.0.type = none', (self.fake / 'conf-web').read_text())
        self.assertIn('lxc.idmap = u 0 200000 65536', (self.fake / 'conf-web').read_text())
        self.assertEqual((self.fake / 'fence-wl-web').read_text(), 'wl-web 8080,8443 10.0.0.0/8 -\n')
        out = self.run_fn('t_lxc', True, 'nat', 'debian', 'trixie', 'amd64', '', '', '', '', '8080', '10.0.0.0/8')
        self.assertIn('behind NAT on lxcbr0', out.stdout)
        out = self.run_fn('t_lxc', True, 'br', 'debian', 'trixie', 'amd64', 'bridge', 'nobr', '', '', '', '')
        self.assertIn('there is no bridge nobr here', out.stdout)

    def test_remove_stack_checks_all_members_before_removing_any(self):
        stub(self.bin, 'docker', """
case "$1" in
  ps) cat "$FAKE/members" ;;
  inspect) cat "$FAKE/labels-${!#}" ;;
  rm) : >"$FAKE/members" ;;
esac""")
        members = self.fake / 'members'
        members.write_text('web1\nweb2\n')
        (self.fake / 'labels-web1').write_text('true:wiki')
        (self.fake / 'labels-web2').write_text('false:')
        args = ('docker', 'wiki')
        self.assertIn('did not deploy', self.run_fn('t_managed_workload_remove', True, *args).stdout)
        self.assertNotIn('docker rm', self.log())
        (self.fake / 'labels-web2').write_text('true:wiki')
        self.assertIn('would: remove 2 containers', self.run_fn('t_managed_workload_remove', False, *args).stdout)
        self.assertNotIn('docker rm', self.log())
        self.assertIn('removed stack wiki', self.run_fn('t_managed_workload_remove', True, *args).stdout)
        self.assertIn('docker rm -f web1 web2', self.log())
        self.assertIn('no containers', self.run_fn('t_managed_workload_remove', True, *args).stdout)

    def test_remove_lxc_requires_creation_marker(self):
        self.lxc_stubs()
        directory = self.d / 'lxc/web'
        directory.mkdir()
        stub(self.bin, 'lxc-destroy', 'exit 0')
        args = ('lxc', 'web')
        self.assertIn('did not make', self.run_fn('t_managed_workload_remove', True, *args).stdout)
        self.assertNotIn('lxc-destroy', self.log())
        (directory / 'storageforge.made').touch()
        self.assertIn('would: destroy', self.run_fn('t_managed_workload_remove', False, *args).stdout)
        self.assertNotIn('lxc-destroy', self.log())
        self.assertIn('destroyed LXC container web', self.run_fn('t_managed_workload_remove', True, *args).stdout)
        self.assertIn(f'lxc-destroy -P {directory.parent} -n web -f', self.log())

    def incus_stubs(self):
        stub(self.bin, 'incus', r'''
case "$1 $2" in
  "info ") exit 0 ;;
  "config show") [[ -e $FAKE/i-$3 ]] ;;
  "config get") cat "$FAKE/i-$3.$4" 2>/dev/null || true ;;
  "config set") k=${4%%=*}; echo "${4#*=}" >"$FAKE/i-$3.$k" ;;
  "config device") case $3 in get) [[ -e $FAKE/dev-$4-$5 ]] ;; add) touch "$FAKE/dev-$4-$5" ;; esac ;;
  "profile show") [[ $3 == default ]] ;;
  "profile device") echo "root"; echo "eth0" ;;
  "storage show") [[ $3 == fast ]] ;;
  "network show") [[ $3 == incusbr0 ]] ;;
  "image info") echo "Fingerprint: 0123abcd" ;;
  "init "*) touch "$FAKE/i-$3"; echo true >"$FAKE/i-$3.user.storageforge.managed" ;;
  "list "*) echo RUNNING ;;
esac''')

    def test_incus_report_then_apply_with_ports_labels_and_a_fence(self):
        self.incus_stubs()
        words = ('c1', 'images:debian/13', 'container', 'default', '2', '1024', 'fast', 'incusbr0', '8080:80/tcp,127.0.0.1:5353:53/udp', '', '1', 'team=web', '10.0.0.0/8', '8080/tcp')
        out = self.run_fn('t_incus', False, *words)
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertIn('image images:debian/13, fingerprint 0123abcd', out.stdout)
        self.assertIn('profile default brings: root eth0', out.stdout)
        self.assertIn('would: create Incus container c1', out.stdout)
        self.assertNotIn('incus init', self.log())
        out = self.run_fn('t_incus', True, *words)
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        init = next(l for l in self.log().splitlines() if l.startswith('incus init'))
        for want in ('-p default', '-s fast', '-n incusbr0', 'limits.cpu=2', 'limits.memory=1024MiB', 'boot.autostart=true', 'user.storageforge.managed=true', 'user.team=web'):
            self.assertIn(want, init)
        self.assertNotIn('--vm', init)
        self.assertIn('incus config device add c1 sf-port-tcp-8080 proxy listen=tcp:0.0.0.0:8080 connect=tcp:127.0.0.1:80', self.log())
        self.assertIn('listen=udp:127.0.0.1:5353 connect=udp:127.0.0.1:53', self.log())
        self.assertEqual((self.fake / 'fence-wl-c1').read_text(), 'wl-c1 8080 10.0.0.0/8 -\n')
        again = self.run_fn('t_incus', True, *words[:11], 'team=ops', *words[12:])
        self.assertIn('c1 exists, made by StorageForge, and runs', again.stdout)
        self.assertIn('only 10.0.0.0/8 reach ports 8080', again.stdout)
        self.assertIn('label team=ops on c1', again.stdout)
        self.assertEqual(self.log().count('incus init'), 1)

    def test_incus_refuses_what_it_did_not_make_and_a_missing_profile(self):
        self.incus_stubs()
        (self.fake / 'i-old').touch()
        out = self.run_fn('t_incus', True, 'old', '', '', '', '', '', '', '', '', '', '', '', '', '')
        self.assertIn('StorageForge did not make it', out.stdout)
        out = self.run_fn('t_incus', True, 'new', '', '', 'default,gpu', '', '', '', '', '', '', '', '', '', '')
        self.assertIn('there is no Incus profile gpu here', out.stdout)

    def test_published_ports_are_fenced_in_docker_user_or_refused_without_it(self):
        stub(self.bin, 'iptables', '[[ -e $FAKE/docker-user ]]')
        script = 'wl_fw stack wiki forward 8080/tcp,5353/udp 10.0.0.0/8,192.168.1.5'
        out = self.run_fn('eval', True, script)
        self.assertIn('no DOCKER-USER chain here', out.stdout)
        (self.fake / 'docker-user').touch()
        out = self.run_fn('eval', False, script)
        self.assertIn('would: let only 10.0.0.0/8,192.168.1.5 reach ports 8080/tcp,5353/udp of wiki, in DOCKER-USER', out.stdout)
        self.assertNotIn('ensure', self.log())
        out = self.run_fn('eval', True, script)
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        ensures = [l.split()[2:] for l in self.log().splitlines() if l.startswith('fw ensure')]
        self.assertEqual([e[1:] for e in ensures], [['deny', 'tcp', '8080', '-', '-', 'forward'], ['allow', 'tcp', '8080', '10.0.0.0/8', '-', 'forward'],
                                                     ['allow', 'tcp', '8080', '192.168.1.5', '-', 'forward'], ['deny', 'udp', '5353', '-', '-', 'forward'],
                                                     ['allow', 'udp', '5353', '10.0.0.0/8', '-', 'forward'], ['allow', 'udp', '5353', '192.168.1.5', '-', 'forward']])
        # the ids are the ones a fw-rule step with the same fields gets, so the two never write the same rule twice
        rid = steps_infra._rule_id({'action': 'deny', 'proto': 'tcp', 'port': '8080', 'source': '', 'iface': '', 'hook': 'forward'})
        self.assertEqual(ensures[0][0], rid)
        again = self.run_fn('eval', True, script)
        self.assertIn('only 10.0.0.0/8,192.168.1.5 reach the ports wiki publishes', again.stdout)


def docker_ok() -> bool:
    return bool(shutil.which('docker')) and subprocess.run(['docker', 'compose', 'version'], capture_output=True).returncode == 0 \
        and subprocess.run(['docker', 'image', 'inspect', 'busybox:latest'], capture_output=True).returncode == 0


@unittest.skipUnless(docker_ok(), 'needs a Docker engine with the compose plugin and the busybox image')
class RealDockerStack(unittest.TestCase):
    """t_stack with the real Docker and compose: a report that changes nothing, an apply, a second run that finds it up, a changed file
    shown as a diff, and a stack of the same name from another folder refused. Everything it starts is taken down."""
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.d, True)
        self.name = f'sfwltest{os.getpid()}{int(time.time()) % 100000}'
        self.dir = self.d / 'stack'
        self.addCleanup(subprocess.run, ['docker', 'compose', '-p', self.name, 'down', '--remove-orphans', '-t', '1'], capture_output=True, cwd=self.d)

    def run_stack(self, apply, compose, dir_=None):
        m = wl.compose_model(compose)
        words = ['docker', self.name, compose, str(dir_ or self.dir), 'team=test', '', wl.override(self.name, m, {'team': 'test'}), '', 'forward']
        script = HARNESS + f'APPLY={int(apply)}\nFAKE={self.d}\n' + wl.BASH + '\nt_stack ' + ' '.join(shlex.quote(w) for w in words) + '\nexit $((PROBLEMS > 0))\n'
        return subprocess.run(['bash', '-c', script], capture_output=True, text=True, timeout=180, env={**os.environ, 'LOG': str(self.d / 'log')})

    def test_report_apply_and_a_second_run(self):
        compose = 'services:\n  app:\n    image: busybox:latest\n    command: ["sleep", "300"]\n    stop_grace_period: 1s\n'
        out = self.run_stack(False, compose)
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertIn(f'would: deploy stack {self.name}', out.stdout)
        self.assertFalse(self.dir.exists())
        out = self.run_stack(True, compose)
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertIn(f'ok: stack {self.name} is up', out.stdout)
        labels = subprocess.run(['docker', 'ps', '--filter', f'label=com.docker.compose.project={self.name}', '--format', '{{.Labels}}'], capture_output=True, text=True).stdout
        self.assertIn('storageforge.managed=true', labels)
        self.assertIn('team=test', labels)
        self.assertTrue((self.dir / 'storageforge.yaml').exists())
        again = self.run_stack(True, compose)
        self.assertIn('is up, from this compose file', again.stdout)
        changed = self.run_stack(False, compose.replace('300', '301'))
        self.assertIn('info:   -    command: ["sleep", "300"]', changed.stdout)
        self.assertIn('info:   +    command: ["sleep", "301"]', changed.stdout)
        other = self.run_stack(True, compose, self.d / 'elsewhere')
        self.assertIn(f'a stack named {self.name} runs from {self.dir}', other.stdout)
        bad = self.run_stack(False, 'services:\n  app:\n    image: busybox:latest\n    ports: ["notaport"]\n')
        self.assertIn('compose refuses this file', bad.stdout)
        remove = HARNESS + 'APPLY=1\n' + wl.BASH + f'\nt_managed_workload_remove docker {self.name}\nexit "$PROBLEMS"'
        removed = subprocess.run(['bash', '-c', remove], capture_output=True, text=True, timeout=60)
        self.assertEqual(removed.returncode, 0, removed.stderr + removed.stdout)
        self.assertIn(f'removed stack {self.name}', removed.stdout)
        self.assertTrue((self.dir / 'compose.yaml').exists())
        again = subprocess.run(['bash', '-c', remove], capture_output=True, text=True, timeout=60)
        self.assertIn(f'no containers in stack {self.name}', again.stdout)


if __name__ == '__main__':
    unittest.main()
