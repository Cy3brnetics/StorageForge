"""VMs from cloud images: the catalog, VM specs, the vm-create step's checks and its script against stand-in libvirt tools."""
import hashlib
import json
import os
import re
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
from storageforge_index import changes, steps_vm

KEY = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl ops@laptop'
CANARY = '$(touch${IFS}/tmp/CANARY)`id`"q;x'
HARNESS = r'''
set -u
ok() { echo "ok: $*"; }; missing() { echo "missing: $*"; }; conflict() { echo "conflict: $*"; PROBLEMS=$((PROBLEMS + 1)); }
info() { echo "info: $*"; }; doing() { echo "doing: $*"; }; PROBLEMS=0; STAMP=20261107-120000
act() { if ((!APPLY)); then missing "would: $*"; return 1; fi; doing "$*"; }
try() { "$@" || { conflict "failed: $*"; return 1; }; }
later() { if ((APPLY)); then conflict "$*"; else missing "after the tasks before it: $*"; fi; }
'''


def task(**p):
    return {'type': 'vm-create', 'host': 'kvm', 'params': {'name': 'web-copy', 'image': 'debian13', 'ssh_key': KEY, **p}}


def plan(*tasks):
    return {'name': 'vm test', 'tasks': list(tasks)}


class Catalog(unittest.TestCase):
    def test_every_image_is_https_with_a_checksum(self):
        for k, (label, url, sums, osinfo, distro, _) in steps_vm.IMAGES.items():
            self.assertTrue(url.startswith('https://') and sums.startswith('https://'), k)
            self.assertTrue(changes.CHECKS['url'].fullmatch(url), k)
            self.assertIn(f'    {k}) printf', steps_vm.bash())

    def test_every_new_step_function_parses(self):
        from storageforge_index import steps_clone
        for text in (steps_vm.bash(), steps_clone.BASH):
            self.assertEqual(subprocess.run(['bash', '-n'], input=text, text=True, capture_output=True).stderr, '')

    def test_a_source_host_finds_its_image(self):
        self.assertEqual(steps_vm.image_for('ubuntu', '24.04'), 'ubuntu2404')
        self.assertEqual(steps_vm.image_for('debian', '13'), 'debian13')
        self.assertEqual(steps_vm.image_for('rocky', '9.6'), 'rocky9')
        self.assertEqual(steps_vm.image_for('cachyos', None), 'arch')
        self.assertIsNone(steps_vm.image_for('gentoo', '2.17'))


class Fields(unittest.TestCase):
    def test_values_that_could_break_out_are_refused(self):
        for bad in ({'name': 'a;b'}, {'name': CANARY}, {'ssh_key': KEY + '"'}, {'ssh_key': 'ssh-ed25519 AAAA\nrm'},
                    {'image': 'custom', 'image_url': 'https://x.example/a.img?token=1'}, {'image_url': 'http://x.example/a.img'},
                    {'data_disks': '10,abc'}, {'user': 'root;id'}, {'image_sha': 'abc'}, {'image': 'windows'}):
            with self.assertRaises(ValueError, msg=bad):
                changes.normalize(plan(task(**bad)))

    def test_a_good_step_normalizes(self):
        got = changes.normalize(plan(task(data_disks='50,50', firmware='uefi', autostart=True)))['tasks'][0]['params']
        self.assertEqual((got['data_disks'], got['firmware'], got['autostart'], got['vcpus']), ('50,50', 'uefi', True, ''))


class Db(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.db = dbfactory.make(self, Path(self.tmp) / 'index.db')
        self.conn = self.db.connect()
        self.db.migrate(self.conn)
        self.addCleanup(self.conn.close)
        self.conn.execute("INSERT INTO hosts (hostname, ssh_host, ssh_user, inventory_json) VALUES ('kvm', 'kvm', 'scan', '{}')")
        hid = self.conn.scalar("SELECT host_id FROM hosts WHERE hostname = 'kvm'")
        self.conn.execute("""INSERT INTO mounts (host_id, mount_point, source, filesystem_type, total_bytes, used_bytes, scan_state)
                             VALUES (:h, '/', '/dev/vda1', 'ext4', :t, :u, 'indexed')""", {'h': hid, 't': 100 * 2**30, 'u': 30 * 2**30})

    def reading(self, **extra):
        from storageforge_index import security
        data = {'tools': ['virsh'], 'libvirt': [{'name': 'taken', 'state': 'running'}],
                'libvirt_pools': [{'name': 'default', 'type': 'dir', 'path': '/var/lib/libvirt/images'}],
                'libvirt_networks': [{'name': 'default', 'mode': 'nat'}, {'name': 'lab', 'mode': 'isolated'}], **extra}
        security._save_measurement(self.conn, 'kvm', 'infra', int(time.time()), 'test', data)

    def items(self, *tasks):
        return [(it['level'], it['text']) for it in changes.check(self.conn, changes.normalize(changes.prepare(self.conn, plan(*tasks))))['tasks'][0]['items']]


class Specs(Db):
    def test_built_in_and_your_own(self):
        names = [s['name'] for s in steps_vm.specs(self.conn)]
        self.assertEqual(names[:4], ['small', 'server', 'desktop', 'test-copy'])
        steps_vm.save_spec(self.conn, 'db', {'vcpus': '8', 'ram_mb': '32768', 'data_disks': '200', 'image': 'rocky9', 'note': 'Postgres'}, 'alice')
        self.assertEqual(steps_vm.spec(self.conn, 'DB')['ram_mb'], '32768')
        with self.assertRaises(ValueError):
            steps_vm.save_spec(self.conn, 'server', {'vcpus': '1'}, 'alice')
        with self.assertRaises(ValueError):
            steps_vm.save_spec(self.conn, 'bad', {'vcpus': '1;id'}, 'alice')
        with self.assertRaises(ValueError):
            steps_vm.delete_spec(self.conn, 'desktop', 'alice')
        steps_vm.delete_spec(self.conn, 'db', 'alice')
        self.assertIsNone(steps_vm.spec(self.conn, 'db'))
        with self.assertRaises(LookupError):
            steps_vm.delete_spec(self.conn, 'db', 'alice')

    def test_a_spec_fills_only_empty_fields_and_is_saved_into_the_plan(self):
        steps_vm.save_spec(self.conn, 'db', {'vcpus': '8', 'ram_mb': '32768', 'data_disks': '200', 'autostart': True}, 'alice')
        pid = changes.save_plan(self.conn, plan(task(spec='db', vcpus='4')), 'alice')
        p = changes.get_plan(self.conn, pid)['tasks'][0]['params']
        self.assertEqual((p['vcpus'], p['ram_mb'], p['data_disks'], p['autostart']), ('4', '32768', '200', True))
        steps_vm.save_spec(self.conn, 'db', {'vcpus': '1'}, 'alice')            # a later change to the spec changes no saved plan
        self.assertEqual(changes.get_plan(self.conn, pid)['tasks'][0]['params']['ram_mb'], '32768')
        with self.assertRaises(ValueError):
            changes.save_plan(self.conn, plan(task(spec='nope')), 'alice')


class Check(Db):
    def test_no_reading_means_nothing_is_known(self):
        self.assertEqual(self.items(task())[0][0], 'crit')

    def test_what_the_reading_shows(self):
        self.reading()
        got = dict((t, l) for l, t in self.items(task(name='taken', pool='nope', network='nowhere')))
        self.assertIn('crit', [got[t] for t in got if 'already on kvm' in t])
        self.assertTrue(any('no libvirt pool nope' in t for t in got))
        self.assertTrue(any('no libvirt network nowhere' in t for t in got))
        ok = self.items(task(data_disks='20'))
        self.assertNotIn('crit', [l for l, _ in ok])
        self.assertIn(('ok', 'its disks can grow to 40 GiB, and /var/lib/libvirt/images has 70 GiB free'), ok)
        self.assertTrue(any('not in the vault' in t for _, t in ok))

    def test_a_custom_image_needs_its_checksum_and_a_vault_key_is_named(self):
        self.reading()
        self.conn.execute("INSERT INTO ssh_keys (key_uuid, name, key_type, public_key, fingerprint, comment, dek_nonce, wrapped_dek, key_nonce, ciphertext, created_at, origin) "
                          "VALUES ('u1', 'fleet', 'ssh-ed25519', :k, 'SHA256:x', '', :b, :b, :b, :b, 1, 'generated')", {'k': KEY, 'b': b'x'})
        got = self.items(task(image='custom', image_url='https://x.example/a.qcow2'))
        self.assertIn('crit', [l for l, t in got if 'custom image' in t])
        self.assertTrue(any(l == 'ok' and 'vault key fleet' in t for l, t in got))

    def test_without_virsh(self):
        self.reading(tools=[])
        self.assertIn('no virsh', self.items(task())[0][1])

    def test_the_whole_script_is_valid_bash_and_ansible_renders(self):
        self.reading()
        text = changes.script(self.conn, plan(task(data_disks='10')))
        path = Path(self.tmp) / 'c.sh'
        path.write_text(text)
        self.assertEqual(subprocess.run(['bash', '-n', str(path)]).returncode, 0)
        self.assertIn('t_vm_create', text)
        self.assertIn('t_vm_create', changes.ansible(self.conn, plan(task())))


def stub(d: Path, name: str, body: str):
    p = d / name
    p.write_text('#!/bin/bash\n' + body + '\n')
    p.chmod(0o755)


class Script(unittest.TestCase):
    """t_vm_create against stand-in virsh, virt-install, qemu-img, curl and xorriso: what it runs, and what it refuses."""
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.d)
        self.pool = self.d / 'pool'
        self.pool.mkdir()
        self.bin = self.d / 'bin'
        self.bin.mkdir()
        self.image = b'not really a disk image'
        self.sum = hashlib.sha512(self.image).hexdigest()
        (self.d / 'image').write_bytes(self.image)
        stub(self.bin, 'virsh', f'''echo "virsh $*" >>"$LOG"
case "$*" in
  *pool-dumpxml*) echo "<pool><target><path>{self.pool}</path></target></pool>" ;;
  *net-info*) [[ "$*" == *default* ]] ;;
  *dominfo*) [[ -e "$FAKE/domain-$4" ]] ;;
  *metadata*--set*) : ;;
  *metadata*) [[ -e "$FAKE/ours" ]] && echo '<sf image="debian13"/>' ;;
  *domiflist*) printf 'Interface Type Source Model MAC\\n---\\nvnet0 network default virtio 52:54:00:aa:bb:cc\\n' ;;
  *domifaddr*) printf 'Name MAC proto Address\\n---\\nvnet0 52:54:00:aa:bb:cc ipv4 192.168.122.50/24\\n' ;;
esac''')
        stub(self.bin, 'virt-install', 'echo "virt-install $*" >>"$LOG"')
        stub(self.bin, 'qemu-img', 'echo "qemu-img $*" >>"$LOG"; case $1 in info) echo "file format: qcow2" ;; convert) touch "${@: -1}" ;; create) touch "${@: -2:1}" ;; esac')
        stub(self.bin, 'curl', f'''echo "curl $*" >>"$LOG"
case "$*" in *SHA512SUMS*) echo "$SUM  debian-13-genericcloud-amd64.qcow2" ;; *) out=; while (($#)); do [[ $1 == -o ]] && out=$2; shift; done; cp "{self.d}/image" "$out" ;; esac''')
        stub(self.bin, 'xorriso', 'echo "xorriso $*" >>"$LOG"; out=; for a; do [[ $prev == -o ]] && out=$a; prev=$a; done; cp "${@: -2:1}" "$FAKE/user-data"; touch "$out"')
        (self.d / 'fake').mkdir()

    def run_fn(self, apply, **p):
        params = changes.normalize(plan(task(**p)))['tasks'][0]['params']
        call = ' '.join(__import__('shlex').quote(str(params[a]) if not isinstance(params[a], bool) else ('1' if params[a] else '')) for a in steps_vm.ARGS)
        script = HARNESS + f'APPLY={int(apply)}\n' + steps_vm.bash() + f'\nt_vm_create {call}\nexit $((PROBLEMS > 0))\n'
        return subprocess.run(['bash', '-c', script], capture_output=True, text=True, timeout=120,
                              env={**os.environ, 'PATH': f'{self.bin}:{os.environ["PATH"]}', 'LOG': str(self.d / 'log'), 'FAKE': str(self.d / 'fake'), 'SUM': self.sum})

    def log(self):
        p = self.d / 'log'
        return p.read_text() if p.exists() else ''

    def test_the_report_changes_nothing(self):
        out = self.run_fn(False, data_disks='10,20')
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertIn('would: create VM web-copy in default', out.stdout)
        self.assertIn('a 20 GiB root disk and data disks of 10,20 GiB', out.stdout)
        self.assertNotIn('virt-install', self.log())
        self.assertNotIn('curl', self.log())
        self.assertEqual(list(self.pool.iterdir()), [])

    def test_apply_checks_the_image_then_builds_the_vm(self):
        out = self.run_fn(True, data_disks='10', firmware='uefi', console='spice', autostart=True)
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertIn('downloaded and checked debian-13-genericcloud-amd64.qcow2', out.stdout)
        self.assertTrue((self.pool / 'web-copy-root.qcow2').exists() and (self.pool / 'web-copy-data1.qcow2').exists())
        log = self.log()
        self.assertIn('qemu-img resize -q', log)
        install = next(l for l in log.splitlines() if l.startswith('virt-install'))
        for want in ('--import --name web-copy', '--osinfo debian13', '--boot uefi', '--graphics spice,listen=127.0.0.1', 'serial=sf-data1', 'device=cdrom', '--cpu host-model'):
            self.assertIn(want, install)
        self.assertIn('autostart web-copy', log)
        ud = (self.d / 'fake' / 'user-data').read_text()
        self.assertTrue(ud.startswith('#cloud-config\n'))
        cfg = json.loads(ud.split('\n', 1)[1])
        self.assertEqual(cfg['users'][0], {'name': 'admin', 'lock_passwd': True, 'ssh_authorized_keys': [KEY], 'sudo': 'ALL=(ALL) NOPASSWD:ALL'})
        self.assertEqual((cfg['hostname'], cfg['ssh_pwauth']), ('web-copy', False))
        self.assertIn('web-copy has 192.168.122.50', out.stdout)
        # run again: the image is not fetched twice, and the VM it made is recognised
        (self.d / 'fake' / 'domain-web-copy').touch()
        (self.d / 'fake' / 'ours').touch()
        again = self.run_fn(True)
        self.assertIn('web-copy exists, made by StorageForge', again.stdout)

    def test_no_sudo_leaves_it_out(self):
        self.run_fn(True, sudo='none')
        self.assertNotIn('sudo', json.loads((self.d / 'fake' / 'user-data').read_text().split('\n', 1)[1])['users'][0])

    def test_a_disk_already_there_is_never_written_over(self):
        (self.pool / 'web-copy-root.qcow2').write_text('precious')
        out = self.run_fn(True)
        self.assertEqual(out.returncode, 1)
        self.assertIn('never writes over a disk', out.stdout)
        self.assertEqual((self.pool / 'web-copy-root.qcow2').read_text(), 'precious')
        self.assertNotIn('virt-install', self.log())

    def test_a_vm_someone_else_made_is_left_alone(self):
        (self.d / 'fake' / 'domain-web-copy').touch()
        out = self.run_fn(True)
        self.assertIn('StorageForge did not make it', out.stdout)
        self.assertNotIn('virt-install', self.log())

    def test_a_bad_checksum_stops_it(self):
        self.sum = '0' * 128
        out = self.run_fn(True)
        self.assertEqual(out.returncode, 1)
        self.assertIn('does not match its checksum', out.stdout)
        self.assertFalse(any(self.pool.glob('*.qcow2')))
        self.assertFalse((self.pool / '.storageforge-images' / 'debian-13-genericcloud-amd64.qcow2').exists())

    def test_a_missing_network_is_a_conflict(self):
        out = self.run_fn(True, network='nowhere')
        self.assertIn('no libvirt network nowhere', out.stdout)

    def test_the_isolated_network_is_made_first(self):
        out = self.run_fn(True, network='sf-isolated')
        self.assertEqual(out.returncode, 0, out.stdout)
        self.assertIn('virsh -c qemu:///system net-define', self.log())
        self.assertIn('made the isolated network sf-isolated', out.stdout)


class Clone(Db):
    """vm clone: a VM plan from the source's distro, and a packages plan for once the VM is scanned."""
    def setUp(self):
        super().setUp()
        from storageforge_index import pkglist
        self.reading()
        inv = {'pkglist': pkglist.parse('distro\tubuntu\t24.04\tdebian\npm apt-get\nm\tvim\nm\tnginx\nm\tsteam\ncomplete')}
        self.conn.execute("INSERT INTO hosts (hostname, ssh_host, ssh_user, inventory_json) VALUES ('web-01', 'web-01', 'scan', :i)", {'i': json.dumps(inv)})
        self.conn.execute("INSERT INTO ssh_keys (key_uuid, name, key_type, public_key, fingerprint, comment, dek_nonce, wrapped_dek, key_nonce, ciphertext, created_at, origin) "
                          "VALUES ('u1', 'fleet', 'ssh-ed25519', :k, 'SHA256:x', '', :b, :b, :b, :b, 1, 'generated')", {'k': KEY, 'b': b'x'})

    def cli(self, *args):
        import contextlib
        import io
        from storageforge_index import cli
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = cli.main(['--db', str(Path(self.tmp) / 'index.db'), 'vm', *args])
        return rc, out.getvalue() + err.getvalue()

    def test_specs_and_create_from_the_cli(self):
        rc, out = self.cli('spec', 'db', '--set', 'vcpus=8', '--set', 'ram_mb=32768', '--key', 'fleet', '--note', 'Postgres')
        self.assertEqual(rc, 0, out)
        self.assertIn('db ', self.cli('specs')[1])
        self.assertIn('debian13', self.cli('images')[1])
        rc, out = self.cli('create', '--host', 'kvm', '--name', 'pg-01', '--spec', 'db', '--image', 'rocky9')
        self.assertEqual(rc, 0, out)
        plan = changes.get_plan(self.conn, int(out.split('#')[1].split(':')[0]))
        p = plan['tasks'][0]['params']
        self.assertEqual((p['vcpus'], p['ram_mb'], p['image'], p['ssh_key']), ('8', '32768', 'rocky9', ' '.join(KEY.split()[:2])))
        self.assertEqual(self.cli('create', '--host', 'kvm', '--name', 'x', '--set', 'vcpus')[0], 1)
        self.assertEqual(self.cli('spec-remove', 'server')[0], 1)

    def test_clone_picks_the_image_and_points_at_the_clone_command(self):
        rc, out = self.cli('clone', 'web-01', '--host', 'kvm', '--key', 'fleet', '--test', '--skip', 'steam')
        self.assertEqual(rc, 0, out)
        self.assertIn('storageforge-index clone web-01 --to web-01-copy --test --skip steam', out)
        plans = {p['name']: changes.get_plan(self.conn, p['id']) for p in changes.list_plans(self.conn)}
        self.assertEqual(list(plans), ['Copy web-01 to web-01-copy: the VM'])
        vm = plans['Copy web-01 to web-01-copy: the VM']['tasks'][0]['params']
        self.assertEqual((vm['image'], vm['network'], vm['spec']), ('ubuntu2404', 'sf-isolated', 'test-copy'))

    def test_the_packages_step_compares_both_lists(self):
        from storageforge_index import pkglist
        pk = {'name': 'pk', 'tasks': [{'type': 'packages', 'host': 'web-01-copy', 'params': {'from_host': 'web-01', 'skip': 'steam'}}]}
        self.assertEqual(changes.check(self.conn, changes.normalize(pk))['tasks'][0]['items'][0]['level'], 'crit')    # the copy is not scanned yet
        self.conn.execute("INSERT INTO hosts (hostname, ssh_host, ssh_user, inventory_json) VALUES ('web-01-copy', 'w', 'scan', :i)",
                          {'i': json.dumps({'pkglist': pkglist.parse('distro\tubuntu\t24.04\npm apt-get\nm\tvim\ncomplete')})})
        texts = [it['text'] for it in changes.check(self.conn, changes.normalize(pk))['tasks'][0]['items']]
        self.assertIn('1 to install: nginx', texts)
        script = changes.script(self.conn, pk)
        sh = Path(self.tmp) / 'pk.sh'
        sh.write_text(script)
        self.assertEqual(subprocess.run(['bash', '-n', str(sh)]).returncode, 0)
        self.assertIn('bash -s -- --apply --skip steam', changes.ansible(self.conn, pk))

    def test_the_packages_function_runs_the_list_inside_it(self):
        import base64
        import shlex
        from storageforge_index import pkglist, steps_clone
        body = base64.b64encode(pkglist.script(pkglist.parse('pm pacman\nm\tsf-surely-not-installed\ncomplete'), 'web-01', 'now').encode()).decode()
        here = 'here_pm() { echo pacman; }'
        out = subprocess.run(['bash', '-c', HARNESS + 'APPLY=0\n' + steps_clone.BASH + f'\nt_packages web-01 "" 1 {shlex.quote(body)}\nexit $((PROBLEMS > 0))\n'],
                             capture_output=True, text=True, timeout=60, env={**os.environ, 'PATH': f'{Path(self.tmp)}:{os.environ["PATH"]}'})
        if shutil.which('pacman'):
            self.assertIn('would install the packages of web-01', out.stdout, out.stdout + out.stderr)
        else:
            self.assertIn('package names differ', out.stdout)
        out = subprocess.run(['bash', '-c', HARNESS + 'APPLY=0\n' + steps_clone.BASH + '\nt_packages web-01 "" 1 ""\nexit $((PROBLEMS > 0))\n'], capture_output=True, text=True)
        self.assertIn('has no package list', out.stdout)

    def test_the_routes(self):
        from storageforge_index import server, users
        users.create(self.conn, 'alice', 'a long enough password')
        client = server.create_app(server.App(self.db), 's' * 48).test_client()
        self.assertEqual(client.get('/api/vm/specs').status_code, 401)
        client.post('/api/login', json={'username': 'alice', 'password': 'a long enough password'})
        self.assertIn('debian13', [i['key'] for i in client.get('/api/vm/images').json['images']])
        self.assertEqual(client.put('/api/vm/specs/db', json={'vcpus': '8'}).json['vcpus'], '8')
        self.assertEqual(client.put('/api/vm/specs/db', json={'vcpus': 'x'}).status_code, 400)
        self.assertEqual(client.put('/api/vm/specs/server', json={'vcpus': '1'}).status_code, 400)
        self.assertIn('db', [x['name'] for x in client.get('/api/vm/specs').json['specs']])
        self.assertEqual(client.delete('/api/vm/specs/db').status_code, 200)
        self.assertEqual(client.delete('/api/vm/specs/db').status_code, 404)
        got = client.post('/api/changes/check', json=plan(task(spec='server'))).json
        self.assertNotIn('choose an image', json.dumps(got))


class Portable(unittest.TestCase):
    """What the lab found that a syntax check on a new bash cannot: scripts run on the bash of each host."""
    # bash before 5.2 (Ubuntu 22.04, Debian 12, RHEL 9) cannot parse a case pattern without its opening ( inside $( )
    CASE_IN_SUBST = re.compile(r'\$\((?:[^()]|\([^()]*\))*?\bcase\s+\S+\s+in\s+(?!\()(\S)')

    def test_the_pattern_finds_what_bash_5_1_rejects(self):
        self.assertTrue(self.CASE_IN_SUBST.search('x=$(case $a in b) echo ;; esac)'))
        self.assertFalse(self.CASE_IN_SUBST.search('x=$(case $a in (b) echo ;; esac)'))
        self.assertFalse(self.CASE_IN_SUBST.search('case $a in b) echo ;; esac'))

    def test_no_script_has_a_bare_case_pattern_inside_a_command_substitution(self):
        hits = [f'{f.name}:{n}' for f in sorted(Path(steps_vm.__file__).parent.glob('*.py'))
                for n, line in enumerate(f.read_text().splitlines(), 1) if self.CASE_IN_SUBST.search(line)]
        self.assertEqual(hits, [])

    def test_the_agent_goes_with_the_first_connection(self):
        # sessions over a shared connection get the agent only if the connection was opened with it: with -A on the
        # later session alone, --forward-agent never reached the host (found copying a host's files in the lab)
        from storageforge_index import scriptkit
        first = next(line for line in scriptkit.REMOTE.splitlines() if 'mktemp -d /tmp/sf-move' in line)
        self.assertIn('${FWD[@]+"${FWD[@]}"}', first)
        self.assertLess(scriptkit.REMOTE.index('FWD=()'), scriptkit.REMOTE.index(first))

    def test_a_failed_create_takes_away_only_what_it_made(self):
        body = steps_vm.bash()
        self.assertIn('vm_undo() {', body)
        self.assertIn('virt-install --connect qemu:///system', body)
        tail = body[body.index('try virt-install'):]
        self.assertIn('{ vm_undo; return 0; }', tail[:tail.index('\n', tail.index('--noautoconsole'))])


if __name__ == '__main__':
    unittest.main()
