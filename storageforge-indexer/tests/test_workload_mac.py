"""MAC at deploy (steps_mac.py, steps_workloads.py, wlread.py): :Z and :z for a stack's bind mounts and the folders that must never get
one, the vm_mac section of the infrastructure reading and the VM findings it gives, and the vm-mac step against stand-in SELinux tools and
the real apparmor_parser, which checks the local abstraction as libvirt reads it."""
import base64
import json
import os
import shlex
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

import yaml

try:
    import dbfactory
except ImportError:      # run as tests.test_x from the project folder
    from tests import dbfactory
from storageforge_index import changes, inframeasure, steps_mac, steps_workloads as wl, wlread
from test_workload_steps import HARNESS


def b64(s):
    return base64.b64encode(s.encode()).decode()


class Relabel(unittest.TestCase):
    def test_the_labels_file_repeats_each_bind_mount_with_its_label(self):
        m = wl.compose_model('services:\n  db:\n    image: postgres:16\n    volumes: ["/tank/db:/var/lib/postgresql/data", "./conf:/etc/x:ro", "/srv/shared:/s:z", "cache:/c"]\n')
        got = yaml.safe_load(wl.override('app', m, {}, 'private'))['services']['db']['volumes']
        self.assertEqual(got, ['/tank/db:/var/lib/postgresql/data:Z', './conf:/etc/x:ro,Z', '/srv/shared:/s:z'])
        self.assertNotIn('volumes', yaml.safe_load(wl.override('app', m, {}))['services']['db'])

    def test_folders_that_must_never_be_relabelled(self):
        binds = [{'source': '/etc', 'target': '/e', 'options': ''}, {'source': '/home/alice', 'target': '/h', 'options': ''}, {'source': '/srv/app', 'target': '/a', 'options': ''}]
        got = wl.relabel_findings(binds, 'private')
        self.assertEqual(len(got), 2)
        self.assertEqual(wl.relabel_findings(binds, ''), [])
        self.assertEqual(len(wl.relabel_findings([{'source': '/usr', 'target': '/u', 'options': 'Z'}], '')), 1)


class Reading(unittest.TestCase):
    def test_the_vm_mac_section_is_read_and_junk_is_left_out(self):
        rule = b64('  "/tank/vm/**" rwk,')
        lines = ['m\tselinux', f's\t{b64("/tank/vm")}\tsystem_u:object_r:default_t:s0\tsystem_u:object_r:default_t:s0', 's\tnot base64!\tx', f'a\t{rule}',
                 'junk', f'p\t{b64("relative")}']
        got = wlread.vm_mac(lines)
        self.assertEqual(got['mac'], 'selinux')
        self.assertEqual(got['paths'], [{'path': '/tank/vm', 'type': 'default_t', 'expected': 'default_t'}])
        self.assertEqual(got['apparmor_local'], ['"/tank/vm/**" rwk,'])
        s = inframeasure.script()
        self.assertIn('sec vm_mac', s)
        self.assertEqual(subprocess.run(['bash', '-n'], input=s, text=True).returncode, 0)
        whole = inframeasure.parse('@@tools\nvirsh\n@@vm_mac\n' + '\n'.join(lines) + '\n@@end\n')
        self.assertEqual(whole['vm_mac']['mac'], 'selinux')

    def test_vm_findings_name_the_step_that_fixes_them(self):
        disks = [{'source': '/tank/vm/a.qcow2', 'device': 'disk'}, {'source': '/var/lib/libvirt/images/b.qcow2', 'device': 'disk'}, {'source': '/iso/x.iso', 'device': 'cdrom'}]
        se = {'vm_mac': {'mac': 'selinux', 'paths': [{'path': '/tank/vm', 'type': 'default_t', 'expected': None},
                                                      {'path': '/var/lib/libvirt/images', 'type': 'virt_image_t', 'expected': None}]}}
        self.assertEqual(wlread.disk_findings(se, disks), ['/tank/vm is labelled default_t, not virt_image_t, so SELinux keeps QEMU from it: stage a vm-mac step for /tank/vm'])
        aa = {'vm_mac': {'mac': 'apparmor', 'paths': [], 'apparmor_local': []}}
        self.assertEqual(len(wlread.disk_findings(aa, disks)), 1)
        aa['vm_mac']['apparmor_local'] = ['"/tank/**" rwk,']
        self.assertEqual(wlread.disk_findings(aa, disks), [])
        self.assertEqual(wlread.disk_findings({}, disks), [])


class Check(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.db = dbfactory.make(self, Path(self.tmp) / 'index.db')
        self.conn = self.db.connect()
        self.db.migrate(self.conn)
        self.addCleanup(self.conn.close)
        self.conn.execute("INSERT INTO hosts (hostname, ssh_host, ssh_user, inventory_json) VALUES ('fed', 'fed', 'scan', '{}')")

    def items(self, kind, **p):
        plan = {'name': 'm', 'tasks': [{'type': kind, 'host': 'fed', 'params': p}]}
        return [(it['level'], it['text']) for it in changes.check(self.conn, changes.normalize(plan))['tasks'][0]['items']]

    def selinux(self, mode='Enforcing'):
        from storageforge_index import security
        security._save_measurement(self.conn, 'fed', 'host', int(time.time()), 'test', {'selinux': mode})

    def test_a_stack_on_an_selinux_host_is_told_to_label_its_bind_mounts(self):
        compose = 'services:\n  app:\n    image: nginx:1.27\n    volumes: ["/srv/app:/data"]\n'
        self.assertFalse([t for _, t in self.items('stack', runtime='podman', name='a', compose=compose) if ':z or :Z' in t])     # no reading: nothing said
        self.selinux()
        got = self.items('stack', runtime='podman', name='a', compose=compose)
        self.assertTrue(any(l == 'warn' and 'runs SELinux (enforcing): /srv/app has no :z or :Z' in t for l, t in got), got)
        got = self.items('stack', runtime='podman', name='a', compose=compose, selinux='private')
        self.assertIn(('ok', 'its bind mounts get :Z, so SELinux lets the containers use them'), got)
        got = self.items('stack', runtime='podman', name='a', compose=compose.replace('/srv/app', '/etc'), selinux='shared')
        self.assertTrue(any(l == 'crit' and '/etc is a system folder' in t for l, t in got))

    def test_vm_mac_check(self):
        self.assertEqual(self.items('vm-mac', path='/var')[0][0], 'crit')
        self.selinux()
        got = self.items('vm-mac', path='/tank/vm', system='apparmor')
        self.assertTrue(any(l == 'warn' and 'runs selinux, not apparmor' in t for l, t in got))
        self.assertTrue(any('virt_image_t with semanage fcontext' in t for _, t in self.items('vm-mac', path='/tank/vm')))


def stub(d: Path, name: str, body: str):
    (d / name).write_text('#!/bin/bash\necho "' + name + ' $*" >>"$LOG"\n' + body + '\n')
    (d / name).chmod(0o755)


class Script(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.d)
        self.bin, self.root, self.pool = self.d / 'bin', self.d / 'root', self.d / 'pool'
        for p in (self.bin, self.root / 'etc/apparmor.d/abstractions', self.root / 'sys/module/apparmor/parameters', self.pool):
            p.mkdir(parents=True)

    def run_fn(self, apply, *words, path=None):
        script = HARNESS + f'APPLY={int(apply)}\n' + steps_mac.BASH + '\nt_vm_mac ' + ' '.join(shlex.quote(w) for w in words) + '\nexit $((PROBLEMS > 0))\n'
        return subprocess.run(['bash', '-c', script], capture_output=True, text=True, timeout=60,
                              env={**os.environ, 'PATH': f'{self.bin}:{path or os.environ["PATH"]}', 'LOG': str(self.d / 'log'), 'FAKE': str(self.d), 'WLM_ROOT': str(self.root)})

    def log(self):
        p = self.d / 'log'
        return p.read_text() if p.exists() else ''

    def test_selinux_registers_the_folder_and_relabels_it(self):
        stub(self.bin, 'getenforce', 'echo Enforcing')
        stub(self.bin, 'semanage', '[[ $2 == -l ]] && cat "$FAKE/fcontext" 2>/dev/null; [[ $2 == -a ]] && echo "${@: -1} virt_image_t" >>"$FAKE/fcontext"; exit 0')
        stub(self.bin, 'restorecon', 'touch "$FAKE/relabelled"')
        stub(self.bin, 'stat', '[[ -e $FAKE/relabelled ]] && echo system_u:object_r:virt_image_t:s0 || echo system_u:object_r:default_t:s0')
        out = self.run_fn(False, str(self.pool), '')
        self.assertIn(f'{self.pool} is default_t now', out.stdout)
        self.assertNotIn('semanage fcontext -a', self.log())
        out = self.run_fn(True, str(self.pool), '')
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertIn(f'semanage fcontext -a -t virt_image_t {self.pool}(/.*)?', self.log())
        self.assertIn(f'restorecon -R -- {self.pool}', self.log())
        self.assertIn('is virt_image_t, and registered', self.run_fn(True, str(self.pool), '').stdout)
        self.assertIn('is a system folder', self.run_fn(True, '/var/lib', '').stdout)

    def test_neither_mac_means_nothing_to_do(self):
        out = self.run_fn(True, str(self.pool), '', path='/usr/bin:/bin')
        self.assertIn('neither SELinux nor AppArmor is on here', out.stdout)

    @unittest.skipUnless(shutil.which('apparmor_parser'), 'needs apparmor_parser')
    def test_apparmor_rules_are_checked_by_the_real_parser_and_put_back_when_refused(self):
        (self.root / 'sys/module/apparmor/parameters/enabled').write_text('Y\n')
        # an abstraction as libvirt ships it: it includes the local file
        (self.root / 'etc/apparmor.d/abstractions/libvirt-qemu').write_text('  /usr/share/qemu/** r,\n  include if exists <local/abstractions/libvirt-qemu>\n')
        out = self.run_fn(False, str(self.pool), '', path='/usr/sbin:/usr/bin:/bin')
        self.assertIn('would: let QEMU use', out.stdout)
        local = self.root / 'etc/apparmor.d/local/abstractions/libvirt-qemu'
        self.assertFalse(local.exists())
        out = self.run_fn(True, str(self.pool), '', path='/usr/sbin:/usr/bin:/bin')
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertIn(f'  "{self.pool}/**" rwk,', local.read_text())
        self.assertIn('AppArmor lets QEMU use', self.run_fn(True, str(self.pool), '', path='/usr/sbin:/usr/bin:/bin').stdout)
        # a folder whose name the parser refuses: the file goes back to what it was
        before = local.read_text()
        bad = self.d / 'bad"name'
        bad.mkdir()
        out = self.run_fn(True, str(bad), 'apparmor', path='/usr/sbin:/usr/bin:/bin')
        self.assertIn('apparmor_parser refused it, so the file was put back', out.stdout)
        self.assertEqual(local.read_text(), before)


if __name__ == '__main__':
    unittest.main()
