"""VMs from installer ISOs (steps_vmiso.py): the catalog, the check against the infrastructure reading, picking the newest ISO from a
checksum list in either form, and the script against stand-in virsh, qemu-img and curl. Its virt-install line is handed to the real
virt-install, against libvirt's own test driver, which builds the domain without a daemon and refuses what it would not accept."""
import hashlib
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
from storageforge_index import changes, steps_vm, steps_vmiso
from test_workload_steps import HARNESS


def stub(d: Path, name: str, body: str):
    (d / name).write_text('#!/bin/bash\n' + body + '\n')
    (d / name).chmod(0o755)


class Catalog(unittest.TestCase):
    def test_every_iso_is_https_with_a_checksum_list_and_a_pattern(self):
        import re
        for key, (label, sums, pattern, osinfo, fw) in steps_vmiso.ISOS.items():
            self.assertTrue(sums.startswith('https://'), key)
            re.compile(pattern)
            self.assertIn(fw, ('bios', 'uefi'))
            self.assertTrue(changes.CHECKS['osinfo'].fullmatch(osinfo), key)


class Pick(unittest.TestCase):
    def pick(self, text, pattern):
        d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d)
        (d / 'sums').write_text(text)
        return subprocess.run(['bash', '-c', steps_vmiso.bash() + '\nviso_pick "$1" "$2"', '_', str(d / 'sums'), pattern], capture_output=True, text=True).stdout.strip()

    def test_the_newest_file_of_the_release_in_either_form(self):
        a, b, c = 'a' * 64, 'b' * 64, 'c' * 128
        gnu = f'{a}  proxmox-ve_9.0-1.iso\n{b}  proxmox-ve_9.10-1.iso\n{a}  proxmox-ve_8.4-1.iso\n{b}  proxmox-backup-server_4.0-1.iso\n'
        self.assertEqual(self.pick(gnu, steps_vmiso.ISOS['proxmox-ve9'][2]), f'proxmox-ve_9.10-1.iso {b}')      # 9.10 is newer than 9.0
        bsd = f'# a comment\nSHA256 (Rocky-10.0-x86_64-minimal.iso) = {a}\nSHA256 (Rocky-10.1-x86_64-minimal.iso) = {b}\nSHA256 (Rocky-10.1-x86_64-dvd.iso) = {a}\n'
        self.assertEqual(self.pick(bsd, steps_vmiso.ISOS['rocky10'][2]), f'Rocky-10.1-x86_64-minimal.iso {b}')
        star = f'{c} *debian-13.2.0-amd64-netinst.iso\n{c} *debian-13.2.0-amd64-DVD-1.iso\n'
        self.assertEqual(self.pick(star, steps_vmiso.ISOS['debian13'][2]), f'debian-13.2.0-amd64-netinst.iso {c}')
        self.assertEqual(self.pick(f'{a}  other.iso\n$(touch /tmp/x)\n', steps_vmiso.ISOS['arch'][2]), '')


class Check(unittest.TestCase):
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
                'libvirt_networks': [{'name': 'default', 'mode': 'nat'}], **extra}
        security._save_measurement(self.conn, 'kvm', 'infra', int(time.time()), 'test', data)

    def items(self, **p):
        plan = {'name': 'v', 'tasks': [{'type': 'vm-iso', 'host': 'kvm', 'params': {'name': 'pve-lab', 'iso': 'proxmox-ve9', **p}}]}
        return [(it['level'], it['text']) for it in changes.check(self.conn, changes.normalize(plan))['tasks'][0]['items']]

    def test_what_the_reading_shows(self):
        self.assertEqual(self.items()[0][0], 'crit')                   # no reading
        self.reading()
        got = self.items(name='taken', pool='nope', network='nowhere')
        self.assertEqual(len([l for l, _ in got if l == 'crit']), 3, got)
        ok = self.items(firmware='uefi-secure', tpm=True)
        self.assertNotIn('crit', [l for l, _ in ok])
        self.assertIn(('ok', 'its disk can grow to 32 GiB with the ISO beside it, and /var/lib/libvirt/images has 70 GiB free'), ok)
        self.assertTrue(any('Proxmox VE 9: the newest file of the release in SHA256SUMS' in t for _, t in ok))
        self.assertTrue(any('listens on 127.0.0.1 only' in t for _, t in ok))
        got = self.items(iso='custom', iso_url='https://x.example/a.iso.bz2')
        self.assertIn('crit', [l for l, t in got if 'custom ISO' in t])
        self.assertTrue(any('choose uefi' in t for _, t in self.items()))

    def test_the_whole_script_is_valid_bash_and_ansible_renders(self):
        self.reading()
        plan = {'name': 'v', 'tasks': [{'type': 'vm-iso', 'host': 'kvm', 'params': {'name': 'pve-lab', 'iso': 'debian13'}}]}
        self.assertEqual(subprocess.run(['bash', '-n'], input=changes.script(self.conn, plan), text=True).returncode, 0)
        self.assertIn('t_vm_iso', changes.ansible(self.conn, plan))

    def test_an_export_carries_the_fetch_function_it_calls(self):
        t = {'type': 'vm-iso', 'host': 'kvm', 'params': {'name': 'pve-lab', 'iso': 'debian13'}}
        cmd = steps_vmiso._ansible(t)['ansible.builtin.shell']['cmd']
        self.assertIn('sf_vm_fetch() {', cmd)
        self.assertIn('sf_vm_fetch "$url" "$sum" "" "$base" || return 0', cmd)
        self.assertEqual(subprocess.run(['bash', '-n'], input=cmd, text=True).returncode, 0)


class Script(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.d)
        self.pool, self.bin, self.fake = self.d / 'pool', self.d / 'bin', self.d / 'fake'
        for p in (self.pool, self.bin, self.fake, self.d / 'root/usr/share/qemu/firmware'):
            p.mkdir(parents=True)
        self.iso = b'an installer, honestly'
        self.sum = hashlib.sha256(self.iso).hexdigest()
        (self.d / 'iso').write_bytes(self.iso)
        (self.d / 'sums').write_text(f'{"0" * 64}  proxmox-ve_9.0-1.iso\n{self.sum}  proxmox-ve_9.1-1.iso\n')
        stub(self.bin, 'virsh', f'''echo "virsh $*" >>"$LOG"
case "$*" in
  *pool-dumpxml*) echo "<pool><target><path>{self.pool}</path></target></pool>" ;;
  *net-info*) [[ "$*" == *default* ]] ;;
  *dominfo*) [[ -e "$FAKE/domain-$4" ]] ;;
  *metadata*--set*) : ;;
  *metadata*) [[ -e "$FAKE/ours" ]] && echo "<sf iso=x/>" ;;
esac''')
        stub(self.bin, 'qemu-img', 'echo "qemu-img $*" >>"$LOG"; [[ $1 == create ]] && touch "${@: -2:1}"')
        stub(self.bin, 'curl', f'''echo "curl $*" >>"$LOG"; out=; url=; while (($#)); do [[ $1 == -o ]] && {{ out=$2; shift; }}; url=$1; shift; done
case $url in *SHA256SUMS) cp "{self.d}/sums" "$out" ;; */proxmox-ve_9.1-1.iso) cp "{self.d}/iso" "$out" ;; *) exit 22 ;; esac''')
        real = shutil.which('virt-install')
        # the real virt-install, on libvirt's test driver: it builds the domain XML and refuses arguments it would not take.
        # The test driver has no UEFI, so a UEFI line is only logged.
        stub(self.bin, 'virt-install', f'''[[ $1 == --osinfo && $2 == list ]] && {{ echo debian13; exit 0; }}
echo "virt-install $*" >>"$LOG"
args=(); for a; do [[ $a == qemu:///system ]] && a=test:///default; args+=("$a"); done
[[ " $* " == *" --boot uefi"* || -z "{real or ''}" ]] && exit 0
/usr/bin/python3 "{real}" "${{args[@]}}" --print-xml --dry-run >"$FAKE/domain.xml"''')
        stub(self.bin, 'swtpm', ':')

    def run_fn(self, apply, *words, path_extra=''):
        # the download is steps_vm's sf_vm_fetch, which the plan script and the export carry beside t_vm_iso
        script = HARNESS + f'APPLY={int(apply)}\n' + changes.bash_fn(steps_vm.bash(), 'sf_vm_fetch') + steps_vmiso.bash() + '\nt_vm_iso ' + ' '.join(shlex.quote(w) for w in words) + '\nexit $((PROBLEMS > 0))\n'
        return subprocess.run(['bash', '-c', script], capture_output=True, text=True, timeout=120,
                              env={**os.environ, 'PATH': f'{self.bin}:{os.environ["PATH"]}', 'LOG': str(self.d / 'log'), 'FAKE': str(self.fake), 'VISO_ROOT': str(self.d / 'root')})

    def log(self):
        p = self.d / 'log'
        return p.read_text() if p.exists() else ''

    def words(self, **kw):
        p = {'name': 'pve-lab', 'iso': 'proxmox-ve9', 'iso_url': '', 'iso_sha': '', 'osinfo': '', 'vcpus': '2', 'ram_mb': '4096', 'disk_gb': '32', 'pool': 'default',
             'network': 'default', 'bridge': '', 'firmware': '', 'tpm': '', 'console': '', 'autostart': '', **kw}
        return [p[a] for a in steps_vmiso.ARGS]

    def test_report_changes_nothing_then_apply_picks_checks_and_boots_the_installer(self):
        out = self.run_fn(False, *self.words())
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertIn('would: create VM pve-lab in default and boot its installer', out.stdout)
        self.assertNotIn('curl', self.log())
        out = self.run_fn(True, *self.words(autostart='1', tpm='1'))
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertIn('downloaded and checked proxmox-ve_9.1-1.iso', out.stdout)
        self.assertTrue((self.pool / '.storageforge-images/proxmox-ve_9.1-1.iso').exists())
        install = next(l for l in self.log().splitlines() if l.startswith('virt-install'))
        for want in ('--name pve-lab', '--osinfo debian13', f'--cdrom {self.pool}/.storageforge-images/proxmox-ve_9.1-1.iso', '--graphics spice,listen=127.0.0.1',
                     '--tpm backend.type=emulator', 'org.qemu.guest_agent.0', f'path={self.pool}/pve-lab-root.qcow2,format=qcow2,bus=virtio'):
            self.assertIn(want, install)
        self.assertIn('autostart pve-lab', self.log())
        if shutil.which('virt-install'):
            xml = (self.fake / 'domain.xml').read_text()
            self.assertIn('<graphics type="spice"', xml)
            self.assertIn('listen="127.0.0.1"', xml)
            self.assertIn('<tpm model="tpm-crb">', xml)
            self.assertIn('proxmox-ve_9.1-1.iso', xml)

    def test_a_bad_checksum_and_what_is_already_there_stop_it(self):
        (self.d / 'iso').write_bytes(b'tampered')
        out = self.run_fn(True, *self.words())
        self.assertIn('does not match its checksum: not used', out.stdout)
        self.assertFalse((self.pool / '.storageforge-images/proxmox-ve_9.1-1.iso').exists())
        (self.pool / 'pve-lab-root.qcow2').touch()
        out = self.run_fn(True, *self.words())
        self.assertIn('never writes over a disk', out.stdout)
        (self.fake / 'domain-pve-lab').touch()
        out = self.run_fn(True, *self.words())
        self.assertIn('StorageForge did not make it', out.stdout)
        (self.fake / 'ours').touch()
        self.assertIn('pve-lab exists, made by StorageForge', self.run_fn(True, *self.words()).stdout)

    def test_uefi_needs_firmware_a_tpm_needs_swtpm_and_a_custom_iso_its_checksum(self):
        out = self.run_fn(True, *self.words(firmware='uefi-secure'))
        self.assertIn('no UEFI firmware for QEMU here', out.stdout)
        (self.d / 'root/usr/share/qemu/firmware/60-edk2.json').write_text('{}')
        out = self.run_fn(True, *self.words(firmware='uefi-secure'))
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertIn('--boot uefi,firmware.feature0.name=secure-boot,firmware.feature0.enabled=yes', self.log())
        (self.bin / 'swtpm').unlink()
        self.assertIn('swtpm is not installed', self.run_fn(True, *self.words(name='b', tpm='1')).stdout)
        self.assertIn('needs its URL and its checksum', self.run_fn(True, *self.words(name='c', iso='custom', iso_url='https://x.example/a.iso')).stdout)


if __name__ == '__main__':
    unittest.main()
