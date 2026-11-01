"""Tier 0: the running KVM lab is what examples/lab says it is, so later tiers can trust it.
Needs a running lab. Run with: examples/lab/lab.sh test (not part of the normal test run)."""
import json
import os
import shlex
import ssl
import subprocess
import sys
import time
import unittest
import urllib.request
from pathlib import Path

LAB_DIR = Path(__file__).resolve().parents[2] / 'examples' / 'lab'
LAB = str(LAB_DIR / 'lab.sh')
STATE = Path(os.environ.get('SFLAB_STATE', Path.home() / '.local' / 'state' / 'sflab'))


def conf(path):
    lines = (LAB_DIR / path).read_text().splitlines()
    return [line.split('|') for line in lines if line.strip() and not line.startswith('#')]


def running():
    if not (STATE / 'id_ed25519').exists():
        return []
    nodes = json.loads(subprocess.run([LAB, 'status', '--json'], capture_output=True, text=True, timeout=60).stdout)
    return [n['name'] for n in nodes if n['state'] == 'running' and n['ssh'] == 'yes']


def raw(vm, command):
    return subprocess.run([LAB, 'ssh', vm, command], stdin=subprocess.DEVNULL, capture_output=True, timeout=300)


def sh(vm, command):
    p = raw(vm, command)
    if p.returncode:
        raise AssertionError(f'{vm}: {command}: exit {p.returncode}: {p.stderr.decode(errors="replace")[-400:]}')
    return p.stdout.decode(errors='surrogateescape')


sys.path.insert(0, str(LAB_DIR))
import roles  # noqa: E402

BUILD = roles.build()
VMS = list(BUILD)
UP = running()
SCANNED = [vm for vm in VMS if vm != 'sf-ctl']


def having(ability):
    return [n.name for n in BUILD.values() if n.can(ability)]


@unittest.skipUnless(set(UP) == set(VMS), f'needs every lab VM up, have {UP}')
class Identity(unittest.TestCase):
    def test_host_names(self):
        for vm in VMS:
            with self.subTest(vm=vm):
                self.assertEqual(sh(vm, 'uname -n').strip(), vm)

    def test_machine_ids_are_unique(self):
        # Alpine has none: deploys can't run there anyway.
        ids = {vm: sh(vm, 'cat /etc/machine-id').strip() for vm in VMS if vm not in having('nosystemd')}
        self.assertEqual(len(set(ids.values())), len(ids), ids)
        self.assertTrue(all(ids.values()), ids)

    def test_accounts(self):
        for vm in VMS:
            with self.subTest(vm=vm):
                # Not `sudo -l`: Leap's stock sudoers lists everyone, but asks for the password of root, which is locked.
                self.assertNotEqual(raw(vm, 'sudo -n -u scan sudo -n true').returncode, 0)
                self.assertIn('ALL', sh(vm, 'sudo -n -l -U sfadmin'))


@unittest.skipUnless(set(UP) == set(VMS), f'needs every lab VM up, have {UP}')
class Layout(unittest.TestCase):
    """The golden snapshot is taken after a reboot, so these also show the layouts survive one."""

    def test_mounts(self):
        for vm in VMS:
            table = {}
            for line in sh(vm, 'cat /proc/self/mountinfo').splitlines():
                left, right = line.split(' - ', 1)
                fields = left.split()
                table[fields[4]] = (right.split()[0], fields[3])    # a later mount over the same point wins
            for _, mount, fstype, fsroot in (r for r in conf('provision/layout.conf') if r[0] == vm):
                with self.subTest(vm=vm, mount=mount):
                    self.assertIn(mount, table)
                    self.assertEqual(table[mount][0], fstype)
                    if fsroot:
                        self.assertEqual(table[mount][1], fsroot)

    def test_zfs_pools(self):
        for node in (BUILD[v] for v in having('zfs')):
            with self.subTest(vm=node.name):
                pool = node.tag('zfs-pool')
                self.assertEqual(sh(node.name, f'sudo -n zpool list -H -o health {pool}').strip(), 'ONLINE')

    def test_btrfs_profiles(self):
        for node in BUILD.values():
            profile = node.tag('btrfs-profile')
            if profile:
                with self.subTest(vm=node.name):
                    out = sh(node.name, f'sudo -n btrfs filesystem df {node.data}').lower()
                    self.assertIn(f'data, {profile}', out)

    def test_lvm_volumes(self):
        for node in (BUILD[v] for v in having('lvm')):
            with self.subTest(vm=node.name):
                vg, lv = node.tag('vg'), node.tag('lv')
                self.assertIn(lv, sh(node.name, f'sudo -n lvs --noheadings -o lv_name {vg}').split())

    def test_md_arrays_are_whole(self):
        for vm in having('md'):
            with self.subTest(vm=vm):
                self.assertNotRegex(sh(vm, 'cat /proc/mdstat'), r'\[U*_+U*\]')

    def test_child_subvolumes_have_no_mount(self):
        for node in BUILD.values():
            child = node.tag('btrfs-child')
            if child:
                with self.subTest(vm=node.name):
                    self.assertNotIn(f' {child} ', sh(node.name, 'cat /proc/self/mountinfo'))
                    self.assertEqual(sh(node.name, f'sudo -n btrfs subvolume show {child} >/dev/null && echo yes').strip(), 'yes')

    def test_mergerfs_branches(self):
        for vm in having('mergerfs'):
            with self.subTest(vm=vm):
                self.assertEqual(sh(vm, 'lsblk -no TYPE /dev/mapper/secure').split()[0], 'crypt')
                branches = sh(vm, 'sudo -n getfattr --only-values -n user.mergerfs.srcmounts /mnt/pool/.mergerfs')
                self.assertEqual(branches.strip(), '/mnt/disk1:/mnt/disk2')

    def test_containers(self):
        for vm in having('docker'):
            self.assertIn('sflab-web', sh(vm, 'sudo -n docker ps --format "{{.Names}}"').split())
        for vm in having('podman'):
            self.assertIn('sflab-web', sh(vm, 'sudo -n podman ps --format "{{.Names}}"').split())

    def test_hosts_without_systemd_have_no_known_package_manager(self):
        for vm in having('nosystemd'):
            out = sh(vm, 'for c in systemctl apt-get dnf yum zypper pacman; do command -v $c; done; true')
            self.assertEqual(out.strip(), '')

    def test_share_servers_are_left_for_deploys_to_install(self):
        if raw('sf-ctl', 'test -e /var/lib/sflab/demo').returncode == 0:
            self.skipTest('the demo has deployed shares: Reset to check this')
        for vm in SCANNED:
            with self.subTest(vm=vm):
                # Some Enterprise Linux images ship nfs-utils, so there Samba is the install a deploy exercises.
                programs = 'smbd' if BUILD[vm].pm == 'dnf' else 'exportfs smbd'
                self.assertEqual(sh(vm, f'PATH=$PATH:/usr/sbin:/sbin; for c in {programs}; do command -v $c; done; true').strip(), '')


@unittest.skipUnless(set(UP) == set(VMS), f'needs every lab VM up, have {UP}')
class Controller(unittest.TestCase):
    def test_storageforge_is_healthy_from_this_machine(self):
        for _ in range(40):           # just after a reset the container is still starting
            out = sh('sf-ctl', "sudo -n docker ps --format '{{.Names}} {{.Status}}'")
            if '(healthy)' in out:
                break
            time.sleep(5)
        self.assertRegex(out, r'storageforge-1 Up .*\(healthy\)')
        context = ssl.create_default_context()
        context.check_hostname, context.verify_mode = False, ssl.CERT_NONE      # self-signed: only reachability matters here
        with urllib.request.urlopen('https://10.77.0.10:8443/healthz', context=context, timeout=15) as r:
            self.assertEqual(json.load(r)['status'], 'ok')

    def test_ntfy_answers(self):
        with urllib.request.urlopen('http://10.77.0.10:8090/v1/health', timeout=15) as r:
            self.assertTrue(json.load(r)['healthy'])

    def test_stack_does_not_build_on_the_vm(self):
        self.assertIn('storageforge:', sh('sf-ctl', "sudo -n docker images --format '{{.Repository}}:{{.Tag}}'"))
        self.assertNotEqual(raw('sf-ctl', 'sudo -n test -e /opt/storageforge/Dockerfile').returncode, 0)


@unittest.skipUnless(set(UP) == set(VMS), f'needs every lab VM up, have {UP}')
class Seed(unittest.TestCase):
    def manifests(self):
        for vm, root, profile in (r for r in conf('provision/seed-roots.conf') if r[0] in BUILD):
            path = STATE / 'manifests' / f'{vm}{root.replace("/", "_")}.json'
            self.assertTrue(path.exists(), f'no manifest for {vm}:{root}')
            manifest = json.loads(path.read_text())
            self.assertEqual(manifest['profile'], profile)
            yield vm, manifest

    def test_every_root_holds_exactly_its_manifest(self):
        for vm, manifest in self.manifests():
            root = shlex.quote(manifest['root'])
            with self.subTest(vm=vm, root=manifest['root']):
                listing = raw(vm, f"sudo -n find {root} -mindepth 1 -printf '%P\\0%y\\0%s\\0%m\\0%l\\0'")
                self.assertEqual(listing.returncode, 0, listing.stderr)
                parts = listing.stdout.split(b'\0')[:-1]
                found = {os.fsdecode(parts[i]): parts[i + 1:i + 5] for i in range(0, len(parts), 5)}
                expected = {e['path']: e for e in manifest['entries']}
                self.assertEqual(sorted(found), sorted(expected))
                for path, e in expected.items():
                    kind, size, mode, link = found[path]
                    self.assertEqual(kind.decode(), e['type'], path)
                    if e['type'] == 'f':
                        self.assertEqual(int(size), e['size'], path)
                    if e['type'] == 'l':
                        self.assertEqual(os.fsdecode(link), e['target'], path)
                    if manifest['profile'] == 'full' and e['type'] != 'l':
                        self.assertEqual(int(mode, 8), e['mode'], path)

    def test_every_file_hash_matches(self):
        for vm, manifest in self.manifests():
            root = shlex.quote(manifest['root'])
            with self.subTest(vm=vm, root=manifest['root']):
                p = raw(vm, f"cd {root} && sudo -n find . -type f -size -512M -print0 | sudo -n xargs -0 sha256sum -z")
                self.assertEqual(p.returncode, 0, p.stderr)
                sums = {}
                for row in p.stdout.split(b'\0')[:-1]:
                    digest, name = row.split(b'  ', 1)
                    sums[os.fsdecode(name).removeprefix('./')] = digest.decode()
                want = {e['path']: e['sha256'] for e in manifest['entries'] if e['type'] == 'f' and not e.get('sparse')}
                self.assertEqual(sums, want)

    def test_scan_user_cannot_read_restricted(self):
        for vm, manifest in self.manifests():
            if manifest['profile'] != 'full':
                continue
            with self.subTest(vm=vm):
                p = raw(vm, f"sudo -n -u scan cat {shlex.quote(manifest['root'])}/restricted/secret.txt")
                self.assertNotEqual(p.returncode, 0)
                self.assertEqual(p.stdout, b'')

    def test_hardlinks_share_an_inode(self):
        for vm, manifest in self.manifests():
            if manifest['profile'] != 'full':
                continue
            with self.subTest(vm=vm):
                root = shlex.quote(manifest['root'])
                inodes = sh(vm, f'sudo -n stat -c %i {root}/links/hard-a.txt {root}/links/hard-b.txt').split()
                self.assertEqual(inodes[0], inodes[1])

    def test_sparse_file_takes_almost_no_space(self):
        for vm, manifest in self.manifests():
            if manifest['profile'] != 'full':
                continue
            with self.subTest(vm=vm):
                blocks = sh(vm, f"sudo -n stat -c %b {shlex.quote(manifest['root'])}/links/sparse.img").strip()
                self.assertLess(int(blocks), 1024)


if __name__ == '__main__':
    unittest.main()
