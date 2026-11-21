"""The runtime-install step (steps_runtime.py), run as Bash against stand-in package managers, systemctl and friends on a folder
standing in for the host's root: what the report says (present, installable, blocked, and why) for each family, that the report changes
nothing, what an apply installs and sets up, rootless setup, and the Docker repository whose key is installed only when its fingerprint
is the pinned one, checked by the real gpg against keys made for the test."""
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import dbfactory
from storageforge_index import changes, steps_runtime

HARNESS = r'''
set -u
ok() { echo "ok: $*"; }; missing() { echo "missing: $*"; }; conflict() { echo "conflict: $*"; PROBLEMS=$((PROBLEMS + 1)); }
info() { echo "info: $*"; }; doing() { echo "doing: $*"; }; durable() { :; }
act() { if ((APPLY)); then echo "doing: $*"; return 0; else echo "would: $*"; return 1; fi; }
try() { "$@" || { conflict "failed: $*"; return 1; }; }
PROBLEMS=0
'''
REAL = ('bash', 'env', 'awk', 'grep', 'sed', 'cat', 'head', 'tail', 'tr', 'mktemp', 'rm', 'mkdir', 'install', 'printf', 'wc', 'cut', 'sort',
        'chmod', 'mv', 'cp', 'touch', 'sync', 'gpg', 'ls', 'dirname', 'basename', 'stat')
OS = {
    'debian13': 'ID=debian\nVERSION_ID="13"\nVERSION_CODENAME=trixie\n',
    'debian12': 'ID=debian\nVERSION_ID="12"\nVERSION_CODENAME=bookworm\n',
    'ubuntu': 'ID=ubuntu\nID_LIKE=debian\nVERSION_ID="24.04"\nVERSION_CODENAME=noble\nUBUNTU_CODENAME=noble\n',
    'rocky': 'ID="rocky"\nID_LIKE="rhel centos fedora"\nVERSION_ID="9.5"\n',
    'fedora': 'ID=fedora\nVERSION_ID=43\n',
    'suse': 'ID="opensuse-tumbleweed"\nID_LIKE="opensuse suse"\nVERSION_ID="20261101"\n',
    'arch': 'ID=arch\n',
}
PM = {'debian13': 'apt', 'debian12': 'apt', 'ubuntu': 'apt', 'rocky': 'dnf', 'fedora': 'dnf', 'suse': 'zypper', 'arch': 'pacman'}

# What installing a package puts on PATH. Each stand-in logs its command line.
PROVIDES = {
    'docker.io': ('docker', 'echo "Docker version 26.1.5+dfsg1, build a72d7cd"'), 'moby-engine': ('docker', 'echo "Docker version 27.3.1, build ce1223"'),
    'docker': ('docker', 'echo "Docker version 27.5.1, build 9f9e405"'), 'docker-ce': ('docker', 'echo "Docker version 28.0.1, build 068a01e"'),
    'podman': ('podman', 'echo "podman version 5.4.0"'),
    'incus': ('incus', 'case "$1 $2" in "--version ") echo 6.0.4 ;; "storage list") [[ -e $FAKE/incus-init ]] && echo "default,dir" ;; "admin init") touch "$FAKE/incus-init" ;; esac'),
    'lxc': ('lxc-create', 'echo 6.0.3'),
    'libvirt-daemon-system': ('virsh', 'echo 11.3.0'), 'libvirt': ('virsh', 'echo 11.3.0'),
}
PM_STUB = r'''
installed() { grep -qx "$1" "$FAKE/installed" 2>/dev/null; }
avail() { [[ " $AVAIL " == *" $1 "* ]] || { installed epel-release && [[ " ${EPEL:-} " == *" $1 "* ]]; } || installed "$1"; }
put() { local p c; for p; do avail "$p" || { echo "No match for argument: $p" >&2; exit 1; }; done
  for p; do echo "$p" >>"$FAKE/installed"
    if [[ -r $FAKE/provides/$p ]]; then c=$(head -n 1 "$FAKE/provides/$p")
      { printf "#!/bin/bash\necho \"%s \$*\" >>\"\$LOG\"\n" "$c"; tail -n +2 "$FAKE/provides/$p"; } >"$BIN/$c"; chmod +x "$BIN/$c"; fi
    [[ $p == libvirt-daemon-system || $p == libvirt ]] && { printf "#!/bin/bash\n" >"$BIN/libvirtd"; chmod +x "$BIN/libvirtd"; }
  done; return 0; }
'''


def stub(d: Path, name: str, body: str):
    (d / name).write_text('#!/bin/bash\necho "' + name + ' $*" >>"$LOG"\n' + body + '\n')
    (d / name).chmod(0o755)


class Runtime(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.d, True)
        self.root, self.bin, self.real = self.d / 'root', self.d / 'bin', self.d / 'real'
        for p in (self.root / 'etc', self.root / 'sys/fs/cgroup', self.root / 'proc/sys/user', self.root / 'var/lib/apt/lists', self.bin, self.real,
                  self.d / 'gnupg'):
            p.mkdir(parents=True)
        (self.d / 'gnupg').chmod(0o700)
        (self.root / 'sys/fs/cgroup/cgroup.controllers').write_text('cpu memory\n')
        (self.root / 'proc/sys/user/max_user_namespaces').write_text('63000\n')
        (self.root / 'proc/filesystems').write_text('nodev\toverlay\n')
        (self.root / 'var/lib/apt/lists/deb.debian.org_dists_trixie_main_binary-amd64_Packages').write_text('')
        for name in REAL:
            if shutil.which(name):
                (self.real / name).symlink_to(shutil.which(name))
        (self.d / 'provides').mkdir()
        for pkg, (cmd, body) in PROVIDES.items():
            (self.d / 'provides' / pkg).write_text(f'{cmd}\n{body}\n')
        common = PM_STUB
        stub(self.bin, 'uname', 'echo "${ARCH:-x86_64}"')
        stub(self.bin, 'systemctl', 'u=${@: -1}; case "$*" in *"cat "*) [[ " ${UNITS:-} " == *" $u "* ]] ;; *is-enabled*|*is-active*) [[ -e $FAKE/on-$u ]] ;; '
                                    '*"enable --now"*) touch "$FAKE/on-$u" ;; esac')
        stub(self.bin, 'loginctl', 'mkdir -p "$RT_ROOT/var/lib/systemd/linger"; touch "$RT_ROOT/var/lib/systemd/linger/$2"')
        stub(self.bin, 'usermod', 'exit 0')
        stub(self.bin, 'id', 'case $1 in -u) [[ " ${USERS:-alice} " == *" $2 "* ]] && echo 1000 ;; -nG) echo "$2" ;; *) echo 0 ;; esac')
        stub(self.bin, 'getent', 'exit 0')
        stub(self.bin, 'modprobe', 'exit 0')
        stub(self.bin, 'df', 'printf "Filesystem 1024-blocks Used Available Capacity Mounted\\n/dev/vda1 20000000 1000 %s 1%% /\\n" "${FREE_KB:-10485760}"')
        stub(self.bin, 'findmnt', 'case "$*" in *OPTIONS*) echo rw ;; *) echo "${FSTYPE:-ext4}" ;; esac')
        stub(self.bin, 'dpkg', 'echo amd64')
        stub(self.bin, 'curl', 'while (($#)); do [[ $1 == -o ]] && cp "$KEYFILE" "$2"; shift; done')
        stub(self.bin, 'apt-get', common + 'case " $* " in *" install "*) a=(); for x; do case $x in -*|install|DPkg*) ;; *) a+=("$x") ;; esac; done; put "${a[@]}" ;; esac')
        stub(self.bin, 'apt-cache', common + 'avail "$2" && echo "  Candidate: 1.0-1" || echo "  Candidate: (none)"')
        for pm in ('dnf', 'yum'):
            stub(self.bin, pm, common + 'case " $* " in *" list --available "*) avail "${@: -1}" ;; *" list --installed "*) installed "${@: -1}" ;; *" repolist "*) exit 0 ;; '
                                        '*" install "*) a=(); for x; do [[ $x == -* || $x == install ]] || a+=("$x"); done; put "${a[@]}" ;; esac')
        stub(self.bin, 'rpm', common + 'installed "${@: -1}"')
        stub(self.bin, 'zypper', common + 'case " $* " in *" info "*) avail "${@: -1}" && echo "Name           : ${@: -1}" ;; '
                                 '*" install "*) a=(); for x; do [[ $x == -* || $x == install ]] || a+=("$x"); done; put "${a[@]}" ;; esac')
        stub(self.bin, 'pacman', common + 'case $1 in -Si) avail "$2" ;; -Qi) installed "$2" ;; -S) a=(); for x; do [[ $x == -* ]] || a+=("$x"); done; put "${a[@]}" ;; esac')

    def host(self, distro):
        (self.root / 'etc/os-release').write_text(OS[distro])
        keep = {'apt': ('apt-get', 'apt-cache', 'dpkg'), 'dnf': ('dnf', 'rpm'), 'zypper': ('zypper', 'rpm'), 'pacman': ('pacman',)}[PM[distro]]
        for pm in ('apt-get', 'apt-cache', 'dpkg', 'dnf', 'yum', 'rpm', 'zypper', 'pacman'):
            if pm not in keep and (self.bin / pm).exists():
                (self.bin / pm).rename(self.bin / f'.{pm}')
            elif pm in keep and (self.bin / f'.{pm}').exists():
                (self.bin / f'.{pm}').rename(self.bin / pm)

    def run_step(self, apply, runtime, source='distro', rootless='', user='', **env):
        call = f't_runtime_install {runtime} {source} "{rootless}" "{user}"'
        e = {'PATH': f'{self.bin}:{self.real}', 'FAKE': str(self.d), 'BIN': str(self.bin), 'LOG': str(self.d / 'log'), 'RT_ROOT': str(self.root),
             'GNUPGHOME': str(self.d / 'gnupg'), 'HOME': str(self.d), 'AVAIL': '', **env}
        p = subprocess.run([str(self.real / 'bash'), '-c', HARNESS + f'APPLY={int(apply)}\n' + steps_runtime.BASH + '\n' + call + '\nexit $((PROBLEMS > 0))\n'],
                           capture_output=True, text=True, timeout=60, env=e)
        return p.stdout + p.stderr

    def log(self):
        return (self.d / 'log').read_text() if (self.d / 'log').exists() else ''

    def tree(self):
        return sorted((str(p.relative_to(self.root)), p.read_bytes() if p.is_file() else b'') for p in self.root.rglob('*'))

    # ── the report: present, installable, blocked, and it changes nothing ──
    def test_the_report_says_installable_and_changes_nothing(self):
        self.host('debian13')
        before = self.tree()
        out = self.run_step(False, 'podman', rootless='1', user='alice', AVAIL='podman buildah skopeo uidmap passt')
        self.assertIn('missing: installable: podman buildah skopeo uidmap, and when there passt, from the debian repositories', out)
        self.assertIn('ok: cgroup v2', out)
        self.assertIn('would: give alice 65536 subordinate ids from 100000 in /etc/subuid', out)
        self.assertEqual(self.tree(), before)
        self.assertNotRegex(self.log(), r'(?m)^(apt-get install|systemctl enable|loginctl|usermod)')

    def test_present_is_said_with_its_version(self):
        self.host('arch')
        stub(self.bin, 'docker', 'echo "Docker version 27.5.1, build 9f9e405"')
        out = self.run_step(False, 'docker', UNITS='docker.service')
        self.assertIn('ok: present: Docker version 27.5.1, build 9f9e405', out)
        self.assertIn('would: systemctl enable --now docker.service', out)

    def test_blocked_says_why(self):
        cases = [
            ('rocky', 'docker', 'distro', {}, 'blocked: rocky carries Podman and not Docker: choose the Docker repository as the source, or Podman'),
            ('debian12', 'incus', 'distro', {'AVAIL': 'lxc'}, 'blocked: incus is not in the repositories this host has: Debian 12 has it in bookworm-backports'),
            ('suse', 'docker', 'vendor', {}, 'blocked: Docker publishes no repository for opensuse-tumbleweed'),
            ('debian13', 'podman', 'vendor', {}, 'blocked: only Docker is installed from a repository of its own'),
            ('debian13', 'podman', 'distro', {'AVAIL': 'podman buildah skopeo uidmap', 'FREE_KB': '512000'}, 'blocked: only 500 MiB free under /var/lib'),
            ('debian13', 'libvirt', 'distro', {'ARCH': 'riscv64'}, 'blocked: libvirt is set up here for x86_64 and aarch64, and this is riscv64'),
        ]
        for distro, rt, src, env, said in cases:
            self.host(distro)
            out = self.run_step(True, rt, src, **env)
            self.assertIn(said, out, (distro, rt))
            self.assertNotIn('doing: install', out)
        self.assertNotRegex(self.log(), r'(?m)^(apt-get|dnf|zypper) .*install')

    def test_an_image_based_system_is_blocked(self):
        self.host('fedora')
        (self.root / 'run').mkdir()
        (self.root / 'run/ostree-booted').touch()
        self.assertIn('blocked: an image-based system (rpm-ostree)', self.run_step(True, 'podman', AVAIL='podman'))

    def test_rootless_is_blocked_without_user_namespaces_or_the_account(self):
        self.host('debian13')
        avail = {'AVAIL': 'podman buildah skopeo uidmap'}
        self.assertIn('blocked: there is no account bob on this host', self.run_step(True, 'podman', rootless='1', user='bob', **avail))
        (self.root / 'proc/sys/user/max_user_namespaces').write_text('0\n')
        self.assertIn('blocked: user namespaces are turned off', self.run_step(True, 'podman', rootless='1', user='alice', **avail))
        self.assertNotIn('podman', (self.d / 'installed').read_text() if (self.d / 'installed').exists() else '')

    def test_a_docker_that_is_podman_is_not_docker(self):
        self.host('fedora')
        stub(self.bin, 'docker', 'echo "podman version 5.4.0"')
        out = self.run_step(True, 'docker', AVAIL='moby-engine docker-compose')
        self.assertIn('blocked: docker here is the Podman shim (podman-docker): remove it first', out)

    def test_libvirt_says_what_the_cpu_offers(self):
        self.host('fedora')
        env = {'AVAIL': 'qemu-kvm libvirt virt-install edk2-ovmf swtpm'}
        self.assertIn('info: no hardware virtualization here (no vmx or svm, no /dev/kvm): VMs would run emulated', self.run_step(False, 'libvirt', **env))
        (self.root / 'dev').mkdir()
        (self.root / 'dev/kvm').touch()
        (self.root / 'sys/module/kvm_intel/parameters').mkdir(parents=True)
        (self.root / 'sys/module/kvm_intel/parameters/nested').write_text('Y\n')
        (self.root / 'sys/class/net/br0').mkdir(parents=True)
        out = self.run_step(False, 'libvirt', FSTYPE='btrfs', **env)
        for said in ('ok: hardware virtualization: /dev/kvm is there', 'info: nested virtualization is on', 'br0 exists: libvirt makes virbr0',
                     'chattr +C on /var/lib/libvirt/images', 'missing: installable: qemu-kvm libvirt virt-install edk2-ovmf, and when there swtpm'):
            self.assertIn(said, out)

    # ── an apply ──
    def test_podman_rootless_on_debian(self):
        self.host('debian13')
        (self.root / 'etc/subuid').write_text('bob:100000:65536\n')
        out = self.run_step(True, 'podman', rootless='1', user='alice', AVAIL='podman buildah skopeo uidmap passt')
        self.assertIn('ok: installed: podman version 5.4.0', out)
        self.assertIn('apt-get -o DPkg::Lock::Timeout=120 install -y -qq podman buildah skopeo uidmap passt', self.log())
        self.assertEqual((self.root / 'etc/subuid').read_text(), 'bob:100000:65536\nalice:165536:65536\n')
        self.assertEqual((self.root / 'etc/subgid').read_text(), 'alice:100000:65536\n')
        self.assertTrue((self.root / 'var/lib/systemd/linger/alice').exists())
        self.assertIn('systemctl --user -M alice@ enable --now podman.socket', self.log())
        again = self.run_step(True, 'podman', rootless='1', user='alice', AVAIL='podman buildah skopeo uidmap passt')
        self.assertIn('ok: present: podman version 5.4.0', again)
        self.assertIn('ok: alice has subordinate ids in /etc/subuid', again)
        self.assertEqual((self.root / 'etc/subuid').read_text().count('alice'), 1)

    def test_docker_from_the_distribution_writes_log_limits_once(self):
        self.host('ubuntu')
        out = self.run_step(True, 'docker', AVAIL='docker.io docker-compose-v2', UNITS='docker.service')
        self.assertIn('ok: installed: Docker version 26.1.5', out)
        self.assertIn('install -y -qq docker.io docker-compose-v2', self.log())
        self.assertIn('"max-size": "10m"', (self.root / 'etc/docker/daemon.json').read_text())
        self.assertIn('systemctl enable --now docker.service', self.log())
        (self.root / 'etc/docker/daemon.json').write_text('{"mine": true}\n')
        self.assertIn('left as it is', self.run_step(True, 'docker', AVAIL='docker.io'))
        self.assertEqual((self.root / 'etc/docker/daemon.json').read_text(), '{"mine": true}\n')

    def test_each_family_installs_its_own_packages(self):
        for distro, rt, avail, want in (
                ('arch', 'docker', 'docker docker-compose', 'pacman -S --needed --noconfirm docker docker-compose'),
                ('suse', 'podman', 'podman buildah skopeo', 'zypper -n -q install podman buildah skopeo'),
                ('fedora', 'libvirt', 'qemu-kvm libvirt virt-install edk2-ovmf', 'dnf install -y -q qemu-kvm libvirt virt-install edk2-ovmf'),
                ('fedora', 'incus', 'incus', 'dnf install -y -q incus')):
            with self.subTest(distro=distro, rt=rt):
                self.host(distro)
                out = self.run_step(True, rt, AVAIL=avail, UNITS='virtqemud.socket incus.socket')
                self.assertIn('ok: installed', out)
                self.assertIn(want, self.log())
        self.assertIn('systemctl enable --now virtqemud.socket', self.log())
        self.assertIn('ok: incus has a storage pool', self.run_step(False, 'incus', AVAIL='incus'))       # init --minimal ran once

    def test_lxc_on_rocky_comes_from_epel(self):
        self.host('rocky')
        out = self.run_step(False, 'lxc', AVAIL='epel-release', EPEL='lxc lxc-templates')
        self.assertIn('installable: lxc, and when there lxc-templates, from the rocky repositories and EPEL', out)
        out = self.run_step(True, 'lxc', rootless='1', user='alice', AVAIL='epel-release', EPEL='lxc lxc-templates', UNITS='lxc-net.service')
        self.assertIn('ok: installed: lxc 6.0.3', out)
        self.assertLess(self.log().index('install -y -q epel-release'), self.log().index('install -y -q lxc lxc-templates'))
        self.assertEqual((self.root / 'etc/lxc/lxc-usernet').read_text(), 'alice veth lxcbr0 10\n')

    # ── the Docker repository and its pinned key ──
    def make_key(self, name):
        subprocess.run(['gpg', '--batch', '--passphrase', '', '--quick-gen-key', f'{name} <{name}@example.invalid>', 'ed25519', 'sign', 'never'],
                       env={**os.environ, 'GNUPGHOME': str(self.d / 'gnupg')}, capture_output=True, check=True, timeout=60)
        out = subprocess.run(['gpg', '--batch', '--with-colons', '--fingerprint', name], env={**os.environ, 'GNUPGHOME': str(self.d / 'gnupg')},
                             capture_output=True, text=True, check=True).stdout
        return next(line.split(':')[9] for line in out.splitlines() if line.startswith('fpr:'))

    def export(self, *names):
        f = self.d / ('key-' + '-'.join(names))
        f.write_bytes(subprocess.run(['gpg', '--batch', '--armor', '--export', *names], env={**os.environ, 'GNUPGHOME': str(self.d / 'gnupg')},
                                     capture_output=True, check=True).stdout)
        return f

    def with_pin(self, fpr):
        return mock.patch.object(steps_runtime, 'BASH', steps_runtime.BASH.replace(steps_runtime.DOCKER_APT_FPR, fpr).replace(steps_runtime.DOCKER_RPM_FPR, fpr))

    @unittest.skipUnless(shutil.which('gpg'), 'needs gpg')
    def test_the_docker_key_is_installed_only_when_it_is_the_pinned_one(self):
        self.host('ubuntu')
        (self.root / 'etc/apt/sources.list.d').mkdir(parents=True)
        good, evil = self.make_key('docker-test'), self.make_key('someone-else')
        pkgs = 'docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin'
        with self.with_pin(good):
            out = self.run_step(True, 'docker', 'vendor', AVAIL=pkgs, KEYFILE=str(self.export('someone-else')))
            self.assertIn(f'the key at https://download.docker.com/linux/ubuntu/gpg is not the pinned one (fingerprint {evil}', out)
            out = self.run_step(True, 'docker', 'vendor', AVAIL=pkgs, KEYFILE=str(self.export('docker-test', 'someone-else')))
            self.assertIn('2 keys', out)                                   # the right key with another beside it: apt would trust both
            self.assertFalse((self.root / 'etc/apt/keyrings/docker.asc').exists())
            self.assertNotIn('docker-ce', self.log().split('curl', 1)[-1].replace('linux/ubuntu', ''))
            out = self.run_step(True, 'docker', 'vendor', AVAIL=pkgs, KEYFILE=str(self.export('docker-test')))
        self.assertIn(f'ok: Docker signing key {good} installed at /etc/apt/keyrings/docker.asc', out)
        self.assertIn('ok: installed: Docker version 28.0.1', out)
        self.assertEqual((self.root / 'etc/apt/sources.list.d/docker.list').read_text(),
                         'deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu noble stable\n')
        self.assertIn('curl -fsSL --proto =https --tlsv1.2 --retry 3 -o', self.log())
        self.assertNotRegex(self.log(), r'(?m)^(sh|bash) ')                 # nothing downloaded is run

    @unittest.skipUnless(shutil.which('gpg'), 'needs gpg')
    def test_the_docker_repository_on_rocky(self):
        self.host('rocky')
        good = self.make_key('docker-rpm')
        with self.with_pin(good):
            report = self.run_step(False, 'docker', 'vendor', AVAIL='')
            self.assertIn('installable: docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin, from the Docker repository', report)
            out = self.run_step(True, 'docker', 'vendor', AVAIL='docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin',
                                KEYFILE=str(self.export('docker-rpm')))
        self.assertIn('ok: installed', out)
        repo = (self.root / 'etc/yum.repos.d/docker-ce.repo').read_text()
        self.assertIn('baseurl=https://download.docker.com/linux/centos/$releasever/$basearch/stable\n', repo)
        self.assertIn('gpgcheck=1\ngpgkey=file:///etc/pki/rpm-gpg/docker-ce.asc\n', repo)
        self.assertTrue((self.root / 'etc/pki/rpm-gpg/docker-ce.asc').exists())
        (self.d / 'installed').write_text('podman-docker\n')
        (self.bin / 'docker').unlink()
        self.assertIn('blocked: podman-docker is installed and conflicts with docker-ce', self.run_step(True, 'docker', 'vendor'))


class Check(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.db = dbfactory.make(self, self.tmp / 'index.db')
        self.conn = self.db.connect()
        self.addCleanup(self.conn.close)
        self.db.migrate(self.conn)
        self.conn.execute("INSERT INTO hosts (hostname, ssh_host, ssh_user, inventory_json) VALUES ('nas', 'nas', 'scan', '{}')")

    def said(self, pk, **p):
        items = []
        params = {'runtime': 'podman', 'source': 'distro', 'rootless': False, 'user': '', **p}
        with mock.patch('storageforge_index.pkglist.for_host', return_value=pk):
            steps_runtime._check(self.conn, None, {'name': 'nas'}, params, lambda level, text: items.append((level, text)))
        return items

    def test_what_the_scan_predicts(self):
        rocky = {'pm': 'dnf', 'distro': 'rocky', 'mode': 'normal'}
        self.assertIn(('crit', 'rocky carries Podman and not Docker: choose the Docker repository as the source, or Podman'), self.said(rocky, runtime='docker'))
        self.assertFalse([t for lvl, t in self.said(rocky, runtime='docker', source='vendor') if lvl == 'crit'])
        self.assertIn('crit', [lvl for lvl, _ in self.said({'pm': 'zypper', 'distro': 'opensuse-leap'}, runtime='docker', source='vendor')])
        self.assertIn('crit', [lvl for lvl, _ in self.said({'pm': 'rpm-ostree', 'distro': 'fedora', 'mode': 'image'})])
        self.assertIn('crit', [lvl for lvl, _ in self.said(None, runtime='incus', source='vendor')])
        self.assertIn('crit', [lvl for lvl, _ in self.said(None, runtime='docker', rootless=True, user='alice')])
        self.assertIn('crit', [lvl for lvl, _ in self.said(None, rootless=True, user='')])
        self.assertTrue(any('rescan nas' in t for _, t in self.said(None)))

    def test_the_plan_script_and_the_playbook(self):
        plan = {'name': 'runtime', 'tasks': [{'host': 'nas', 'type': 'runtime-install', 'params': {'runtime': 'libvirt', 'rootless': True, 'user': 'alice'}}]}
        text = changes.script(self.conn, plan)
        self.assertIn("run 1 nas runtime-install 'Install KVM and libvirt, rootless for alice' libvirt distro 1 alice", text)
        self.assertIn('t_runtime_install() {', text)
        self.assertNotIn('| sh', text.split('t_runtime_install() {')[1].split('\n}\n')[0])
        self.assertIn('t_runtime_install libvirt distro 1 alice', changes.ansible(self.conn, plan))
        self.assertEqual(changes.check(self.conn, plan)['tasks'][0]['items'][-1]['level'], 'note')


if __name__ == '__main__':
    unittest.main()
