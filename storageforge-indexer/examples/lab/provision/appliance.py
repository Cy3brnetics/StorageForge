#!/usr/bin/env python3
"""Installs an appliance from its vendor's ISO onto an existing, defined-here VM, with nobody at the console. These
systems have no cloud images, so lab.sh calls this in place of cloud-init. Afterwards the VM is running from its disk, with
the same lab, sfadmin and scan accounts as every other config.

    appliance.py proxmox|xcp-ng|truenas <name> <ip> <network> <vm dir> <iso> <pubkey file> <password file> <root GB> <RAM MB> <vcpus> <data GB,...>
"""
import base64
import gzip
import json
import os
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from pathlib import Path

PROXMOX_REPO = 'deb http://download.proxmox.com/debian/pve trixie pve-no-subscription'
PROXMOX_KEY = 'https://enterprise.proxmox.com/debian/proxmox-archive-keyring-trixie.gpg'
INSTALL_SECS = 1800
MIN_INSTALLED = 500 << 20


def run(*argv, **kw):
    return subprocess.run(argv, check=True, text=True, **kw)


def virsh(*argv):
    return run('virsh', *argv, capture_output=True).stdout.strip()


def mac_of(ip):
    return f'52:54:00:77:00:{int(ip.rsplit(".", 1)[1]):02x}'


class Vm:
    def __init__(self, a):
        self.kind, self.name, self.ip, self.net = a[:4]
        self.dir, self.iso = Path(a[4]), a[5]
        self.pubkey = Path(a[6]).read_text().strip()
        self.password = Path(a[7]).read_text().strip()
        self.root, self.ram, self.vcpus = a[8:11]
        self.data = [d for d in a[11].split(',') if d] if len(a) > 11 else []
        self.fqdn = f'{self.name}.lab'
        self.console_port = 44000 + int(self.ip.rsplit('.', 1)[1])
        self.log_path = self.dir / f'{self.name}-console.log'
        self.console_text = ''

    def define(self, iso, bus='virtio'):
        """Root disk first and the ISO second, so the machine boots the ISO once the disk is blank and the disk after."""
        root = self.dir / f'{self.name}-root.qcow2'
        run('qemu-img', 'create', '-q', '-f', 'qcow2', str(root), f'{self.root}G')
        disks = ['--disk', f'path={root},format=qcow2,bus={bus},boot.order=1']
        for i, size in enumerate(self.data, 1):
            path = self.dir / f'{self.name}-data{i}.qcow2'
            run('qemu-img', 'create', '-q', '-f', 'qcow2', str(path), f'{size}G')
            disks += ['--disk', f'path={path},format=qcow2,bus={bus},serial=sflab-data{i}']
        run('virt-install', '--import', '--noautoconsole', '--noreboot', '--name', self.name, '--osinfo', 'detect=off,name=linux2022',
            '--vcpus', self.vcpus, '--memory', self.ram, '--cpu', 'host-passthrough', '--rng', '/dev/urandom',
            '--network', f'network={self.net},mac={mac_of(self.ip)},model=virtio',
            '--graphics', 'vnc,listen=127.0.0.1', '--serial', f'tcp,host=127.0.0.1:{self.console_port},mode=bind,protocol.type=raw', '--events', 'on_reboot=destroy',
            '--disk', f'path={iso},device=cdrom,bus=sata,readonly=on,boot.order=2', *disks, capture_output=True)
        virsh('metadata', self.name, os.environ.get('SFLAB_META', 'https://storageforge.invalid/sflab'), '--key', 'sflab', '--set', '<lab/>', '--config')
        if virsh('domstate', self.name).splitlines()[0] != 'running':
            virsh('start', self.name)
        self.watch_console()

    def watch_console(self):
        """Keeps what the serial console prints, in the log and in console_text for anything waiting on it."""
        def read():
            while True:
                try:
                    self.sock = socket.create_connection(('127.0.0.1', self.console_port), timeout=5)
                    self.sock.settimeout(None)
                    while chunk := self.sock.recv(65536):
                        text = chunk.decode('utf-8', 'replace')
                        self.console_text += text
                        # private: an install's console can show its password
                        with open(os.open(self.log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600), 'a') as log:
                            log.write(text)
                except OSError:
                    pass
                time.sleep(0.2)
        threading.Thread(target=read, daemon=True).start()

    def send(self, text):
        self.sock.sendall(text.encode())

    def wait_for(self, text, secs=600):
        """Blocks until the console has printed text since the last wait, and returns what came before it."""
        until = time.time() + secs
        while time.time() < until:
            if text in self.console_text:
                before, _, self.console_text = self.console_text.partition(text)
                return before
            time.sleep(0.5)
        raise SystemExit(f'{self.name}: the console never showed {text!r}. See {self.log_path}')

    def wait_for_code(self):
        time.sleep(1)
        return self.console_text[:1]

    def wait_off(self):
        until = time.time() + INSTALL_SECS
        while time.time() < until:
            if virsh('domstate', self.name).splitlines()[0] == 'shut off':
                return self.check_installed()
            time.sleep(5)
        raise SystemExit(f'{self.name}: the installer did not finish in {INSTALL_SECS} s')

    def check_installed(self):
        """A crash or an installer giving up also stops the VM, so stopping proves nothing: the disk must hold a system."""
        root = self.dir / f'{self.name}-root.qcow2'
        if root.stat().st_blocks * 512 < MIN_INSTALLED:
            raise SystemExit(f'{self.name}: the VM stopped with nothing on its disk. See {self.dir}/{self.name}-console.log')

    def finish(self):
        """The installer's reboot stopped the VM, as on_reboot=destroy asked. From here it boots its disk and reboots normally."""
        target = next(line.split()[2] for line in virsh('domblklist', self.name, '--details').splitlines() if ' cdrom ' in line)
        virsh('change-media', self.name, target, '--eject', '--config')
        xml = virsh('dumpxml', '--inactive', self.name).replace('<on_reboot>destroy</on_reboot>', '<on_reboot>restart</on_reboot>')
        run('virsh', 'define', '/dev/stdin', input=xml, capture_output=True)


def password_hash(password):
    return run('openssl', 'passwd', '-6', '-stdin', input=password, capture_output=True).stdout.strip()


def proxmox(vm):
    """Proxmox's own auto-installer. Its tool is a Debian package, so it runs in a throwaway container."""
    work = Path(tempfile.mkdtemp(prefix='sflab-pve-'))
    (work / 'answer.toml').write_text(f'''[global]
keyboard = "en-us"
country = "us"
fqdn = "{vm.fqdn}"
mailto = "root@lab.invalid"
timezone = "UTC"
root-password-hashed = "{password_hash(vm.password)}"
root-ssh-keys = ["{vm.pubkey}"]
reboot-mode = "power-off"

[network]
source = "from-dhcp"

[disk-setup]
filesystem = "ext4"
disk-list = ["vda"]
''')
    built = vm.dir / f'{vm.name}-install.iso'
    script = (f'set -e; apt-get update -qq; apt-get install -y -qq --no-install-recommends curl ca-certificates >/dev/null; '
              f'curl -fsSL {PROXMOX_KEY} -o /etc/apt/trusted.gpg.d/proxmox.gpg; echo "{PROXMOX_REPO}" >/etc/apt/sources.list.d/pve.list; '
              f'apt-get update -qq; apt-get install -y -qq --no-install-recommends proxmox-auto-install-assistant xorriso >/dev/null; '
              f'proxmox-auto-install-assistant prepare-iso /in/source.iso --fetch-from iso --answer-file /work/answer.toml --output /work/out.iso; '
              f'chmod 644 /work/out.iso')
    run('docker', 'run', '--rm', '-v', f'{vm.iso}:/in/source.iso:ro', '-v', f'{work}:/work', 'debian:trixie', 'sh', '-c', script)
    shutil.copy(work / 'out.iso', built)
    shutil.rmtree(work, ignore_errors=True)
    vm.define(built)
    vm.wait_off()
    vm.finish()
    built.unlink()


def cpio_newc(name, data):
    """One file as a cpio archive. The kernel unpacks every archive it finds in an initrd, so this adds a file to one."""
    def entry(path, body, mode):
        fields = (0, mode, 0, 0, 1, 0, len(body), 0, 0, 0, 0, len(path) + 1, 0)
        head = b'070701' + b''.join(b'%08X' % f for f in fields) + path.encode() + b'\0'
        return head + b'\0' * (-len(head) % 4) + body + b'\0' * (-len(body) % 4)
    return entry(name, data, 0o100644) + entry('TRAILER!!!', b'', 0)


def xcp_ng(vm):
    """The installer reads an answer file named on its kernel line. It goes inside the initrd, so nothing has to serve it."""
    work = Path(tempfile.mkdtemp(prefix='sflab-xcp-', dir=vm.dir))
    answer = f'''<?xml version="1.0"?>
<installation srtype="ext">
  <primary-disk>sda</primary-disk>
  <keymap>us</keymap>
  <root-password type="hash">{password_hash(vm.password)}</root-password>
  <source type="local"/>
  <admin-interface name="eth0" proto="dhcp"/>
  <hostname>{vm.name}</hostname>
  <timezone>UTC</timezone>
</installation>
'''
    run('xorriso', '-osirrox', 'on', '-indev', vm.iso, '-extract', '/install.img', str(work / 'install.img'),
        '-extract', '/boot/isolinux/isolinux.cfg', str(work / 'isolinux.cfg'), capture_output=True)
    for f in work.iterdir():
        f.chmod(0o644)
    with open(work / 'install.img', 'ab') as img:
        img.write(gzip.compress(cpio_newc('answerfile.xml', answer.encode())))
    cfg = (work / 'isolinux.cfg').read_text()
    cfg = cfg.replace('console=hvc0 console=tty0 --- /install.img', 'console=hvc0 console=tty0 answerfile=file:///answerfile.xml install --- /install.img', 1)
    (work / 'isolinux.cfg').write_text(cfg.replace('TIMEOUT 50', 'TIMEOUT 10'))
    built = vm.dir / f'{vm.name}-install.iso'
    run('xorriso', '-indev', vm.iso, '-outdev', str(built), '-boot_image', 'any', 'replay',
        '-map', str(work / 'install.img'), '/install.img', '-map', str(work / 'isolinux.cfg'), '/boot/isolinux/isolinux.cfg', capture_output=True)
    shutil.rmtree(work, ignore_errors=True)
    vm.define(built, bus='sata')       # its control domain's kernel may not drive virtio, and every install finds SATA
    vm.wait_off()
    vm.finish()
    built.unlink()


TRUENAS_INSTALL = '''
import asyncio
from truenas_installer.disks import list_disks
from truenas_installer.install import install
async def main():
    disks = {d.name: d for d in await list_disks()}
    await install([disks['vda']], [], False, {'username': 'truenas_admin', 'password': open('/tmp/pw').read().strip()}, {}, None, lambda p, m: print(m, flush=True))
asyncio.run(main())
'''


def truenas(vm):
    """No answer file exists, so this boots the ISO on its serial console, takes the menu's shell and calls the same
    install function the menu does."""
    vm.define(vm.iso)
    vm.wait_for('Start TrueNAS SCALE Installation')
    vm.send('j')                              # the boot menu's hotkey for its serial console entry
    vm.wait_for('Console Setup')
    time.sleep(3)
    vm.send('\x1b[B\r')                      # the menu's second item, Shell
    time.sleep(3)
    vm.send(f'stty -echo; echo {base64.b64encode(vm.password.encode()).decode()} | base64 -d >/tmp/pw; '
            f'echo {base64.b64encode(TRUENAS_INSTALL.encode()).decode()} | base64 -d >/tmp/i.py; stty echo; '
            f'python3 /tmp/i.py; echo SFLAB""-EXIT-$?\r')      # split, so the echoed command does not match
    tail = vm.wait_for('SFLAB-EXIT-', 1500)
    if vm.wait_for_code() != '0':
        raise SystemExit(f'{vm.name}: the install failed: {tail[-600:]}')
    vm.send('reboot\r')
    vm.wait_off()
    vm.finish()
    vm.log_path.unlink()                      # it holds the password, as the shell echoed it


def truenas_setup(vm):
    """A new TrueNAS has SSH off and no root login, so its API makes the pool, the lab's accounts and turns SSH on."""
    def api(method, path, body=None):
        req = urllib.request.Request(f'http://{vm.ip}/api/v2.0/{path}', method=method, data=None if body is None else json.dumps(body).encode(),
                                     headers={'Content-Type': 'application/json', 'Authorization': 'Basic ' +
                                              base64.b64encode(f'truenas_admin:{vm.password}'.encode()).decode()})
        with urllib.request.urlopen(req, timeout=120) as r:
            return json.loads(r.read() or 'null')

    def job(jid):
        until = time.time() + 300
        while time.time() < until:
            row = api('GET', f'core/get_jobs?id={jid}')[0]
            if row['state'] in ('SUCCESS', 'FAILED', 'ABORTED'):
                if row['state'] != 'SUCCESS':
                    raise SystemExit(f'{vm.name}: job {row["method"]}: {row["error"]}')
                return row['result']
            time.sleep(2)
        raise SystemExit(f'{vm.name}: job {jid} did not finish')

    until = time.time() + 900
    while True:
        try:
            if api('GET', 'system/ready'):
                break
        except (OSError, ValueError):
            pass
        if time.time() > until:
            raise SystemExit(f'{vm.name}: its API did not come up')
        time.sleep(5)
    if not api('GET', 'pool'):
        job(api('POST', 'pool', {'name': 'tank', 'topology': {'data': [{'type': 'MIRROR', 'disks': ['vdb', 'vdc']}]}}))
    have = {row['name'] for row in api('GET', 'pool/dataset')}
    for dataset in {'tank/home', 'tank/media', 'tank/backups'} - have:
        api('POST', 'pool/dataset', {'name': dataset})
    users = {row['username'] for row in api('GET', 'user')}
    for name, sudo in (('lab', ['ALL']), ('scan', [])):
        if name in users:
            continue
        api('POST', 'user', {'username': name, 'full_name': name, 'group_create': True, 'home': '/mnt/tank/home', 'home_create': True, 'smb': False,
                             'password_disabled': True, 'shell': '/usr/bin/bash', 'sshpubkey': vm.pubkey, 'sudo_commands_nopasswd': sudo})
    if 'sfadmin' not in users:
        api('POST', 'user', {'username': 'sfadmin', 'full_name': 'sfadmin', 'group_create': True, 'home': '/mnt/tank/home', 'home_create': True, 'smb': False,
                             'password': vm.password, 'shell': '/usr/bin/bash', 'sshpubkey': vm.pubkey, 'sudo_commands': ['ALL']})
    api('PUT', 'network/configuration', {'hostname': vm.name})
    ssh = next(row for row in api('GET', 'service') if row['service'] == 'ssh')
    api('PUT', f'service/id/{ssh["id"]}', {'enable': True})
    api('POST', 'service/start', {'service': 'ssh'})


ACCOUNTS = r"""set -eu
for u in lab sfadmin scan; do
  id "$u" >/dev/null 2>&1 || useradd -m -s /bin/sh "$u"
  usermod -p "$HASH" "$u"
  h=$(getent passwd "$u" | cut -d: -f6); mkdir -p "$h/.ssh"; echo "$KEY" >"$h/.ssh/authorized_keys"; chown -R "$u" "$h/.ssh"; chmod 700 "$h/.ssh"; chmod 600 "$h/.ssh/authorized_keys"
done
printf 'lab ALL=(ALL) NOPASSWD: ALL\nsfadmin ALL=(ALL) ALL\n' >/etc/sudoers.d/sflab; chmod 440 /etc/sudoers.d/sflab
"""
# Proxmox as a home lab runs it: the paid repositories off, the free one on, and sudo, which it does not ship.
PROXMOX_SETUP = r"""for f in /etc/apt/sources.list.d/pve-enterprise.sources /etc/apt/sources.list.d/ceph.sources; do
  [ -e "$f" ] && { grep -q '^Enabled:' "$f" && sed -i 's/^Enabled:.*/Enabled: no/' "$f" || echo 'Enabled: no' >>"$f"; }
done
cat >/etc/apt/sources.list.d/pve-no-subscription.sources <<EOF
Types: deb
URIs: http://download.proxmox.com/debian/pve
Suites: trixie
Components: pve-no-subscription
Signed-By: /usr/share/keyrings/proxmox-archive-keyring.gpg
EOF
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq; apt-get install -y -qq --no-install-recommends sudo >/dev/null
"""


def root_setup(vm, script):
    """Over root's SSH, with its password (XCP-ng's installer takes no key). A password only ever goes through askpass."""
    with tempfile.TemporaryDirectory() as tmp:
        askpass = Path(tmp) / 'askpass'
        askpass.write_text(f'#!/bin/sh\ncat {shlex.quote(str(Path(tmp) / "pw"))}\n')
        askpass.chmod(0o700)
        (Path(tmp) / 'pw').write_text(vm.password)
        env = {**os.environ, 'SSH_ASKPASS': str(askpass), 'SSH_ASKPASS_REQUIRE': 'force'}
        argv = ['ssh', '-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=/dev/null', '-o', 'LogLevel=ERROR', '-o', 'ConnectTimeout=5',
                '-o', 'PreferredAuthentications=password', f'root@{vm.ip}']
        until = time.time() + 900
        while subprocess.run([*argv, 'true'], env=env, stdin=subprocess.DEVNULL, capture_output=True, start_new_session=True).returncode:
            if time.time() > until:
                raise SystemExit(f'{vm.name}: no root login over SSH')
            time.sleep(5)
        head = f'KEY={shlex.quote(vm.pubkey)}\nHASH={shlex.quote(password_hash(vm.password))}\n'
        subprocess.run([*argv, 'sh -s'], env=env, input=head + script, text=True, check=True, start_new_session=True)


def setup(vm):
    virsh('start', vm.name)
    if vm.kind == 'truenas':
        truenas_setup(vm)
    elif vm.kind == 'proxmox':
        root_setup(vm, ACCOUNTS.replace('printf', PROXMOX_SETUP + 'printf', 1))
    else:
        root_setup(vm, ACCOUNTS)


if __name__ == '__main__':
    target = Vm(sys.argv[1:])
    {'proxmox': proxmox, 'xcp-ng': xcp_ng, 'truenas': truenas}[target.kind](target)
    setup(target)
