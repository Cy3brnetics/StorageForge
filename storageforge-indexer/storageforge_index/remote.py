"""Agentless SSH transport and the read-only commands it runs on a target host.

Nothing is installed remotely. Commands go through the system OpenSSH client
with key authentication (BatchMode, so it never prompts), and one multiplexed
master connection (ControlMaster) carries the inventory probe, the parallel
per-mount `find` streams and the optional checksum pass.
"""
from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import subprocess
import tempfile
import threading
import datetime as dt
from collections import deque
from dataclasses import asdict, dataclass, field

from .stream import FIND_FORMAT

PSEUDO_FS = frozenset({
    'proc', 'sysfs', 'devtmpfs', 'devpts', 'securityfs', 'cgroup', 'cgroup2', 'pstore', 'efivarfs',
    'bpf', 'debugfs', 'tracefs', 'configfs', 'fusectl', 'hugetlbfs', 'mqueue', 'autofs', 'binfmt_misc',
    'rpc_pipefs', 'nsfs', 'selinuxfs', 'nfsd', 'squashfs', 'overlay', 'fuse.portal', 'fuse.gvfsd-fuse',
    'fuse.lxcfs', 'ramfs', 'zram',
})
TMP_FS = frozenset({'tmpfs'})
NETWORK_FS = frozenset({
    'nfs', 'nfs4', 'cifs', 'smb3', 'smbfs', 'sshfs', 'fuse.sshfs', 'fuse.rclone', 'rclone', 'davfs',
    'fuse.s3fs', 'fuse.gcsfuse', 'glusterfs', 'fuse.glusterfs', 'ceph', 'fuse.ceph', '9p', 'afs',
    'lustre', 'beegfs', 'fuse.juicefs',
})
DEFAULT_EXCLUDE_PATHS = ('/proc', '/sys', '/dev', '/run')
RECORD_PRUNED = frozenset({'.git'})        # pruned names whose own entry is still indexed
DEFAULT_EXCLUDE_NAMES = ('.git', 'node_modules', '.Trash', '.Trash-*', '__pycache__', '.snapshots', '.zfs')


class RemoteError(RuntimeError):
    pass


def is_under(path: str, root: str) -> bool:
    if root == '/':
        return path.startswith('/')
    return path == root or path.startswith(root.rstrip('/') + '/')


def glob_escape(path: str) -> str:
    """Escape a literal path for find's -path, which treats it as a glob."""
    return re.sub(r'([\[\]*?\\])', r'\\\1', path)


@dataclass
class Transport:
    host: str
    user: str | None = None
    key: str | None = None
    port: int = 22
    local: bool = False
    connect_timeout: int = 10
    extra_opts: list[str] = field(default_factory=list)
    agent_sock: str | None = None      # vault-managed ephemeral agent
    known_hosts: str | None = None     # persistent known_hosts (trust on first use)
    isolated: bool = False             # ignore ~/.ssh/config so only vault settings apply

    def __post_init__(self):
        self._ctl_dir = None if self.local else tempfile.mkdtemp(prefix='sfidx-ssh-')

    @property
    def target(self) -> str:
        return f'{self.user}@{self.host}' if self.user else self.host

    def _base(self) -> list[str]:
        return ['ssh', '-p', str(self.port), '-o', f'ControlPath={self._ctl_dir}/%C']

    def argv(self, script: str) -> list[str]:
        if self.local:
            return ['/bin/sh', '-c', script]
        argv = self._base() + [
            '-T', '-o', 'BatchMode=yes', '-o', f'ConnectTimeout={self.connect_timeout}',
            '-o', 'ServerAliveInterval=30', '-o', 'ServerAliveCountMax=4',
            '-o', 'StrictHostKeyChecking=accept-new',
            '-o', 'ControlMaster=auto', '-o', 'ControlPersist=120',
        ]
        if self.isolated:
            argv[1:1] = ['-F', '/dev/null']
        if self.known_hosts:
            argv += ['-o', f'UserKnownHostsFile={self.known_hosts}', '-o', 'GlobalKnownHostsFile=/dev/null']
        if self.agent_sock:
            argv += ['-o', f'IdentityAgent={self.agent_sock}', '-o', 'IdentitiesOnly=no',
                     '-o', 'PasswordAuthentication=no', '-o', 'KbdInteractiveAuthentication=no']
        elif self.key:
            argv += ['-i', os.path.expanduser(self.key), '-o', 'IdentitiesOnly=yes']
        for opt in self.extra_opts:
            argv += ['-o', opt]
        # The login shell might be fish or csh; always hand the script to POSIX sh.
        return argv + [self.target, 'sh -c ' + shlex.quote(script)]

    def run(self, script: str, timeout: int = 120) -> str:
        proc = subprocess.run(self.argv(script), capture_output=True, timeout=timeout)
        if proc.returncode == 255 and not self.local:
            raise RemoteError(f'ssh {self.target}: {proc.stderr.decode(errors="replace").strip() or "connection failed"}')
        return proc.stdout.decode('utf-8', 'replace')

    def stream(self, script: str, stdin: bool = False) -> subprocess.Popen:
        return subprocess.Popen(self.argv(script), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                stdin=subprocess.PIPE if stdin else subprocess.DEVNULL, bufsize=1 << 20)

    def close(self):
        if self._ctl_dir:
            subprocess.run(self._base() + ['-O', 'exit', self.target], capture_output=True)
            shutil.rmtree(self._ctl_dir, ignore_errors=True)
            self._ctl_dir = None


class StderrTail(threading.Thread):
    """Drains a stderr pipe so the remote process never blocks, keeping a count, the last lines and the first
    directories find could not read."""

    def __init__(self, pipe, keep: int = 5, keep_denied: int = 300):
        super().__init__(daemon=True)
        self.pipe, self.count, self.tail = pipe, 0, deque(maxlen=keep)
        self.denied, self.denied_count, self.keep_denied = [], 0, keep_denied
        self.start()

    def run(self):
        for line in iter(self.pipe.readline, b''):
            self.count += 1
            text = line.decode('utf-8', 'replace').rstrip()
            self.tail.append(text)
            m = DENIED.match(text)
            if m:
                self.denied_count += 1
                if len(self.denied) < self.keep_denied:
                    self.denied.append(m.group(1))


# find: '/srv/x': Permission denied   (LC_ALL=C quotes; UTF-8 locales use ‘ ’)
DENIED = re.compile(r"^\S*find: ['‘](.*)['’]: Permission denied$")


# Read-only scan access (storageforge_index.access): private copies of find and sha256sum carrying
# CAP_DAC_READ_SEARCH, executable only by the storageforge-scan group. Used when present, plain tools otherwise.
READONLY_DIR = '/usr/local/lib/storageforge'


def _tool(name: str) -> str:
    t = f'{READONLY_DIR}/{name}'           # used only if it runs: a capability the kernel refuses would break every scan
    probe = f'{t} / -maxdepth 0' if name == 'find' else f'{t} /dev/null'
    return f'"$({probe} >/dev/null 2>&1 && echo {t} || echo {name})"'


NICE = "$(command -v ionice >/dev/null 2>&1 && echo 'ionice -c3') nice -n 10 "


def find_command(root: str, prune_paths, prune_names, nice: bool = True) -> str:
    q = shlex.quote
    # .git is still pruned (its objects are noise), but the .git entry itself is recorded: it marks a repository
    keep = [n for n in prune_names if n in RECORD_PRUNED]
    tests = [f'-path {q(glob_escape(p))}' for p in prune_paths] + [f'-name {q(n)}' for n in prune_names if n not in keep]
    marks = ''.join(f"\\( -name {q(n)} -printf '{FIND_FORMAT}' -prune \\) -o " for n in keep)
    prune = marks + (f"\\( {' -o '.join(tests)} \\) -prune -o " if tests else '')
    # -P (default) never follows symlinks, so symlink loops cannot recurse; -xdev stays on one
    # filesystem and every other mount point below the root is pruned explicitly, which also
    # stops same-device bind mounts from being walked twice.
    return f"LC_ALL=C {NICE if nice else ''}{_tool('find')} -P {q(root)} -xdev {prune}-printf '{FIND_FORMAT}'"


def checksum_command(nice: bool = True) -> str:
    return f"LC_ALL=C {NICE if nice else ''}xargs -0 -r {_tool('sha256sum')} -z --"


INVENTORY_SCRIPT = r"""
echo '@@hostname'; hostname -f 2>/dev/null || hostname 2>/dev/null || uname -n
echo '@@ip'; hostname -I 2>/dev/null || ip -o -4 addr show scope global 2>/dev/null | awk '{print $4}'
echo '@@os'; (. /etc/os-release 2>/dev/null && echo "$PRETTY_NAME"); uname -srm
echo '@@lsblk'
lsblk -J -b -o NAME,PATH,SIZE,TYPE,FSTYPE,MOUNTPOINT,LABEL,UUID,PARTLABEL,SERIAL,MODEL,TRAN,ROTA,PTTYPE,START,LOG-SEC,PHY-SEC 2>/dev/null \
  || lsblk -J -b -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT,LABEL,UUID,SERIAL,MODEL,TRAN,ROTA 2>/dev/null
echo '@@zpool'; zpool status -P 2>/dev/null
echo '@@lvs'; lvs --reportformat json --units b --nosuffix -o vg_name,lv_name,segtype,lv_size,data_stripes,lv_health_status,copy_percent 2>/dev/null
echo '@@findmnt'; findmnt -J -b -l -o TARGET,SOURCE,FSTYPE,SIZE,USED,OPTIONS,MAJ:MIN,FSROOT 2>/dev/null
echo '@@mountinfo'; cat /proc/self/mountinfo 2>/dev/null
echo '@@df'; df -B1 -P 2>/dev/null
echo '@@btrfs'; for d in /sys/fs/btrfs/*-*/; do [ -d "$d" ] || continue; printf '%s\t%s\t%s\t%s\n' "$(basename "$d")" "$(ls -d "$d"allocation/data/*/ 2>/dev/null | xargs -rn1 basename | paste -sd, -)" "$(ls -d "$d"allocation/metadata/*/ 2>/dev/null | xargs -rn1 basename | paste -sd, -)" "$(cat "$d"label 2>/dev/null)"; done
echo '@@nfs'; cat /var/lib/nfs/etab 2>/dev/null || cat /etc/exports /etc/exports.d/*.exports 2>/dev/null
echo '@@smb'; if command -v smbd >/dev/null 2>&1 || [ -f /etc/samba/smb.conf ]; then
  pgrep -x smbd >/dev/null 2>&1 && echo '# smbd running'; testparm -s 2>/dev/null || cat /etc/samba/smb.conf 2>/dev/null; fi
echo '@@access'; if [ -x /usr/local/lib/storageforge/find ]; then echo capability; else echo user; fi; id -un 2>/dev/null
echo '@@end'
"""


@dataclass
class MountInfo:
    target: str
    source: str
    fstype: str
    options: str = ''
    majmin: str = ''
    fsroot: str = '/'
    total: int | None = None
    used: int | None = None


@dataclass
class HostInventory:
    hostname: str
    ip: str | None
    os_info: str | None
    mounts: list[MountInfo]
    lsblk: dict | None
    zpool_status: str
    df: str
    lvs: str = ''     # empty unless the scan user may run lvs; lsblk alone still shows LVM RAID legs
    access: str = ''  # 'capability' once read-only scan access is set up, else 'user'
    user: str = ''
    nfs: str = ''     # /var/lib/nfs/etab (live exports) or /etc/exports
    btrfs: str = ''   # per filesystem: uuid, data and metadata profiles, label (from /sys/fs/btrfs)
    smb: str = ''     # testparm -s or smb.conf

    def to_json(self) -> str:
        return json.dumps({
            'collected_at': dt.datetime.now(dt.timezone.utc).isoformat(timespec='seconds'),
            'lsblk': self.lsblk, 'zpool_status': self.zpool_status, 'df': self.df, 'lvs': self.lvs, 'access': self.access, 'scan_user': self.user, 'nfs': self.nfs, 'smb': self.smb, 'btrfs': self.btrfs,
            'mounts': [asdict(m) for m in self.mounts],
        })


def parse_sections(text: str) -> dict[str, str]:
    out, cur, buf = {}, None, []
    for line in text.splitlines():
        if line.startswith('@@'):
            if cur:
                out[cur] = '\n'.join(buf)
            cur, buf = line[2:].strip(), []
        else:
            buf.append(line)
    return out


def _int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _unoctal(s: str) -> str:
    return re.sub(r'\\([0-7]{3})', lambda m: chr(int(m.group(1), 8)), s)


def parse_findmnt(text: str) -> list[MountInfo]:
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return []
    out = []

    def walk(items):
        for fs in items or []:
            out.append(MountInfo(target=fs.get('target') or '', source=fs.get('source') or '',
                                 fstype=fs.get('fstype') or '', options=fs.get('options') or '',
                                 majmin=fs.get('maj:min') or '', fsroot=fs.get('fsroot') or '/',
                                 total=_int(fs.get('size')), used=_int(fs.get('used'))))
            walk(fs.get('children'))
    walk(data.get('filesystems'))
    return [m for m in out if m.target]


def parse_mountinfo(text: str, df_text: str = '') -> list[MountInfo]:
    sizes = {}
    for line in df_text.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 6:
            sizes[' '.join(parts[5:])] = (_int(parts[1]), _int(parts[2]))
    out = []
    for line in text.splitlines():
        left, sep, right = line.partition(' - ')
        if not sep:
            continue
        a, b = left.split(), right.split()
        if len(a) < 6 or len(b) < 2:
            continue
        target = _unoctal(a[4])
        total, used = sizes.get(target, (None, None))
        out.append(MountInfo(target=target, source=_unoctal(b[1]), fstype=b[0], options=a[5],
                             majmin=a[2], fsroot=_unoctal(a[3]), total=total, used=used))
    return out


def collect_inventory(t: Transport) -> HostInventory:
    sec = parse_sections(t.run(INVENTORY_SCRIPT, timeout=90))

    def lines(key):
        return [l.strip() for l in sec.get(key, '').splitlines() if l.strip()]

    hostname = (lines('hostname') or [t.host])[0]
    ips = ' '.join(lines('ip')).split()
    ip = ips[0].split('/')[0] if ips else (None if t.local else t.host)
    try:
        lsblk = json.loads(sec['lsblk']) if sec.get('lsblk', '').strip() else None
    except ValueError:
        lsblk = None
    mounts = parse_findmnt(sec.get('findmnt', '')) or parse_mountinfo(sec.get('mountinfo', ''), sec.get('df', ''))
    if not mounts:
        raise RemoteError(f'{t.host}: could not read the mount table (findmnt and /proc/self/mountinfo both failed)')
    access, user = (lines('access') + ['', ''])[:2]
    return HostInventory(hostname, ip, ' · '.join(lines('os')) or None, mounts, lsblk,   # optional fields by name: order-proof
                         sec.get('zpool', '').strip(), sec.get('df', '').strip(), lvs=sec.get('lvs', '').strip(),
                         access=access, user=user, nfs=sec.get('nfs', '').strip(), smb=sec.get('smb', '').strip(),
                         btrfs=sec.get('btrfs', '').strip())
