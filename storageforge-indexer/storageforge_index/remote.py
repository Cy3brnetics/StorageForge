"""Agentless SSH transport and the read-only commands it runs on a target host.

Nothing is installed remotely. Commands go through the system OpenSSH client
with key authentication (BatchMode, so it never prompts), and one multiplexed
master connection (ControlMaster) carries the inventory probe, the parallel
per-mount `find` streams and the optional checksum pass.
"""
from __future__ import annotations

import base64
import hashlib
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


def child_env() -> dict:
    """The environment for ssh and local shells: ours without STORAGEFORGE_*, so a vault or session secret given as an
    environment variable never reaches a child process (or a ProxyCommand in someone's ssh config)."""
    return {k: v for k, v in os.environ.items() if not k.startswith('STORAGEFORGE_')}


def key_fingerprint(b64: str) -> str | None:
    """OpenSSH's SHA256:… fingerprint of a base64 public key blob."""
    try:
        blob = base64.b64decode(b64, validate=True)
    except ValueError:
        return None
    return 'SHA256:' + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip('=')


def known_hosts_name(host: str, port: int | None) -> str:
    addr = host.strip('[]')
    return addr if port in (None, 22) else f'[{addr}]:{port}'


def known_host_keys(host: str, port: int | None = 22, known_hosts: str | None = None) -> list[str]:
    """Fingerprints of the keys known_hosts holds for host:port (none: never connected)."""
    argv = ['ssh-keygen', '-F', known_hosts_name(host, port)] + (['-f', known_hosts] if known_hosts else [])
    try:
        out = subprocess.run(argv, capture_output=True, text=True, timeout=10, env=child_env()).stdout
    except (OSError, subprocess.TimeoutExpired):
        return []
    fps = set()
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 3 or line.startswith('#') or parts[0].startswith('@'):   # comments, @cert-authority, @revoked
            continue
        if fp := key_fingerprint(parts[2]):
            fps.add(fp)
    return sorted(fps)


# What a host may send back for one inventory, Docker or git survey (the file index streams separately). A host that was
# taken over could otherwise print until the StorageForge container runs out of memory.
MAX_REMOTE_OUTPUT = 64 << 20


def read_capped(proc: subprocess.Popen, what: str, limit: int = MAX_REMOTE_OUTPUT) -> bytes:
    """proc's stdout, at most limit bytes: beyond that the process is killed and RemoteError raised."""
    chunks, size = [], 0
    while chunk := proc.stdout.read(1 << 20):
        size += len(chunk)
        if size > limit:
            proc.kill()
            raise RemoteError(f'{what}: the host sent more than {limit >> 20} MiB; refused')
        chunks.append(chunk)
    return b''.join(chunks)


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
    strict: bool = False               # only a host key already in known_hosts (password flows); else trust on first use

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
            '-o', 'StrictHostKeyChecking=' + ('yes' if self.strict else 'accept-new'),
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
        return argv + ['--', self.target, 'sh -c ' + shlex.quote(script)]      # --: a target is never an option

    def host_keys(self) -> list[str]:
        """SHA-256 fingerprints of the host keys ssh verified for this address (known_hosts): what the machine
        proved by holding the private keys, unlike anything it prints about itself. ['local'] for local scans."""
        return ['local'] if self.local else known_host_keys(self.host, self.port, self.known_hosts)

    def run(self, script: str, timeout: int = 120) -> str:
        proc = subprocess.Popen(self.argv(script), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                stdin=subprocess.DEVNULL, env=child_env())
        expired = threading.Event()
        timer = threading.Timer(timeout, lambda: (expired.set(), proc.kill()))
        timer.start()
        err = StderrTail(proc.stderr)
        try:
            out = read_capped(proc, f'ssh {self.target}')
            rc = proc.wait()
        finally:
            timer.cancel()
            err.join(5)
            proc.stdout.close()
            proc.stderr.close()
        if expired.is_set():
            raise subprocess.TimeoutExpired(self.argv(script), timeout)
        if rc == 255 and not self.local:
            raise RemoteError(f'ssh {self.target}: {" ".join(err.tail).strip() or "connection failed"}')
        return out.decode('utf-8', 'replace')

    def stream(self, script: str, stdin: bool = False) -> subprocess.Popen:
        return subprocess.Popen(self.argv(script), stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=child_env(),
                                stdin=subprocess.PIPE if stdin else subprocess.DEVNULL, bufsize=1 << 20)

    def close(self):
        if self._ctl_dir:
            subprocess.run(self._base() + ['-O', 'exit', self.target], capture_output=True, env=child_env())
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
        for line in iter(lambda: self.pipe.readline(1 << 16), b''):     # a line without an end is read in pieces
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
echo '@@machineid'; cat /etc/machine-id 2>/dev/null || cat /var/lib/dbus/machine-id 2>/dev/null
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
echo '@@jobs'; for f in /var/lib/storageforge/jobs/*/runs.jsonl; do [ -r "$f" ] && tail -n 50 "$f"; done
echo '@@managed'; for f in /var/lib/storageforge/managed/*.sha256; do [ -r "$f" ] || continue; echo "## $(basename "$f" .sha256)"; sha256sum -c "$f" 2>&1 | tail -n 300; done
for f in /var/lib/storageforge/managed/*.lines; do [ -r "$f" ] || continue; echo "## $(basename "$f" .lines)"; while IFS= read -r l; do if grep -Fxq -- "$l" /etc/fstab 2>/dev/null; then echo "LINE-OK $l"; else echo "LINE-MISSING $l"; fi; done <"$f"; done
for t in /etc/systemd/system/sf-job-*.timer; do [ -e "$t" ] && echo "TIMER $(basename "$t") $(systemctl is-enabled "$(basename "$t")" 2>/dev/null)"; done
echo '@@ids'; getent passwd 2>/dev/null | awk -F: '$3>=1000 && $3<60000 {print "u " $1 " " $3}'; getent group 2>/dev/null | awk -F: '$3>=1000 && $3<60000 {print "g " $1 " " $3}'
echo '@@nfs'; cat /var/lib/nfs/etab 2>/dev/null || cat /etc/exports /etc/exports.d/*.exports 2>/dev/null
echo '@@smb'; if command -v smbd >/dev/null 2>&1 || [ -f /etc/samba/smb.conf ]; then
  pgrep -x smbd >/dev/null 2>&1 && echo '# smbd running'; testparm -s 2>/dev/null || cat /etc/samba/smb.conf 2>/dev/null; fi
echo '@@packages'; (PATH="$PATH:/usr/sbin:/sbin"; for m in apt-get dnf yum zypper pacman; do command -v "$m" >/dev/null 2>&1 && { echo "pm $m"; break; }; done
  for c in exportfs smbd mount.nfs mount.cifs rsync rsnapshot; do command -v "$c" >/dev/null 2>&1 && echo "have $c"; done)
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
    jobs: str = ''    # run lines of StorageForge jobs (the fallback when a run could not report)
    managed: str = '' # sha256sum -c of what deploys wrote, StorageForge fstab lines, job timers (drift)
    ids: str = ''     # users and groups with UID/GID >= 1000 (NFS ownership check)
    packages: str = ''  # the package manager, and which NFS, SMB, rsync and rsnapshot programs are installed (what a deploy would add)
    machine_id: str = ''  # /etc/machine-id: signed into deploy requests (self-reported, so never used as identity)

    def to_json(self) -> str:
        return json.dumps({
            'collected_at': dt.datetime.now(dt.timezone.utc).isoformat(timespec='seconds'),
            'lsblk': self.lsblk, 'zpool_status': self.zpool_status, 'df': self.df, 'lvs': self.lvs, 'access': self.access, 'scan_user': self.user, 'nfs': self.nfs, 'smb': self.smb, 'btrfs': self.btrfs,
            'jobs': self.jobs, 'managed': self.managed, 'ids': self.ids, 'packages': self.packages,
            'mounts': [asdict(m) for m in self.mounts],
        })


# the section headers the inventory script prints: a line of a file it shows (fstab, exports, a job log) can start
# with @@ too, and must stay in its section
SECTIONS = frozenset(re.findall(r"echo '@@(\w+)'", INVENTORY_SCRIPT))


def parse_sections(text: str) -> dict[str, str]:
    """Sections up to @@end. One cut short (the output stopped before the next header) is left out."""
    out, cur, buf = {}, None, []
    for line in text.splitlines():
        if line.startswith('@@') and line[2:].strip() in SECTIONS:
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
        # the mount's own options, then the filesystem's (subvolid=, compress=, vers=), as findmnt shows them
        opts = list(dict.fromkeys(a[5].split(',') + (b[2].split(',') if len(b) > 2 else [])))
        out.append(MountInfo(target=target, source=_unoctal(b[1]), fstype=b[0], options=','.join(opts),
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
                         btrfs=sec.get('btrfs', '').strip(), jobs=sec.get('jobs', '').strip(),
                         managed=sec.get('managed', '').strip(), ids=sec.get('ids', '').strip(),
                         packages=sec.get('packages', '').strip(),
                         machine_id=next((m for m in lines('machineid') if re.fullmatch(r'[0-9a-f]{32}', m)), ''))
