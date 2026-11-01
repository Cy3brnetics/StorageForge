"""Host configuration history: what it takes to rebuild a host after its system disk is reinstalled.

Each scan reads the host's config files (fstab, crypttab, mdadm.conf, exports, Samba) and accounts. build() joins them
with the mount table, drives, pools, cross-mount symlinks and the saved design, and capture() stores a new version
when any of that changed, so a host keeps a history in the database, and with it in every essentials backup.
reinstall.py turns a version into a script; bundle() packs versions into a .tar.gz to keep somewhere else.

Passwords in fstab options and Samba files are blanked when a scan reads them and never reach the database. Keys, Samba
password databases and account passwords are never read. The script says what the operator has to supply again.
"""
from __future__ import annotations

import base64
import binascii
import datetime as dt
import difflib
import hashlib
import io
import json
import os
import posixpath
import re
import tarfile
import time
from pathlib import Path

from .db import Conn, loads
from .moves import host_slug
from .payloads import node_from_index, shares_from_inventory
from .remote import NETWORK_FS, PSEUDO_FS, TMP_FS, is_under

KEEP = 30              # versions kept per host
CONFIG_PATH = re.compile(r'/etc/(fstab|crypttab|mdadm\.conf|mdadm/mdadm\.conf|exports|exports\.d/[\w.-]+\.exports'
                         r'|samba/[\w.-]+\.conf)')
REDACTED = '**removed**'
REBUILT_MARK = '# Rebuilt by StorageForge from '      # such a file says the same as the original, in other words
# fstab options (cifs password=, sshfs password_stdin stays), and smb.conf lines naming a password or secret
_OPT_SECRET = re.compile(r'(?<![\w-])(pass|passwd|password|password2|sec_key|secret)=[^\s,]*', re.I)
_SMB_SECRET = re.compile(r'^(\s*[^#;\s][^=\n]*(?:password|secret)[^=\n]*=).*$', re.I | re.M)
_CONTROL = re.compile(r'[\x00-\x08\x0a-\x1f\x7f\x85  ]')
_NAME = re.compile(r'[A-Za-z_][A-Za-z0-9_.-]{0,63}\$?')
_POOL = re.compile(r'[A-Za-z0-9][A-Za-z0-9._:-]*')
SYSTEM_TARGETS = ('/', '/boot', '/boot/efi', '/efi')
RUNTIME_ROOTS = ('/proc', '/sys', '/dev', '/run', '/tmp', '/var/lib/docker', '/var/lib/containers', '/var/lib/kubelet',
                 '/snap', '/var/snap')
# a symlink into one of these (/var/lock -> ../run/lock) belongs to the OS, and the new install makes its own
OS_TARGETS = ('/usr', '/run', '/etc', '/bin', '/sbin', '/lib', '/lib64', '/proc', '/sys', '/dev', '/var/lib', '/var/run', '/var/lock')
# what the kernel adds to a mount's options: a line built from the mount table leaves these out
_KERNEL_OPTS = ('rw', 'relatime', 'seclabel', 'ssd', 'attr2', 'inode64', 'noquota', 'user_xattr', 'acl', 'barrier',
                'discard=async')
_KERNEL_PREFIX = ('subvolid=', 'space_cache', 'logbufs=', 'logbsize=', 'sunit=', 'swidth=', 'stripe=', 'data=',
                  'errors=continue', 'fmask=', 'dmask=', 'codepage=', 'iocharset=', 'shortname=', 'utf8',
                  'iosize=', 'background_gc=', 'gc_merge', 'nogc_merge', 'discard_unit=', 'alloc_mode=', 'fsync_mode=',
                  'active_logs=', 'extent_cache', 'mode=', 'flush_merge', 'inline_', 'user_xattr', 'lazytime')


def parse_configs(text: str) -> dict:
    """The @@configs section: <path><TAB><base64>, or <path><TAB>! for a file the scan user may not read."""
    files, unreadable = {}, []
    for line in text.splitlines():
        path, _, data = line.partition('\t')
        if not CONFIG_PATH.fullmatch(path):
            continue
        if data == '!':
            unreadable.append(path)
            continue
        try:
            body = base64.b64decode(data, validate=True).decode('utf-8', 'surrogateescape')
        except (binascii.Error, ValueError):
            continue
        files[path] = _redact(path, body)
    return {'files': files, 'unreadable': unreadable}


def _redact(path: str, body: str) -> str:
    if path.startswith('/etc/samba/'):
        return _SMB_SECRET.sub(lambda m: f'{m.group(1)} {REDACTED}', body)
    if path == '/etc/fstab':
        return _OPT_SECRET.sub(lambda m: f'{m.group(1)}={REDACTED}', body)
    return body


def parse_accounts(text: str) -> dict:
    users, groups = [], []
    for line in text.splitlines():
        f = line.split('\t')
        if f[0] == 'u' and len(f) == 6 and _NAME.fullmatch(f[1]) and f[2].isdigit() and f[3].isdigit():
            users.append({'name': f[1], 'uid': int(f[2]), 'gid': int(f[3]), 'home': f[4], 'shell': f[5]})
        elif f[0] == 'g' and len(f) in (3, 4) and _NAME.fullmatch(f[1]) and f[2].isdigit():   # no members: the section's last line loses its tab
            groups.append({'name': f[1], 'gid': int(f[2]), 'members': sorted(m for m in (f[3:] or [''])[0].split(',') if _NAME.fullmatch(m))})
    names = {u['name'] for u in users}
    return {'users': sorted(users, key=lambda u: u['uid']),
            'groups': sorted(({**g, 'members': [m for m in g['members'] if m in names]} for g in groups), key=lambda g: g['gid'])}


def parse_fstab_lines(text: str) -> list[dict]:
    """fstab entries with their exact line, and their target and spec decoded."""
    out = []
    for raw in text.splitlines():
        parts = raw.split('#', 1)[0].split()
        if len(parts) < 3 or _CONTROL.search(raw):
            continue
        out.append({'spec': _unoctal(parts[0]), 'target': _unoctal(parts[1]), 'target_raw': parts[1], 'fstype': parts[2],
                    'options': parts[3] if len(parts) > 3 else 'defaults', 'line': raw.strip()})
    return out


def _unoctal(s: str) -> str:
    return re.sub(r'\\([0-7]{3})', lambda m: chr(int(m.group(1), 8)), s)


def _octal(s: str) -> str:
    return re.sub(r'[ \t\\#]', lambda m: f'\\{ord(m.group()):03o}', s)


def _uses_password(line: str) -> bool:
    return REDACTED in line or bool(re.search(r'(?<![\w-])(pass|passwd|password)=', line))


def _classify(e: dict, root_specs: set) -> str:
    """device | network | derived | zfs | virtual | system | rootfs"""
    fs, opts = e['fstype'], e['options'].split(',')
    if fs == 'swap' or e['target'] in SYSTEM_TARGETS or e['target'] in ('none', 'swap'):
        return 'system'
    if fs == 'zfs':
        return 'zfs'
    if fs in NETWORK_FS:
        return 'network'
    if 'bind' in opts or 'rbind' in opts or fs == 'fuse.mergerfs' or fs == 'mergerfs' or fs == 'overlay':
        return 'derived'
    if fs in PSEUDO_FS or fs in TMP_FS or fs.startswith('cgroup'):
        return 'virtual'
    if e['spec'] in root_specs:
        return 'rootfs'
    return 'device'


def _live_options(m: dict) -> list[str]:
    keep = [o for o in m.get('options') or [] if o and o not in _KERNEL_OPTS and not o.startswith(_KERNEL_PREFIX)]
    return [_OPT_SECRET.sub(lambda x: f'{x.group(1)}={REDACTED}', o) for o in keep]


def _live_entry(m: dict, uuids: dict) -> dict | None:
    """An fstab entry for a mount this host has but its fstab does not (mounted by hand or by a unit)."""
    target, fs = m['target'], m.get('fstype') or ''
    if _CONTROL.search(target) or any(is_under(target, r) for r in RUNTIME_ROOTS):
        return None
    if fs in PSEUDO_FS or fs in TMP_FS or fs.startswith('cgroup') or fs == 'zfs':
        return None
    if fs.startswith('fuse.') and fs not in NETWORK_FS and fs != 'fuse.mergerfs':
        return None
    opts = _live_options(m)
    if m.get('kind') == 'bind' and m.get('spec', '').startswith('/'):
        spec, fs, opts = m['spec'], 'none', ['bind']
    else:
        src = (m.get('source') or '').split('[')[0]       # /dev/sda1[/@data]: the device, and the subvolume in options
        spec = uuids.get(src) or src
        if not spec:
            return None
    if _CONTROL.search(spec):
        return None
    if 'bind' not in opts:      # it was never in fstab, so a missing drive must not hold up the next boot
        opts = list(dict.fromkeys([*opts, 'nofail', *(['_netdev'] if m.get('kind') == 'remote' else [])]))
    options = ','.join(opts) or 'defaults'
    line = f'{_octal(spec)} {_octal(target)} {fs} {options} 0 0'
    return {'spec': spec, 'target': target, 'target_raw': _octal(target), 'fstype': fs, 'options': options, 'line': line}


def _device_map(lsblk: dict | None) -> tuple[dict, list, list, bool]:
    """/dev path to UUID=, the drives a rebuild looks for, open LUKS mappings (name, UUID of what holds them), any LVM."""
    uuids, drives, crypts = {}, [], []
    lvm = False

    def walk(items, disk, parent):
        nonlocal lvm
        for b in items or []:
            path = b.get('path') or ('/dev/' + b['name'] if b.get('name') else None)
            kind = b.get('type')
            lvm = lvm or kind == 'lvm'
            this = (b.get('model'), b.get('serial')) if kind == 'disk' else disk
            if b.get('uuid') and path:
                # a mapper or LVM path is stable and says more than a UUID: keep those by name
                if not path.startswith('/dev/mapper/') and kind not in ('lvm', 'crypt'):
                    uuids[path] = 'UUID=' + b['uuid']
            if kind == 'crypt' and parent and parent.get('uuid') and b.get('name'):
                crypts.append({'name': b['name'], 'spec': 'UUID=' + parent['uuid']})
            if b.get('fstype') and b.get('uuid') and kind not in ('rom', 'loop'):
                drives.append({'uuid': b['uuid'], 'fstype': b['fstype'], 'label': b.get('label'), 'dev': path,
                               'model': (this or (None,))[0], 'serial': (this or (None, None))[1], 'size': b.get('size')})
            walk(b.get('children'), this, b)
    walk((lsblk or {}).get('blockdevices'), None, None)
    return uuids, drives, crypts, lvm


def _parse_crypttab(text: str) -> list[dict]:
    out = []
    for raw in text.splitlines():
        p = raw.split('#', 1)[0].split()
        if len(p) >= 2 and not _CONTROL.search(raw):
            out.append({'name': p[0], 'spec': p[1], 'key': p[2] if len(p) > 2 and p[2] not in ('none', '-') else None, 'line': raw.strip()})
    return out


def _links(node: dict, mounts: list[dict], design: dict | None) -> tuple[list, int]:
    """Symlinks worth putting back: ones that cross a mount, and any the design adds. A link on a data drive comes back with it."""
    rows = {}
    for l in node.get('links') or []:
        if l.get('kind') == 'symlink' and l.get('exists') is not False and l.get('cross_mount') \
                and not any(is_under(l.get('resolved') or '', r) for r in OS_TARGETS):
            rows[l['path']] = l['target']
    for l in (design or {}).get('links') or []:
        if l.get('kind') == 'symlink' and not l.get('fromScan') and l.get('path') and l.get('target'):
            rows.setdefault(l['path'], l['target'])
    clean = {p: t for p, t in rows.items() if p.startswith('/') and not _CONTROL.search(p + t)}
    roots = sorted((m['target'] for m in mounts if m['kind'] in ('device', 'network', 'derived', 'zfs')), key=len, reverse=True)
    out = [{'path': p, 'target': t, 'needs': next((r for r in roots if is_under(p, r)), None)} for p, t in sorted(clean.items())]
    return out[:500], max(0, len(out) - 500)


def build(conn: Conn, host: str) -> dict:
    """The rebuild record of a scanned host, from its latest scan and saved design."""
    from .graph import stored_blueprint
    rows = conn.all('SELECT hostname, ip_address, os_info, inventory_json FROM hosts WHERE lower(hostname) = lower(:h)', {'h': host})
    if not rows:
        raise LookupError(f'{host} has not been scanned')
    name, ip, os_info, inv_json = rows[0]
    inv = loads(inv_json) or {}
    node = node_from_index(conn, name, stats=False)
    design = stored_blueprint(conn, name)
    configs = inv.get('configs') or {}
    files = dict(configs.get('files') or {})
    unreadable = list(configs.get('unreadable') or [])
    _recover_shares(files, unreadable, inv)
    uuids, drives, crypts, lvm = _device_map(inv.get('lsblk'))

    fstab = parse_fstab_lines(files.get('/etc/fstab', ''))
    # the system disk, however this host names it: what else lives on it comes from the new install
    root_specs = {e['spec'] for e in fstab if e['target'] == '/'}
    for m in node.get('mounts') or []:
        if m['target'] == '/':
            src = (m.get('source') or '').split('[')[0]
            root_specs |= {src, uuids.get(src, src)}
    seen = {e['target'] for e in fstab}
    mounts = []
    for e in fstab:
        mounts.append({**e, 'kind': _classify(e, root_specs), 'origin': 'fstab'})
    for m in node.get('mounts') or []:
        if m['target'] in seen:
            continue
        e = _live_entry(m, uuids)
        if e:
            seen.add(e['target'])
            mounts.append({**e, 'kind': _classify(e, root_specs), 'origin': 'live'})
    for m in mounts:
        m['blocked'] = 'its password is not kept: use a credentials= file' if _uses_password(m['line']) else None
    rank = {'device': 0, 'zfs': 0, 'virtual': 1, 'network': 2, 'derived': 3, 'rootfs': 4, 'system': 5}
    mounts.sort(key=lambda m: (rank[m['kind']], m['target'].count('/'), m['target']))

    crypttab = _parse_crypttab(files.get('/etc/crypttab', ''))
    known = {c['name'] for c in crypttab}
    specs = {m['spec'] for m in mounts if m['kind'] != 'system'}
    crypt = [{**c, 'in_crypttab': True} for c in crypttab]
    crypt += [{**c, 'key': None, 'line': None, 'in_crypttab': False} for c in crypts
              if c['name'] not in known and f'/dev/mapper/{c["name"]}' in specs]

    zpools = sorted({m.group(1) for m in re.finditer(r'^\s*pool:\s*(\S+)', inv.get('zpool_status') or '', re.M)
                     if _POOL.fullmatch(m.group(1))})
    datasets = sorted(({'name': m['source'], 'target': m['target']} for m in node.get('mounts') or []
                       if m.get('fstype') == 'zfs' and not _CONTROL.search(m['target'] + (m.get('source') or ''))),
                      key=lambda d: d['target'])
    used = {m['spec'].removeprefix('UUID=') for m in mounts}
    links, more_links = _links(node, mounts, design)
    fstypes = sorted({m['fstype'] for m in mounts if m['kind'] not in ('system', 'rootfs')} | {d['fstype'] for d in drives if d['uuid'] in used})
    return {'host': name, 'ip': ip, 'os': os_info, 'collected_at': inv.get('collected_at'),
            'files': files, 'unreadable': unreadable, 'captured_files': bool(configs),
            'mounts': mounts, 'drives': sorted(drives, key=lambda d: d['uuid']), 'crypt': crypt,
            'zpools': zpools, 'datasets': datasets, 'has_md': any(re.search(r'^\s*ARRAY\b', files.get(p, ''), re.M) for p in ('/etc/mdadm.conf', '/etc/mdadm/mdadm.conf'))
            or any(d['fstype'] == 'linux_raid_member' for d in drives), 'has_lvm': lvm, 'fstypes': fstypes,
            'accounts': parse_accounts(inv.get('accounts') or ''),
            'exports': [{k: e.get(k) for k in ('name', 'path', 'protocol', 'proto', 'clients') if e.get(k) is not None} for e in shares_from_inventory(inv)],
            'links': links, 'links_left_out': more_links, 'design': design}


def _recover_shares(files: dict, unreadable: list, inv: dict) -> None:
    """Deployed share files are often private to root, but the scan also reads what is live: etab, and testparm's
    view of Samba. When a share file could not be read, the live view takes its place."""
    nfs = [l for l in (inv.get('nfs') or '').splitlines() if l.strip() and not l.lstrip().startswith('#')]
    closed = [p for p in unreadable if p == '/etc/exports' or p.startswith('/etc/exports.d/')]
    readable = any(re.search(r'^\s*[^#\s]', t, re.M) for p, t in files.items() if p == '/etc/exports' or p.startswith('/etc/exports.d/'))
    if nfs and not readable:
        path = next((p for p in closed if p != '/etc/exports'), '/etc/exports.d/storageforge.exports')
        files[path] = REBUILT_MARK + 'the live export table of the last scan\n' + '\n'.join(nfs) + '\n'
    if nfs or readable:
        unreadable[:] = [p for p in unreadable if p not in closed]
    closed = [p for p in unreadable if p.startswith('/etc/samba/')]
    sections = re.split(r'^(?=\[)', inv.get('smb') or '', flags=re.M)
    shares = [x for x in sections if x.startswith('[') and x[1:x.find(']')].lower() not in ('global', 'printers', 'print$', 'homes')]
    present = {m.lower() for t in (v for p, v in files.items() if p.startswith('/etc/samba/')) for m in re.findall(r'^\s*\[([^\]]+)\]', t, re.M)}
    wanted = [x for x in shares if x[1:x.find(']')].lower() not in present]
    if closed and wanted:
        files[closed[0]] = REBUILT_MARK + 'testparm in the last scan\n' + _redact('/etc/samba/', ''.join(wanted))
        unreadable[:] = [p for p in unreadable if p != closed[0]]


def _digest(body: dict) -> str:
    return hashlib.sha256(json.dumps({k: v for k, v in body.items() if k != 'collected_at'}, sort_keys=True).encode()).hexdigest()


def capture(conn: Conn, host: str) -> dict:
    """Store a new version if anything changed since the last one. Returns {'config_id', 'new'}."""
    body = build(conn, host)
    digest = _digest(body)
    last = conn.all('SELECT config_id, digest FROM host_configs WHERE hostname = :h ORDER BY config_id DESC LIMIT 1', {'h': body['host']})
    if last and last[0][1] == digest:
        return {'config_id': last[0][0], 'new': False}
    cid = conn.scalar("""INSERT INTO host_configs (hostname, captured_at, digest, body_json)
                         VALUES (:h, :t, :d, :b) RETURNING config_id""",
                      {'h': body['host'], 't': int(time.time()), 'd': digest, 'b': json.dumps(body)})
    conn.execute("""DELETE FROM host_configs WHERE hostname = :h AND config_id NOT IN
                    (SELECT config_id FROM host_configs WHERE hostname = :h ORDER BY config_id DESC LIMIT :k)""",
                 {'h': body['host'], 'k': KEEP})
    return {'config_id': cid, 'new': True}


def get(conn: Conn, config_id: int) -> dict | None:
    rows = conn.all('SELECT config_id, hostname, captured_at, body_json FROM host_configs WHERE config_id = :i', {'i': config_id})
    if not rows:
        return None
    cid, host, at, body = rows[0]
    return {'config_id': cid, 'host': host, 'captured_at': at, 'body': json.loads(body)}


def latest(conn: Conn, host: str) -> dict | None:
    cid = conn.scalar('SELECT max(config_id) FROM host_configs WHERE lower(hostname) = lower(:h)', {'h': host})
    return get(conn, cid) if cid else None


def summary(body: dict) -> dict:
    live = [m for m in body.get('mounts') or [] if m['kind'] not in ('system', 'rootfs', 'virtual')]
    return {'mounts': len(live), 'not_in_fstab': sum(m['origin'] == 'live' for m in live),
            'subvolumes': sum('subvol=' in m['options'] for m in live), 'zfs_pools': len(body.get('zpools') or []),
            'files': len(body.get('files') or {}), 'unreadable': len(body.get('unreadable') or []),
            'shares': len(body.get('exports') or []), 'users': len((body.get('accounts') or {}).get('users') or []),
            'links': len(body.get('links') or []), 'design': bool(body.get('design')),
            'complete': bool(body.get('captured_files'))}


def versions(conn: Conn, host: str | None = None) -> list[dict]:
    """Newest first, per host when none is named: every version of it, or the newest of every host."""
    if host:
        rows = conn.all('SELECT config_id, hostname, captured_at, body_json FROM host_configs WHERE lower(hostname) = lower(:h) '
                        'ORDER BY config_id DESC', {'h': host})
    else:
        rows = conn.all("""SELECT config_id, hostname, captured_at, body_json FROM host_configs WHERE config_id IN
                           (SELECT max(config_id) FROM host_configs GROUP BY hostname) ORDER BY lower(hostname)""")
    return [{'config_id': c, 'host': h, 'captured_at': t, **summary(json.loads(b))} for c, h, t, b in rows]


def _describe(body: dict) -> dict[str, str]:
    """A version as named text blocks, for comparing two of them. Config files as they are, the rest a line per item."""
    out = {path: text for path, text in (body.get('files') or {}).items()}
    out['mounts'] = '\n'.join(f'{m["target"]}  {m["spec"]}  {m["fstype"]}  {m["options"]}  ({m["origin"]})' for m in sorted(body.get('mounts') or [], key=lambda m: m['target']))
    acc = body.get('accounts') or {}
    out['users'] = '\n'.join(f'{u["name"]} uid={u["uid"]} gid={u["gid"]} {u["home"]} {u["shell"]}' for u in acc.get('users') or [])
    out['groups'] = '\n'.join(f'{g["name"]} gid={g["gid"]} {",".join(g["members"])}' for g in acc.get('groups') or [])
    out['symlinks'] = '\n'.join(f'{l["path"]} -> {l["target"]}' for l in body.get('links') or [])
    out['zfs'] = '\n'.join(f'{d["name"]} {d["target"]}' for d in body.get('datasets') or [])
    out['design'] = json.dumps(body.get('design'), indent=1, sort_keys=True) if body.get('design') else ''
    return out


def diff(old: dict, new: dict, limit: int = 400) -> list[dict]:
    """What changed between two versions: [{'name', 'lines'}], unified diffs without their headers."""
    a, b = _describe(old), _describe(new)
    out = []
    for name in sorted(set(a) | set(b)):
        lines = list(difflib.unified_diff(a.get(name, '').splitlines(), b.get(name, '').splitlines(), lineterm='', n=1))[2:]
        if lines:
            out.append({'name': name, 'lines': lines[:limit], 'more': max(0, len(lines) - limit)})
    return out


def _add(tar: tarfile.TarFile, path: str, data: bytes, mtime: int, mode: int = 0o600):
    info = tarfile.TarInfo(path)
    info.size, info.mtime, info.mode = len(data), mtime, mode
    tar.addfile(info, io.BytesIO(data))


README = """Rebuild record of {host}, captured {when} UTC by StorageForge.

reinstall.sh   Reports what is missing; with --apply it mounts every drive and subvolume, and restores fstab lines,
               accounts, shares and symlinks. It never formats or partitions anything. Everything it needs is inside it.
config.json    The whole record.
design.json    The saved StorageForge design, if there is one. Import it with: storageforge-index graph import --blueprint
etc/           The config files as they were, with passwords removed.

Run after reinstalling the operating system:
  bash reinstall.sh                 # read-only report
  sudo bash reinstall.sh --apply

Not here, on purpose: passwords, LUKS and SSH keys, Samba's password database. Keep those somewhere safe.
"""


def bundle(conn: Conn, hosts: list[str] | None = None, config_id: int | None = None) -> bytes:
    """A .tar.gz with one folder per host: its reinstall script, record, design and config files."""
    from .reinstall import script
    from .site import stamp
    if config_id is not None:
        one = get(conn, config_id)
        if not one:
            raise LookupError(f'no configuration version {config_id}')
        picked = [one]
    else:
        names = hosts or [r[0] for r in conn.all('SELECT DISTINCT hostname FROM host_configs ORDER BY hostname')]
        picked = [v for v in (latest(conn, h) for h in names) if v]
    if not picked:
        raise LookupError('no host configuration captured yet: scan a host first')
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w:gz') as tar:
        for v in picked:
            body, at = v['body'], v['captured_at']
            root = host_slug(v['host'])
            when = time.strftime('%Y-%m-%d %H:%M', time.gmtime(at))
            _add(tar, f'{root}/README.txt', README.format(host=v['host'], when=when).encode(), at, 0o644)
            _add(tar, f'{root}/reinstall.sh', stamp(conn, script(v)).encode('utf-8', 'surrogateescape'), at, 0o755)
            _add(tar, f'{root}/config.json', json.dumps(body, indent=1).encode(), at)
            if body.get('design'):
                _add(tar, f'{root}/design.json', json.dumps(body['design'], indent=1).encode(), at)
            for path, text in (body.get('files') or {}).items():
                if CONFIG_PATH.fullmatch(path):
                    _add(tar, posixpath.normpath(f'{root}/{path.lstrip("/")}'), text.encode('utf-8', 'surrogateescape'), at)
    return buf.getvalue()


def export_to(conn: Conn, dest: str, keep: int = 14) -> dict | None:
    """Write the bundle of every host into dest (a mount that lives elsewhere), keeping the newest few. None: nothing yet."""
    folder = Path(dest)
    if not folder.is_dir():         # a share that is not mounted must not fill the disk underneath it
        raise FileNotFoundError(f'{dest} is not a folder: is it mounted?')
    try:
        data = bundle(conn)
    except LookupError:
        return None
    out = folder / f'hostconfigs-{dt.datetime.now():%Y%m%d-%H%M%S}.tar.gz'
    part = out.with_name(out.name + '.part')
    fd = os.open(part, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(data)
    part.rename(out)
    for old in sorted(folder.glob('hostconfigs-*.tar.gz'), reverse=True)[keep:]:
        old.unlink()
    return {'path': str(out), 'bytes': len(data)}
