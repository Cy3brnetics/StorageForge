"""The file system of a scanned host, from the index alone: folders, files, and what is mounted where.

browse() is what the folder pickers show (shares, tasks, moves): the folders and files at a path with their sizes,
the mount each one lives on, mounts that start below it, shares exported from it, and shares other hosts' designs
mount on it. Nothing here connects to a host; a folder created since the last scan is not listed until the next one.
"""
from __future__ import annotations

import posixpath

from .db import Conn
from .moves import _path, _subtree_sql, _under, find_host, hosts, mount_of, subtree

NETWORK = {'nfs': 'nfs', 'nfs4': 'nfs', 'cifs': 'smb', 'smb3': 'smb', 'smbfs': 'smb', 'fuse.sshfs': 'sshfs',
           'fuse.rclone': 'rclone', '9p': 'virtfs', 'virtiofs': 'virtfs'}
VIRTUAL = {'proc', 'sysfs', 'devtmpfs', 'devpts', 'tmpfs', 'ramfs', 'cgroup', 'cgroup2', 'overlay', 'squashfs', 'securityfs',
           'pstore', 'bpf', 'tracefs', 'debugfs', 'mqueue', 'hugetlbfs', 'fusectl', 'configfs', 'efivarfs', 'autofs',
           'binfmt_misc', 'nsfs', 'rpc_pipefs', 'nfsd', 'fuse.portal', 'fuse.gvfsd-fuse', 'selinuxfs', 'zram'}
PSEUDO_ROOTS = ('/proc', '/sys', '/dev')
# FUSE filesystems that keep their files on this host's disks; other fuse.* mounts are remote or synthetic
LOCAL_FUSE = {'fuse.mergerfs', 'fuse.unionfs', 'fuse.ntfs-3g', 'fuse.ntfs'}
SYSTEM_DIRS = ('/', '/bin', '/boot', '/dev', '/etc', '/home', '/lib', '/lib64', '/proc', '/root', '/run', '/sbin',
               '/sys', '/tmp', '/usr', '/var', '/var/lib', '/var/log')
FILE_LIMIT = 300


def mount_kind(m: dict) -> str:
    """local | nfs | smb | sshfs | rclone | virtfs | virtual | bind"""
    fs = (m.get('fstype') or '').lower()
    if m.get('state') == 'bind-alias':
        return 'bind'
    if fs in NETWORK:
        return NETWORK[fs]
    if fs in VIRTUAL or (fs.startswith('fuse.') and fs not in LOCAL_FUSE) or any(m.get('target', '').startswith(r + '/') for r in PSEUDO_ROOTS):
        return 'virtual'
    return 'local'


def remote_of(m: dict) -> dict | None:
    """The server side of a network mount: {'server', 'path'} for NFS, {'server', 'share'} for SMB."""
    src, kind = m.get('source') or '', mount_kind(m)
    if kind == 'nfs' and ':' in src:
        server, _, path = src.partition(':')
        return {'server': server.strip('[]'), 'path': path or '/'}
    if kind == 'smb' and src.startswith('//'):
        server, _, share = src[2:].partition('/')
        return {'server': server, 'share': share.split('/')[0]}
    return None


def _mount_row(m: dict) -> dict:
    return {'target': m['target'], 'source': m['source'], 'fstype': m['fstype'], 'kind': mount_kind(m), 'state': m['state'],
            'total': m['total'], 'used': m['used'], 'options': m['options'], 'remote': remote_of(m)}


def host_mounts(h: dict) -> list[dict]:
    """Every mount of a host the scan saw, real ones first, sorted by path."""
    return sorted((_mount_row(m) for m in h['mounts']), key=lambda r: (r['kind'] == 'virtual', r['target']))


def exports_of(conn: Conn, host: str) -> list[dict]:
    """Shares a host serves or is designed to serve: the saved design, or what the scan found."""
    from .blueprint import from_index
    from .graph import stored_blueprint
    from .shares import proto
    bp = stored_blueprint(conn, host)
    if bp is None:
        try:
            bp = from_index(conn, host)
        except Exception:                   # noqa: BLE001 — a host scanned before exports were collected
            bp = {}
    return [{'i': i, 'proto': proto(e), 'name': str(e.get('name') or ''), 'path': str(e.get('path') or '').rstrip('/') or '/',
             'planned': not e.get('fromScan'), 'mounts': [m for m in e.get('mounts') or [] if m.get('host')]}
            for i, e in enumerate(bp.get('exports') or [])]


def designed_mounts(conn: Conn) -> list[dict]:
    """Every "mount on" entry in every saved design: {'server', 'proto', 'name', 'path', 'host', 'target', 'i'}."""
    import json

    from .shares import proto
    out = []
    for server, body in conn.all('SELECT hostname, body_json FROM blueprints'):
        for i, e in enumerate((json.loads(body) or {}).get('exports') or []):
            for m in e.get('mounts') or []:
                if m.get('host') and m.get('path'):
                    out.append({'server': server, 'proto': proto(e), 'name': str(e.get('name') or ''), 'i': i,
                                'path': str(e.get('path') or '').rstrip('/') or '/', 'host': str(m['host']),
                                'target': str(m['path']).rstrip('/') or '/'})
    return out


def same_host(a: str, b: str) -> bool:
    a, b = (a or '').lower(), (b or '').lower()
    return a == b or a.split('.')[0] == b.split('.')[0]


def _dir_exists(conn: Conn, m: dict, path: str) -> bool:
    if path == m['target']:
        return True
    return bool(conn.scalar("""SELECT 1 FROM file_records f JOIN directories d ON d.dir_id = f.dir_id
                               WHERE d.mount_id = :m AND d.path = :p AND f.filename = :n AND f.is_directory""", {'m': m['id'], 'p': posixpath.dirname(path), 'n': posixpath.basename(path)}))


def path_info(conn: Conn, h: dict, path: str) -> dict:
    """What the index knows about one path on a host: its mount, whether the folder exists, what it holds directly."""
    m = mount_of(h, path)
    out = {'path': path, 'mount': _mount_row(m) if m else None, 'indexed': bool(m and m['state'] == 'indexed'),
           'exists': None, 'entries': None, 'is_mount': any(x['target'] == path for x in h['mounts']),
           'mounts_below': [_mount_row(x) for x in h['mounts'] if x['target'] != path and _under(x['target'], path)
                            and mount_kind(x) not in ('virtual',)]}
    if out['indexed']:
        out['exists'] = _dir_exists(conn, m, path)
        out['entries'] = conn.scalar('SELECT count(*) FROM file_records f JOIN directories d ON d.dir_id = f.dir_id '
                                     'WHERE d.mount_id = :m AND d.path = :p',
                                     {'m': m['id'], 'p': path}) if out['exists'] else 0
    return out


def browse(conn: Conn, host_name: str, path: str = '/') -> dict:
    hs = hosts(conn)
    h = find_host(hs, host_name)
    if not h:
        raise LookupError(f'{host_name} has not been scanned')
    path = _path(path or '/', 'path')
    m = mount_of(h, path)
    children: dict[str, dict] = {}
    if m and m['state'] == 'indexed':
        where, p = _subtree_sql(path, m['target'])
        base = path.rstrip('/') + '/'
        for parent, size, n in conn.all(f"""SELECT d.path, coalesce(sum(f.file_size_bytes), 0), count(*)
                                            FROM file_records f JOIN directories d ON d.dir_id = f.dir_id WHERE {where} GROUP BY d.path""", {'m': m['id'], **p}):
            if parent == path or not parent.startswith(base):
                continue
            first = parent[len(base):].split('/', 1)[0]
            c = children.setdefault(first, {'name': first, 'bytes': 0, 'entries': 0})
            c['bytes'] += size
            c['entries'] += n
        for name, size in conn.all("""SELECT f.filename, f.file_size_bytes FROM file_records f JOIN directories d ON d.dir_id = f.dir_id
                                      WHERE d.mount_id = :m AND d.path = :p AND f.is_directory""", {'m': m['id'], 'p': path}):
            children.setdefault(name, {'name': name, 'bytes': 0, 'entries': 0})
    for mm in h['mounts']:                      # a mount below: list its first folder on the way down, badge the mount itself
        if mm['target'] == path or not _under(mm['target'], path):
            continue
        rel = mm['target'][len(path.rstrip('/')) + 1:]
        first = rel.split('/', 1)[0]
        c = children.setdefault(first, {'name': first, 'bytes': 0, 'entries': None})
        if '/' not in rel:
            c['mount'] = _mount_row(mm)
            c['bytes'] = mm['used'] or c['bytes']
        elif mount_kind(mm) != 'virtual':          # container overlays and the like deeper down are noise
            c.setdefault('mounts_inside', []).append(mm['target'])
    files, more = [], 0
    if m and m['state'] == 'indexed':
        rows = conn.all("""SELECT f.filename, f.file_size_bytes, f.modified_at, f.is_symlink, f.symlink_target
                           FROM file_records f JOIN directories d ON d.dir_id = f.dir_id
                           WHERE d.mount_id = :m AND d.path = :p AND NOT f.is_directory ORDER BY f.filename LIMIT :n""",
                        {'m': m['id'], 'p': path, 'n': FILE_LIMIT + 1})
        files = [{'name': n, 'bytes': s or 0, 'mtime': t, 'link': lt if ln else None} for n, s, t, ln, lt in rows[:FILE_LIMIT]]
        if len(rows) > FILE_LIMIT:
            more = conn.scalar('SELECT count(*) FROM file_records f JOIN directories d ON d.dir_id = f.dir_id '
                               'WHERE d.mount_id = :m AND d.path = :p AND NOT f.is_directory',
                               {'m': m['id'], 'p': path}) - FILE_LIMIT
    exps = exports_of(conn, h['name'])
    for e in exps:                              # shares at or below each child folder
        if e['path'] == path:
            continue
        if _under(e['path'], path):
            first = e['path'][len(path.rstrip('/')) + 1:].split('/', 1)[0]
            if first in children:
                children[first].setdefault('exports', []).append({'proto': e['proto'], 'name': e['name'], 'path': e['path'],
                                                                   'planned': e['planned']})
    incoming = [d for d in designed_mounts(conn) if same_host(d['host'], h['name'])]
    for d in incoming:
        if d['target'] != path and _under(d['target'], path):
            first = d['target'][len(path.rstrip('/')) + 1:].split('/', 1)[0]
            children.setdefault(first, {'name': first, 'bytes': 0, 'entries': None}).setdefault('planned_mounts', []).append(d)
    crumbs, acc = [{'name': '/', 'path': '/', 'mount': next((mount_kind(x) for x in h['mounts'] if x['target'] == '/'), None)}], ''
    for part in [x for x in path.split('/') if x]:
        acc += '/' + part
        mt = next((x for x in h['mounts'] if x['target'] == acc), None)
        crumbs.append({'name': part, 'path': acc, 'mount': mt and mount_kind(mt), 'fstype': mt and mt['fstype']})
    here = path_info(conn, h, path)
    return {'host': h['name'], 'path': path, 'crumbs': crumbs, 'here': here,
            'size': subtree(conn, m, path) if m and m['state'] == 'indexed' else None,
            'dirs': sorted(children.values(), key=lambda c: c['name'].lower()), 'files': files, 'more_files': more,
            'mounts': host_mounts(h), 'exports': exps, 'incoming': incoming,
            'exported_here': [e for e in exps if e['path'] == path],
            'under_export': [e for e in exps if e['path'] != path and _under(path, e['path'])]}
