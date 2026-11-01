"""Duplicate folders by name and structure, from the index alone (no checksums, no extra scan).

Two folders match when they hold the same file names with the same sizes, in the same subfolder layout, at any
depth. The folder's own name does not count, so "Photos" and "Photos (copy)" match. Each folder gets a
fingerprint built bottom-up: an order-independent sum of (name, size) hashes for its files plus (name, fingerprint)
for its subfolders. Rows stream from the database, so memory grows with the number of folders, not files.

Only the outermost copy is reported: when two parents already match, their matching children are not listed again.
Matching structure is strong evidence of a copy, not proof; a --checksum scan confirms identical content.
"""
from __future__ import annotations

import posixpath
import re

from .db import Conn, epoch
from .remote import is_under

M64 = (1 << 64) - 1
NOISE_DIRS = ('/usr', '/lib', '/lib32', '/lib64', '/libx32', '/bin', '/sbin', '/boot', '/etc', '/opt/containerd', '/opt/vc', '/snap',
              '/var/lib', '/var/cache', '/var/log', '/var/tmp', '/tmp')
NOISE_NAMES = frozenset({'node_modules', '__pycache__', '.cache', 'site-packages', '.venv', 'venv', '.git',
                         '.npm', '.cargo', '.rustup', '.local', '.storageforge-trash',
                         'overlay2', 'io.containerd.snapshotter.v1.overlayfs'})
# rsnapshot's daily.0, weekly.1: copies by design, and the links in them point into the host they came from
BACKUP_ROTATION = re.compile(r'(hourly|daily|weekly|monthly|yearly)\.\d+')


def _noise(path: str) -> bool:
    parts = path.split('/')
    return (any(path == d or path.startswith(d + '/') for d in NOISE_DIRS) or bool(NOISE_NAMES & set(parts))
            or any(BACKUP_ROTATION.fullmatch(p) for p in parts))


def ignore_lists(conn: Conn) -> dict[str, list[str]]:
    from .alerts import get_setting
    return get_setting(conn, 'files.ignore') or {}


def save_ignore(conn: Conn, host: str, paths: list[str], actor: str):
    from .alerts import set_setting
    cur = ignore_lists(conn)
    clean = sorted({x.strip() for x in paths if x.strip() and x.strip() != '!'})
    key = host or '*'
    if clean:
        cur[key] = clean
    else:
        cur.pop(key, None)
    set_setting(conn, 'files.ignore', cur, actor)


def _matches(entry: str, path: str) -> bool:
    if entry.startswith('/'):              # a path: that path and everything under it
        return is_under(path, entry.rstrip('/') or '/')
    return entry in path + '/'             # a fragment: 'Thumbs.db', '.cache/'


def is_ignored(host: str | None, path: str, lists: dict | None = None, system: bool = True, extra: tuple = ()) -> bool:
    """The user's list for this host and all hosts, then the built-in system paths. An entry starting with ! shows
    what matches it, whatever else says."""
    entries = (lists or {}).get('*', []) + (lists or {}).get(host or '', [])
    if any(x.startswith('!') and _matches(x[1:], path) for x in entries):
        return False
    return (any(not x.startswith('!') and _matches(x, path) for x in entries) or (system and _noise(path))
            or any(is_under(path, d) for d in extra))


def duplicate_folders(conn: Conn, host: str | None = None, min_files: int = 3, min_bytes: int = 1 << 20,
                      limit: int = 100, include_system: bool = False) -> dict:
    hsql = 'AND (h.hostname = :host OR h.ip_address = :host)' if host else ''
    mounts = {mid: (hn, mp) for mid, hn, mp in conn.all(
        f'SELECT m.mount_id, h.hostname, m.mount_point FROM mounts m JOIN hosts h ON h.host_id = m.host_id '
        f"WHERE m.scan_state = 'indexed' {hsql}", {'host': host})}
    # per folder: [own-file hash sum, file count, bytes]; children are folded in afterwards
    own: dict[tuple, list] = {}
    cur = conn.execute(f"""SELECT f.mount_id, d.path, f.filename, f.file_size_bytes, f.is_directory
                           FROM file_records f JOIN directories d ON d.dir_id = f.dir_id JOIN mounts m ON m.mount_id = f.mount_id JOIN hosts h ON h.host_id = m.host_id
                           WHERE NOT f.is_symlink AND m.scan_state = 'indexed' {hsql}""", {'host': host})
    while rows := cur.fetchmany(50_000):
        for mid, parent, name, size, is_dir in rows:
            if is_dir:
                path = posixpath.join(parent, name) if parent else '/'
                own.setdefault((mid, path), [0, 0, 0])
                if parent:
                    own.setdefault((mid, parent), [0, 0, 0])
                continue
            acc = own.setdefault((mid, parent), [0, 0, 0])
            acc[0] = (acc[0] + hash((name, size))) & M64
            acc[1] += 1
            acc[2] += size or 0
    # fold children into parents, deepest first: fp = mix(own files + subfolder (name, fp))
    tree: dict[tuple, list] = {k: [v[0], v[1], v[2]] for k, v in own.items()}
    fps: dict[tuple, int] = {}
    for key in sorted(tree, key=lambda k: 0 if k[1] == '/' else k[1].count('/'), reverse=True):
        acc = tree[key]
        fp = hash(('dir', acc[0], acc[1])) & M64
        fps[key] = fp
        mid, path = key
        if path != '/':
            parent = (mid, posixpath.dirname(path))
            if parent in tree:
                p = tree[parent]
                p[0] = (p[0] + hash((posixpath.basename(path), fp))) & M64
                p[1] += acc[1]
                p[2] += acc[2]
    groups: dict[int, list] = {}
    for key, fp in fps.items():
        _, files, size = tree[key]
        if (files >= min_files and size >= min_bytes and is_under(key[1], mounts[key[0]][1])
                and (include_system or not _noise(key[1]))):
            groups.setdefault(fp, []).append(key)
    groups = {fp: ks for fp, ks in groups.items() if len(ks) > 1}
    dup_keys = {k for ks in groups.values() for k in ks}

    def nested(key):                       # its parent is itself part of a reported copy
        mid, path = key
        return path != '/' and (mid, posixpath.dirname(path)) in dup_keys and len(groups.get(fps[(mid, posixpath.dirname(path))], ())) > 1

    out = []
    for fp, keys in groups.items():
        keys = [k for k in keys if not nested(k)]
        if len(keys) < 2:
            continue
        _, files, size = tree[keys[0]]
        copies = [{'host': mounts[m][0], 'mount': mounts[m][1], 'path': p} for m, p in sorted(keys, key=lambda k: (mounts[k[0]], k[1]))]
        hosts = {c['host'] for c in copies}
        out.append({'files': files, 'bytes': size, 'copies': copies, 'count': len(copies),
                    'reclaimable': size * (len(copies) - 1), 'same_name': len({posixpath.basename(c['path']) for c in copies}) == 1,
                    'scope': 'same host' if len(hosts) == 1 else 'across hosts'})
    out.sort(key=lambda g: (g['scope'] != 'same host', -g['reclaimable']))
    return {'groups': out[:limit], 'total_groups': len(out), 'folders_checked': len(tree),
            'reclaimable_same_host': sum(g['reclaimable'] for g in out if g['scope'] == 'same host')}


def cold_folders(conn: Conn, host: str | None = None, years: float = 2.0, min_bytes: int = 1 << 30,
                 limit: int = 100, include_system: bool = False, now: float | None = None) -> dict:
    """Folders whose newest file is older than the cutoff: candidates for cold storage. Like duplicate_folders,
    one streaming pass with per-folder totals folded bottom-up; only the outermost cold folder is listed."""
    import time
    cutoff = (now or time.time()) - years * 365.25 * 86400
    hsql = 'AND (h.hostname = :host OR h.ip_address = :host)' if host else ''
    mounts = {mid: (hn, mp) for mid, hn, mp in conn.all(
        f'SELECT m.mount_id, h.hostname, m.mount_point FROM mounts m JOIN hosts h ON h.host_id = m.host_id '
        f"WHERE m.scan_state = 'indexed' {hsql}", {'host': host})}
    tree: dict[tuple, list] = {}            # (mount, path) → [newest mtime, files, bytes]
    cur = conn.execute(f"""SELECT f.mount_id, d.path, f.filename, f.file_size_bytes, f.is_directory, f.modified_at
                           FROM file_records f JOIN directories d ON d.dir_id = f.dir_id JOIN mounts m ON m.mount_id = f.mount_id JOIN hosts h ON h.host_id = m.host_id
                           WHERE NOT f.is_symlink AND m.scan_state = 'indexed' {hsql}""", {'host': host})
    while rows := cur.fetchmany(50_000):
        for mid, parent, name, size, is_dir, mtime in rows:
            if is_dir:
                tree.setdefault((mid, posixpath.join(parent, name) if parent else '/'), [0, 0, 0])
                continue
            acc = tree.setdefault((mid, parent), [0, 0, 0])
            acc[0] = max(acc[0], epoch(mtime) or 0)
            acc[1] += 1
            acc[2] += size or 0
    for key in sorted(tree, key=lambda k: 0 if k[1] == '/' else k[1].count('/'), reverse=True):
        mid, path = key
        if path != '/':
            parent = tree.get((mid, posixpath.dirname(path)))
            if parent is not None:
                acc = tree[key]
                parent[0] = max(parent[0], acc[0])
                parent[1] += acc[1]
                parent[2] += acc[2]

    def cold(key):
        newest, files, size = tree[key]
        return files and newest and newest < cutoff and is_under(key[1], mounts[key[0]][1])
    out = []
    for key, (newest, files, size) in tree.items():
        if size < min_bytes or not cold(key) or (not include_system and _noise(key[1])):
            continue
        mid, path = key
        parent = (mid, posixpath.dirname(path))
        if path != '/' and parent in tree and cold(parent):
            continue                        # its parent is cold too: list the outermost only
        out.append({'host': mounts[mid][0], 'mount': mounts[mid][1], 'path': path, 'files': files, 'bytes': size,
                    'newest': newest})
    out.sort(key=lambda g: -g['bytes'])
    return {'folders': out[:limit], 'total': len(out), 'bytes': sum(g['bytes'] for g in out), 'cutoff': int(cutoff)}
