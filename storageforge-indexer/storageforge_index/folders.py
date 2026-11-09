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
from array import array
from bisect import bisect_left, bisect_right

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


class MountDirs:
    """One mount's folders, compact enough to keep: 360,000 folders take about 70 MB. Sizes under a folder are a
    difference of running totals, so a listing costs a few binary searches however much is below it."""
    __slots__ = ('paths', 'bytes', 'entries', 'prints', 'fp', 'files', 'size')

    def __init__(self, own: dict[str, list[int]], prints: dict[str, tuple[int, int, int]]):
        self.paths = sorted(own)
        self.bytes, self.entries = array('q', [0]), array('q', [0])     # running totals, by position in paths
        for path in self.paths:
            self.bytes.append(self.bytes[-1] + own[path][0])
            self.entries.append(self.entries[-1] + own[path][1])
        same = {p: p for p in self.paths}      # both lists hold nearly the same paths: one copy of each string
        self.prints = [same.get(p, p) for p in sorted(prints)]
        self.fp = array('Q', (prints[p][0] for p in self.prints))
        self.files = array('q', (prints[p][1] for p in self.prints))
        self.size = array('q', (prints[p][2] for p in self.prints))

    def _span(self, lo: int, hi: int) -> tuple[int, int]:
        return self.bytes[hi] - self.bytes[lo], self.entries[hi] - self.entries[lo]

    def children(self, path: str) -> dict[str, dict]:
        """First-level folders under path that hold anything, totalled over everything below each."""
        base, out = path.rstrip('/') + '/', {}
        at, end = bisect_right(self.paths, base), bisect_left(self.paths, base[:-1] + '0')   # '0' sorts right after '/'
        while at < end:
            rel = self.paths[at][len(base):]
            first, slash, _ = rel.partition('/')
            c = out.setdefault(first, {'name': first, 'bytes': 0, 'entries': 0})
            if not slash:                      # the folder's own row: "a-b" can sort between "a" and "a/x", so go on one by one
                size, n = self._span(at, at + 1)
                at += 1
            else:
                lo, at = bisect_left(self.paths, f'{base}{first}/'), bisect_left(self.paths, f'{base}{first}0')
                size, n = self._span(lo, at)
            c['bytes'] += size
            c['entries'] += n
        return out


def mount_marks(conn: Conn, host: str | None = None) -> dict[int, int]:
    """Each indexed mount's last scan: a scan rewrites a mount's rows and this mark in one transaction, so a mount whose
    mark has not moved still has the rows it had."""
    hsql = 'AND (h.hostname = :host OR h.ip_address = :host)' if host else ''
    return {mid: mark for mid, mark in conn.all(
        f"""SELECT m.mount_id, coalesce(m.last_scan_id, 0) FROM mounts m JOIN hosts h ON h.host_id = m.host_id
            WHERE m.scan_state = 'indexed' {hsql}""", {'host': host})}


def scanning_mounts(conn: Conn) -> set[int]:
    """The mounts of hosts with a scan running: one scan can apply a mount more than once under the same mark."""
    return {r[0] for r in conn.all("""SELECT m.mount_id FROM mounts m WHERE m.host_id IN
                                      (SELECT host_id FROM scans WHERE status = 'running')""")}


def dir_index(conn: Conn, host: str | None = None, mounts: list[int] | None = None) -> dict[int, MountDirs]:
    """The one pass over every file that folder listings and folder comparison both need, by mount. `mounts` limits it
    to those mounts, so a cache can rebuild only what a scan changed."""
    hsql = 'AND (h.hostname = :host OR h.ip_address = :host)' if host else ''
    if mounts is not None:
        if not mounts:
            return {}
        hsql += f" AND m.mount_id IN ({', '.join(str(int(m)) for m in mounts)})"
    dirs = {did: (mid, path) for did, mid, path in conn.all(
        f"""SELECT d.dir_id, d.mount_id, d.path FROM directories d JOIN mounts m ON m.mount_id = d.mount_id JOIN hosts h ON h.host_id = m.host_id
            WHERE m.scan_state = 'indexed' {hsql}""", {'host': host})}
    # per folder: [own-file hash sum, file count, bytes]; children are folded in afterwards
    own: dict[tuple, list] = {}
    raw: dict[int, list[int]] = {}         # per folder, as a listing counts it: every row, links and subfolders too
    cur = conn.execute(f"""SELECT f.mount_id, f.dir_id, f.filename, f.file_size_bytes, f.is_directory, f.is_symlink
                           FROM file_records f JOIN mounts m ON m.mount_id = f.mount_id JOIN hosts h ON h.host_id = m.host_id
                           WHERE m.scan_state = 'indexed' {hsql}""", {'host': host})
    at, acc, total = None, None, None      # a folder's files mostly arrive together: one dict lookup per run of them
    while rows := cur.fetchmany(50_000):
        for mid, dir_id, name, size, is_dir, is_link in rows:
            parent = dirs[dir_id][1]
            if dir_id != at:
                at, acc, total = dir_id, None, raw.setdefault(dir_id, [0, 0])
            total[0] += size or 0
            total[1] += 1
            if is_link:
                continue
            if is_dir:
                path = (f'/{name}' if parent == '/' else f'{parent}/{name}') if parent else '/'
                own.setdefault((mid, path), [0, 0, 0])
                if parent:
                    own.setdefault((mid, parent), [0, 0, 0])
                continue
            if acc is None:
                acc = own.setdefault((mid, parent), [0, 0, 0])
            acc[0] = (acc[0] + hash((name, size))) & M64
            acc[1] += 1
            acc[2] += size or 0
    # fold children into parents, deepest first: fp = mix(own files + subfolder (name, fp))
    prints: dict[int, dict] = {}
    for key in sorted(own, key=lambda k: 0 if k[1] == '/' else k[1].count('/'), reverse=True):
        acc = own[key]
        mid, path = key
        fp = hash(('dir', acc[0], acc[1])) & M64
        prints.setdefault(mid, {})[path] = (fp, acc[1], acc[2])
        if path != '/':
            up, _, name = path.rpartition('/')
            p = own.get((mid, up or '/'))
            if p is not None:
                p[0] = (p[0] + hash((name, fp))) & M64
                p[1] += acc[1]
                p[2] += acc[2]
    by_mount: dict[int, dict] = {}
    for dir_id, (mid, path) in dirs.items():
        if path:                               # '' only parents a filesystem's root entry
            by_mount.setdefault(mid, {})[path] = raw.get(dir_id, [0, 0])
    return {mid: MountDirs(by_mount.get(mid, {}), prints.get(mid, {})) for mid in {*by_mount, *prints}}


def duplicate_folders(conn: Conn, host: str | None = None, min_files: int = 3, min_bytes: int = 1 << 20,
                      limit: int = 100, include_system: bool = False, index: dict[int, MountDirs] | None = None) -> dict:
    hsql = 'AND (h.hostname = :host OR h.ip_address = :host)' if host else ''
    mounts = {mid: (hn, mp) for mid, hn, mp in conn.all(
        f'SELECT m.mount_id, h.hostname, m.mount_point FROM mounts m JOIN hosts h ON h.host_id = m.host_id '
        f"WHERE m.scan_state = 'indexed' {hsql}", {'host': host})}
    if index is None:
        index = dir_index(conn, host)
    groups: dict[int, list] = {}
    checked = 0
    for mid, md in index.items():
        if mid not in mounts:
            continue
        checked += len(md.prints)
        files, size, fps = md.files, md.size, md.fp
        for i, path in enumerate(md.prints):
            if (files[i] >= min_files and size[i] >= min_bytes and is_under(path, mounts[mid][1])
                    and (include_system or not _noise(path))):
                groups.setdefault(fps[i], []).append((mid, path, files[i], size[i]))
    groups = {fp: ks for fp, ks in groups.items() if len(ks) > 1}
    dup_keys = {(k[0], k[1]) for ks in groups.values() for k in ks}

    def nested(key):                       # its parent is itself part of a reported copy
        mid, path = key[:2]
        return path != '/' and (mid, posixpath.dirname(path)) in dup_keys

    out = []
    for keys in groups.values():
        keys = [k for k in keys if not nested(k)]
        if len(keys) < 2:
            continue
        files, size = keys[0][2:]
        copies = [{'host': mounts[k[0]][0], 'mount': mounts[k[0]][1], 'path': k[1]} for k in sorted(keys, key=lambda k: (mounts[k[0]], k[1]))]
        hosts = {c['host'] for c in copies}
        out.append({'files': files, 'bytes': size, 'copies': copies, 'count': len(copies),
                    'reclaimable': size * (len(copies) - 1), 'same_name': len({posixpath.basename(c['path']) for c in copies}) == 1,
                    'scope': 'same host' if len(hosts) == 1 else 'across hosts'})
    out.sort(key=lambda g: (g['scope'] != 'same host', -g['reclaimable']))
    return {'groups': out[:limit], 'total_groups': len(out), 'folders_checked': checked,
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
