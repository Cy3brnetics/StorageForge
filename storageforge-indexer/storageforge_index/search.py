"""Query layer: turns a shell-style name pattern plus filters into an index-friendly query.

Pattern strategy (cheapest first):
  *.cr2        → extension = 'cr2'               (B-tree on extension, size)
  report.pdf   → filename = ... COLLATE NOCASE   (B-tree on filename)
  IMG_*        → filename LIKE 'IMG_%'           (B-tree prefix range)
  *2019*raw*   → trigram candidates, then exact GLOB
                 SQLite: FTS5 trigram table; PostgreSQL: pg_trgm GIN with ~*
  --path-contains scans directories.path in SQLite (one row per folder) and uses pg_trgm in PostgreSQL.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field

from .db import Conn, Database, epoch
from .stream import extension, join_path

GLOB_CHARS = '*?['
EXT_RE = re.compile(r'^\*\.([^*?\[\]/]+)$')


@dataclass
class SearchQuery:
    pattern: str | None = None
    hosts: list[str] = field(default_factory=list)
    size_gt: int | None = None
    size_lt: int | None = None
    ftype: str | None = None            # f | d | l
    exts: list[str] = field(default_factory=list)
    under: str | None = None
    path_contains: str | None = None
    newer_than: int | None = None       # seconds
    older_than: int | None = None
    limit: int = 100
    sort: str = 'path'
    desc: bool = False


def classify(pattern: str | None):
    if not pattern:
        return 'any', None
    m = EXT_RE.match(pattern)
    # only what stream.extension() can have stored: of backup.tar.gz it keeps gz, so *.tar.gz has to match by name
    if m and extension('x.' + m.group(1), False) == m.group(1).lower():
        return 'ext', m.group(1).lower()
    if not any(c in pattern for c in GLOB_CHARS):
        return 'exact', pattern
    if pattern.endswith('*') and not any(c in pattern[:-1] for c in GLOB_CHARS):
        return 'prefix', pattern[:-1]
    return 'glob', pattern


def glob_to_like(pattern: str) -> str:
    """A LIKE pattern matching a superset of the glob (used for index candidates only)."""
    out, i = [], 0
    while i < len(pattern):
        c = pattern[i]
        if c == '*':
            out.append('%')
        elif c == '?':
            out.append('_')
        elif c == '[' and (j := pattern.find(']', i + 2)) != -1:
            out.append('_')
            i = j
        else:
            out.append(c)
        i += 1
    return ''.join(out)


def glob_to_regex(pattern: str) -> str:
    out, i = ['^'], 0
    while i < len(pattern):
        c = pattern[i]
        if c == '*':
            out.append('.*')
        elif c == '?':
            out.append('.')
        elif c == '[' and (j := pattern.find(']', i + 2)) != -1:
            body = pattern[i + 1:j]
            out.append('[' + ('^' + body[1:] if body.startswith('!') else body).replace('\\', '\\\\') + ']')
            i = j
        else:
            out.append(re.escape(c))
        i += 1
    return ''.join(out) + '$'


def longest_literal(pattern: str) -> int:
    return max((len(s) for s in re.split(r'\[[^\]]*\]|[*?]', pattern)), default=0)


def like_escape(s: str) -> str:
    return s.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')


SORTS = {'path': 'd.path, f.filename', 'name': 'f.filename', 'size': 'f.file_size_bytes',
         'mtime': 'f.modified_at', 'host': 'h.hostname, d.path, f.filename'}


def build_search(db: Database, q: SearchQuery) -> tuple[str, dict]:
    where, p = [], {}
    sqlite = db.dialect == 'sqlite'
    kind, val = classify(q.pattern)
    if kind == 'ext':
        where.append('f.extension = :ext')
        p['ext'] = val
    elif kind == 'exact':
        where.append('f.filename = :name COLLATE NOCASE' if sqlite else 'lower(f.filename) = lower(:name)')
        p['name'] = val
    elif kind in ('prefix', 'glob'):
        if sqlite:
            p['glob'], p['like'] = q.pattern, glob_to_like(q.pattern)
            if kind == 'prefix':
                where.append('f.filename LIKE :like')
            elif longest_literal(q.pattern) >= 3:
                where.append('f.file_id IN (SELECT rowid FROM file_fts WHERE file_fts.filename LIKE :like)')
            where.append('lower(f.filename) GLOB lower(:glob)')
        else:
            where.append('f.filename ~* :re')
            p['re'] = glob_to_regex(q.pattern)
    if q.exts:
        names = []
        for i, e in enumerate(q.exts):
            p[f'x{i}'] = e.lower().lstrip('.')
            names.append(f':x{i}')
        where.append(f'f.extension IN ({", ".join(names)})')
    if q.hosts:
        ors = []
        for i, h in enumerate(q.hosts):
            p[f'h{i}'], p[f'hd{i}'] = h, h + '.%'
            ors.append(f'(h.hostname = :h{i} OR h.hostname LIKE :hd{i} OR h.ip_address = :h{i} OR h.ssh_host = :h{i})')
        where.append('(' + ' OR '.join(ors) + ')')
    if q.size_gt is not None:
        where.append('f.file_size_bytes > :sgt')
        p['sgt'] = q.size_gt
    if q.size_lt is not None:
        where.append('f.file_size_bytes < :slt')
        p['slt'] = q.size_lt
    if q.ftype == 'f':
        where.append('NOT f.is_directory AND NOT f.is_symlink')
    elif q.ftype == 'd':
        where.append('f.is_directory')
    elif q.ftype == 'l':
        where.append('f.is_symlink')
    if q.under:
        u = q.under.rstrip('/') or '/'
        if u == '/':
            pass
        elif sqlite:
            # '0' sorts right after '/', so this is the B-tree range of everything below u
            where.append('(d.path = :u OR (d.path >= :us AND d.path < :ue))')
            p.update(u=u, us=u + '/', ue=u + '0')
        else:
            where.append('(d.path = :u OR d.path LIKE :ul)')
            p.update(u=u, ul=like_escape(u) + '/%')
    if q.path_contains:
        if sqlite:
            where.append('d.path LIKE :pc')
        else:
            where.append('d.path ILIKE :pc')
        p['pc'] = '%' + q.path_contains + '%'
    now = int(time.time())
    if q.newer_than:
        where.append(f'f.modified_at >= {db.ts(":nt")}')
        p['nt'] = now - q.newer_than
    if q.older_than:
        where.append(f'f.modified_at < {db.ts(":ot")}')
        p['ot'] = now - q.older_than
    p['limit'] = q.limit
    sql = f"""SELECT h.hostname, m.mount_point, d.path, f.filename, f.file_size_bytes, f.is_directory,
                     f.is_symlink, f.symlink_target, f.mode_permissions, f.owner_uid, f.group_gid, f.modified_at,
                     f.checksum_hash
              FROM file_records f
              JOIN directories d ON d.dir_id = f.dir_id
              JOIN mounts m ON m.mount_id = f.mount_id
              JOIN hosts h ON h.host_id = m.host_id
              {'WHERE ' + ' AND '.join(where) if where else ''}
              ORDER BY {SORTS.get(q.sort, SORTS['path'])}{' DESC' if q.desc else ''}
              LIMIT :limit"""
    return sql, p


def run_search(db: Database, conn: Conn, q: SearchQuery) -> list[dict]:
    sql, params = build_search(db, q)
    out = []
    for r in conn.all(sql, params):
        out.append({'host': r[0], 'mount': r[1], 'path': join_path(r[2], r[3]), 'size': r[4],
                    'type': 'dir' if r[5] else 'symlink' if r[6] else 'file', 'symlink_target': r[7],
                    'mode': r[8], 'uid': r[9], 'gid': r[10], 'modified_at': epoch(r[11]), 'sha256': r[12]})
    return out


def run_dupes(conn: Conn, host: str | None, min_size: int, limit: int) -> list[dict]:
    p = {'min': min_size, 'limit': limit}
    host_sql = ''
    if host:
        host_sql = 'AND (h.hostname = :host OR h.ip_address = :host OR h.ssh_host = :host)'
        p['host'] = host
    groups = conn.all(f"""
        SELECT f.checksum_hash, count(*), max(f.file_size_bytes), (count(*) - 1) * max(f.file_size_bytes) AS reclaimable
        FROM file_records f JOIN mounts m ON m.mount_id = f.mount_id JOIN hosts h ON h.host_id = m.host_id
        WHERE f.checksum_hash IS NOT NULL AND f.file_size_bytes >= :min {host_sql}
        GROUP BY f.checksum_hash HAVING count(*) > 1
        ORDER BY reclaimable DESC LIMIT :limit""", p)
    out = []
    for h, n, size, reclaim in groups:
        members = conn.all(f"""SELECT h.hostname, d.path, f.filename FROM file_records f JOIN directories d ON d.dir_id = f.dir_id
                              JOIN mounts m ON m.mount_id = f.mount_id JOIN hosts h ON h.host_id = m.host_id
                              WHERE f.checksum_hash = :c {host_sql} ORDER BY h.hostname, d.path, f.filename""", {'c': h, 'host': host})
        out.append({'sha256': h, 'copies': n, 'size': size, 'reclaimable': reclaim,
                    'files': [f'{hn}:{join_path(pp, fn)}' for hn, pp, fn in members]})
    return out


def run_changes(conn: Conn, host: str, scan_id: int | None, limit: int) -> tuple[dict | None, list[dict]]:
    p = {'x': host}
    scan = conn.all(f"""SELECT s.scan_id, s.started_at, s.status, s.added, s.modified, s.deleted
                        FROM scans s JOIN hosts h ON h.host_id = s.host_id
                        WHERE (h.hostname = :x OR h.ip_address = :x OR h.ssh_host = :x)
                        {'AND s.scan_id = :s' if scan_id else "AND s.status <> 'running'"}
                        ORDER BY s.scan_id DESC LIMIT 1""", {**p, 's': scan_id})
    if not scan:
        return None, []
    sid, started, status, a, mo, d = scan[0]
    rows = conn.all("""SELECT c.change_type, m.mount_point, c.parent_path, c.filename, c.old_size, c.new_size
                       FROM file_changes c JOIN mounts m ON m.mount_id = c.mount_id
                       WHERE c.scan_id = :s ORDER BY c.change_type, c.parent_path, c.filename LIMIT :limit""",
                    {'s': sid, 'limit': limit})
    return ({'scan_id': sid, 'started_at': epoch(started), 'status': status, 'added': a, 'modified': mo, 'deleted': d},
            [{'change': r[0], 'mount': r[1], 'path': join_path(r[2], r[3]), 'old_size': r[4], 'new_size': r[5]}
             for r in rows])
