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

import functools
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


def _class_body(s: str) -> str:
    """A class's characters (after any !) as a regex class body, read as fnmatch reads them: a - between two characters is a range, a backwards
    range holds nothing and is dropped (PostgreSQL refuses one outright), and anything else is that character. Every character but a range's
    hyphen is escaped, which Python's re and PostgreSQL's regular expressions both take inside brackets."""
    def esc(chunk):
        return ''.join('\\' + c if c in '\\-^[]&~|' else c for c in chunk)
    if '-' not in s:
        return esc(s)
    chunks, i, k = [], 0, 1
    while (k := s.find('-', k)) >= 0:
        chunks.append(s[i:k])
        i, k = k + 1, k + 3
    if s[i:]:
        chunks.append(s[i:])
    else:
        chunks[-1] += '-'
    for k in range(len(chunks) - 1, 0, -1):
        if chunks[k - 1][-1] > chunks[k][0]:
            chunks[k - 1] = chunks[k - 1][:-1] + chunks[k][1:]
            del chunks[k]
    return '-'.join(esc(c) for c in chunks)


def _glob_tokens(pattern: str) -> list[tuple[str, str]]:
    """The pattern read as a shell and fnmatch read it: ('*' | '?' | 'lit' | 'class', text). A class's text is its regex. A [ with no ] to close
    it is a plain [, a ] right after [ or [! is in the class, and [!...] is everything but. Every road of a search reads a pattern through this,
    so they agree on what it means (SQLite's GLOB negates with ^, and took [!x] as "! or x")."""
    out, i, n = [], 0, len(pattern)
    while i < n:
        c = pattern[i]
        i += 1
        if c == '*':
            if not out or out[-1][0] != '*':
                out.append(('*', '.*'))
        elif c == '?':
            out.append(('?', '.'))
        elif c == '[':
            j = i
            if j < n and pattern[j] == '!':
                j += 1
            if j < n and pattern[j] == ']':
                j += 1
            while j < n and pattern[j] != ']':
                j += 1
            if j >= n:
                out.append(('lit', '['))
                continue
            body, i = pattern[i:j], j + 1
            negated = body.startswith('!')
            inner = _class_body(body[1:] if negated else body)
            out.append(('class', ('.' if negated else '(?!)') if not inner else f'[{"^" if negated else ""}{inner}]'))
        else:
            out.append(('lit', c))
    return out


def has_class(pattern: str) -> bool:
    return any(kind == 'class' for kind, _ in _glob_tokens(pattern))


def glob_to_like(pattern: str) -> str:
    """A LIKE pattern matching a superset of the glob (used for index candidates only)."""
    return ''.join({'*': '%', '?': '_', 'class': '_'}.get(kind, text) for kind, text in _glob_tokens(pattern))


def glob_to_sqlite(pattern: str) -> str:
    """For SQLite's GLOB, which reads classes its own way: each class is loosened to ?, and the match is made exact by sf_glob() after."""
    return ''.join('?' if kind == 'class' else '[[]' if text == '[' else text if kind == 'lit' else kind for kind, text in _glob_tokens(pattern))


def glob_to_regex(pattern: str) -> str:
    """The exact match, anchored, for PostgreSQL's ~* and Python's re (with re.S, as PostgreSQL's . takes a newline too)."""
    return '^' + ''.join(re.escape(text) if kind == 'lit' else text for kind, text in _glob_tokens(pattern)) + '$'


@functools.lru_cache(maxsize=256)
def _compiled(regex: str):
    return re.compile(regex, re.S)


def sf_glob(regex: str, name: str | None) -> int:
    """SQLite's side of an exact class match, registered on every connection (db.py)."""
    return 1 if name is not None and _compiled(regex).search(name) else 0


def longest_literal(pattern: str) -> int:
    return max((len(s) for s in re.split(r'\[[^\]]*\]|[*?]', pattern)), default=0)


_ASCII_LOWER = str.maketrans('ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')


def ascii_lower(s: str) -> str:
    """What SQLite's lower() does, so a range like [B-a] means the same on both databases."""
    return s.translate(_ASCII_LOWER)


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
            p['glob'], p['like'] = glob_to_sqlite(q.pattern), glob_to_like(q.pattern)
            if kind == 'prefix':
                where.append('f.filename LIKE :like')
            elif longest_literal(q.pattern) >= 3:
                where.append('f.file_id IN (SELECT rowid FROM file_fts WHERE file_fts.filename LIKE :like)')
            where.append('lower(f.filename) GLOB lower(:glob)')
            if has_class(q.pattern):            # GLOB took each class as ?: only the names it kept are checked exactly
                where.append('sf_glob(:re, lower(f.filename))')
                p['re'] = glob_to_regex(ascii_lower(q.pattern))
        else:
            where.append('f.filename ~* :re')
            p['re'] = glob_to_regex(ascii_lower(q.pattern))
    if q.exts:
        names = []
        for i, e in enumerate(q.exts):
            p[f'x{i}'] = e.lower().lstrip('.')
            names.append(f':x{i}')
        where.append(f'f.extension IN ({", ".join(names)})')
    if q.hosts:
        ors = []
        esc = " ESCAPE '\\'" if sqlite else ''        # PostgreSQL's own escape is the backslash
        for i, h in enumerate(q.hosts):
            p[f'h{i}'], p[f'hd{i}'] = h, like_escape(h) + '.%'
            ors.append(f'(h.hostname = :h{i} OR h.hostname LIKE :hd{i}{esc} OR h.ip_address = :h{i} OR h.ssh_host = :h{i})')
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
            where.append("d.path LIKE :pc ESCAPE '\\'")
        else:
            where.append('d.path ILIKE :pc')
        p['pc'] = '%' + like_escape(q.path_contains) + '%'
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


def _dupes_sql(host: str | None, min_size: int) -> tuple[str, dict]:
    """One row per checksum with more than one file: its files, its size, and how many hosts hold it."""
    p = {'min': min_size}
    mine = ''
    if host:
        mine = 'AND sum(CASE WHEN h.hostname = :host OR h.ip_address = :host OR h.ssh_host = :host THEN 1 ELSE 0 END) > 0'
        p['host'] = host
    return f"""SELECT f.checksum_hash AS sha, count(*) AS n, max(f.file_size_bytes) AS size, count(DISTINCT m.host_id) AS hosts
               FROM file_records f JOIN mounts m ON m.mount_id = f.mount_id JOIN hosts h ON h.host_id = m.host_id
               WHERE f.checksum_hash IS NOT NULL AND f.file_size_bytes >= :min
               GROUP BY f.checksum_hash HAVING count(*) > 1 {mine}""", p


def run_dupes(conn: Conn, host: str | None, min_size: int, limit: int) -> list[dict]:
    """Identical files across the fleet; with a host, the groups with a copy on it, listing every copy wherever it is.

    Two classes (the owner's request of 2026-11-19). A second copy on the same host is space that could be freed: `reclaimable`
    counts those, one copy kept per host. A copy on another host is a possible backup: it is never counted as reclaimable, and a
    group with one copy per host has `scope` 'across hosts' and `reclaimable` 0. The limit is shared, so that neither class
    crowds the other out: up to half goes to the groups across hosts when both have more than fit."""
    sql, p = _dupes_sql(host, min_size)
    p['limit'] = limit
    same = conn.all(f"""{sql} AND count(*) > count(DISTINCT m.host_id)
                        ORDER BY (count(*) - count(DISTINCT m.host_id)) * max(f.file_size_bytes) DESC, f.checksum_hash LIMIT :limit""", p)
    across = conn.all(f"""{sql} AND count(*) = count(DISTINCT m.host_id)
                          ORDER BY max(f.file_size_bytes) DESC, f.checksum_hash LIMIT :limit""", p)
    take = min(len(across), max(limit // 2, limit - len(same)))
    out = []
    for sha, n, size, hosts in [*same[:limit - take], *across[:take]]:
        members = conn.all("""SELECT h.hostname, d.path, f.filename FROM file_records f JOIN directories d ON d.dir_id = f.dir_id
                              JOIN mounts m ON m.mount_id = f.mount_id JOIN hosts h ON h.host_id = m.host_id
                              WHERE f.checksum_hash = :c ORDER BY h.hostname, d.path, f.filename""", {'c': sha})
        out.append({'sha256': sha, 'copies': n, 'size': size, 'reclaimable': (n - hosts) * size, 'hosts': hosts,
                    'scope': 'same host' if hosts == 1 else 'across hosts', 'elsewhere': (hosts - 1) * size,
                    'places': [{'host': hn, 'path': join_path(pp, fn)} for hn, pp, fn in members],
                    'files': [f'{hn}:{join_path(pp, fn)}' for hn, pp, fn in members]})
    return out


def dupes_totals(conn: Conn, host: str | None, min_size: int) -> dict:
    """Over every group, not only the ones listed: what could be freed within hosts, and what is also held on another host."""
    sql, p = _dupes_sql(host, min_size)
    n, reclaim, across, elsewhere = conn.all(f"""SELECT count(*), coalesce(sum((g.n - g.hosts) * g.size), 0),
                                                        coalesce(sum(CASE WHEN g.hosts > 1 THEN 1 ELSE 0 END), 0),
                                                        coalesce(sum((g.hosts - 1) * g.size), 0) FROM ({sql}) g""", p)[0]
    return {'total_groups': n, 'reclaimable': reclaim, 'across_hosts': {'groups': across, 'bytes': elsewhere}}


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
