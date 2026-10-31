"""Database layer for SQLite (WAL + FTS5 trigram) and PostgreSQL (COPY + pg_trgm).

SQL is written once with :named parameters; the PostgreSQL connection rewrites
them to %(named)s. The few dialect differences (timestamps, IS DISTINCT FROM,
JSONB, full-text maintenance) go through small helpers on Database.
"""
from __future__ import annotations

import copy
import datetime as dt
import json
import os
import re
import secrets
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from .stream import ROW_COLUMNS, split_path

MIGRATIONS = Path(__file__).with_name('migrations')
# A mount that gains more entries than this in one scan (a new disk or a restored folder) is a bulk import: the
# scan counts the adds, but the change log doesn't list them one by one.
CHANGE_LOG_MAX_ADDS = 50_000
CHANGE_DAYS = int(os.environ.get('STORAGEFORGE_CHANGE_DAYS', '90'))
SCHEDULE_RUNS_KEPT = 200    # per schedule; each can hold 256 KiB of output
CHANGE_MAX_ROWS = int(os.environ.get('STORAGEFORGE_CHANGE_MAX_ROWS', '2000000'))


class HostIdentityError(RuntimeError):
    """A scan reached a machine that claims the name of another indexed host. Nothing about that host was changed."""


def short_name(name: str) -> str:   # moves.host_slug's rule: what host matching and storageforge-run compare
    return re.sub(r'[^a-z0-9_-]', '', (name or '').split('.')[0].lower()) or 'unknown'


class MassDeleteRefused(RuntimeError):
    pass


@dataclass
class DiffStats:
    seen: int = 0
    added: int = 0
    modified: int = 0
    deleted: int = 0
    first_scan: bool = False


class ScanBusy(RuntimeError):
    pass


def dir_id(conn: 'Conn', mount_id: int, path: str) -> int:
    """The directories row for a folder path on a mount, created if needed."""
    conn.execute('INSERT INTO directories (mount_id, path) VALUES (:m, :p) ON CONFLICT (mount_id, path) DO NOTHING',
                 {'m': mount_id, 'p': path})
    return conn.scalar('SELECT dir_id FROM directories WHERE mount_id = :m AND path = :p', {'m': mount_id, 'p': path})


class Conn:
    def __init__(self, raw, dialect: str):
        self.raw, self.dialect = raw, dialect

    def _sql(self, sql: str) -> str:
        if self.dialect == 'sqlite':
            return sql
        # psycopg reads every % as a placeholder: a literal one (LIKE 'x%') is written %%
        return re.sub(r'(?<![:\w]):([A-Za-z_]\w*)', r'%(\1)s', sql.replace('%', '%%'))

    def execute(self, sql: str, params=None):
        cur = self.raw.cursor()
        cur.execute(self._sql(sql), params or {})
        return cur

    def all(self, sql: str, params=None) -> list:
        return self.execute(sql, params).fetchall()

    def scalar(self, sql: str, params=None):
        rows = self.all(sql, params)  # fetch everything so SQLite finalises RETURNING statements
        return rows[0][0] if rows else None

    @contextmanager
    def tx(self):
        if self.dialect == 'sqlite' and self.raw.in_transaction:     # nested: a savepoint, as psycopg makes one
            name = f'sf_tx_{secrets.token_hex(4)}'
            self.raw.execute(f'SAVEPOINT {name}')
            try:
                yield
            except BaseException:
                self.raw.execute(f'ROLLBACK TO {name}')
                self.raw.execute(f'RELEASE {name}')
                raise
            else:
                self.raw.execute(f'RELEASE {name}')
        elif self.dialect == 'sqlite':
            self.raw.execute('BEGIN IMMEDIATE')
            try:
                yield
            except BaseException:
                self.raw.execute('ROLLBACK')
                raise
            else:
                self.raw.execute('COMMIT')
        else:
            with self.raw.transaction():
                yield

    def close(self):
        self.raw.close()


def loads(value, default=None):
    """A JSON column: SQLite returns its text, PostgreSQL (JSONB) the decoded value."""
    if value is None or value == '':
        return default
    return json.loads(value) if isinstance(value, (str, bytes)) else value


def epoch(value) -> int | None:
    """SQLite returns epoch ints, PostgreSQL returns datetimes; normalise to epoch."""
    if value is None or isinstance(value, (int, float)):
        return value
    return int(value.timestamp())


USAGE_DETAIL_DAYS = 90        # after that, one mount_usage row per day per mount


class Database:
    def __init__(self, url: str):
        self.url, self.busy_ms = url, 60000
        if url.startswith(('postgres://', 'postgresql://')):
            self.dialect, self.max_writers = 'postgres', 8
            try:
                import psycopg  # noqa: F401
            except ImportError as exc:
                raise SystemExit('PostgreSQL support needs psycopg 3: pip install "psycopg[binary]"') from exc
        else:
            self.dialect, self.max_writers = 'sqlite', 1
            self.path = os.path.expanduser(url.removeprefix('sqlite:///').removeprefix('sqlite://'))
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
            if sqlite3.sqlite_version_info < (3, 35, 0):
                raise SystemExit(f'SQLite {sqlite3.sqlite_version} is too old; 3.35 or newer is required')

    # dialect helpers
    def ts(self, expr: str) -> str:
        return expr if self.dialect == 'sqlite' else f'to_timestamp({expr})'

    def distinct(self, a: str, b: str) -> str:
        return f'{a} IS NOT {b}' if self.dialect == 'sqlite' else f'{a} IS DISTINCT FROM {b}'

    def jsonp(self, expr: str) -> str:
        return expr if self.dialect == 'sqlite' else f'CAST({expr} AS jsonb)'

    @property
    def boolean(self) -> str:
        return 'INTEGER' if self.dialect == 'sqlite' else 'BOOLEAN'

    def patient(self, busy_ms: int = 30 * 60000) -> 'Database':
        """The same database, for work that should wait out a long write instead of failing. Applying a large host's
        scan holds SQLite's one write lock for minutes, longer than a web request should wait."""
        db = copy.copy(self)
        db.busy_ms = busy_ms
        return db

    def connect(self) -> Conn:
        if self.dialect == 'sqlite':
            raw = sqlite3.connect(self.path, isolation_level=None, check_same_thread=False, timeout=self.busy_ms / 1000)
            for pragma in ('journal_mode=WAL', 'synchronous=NORMAL', 'foreign_keys=ON', 'cache_size=-262144',
                           'mmap_size=1073741824', f'busy_timeout={self.busy_ms}'):
                raw.execute('PRAGMA ' + pragma)
            return Conn(raw, 'sqlite')
        import psycopg
        from psycopg.adapt import Loader

        class Number(Loader):       # sum() of integers is numeric (Decimal), which int and float arithmetic refuses
            def load(self, data):
                s = bytes(data).decode()
                return float(s) if '.' in s or 'e' in s.lower() or s == 'NaN' else int(s)
        raw = psycopg.connect(self.url, autocommit=True)
        raw.adapters.register_loader('numeric', Number)
        return Conn(raw, 'postgres')

    def migrate(self, conn: Conn) -> list[str]:
        conn.execute('CREATE TABLE IF NOT EXISTS schema_version (version INTEGER PRIMARY KEY, '
                     'name TEXT NOT NULL, applied_at BIGINT NOT NULL)')
        done = {r[0] for r in conn.all('SELECT version FROM schema_version')}
        applied = []
        for f in sorted((MIGRATIONS / self.dialect).glob('*.sql')):
            if int(f.name.split('_')[0]) in done:
                continue
            sql = f.read_text()
            if self.dialect == 'sqlite':
                conn.raw.executescript(sql)
            else:
                with conn.tx():
                    conn.raw.execute(sql)
            applied.append(f.name)
        return applied

    # hosts, mounts, scans
    def upsert_host(self, conn: Conn, inv, t, host_keys: list[str] | None = None) -> int:
        """The indexed host this scan belongs to. A host's name is what it reports, so the name alone proves nothing:
        the row is only updated when the SSH host keys verified at this address match the ones pinned for it (or,
        for a row from before keys were pinned, when it was scanned at the same address). Another machine claiming
        an indexed name, or one with the same short name (host matching and deploys compare short names), is refused
        with HostIdentityError instead of taking over the row, its address and the deploys sent to it."""
        keys = set(host_keys or [])
        mine = None
        for hid, name, ssh, pinned in conn.all('SELECT host_id, hostname, ssh_host, host_keys FROM hosts'):
            same_name = name.lower() == inv.hostname.lower()
            if not same_name and short_name(name) != short_name(inv.hostname):
                continue
            old = set(json.loads(pinned)) if pinned else set()
            same = bool(old & keys) if old and keys else (not ssh or ssh == t.host)
            if not same:
                why = (f'its SSH host keys are not the ones pinned for {name}' if old and keys
                       else f'{name} was scanned at {ssh}, not {t.host}')
                if not same_name:
                    why = f'that has the same short name as {name}, and {why}'
                raise HostIdentityError(
                    f'{t.host} says it is {inv.hostname!r}, but {why}. Refused: nothing about {name} was changed. '
                    f'If {name} was reinstalled or moved, run: storageforge-index hosts rekey {name}')
            if same_name:
                mine = (hid, old)
        p = {'hn': inv.hostname, 'ip': inv.ip, 'os': inv.os_info, 'sh': t.host, 'su': t.user,
             'sp': None if t.local else t.port, 'inv': inv.to_json(), 'mid': inv.machine_id or None}
        if mine:
            p.update(id=mine[0], keys=json.dumps(sorted(mine[1] | keys)) if mine[1] | keys else None)
            conn.execute(f"""UPDATE hosts SET ip_address = :ip, os_info = :os, ssh_host = :sh, ssh_user = :su, ssh_port = :sp,
                                inventory_json = {self.jsonp(':inv')}, host_keys = :keys, machine_id = :mid
                             WHERE host_id = :id""", p)
            return mine[0]
        p['keys'] = json.dumps(sorted(keys)) if keys else None
        return conn.scalar(f"""
            INSERT INTO hosts (hostname, ip_address, os_info, ssh_host, ssh_user, ssh_port, inventory_json, host_keys, machine_id)
            VALUES (:hn, :ip, :os, :sh, :su, :sp, {self.jsonp(':inv')}, :keys, :mid)
            RETURNING host_id""", p)

    @staticmethod
    def rekey_host(conn: Conn, name: str) -> tuple[str, str | None]:
        """Forget a host's pinned identity (it was reinstalled or moved): the next scan that claims the name pins anew.
        Returns (hostname, the address it was scanned at), so the caller can drop that address from known_hosts."""
        rows = conn.all('SELECT hostname, ssh_host FROM hosts WHERE lower(hostname) = lower(:n)', {'n': name})
        if not rows:
            raise LookupError(f'no indexed host {name!r}')
        conn.execute('UPDATE hosts SET host_keys = NULL, ssh_host = NULL WHERE lower(hostname) = lower(:n)', {'n': name})
        # a person confirmed the old keys: if one of them shows up again, that is not the reinstalled machine
        conn.execute('DELETE FROM host_key_confirmations WHERE lower(address) IN (lower(:h), lower(:a))',
                     {'h': rows[0][0], 'a': rows[0][1] or rows[0][0]})
        return rows[0]

    def sync_mounts(self, conn: Conn, host_id: int, plans) -> None:
        now = int(time.time())
        state = {'scan': 'indexed', 'skip': 'skipped', 'alias': 'bind-alias'}
        with conn.tx():
            for p in plans:
                i = p.info
                p.mount_id = conn.scalar(f"""
                    INSERT INTO mounts (host_id, mount_point, source, filesystem_type, mount_options, dev_majmin,
                                        fs_root, total_bytes, used_bytes, scan_state, skip_reason, seen_at)
                    VALUES (:h, :mp, :src, :fs, :opt, :mm, :root, :tot, :used, :st, :why, {self.ts(':now')})
                    ON CONFLICT (host_id, mount_point) DO UPDATE SET source = excluded.source,
                        filesystem_type = excluded.filesystem_type, mount_options = excluded.mount_options,
                        dev_majmin = excluded.dev_majmin, fs_root = excluded.fs_root,
                        total_bytes = excluded.total_bytes, used_bytes = excluded.used_bytes,
                        scan_state = excluded.scan_state, skip_reason = excluded.skip_reason, seen_at = excluded.seen_at
                    RETURNING mount_id""",
                    {'h': host_id, 'mp': i.target, 'src': i.source, 'fs': i.fstype, 'opt': i.options,
                     'mm': i.majmin, 'root': i.fsroot, 'tot': i.total, 'used': i.used,
                     'st': state[p.action], 'why': p.reason or None, 'now': now})
            for p in plans:
                conn.execute('UPDATE mounts SET bind_of_mount_id = :a WHERE mount_id = :m',
                             {'a': p.alias_of.mount_id if p.alias_of else None, 'm': p.mount_id})
            seen = {p.info.target for p in plans}
            for mid, mp in conn.all('SELECT mount_id, mount_point FROM mounts WHERE host_id = :h', {'h': host_id}):
                if mp not in seen:
                    conn.execute("UPDATE mounts SET scan_state = 'gone' WHERE mount_id = :m", {'m': mid})

    def begin_scan(self, conn: Conn, host_id: int, stale_after: int = 6 * 3600) -> int:
        """Start a scan, unless one of the same host is already running: two writers diffing the same mounts would
        lock each other out ("database is locked") and race on the file table. A run older than stale_after is
        assumed dead (a killed process never marks its row finished)."""
        now = int(time.time())
        with conn.tx():
            busy = conn.scalar(f"""SELECT scan_id FROM scans WHERE host_id = :h AND status = 'running'
                                   AND started_at > {self.ts(':since')}""", {'h': host_id, 'since': now - stale_after})
            if busy:
                raise ScanBusy(f'this host is already being scanned (scan #{busy}); wait for it to finish')
            return conn.scalar(f"INSERT INTO scans (host_id, started_at, status) VALUES (:h, {self.ts(':now')}, 'running') "
                               'RETURNING scan_id', {'h': host_id, 'now': now})

    def prune(self, conn: Conn, change_days: int | None = None, job_days: int = 90, max_change_rows: int | None = None,
              now: float | None = None) -> dict:
        """Retention: file change history for change_days and at most max_change_rows rows, dropping whole scans
        oldest first (the newest scan per host always stays); unreadable-folder lists of the newest scan only;
        finished scan jobs for job_days. Scan summaries are tiny and stay."""
        now = int(now or time.time())
        change_days = CHANGE_DAYS if change_days is None else change_days
        max_change_rows = CHANGE_MAX_ROWS if max_change_rows is None else max_change_rows
        latest = 'SELECT max(scan_id) FROM scans x WHERE x.host_id = s.host_id AND x.status <> \'running\''
        out = {}
        with conn.tx():
            out['changes'] = conn.execute(f"""DELETE FROM file_changes WHERE scan_id IN (
                SELECT s.scan_id FROM scans s WHERE s.started_at < {self.ts(':cut')} AND s.scan_id < ({latest}))""",
                {'cut': now - change_days * 86400}).rowcount
            newest = {r[0] for r in conn.all("SELECT max(scan_id) FROM scans WHERE status <> 'running' GROUP BY host_id")}
            total, over = 0, []
            for sid, n in conn.all('SELECT scan_id, count(*) FROM file_changes GROUP BY scan_id ORDER BY scan_id DESC'):
                total += n
                if total > max_change_rows and sid not in newest:
                    over.append(sid)
            for i in range(0, len(over), 500):
                ids = {f's{k}': sid for k, sid in enumerate(over[i:i + 500])}
                out['changes'] += conn.execute(f'DELETE FROM file_changes WHERE scan_id IN ({", ".join(":" + k for k in ids)})',
                                               ids).rowcount
            out['denied'] = conn.execute(f"""DELETE FROM scan_denied WHERE scan_id IN (
                SELECT s.scan_id FROM scans s WHERE s.scan_id < ({latest}))""").rowcount
            out['usage'] = conn.execute("""DELETE FROM mount_usage WHERE at < :cut AND usage_id NOT IN (
                SELECT max(usage_id) FROM mount_usage GROUP BY host_id, mount_point, at / 86400)""",
                {'cut': now - USAGE_DETAIL_DAYS * 86400}).rowcount
            out['schedule_runs'] = conn.execute("""DELETE FROM schedule_runs WHERE run_id IN (
                SELECT run_id FROM (SELECT run_id, row_number() OVER (PARTITION BY schedule_id ORDER BY run_id DESC) AS n FROM schedule_runs) x
                WHERE n > :keep)""", {'keep': SCHEDULE_RUNS_KEPT}).rowcount
            out['jobs'] = conn.execute("""DELETE FROM scan_jobs WHERE status NOT IN ('queued', 'running')
                                          AND queued_at < :cut""", {'cut': now - job_days * 86400}).rowcount
        if self.dialect == 'sqlite':
            conn.execute('PRAGMA optimize')
        return out

    def vacuum(self, conn: Conn):
        """Give freed pages back to the filesystem. Rewrites the whole file: needs that much free space, and locks it."""
        conn.execute('VACUUM' if self.dialect == 'sqlite' else 'VACUUM ANALYZE')

    def save_denied(self, conn: Conn, scan_id: int, rows):
        with conn.tx():
            for mount, path in dict.fromkeys(rows):
                conn.execute('INSERT INTO scan_denied (scan_id, mount_point, path) VALUES (:s, :m, :p) ON CONFLICT DO NOTHING',
                             {'s': scan_id, 'm': mount, 'p': path})

    def finish_scan(self, conn: Conn, scan_id: int, host_id: int, tot: dict, status: str, seconds: float):
        now = int(time.time())
        with conn.tx():
            conn.execute(f"""UPDATE scans SET finished_at = {self.ts(':now')}, status = :st, entries_seen = :e,
                             bytes_seen = :b, added = :a, modified = :mo, deleted = :d, read_errors = :re, duration_ms = :ms
                             WHERE scan_id = :s""",
                         {'now': now, 'st': status, 'e': tot['entries'], 'b': tot['bytes'], 'a': tot['added'],
                          'mo': tot['modified'], 'd': tot['deleted'], 're': tot['read_errors'],
                          'ms': int(seconds * 1000), 's': scan_id})
            if status != 'failed':
                conn.execute(f'UPDATE hosts SET last_scanned_at = {self.ts(":now")} WHERE host_id = :h',
                             {'now': now, 'h': host_id})
                conn.execute("""INSERT INTO mount_usage (host_id, mount_point, at, used_bytes, total_bytes)
                                SELECT host_id, mount_point, :now, used_bytes, total_bytes FROM mounts
                                WHERE host_id = :h AND total_bytes > 0 AND used_bytes IS NOT NULL
                                AND scan_state NOT IN ('gone', 'bind-alias')""", {'now': now, 'h': host_id})

    # staging and diff
    def stage_create(self, conn: Conn, job_id: int):
        b = self.boolean
        conn.execute(f'DROP TABLE IF EXISTS stage_{job_id}')
        conn.execute(f"""CREATE TEMP TABLE stage_{job_id} (parent_path TEXT NOT NULL, filename TEXT NOT NULL,
            extension TEXT NOT NULL, size BIGINT NOT NULL, is_dir {b} NOT NULL, is_link {b} NOT NULL, target TEXT,
            mode TEXT, uid BIGINT, gid BIGINT, mtime BIGINT NOT NULL, dir_id BIGINT)""")

    def stage_insert(self, conn: Conn, job_id: int, rows: list[tuple]):
        if self.dialect == 'sqlite':     # a temp table: not tx(), whose write lock would wait for other hosts' scans
            conn.raw.execute('BEGIN')
            try:
                conn.raw.executemany(f'INSERT INTO stage_{job_id} ({", ".join(ROW_COLUMNS)}) VALUES (?,?,?,?,?,?,?,?,?,?,?)',
                                     rows)
            except BaseException:
                conn.raw.execute('ROLLBACK')
                raise
            conn.raw.execute('COMMIT')
        else:
            with conn.raw.cursor() as cur:
                with cur.copy(f'COPY stage_{job_id} ({", ".join(ROW_COLUMNS)}) FROM STDIN') as cp:
                    for r in rows:
                        cp.write_row(r)

    def stage_drop(self, conn: Conn, job_id: int):
        for t in ('stage', 'gone', 'chg'):
            conn.execute(f'DROP TABLE IF EXISTS {t}_{job_id}')

    def apply_diff(self, conn: Conn, scan_id: int, job_id: int, mount_id: int, root: str, full: bool,
                   max_delete_ratio: float = 0.5) -> DiffStats:
        """Compare the staged walk with the stored index for one mount (or subtree) and apply it atomically."""
        t, j, ts, dist, sqlite = f'stage_{job_id}', job_id, self.ts, self.distinct, self.dialect == 'sqlite'
        p = {'m': mount_id, 'scan': scan_id}
        scope = ''
        if not full:
            parent, name = split_path(root)
            scope = (' AND (r.dir_id IN (SELECT dir_id FROM directories WHERE mount_id = :m'
                     ' AND (path = :root OR substr(path, 1, :rlen) = :rootslash))'
                     ' OR (r.dir_id = (SELECT dir_id FROM directories WHERE mount_id = :m AND path = :rparent)'
                     ' AND r.filename = :rname))')
            p.update(root=root, rlen=len(root.rstrip('/')) + 1, rootslash=root.rstrip('/') + '/',
                     rparent=parent, rname=name)
        stats = DiffStats(seen=conn.scalar(f'SELECT count(*) FROM {t}'))
        prev = conn.scalar('SELECT count(*) FROM file_records WHERE mount_id = :m', p)
        stats.first_scan = prev == 0
        match = 'r.dir_id = s.dir_id AND r.filename = s.filename'
        content_changed = f'(r.file_size_bytes <> s.size OR r.modified_at <> {ts("s.mtime")})'
        with conn.tx():
            # folders of this walk, then the staged rows keyed by dir_id like file_records
            conn.execute(f"""INSERT INTO directories (mount_id, path) SELECT DISTINCT :m, parent_path FROM {t} WHERE true
                             ON CONFLICT (mount_id, path) DO NOTHING""", p)
            conn.execute(f"""UPDATE {t} SET dir_id = (SELECT d.dir_id FROM directories d
                                                     WHERE d.mount_id = :m AND d.path = {t}.parent_path)""", p)
            conn.execute(f'CREATE INDEX ix_{t} ON {t} (dir_id, filename)')
            if not sqlite:
                conn.execute(f'ANALYZE {t}')

            # deleted: in the index (and in scope) but not in this walk
            conn.execute(f'CREATE TEMP TABLE gone_{j} (file_id BIGINT PRIMARY KEY)')
            conn.execute(f"""INSERT INTO gone_{j} (file_id) SELECT r.file_id FROM file_records r
                             WHERE r.mount_id = :m{scope} AND NOT EXISTS (SELECT 1 FROM {t} s WHERE {match})""", p)
            stats.deleted = conn.scalar(f'SELECT count(*) FROM gone_{j}')
            if not stats.first_scan and prev >= 1000 and stats.deleted > prev * max_delete_ratio:
                raise MassDeleteRefused(
                    f'{stats.deleted:,} of {prev:,} indexed entries vanished; refusing to apply. If the data really '
                    f'is gone, rerun with --max-delete-ratio 1')
            if stats.deleted:
                conn.execute(f"""INSERT INTO file_changes (scan_id, mount_id, change_type, parent_path, filename, is_directory,
                                     old_size, new_size, old_modified_at, new_modified_at)
                                 SELECT :scan, :m, 'deleted', d.path, r.filename, r.is_directory,
                                        r.file_size_bytes, NULL, r.modified_at, NULL
                                 FROM file_records r JOIN gone_{j} g ON g.file_id = r.file_id
                                 JOIN directories d ON d.dir_id = r.dir_id""", p)
                if sqlite:
                    conn.execute(f"""INSERT INTO file_fts (file_fts, rowid, filename)
                                     SELECT 'delete', r.file_id, r.filename
                                     FROM file_records r JOIN gone_{j} g ON g.file_id = r.file_id""")
                conn.execute(f'DELETE FROM file_records WHERE file_id IN (SELECT file_id FROM gone_{j})')

            # modified: same identity, different metadata
            b = self.boolean
            conn.execute(f"""CREATE TEMP TABLE chg_{j} (file_id BIGINT PRIMARY KEY, extension TEXT, size BIGINT,
                             is_dir {b}, is_link {b}, target TEXT, mode TEXT, uid BIGINT, gid BIGINT, mtime BIGINT,
                             content_changed {b})""")
            conn.execute(f"""INSERT INTO chg_{j}
                SELECT r.file_id, s.extension, s.size, s.is_dir, s.is_link, s.target, s.mode, s.uid, s.gid, s.mtime,
                       {content_changed}
                FROM {t} s JOIN file_records r ON {match}
                WHERE {content_changed} OR {dist('r.mode_permissions', 's.mode')} OR {dist('r.owner_uid', 's.uid')}
                   OR {dist('r.group_gid', 's.gid')} OR {dist('r.symlink_target', 's.target')}
                   OR r.is_directory <> s.is_dir OR r.is_symlink <> s.is_link""", p)
            stats.modified = conn.scalar(f'SELECT count(*) FROM chg_{j}')
            if stats.modified:
                if not stats.first_scan:
                    conn.execute(f"""INSERT INTO file_changes (scan_id, mount_id, change_type, parent_path, filename,
                                         is_directory, old_size, new_size, old_modified_at, new_modified_at)
                                     SELECT :scan, :m, 'modified', d.path, r.filename, r.is_directory,
                                            r.file_size_bytes, c.size, r.modified_at, {ts('c.mtime')}
                                     FROM chg_{j} c JOIN file_records r ON r.file_id = c.file_id
                                     JOIN directories d ON d.dir_id = r.dir_id
                                     WHERE NOT c.is_dir""", p)
                conn.execute(f"""UPDATE file_records SET extension = c.extension, file_size_bytes = c.size,
                                     is_directory = c.is_dir, is_symlink = c.is_link, symlink_target = c.target,
                                     mode_permissions = c.mode, owner_uid = c.uid, group_gid = c.gid,
                                     modified_at = {ts('c.mtime')},
                                     checksum_hash = CASE WHEN c.content_changed THEN NULL ELSE file_records.checksum_hash END,
                                     last_changed_scan_id = :scan
                                 FROM chg_{j} c WHERE file_records.file_id = c.file_id""", p)

            # added: in this walk but not in the index
            cur = conn.execute(f"""INSERT INTO file_records (mount_id, dir_id, filename, extension, file_size_bytes,
                                       is_directory, is_symlink, symlink_target, mode_permissions, owner_uid, group_gid,
                                       modified_at, first_seen_scan_id, last_changed_scan_id)
                                   SELECT :m, s.dir_id, s.filename, s.extension, s.size, s.is_dir, s.is_link,
                                          s.target, s.mode, s.uid, s.gid, {ts('s.mtime')}, :scan, :scan
                                   FROM {t} s
                                   WHERE NOT EXISTS (SELECT 1 FROM file_records r WHERE {match})
                                   ON CONFLICT (dir_id, filename) DO NOTHING""", p)
            stats.added = max(cur.rowcount, 0)
            if stats.added:
                if not stats.first_scan and stats.added <= CHANGE_LOG_MAX_ADDS:
                    conn.execute("""INSERT INTO file_changes (scan_id, mount_id, change_type, parent_path, filename,
                                        is_directory, old_size, new_size, old_modified_at, new_modified_at)
                                    SELECT :scan, :m, 'added', d.path, f.filename, f.is_directory,
                                           NULL, f.file_size_bytes, NULL, f.modified_at
                                    FROM file_records f JOIN directories d ON d.dir_id = f.dir_id
                                    WHERE f.mount_id = :m AND f.first_seen_scan_id = :scan""", p)
                if sqlite:
                    conn.execute("""INSERT INTO file_fts (rowid, filename)
                                    SELECT file_id, filename FROM file_records
                                    WHERE mount_id = :m AND first_seen_scan_id = :scan""", p)
            if stats.deleted:                       # folders whose last entry went
                conn.execute("""DELETE FROM directories WHERE mount_id = :m
                                AND NOT EXISTS (SELECT 1 FROM file_records r WHERE r.dir_id = directories.dir_id)""", p)
            conn.execute('UPDATE mounts SET last_scan_id = :scan WHERE mount_id = :m', p)
        return stats

    # checksums
    def checksum_candidates(self, conn: Conn, host_id: int, min_size: int) -> list[tuple]:
        return conn.all("""
            SELECT f.file_id, d.path, f.filename FROM file_records f JOIN mounts m ON m.mount_id = f.mount_id
            JOIN directories d ON d.dir_id = f.dir_id
            WHERE m.host_id = :h AND f.checksum_hash IS NULL AND NOT f.is_directory AND NOT f.is_symlink
              AND f.file_size_bytes >= :min
              AND f.file_size_bytes IN (SELECT file_size_bytes FROM file_records
                                        WHERE NOT is_directory AND NOT is_symlink AND file_size_bytes >= :min
                                        GROUP BY file_size_bytes HAVING count(*) > 1)""",
            {'h': host_id, 'min': min_size})

    def set_checksums(self, conn: Conn, updates: list[tuple[str, int]]) -> int:
        with conn.tx():
            cur = conn.raw.cursor()
            cur.executemany(conn._sql('UPDATE file_records SET checksum_hash = :h WHERE file_id = :id'),
                            [{'h': h, 'id': i} for h, i in updates])
        return len(updates)


def now_utc() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)
