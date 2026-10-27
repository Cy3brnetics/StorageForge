"""Database backups: small "essentials" copies nightly, full copies on demand, and restore.

The database is mostly the file index, which a rescan rebuilds. What cannot be rebuilt is small: the encrypted SSH
keys and their bindings, web users, designs, move plans, the audit log and the host list. An essentials backup is a
fresh database with the full schema holding just those tables (a few MB), so it restores into a working instance
that then rescans. A full backup is SQLite's online backup of everything, consistent while the server runs.

Neither contains the vault secret, by design: a backup plus its secret would be the keys. Back the secret
(secrets/vault_secret) up separately, somewhere else.
"""
from __future__ import annotations

import datetime as dt
import os
import shutil
import sqlite3
import time
from pathlib import Path

from .db import Database

ESSENTIAL = ('vault_meta', 'ssh_keys', 'key_bindings', 'users', 'hosts', 'blueprints', 'move_plans', 'audit_log')
PREFIX = {'essentials': 'storageforge-essentials-', 'full': 'storageforge-full-'}


def backup_dir() -> Path:
    d = Path(os.environ.get('STORAGEFORGE_BACKUP_DIR') or
             Path(os.environ.get('STORAGEFORGE_DATA_DIR', '~/.local/share/storageforge')).expanduser() / 'backups')
    d.mkdir(parents=True, exist_ok=True, mode=0o700)
    return d


def _sqlite_path(db: Database) -> str:
    if db.dialect != 'sqlite':
        raise SystemExit('backups of a PostgreSQL database are pg_dump\'s job: pg_dump -Fc storageforge > storageforge.dump')
    return db.path


def create(db: Database, kind: str = 'essentials', dest: Path | None = None, keep: int | None = None) -> dict:
    """Write one backup; with keep, delete the oldest of that kind beyond it. Returns path, size and seconds."""
    src = _sqlite_path(db)
    dest = dest or backup_dir()
    stamp = dt.datetime.now().strftime('%Y%m%d-%H%M%S')
    out = dest / f'{PREFIX[kind]}{stamp}.db'
    part = out.with_suffix('.db.part')
    started = time.time()
    if kind == 'full':
        s, d = sqlite3.connect(f'file:{src}?mode=ro', uri=True), sqlite3.connect(part)
        try:
            s.backup(d, pages=4096, sleep=0.01)       # online: the server keeps writing while this runs
        finally:
            d.close()
            s.close()
    else:
        fresh = Database(str(part))
        c = fresh.connect()
        try:
            fresh.migrate(c)
        finally:
            c.close()
        d = sqlite3.connect(str(part), isolation_level=None, uri=True)
        try:
            d.execute('ATTACH DATABASE ? AS src', (f'file:{src}?mode=ro',))
            d.execute('BEGIN')
            for t in ESSENTIAL:
                cols = [r[1] for r in d.execute(f'PRAGMA main.table_info({t})')]
                have = {r[1] for r in d.execute(f'PRAGMA src.table_info({t})')}
                shared = ', '.join(c for c in cols if c in have)
                d.execute(f'INSERT INTO main.{t} ({shared}) SELECT {shared} FROM src.{t}')
            d.execute('COMMIT')
            d.execute('DETACH DATABASE src')
            d.execute('VACUUM')
        finally:
            d.close()
    os.chmod(part, 0o600)
    part.rename(out)
    removed = prune(dest, kind, keep) if keep else []
    return {'path': str(out), 'kind': kind, 'bytes': out.stat().st_size, 'seconds': round(time.time() - started, 1),
            'removed': removed}


def listing(dest: Path | None = None) -> list[dict]:
    dest = dest or backup_dir()
    out = []
    for kind, pre in PREFIX.items():
        for f in sorted(dest.glob(pre + '*.db'), reverse=True):
            out.append({'kind': kind, 'path': str(f), 'bytes': f.stat().st_size, 'created': int(f.stat().st_mtime)})
    return sorted(out, key=lambda b: -b['created'])


def prune(dest: Path, kind: str, keep: int) -> list[str]:
    old = sorted(dest.glob(PREFIX[kind] + '*.db'), reverse=True)[keep:]
    for f in old:
        f.unlink()
    return [str(f) for f in old]


def restore(db: Database, source: str) -> dict:
    """Replace the database with a backup. The current one is kept beside it as index.db.pre-restore-<time>.
    Stop the server first: restoring under a running server would be overwritten by its next write."""
    src, target = Path(source), Path(_sqlite_path(db))
    con = sqlite3.connect(f'file:{src}?mode=ro', uri=True)
    try:
        try:
            tables = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
        except sqlite3.DatabaseError:
            raise SystemExit(f'{src} is not a database') from None
        if not {'vault_meta', 'ssh_keys', 'schema_version'} <= tables:
            raise SystemExit(f'{src} is not a StorageForge backup')
        if con.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
            raise SystemExit(f'{src} fails integrity_check; pick another backup')
        keys = con.execute('SELECT count(*) FROM ssh_keys').fetchone()[0]
        files = con.execute('SELECT count(*) FROM file_records').fetchone()[0] if 'file_records' in tables else 0
    finally:
        con.close()
    kept = None
    if target.exists():
        kept = target.with_name(f'{target.name}.pre-restore-{dt.datetime.now():%Y%m%d-%H%M%S}')
        target.rename(kept)
        for side in ('-wal', '-shm'):
            p = Path(str(target) + side)
            if p.exists():
                p.rename(Path(str(kept) + side))
    shutil.copy2(src, target)
    os.chmod(target, 0o600)
    restored = Database(str(target))
    c = restored.connect()
    try:
        restored.migrate(c)                       # bring an older backup up to this schema
    finally:
        c.close()
    return {'restored': str(src), 'keys': keys, 'files': files, 'previous': str(kept) if kept else None}
