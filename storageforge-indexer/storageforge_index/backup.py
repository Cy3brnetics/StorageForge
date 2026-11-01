"""Database backups: small "essentials" copies nightly, full copies on demand, and restore.

The database is mostly the file index, which a rescan rebuilds. What cannot be rebuilt is small: the encrypted SSH
keys and their bindings, web users, designs, plans and tasks, settings, deploy state, confirmed host keys, the audit
log, the host list and each host's configuration history. An essentials backup is a
fresh database with the full schema holding just those tables (a few MB), so it restores into a working instance
that then rescans. A full backup is SQLite's online backup of everything, consistent while the server runs.

Neither contains the vault secret, by design: a backup plus its secret would be the keys. Back the secret
(secrets/vault_secret) up separately, somewhere else.
"""
from __future__ import annotations

import datetime as dt
import os
import shlex
import shutil
import sqlite3
import tempfile
import threading
import time
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import site
from .db import Database
from .vault import derive_kek

_names = threading.Lock()

ESSENTIAL = ('vault_meta', 'ssh_keys', 'key_bindings', 'users', 'hosts', 'blueprints', 'move_plans', 'audit_log',
             'change_plans', 'storage_tasks', 'settings', 'deploy_access', 'deployed', 'jobs',
             'host_key_confirmations', 'host_configs', 'schedules', 'roles', 'invites', 'clamav_detections')
# Left out of essentials: a rescan or the next deploy rebuilds these, they are history, or they are sessions.
# Every table is in exactly one of the two lists (tests/test_consistency.py).
REBUILDABLE = ('mounts', 'scans', 'directories', 'file_records', 'file_fts', 'file_changes', 'scan_denied', 'scan_jobs',
               'graph_nodes', 'graph_edges', 'git_repos', 'docker_hosts', 'deploy_runs', 'deploy_groups', 'host_checks', 'job_runs', 'alerts',
               'web_sessions', 'schema_version', 'task_runs', 'host_logs', 'mount_usage', 'schedule_runs', 'job_state', 'clamav_runs')
ENC_MAGIC, ENC_SUFFIX, ENC_CHUNK = b'STORAGEFORGE-BACKUP-1\n', '.enc', 1 << 20
ENC_KDF = {'time_cost': 3, 'memory_kib': 65536, 'lanes': 4}    # as the vault's own key
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
    with _names:      # two backups in the same second (the button and the nightly one) get their own files
        for extra in ('', *'bcdefghijklmnopqrstuvwxyz'):     # a letter sorts after the plain name: still newest first
            out = dest / f'{PREFIX[kind]}{stamp}{extra}.db'
            part = out.with_suffix('.db.part')
            if not out.exists() and not part.exists():
                part.touch(mode=0o600)
                break
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
                if not shared:                    # the live database predates this table
                    continue
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


def receive_script(path: str, directory: str, keep: int, suffix: str = '') -> str:
    """Bash that writes its stdin into a folder as one backup, then keeps the newest few there."""
    d, name = shlex.quote(directory.rstrip('/') or '/'), Path(path).name + suffix
    q = shlex.quote(name)
    return (f'umask 077; mkdir -p {d} && cat > {d}/{q}.part && mv {d}/{q}.part {d}/{q} && '
            f'ls -1t {d} | grep "^{PREFIX["essentials"]}" | grep -v "\\.part$" | tail -n +{keep + 1} | while read -r f; do rm -f -- {d}/"$f"; done')


def send_file(t, path: str, directory: str, keep: int) -> None:
    """Write one essentials backup into a folder over t, then keep the newest few there. Only the folder's own backups
    are ever removed."""
    script = receive_script(path, directory, keep)
    proc = t.stream(script, stdin=True)
    try:
        with open(path, 'rb') as f:
            shutil.copyfileobj(f, proc.stdin)
        proc.stdin.close()
        err = proc.stderr.read().decode('utf-8', 'replace').strip()
        if proc.wait() != 0:
            raise RuntimeError(err[-300:] or f'copy to {directory} failed')
    finally:
        proc.stdout.close()
        proc.stderr.close()


def encrypted(path: str, secret: bytes):
    """A backup as chunks of ciphertext. It holds password hashes, alert tokens and host configs in the clear, and the key
    comes from the vault secret alone: the backup is what you restore a lost vault from, so nothing inside it can be needed."""
    salt, n = os.urandom(16), 0
    header = ENC_MAGIC + salt
    key = derive_kek(secret, salt, ENC_KDF)
    sealer = AESGCM(bytes(key.view()))
    yield header
    with open(path, 'rb') as f:
        chunk = f.read(ENC_CHUNK)
        while True:
            following = f.read(ENC_CHUNK)
            last = not following
            box = sealer.encrypt(n.to_bytes(11, 'big') + (b'\1' if last else b'\0'), chunk, header)
            yield len(box).to_bytes(4, 'big') + box
            if last:
                return
            chunk, n = following, n + 1


def decrypt_file(source: str, target: str, secret: bytes) -> None:
    """Undoes encrypted(). A wrong secret, a changed byte or a file cut short all fail here."""
    with open(source, 'rb') as f, open(target, 'wb') as out:
        os.chmod(target, 0o600)
        header = f.read(len(ENC_MAGIC) + 16)
        if not header.startswith(ENC_MAGIC) or len(header) != len(ENC_MAGIC) + 16:
            raise SystemExit(f'{source} is not an encrypted StorageForge backup')
        key = derive_kek(secret, header[len(ENC_MAGIC):], ENC_KDF)
        sealer, n = AESGCM(bytes(key.view())), 0
        while True:
            size = int.from_bytes(f.read(4), 'big')
            box = f.read(size)
            at_end = f.peek(1) == b''
            try:
                out.write(sealer.decrypt(n.to_bytes(11, 'big') + (b'\1' if at_end else b'\0'), box, header))
            except InvalidTag:
                raise SystemExit(f'{source} cannot be decrypted: wrong vault secret, or the file is damaged or cut short') from None
            if at_end:
                return
            n += 1


def copy_off(db: Database, conn, path: str, target: dict, keep: int) -> None:
    """Send a backup to target {"host", "path"}, encrypted, as a signed run with the file on its stdin: the deploy key can start
    only the runner, which refuses anything unsigned. No vault secret here means no copy, never a copy in the clear."""
    from . import deploy
    from .vault import secret_from_env
    res = deploy.run(db, target['host'], receive_script(path, target['path'], keep, ENC_SUFFIX), kind='backup_copy', ref=Path(path).name,
                     mode='apply', actor='system', data=encrypted(path, secret_from_env()), timeout=3600)
    if res['status'] != 'ok':
        raise RuntimeError(res['output'].strip()[-300:] or f'copy to {target["host"]} failed')


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
    with open(src, 'rb') as f:
        sealed = f.read(len(ENC_MAGIC)) == ENC_MAGIC
    if sealed:
        from .vault import secret_from_env
        # a private folder that goes whole: reading the copy can leave -wal and -shm beside it, all of it in the clear
        with tempfile.TemporaryDirectory(dir=target.parent, prefix='.restore-') as folder:
            plain = Path(folder) / 'backup.db'
            decrypt_file(str(src), str(plain), secret_from_env())
            return restore(db, str(plain))
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
    refused, warning = site.restore_problem(site.read_file(target) if target.exists() else None, site.read_file(src))
    if refused:
        raise SystemExit(refused)
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
    return {'restored': str(src), 'keys': keys, 'files': files, 'previous': str(kept) if kept else None, 'warning': warning}
