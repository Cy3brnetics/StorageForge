"""Start a new environment on this install: archive everything of the old site, then a new database and a new vault.

Nothing is deleted until the archive is complete. A new database rather than emptied tables, because the audit log's
triggers refuse DELETE, and the old log stays whole in the archive. The vault secret always changes and the archive
holds the old one, so the archive belongs outside anything the new site's server can read: --archive may not be in its
data or backup folders. The new site only takes keys generated in its own vault.
"""
from __future__ import annotations

import datetime as dt
import fcntl
import json
import os
import secrets
import shutil
from pathlib import Path

from . import backup, site, users
from .alerts import get_setting, set_setting
from .db import Conn, Database
from .runner import data_dir
from .vault import MIN_SECRET_LEN, POLICY_KEY, AuditLog, Vault, actor_name, importable_keys, secret_from_env

README = """StorageForge archive of {name} (site {id}), made {when}.

  database/       a full backup of the database
  backups/        the backups that were on that install
  data/           its known_hosts and SSH home, and databases kept by earlier restores
  left-behind.json  what is still on that client's machines: remove it there
  vault_secret    the secret that unlocks this vault

The database plus vault_secret are that client's SSH keys. Keep them apart, off this machine, or destroy them when the
contract says so.

To read it: storageforge-index --db database/<file> with STORAGEFORGE_VAULT_SECRET_FILE set to vault_secret.
"""


def hold_server_lock(db: Database):
    """Held while a server runs on this database, across containers too (same volume, same kernel). Keep the returned
    file open; the lock goes with the process however it ends. PostgreSQL has no file to lock."""
    if db.dialect != 'sqlite':
        return None
    f = open(f'{db.path}.serverlock', 'a')    # noqa: SIM115
    try:
        fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        f.close()
        raise SystemExit('a server is running on this database; stop it first '
                         '(docker compose stop storageforge)') from None
    return f


def left_behind(conn: Conn) -> dict:
    """What StorageForge put on this client's machines or elsewhere, which a new database can no longer see."""
    out = {'deployed': [{'host': h, 'kind': k, 'ref': r} for h, k, r in conn.all('SELECT host, kind, ref FROM deployed')],
           'jobs': [{'name': n, 'runner_host': h} for n, h in conn.all(
               'SELECT name, runner_host FROM jobs WHERE removed_at IS NULL')],
           'schedules': [{'name': n, 'host': h} for n, h in conn.all('SELECT name, host FROM schedules')],
           'deploy_access': [{'host': h, 'state': s} for h, s in conn.all('SELECT host, state FROM deploy_access')]}
    out['keys_on_hosts'] = [{'key': n, 'fingerprint': f, 'host': p, 'user': u} for n, f, p, u in conn.all(
        """SELECT k.name, k.fingerprint, b.host_pattern, b.ssh_user
           FROM key_bindings b JOIN ssh_keys k ON k.key_id = b.key_id""")]
    out['backup_copies'] = get_setting(conn, 'backup.target') or None
    return out


def _blocking(left: dict) -> list[str]:
    lines = [f'{x["kind"]} {x["ref"]} is deployed on {x["host"]}' for x in left['deployed']]
    lines += [f'job {x["name"]} runs on {x["runner_host"]}' for x in left['jobs']]
    lines += [f'schedule {x["name"]} runs on {x["host"]}' for x in left['schedules']]
    lines += [f'{x["host"]} has deploy access ({x["state"]})' for x in left['deploy_access']]
    return lines


def _new_secret(current: bytes) -> tuple[str, bool]:
    """(the new vault secret, whether this command can put it in place)."""
    given = os.environ.get('STORAGEFORGE_VAULT_NEW_SECRET')
    if given:
        if len(given) < MIN_SECRET_LEN:
            raise SystemExit(f'STORAGEFORGE_VAULT_NEW_SECRET must be at least {MIN_SECRET_LEN} characters')
        if given.encode() == current:
            raise SystemExit("STORAGEFORGE_VAULT_NEW_SECRET is the old secret; a new site never shares its client's secret")
        return given, False
    path = os.environ.get('STORAGEFORGE_VAULT_SECRET_FILE')
    if not path or os.environ.get('STORAGEFORGE_VAULT_SECRET'):
        raise SystemExit('the vault secret comes from the environment, which this command cannot change. '
                         'Set STORAGEFORGE_VAULT_NEW_SECRET to a new one (openssl rand -base64 48) and rerun.')
    folder = Path(path).parent
    if folder.stat().st_uid != os.getuid() or os.statvfs(folder).f_flag & os.ST_RDONLY:
        raise SystemExit(f'{folder} is not writable here, so the vault secret cannot change. In Docker, run this '
                         'through the admin service: docker compose run --rm admin reset ...')
    return secrets.token_urlsafe(48), True


def _install_secret(path: Path, value: str) -> None:
    """Replace the secret file. init-volumes.sh leaves its folder read-only, even to its owner."""
    folder, mode = path.parent, path.stat().st_mode & 0o777
    was = folder.stat().st_mode & 0o777
    folder.chmod(was | 0o700)
    try:
        part = path.with_name(f'.{path.name}.new')
        fd = os.open(part, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'w') as f:
            f.write(value)
        part.chmod(mode)
        os.replace(part, path)
    finally:
        folder.chmod(was)


def _check_archive(root: str | None, db_path: Path, backups: Path) -> Path:
    if not root:
        raise SystemExit('say where the archive goes: --archive DIR or $STORAGEFORGE_ARCHIVE_DIR. It holds the old '
                         'keys and their secret, so outside the data and backup folders.')
    out = Path(root).expanduser().resolve()
    for inside in (data_dir().resolve(), db_path.parent.resolve(), backups.resolve()):
        if out == inside or inside in out.parents:
            raise SystemExit(f'{out} is inside {inside}, where the new site could read the old keys and their secret')
    if not (out.is_dir() and os.access(out, os.W_OK | os.X_OK)):
        raise SystemExit(f'{out} must be a folder writable by uid {os.getuid()}')
    return out


def _check_keys_folder() -> None:
    """Keys waiting in the import folder are the old client's. The new vault refuses them; empty it all the same."""
    folder = Path(os.environ.get('STORAGEFORGE_IMPORT_DIR', '/run/secrets/ssh-import'))
    if not folder.is_dir():
        return
    try:
        found = [f.name for f in importable_keys(folder)]
    except OSError as exc:
        raise SystemExit(f'cannot check {folder} for old keys: {exc}') from None
    if found:
        raise SystemExit(f'{folder} still holds keys ({", ".join(found[:5])}); they belong to the old client. '
                         'Take them out (./keys on the Docker host) and rerun.')


def _copy_into(paths, dest: Path) -> None:
    for p in paths:
        dest.mkdir(parents=True, exist_ok=True, mode=0o700)
        if p.is_dir() and not p.is_symlink():
            shutil.copytree(p, dest / p.name, symlinks=True)
        else:
            shutil.copy2(p, dest / p.name, follow_symlinks=False)


def _remove(paths) -> None:
    for p in paths:
        if p.is_dir() and not p.is_symlink():
            shutil.rmtree(p)
        else:
            p.unlink(missing_ok=True)


def _build(path: Path, new_name: str, secret: str, previous: str | None, actor: str) -> str:
    """The new database, off to the side. Returns the token of the first admin's invite."""
    fresh = Database(str(path))
    conn = fresh.connect()
    try:
        fresh.migrate(conn)
        site.ensure(conn)
        site.rename(conn, new_name, actor)
        set_setting(conn, POLICY_KEY, 'generate-only', actor)
        v = Vault(fresh, conn, secret.encode())
        v.init()
        with v.unlock():
            AuditLog(fresh, conn, v.audit_key).append(actor, 'site.created', 'ok', None, None,
                                                      {'name': new_name, 'replaces': previous})
        return users.create_invite(conn, 'admin', 'reset', hours=72, note='first admin')[1]
    finally:
        conn.close()


def _old_files(target: Path, backups: Path) -> tuple[list[Path], list[Path]]:
    kept = [p for p in (data_dir() / d for d in ('ssh', 'home')) if p.exists()] + sorted(
        target.parent.glob(f'{target.name}.pre-restore-*'))
    return kept, sorted(backups.glob('storageforge-*'))


def _check_space(root: Path, target: Path, old_backups: list[Path]) -> None:
    need = target.stat().st_size + sum(p.stat().st_size for p in old_backups if p.is_file())
    if shutil.disk_usage(root).free < need * 1.1:
        raise SystemExit(f'{root} has too little free space for the archive ({need:,} bytes)')


def _write_archive(db: Database, part: Path, secret: bytes, old_backups, kept_data, left: dict, old_name, old_id) -> None:
    part.mkdir(mode=0o700)
    (part / 'database').mkdir(mode=0o700)
    backup.create(db, 'full', part / 'database')
    _copy_into(old_backups, part / 'backups')
    _copy_into(kept_data, part / 'data')
    fd = os.open(part / 'vault_secret', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(secret)
    (part / 'left-behind.json').write_text(json.dumps(left, indent=2) + '\n')
    (part / 'README.txt').write_text(README.format(name=old_name or 'an unnamed site', id=old_id,
                                                   when=dt.datetime.now().strftime('%Y-%m-%d %H:%M')))


def archive(db: Database, archive_root: str | None) -> dict:
    """The same archive reset makes, leaving the site as it is. A site that is leaving, before its volumes go."""
    if db.dialect != 'sqlite':
        raise SystemExit('archives are of SQLite databases (PostgreSQL: pg_dump -Fc)')
    target, backups = Path(db.path), backup.backup_dir()
    archive_root = _check_archive(archive_root, target, backups)
    lock = hold_server_lock(db)
    conn = db.connect()
    try:
        db.migrate(conn)
        current = secret_from_env()
        v = Vault(db, conn, current)
        audit_key = v.unlock().audit_key if v.initialized else None     # a wrong secret stops here: the archive would be unreadable
        kept_data, old_backups = _old_files(target, backups)
        _check_space(archive_root, target, old_backups)
        left, old_id, old_name = left_behind(conn), site.ensure(conn), site.name(conn)
        name = f'{site.slug(old_name)}-{dt.datetime.now():%Y%m%d-%H%M%S}'
        AuditLog(db, conn, audit_key).append(actor_name(), 'site.archive', 'ok', None, None, {'archive': name})
        if v.initialized:
            v.close()
        part = archive_root / f'.{name}.part'
        _write_archive(db, part, current, old_backups, kept_data, left, old_name, old_id)
        part.rename(archive_root / name)
        return {'archive': str(archive_root / name), 'left': left}
    finally:
        conn.close()
        if lock:
            lock.close()


def run(db: Database, new_name: str, archive_root: str | None, abandon_deployed: bool) -> dict:
    if db.dialect != 'sqlite':
        raise SystemExit('reset works on SQLite. For PostgreSQL: pg_dump -Fc the database, create a new one, point '
                         'STORAGEFORGE_DB at it, and change the vault secret.')
    new_name = site.clean_name(new_name)
    target, backups = Path(db.path), backup.backup_dir()
    archive_root = _check_archive(archive_root, target, backups)
    lock = hold_server_lock(db)
    conn = db.connect()
    try:
        db.migrate(conn)
        _check_keys_folder()
        current = secret_from_env()
        v = Vault(db, conn, current)
        audit_key = v.unlock().audit_key if v.initialized else None     # a wrong secret stops here: the archive would be unreadable
        new_secret, installs = _new_secret(current)
        left = left_behind(conn)
        if (blocking := _blocking(left)) and not abandon_deployed:
            shown = '\n  '.join(blocking[:20]) + (f'\n  ... and {len(blocking) - 20} more' if len(blocking) > 20 else '')
            raise SystemExit(f'still on the old machines, running as root:\n  {shown}\nRemove them first (Deploy, or '
                             'storageforge-index schedule remove), or pass --abandon-deployed to leave them there; '
                             'the list goes in the archive.')
        old_id, old_name = site.ensure(conn), site.name(conn)
        kept_data, old_backups = _old_files(target, backups)
        _check_space(archive_root, target, old_backups)
        name = f'{site.slug(old_name)}-{dt.datetime.now():%Y%m%d-%H%M%S}'
        final, part = archive_root / name, archive_root / f'.{name}.part'
        actor = actor_name()
        AuditLog(db, conn, audit_key).append(actor, 'site.reset', 'ok', None, None, {'archive': name, 'new_name': new_name})
        if v.initialized:
            v.close()

        # the archive, whole, before anything goes
        _write_archive(db, part, current, old_backups, kept_data, left, old_name, old_id)
        conn.close()
        conn = None

        side = target.with_name(f'{target.name}.new')
        _remove(side.with_name(side.name + s) for s in ('', '-wal', '-shm'))
        token = _build(side, new_name, new_secret, old_id, actor)
        part.rename(final)

        # from here on the old site only exists in the archive
        _remove(target.with_name(target.name + s) for s in ('', '-wal', '-shm'))
        os.replace(side, target)
        os.chmod(target, 0o600)
        if installs:
            _install_secret(Path(os.environ['STORAGEFORGE_VAULT_SECRET_FILE']), new_secret)
        _remove([*old_backups, *kept_data])
        if (data_dir() / 'tmp').is_dir():
            _remove(list((data_dir() / 'tmp').iterdir()))
        return {'archive': str(final), 'token': token, 'secret_installed': installs, 'left': left,
                'abandoned': len(blocking), 'name': new_name}
    finally:
        if conn:
            conn.close()
        if lock:
            lock.close()
