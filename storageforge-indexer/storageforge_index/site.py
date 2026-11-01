"""Which client a database belongs to. One database is one site: the id stops one client's backup being restored over
another's, and the name is shown wherever someone could act on the wrong client by mistake. Kept in settings, so
backups carry it."""
from __future__ import annotations

import datetime as dt
import json
import os
import re
import sqlite3
import uuid
from functools import wraps
from pathlib import Path

from .alerts import get_setting, set_setting
from .db import Conn
from .scriptkit import one_line

ID_KEY, NAME_KEY = 'site.id', 'site.name'
MAX_NAME = 64


def clean_name(name: str) -> str:
    name = ' '.join(str(name or '').split())
    if not name or len(name) > MAX_NAME:
        raise SystemExit(f'a site name is 1 to {MAX_NAME} characters')
    return name


def slug(name: str | None) -> str:
    """The name as a folder name."""
    return re.sub(r'[^a-z0-9]+', '-', (name or '').lower()).strip('-') or 'unnamed'


def site_id(conn: Conn) -> str | None:
    return get_setting(conn, ID_KEY)


def ensure(conn: Conn) -> str:
    """This database's id, made the first time it is asked for."""
    sid = site_id(conn)
    if not sid:
        sid = uuid.uuid4().hex
        set_setting(conn, ID_KEY, sid, 'system')
    return sid


def name(conn: Conn) -> str | None:
    return get_setting(conn, NAME_KEY)


def rename(conn: Conn, new: str, actor: str) -> str:
    new = clean_name(new)
    set_setting(conn, NAME_KEY, new, actor)
    return new


def stamp(conn: Conn, script: str) -> str:
    """A script says which client it is for, so nobody runs it on the wrong client's machines. Nothing for an unnamed site."""
    named = name(conn)
    if not named:
        return script
    line = f'# Site: {one_line(named)}\n'
    if script.startswith('#!'):
        first, _, rest = script.partition('\n')
        return f'{first}\n{line}{rest}'
    return line + script


def stamped(fn):
    """For a generator whose first argument is the connection."""
    @wraps(fn)
    def inner(conn, *args, **kwargs):
        return stamp(conn, fn(conn, *args, **kwargs))
    return inner


def export_dir(conn: Conn, root: str) -> str:
    """A named site's host configuration bundles get their own folder, so a shared mount never mixes two clients."""
    named = name(conn)
    return str(Path(root) / slug(named)) if named else root


def fingerprints(conn: Conn) -> list[tuple[str, str, str]]:
    """(kind, fingerprint, label) of this site's keys and machines, for comparing sites. Public values only."""
    out = [('key', fp, n) for n, fp in conn.all('SELECT name, fingerprint FROM ssh_keys')]
    for hostname, keys in conn.all('SELECT hostname, host_keys FROM hosts WHERE host_keys IS NOT NULL'):
        out += [('host', fp, hostname) for fp in json.loads(keys) if fp.startswith('SHA256:')]
    return out


def foreign() -> dict[str, set[str]]:
    """Fingerprints in use on other sites of this machine, from the file sf-site writes. It names no sites, so one
    client's stack learns nothing about another's. Empty when there is no such file."""
    found = {'key': set(), 'host': set()}
    try:
        lines = Path(os.environ.get('STORAGEFORGE_FOREIGN_FILE', '/run/sf-foreign')).read_text().splitlines()
    except OSError:
        return found
    for line in lines:
        kind, _, fp = line.partition(' ')
        if kind in found and fp:
            found[kind].add(fp)
    return found


def shared_problems(conn: Conn) -> dict:
    """Alerts for what this site shares with another. Not refused: a machine can change owners, or a VM be cloned."""
    other, now = foreign(), {}
    for kind, fp, label in fingerprints(conn):
        if fp not in other[kind]:
            continue
        if kind == 'key':
            now[f'shared-key:{label}'] = ('shared-key', label, f'Key {label} is also in another site',
                                          f'{fp}: one key should not serve two clients. Generate a new one here.', 'crit')
        else:
            now[f'shared-host:{label}'] = ('shared-host', label, f'{label} is also in another site',
                                           f'{fp}: the same SSH host key is in another site. A machine that changed '
                                           'owners should be retired from the old site; a cloned VM needs new host keys.', 'warn')
    return now


def status(conn: Conn) -> dict:
    """The few facts an overview of all sites shows. No file names, paths or addresses."""
    from .backup import listing
    from .db import epoch
    def clock(ts):
        return dt.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M') if ts else '-'
    made = [b['created'] for b in listing()]
    scans = [epoch(r[0]) for r in conn.all('SELECT last_scanned_at FROM hosts WHERE last_scanned_at IS NOT NULL')]
    return {'name': name(conn) or '(no name)', 'hosts': conn.scalar('SELECT count(*) FROM hosts'),
            'last_scan': clock(max(scans, default=None)), 'alerts': conn.scalar("SELECT count(*) FROM alerts WHERE state = 'open'"),
            'last_backup': clock(max(made, default=None))}


def read_file(path) -> dict | None:
    """What a SQLite file says about its site, without changing it. None when it cannot be read as a database."""
    con = None
    try:
        con = sqlite3.connect(f'file:{path}?mode=ro', uri=True)
        tables = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
        found = dict(con.execute('SELECT key, value_json FROM settings')) if 'settings' in tables else {}

        def count(table):
            return con.execute(f'SELECT count(*) FROM {table}').fetchone()[0] if table in tables else 0
        value = lambda k: json.loads(found[k]) if found.get(k) else None    # noqa: E731
        return {'id': value(ID_KEY), 'name': value(NAME_KEY), 'policy': value('vault.policy'),
                'hosts': count('hosts'), 'keys': count('ssh_keys')}
    except sqlite3.DatabaseError:
        return None
    finally:
        if con:
            con.close()


def restore_problem(mine: dict | None, theirs: dict | None) -> tuple[str | None, str | None]:
    """(why this restore is refused, what to warn about). Nothing is at stake in a database with no name, hosts or keys:
    that is a rebuild. A backup holds a vault, so it is never merged: it goes back on its own site or on a blank one."""
    if not mine or not (mine['name'] or mine['hosts'] or mine['keys']):
        return None, None
    label = mine['name'] or mine['id'] or 'this site'
    if not (theirs and theirs['id']):
        if mine['policy'] == 'generate-only':
            return (f'that backup names no site, and {label} only takes keys generated in its own vault. '
                    'Restore it on a blank site.'), None
        return None, f'that backup names no site, so it could not be checked against {label}'
    if mine['id'] and mine['id'] != theirs['id']:
        return (f'that backup is from {theirs["name"] or "another site"} (site {theirs["id"]}), not {label}. '
                "A backup holds its site's SSH keys, so it only goes back on that site or on a blank one."), None
    return None, None
