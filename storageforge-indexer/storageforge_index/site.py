"""Which client a database belongs to. One database is one site: the id stops one client's backup being restored over
another's, and the name is shown wherever someone could act on the wrong client by mistake. Kept in settings, so
backups carry it."""
from __future__ import annotations

import json
import re
import sqlite3
import uuid
from pathlib import Path

from .alerts import get_setting, set_setting
from .db import Conn

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


def export_dir(conn: Conn, root: str) -> str:
    """A named site's host configuration bundles get their own folder, so a shared mount never mixes two clients."""
    named = name(conn)
    return str(Path(root) / slug(named)) if named else root


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
