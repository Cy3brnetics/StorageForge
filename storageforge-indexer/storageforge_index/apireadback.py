"""The read-back (roadmap section 13): what a platform token can really do, read from the platform itself and compared with the guide.

After a token is entered and on every read, the platform is asked for the token's own effective permissions (each Proxmox product's
GET /access/permissions, which with no user named answers for the token making the request), and, where the platform says, the token's
expiry and privilege separation (GET /access/users/USER/token/NAME). Then, against apiguide.GUIDES:

    short     a reading feature whose privilege the token lacks: that feature will not be read, and the answer says what to add, where.
    over      a privilege that changes something (anything but .Audit) that no action turned on needs. A security finding in the
              notification center that cannot be muted or snoozed (its kind starts with security-), and that leaves when a read-back
              finds the token narrowed or replaced. A privilege that gives control of the platform itself (its users, permissions or
              system) makes it critical.
    exact     neither.

Read-only privileges beyond the guide (Pool.Audit, SDN.Audit, a whole cluster rather than three paths) are listed, not a finding: they
change nothing.
"""
from __future__ import annotations

import json
import time

from . import apiguide
from .db import Conn, loads


def _data(text: str):
    """The 'data' of a Proxmox API answer, or None when the text is not one."""
    try:
        doc = json.loads(text)
    except (ValueError, TypeError, RecursionError):
        return None
    return doc.get('data') if isinstance(doc, dict) else None


def parse_permissions(text: str) -> dict:
    """{'paths': {path: {privilege: propagates}}, 'unreadable': bool}. A path or privilege that is not a string is dropped."""
    data = _data(text)
    if not isinstance(data, dict):
        return {'paths': {}, 'unreadable': True}
    paths = {}
    for path, privs in data.items():
        if not isinstance(path, str) or not path.startswith('/') or not isinstance(privs, dict):
            continue
        paths[path[:300]] = {p[:100]: bool(v) for p, v in privs.items() if isinstance(p, str) and p and isinstance(v, (bool, int, float))}
    return {'paths': paths, 'unreadable': False}


def parse_token_info(text: str) -> dict:
    """{'expire': epoch or 0 for none or None unread, 'privsep': bool or None, 'enable': bool or None}."""
    data = _data(text)
    if not isinstance(data, dict):
        return {'expire': None, 'privsep': None, 'enable': None}

    def num(v):
        return int(v) if isinstance(v, (int, float)) and not isinstance(v, bool) and v == v and abs(v) < 1e12 else None

    def flag(v):
        return bool(v) if isinstance(v, (bool, int)) else None
    return {'expire': num(data.get('expire')), 'privsep': flag(data.get('privsep')), 'enable': flag(data.get('enable'))}


def _covers(path: str, roots: list[str]) -> bool:
    return any(path == r or (r != '/' and path.startswith(r + '/')) for r in roots)


def judge(kind: str, paths: dict, actions: list[str] | None = None, token: dict | None = None, now: float | None = None) -> dict:
    """Compare a token's effective permissions with the guide."""
    g = apiguide.GUIDES[kind]
    allowed = {p for a in (actions or []) for p in (g['actions'].get(a) or {}).get('privs', [])}
    features, short = {}, []
    for f, need in g['read'].items():
        have = [p for p, privs in paths.items() if _covers(p, need['paths']) and all(privs.get(x) is not None for x in need['privs'])]
        ok = bool(have)
        features[f] = {'ok': ok, 'what': need['what'], 'on': have}
        if not ok:
            short.append({'feature': f, 'what': need['what'],
                          'add': f'{" and ".join(need["privs"])} ({g["role"]}) for the token and its user on {" or ".join(need["paths"])}'})
    for a in actions or []:
        need = (g['actions'].get(a) or {}).get('privs', [])
        missing = [x for x in need if not any(x in privs for privs in paths.values())]
        if missing:
            short.append({'feature': f'action {a}', 'what': g['actions'][a]['title'], 'add': f'{", ".join(missing)} on {g["actions"][a]["on"]}'})
    over, extra = [], []
    for path, privs in sorted(paths.items()):
        for priv in sorted(privs):
            if priv.endswith('.Audit'):
                if not any(priv in need['privs'] for need in g['read'].values()):
                    extra.append({'path': path, 'priv': priv})
            elif priv not in allowed:
                over.append({'path': path, 'priv': priv, 'admin': priv in g['admin']})
    notes = []
    token = token or {}
    if token.get('privsep') is False:
        notes.append('privilege separation is off: the token has every right its user has. Make it again with -privsep 1')
    if token.get('enable') is False:
        notes.append('the token is disabled on the platform')
    expire = token.get('expire')
    if expire == 0:
        notes.append('the token has no expiry date: the guide recommends one')
    elif expire and expire < (now or time.time()):
        notes.append('the token has expired')
    admin = any(o['admin'] for o in over)
    return {'kind': kind, 'verdict': 'over' if over else 'short' if short else 'exact', 'admin': admin, 'features': features, 'short': short,
            'over': over, 'extra_read': extra, 'token': token, 'notes': notes, 'actions': list(actions or [])}


def readback(client, row: dict) -> dict:
    """Ask the platform what this token can do. Raises apiconn.ApiError when the platform cannot be asked at all."""
    from . import apiconn
    perms = parse_permissions(client.get('/access/permissions'))
    if perms['unreadable']:
        raise apiconn.ApiError(f'{row["title"]} answered /access/permissions with something that is not a permission list')
    user, _, name = row['token_id'].partition('!')
    try:
        token = parse_token_info(client.get(f'/access/users/{client.seg(user)}/token/{client.seg(name)}'))
    except apiconn.ApiError:
        token = {'expire': None, 'privsep': None, 'enable': None}       # some platforms keep this from a token: the permissions above still stand
    return {**judge(row['kind'], perms['paths'], row.get('actions'), token), 'paths': perms['paths'], 'at': int(time.time())}


def store(conn: Conn, row: dict, result: dict) -> None:
    from . import apiconn
    conn.execute('UPDATE platform_connections SET readback_json = :r, readback_at = :t WHERE conn_id = :i',
                 {'r': json.dumps(result, sort_keys=True), 't': result.get('at') or int(time.time()), 'i': row['conn_id']})
    apiconn.note_expiry(conn, row, (result.get('token') or {}).get('expire'))


def problems(conn: Conn) -> dict:
    out = {}
    for name, kind, host, raw in conn.all('SELECT name, kind, host, readback_json FROM platform_connections WHERE readback_json IS NOT NULL'):
        r = loads(raw) or {}
        title = apiguide.GUIDES.get(kind, {}).get('title', kind)
        if r.get('verdict') == 'over':
            privs = sorted({o['priv'] for o in r.get('over') or []})
            out[f'security-api-token:{name}'] = ('security-api-token', host or name, f'The {title} token of {name} can do more than StorageForge needs',
                                                f'It holds {", ".join(privs[:12])}{" and more" if len(privs) > 12 else ""}. Narrow it to {apiguide.GUIDES[kind]["role"]} '
                                                'as the guide in Keys, Platform connections shows, or replace it. This leaves when a read-back finds it narrowed.',
                                                'crit' if r.get('admin') else 'warn')
        if r.get('short'):
            out[f'api-token-short:{name}'] = ('api-token-short', host or name, f'The {title} token of {name} lacks what some features need',
                                             '; '.join(f'{s["what"]}: add {s["add"]}' for s in r['short'])[:500], 'warn')
    return out
