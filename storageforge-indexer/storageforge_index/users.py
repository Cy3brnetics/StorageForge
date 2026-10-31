"""Local web UI accounts. Hashing is Werkzeug's (scrypt), sessions are Flask-Login's; this module only stores rows."""
from __future__ import annotations

import hashlib
import json
import re
import secrets
import time
from dataclasses import dataclass

from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash

from .db import Conn
from .permissions import ALL, BUILTIN

USERNAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,63}')
MIN_PASSWORD = 12
# A session ends this long after sign-in; users may raise their own up to the maximum.
SESSION_MINUTES, MAX_SESSION_MINUTES = 30, 480
# Compared against when the username does not exist, so a miss costs the same as a wrong password.
_DUMMY_HASH = generate_password_hash('storageforge-no-such-user')


ROLE_NAME = re.compile(r'[a-z0-9][a-z0-9._-]{0,31}')
# An invite link works once, until it expires; the lifetime is chosen when it is made.
INVITE_HOURS, MAX_INVITE_HOURS = 72, 720


class UserError(ValueError):
    pass


class InviteError(UserError):
    pass


@dataclass
class User(UserMixin):
    user_id: int
    username: str
    session_version: int
    session_minutes: int = SESSION_MINUTES
    role: str = 'admin'
    permissions: frozenset = frozenset()

    def get_id(self) -> str:   # Flask-Login stores this in the session; a version bump invalidates old sessions
        return f'{self.user_id}:{self.session_version}'


def load(conn: Conn, session_id: str) -> User | None:
    try:
        uid, ver = (int(x) for x in session_id.split(':'))
    except ValueError:
        return None
    rows = conn.all('SELECT user_id, username, session_version, session_minutes, role FROM users '
                    'WHERE user_id = :u AND session_version = :v AND disabled_at IS NULL', {'u': uid, 'v': ver})
    return User(*rows[0], permissions_of(conn, rows[0][4])) if rows else None


def authenticate(conn: Conn, username: str, password: str) -> User | None:
    rows = conn.all('SELECT user_id, username, session_version, session_minutes, role, password_hash FROM users '
                    'WHERE lower(username) = lower(:n) AND disabled_at IS NULL', {'n': username})
    if not rows:
        check_password_hash(_DUMMY_HASH, password)
        return None
    uid, name, ver, minutes, role, pw_hash = rows[0]
    if not check_password_hash(pw_hash, password):
        return None
    conn.execute('UPDATE users SET last_login_at = :t WHERE user_id = :u', {'t': int(time.time()), 'u': uid})
    return User(uid, name, ver, minutes, role, permissions_of(conn, role))


def confirm(conn: Conn, user_id: int, password: str) -> bool:
    """The signed-in user's password again, before commands run on hosts. Does not count as a sign-in."""
    pw_hash = conn.scalar('SELECT password_hash FROM users WHERE user_id = :u AND disabled_at IS NULL', {'u': user_id})
    return check_password_hash(pw_hash or _DUMMY_HASH, password) and pw_hash is not None


def _sid_hash(sid: str) -> str:
    return hashlib.sha256(sid.encode()).hexdigest()


def start_session(conn: Conn, user_id: int, client: str | None) -> str:
    """A new server-side session; returns the id that goes into the (signed) cookie. Only its hash is stored."""
    now = int(time.time())
    conn.execute('DELETE FROM web_sessions WHERE created_at < :t', {'t': now - MAX_SESSION_MINUTES * 60})
    sid = secrets.token_urlsafe(32)
    conn.execute('INSERT INTO web_sessions (sid_hash, user_id, created_at, client) VALUES (:h, :u, :t, :c)',
                 {'h': _sid_hash(sid), 'u': user_id, 't': now, 'c': (client or '')[:64]})
    return sid


def session_alive(conn: Conn, sid: str | None, user_id: int) -> bool:
    return bool(sid) and bool(conn.scalar('SELECT 1 FROM web_sessions WHERE sid_hash = :h AND user_id = :u',
                                          {'h': _sid_hash(sid), 'u': user_id}))


def end_session(conn: Conn, sid: str | None) -> None:
    if sid:
        conn.execute('DELETE FROM web_sessions WHERE sid_hash = :h', {'h': _sid_hash(sid)})


def end_all_sessions(conn: Conn, username: str) -> int:
    """Sign a user out of every browser."""
    uid = conn.scalar('SELECT user_id FROM users WHERE lower(username) = lower(:n)', {'n': username})
    if uid is None:
        raise UserError(f'no user {username!r}')
    return conn.execute('DELETE FROM web_sessions WHERE user_id = :u', {'u': uid}).rowcount


def set_session_minutes(conn: Conn, user_id: int, minutes: int) -> int:
    if not SESSION_MINUTES <= minutes <= MAX_SESSION_MINUTES:
        raise UserError(f'session length is {SESSION_MINUTES} to {MAX_SESSION_MINUTES} minutes')
    conn.execute('UPDATE users SET session_minutes = :m WHERE user_id = :u', {'m': minutes, 'u': user_id})
    return minutes


def _check_password(password: str):
    if len(password) < MIN_PASSWORD:
        raise UserError(f'password must be at least {MIN_PASSWORD} characters')


def permissions_of(conn: Conn, role: str) -> frozenset[str]:
    """What a role allows. A role that no longer exists allows nothing."""
    if role in BUILTIN:
        return BUILTIN[role][1]
    raw = conn.scalar('SELECT permissions FROM roles WHERE name = :n', {'n': role})
    return frozenset(json.loads(raw)) & ALL if raw else frozenset()


def role_exists(conn: Conn, role: str) -> bool:
    return role in BUILTIN or bool(conn.scalar('SELECT 1 FROM roles WHERE name = :n', {'n': role}))


def _check_role(conn: Conn, role: str):
    if not role_exists(conn, role):
        raise UserError(f'no role {role!r}')


def list_roles(conn: Conn) -> list[dict]:
    held = {r[0]: r[1] for r in conn.all('SELECT role, count(*) FROM users GROUP BY role')}
    out = [dict(name=n, description=d, permissions=sorted(p), builtin=True, users=held.get(n, 0)) for n, (d, p) in BUILTIN.items()]
    for name, desc, perms in conn.all('SELECT name, description, permissions FROM roles ORDER BY name'):
        out.append(dict(name=name, description=desc, permissions=sorted(set(json.loads(perms)) & ALL), builtin=False, users=held.get(name, 0)))
    return out


def _check_permissions(permissions) -> list[str]:
    if not isinstance(permissions, list) or not all(isinstance(p, str) for p in permissions):
        raise UserError('permissions must be a list')
    unknown = sorted(set(permissions) - ALL)
    if unknown:
        raise UserError(f'no such permission: {", ".join(unknown)}')
    return sorted(set(permissions))


def save_role(conn: Conn, name: str, description: str, permissions, by: str, new: bool) -> None:
    """Add a custom role, or replace one. Its accounts get the new permissions on their next request."""
    if name in BUILTIN:
        raise UserError(f'{name} is a built-in role and cannot be changed')
    perms = json.dumps(_check_permissions(permissions))
    exists = bool(conn.scalar('SELECT 1 FROM roles WHERE name = :n', {'n': name}))
    if new:
        if not ROLE_NAME.fullmatch(name):
            raise UserError('role name: lowercase letters, digits, . _ - only (max 32), starting with a letter or digit')
        if exists:
            raise UserError(f'role {name!r} already exists')
        conn.execute('INSERT INTO roles (name, description, permissions, created_at, created_by) VALUES (:n, :d, :p, :t, :b)',
                     {'n': name, 'd': description[:200], 'p': perms, 't': int(time.time()), 'b': by})
    elif not exists:
        raise UserError(f'no role {name!r}')
    else:
        conn.execute('UPDATE roles SET description = :d, permissions = :p WHERE name = :n', {'n': name, 'd': description[:200], 'p': perms})


def remove_role(conn: Conn, name: str) -> None:
    if name in BUILTIN:
        raise UserError(f'{name} is a built-in role and cannot be removed')
    if conn.scalar('SELECT count(*) FROM users WHERE role = :n', {'n': name}):
        raise UserError(f'accounts still have the role {name}: give them another role first')
    if conn.scalar('SELECT count(*) FROM invites WHERE role = :n AND reset_user IS NULL AND used_at IS NULL AND revoked_at IS NULL AND expires_at > :t',
                   {'n': name, 't': int(time.time())}):
        raise UserError(f'an open invite link gives the role {name}: revoke it first')
    if not conn.execute('DELETE FROM roles WHERE name = :n', {'n': name}).rowcount:
        raise UserError(f'no role {name!r}')


def _grants(conn: Conn, role: str) -> str:
    return json.dumps(sorted(permissions_of(conn, role)))


def _invite_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create_invite(conn: Conn, role: str, by: str, hours: int = INVITE_HOURS, note: str = '') -> tuple[int, str]:
    """A single-use link for someone to make their own account. The token is returned once and only its hash is kept."""
    _check_role(conn, role)
    if not 1 <= hours <= MAX_INVITE_HOURS:
        raise UserError(f'an invite lasts 1 to {MAX_INVITE_HOURS} hours')
    token, now = secrets.token_urlsafe(32), int(time.time())
    conn.execute('INSERT INTO invites (token_hash, role, note, created_by, created_at, expires_at, grants_json) VALUES (:h, :r, :o, :b, :t, :e, :g)',
                 {'h': _invite_hash(token), 'r': role, 'o': note[:200], 'b': by, 't': now, 'e': now + hours * 3600, 'g': _grants(conn, role)})
    return conn.scalar('SELECT invite_id FROM invites WHERE token_hash = :h', {'h': _invite_hash(token)}), token


def create_reset(conn: Conn, username: str, by: str, hours: int = 24) -> tuple[int, str]:
    """A single-use link to set a new password, for accounts that forgot theirs (StorageForge sends no email)."""
    row = conn.all('SELECT username, role, user_id, session_version FROM users WHERE lower(username) = lower(:n)', {'n': username})
    if not row:
        raise UserError(f'no user {username!r}')
    if not 1 <= hours <= MAX_INVITE_HOURS:
        raise UserError(f'a reset link lasts 1 to {MAX_INVITE_HOURS} hours')
    token, now = secrets.token_urlsafe(32), int(time.time())
    conn.execute('UPDATE invites SET revoked_at = :t WHERE reset_user = :u AND used_at IS NULL AND revoked_at IS NULL', {'t': now, 'u': row[0][0]})
    conn.execute("""INSERT INTO invites (token_hash, role, reset_user, created_by, created_at, expires_at, grants_json, reset_user_id, reset_version)
                    VALUES (:h, :r, :u, :b, :t, :e, :g, :i, :v)""",
                 {'h': _invite_hash(token), 'r': row[0][1], 'u': row[0][0], 'b': by, 't': now, 'e': now + hours * 3600,
                  'g': _grants(conn, row[0][1]), 'i': row[0][2], 'v': row[0][3]})
    return conn.scalar('SELECT invite_id FROM invites WHERE token_hash = :h', {'h': _invite_hash(token)}), token


def open_invite(conn: Conn, token: str) -> dict | None:
    """What an open link does, or None: one answer for every way a token can be bad. A link dies if its role came to allow
    more than when it was made. A reset link also dies if the account was replaced, or its role, password or state changed,
    so a link made for a viewer cannot take over the admin that viewer became. A link from before these checks is dead too."""
    rows = conn.all("""SELECT role, reset_user, grants_json, reset_user_id, reset_version FROM invites
                       WHERE token_hash = :h AND used_at IS NULL AND revoked_at IS NULL AND expires_at > :t""",
                    {'h': _invite_hash(token), 't': int(time.time())})
    if not rows or not role_exists(conn, rows[0][0]):
        return None
    role, reset, grants, user_id, version = rows[0]
    if not grants or not permissions_of(conn, role) <= set(json.loads(grants)):
        return None
    if reset and not conn.scalar("""SELECT 1 FROM users WHERE user_id = :u AND session_version = :v AND role = :r""",
                                 {'u': user_id, 'v': version, 'r': role}):
        return None
    return dict(role=role, reset_user=reset)


def enroll(conn: Conn, token: str, username: str, password: str) -> dict:
    """Use a link: make the account, or set the password of the account a reset link names. The role and a reset's account
    come from the link, never from the person using it. Claiming is one UPDATE, so one link cannot be used twice."""
    invite = open_invite(conn, token)
    bad = InviteError('this link is not valid: it may have expired or been used')
    if invite is None:
        raise bad
    username = invite['reset_user'] or username
    if invite['reset_user']:
        _check_password(password)
    else:
        _check_new_account(conn, username, password)
    claimed = conn.execute('UPDATE invites SET used_at = :t, used_by = :n WHERE token_hash = :h AND used_at IS NULL '
                           'AND revoked_at IS NULL AND expires_at > :t', {'t': int(time.time()), 'n': username, 'h': _invite_hash(token)}).rowcount
    if not claimed:
        raise bad
    try:
        if invite['reset_user']:
            set_password(conn, username, password)
            end_all_sessions(conn, username)
        else:
            create(conn, username, password, invite['role'])
    except Exception:            # the name was taken in between: the link still works
        conn.execute('UPDATE invites SET used_at = NULL, used_by = NULL WHERE token_hash = :h', {'h': _invite_hash(token)})
        raise
    return dict(username=username, role=invite['role'], reset=bool(invite['reset_user']))


def list_invites(conn: Conn) -> list[dict]:
    """Open invites and the last few closed ones, without anything that could rebuild a link."""
    cols = ('invite_id', 'role', 'reset_user', 'note', 'created_by', 'created_at', 'expires_at', 'used_at', 'used_by', 'revoked_at')
    return [dict(zip(cols, r)) for r in conn.all(f'SELECT {", ".join(cols)} FROM invites ORDER BY invite_id DESC LIMIT 50')]


def invite_role(conn: Conn, invite_id: int) -> str | None:
    return conn.scalar('SELECT role FROM invites WHERE invite_id = :i', {'i': invite_id})


def revoke_invite(conn: Conn, invite_id: int) -> None:
    if not conn.execute('UPDATE invites SET revoked_at = :t WHERE invite_id = :i AND used_at IS NULL AND revoked_at IS NULL',
                        {'t': int(time.time()), 'i': invite_id}).rowcount:
        raise UserError('that invite is not open')


def keep_an_admin(conn: Conn, username: str):
    """For the web UI: refuses what would leave no enabled admin. The CLI needs a shell on the server and can always recover."""
    others = conn.scalar("""SELECT count(*) FROM users WHERE role = 'admin' AND disabled_at IS NULL
                            AND lower(username) <> lower(:n)""", {'n': username})
    if not others:
        raise UserError(f'{username} is the last admin: make another account admin first')


def set_role(conn: Conn, username: str, role: str) -> None:
    _check_role(conn, role)
    _update(conn, username, 'role = :r, session_version = session_version + 1', {'r': role})


def role_of(conn: Conn, username: str) -> str | None:
    return conn.scalar('SELECT role FROM users WHERE lower(username) = lower(:n)', {'n': username})


def _check_new_account(conn: Conn, username: str, password: str):
    if not USERNAME.fullmatch(username):
        raise UserError('username: letters, digits, . _ - only (max 64), starting with a letter or digit')
    _check_password(password)
    if conn.scalar('SELECT 1 FROM users WHERE lower(username) = lower(:n)', {'n': username}):
        raise UserError(f'user {username!r} already exists')


def create(conn: Conn, username: str, password: str, role: str = 'admin') -> None:
    _check_role(conn, role)
    _check_new_account(conn, username, password)
    conn.execute('INSERT INTO users (username, password_hash, created_at, role) VALUES (:n, :h, :t, :r)',
                 {'n': username, 'h': generate_password_hash(password), 't': int(time.time()), 'r': role})


def set_password(conn: Conn, username: str, password: str) -> None:
    _check_password(password)
    _update(conn, username, 'password_hash = :h, session_version = session_version + 1',
            {'h': generate_password_hash(password)})


def set_disabled(conn: Conn, username: str, disabled: bool) -> None:
    _update(conn, username, 'disabled_at = :d, session_version = session_version + 1',
            {'d': int(time.time()) if disabled else None})


def remove(conn: Conn, username: str) -> None:
    conn.execute('UPDATE invites SET revoked_at = :t WHERE lower(reset_user) = lower(:n) AND used_at IS NULL AND revoked_at IS NULL',
                 {'t': int(time.time()), 'n': username})     # SQLite can give the next account this one's id
    conn.execute('DELETE FROM web_sessions WHERE user_id IN (SELECT user_id FROM users WHERE lower(username) = lower(:n))',
                 {'n': username})
    if not conn.execute('DELETE FROM users WHERE lower(username) = lower(:n)', {'n': username}).rowcount:
        raise UserError(f'no user {username!r}')


def _update(conn: Conn, username: str, sets: str, params: dict) -> None:
    if not conn.execute(f'UPDATE users SET {sets} WHERE lower(username) = lower(:n)', {**params, 'n': username}).rowcount:
        raise UserError(f'no user {username!r}')


def listing(conn: Conn) -> list[tuple]:
    return conn.all('SELECT username, created_at, last_login_at, disabled_at, role FROM users ORDER BY lower(username)')


def count(conn: Conn) -> int:
    return conn.scalar('SELECT count(*) FROM users WHERE disabled_at IS NULL') or 0
