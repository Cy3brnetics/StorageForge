"""Local web UI accounts. Hashing is Werkzeug's (scrypt), sessions are Flask-Login's; this module only stores rows."""
from __future__ import annotations

import hashlib
import re
import secrets
import time
from dataclasses import dataclass

from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash

from .db import Conn

USERNAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,63}')
MIN_PASSWORD = 12
# A session ends this long after sign-in; users may raise their own up to the maximum.
SESSION_MINUTES, MAX_SESSION_MINUTES = 30, 480
# Compared against when the username does not exist, so a miss costs the same as a wrong password.
_DUMMY_HASH = generate_password_hash('storageforge-no-such-user')


ROLES = ('viewer', 'operator', 'admin')


class UserError(ValueError):
    pass


@dataclass
class User(UserMixin):
    user_id: int
    username: str
    session_version: int
    session_minutes: int = SESSION_MINUTES
    role: str = 'admin'

    def get_id(self) -> str:   # Flask-Login stores this in the session; a version bump invalidates old sessions
        return f'{self.user_id}:{self.session_version}'


def load(conn: Conn, session_id: str) -> User | None:
    try:
        uid, ver = (int(x) for x in session_id.split(':'))
    except ValueError:
        return None
    rows = conn.all('SELECT user_id, username, session_version, session_minutes, role FROM users '
                    'WHERE user_id = :u AND session_version = :v AND disabled_at IS NULL', {'u': uid, 'v': ver})
    return User(*rows[0]) if rows else None


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
    return User(uid, name, ver, minutes, role)


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


def _check_role(role: str):
    if role not in ROLES:
        raise UserError(f'role must be one of {", ".join(ROLES)}')


def keep_an_admin(conn: Conn, username: str):
    """For the web UI: refuses what would leave no enabled admin. The CLI needs a shell on the server and can always recover."""
    others = conn.scalar("""SELECT count(*) FROM users WHERE role = 'admin' AND disabled_at IS NULL
                            AND lower(username) <> lower(:n)""", {'n': username})
    if not others:
        raise UserError(f'{username} is the last admin: make another account admin first')


def set_role(conn: Conn, username: str, role: str) -> None:
    _check_role(role)
    _update(conn, username, 'role = :r, session_version = session_version + 1', {'r': role})


def create(conn: Conn, username: str, password: str, role: str = 'admin') -> None:
    _check_role(role)
    if not USERNAME.fullmatch(username):
        raise UserError('username: letters, digits, . _ - only (max 64), starting with a letter or digit')
    _check_password(password)
    if conn.scalar('SELECT 1 FROM users WHERE lower(username) = lower(:n)', {'n': username}):
        raise UserError(f'user {username!r} already exists')
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
