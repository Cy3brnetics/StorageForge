"""Local web UI accounts. Hashing is Werkzeug's (scrypt), sessions are Flask-Login's; this module only stores rows."""
from __future__ import annotations

import re
import time
from dataclasses import dataclass

from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash

from .db import Conn

USERNAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,63}')
MIN_PASSWORD = 12
# Compared against when the username does not exist, so a miss costs the same as a wrong password.
_DUMMY_HASH = generate_password_hash('storageforge-no-such-user')


class UserError(ValueError):
    pass


@dataclass
class User(UserMixin):
    user_id: int
    username: str
    session_version: int

    def get_id(self) -> str:   # Flask-Login stores this in the session; a version bump invalidates old sessions
        return f'{self.user_id}:{self.session_version}'


def load(conn: Conn, session_id: str) -> User | None:
    try:
        uid, ver = (int(x) for x in session_id.split(':'))
    except ValueError:
        return None
    rows = conn.all('SELECT user_id, username, session_version FROM users '
                    'WHERE user_id = :u AND session_version = :v AND disabled_at IS NULL', {'u': uid, 'v': ver})
    return User(*rows[0]) if rows else None


def authenticate(conn: Conn, username: str, password: str) -> User | None:
    rows = conn.all('SELECT user_id, username, session_version, password_hash FROM users '
                    'WHERE lower(username) = lower(:n) AND disabled_at IS NULL', {'n': username})
    if not rows:
        check_password_hash(_DUMMY_HASH, password)
        return None
    uid, name, ver, pw_hash = rows[0]
    if not check_password_hash(pw_hash, password):
        return None
    conn.execute('UPDATE users SET last_login_at = :t WHERE user_id = :u', {'t': int(time.time()), 'u': uid})
    return User(uid, name, ver)


def _check_password(password: str):
    if len(password) < MIN_PASSWORD:
        raise UserError(f'password must be at least {MIN_PASSWORD} characters')


def create(conn: Conn, username: str, password: str) -> None:
    if not USERNAME.fullmatch(username):
        raise UserError('username: letters, digits, . _ - only (max 64), starting with a letter or digit')
    _check_password(password)
    if conn.scalar('SELECT 1 FROM users WHERE lower(username) = lower(:n)', {'n': username}):
        raise UserError(f'user {username!r} already exists')
    conn.execute('INSERT INTO users (username, password_hash, created_at) VALUES (:n, :h, :t)',
                 {'n': username, 'h': generate_password_hash(password), 't': int(time.time())})


def set_password(conn: Conn, username: str, password: str) -> None:
    _check_password(password)
    _update(conn, username, 'password_hash = :h, session_version = session_version + 1',
            {'h': generate_password_hash(password)})


def set_disabled(conn: Conn, username: str, disabled: bool) -> None:
    _update(conn, username, 'disabled_at = :d, session_version = session_version + 1',
            {'d': int(time.time()) if disabled else None})


def remove(conn: Conn, username: str) -> None:
    if not conn.execute('DELETE FROM users WHERE lower(username) = lower(:n)', {'n': username}).rowcount:
        raise UserError(f'no user {username!r}')


def _update(conn: Conn, username: str, sets: str, params: dict) -> None:
    if not conn.execute(f'UPDATE users SET {sets} WHERE lower(username) = lower(:n)', {**params, 'n': username}).rowcount:
        raise UserError(f'no user {username!r}')


def listing(conn: Conn) -> list[tuple]:
    return conn.all('SELECT username, created_at, last_login_at, disabled_at FROM users ORDER BY lower(username)')


def count(conn: Conn) -> int:
    return conn.scalar('SELECT count(*) FROM users WHERE disabled_at IS NULL') or 0
