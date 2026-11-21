"""The console on a monitoring-only host (decision of 2026-11-16; roadmap section 11.5): SSH turned on for that session through
storageforge-agentctl, and off again after. Never a shell in the agent: the agent has no part in it.

    grant(db, host, user, actor)     a key made here for this session alone, held in memory, its public half put in the account's
                                     authorized_keys by storageforge-agentctl as a line sshd stops taking after LOGIN_MINUTES, with no
                                     forwarding; returns the grant, with the private key in a wipeable buffer for the session's ssh-agent
    close(db, host, grant_id, why)   the line taken out again, when the session ends
    sweep(db)                        grants left open (the web app stopped mid-session) closed; storageforge-agentctl also closes
                                     every grant whose time is past at each request, and sshd refused the key long before

Only an account the host's own admin listed in /etc/storageforge-agent/console_users may be logged in as: no request writes that file,
so a controller that was taken over gets a console only where a person on the host allowed one, as whom they named.
"""
from __future__ import annotations

import secrets
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from . import sfagent
from .db import Database
from .vault import SecretBuffer

LOGIN_MINUTES = 5


class ConsoleGrantError(RuntimeError):
    pass


def grant(db: Database, host: str, user: str, actor: str) -> tuple[str, SecretBuffer]:
    key = ed25519.Ed25519PrivateKey.generate()
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, serialization.NoEncryption())
    public = key.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()
    buf = SecretBuffer(len(pem))
    buf.buf[:len(pem)] = pem
    buf.length = len(pem)
    del pem, key
    gid = secrets.token_hex(16)
    from .sfagent import fingerprint
    conn = db.connect()
    try:
        conn.execute("""INSERT INTO agent_console_grants (grant_id, host, user_name, fingerprint, opened_by, opened_at, expires_at)
                        VALUES (:g, :h, :u, :f, :a, :t, :e)""",
                     {'g': gid, 'h': host, 'u': user, 'f': fingerprint(public), 'a': actor, 't': int(time.time()), 'e': int(time.time()) + LOGIN_MINUTES * 60})
    finally:
        conn.close()
    try:
        sfagent.call(db, host, 'console-open', actor=actor, timeout=60, console={'grant': gid, 'user': user, 'key': ' '.join(public.split()[:2]), 'minutes': LOGIN_MINUTES})
    except sfagent.AgentError as exc:
        buf.wipe()
        _closed(db, gid, f'not opened: {exc}')
        raise ConsoleGrantError(str(exc)) from None
    return gid, buf


def _closed(db: Database, gid: str, why: str):
    conn = db.connect()
    try:
        conn.execute('UPDATE agent_console_grants SET closed_at = :t, close_detail = :d WHERE grant_id = :g AND closed_at IS NULL',
                     {'t': int(time.time()), 'd': why[:500], 'g': gid})
    finally:
        conn.close()


def close(db: Database, host: str, gid: str, why: str) -> bool:
    try:
        sfagent.call(db, host, 'console-close', timeout=60, console={'grant': gid})
    except sfagent.AgentError as exc:
        # the line stays until storageforge-agentctl's next request takes it out; sshd stopped taking it after LOGIN_MINUTES
        _closed(db, gid, f'{why}; closing it on the host failed ({exc}): sshd stopped taking the key at its expiry, and the next request removes it')
        return False
    _closed(db, gid, why)
    return True


def sweep(db: Database) -> int:
    conn = db.connect()
    try:
        rows = conn.all('SELECT grant_id, host FROM agent_console_grants WHERE closed_at IS NULL AND expires_at < :t', {'t': int(time.time()) - 8 * 3600})
    finally:
        conn.close()
    return sum(close(db, host, gid, 'left open; closed by the sweep') for gid, host in rows)


def recent(conn, host: str, limit: int = 20) -> list[dict]:
    keys = ('grant', 'user', 'fingerprint', 'opened_by', 'opened_at', 'expires_at', 'closed_at', 'detail')
    return [dict(zip(keys, r)) for r in conn.all("""SELECT grant_id, user_name, fingerprint, opened_by, opened_at, expires_at, closed_at, close_detail
                                                   FROM agent_console_grants WHERE host = :h ORDER BY opened_at DESC LIMIT :n""", {'h': host, 'n': limit})]
