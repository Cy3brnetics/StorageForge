"""Keys that rotate by themselves, on a schedule (roadmap section 14, "Layers").

What can rotate cheaply does, so that a key someone took is of use for a short time only:

    the session-signing key   A new one every STORAGEFORGE_SESSION_ROTATE_HOURS (24; 0 turns it off). It is made from two things kept
                              in two places: the session secret, which is in the server's secret file, and a random value made at
                              each rotation and kept in the database (settings, `session.ring`). Either alone signs nothing. The keys of
                              the last periods still check cookies, for as long as a session can last, and no longer; nothing is
                              signed with them. So nobody is signed out by a rotation, and a signing key read out of the server's
                              memory is dead a day later.
    the vault key (KEK)       Derived again under a new salt every STORAGEFORGE_KEK_ROTATE_DAYS (30; 0 turns it off), and every DEK
                              rewrapped under it. No key's ciphertext is touched. With the key enclave this happens inside, from the
                              secret the enclave holds: nobody hands it over again. Without the enclave the server derives it from
                              the secret in its environment, as it does at start.
    the enclave's tokens      A step-up token lasts five minutes and dies with a lock or a restart (enclave_stepup.py): nothing to do here.

SSH keys are rotated by the `rotate` plan, when the operator runs it: that changes what hosts trust, and is not done unasked.

A rotation that fails is said in the audit log and in the notification center (`rotation-failed`), and tried again at the next look.
It leaves when one succeeds.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time

from . import alerts

RING = 'session.ring'
FAILED = 'rotation.failed'
SESSION_HOURS_ENV, KEK_DAYS_ENV = 'STORAGEFORGE_SESSION_ROTATE_HOURS', 'STORAGEFORGE_KEK_ROTATE_DAYS'
LONGEST_SESSION = 8 * 3600          # users.MAX_SESSION_MINUTES: a key that signed a cookie checks it for this long after it stopped signing
TICK = 300


def _period(env: str, default: float, unit: int) -> int:
    """Seconds between rotations, 0 for never."""
    try:
        value = float(os.environ.get(env, default))
    except ValueError:
        value = default
    return int(max(0.0, value) * unit)


def session_period() -> int:
    return _period(SESSION_HOURS_ENV, 24, 3600)


def kek_period() -> int:
    return _period(KEK_DAYS_ENV, 30, 86400)


# ── the session-signing key ─────────────────────────────────────────
def _key(master: str, value: str) -> str:
    return hmac.new(master.encode(), b'storageforge:session-key\0' + base64.b64decode(value), hashlib.sha256).hexdigest()


def session_keys(conn, master: str, now: float | None = None) -> list[str]:
    """The keys cookies are checked with, newest first: the first signs. A new one is made when the newest is older than the
    period, and one that stopped signing longer ago than a session can last is forgotten. With the period at 0 the session
    secret itself signs, as before."""
    period = session_period()
    if not period:
        return [master]
    now = time.time() if now is None else now
    with conn.tx():
        ring = alerts.get_setting(conn, RING) or []
        if not ring or ring[0]['at'] + period <= now:
            ring.insert(0, {'value': base64.b64encode(secrets.token_bytes(32)).decode(), 'at': int(now)})
            # entry i stopped signing when entry i-1 was made
            ring = [e for i, e in enumerate(ring) if i == 0 or ring[i - 1]['at'] + LONGEST_SESSION > now][:32]
            alerts.set_setting(conn, RING, ring, 'system')
    return [_key(master, e['value']) for e in ring]


def use_session_keys(web, keys: list[str]) -> bool:
    """Whether the signing key changed."""
    changed = web.config.get('SECRET_KEY') != keys[0]
    web.config['SECRET_KEY'], web.config['SECRET_KEY_FALLBACKS'] = keys[0], keys[1:] or None
    return changed


# ── the vault key ───────────────────────────────────────────────────
def kek_due(conn, now: float | None = None) -> bool:
    period = kek_period()
    if not period:
        return False
    row = conn.all('SELECT coalesce(rotated_at, created_at) FROM vault_meta WHERE id = 1')
    return bool(row) and row[0][0] + period <= (time.time() if now is None else now)


def rewrap(db, conn) -> int:
    """The KEK derived again under a new salt, and every DEK rewrapped. With the enclave, inside and from the secret it holds."""
    from .vault import Vault, secret_from_env
    with Vault(db, conn).unlock() as v:
        return v.rotate_secret(None if v.enclave else secret_from_env())


def _failed(conn, what: str, why: str | None) -> None:
    was = alerts.get_setting(conn, FAILED) or {}
    if why is None:
        was.pop(what, None)
    else:
        was[what] = {'why': why[:300], 'at': int(time.time()), 'since': (was.get(what) or {}).get('since') or int(time.time())}
    alerts.set_setting(conn, FAILED, was, 'system')


def tick(db, web=None, master: str | None = None, audit=None, now: float | None = None) -> dict:
    """One look: rotate what is due. audit(conn, action, outcome, detail) writes the audit log. Returns what was done."""
    done = {}
    conn = db.connect()
    try:
        if web is not None and master:
            try:
                if use_session_keys(web, session_keys(conn, master, now)):
                    done['session'] = True
                    if audit:
                        audit(conn, 'session.key.rotate', 'ok', {'kept': len(web.config.get('SECRET_KEY_FALLBACKS') or [])})
                if (alerts.get_setting(conn, FAILED) or {}).get('session'):
                    _failed(conn, 'session', None)
            except Exception as exc:          # the key in use stays in use
                _failed(conn, 'session', str(exc) or type(exc).__name__)
                if audit:
                    audit(conn, 'session.key.rotate', 'failed', {'why': str(exc)[:200]})
        try:
            due = kek_due(conn, now)
        except Exception:
            due = False
        if due:
            try:
                done['kek'] = rewrap(db, conn)
                _failed(conn, 'kek', None)
                if audit:
                    audit(conn, 'vault.rekey', 'ok', {'rewrapped': done['kek'], 'scheduled': True})
            except Exception as exc:          # a locked vault, an enclave that is down: said, and tried again at the next look
                _failed(conn, 'kek', str(exc) or type(exc).__name__)
                if audit:
                    audit(conn, 'vault.rekey', 'failed', {'why': str(exc)[:200], 'scheduled': True})
    finally:
        conn.close()
    return done


def problems(conn) -> dict:
    """For the notification center: a rotation that failed, until one succeeds."""
    names = {'session': 'the session-signing key', 'kek': 'the vault key'}
    out = {}
    for what, f in (alerts.get_setting(conn, FAILED) or {}).items():
        out[f'rotation-failed:{what}'] = ('rotation-failed', what, f'Rotating {names.get(what, what)} failed',
                                          f'{f["why"]}. It has been failing since {time.strftime("%Y-%m-%d %H:%M", time.localtime(f["since"]))} and is tried again every few minutes. '
                                          'The key in use stays in use meanwhile.', 'warn')
    return out


def run(db, web, master: str, audit) -> None:
    """The server's thread: a look every few minutes."""
    while True:
        time.sleep(TICK)
        try:
            tick(db, web, master, audit)
        except Exception:
            from . import errlog
            errlog.trace()
