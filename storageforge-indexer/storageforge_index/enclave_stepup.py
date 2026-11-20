"""Step-up checked inside the key enclave (roadmap section 14, "Step-up checked inside").

For what matters most (making or rotating a key, releasing a secret marked sensitive, lifting a lock-down) the web app's own "password
typed in the last five minutes" is not enough: a web app that has been taken over can say so about anyone. So the enclave checks the
person itself. It holds, for each person who enrolled, the hash of a password and the public keys of their FIDO2 tokens; the proof goes
to it, and what comes back is a session token that is good for five minutes and that the web app cannot make.

"Holds" means what it means for every key: the record is sealed under the KEK and kept in the database (enclave_stepup), and goes with the
request that needs it. This module keeps the rows. It never sees inside one.

What it does not do, said plainly:
    a password is typed into the web app on its way to the enclave, so a web app that is taken over and waits sees the next one typed.
        A FIDO2 assertion answers a challenge the enclave made and counts once, so it cannot be kept and used again.
    the enclave knows step-up is on because it is shown a record at unlock. Whoever can write the database can remove every record
        before a restart. STORAGEFORGE_ENCLAVE_STEPUP=required, set where the enclave is unlocked from, insists on it whatever is shown.
    a record of a person's earlier password, kept by someone who could read the database then, still opens: the enclave has no disk to
        remember that it was replaced.
"""
from __future__ import annotations

import json
import os
import secrets
import time

from . import enclave

STEPUP_ENV = 'STORAGEFORGE_ENCLAVE_STEPUP'
COLS = 'rec_uuid, dek_nonce, wrapped_dek, nonce, ciphertext'


def _sealed(row) -> dict:
    return {'uuid': row[0], 'dek_nonce': bytes(row[1]), 'wrapped_dek': bytes(row[2]), 'nonce': bytes(row[3]), 'ciphertext': bytes(row[4])}


def wanted() -> str | None:
    """'required' where this installation insists on step-up whatever records the database shows."""
    return 'required' if (os.environ.get(STEPUP_ENV) or '').strip().lower() in ('required', '1', 'on', 'yes') else None


def records(conn) -> list[dict]:
    """Every record, to show the enclave at unlock."""
    return [_sealed(r) for r in conn.all(f'SELECT {COLS} FROM enclave_stepup ORDER BY username')]


def record_of(conn, user: str) -> dict | None:
    rows = conn.all(f'SELECT {COLS} FROM enclave_stepup WHERE username = :u', {'u': user})
    return _sealed(rows[0]) if rows else None


def enrolled(conn) -> list[dict]:
    return [{'username': r[0], 'security_keys': len(json.loads(r[1] or '[]')), 'updated_at': r[2]}
            for r in conn.all('SELECT username, fido_ids, updated_at FROM enclave_stepup ORDER BY username')]


def fido_keys(conn, user: str) -> list[dict]:
    """The FIDO2 public keys the app already has for this account (webauthn.py), as the enclave takes them."""
    return [{'id': r[0], 'key': r[1]} for r in conn.all('SELECT credential_id, public_key FROM security_webauthn WHERE username = :u ORDER BY id', {'u': user})][:8]


def stale_keys(conn, user: str) -> bool:
    """Whether the account's security keys are no longer the ones in its record: one was added or removed since it enrolled."""
    held = conn.scalar('SELECT fido_ids FROM enclave_stepup WHERE username = :u', {'u': user})
    return held is not None and sorted(json.loads(held or '[]')) != sorted(k['id'] for k in fido_keys(conn, user))


def enroll(conn, address: str, user: str, password: str, rp: str = '', origin: str = '', token: str | None = None, secret: bytes | None = None, meta: dict | None = None) -> dict:
    """Make this person's record inside the enclave and keep it. Raises enclave.EnclaveError as the enclave refuses: `stepup` where a
    token or the vault secret is needed and neither was given."""
    keys = fido_keys(conn, user)
    with enclave.Enclave(address) as e:
        sealed = e.stepup_enroll(secrets.token_hex(16), user, password, keys, rp, origin, token=token, secret=secret, meta=meta)
    now = int(time.time())
    with conn.tx():
        was = conn.scalar('SELECT created_at FROM enclave_stepup WHERE username = :u', {'u': user})
        conn.execute('DELETE FROM enclave_stepup WHERE username = :u', {'u': user})
        conn.execute("""INSERT INTO enclave_stepup (username, rec_uuid, dek_nonce, wrapped_dek, nonce, ciphertext, fido_ids, created_at, updated_at)
                        VALUES (:u, :id, :dn, :wd, :n, :ct, :f, :c, :t)""",
                     {'u': user, 'id': sealed['uuid'], 'dn': sealed['dek_nonce'], 'wd': sealed['wrapped_dek'], 'n': sealed['nonce'], 'ct': sealed['ciphertext'],
                      'f': json.dumps([k['id'] for k in keys]), 'c': was or now, 't': now})
    return {'username': user, 'security_keys': len(keys), 'replaced': was is not None}


def check(conn, address: str, user: str, password: str | None = None, fido: dict | None = None) -> dict:
    """The proof, checked inside. {'token', 'seconds', 'user'}, or enclave.EnclaveError: `auth` for a proof that did not check out,
    `rate` after five tries in a minute, `stepup` where this person has no record."""
    record = record_of(conn, user)
    if record is None:
        raise enclave.EnclaveError('stepup', f'{user} has no step-up record in the key enclave: enroll on the Keys page, or with: storageforge-index vault stepup-enroll {user}')
    with enclave.Enclave(address) as e:
        return e.stepup(user, record, password, fido)


def remove(conn, user: str) -> int:
    return conn.execute('DELETE FROM enclave_stepup WHERE username = :u', {'u': user}).rowcount
