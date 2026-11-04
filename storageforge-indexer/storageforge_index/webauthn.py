"""FIDO2 step-up: a touch on a hardware token before a guarded action. The server side of WebAuthn, with no new dependency.

Only ES256 (every FIDO2 token has it) and attestation is not checked: this asks "is it the token enrolled here", not "who made the
token". The browser only offers WebAuthn on HTTPS or localhost. Having a key enrolled makes the step-up required on that account
for the actions that take it, adding or removing a key among them. Someone who lost their only token clears it from the server's
shell (`user clear-keys`), which is audited: the offline key covers the holds meanwhile.
"""
from __future__ import annotations

import base64
import hashlib
import json
import secrets
import struct
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from .db import Conn

FRESH = 300                 # how long one touch counts for


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


def unb64u(text: str) -> bytes:
    text = str(text)
    return base64.urlsafe_b64decode(text + '=' * (-len(text) % 4))


def cbor(data: bytes, i: int = 0):
    """Enough CBOR for what a token sends: (value, next offset). Anything else raises, and the registration fails."""
    head = data[i]
    major, info = head >> 5, head & 31
    i += 1
    if info < 24:
        n = info
    elif info == 24:
        n = data[i]
        i += 1
    elif info == 25:
        n = struct.unpack('>H', data[i:i + 2])[0]
        i += 2
    elif info == 26:
        n = struct.unpack('>I', data[i:i + 4])[0]
        i += 4
    else:
        raise ValueError('CBOR form not understood')
    if major == 0:
        return n, i
    if major == 1:
        return -1 - n, i
    if major == 2:
        return data[i:i + n], i + n
    if major == 3:
        return data[i:i + n].decode(), i + n
    if major == 4:
        out = []
        for _ in range(n):
            v, i = cbor(data, i)
            out.append(v)
        return out, i
    if major == 5:
        out = {}
        for _ in range(n):
            k, i = cbor(data, i)
            v, i = cbor(data, i)
            out[k] = v
        return out, i
    if major == 7:
        return {20: False, 21: True, 22: None}.get(info), i
    raise ValueError('CBOR form not understood')


def _client_data(raw_b64: str, want_type: str, challenge: str, origin: str) -> bytes:
    raw = unb64u(raw_b64)
    data = json.loads(raw)
    if data.get('type') != want_type:
        raise ValueError('this is not the right kind of answer')
    if data.get('challenge') != challenge:
        raise ValueError('the challenge does not match')
    if data.get('origin') != origin:
        raise ValueError(f'the origin {str(data.get("origin"))[:80]} is not this site')
    return raw


def _check_auth_data(auth: bytes, rp_id: str) -> tuple[int, int]:
    if len(auth) < 37 or auth[:32] != hashlib.sha256(rp_id.encode()).digest():
        raise ValueError('this key was made for another site')
    flags = auth[32]
    if not flags & 1:
        raise ValueError('the token saw no touch')
    return flags, struct.unpack('>I', auth[33:37])[0]


def register_options(username: str, rp_id: str, existing: list[str]) -> tuple[dict, str]:
    challenge = b64u(secrets.token_bytes(32))
    return ({'challenge': challenge, 'rp': {'id': rp_id, 'name': 'StorageForge'}, 'user': {'id': b64u(hashlib.sha256(username.encode()).digest()), 'name': username, 'displayName': username},
             'pubKeyCredParams': [{'type': 'public-key', 'alg': -7}], 'timeout': 60000, 'attestation': 'none',
             'authenticatorSelection': {'userVerification': 'discouraged'}, 'excludeCredentials': [{'type': 'public-key', 'id': c} for c in existing]}, challenge)


def register_finish(body: dict, challenge: str, origin: str, rp_id: str) -> dict:
    _client_data(body['clientDataJSON'], 'webauthn.create', challenge, origin)
    att, _ = cbor(unb64u(body['attestationObject']))
    auth = att['authData']
    flags, count = _check_auth_data(auth, rp_id)
    if not flags & 0x40:
        raise ValueError('the token sent no key')
    i = 37 + 16
    n = struct.unpack('>H', auth[i:i + 2])[0]
    i += 2
    cred = auth[i:i + n]
    key, _ = cbor(auth, i + n)
    if key.get(1) != 2 or key.get(3) != -7 or key.get(-1) != 1:
        raise ValueError('only ES256 keys on P-256 are taken')
    if len(key[-2]) != 32 or len(key[-3]) != 32:
        raise ValueError('that key is malformed')
    return {'credential_id': b64u(cred), 'public_key': b64u(b'\x04' + key[-2] + key[-3]), 'sign_count': count}


def assert_options(rp_id: str, credentials: list[str]) -> tuple[dict, str]:
    challenge = b64u(secrets.token_bytes(32))
    return ({'challenge': challenge, 'rpId': rp_id, 'timeout': 60000, 'userVerification': 'discouraged', 'allowCredentials': [{'type': 'public-key', 'id': c} for c in credentials]}, challenge)


def assert_finish(body: dict, challenge: str, origin: str, rp_id: str, public_key: str, sign_count: int) -> int:
    """The new counter, or ValueError. A counter that did not go up means the key was copied, for tokens that keep one."""
    client = _client_data(body['clientDataJSON'], 'webauthn.get', challenge, origin)
    auth = unb64u(body['authenticatorData'])
    _, count = _check_auth_data(auth, rp_id)
    key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), unb64u(public_key))
    try:
        key.verify(unb64u(body['signature']), auth + hashlib.sha256(client).digest(), ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        raise ValueError('the signature does not check out') from None
    if count and sign_count and count <= sign_count:
        raise ValueError('the counter went backwards: this key may have been copied')
    return count


# ── the store ───────────────────────────────────────────────────────
def keys_of(conn: Conn, username: str) -> list[dict]:
    return [{'id': r[0], 'credential_id': r[1], 'public_key': r[2], 'sign_count': r[3], 'name': r[4], 'created_at': r[5]}
            for r in conn.all('SELECT id, credential_id, public_key, sign_count, name, created_at FROM security_webauthn WHERE username = :u ORDER BY id', {'u': username})]


def add_key(conn: Conn, username: str, cred: dict, name: str) -> int:
    return conn.scalar('INSERT INTO security_webauthn (username, credential_id, public_key, sign_count, name, created_at) VALUES (:u, :c, :p, :s, :n, :t) RETURNING id',
                       {'u': username, 'c': cred['credential_id'], 'p': cred['public_key'], 's': cred['sign_count'], 'n': name[:60], 't': int(time.time())})


def delete_key(conn: Conn, username: str, key_id: int):
    conn.execute('DELETE FROM security_webauthn WHERE id = :i AND username = :u', {'i': key_id, 'u': username})


def clear_keys(conn: Conn, username: str) -> int:
    """Every key of one account: for a lost token, and only from the server's shell. The web routes cannot do this without a touch."""
    n = len(keys_of(conn, username))
    conn.execute('DELETE FROM security_webauthn WHERE username = :u', {'u': username})
    return n


def required(conn: Conn, username: str) -> bool:
    return bool(keys_of(conn, username))
