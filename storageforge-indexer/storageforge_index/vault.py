"""Encrypted SSH credential vault and tamper-evident audit log.

Envelope encryption:

    STORAGEFORGE_VAULT_SECRET ──Argon2id(salt, t=3, m=64 MiB, p=4)──► KEK (32 bytes, never stored)
    KEK ──AES-256-GCM──► wraps one random DEK per key, the audit MAC key and a verifier
    DEK ──AES-256-GCM──► encrypts the OpenSSH private key

Each ciphertext carries associated data naming its row and purpose, so a ciphertext
copied into another row fails authentication. Rotating the secret rewraps DEKs only;
the key ciphertexts never change.

Plaintext handling: secrets are decrypted with `update_into` into bytearrays that are
mlock()ed (best effort) and zeroed after use. Python cannot guarantee no other copy
exists (the import path and the env var itself are ordinary objects), so the design
goal is minimal lifetime, never zero copies.
"""
from __future__ import annotations

import base64
import ctypes
import ctypes.util
import fnmatch
import getpass
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import socket
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

MIN_SECRET_LEN = 32
KDF_DEFAULTS = {'time_cost': 3, 'memory_kib': 64 * 1024, 'lanes': 4}
VERIFIER = b'storageforge-vault-v1'
GENESIS = '0' * 64


POLICY_KEY = 'vault.policy'


class VaultError(RuntimeError):
    pass


class VaultLocked(VaultError):
    pass


class NoBinding(VaultError):
    pass


# memory hygiene

_libc = None
if os.name == 'posix':
    try:
        _libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)
    except OSError:
        _libc = None


def _with_address(buf: bytearray, fn):
    if not buf:
        return None
    arr = (ctypes.c_char * len(buf)).from_buffer(buf)
    try:
        return fn(ctypes.addressof(arr), len(buf))
    finally:
        del arr


def lock_memory(buf: bytearray):
    """Keep the page out of swap where RLIMIT_MEMLOCK allows; silently best effort."""
    if _libc is not None:
        _with_address(buf, lambda a, n: _libc.mlock(ctypes.c_void_p(a), ctypes.c_size_t(n)))


def wipe(buf: bytearray | None):
    if not buf:
        return
    _with_address(buf, lambda a, n: ctypes.memset(a, 0, n))
    if _libc is not None:
        _with_address(buf, lambda a, n: _libc.munlock(ctypes.c_void_p(a), ctypes.c_size_t(n)))


class SecretBuffer:
    """A wipeable plaintext buffer; use as a context manager or call wipe()."""

    def __init__(self, size: int):
        self.buf = bytearray(size)
        self.length = 0
        lock_memory(self.buf)

    def view(self) -> memoryview:
        return memoryview(self.buf)[:self.length]

    def wipe(self):
        wipe(self.buf)
        self.length = 0

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.wipe()


# AES-256-GCM

def seal(key, plaintext, aad: bytes) -> tuple[bytes, bytes]:
    nonce = os.urandom(12)
    enc = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
    enc.authenticate_additional_data(aad)
    ct = enc.update(plaintext) + enc.finalize()
    return nonce, ct + enc.tag


def open_into(key, nonce: bytes, blob: bytes, aad: bytes) -> SecretBuffer:
    if len(blob) < 16:
        raise VaultError('ciphertext too short')
    ct, tag = blob[:-16], blob[-16:]
    dec = Cipher(algorithms.AES(key), modes.GCM(nonce, tag)).decryptor()
    dec.authenticate_additional_data(aad)
    out = SecretBuffer(len(ct) + 15)
    out.length = dec.update_into(ct, out.buf)
    try:
        dec.finalize()
    except InvalidTag:
        out.wipe()
        raise VaultError('authentication failed: wrong secret or tampered ciphertext') from None
    return out


# Argon2id hung when two threads derived at once in the image, and later callers failed with "Not enough memory to
# derive key" until a restart: one at a time. Each takes about 0.1 s.
_KDF_LOCK = threading.Lock()


def derive_kek(secret: bytes, salt: bytes, p: dict) -> SecretBuffer:
    kdf = Argon2id(salt=salt, length=32, iterations=p['time_cost'], lanes=p['lanes'], memory_cost=p['memory_kib'])
    out = SecretBuffer(32)
    with _KDF_LOCK:
        kdf.derive_into(secret, out.buf)
    out.length = 32
    return out


def importable_keys(folder) -> list[Path]:
    """The files vault import-dir would take from a folder."""
    return [f for f in sorted(Path(folder).iterdir())
            if f.suffix not in ('.pub', '.md', '.txt') and f.is_file() and not f.name.startswith('.')]


def secret_from_env() -> bytes:
    s = os.environ.get('STORAGEFORGE_VAULT_SECRET')
    path = os.environ.get('STORAGEFORGE_VAULT_SECRET_FILE')
    if not s and path:
        s = Path(path).read_text().strip()
    if not s:
        raise VaultLocked('Set STORAGEFORGE_VAULT_SECRET (or STORAGEFORGE_VAULT_SECRET_FILE) to unlock the vault')
    if len(s) < MIN_SECRET_LEN:
        raise VaultError(f'The vault secret must be at least {MIN_SECRET_LEN} characters. '
                         'Generate one with: openssl rand -base64 48')
    return s.encode()


def fingerprint(public_line: str) -> str:
    blob = base64.b64decode(public_line.split()[1])
    return 'SHA256:' + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip('=')


def actor_name(kind: str = 'cli') -> str:
    try:
        return f'{kind}:{getpass.getuser()}'
    except Exception:
        return f'{kind}:uid{os.getuid()}'


def _ip(s: str):
    try:
        return ipaddress.ip_address(s)
    except ValueError:
        return None


def resolve_ips(host: str, timeout: float = 3.0) -> set:
    """IP literals as-is; names through getaddrinfo with a hard timeout (it has none of its own)."""
    if _ip(host):
        return {_ip(host)}
    out: set = set()

    def lookup():
        try:
            out.update(ipaddress.ip_address(a[4][0].split('%')[0]) for a in socket.getaddrinfo(host, None))
        except (OSError, ValueError):
            pass
    t = threading.Thread(target=lookup, daemon=True)
    t.start()
    t.join(timeout)
    return set(out)


@dataclass
class Binding:
    binding_id: int
    key_id: int
    key_name: str
    fingerprint: str
    pattern: str
    user: str
    port: int
    actions: list[str]


class Vault:
    def __init__(self, db, conn, secret: bytes | None = None):
        self.db, self.conn = db, conn
        self._secret = secret
        self._kek: SecretBuffer | None = None
        self.audit_key: SecretBuffer | None = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def close(self):
        for b in (self._kek, self.audit_key):
            if b:
                b.wipe()
        self._kek = self.audit_key = None

    def _blob(self, v) -> bytes:
        return bytes(v) if v is not None else b''

    @property
    def initialized(self) -> bool:
        return bool(self.conn.scalar('SELECT count(*) FROM vault_meta'))

    def init(self) -> bool:
        if self.initialized:
            return False
        p = dict(KDF_DEFAULTS)
        salt = os.urandom(16)
        kek = derive_kek(self._secret, salt, p)
        try:
            vn, vct = seal(kek.view(), VERIFIER, b'storageforge:verifier')
            with SecretBuffer(32) as audit:
                audit.buf[:] = os.urandom(32)
                audit.length = 32
                an, act = seal(kek.view(), audit.view(), b'storageforge:audit-key')
        finally:
            kek.wipe()
        self.conn.execute("""INSERT INTO vault_meta (id, kdf, kdf_salt, kdf_time_cost, kdf_memory_kib, kdf_lanes,
                                 verifier_nonce, verifier, audit_key_nonce, audit_key_wrapped, created_at)
                             VALUES (1, 'argon2id', :s, :t, :m, :l, :vn, :v, :an, :ak, :now)""",
                          {'s': salt, 't': p['time_cost'], 'm': p['memory_kib'], 'l': p['lanes'], 'vn': vn, 'v': vct,
                           'an': an, 'ak': act, 'now': int(time.time())})
        return True

    def unlock(self) -> 'Vault':
        if self._secret is None:
            self._secret = secret_from_env()
        row = self.conn.all("""SELECT kdf_salt, kdf_time_cost, kdf_memory_kib, kdf_lanes, verifier_nonce, verifier,
                                      audit_key_nonce, audit_key_wrapped FROM vault_meta WHERE id = 1""")
        if not row:
            raise VaultLocked('The vault is not initialised. Run: storageforge-index vault init')
        salt, t, m, l, vn, v, an, ak = row[0]
        kek = derive_kek(self._secret, self._blob(salt), {'time_cost': t, 'memory_kib': m, 'lanes': l})
        try:
            with open_into(kek.view(), self._blob(vn), self._blob(v), b'storageforge:verifier') as check:
                if not hmac.compare_digest(bytes(check.view()), VERIFIER):
                    raise VaultError('verifier mismatch')
            self.audit_key = open_into(kek.view(), self._blob(an), self._blob(ak), b'storageforge:audit-key')
        except VaultError:
            kek.wipe()
            raise VaultLocked('Wrong vault secret: the stored verifier did not authenticate') from None
        self._kek = kek
        return self

    def _need_kek(self) -> memoryview:
        if self._kek is None:
            raise VaultLocked('vault is locked')
        return self._kek.view()

    # keys
    @staticmethod
    def _aad(uuid: str, purpose: str) -> bytes:
        return f'storageforge:{purpose}:{uuid}'.encode()

    def key_policy(self) -> str:
        """'generate-only': this site's keys are made in this vault and never leave it, so none can be shared with
        another client. 'open' takes imports too."""
        v = self.conn.scalar('SELECT value_json FROM settings WHERE key = :k', {'k': POLICY_KEY})
        return json.loads(v) if v else 'open'

    def add_key(self, name: str, private_bytes: bytes, passphrase: bytes | None = None, comment: str | None = None) -> dict:
        if self.key_policy() == 'generate-only':
            raise VaultError('This site only takes keys generated in its vault, so no key is shared between clients. '
                             'Use: vault generate')
        return self._store_key(name, private_bytes, passphrase, comment, 'imported')

    def _store_key(self, name: str, private_bytes: bytes, passphrase: bytes | None, comment: str | None, origin: str) -> dict:
        kek = self._need_kek()
        try:
            key = serialization.load_ssh_private_key(private_bytes, passphrase)
        except ValueError:
            try:
                key = serialization.load_pem_private_key(private_bytes, passphrase)
            except (ValueError, TypeError) as exc:
                raise VaultError(f'Not a readable private key ({exc}). Passphrase-protected keys need --passphrase-env.') from None
        if isinstance(key, rsa.RSAPrivateKey) and key.key_size < 3072:
            raise VaultError(f'RSA-{key.key_size} is too weak; use ed25519 or RSA ≥ 3072 bits')
        if not isinstance(key, (ed25519.Ed25519PrivateKey, rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)):
            raise VaultError('Only ed25519, RSA and ECDSA keys are supported')
        pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, serialization.NoEncryption())
        public = key.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()
        comment = comment or f'storageforge:{name}'
        public_line = f'{public} {comment}'
        fp = fingerprint(public_line)
        if origin == 'imported':
            from .site import foreign
            if fp in foreign()['key']:
                raise VaultError('Another site on this machine already uses this key, and one key should not serve two '
                                 'clients. Generate a new one.')
        uuid = secrets.token_hex(16)
        with SecretBuffer(32) as dek:
            dek.buf[:] = os.urandom(32)
            dek.length = 32
            dn, wdek = seal(kek, dek.view(), self._aad(uuid, 'dek'))
            kn, ct = seal(dek.view(), pem, self._aad(uuid, 'key'))
        del pem
        self.conn.execute("""INSERT INTO ssh_keys (key_uuid, name, key_type, public_key, fingerprint, comment,
                                 dek_nonce, wrapped_dek, key_nonce, ciphertext, created_at, origin)
                             VALUES (:u, :n, :t, :p, :f, :c, :dn, :wd, :kn, :ct, :now, :o)""",
                          {'u': uuid, 'n': name, 't': public.split()[0], 'p': public_line, 'f': fp, 'c': comment,
                           'dn': dn, 'wd': wdek, 'kn': kn, 'ct': ct, 'now': int(time.time()), 'o': origin})
        return {'name': name, 'type': public.split()[0], 'fingerprint': fp, 'public_key': public_line}

    def generate_key(self, name: str, kind: str = 'ed25519', comment: str | None = None) -> dict:
        key = ed25519.Ed25519PrivateKey.generate() if kind == 'ed25519' else rsa.generate_private_key(65537, 4096)
        pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, serialization.NoEncryption())
        return self._store_key(name, pem, None, comment, 'generated')

    def list_keys(self) -> list[dict]:
        rows = self.conn.all("""SELECT k.key_id, k.name, k.key_type, k.fingerprint, k.created_at, k.disabled_at, k.origin,
                                       (SELECT count(*) FROM key_bindings b WHERE b.key_id = k.key_id)
                                FROM ssh_keys k ORDER BY k.name""")
        return [dict(zip(('key_id', 'name', 'type', 'fingerprint', 'created_at', 'disabled_at', 'origin', 'bindings'), r)) for r in rows]

    def public_key(self, name: str) -> str:
        v = self.conn.scalar('SELECT public_key FROM ssh_keys WHERE name = :n', {'n': name})
        if v is None:
            raise VaultError(f'No key named {name}')
        return v

    def remove_key(self, name: str) -> int:
        return self.conn.execute('DELETE FROM ssh_keys WHERE name = :n', {'n': name}).rowcount

    def decrypt_key(self, key_id: int) -> SecretBuffer:
        kek = self._need_kek()
        rows = self.conn.all("""SELECT key_uuid, dek_nonce, wrapped_dek, key_nonce, ciphertext FROM ssh_keys
                                WHERE key_id = :k AND disabled_at IS NULL""", {'k': key_id})
        if not rows:
            raise VaultError(f'key {key_id} is missing or disabled')
        uuid, dn, wd, kn, ct = rows[0]
        with open_into(kek, self._blob(dn), self._blob(wd), self._aad(uuid, 'dek')) as dek:
            return open_into(dek.view(), self._blob(kn), self._blob(ct), self._aad(uuid, 'key'))

    # device passwords: for gear that takes no SSH key. Each has its own key, wrapped as an SSH key's is
    def store_credential(self, name: str, username: str | None, password: str, enable_password: str | None = None) -> dict:
        kek = self._need_kek()
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,63}', name or ''):
            raise VaultError('a credential name is letters, digits, dot, dash and underscore')
        if not password:
            raise VaultError('a credential needs a password')
        uuid = secrets.token_hex(16)
        body = json.dumps({'password': password, 'enable': enable_password}).encode()
        with SecretBuffer(32) as dek:
            dek.buf[:] = os.urandom(32)
            dek.length = 32
            dn, wdek = seal(kek, dek.view(), self._aad(uuid, 'dek'))
            n, ct = seal(dek.view(), body, self._aad(uuid, 'credential'))
        with self.conn.tx():
            self.conn.execute('DELETE FROM device_credentials WHERE name = :n', {'n': name})
            self.conn.execute("""INSERT INTO device_credentials (cred_uuid, name, username, dek_nonce, wrapped_dek, nonce, ciphertext, created_at)
                                 VALUES (:u, :n, :un, :dn, :wd, :non, :ct, :t)""",
                              {'u': uuid, 'n': name, 'un': username, 'dn': dn, 'wd': wdek, 'non': n, 'ct': ct, 't': int(time.time())})
        return {'name': name, 'username': username}

    def credential(self, name: str) -> dict:
        """{'username', 'password', 'enable'}. For the moment of connecting: a transport needs them as plain strings."""
        kek = self._need_kek()
        rows = self.conn.all('SELECT cred_uuid, username, dek_nonce, wrapped_dek, nonce, ciphertext FROM device_credentials WHERE name = :n', {'n': name})
        if not rows:
            raise VaultError(f'no credential named {name!r}')
        uuid, username, dn, wd, n, ct = rows[0]
        with open_into(kek, self._blob(dn), self._blob(wd), self._aad(uuid, 'dek')) as dek:
            with open_into(dek.view(), self._blob(n), self._blob(ct), self._aad(uuid, 'credential')) as body:
                return {'username': username, **json.loads(bytes(body.view()))}

    def list_credentials(self) -> list[dict]:
        return [dict(zip(('name', 'username', 'created_at', 'rotated_at'), r))
                for r in self.conn.all('SELECT name, username, created_at, rotated_at FROM device_credentials ORDER BY name')]

    def remove_credential(self, name: str) -> int:
        return self.conn.execute('DELETE FROM device_credentials WHERE name = :n', {'n': name}).rowcount

    def rotate_secret(self, new_secret: bytes) -> int:
        """Rewrap every DEK, the audit key and the verifier under a KEK derived from new_secret."""
        kek = self._need_kek()
        p = dict(KDF_DEFAULTS)
        salt = os.urandom(16)
        new = derive_kek(new_secret, salt, p)
        try:
            rows = self.conn.all('SELECT key_id, key_uuid, dek_nonce, wrapped_dek FROM ssh_keys')
            with self.conn.tx():
                for kid, uuid, dn, wd in rows:
                    with open_into(kek, self._blob(dn), self._blob(wd), self._aad(uuid, 'dek')) as dek:
                        n2, w2 = seal(new.view(), dek.view(), self._aad(uuid, 'dek'))
                    self.conn.execute('UPDATE ssh_keys SET dek_nonce = :n, wrapped_dek = :w, rotated_at = :t WHERE key_id = :k',
                                      {'n': n2, 'w': w2, 't': int(time.time()), 'k': kid})
                for cid, uuid, dn, wd in self.conn.all('SELECT credential_id, cred_uuid, dek_nonce, wrapped_dek FROM device_credentials'):
                    with open_into(kek, self._blob(dn), self._blob(wd), self._aad(uuid, 'dek')) as dek:
                        n2, w2 = seal(new.view(), dek.view(), self._aad(uuid, 'dek'))
                    self.conn.execute('UPDATE device_credentials SET dek_nonce = :n, wrapped_dek = :w, rotated_at = :t WHERE credential_id = :c',
                                      {'n': n2, 'w': w2, 't': int(time.time()), 'c': cid})
                vn, vct = seal(new.view(), VERIFIER, b'storageforge:verifier')
                an, act = seal(new.view(), self.audit_key.view(), b'storageforge:audit-key')
                self.conn.execute("""UPDATE vault_meta SET kdf_salt = :s, kdf_time_cost = :t, kdf_memory_kib = :m,
                                         kdf_lanes = :l, verifier_nonce = :vn, verifier = :v, audit_key_nonce = :an,
                                         audit_key_wrapped = :ak, rotated_at = :now WHERE id = 1""",
                                  {'s': salt, 't': p['time_cost'], 'm': p['memory_kib'], 'l': p['lanes'], 'vn': vn,
                                   'v': vct, 'an': an, 'ak': act, 'now': int(time.time())})
        except BaseException:
            new.wipe()
            raise
        self._kek.wipe()
        self._kek, self._secret = new, new_secret
        return len(rows)

    # host bindings
    @staticmethod
    def pattern_kind(pattern: str) -> str:
        try:
            ipaddress.ip_network(pattern, strict=False)
            return 'cidr' if '/' in pattern else 'host'
        except ValueError:
            return 'glob' if any(c in pattern for c in '*?[') else 'host'

    def bind(self, key_name: str, pattern: str, user: str, port: int = 22, actions: str = 'scan', priority: int = 100) -> int:
        kid = self.conn.scalar('SELECT key_id FROM ssh_keys WHERE name = :n', {'n': key_name})
        if kid is None:
            raise VaultError(f'No key named {key_name}')
        bad = set(actions.split(',')) - {'scan', 'checksum', 'deploy', 'console'}
        if bad:
            raise VaultError(f'unknown action(s): {", ".join(sorted(bad))}; allowed: scan, checksum, deploy, console')
        return self.conn.scalar("""INSERT INTO key_bindings (key_id, host_pattern, pattern_kind, ssh_user, ssh_port,
                                       allowed_actions, priority, created_at)
                                   VALUES (:k, :p, :pk, :u, :port, :a, :pr, :now) RETURNING binding_id""",
                                {'k': kid, 'p': pattern, 'pk': self.pattern_kind(pattern), 'u': user, 'port': port,
                                 'a': actions, 'pr': priority, 'now': int(time.time())})

    def set_actions(self, binding_id: int, actions: str) -> int:
        bad = set(actions.split(',')) - {'scan', 'checksum', 'deploy', 'console'}
        if bad or not actions:
            raise VaultError(f'unknown action(s): {", ".join(sorted(bad)) or "none given"}; allowed: scan, checksum, deploy, console')
        return self.conn.execute('UPDATE key_bindings SET allowed_actions = :a WHERE binding_id = :b',
                                 {'a': actions, 'b': binding_id}).rowcount

    def unbind(self, binding_id: int) -> int:
        return self.conn.execute('DELETE FROM key_bindings WHERE binding_id = :b', {'b': binding_id}).rowcount

    def bindings(self) -> list[dict]:
        rows = self.conn.all("""SELECT b.binding_id, k.name, b.host_pattern, b.pattern_kind, b.ssh_user, b.ssh_port,
                                       b.allowed_actions, b.priority, k.fingerprint
                                FROM key_bindings b JOIN ssh_keys k ON k.key_id = b.key_id
                                ORDER BY b.priority, b.binding_id""")
        return [dict(zip(('binding_id', 'key', 'pattern', 'kind', 'user', 'port', 'actions', 'priority', 'fingerprint'), r))
                for r in rows]

    def resolve(self, host: str, action: str = 'scan') -> Binding:
        """Most specific binding wins: exact host > glob > CIDR (longest prefix), then lowest priority."""
        rows = self.conn.all("""SELECT b.binding_id, b.key_id, k.name, k.fingerprint, b.host_pattern, b.pattern_kind,
                                       b.ssh_user, b.ssh_port, b.allowed_actions, b.priority
                                FROM key_bindings b JOIN ssh_keys k ON k.key_id = b.key_id
                                WHERE k.disabled_at IS NULL""")
        ips = resolve_ips(host)
        best, denied = None, False
        for bid, kid, name, fp, pat, kind, user, port, actions, prio in rows:
            if kind == 'host' and (pat.lower() == host.lower() or _ip(pat) in ips):
                score = (3, len(pat))
            elif kind == 'glob' and fnmatch.fnmatch(host.lower(), pat.lower()):
                score = (2, len(pat.replace('*', '')))
            elif kind == 'cidr' and any(ip in ipaddress.ip_network(pat, strict=False) for ip in ips):
                score = (1, ipaddress.ip_network(pat, strict=False).prefixlen)
            else:
                continue
            if action not in actions.split(','):
                denied = True
                continue
            cand = (score, -prio, Binding(bid, kid, name, fp, pat, user, port, actions.split(',')))
            if best is None or cand[:2] > best[:2]:
                best = cand
        if best is None:
            why = f'a binding matches {host} but does not allow "{action}"' if denied else f'no key is bound to {host}'
            raise NoBinding(why + '. Add one with: storageforge-index vault bind --key <name> --host <host|glob|cidr> --user <user>')
        return best[2]


class AuditLog:
    """Append-only, hash-chained log. Each entry's MAC covers the previous entry's hash, so a
    deleted, reordered or edited row breaks verification. The DB also rejects UPDATE/DELETE."""

    def __init__(self, db, conn, mac_key: SecretBuffer | None):
        self.db, self.conn, self.key = db, conn, mac_key

    def _digest(self, prev: str, payload: str, alg: str) -> str:
        msg = prev.encode() + payload.encode()
        if alg == 'hmac-sha256':
            if self.key is None:
                raise VaultLocked('unlock the vault to verify HMAC audit entries')
            return hmac.new(bytes(self.key.view()), msg, hashlib.sha256).hexdigest()
        return hashlib.sha256(msg).hexdigest()

    def append(self, actor: str, action: str, outcome: str, host: str | None = None, key_fp: str | None = None,
               detail: dict | None = None) -> str:
        alg = 'hmac-sha256' if self.key is not None else 'sha256'
        ts = time.time_ns() // 1000
        detail_json = json.dumps(detail or {}, sort_keys=True, separators=(',', ':'), default=str)
        with self.conn.tx():
            if self.db.dialect == 'postgres':
                self.conn.execute('SELECT pg_advisory_xact_lock(727274)')
            prev = self.conn.scalar('SELECT entry_hash FROM audit_log ORDER BY audit_id DESC LIMIT 1') or GENESIS
            payload = json.dumps([ts, actor, action, host, key_fp, outcome, detail_json], separators=(',', ':'))
            h = self._digest(prev, payload, alg)
            self.conn.execute("""INSERT INTO audit_log (ts_us, actor, action, target_host, key_fingerprint, outcome,
                                     detail_json, hash_alg, prev_hash, entry_hash)
                                 VALUES (:ts, :a, :ac, :h, :fp, :o, :d, :alg, :p, :e)""",
                              {'ts': ts, 'a': actor, 'ac': action, 'h': host, 'fp': key_fp, 'o': outcome,
                               'd': detail_json, 'alg': alg, 'p': prev, 'e': h})
        return h

    def tail(self, limit: int = 50) -> list[dict]:
        rows = self.conn.all("""SELECT audit_id, ts_us, actor, action, target_host, key_fingerprint, outcome, detail_json
                                FROM audit_log ORDER BY audit_id DESC LIMIT :l""", {'l': limit})
        return [{'id': r[0], 'ts': r[1] / 1e6, 'actor': r[2], 'action': r[3], 'host': r[4], 'key': r[5],
                 'outcome': r[6], 'detail': json.loads(r[7] or '{}')} for r in rows]

    def unkeyed(self) -> dict:
        """How much of the chain a database writer could rewrite. Entries written while the vault was locked carry a
        plain SHA-256 (no key): anyone who can write the database could replace them, and every entry after them, with
        a chain that still verifies. Expected for the first entries before vault init; suspicious after keyed ones."""
        first_keyed = self.conn.scalar("SELECT min(audit_id) FROM audit_log WHERE hash_alg = 'hmac-sha256'")
        total = self.conn.scalar("SELECT count(*) FROM audit_log WHERE hash_alg <> 'hmac-sha256'") or 0
        later = self.conn.all("""SELECT min(audit_id), count(*) FROM audit_log
                                WHERE hash_alg <> 'hmac-sha256' AND audit_id > :k""", {'k': first_keyed or 0})[0] \
            if first_keyed else (None, 0)
        return {'unkeyed': total, 'unkeyed_after_keyed': later[1] or 0, 'first_unkeyed_after_keyed': later[0]}

    def verify(self) -> tuple[bool, int, int | None]:
        prev, n = GENESIS, 0
        for aid, ts, actor, action, host, fp, outcome, d, alg, p, e in self.conn.all(
                """SELECT audit_id, ts_us, actor, action, target_host, key_fingerprint, outcome, detail_json, hash_alg,
                          prev_hash, entry_hash FROM audit_log ORDER BY audit_id"""):
            payload = json.dumps([ts, actor, action, host, fp, outcome, d], separators=(',', ':'))
            if p != prev or not hmac.compare_digest(self._digest(prev, payload, alg), e):
                return False, n, aid
            prev, n = e, n + 1
        return True, n, None
