"""The controller's side of the key enclave (roadmap section 14; the program is enclave/src/main.rs).

The enclave is a micro VM with no network device that holds the vault's KEK. This speaks to it: a 4-byte length and JSON, one
request at a time, over vsock (`vsock:CID:PORT`, or `fc:PATH:PORT` where Firecracker runs the VM) or, on a developer's machine and in the tests, a socket file (`unix:PATH`).
Nothing here ever holds a private key or the KEK. The vault secret passes through once, on its way in at unlock.

The channel (roadmap section 14, "Layers"): every connection begins with a Noise handshake, Noise_NX_25519_AESGCM_SHA256, and
everything after it is encrypted. The enclave shows its static key in the handshake and proves it holds the secret half. That key is
pinned the first time an address is spoken to, which for an enclave this program starts is the moment it has started it; an enclave
that later shows another key at that address is not spoken to at all. So nothing else on the host reads what crosses the socket, and
the vault secret is never sent to something that only sits where the enclave should be. An enclave makes a new key each time it
starts: whoever restarts it pins the new one (enclave_vm.py does), and `vault enclave-pin --renew` does it by hand for one that
something else runs. STORAGEFORGE_ENCLAVE_KEY names the key to insist on instead.

Every ciphertext stays in the database in the vault's own format (vault.py) and goes with the request that needs it, so turning
the enclave on or off changes nothing that is stored.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import socket
import struct
import time
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAX_FRAME = 1 << 20
ADDRESS_ENV = 'STORAGEFORGE_ENCLAVE'
RUN_DIR_ENV = 'STORAGEFORGE_ENCLAVE_RUN_DIR'
KEY_ENV = 'STORAGEFORGE_ENCLAVE_KEY'
NOISE_NAME = b'Noise_NX_25519_AESGCM_SHA256'
NOISE_PROLOGUE = b'storageforge-enclave-v3'


def run_dir() -> Path:
    """Where the server's enclave has its socket, its address and its pinned key: the runtime folder, or a folder of its own that a
    starter in another container shares (docker-compose.enclave.yml)."""
    from .runner import runtime_dir
    return Path(os.environ.get(RUN_DIR_ENV) or runtime_dir())


class EnclaveError(RuntimeError):
    """The enclave refused, or could not be reached. `code` is its own word for why: locked, lockdown, auth, rate, key, stepup, bad-request, down."""

    def __init__(self, code: str, why: str):
        super().__init__(why)
        self.code = code


def _fits(what: str, data: bytes, most: int) -> bytes:
    """The enclave counts a value over its bound as a bad request, and five of those lock it down. Something a person typed that is too
    long is refused here, where it costs nothing."""
    if len(data) > most:
        raise EnclaveError('bad-request', f'{what} is longer than the enclave takes ({most} bytes)')
    return data


def published_address() -> str | None:
    """Where the server said its enclave is (enclave_start.publish): one line in the run folder, for a starter or a command beside it."""
    try:
        line = Path(os.environ.get('STORAGEFORGE_ENCLAVE_ADDRESS_FILE') or run_dir() / 'enclave.addr').read_text().strip()
    except OSError:
        return None
    return line or None


# ── the enclave's key, pinned ───────────────────────────────────────
def pin_file() -> Path:
    return run_dir() / 'enclave.pins'


def _pins() -> dict:
    try:
        got = json.loads(pin_file().read_text())
        return got if isinstance(got, dict) else {}
    except (OSError, ValueError):
        return {}


def _write_pins(pins: dict) -> None:
    path = pin_file()
    part = path.with_name(f'{path.name}.{os.getpid()}.part')
    fd = os.open(part, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as f:
        json.dump(pins, f)
    os.replace(part, path)


def pinned(address: str) -> bytes | None:
    """The key an enclave at this address has to show: the one named in STORAGEFORGE_ENCLAVE_KEY for the configured enclave, else
    the one pinned when the address was first spoken to. None: not spoken to yet."""
    named = os.environ.get(KEY_ENV)
    if named and address == os.environ.get(ADDRESS_ENV):
        try:
            key = base64.b64decode(named, validate=True)
        except ValueError:
            key = b''
        if len(key) != 32:
            raise EnclaveError('down', f'{KEY_ENV} is not a key: it is the base64 of 32 bytes, as `vault enclave-pin` prints it')
        return key
    got = _pins().get(address)
    return base64.b64decode(got) if got else None


def pin(address: str, key: bytes) -> None:
    pins = _pins()
    pins[address] = _b64(key)
    _write_pins(pins)


def forget_pin(address: str) -> None:
    """For whoever has just started or restarted the enclave at this address: the next contact pins the key it shows now."""
    pins = _pins()
    if pins.pop(address, None) is not None:
        _write_pins(pins)


class _Noise:
    """The initiator's side of Noise NX, as the specification names its parts. The enclave's side is in main.rs."""

    def __init__(self):
        self.h = NOISE_NAME.ljust(32, b'\0')
        self.ck, self.k, self.n = self.h, None, 0
        self.mix_hash(NOISE_PROLOGUE)

    def mix_hash(self, data: bytes):
        self.h = hashlib.sha256(self.h + data).digest()

    @staticmethod
    def hkdf(ck: bytes, ikm: bytes) -> tuple[bytes, bytes]:
        temp = hmac.new(ck, ikm, hashlib.sha256).digest()
        one = hmac.new(temp, b'\x01', hashlib.sha256).digest()
        return one, hmac.new(temp, one + b'\x02', hashlib.sha256).digest()

    def mix_key(self, ikm: bytes):
        self.ck, self.k = self.hkdf(self.ck, ikm)
        self.n = 0

    def decrypt_and_hash(self, sealed: bytes) -> bytes:
        plain = AESGCM(self.k).decrypt(b'\0\0\0\0' + self.n.to_bytes(8, 'big'), sealed, self.h) if self.k else sealed
        self.n += 1 if self.k else 0
        self.mix_hash(sealed)
        return plain


def configured() -> str | None:
    """Where the enclave is, or None where this installation has none. `vm` means this process runs it: the server starts it
    as it starts (enclave_vm.from_env), and a command that turns out to need a key starts one of its own here, for as long as
    the command runs. A command that needs no key (the health check, a search) never starts one."""
    value = os.environ.get(ADDRESS_ENV) or None
    if value == 'vm':
        # A command run in the server's own container (docker compose exec storageforge ...) is told `vm` as the server was. The
        # server's enclave is there, unlocked, and says where in its run folder: the command asks it, as the server does, and
        # needs no vault secret of its own. Only where no server's enclave answers does it start one for itself.
        beside = published_address()
        if beside:
            try:
                with Enclave(beside, timeout=3) as e:
                    e.status()
                return beside
            except EnclaveError:
                pass
        from . import enclave_vm
        try:
            return enclave_vm.on_demand()
        except enclave_vm.EnclaveVMError as exc:
            raise EnclaveError('down', f'the key enclave could not be started: {exc}') from None
    return value


def address() -> str | None:
    """Where the enclave is when one is running, or None: without starting one, and without taking `vm` (not started yet) for an address."""
    value = os.environ.get(ADDRESS_ENV) or None
    return None if not value or value.startswith('vm') else value


def _b64(value) -> str:
    return base64.b64encode(bytes(value)).decode()


def b64_of_url(text: str) -> str:
    """base64url, as a browser sends WebAuthn bytes, as the base64 the enclave takes."""
    return _b64(base64.urlsafe_b64decode(text + '=' * (-len(text) % 4)))


class Enclave:
    def __init__(self, address: str, timeout: float = 30.0):
        self.address, self.timeout, self.sock = address, timeout, None
        self.key: bytes | None = None          # the static key the enclave showed on this connection
        self._send = self._recv = None          # [AESGCM, messages so far] for each direction

    def _connect(self):
        self._open()
        try:
            self._handshake()
        except EnclaveError:
            self.close()
            raise
        except (OSError, ValueError, InvalidTag, struct.error) as exc:
            self.close()
            raise EnclaveError('down', f'what answers at {self.address} does not speak as the key enclave does: {exc or type(exc).__name__}') from None

    def _handshake(self):
        """Noise NX against the enclave's static key. After it the connection is encrypted both ways, and the key the enclave showed
        is the one pinned for this address, or this is the first contact and it is pinned now."""
        mine = X25519PrivateKey.generate()
        e = mine.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        noise = _Noise()
        noise.mix_hash(e)                    # -> e
        noise.mix_hash(b'')                  #    and its empty payload
        self.sock.sendall(struct.pack('>I', 32) + e)
        size = struct.unpack('>I', self._read(4))[0]
        if size != 96:
            raise ValueError('its handshake is not the one expected')
        reply = self._read(96)
        theirs = reply[:32]
        noise.mix_hash(theirs)               # <- e
        noise.mix_key(mine.exchange(X25519PublicKey.from_public_bytes(theirs)))               # ee
        static = noise.decrypt_and_hash(reply[32:80])                                          # s
        noise.mix_key(mine.exchange(X25519PublicKey.from_public_bytes(static)))               # es: only the holder of the static secret gets past here
        noise.decrypt_and_hash(reply[80:])
        send, recv = _Noise.hkdf(noise.ck, b'')
        want = pinned(self.address)
        if want is None:
            pin(self.address, static)
        elif not hmac.compare_digest(want, static):
            raise EnclaveError('down', f'what answers at {self.address} is not the key enclave that was pinned there: it shows the key {_b64(static)}, and {_b64(want)} is pinned. '
                               'Nothing was sent to it. If the enclave was restarted by something other than this program: storageforge-index vault enclave-pin --renew')
        self.key, self._send, self._recv = static, [AESGCM(send), 0], [AESGCM(recv), 0]

    def _open(self):
        kind, _, rest = self.address.partition(':')
        s = None
        try:
            if kind == 'unix':
                s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                s.settimeout(self.timeout)
                s.connect(rest)
            elif kind == 'vsock':
                cid, _, port = rest.partition(':')
                s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
                s.settimeout(self.timeout)
                s.connect((int(cid), int(port)))
            elif kind == 'fc':
                # Firecracker gives the guest's vsock to the host as a socket file: name the guest's port, and from its `OK` on
                # the connection is the enclave's
                path, _, port = rest.rpartition(':')
                s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                s.settimeout(self.timeout)
                s.connect(path)
                s.sendall(f'CONNECT {int(port)}\n'.encode())
                said = b''
                while not said.endswith(b'\n') and len(said) < 64:
                    got = s.recv(1)
                    if not got:
                        break
                    said += got
                if not said.startswith(b'OK '):
                    raise OSError('the VM is up and nothing listens in it yet' if not said else f'the VM answered {said[:40]!r}')
            else:
                raise EnclaveError('down', f'{ADDRESS_ENV} is unix:PATH, vsock:CID:PORT or fc:PATH:PORT, not {self.address!r}')
        except (OSError, ValueError) as exc:
            if s is not None:
                s.close()
            raise EnclaveError('down', f'the key enclave does not answer at {self.address}: {exc}') from None
        self.sock = s

    def close(self):
        if self.sock is not None:
            try:
                self.sock.close()
            finally:
                self.sock = None
        self._send = self._recv = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def _read(self, n: int) -> bytes:
        out = bytearray()
        while len(out) < n:
            chunk = self.sock.recv(n - len(out))
            if not chunk:
                raise EnclaveError('down', 'the key enclave closed the connection')
            out += chunk
        return bytes(out)

    @staticmethod
    def _encrypted(way: list, plain: bytes) -> bytes:
        out = way[0].encrypt(b'\0\0\0\0' + way[1].to_bytes(8, 'big'), plain, None)
        way[1] += 1
        return out

    @staticmethod
    def _opened(way: list, sealed: bytes) -> bytes:
        out = way[0].decrypt(b'\0\0\0\0' + way[1].to_bytes(8, 'big'), sealed, None)
        way[1] += 1
        return out

    def raw(self, frame: bytes) -> dict:
        """One frame out, one answer back, both encrypted for this connection. A refusal comes back as a dict with ok false:
        `request` is what raises."""
        if self.sock is None:
            self._connect()
        try:
            sealed = self._encrypted(self._send, frame)
            self.sock.sendall(struct.pack('>I', len(sealed)) + sealed)
            size = struct.unpack('>I', self._read(4))[0]
            if size > MAX_FRAME + 16:
                raise EnclaveError('down', 'the key enclave sent more than it may')
            return json.loads(self._opened(self._recv, self._read(size)))
        except (OSError, ValueError, InvalidTag) as exc:
            self.close()
            raise EnclaveError('down', f'the key enclave stopped answering: {exc or "what it sent was not encrypted for this connection"}') from None
        except EnclaveError:
            self.close()
            raise

    def request(self, op: str, **fields) -> dict:
        frame = json.dumps({'op': op, **fields}, separators=(',', ':')).encode()
        if len(frame) > MAX_FRAME:
            raise EnclaveError('bad-request', 'that request is larger than the enclave takes')
        try:
            got = self.raw(frame)
        finally:
            self.close()                # the enclave serves one connection at a time: none is held between requests
        if not got.get('ok'):
            raise EnclaveError(str(got.get('error') or 'refused'), str(got.get('why') or 'the key enclave refused'))
        return got

    # ── what the vault asks of it ──
    def status(self) -> dict:
        return self.request('status')

    @staticmethod
    def _kdf(secret: bytes, meta: dict) -> dict:
        """meta['share']: the host's share, where the vault has a second lock (lock2.py)."""
        return {'secret': _b64(secret), 'salt': _b64(meta['kdf_salt']), 'time_cost': meta['kdf_time_cost'], 'memory_kib': meta['kdf_memory_kib'], 'lanes': meta['kdf_lanes'],
                **({'share': _b64(meta['share'])} if meta.get('share') else {})}

    @staticmethod
    def _sealed(row: dict) -> dict:
        """A sealed row as the enclave takes one: a step-up record or a secret."""
        return {'uuid': row['uuid'], **{k: _b64(row[k]) for k in ('dek_nonce', 'wrapped_dek', 'nonce', 'ciphertext')}}

    def _proof(self, user: str, record: dict, password: str | None = None, fido: dict | None = None) -> dict:
        out = {'user': user, 'record': self._sealed(record)}
        if password is not None:
            out['password'] = _b64(_fits('the password', password.encode(), 1024))
        if fido is not None:
            if isinstance(fido, dict):
                for field, most in (('authenticator_data', 1024), ('client_data', 4096), ('signature', 80)):
                    if isinstance(fido.get(field), str):
                        _fits(f'the security key\'s {field}', fido[field].encode(), most * 4 // 3 + 4)
            out['fido'] = fido
        return out

    def unlock(self, secret: bytes, meta: dict, records: list | None = None, stepup: str | None = None, proof: dict | None = None) -> dict:
        """meta: the vault_meta row (kdf_salt, kdf_time_cost, kdf_memory_kib, kdf_lanes, verifier_nonce, verifier, audit_key_nonce, audit_key_wrapped).
        records: the step-up records there are, so that the enclave knows step-up is on. stepup: 'required' to insist on it whatever
        is shown. proof: {user, record, password or fido}, which lifting a lock-down takes once step-up is on."""
        more = {}
        if records:
            more['records'] = [self._sealed(r) for r in records[:64]]
        if stepup:
            more['stepup'] = stepup
        if proof:
            more['proof'] = self._proof(**proof)
        return self.request('unlock', **self._kdf(secret, meta), verifier_nonce=_b64(meta['verifier_nonce']), verifier=_b64(meta['verifier']),
                            audit_key_nonce=_b64(meta['audit_key_nonce']), audit_key_wrapped=_b64(meta['audit_key_wrapped']), **more)

    # ── step-up, checked inside (roadmap section 14) ──
    def stepup_enroll(self, uuid: str, user: str, password: str, fido: list | None = None, rp: str = '', origin: str = '', token: str | None = None,
                      secret: bytes | None = None, meta: dict | None = None) -> dict:
        """A person's step-up record, made inside: back come the ciphertexts to store. The first needs nothing. After that: a token
        of a step-up, or the vault secret with the vault_meta row it is derived by."""
        more = {'token': token} if token else {}
        if secret is not None:
            more.update(self._kdf(secret, meta))
        got = self.request('stepup-enroll', uuid=uuid, user=user, password=_b64(_fits('the password', password.encode(), 1024)), fido=fido or [], rp=rp, origin=origin, **more)
        return {'uuid': uuid, **{k: base64.b64decode(got[k]) for k in ('dek_nonce', 'wrapped_dek', 'nonce', 'ciphertext')}}

    def stepup(self, user: str, record: dict, password: str | None = None, fido: dict | None = None) -> dict:
        """The proof of one person, checked inside. Back comes {'token', 'seconds', 'user'}: the token goes with what needs one."""
        return self.request('stepup', **self._proof(user, record, password, fido))

    def stepup_secret(self, secret: bytes, meta: dict) -> dict:
        """The same token for whoever holds the vault secret: a command run with it needs no person beside it."""
        return self.request('stepup', **self._kdf(secret, meta))

    def challenge(self) -> str:
        """A challenge for a FIDO2 assertion, made inside and good once."""
        return self.request('challenge')['challenge']

    def lock(self) -> dict:
        return self.request('lock')

    @staticmethod
    def _key(row: dict) -> dict:
        return {'uuid': row['key_uuid'], 'dek_nonce': _b64(row['dek_nonce']), 'wrapped_dek': _b64(row['wrapped_dek']), 'key_nonce': _b64(row['key_nonce']), 'ciphertext': _b64(row['ciphertext'])}

    def sign(self, row: dict, data: bytes, flags: int = 0, task: str = 'other') -> tuple[bytes, bytes]:
        """(signature, public key), both in SSH wire form, made inside the enclave with the key of this ssh_keys row. task: the
        kind of work it is for (scan, deploy, console, device, access, rotate, git, sign), which has its own limit and count inside."""
        got = self.request('sign', data=_b64(data), flags=flags, task=task, **self._key(row))
        return base64.b64decode(got['signature']), base64.b64decode(got['public'])

    def generate(self, uuid: str, kind: str = 'ed25519', comment: str = '', token: str | None = None) -> dict:
        """A key made inside. Back come its public line and the ciphertexts for an ssh_keys row, as bytes."""
        if len(comment.encode()) > 200 or any(ord(c) < 0x20 or ord(c) == 0x7f for c in comment):
            raise EnclaveError('bad-request', 'a key comment is at most 200 printable characters')
        got = self.request('generate', uuid=uuid, kind=kind, comment=comment, **({'token': token} if token else {}))
        return {'public_key': got['public_key'], **{k: base64.b64decode(got[k]) for k in ('dek_nonce', 'wrapped_dek', 'key_nonce', 'ciphertext')}}

    def import_key(self, uuid: str, private: bytes, token: str | None = None) -> dict:
        """An unencrypted OpenSSH private key, sealed inside. Back come the ciphertexts for an ssh_keys row and the public blob."""
        got = self.request('import', uuid=uuid, private=_b64(private), **({'token': token} if token else {}))
        return {'public': base64.b64decode(got['public']), **{k: base64.b64decode(got[k]) for k in ('dek_nonce', 'wrapped_dek', 'key_nonce', 'ciphertext')}}

    def seal(self, uuid: str, plaintext: bytes, purpose: str = 'credential', policy: dict | None = None) -> dict:
        """A secret that will have to be given back (a device password, a step's secret), sealed inside. policy: {'steps', 'hosts',
        'platforms', 'sensitive'}, what it may be released for; it comes back as the text to store beside the secret ('policy'),
        which is in the ciphertext's associated data."""
        got = self.request('seal', uuid=uuid, purpose=purpose, plaintext=_b64(plaintext), **({'policy': policy} if policy is not None else {}))
        return {**{k: base64.b64decode(got[k]) for k in ('dek_nonce', 'wrapped_dek', 'nonce', 'ciphertext')}, 'policy': got.get('policy')}

    def release(self, uuid: str, row: dict, named: dict, ts: int, prev: str, purpose: str = 'credential', policy: str | None = None, token: str | None = None) -> tuple[bytes, dict]:
        """That secret, released for a named request. named: {'step', 'host', 'platform'}, at least one. ts and prev: the time and
        the last entry of the audit log, which the entry the enclave makes for this release is written after. policy: the text
        stored beside the secret. Back come the secret and that entry: {'ts', 'actor', 'action', 'host', 'outcome', 'detail_json',
        'prev', 'hash'}, to be stored as it is."""
        more = {k: v for k, v in (('policy', policy), ('token', token)) if v}
        got = self.request('release', uuid=uuid, purpose=purpose, audit={'ts': ts, 'prev': prev}, **{k: _b64(row[k]) for k in ('dek_nonce', 'wrapped_dek', 'nonce', 'ciphertext')},
                           **{'for': {k: v for k, v in named.items() if v}}, **more)
        return base64.b64decode(got['plaintext']), got['audit']

    def rotate_begin(self, new_secret: bytes | None, salt: bytes, time_cost: int, memory_kib: int, lanes: int, token: str | None = None, share: bytes | None = None,
                     current: bytes | None = None) -> dict:
        """The KEK of a new vault secret, held beside the current one. Back come the verifier and audit key wrapped under it.
        share: the host's share to mix in, for a vault with a second lock. new_secret None: the same secret and share under this
        new salt, from what the enclave holds, which takes no step-up (a scheduled rewrap)."""
        # current: the vault secret in force, which the enclave checks before it takes a new one (nobody else may turn the vault over)
        how = {'rekey': True} if new_secret is None else {'secret': _b64(new_secret), **({'share': _b64(share)} if share else {}),
                                                          **({'current': _b64(current)} if current else {})}
        got = self.request('rotate-begin', salt=_b64(salt), time_cost=time_cost, memory_kib=memory_kib, lanes=lanes, **how, **({'token': token} if token else {}))
        return {k: base64.b64decode(got[k]) for k in ('verifier_nonce', 'verifier', 'audit_key_nonce', 'audit_key_wrapped')}

    def rewrap(self, uuid: str, dek_nonce: bytes, wrapped_dek: bytes) -> tuple[bytes, bytes]:
        got = self.request('rewrap', uuid=uuid, dek_nonce=_b64(dek_nonce), wrapped_dek=_b64(wrapped_dek))
        return base64.b64decode(got['dek_nonce']), base64.b64decode(got['wrapped_dek'])

    def rotate_commit(self) -> dict:
        return self.request('rotate-commit')

    def rotate_abort(self) -> dict:
        return self.request('rotate-abort')

    def mac(self, prev: str, payload: str, append: bool = False) -> str:
        """append: this entry is about to be written. The enclave remembers it as the head of the chain, and refuses (`chain`) one
        that does not follow the head it has."""
        return self.request('mac', prev=prev, payload=payload, **({'append': True} if append else {}))['mac']

    def advance(self, start: str, entries: list) -> dict:
        """Entries others wrote after the enclave's head, as (algorithm, payload, hash) in order from `start`: it checks each follows
        the one before and moves its head along. Back comes its chain state."""
        return self.request('advance', **{'from': start}, entries=[list(e) for e in entries])['chain']

    def chain(self) -> dict:
        """{'head', 'prior', 'head_release', 'appended', 'taken_in', 'unwritten', 'releases_unwritten', 'behind'}."""
        return self.status().get('chain') or {}

    def chain_accept(self, head: str, token: str | None = None) -> dict:
        return self.request('chain-accept', head=head, **({'token': token} if token else {}))['chain']

    def mac_matches(self, prev: str, payload: str, expect: str) -> bool:
        return bool(self.request('mac', prev=prev, payload=payload, expect=expect)['matches'])


def describe() -> dict:
    """For the Keys page and the security view: whether the extra layer is there, and where it is not, that it is not and why
    (roadmap section 14, "Where it runs"). Looking never starts a VM."""
    from . import enclave_vm
    address = os.environ.get(ADDRESS_ENV) or None
    try:
        why = enclave_vm.missing()
    except enclave_vm.EnclaveVMError as exc:
        why = str(exc)
    out = {'on': bool(address), 'state': 'off', 'kvm': os.access('/dev/kvm', os.R_OK | os.W_OK), 'vm_possible': why is None, 'why_no_vm': why}
    if not address:
        out['label'] = 'Key enclave: off'
        out['detail'] = ('The vault opens its keys in the web app, as before. This machine can run the enclave: set STORAGEFORGE_ENCLAVE=vm.' if why is None else
                         f'The vault opens its keys in the web app, as before: the extra layer is not there. This machine cannot run the enclave: {why}.')
        return out
    out['runs'] = 'this server' if address.startswith(('fc:', 'vm')) or os.environ.get('STORAGEFORGE_ENCLAVE_IMAGE_DIR') else 'something else'
    if address.startswith('vm'):          # asked for, and not started (yet): nothing may take that for no enclave at all
        return {**out, 'state': 'down', 'label': 'Key enclave: not started', 'detail': 'It was asked for and is not running. Nothing that needs a key works until it is.'}
    client = Enclave(address, timeout=3)
    try:
        status = client.status()
    except EnclaveError as exc:
        return {**out, 'state': 'down', 'label': 'Key enclave: not answering', 'detail': f'{exc}. Nothing that needs a key works until it is back.'}
    finally:
        client.close()
    state = str(status.get('state'))
    out.update(state=state, version=status.get('version'), protocol=status.get('protocol'), in_vm=bool(status.get('pid1') and status.get('memory_locked')),
               counts={k: status.get(k) for k in ('signed', 'released', 'refused', 'bad_requests', 'bad_limit', 'auth_failed', 'policy_refused', 'stepup_missing')},
               tasks=status.get('tasks') or {}, limits=status.get('limits') or {}, stepup=status.get('stepup') or {},
               channel={'key': (status.get('channel') or {}).get('key'), 'named': bool(os.environ.get(KEY_ENV))}, second_lock=bool(status.get('second_lock')),
               chain={k: v for k, v in (status.get('chain') or {}).items() if k not in ('head', 'prior')})
    where = 'a micro VM with no network device' if out['in_vm'] else 'a program on this machine, not a micro VM: for development and tests only'
    out['label'] = {'unlocked': 'Key enclave: on', 'locked': 'Key enclave: locked', 'lockdown': 'Key enclave: locked down'}.get(state, f'Key enclave: {state}')
    out['detail'] = {'unlocked': f'The vault\'s keys are held in {where}. Root on this machine can still read a VM\'s memory.',
                     'locked': f'It runs in {where} and holds no key, as after a restart. The starter unlocks it, or a person here with the vault secret.',
                     'lockdown': f'It was sent {status.get("bad_requests")} requests no honest client sends, and wiped its keys. Find what sent them, then unlock it here with the vault secret.'}.get(state, '')
    return out


# The enclave's own counts, as the notification center reads them (roadmap section 14, "Its own limits"). The counts are kept
# inside, where the web app cannot change them, and only ever go up; what matters is how far they went in the last hour. So each
# look is remembered here, and a count is compared with what it was an hour ago: a notification opens when it has grown and leaves
# an hour after it last did. Nothing is remembered across a restart of the server, and an enclave that restarted starts from nothing.
WINDOW = 3600
COUNTS = ('refused', 'auth_failed', 'stepup_failed', 'stepup_missing', 'policy_refused', 'released', 'unwritten', 'releases_unwritten')
# count → (kind, title, what it means, warn from, critical from)
RISES = {
    'refused': ('security-enclave-limits', 'The key enclave refused requests at its limits', 'were more than its limits allow: more signatures or releases were asked for than any honest run of tasks needs, or a job is running away', 1, 50),
    'auth_failed': ('security-enclave-probed', 'The key enclave was sent ciphertexts or secrets that did not check out', 'did not authenticate: a wrong vault secret, or a ciphertext that was changed or moved to another row', 3, 20),
    'stepup_failed': ('security-enclave-stepup', 'Step-ups failed in the key enclave', 'were wrong passwords or security keys it does not hold', 5, 20),
    'stepup_missing': ('security-enclave-stepup-missing', 'The key enclave was asked for what needs a step-up, without one', 'asked it to make or change a key, or release a sensitive secret, with no token of a step-up', 10, 50),
    'policy_refused': ('security-enclave-policy', 'Secrets were asked for what their policy does not name', 'named a step, host or platform the secret is not released for', 1, 20),
    'released': ('security-enclave-releases', 'The key enclave released many secrets', 'were releases of stored secrets: half of what it allows in an hour', 300, 550),
    'unwritten': ('security-enclave-audit-unwritten', 'Audit entries the key enclave signed were not written', 'were signed and then not found in the log: a write that failed, or the log\'s last entry removed', 1, 5),
    'releases_unwritten': ('security-enclave-audit-release', 'A released secret is missing from the audit log', 'were secrets it released whose audit entry, which it made itself, is not in the log', 1, 1),
}
_looks: dict = {}          # address → [(when, counts)]


def _counts(status: dict) -> dict:
    chain, stepup = status.get('chain') or {}, status.get('stepup') or {}
    return {'refused': status.get('refused', 0), 'auth_failed': status.get('auth_failed', 0), 'stepup_failed': stepup.get('failed', 0), 'stepup_missing': status.get('stepup_missing', 0),
            'policy_refused': status.get('policy_refused', 0), 'released': status.get('released', 0), 'unwritten': chain.get('unwritten', 0), 'releases_unwritten': chain.get('releases_unwritten', 0)}


def risen(address: str, status: dict, now: float | None = None) -> dict:
    """How far each count went in the last hour, from the looks remembered here. At the first look an enclave that has run for
    less than an hour is counted from zero, since all it shows happened in that hour; an older one from what it shows now."""
    now = time.time() if now is None else now
    counts = _counts(status)
    looks = _looks.setdefault(address, [])
    if looks and any(counts[k] < looks[-1][1][k] for k in COUNTS):          # it restarted: its counts began again
        looks.clear()
    if not looks:
        looks.append((now - WINDOW, {k: 0 for k in COUNTS} if int(status.get('uptime') or 0) <= WINDOW else dict(counts)))
    looks.append((now, counts))
    while len(looks) > 2 and looks[1][0] <= now - WINDOW:          # keep one look from before the window, to count from
        looks.pop(0)
    base = looks[0][1]
    return {k: counts[k] - base[k] for k in COUNTS}


def problems() -> dict:
    """For the notification center (alerts.problems): an enclave that was asked for and is not answering, has locked itself down,
    or is locked, and what its own counts say. Every kind starts with security-, so none can be muted or snoozed: they leave when
    they are resolved."""
    address = os.environ.get(ADDRESS_ENV) or None          # not configured(): looking for problems never starts a VM
    if not address or address == 'vm':
        return {}
    client = Enclave(address, timeout=3)
    try:
        status = client.status()
    except EnclaveError as exc:
        return {'security-enclave': ('security-enclave', 'enclave', 'The key enclave does not answer',
                                     f'{exc}. Nothing that needs a key works until it is back: scans, deploys, sends, the console. The vault is not opened without it.', 'crit')}
    finally:
        client.close()
    if status.get('state') == 'lockdown':
        return {'security-enclave': ('security-enclave', 'enclave', 'The key enclave has locked itself down',
                                     f'It was sent {status.get("bad_requests")} requests no honest client sends, and wiped its keys. Find what sent them before unlocking it again with the vault secret.', 'crit')}
    out = {}
    if status.get('foreign_unlocks'):
        out['security-enclave-foreign'] = ('security-enclave-foreign', 'enclave', 'The key enclave refused an unlock for another vault',
                                           f'{status["foreign_unlocks"]} unlock(s) since it started came with a secret and verifier of some other vault. Only something that can '
                                           'reach the enclave\'s socket sends one: find it. If this installation\'s own starter is refused, the enclave was unlocked by '
                                           'someone else first: restart the enclave and let the starter unlock it.', 'crit')
    if status.get('state') != 'unlocked':
        out['security-enclave'] = ('security-enclave', 'enclave', 'The key enclave is locked',
                                   'It holds no key, as after a restart. The starter unlocks it, or a person on the Keys page with the vault secret.', 'warn')
    if status.get('bad_requests'):
        out['security-enclave-malformed'] = ('security-enclave-malformed', 'enclave', 'The key enclave was sent malformed requests',
                                             f'{status["bad_requests"]} of the {status.get("bad_limit", 5)} after which it wipes its keys and locks itself down. No honest client sends one: find what did.', 'warn')
    if (status.get('chain') or {}).get('behind'):
        out['security-enclave-audit'] = ('security-enclave-audit', 'enclave', 'The audit log no longer ends where the key enclave signed it',
                                         'Entries were removed or changed in the database. Audit → Verify chain shows what is there. No secret is released until someone has looked and taken the log as it is, on the Keys page.', 'crit')
    for count, grew in risen(address, status).items():
        kind, title, means, warn, crit = RISES[count]
        if grew >= warn:
            out[kind] = (kind, 'enclave', title, f'{grew} in the last hour {means}. The count is the enclave\'s own, kept where the web app cannot change it.', 'crit' if grew >= crit else 'warn')
    return out


# ── an ssh-agent whose key is in the enclave ────────────────────────
# What `ssh` needs from an agent is two answers: which keys it has, and a signature. This serves both on a socket file for the length
# of one task, as the per-task ssh-agent does today (runner.ephemeral_agent), with one difference: there is no key here to load. The
# list is the row's public key, and each signature is asked of the enclave. Nothing else an agent can be asked is answered: no adding,
# no removing, no locking, no extensions.
import contextlib          # noqa: E402
import shutil              # noqa: E402
import tempfile            # noqa: E402
import threading           # noqa: E402

AGENT_FAILURE, AGENTC_REQUEST_IDENTITIES, AGENT_IDENTITIES_ANSWER, AGENTC_SIGN_REQUEST, AGENT_SIGN_RESPONSE = 5, 11, 12, 13, 14
AGENT_MAX_MESSAGE = 256 * 1024 + 4096


def _string(b: bytes) -> bytes:
    return struct.pack('>I', len(b)) + b


def _take_string(buf: bytes, at: int) -> tuple[bytes, int]:
    if at + 4 > len(buf):
        raise ValueError('short')
    n = struct.unpack('>I', buf[at:at + 4])[0]
    if at + 4 + n > len(buf):
        raise ValueError('short')
    return buf[at + 4:at + 4 + n], at + 4 + n


def agent_reply(message: bytes, public_blob: bytes, comment: bytes, sign) -> bytes:
    """The answer to one agent message. sign(data, flags) -> the signature in SSH wire form, from the enclave."""
    if not message:
        return bytes([AGENT_FAILURE])
    kind = message[0]
    if kind == AGENTC_REQUEST_IDENTITIES and len(message) == 1:
        return bytes([AGENT_IDENTITIES_ANSWER]) + struct.pack('>I', 1) + _string(public_blob) + _string(comment)
    if kind == AGENTC_SIGN_REQUEST:
        try:
            blob, at = _take_string(message, 1)
            data, at = _take_string(message, at)
            flags = struct.unpack('>I', message[at:at + 4])[0] if at + 4 == len(message) else None
        except (ValueError, struct.error):
            return bytes([AGENT_FAILURE])
        if flags is None or blob != public_blob:          # a key this agent does not have, or a message with more in it than a request
            return bytes([AGENT_FAILURE])
        try:
            return bytes([AGENT_SIGN_RESPONSE]) + _string(sign(data, flags))
        except EnclaveError:
            return bytes([AGENT_FAILURE])
    return bytes([AGENT_FAILURE])


@contextlib.contextmanager
def agent(address: str, row: dict, ttl: int, base: str | None = None, task: str = 'other'):
    """A socket file `ssh` can use as SSH_AUTH_SOCK for the key of this ssh_keys row, for at most ttl seconds. row needs key_uuid,
    dek_nonce, wrapped_dek, key_nonce, ciphertext and public_key (the line). Each client gets its own connection to the enclave.
    task: the kind of work the signatures are for."""
    public_blob = base64.b64decode(row['public_key'].split()[1])
    comment = ' '.join(row['public_key'].split()[2:]).encode()
    folder = tempfile.mkdtemp(prefix='agent-', dir=base)
    os.chmod(folder, 0o700)
    path = os.path.join(folder, 'agent.sock')
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(path)
    os.chmod(path, 0o600)
    listener.listen(8)
    listener.settimeout(0.2)
    until, stop = time.time() + ttl, threading.Event()

    def serve(client):
        try:
            client.settimeout(30)
            with Enclave(address) as enclave:
                while not stop.is_set() and time.time() < until:
                    head = b''
                    while len(head) < 4:
                        chunk = client.recv(4 - len(head))
                        if not chunk:
                            return
                        head += chunk
                    size = struct.unpack('>I', head)[0]
                    if not 1 <= size <= AGENT_MAX_MESSAGE:
                        return
                    body = b''
                    while len(body) < size:
                        chunk = client.recv(size - len(body))
                        if not chunk:
                            return
                        body += chunk
                    reply = agent_reply(body, public_blob, comment, lambda data, flags: enclave.sign(row, data, flags, task)[0])
                    client.sendall(struct.pack('>I', len(reply)) + reply)
        except OSError:
            pass
        finally:
            client.close()

    def accept():
        while not stop.is_set() and time.time() < until:
            try:
                client, _ = listener.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            threading.Thread(target=serve, args=(client,), daemon=True).start()

    thread = threading.Thread(target=accept, daemon=True)
    thread.start()
    try:
        yield path
    finally:
        stop.set()
        listener.close()
        thread.join(2)
        shutil.rmtree(folder, ignore_errors=True)
