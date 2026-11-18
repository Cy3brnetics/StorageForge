"""The controller's side of the key enclave (roadmap section 14; the program is enclave/src/main.rs).

The enclave is a micro VM with no network device that holds the vault's KEK. This speaks to it: a 4-byte length and JSON, one
request at a time, over vsock (`vsock:CID:PORT`) or, on a developer's machine and in the tests, a socket file (`unix:PATH`).
Nothing here ever holds a private key or the KEK. The vault secret passes through once, on its way in at unlock.

Every ciphertext stays in the database in the vault's own format (vault.py) and goes with the request that needs it, so turning
the enclave on or off changes nothing that is stored.
"""
from __future__ import annotations

import base64
import json
import os
import socket
import struct

MAX_FRAME = 1 << 20
ADDRESS_ENV = 'STORAGEFORGE_ENCLAVE'


class EnclaveError(RuntimeError):
    """The enclave refused, or could not be reached. `code` is its own word for why: locked, lockdown, auth, rate, key, bad-request, down."""

    def __init__(self, code: str, why: str):
        super().__init__(why)
        self.code = code


def configured() -> str | None:
    return os.environ.get(ADDRESS_ENV) or None


def _b64(value) -> str:
    return base64.b64encode(bytes(value)).decode()


class Enclave:
    def __init__(self, address: str, timeout: float = 30.0):
        self.address, self.timeout, self.sock = address, timeout, None

    def _connect(self):
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
            else:
                raise EnclaveError('down', f'{ADDRESS_ENV} is unix:PATH or vsock:CID:PORT, not {self.address!r}')
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

    def raw(self, frame: bytes) -> dict:
        """One frame out, one answer back. A refusal comes back as a dict with ok false: `request` is what raises."""
        if self.sock is None:
            self._connect()
        try:
            self.sock.sendall(struct.pack('>I', len(frame)) + frame)
            size = struct.unpack('>I', self._read(4))[0]
            if size > MAX_FRAME:
                raise EnclaveError('down', 'the key enclave sent more than it may')
            return json.loads(self._read(size))
        except (OSError, ValueError) as exc:
            self.close()
            raise EnclaveError('down', f'the key enclave stopped answering: {exc}') from None
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

    def unlock(self, secret: bytes, meta: dict) -> dict:
        """meta: the vault_meta row (kdf_salt, kdf_time_cost, kdf_memory_kib, kdf_lanes, verifier_nonce, verifier, audit_key_nonce, audit_key_wrapped)."""
        return self.request('unlock', secret=_b64(secret), salt=_b64(meta['kdf_salt']), time_cost=meta['kdf_time_cost'], memory_kib=meta['kdf_memory_kib'], lanes=meta['kdf_lanes'],
                            verifier_nonce=_b64(meta['verifier_nonce']), verifier=_b64(meta['verifier']), audit_key_nonce=_b64(meta['audit_key_nonce']), audit_key_wrapped=_b64(meta['audit_key_wrapped']))

    def lock(self) -> dict:
        return self.request('lock')

    @staticmethod
    def _key(row: dict) -> dict:
        return {'uuid': row['key_uuid'], 'dek_nonce': _b64(row['dek_nonce']), 'wrapped_dek': _b64(row['wrapped_dek']), 'key_nonce': _b64(row['key_nonce']), 'ciphertext': _b64(row['ciphertext'])}

    def sign(self, row: dict, data: bytes, flags: int = 0) -> tuple[bytes, bytes]:
        """(signature, public key), both in SSH wire form, made inside the enclave with the key of this ssh_keys row."""
        got = self.request('sign', data=_b64(data), flags=flags, **self._key(row))
        return base64.b64decode(got['signature']), base64.b64decode(got['public'])

    def generate(self, uuid: str, kind: str = 'ed25519', comment: str = '') -> dict:
        """A key made inside. Back come its public line and the ciphertexts for an ssh_keys row, as bytes."""
        got = self.request('generate', uuid=uuid, kind=kind, comment=comment)
        return {'public_key': got['public_key'], **{k: base64.b64decode(got[k]) for k in ('dek_nonce', 'wrapped_dek', 'key_nonce', 'ciphertext')}}

    def import_key(self, uuid: str, private: bytes) -> dict:
        """An unencrypted OpenSSH private key, sealed inside. Back come the ciphertexts for an ssh_keys row and the public blob."""
        got = self.request('import', uuid=uuid, private=_b64(private))
        return {'public': base64.b64decode(got['public']), **{k: base64.b64decode(got[k]) for k in ('dek_nonce', 'wrapped_dek', 'key_nonce', 'ciphertext')}}

    def seal(self, uuid: str, plaintext: bytes, purpose: str = 'credential') -> dict:
        """A secret that will have to be given back (a device password, a step's secret), sealed inside."""
        got = self.request('seal', uuid=uuid, purpose=purpose, plaintext=_b64(plaintext))
        return {k: base64.b64decode(got[k]) for k in ('dek_nonce', 'wrapped_dek', 'nonce', 'ciphertext')}

    def release(self, uuid: str, row: dict, purpose: str = 'credential') -> bytes:
        """That secret, released: the enclave counts it and limits how often. row has dek_nonce, wrapped_dek, nonce and ciphertext."""
        got = self.request('release', uuid=uuid, purpose=purpose, **{k: _b64(row[k]) for k in ('dek_nonce', 'wrapped_dek', 'nonce', 'ciphertext')})
        return base64.b64decode(got['plaintext'])

    def rotate_begin(self, new_secret: bytes, salt: bytes, time_cost: int, memory_kib: int, lanes: int) -> dict:
        """The KEK of a new vault secret, held beside the current one. Back come the verifier and audit key wrapped under it."""
        got = self.request('rotate-begin', secret=_b64(new_secret), salt=_b64(salt), time_cost=time_cost, memory_kib=memory_kib, lanes=lanes)
        return {k: base64.b64decode(got[k]) for k in ('verifier_nonce', 'verifier', 'audit_key_nonce', 'audit_key_wrapped')}

    def rewrap(self, uuid: str, dek_nonce: bytes, wrapped_dek: bytes) -> tuple[bytes, bytes]:
        got = self.request('rewrap', uuid=uuid, dek_nonce=_b64(dek_nonce), wrapped_dek=_b64(wrapped_dek))
        return base64.b64decode(got['dek_nonce']), base64.b64decode(got['wrapped_dek'])

    def rotate_commit(self) -> dict:
        return self.request('rotate-commit')

    def rotate_abort(self) -> dict:
        return self.request('rotate-abort')

    def mac(self, prev: str, payload: str) -> str:
        return self.request('mac', prev=prev, payload=payload)['mac']

    def mac_matches(self, prev: str, payload: str, expect: str) -> bool:
        return bool(self.request('mac', prev=prev, payload=payload, expect=expect)['matches'])


# ── an ssh-agent whose key is in the enclave ────────────────────────
# What `ssh` needs from an agent is two answers: which keys it has, and a signature. This serves both on a socket file for the length
# of one task, as the per-task ssh-agent does today (runner.ephemeral_agent), with one difference: there is no key here to load. The
# list is the row's public key, and each signature is asked of the enclave. Nothing else an agent can be asked is answered: no adding,
# no removing, no locking, no extensions.
import contextlib          # noqa: E402
import shutil              # noqa: E402
import tempfile            # noqa: E402
import threading           # noqa: E402
import time                # noqa: E402

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
def agent(address: str, row: dict, ttl: int, base: str | None = None):
    """A socket file `ssh` can use as SSH_AUTH_SOCK for the key of this ssh_keys row, for at most ttl seconds. row needs key_uuid,
    dek_nonce, wrapped_dek, key_nonce, ciphertext and public_key (the line). Each client gets its own connection to the enclave."""
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
                    reply = agent_reply(body, public_blob, comment, lambda data, flags: enclave.sign(row, data, flags)[0])
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
