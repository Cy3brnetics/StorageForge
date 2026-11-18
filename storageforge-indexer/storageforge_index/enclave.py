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
        got = self.raw(frame)
        if not got.get('ok'):
            if got.get('error') == 'bad-request':
                self.close()            # the enclave has hung up on it
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

    def mac(self, prev: str, payload: str) -> str:
        return self.request('mac', prev=prev, payload=payload)['mac']

    def mac_matches(self, prev: str, payload: str, expect: str) -> bool:
        return bool(self.request('mac', prev=prev, payload=payload, expect=expect)['matches'])
