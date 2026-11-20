"""The controller's end of the agent's tunnel (roadmap section 11.1, "Delivery", and 11.2; the agent's end is agent/src/tunnel.rs).

    agent ──TCP, Noise_IK_25519_AESGCM_SHA256──► receiver (agentreceiver.py, a process of its own)
        the agent knows the receiver's static key before it dials: pinned on its host by storageforge-agentctl, from a signed request
        the receiver knows the agent from the static key in the first message, and from nothing else: its ed25519 key pinned at
        enrollment, used as X25519 (the same scalar, as `age` uses SSH keys), so nothing new has to be pinned

The same primitives as the key enclave's channel (enclave.py): X25519, AES-256-GCM, SHA-256 and its HKDF, here in the IK pattern so
that both ends prove their keys. What goes through it is in tunnel.rs's header: the agent's hello, then the delivery (the manifest
the controller signed for the host and the plugin files it names, none of it secret, all of it checked by the agent), then signed
batches and their answers.

The receiver's key: an X25519 key of its own, made by the receiver the first time it starts, in its folder, readable by its account
alone. It opens sessions and does nothing else: it signs no manifest and no plugin, so whoever stole it could read what agents say and
offer them files they would refuse. The web app reads only its public half, to give it to hosts.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import socket
import struct
from pathlib import Path

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PROTOCOL_NAME = b'Noise_IK_25519_AESGCM_SHA256'
PROLOGUE = b'storageforge-agent-tunnel-v1'
NS_BATCH = 'storageforge-agent-batch'
TAG = 16
MAX_FRAME = 1 << 20
MAX_HANDSHAKE_PAYLOAD = 4096
CHUNK = 512 << 10
KEY_FILE, PUBLIC_FILE = 'receiver_key', 'receiver_key.pub'
DEFAULT_PORT = 7843
_P = 2 ** 255 - 19


class TunnelError(RuntimeError):
    """What ends a conversation: a frame of a size no honest peer sends, one that does not open, a key not accepted."""


# ── keys ────────────────────────────────────────────────────────────
def ed25519_to_x25519(public: bytes) -> bytes:
    """The X25519 key of an ed25519 public key: the Montgomery u of the Edwards point, u = (1 + y) / (1 - y). The agent's secret
    half is the scalar of its ed25519 seed, so the two meet. ValueError for anything that is not a key."""
    if len(public) != 32:
        raise ValueError('an ed25519 key is 32 bytes')
    y = int.from_bytes(public, 'little') & ((1 << 255) - 1)
    if y >= _P or y == 1:
        raise ValueError('not an ed25519 key')
    u = (1 + y) * pow((1 - y) % _P, _P - 2, _P) % _P
    return u.to_bytes(32, 'little')


def x25519_of_seed(seed: bytes) -> bytes:
    """The agent's X25519 secret, from its ed25519 seed: the scalar half of SHA-512 of the seed, as ed25519 makes it. For the tests,
    which play agents."""
    return hashlib.sha512(seed).digest()[:32]


def public_of(secret: bytes) -> bytes:
    return X25519PrivateKey.from_private_bytes(secret).public_key().public_bytes_raw()


def _dh(secret: bytes, public: bytes) -> bytes:
    try:
        out = X25519PrivateKey.from_private_bytes(secret).exchange(X25519PublicKey.from_public_bytes(public))
    except ValueError:
        raise TunnelError('a key of small order') from None
    if not any(out):
        raise TunnelError('a key of small order')
    return out


def receiver_dir() -> Path | None:
    folder = os.environ.get('STORAGEFORGE_AGENT_RECEIVER_DIR', '').strip()
    return Path(folder) if folder else None


def load_or_make_key(folder: Path) -> bytes:
    """The receiver's secret, made on first start: mode 0600 in its own folder, the public half beside it for the web app."""
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / KEY_FILE
    try:
        st = path.lstat()
    except FileNotFoundError:
        secret = os.urandom(32)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w') as f:
            f.write(secret.hex() + '\n')
        tmp = folder / (PUBLIC_FILE + '.new')
        tmp.write_text(base64.b64encode(public_of(secret)).decode() + '\n')
        tmp.chmod(0o644)
        tmp.replace(folder / PUBLIC_FILE)
        return secret
    if not path.is_file() or path.is_symlink() or st.st_mode & 0o077:
        raise TunnelError(f'{path} is not a file only its owner can read')
    secret = bytes.fromhex(path.read_text().strip())
    if len(secret) != 32:
        raise TunnelError(f'{path} is not a key')
    if not (folder / PUBLIC_FILE).exists():
        (folder / PUBLIC_FILE).write_text(base64.b64encode(public_of(secret)).decode() + '\n')
    return secret


def receiver_public(folder: Path | None = None) -> str | None:
    """The receiver's public key, base64, as hosts pin it; None when no receiver has started yet."""
    folder = folder or receiver_dir()
    if folder is None:
        return None
    try:
        text = (folder / PUBLIC_FILE).read_text().strip()
    except OSError:
        return None
    try:
        return text if len(base64.b64decode(text, validate=True)) == 32 else None
    except ValueError:
        return None


# ── framing and the handshake ───────────────────────────────────────
def read_exact(sock, n: int) -> bytes:
    out = bytearray()
    while len(out) < n:
        chunk = sock.recv(min(n - len(out), 1 << 16))
        if not chunk:
            raise ConnectionError('the connection ended')
        out += chunk
    return bytes(out)


def read_frame(sock, least: int, most: int) -> bytes:
    n = struct.unpack('>I', read_exact(sock, 4))[0]
    if n < least or n > most:
        raise TunnelError(f'a frame of {n} bytes is outside what is accepted')
    return read_exact(sock, n)


def write_frame(sock, body: bytes):
    sock.sendall(struct.pack('>I', len(body)) + body)


def _hkdf(ck: bytes, ikm: bytes) -> tuple[bytes, bytes]:
    temp = hmac.new(ck, ikm, hashlib.sha256).digest()
    one = hmac.new(temp, b'\x01', hashlib.sha256).digest()
    return one, hmac.new(temp, one + b'\x02', hashlib.sha256).digest()


class Cipher:
    """One direction of a connection: a key and the count of frames it has sealed or opened."""

    def __init__(self, key: bytes):
        self.aead, self.n = AESGCM(key), 0

    def _nonce(self) -> bytes:
        if self.n >= 2 ** 64 - 1:
            raise TunnelError('the connection has used every nonce')
        nonce = b'\0\0\0\0' + struct.pack('>Q', self.n)
        self.n += 1
        return nonce

    def seal(self, plain: bytes, ad: bytes = b'') -> bytes:
        return self.aead.encrypt(self._nonce(), plain, ad)

    def open(self, sealed: bytes, ad: bytes = b'') -> bytes:
        try:
            return self.aead.decrypt(self._nonce(), sealed, ad)
        except InvalidTag:
            raise TunnelError('a frame that does not open: changed on the way, or not sealed for this connection') from None


class _Symmetric:
    def __init__(self):
        self.h = PROTOCOL_NAME.ljust(32, b'\0')
        self.ck = self.h
        self.k: Cipher | None = None
        self.mix_hash(PROLOGUE)

    def mix_hash(self, data: bytes):
        self.h = hashlib.sha256(self.h + data).digest()

    def mix_key(self, ikm: bytes):
        self.ck, k = _hkdf(self.ck, ikm)
        self.k = Cipher(k)

    def encrypt_and_hash(self, plain: bytes) -> bytes:
        out = self.k.seal(plain, self.h) if self.k else plain
        self.mix_hash(out)
        return out

    def decrypt_and_hash(self, sealed: bytes) -> bytes:
        out = self.k.open(sealed, self.h) if self.k else sealed
        self.mix_hash(sealed)
        return out

    def split(self) -> tuple[Cipher, Cipher]:
        one, two = _hkdf(self.ck, b'')
        return Cipher(one), Cipher(two)


class Session:
    def __init__(self, send: Cipher, recv: Cipher, hash_: bytes, remote: bytes):
        self.send, self.recv, self.hash, self.remote = send, recv, hash_, remote

    def write(self, sock, plain: bytes):
        if len(plain) > MAX_FRAME:
            raise TunnelError('a frame too large to send')
        write_frame(sock, self.send.seal(plain))

    def read(self, sock, most: int = MAX_FRAME) -> bytes:
        return self.recv.open(read_frame(sock, TAG, min(most, MAX_FRAME) + TAG))

    def send_json(self, sock, value: dict):
        self.write(sock, json.dumps(value, separators=(',', ':')).encode())


def initiate(sock, local: bytes, remote: bytes, payload: bytes = b'', ephemeral: bytes | None = None) -> tuple[Session, bytes]:
    """The agent's side, for the tests that play agents."""
    s = _Symmetric()
    s.mix_hash(remote)
    eph = ephemeral or os.urandom(32)
    e_pub = public_of(eph)
    s.mix_hash(e_pub)
    s.mix_key(_dh(eph, remote))
    first = e_pub + s.encrypt_and_hash(public_of(local))
    s.mix_key(_dh(local, remote))
    first += s.encrypt_and_hash(payload)
    write_frame(sock, first)
    reply = read_frame(sock, 32 + TAG, 32 + TAG + MAX_HANDSHAKE_PAYLOAD)
    re = reply[:32]
    s.mix_hash(re)
    s.mix_key(_dh(eph, re))
    s.mix_key(_dh(local, re))
    theirs = s.decrypt_and_hash(reply[32:])
    send, recv = s.split()
    return Session(send, recv, s.h, remote), theirs


def respond(sock, local: bytes, admit, answer) -> tuple[Session, bytes]:
    """The receiver's side. admit(static key) is asked as soon as the initiator's static key is known, after one DH and before any
    more work; answer(static key, payload) gives what goes back. TunnelError for a key not admitted, or anything else no honest agent
    sends."""
    first = read_frame(sock, 32 + 48 + TAG, 32 + 48 + TAG + MAX_HANDSHAKE_PAYLOAD)
    s = _Symmetric()
    s.mix_hash(public_of(local))
    re = first[:32]
    s.mix_hash(re)
    s.mix_key(_dh(local, re))
    rs = s.decrypt_and_hash(first[32:80])
    if not admit(rs):
        raise TunnelError('a key that is not the pinned key of an enrolled agent')
    s.mix_key(_dh(local, rs))
    theirs = s.decrypt_and_hash(first[80:])
    payload = answer(rs, theirs)
    if len(payload) > MAX_HANDSHAKE_PAYLOAD:
        raise TunnelError('the answer is too large')
    eph = os.urandom(32)
    e_pub = public_of(eph)
    s.mix_hash(e_pub)
    s.mix_key(_dh(eph, re))
    s.mix_key(_dh(eph, rs))
    write_frame(sock, e_pub + s.encrypt_and_hash(payload))
    recv, send = s.split()
    return Session(send, recv, s.h, rs), theirs


# ── what the agent signs ────────────────────────────────────────────
def _string(blob: bytes, at: int) -> tuple[bytes, int]:
    if at + 4 > len(blob):
        raise ValueError('cut short')
    n = struct.unpack('>I', blob[at:at + 4])[0]
    if at + 4 + n > len(blob):
        raise ValueError('cut short')
    return blob[at + 4:at + 4 + n], at + 4 + n


def _s(b: bytes) -> bytes:
    return struct.pack('>I', len(b)) + b


def verify_batch(public: bytes, body: bytes, armored: str) -> bool:
    """Whether `armored` is an SSH signature of `body` by the ed25519 key `public`, made for batches and nothing else."""
    if len(armored) > 4096:
        return False
    text = armored.strip()
    if not text.startswith('-----BEGIN SSH SIGNATURE-----') or not text.endswith('-----END SSH SIGNATURE-----'):
        return False
    try:
        raw = base64.b64decode(''.join(text.split('\n')[1:-1]), validate=True)
        if raw[:6] != b'SSHSIG' or raw[6:10] != b'\0\0\0\1':
            return False
        key_blob, at = _string(raw, 10)
        namespace, at = _string(raw, at)
        reserved, at = _string(raw, at)
        hash_name, at = _string(raw, at)
        sig_blob, at = _string(raw, at)
        if at != len(raw) or reserved or namespace != NS_BATCH.encode() or hash_name != b'sha512':
            return False
        if key_blob != _s(b'ssh-ed25519') + _s(public):
            return False
        kind, at2 = _string(sig_blob, 0)
        sig, at2 = _string(sig_blob, at2)
        if kind != b'ssh-ed25519' or len(sig) != 64 or at2 != len(sig_blob):
            return False
        signed = b'SSHSIG' + _s(NS_BATCH.encode()) + _s(b'') + _s(b'sha512') + _s(hashlib.sha512(body).digest())
        Ed25519PublicKey.from_public_bytes(public).verify(sig, signed)
        return True
    except (ValueError, InvalidSignature):
        return False


def sign_batch(private, body: bytes) -> str:
    """An agent's signature of a batch, for the tests that play agents: private is an Ed25519PrivateKey."""
    from . import deploy
    return deploy.sshsig(private, body, NS_BATCH)


def ed25519_of_line(line: str) -> bytes:
    """The 32 bytes of an `ssh-ed25519 AAAA...` line. ValueError for anything else."""
    parts = (line or '').split()
    if len(parts) < 2 or parts[0] != 'ssh-ed25519':
        raise ValueError('not an ed25519 key')
    blob = base64.b64decode(parts[1], validate=True)
    kind, at = _string(blob, 0)
    key, at = _string(blob, at)
    if kind != b'ssh-ed25519' or len(key) != 32 or at != len(blob):
        raise ValueError('not an ed25519 key')
    return key


# ── the delivery ────────────────────────────────────────────────────
def plugins_dir() -> Path | None:
    """Where the release's plugins are: STORAGEFORGE_AGENT_PLUGINS, or plugins/ in STORAGEFORGE_AGENT_DIR, with a folder per machine
    (x86_64, aarch64) holding NAME.plugin.json, NAME.plugin.sig and NAME.plugin as agent/build.sh lays them out."""
    folder = os.environ.get('STORAGEFORGE_AGENT_PLUGINS', '').strip()
    if folder:
        return Path(folder)
    base = os.environ.get('STORAGEFORGE_AGENT_DIR', '').strip()
    return Path(base) / 'plugins' if base else None


def program_of(descriptor: str) -> bytes:
    """The program a signed descriptor names, from the release's folder, checked against the descriptor's hash and size before it is
    handed to anyone. The agent checks again; this keeps a broken release from being sent at all."""
    d = json.loads(descriptor)
    name, arch = str(d.get('name') or ''), str(d.get('arch') or '')
    folder = plugins_dir()
    if folder is None or arch not in ('x86_64', 'aarch64') or not name.replace('-', '').isalnum():
        raise TunnelError(f'no program for plugin {name[:40]}: STORAGEFORGE_AGENT_PLUGINS names no folder')
    path = folder / arch / f'{name}.plugin'
    data = path.read_bytes() if path.is_file() and path.stat().st_size <= 32 << 20 else b''
    if len(data) != d.get('size') or hashlib.sha256(data).hexdigest() != d.get('sha256'):
        raise TunnelError(f'the program for plugin {name} in {folder} is not the one its descriptor names')
    return data


def delivery_frames(delivery: dict | None, have: list) -> list[dict]:
    """What the receiver sends after an agent's hello: the manifest, then each plugin the agent does not have loaded, in chunks."""
    if not delivery:
        return [{'op': 'manifest', 'manifest': None, 'signature': None}, {'op': 'ready'}]
    out = [{'op': 'manifest', 'manifest': delivery['manifest'], 'signature': delivery['signature']}]
    for p in delivery.get('plugins') or []:
        name = json.loads(p['descriptor']).get('name')
        if name in have:
            continue
        program = program_of(p['descriptor'])
        out.append({'op': 'plugin', 'name': name, 'descriptor': p['descriptor'], 'signature': p['signature']})
        for i in range(0, len(program), CHUNK):
            out.append({'op': 'chunk', 'name': name, 'data': base64.b64encode(program[i:i + CHUNK]).decode()})
        out.append({'op': 'plugin-end', 'name': name})
    out.append({'op': 'ready'})
    return out


def connect(address: str, port: int, timeout: float = 10.0):
    return socket.create_connection((address, port), timeout=timeout)
