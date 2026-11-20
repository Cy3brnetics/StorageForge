"""The second lock on the KEK (roadmap section 14, "Layers").

Without it the KEK comes from the vault secret alone, so the secret beside a stolen database, or a backup with its secret, is the keys.
With it a second share, 32 random bytes in a file on the machine the vault runs on, is mixed into the KEK:

    KEK = HMAC-SHA256(key = host share, "storageforge:second-lock:v1" ‖ 0 ‖ Argon2id(vault secret))

The secret alone then derives a key that opens nothing, on this machine or another. Nothing stored changes format: turning the
lock on or off is a rotation, which rewraps each DEK under the new KEK and never touches a key's ciphertext, and vault_meta.second_lock
says which way the KEK is derived.

The share is a file only its owner can read, kept outside the database, its backups and the secret volume: STORAGEFORGE_HOST_SHARE_FILE,
/etc/storageforge/host_share if not set. Whoever unlocks the vault reads it: the starter, or a command that holds the secret.

The recovery share is printed once when the lock is turned on. With it and the database, `vault second-lock recover` writes the host
share again on a machine that lost it, or on a new one. The database holds the host share sealed under a key made from the recovery
share, and nothing else of it. Kept with the vault secret, the recovery share undoes what the second lock is for: keep them apart.

Sealing the share to a TPM is not built: it needs tpm2-tools on the host and a TPM to test against, and neither was there. The file
is what there is, and `vault second-lock status` says so.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import shutil
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SHARE_ENV = 'STORAGEFORGE_HOST_SHARE_FILE'
DEFAULT = '/etc/storageforge/host_share'
LABEL = b'storageforge:second-lock:v1\0'
KEEP = object()          # "leave the second lock as it is", for a rotation that is about something else


def share_path() -> Path:
    return Path(os.environ.get(SHARE_ENV) or DEFAULT)


def mix(kek: bytes, share: bytes) -> bytes:
    """The KEK of a vault with a second lock, from the key the secret derives and the host's share. The enclave does the same (main.rs, kdf)."""
    return hmac.new(share, LABEL + bytes(kek), hashlib.sha256).digest()


def share_id(share: bytes) -> str:
    """Which share a vault is locked to, without saying anything of the share."""
    return hashlib.sha256(b'storageforge:share-id\0' + share).hexdigest()[:16]


def _errors():
    from .vault import VaultError, VaultLocked
    return VaultError, VaultLocked


def read_share(marker: dict | None = None) -> bytes:
    """The host's share from its file. marker: the vault's second_lock, to tell a share of another vault from this one's."""
    VaultError, VaultLocked = _errors()
    path = share_path()
    try:
        mode = path.stat().st_mode
        text = path.read_text().strip()
    except OSError as exc:
        raise VaultLocked(f'this vault has a second lock, and the host share {path} cannot be read here ({exc.strerror}): it opens only on the machine that holds the share. '
                          'On a new machine: storageforge-index vault second-lock recover') from None
    if mode & 0o077:
        raise VaultError(f'{path} can be read by others than its owner: chmod 600 {path}')
    try:
        share = base64.b64decode(text, validate=True)
    except ValueError:
        share = b''
    if len(share) != 32:
        raise VaultError(f'{path} does not hold a host share')
    if marker and share_id(share) != marker.get('share'):
        raise VaultLocked(f'the host share in {path} is not the one this vault is locked to')
    return share


def write_share(share: bytes, path: Path | None = None) -> Path:
    """The share into its file, which only this account can read. An existing file is never overwritten."""
    VaultError, _ = _errors()
    path = path or share_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        raise VaultError(f'{path} is there already, and a host share is never overwritten: move it away first if it is not this vault\'s') from None
    except OSError as exc:
        raise VaultError(f'the host share cannot be written to {path}: {exc.strerror}. Set {SHARE_ENV} to a file this account can write') from None
    with os.fdopen(fd, 'w') as f:
        f.write(base64.b64encode(share).decode() + '\n')
    return path


def _recovery_key(code: bytes) -> bytes:
    return hmac.new(code, b'storageforge:second-lock-recovery', hashlib.sha256).digest()


def recovery(share: bytes) -> tuple[str, dict]:
    """A recovery share to print once, and what goes in the database for it: the host share sealed under a key made from it."""
    code = secrets.token_bytes(20)
    nonce = os.urandom(12)
    sealed = AESGCM(_recovery_key(code)).encrypt(nonce, share, b'storageforge:second-lock-recovery')
    text = base64.b32encode(code).decode()
    return '-'.join(text[i:i + 4] for i in range(0, len(text), 4)), {'nonce': base64.b64encode(nonce).decode(), 'sealed': base64.b64encode(sealed).decode()}


def recover(marker: dict, code_text: str) -> bytes:
    """The host share, from the recovery share and what the database holds."""
    VaultError, _ = _errors()
    try:
        code = base64.b32decode(''.join(c for c in code_text.upper() if c.isalnum()))
        held = marker['recovery']
        return AESGCM(_recovery_key(code)).decrypt(base64.b64decode(held['nonce']), base64.b64decode(held['sealed']), b'storageforge:second-lock-recovery')
    except (ValueError, KeyError, TypeError, InvalidTag):
        raise VaultError('that is not the recovery share this vault was given') from None


def marker(share: bytes, held: dict) -> str:
    """vault_meta.second_lock for a vault locked to this share."""
    return json.dumps({'v': 1, 'kind': 'file', 'share': share_id(share), 'recovery': held}, sort_keys=True, separators=(',', ':'))


def tpm() -> str:
    """What this build does with a TPM, in words for `vault second-lock status`."""
    tools = shutil.which('tpm2_create') or shutil.which('tpm2')
    return ('not used. Sealing the host share to a TPM is not built: the share is a file only its owner can read'
            + ('' if tools else ' (and tpm2-tools are not installed here)'))
