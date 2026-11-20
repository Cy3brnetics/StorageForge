"""Unlocking the key enclave: the starter, and a person typing the secret (roadmap section 14, "Unlock").

The vault secret is needed by one thing, the enclave, at one moment, its unlock. Three ways it gets there, and none of them leaves
it in the web app:

    the starter, apart      `storageforge-index vault starter`: a process of its own that reads the secret file, hands the secret
                            to the enclave the server runs, and ends (or, with --watch, stays, holding nothing, and reads the file
                            again only when the enclave has come back locked after a restart). The web app is then run without
                            the secret in its environment and without the file in its container: docker-compose.enclave.yml.
    the starter, in place   a server that does find the secret in its own environment does the same thing once as it starts, then
                            overwrites the variable where it lies in the process's memory and takes both variables out of its
                            environment. Python cannot promise no copy of the bytes is left on its heap, and a file the server's
                            account can read is still a file it can read: the starter apart is the one that closes that.
    a person                types the secret on the Keys page (POST /api/enclave/unlock). It crosses the web app once, on its way in.

An enclave that locked itself down after malformed requests is never unlocked by a starter: a person looks first.
"""
from __future__ import annotations

import ctypes
import os
import time
from pathlib import Path

from . import enclave, vault

ADDRESS_FILE_ENV = 'STORAGEFORGE_ENCLAVE_ADDRESS_FILE'
SECRET_ENVS = ('STORAGEFORGE_VAULT_SECRET', 'STORAGEFORGE_VAULT_SECRET_FILE')


def address_file() -> Path:
    return Path(os.environ.get(ADDRESS_FILE_ENV) or enclave.run_dir() / 'enclave.addr')


def publish(address: str) -> None:
    """Where the server's enclave is, for a starter beside it: one line in the runtime folder, which only this account can read."""
    path = address_file()
    part = path.with_name(path.name + '.part')
    fd = os.open(part, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as f:
        f.write(address + '\n')
    os.replace(part, path)


def published() -> str | None:
    try:
        line = address_file().read_text().strip()
    except OSError:
        return None
    return line or None


def scrub_env(name: str) -> None:
    """Take a variable out of this process's environment, and overwrite its value where it lies. Taking it out alone leaves the
    bytes in the block /proc/PID/environ shows."""
    if name not in os.environ:
        return
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        libc.getenv.restype = ctypes.c_void_p
        libc.getenv.argtypes = [ctypes.c_char_p]
        at = libc.getenv(name.encode())
        if at:
            ctypes.memset(at, 0x20, len(os.environb.get(name.encode(), b'')))
    except (OSError, AttributeError, ValueError):
        pass
    os.environ.pop(name, None)


def take_secret(forget: bool = True) -> bytearray | None:
    """The vault secret, read once, as bytes that can be overwritten: from the variable, else from the file it names. None where
    this process was given neither. forget: both variables leave the environment, so nothing later in this process reads it again."""
    out = None
    text = os.environ.get(SECRET_ENVS[0])
    path = os.environ.get(SECRET_ENVS[1])
    if text:
        out = bytearray(text.strip().encode())
    elif path:
        try:
            fd = os.open(path, os.O_RDONLY)
        except OSError as exc:
            raise vault.VaultLocked(f'the vault secret file {path} cannot be read: {exc.strerror}') from None
        try:
            raw = bytearray(8192)
            n = os.readv(fd, [raw])
        finally:
            os.close(fd)
        out = bytearray(bytes(raw[:n]).strip())          # bytes() here is one more copy; it is dropped at once and Python gives no better
        vault.wipe(raw)
    del text
    if forget:
        for name in SECRET_ENVS:
            scrub_env(name)
    if out is None:
        return None
    if len(out) < vault.MIN_SECRET_LEN:
        vault.wipe(out)
        raise vault.VaultError(f'The vault secret must be at least {vault.MIN_SECRET_LEN} characters. Generate one with: openssl rand -base64 48')
    return out


def state_of(address: str) -> str:
    """locked, unlocked, lockdown, or down."""
    try:
        with enclave.Enclave(address, timeout=5) as e:
            return str(e.status().get('state'))
    except enclave.EnclaveError:
        return 'down'


def hand_over(db, conn, secret: bytearray, address: str) -> str:
    """The secret to the enclave, and then it is overwritten here whatever happened. Returns the enclave's state afterwards. The
    vault is made first where the database has none: only whoever holds the secret can."""
    try:
        state = state_of(address)
        if state == 'lockdown':
            raise vault.VaultLocked('the key enclave has locked itself down after requests no honest client sends: a person unlocks it, after finding what sent them')
        if state == 'down':
            raise vault.VaultLocked(f'the key enclave does not answer at {address}')
        if not vault.Vault(db, conn).initialized:
            with vault.Vault(db, conn, bytes(secret)) as v:
                v.init()
        if state != 'unlocked':
            vault.Vault(db, conn).unlock_enclave(secret, address).close()
        return state_of(address)
    finally:
        vault.wipe(secret)


_file_was: str | None = None


def after_restart(db, address: str) -> str | None:
    """The server's enclave came back after stopping, and holds nothing. Where the secret came from a file this account can
    read, it is read once more and handed over; a secret that came in a variable is gone, and a starter or a person unlocks."""
    publish(address)
    if not _file_was:
        return None
    os.environ[SECRET_ENVS[1]] = _file_was
    try:
        secret = take_secret()
    except vault.VaultError:
        return None
    if secret is None:
        return None
    conn = db.connect()
    try:
        return hand_over(db, conn, secret, address)
    except vault.VaultError:
        return None
    finally:
        conn.close()


def at_server_start(db) -> str | None:
    """Called once by `serve`, after the enclave is up and before anything opens the vault. With the secret in this process's
    environment it is handed over and forgotten here. Without it the enclave stays locked until the starter or a person comes:
    the server starts all the same, and says so. None where there is no enclave: nothing changes for that installation."""
    address = os.environ.get(enclave.ADDRESS_ENV) or None
    if not address or address.startswith('vm'):
        return None
    global _file_was
    publish(address)
    _file_was = None if os.environ.get(SECRET_ENVS[0]) else os.environ.get(SECRET_ENVS[1]) or None
    secret = take_secret()
    if secret is None:
        return 'locked'
    conn = db.connect()
    try:
        return hand_over(db, conn, secret, address)
    finally:
        conn.close()


def typed(db, conn, text: str) -> str:
    """A person typed the secret. It is checked nowhere but inside the enclave. This is also the one way out of a lock-down."""
    try:
        address = enclave.configured()
    except enclave.EnclaveError as exc:
        raise vault.VaultLocked(str(exc)) from None
    if not address:
        raise vault.VaultError('this installation has no key enclave: the vault is unlocked from STORAGEFORGE_VAULT_SECRET')
    secret = bytearray(text.strip().encode())
    del text
    try:
        if len(secret) < vault.MIN_SECRET_LEN:
            raise vault.VaultError(f'the vault secret is at least {vault.MIN_SECRET_LEN} characters')
        if state_of(address) == 'unlocked':
            return 'unlocked'
        vault.Vault(db, conn).unlock_enclave(secret, address).close()
        return state_of(address)
    finally:
        vault.wipe(secret)


def starter(db, address: str | None = None, wait: float = 60.0, watch: bool = False, say=print, pause: float = 5.0, rounds: int | None = None) -> int:
    """`vault starter`. Finds the enclave (the address given, or the one the server published), hands it the secret, and ends
    with 0 once it is unlocked. watch: stays, and does it again whenever the enclave is found locked, reading the secret file
    again each time and keeping nothing between. rounds: how many looks a watch takes, for the tests; None is until stopped."""
    until = time.time() + wait
    looked = 0
    while True:
        looked += 1
        where = address or published()
        state = state_of(where) if where else 'down'
        if state == 'locked':
            try:
                secret = take_secret(forget=False)          # the file is read again at the next restart: this process keeps nothing
            except vault.VaultError as exc:
                say(f'starter: {exc}')
                return 1
            if secret is None:
                say('starter: no vault secret here: set STORAGEFORGE_VAULT_SECRET_FILE')
                return 2
            conn = db.connect()
            try:
                state = hand_over(db, conn, secret, where)
            except vault.VaultError as exc:
                say(f'starter: {exc}')
                return 1
            finally:
                conn.close()
            say(f'starter: the key enclave is {state}')
        elif state == 'lockdown':
            say('starter: the key enclave has locked itself down: a person unlocks it (Keys → Key enclave), after finding what sent the bad requests')
            if not watch:
                return 1
        if state == 'unlocked' and not watch:
            return 0
        if not watch and time.time() > until:
            say(f'starter: no key enclave answered within {int(wait)} seconds' + (f' at {where}' if where else ': the server has not published its address'))
            return 1
        if rounds is not None and looked >= rounds:
            return 0 if state == 'unlocked' else 1
        time.sleep(pause if state in ('unlocked', 'lockdown') else min(pause, 0.5))
