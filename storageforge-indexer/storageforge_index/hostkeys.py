"""Host keys confirmed by a person before a password is sent.

Scans trust a host key on first use: the worst a wrong first answer gets is a scan of the wrong machine, which host
pinning (db.upsert_host) then keeps from taking over anything. A password is different: whoever receives it has the
account. So key install, scan access and deploy access refuse until someone has compared the host's key fingerprint
with the one the host itself shows (ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub) and confirmed it here; the
password then goes over a connection that accepts only that key (StrictHostKeyChecking=yes).
"""
from __future__ import annotations

import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from .db import Conn
from .keyinstall import HOST
from .remote import child_env, key_fingerprint, known_host_keys, known_hosts_name
from .runner import known_hosts_path, runtime_dir

TIMEOUT = 15


class HostKeyNeeded(Exception):
    """A password would go to host:port, whose key nobody has confirmed. keys: what to show the person."""

    def __init__(self, host: str, port: int, keys: list[dict], pinned: bool):
        super().__init__(f'confirm the SSH host key of {host} before a password is sent to it')
        self.host, self.port, self.keys, self.pinned = host, port, keys, pinned

    def as_dict(self) -> dict:
        return {'host': self.host, 'port': self.port, 'keys': self.keys, 'pinned': self.pinned}


def _check(host: str, port: int):
    if not HOST.fullmatch(host) or host.startswith('-') or not 1 <= int(port) <= 65535:
        raise ValueError('host must be a hostname or IP address and port 1-65535')


def offered(host: str, port: int = 22) -> list[dict]:
    """The host key the server presents, fetched without trusting or authenticating (nothing is sent but the key
    exchange). [{'type', 'fingerprint', 'line'}]; line is its known_hosts line."""
    _check(host, port)
    work = Path(tempfile.mkdtemp(prefix='hostkey-', dir=runtime_dir()))
    try:
        kh = work / 'known_hosts'
        argv = ['ssh', '-F', '/dev/null', '-T', '-p', str(port), '-o', 'StrictHostKeyChecking=no',
                '-o', f'UserKnownHostsFile={kh}', '-o', 'GlobalKnownHostsFile=/dev/null', '-o', 'BatchMode=yes',
                '-o', 'PubkeyAuthentication=no', '-o', 'PasswordAuthentication=no', '-o', 'KbdInteractiveAuthentication=no',
                '-o', 'ConnectTimeout=10', f'storageforge-hostkey@{host.strip("[]")}', 'true']
        try:
            subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, timeout=TIMEOUT, env=child_env())
        except subprocess.TimeoutExpired:
            raise ValueError(f'{host}:{port} did not answer') from None
        out = []
        for line in (kh.read_text().splitlines() if kh.exists() else []):
            parts = line.split()
            if len(parts) >= 3 and (fp := key_fingerprint(parts[2])):
                out.append({'type': parts[1], 'fingerprint': fp, 'line': line})
        if not out:
            raise ValueError(f'no SSH server answered at {host}:{port}')
        return out
    finally:
        shutil.rmtree(work, ignore_errors=True)


def _confirmed(conn: Conn, host: str, port: int) -> set[str]:
    return {r[0] for r in conn.all('SELECT fingerprint FROM host_key_confirmations WHERE address = :a AND port = :p',
                                   {'a': host, 'p': port})}


def require_confirmed(conn: Conn, host: str, port: int = 22) -> None:
    """Raises HostKeyNeeded unless the key StorageForge holds for host:port was confirmed by a person."""
    pinned = known_host_keys(host, port, str(known_hosts_path()))
    if pinned and set(pinned) & _confirmed(conn, host, port):
        return
    if pinned:   # pinned by a scan (trust on first use): show that key, it is the one the password would go to
        raise HostKeyNeeded(host, port, [{'type': '', 'fingerprint': fp} for fp in pinned], True)
    raise HostKeyNeeded(host, port, [{k: x[k] for k in ('type', 'fingerprint')} for x in offered(host, port)], False)


def confirm(conn: Conn, host: str, port: int, fingerprint: str, actor: str) -> dict:
    """A person compared fingerprint with the host's own: pin it (if it is not pinned yet) and remember the check."""
    _check(host, port)
    kh = known_hosts_path()
    pinned = known_host_keys(host, port, str(kh))
    if pinned:
        if fingerprint not in pinned:
            raise ValueError(f'{fingerprint} is not the key StorageForge holds for {host}. If the host was reinstalled, '
                             f'run: storageforge-index hosts rekey <name>, then scan it')
    else:
        match = [k for k in offered(host, port) if k['fingerprint'] == fingerprint]
        if not match:
            raise ValueError(f'{host}:{port} now presents a different key than the one you confirmed: nothing was pinned')
        with kh.open('a') as f:
            f.write(match[0]['line'].strip() + '\n')
    conn.execute('DELETE FROM host_key_confirmations WHERE address = :a AND port = :p AND fingerprint = :f',
                 {'a': host, 'p': port, 'f': fingerprint})
    conn.execute("""INSERT INTO host_key_confirmations (address, port, fingerprint, confirmed_by, confirmed_at)
                    VALUES (:a, :p, :f, :b, :t)""", {'a': host, 'p': port, 'f': fingerprint, 'b': actor, 't': int(time.time())})
    return {'host': host, 'port': port, 'fingerprint': fingerprint, 'known_hosts': known_hosts_name(host, port)}
