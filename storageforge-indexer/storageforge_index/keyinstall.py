"""Install a vault public key on a host with ssh-copy-id, using the host's password once.

Only the public key is written to a file. The password travels to ssh through the askpass helper's environment, never
argv or disk, and ssh tries it exactly once. Host keys are trusted on first use into the vault's known_hosts, the same
file scans use, so a later scan fails if the host key changes.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from . import hostid
from .remote import RemoteError, Transport
from .runner import ephemeral_agent, known_hosts_path, runtime_dir
from .vault import Vault, VaultError

TIMEOUT = 60
HOST = hostid.HOST_RE
USER = re.compile(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,31}')


class InstallError(RuntimeError):
    pass


def askpass_path() -> str:
    path = shutil.which('storageforge-askpass')
    if not path:
        raise InstallError('storageforge-askpass is not on PATH; install the package (pip install .)')
    return path


def validate(host: str, user: str, port: int) -> None:
    if not HOST.fullmatch(host) or host.startswith('-'):
        raise ValueError('host must be a hostname or IP address')
    if not USER.fullmatch(user):
        raise ValueError('user must be a plain login name')
    if not 1 <= port <= 65535:
        raise ValueError('port must be between 1 and 65535')


def key_login_works(db, conn, key_name: str, host: str, user: str, port: int = 22) -> bool:
    """Try a key-only login through an ephemeral agent, the same way scans connect, but only to a host key that is
    already in known_hosts (confirmed by a person, or pinned by a scan)."""
    validate(host, user, port)
    with Vault(db, conn).unlock() as v:
        key_id = conn.scalar('SELECT key_id FROM ssh_keys WHERE name = :n', {'n': key_name})
        if key_id is None:
            raise VaultError(f'No key named {key_name}')
        with ephemeral_agent(v.decrypt_key(key_id, 'access'), ttl=60) as sock:
            t = Transport(host=host, user=user, port=port, agent_sock=sock, known_hosts=str(known_hosts_path()),
                          isolated=True, connect_timeout=10, strict=True)   # a probe never pins a host key
            try:
                return t.run('true', timeout=30) is not None
            except (RemoteError, subprocess.TimeoutExpired):
                return False
            finally:
                t.close()


FROM_ENV = 'STORAGEFORGE_SSH_FROM'       # the addresses or networks the controller logs in from, as hosts see them: from= on every key line


def restricted_line(public_line: str) -> str:
    """The authorized_keys line for a vault key: `restrict` (no port, agent or X11 forwarding, no ~/.ssh/rc) and `pty` back on for
    the console; `from=` when STORAGEFORGE_SSH_FROM names where the controller comes from. A command can still be run: scans are
    commands. Options already on the line are kept off: this is the line as StorageForge means it."""
    import ipaddress
    parts = public_line.strip().split()
    i = next((n for n, p in enumerate(parts) if p.startswith(('ssh-', 'ecdsa-', 'sk-'))), None)
    if i is None or len(parts) < i + 2:
        raise ValueError('not an OpenSSH public key line')
    opts = ['restrict', 'pty']
    nets = []
    for item in (os.environ.get(FROM_ENV) or '').replace(' ', ',').split(','):
        if item:
            try:
                nets.append(str(ipaddress.ip_network(item, strict=False)))
            except ValueError:
                raise ValueError(f'{FROM_ENV}: {item[:60]} is not an address or network') from None
    if nets:
        opts.append(f'from="{",".join(nets)}"')
    return ' '.join([','.join(opts), *parts[i:]])


def install_public_key(public_line: str, host: str, user: str, password: str, port: int = 22) -> dict:
    validate(host, user, port)
    if not password:
        raise ValueError('the host password is required to install the key')
    if not shutil.which('ssh-copy-id'):
        raise InstallError('ssh-copy-id is not installed (package openssh-client)')
    work = Path(tempfile.mkdtemp(prefix='copy-id-', dir=runtime_dir()))
    try:
        pub = work / 'key.pub'
        pub.write_text(restricted_line(public_line) + '\n')   # ssh-copy-id -f appends the file as it is, options and all
        (work / '.ssh').mkdir(mode=0o700)       # ssh-copy-id makes its scratch dir under ~/.ssh; HOME is this dir
        argv = ['ssh-copy-id', '-f', '-i', str(pub), '-p', str(port),
                '-o', 'StrictHostKeyChecking=yes',      # the caller made sure a person confirmed this key
                '-o', f'UserKnownHostsFile={known_hosts_path()}', '-o', 'GlobalKnownHostsFile=/dev/null',
                '-o', 'PreferredAuthentications=password,keyboard-interactive', '-o', 'PubkeyAuthentication=no',
                '-o', 'NumberOfPasswordPrompts=1', '-o', 'ConnectTimeout=10',
                f'{user}@{host}']
        env = {'PATH': os.environ.get('PATH', '/usr/bin:/bin'), 'HOME': str(work),
               'SSH_ASKPASS': askpass_path(), 'SSH_ASKPASS_REQUIRE': 'force', 'DISPLAY': 'none',
               'STORAGEFORGE_ASKPASS_SECRET': password}
        try:   # no stdin and a new session (no controlling tty), so ssh can only ask the askpass helper
            p = subprocess.run(argv, env=env, stdin=subprocess.DEVNULL, capture_output=True, text=True,
                               timeout=TIMEOUT, start_new_session=True)
        except subprocess.TimeoutExpired:
            raise InstallError(f'ssh-copy-id timed out after {TIMEOUT}s') from None
    finally:
        shutil.rmtree(work, ignore_errors=True)
    out = (p.stdout + p.stderr).strip()
    if p.returncode != 0:
        lines = [re.sub(r'^\S*ssh-copy-id: (ERROR: )?', '', l) for l in out.splitlines()
                 if l.strip() and not re.match(r'^\S*ssh-copy-id: INFO', l)]
        reason = next((l for l in reversed(lines) if 'denied' in l.lower() or 'error' in l.lower()), lines[-1] if lines else '')
        if 'timed out' in reason.lower():
            reason += (' · nothing answered on that port. If this is the machine running StorageForge, its firewall is'
                       ' probably dropping connections from the Docker network (with ufw: sudo ufw allow in on br-sforge to'
                       ' any port 22 proto tcp); otherwise check sshd, the address and any VPN routes.')
        raise InstallError(f'ssh-copy-id failed (exit {p.returncode}): {reason}')
    added = re.search(r'Number of key\(s\) added:\s*(\d+)', out)
    return {'host': host, 'user': user, 'port': port, 'keys_added': int(added.group(1)) if added else None}
