"""Vault-backed task runner: one ephemeral ssh-agent per task, an audit entry per step.

    vault.decrypt_key ──► SecretBuffer (mlocked) ──stdin──► ssh-add - ──► ssh-agent -D -a <tmpfs>/agent-XXXX/agent.sock
                          wiped right after                              lifetime-limited, killed and removed after the task
    ssh -o IdentityAgent=<sock> -o IdentitiesOnly=no ...

The private key never touches a filesystem. The agent socket lives in a 0700 directory
on the runtime tmpfs (/run/storageforge in the container) and is deleted with it.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import time
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path

from . import errlog
from .db import Database
from .remote import Transport, child_env
from .scanner import ScanOptions, scan_host
from .vault import AuditLog, NoBinding, SecretBuffer, Vault, VaultError, actor_name

AGENT_TTL = 3600


def data_dir() -> Path:
    return Path(os.environ.get('STORAGEFORGE_DATA_DIR', '~/.local/share/storageforge')).expanduser()


def known_hosts_path() -> Path:
    p = data_dir() / 'ssh' / 'known_hosts'
    p.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    p.touch(mode=0o600, exist_ok=True)
    return p


def runtime_dir() -> Path:
    for cand in (os.environ.get('STORAGEFORGE_RUNTIME_DIR'), '/run/storageforge', os.environ.get('XDG_RUNTIME_DIR')):
        if cand and os.path.isdir(cand) and os.access(cand, os.W_OK):
            return Path(cand)
    return Path(tempfile.gettempdir())


def is_memory_backed(path: Path) -> bool:
    try:
        best, fstype = '', ''
        for line in Path('/proc/self/mounts').read_text().splitlines():
            _, target, fs, *_ = line.split()
            if str(path).startswith(target) and len(target) > len(best):
                best, fstype = target, fs
        return fstype in ('tmpfs', 'ramfs')
    except OSError:
        return False


@contextmanager
def ephemeral_agent(key: SecretBuffer, ttl: int = AGENT_TTL):
    """Start a private ssh-agent, load the key from memory, yield its socket, then tear it all down."""
    base = runtime_dir()
    if not is_memory_backed(base):
        errlog.say(f'warning: {base} is not tmpfs; the agent socket (never the key) is on disk')
    d = Path(tempfile.mkdtemp(prefix='agent-', dir=base))
    os.chmod(d, 0o700)
    sock = d / 'agent.sock'
    agent = subprocess.Popen(['ssh-agent', '-D', '-a', str(sock)], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                             env=child_env())
    try:
        for _ in range(100):
            if sock.exists():
                break
            if agent.poll() is not None:
                raise VaultError(f'ssh-agent failed: {agent.stderr.read().decode(errors="replace").strip()}')
            time.sleep(0.02)
        else:
            raise VaultError('ssh-agent did not create its socket')
        env = {'PATH': os.environ.get('PATH', '/usr/bin:/bin'), 'SSH_AUTH_SOCK': str(sock)}
        add = subprocess.Popen(['ssh-add', '-q', '-t', str(ttl), '-'], stdin=subprocess.PIPE,
                               stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env=env)
        try:
            view = key.view()
            while view:                                   # write from the locked buffer, no bytes() copy
                n = os.write(add.stdin.fileno(), view)
                view = view[n:]
        finally:
            key.wipe()
            add.stdin.close()
        if add.wait(10) != 0:
            raise VaultError(f'ssh-add rejected the key: {add.stderr.read().decode(errors="replace").strip()}')
        add.stderr.close()
        yield str(sock)
    finally:
        key.wipe()
        agent.terminate()
        try:
            agent.wait(5)
        except subprocess.TimeoutExpired:
            agent.kill()
        agent.stderr.close()
        shutil.rmtree(d, ignore_errors=True)


def connect_address(conn, host: str) -> str:
    """The address an indexed host was scanned at. After the first scan a host is known by its own hostname
    (cachyos-x8664), which the container often cannot resolve and which the key binding (10.42.0.100) never named."""
    row = conn.all('SELECT ssh_host FROM hosts WHERE lower(hostname) = lower(:h) AND ssh_host IS NOT NULL', {'h': host})
    return row[0][0] if row else host


def checksum_catchup(db: Database, host_id: int, hostname: str, opts: ScanOptions, actor: str, log) -> dict:
    """A checksum pass hashes files whose size another file has at that moment. A file copied to this host after the other
    host's pass got hashed here, and its twin there never was, so the copy across hosts never showed (bug report
    2026-11-10). After this host's pass: on every other host with files of a size hashed here, hash just those files,
    through a binding that allows checksums. A host with no such binding, or being scanned, waits for its own next pass."""
    from .scanner import checksum_pass
    from .scansign import for_scan
    conn = db.connect()
    done: dict[str, int | str] = {}
    try:
        busy = {r[0] for r in conn.all("SELECT host_id FROM scans WHERE status = 'running'")}
        for other_id, other in db.checksum_catchup_hosts(conn, host_id, opts.checksum_min_size):
            if other_id in busy:
                done[other] = 'being scanned'
                continue
            address = connect_address(conn, other)
            with Vault(db, conn).unlock() as vault:
                try:
                    b = vault.resolve(address, 'checksum')
                except NoBinding:
                    done[other] = 'no binding allows checksums'
                    log(f'  {other} may hold copies of files hashed on {hostname}, but no binding there allows checksums '
                        '(Keys → Bindings: Checksums on)')
                    continue
                audit = AuditLog(db, conn, vault.audit_key)
                t = None
                try:
                    with ephemeral_agent(vault.decrypt_key(b.key_id)) as sock:
                        t = Transport(host=address, user=b.user, port=b.port, agent_sock=sock,
                                      known_hosts=str(known_hosts_path()), isolated=True)
                        t.signing = for_scan(conn, address, b.port, str(known_hosts_path()))
                        n = checksum_pass(db, conn, t, other_id, opts.checksum_min_size, opts.nice, like_host=host_id)
                except Exception as exc:
                    done[other] = f'failed: {str(exc)[:200]}'
                    audit.append(actor, 'ssh.checksum.catchup', 'failed', address, b.fingerprint, {'after': hostname, 'error': str(exc)[:500]})
                    log(f'  checksum catch-up on {other} failed: {exc}')
                    continue
                finally:
                    if t:
                        t.close()
                done[other] = n
                audit.append(actor, 'ssh.checksum.catchup', 'ok', address, b.fingerprint, {'after': hostname, 'hashed': n})
                log(f'  hashed {n:,} file(s) on {other} the size of files hashed here: copies across hosts show now')
        if any(isinstance(v, int) and v for v in done.values()):
            from .graph import rebuild_host
            for other, v in done.items():
                if isinstance(v, int) and v:
                    rebuild_host(db, conn, other)
        return done
    finally:
        conn.close()


def scan_via_vault(db: Database, host: str, opts: ScanOptions, actor: str | None = None, log=None,
                   rebuild_graph: bool = True) -> dict | None:
    """Resolve the host's key binding, scan through an ephemeral agent and audit every step."""
    actor = actor or actor_name()
    conn = db.connect()
    try:
        if conn.scalar('SELECT count(*) FROM network_devices WHERE lower(name) = lower(:h) OR address = :h', {'h': host}):
            raise ValueError(f'{host} is a network device: it has no filesystem to scan. Read it from the management planner')
        host = connect_address(conn, host)
        with Vault(db, conn).unlock() as vault:
            audit = AuditLog(db, conn, vault.audit_key)
            if opts.checksum is None:                    # checksums when the binding allows them (Keys → Bindings), else a plain scan
                try:
                    vault.resolve(host, 'checksum')
                    opts = replace(opts, checksum=True)
                except NoBinding:
                    opts = replace(opts, checksum=False)
            action = 'checksum' if opts.checksum else 'scan'
            try:
                b = vault.resolve(host, action)
            except NoBinding as exc:
                audit.append(actor, f'ssh.{action}', 'denied', host, None, {'reason': str(exc)})
                raise
            audit.append(actor, 'ssh.connect', 'info', host, b.fingerprint,
                         {'user': b.user, 'port': b.port, 'binding': b.pattern, 'key': b.key_name})
            started = time.time()
            t = None
            try:
                with ephemeral_agent(vault.decrypt_key(b.key_id)) as sock:
                    t = Transport(host=host, user=b.user, port=b.port, agent_sock=sock,
                                  known_hosts=str(known_hosts_path()), isolated=True)
                    from .scansign import for_scan
                    t.signing = for_scan(conn, host, b.port, str(known_hosts_path()))      # every payload signed on the host, checked here
                    kw = {'log': log} if log else {}
                    result = scan_host(db, t, opts, **kw)
            except Exception as exc:
                audit.append(actor, f'ssh.{action}', 'failed', host, b.fingerprint,
                             {'error': str(exc)[:500], 'seconds': round(time.time() - started, 1)})
                raise
            finally:
                if t:
                    t.close()
            if result is not None:
                audit.append(actor, f'ssh.{action}', 'ok' if result['status'] == 'ok' else 'failed', host, b.fingerprint,
                             {k: result[k] for k in ('scan_id', 'status', 'entries', 'added', 'modified', 'deleted',
                                                    'read_errors', 'failed')} | {'seconds': round(time.time() - started, 1)})
                if rebuild_graph:
                    from .graph import rebuild_host
                    rebuild_host(db, conn, result['host'])
        if result is not None and result.get('checksummed') and result['status'] != 'failed':
            try:
                checksum_catchup(db, result['host_id'], result['host'], opts, actor, log or errlog.say)
            except Exception as exc:                    # never fail a finished scan over the catch-up
                (log or errlog.say)(f'  checksum catch-up: {exc}')
        return result
    finally:
        conn.close()
