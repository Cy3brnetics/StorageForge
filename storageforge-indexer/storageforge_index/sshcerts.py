"""The SSH certificate authority as StorageForge runs it (roadmap section 2, "SSH CA"). sshca.py builds a certificate; this keeps the CA,
says who gets one, and remembers each one so it can be revoked.

    the CA          a vault key like any other (`storageforge-ssh-ca`, ed25519, made in the vault and never imported). With the key
                    enclave it is made inside and signs inside: this process never holds it. Without one it is decrypted for the
                    length of one signature, as the signing key of deploys is.
    a host trusts   through the `ssh-ca-trust` plan step (steps_sshca.py), which leaves authorized_keys as it is.
    a login         for a host that was opted in (`ssh_ca_hosts`), the console and scans get a certificate for the key the binding
                    already names: minutes long, for one principal, `<user>@<host>`, so it logs in as that user on that host and
                    nowhere else. ssh offers the certificate first and the plain key after it, so opting a host in before it trusts
                    the CA breaks nothing.
    revoking        marks the row. The list of revoked serial numbers (sshca.krl) reaches hosts through the `ssh-ca-krl` step.

A user certificate is not kept: it is written to a file for ssh to read and removed when ssh has started. Its row is.
"""
from __future__ import annotations

import contextlib
import os
import re
import secrets
import tempfile
import time

from . import sshca
from .sshwire import put
from .db import Conn

CA_KEY = 'storageforge-ssh-ca'
CONSOLE_SECONDS = 5 * 60            # only the login has to fall inside it: an open session is not cut when it ends
SCAN_SECONDS = 60 * 60              # a scan keeps one connection, and opens another if that one drops
HOST_SECONDS = 90 * 24 * 3600
HOST_RENEW_SECONDS = 14 * 24 * 3600
PURPOSES = ('console', 'scan')
LOGIN_SECONDS = {'console': CONSOLE_SECONDS, 'scan': SCAN_SECONDS, 'user': 24 * 3600}
KRL_VERSION_KEY = 'sshca.krl_version'
KEEP_SECONDS = 90 * 24 * 3600       # how long the row of an ended certificate is kept
MAX_LISTED = 8000                   # revoked certificates that have not ended. The list reaches a host as one word of a script, which the kernel caps at 128 KiB
HOST_NAME = re.compile(r'[A-Za-z0-9]([A-Za-z0-9_.-]{0,253}[A-Za-z0-9])?')
USER_NAME = re.compile(r'[A-Za-z_][A-Za-z0-9_.-]{0,31}')


class CAError(ValueError):
    pass


# ── the CA ──────────────────────────────────────────────────────────
def ca_public(conn: Conn) -> str | None:
    """The CA's public key, `type base64` and nothing after it. None where no CA was made."""
    line = conn.scalar('SELECT public_key FROM ssh_keys WHERE name = :n AND disabled_at IS NULL', {'n': CA_KEY})
    return sshca.trusted_user_ca_line(line) if line else None


def ensure_ca(vault) -> dict:
    """Make the CA if there is none. Returns {'public_key', 'fingerprint', 'made'}."""
    from .vault import fingerprint
    have = ca_public(vault.conn)
    if have:
        return {'public_key': have, 'fingerprint': fingerprint(have), 'made': False}
    made = vault.generate_key(CA_KEY, 'ed25519', comment='storageforge:ssh-ca')
    return {'public_key': sshca.trusted_user_ca_line(made['public_key']), 'fingerprint': made['fingerprint'], 'made': True}


def signer(vault):
    """sign(data) -> an SSH signature blob made with the CA key, for sshca.issue. With the enclave the key signs inside it."""
    from cryptography.hazmat.primitives import serialization
    from .vault import EnclaveKey
    kid = vault.conn.scalar('SELECT key_id FROM ssh_keys WHERE name = :n AND disabled_at IS NULL', {'n': CA_KEY})
    if kid is None:
        raise CAError('there is no SSH CA yet: make it under Keys')
    if vault.conn.scalar('SELECT key_type FROM ssh_keys WHERE key_id = :k', {'k': kid}) != 'ssh-ed25519':
        raise CAError('the SSH CA is an ed25519 key made in the vault')

    def sign(data: bytes) -> bytes:
        key = vault.decrypt_key(kid)
        if isinstance(key, EnclaveKey):
            return put(b'ssh-ed25519') + put(key.sign(data))
        try:
            return put(b'ssh-ed25519') + put(serialization.load_ssh_private_key(bytes(key.view()), None).sign(data))
        finally:
            key.wipe()
    return sign


# ── which hosts, and for what ───────────────────────────────────────
def principal(user: str, host: str) -> str:
    """The one principal a login certificate carries: this user on this host. The trust step writes the same line on the host."""
    if not USER_NAME.fullmatch(user or '') or not HOST_NAME.fullmatch(host or ''):
        raise CAError(f'{user}@{host} is not a user on a host')
    return f'{user}@{host}'


def _known_host(conn: Conn, host) -> str:
    from .deploy import canonical
    name = canonical(conn, str(host or '').strip())
    if not conn.scalar('SELECT 1 FROM hosts WHERE hostname = :h', {'h': name}):
        raise LookupError(f'no host named {host!r}')
    return name


def host_setting(conn: Conn, host: str) -> dict:
    rows = conn.all('SELECT console, scan, updated_at, updated_by FROM ssh_ca_hosts WHERE host = :h', {'h': host})
    return {'host': host, 'console': bool(rows[0][0]), 'scan': bool(rows[0][1]), 'updated_at': rows[0][2], 'updated_by': rows[0][3]} if rows else \
        {'host': host, 'console': False, 'scan': False, 'updated_at': None, 'updated_by': None}


def set_host(conn: Conn, host, body: dict, actor: str) -> dict:
    """Opt a host in or out: {'console': bool, 'scan': bool}. Both false removes the row."""
    name = _known_host(conn, host)
    want = {p: body.get(p) for p in PURPOSES}
    if not all(isinstance(v, bool) for v in want.values()):
        raise CAError('console and scan are true or false')
    with conn.tx():
        conn.execute('DELETE FROM ssh_ca_hosts WHERE host = :h', {'h': name})
        if any(want.values()):
            conn.execute('INSERT INTO ssh_ca_hosts (host, console, scan, updated_at, updated_by) VALUES (:h, :c, :s, :t, :a)',
                         {'h': name, 'c': int(want['console']), 's': int(want['scan']), 't': int(time.time()), 'a': actor})
    return host_setting(conn, name)


def wanted(conn: Conn, host: str, purpose: str) -> str | None:
    """The host's own name when it was opted in for this purpose and there is a CA, None otherwise. host: a name or the address it is scanned at."""
    if purpose not in PURPOSES:
        return None
    from .deploy import canonical
    name = canonical(conn, host)
    column = 'console' if purpose == 'console' else 'scan'
    if not conn.scalar(f'SELECT {column} FROM ssh_ca_hosts WHERE host = :h', {'h': name}):
        return None
    return name if ca_public(conn) else None


# ── issuing ─────────────────────────────────────────────────────────
def _record(conn: Conn, kind: str, purpose: str, host: str, key_id: str, principals: list[str], subject: str, seconds: int, actor: str, issue) -> tuple[int, str]:
    """A serial of its own, and the certificate is handed on only once its row is written: one that exists can be revoked."""
    from .vault import fingerprint
    now = int(time.time())
    conn.execute('DELETE FROM ssh_certificates WHERE expires_at < :t', {'t': now - KEEP_SECONDS})
    for _ in range(5):
        serial = secrets.randbits(62) + 1
        if not conn.scalar('SELECT 1 FROM ssh_certificates WHERE serial = :s', {'s': serial}):
            break
    line = issue(serial, now)
    conn.execute("""INSERT INTO ssh_certificates (serial, kind, purpose, host, key_id, principals, subject_fp, issued_at, expires_at, issued_by, certificate)
                    VALUES (:s, :k, :p, :h, :i, :pr, :f, :t, :e, :a, :c)""",
                 {'s': serial, 'k': kind, 'p': purpose, 'h': host, 'i': key_id, 'pr': ','.join(principals), 'f': fingerprint(subject), 't': now, 'e': now + seconds,
                  'a': actor, 'c': line if kind == 'host' else None})
    return serial, line


def issue_user(vault, *, host: str, user: str, key_name: str, purpose: str, actor: str, source_addresses: list[str] | None = None) -> dict:
    """A certificate for the vault key key_name to log in as user on host (its StorageForge name), for the console, a scan, or a person.
    Interactive sessions get a terminal. None of these certificates permits forwarding."""
    if purpose not in LOGIN_SECONDS:
        raise CAError('unknown login certificate purpose')
    conn = vault.conn
    ca = ca_public(conn)
    if not ca:
        raise CAError('there is no SSH CA yet: make it under Keys')
    subject = vault.public_key(key_name)
    who = principal(user, host)
    seconds = LOGIN_SECONDS[purpose]
    key_id = f'storageforge {purpose} {host} {actor}'[:200]
    key_id = key_id if sshca.KEY_ID.fullmatch(key_id) else f'storageforge {purpose} {host}'
    sign = signer(vault)
    serial, line = _record(conn, 'user', purpose, host, key_id, [who], subject, seconds, actor,
                           lambda serial, now: sshca.issue(subject, ca, sign, key_id=key_id, principals=[who], serial=serial, seconds=seconds, now=now,
                                                           extensions=('permit-pty',) if purpose in ('console', 'user') else (), source_addresses=source_addresses))
    return {'serial': serial, 'certificate': line, 'principal': who, 'seconds': seconds, 'key_id': key_id}


def host_public_key(address: str, port: int | None, known_hosts: str) -> str | None:
    """The host key StorageForge already holds for this address (known_hosts, pinned by a scan), ed25519 first. `type base64`."""
    from .remote import known_host_entries
    found = {}
    for kind, b64 in known_host_entries(address, port, known_hosts):
        if kind in sshca.KEY_TYPES:
            found.setdefault(kind, f'{kind} {b64}')
    return next((found[t] for t in sshca.KEY_TYPES if t in found), None)


def issue_host(vault, host, actor: str, known_hosts: str | None = None) -> dict:
    """A host certificate for the host key a scan pinned, good for its name and the address it is scanned at. It is kept, and the
    `ssh-ca-trust` step installs it where asked. Nothing here reaches the host."""
    from .runner import known_hosts_path
    conn = vault.conn
    name = _known_host(conn, host)
    ca = ca_public(conn)
    if not ca:
        raise CAError('there is no SSH CA yet: make it under Keys')
    address, port = conn.all('SELECT ssh_host, ssh_port FROM hosts WHERE hostname = :h', {'h': name})[0]
    subject = host_public_key(address or name, port or 22, known_hosts or str(known_hosts_path()))
    if not subject:
        raise CAError(f'no host key of {name} is on record yet: scan it first, so the certificate is for the key a scan confirmed')
    principals = [p for p in dict.fromkeys([name, address]) if p and sshca.PRINCIPAL.fullmatch(p)]
    sign = signer(vault)
    serial, line = _record(conn, 'host', 'host', name, name, principals, subject, HOST_SECONDS, actor,
                           lambda serial, now: sshca.issue(subject, ca, sign, key_id=name, principals=principals, serial=serial, seconds=HOST_SECONDS, kind=sshca.HOST, now=now))
    return {'serial': serial, 'host': name, 'principals': principals, 'expires_at': int(time.time()) + HOST_SECONDS, 'certificate': line}


def host_certificate(conn: Conn, host: str, now: int | None = None) -> dict | None:
    """The newest host certificate of this host that is neither revoked nor ended."""
    rows = conn.all("""SELECT serial, certificate, expires_at FROM ssh_certificates WHERE host = :h AND kind = 'host' AND revoked_at IS NULL AND expires_at > :t
                       ORDER BY issued_at DESC, serial DESC""", {'h': host, 't': int(now if now is not None else time.time())})
    return {'serial': rows[0][0], 'certificate': rows[0][1], 'expires_at': rows[0][2]} if rows else None


def login_line(vault, conn: Conn, *, address: str, user: str, key_name: str, purpose: str, actor: str, audit=None) -> str | None:
    """The certificate for this login, or None where the host was not opted in. A certificate that cannot be made is said
    (audit(outcome, detail)) and the login goes on with the key alone, which still works wherever it is authorized."""
    host = wanted(conn, address, purpose)
    if not host:
        return None
    try:
        made = issue_user(vault, host=host, user=user, key_name=key_name, purpose=purpose, actor=actor)
    except Exception as exc:          # VaultError, and the enclave through it; CAError
        if audit:
            audit('failed', {'purpose': purpose, 'user': user, 'error': str(exc)[:300]})
        return None
    if audit:
        audit('ok', {'purpose': purpose, 'serial': str(made['serial']), 'principal': made['principal'], 'seconds': made['seconds']})
    return made['certificate']


@contextlib.contextmanager
def login_options(vault, *, address: str, binding, purpose: str, actor: str, audit_log=None):
    """The ssh options for one login through a vault binding: `['CertificateFile=…']` where the host was opted in, [] otherwise.
    ssh signs with the key the agent holds, so the key stays where it is. The audit log gets a row for each certificate, made or not."""
    def said(outcome, detail):
        if audit_log is not None:
            audit_log.append(actor, 'ssh.certificate', outcome, address, binding.fingerprint, detail)
    line = login_line(vault, vault.conn, address=address, user=binding.user, key_name=binding.key_name, purpose=purpose, actor=actor, audit=said)
    with certificate_file(line) as option:
        yield [option] if option else []


@contextlib.contextmanager
def certificate_file(line: str | None):
    """Yields ssh's `CertificateFile=…` option for a certificate, None for None. The file holds no secret and is removed afterwards."""
    if not line:
        yield None
        return
    from .runner import runtime_dir
    fd, path = tempfile.mkstemp(prefix='cert-', suffix='-cert.pub', dir=str(runtime_dir()))
    try:
        with os.fdopen(fd, 'w') as f:
            f.write(line + '\n')
        yield f'CertificateFile={path}'
    finally:
        with contextlib.suppress(OSError):
            os.unlink(path)


# ── revoking ────────────────────────────────────────────────────────
def krl_version(conn: Conn) -> int:
    import json
    v = conn.scalar('SELECT value_json FROM settings WHERE key = :k', {'k': KRL_VERSION_KEY})
    return int(json.loads(v)) if v else 0


def revoke(conn: Conn, serial, actor: str, reason: str = '') -> dict:
    """Mark one certificate revoked and move the list on by one version. Hosts learn of it when the `ssh-ca-krl` step has run there."""
    if not isinstance(serial, int) or isinstance(serial, bool):
        raise CAError('a certificate is named by its serial number')
    reason = ' '.join(str(reason or '').split())[:200]
    with conn.tx():
        rows = conn.all('SELECT host, kind, key_id, revoked_at FROM ssh_certificates WHERE serial = :s', {'s': serial})
        if not rows:
            raise LookupError(f'no certificate with serial {serial}')
        if rows[0][3]:
            raise CAError('that certificate is revoked already')
        if len(revoked_serials(conn)) >= MAX_LISTED:
            raise CAError(f'{MAX_LISTED} revoked certificates have not ended yet, and the list holds no more: make a new CA, which ends them all')
        now, version = int(time.time()), krl_version(conn) + 1
        conn.execute('UPDATE ssh_certificates SET revoked_at = :t, revoked_by = :a, revoked_reason = :r WHERE serial = :s', {'t': now, 'a': actor, 'r': reason, 's': serial})
        conn.execute('DELETE FROM settings WHERE key = :k', {'k': KRL_VERSION_KEY})
        conn.execute('INSERT INTO settings (key, value_json, updated_at, updated_by) VALUES (:k, :v, :t, :a)', {'k': KRL_VERSION_KEY, 'v': str(version), 't': now, 'a': actor})
    return {'serial': serial, 'host': rows[0][0], 'kind': rows[0][1], 'key_id': rows[0][2], 'krl_version': version}


def revoked_serials(conn: Conn, now: int | None = None) -> list[int]:
    """What the list has to name: revoked certificates that have not ended. One that ended is refused for that, by every sshd."""
    now = int(now if now is not None else time.time())
    return [r[0] for r in conn.all('SELECT serial FROM ssh_certificates WHERE revoked_at IS NOT NULL AND expires_at > :t ORDER BY serial', {'t': now - 86400})]


def krl(conn: Conn) -> tuple[bytes, int] | None:
    """(the revocation list, its version), None where there is no CA."""
    ca = ca_public(conn)
    if not ca:
        return None
    version = krl_version(conn)
    return sshca.krl(ca, revoked_serials(conn), version), version


# ── plans: what reaches a host is a change plan, run like any other ──
def _login_users(conn: Conn, name: str) -> str:
    """The accounts StorageForge logs in to this host as, for the console and for scans: what a trust step is for unless told otherwise."""
    from .runner import connect_address
    from .vault import Vault, VaultError
    users = []
    for action in ('console', 'scan'):
        try:
            users.append(Vault(None, conn).resolve(connect_address(conn, name), action).user)
        except VaultError:
            pass
    return ','.join(u for u in dict.fromkeys(users) if USER_NAME.fullmatch(u or ''))


def plan(conn: Conn, body: dict, actor: str) -> dict:
    """Save a change plan and run nothing. {'kind': 'trust', 'hosts': [...], 'users': 'root,backup', 'host_cert': bool, 'rollback': 10}:
    an ssh-ca-trust step for each host named. {'kind': 'krl', 'hosts': [...]}: an ssh-ca-krl step for each host named, or for every
    host that is given certificates or has a host certificate when none is named."""
    from . import changes
    kind = body.get('kind')
    if kind not in ('trust', 'krl'):
        raise CAError('kind is trust or krl')
    if not ca_public(conn):
        raise CAError('there is no SSH CA yet: make it under Keys')
    wanted_hosts = body.get('hosts') or []
    if not isinstance(wanted_hosts, list) or len(wanted_hosts) > 500:
        raise CAError('hosts is a list of host names')
    names = list(dict.fromkeys(_known_host(conn, h) for h in wanted_hosts))
    stamp = time.strftime('%Y-%m-%d %H:%M:%S')
    if kind == 'krl':
        names = names or sorted({r[0] for r in conn.all('SELECT host FROM ssh_ca_hosts')} | {r[0] for r in conn.all("SELECT DISTINCT host FROM ssh_certificates WHERE kind = 'host'")})
        tasks = [{'type': 'ssh-ca-krl', 'host': n, 'params': {}} for n in names]
        title = f'SSH revocation list {krl_version(conn)} {stamp}'
    else:
        if not names:
            raise CAError('name the hosts that are to trust the CA')
        rollback = body.get('rollback', 10)
        if rollback not in (None, '') and (not isinstance(rollback, int) or isinstance(rollback, bool) or not 1 <= rollback <= 120):
            raise CAError('the rollback timer is 1 to 120 minutes, or empty for none')
        tasks = []
        for n in names:
            users = str(body.get('users') or '').strip() or _login_users(conn, n)
            if not users:
                raise CAError(f'no key is bound to {n} for the console or for scans, so name the users a certificate may log in as')
            tasks.append({'type': 'ssh-ca-trust', 'host': n, 'params': {'users': users, 'principals': '', 'host_cert': body.get('host_cert') is True and bool(host_certificate(conn, n)),
                                                                        'state': 'present', 'rollback': str(rollback or '')}})
        title = f'Trust the SSH CA {stamp}'
    if not tasks:
        return {'plan_id': None, 'tasks': 0, 'name': None}
    return {'plan_id': changes.save_plan(conn, {'name': title, 'tasks': tasks}, actor), 'tasks': len(tasks), 'name': title, 'hosts': names}


# ── what the page shows ─────────────────────────────────────────────
def view(conn: Conn, limit: int = 200) -> dict:
    from .vault import fingerprint
    ca = ca_public(conn)
    now = int(time.time())
    settings = {r[0]: {'console': bool(r[1]), 'scan': bool(r[2])} for r in conn.all('SELECT host, console, scan FROM ssh_ca_hosts')}
    host_certs = {}
    for serial, host, expires in conn.all("""SELECT serial, host, expires_at FROM ssh_certificates WHERE kind = 'host' AND revoked_at IS NULL AND expires_at > :t
                                             ORDER BY issued_at, serial""", {'t': now}):
        host_certs[host] = {'serial': str(serial), 'expires_at': expires, 'renew': expires - now < HOST_RENEW_SECONDS}
    hosts = [{'host': name, **settings.get(name, {'console': False, 'scan': False}), 'host_certificate': host_certs.get(name)}
             for (name,) in conn.all('SELECT hostname FROM hosts ORDER BY hostname')]
    rows = conn.all(f"""SELECT serial, kind, purpose, host, key_id, principals, subject_fp, issued_at, expires_at, issued_by, revoked_at, revoked_by, revoked_reason
                        FROM ssh_certificates ORDER BY issued_at DESC, serial DESC LIMIT {int(limit)}""")
    names = ('serial', 'kind', 'purpose', 'host', 'key_id', 'principals', 'subject_fp', 'issued_at', 'expires_at', 'issued_by', 'revoked_at', 'revoked_by', 'revoked_reason')
    # a serial is 62 bits: more than a number in JavaScript holds, so it travels as text
    certificates = [dict(zip(names, r)) | {'serial': str(r[0]), 'principals': r[5].split(','), 'ended': r[8] <= now} for r in rows]
    return {'ca': {'public_key': ca, 'fingerprint': fingerprint(ca), 'key': CA_KEY, 'known_hosts': sshca.known_hosts_line(ca, '*')} if ca else None,
            'hosts': hosts, 'certificates': certificates, 'krl_version': krl_version(conn), 'revoked': len(revoked_serials(conn, now)),
            'seconds': {'console': CONSOLE_SECONDS, 'scan': SCAN_SECONDS, 'host': HOST_SECONDS}}


def problems(conn: Conn) -> dict:
    """For the notification center: a host certificate that ends soon. sshd stops presenting one that ended, and clients that trust
    only the CA then refuse the host."""
    out = {}
    now = int(time.time())
    try:
        rows = conn.all("""SELECT host, max(expires_at) FROM ssh_certificates WHERE kind = 'host' AND revoked_at IS NULL GROUP BY host""")
    except Exception:
        return out
    for host, expires in rows:
        if now - KEEP_SECONDS < expires < now + HOST_RENEW_SECONDS:
            days = (expires - now) // 86400
            out[f'sshca-host:{host}'] = ('sshca-host', host, f'The SSH host certificate of {host} ' + (f'ends in {days} day(s)' if expires > now else 'has ended'),
                                         'Issue a new one under Keys, and run the ssh-ca-trust step there again to install it', 'warn')
    return out
