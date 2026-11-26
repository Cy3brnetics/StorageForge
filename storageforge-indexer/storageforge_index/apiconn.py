"""API connections (roadmap section 13): StorageForge reading a platform through the platform's own HTTPS API, beside SSH.

One connection is one platform instance (a Proxmox VE cluster, a Backup Server, a Datacenter Manager), switched on by a person. What
holds for every one of them:

    the certificate  pinned as SSH host keys are, but only after a person accepted it: the server's certificate is fetched with
                     nothing sent but the TLS handshake, its SHA-256 fingerprint shown, and only the fingerprint the person accepted is
                     trusted. Every request checks the certificate the server presents before the token is written to the socket, so a
                     changed certificate gets nothing; it is refused, recorded, and waits until a person accepts the new one.
    the token        a row of the vault (device_credentials), sealed inside the key enclave when it is configured, with a policy
                     that releases it for this one platform instance and nothing else (`platform: KIND:NAME`). It is released for
                     the moment of a read, and goes only into the Authorization header: never a URL, a command line, a log line, an
                     audit row, a report or an error message. Errors are cleaned of it before they leave this module.
    plain HTTP       refused: the token would cross the network readable.
    limits           a timeout on every request, at most RATE requests a second per connection, a budget per read, a cap on the size
                     of an answer, and a retry only for a read that failed in a way a retry can fix (a dropped connection, 502, 503,
                     504, 429), never for a refused token or a changed certificate.
    read-only        the default. A request that is not a GET is refused here unless the person turned on the action it is for.
    root             a token of root@pam is refused with the reason, not warned about: it can do everything on the platform.

The platforms' own readers are apipve.py, apipbs.py and apipdm.py; the guide to the least each token needs is apiguide.py.
"""
from __future__ import annotations

import base64
import hashlib
import http.client
import json
import os
import re
import socket
import ssl
import threading
import time
from urllib.parse import quote, urlencode, urlsplit

from .db import Conn, loads

# kind: what it is, its default port, the Authorization scheme, and what separates the token's name from its secret in that header
#   auth      how the token goes into a request: proxmox (Authorization: SCHEME=ID SEP SECRET), bearer (Authorization: Bearer SECRET),
#             bearer-id (Authorization: Bearer KEYID.SECRET), x-api-key (X-API-Key: SECRET), komodo (X-Api-Key: ID, X-Api-Secret: SECRET),
#             cookie (Cookie: authenticationToken=SECRET), websocket (sent once inside the TLS connection, in the login call)
#   prefix    what every API path starts with
#   token_id  what names the token (not secret), with what a person is told it looks like
#   read_post POST paths that only read (Komodo reads through POST /read/NAME): allowed without an action
PROXMOX_ID = (r'([^\s@:!/=]{1,64})@([A-Za-z0-9][A-Za-z0-9._-]{0,63})!([A-Za-z][A-Za-z0-9._-]{0,63})', 'user@realm!tokenname, as the platform shows it when the token is made')
KINDS = {
    'pve': {'title': 'Proxmox VE', 'port': 8006, 'auth': 'proxmox', 'scheme': 'PVEAPIToken', 'sep': '=', 'prefix': '/api2/json', 'token_id': PROXMOX_ID,
            'cert_file': '/etc/pve/local/pveproxy-ssl.pem (or /etc/pve/local/pve-ssl.pem when no custom certificate was uploaded)'},
    'pbs': {'title': 'Proxmox Backup Server', 'port': 8007, 'auth': 'proxmox', 'scheme': 'PBSAPIToken', 'sep': ':', 'prefix': '/api2/json', 'token_id': PROXMOX_ID,
            'cert_file': '/etc/proxmox-backup/proxy.pem'},
    'pdm': {'title': 'Proxmox Datacenter Manager', 'port': 8443, 'auth': 'proxmox', 'scheme': 'PDMAPIToken', 'sep': ':', 'prefix': '/api2/json', 'token_id': PROXMOX_ID,
            'cert_file': '/etc/proxmox-datacenter-manager/auth/api.pem'},
    'truenas': {'title': 'TrueNAS', 'port': 443, 'auth': 'websocket', 'prefix': '/api/current',
                'token_id': (r'[a-z_][a-z0-9_.-]{0,31}', 'the TrueNAS user name the API key belongs to: TrueNAS logs a key in together with its user name'),
                'cert_file': 'System, Certificates in the TrueNAS web interface (the certificate the web interface uses)'},
    'xo': {'title': 'Xen Orchestra', 'port': 443, 'auth': 'cookie', 'prefix': '/rest/v0',
           'token_id': (r'[^\s]{1,128}', 'the Xen Orchestra user the token belongs to (its name or email), to know it by: the token alone signs in'),
           'cert_file': 'the certificate set in xo-server configuration ([[http.listen]] cert), or the one XOA made'},
    'dockhand': {'title': 'Dockhand', 'port': 3000, 'auth': 'bearer', 'prefix': '/api',
                 'token_id': (r'[^\s]{1,128}', 'the Dockhand user the token belongs to, to know it by: the token alone signs in'),
                 'cert_file': 'the certificate of the HTTPS proxy in front of Dockhand (Dockhand itself serves plain HTTP, which is refused)'},
    'portainer': {'title': 'Portainer', 'port': 9443, 'auth': 'x-api-key', 'prefix': '/api',
                  'token_id': (r'[^\s]{1,128}', 'the Portainer user the access token belongs to, to know it by: the token alone signs in'),
                  'cert_file': 'Settings, SSL certificate in Portainer (its own self-signed one unless one was uploaded)'},
    'komodo': {'title': 'Komodo', 'port': 9120, 'auth': 'komodo', 'prefix': '', 'read_post': r'/read/[A-Za-z]+',
               'token_id': (r'[A-Za-z0-9_-]{4,128}', 'the API key Komodo showed beside the secret (the key names it, the secret is what signs in)'),
               'cert_file': 'the certificate of the HTTPS proxy in front of Komodo Core, or the one set by KOMODO_SSL_CERT_FILE'},
    'pangolin': {'title': 'Pangolin', 'port': 443, 'auth': 'bearer-id', 'prefix': '/v1',
                 'token_id': (r'([A-Za-z0-9]{1,64})@([A-Za-z0-9][A-Za-z0-9_-]{0,63})', 'KEYID@ORG: the part of the key before the dot, then the organization ID it is scoped to'),
                 'cert_file': 'the certificate Pangolin\'s Traefik serves for api.YOUR-DOMAIN (Let\'s Encrypt unless you set another)'},
}
REFUSED = {
    'truenas': {'root': 'root holds FULL_ADMIN', 'truenas_admin': 'truenas_admin holds FULL_ADMIN', 'admin': 'admin holds FULL_ADMIN'},
    'xo': {'admin@admin.net': 'admin@admin.net is the administrator Xen Orchestra makes at install'},
    'portainer': {'admin': 'admin is the administrator Portainer makes at install'},
}
NAME = re.compile(r'[a-z0-9][a-z0-9-]{0,39}')
TOKEN_ID = re.compile(PROXMOX_ID[0])
SECRET = re.compile(r'[\x21-\x7e]{8,512}')            # printable, no space: no header can be ended or added from inside it
HOSTNAME = re.compile(r'[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?|\[[0-9A-Fa-f:.]+\]')
REFUSED_USERS = {'root@pam': 'root@pam can do everything on the platform: make a dedicated user and a token for it, as the guide shows'}
TIMEOUT = 15
RATE = 10                     # requests a second, per connection
BUDGET = 3000                 # requests in one read: a platform that would need more is read in part, and says so
MAX_BODY = 32 << 20
RETRIES = 2
RETRY_STATUS = {429, 502, 503, 504}


class ApiError(Exception):
    """Something went wrong talking to the platform. Its text never holds the token: it is cleaned before it is raised."""


class NotPinned(ApiError):
    pass


class CertificateChanged(ApiError):
    def __init__(self, text: str, offered: str):
        super().__init__(text)
        self.offered = offered


class ReadOnly(ApiError):
    pass


class Refused(ApiError):
    """The platform refused the token (401 or 403)."""

    def __init__(self, text: str, status: int):
        super().__init__(text)
        self.status = status


class ConnError(ValueError):
    """What a person typed cannot make a connection."""


# ── what a person gives ──────────────────────────────────────────────
def normalize_url(url: str, kind: str) -> str:
    """https://host:port, from what a person typed: a host, host:port or an https URL. Plain HTTP, a user name or password in the URL,
    and a path beyond /api2/json are refused."""
    if kind not in KINDS:
        raise ConnError(f'the platform is one of {", ".join(KINDS)}')
    text = (url or '').strip()
    if not text:
        raise ConnError('give the address of the platform: a host name or IP address, with its port if it is not the usual one')
    if '://' not in text:
        text = 'https://' + text
    try:
        u = urlsplit(text)
        port = u.port
    except ValueError:
        raise ConnError('that is not an address') from None
    if u.scheme == 'http':
        raise ConnError('plain HTTP is refused: the token would cross the network readable. Use https://')
    if u.scheme != 'https':
        raise ConnError('the address starts with https://')
    if u.username or u.password or '@' in u.netloc:
        raise ConnError('no user name or password in the address: the token is given apart, and kept in the vault')
    if u.path.rstrip('/') not in ('', KINDS[kind]['prefix']) or u.query or u.fragment:
        raise ConnError(f'give only the scheme, host and port, as https://{kind}.example:{KINDS[kind]["port"]}')
    host = u.hostname or ''
    if ':' in host:
        host = f'[{host}]'
    if not HOSTNAME.fullmatch(host):
        raise ConnError('the host is a name or an IP address')
    return f'https://{host}:{port or KINDS[kind]["port"]}'


def check_token_id(token_id: str, kind: str = 'pve') -> str:
    token_id = (token_id or '').strip()
    pattern, hint = KINDS.get(kind, KINDS['pve'])['token_id']
    m = re.fullmatch(pattern, token_id)
    if not m:
        raise ConnError(f'the token ID is {hint}')
    if KINDS.get(kind, {}).get('auth') == 'proxmox':
        user = f'{m.group(1)}@{m.group(2)}'
        if user in REFUSED_USERS:
            raise ConnError(f'a token of {user} is refused: {REFUSED_USERS[user]}')
    why = REFUSED.get(kind, {}).get(token_id.lower())
    if why:
        raise ConnError(f'a key of {token_id} is refused: {why}. Make a dedicated user and a key for it, as the guide shows')
    return token_id


def check_secret(secret: str) -> str:
    if not isinstance(secret, str) or not SECRET.fullmatch(secret):
        raise ConnError('the token secret is 8 to 512 printable characters with no spaces, as the platform showed it once')
    return secret


def platform_of(kind: str, name: str) -> str:
    """What the secret's policy names, and what a release of it says it is for."""
    return f'{kind}:{name}'


def secret_name(kind: str, name: str) -> str:
    return f'api-{kind}-{name}'


# ── the rows ─────────────────────────────────────────────────────────
COLS = ('conn_id', 'kind', 'name', 'base_url', 'host', 'token_id', 'secret_name', 'cert_sha256', 'cert_offered', 'cert_pinned_by', 'cert_pinned_at',
        'actions_json', 'created_by', 'created_at', 'read_at', 'read_ok', 'read_error', 'readback_json', 'readback_at',
        'token_expires_at', 'token_expiry_source', 'token_set_at', 'token_previous')


def _row(r) -> dict:
    d = dict(zip(COLS, r))
    d['actions'] = loads(d.pop('actions_json')) or []
    d['readback'] = loads(d.pop('readback_json'))
    d['read_ok'] = bool(d['read_ok'])
    d['title'] = KINDS.get(d['kind'], {}).get('title', d['kind'])
    d['state'] = state_of(d)
    d['expiry'] = expiry_of(d)
    return d


def state_of(d: dict) -> str:
    if not d.get('cert_sha256'):
        return 'certificate-unaccepted'
    if d.get('cert_offered'):
        return 'certificate-changed'
    if not d.get('read_at'):
        return 'not-read'
    return 'ok' if d.get('read_ok') else 'failed'


def get(conn: Conn, conn_id) -> dict | None:
    rows = conn.all(f'SELECT {", ".join(COLS)} FROM platform_connections WHERE conn_id = :i', {'i': int(conn_id)})
    return _row(rows[0]) if rows else None


def by_name(conn: Conn, name: str) -> dict | None:
    rows = conn.all(f'SELECT {", ".join(COLS)} FROM platform_connections WHERE name = :n', {'n': name})
    return _row(rows[0]) if rows else None


def listing(conn: Conn) -> list[dict]:
    return [_row(r) for r in conn.all(f'SELECT {", ".join(COLS)} FROM platform_connections ORDER BY name')]


def host_for(conn: Conn, base_url: str) -> str | None:
    """The scanned host this platform runs on, by the address in its URL, when one matches."""
    address = (urlsplit(base_url).hostname or '').lower()
    for name, ssh_host, ip in conn.all('SELECT hostname, ssh_host, ip_address FROM hosts'):
        if address and address in {(name or '').lower(), (ssh_host or '').lower(), (ip or '').lower(), (name or '').split('.')[0].lower()}:
            return name
    return None


def add(v, conn: Conn, kind: str, name: str, url: str, token_id: str, secret: str, actor: str, host: str | None = None, expires_at=None) -> dict:
    """A new connection: the token sealed in the vault with a policy for this platform alone, and the row. Nothing is sent to the
    platform here: the certificate is accepted first, and only then does the token go anywhere."""
    if kind not in KINDS:
        raise ConnError(f'the platform is one of {", ".join(KINDS)}')
    if not NAME.fullmatch(name or ''):
        raise ConnError('a connection name is lower-case letters, digits and dashes, up to 40, starting with a letter or digit')
    base = normalize_url(url, kind)
    token_id = check_token_id(token_id, kind)
    check_secret(secret)
    expires = check_expiry(expires_at)
    if host:
        found = conn.scalar('SELECT hostname FROM hosts WHERE lower(hostname) = lower(:h)', {'h': host})
        if not found:
            raise ConnError(f'no scanned host is named {host}')
        host = found
    else:
        host = host_for(conn, base)
    sname = secret_name(kind, name)
    if conn.scalar('SELECT COUNT(*) FROM platform_connections WHERE name = :n', {'n': name}):
        raise ConnError(f'there is already a connection named {name}')
    if conn.scalar('SELECT COUNT(*) FROM device_credentials WHERE name = :n', {'n': sname}):
        raise ConnError(f'the vault already holds a secret named {sname}: remove it first, or name this connection another way')
    v.store_credential(sname, token_id, secret, policy={'platforms': [platform_of(kind, name)]}, made={'origin': 'given'})
    try:
        now = int(time.time())
        conn.execute("""INSERT INTO platform_connections (kind, name, base_url, host, token_id, secret_name, created_by, created_at, token_set_at,
                                                          token_expires_at, token_expiry_source)
                        VALUES (:k, :n, :b, :h, :t, :s, :a, :at, :at, :e, :es)""",
                     {'k': kind, 'n': name, 'b': base, 'h': host, 't': token_id, 's': sname, 'a': actor, 'at': now, 'e': expires,
                      'es': 'given' if expires is not None else None})
    except Exception:
        conn.execute('DELETE FROM device_credentials WHERE name = :n', {'n': sname})
        raise
    return by_name(conn, name)


class RotationRefused(ApiError):
    """The new token was not taken: the old one stays in place and keeps working. Its text never holds either token."""


def check_expiry(value) -> int | None:
    """When a token lapses, as a person gives it where the platform cannot say: epoch seconds, a YYYY-MM-DD date, or nothing."""
    if value in (None, ''):
        return None
    bad = ConnError('the expiry is a date (YYYY-MM-DD) or epoch seconds')
    if isinstance(value, bool):
        raise bad
    if isinstance(value, (int, float)):
        when = int(value)
    elif isinstance(value, str) and re.fullmatch(r'\d{4}-\d{2}-\d{2}', value.strip()):
        try:
            when = int(time.mktime(time.strptime(value.strip(), '%Y-%m-%d')))
        except (ValueError, OverflowError):
            raise bad from None
    elif isinstance(value, str) and value.strip().isdigit() and len(value.strip()) < 13:
        when = int(value.strip())
    else:
        raise bad
    if not 0 < when < 1 << 40:
        raise bad
    return when


EXPIRY_WARN = 30 * 86400          # a warning this long before a token lapses
EXPIRY_CRIT = 7 * 86400           # and a critical one this long before


def expiry_of(d: dict, now: float | None = None) -> dict:
    """{'at', 'source', 'state', 'days'}: state is unknown (nobody said), never (the platform says it does not lapse), ok, soon (within
    30 days), very-soon (within 7) or expired."""
    at, now = d.get('token_expires_at'), now or time.time()
    if at is None:
        return {'at': None, 'source': None, 'state': 'unknown', 'days': None}
    if at == 0:
        return {'at': 0, 'source': d.get('token_expiry_source'), 'state': 'never', 'days': None}
    left = at - now
    state = 'expired' if left <= 0 else 'very-soon' if left < EXPIRY_CRIT else 'soon' if left < EXPIRY_WARN else 'ok'
    return {'at': at, 'source': d.get('token_expiry_source'), 'state': state, 'days': int(left // 86400)}


def note_expiry(conn: Conn, row: dict, expire) -> None:
    """What a read-back found of the token's expiry: the platform's word replaces a person's, and a platform that does not say leaves
    what a person gave."""
    if expire is None:
        return
    conn.execute("UPDATE platform_connections SET token_expires_at = :e, token_expiry_source = 'platform' WHERE conn_id = :i",
                 {'e': int(expire), 'i': row['conn_id']})


def staged_name(row: dict) -> str:
    return f'{row["secret_name"]}.next'


def rotate(db, conn: Conn, conn_id, token_id: str, secret: str, actor: str, expires_at=None) -> dict:
    """A new token for a connection, without a gap. The new one is sealed beside the old one and checked by the read-back against the
    platform. Only when the platform takes it, it reads at least what the old one read, and it can do no more than StorageForge needs
    does it replace the old one in the vault. Otherwise the new one is dropped and the old one keeps working. Either way the old token
    still works on the platform until someone deletes it there, and the connection says so until a person says it is done.

    The secret store rotates a step's secret the same way (secretstore.rotate): staged where it is used, switched over only when every
    place took it. Here the one place is the platform, and the read-back is how it is asked."""
    from . import apireadback
    from .vault import Vault
    row = get(conn, conn_id)
    if not row:
        raise LookupError('no such connection')
    token_id = check_token_id(token_id, row['kind'])
    check_secret(secret)
    expires = check_expiry(expires_at)
    if not row.get('cert_sha256') or row.get('cert_offered'):
        raise ConnError('accept the platform certificate first: a new token is checked against the platform before it is taken')
    staged = staged_name(row)
    policy = {'platforms': [platform_of(row['kind'], row['name'])]}
    with Vault(db, conn).unlock() as v:
        v.store_credential(staged, token_id, secret, policy=policy, made={'origin': 'given'})
    trial = {**row, 'token_id': token_id, 'secret_name': staged}
    try:
        try:
            with open_client(db, conn, trial) as client:
                rb = apireadback.readback(client, trial)
        except ApiError as exc:
            raise RotationRefused(f'the platform did not take the new token: {_clean(str(exc), secret)}. The old token stays in place') from None
        old = row.get('readback') or {}
        lost = sorted(f for f, v in (old.get('features') or {}).items() if v.get('ok') and not (rb.get('features') or {}).get(f, {}).get('ok'))
        if lost:
            raise RotationRefused(f'the new token cannot read what the old one reads ({", ".join(lost)}): give it what the guide shows. The old token stays in place')
        if rb.get('verdict') == 'over' and old.get('verdict') != 'over':
            privs = sorted({str(o.get('priv', '')) for o in rb.get('over') or []})
            raise RotationRefused(f'the new token can do more than StorageForge needs ({", ".join(privs[:8])}): narrow it as the guide shows. The old token stays in place')
    except Exception:
        conn.execute('DELETE FROM device_credentials WHERE name = :n', {'n': staged})
        raise
    with Vault(db, conn).unlock() as v:
        v.store_credential(row['secret_name'], token_id, secret, policy=policy, made={'origin': 'given', 'rotated_at': int(time.time())})
    conn.execute('DELETE FROM device_credentials WHERE name = :n', {'n': staged})
    expire = (rb.get('token') or {}).get('expire')
    previous = row['token_id'] if row['token_id'] != token_id else f'{row["token_id"]} (its old secret)'
    conn.execute("""UPDATE platform_connections SET token_id = :t, token_set_at = :now, token_previous = :p, token_expires_at = :e,
                    token_expiry_source = :es WHERE conn_id = :i""",
                 {'t': token_id, 'now': int(time.time()), 'p': previous, 'e': expire if expire is not None else expires,
                  'es': 'platform' if expire is not None else 'given' if expires is not None else None, 'i': row['conn_id']})
    apireadback.store(conn, row, rb)
    return {'connection': get(conn, conn_id), 'readback': rb, 'previous': previous,
            'note': f'The old token {previous} still works on the platform until you delete it there.'}


def forget_previous(conn: Conn, conn_id) -> dict:
    """A person deleted the replaced token on the platform: the connection stops reminding them."""
    row = get(conn, conn_id)
    if not row:
        raise LookupError('no such connection')
    conn.execute('UPDATE platform_connections SET token_previous = NULL WHERE conn_id = :i', {'i': row['conn_id']})
    return get(conn, conn_id)


def remove(conn: Conn, conn_id) -> dict | None:
    """The connection, what it read and its token. The token stays valid on the platform until someone deletes it there: the answer
    says so."""
    row = get(conn, conn_id)
    if not row:
        return None
    with conn.tx():
        conn.execute('DELETE FROM platform_objects WHERE conn_id = :i', {'i': row['conn_id']})
        conn.execute('DELETE FROM platform_connections WHERE conn_id = :i', {'i': row['conn_id']})
        conn.execute('DELETE FROM device_credentials WHERE name IN (:n, :s)', {'n': row['secret_name'], 's': staged_name(row)})
    return row


def set_actions(conn: Conn, conn_id, actions: list) -> dict:
    from . import apiguide
    row = get(conn, conn_id)
    if not row:
        raise LookupError('no such connection')
    known = apiguide.actions(row['kind'])
    if not isinstance(actions, list) or not all(isinstance(a, str) for a in actions):
        raise ConnError('actions is a list of names')
    unknown = sorted(set(actions) - set(known))
    if unknown:
        raise ConnError(f'{row["title"]} has no action {", ".join(unknown)}' + (f': it has {", ".join(known)}' if known else ': only reading is offered'))
    conn.execute('UPDATE platform_connections SET actions_json = :a WHERE conn_id = :i', {'a': json.dumps(sorted(set(actions))), 'i': row['conn_id']})
    return get(conn, conn_id)


# ── the certificate ──────────────────────────────────────────────────
def fingerprint(der: bytes) -> str:
    """SHA-256 of the certificate, as Proxmox shows it and `openssl x509 -noout -fingerprint -sha256` prints it."""
    return ':'.join(f'{b:02X}' for b in hashlib.sha256(der).digest())


def _context() -> ssl.SSLContext:
    """No CA check and no host name check: the certificate is checked by its pinned fingerprint instead, which is stricter (one
    certificate, not any a CA signed) and works with the self-signed certificates these platforms make at install."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


def _split(base_url: str) -> tuple[str, int]:
    u = urlsplit(base_url)
    return (u.hostname or ''), (u.port or 443)


def describe(der: bytes) -> dict:
    out = {'sha256': fingerprint(der)}
    try:
        from cryptography import x509
        c = x509.load_der_x509_certificate(der)
        out.update({'subject': c.subject.rfc4514_string()[:300], 'issuer': c.issuer.rfc4514_string()[:300],
                    'not_before': int(c.not_valid_before_utc.timestamp()), 'not_after': int(c.not_valid_after_utc.timestamp()),
                    'self_signed': c.subject == c.issuer})
        try:
            out['names'] = c.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)[:20]
        except x509.ExtensionNotFound:
            out['names'] = []
    except Exception:            # an odd certificate is still pinned by its fingerprint; only the description is lost
        pass
    return out


def offered(base_url: str, timeout: float = TIMEOUT) -> dict:
    """The certificate the server presents, fetched with nothing sent but the TLS handshake."""
    host, port = _split(base_url)
    try:
        with socket.create_connection((host.strip('[]'), port), timeout=timeout) as raw:
            with _context().wrap_socket(raw, server_hostname=None if re.fullmatch(r'[\d.]+|\[.*\]', host) else host) as s:
                der = s.getpeercert(binary_form=True)
    except (OSError, ssl.SSLError) as exc:
        raise ApiError(f'{host}:{port} did not answer over TLS: {_clean(str(exc))}') from None
    if not der:
        raise ApiError(f'{host}:{port} presented no certificate')
    return describe(der)


def pin(conn: Conn, conn_id, sha256: str, actor: str, seen: dict | None = None) -> dict:
    """A person compared the fingerprint with the platform's own and accepted it. It must be what the server presents now: a person
    who accepted one certificate has not accepted another."""
    row = get(conn, conn_id)
    if not row:
        raise LookupError('no such connection')
    want = (sha256 or '').strip().upper()
    if not re.fullmatch(r'([0-9A-F]{2}:){31}[0-9A-F]{2}', want):
        raise ConnError('the fingerprint is 32 pairs of hex digits separated by colons, as the platform shows it')
    now = (seen or offered(row['base_url']))['sha256']
    if now != want:
        raise ConnError(f'{row["base_url"]} now presents a different certificate than the one you accepted: nothing was pinned')
    conn.execute("""UPDATE platform_connections SET cert_sha256 = :f, cert_offered = NULL, cert_pinned_by = :a, cert_pinned_at = :t,
                    read_at = NULL, read_ok = 0, read_error = '' WHERE conn_id = :i""", {'f': want, 'a': actor, 't': int(time.time()), 'i': row['conn_id']})
    return get(conn, conn_id)


# ── the client ───────────────────────────────────────────────────────
_last: dict[int, float] = {}
_last_lock = threading.Lock()


def _wait_turn(conn_id: int, rate: float):
    """At most `rate` requests a second for one connection, across every thread of this process."""
    gap = 1.0 / rate
    with _last_lock:
        now = time.monotonic()
        at = max(now, _last.get(conn_id, 0.0) + gap)
        _last[conn_id] = at
    if at > now:
        time.sleep(at - now)


_CONTROL = re.compile(r'[\x00-\x1f\x7f]+')


def _clean(text: str, *secrets_: str) -> str:
    text = str(text)
    for s in secrets_:
        if s:
            text = text.replace(s, '[token]')
    return _CONTROL.sub(' ', text)[:300]


class Client:
    """Requests to one platform with its token. The token is held only as long as this object, which a read closes when it ends."""

    def __init__(self, row: dict, secret: str, timeout: float = TIMEOUT, rate: float = RATE, budget: int = BUDGET):
        self.row, self.timeout, self.rate, self.budget = row, timeout, rate, budget
        self.kind = row['kind']
        self.spec = KINDS[self.kind]
        self._secret = secret
        self._auth = auth_headers(self.spec, row['token_id'], secret)
        self.host, self.port = _split(row['base_url'])
        self.sent = 0
        self.fatal: ApiError | None = None       # a changed certificate or a lost pin: nothing more is sent, whatever the caller does with the error

    def close(self):
        self._secret = self._auth = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def clean(self, text: str) -> str:
        return _clean(text, self._secret or '', *(self._auth or {}).values())

    def _connect(self) -> http.client.HTTPSConnection:
        try:
            return self._pinned()
        except (CertificateChanged, NotPinned) as exc:
            self.fatal = exc
            raise

    def _pinned(self) -> http.client.HTTPSConnection:
        pinned = self.row.get('cert_sha256')
        if not pinned:
            raise NotPinned(f'the certificate of {self.row["base_url"]} has not been accepted yet: nothing was sent')
        c = http.client.HTTPSConnection(self.host.strip('[]'), self.port, timeout=self.timeout, context=_context())
        try:
            c.connect()
            der = c.sock.getpeercert(binary_form=True) or b''
        except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
            c.close()
            raise ApiError(f'{self.host}:{self.port} did not answer: {self.clean(exc)}') from None
        got = fingerprint(der)
        if got != pinned:
            c.close()
            raise CertificateChanged(f'{self.row["base_url"]} presented a different certificate ({got}) than the one accepted ({pinned}): '
                                     'nothing was sent. If the platform renewed it, accept the new one', got)
        return c

    def path_of(self, path: str, params: dict | None = None) -> str:
        if not path.startswith('/') or '..' in path or not re.fullmatch(r"[A-Za-z0-9/_.~%:@!$&'()*+,;=-]*", path):
            raise ApiError(f'not an API path: {path[:80]}')
        q = {k: v for k, v in (params or {}).items() if v is not None}
        return self.spec['prefix'] + path + ('?' + urlencode(q) if q else '')

    def reads_only(self, method: str, path: str) -> bool:
        """A GET, or a POST the platform uses for reading (Komodo's /read/NAME)."""
        return method == 'GET' or (method == 'POST' and bool(self.spec.get('read_post')) and re.fullmatch(self.spec['read_post'], path) is not None)

    def request(self, method: str, path: str, params: dict | None = None, action: str | None = None) -> str:
        """The body of the answer, as text. Anything that changes something: refused unless the person turned on the action it is for."""
        if self._auth is None:
            raise ApiError('this client was closed')
        if self.fatal:
            raise self.fatal
        reading = self.reads_only(method, path)
        if not reading and (not action or action not in (self.row.get('actions') or [])):
            raise ReadOnly(f'{self.row["name"]} is read-only: {method} {path} needs an action turned on for it' + (f' ({action})' if action else ''))
        if self.sent >= self.budget:
            raise ApiError(f'this read reached its limit of {self.budget} requests: the rest was not read')
        url = self.path_of(path, params if method == 'GET' else None)
        body = json.dumps(params if params is not None else {}).encode() if method != 'GET' else None
        tries = RETRIES if reading else 0
        attempt = redirects = 0
        while attempt <= tries:
            _wait_turn(int(self.row.get('conn_id') or 0), self.rate)
            self.sent += 1
            try:
                status, reason, text, retry_after, location = self._once(method, url, body)
            except (CertificateChanged, NotPinned):
                raise
            except ApiError:
                if attempt < tries:
                    attempt += 1
                    time.sleep(0.5 * attempt)
                    continue
                raise
            if status in (301, 302, 303, 307, 308) and method == 'GET' and redirects < 3:
                url = self._redirect(location, url)          # Xen Orchestra sends /users/me on to /users/ID
                redirects += 1
                continue
            if status in RETRY_STATUS and attempt < tries:
                attempt += 1
                time.sleep(min(retry_after or 0.5 * attempt, 5))
                continue
            if status in (401, 403):
                raise Refused(f'{self.row["title"]} refused the token for {path}: {status} {self.clean(reason)}', status)
            if status >= 400:
                raise ApiError(f'{self.row["title"]} answered {status} {self.clean(reason)} for {path}')
            return text
        raise ApiError(f'{self.row["title"]} did not answer {path}')       # not reached: the loop returns or raises

    def _redirect(self, location: str | None, was: str) -> str:
        """Where a redirect may lead: only to another API path on the same server, so the token never follows it anywhere else."""
        target = urlsplit(location or '')
        if (target.scheme and target.scheme != 'https') or (target.netloc and (target.hostname or '').lower() != self.host.strip('[]').lower()) \
                or (target.port not in (None, self.port) if target.netloc else False):
            raise ApiError(f'{self.row["title"]} sent the request to another server: not followed')
        if not target.path.startswith(self.spec['prefix'] + '/') or '..' in target.path:
            raise ApiError(f'{self.row["title"]} sent the request outside its API: not followed')
        return target.path + ('?' + (target.query or urlsplit(was).query) if (target.query or urlsplit(was).query) else '')

    def _once(self, method: str, url: str, body: bytes | None):
        c = self._connect()
        try:
            headers = {**self._auth, 'Accept': 'application/json', 'User-Agent': 'StorageForge'}
            if body is not None:
                headers['Content-Type'] = 'application/json'
            c.request(method, url, body=body, headers=headers)
            r = c.getresponse()
            data = r.read(MAX_BODY + 1)
            if len(data) > MAX_BODY:
                raise ApiError(f'the answer to {url.split("?")[0]} is larger than {MAX_BODY >> 20} MiB: not read')
            retry = r.getheader('Retry-After')
            return r.status, r.reason or '', data.decode('utf-8', 'replace'), float(retry) if retry and retry.isdigit() else None, r.getheader('Location')
        except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
            raise ApiError(f'{self.host}:{self.port}: {self.clean(exc)}') from None
        finally:
            c.close()

    def get(self, path: str, **params) -> str:
        return self.request('GET', path, params)

    def post_read(self, path: str, params: dict | None = None) -> str:
        """A read the platform takes as a POST (Komodo): refused by request() unless the path is one of the platform's reading paths."""
        return self.request('POST', path, params or {})

    def seg(self, text) -> str:
        """One path segment from a value the platform gave (a node, a store, a remote): quoted, so it cannot climb or add a query."""
        return quote(str(text), safe='')


def auth_headers(spec: dict, token_id: str, secret: str) -> dict:
    """The headers that carry the token, in the platform's own form. The only place the secret is put into a request."""
    how = spec['auth']
    if how == 'proxmox':
        return {'Authorization': f'{spec["scheme"]}={token_id}{spec["sep"]}{secret}'}
    if how == 'bearer':
        return {'Authorization': f'Bearer {secret}'}
    if how == 'bearer-id':
        return {'Authorization': f'Bearer {token_id.split("@", 1)[0]}.{secret}'}
    if how == 'x-api-key':
        return {'X-API-Key': secret}
    if how == 'komodo':
        return {'X-Api-Key': token_id, 'X-Api-Secret': secret}
    if how == 'cookie':
        return {'Cookie': f'authenticationToken={secret}'}
    if how == 'websocket':
        return {}
    raise ApiError(f'no way to send a token of kind {how}')


# ── the WebSocket JSON-RPC client (TrueNAS) ───────────────────────────
WS_GUID = b'258EAFA5-E914-47DA-95CA-C5AB0DC85B11'


class RpcError(ApiError):
    """The platform answered a call with a JSON-RPC error."""

    def __init__(self, text: str, code=None, errname: str | None = None):
        super().__init__(text)
        self.code, self.errname = code, errname


class WsClient(Client):
    """JSON-RPC 2.0 over one WebSocket (RFC 6455) on the pinned TLS connection, as TrueNAS's middleware API speaks it. The key goes once,
    in the login call inside the TLS connection; nothing carries it after. Every call is checked against reads_only_call before it
    is sent: a method that is not a query, a get or a read of state is refused unless an action turned on names it."""

    READ_METHODS = re.compile(r'([a-z_]+\.)+(query|get_instance|config|info|my_keys|me|list|roles)|auth\.login_ex|core\.ping')

    def __init__(self, row: dict, secret: str, **kw):
        super().__init__(row, secret, **kw)
        self._sock = None
        self._next = 0
        self.user_info = None

    def close(self):
        if self._sock is not None:
            try:
                self._sock.sendall(self._frame(0x8, b''))
            except OSError:
                pass
            try:
                self._sock.close()
            except OSError:
                pass
        self._sock = None
        super().close()

    def get(self, path: str, **params) -> str:
        raise ApiError(f'{self.row["title"]} is read through calls, not paths')

    def _open(self):
        c = self._connect()
        sock = c.sock
        key = base64.b64encode(os.urandom(16)).decode()
        host = self.host if self.port == 443 else f'{self.host}:{self.port}'
        req = (f'GET {self.spec["prefix"]} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n'
               'Sec-WebSocket-Version: 13\r\nUser-Agent: StorageForge\r\n\r\n')
        try:
            sock.sendall(req.encode())
            head = b''
            while b'\r\n\r\n' not in head:
                chunk = sock.recv(4096)
                if not chunk:
                    raise ApiError(f'{self.host}:{self.port} closed the connection during the WebSocket handshake')
                head += chunk
                if len(head) > 65536:
                    raise ApiError('the WebSocket handshake answer is too long')
        except (OSError, ssl.SSLError) as exc:
            raise ApiError(f'{self.host}:{self.port}: {self.clean(exc)}') from None
        head, _, rest = head.partition(b'\r\n\r\n')
        lines = head.decode('latin-1').split('\r\n')
        status = lines[0].split(' ', 2)
        if len(status) < 2 or status[1] != '101':
            raise ApiError(f'{self.row["title"]} did not open a WebSocket at {self.spec["prefix"]}: {self.clean(lines[0])}')
        fields = {k.strip().lower(): v.strip() for k, _, v in (ln.partition(':') for ln in lines[1:])}
        want = base64.b64encode(hashlib.sha1(key.encode() + WS_GUID).digest()).decode()
        if fields.get('sec-websocket-accept') != want:
            raise ApiError(f'{self.row["title"]} answered the WebSocket handshake wrongly')
        self._sock, self._buf = sock, rest
        c.sock = None                         # the socket is ours now; closing the HTTP connection object must not close it

    @staticmethod
    def _frame(opcode: int, payload: bytes) -> bytes:
        n = len(payload)
        head = bytes([0x80 | opcode])
        if n < 126:
            head += bytes([0x80 | n])
        elif n < 1 << 16:
            head += bytes([0x80 | 126]) + n.to_bytes(2, 'big')
        else:
            head += bytes([0x80 | 127]) + n.to_bytes(8, 'big')
        mask = os.urandom(4)
        return head + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(payload))

    def _read(self, n: int) -> bytes:
        while len(self._buf) < n:
            chunk = self._sock.recv(65536)
            if not chunk:
                raise ApiError(f'{self.host}:{self.port} closed the WebSocket')
            self._buf += chunk
        out, self._buf = self._buf[:n], self._buf[n:]
        return out

    def _message(self) -> str:
        parts, total = [], 0
        while True:
            b0, b1 = self._read(2)
            opcode, n = b0 & 0x0F, b1 & 0x7F
            if n == 126:
                n = int.from_bytes(self._read(2), 'big')
            elif n == 127:
                n = int.from_bytes(self._read(8), 'big')
            mask = self._read(4) if b1 & 0x80 else None
            total += n
            if total > MAX_BODY:
                raise ApiError(f'an answer from {self.row["title"]} is larger than {MAX_BODY >> 20} MiB: not read')
            data = self._read(n)
            if mask:
                data = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
            if opcode == 0x9:                                 # ping: answer and wait on
                self._sock.sendall(self._frame(0xA, data))
                total -= n
                continue
            if opcode == 0xA:
                total -= n
                continue
            if opcode == 0x8:
                raise ApiError(f'{self.row["title"]} closed the WebSocket')
            parts.append(data)
            if b0 & 0x80:
                return b''.join(parts).decode('utf-8', 'replace')

    def call(self, method: str, *params, action: str | None = None):
        """The result of one call. Raises RpcError for an error the platform answered, Refused for one that says the session may not."""
        if self._auth is None:
            raise ApiError('this client was closed')
        if self.fatal:
            raise self.fatal
        if not self.READ_METHODS.fullmatch(method) and (not action or action not in (self.row.get('actions') or [])):
            raise ReadOnly(f'{self.row["name"]} is read-only: {method} needs an action turned on for it' + (f' ({action})' if action else ''))
        if self.sent >= self.budget:
            raise ApiError(f'this read reached its limit of {self.budget} requests: the rest was not read')
        _wait_turn(int(self.row.get('conn_id') or 0), self.rate)
        self.sent += 1
        try:
            if self._sock is None:
                self._open()
                self._login()
            return self._rpc(method, list(params))
        except (OSError, ssl.SSLError) as exc:
            raise ApiError(f'{self.host}:{self.port}: {self.clean(exc)}') from None

    def _rpc(self, method: str, params: list):
        self._next += 1
        ident = self._next
        self._sock.sendall(self._frame(0x1, json.dumps({'jsonrpc': '2.0', 'id': ident, 'method': method, 'params': params}).encode()))
        while True:
            try:
                doc = json.loads(self._message())
            except (ValueError, RecursionError):
                raise ApiError(f'{self.row["title"]} answered {method} with something that is not JSON') from None
            if not isinstance(doc, dict) or doc.get('id') != ident:
                continue                                       # a notification (collection_update) or another call's answer
            err = doc.get('error')
            if isinstance(err, dict):
                data = err.get('data') if isinstance(err.get('data'), dict) else {}
                errname = data.get('errname') if isinstance(data.get('errname'), str) else None
                reason = data.get('reason') if isinstance(data.get('reason'), str) else err.get('message')
                text = f'{self.row["title"]} refused {method}: {self.clean(reason or "")}'
                if errname in ('EACCES', 'EPERM') or 'not authorized' in str(reason).lower():
                    raise Refused(text, 403)
                raise RpcError(text, err.get('code'), errname)
            return doc.get('result')

    def _login(self):
        """auth.login_ex with the API_KEY_PLAIN mechanism (TrueNAS 25.04 and later): the user name and the key, once, inside TLS."""
        got = self._rpc('auth.login_ex', [{'mechanism': 'API_KEY_PLAIN', 'username': self.row['token_id'], 'api_key': self._secret,
                                           'login_options': {'user_info': True}}])
        kind = got.get('response_type') if isinstance(got, dict) else None
        if kind != 'SUCCESS':
            why = {'AUTH_ERR': 'the key or its user name is wrong, or the key was revoked', 'EXPIRED': 'the key has expired',
                   'OTP_REQUIRED': 'the user asks for a one-time password, which an API key cannot give', 'REDIRECT': 'the login has to be made on another node'}.get(kind, 'the login did not succeed')
            raise Refused(f'{self.row["title"]} refused the key: {why}', 401)
        self.user_info = got.get('user_info') if isinstance(got.get('user_info'), dict) else None


def open_client(db, conn: Conn, row: dict, **kw) -> Client:
    """The token released from the vault for this platform instance, and a client holding it. With the key enclave, the release is
    checked against the policy inside the enclave and written into the audit log by it."""
    from .vault import Vault
    if not row.get('cert_sha256'):
        raise NotPinned(f'the certificate of {row["base_url"]} has not been accepted yet: the token was not released')
    with Vault(db, conn).unlock() as v:
        cred = v.credential(row['secret_name'], platform=platform_of(row['kind'], row['name']))
    try:
        if cred.get('username') and cred['username'] != row['token_id']:
            raise ApiError('the vault holds a token of another name for this connection: replace the token')
        return (WsClient if KINDS[row['kind']]['auth'] == 'websocket' else Client)(row, cred['password'], **kw)
    finally:
        cred.clear()


def record_failure(conn: Conn, row: dict, exc: Exception) -> None:
    text = _clean(str(exc))
    if isinstance(exc, CertificateChanged):
        conn.execute('UPDATE platform_connections SET cert_offered = :o, read_ok = 0, read_error = :e, read_at = :t WHERE conn_id = :i',
                     {'o': exc.offered, 'e': text, 't': int(time.time()), 'i': row['conn_id']})
    else:
        conn.execute('UPDATE platform_connections SET read_ok = 0, read_error = :e, read_at = :t WHERE conn_id = :i',
                     {'e': text, 't': int(time.time()), 'i': row['conn_id']})


def problems(conn: Conn) -> dict:
    """A changed certificate is a security finding: someone may be in the middle. It cannot be muted, and leaves when a person
    accepts the new certificate or the connection is removed."""
    out = {}
    for row in listing(conn):
        if row['state'] == 'certificate-changed':
            out[f'security-api-cert:{row["name"]}'] = ('security-api-cert', row['host'] or row['name'],
                                                      f'{row["title"]} {row["name"]} presented a different certificate',
                                                      f'now {row["cert_offered"]}, accepted {row["cert_sha256"]}. Nothing is sent to it until a person accepts the new one in Keys, Platform connections.', 'crit')
        elif row['state'] == 'failed':
            out[f'api-read:{row["name"]}'] = ('api-read', row['host'] or row['name'], f'Reading {row["title"]} {row["name"]} failed', row['read_error'], 'warn')
        exp = row['expiry']
        if exp['state'] in ('soon', 'very-soon', 'expired'):
            when = time.strftime('%Y-%m-%d', time.localtime(exp['at']))
            title = (f'The {row["title"]} token of {row["name"]} expired on {when}' if exp['state'] == 'expired'
                     else f'The {row["title"]} token of {row["name"]} expires on {when}')
            said = ' The date is the one given when the token was entered: the platform does not say.' if exp['source'] == 'given' else ''
            out[f'api-token-expiry:{row["name"]}'] = ('api-token-expiry', row['host'] or row['name'], title,
                                                      'Make a new token as the guide shows and give it under Keys, Platform connections, Replace the token: '
                                                      'it is checked against the platform before the old one is dropped.' + said,
                                                      'warn' if exp['state'] == 'soon' else 'crit')
        if row.get('token_previous'):
            out[f'api-token-previous:{row["name"]}'] = ('api-token-previous', row['host'] or row['name'], f'The replaced {row["title"]} token of {row["name"]} still works',
                                                        f'{row["token_previous"]} was replaced and works on the platform until it is deleted there. Delete it, then '
                                                        'say so under Keys, Platform connections.', 'info')
    from . import apiread, apireadback
    out.update(apireadback.problems(conn))
    out.update(apiread.problems(conn))
    return out
