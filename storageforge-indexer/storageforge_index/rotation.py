"""Change every key StorageForge holds, for when one may have leaked.

What it changes by itself, each step only once the one before it worked:

- **SSH keys in the vault.** For each key that a scan or deploy would use on a host now: a new key is made in the vault, its public half is
  added to that account's authorized_keys over the old key, and a login with the new key is tried on every one of those hosts. Only when
  every host takes it are the bindings moved to the new key, the old key's line taken out of each authorized_keys (over the new key), and
  the old key deleted. The new key then takes the old one's name, so nothing that names it changes. If one host does not take the new key,
  nothing moves for that key: the new line is taken off the hosts that had it, the new key is deleted, and the old one stays.
- **Web sessions**: all of them end, so everyone signs in again.
- **Invites**: every one not yet used is revoked.
- **The vault's own secret**, when a new one is given: every key is wrapped again under it.

What it cannot change, and lists with what to do: the session secret and the TLS certificate (files the stack reads at start), the report
tokens of deployed jobs, schedules and remote nodes (a deploy issues new ones), each host's scan signing key, the passwords of network
devices, and the addresses alerts are sent to. None of those is in the database in a form that can be replaced from here.

plan() says what would happen and changes nothing. apply() does it and returns the same shape with what happened.
"""
from __future__ import annotations

import base64
import shlex
import subprocess
import time

from .remote import RemoteError, Transport
from .runner import ephemeral_agent, known_hosts_path
from .vault import NoBinding, Vault, VaultError

ACTIONS = ('scan', 'checksum', 'deploy')
NEXT = '{name}.rotating'              # the new key's name while it is being installed


class RotationError(RuntimeError):
    pass


def key_hosts(v: Vault, conn) -> dict[str, list[dict]]:
    """Each vault key -> the scanned hosts and accounts that a scan, checksum or deploy reaches with it now."""
    out: dict[str, list[dict]] = {}
    for hostname, ssh_host, ip, _user, _port in conn.all('SELECT hostname, ssh_host, ip_address, ssh_user, ssh_port FROM hosts ORDER BY hostname'):
        target = ssh_host or ip or hostname
        seen = set()
        for action in ACTIONS:
            try:
                b = v.resolve(target, action)
            except NoBinding:
                continue
            if (b.key_name, b.user, b.port) in seen:
                continue
            seen.add((b.key_name, b.user, b.port))
            out.setdefault(b.key_name, []).append({'host': hostname, 'address': target, 'user': b.user, 'port': b.port})
    return out


def _blob(public_line: str) -> str:
    """The base64 part of an OpenSSH public key line: what identifies it in authorized_keys, whatever the options and comment."""
    parts = public_line.split()
    for p in parts:
        if p.startswith('AAAA'):
            base64.b64decode(p, validate=True)
            return p
    raise RotationError('not an OpenSSH public key line')


def _run(v: Vault, conn, key_name: str, place: dict, command: str) -> str:
    """One command on a host's account, logged in with the named vault key, to a host key already pinned."""
    key_id = conn.scalar('SELECT key_id FROM ssh_keys WHERE name = :n', {'n': key_name})
    if key_id is None:
        raise RotationError(f'no key named {key_name}')
    with ephemeral_agent(v.decrypt_key(key_id), ttl=120) as sock:
        t = Transport(host=place['address'], user=place['user'], port=place['port'], agent_sock=sock, known_hosts=str(known_hosts_path()),
                      isolated=True, connect_timeout=10, strict=True)
        try:
            return t.run(command, timeout=60) or ''
        except (RemoteError, subprocess.TimeoutExpired) as exc:
            raise RotationError(f'{place["user"]}@{place["host"]}: {str(exc)[:200]}') from None
        finally:
            t.close()


def add_line(public_line: str) -> str:
    q = shlex.quote(public_line.strip())
    return ('umask 077; mkdir -p "$HOME/.ssh" && touch "$HOME/.ssh/authorized_keys" && '
            f'{{ grep -qxF -- {q} "$HOME/.ssh/authorized_keys" || printf "%s\\n" {q} >>"$HOME/.ssh/authorized_keys"; }} && echo added')


def drop_line(blob: str) -> str:
    """Every line that holds this key goes; the file keeps its owner and mode because it is written in place."""
    q = shlex.quote(blob)
    return ('f="$HOME/.ssh/authorized_keys"; [ -f "$f" ] || { echo dropped; exit 0; }; t=$(mktemp) || exit 1; '
            f'grep -vF -- {q} "$f" >"$t"; cat "$t" >"$f" && rm -f "$t" && echo dropped')


def _login_works(v: Vault, conn, key_name: str, place: dict) -> bool:
    try:
        return 'ok' in _run(v, conn, key_name, place, 'echo ok')
    except RotationError:
        return False


def rotate_key(v: Vault, conn, name: str, places: list[dict]) -> dict:
    """See the module's first point. Returns {'key', 'hosts', 'ok', 'steps': [...]}, and never leaves a host without a key that works."""
    steps: list[str] = []
    rows = conn.all('SELECT key_id, key_type, public_key, comment FROM ssh_keys WHERE name = :n', {'n': name})
    if not rows:
        return {'key': name, 'hosts': places, 'ok': False, 'steps': ['no such key']}
    old_id, kind, old_public, comment = rows[0]
    nxt = NEXT.format(name=name)
    v.remove_key(nxt)                                         # a run that stopped half-way left one
    v.generate_key(nxt, 'rsa' if kind == 'ssh-rsa' else 'ed25519', comment)       # an ECDSA key comes back as ed25519: the vault makes those two
    new_public = v.public_key(nxt)
    done: list[dict] = []
    try:
        for p in places:
            if 'added' not in _run(v, conn, name, p, add_line(new_public)):
                raise RotationError(f'{p["user"]}@{p["host"]}: the new key was not added')
            done.append(p)
            if not _login_works(v, conn, nxt, p):
                raise RotationError(f'{p["user"]}@{p["host"]}: the new key was added but does not log in')
            steps.append(f'{p["user"]}@{p["host"]}: the new key logs in')
    except RotationError as exc:
        for p in done:                                        # take the new line back off, over the old key that still works
            try:
                _run(v, conn, name, p, drop_line(_blob(new_public)))
            except RotationError:
                steps.append(f'{p["user"]}@{p["host"]}: could not take the new key back off: remove it by hand')
        v.remove_key(nxt)
        return {'key': name, 'hosts': places, 'ok': False, 'steps': steps + [f'stopped: {exc}. The old key is unchanged and still bound']}
    new_id = conn.scalar('SELECT key_id FROM ssh_keys WHERE name = :n', {'n': nxt})
    conn.execute('UPDATE key_bindings SET key_id = :new WHERE key_id = :old', {'new': new_id, 'old': old_id})
    steps.append('bindings moved to the new key')
    blob = _blob(old_public)
    for p in places:
        try:
            _run(v, conn, nxt, p, drop_line(blob))
            steps.append(f'{p["user"]}@{p["host"]}: the old key is out of authorized_keys')
        except RotationError as exc:
            steps.append(f'the old key could not be taken off: {exc}. Remove the line ending in its fingerprint by hand')
    v.remove_key(name)
    conn.execute('UPDATE ssh_keys SET name = :n, rotated_at = :t WHERE key_id = :k', {'n': name, 't': int(time.time()), 'k': new_id})
    steps.append(f'the old key is deleted from the vault, and the new one is called {name}')
    return {'key': name, 'hosts': places, 'ok': True, 'steps': steps,
            'fingerprint': conn.scalar('SELECT fingerprint FROM ssh_keys WHERE key_id = :k', {'k': new_id})}


MANUAL = [
    ('session secret', 'Sessions are signed with it. Make a new one and restart: delete secrets/session_secret, run docker/init-secrets.sh, '
                       'then docker compose up -d. Everyone signs in again (this run already ended every session).'),
    ('TLS certificate', 'Delete secrets/tls_cert and secrets/tls_key, run docker/init-secrets.sh and restart; browsers ask to trust the new one.'),
    ('vault secret', 'Wrap every key under a new one: set STORAGEFORGE_VAULT_NEW_SECRET (32 characters or more) and run this again, or run '
                     'vault rotate-secret. Then put the new value in secrets/vault_secret and restart. Keep a copy: without it the vault cannot be opened.'),
    ('report tokens', 'Deployed jobs, schedules and remote nodes report with a token each, kept here only as a hash. Deploy them again from the '
                      'web UI and each gets a new one; the old one stops working at that deploy.'),
    ('scan signing keys', 'Each host signs its scans with a key of its own. On a host you doubt: delete /usr/local/lib/storageforge/scan-sign*, '
                          'run the scan access script again, and forget the old key here (access signing --forget <address>).'),
    ('device passwords', 'Router and switch passwords are in the vault as credentials. Change each on the device, then store the new one.'),
    ('alert addresses', 'ntfy topics, Gotify tokens and webhook URLs are secrets to whoever holds them. Make new ones where they are hosted and '
                        'set them under Settings, Alerts.'),
]


def installed(conn) -> dict[str, list[str]]:
    """Fingerprint -> 'user@host' for every authorized_keys line the last scan of each host read. A key can be there with no binding that
    uses it (put there by hand, or for an account StorageForge does not log in as), and then a rotation does not reach it."""
    from . import authkeys
    out: dict[str, list[str]] = {}
    for h in authkeys.report(conn):
        for k in h['keys']:
            out.setdefault(k['fingerprint'], []).append(f'{k["user"]}@{h["host"]}')
    return out


def plan(db, conn) -> dict:
    seen = installed(conn)
    with Vault(db, conn).unlock() as v:
        hosts = key_hosts(v, conn)
        keys = []
        for k in v.list_keys():
            if k['name'].endswith('.rotating'):
                continue
            used = {f'{h["user"]}@{h["host"]}' for h in hosts.get(k['name'], [])}
            keys.append({'key': k['name'], 'fingerprint': k['fingerprint'], 'hosts': hosts.get(k['name'], []),
                         'elsewhere': sorted(set(seen.get(k['fingerprint'], [])) - used)})
        creds = len(v.list_credentials())
    return {'keys': keys,
            'sessions': conn.scalar('SELECT count(*) FROM web_sessions'),
            'invites': conn.scalar('SELECT count(*) FROM invites WHERE used_at IS NULL AND revoked_at IS NULL'),
            'device_credentials': creds,
            'manual': [{'what': w, 'how': h} for w, h in MANUAL]}


def apply(db, conn, actor: str, new_vault_secret: bytes | None = None, only: set | None = None) -> dict:
    """Do it. `only` limits the keys rotated to these names. A key no host uses is left alone and said so: deleting it is a person's choice."""
    from .vault import AuditLog
    out = plan(db, conn)
    with Vault(db, conn).unlock() as v:
        audit = AuditLog(db, conn, v.audit_key)
        results = []
        for k in out['keys']:
            if only and k['key'] not in only:
                continue
            left = [f'it is also in authorized_keys of {", ".join(k["elsewhere"])}, where no binding uses it, so it is still there. '
                    f'Take it out by hand (its fingerprint is {k["fingerprint"]}), or bind it to those accounts and run this again'] if k['elsewhere'] else []
            if not k['hosts']:
                results.append({'key': k['key'], 'hosts': [], 'ok': None,
                                'steps': ['no binding uses it on a scanned host: left alone (delete it if it is not needed)'] + left})
                continue
            r = rotate_key(v, conn, k['key'], k['hosts'])
            r['steps'] += left
            audit.append(actor, 'rotate.key', 'ok' if r['ok'] else 'failed', None, r.get('fingerprint'),
                         {'key': k['key'], 'hosts': [p['host'] for p in k['hosts']], 'steps': r['steps'][-3:]})
            results.append(r)
        ended = conn.execute('DELETE FROM web_sessions').rowcount
        revoked = conn.execute('UPDATE invites SET revoked_at = :t WHERE used_at IS NULL AND revoked_at IS NULL', {'t': int(time.time())}).rowcount
        audit.append(actor, 'rotate.sessions', 'ok', None, None, {'ended': ended, 'invites_revoked': revoked})
        rewrapped = None
        if new_vault_secret:
            if len(new_vault_secret) < 32:
                raise VaultError('the new vault secret needs 32 characters or more')
            rewrapped = v.rotate_secret(new_vault_secret)
            audit.append(actor, 'vault.rotate-secret', 'ok', None, None, {'rewrapped': rewrapped})
    out.update({'results': results, 'sessions_ended': ended, 'invites_revoked': revoked, 'vault_rewrapped': rewrapped})
    return out
