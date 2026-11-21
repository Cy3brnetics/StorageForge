"""Keys in accounts' authorized_keys on scanned hosts, compared with the vault. This is how a key someone added by hand
shows up, such as an admin's own: the vault cannot refuse a key it never sees.

Scans record fingerprints and comments, for root and accounts with UID 1000 and up. System accounts are left out: job
keys live in storageforge-deploy's. An account the scan user cannot read is listed as unreadable, not as clean.
Alerts are on for sites that only take generated keys; elsewhere `hosts keys` reports the same without alerting.
"""
from __future__ import annotations

import re

from .alerts import get_setting, set_setting
from .db import Conn, loads
from .remote import key_fingerprint
from .scriptkit import one_line
from .vault import POLICY_KEY

ALLOWED_KEY = 'keys.allowed'
FINGERPRINT = re.compile(r'SHA256:[A-Za-z0-9+/]{43}')
OPTION = re.compile(r'[A-Za-z][A-Za-z0-9-]{0,30}')
# a member of one of these is root in effect: docker and lxd hand out the host, the others sudo or polkit
PRIVILEGED_GROUPS = ('docker', 'lxd', 'incus-admin', 'wheel', 'sudo', 'admin', 'libvirt')


def parse(text: str) -> dict:
    """The @@authkeys section: <user><TAB><base64 key><TAB><comment>[<TAB><option names>], or !<TAB><user> for what could not
    be read. The option names are what the line starts with (restrict, pty, from, command...), their values cut off on the host:
    a forced command can hold anything. A scan from before they were read has three fields, and its options are None: not known."""
    keys, unreadable = [], set()
    for line in text.splitlines():
        f = line.split('\t')
        if f[0] == '!' and len(f) == 2:
            unreadable.add(one_line(f[1])[:64])
        elif len(f) in (3, 4) and (fp := key_fingerprint(f[1])):
            options = None if len(f) == 3 else sorted({o.strip().lower() for o in f[3].split(',') if OPTION.fullmatch(o.strip())})[:16]
            keys.append({'user': one_line(f[0])[:64], 'fingerprint': fp, 'comment': one_line(f[2]).strip()[:80], 'options': options})
    return {'keys': keys, 'unreadable': sorted(unreadable)}


def _check(fp: str) -> str:
    if not FINGERPRINT.fullmatch(fp):
        raise SystemExit(f'{fp} is not a key fingerprint (SHA256:... from hosts keys)')
    return fp


def allow(conn: Conn, fp: str, note: str, actor: str) -> None:
    allowed = get_setting(conn, ALLOWED_KEY) or {}
    allowed[_check(fp)] = one_line(note)[:80]
    set_setting(conn, ALLOWED_KEY, allowed, actor)


def disallow(conn: Conn, fp: str, actor: str) -> None:
    allowed = get_setting(conn, ALLOWED_KEY) or {}
    allowed.pop(_check(fp), None)
    set_setting(conn, ALLOWED_KEY, allowed, actor)


def report(conn: Conn, host: str | None = None) -> list[dict]:
    """Each host checked by its last scan, with every key marked 'vault', 'allowed' or None."""
    vault = {r[0] for r in conn.all('SELECT fingerprint FROM ssh_keys')}
    allowed = get_setting(conn, ALLOWED_KEY) or {}
    out = []
    for name, inv_json in conn.all('SELECT hostname, inventory_json FROM hosts ORDER BY hostname'):
        seen = (loads(inv_json) or {}).get('authkeys')
        if seen is None or (host and name.lower() != host.lower()):
            continue
        out.append({'host': name, 'unreadable': seen['unreadable'], 'keys': [
            {**k, 'known': 'vault' if k['fingerprint'] in vault else 'allowed' if k['fingerprint'] in allowed else None}
            for k in seen['keys']]})
    return out


def privileged_groups(inventory: dict, user: str) -> list[str]:
    """The groups in PRIVILEGED_GROUPS that the account is in on that host, by membership or as its own group, as the last scan read."""
    from .hostconfig import parse_accounts
    acc = parse_accounts((inventory or {}).get('accounts') or '')
    gid = next((u['gid'] for u in acc['users'] if u['name'] == user), None)
    return sorted(g['name'] for g in acc['groups'] if g['name'] in PRIVILEGED_GROUPS and (user in g['members'] or g['gid'] == gid))


def vault_logins(conn: Conn) -> list[dict]:
    """Each vault key in an account's authorized_keys, with what the line allows: {host, user, fingerprint, restricted, groups}.
    restricted is None where the scan did not read the options (a scan from before they were read)."""
    vault = {r[0] for r in conn.all('SELECT fingerprint FROM ssh_keys')}
    out = []
    for name, inv_json in conn.all('SELECT hostname, inventory_json FROM hosts ORDER BY hostname'):
        inv = loads(inv_json) or {}
        for k in (inv.get('authkeys') or {}).get('keys') or []:
            if k['fingerprint'] in vault:
                opts = k.get('options')
                out.append({'host': name, 'user': k['user'], 'fingerprint': k['fingerprint'],
                            'restricted': None if opts is None else 'restrict' in opts, 'groups': privileged_groups(inv, k['user'])})
    return out


def login_problems(conn: Conn) -> dict:
    """A StorageForge key that logs in with no restriction, or to an account that is root in effect. Either way, whoever can make
    StorageForge run a command over that key has that account: with both, root on the host."""
    now = {}
    for x in vault_logins(conn):
        if x['groups']:
            now[f'key-account-root:{x["host"]}:{x["user"]}'] = (
                'key-account-root', x['host'], f'StorageForge logs in to {x["host"]} as {x["user"]}, who is root in effect',
                f'{x["user"]} is in {", ".join(x["groups"])}. Scans need none of these: use an account outside them for the scan key', 'warn')
        if x['restricted'] is False:
            now[f'key-unrestricted:{x["host"]}:{x["user"]}'] = (
                'key-unrestricted', x['host'], f'A StorageForge key in {x["user"]}@{x["host"]} has no restrictions',
                'Its authorized_keys line has no restrict option, so it allows port and agent forwarding. Put restrict,pty (and from= with the '
                "controller's address) in front of the key on that line, or install it again from Keys, which writes it that way", 'warn')
    return now


def problems(conn: Conn) -> dict:
    now = login_problems(conn)
    if get_setting(conn, POLICY_KEY) != 'generate-only':
        return now
    for h in report(conn):
        unknown = [k for k in h['keys'] if not k['known']]
        if unknown:
            lines = '; '.join(f'{k["user"]}: {k["fingerprint"]} {k["comment"]}'.strip() for k in unknown)
            now[f'unknown-key:{h["host"]}'] = (
                'unknown-key', h['host'], f'{len(unknown)} SSH key(s) on {h["host"]} are not from this site',
                f'{lines}. Remove them there, or: storageforge-index hosts allow-key FINGERPRINT', 'warn')
    return now
