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


def parse(text: str) -> dict:
    """The @@authkeys section: <user><TAB><base64 key><TAB><comment>, or !<TAB><user> for what could not be read."""
    keys, unreadable = [], set()
    for line in text.splitlines():
        f = line.split('\t')
        if f[0] == '!' and len(f) == 2:
            unreadable.add(one_line(f[1])[:64])
        elif len(f) == 3 and (fp := key_fingerprint(f[1])):
            keys.append({'user': one_line(f[0])[:64], 'fingerprint': fp, 'comment': one_line(f[2]).strip()[:80]})
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


def problems(conn: Conn) -> dict:
    if get_setting(conn, POLICY_KEY) != 'generate-only':
        return {}
    now = {}
    for h in report(conn):
        unknown = [k for k in h['keys'] if not k['known']]
        if unknown:
            lines = '; '.join(f'{k["user"]}: {k["fingerprint"]} {k["comment"]}'.strip() for k in unknown)
            now[f'unknown-key:{h["host"]}'] = (
                'unknown-key', h['host'], f'{len(unknown)} SSH key(s) on {h["host"]} are not from this site',
                f'{lines}. Remove them there, or: storageforge-index hosts allow-key FINGERPRINT', 'warn')
    return now
