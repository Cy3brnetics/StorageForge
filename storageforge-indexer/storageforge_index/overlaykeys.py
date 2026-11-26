"""Keys for the private networks' join steps (roadmap section 2), made where they belong and kept in the vault.

    Nebula      a certificate authority whose key is a vault key (in the key enclave where there is one, and it signs there), its
                certificate kept as a setting, host certificates issued from it, and a list of what was issued so one can be
                revoked. A host's own key pair is made on the host and stays there: only its public half is read.
    Headscale   a pre-auth key made on the Headscale server and stored as a vault secret for the `tailscale` step. It goes from
                the server's answer into the vault and is never printed.

Both reach a host as `vault send-secret` does: over ssh with the operator's own login and `sudo -n`. Nothing secret is on a command
line here: a Nebula certificate and a public key are not secrets, and the Headscale key comes back on ssh's output, inside the
connection, and is never an argument.
"""
from __future__ import annotations

import json
import re
import shlex
import subprocess
import sys
import time
from pathlib import Path

from . import alerts, nebulaca
from .secretstore import NAME as SECRET_NAME

SETTING = 'nebula_cas'
DIR = nebulaca.DIR
CA_NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9_-]{0,31}')
HOST = re.compile(r'[A-Za-z0-9_.:-]{1,253}')
LOGIN = re.compile(r'[a-z_][a-z0-9_.-]{0,31}')
HS_USER = re.compile(r'[A-Za-z0-9][A-Za-z0-9._@-]{0,63}')
HS_TAGS = re.compile(r'tag:[a-z0-9][a-z0-9-]{0,62}(,tag:[a-z0-9][a-z0-9-]{0,62}){0,9}')
HS_EXPIRY = re.compile(r'[0-9]{1,4}[mhd]')
HS_KEY = re.compile(r'[A-Za-z0-9_-]{16,200}')
CONTAINER = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}')

# What runs on the host, as root. Nothing in these is a value somebody typed: the names are fixed.
# A key that is there without its public half was not made here, and is left alone.
KEYGEN = ('umask 077; mkdir -p @DIR@ && cd @DIR@ || exit 1; '
          'if [ -s host.key ] && [ ! -s host.pub ]; then echo "there is a host.key and no host.pub in @DIR@: a Nebula key that was not made here, left alone" >&2; exit 3; fi; '
          'command -v nebula-cert >/dev/null || { echo "nebula-cert is not installed" >&2; exit 4; }; '
          '[ -s host.key ] || nebula-cert keygen -out-key host.key -out-pub host.pub || exit 1; chmod 600 host.key; cat host.pub')
WRITE = ('umask 077; cd @DIR@ && cat > @NAME@.part && { [ ! -s @NAME@ ] || cmp -s @NAME@ @NAME@.part || cp -p @NAME@ @NAME@.sf-before; } '
         '&& chmod 644 @NAME@.part && mv -f @NAME@.part @NAME@')


class KeyError_(ValueError):
    """Something asked for that cannot be given, with the sentence to show."""


def _ssh(conn, args) -> list[str]:
    """ssh's words up to and including the target, from the same options `vault send-secret` takes."""
    if not HOST.fullmatch(args.host or '') or args.host.startswith('-'):
        raise KeyError_('a host name or address, please')
    user = args.user or conn.scalar('SELECT ssh_user FROM hosts WHERE lower(hostname) = lower(:h) OR ssh_host = :h', {'h': args.host})
    if user and not LOGIN.fullmatch(user):
        raise KeyError_(f'{user} is not a login name')
    argv = ['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10']
    for o in args.ssh_option or []:
        argv += ['-o', o]
    if args.key:
        argv += ['-i', str(Path(args.key).expanduser()), '-o', 'IdentitiesOnly=yes']
    return argv + ['--', f'{user}@{args.host}' if user else args.host]


def _as_root(script: str) -> str:
    return 'sudo -n sh -c ' + shlex.quote(script)


def _tail(raw: bytes) -> str:
    return raw.decode(errors='replace').strip()[-300:]


# ── Nebula ──
def cas(conn) -> dict:
    return alerts.get_setting(conn, SETTING) or {}


def key_name(ca: str) -> str:
    return f'nebula-ca-{ca}'


def signer(v, name: str):
    """(the CA key's 32 public bytes, sign(data) -> the bare signature). With the key enclave the key never leaves it."""
    from cryptography.hazmat.primitives import serialization
    from .vault import EnclaveKey, VaultError
    kid = v.conn.scalar('SELECT key_id FROM ssh_keys WHERE name = :n AND disabled_at IS NULL', {'n': name})
    if kid is None:
        raise VaultError(f'the vault has no key named {name}')
    public = nebulaca.ed25519_public(v.public_key(name))

    def sign(data: bytes) -> bytes:
        buf = v.decrypt_key(kid)
        if isinstance(buf, EnclaveKey):
            return buf.sign(data)
        try:
            return serialization.load_ssh_private_key(bytes(buf.view()), None).sign(data)
        finally:
            buf.wipe()
    return public, sign


def ca_create(conn, v, name: str, actor: str, days: int = 730, networks: list[str] | None = None, now: float | None = None) -> dict:
    """A new CA: an ed25519 key made in the vault and a certificate it signs for itself. The certificate is kept as a setting."""
    if not CA_NAME.fullmatch(name or ''):
        raise KeyError_('a CA name is letters, digits, _ and -, up to 32')
    known = cas(conn)
    if name in known:
        raise KeyError_(f'there is a Nebula CA named {name} already: its certificate ends {time.strftime("%Y-%m-%d", time.gmtime(known[name]["not_after"]))}')
    if not 1 <= days <= 3660:
        raise KeyError_('a CA lasts between a day and ten years')
    if conn.scalar('SELECT 1 FROM ssh_keys WHERE name = :n', {'n': key_name(name)}) is None:
        v.generate_key(key_name(name), 'ed25519', comment=f'storageforge:nebula-ca:{name}')
    public, sign = signer(v, key_name(name))
    cert = nebulaca.ca_certificate(name, public, sign, seconds=days * 86400, networks=networks, now=now)
    said = nebulaca.read(cert)
    known[name] = {'key': key_name(name), 'certificate': cert, 'fingerprint': said['fingerprint'], 'networks': said['networks'], 'not_after': said['not_after'],
                   'made': int(now if now is not None else time.time()), 'issued': []}
    alerts.set_setting(conn, SETTING, known, actor[:60])
    return known[name]


def _ca(conn, name: str) -> tuple[dict, dict]:
    known = cas(conn)
    if name not in known:
        raise KeyError_(f'there is no Nebula CA named {name}: storageforge-index vault nebula-ca {name}')
    return known, known[name]


def issue(conn, v, ca: str, actor: str, *, name: str, address: str, public_pem: str, host: str | None = None, groups: list[str] | None = None,
          behind: list[str] | None = None, days: int | None = None, now: float | None = None) -> str:
    """A host certificate for the public key a host made, and a line in the CA's list of what it issued. An address belongs to one
    name: it is given to another only after the first one's certificates are revoked."""
    known, record = _ca(conn, ca)
    at = int(now if now is not None else time.time())
    taken = [i for i in record['issued'] if i['address'].split('/')[0] == address.split('/')[0] and i['name'] != name and not i.get('revoked') and i['not_after'] > at]
    if taken:
        raise KeyError_(f'{address.split("/")[0]} is {taken[0]["name"]}\'s on this network: revoke that certificate first, or give {name} another address')
    public, sign = signer(v, record['key'])
    cert = nebulaca.host_certificate(record['certificate'], sign, name=name, address=address, public=nebulaca.public_key(public_pem), groups=groups,
                                     unsafe_networks=behind, seconds=days * 86400 if days else None, now=now)
    said = nebulaca.verify(cert, record['certificate'], at)          # what was just signed is read back before it goes anywhere
    record['issued'].append({'name': name, 'address': address, 'groups': said['groups'], 'fingerprint': said['fingerprint'], 'not_after': said['not_after'],
                             'host': host, 'at': at, 'revoked': None})
    alerts.set_setting(conn, SETTING, known, actor[:60])
    return cert


def revoke(conn, ca: str, name: str, actor: str, now: float | None = None) -> list[str]:
    """Every certificate of this name that still runs goes on the CA's blocklist. The fingerprints, for the audit log."""
    known, record = _ca(conn, ca)
    at = int(now if now is not None else time.time())
    hit = [i for i in record['issued'] if i['name'] == name and not i.get('revoked') and i['not_after'] > at]
    for i in hit:
        i['revoked'] = at
    if hit:
        alerts.set_setting(conn, SETTING, known, actor[:60])
    return [i['fingerprint'] for i in hit]


def blocklist(conn, ca: str, now: float | None = None) -> list[str]:
    """What every host of this CA should refuse: revoked certificates that have not ended yet. One that has ended needs no line."""
    at = int(now if now is not None else time.time())
    return sorted(i['fingerprint'] for i in (cas(conn).get(ca) or {}).get('issued', []) if i.get('revoked') and i['not_after'] > at)


def issue_to_host(conn, v, args, actor: str, run=None) -> dict:
    """The whole of `vault nebula-issue`: the host makes its key pair if it has none and prints the public half, the CA signs, and
    the certificate and the CA's go back. Three ssh calls, none carrying a secret."""
    run = run or subprocess.run
    argv = _ssh(conn, args)
    _ca(conn, args.ca)
    p = run(argv + [_as_root(KEYGEN.replace('@DIR@', DIR))], input=b'', capture_output=True, timeout=60)
    if p.returncode != 0:
        raise KeyError_(f'{args.host}: could not read a Nebula public key: {_tail(p.stderr)}')
    name = args.name or args.host.split('.')[0].lower()
    cert = issue(conn, v, args.ca, actor, name=name, address=args.address, public_pem=p.stdout.decode(errors='replace'), host=args.host,
                 groups=[g for g in (args.groups or '').split(',') if g], behind=[n for n in (args.behind or '').split(',') if n], days=args.days)
    for file, text in (('ca.crt', cas(conn)[args.ca]['certificate']), ('host.crt', cert)):
        p = run(argv + [_as_root(WRITE.replace('@DIR@', DIR).replace('@NAME@', file))], input=text.encode(), capture_output=True, timeout=60)
        if p.returncode != 0:
            raise KeyError_(f'{args.host}: could not write {DIR}/{file}: {_tail(p.stderr)}')
    return nebulaca.read(cert) | {'name': name}


# ── Headscale ──
def headscale_command(user: str | None, expiration: str, reusable: bool, ephemeral: bool, tags: str | None, container: str | None) -> str:
    """The one command run on the Headscale server. Every word is checked against a pattern, and quoted."""
    if user and not HS_USER.fullmatch(user):
        raise KeyError_('the Headscale user is its number or its name')
    if tags and not HS_TAGS.fullmatch(tags):
        raise KeyError_('tags are tag:name, separated by commas, up to 10')
    if not user and not tags:
        raise KeyError_('a pre-auth key is for a Headscale user (--hs-user) or for tags (--tags)')
    if not HS_EXPIRY.fullmatch(expiration or ''):
        raise KeyError_('an expiration is a number and m, h or d, such as 1h')
    if container and not CONTAINER.fullmatch(container):
        raise KeyError_('a container name, please')
    words = (['docker', 'exec', container] if container else []) + ['headscale', 'preauthkeys', 'create', '--expiration', expiration, '-o', 'json']
    words += (['--user', user] if user else []) + (['--tags', tags] if tags else []) + (['--reusable'] if reusable else []) + (['--ephemeral'] if ephemeral else [])
    return 'sudo -n ' + ' '.join(shlex.quote(w) for w in words)


def headscale_answer(text: str) -> tuple[str, dict]:
    """(the key, what else Headscale said about it) from `preauthkeys create -o json`. The key is in neither the error nor the dict."""
    at = text.find('{')
    try:
        doc = json.loads(text[at:]) if at >= 0 else None
    except ValueError:
        doc = None
    key = doc.get('key') if isinstance(doc, dict) else None
    if not isinstance(key, str) or not HS_KEY.fullmatch(key):
        raise KeyError_('Headscale did not answer with a pre-auth key')
    expiry = doc.get('expiration')
    if isinstance(expiry, dict) and isinstance(expiry.get('seconds'), int):          # a protobuf timestamp, as older releases print it
        expiry = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(expiry['seconds']))
    return key, {'id': str(doc.get('id') or '')[:20], 'reusable': bool(doc.get('reusable')), 'ephemeral': bool(doc.get('ephemeral')),
                 'expiration': expiry[:40] if isinstance(expiry, str) else None}


def headscale_key(conn, v, args, run=None) -> dict:
    """The whole of `vault headscale-key`: the key is made on the server, read from ssh's output and stored as the secret
    args.name, replacing one of that name. What comes back has no key in it."""
    run = run or subprocess.run
    if not SECRET_NAME.fullmatch(args.name or ''):
        raise KeyError_('a secret name is letters, digits, . _ and -, up to 64')
    from . import secretstore
    try:
        secretstore.free_for(conn, args.name, 'secret')          # before a key is made on the server that could not be stored
    except secretstore.SecretError as exc:
        raise KeyError_(str(exc)) from None
    command = headscale_command(args.hs_user, args.expiration, args.reusable, args.ephemeral, args.tags, args.container)
    p = run(_ssh(conn, args) + [command], input=b'', capture_output=True, timeout=60)
    if p.returncode != 0:
        raise KeyError_(f'{args.host}: headscale made no key: {_tail(p.stderr)}')
    key, said = headscale_answer(p.stdout.decode(errors='replace'))
    del p
    try:
        secretstore.put_given(v, conn, args.name, key)           # a secret of that name keeps its policy
    except secretstore.SecretError as exc:
        raise KeyError_(str(exc)) from None
    del key
    return said


# ── the commands ──
def command(db, conn, v, args, audit) -> int:
    """`vault nebula-ca`, `nebula-issue`, `nebula-revoke`, `nebula-list` and `headscale-key`. audit(action, outcome, host, **detail)."""
    from .vault import VaultError, actor_name
    a, actor = args.vault_cmd, actor_name()
    try:
        if a == 'nebula-ca':
            made = ca_create(conn, v, args.name, actor, args.days, [n for n in (args.networks or '').split(',') if n])
            audit('vault.nebula_ca', 'ok', None, name=args.name, fingerprint=made['fingerprint'])
            print(f'Nebula CA {args.name}: its key is the vault key {made["key"]}, its certificate ends {time.strftime("%Y-%m-%d", time.gmtime(made["not_after"]))}', file=sys.stderr)
            print(made['certificate'], end='')
        elif a == 'nebula-issue':
            try:
                said = issue_to_host(conn, v, args, actor)
            except (KeyError_, nebulaca.CertificateError, VaultError):
                audit('vault.nebula_issue', 'failed', args.host, ca=args.ca)
                raise
            audit('vault.nebula_issue', 'ok', args.host, ca=args.ca, name=said['name'], address=said['networks'][0], fingerprint=said['fingerprint'])
            print(f'{args.host}: {DIR}/host.crt for {said["name"]} at {said["networks"][0]}, until {time.strftime("%Y-%m-%d", time.gmtime(said["not_after"]))}. '
                  f'Its key was made on the host and stays there. Now the nebula plan step writes the configuration and starts it')
        elif a == 'nebula-revoke':
            gone = revoke(conn, args.ca, args.name, actor)
            audit('vault.nebula_revoke', 'ok' if gone else 'failed', None, ca=args.ca, name=args.name, fingerprints=gone)
            if not gone:
                print(f'{args.ca} has no running certificate for {args.name}', file=sys.stderr)
                return 1
            print(f'revoked {len(gone)} certificate(s) of {args.name}. A host refuses them once the nebula plan step has run on it again: it writes the blocklist')
        elif a == 'nebula-list':
            now = time.time()
            for name, record in sorted(cas(conn).items()):
                print(f'{name}  {record["fingerprint"][:16]}  ends {time.strftime("%Y-%m-%d", time.gmtime(record["not_after"]))}  {", ".join(record["networks"]) or "any network"}')
                for i in record['issued']:
                    state = 'revoked' if i.get('revoked') else 'ended' if i['not_after'] <= now else 'runs'
                    print(f'    {i["name"]:<24} {i["address"]:<18} {i["fingerprint"][:16]}  until {time.strftime("%Y-%m-%d", time.gmtime(i["not_after"]))}  {state}')
        elif a == 'headscale-key':
            try:
                said = headscale_key(conn, v, args)
            except (KeyError_, VaultError):
                audit('vault.secret_add', 'failed', args.host, name=args.name, source='headscale')
                raise
            audit('vault.secret_add', 'ok', args.host, name=args.name, source='headscale', key_id=said['id'], reusable=said['reusable'], expiration=said['expiration'])
            print(f'stored secret {args.name}: a Headscale pre-auth key from {args.host}' + (f', good until {said["expiration"]}' if said['expiration'] else '')
                  + (', reusable' if said['reusable'] else ', for one machine') + f'. Send it with  storageforge-index vault send-secret {args.name} --host HOST')
        else:
            return 2
    except (KeyError_, nebulaca.CertificateError, VaultError) as exc:
        print(exc, file=sys.stderr)
        return 1
    return 0
