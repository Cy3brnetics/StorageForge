"""The secret store (roadmap section 5): secrets StorageForge generates for plan steps, shown once, delivered to a host through the
signed runner's stdin, and rotated.

    make         a new value of a kind (password, token, hex, pin, wireguard) and length, sealed in the vault, inside the key
                 enclave when it is configured, with the policy it is bound by (a step, a host, a platform). The value is given back
                 this once, to show; nothing lists it again.
    a plan run   a step that names a vault secret (tailscale, netbird, cloudflared...) gets it on the runner's stdin in an apply,
                 after the signed request: released for that host and that step, so a policy that names others refuses it and the
                 enclave writes the release into the audit log. The script writes it to /run/storageforge/secrets/NAME (memory, mode
                 600), where the step reads it, as it reads what `vault send-secret` writes there.
    rotate       a new value, sent the same way to every host the secret was delivered to, into NAME.next; only when every host
                 has it is the vault row replaced and NAME.next moved over NAME. A host that does not take it leaves the old value in
                 place everywhere, as `rotate` leaves an SSH key when one host does not take the new one.

What it never does: put a value on a command line, in a plan, a script, a playbook, an export, deploy_runs output, a log line or an
audit row. The tests search each of those for the value.

The rows are device_credentials rows with the username 'secret', as `vault secret-add` has stored them since 0.5.0: one store, one
sealing, one rewrap when the vault key rotates. Columns added in migration 063 say how a row was made; secret_deliveries says where it
went.
"""
from __future__ import annotations

import base64
import json
import re
import secrets
import string
import time

from .vault import NotReleased, StepUpNeeded, VaultError, VaultLocked, present_token, presented_token

NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,63}')
SECRET_DIR = '/run/storageforge/secrets'
USERNAME = 'secret'                     # what marks a row of device_credentials as a step's secret, since vault secret-add
MARK = 'SF-SECRETS 1'

# kind: (what it is made of, alphabet, default length, shortest, longest). wireguard is 32 random bytes in base64, as wg genkey
# prints a private key: its length is fixed.
_SYMBOLS = '-_.,:+=@%'                  # none that a shell, a URL, an INI or a YAML file would take for syntax: no quotes, $, #, \ or space
KINDS = {
    'password': ('letters, digits and - _ . , : + = @ %, at least one of each', string.ascii_letters + string.digits + _SYMBOLS, 24, 12, 128),
    'token': ('letters and digits', string.ascii_letters + string.digits, 40, 16, 256),
    'hex': ('0 to 9 and a to f', '0123456789abcdef', 64, 16, 256),
    'pin': ('digits', string.digits, 8, 6, 32),
    'wireguard': ('a WireGuard private key: 32 random bytes in base64', '', 44, 44, 44),
}


class SecretError(ValueError):
    pass


def kinds() -> list[dict]:
    return [{'kind': k, 'made_of': v[0], 'length': v[2], 'min': v[3], 'max': v[4]} for k, v in KINDS.items()]


def length_of(kind: str, length) -> int:
    if kind not in KINDS:
        raise SecretError(f'kind is one of {", ".join(KINDS)}')
    _, _, default, lo, hi = KINDS[kind]
    if length in (None, ''):
        return default
    try:
        n = int(length)
    except (TypeError, ValueError):
        raise SecretError('the length is a whole number') from None
    if not lo <= n <= hi:
        raise SecretError(f'a {kind} is {lo} characters long' if lo == hi else f'a {kind} is {lo} to {hi} characters long')
    return n


def generate(kind: str, length=None) -> str:
    """A new value from the operating system's random source. A password has a lower-case and an upper-case letter, a digit and a
    symbol: values without are drawn again, so each value that has them is as likely as any other."""
    n = length_of(kind, length)
    if kind == 'wireguard':
        return base64.b64encode(secrets.token_bytes(32)).decode()
    alphabet = KINDS[kind][1]
    while True:
        value = ''.join(secrets.choice(alphabet) for _ in range(n))
        if kind != 'password' or all(any(c in group for c in value) for group in (string.ascii_lowercase, string.ascii_uppercase, string.digits, _SYMBOLS)):
            return value


# ── the store ────────────────────────────────────────────────────────
def _row(conn, name: str) -> dict | None:
    rows = conn.all("""SELECT name, created_at, value_rotated_at, policy_json, secret_kind, secret_length, secret_origin, rotated_at
                       FROM device_credentials WHERE name = :n AND username = :u""", {'n': name, 'u': USERNAME})
    if not rows:
        return None
    r = rows[0]
    return {'name': r[0], 'created_at': r[1], 'value_rotated_at': r[2], 'policy': json.loads(r[3]) if r[3] else None,
            'kind': r[4], 'length': r[5], 'origin': r[6] or ('generated' if r[4] else 'given'), 'rewrapped_at': r[7]}


def meta(conn, name: str) -> dict | None:
    """How a step's secret was made, and its policy. Never its value."""
    return _row(conn, name)


def made_of(row: dict | None) -> dict:
    """What store_credential keeps beside a value, to keep it when the row is sealed again (a policy change, a rotation)."""
    row = row or {}
    return {'kind': row.get('kind'), 'length': row.get('length'), 'origin': row.get('origin') or 'given', 'created_at': row.get('created_at'),
            'rotated_at': row.get('value_rotated_at')}


def listing(conn) -> list[dict]:
    """Every step's secret with where it went. No value: there is none to give."""
    went: dict[str, list] = {}
    for name, host, step, how, first, last in conn.all('SELECT name, host, step, how, first_at, last_at FROM secret_deliveries ORDER BY name, host'):
        went.setdefault(name, []).append({'host': host, 'step': step, 'how': how, 'first_at': first, 'last_at': last})
    out = []
    for (name,) in conn.all('SELECT name FROM device_credentials WHERE username = :u ORDER BY name', {'u': USERNAME}):
        row = _row(conn, name)
        out.append({**row, 'delivered': went.get(name, [])})
    return out


def make(v, conn, name: str, kind: str, length=None, policy: dict | None = None) -> tuple[dict, str]:
    """A new secret: (what is stored about it, the value). The value goes back to whoever asked, once, and is not kept anywhere
    but the vault. A name in use is refused: an existing secret changes by rotation, which knows where it was sent."""
    if not NAME.fullmatch(name or ''):
        raise SecretError('a secret name is letters, digits, dot, dash and underscore, up to 64, starting with a letter or digit')
    n = length_of(kind, length)
    if conn.scalar('SELECT COUNT(*) FROM device_credentials WHERE name = :n', {'n': name}):
        raise SecretError(f'there is already a secret or device credential named {name}: rotate it, or remove it first')
    value = generate(kind, n)
    v.store_credential(name, USERNAME, value, policy=policy, made={'kind': kind, 'length': n, 'origin': 'generated'})
    return _row(conn, name), value


def remove(conn, name: str) -> int:
    """The secret and the record of where it went. Copies already on hosts stay until they reboot (/run is memory) or a step removes them."""
    if not _row(conn, name):
        return 0
    with conn.tx():
        conn.execute('DELETE FROM secret_deliveries WHERE name = :n', {'n': name})
        n = conn.execute('DELETE FROM device_credentials WHERE name = :n AND username = :u', {'n': name, 'u': USERNAME}).rowcount
    return n


def delivered(conn, name: str, host: str, step: str, how: str) -> None:
    now = int(time.time())
    with conn.tx():
        if conn.scalar('SELECT COUNT(*) FROM secret_deliveries WHERE name = :n AND host = :h', {'n': name, 'h': host}):
            conn.execute('UPDATE secret_deliveries SET step = :s, how = :w, last_at = :t WHERE name = :n AND host = :h',
                         {'n': name, 'h': host, 's': step or '', 'w': how, 't': now})
        else:
            conn.execute('INSERT INTO secret_deliveries (name, host, step, how, first_at, last_at) VALUES (:n, :h, :s, :w, :t, :t)',
                         {'n': name, 'h': host, 's': step or '', 'w': how, 't': now})


# ── delivery to a plan step, on the runner's stdin ───────────────────
def secret_fields(spec: dict) -> list[str]:
    """The fields of a step type that name a vault secret: kind 'secret', or the field called secret that the tailscale, netbird,
    ziti, cloudflared and newt steps have."""
    return [f['name'] for f in spec.get('fields', []) if f.get('kind') == 'secret' or (f['name'] == 'secret' and f.get('kind') == 'name')]


def plan_secrets(conn, plan: dict) -> dict[str, list[tuple[str, str]]]:
    """host name -> [(secret, step kind)] that the plan's apply delivers. A step that leaves (state absent) needs no secret."""
    from . import changes
    from .moves import find_host, hosts
    hs, out = hosts(conn), {}
    for t in changes.normalize(plan)['tasks']:
        spec = changes.TYPES.get(t['type']) or {}
        if t['params'].get('state') == 'absent':
            continue
        for field in secret_fields(spec):
            name = str(t['params'].get(field) or '')
            if not NAME.fullmatch(name):
                continue
            h = find_host(hs, t['host'])
            want = (name, t['type'])
            got = out.setdefault(h['name'] if h else t['host'], [])
            if want not in got:
                got.append(want)
    return out


def _why(exc: Exception) -> str:
    text = ('its policy does not name this host or step' if isinstance(exc, NotReleased) else
            'it is marked sensitive and takes a step-up' if isinstance(exc, StepUpNeeded) else
            'the vault is locked' if isinstance(exc, VaultLocked) else str(exc))
    return re.sub(r'[^A-Za-z0-9 ,.:()-]', '', text)[:160] or 'refused'


def payload(pairs) -> bytes:
    """What the script reads on stdin: the mark, NAME BASE64 per secret, END. A refusal is a REFUSED line with why, to show in the run."""
    lines = [MARK]
    for name, value in pairs:
        lines.append(f'REFUSED {name} {value.why}' if isinstance(value, Refused) else f'{name} ' + base64.b64encode((value + '\n').encode()).decode())
    return ('\n'.join(lines) + '\nEND\n').encode()


class Refused:
    def __init__(self, why: str):
        self.why = why


def stream(db, host: str, wants: list[tuple[str, str]], token: str | None = None):
    """deploy.run's data for one host: a generator, so nothing is released until the run starts and the signed request has gone
    first. Each secret is released for this host and its step, which the enclave checks against the secret's policy and writes up."""
    from .vault import Vault

    def gen():
        present_token(token)
        conn = db.connect()
        pairs = []
        try:
            try:
                v = Vault(db, conn).unlock()
            except VaultError as exc:
                pairs = [(name, Refused(_why(exc))) for name, _ in wants]
            else:
                with v:
                    for name, step in wants:
                        try:
                            pairs.append((name, v.credential(name, host=host, step=step)['password']))
                        except VaultError as exc:
                            pairs.append((name, Refused(_why(exc))))
                            continue
                        delivered(conn, name, host, step, 'plan')
            data = payload(pairs)
            pairs.clear()
            yield data
        finally:
            conn.close()
            present_token(None)
    return gen()


def items_data(db, conn, plan: dict, mode: str) -> dict[str, dict]:
    """host -> {'data': ...} for changes.deploy_items: an apply carries the secrets its steps name, a report carries none."""
    if mode != 'apply':
        return {}
    token = presented_token()
    return {h: {'data': stream(db, h, wants, token)} for h, wants in plan_secrets(conn, plan).items()}


# Read before the first step of a plan script, in an apply that a signed run started with --secrets-stdin: a downloaded script never
# reads its stdin (run as curl | bash, that is the script itself), and finds the secret files vault send-secret wrote. Each value goes from stdin through base64 into a file under umask 077:
# printf is a shell builtin and base64 reads a pipe, so the value is on no command line, and nothing here prints it.
# No apostrophes: the script text is checked for values that could end a quoted word.
BASH = r"""
sf_secrets_in() { local line name b64 d=/run/storageforge/secrets n=0
  ((EUID != 0)) && d=${SF_SECRET_DIR:-$d}
  [[ -t 0 ]] && return 0
  IFS= read -r -t 10 line || return 0
  [[ $line == "SF-SECRETS 1" ]] || return 0
  (umask 077; mkdir -p "$d") && chmod 700 "$d" || { conflict "could not make $d for the secrets this plan needs"; return 0; }
  while IFS=" " read -r -t 10 name b64; do
    [[ $name == END ]] && break
    if [[ $name == REFUSED ]]; then conflict "StorageForge did not release the secret ${b64%% *} for this host: ${b64#* }"; continue; fi
    if [[ ! $name =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$ || ! $b64 =~ ^[A-Za-z0-9+/]+=*$ ]]; then conflict "a secret on stdin was not in the expected form: skipped"; continue; fi
    if (umask 077; printf "%s\n" "$b64" | base64 -d >"$d/$name.part") && mv -f -- "$d/$name.part" "$d/$name"; then n=$((n + 1))
    else rm -f -- "$d/$name.part"; conflict "could not write the secret $name in $d"; fi
  done
  b64=
  ((n)) && info "$n secret(s) from StorageForge written to $d (mode 600, in memory: gone at reboot)"
  return 0
}
((APPLY && ${SECRETS_STDIN:-0})) && sf_secrets_in
"""


# ── rotation ─────────────────────────────────────────────────────────
# One signed run per host and phase. stage: the new value from stdin into NAME.next, only where NAME is (a step that removed it after
# use, as tailscale does, has nothing to replace). commit: NAME.next over NAME. discard: NAME.next removed.
ROTATE_SCRIPT = r"""#!/bin/bash
# Written by StorageForge: one phase of a secret rotation. The new value comes on stdin; it is on no command line and in no output.
set -euo pipefail
name=${1:-} phase=${2:-} d=/run/storageforge/secrets
((EUID != 0)) && d=${SF_SECRET_DIR:-$d}
[[ $name =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$ ]] || { echo "not a secret name"; exit 2; }
f=$d/$name
case $phase in
  stage)
    IFS= read -r line || { echo "nothing on stdin"; exit 1; }
    [[ $line == "SF-SECRETS 1" ]] || { echo "stdin is not a secret from StorageForge"; exit 1; }
    IFS=" " read -r got b64 || { echo "no secret on stdin"; exit 1; }
    [[ $got == "$name" && $b64 =~ ^[A-Za-z0-9+/]+=*$ ]] || { echo "the secret on stdin is not $name"; exit 1; }
    if [[ ! -e $f ]]; then b64=; echo "SF-SECRET absent: $f is not on this host, so there is nothing to replace"; exit 0; fi
    (umask 077; printf "%s\n" "$b64" | base64 -d >"$f.next")
    b64=
    echo "SF-SECRET staged: the new value is in $f.next" ;;
  commit)
    if [[ ! -e $f.next ]]; then echo "SF-SECRET nothing staged"; exit 0; fi
    mv -f -- "$f.next" "$f"
    echo "SF-SECRET switched: $f holds the new value" ;;
  discard)
    rm -f -- "$f.next"
    echo "SF-SECRET discarded" ;;
  *) echo "the phase is stage, commit or discard"; exit 2 ;;
esac
"""


def rotate_plan(conn, name: str) -> dict:
    """What a rotation would do, changing nothing: the hosts it sends the new value to, and whether each can be reached by a signed run."""
    from . import deploy
    row = _row(conn, name)
    if not row:
        raise LookupError(f'no secret named {name}')
    hosts = []
    for d in conn.all('SELECT host, step, how, last_at FROM secret_deliveries WHERE name = :n ORDER BY host', {'n': name}):
        try:
            ready = deploy.ready(conn, deploy.canonical(conn, d[0]))
        except Exception:
            ready = False
        hosts.append({'host': d[0], 'step': d[1], 'how': d[2], 'last_at': d[3], 'ready': bool(ready),
                      'why': '' if ready else f'{d[0]} is not set up for deploys, so a signed run cannot bring it the new value'})
    blocked = [h['why'] for h in hosts if not h['ready']]
    if row['origin'] != 'generated':
        note = 'a secret a person gave is rotated with a new value given the same way (vault secret-rotate NAME --given)'
    else:
        note = f'a new {row["kind"]} of {row["length"]} characters'
    return {'name': name, 'kind': row['kind'], 'origin': row['origin'], 'hosts': hosts, 'blocked': blocked, 'note': note}


def _phase(db, host: str, name: str, phase: str, actor: str, data=None) -> dict:
    from . import deploy
    res = deploy.run(db, host, ROTATE_SCRIPT, [name, phase], kind='secrets', ref=f'rotate {name}: {phase}', mode='apply', actor=actor,
                     data=data, timeout=120)
    out = res.get('output') or ''
    said = next((line.split(':', 1)[0].split(' ', 1)[1] for line in out.splitlines() if line.startswith('SF-SECRET ')), '')
    return {'ok': res['status'] in deploy.FINISHED and bool(said), 'said': said, 'run_id': res.get('run_id')}


def rotate(db, conn, v, name: str, actor: str, value: str | None = None) -> dict:
    """A new value for this secret, everywhere it went, or nowhere. Back comes what happened on each host and, when it rotated, the new
    value, once. value: a person's new value for a secret they gave; a generated one gets a new value made here."""
    plan = rotate_plan(conn, name)
    row = _row(conn, name)
    if plan['blocked']:
        return {**plan, 'rotated': False, 'why': '; '.join(plan['blocked'])}
    if row['origin'] == 'generated':
        if value is not None:
            raise SecretError('a generated secret gets its new value here: give none')
        new = generate(row['kind'], row['length'])
    else:
        if not value or '\n' in value or len(value) > 4096:
            raise SecretError(plan['note'])
        new = value
    data = payload([(name, new)])
    staged, results = [], []
    for h in plan['hosts']:
        got = _phase(db, h['host'], name, 'stage', actor, data)
        results.append({'host': h['host'], 'stage': got['said'] or 'failed', 'run_id': got['run_id']})
        if not got['ok']:
            for back in staged:
                _phase(db, back, name, 'discard', actor)
            return {**plan, 'rotated': False, 'results': results,
                    'why': f'{h["host"]} did not take the new value: nothing changed, and the old value stays everywhere'}
        if got['said'] == 'staged':
            staged.append(h['host'])
    del data
    try:
        v.store_credential(name, USERNAME, new, policy=row['policy'], made={**made_of(row), 'rotated_at': int(time.time())})
    except Exception:
        for back in staged:
            _phase(db, back, name, 'discard', actor)
        raise
    for r in results:
        if r['host'] in staged:
            got = _phase(db, r['host'], name, 'commit', actor)
            r['commit'] = (got['said'] or 'failed') if got['ok'] else 'failed'
            if r['commit'] == 'switched':
                delivered(conn, name, r['host'], next(h['step'] for h in plan['hosts'] if h['host'] == r['host']), 'rotate')
    late = [r['host'] for r in results if r.get('commit') not in (None, 'switched')]
    return {**plan, 'rotated': True, 'results': results, 'value': new if row['origin'] == 'generated' else None,
            'why': (f'the vault holds the new value; {", ".join(late)} still has the old one in place and the new one beside it: '
                    'the next apply of a plan with this step delivers it') if late else ''}
