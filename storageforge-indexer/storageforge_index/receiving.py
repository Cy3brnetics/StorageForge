"""A btrfs or ZFS send between two hosts: each side a signed run on an enrolled host, and one narrow key between them.

    receiver, signed run   /etc/storageforge/receive/<id>.conf (tool, folder or dataset, retention) and a forced-command line for this
                           send's key in storageforge-deploy's authorized_keys: sudo -n storageforge-job --serve <id> "$SSH_ORIGINAL_COMMAND"
    sender, signed run     /etc/storageforge/sends/<id>.key (0600) and .hostkey (the receiver's key, as StorageForge pinned it)
    sender, the plan's or  btrfs send | ssh -i <key> storageforge-deploy@receiver "recv-receive <nonce> <name>"
      task's own script    and the receiver runs a fixed verb (scriptkit.RECEIVE_KIT) and keeps its own run record

No root key between the hosts, and no unsigned way: a receiver that is not enrolled is a crit in the check, and a deploy is refused.
A sender names a verb, a nonce and a snapshot. Where it lands and what retention may remove are in the signed conf.

What a send's id is made of: r<owner>-<hash>. The owner is c<plan>, t<task> or s<schedule>, so each deploy only touches its own, as
jobs do with p<plan>-. A plan's send and a one-off Run now end: the conf carries an expiry, and a signed --remove follows the run. A task or
schedule on a timer has nobody there when it fires, so its key stays until it is uninstalled: signed at install, as jobs are.

docs/security.md says what this does not stop.
"""
from __future__ import annotations

import hashlib
import json
import re
import shlex
import time

from .moves import find_host
from .scriptkit import SEND_KIT, need_line, one_line

KIND = 'sends'                     # deploy_runs and deployed: what this module's runs are called
ONE_OFF_SECONDS = 12 * 3600        # how long a plan's key can be used if the signed removal after it never runs
NAME_RE = re.compile(r'[A-Za-z0-9_][A-Za-z0-9_.:+-]{0,127}')       # what a snapshot may be called, to cross hosts: RECEIVE_KIT's recv_name_ok
PREFIX_RE = re.compile(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,39}')
DATASET_RE = re.compile(r'[A-Za-z0-9_][A-Za-z0-9_.:-]*(/[A-Za-z0-9_][A-Za-z0-9_.:-]*)+')
ADDRESS_RE = re.compile(r'[A-Za-z0-9_.:%-]{1,253}')
LOCAL, NOT_ENROLLED = 'local', 'none'


class NotEnrolled(ValueError):
    """A send's receiving host has no deploy access. hosts: who needs it."""

    def __init__(self, text: str, hosts: list[str]):
        super().__init__(text)
        self.hosts = hosts


def _deploy():
    from . import deploy        # deploy imports moves, and tasks and changes import this
    return deploy


def is_local(hs: dict, sender: dict | None, there: str) -> bool:
    if not there:
        return True
    other = find_host(hs, there.split('@')[-1])
    return bool(other and sender and other['id'] == sender['id'])


def receiver_of(hs: dict, there: str) -> dict | None:
    return find_host(hs, there.split('@')[-1]) if there else None


def enrol_steps(name: str, known: bool) -> str:
    """The exact steps, for the check and for a refused deploy."""
    q = shlex.quote(name)
    first = '' if known else f'1. Scan it, so StorageForge knows it: bind a scan key (Keys tab), then Scan, or storageforge-index scan --host {q}. '
    n = 1 if known else 2
    return (f'{name} is not enrolled, and a send reaches only an enrolled host: there is no unsigned way. To enrol it: {first}'
            f'{n}. Deploy tab, Set up… on {name}, with a sudo password. Or run storageforge-index deploy setup-script as root on it, then press I ran it: test. '
            f'{n + 1}. Check this again and deploy. No root key is needed between the hosts: remove any you made for sends')


def check(conn, hs: dict, sender: dict | None, there: str, tool: str, root: str, name: str | None = None, prefix: str | None = None) -> list[tuple[str, str]]:
    """What the plan and task checks say about a send's other side, as (level, text)."""
    out = []
    if tool == 'zfs' and root and ('/' in root and (not DATASET_RE.fullmatch(root) or '..' in root)):
        out.append(('crit', f'{root} is not a dataset a send can receive into'))
    if is_local(hs, sender, there):
        return out
    other = receiver_of(hs, there)
    if not other:
        return [*out, ('crit', enrol_steps(there.split('@')[-1], False))]
    if not _deploy().ready(conn, other['name']):
        return [*out, ('crit', enrol_steps(other['name'], True))]
    address = other['ssh_host'] or ''
    if address.startswith('127.'):
        out.append(('crit', f'{other["name"]} is at {address}, which only StorageForge can reach: another host cannot send to it. A remote node needs an address the sender can reach'))
    elif not ADDRESS_RE.fullmatch(address.strip('[]')):
        out.append(('crit', f'{other["name"]} has no address another host can use: scan it by a name or an address'))
    if name and not NAME_RE.fullmatch(name):
        out.append(('crit', f'{name} cannot go to another host: a snapshot sent between hosts starts with a letter, digit or _, and holds only those and . : + -'))
    if prefix and not PREFIX_RE.fullmatch(prefix):
        out.append(('crit', f'the prefix {prefix} cannot go to another host: it starts with a letter, digit or _, and holds only those and . -'))
    if '@' in there:
        out.append(('note', f'the login {there.split("@")[0]} is not used: a send logs in with its own key, which can do nothing but this send'))
    out.append(('ok', f'a signed run on {other["name"]} says what it may receive, and {sender["name"] if sender else "the sender"} sends with a key that can do nothing else. '
                      f'{other["name"]} keeps its own run record, and neither host needs a root key for the other'))
    return out


def grant_id(owner: str, sender: str, receiver: str, tool: str, root: str, prefix: str, keep: int, recursive: bool) -> str:
    """Two steps that send the same way to the same place are one send, and another retention is another send."""
    digest = hashlib.sha256('\0'.join((sender, receiver, tool, root, prefix, str(int(keep or 0)), str(bool(recursive)))).encode()).hexdigest()[:12]
    return f'r{owner}-{digest}'


def send(conn, hs: dict, sender: dict | None, sender_name: str, there: str, tool: str, root: str, owner: str, prefix: str = '', keep: int = 0, recursive: bool = False) -> dict:
    """One send, as scripts and deploys need it. local: it stays on the host, and none of the rest applies."""
    if is_local(hs, sender, there):
        return {'id': LOCAL, 'local': True, 'address': '', 'port': 22}
    name = sender['name'] if sender else sender_name
    other = receiver_of(hs, there)
    receiver = other['name'] if other else there.split('@')[-1]
    return {'id': grant_id(owner, name, receiver, tool, root, prefix, keep, recursive), 'local': False, 'tool': tool, 'sender': name, 'receiver': receiver, 'known': bool(other),
            'enrolled': bool(other) and _deploy().ready(conn, receiver), 'root': root, 'prefix': prefix, 'keep': int(keep or 0), 'recursive': bool(recursive),
            'address': ((other or {}).get('ssh_host') or '').strip('[]'), 'port': int((other or {}).get('ssh_port') or 22)}


def script_args(s: dict) -> tuple[str, str, int]:
    """(send id, address, port) as a script takes them. Nothing to reach a host with when it is not enrolled: the script says so and stops."""
    if s['local']:
        return LOCAL, '', 22
    return (s['id'], s['address'], s['port']) if s['enrolled'] else (NOT_ENROLLED, s['receiver'], 22)


def only_between_hosts(sends: list[dict]) -> list[dict]:
    """The sends that need anything from a deploy, each once."""
    return list({s['id']: s for s in sends if not s['local']}.values())


def receivers(sends: list[dict]) -> list[str]:
    """Who gets a signed run for these sends: for the audit row of a deploy."""
    return sorted({s['receiver'] for s in sends})


def conf_text(s: dict, expires: int) -> str:
    """Line by line, and read that way by RECEIVE_KIT: nothing here is ever run, whatever a path holds."""
    values = {'TOOL': s['tool'], 'ROOT': s['root'], 'PREFIX': s['prefix'], 'KEEP': int(s['keep']), 'RECURSIVE': int(bool(s['recursive'])), 'EXPIRES': int(expires), 'SENDER': one_line(s['sender'])}
    return f'# StorageForge: what send {s["id"]} may do on this host (its key\'s forced command)\n' + ''.join(f'{k}={v}\n' for k, v in values.items())


HEAD = r"""#!/usr/bin/env bash
# StorageForge sends of "@TITLE@", the @ROLE@ side, on @HOST@: generated @DATE@. Report by default, --apply to make it so, --remove to take them off.
set -uo pipefail
export LC_ALL=C PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
MODE=report
case ${1:-} in
  --apply) MODE=apply ;;
  --remove) MODE=remove ;;
  '') ;;
  *) echo "unknown option: $1 (--apply, --remove, or none to report)" >&2; exit 2 ;;
esac
APPLY=0; [[ $MODE == apply ]] && APPLY=1
PREFIX=@PREFIX@
KEYS=/var/lib/storageforge/deploy/.ssh/authorized_keys
SUMS=/var/lib/storageforge/managed/sends-$PREFIX.sha256
RECORDS=/var/lib/storageforge/receive
"""

# This host's part in what the deploy user's key file holds: every line of this owner's, and any conf whose time is up, whichever owner made it
KEY_FUNCS = r"""
set_key_lines() { # the lines this owner wants, or none
  [[ -f $KEYS ]] || { conflict "$KEYS is missing: set up deploy access on this host again"; return 1; }
  { grep -v -- "storageforge-job --serve $PREFIX" "$KEYS" || true; if [[ -n ${1:-} ]]; then printf '%s\n' "$1"; fi; } >"$KEYS.new"
  chown root:root "$KEYS.new"; chmod 0644 "$KEYS.new"; mv "$KEYS.new" "$KEYS"
}
sweep_ended() { # the key of a plan whose removal never ran is refused already: this takes it off
  local f id end now; now=$(date +%s)
  for f in /etc/storageforge/receive/*.conf; do
    [[ -e $f ]] || continue
    end=$(sed -n 's/^EXPIRES=//p' "$f"); id=$(basename "$f" .conf)
    [[ $end =~ ^[0-9]+$ ]] && ((end && end <= now)) || continue
    rm -f -- "$f"
    if [[ -f $KEYS ]]; then
      { grep -v -- "storageforge-job --serve $id " "$KEYS" || true; } >"$KEYS.new"
      chown root:root "$KEYS.new"; chmod 0644 "$KEYS.new"; mv "$KEYS.new" "$KEYS"
    fi
    info "removed $id, whose time was up"
  done
}
show_records() { # what this host kept of the sends of this owner: the own say of the receiving side
  local d
  for d in "$RECORDS/$PREFIX"*/; do
    [[ -r ${d}runs.jsonl ]] || continue
    section "what this host recorded for $(basename "$d")"
    tail -n 5 "${d}runs.jsonl"
  done
}
take_off() { # with no flags it says what it would take off, and changes nothing
  local f found=0
  show_records
  section "the sends of this plan on this host"
  for f in /etc/storageforge/receive/"$PREFIX"*.conf /etc/storageforge/sends/"$PREFIX"*.key /etc/storageforge/sends/"$PREFIX"*.hostkey; do
    [[ -e $f ]] || continue
    found=1
    if [[ $MODE == remove ]]; then rm -f -- "$f"; doing "removed $f"; else info "--remove takes off $f"; fi
  done
  if [[ $MODE == remove ]]; then rm -f -- "$SUMS"; fi
  if grep -q -- "storageforge-job --serve $PREFIX" "$KEYS" 2>/dev/null; then
    found=1
    if [[ $MODE == remove ]]; then set_key_lines '' && doing "the job keys of this plan may no longer log in"; else info "--remove stops the job keys of this plan logging in"; fi
  fi
  ((found)) || ok "nothing of this plan is here"
  echo; if ((PROBLEMS)); then echo "$PROBLEMS problem(s)"; exit 1; fi; echo "done"
  exit 0
}
"""

STALE = r"""
section "left over from before"
stale=0
for f in @PATTERNS@; do
  [[ -e $f ]] || continue
  printf '%s\n' "${WANT[@]-}" | grep -Fx -- "$f" >/dev/null && continue
  stale=1
  if ((APPLY)); then rm -f -- "$f"; doing "removed $f"; else missing "would remove $f"; fi
done
((stale)) || ok "nothing to remove"
"""

ENDING = 'echo\nif ((PROBLEMS)); then echo "$PROBLEMS problem(s)"; exit 1; fi\necho "done"\n'


def _head(prefix: str, title: str, host: str, role: str) -> str:
    from .jobs import HOST_FUNCS
    head = HEAD.replace('@TITLE@', one_line(title)).replace('@ROLE@', role).replace('@HOST@', one_line(host)).replace('@DATE@', time.strftime('%Y-%m-%d %H:%M')).replace('@PREFIX@', shlex.quote(prefix))
    return head + HOST_FUNCS + KEY_FUNCS + 'if [[ $MODE == remove ]]; then take_off; fi\n'


def receive_script(prefix: str, title: str, host: str, sends: list[dict], secrets_: dict | None, expires: int = 0) -> str:
    """The signed run on a receiving host: what each send may do here, and its key's forced command. With no flags it only reports."""
    from .deploy import JOBBIN
    from .jobs import _heredoc
    from .jobscript import JOB_SCRIPT
    q = shlex.quote
    parts = [_head(prefix, title, host, 'receiving'), 'section "tools"\n']
    if any(s['tool'] == 'btrfs' for s in sends):
        parts.append(need_line('btrfs-progs'))
    if any(s['tool'] == 'zfs' for s in sends):
        parts.append('need zfs "ZFS receive"\n')
    parts.append('if [[ ! -e /etc/sudoers.d/storageforge-deploy ]] || grep -Fq -- "--serve" /etc/sudoers.d/storageforge-deploy; then ok "job keys may start storageforge-job --serve"\n'
                 'else conflict "the sudoers file here lets no job key start storageforge-job --serve: run Set up again on this host"; fi\n')
    parts.append('section "storageforge-job"\n' + _heredoc(f'want_file {JOBBIN} 0755', JOB_SCRIPT))
    keylines = []
    for s in sends:
        parts.append(f'section {q("receives for " + s["sender"] + " into " + s["root"] + " (" + s["id"] + ")")}\n')
        if s['tool'] == 'btrfs':
            parts.append(f'if [[ -d {q(s["root"])} ]]; then ok {q("folder " + s["root"])}; else info {q("the first send makes " + s["root"])}; fi\n')
        else:
            parent = s['root'].rsplit('/', 1)[0]
            parts.append(f'if zfs list -H -o name -- {q(s["root"])} >/dev/null 2>&1; then ok {q("dataset " + s["root"])}\n'
                         f'elif zfs list -H -o name -- {q(parent)} >/dev/null 2>&1; then info {q("the first send makes " + s["root"])}\n'
                         f'else conflict {q("there is no dataset " + parent + " to receive under")}; fi\n')
        parts.append(_heredoc(f'want_file {q("/etc/storageforge/receive/" + s["id"] + ".conf")} 0644', conf_text(s, expires)))
        if s['keep'] and s['prefix']:
            parts.append(f'info {q("retention here: the newest " + str(s["keep"]) + " of " + s["prefix"] + "-*. The sender cannot change that")}\n')
        else:
            parts.append('info "retention here: none, so the key of this send can remove no finished copy"\n')
        if secrets_:
            keylines.append(f'restrict,command="sudo -n {JOBBIN} --serve {s["id"]} \\"$SSH_ORIGINAL_COMMAND\\"" {secrets_[s["id"]]["pub"]} storageforge:recv:{s["id"]}\n')
    parts.append(STALE.replace('@PATTERNS@', '/etc/storageforge/receive/"$PREFIX"*.conf'))
    parts.append('show_records\n')
    parts.append(_heredoc('KEYLINES=$(cat', ''.join(keylines)) + ')\n' if keylines else "KEYLINES=''\n")
    parts.append('if ((APPLY)); then\n'
                 '  section "the job keys of this plan, in the authorized_keys of storageforge-deploy"\n'
                 '  sweep_ended\n'
                 '  set_key_lines "$KEYLINES" && ok "$(printf \'%s\' "$KEYLINES" | grep -c . || true) job key(s), each able to start only its own send"\n'
                 '  # the job records on this host name the program as it was: a newer copy from a signed run is no change by hand\n'
                 f'  sum=$(sha256sum {JOBBIN} 2>/dev/null | cut -d" " -f1)\n'
                 f'  if [[ -n $sum ]]; then for f in "$MANAGED"/jobs-*.sha256; do [[ -e $f ]] && sed -i "s|^[0-9a-f]\\{{64\\}}  {JOBBIN}\\$|$sum  {JOBBIN}|" "$f"; done; fi\n'
                 '  mkdir -p "$MANAGED"; chmod 0755 "$MANAGED"\n'
                 '  confs=(); for f in "${WANT[@]-}"; do if [[ $f == /etc/storageforge/receive/* ]]; then confs+=("$f"); fi; done\n'
                 '  if ((${#confs[@]})); then sha256sum "${confs[@]}" >"$SUMS"; chmod 0644 "$SUMS"; else rm -f "$SUMS"; fi\n'
                 'fi\n' + ENDING)
    return ''.join(parts)


def send_script(prefix: str, title: str, host: str, sends: list[dict], secrets_: dict | None, pins: dict) -> str:
    """The signed run on a sending host: each send's key and the receiver's pinned host key. Apart from the plan's or task's script, because a
    task copies itself to disk when it is installed, and a private key must not go with it. pins: {send id: known_hosts lines}."""
    from .jobs import _heredoc
    q = shlex.quote
    parts = [_head(prefix, title, host, 'sending'), 'section "tools"\nneed ssh "the OpenSSH client"\n']
    for s in sends:
        key, known = f'/etc/storageforge/sends/{s["id"]}.key', f'/etc/storageforge/sends/{s["id"]}.hostkey'
        parts.append(f'section {q("sends to " + s["receiver"] + ":" + s["root"] + " (" + s["id"] + ")")}\n')
        if secrets_:
            parts.append(_heredoc(f'secret_file {q(key)}', secrets_[s['id']]['key']))
            parts.append(_heredoc(f'want_file {q(known)} 0644', pins[s['id']]))
        else:
            parts.append(f'WANT+=({q(key)} {q(known)})\n'
                         f'if [[ -e {q(key)} ]]; then ok "job key present (apply makes a new one)"; else missing "would write the job key of this send"; fi\n')
    parts.append(STALE.replace('@PATTERNS@', '/etc/storageforge/sends/"$PREFIX"*.key /etc/storageforge/sends/"$PREFIX"*.hostkey'))
    probes = ''.join(f'  send_to {q(s["tool"])} {q(s["id"])} {q(s["address"])} {int(s["port"])} {q(s["root"])}\n'
                     f'  if out=$(there recv-probe 2>&1); then ok {q("this key reaches " + s["receiver"])}\n'
                     f'  else conflict {q("this key does not reach " + s["receiver"] + ": ")}"${{out:0:300}}"; fi\n' for s in sends)
    parts.append(SEND_KIT + 'if ((APPLY)); then\n  section "does each key work?"\n' + probes + 'fi\n' + ENDING)
    return ''.join(parts)


def _pins(sends: list[dict]) -> dict:
    """The receiver's host key as StorageForge pinned it. A deploy with no pin is refused: a stranger holding the address would get the data."""
    from .jobs import pinned_key
    pins = {}
    for s in sends:
        pins[s['id']] = pinned_key({'ssh_host': s['address'], 'ssh_port': s['port']})
        if not pins[s['id']]:
            raise ValueError(f'no pinned SSH host key for {s["receiver"]} at {s["address"]}: scan it first, so its key is pinned and a stranger holding that address cannot receive this')
    return pins


def items(db, conn, sends: list[dict], owner: str, mode: str, actor: str, title: str, *, one_off: bool = False, remove: bool = False) -> tuple[list[dict], list[dict]]:
    """deploy.start_group items around a plan's or task's own: (what goes before them, what goes after). They take no phase, so they run in order:
    receivers before senders, whose script tries each key. one_off: a plan, whose key goes when it ends. remove: take everything off."""
    from .jobs import new_secrets
    deploy = _deploy()
    sends = only_between_hosts(sends)
    prefix = f'r{owner}-'
    before_hosts = {d['host'] for d in deploy.deployed(conn, kind=KIND) if d['ref'] == prefix}
    used = {h for s in sends for h in (s['sender'], s['receiver'])}
    if remove:
        return [], _removals(db, conn, sorted(before_hosts | used), prefix, actor, title)
    if mode == 'apply':
        missing = [s for s in sends if not s['enrolled']]
        if missing:
            raise NotEnrolled(' '.join(enrol_steps(s['receiver'], s['known']) for s in missing), sorted({s['receiver'] for s in missing}))
    else:                # a report runs where it can, and the sender's script says the rest
        sends = [s for s in sends if s['enrolled']]
        return [_item(conn, h, receive_script(prefix, title, h, [s for s in sends if s['receiver'] == h], None), [], prefix, mode) for h in sorted({s['receiver'] for s in sends})] + \
            [_item(conn, h, send_script(prefix, title, h, [s for s in sends if s['sender'] == h], None, {}), [], prefix, mode) for h in sorted({s['sender'] for s in sends})], []
    gone = _removals(db, conn, sorted(before_hosts - used), prefix, actor, title)            # hosts this owner no longer uses
    if not sends:
        return gone, []
    pins, secrets_ = _pins(sends), new_secrets(sends)
    expires = int(time.time()) + ONE_OFF_SECONDS if one_off else 0
    digest = hashlib.sha256(json.dumps([[s[k] for k in ('id', 'tool', 'root', 'prefix', 'keep', 'recursive')] for s in sends]).encode()).hexdigest()[:16]

    def mark(host):        # a plan's send ends with it: only what stays on a host is remembered as being there
        def hook(_res):
            c = db.connect()
            try:
                deploy.mark_deployed(c, host, KIND, prefix, digest, {'name': title, 'sends': [s['id'] for s in sends if host in (s['sender'], s['receiver'])]}, actor)
            finally:
                c.close()
        return hook
    extra = (lambda host: {}) if one_off else (lambda host: {'on_ok': mark(host)})
    first = [{**_item(conn, h, receive_script(prefix, title, h, [s for s in sends if s['receiver'] == h], secrets_, expires), ['--apply'], prefix, mode), **extra(h)} for h in sorted({s['receiver'] for s in sends})]
    then = [{**_item(conn, h, send_script(prefix, title, h, [s for s in sends if s['sender'] == h], secrets_, pins), ['--apply'], prefix, mode), **extra(h)} for h in sorted({s['sender'] for s in sends})]
    return gone + first + then, _removals(db, conn, sorted(used), prefix, actor, title) if one_off else []


def _item(conn, host: str, script: str, args: list[str], prefix: str, mode: str) -> dict:
    from . import site
    return {'host': host, 'script': site.stamp(conn, script), 'args': args, 'kind': KIND, 'ref': prefix, 'mode': mode}


def _removals(db, conn, hosts_: list[str], prefix: str, actor: str, title: str) -> list[dict]:
    """A signed --remove on each host still set up: one that lost its deploy access has nothing StorageForge can reach."""
    deploy = _deploy()

    def forgotten(host):
        def hook(_res):
            c = db.connect()
            try:
                c.execute('DELETE FROM deployed WHERE host = :h AND kind = :k AND ref = :r', {'h': host, 'k': KIND, 'r': prefix})
            finally:
                c.close()
        return hook
    return [{**_item(conn, h, _head(prefix, title, h, 'removal') + 'take_off\n', ['--remove'], prefix, 'apply'), 'on_ok': forgotten(h)} for h in hosts_ if deploy.ready(conn, h)]
