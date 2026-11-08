"""The tailscale plan step: install Tailscale and join a tailnet with an auth key from the vault, or leave it.

The key is never in the plan, the script or a log. It is a vault secret (`vault secret-add`), written to the host by
`vault send-secret` into /run/storageforge/secrets/<name> (memory, mode 600), and tailscale reads it from there itself
(`--auth-key=file:...`), so it is on no command line either. Once the node has joined, the file is removed: the node
keeps a key of its own, and a reusable auth key left behind would let anyone with root there join other machines.

Tailscale is installed with its own install script, which adds its package source and signing key: the one step that
adds a package source, because it says so and that is all it is for.
"""
from __future__ import annotations

import re
import shlex

from . import changes
from .changes import F

NAME = re.compile(r'[A-Za-z0-9_.-]{1,64}')
TAGS = re.compile(r'tag:[a-z0-9][a-z0-9-]{0,62}(,tag:[a-z0-9][a-z0-9-]{0,62}){0,9}')
HOSTNAME = re.compile(r'[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?')
SECRET_DIR = '/run/storageforge/secrets'
ARGS = ('secret', 'tags', 'hostname', 'accept_routes', 'ssh', 'state')

# No apostrophes: the script text is checked for values that could end a quoted word.
BASH = r"""
ts_state() { tailscale status --json 2>/dev/null | sed -n "s/.*\"BackendState\": *\"\([A-Za-z]*\)\".*/\1/p" | head -n 1; }
t_tailscale() { local secret=$1 tags=$2 name=$3 routes=$4 tsssh=$5 state=${6:-present} f st inst ip args=()
  f=/run/storageforge/secrets/$secret
  if [[ $state == absent ]]; then
    command -v tailscale >/dev/null || { ok "Tailscale is not installed"; return 0; }
    [[ $(ts_state) == Running ]] || { ok "not on a tailnet"; return 0; }
    act "tailscale logout (the package stays)" && try tailscale logout && ok "left the tailnet"
    return 0
  fi
  if ! command -v tailscale >/dev/null; then
    act "install Tailscale with its own script (https://tailscale.com/install.sh), which adds its package source and signing key" || {
      [[ -r $f ]] || missing "then it needs the auth key at $f: storageforge-index vault send-secret $secret --host $(uname -n)"; return 0; }
    inst=$(mktemp) || { conflict "could not make a temporary file"; return 0; }
    if ! curl -fsSL --retry 3 -o "$inst" https://tailscale.com/install.sh; then rm -f "$inst"; conflict "could not download https://tailscale.com/install.sh"; return 0; fi
    if ! sh "$inst" >"$inst.log" 2>&1; then conflict "the Tailscale install script failed: $(tail -n 2 "$inst.log" | tr "\n" " ")"; rm -f "$inst" "$inst.log"; return 0; fi
    rm -f "$inst" "$inst.log"
    command -v tailscale >/dev/null || { conflict "the install script ran, and there is no tailscale command"; return 0; }
    ok "installed $(tailscale version 2>/dev/null | head -n 1)"
  fi
  if command -v systemctl >/dev/null && [[ -d /run/systemd/system ]] && ! systemctl is-active --quiet tailscaled; then
    act "systemctl enable --now tailscaled" && { try systemctl enable --now tailscaled >/dev/null 2>&1 || return 0; }
  elif command -v rc-service >/dev/null && ! rc-service tailscale status >/dev/null 2>&1; then
    act "rc-update add tailscale default, and start it" && { rc-update add tailscale default >/dev/null 2>&1; try rc-service tailscale start >/dev/null || return 0; }
  fi
  st=$(ts_state)
  if [[ $st == Running ]]; then
    ok "on a tailnet already, as $(tailscale ip -4 2>/dev/null | head -n 1): left as it is (state absent, then present, joins again)"
    [[ -e $f ]] && rm -f -- "$f" && info "removed the auth key file it no longer needs"
    return 0
  fi
  if [[ ! -r $f ]]; then
    if ((APPLY)); then conflict "no auth key at $f: storageforge-index vault send-secret $secret --host $(uname -n), then run this again"
    else missing "it needs the auth key at $f: storageforge-index vault send-secret $secret --host $(uname -n)"; fi
    return 0
  fi
  # --reset: the flags here are all of it. Without it tailscale keeps settings an earlier attempt left, and refuses an up
  # that does not repeat them all
  args=(--reset "--auth-key=file:$f")
  [[ -n $name ]] && args+=("--hostname=$name")
  [[ -n $tags ]] && args+=("--advertise-tags=$tags")
  [[ -n $routes ]] && args+=(--accept-routes)
  [[ -n $tsssh ]] && args+=(--ssh)
  act "tailscale up ${args[*]}" || return 0
  if ! out=$(tailscale up "${args[@]}" --timeout=90s 2>&1); then conflict "tailscale up failed: $(tail -n 2 <<<"$out" | tr "\n" " ")"; return 0; fi
  rm -f -- "$f"
  ip=$(tailscale ip -4 2>/dev/null | head -n 1)
  ok "joined the tailnet as ${ip:-an address not known yet}; the auth key file is removed, as the node keeps a key of its own"
}
"""


def _check(conn, c, h, p, say):
    if not NAME.fullmatch(p['secret']):
        say('crit', f'{p["secret"]} is not a secret name: letters, digits, . _ and -')
        return
    if p['tags'] and not TAGS.fullmatch(p['tags']):
        say('crit', 'tags are tag:name, separated by commas, up to 10')
    if p['hostname'] and not HOSTNAME.fullmatch(p['hostname']):
        say('crit', f'{p["hostname"]} is not a Tailscale machine name: lower-case letters, digits and -')
    if p['state'] == 'absent':
        say('note', 'logs out of the tailnet; Tailscale stays installed')
        return
    say('note', f'the auth key is read on {h["name"]} from {SECRET_DIR}/{p["secret"]}: before running, '
                f'storageforge-index vault send-secret {p["secret"]} --host {h["name"]}. It is removed once the node has joined')
    say('note', 'installs Tailscale with its own script when it is missing, which adds its package source and signing key')
    if p['tags']:
        say('note', f'the auth key must be allowed to give {p["tags"]}, or tailscale up is refused')


def _ansible(t):
    q = shlex.quote
    p = t['params']
    head = ('APPLY=1; ok() { echo "ok: $*"; }; missing() { echo "missing: $*"; }; conflict() { echo "conflict: $*" >&2; exit 1; }; info() { :; }\n'
            'act() { echo "changed: $*"; }; try() { "$@" || { conflict "failed: $*"; return 1; }; }\n')
    call = ' '.join(q(str(p.get(a) if not isinstance(p.get(a), bool) else ('1' if p[a] else ''))) for a in ARGS)
    return {'name': changes.title(t), 'ansible.builtin.shell': {'cmd': head + BASH + f'\nt_tailscale {call}\n', 'executable': '/bin/bash'},
            'register': 'sf_out', 'changed_when': "'changed' in sf_out.stdout"}


changes.register('tailscale', {'group': 'Network', 'label': 'Join a tailnet (Tailscale)', 'fields': [
    F('secret', 'name', 'Auth key (a vault secret)', required=True, placeholder='tailscale-key'),
    F('tags', 'text', 'Tags', placeholder='tag:vm-test'), F('hostname', 'text', 'Machine name on the tailnet'),
    F('accept_routes', 'bool', 'Accept routes others advertise'), F('ssh', 'bool', 'Tailscale SSH'),
    F('state', 'choice', 'Join or leave', options=['present', 'absent'], default='present')],
    'help': 'Installs Tailscale if it is missing, with its own script, and joins with an auth key the vault holds. The key reaches the '
            'host with vault send-secret, is read from a file in memory, and is removed once the node has joined.'},
    ARGS, lambda p: f'{"Leave the tailnet" if p["state"] == "absent" else "Join the tailnet"}' + (f' ({p["tags"]})' if p.get('tags') and p['state'] != 'absent' else ''),
    _check, _ansible)
changes.EXTRA_BASH.append(BASH)
