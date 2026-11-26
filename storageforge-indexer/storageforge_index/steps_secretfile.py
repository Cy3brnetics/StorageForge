"""The secret-file plan step: a vault secret written to a file on the host, for a service that reads its password or key from a file
(a database password for a compose stack, an API token for a backup tool).

The value reaches the host as for every step that names a secret (secretstore.py): on the signed runner's stdin in an apply, into
/run/storageforge/secrets/NAME. This step copies that file to the path, owner and mode it names, through a temporary file in the same
folder and a rename, and only when what is there differs. The value is on no command line (cat and cmp read files) and is never
printed. The report has no value to compare with, so it says what an apply would look at.

The file holds the secret in the clear for whoever can read it: the mode and owner are what protect it, 0600 and root unless said.
"""
from __future__ import annotations

import posixpath
import re
import shlex

from . import changes
from .changes import F

NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,63}')
ACCOUNT = re.compile(r'[a-z_][a-z0-9_.-]{0,31}')
MODE = re.compile(r'0?[0-7]{3}')
ARGS = ('secret', 'path', 'owner', 'group', 'mode', 'state', 'prepare')

# No apostrophes: the script text is checked for values that could end a quoted word.
BASH = r"""
t_secret_file() { local secret=$1 path=$2 owner=${3:-root} group=${4:-} mode=${5:-0600} state=${6:-present} prepare=${7:-} d=/run/storageforge/secrets src dir tmp have
  ((EUID != 0)) && d=${SF_SECRET_DIR:-$d}
  src=$d/$secret dir=${path%/*}
  [[ -n $dir ]] || dir=/      # a file directly under / has no folder part
  # a numeric owner is a user id, which needs no account on the host (a container image names its own user that way)
  [[ -n $group ]] || group=$(id -gn "$owner" 2>/dev/null || { [[ $owner =~ ^[0-9]+$ ]] && echo "$owner" || echo root; })
  if [[ $state == absent ]]; then
    [[ -e $path ]] || { ok "$path is not there"; return 0; }
    act "remove $path" && try rm -f -- "$path" && ok "removed $path"
    return 0
  fi
  if ((!APPLY)); then
    if [[ -e $path ]]; then info "$path is there: an apply writes the secret $secret over it if it differs, and sets $owner:$group, mode $mode"
    else missing "would: write the secret $secret to $path ($owner:$group, mode $mode), from what StorageForge brings when the plan is applied"; fi
    return 0
  fi
  if [[ ! -r $src ]]; then conflict "the secret $secret is not on this host: apply this plan from StorageForge, which brings it on the runner stdin, or send it first (storageforge-index vault send-secret $secret --host $(uname -n))"; return 0; fi
  # prepare: a Toolbox install is later in this plan and makes the account, so the folder is made here and an account that is not there
  # yet owns nothing: the file waits as root, and the install hands the folder and its files over (tb_hand_over)
  if [[ ! $owner =~ ^[0-9]+$ ]] && ! id -u "$owner" >/dev/null 2>&1; then
    [[ -n $prepare ]] || { conflict "there is no account $owner here"; return 0; }
    info "the account $owner is not made yet: the file stays with root until the install step after this one makes it and takes the file over"
    owner=root group=root
  fi
  if [[ ! -d $dir ]]; then
    [[ -n $prepare ]] || { conflict "the folder $dir does not exist"; return 0; }
    act "make the folder $dir ($owner:$group, mode 0750)" || return 0
    mkdir -p -- "$dir" && chmod 0750 -- "$dir" && chown "$owner:$group" -- "$dir" || { conflict "could not make the folder $dir"; return 0; }
  fi
  have=$(stat -c "%U:%G %a" -- "$path" 2>/dev/null || true)
  if [[ -f $path ]] && cmp -s -- "$src" "$path" && [[ $have == "$owner:$group $(printf %o $((8#$mode)))" ]]; then
    ok "$path holds the secret $secret ($owner:$group, mode $mode)"; return 0
  fi
  act "write the secret $secret to $path ($owner:$group, mode $mode)" || return 0
  tmp=$(mktemp "$dir/.sf-secret.XXXXXX") || { conflict "could not make a temporary file in $dir"; return 0; }
  if chmod "$mode" "$tmp" && chown "$owner:$group" "$tmp" && cat -- "$src" >"$tmp" && durable "$tmp" && mv -f -- "$tmp" "$path"; then ok "$path holds the secret $secret"
  else rm -f -- "$tmp"; conflict "could not write $path"; fi
}
"""


def _check(conn, c, h, p, say):
    if not NAME.fullmatch(p.get('secret') or ''):
        say('crit', 'the secret is the name of a vault secret: letters, digits, dot, dash and underscore')
    path = p.get('path') or ''
    if not path.startswith('/') or posixpath.normpath(path) != path or path.endswith('/') or any(ch in path for ch in '\n\t\0'):
        say('crit', 'the path is an absolute path to a file, written out in full')
    elif path.startswith('/run/storageforge/') or path in ('/etc/shadow', '/etc/passwd', '/etc/sudoers'):
        say('crit', f'{path} is not a place for this step to write')
    for what in ('owner', 'group'):
        if p.get(what) and not ACCOUNT.fullmatch(p[what]):
            say('crit', f'the {what} is a name, such as postgres')
    if p.get('mode') and not MODE.fullmatch(p['mode']):
        say('crit', 'the mode is three octal digits, such as 0600')
    elif (p.get('mode') or '0600')[-1] != '0':
        say('warn', 'every account on the host can read the file at this mode')
    if p.get('state') == 'absent':
        say('note', f'removes {path}')
        return
    say('note', f'the secret reaches {h["name"]} on the runner stdin when this plan is applied from StorageForge, and is copied to {path}; '
                'the report has no value to compare with. A policy on the secret that names steps must name secret-file')


def _title(p) -> str:
    return f'Remove {p.get("path")}' if p.get('state') == 'absent' else f'Write the secret {p.get("secret")} to {p.get("path")}'


def _ansible(t, conn=None):
    q = shlex.quote
    p = t['params']
    head = ('APPLY=1; ok() { echo "ok: $*"; }; missing() { echo "missing: $*"; }; conflict() { echo "conflict: $*" >&2; exit 1; }; info() { :; }\n'
            'act() { echo "changed: $*"; }; try() { "$@" || { conflict "failed: $*"; return 1; }; }; durable() { sync; }\n')
    words = changes.words_of(p, ARGS)
    return changes.shell_task(t, head + BASH + '\nt_secret_file ' + ' '.join(q(w) for w in words) + '\n')


changes.register('secret-file', {'group': 'Software', 'label': 'Write a vault secret to a file', 'fields': [
    F('secret', 'name', 'Secret (a vault secret)', required=True, placeholder='grafana-admin'),
    F('path', 'path', 'File', required=True, placeholder='/etc/grafana/admin-password'),
    F('owner', 'user', 'Owner', placeholder='root'), F('group', 'user', 'Group'),
    F('mode', 'mode', 'Mode', placeholder='0600'),
    F('prepare', 'bool', 'Make its folder, and wait for an owner account that a later Toolbox install makes'),
    F('state', 'choice', 'Write or remove', options=['present', 'absent'], default='present')],
    'help': 'Copies a secret from the vault into a file a service reads, with the owner and mode given. The secret comes with the plan '
            'when it is applied from StorageForge, on the signed runner stdin, and is in no plan, script or log.'},
    ARGS, _title, _check, _ansible)
changes.EXTRA_BASH.append(BASH)
