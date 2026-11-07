"""Plan steps that copy one host onto another (docs/host-migration.md): the packages of another host.

`packages` runs on the host it is staged for, with the package list of another host's last scan. It is pkglist.py's
script, carried inside the change script as base64 when the script is written, so it reports first, installs with the
same package manager only, never removes a package, and never adds a source. The check compares both hosts' lists when
both have been scanned.
"""
from __future__ import annotations

import base64
import re
import shlex

from . import changes, pkglist
from .changes import F

changes.CHECKS['names'] = re.compile(r'[A-Za-z0-9][A-Za-z0-9+._@:~-]{0,199}(,[A-Za-z0-9][A-Za-z0-9+._@:~-]{0,199}){0,499}')

FIELDS = [
    F('from_host', 'host', 'Install the packages of', required=True, placeholder='web-01'),
    F('skip', 'names', 'Leave out these packages', placeholder='steam,nvidia-dkms'),
    F('apps', 'bool', 'Flatpak and Snap apps too', default=True),
]
ARGS = ('from_host', 'skip', 'apps')

BASH = r"""
t_packages() { local from=$1 skip=$2 apps=$3 body=$4 f rc=0 out s args=()
  [[ -n $body ]] || { conflict "$from has no package list: scan it again with this version of StorageForge"; return 0; }
  f=$(mktemp) || { conflict "could not make a temporary file"; return 0; }
  if ! base64 -d <<<"$body" >"$f" 2>/dev/null; then rm -f "$f"; conflict "the package script inside this one is damaged"; return 0; fi
  ((APPLY)) && args+=(--apply)
  [[ -n $apps ]] || args+=(--no-apps)
  for s in ${skip//,/ }; do args+=(--skip "$s"); done
  out=$(bash "$f" "${args[@]+"${args[@]}"}" 2>&1) || rc=$?
  rm -f "$f"
  sed 's/^/    /' <<<"$out"
  if ((rc)); then conflict "the packages of $from: problems above"
  elif ((APPLY)); then ok "the packages of $from are installed"
  elif grep -q 'missing' <<<"$out"; then missing "would install the packages of $from that this host lacks (above)"
  else ok "this host has the packages of $from"; fi
}
"""


def _script_for(conn, t) -> str:
    try:
        pk = pkglist.for_host(conn, t['params']['from_host'])
    except LookupError:
        return ''
    return pkglist.script(pk, pk['host'], pk.get('collected_at') or '') if pk else ''


def _args(conn, t) -> list[str]:
    text = _script_for(conn, t)
    return [base64.b64encode(text.encode()).decode() if text else '']


def _check(conn, c, h, p, say):
    try:
        src = pkglist.for_host(conn, p['from_host'])
    except LookupError:
        say('crit', f'{p["from_host"]} has not been scanned')
        return
    if not src:
        say('crit', f'{src and src["host"] or p["from_host"]} has no package list: scan it again with this version')
        return
    if not src.get('complete'):
        say('warn', f'the package list of {src["host"]} was cut short in its last scan')
    if src['basis'] != 'manual':
        say('warn', f'{src["host"]} could not say which packages were installed on purpose, so this is every package it has')
    try:
        here = pkglist.for_host(conn, h['name'])
    except LookupError:
        here = None
    skip = set(filter(None, (p['skip'] or '').split(',')))
    if not here:
        say('note', f'{h["name"]} has no package list yet: the script finds what it lacks when it runs')
        return
    cmp = pkglist.compare(src, here)
    if not cmp['comparable']:
        say('crit', f'{src["host"]} uses {src.get("pm")} and {h["name"]} {here.get("pm")}: package names differ, so nothing would be installed')
        return
    if not cmp['same_distro']:
        say('warn', f'{src["host"]} is {src.get("distro")} {src.get("version") or ""} and {h["name"]} {here.get("distro")} {here.get("version") or ""}: '
                    'some names may not exist there, and each is reported')
    want = [n for n in cmp['only_a'] if n not in skip]
    say('ok' if not want else 'note', f'{h["name"]} has all {cmp["both"]} of them' if not want else
        f'{len(want)} to install: {", ".join(want[:12])}{" …" if len(want) > 12 else ""}')
    if src.get('foreign'):
        say('note', f'{len(src["foreign"])} came from no package source (the AUR, or a file) and are listed, not installed')
    if src.get('repos'):
        say('note', 'package sources are listed in the script, never added: add any the target lacks first')
    say('note', 'never removes a package to make room for another')


def _ansible(t, conn):
    q = shlex.quote
    p = t['params']
    text = _script_for(conn, t) if conn is not None else ''
    args = ' '.join(['--apply'] + ([] if p['apps'] else ['--no-apps']) + [f'--skip {q(s)}' for s in filter(None, (p['skip'] or '').split(','))])
    return {'name': changes.title(t), 'ansible.builtin.shell': {'cmd': f"bash -s -- {args} <<'SF_PACKAGES'\n{text}\nSF_PACKAGES\n", 'executable': '/bin/bash'},
            'register': 'sf_out', 'changed_when': "'installed' in sf_out.stdout"}


changes.register('packages', {'group': 'Software', 'label': 'Install the packages of another host', 'fields': FIELDS,
    'help': 'What that host was given on purpose, from its last scan, with the same package manager. Reports first, never removes a package, never adds a source.'},
    ARGS, lambda p: f'Packages of {p["from_host"]}' + (f', less {p["skip"]}' if p['skip'] else ''), _check, _ansible, args_of=_args)
changes.EXTRA_BASH.append(BASH)


# ── accounts and config files, from another host's config history (hostconfig.py) ─────────────────────────────
import re as _re

from . import hostconfig, reinstall

# the account functions of the reinstall script, word for word: one way of adding an account, and one set of refusals
_HELPERS = '\n'.join(_re.search(rf'^{fn}\(\) \{{.*?^\}}$', reinstall.BODY, _re.M | _re.S)[0] for fn in ('group_on', 'user_on', 'member_on', 'home_on'))
_SAFE_PATH = _re.compile(r'/[A-Za-z0-9._/@+-]{0,250}')
SHARE_FILE = _re.compile(r'/etc/(exports|exports\.d/[\w.-]+\.exports|samba/[\w.-]+\.conf)')


def _record(conn, host):
    try:
        return hostconfig.build(conn, host)
    except LookupError:
        return None


def _account_lines(rec: dict) -> list[str]:
    acc = (rec or {}).get('accounts') or {}
    users, groups = acc.get('users') or [], acc.get('groups') or []
    gids = {u['gid'] for u in users}
    out = [f'g\t{g["name"]}\t{int(g["gid"])}' for g in groups if g['gid'] >= 1000 or g['gid'] in gids]
    for u in users:
        home = u['home'] if _SAFE_PATH.fullmatch(u.get('home') or '') else f'/home/{u["name"]}'
        shell = u['shell'] if _SAFE_PATH.fullmatch(u.get('shell') or '') else '/bin/bash'
        out.append(f'u\t{u["name"]}\t{int(u["uid"])}\t{int(u["gid"])}\t{home}\t{shell}')
    out += [f'm\t{m}\t{g["name"]}' for g in groups for m in g['members']]
    return out


def _accounts_args(conn, t):
    lines = _account_lines(_record(conn, t['params']['from_host']))
    return [base64.b64encode(('\n'.join(lines) + '\n').encode()).decode() if lines else '']


def _share_files(rec: dict) -> dict:
    return {p: text for p, text in sorted(((rec or {}).get('files') or {}).items()) if SHARE_FILE.fullmatch(p)}


def _config_args(conn, t):
    files = _share_files(_record(conn, t['params']['from_host']))
    lines = [f'{p}\t{base64.b64encode(text.encode()).decode()}' for p, text in files.items()]
    return [base64.b64encode(('\n'.join(lines) + '\n').encode()).decode() if lines else '']


ACCOUNTS_BASH = _HELPERS + r"""
t_accounts() { local from=$1 homes=$2 body=$3 kind a b c d e
  [[ -n $body ]] || { conflict "$from has no accounts in its config history: scan it again with this version"; return 0; }
  while IFS=$'\t' read -r kind a b c d e || [[ -n ${kind:-} ]]; do     # || : a last line with no line break is a line too
    case $kind in
      g) group_on "$a" "$b" ;;
      u) user_on "$a" "$b" "$c" "$d" "$e"; [[ -n $homes ]] && home_on "$a" "$d" "$b" "$c" ;;
      m) member_on "$a" "$b" ;;
    esac
  done < <(base64 -d <<<"$body")
  ((APPLY)) && info "accounts come with no password: set one with passwd, or log in with a key"
  return 0
}

t_config_files() { local from=$1 body=$2 path data tmp changed=0
  [[ -n $body ]] || { ok "$from had no NFS or Samba share files"; return 0; }
  while IFS=$'\t' read -r path data || [[ -n ${path:-} ]]; do
    case $path in /etc/exports|/etc/exports.d/*.exports|/etc/samba/*.conf) ;; *) conflict "not a file this step writes: $path"; continue ;; esac
    tmp=$(mktemp) || { conflict "could not make a temporary file"; return 0; }
    base64 -d <<<"$data" >"$tmp" 2>/dev/null || { rm -f "$tmp"; conflict "$path: damaged in this script"; continue; }
    if [[ -f $path ]] && cmp -s "$tmp" "$path"; then ok "$path is as on $from"; rm -f "$tmp"; continue; fi
    grep -q '\*\*removed\*\*' "$tmp" && info "$path held a password the scan does not keep: put it back by hand"
    if ((!APPLY)); then
      if [[ -f $path ]]; then missing "would replace $path, keeping the one here as $path.sf-$STAMP"; else missing "would write $path"; fi
      rm -f "$tmp"; continue
    fi
    if [[ -f $path ]]; then cp -a -- "$path" "$path.sf-$STAMP" || { rm -f "$tmp"; conflict "could not keep $path: not replaced"; continue; }; fi
    local old=''; [[ -f $path.sf-$STAMP ]] && old=", the old one is $path.sf-$STAMP"
    if install -D -m 0644 -- "$tmp" "$path"; then doing "wrote $path$old"; changed=1
    else conflict "could not write $path"; fi
    rm -f "$tmp"
  done < <(base64 -d <<<"$body")
  if ((APPLY && changed)); then
    command -v exportfs >/dev/null && { exportfs -ra 2>/dev/null && ok "NFS exports reloaded" || info "exportfs -ra failed: is the NFS server installed and running?"; }
    if command -v systemctl >/dev/null; then systemctl try-reload-or-restart smb.service smbd.service 2>/dev/null || true; fi
  fi
  return 0
}
"""


def _check_accounts(conn, c, h, p, say):
    src = _record(conn, p['from_host'])
    if not src:
        say('crit', f'{p["from_host"]} has not been scanned')
        return
    acc = src.get('accounts') or {}
    if not acc.get('users') and not acc.get('groups'):
        say('crit', f'{p["from_host"]} has no accounts in its config history: scan it again with this version')
        return
    here = ((_record(conn, h['name']) or {}).get('accounts') or {})
    have = {u['name']: u['uid'] for u in here.get('users') or []}
    uids = {u['uid']: u['name'] for u in here.get('users') or []}
    clash = [f'{u["name"]} is {have[u["name"]]} here, {u["uid"]} there' for u in acc.get('users') or [] if u['name'] in have and have[u['name']] != u['uid']]
    clash += [f'{u["uid"]} is {uids[u["uid"]]} here and {u["name"]} there' for u in acc.get('users') or [] if u['uid'] in uids and uids[u['uid']] != u['name']]
    if clash:
        say('warn', 'IDs that differ are never changed, and files keep the numbers they have: ' + '; '.join(clash[:6]))
    new = [u['name'] for u in acc.get('users') or [] if u['name'] not in have]
    say('ok' if not new else 'note', f'{len(new)} account(s) to add, with no password: {", ".join(new[:10])}' if new else 'every account is here already')


def _check_config(conn, c, h, p, say):
    src = _record(conn, p['from_host'])
    if not src:
        say('crit', f'{p["from_host"]} has not been scanned')
        return
    files = _share_files(src)
    if not files:
        say('ok', f'{p["from_host"]} had no NFS or Samba share files')
        return
    here = (_record(conn, h['name']) or {}).get('files') or {}
    for path, text in files.items():
        if path in here and here[path] != text:
            say('warn', f'replaces {path}: this host\'s is kept beside it as {path}.sf-<date>')
        elif path not in here:
            say('note', f'writes {path}')
        if hostconfig.REDACTED in text:
            say('note', f'{path} held a password that scans never keep: put it back by hand')
    say('note', 'the folders the shares name must be there: stage the storage and files before this')


def _ansible_lines(fn: str, head: str):
    def render(t, conn):
        q = shlex.quote
        p = t['params']
        extra = (_accounts_args if fn == 't_accounts' else _config_args)(conn, t) if conn is not None else ['']
        args = [p['from_host']] + ([('1' if p.get('homes') else '')] if fn == 't_accounts' else []) + extra
        prelude = ('APPLY=1; STAMP=$(date +%Y%m%d-%H%M%S); ok() { echo "ok: $*"; }; missing() { echo "missing: $*"; }; conflict() { echo "conflict: $*" >&2; exit 1; }\n'
                   'info() { :; }; doing() { echo "changed: $*"; }\n')
        return {'name': changes.title(t), 'ansible.builtin.shell': {'cmd': prelude + ACCOUNTS_BASH + f'\n{fn} ' + ' '.join(q(a) for a in args) + '\n', 'executable': '/bin/bash'},
                'register': 'sf_out', 'changed_when': "'changed' in sf_out.stdout"}
    return render


changes.register('accounts', {'group': 'Software', 'label': 'Add the accounts of another host', 'fields': [
    F('from_host', 'host', 'The accounts of', required=True, placeholder='web-01'), F('homes', 'bool', 'Make their home folders', default=True)],
    'help': 'Users and groups with the same IDs, so copied files keep their owners. No passwords: a scan never reads them. An ID that differs here is never changed.'},
    ('from_host', 'homes'), lambda p: f'Accounts of {p["from_host"]}', _check_accounts, _ansible_lines('t_accounts', ''), args_of=_accounts_args)

changes.register('config-files', {'group': 'Software', 'label': 'Copy the share files of another host', 'fields': [
    F('from_host', 'host', 'The NFS and Samba files of', required=True, placeholder='web-01')],
    'help': '/etc/exports and the Samba files from its config history. A file that differs here is kept beside the new one. Passwords are not copied: scans never keep them.'},
    ('from_host',), lambda p: f'Share files of {p["from_host"]}', _check_config, _ansible_lines('t_config_files', ''), args_of=_config_args)
changes.EXTRA_BASH.append(ACCOUNTS_BASH)
