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
