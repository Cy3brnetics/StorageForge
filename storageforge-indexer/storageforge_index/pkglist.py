"""The packages a host was given on purpose, so another machine can be given the same: a clone in a lab, or the machine a
host moves to.

A scan reads the distro, the packages installed on purpose (not what they pulled in), Flatpak and Snap apps, and the
package sources (remote.py, section @@pkglist). parse() keeps only names that look like package names, and source URLs
with any user, password or query taken out. script() writes a bash script that reports what this host lacks, and with
--apply installs it with the same package manager. It never removes a package to make room for another. Names are not translated between package managers: a package list
from apt is refused on a host with dnf, because a guessed mapping would install the wrong things.

Package sources are listed in the script and never added: a source brings its own signing key, and adding a key is a
decision for whoever runs it.

Values come from the host's scan, so they reach the script only as shlex-quoted words or one_line() comments.
"""
from __future__ import annotations

import re
import shlex
import time
from urllib.parse import urlsplit, urlunsplit

from . import __version__
from .scriptkit import HELPERS, REMOTE, comments, one_line

MANAGERS = ('apt-get', 'dnf', 'yum', 'zypper', 'pacman', 'apk', 'rpm-ostree', 'apt-rpm')
# names are only comparable within a family. rpm-ostree layers Fedora's own rpms; apt on rpm (ALT, PCLinuxOS) has names of its own
FAMILY = {'apt-get': 'apt', 'dnf': 'rpm', 'yum': 'rpm', 'rpm-ostree': 'rpm', 'zypper': 'zypper', 'pacman': 'pacman', 'apk': 'apk', 'apt-rpm': 'apt-rpm'}
MODES = ('normal', 'image', 'transactional', 'readonly')
MAX_NAMES = 20000
_NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9+._@:~-]{0,199}')
_APP = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,199}')
_DISTRO = re.compile(r'[A-Za-z0-9._-]{1,64}')
_SKIP = frozenset({'gpg-pubkey'})      # rpm lists each imported signing key as a package, which no repository holds
_CONTROL = re.compile(r'[\x00-\x20\x7f-\x9f  ]')


def _url(text: str) -> str | None:
    """A package source with the user, password, query and fragment taken out. A path (pacman's Include) is kept."""
    text = text.strip()
    if not text or len(text) > 500 or _CONTROL.search(text):
        return None
    if text.startswith('/'):
        return text if re.fullmatch(r'/[\w./+-]*', text) else None
    try:
        u = urlsplit(text)
    except ValueError:
        return None
    if u.scheme not in ('http', 'https', 'ftp', 'file', 'mirror', 'cdrom') or (u.scheme != 'file' and not u.hostname):
        return None
    netloc = u.hostname or ''
    if ':' in netloc:
        netloc = f'[{netloc}]'
    try:
        if u.port:
            netloc += f':{u.port}'
    except ValueError:
        return None
    return urlunsplit((u.scheme, netloc, u.path, '', ''))


def _nevra_name(nevra: str) -> str:
    """bash-5.2.26-3.fc40.x86_64 -> bash: name, then version and release, each after a dash."""
    parts = nevra.rsplit('-', 2)
    return parts[0] if len(parts) == 3 else nevra


def _ostree(b64: str, manual: set, foreign: set) -> str | None:
    """rpm-ostree status --json: the booted deployment's layered packages, and the image or ref it is built on."""
    import base64
    import binascii
    import json
    try:
        data = json.loads(base64.b64decode(b64.strip(), validate=True).decode('utf-8', 'replace'))
    except (binascii.Error, ValueError):
        return None
    deps = data.get('deployments') if isinstance(data, dict) else None
    booted = next((d for d in deps or [] if isinstance(d, dict) and d.get('booted')), None)
    if not booted:
        return None
    for key, into in (('requested-packages', manual), ('requested-local-packages', foreign)):
        for n in booted.get(key) or []:
            n = _nevra_name(n) if key == 'requested-local-packages' else n
            if isinstance(n, str) and _NAME.fullmatch(n):
                into.add(n)
                if into is foreign:
                    manual.add(n)
    ref = booted.get('container-image-reference') or booted.get('origin')
    return ref if isinstance(ref, str) and len(ref) <= 300 and not _CONTROL.search(ref) else None


def parse(text: str) -> dict:
    """The @@pkglist section -> what to install elsewhere. 'basis' says how sure the list is: 'manual' is what was
    installed on purpose, 'all' every package (dnf had no cache or history to tell them apart)."""
    pm = distro = version = None
    like: list[str] = []
    manual, every, auto, foreign, holds, backports = set(), set(), set(), set(), set(), set()
    flatpak, snap, repos, versions = {}, {}, [], {}
    from_history = complete = False
    mode, image_ref = 'normal', None
    for raw in text.splitlines():
        line = raw.rstrip('\r')
        if line == 'complete':
            complete = True
            continue
        if line.startswith('mode '):
            mode = line[5:].strip() if line[5:].strip() in MODES else mode
            continue
        if line.startswith('pm '):
            pm = line[3:].strip() if line[3:].strip() in MANAGERS else pm
            continue
        kind, _, rest = line.partition('\t')
        if kind == 'distro':
            d, _, rest = rest.partition('\t')
            v, _, lk = rest.partition('\t')
            distro = d if _DISTRO.fullmatch(d) else None
            version = v if _DISTRO.fullmatch(v) else None
            like = [x for x in lk.split() if _DISTRO.fullmatch(x)][:8]
        elif kind == 'o':
            name, _, ver = rest.partition('\t')
            if _NAME.fullmatch(name.strip()):
                foreign.add(name.strip())
                if _NAME.fullmatch(ver.strip()):
                    versions[name.strip()] = ver.strip()
        elif kind in ('h', 'b'):
            if _NAME.fullmatch(rest.strip()):
                (holds if kind == 'h' else backports).add(rest.strip())
        elif kind == 'O':
            image_ref = _ostree(rest, manual, foreign) or image_ref
        elif kind in ('m', 'a', 'x', 'v'):
            name = rest.strip().split()[0] if rest.strip() else ''
            if kind == 'v':
                name, from_history = _nevra_name(name), True
            if _NAME.fullmatch(name) and name not in _SKIP:
                (manual if kind in ('m', 'v') else every if kind == 'a' else auto).add(name)
        elif kind == 'f':
            words = rest.split()
            if words and _APP.fullmatch(words[0]) and words[0] != 'Application':
                flatpak[words[0]] = words[1] if len(words) > 1 and _APP.fullmatch(words[1]) else None
        elif kind == 's':
            name, _, note = rest.partition('\t')
            if _APP.fullmatch(name):
                snap[name] = note.strip() if note.strip() in ('classic', 'devmode') else None
        elif kind == 'r':
            where, _, url = rest.partition('\t')
            u = _url(url)
            if u and not _CONTROL.search(where) and len(where) <= 200 and len(repos) < 500:
                repos.append({'where': where, 'url': u})
    if not manual and every:
        manual, basis = every - auto, ('manual' if auto else 'all')
    else:
        basis = 'manual'
    base = 0
    if mode == 'readonly':            # what is there is the vendor's image: only the apps are the user's own
        base, manual = len(manual), set()
    names = sorted(manual - foreign)
    return {'pm': pm, 'distro': distro, 'version': version, 'like': like, 'basis': basis, 'from_history': from_history,
            'mode': mode, 'image_ref': image_ref, 'base_packages': base,
            'holds': sorted(holds & set(names)), 'backports': sorted(backports & set(names)),
            'packages': names[:MAX_NAMES], 'foreign': sorted(foreign & manual)[:MAX_NAMES],
            'foreign_versions': {k: v for k, v in versions.items() if k in manual}, 'flatpak': [{'id': k, 'origin': v} for k, v in sorted(flatpak.items())],
            'snap': [{'name': k, 'confinement': v} for k, v in sorted(snap.items())],
            'repos': [dict(t) for t in dict.fromkeys(tuple(r.items()) for r in repos)],
            'complete': complete and len(names) <= MAX_NAMES}


def for_host(conn, host: str) -> dict | None:
    """The package list of the host's last scan, or None if that scan was too old to read one."""
    from .db import loads
    rows = conn.all('SELECT hostname, inventory_json FROM hosts WHERE lower(hostname) = lower(:h)', {'h': host})
    if not rows:
        raise LookupError(f'{host} is not indexed: scan it first')
    inv = loads(rows[0][1]) or {}
    pk = inv.get('pkglist')
    return {**pk, 'host': rows[0][0], 'collected_at': inv.get('collected_at')} if pk else None


def script_for(conn, host: str) -> str:
    pk = for_host(conn, host)
    if not pk:
        raise LookupError(f'{host} has no package list: its last scan is older than this version, so scan it again')
    return script(pk, pk['host'], pk.get('collected_at') or '')


def compare(a: dict, b: dict) -> dict:
    """What one host has that the other lacks. Names are only comparable within one package manager family."""
    same = FAMILY.get(a.get('pm')) == FAMILY.get(b.get('pm')) and a.get('pm') is not None
    pa, pb = set(a.get('packages') or []), set(b.get('packages') or [])
    fa, fb = {x['id'] for x in a.get('flatpak') or []}, {x['id'] for x in b.get('flatpak') or []}
    sa, sb = {x['name'] for x in a.get('snap') or []}, {x['name'] for x in b.get('snap') or []}
    ra, rb = {r['url'] for r in a.get('repos') or []}, {r['url'] for r in b.get('repos') or []}
    return {'comparable': same, 'same_distro': (a.get('distro'), a.get('version')) == (b.get('distro'), b.get('version')),
            'only_a': sorted(pa - pb) if same else [], 'only_b': sorted(pb - pa) if same else [], 'both': len(pa & pb) if same else 0,
            'flatpak_only_a': sorted(fa - fb), 'flatpak_only_b': sorted(fb - fa),
            'snap_only_a': sorted(sa - sb), 'snap_only_b': sorted(sb - sa),
            'repos_only_a': sorted(ra - rb), 'repos_only_b': sorted(rb - ra)}


BODY = r"""
HOST= APPLY=0 APPS=1 SKIP=() ARGS=("$@")
usage() { sed -n '/^# Usage/,/^$/p' "$0" | sed 's/^# \{0,1\}//'; }
while (($#)); do case $1 in
  --apply) APPLY=1 ;;
  --no-apps) APPS=0 ;;
  --skip) SKIP+=("${2:?--skip needs a package name}"); shift ;;
  --host) HOST=${2:?--host needs a name}; shift ;;
  -h|--help) usage; exit 0 ;;
  *) echo "unknown option $1 (see --help)" >&2; exit 2 ;;
esac; shift; done
@@REMOTE@@
export PATH="$PATH:/usr/sbin:/sbin:/usr/local/sbin"
if ((APPLY)) && [[ $EUID -ne 0 ]]; then echo "--apply needs root: sudo $0 ${ARGS[*]}" >&2; exit 1; fi
@@HELPERS@@
here_pm() { # the way packages get on here, as the scan names it
  if [[ -e /run/ostree-booted ]]; then command -v rpm-ostree >/dev/null && { echo rpm-ostree; return; }; echo none; return; fi
  if command -v transactional-update >/dev/null && findmnt -no OPTIONS / 2>/dev/null | grep -qE '(^|,)ro(,|$)'; then echo transactional; return; fi
  command -v apt-get >/dev/null && command -v dpkg-query >/dev/null && { echo apt-get; return; }
  for m in dnf yum zypper pacman; do command -v $m >/dev/null && { echo $m; return; }; done
  command -v apt-get >/dev/null && command -v rpm >/dev/null && { echo apt-rpm; return; }
  command -v apk >/dev/null && { echo apk; return; }
  echo none
}
family() { case $1 in apt-get) echo apt ;; dnf|yum|rpm-ostree) echo rpm ;; transactional) echo zypper ;; *) echo "$1" ;; esac; }
installed() { # one name per line
  case $1 in
    apt-get) dpkg-query -W -f='${binary:Package}\t${db:Status-Status}\n' 2>/dev/null | awk -F'\t' '$2 == "installed" {print $1; sub(/:.*/, "", $1); print $1}' ;;
    dnf|yum|zypper|rpm-ostree|transactional|apt-rpm) rpm -qa --qf '%{NAME}\n' 2>/dev/null ;;
    pacman) pacman -Qq 2>/dev/null ;;
    apk) apk info 2>/dev/null ;;
  esac
}
removes() { # manager name... -> what installing them would remove, from a simulated run; empty when nothing
  local m=$1; shift
  case $m in
    zypper) zypper -n install --dry-run "$@" 2>&1 | awk '/going to be REMOVED/ {r = 1; next} r && /^ *$/ {r = 0} r {for (i = 1; i <= NF; i++) o = o (o == "" ? "" : " ") $i} END {print o}' ;;
    apk) apk add --simulate "$@" 2>&1 | awk '$2 == "Purging" {o = o (o == "" ? "" : " ") $3} END {print o}' ;;
    apt-rpm) apt-get -s install "$@" 2>&1 | awk '$1 == "Remv" {o = o (o == "" ? "" : " ") $2} END {print o}' ;;
  esac
}
install_these() { # manager name... Never removes a package to make room: apt with --no-remove, dnf without --allowerasing,
  local m=$1 gone; shift    # pacman with --noconfirm answers no to removing a conflict, and zypper and apk are simulated first
  case $m in
    apt-get) DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=120 install -y -qq --no-remove "$@" 2>&1 ;;
    dnf|yum) "$m" install -y -q "$@" 2>&1 ;;
    zypper|apk|apt-rpm) gone=$(removes "$m" "$@")
      if [[ -n $gone ]]; then echo "refused: installing would remove $gone"; return 1; fi
      case $m in zypper) zypper -nq install "$@" 2>&1 ;; apk) apk add -q "$@" 2>&1 ;; apt-rpm) apt-get install -y -q "$@" 2>&1 ;; esac ;;
    # both make a new snapshot of the system, which the next boot uses: the running one is not touched, and can be gone back to
    rpm-ostree) rpm-ostree install -y --idempotent --allow-inactive "$@" 2>&1 ;;
    transactional) transactional-update -n pkg install "$@" 2>&1 ;;
    pacman) pacman -S --needed --noconfirm "$@" 2>&1 ;;
  esac
}

section "Packages from $SRC_HOST"
info "listed by its scan of $SRC_WHEN: $SRC_DISTRO $SRC_VERSION, $SRC_PM, ${#PKGS[@]} package(s) ($SRC_BASIS)"
((SRC_COMPLETE)) || info "the list may be cut short: the output of the scan stopped before its end"
case $SRC_MODE in
  image) info "$SRC_HOST is image-based (${SRC_IMAGE:-its image}): only the packages layered onto it are here, not the image itself" ;;
  readonly) info "$SRC_HOST is a read-only system ($SRC_BASE packages of the vendor image): only its apps come across" ;;
esac
REBOOT=0
M=$(here_pm)
. /etc/os-release 2>/dev/null || true
if [[ $(family "$M") != $(family "$SRC_PM") ]]; then
  conflict "this host uses $M and the list is from $SRC_PM: package names differ between them, so nothing is installed. Clone onto $SRC_DISTRO, or install by hand"
  exit 1
fi
[[ ${ID:-} == "$SRC_DISTRO" && ${VERSION_ID:-} == "$SRC_VERSION" ]] || info "this host is ${ID:-unknown} ${VERSION_ID:-} and the list is from $SRC_DISTRO $SRC_VERSION: some names may not exist here, and each is tried on its own"
declare -A HAVE=() SKIPPED=() BP=()
for p in "${BACKPORTS[@]+"${BACKPORTS[@]}"}"; do BP[$p]=1; done
BPW=()
while IFS= read -r p; do [[ -n $p ]] && HAVE[$p]=1; done < <(installed "$M")
for p in "${SKIP[@]+"${SKIP[@]}"}"; do SKIPPED[$p]=1; done
WANT=() N=0
for p in "${PKGS[@]+"${PKGS[@]}"}"; do
  [[ -n ${SKIPPED[$p]:-} ]] && { skip "$p (--skip)"; continue; }
  N=$((N + 1)); [[ -n ${HAVE[$p]:-} ]] && continue
  if [[ $M == apt-get && -n ${BP[$p]:-} ]]; then BPW+=("$p"); else WANT+=("$p"); fi
done
ok "$((N - ${#WANT[@]} - ${#BPW[@]})) of $N already installed"
if ((${#WANT[@]})); then
  if ((!APPLY)); then
    missing "${#WANT[@]} to install with $M: ${WANT[*]}"
  else
    doing "install ${#WANT[@]} package(s) with $M"
    [[ $M == apt-get ]] && apt-get -o DPkg::Lock::Timeout=120 update -qq 2>&1 | tail -n 3
    case $M in rpm-ostree|transactional) REBOOT=1 ;; esac
    if out=$(install_these "$M" "${WANT[@]}"); then ok "installed ${#WANT[@]}"
    else
      info "together they did not install ($(tail -n 1 <<<"$out")): trying each on its own"
      for p in "${WANT[@]}"; do
        if out=$(install_these "$M" "$p"); then ok "$p"; else conflict "$p: $(tail -n 1 <<<"$out")"; fi
      done
    fi
  fi
fi
if ((${#BPW[@]})); then
  # those came from the backports of the release on the source, so they are asked for from there and not from the release
  bp="${VERSION_CODENAME:-}-backports"
  if ! apt-cache policy 2>/dev/null | grep -q -- "$bp"; then missing "${#BPW[@]} came from backports, which this host has no source for ($bp): ${BPW[*]}"
  elif ((!APPLY)); then missing "would take ${BPW[*]} from $bp"
  elif out=$(DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=120 install -y -qq --no-remove -t "$bp" "${BPW[@]}" 2>&1); then ok "from $bp: ${BPW[*]}"
  else conflict "from $bp: $(tail -n 1 <<<"$out")"; fi
fi
if ((${#HOLDS[@]})) && [[ $M == apt-get ]]; then
  if ((!APPLY)); then missing "would hold ${HOLDS[*]} at the installed version, as on $SRC_HOST"
  elif apt-mark hold "${HOLDS[@]}" >/dev/null 2>&1; then ok "held, as on $SRC_HOST: ${HOLDS[*]}"
  else conflict "could not hold ${HOLDS[*]}"; fi
fi
((REBOOT)) && info "installed into a new snapshot of the system: reboot to use them"

if ((${#FOREIGN[@]})); then
  section "Built or downloaded by hand"
  info "${#FOREIGN[@]} package(s) came from no package source (the AUR, a local .deb or .rpm, or a file): never installed by this script"
  info "${FOREIGN[*]}"
fi

if ((APPS)) && ((${#FLATPAKS[@]})); then
  section "Flatpak apps"
  if ! command -v flatpak >/dev/null; then missing "flatpak is not installed, so ${#FLATPAKS[@]} app(s) cannot be: install it, then run this again"
  else
    for i in "${!FLATPAKS[@]}"; do
      app=${FLATPAKS[$i]} origin=${FLATPAK_ORIGINS[$i]}
      if flatpak info "$app" >/dev/null 2>&1; then ok "$app"
      elif [[ -z $origin ]] || ! flatpak remotes --columns=name 2>/dev/null | grep -Fxq -- "$origin"; then missing "$app needs the remote ${origin:-it came from}, which this host lacks: flatpak remote-add it first"
      elif ((!APPLY)); then missing "$app (would install from $origin)"
      elif out=$(flatpak install -y --noninteractive "$origin" "$app" 2>&1); then ok "$app installed"
      else conflict "$app: $(tail -n 1 <<<"$out")"; fi
    done
  fi
fi

if ((APPS)) && ((${#SNAPS[@]})); then
  section "Snaps"
  if ! command -v snap >/dev/null; then missing "snapd is not installed, so ${#SNAPS[@]} snap(s) cannot be: install it, then run this again"
  else
    for i in "${!SNAPS[@]}"; do
      s=${SNAPS[$i]} c=${SNAP_FLAGS[$i]}
      if snap list "$s" >/dev/null 2>&1; then ok "$s"
      elif ((!APPLY)); then missing "$s (would install${c:+ with --$c})"
      elif out=$(snap install "$s" ${c:+"--$c"} 2>&1); then ok "$s installed"
      else conflict "$s: $(tail -n 1 <<<"$out")"; fi
    done
  fi
fi

if ((${#REPOS[@]})); then
  section "Package sources on $SRC_HOST"
  info "never added by this script: each brings its own signing key. Add any this host lacks before --apply"
  for r in "${REPOS[@]}"; do info "$r"; done
fi
echo
if ((PROBLEMS)); then echo "${R}$PROBLEMS problem(s)${N0}"; exit 1; fi
((APPLY)) || { echo "report only: run again with --apply to install"; exit 0; }
finished
"""


def _array(name: str, values) -> str:
    return f'{name}=(' + ' '.join(shlex.quote(v) for v in values) + ')\n'


def script(pk: dict, host: str, when: str = '') -> str:
    """A bash script that installs the packages of pk on the host it runs on. Reports unless --apply."""
    flat = pk.get('flatpak') or []
    snaps = pk.get('snap') or []
    head = ('#!/usr/bin/env bash\n'
            f'# Written by StorageForge {__version__} on {time.strftime("%Y-%m-%d %H:%M")}: the packages of {one_line(host)}, for another machine.\n'
            '# With no flags it only reports.\n'
            '#\n# Usage: packages.sh [--apply] [--no-apps] [--skip NAME]... [--host [user@]name]\n'
            '#   --apply      install what this host lacks, with the same package manager\n'
            '#   --no-apps    leave out Flatpak and Snap apps\n'
            '#   --skip NAME  leave out a package (again for more)\n'
            '#   --host       copy this script to another machine and run it there with sudo\n\n'
            + comments([f'# Made from a list of {len(pk.get("packages") or [])} package(s); sources are listed, never added.'], '') + '\n'
            + 'set -eu\n'
            + f'SRC_HOST={shlex.quote(host)} SRC_WHEN={shlex.quote(when or "an unknown date")}\n'
            + f'SRC_PM={shlex.quote(pk.get("pm") or "none")} SRC_DISTRO={shlex.quote(pk.get("distro") or "unknown")} '
              f'SRC_VERSION={shlex.quote(pk.get("version") or "")} SRC_BASIS={shlex.quote("installed on purpose" if pk.get("basis") == "manual" else "every package")} '
              f'SRC_COMPLETE={int(bool(pk.get("complete")))}\n'
            + _array('PKGS', [p for p in pk.get('packages') or [] if _NAME.fullmatch(p)])
            + _array('FLATPAKS', [f['id'] for f in flat]) + _array('FLATPAK_ORIGINS', [f.get('origin') or '' for f in flat])
            + _array('SNAPS', [s['name'] for s in snaps]) + _array('SNAP_FLAGS', [s.get('confinement') or '' for s in snaps])
            + _array('FOREIGN', [p + (f' {pk["foreign_versions"][p]}' if (pk.get('foreign_versions') or {}).get(p) else '') for p in pk.get('foreign') or [] if _NAME.fullmatch(p)])
            + _array('HOLDS', [p for p in pk.get('holds') or [] if _NAME.fullmatch(p)])
            + _array('BACKPORTS', [p for p in pk.get('backports') or [] if _NAME.fullmatch(p)])
            + f'SRC_MODE={shlex.quote(pk.get("mode") or "normal")} SRC_IMAGE={shlex.quote(pk.get("image_ref") or "")} SRC_BASE={int(pk.get("base_packages") or 0)}\n'
            + _array('REPOS', [f'{r["where"]}: {r["url"]}' for r in pk.get('repos') or []]))
    return head + BODY.replace('@@REMOTE@@', REMOTE).replace('@@HELPERS@@', HELPERS)
