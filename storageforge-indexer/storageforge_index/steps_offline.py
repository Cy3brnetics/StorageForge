"""Plan steps that point a host at the offline mirrors of the Toolbox (roadmap section 4.2, Offline; tboffline.py, docs/toolbox.md).

registry-mirror  /etc/containers/registries.conf.d/50-storageforge-mirror.conf: Podman pulls docker.io, ghcr.io, quay.io and
                 codeberg.org images through the Zot mirror first, and from the registry itself when the mirror does not answer.
                 Catalog images are pulled by digest, and Podman checks the digest of what the mirror hands it, so a mirror cannot
                 swap one image for another. Docker reads a mirror of Docker Hub only, from its daemon.json, which is left as it is.
apt-proxy        /etc/apt/apt.conf.d/01storageforge-proxy: apt fetches through apt-cacher-ng. Packages stay signed by the distribution
                 and apt checks them as it would from the mirror.

No apostrophes in the Bash below: the script text is checked for values that could end a quoted word.
"""
from __future__ import annotations

import re
import shlex

from . import changes
from .changes import F

MIRROR_ARGS = ('mirror', 'registries', 'scheme', 'state')
PROXY_ARGS = ('proxy', 'state')
REGISTRIES = ('docker.io', 'ghcr.io', 'quay.io', 'codeberg.org')
MIRROR = re.compile(r'[A-Za-z0-9.-]{1,200}(:\d{1,5})?')
PROXY = re.compile(r'http://[A-Za-z0-9.-]{1,200}:\d{1,5}/?')
REGS = re.compile(r'[a-z0-9.-]{1,60}(,[a-z0-9.-]{1,60}){0,9}')

BASH = r"""
# ── offline mirrors (steps_offline.py) ─
of_write() { # file text: written when it differs, the change shown first
  local f=$1 text=$2
  if [[ -f $f && $(cat "$f") == "$text" ]]; then ok "$f is as this plan writes it"; return 0; fi
  [[ -f $f ]] && { diff -u "$f" <(printf "%s\n" "$text") || true; } | tail -n +3 | head -n 40 | while IFS= read -r line; do info "  $line"; done
  act "write $f" || return 0
  mkdir -p -- "${f%/*}" && printf "%s\n" "$text" >"$f" && durable "$f" && ok "wrote $f"
}
of_remove() { [[ -e $1 ]] || { ok "$1 is not there"; return 0; }; act "remove $1" && rm -f -- "$1" && ok "removed $1"; }
t_registry_mirror() { local mirror=$1 regs=${2:-docker.io,ghcr.io,quay.io,codeberg.org} scheme=${3:-http} state=${4:-present}
  local f=${RT_ROOT:-}/etc/containers/registries.conf.d/50-storageforge-mirror.conf text r insecure=false
  if [[ $state == absent ]]; then of_remove "$f"; return 0; fi
  [[ $scheme == http ]] && insecure=true
  text="# Written by StorageForge: images through the mirror $mirror first. Pulls by digest are checked whatever hands them out."
  for r in ${regs//,/ }; do
    text+=$(printf "\n\n[[registry]]\nprefix = \"%s\"\nlocation = \"%s\"\n\n[[registry.mirror]]\nlocation = \"%s/%s\"\ninsecure = %s" "$r" "$r" "$mirror" "$r" "$insecure")
  done
  of_write "$f" "$text"
  [[ $insecure == true ]] && info "the mirror speaks plain HTTP: a pull by digest is still checked, a pull by tag trusts the network"
  command -v docker >/dev/null 2>&1 && info "Docker takes only a mirror of Docker Hub, from /etc/docker/daemon.json, which is left as it is"
  return 0
}
t_apt_proxy() { local proxy=$1 state=${2:-present} f=${RT_ROOT:-}/etc/apt/apt.conf.d/01storageforge-proxy
  if [[ $state == absent ]]; then of_remove "$f"; return 0; fi
  [[ -d ${RT_ROOT:-}/etc/apt ]] || { conflict "this host has no apt: the apt proxy is for Debian and Ubuntu"; return 0; }
  of_write "$f" "$(printf "// Written by StorageForge: packages through apt-cacher-ng. They stay signed by the distribution.\nAcquire::http::Proxy \"%s\";\nAcquire::https::Proxy \"DIRECT\";" "$proxy")"
}
"""


def _check_mirror(conn, c, h, p, say):
    if not MIRROR.fullmatch(p.get('mirror') or ''):
        say('crit', 'the mirror is host or host:port, such as 10.0.0.5:5000')
    if p.get('registries') and not REGS.fullmatch(p['registries']):
        say('crit', 'the registries are names joined by commas, such as docker.io,ghcr.io')
    if p.get('state') == 'absent':
        say('note', 'Podman pulls from each registry itself again')
        return
    say('note', 'catalog images are pulled by digest, and Podman checks the digest of what the mirror hands it')
    if p.get('scheme', 'http') == 'http':
        say('warn', 'the mirror is reached over plain HTTP: a pull by tag trusts the network between them')


def _check_proxy(conn, c, h, p, say):
    if p.get('state') != 'absent' and not PROXY.fullmatch(p.get('proxy') or ''):
        say('crit', 'the proxy is http://address:3142')
    say('note', 'apt checks the signatures of what comes through it, as from the mirror; HTTPS sources go direct')


def _ansible(fn, args):
    def render(t, conn=None):
        q = shlex.quote
        p = t['params']
        head = ('APPLY=1; ok() { echo "ok: $*"; }; missing() { echo "missing: $*"; }; conflict() { echo "conflict: $*" >&2; exit 1; }; info() { echo "$*"; }\n'
                'act() { echo "changed: $*"; }; durable() { sync; }\n')
        return {'name': changes.title(t), 'ansible.builtin.shell': {'cmd': head + BASH + f'\n{fn} ' + ' '.join(q(str(p.get(a) or '')) for a in args) + '\n',
                'executable': '/bin/bash'}, 'register': 'sf_out', 'changed_when': "'changed' in sf_out.stdout"}
    return render


STATE = F('state', 'choice', 'Add or remove', options=['present', 'absent'], default='present')
changes.register('registry-mirror', {'group': 'Toolbox', 'label': 'Pull container images through a mirror', 'fields': [
    F('mirror', 'options', 'Mirror (host:port)', required=True, placeholder='10.0.0.5:5000'),
    F('registries', 'options', 'Registries it mirrors', placeholder=','.join(REGISTRIES)),
    F('scheme', 'choice', 'The mirror speaks', options=['http', 'https'], default='http'), STATE],
    'help': 'Podman pulls through the mirror first, and from the registry when the mirror does not answer. Pulls by digest are checked.'},
    MIRROR_ARGS, lambda p: (f'Pull images through {p["mirror"]}' if p.get('state') != 'absent' else 'Pull images from each registry again'),
    _check_mirror, _ansible('t_registry_mirror', MIRROR_ARGS))
changes.register('apt-proxy', {'group': 'Toolbox', 'label': 'Fetch packages through apt-cacher-ng', 'fields': [
    F('proxy', 'options', 'Proxy', required=True, placeholder='http://10.0.0.5:3142'), STATE],
    'help': 'apt fetches through the cache, and checks the signatures of what comes through as it would from the mirror.'},
    PROXY_ARGS, lambda p: (f'Fetch packages through {p["proxy"]}' if p.get('state') != 'absent' else 'Fetch packages from the mirrors again'),
    _check_proxy, _ansible('t_apt_proxy', PROXY_ARGS))
changes.EXTRA_BASH.append(BASH)
