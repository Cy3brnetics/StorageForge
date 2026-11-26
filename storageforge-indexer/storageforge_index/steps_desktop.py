"""A desktop on a host (roadmap section 7, phase 9): two plan steps.

    dux-install       Dux (duxlabs.dev) through its unattended installer, with the compositor and the terminal chosen here
    desktop-profile   a desktop profile kept on the server (desktop.py), written into a user's compositor configuration

dux-install runs somebody else's program as a user who can become root. The script on the project's site
(install.duxlabs.dev) is a short bootstrap that fetches the installer of whatever release is newest, so naming that script's
hash would pin nothing that matters. The step names a release and the SHA-256 of that release's installer for the host's
architecture, fetches that one file from the project's releases, and runs nothing else. With no hash it runs nothing and says
which release is newest and what hash the project publishes for it. What the installer then installs comes from the
distribution's and the project's package repositories, as they are that day: that part cannot be pinned from here.

desktop-profile writes one file of its own beside the user's configuration, and one line in the user's main configuration that
includes it. The file is the profile as the server rendered it when the plan's script was written; the main configuration is
backed up before its one line is added, and where the compositor can check a configuration (niri), a file it refuses is taken
out again. Nothing else in the user's configuration is changed.
"""
from __future__ import annotations

import base64
import shlex

from . import changes, desktop
from .changes import F

RELEASES = 'https://github.com/duxlabs-dev/dux-shell/releases'
VERSION = r'v[0-9]{1,4}(\.[0-9]{1,4}){1,3}'
DUX_COMPOSITORS = ('niri', 'hyprland', 'mango')          # the ones its installer sets up; the others are by hand, its documentation says
TERMINALS = ('ghostty', 'kitty', 'alacritty')
# compositor -> (its folder under ~/.config, its main file, the line that includes ours)
PLACES = {'niri': ('niri', 'config.kdl', f'include "{desktop.FILES["niri"]}"'),
          'hyprland': ('hypr', 'hyprland.lua', f'require("{desktop.FILES["hyprland"].removesuffix(".lua")}")'),
          'sway': ('sway', 'config', f'include ~/.config/sway/{desktop.FILES["sway"]}')}

BASH = r"""
sf_home() { getent passwd "$1" | cut -d: -f6; }

t_dux_install() { local user=$1 compositor=$2 term=$3 version=$4 sum=$5 home='' file='' have='' arch='' url='' c=''
  home=$(sf_home "$user" || :)
  [[ -n $home && -d $home ]] || { later "there is no account $user with a home folder here"; return 0; }
  if runuser -u "$user" -- sh -c 'command -v dms' >/dev/null 2>&1 || command -v dms >/dev/null 2>&1; then ok "Dux is installed (dms is here)"; return 0; fi
  for c in curl sha256sum gzip runuser sudo; do command -v "$c" >/dev/null || { later "$c is not installed"; return 0; }; done
  case $(uname -m) in x86_64) arch=amd64 ;; aarch64) arch=arm64 ;; *) conflict "Dux has no installer for $(uname -m)"; return 0 ;; esac
  if [[ -z $version || -z $sum ]]; then
    # nothing runs: say what a person would look up, so the step can be filled in after the release notes are read
    c=$(curl -sI "@RELEASES@/latest" | tr -d '\r' | awk 'tolower($1) == "location:" {sub(".*/releases/tag/", "", $2); print $2}' || :)
    [[ $c =~ ^@VERSION@$ ]] || { conflict "name a release and the SHA-256 of its installer; the newest release could not be read from @RELEASES@"; return 0; }
    have=$(curl -fsSL "@RELEASES@/download/$c/duxinstall-$arch.gz.sha256" 2>/dev/null | awk '{print $1; exit}' || :)
    conflict "name a release and the SHA-256 of its installer. The newest is $c, and the project publishes ${have:-no hash} for duxinstall-$arch.gz. Nothing runs without both"; return 0
  fi
  [[ $version =~ ^@VERSION@$ ]] || { conflict "$version is not a release such as v2.1.2"; return 0; }
  runuser -u "$user" -- sudo -n true 2>/dev/null || { conflict "$user cannot use sudo without a password, which the installer needs to run unattended"; return 0; }
  url="@RELEASES@/download/$version/duxinstall-$arch.gz"
  info "the installer of Dux $version for $arch, which must be $sum"
  act "install Dux $version for $user: $compositor and $term" || return 0
  file=$(mktemp -d)
  curl -fsSL --retry 3 -o "$file/installer.gz" "$url" || { rm -rf "$file"; conflict "could not fetch $url"; return 0; }
  have=$(sha256sum "$file/installer.gz"); have=${have%% *}
  if [[ $have != "$sum" ]]; then rm -rf "$file"; conflict "the installer of $version is $have, and this step names $sum: it is not run"; return 0; fi
  gzip -d "$file/installer.gz" && chmod 0755 "$file" "$file/installer" || { rm -rf "$file"; conflict "the installer could not be unpacked"; return 0; }
  if runuser -u "$user" -- env HOME="$home" DMS_PRIVESC=sudo "$file/installer" -c "$compositor" -t "$term" -y >"$home/.storageforge-dux-install.log" 2>&1; then
    rm -rf "$file"; ok "Dux $version is installed for $user with $compositor and $term (its output: $home/.storageforge-dux-install.log)"
  else
    rm -rf "$file"; conflict "the installer failed: $(tail -n 3 "$home/.storageforge-dux-install.log" | tr '\n' ' ' | cut -c1-300)"
  fi
}

t_desktop_profile() { local profile=$1 user=$2 compositor=$3 body=$4 home='' dir='' main='' line='' name='' file='' new='' group=''
  [[ -n $body ]] || { conflict "the server has no desktop profile named $profile"; return 0; }
  home=$(sf_home "$user" || :)
  [[ -n $home && -d $home ]] || { later "there is no account $user with a home folder here"; return 0; }
  case $compositor in
@PLACES@
    *) conflict "no compositor $compositor"; return 0 ;;
  esac
  dir=$home/.config/$dir; file=$dir/$name; group=$(id -gn "$user")
  new=$(mktemp); printf '%s' "$body" | base64 -d >"$new" || { rm -f "$new"; conflict "the profile did not arrive whole"; return 0; }
  [[ -L $dir || -L $file || -L $dir/$main || -L $file.before || -L $dir/$main.before-storageforge ]] && { rm -f "$new"; conflict "$dir or a file in it is a link: this writes only into the folder itself"; return 0; }
  if [[ -f $file ]] && cmp -s "$new" "$file" && grep -qxF "$line" "$dir/$main" 2>/dev/null; then rm -f "$new"; ok "$user has the profile $profile for $compositor"; return 0; fi
  [[ -f $dir/$main ]] || { rm -f "$new"; later "$user has no $dir/$main yet: the compositor, or Dux, writes it first"; return 0; }
  if ! act "write the profile $profile for $user ($compositor): $file, and one line in $main"; then rm -f "$new"; return 0; fi
  [[ -f $file ]] && cp -p "$file" "$file.before"
  install -o "$user" -g "$group" -m 0644 "$new" "$file"; rm -f "$new"
  if ! grep -qxF "$line" "$dir/$main"; then
    [[ -e $dir/$main.before-storageforge ]] || cp -p "$dir/$main" "$dir/$main.before-storageforge"
    printf '\n%s\n' "$line" >>"$dir/$main"
  fi
  # where the compositor can check a configuration, one it refuses is taken out again
  if [[ $compositor == niri ]] && command -v niri >/dev/null; then
    if ! runuser -u "$user" -- niri validate -c "$dir/$main" >/dev/null 2>&1; then
      if [[ -f $file.before ]]; then mv -f "$file.before" "$file"; else rm -f "$file"; grep -vxF "$line" "$dir/$main" >"$dir/$main.sf-new" && cat "$dir/$main.sf-new" >"$dir/$main"; rm -f "$dir/$main.sf-new"; fi
      conflict "niri refuses the configuration with the profile in it: it was taken out again (niri validate -c $dir/$main says why)"; return 0
    fi
  fi
  rm -f "$file.before"
  ok "$user has the profile $profile for $compositor; it is read at the next reload"
}
"""


def bash() -> str:
    places = '\n'.join(f'    {c}) dir={shlex.quote(d)}; main={shlex.quote(m)}; line={shlex.quote(line)}; name={shlex.quote(desktop.FILES[c])} ;;' for c, (d, m, line) in PLACES.items())
    return BASH.replace('@RELEASES@', RELEASES).replace('@VERSION@', VERSION).replace('@PLACES@', places)


def _profile_text(conn, t) -> str:
    p = t['params']
    try:
        return desktop.render(desktop.get(conn, p['profile']), p['compositor'], t.get('host'))
    except (LookupError, ValueError):
        return ''


def _profile_args(conn, t) -> list[str]:
    text = _profile_text(conn, t)
    return [base64.b64encode(text.encode()).decode() if text else '']


def _check_profile(conn, c, h, p, say):
    try:
        profile = desktop.get(conn, p['profile'])
    except LookupError:
        say('crit', f'there is no desktop profile named {p["profile"]}')
        return
    own = any(name.lower() == h['name'].lower() for name in profile.get('hosts') or {})
    say('note', f'{len(profile["binds"])} keys, {len(profile["rules"])} window rules, and ' + ('this host\'s own display layout' if own else f'the profile\'s display layout ({len(profile["displays"])} outputs)'))
    say('note', 'one file of its own and one line in the main configuration, which is backed up first; the script is the profile as it is now')
    if p['user'] in ('root', '0'):
        say('warn', 'a desktop for root')


def _check_dux(conn, c, h, p, say):
    import re
    if not (p.get('version') and p.get('installer_sha')):
        say('crit', f'name a release and the SHA-256 of its installer ({RELEASES}): a report of this step says which is newest and what the project publishes for it. The step runs no other file')
    elif not re.fullmatch(VERSION, p['version']):
        say('crit', f'{p["version"]} is not a release such as v2.1.2')
    say('warn', f'runs the Dux installer as {p["user"]}, who must have sudo without a password: it installs packages and adds the project\'s repositories, as they are that day')
    if p['user'] in ('root', '0'):
        say('crit', 'the installer is run as the desktop\'s user, not as root')


def _ansible(fn: str, args: tuple, with_conn: bool = False):
    def render(t, conn=None):
        q = shlex.quote
        p = t['params']
        words = [str(p.get(a) or '') for a in args] + (_profile_args(conn, t) if with_conn else [])
        head = ('APPLY=1; ok() { echo "ok: $*"; }; missing() { echo "missing: $*"; }; conflict() { echo "conflict: $*" >&2; exit 1; }; info() { :; }\n'
                'doing() { :; }; act() { echo "changed: $*"; }; try() { "$@" || { conflict "failed: $*"; return 1; }; }; later() { conflict "$*"; }\n')
        return {'name': changes.title(t), 'ansible.builtin.shell': {'cmd': head + bash() + f'\n{fn} {" ".join(q(w) for w in words)}\n', 'executable': '/bin/bash'},
                'register': 'sf_out', 'changed_when': "'changed' in sf_out.stdout"}
    return render


changes.register('dux-install', {'group': 'Desktop', 'label': 'Install Dux', 'fields': [
    F('user', 'user', 'The desktop\'s user', required=True), F('compositor', 'choice', 'Compositor', options=list(DUX_COMPOSITORS), required=True),
    F('terminal', 'choice', 'Terminal', options=list(TERMINALS), default='ghostty'), F('version', 'name', 'Dux release', placeholder='v2.1.2'),
    F('installer_sha', 'sha', 'SHA-256 of that release\'s installer (duxinstall-<arch>.gz)')],
    'help': f'Dux through its unattended installer, from {RELEASES}. The step runs only the installer whose release and SHA-256 it names; a report of a step without them says which release is newest.'},
    ('user', 'compositor', 'terminal', 'version', 'installer_sha'), lambda p: f'Dux {p.get("version") or ""} for {p["user"]} with {p["compositor"]}'.replace('  ', ' '), _check_dux,
    _ansible('t_dux_install', ('user', 'compositor', 'terminal', 'version', 'installer_sha')))

changes.register('desktop-profile', {'group': 'Desktop', 'label': 'Write a desktop profile', 'fields': [
    F('profile', 'name', 'Profile', required=True), F('user', 'user', 'For this user', required=True), F('compositor', 'choice', 'Compositor', options=list(desktop.COMPOSITORS), required=True)],
    'help': 'Keys, window rules and displays from a profile kept on the server, as a file of its own that the user\'s configuration includes.'},
    ('profile', 'user', 'compositor'), lambda p: f'Desktop profile {p["profile"]} for {p["user"]} ({p["compositor"]})', _check_profile,
    _ansible('t_desktop_profile', ('profile', 'user', 'compositor'), with_conn=True), args_of=_profile_args)

changes.EXTRA_BASH.append(bash())
