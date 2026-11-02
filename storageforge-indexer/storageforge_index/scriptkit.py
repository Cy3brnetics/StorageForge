"""Shared pieces of the Bash scripts StorageForge writes (moves, share deployment): output in storage-setup.sh's
style (ok / missing / conflict / ->), and --host, which copies the script to another machine and runs it there
with sudo, forwarding your SSH agent."""
import datetime as dt
import re

from .db import Conn, loads

# A host as plans name it: hostname, IPv4, [IPv6] or IPv6%zone. Never a line break, space or leading '-'.
HOST_RE = re.compile(r'[A-Za-z0-9_.:\[\]%-]{1,253}')
# Bash ends a comment at a line break, and terminals act on escape sequences when a script is read with cat or less.
_BREAKS = re.compile('[\x00-\x08\x0a-\x1f\x7f\x85\u2028\u2029]+')


def host_name(value, what: str) -> str:
    h = str(value or '').strip()
    if not HOST_RE.fullmatch(h) or h.startswith('-'):
        raise ValueError(f'{what} must be a host name or address')
    return h


def longest_gap(day_matches, minutes: list[int]) -> int | None:
    """Seconds between the two furthest-apart runs of a schedule, over four years so leap days count. day_matches(date) says
    whether it runs that day, minutes when in the day. None when it never runs."""
    first = dt.date(2024, 1, 1).toordinal()
    span = 1461
    days = [o for o in range(first, first + span) if day_matches(dt.date.fromordinal(o))]
    times = sorted(set(minutes))
    if not days or not times:
        return None
    within = max((b - a for a, b in zip(times, times[1:])), default=0)
    # a day that comes once in the four years waits for its next time round; otherwise the window's own seam is no real gap
    pairs = zip(days, days[1:]) if len(days) > 1 else [(days[0], days[0] + span)]
    across = max((b - a) * 1440 + times[0] - times[-1] for a, b in pairs)
    return max(within, across) * 60


def one_line(text) -> str:
    """Text safe to put after # in a generated script: control characters and line breaks become spaces."""
    return _BREAKS.sub(' ', str(text))


def comments(lines, empty: str) -> str:
    """Header comment lines, each forced onto one line, so no value can end the comment and start a command."""
    return '\n'.join(one_line(l) for l in lines) or empty


HELPERS = r"""if [[ -t 1 ]]; then G=$'\e[32m' Y=$'\e[33m' R=$'\e[31m' B=$'\e[34m' H=$'\e[1m' N0=$'\e[0m'; else G= Y= R= B= H= N0=; fi
section()  { printf '\n%s== %s ==%s\n' "$H" "$*" "$N0"; }
ok()       { printf '  %-9s %s\n' "${G}ok${N0}" "$*"; }
missing()  { printf '  %-9s %s\n' "${Y}missing${N0}" "$*"; MISSING=$((MISSING + 1)); }
conflict() { printf '  %-9s %s\n' "${R}conflict${N0}" "$*"; PROBLEMS=$((PROBLEMS + 1)); }
info()     { printf '  %-9s %s\n' "" "$*"; }
doing()    { printf '  %-9s %s\n' "${Y}->${N0}" "$*"; }
skip()     { printf '  %-9s %s\n' "${B}other${N0}" "$*"; }
PROBLEMS=0 MISSING=0
finished() { if ((${APPLY:-0} && MISSING)); then echo "${Y}$MISSING step(s) not finished${N0}"; else echo "${G}done${N0}"; fi; }
host_slug() { local n=${1%%.*}; n=$(tr 'A-Z' 'a-z' <<<"$n" | tr -cd 'a-z0-9_-'); echo "${n:-unknown}"; }
human() { numfmt --to=iec-i --suffix=B "${1:-0}" 2>/dev/null || echo "$1 B"; }
"""

# Run a command where a btrfs or ZFS stream lands: here when the login is empty, else over SSH as root on this host,
# with sudo unless it logs in as root. The stream is the command's stdin, so checks give it </dev/null.
DEST_CMD = r"""dest_cmd() { # login port command...
  local login=$1 port=$2 line; shift 2
  if [[ -z $login ]]; then "$@"; return; fi
  [[ $login == root@* ]] || set -- sudo -n "$@"
  printf -v line ' %q' "$@"
  ssh -p "$port" -o BatchMode=yes -o ConnectTimeout=15 -- "$login" "$line"
}
"""

# Needs ARGS (the original arguments) and HOST set by the caller's option parsing; FWD_AGENT=1 with --forward-agent.
REMOTE = r"""# ── remote: copy this script over, run it there with sudo, clean up (like storage-setup.sh --host) ──
if [[ -n $HOST ]]; then
  [[ $HOST == -* ]] && { echo "--host: not a host name: $HOST" >&2; exit 2; }
  CTL=$(mktemp -d); trap 'ssh -o ControlPath="$CTL/s" -O exit "$HOST" 2>/dev/null; rm -rf "$CTL"' EXIT
  SSHO=(-o ControlMaster=auto -o ControlPath="$CTL/s" -o ControlPersist=60 -o ConnectTimeout=10)
  REST=(); skipnext=0
  for a in "${ARGS[@]}"; do if ((skipnext)); then skipnext=0; continue; fi; if [[ $a == --host ]]; then skipnext=1; continue; fi; REST+=("$a"); done
  tmp=$(ssh "${SSHO[@]}" -- "$HOST" 'mktemp -d /tmp/sf-move.XXXXXX')
  scp -q -o ControlPath="$CTL/s" -- "$0" "$HOST:$tmp/move.sh"
  # ssh hands the remote side one command line, which its shell splits again: every argument goes quoted
  qtmp=$(printf %q "$tmp") qrest=; ((${#REST[@]})) && printf -v qrest ' %q' "${REST[@]}"
  # Your SSH agent is forwarded only with --forward-agent: while it runs, root on that host can use it to log in
  # wherever your keys work. A step that pulls from a third host needs it (or a key on that host).
  FWD=(); ((${FWD_AGENT:-0})) && FWD=(-A)
  ssh "${SSHO[@]}" ${FWD[@]+"${FWD[@]}"} -t -- "$HOST" "cd $qtmp && if [ \$(id -u) = 0 ]; then bash ./move.sh$qrest; else sudo --preserve-env=SSH_AUTH_SOCK bash ./move.sh$qrest; fi; rc=\$?; rm -rf $qtmp; exit \$rc"
  exit $?
fi
"""


# what deploys need on a host: the program that shows it is there, and its package per package manager
NEEDS = {'NFS server': ('exportfs', {'apt-get': 'nfs-kernel-server', 'dnf': 'nfs-utils', 'yum': 'nfs-utils', 'pacman': 'nfs-utils', 'zypper': 'nfs-kernel-server'}),
         'Samba': ('smbd', {'apt-get': 'samba', 'dnf': 'samba', 'yum': 'samba', 'pacman': 'samba', 'zypper': 'samba'}),
         'NFS client': ('mount.nfs', {'apt-get': 'nfs-common', 'dnf': 'nfs-utils', 'yum': 'nfs-utils', 'pacman': 'nfs-utils', 'zypper': 'nfs-client'}),
         'SMB client': ('mount.cifs', {'apt-get': 'cifs-utils', 'dnf': 'cifs-utils', 'yum': 'cifs-utils', 'pacman': 'cifs-utils', 'zypper': 'cifs-utils'}),
         'rsync': ('rsync', {'apt-get': 'rsync', 'dnf': 'rsync', 'yum': 'rsync', 'pacman': 'rsync', 'zypper': 'rsync'}),
         'rsnapshot': ('rsnapshot', {'apt-get': 'rsnapshot', 'dnf': 'rsnapshot', 'yum': 'rsnapshot', 'pacman': 'rsnapshot', 'zypper': 'rsnapshot'}),
         'git': ('git', {'apt-get': 'git', 'dnf': 'git', 'yum': 'git', 'pacman': 'git', 'zypper': 'git'}),
         'python3': ('python3', {'apt-get': 'python3', 'dnf': 'python3', 'yum': 'python3', 'pacman': 'python', 'zypper': 'python3'}),
         'duperemove': ('duperemove', {'apt-get': 'duperemove', 'dnf': 'duperemove', 'yum': 'duperemove', 'pacman': 'duperemove', 'zypper': 'duperemove'}),
         'snapper': ('snapper', {'apt-get': 'snapper', 'dnf': 'snapper', 'yum': 'snapper', 'pacman': 'snapper', 'zypper': 'snapper'}),
         'btrfs-progs': ('btrfs', {'apt-get': 'btrfs-progs', 'dnf': 'btrfs-progs', 'yum': 'btrfs-progs', 'pacman': 'btrfs-progs', 'zypper': 'btrfsprogs'})}


def package_check(conn: Conn, h: dict, what: str) -> tuple[str, str]:
    """From the host's last scan: is this installed, and if not, what would a deploy install with what?"""
    inv = loads(conn.scalar('SELECT inventory_json FROM hosts WHERE host_id = :h', {'h': h['id']})) or {}
    text = inv.get('packages')
    if not text:
        return 'note', f'rescan {h["name"]} to see whether it needs the {what} installed'
    words = [line.split(None, 1) for line in text.splitlines() if ' ' in line]
    have = {v for k, v in words if k == 'have'}
    manager = next((v for k, v in words if k == 'pm'), None)
    cmd, packages = NEEDS[what]
    if cmd in have:
        return 'ok', f'{what} is installed on {h["name"]}'
    if manager not in packages:
        return 'crit', (f'{what} is not installed on {h["name"]}, and it has no package manager StorageForge knows '
                        f'(apt, dnf, yum, zypper, pacman): install it by hand and rescan')
    epel = ' (from EPEL, which it enables if it has to)' if what == 'rsnapshot' and manager in ('dnf', 'yum') else ''
    return 'note', f'{what} is not installed on {h["name"]}: the deploy installs {packages[manager]} with {manager}{epel}'


def need_line(what: str) -> str:
    """The script line that checks for this and, on --apply, installs it. The script needs PACKAGES."""
    cmd, p = NEEDS[what]
    return f'need_cmd {cmd} "{what}" {p["apt-get"]} {p["dnf"]} {p["pacman"]} {p["zypper"]}\n'


# Needs APPLY and the HELPERS. The host decides when the script runs: the scan only predicts it.
PACKAGES = r"""pm() { for m in apt-get dnf yum zypper pacman; do command -v $m >/dev/null && { echo $m; return; }; done; echo none; }
apt_install() { DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=120 install -y -qq "$1" 2>&1; }
install_pkg() { # manager package
  case $1 in
    apt-get) apt_install "$2" || { apt-get -o DPkg::Lock::Timeout=120 update -qq 2>&1 && apt_install "$2"; } ;;   # the package lists may be stale
    dnf|yum) "$1" install -y -q "$2" 2>&1 && return 0
      # some packages only come from EPEL on RHEL and its rebuilds. Rocky and Alma carry epel-release in their own repos.
      [[ $2 == rsnapshot ]] || return 1
      "$1" install -y -q epel-release 2>&1 && "$1" install -y -q "$2" 2>&1 ;;
    zypper) zypper -nq install "$2" 2>&1 ;;
    pacman) pacman -S --needed --noconfirm "$2" 2>&1 || { echo "(the pacman package lists may be out of date: run pacman -Syu on the host, reboot if the kernel changed, then deploy again)"; return 1; } ;;   # no -Sy: refreshing without upgrading is a partial upgrade
  esac
}
need_cmd() { # command what apt rpm arch suse
  if command -v "$1" >/dev/null; then ok "$2 installed"; return 0; fi
  local m pkg out; m=$(pm)
  case $m in apt-get) pkg=$3 ;; dnf|yum) pkg=$4 ;; pacman) pkg=$5 ;; zypper) pkg=$6 ;;
    *) conflict "$2 is missing and this host has no package manager I know (apt, dnf, yum, zypper, pacman): install it yourself"; return 1 ;;
  esac
  if ((!APPLY)); then missing "$2 (would install $pkg with $m)"; return 0; fi
  doing "install $2: $pkg with $m"
  if out=$(install_pkg "$m" "$pkg") && command -v "$1" >/dev/null; then ok "$2 installed"; return 0; fi
  out=$(tail -n 3 <<<"$out" | tr '\n' ' ')
  conflict "could not install $pkg with $m: ${out:-it stopped without saying why; if the host is short of memory, it may have been killed (dmesg)}"; return 1
}
"""

# Needs PACKAGES
CIFS_KERNEL = r"""cifs_kernel() { # the mount needs cifs and, for iocharset=utf8, nls_utf8. Cloud images keep them in another package
  command -v modprobe >/dev/null || return 0
  if modprobe -n cifs 2>/dev/null && modprobe -n nls_utf8 2>/dev/null; then ok "kernel has cifs and nls_utf8"; return 0; fi
  local m pkg pkgs=() kernel; m=$(pm); kernel=$(uname -r)
  case $m in
    apt-get) pkgs=("linux-modules-extra-$kernel") ;;
    dnf|yum) pkgs=("kernel-modules-$kernel" "kernel-modules-extra-$kernel") ;;
    zypper) pkgs=(kernel-default-optional) ;;
    *) conflict "kernel $kernel has no cifs or nls_utf8, and no package I know has them here: install it yourself"; return 1 ;;
  esac
  if ((!APPLY)); then missing "kernel modules cifs and nls_utf8 (would install ${pkgs[*]} with $m)"; return 0; fi
  for pkg in "${pkgs[@]}"; do
    doing "install kernel modules: $pkg with $m"
    install_pkg "$m" "$pkg" >/dev/null 2>&1 || true
    if modprobe -n cifs 2>/dev/null && modprobe -n nls_utf8 2>/dev/null; then ok "kernel has cifs and nls_utf8"; return 0; fi
  done
  conflict "kernel $kernel still has no cifs or nls_utf8 after installing ${pkgs[*]}: if the host has a newer kernel waiting, reboot into it"; return 1
}
"""
