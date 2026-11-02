"""System updates: every host's own package manager, run as one deploy.

    report  ──► refresh the package lists, say what would be installed, change nothing else
    --apply ──► install it, keeping local config files, then say what is left and whether a reboot is waiting

A deploy of kind 'updates', so it is signed, audited, cancellable and retried like any other. Hosts run side by side and
one failing stops none of the others: they don't depend on each other's packages. It never reboots: that stays a
decision for whoever knows what the host is doing, so the Deploy panel only shows which hosts wait for one.
Appliances are left out: TrueNAS, XCP-ng and XenServer update through their own tools, and this would break them.
"""
from __future__ import annotations

import re

from . import deploy, preflight
from .remote import REFUSE_APPLIANCE
from .scriptkit import HELPERS, PACKAGES, host_name

KIND = 'updates'
ALL = 'all'
PARALLEL = 16             # "all at once", within reason: each host holds an ssh and writes its output every second
TIMEOUT = 3600            # a Proxmox or kernel upgrade on slow disks takes a while
RESULT = re.compile(r'^sf-updates manager=(\S+) pending=(\d+|unknown) reboot=(yes|no)$', re.M)

BODY = r"""set -o pipefail
export LC_ALL=C DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l     # needrestart lists what to restart: no prompt, no surprise restarts
APPLY=0; [[ ${1:-} == --apply ]] && APPLY=1
APT=(-o DPkg::Lock::Timeout=300)
# Proxmox only supports dist-upgrade. Elsewhere: nothing gets removed to make an upgrade fit.
if [[ $platform == proxmox* ]]; then APT_UPGRADE=(dist-upgrade); else APT_UPGRADE=(upgrade --with-new-pkgs); fi
ZYPPER_UPGRADE=update ZYPPER_LIST=list-updates
if grep -qs '^ID="\?opensuse-tumbleweed' /etc/os-release; then ZYPPER_UPGRADE=dist-upgrade ZYPPER_LIST='list-updates --dup'; fi
m=$(pm)

result() { printf 'sf-updates manager=%s pending=%s reboot=%s\n' "$m" "$1" "$(reboot_waiting)"; }
reboot_waiting() {
  local waiting=no newest
  [[ -e /run/reboot-required ]] && waiting=yes
  case $m in
    dnf|yum) if command -v needs-restarting >/dev/null; then needs-restarting -r >/dev/null 2>&1 || waiting=yes; fi ;;
    zypper) zypper -n needs-rebooting >/dev/null 2>&1; (($? == 102)) && waiting=yes ;;
  esac
  if [[ $platform == proxmox* ]]; then       # Proxmox kernels leave no /run/reboot-required
    newest=$(ls /boot/vmlinuz-*-pve 2>/dev/null | sort -V | tail -n 1)
    [[ -n $newest && $newest != "/boot/vmlinuz-$(uname -r)" ]] && waiting=yes
  fi
  # the running kernel's modules are gone once it is replaced. A container has none and no kernel of its own.
  if ! systemd-detect-virt -cq 2>/dev/null && [[ ! -d /lib/modules/$(uname -r) ]]; then waiting=yes; fi
  echo "$waiting"
}
refresh() {
  case $m in
    apt-get) apt-get "${APT[@]}" update -qq </dev/null 2>&1 ;;
    zypper) zypper -n refresh </dev/null 2>&1 ;;
    *) ;;                                    # dnf and yum refresh as they look. pacman must not: -Sy without -u is a partial upgrade
  esac
}
pending() { # the names of what would be upgraded. 1: could not tell. 3: this host has no way to tell without changing it
  local out rc
  case $m in
    apt-get) apt-get -s "${APT_UPGRADE[@]}" </dev/null 2>/dev/null | awk '/^Inst /{print $2}' ;;
    dnf|yum) out=$("$m" -q check-update </dev/null 2>/dev/null); rc=$?
      case $rc in 0) ;; 100) awk 'NF == 3 && $1 ~ /\./ {print $1}' <<<"$out" | sort -u ;; *) return 1 ;; esac ;;
    zypper) zypper -n --quiet $ZYPPER_LIST </dev/null 2>/dev/null | awk -F'|' '$1 ~ /^v/ {gsub(/ /, "", $3); print $3}' ;;
    pacman) command -v checkupdates >/dev/null || return 3
      out=$(checkupdates </dev/null 2>/dev/null); rc=$?
      case $rc in 0) awk '{print $1}' <<<"$out" ;; 2) ;; *) return 1 ;; esac ;;
  esac
}
count() { # sets NAMES and COUNT
  local rc
  NAMES=$(pending); rc=$?
  case $rc in 0) COUNT=$(grep -c . <<<"$NAMES" || true) ;; 3) COUNT=unknown ;; *) return 1 ;; esac
}
upgrade_command() {
  case $m in
    apt-get) UPGRADE=(apt-get -y "${APT[@]}" -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold "${APT_UPGRADE[@]}") ;;
    dnf|yum) UPGRADE=("$m" -y upgrade) ;;
    zypper) UPGRADE=(zypper -n "$ZYPPER_UPGRADE") ;;
    pacman) UPGRADE=(pacman -Syu --noconfirm) ;;
  esac
}
upgrade() { # Detached and writing to a file: losing the connection or a force stop must not kill a package manager half way through
  local log pid rc
  log=$(mktemp /var/log/storageforge/update.XXXXXX 2>/dev/null || mktemp) || return 1
  (
    trap '' HUP PIPE INT TERM
    if [[ $m == apt-get ]]; then setsid dpkg --force-confdef --force-confold --configure -a >>"$log" 2>&1; fi   # an upgrade that was cut short before
    setsid "${UPGRADE[@]}" >>"$log" 2>&1
    echo $? >"$log.rc"
  ) </dev/null >/dev/null 2>&1 &
  pid=$!
  tail -n +1 -f --pid="$pid" "$log"
  wait "$pid"
  rc=$(cat "$log.rc" 2>/dev/null); rc=${rc:-1}
  rm -f "$log" "$log.rc"
  [[ $m == zypper ]] && ((rc >= 100 && rc <= 103)) && rc=0     # worked, and says a reboot or a restart is waiting
  return "$rc"
}

section "System updates on $(uname -n)"
if [[ $m == none ]]; then
  conflict 'no package manager I know here (apt, dnf, yum, zypper, pacman): update this host yourself'
  result unknown; exit 1
fi
if ! out=$(refresh); then
  conflict "could not refresh the package lists with $m: $(tail -n 3 <<<"$out" | tr '\n' ' ')"
  if [[ $platform == proxmox* ]]; then info "without a subscription, turn the paid repository off under Node > Updates > Repositories"; fi
  result unknown; exit 1
fi
if ! count; then conflict "$m could not say what needs updating"; result unknown; exit 1; fi
free=$(df -Pm /var 2>/dev/null | awk 'NR==2 {print $4}')
if [[ $free =~ ^[0-9]+$ ]] && ((free < @@LOW_DISK@@)); then
  conflict "only $free MiB free in /var: make room before updating"
  ((APPLY)) && { result "$COUNT"; exit 1; }
fi
if [[ $COUNT == 0 ]]; then
  ok 'already up to date'
elif ((!APPLY)); then
  if [[ $COUNT == unknown ]]; then
    skip 'pacman cannot count updates without refreshing its lists, which on its own would risk a partial upgrade: install pacman-contrib to see them here'
  else
    missing "$COUNT update(s) with $m"
    head -n 40 <<<"$NAMES" | while IFS= read -r name; do info "$name"; done
    ((COUNT > 40)) && info "and $((COUNT - 40)) more"
  fi
else
  doing "install ${COUNT/unknown/all} update(s) with $m"
  upgrade_command
  if ! upgrade; then
    conflict "$m stopped with an error: read the lines above. Local config files were left as they were"
    count || COUNT=unknown
    result "$COUNT"; exit 1
  fi
  count || COUNT=unknown
  [[ $COUNT == unknown ]] && COUNT=0        # -Syu ended well, and pacman leaves nothing behind
  if ((COUNT)); then missing "$COUNT update(s) still waiting: held back or newly released"; else ok 'up to date'; fi
fi
if [[ $(reboot_waiting) == yes ]]; then skip 'waiting for a reboot: StorageForge never reboots a host for you'; fi
result "$COUNT"
"""
SCRIPT = (REFUSE_APPLIANCE + HELPERS + PACKAGES + BODY).replace('@@LOW_DISK@@', str(preflight.LOW_DISK_MIB))


def deploy_items(conn, ref: str, mode: str) -> list[dict]:
    """One run per host. ref is one host, or 'all': every host set up for deploys that can take this."""
    if ref == ALL:
        ready = [a['host'] for a in deploy.access(conn) if a['state'] == 'ready']
        blocked = {b['host'] for b in preflight.blockers(conn, ready, KIND)}
        hosts = [h for h in ready if h not in blocked]
    else:
        hosts = [deploy.canonical(conn, host_name(ref, 'the host'))]
    return [{'host': h, 'script': SCRIPT, 'args': ['--apply'] if mode == 'apply' else [], 'kind': KIND, 'ref': ref, 'mode': mode,
             'timeout': TIMEOUT, 'phase': 0} for h in hosts]


def group_options(kind: str | None, mode: str) -> dict:
    """How a deploy of this kind runs. Hosts don't wait on each other for updates, so a failure stops only its own host."""
    if kind == KIND:
        return {'stop_on_failure': False, 'parallel': PARALLEL}
    return {'stop_on_failure': mode == 'apply'}


def parse(text: str | None) -> dict:
    found = RESULT.findall(text or '')
    if not found:
        return {'manager': None, 'pending': None, 'reboot': None}
    manager, count, reboot = found[-1]
    return {'manager': manager, 'pending': None if count == 'unknown' else int(count), 'reboot': reboot == 'yes'}


def overview(conn) -> list[dict]:
    """Each host set up for deploys, with what its last check or update found. All of it comes from deploy_runs."""
    hosts = [a['host'] for a in deploy.access(conn) if a['state'] == 'ready']
    why = {}
    for b in preflight.blockers(conn, hosts, KIND):
        why.setdefault(b['host'], b['text'])
    out = []
    for host in hosts:
        last = conn.all("""SELECT run_id, group_id, status, output, started_at, finished_at FROM deploy_runs
                           WHERE kind = :k AND host = :h ORDER BY run_id DESC LIMIT 1""", {'k': KIND, 'h': host})
        applied = conn.scalar("""SELECT max(finished_at) FROM deploy_runs WHERE kind = :k AND host = :h AND mode = 'apply' AND status = 'ok'""",
                              {'k': KIND, 'h': host})
        row = {'host': host, 'blocked': why.get(host), 'status': None, 'group': None, 'checked_at': None, 'updated_at': applied,
               'manager': None, 'pending': None, 'reboot': None}
        if last:
            _, gid, status, text, started, finished = last[0]
            row.update(parse(text), status=status, group=gid, checked_at=finished or started)
        out.append(row)
    return out
