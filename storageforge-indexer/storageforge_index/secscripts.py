"""The Bash that ransomware defense runs on hosts. security.py decides; everything that touches a host is written here.

Every script follows the rules in docs/concepts.md: with no flags it only reports, values reach Bash as data (shlex.quote,
or base64 for paths), and it checks the result of what it did. Lines the controller acts on (HELD, QUARANTINED, CANARY,
STEP...) are printed only after that check, so a row in the database means the thing happened.

A script that fails says so. Nothing here ends in `|| true` to look finished.
"""
from __future__ import annotations

import base64
import shlex

from .scriptkit import HELPERS, PACKAGES, need_line

CONF = '/etc/storageforge/security'
STATE = '/var/lib/storageforge/security'
FORENSICS = '/var/lib/storageforge/forensics'
UNITS = '/etc/systemd/system'
MANAGED = '/var/lib/storageforge/managed'
SBIN = '/usr/local/sbin'
SENTINEL = f'{SBIN}/storageforge-sentinel'
BRAKE = f'{SBIN}/storageforge-brake'
FENCE = f'{SBIN}/storageforge-fence'
AUDIT_RULES = '/etc/audit/rules.d/storageforge-security.rules'
CANARY_KEY = 'sf_canary'
BRAKE_ACTIONS = ('triage', 'quarantine', 'snapshot', 'freeze')
SEBOOLEANS = ('samba_export_all_rw', 'samba_export_all_ro', 'samba_enable_home_dirs', 'nfs_export_all_rw', 'nfs_export_all_ro')
SYSCTLS = {'fs.protected_symlinks': '1', 'fs.protected_hardlinks': '1', 'fs.suid_dumpable': '0', 'kernel.kptr_restrict': '2',
           'kernel.dmesg_restrict': '1', 'kernel.randomize_va_space': '2', 'net.ipv4.conf.all.rp_filter': '1',
           'net.ipv4.conf.all.accept_redirects': '0', 'net.ipv4.tcp_syncookies': '1'}
UMASK = '027'

# Tests run these unprivileged. Under the runner they are root, and this does nothing.
ROOTS = rf"""CONF={CONF} STATE={STATE} FORENSICS={FORENSICS} UNITS={UNITS} MANAGED={MANAGED} SBIN={SBIN}
if ((EUID != 0)) && [[ -n ${{SF_SEC_ROOT:-}} ]]; then
  CONF=$SF_SEC_ROOT$CONF STATE=$SF_SEC_ROOT$STATE FORENSICS=$SF_SEC_ROOT$FORENSICS UNITS=$SF_SEC_ROOT$UNITS MANAGED=$SF_SEC_ROOT$MANAGED SBIN=$SF_SEC_ROOT$SBIN
fi
"""

# The table a quarantine lives in. Its own base chains at a priority ahead of firewalld, ufw and iptables-nft, so it
# works beside whichever of them the host runs, and a drop here cannot be undone by an accept there.
FENCE_LIB = r"""fence_rules() { cat <<'SF_NFT'
table inet storageforge_fence {
  set q4 {
    type ipv4_addr
    flags interval,timeout
  }
  set q6 {
    type ipv6_addr
    flags interval,timeout
  }
  chain input {
    type filter hook input priority -200; policy accept;
    ip saddr @q4 drop
    ip6 saddr @q6 drop
  }
  chain forward {
    type filter hook forward priority -200; policy accept;
    ip saddr @q4 drop
    ip6 saddr @q6 drop
  }
}
SF_NFT
}
fence_ready() { nft list table inet storageforge_fence >/dev/null 2>&1 || fence_rules | nft -f -; }
fence_set() { if [[ $1 == *:* ]]; then echo q6; else echo q4; fi; }
fence_has() { nft get element inet storageforge_fence "$(fence_set "$1")" "{ $1 }" >/dev/null 2>&1; }
fence_add() { # address seconds (0: until someone lifts it)
  local set to=; set=$(fence_set "$1"); (($2 > 0)) && to=" timeout ${2}s"
  nft delete element inet storageforge_fence "$set" "{ $1 }" 2>/dev/null || :   # a new timeout replaces the old one
  nft add element inet storageforge_fence "$set" "{ $1$to }"
}
fence_remember() { # address expires(0: never). Comes back after a reboot through storageforge-fence.
  mkdir -p "$CONF"; local tmp; tmp=$(mktemp "$CONF/.quarantine.XXXXXX")
  { [[ -r $CONF/quarantine.list ]] && awk -v ip="$1" '$1 != ip' "$CONF/quarantine.list"; [[ -z ${2:-} ]] || printf '%s %s\n' "$1" "$2"; } >"$tmp" || :
  chmod 0644 "$tmp"; mv -f "$tmp" "$CONF/quarantine.list"
}
"""

# Whatever else happens, the address this signed run came in from must keep reaching the host.
PEER_LIB = r"""run_peer() { # walks up to the sshd that started this run, and asks ss who is on its other end
  local p=$$ c peer
  while ((p > 1)); do
    c=$(cat "/proc/$p/comm" 2>/dev/null) || return 0
    if [[ $c == sshd* ]]; then
      peer=$(ss -tnpH 2>/dev/null | awk -v t="pid=$p," 'index($0, t) {print $5; exit}')
      if [[ -n $peer ]]; then peer=${peer%:*}; peer=${peer#[}; peer=${peer%]}; echo "${peer#::ffff:}"; return 0; fi
    fi
    p=$(awk '/^PPid:/ {print $2}' "/proc/$p/status" 2>/dev/null) || return 0
    [[ -n $p ]] || return 0
  done
}
ip_num() { local IFS=. a b c d; read -r a b c d <<<"$1"; echo $(((a << 24) + (b << 16) + (c << 8) + d)); }
overlaps() { # two addresses or networks. IPv4 by range; IPv6 only as the same text, the controller has compared them properly
  local x=${1%/*} y=${2%/*} xb=${1##*/} yb=${2##*/} bits m
  if [[ $1 == *:* || $2 == *:* ]]; then [[ $x == "$y" ]]; return; fi
  [[ $xb == "$1" ]] && xb=32; [[ $yb == "$2" ]] && yb=32
  bits=$((xb < yb ? xb : yb)); m=$(((0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF))
  (( ($(ip_num "$x") & m) == ($(ip_num "$y") & m) ))
}
"""


def b64(text: str) -> str:
    return base64.b64encode(text.encode('utf-8', 'surrogateescape')).decode()


def head(*libs: str) -> str:
    return ('#!/usr/bin/env bash\n# Written by StorageForge. With no flags it only reports.\nset -eu\n'
            + HELPERS + ROOTS + ''.join(libs))


APPLY_ONLY = r"""APPLY=0
for a in "$@"; do case $a in --apply) APPLY=1 ;; --dry-run) APPLY=0 ;; *) echo "unknown option: $a" >&2; exit 2 ;; esac; done
"""


# ── measuring: read only ─────────────────────────────────────────────
MEASURE_BODY = r"""
sec() { printf '@@%s\n' "$1"; }
try() { timeout 20 "$@" 2>/dev/null || :; }
has() { command -v "$1" >/dev/null; }
sec now; date +%s
sec uptime; cut -d. -f1 /proc/uptime
sec tools; for c in nft firewall-cmd ufw iptables getenforce aa-status auditctl aide lynis falco chronyc inotifywait clamscan yara smbd exportfs zfs btrfs python3 curl; do has "$c" && echo "$c"; done
sec selinux; has getenforce && try getenforce
sec sebool; has getsebool && for b in "${BOOLEANS[@]}"; do try getsebool "$b"; done
sec apparmor; if has aa-status; then try aa-status --enabled && echo enabled; try aa-status | sed -n 's/^\([0-9][0-9]*\) profiles are in \(enforce\|complain\) mode.*/\2 \1/p'; fi
sec avc; has ausearch && try ausearch --input-logs -m avc -ts recent --raw | grep -a 'denied' | tail -n 50
sec chrony; has chronyc && try chronyc -c tracking
sec chrony_auth; has chronyc && try chronyc -c authdata
sec timedatectl; has timedatectl && try timedatectl show -p NTPSynchronized -p NTP
sec auditd; has systemctl && try systemctl is-active auditd; has auditctl && try auditctl -l | grep -a -c -- 'key=sf_\|-k sf_' || :
sec fence; if has nft; then try nft list tables | sed -n 's/^table inet \(storageforge_[a-z]*\)$/\1/p'; fi
sec quarantined; if has nft; then for s in q4 q6; do try nft list set inet storageforge_fence "$s" | tr ',{}' '\n\n\n' | sed -n 's/^[[:space:]]*\([0-9a-fA-F:.][0-9a-fA-F:./]*\)\( .*\)\{0,1\}$/\1/p'; done; fi
sec sysctl; for k in "${SYSCTLS[@]}"; do printf '%s=%s\n' "$k" "$(sysctl -n "$k" 2>/dev/null)"; done
sec umask; cat /etc/profile.d/storageforge-umask.sh 2>/dev/null || :
sec aide; has aide && { for f in /var/lib/aide/aide.db /var/lib/aide/aide.db.gz; do [[ -r $f ]] && stat -c 'db %Y' "$f"; done; cat "$STATE/aide.last" 2>/dev/null || :; }
sec lynis; if [[ -r $STATE/lynis-report.dat ]]; then stat -c 'at %Y' "$STATE/lynis-report.dat"; grep -aE '^(hardening_index|warning\[\]|suggestion\[\])=' "$STATE/lynis-report.dat" | head -n 200; fi
sec falco; has falco && { try systemctl is-active falco; try systemctl is-active falco-modern-bpf; }
sec sentinel; has systemctl && try systemctl is-active sf-sentinel.service; [[ -r $CONF/sentinel.conf ]] && grep -a '^ARMED=' "$CONF/sentinel.conf"
sec holds_zfs; if has zfs && ((${#ZFS_SNAPS[@]})); then for z in "${ZFS_SNAPS[@]}"; do try zfs holds -H "$z"; done | awk -F'\t' '$2 ~ /^sf-/ {print $1 "\t" $2}'; fi
sec holds_btrfs; for p in "${BTRFS_PATHS[@]}"; do [[ -d $p ]] && printf '%s\t%s\n' "$(printf %s "$p" | base64 -w0)" "$(try btrfs property get -ts "$p" ro)"; done
sec zfs_allow; if has zfs; then for z in $(try zfs list -H -o name -t filesystem | head -n 200); do try zfs allow "$z"; done | grep -aE '(user|group) .*(destroy|release)' | sort -u | head -n 50; fi
sec canaries; while IFS=' ' read -r line; do [[ -n $line ]] || continue; p=$(base64 -d <<<"$line"); if [[ -f $p ]]; then printf '%s\t%s\n' "$line" "$(sha256sum -- "$p" | cut -d' ' -f1)"; else printf '%s\tgone\n' "$line"; fi; done <<<"${CANARIES:-}"
sec fcontext; for m in "${MOUNTS[@]}"; do if has getenforce && [[ -e $m ]]; then c=$(stat -c %C -- "$m" 2>/dev/null) || c=; e=$(has matchpathcon && matchpathcon -n -- "$m" 2>/dev/null) || e=; printf '%s\t%s\t%s\n' "$(printf %s "$m" | base64 -w0)" "$c" "$e"; fi; done
sec samba; has testparm && try testparm -sl | grep -aEc 'shadow_copy2' || :
sec events; [[ -r $STATE/events.tsv ]] && tail -n 500 "$STATE/events.tsv"
sec audit_rules; has auditctl && try auditctl -l | grep -a 'sf_' | head -n 60
sec snapshots; has zfs && try zfs list -H -t snapshot -o name -s creation | tail -n 500
sec sessions; [[ -r $STATE/sessions.tsv ]] && tail -n 200 "$STATE/sessions.tsv"
sec falco_alerts
# named fields only: a rule's output text can hold a command line, and everything printed here lands in deploy_runs
if [[ -r $STATE/falco.jsonl ]]; then tail -n 200 "$STATE/falco.jsonl" | while IFS= read -r l; do
  f() { if [[ $l =~ \"$1\":\"([^\"]*)\" ]]; then printf '%s' "${BASH_REMATCH[1]}"; fi; }
  printf 'a\t%s\t%s\t%s\t%s\t%s\t%s\n' "$(f rule)" "$(f priority)" "$(f time)" "$(f proc.name)" "$(f fs.path.target)$(f fd.name)" "$(f user.name)"
done; fi
sec end
"""


def bash_array(name: str, values) -> str:
    return f'{name}=(' + ' '.join(shlex.quote(str(v)) for v in values) + ')\n'


def measure_script(zfs_snaps=(), btrfs_paths=(), canaries=(), mounts=()) -> str:
    """Reads what the host is, as root through the runner, and changes nothing."""
    return ('#!/usr/bin/env bash\n# Written by StorageForge. Only reads.\nset -u\nexport LC_ALL=C\n' + ROOTS
            + bash_array('BOOLEANS', SEBOOLEANS) + bash_array('SYSCTLS', SYSCTLS) + bash_array('ZFS_SNAPS', zfs_snaps)
            + bash_array('BTRFS_PATHS', btrfs_paths) + bash_array('MOUNTS', mounts)
            + f'CANARIES={shlex.quote(chr(10).join(b64(p) for p in canaries))}\n' + MEASURE_BODY)


# ── retention holds ──────────────────────────────────────────────────
HOLD_BODY = r"""
section "Retention hold on $SNAP"
if [[ $SNAP == *@* ]]; then
  command -v zfs >/dev/null || { conflict "zfs is not on this host"; exit 1; }
  if ! zfs list -H -t snapshot -o name -- "$SNAP" >/dev/null 2>&1; then
    if ((CREATE == 0)); then conflict "$SNAP does not exist"; exit 1; fi
    if ((APPLY)); then doing "take $SNAP"; zfs snapshot -- "$SNAP"; else missing "$SNAP: --apply takes it"; fi
  fi
  if zfs holds -H -- "$SNAP" 2>/dev/null | cut -f2 | grep -qxF -- "$TAG"; then
    ok "$TAG holds $SNAP"
  elif ((APPLY)); then
    doing "hold $SNAP with $TAG"; zfs hold -- "$TAG" "$SNAP"
    zfs holds -H -- "$SNAP" | cut -f2 | grep -qxF -- "$TAG" || { conflict "the hold did not take"; exit 1; }
    ok "$TAG holds $SNAP"
  else
    missing "hold $TAG on $SNAP"; finished; exit 0
  fi
  echo "HELD zfs $(printf %s "$SNAP" | base64 -w0) $(printf %s "$TAG" | base64 -w0)"
else
  command -v btrfs >/dev/null || { conflict "btrfs is not on this host"; exit 1; }
  btrfs subvolume show -- "$SNAP" >/dev/null 2>&1 || { conflict "$SNAP is not a btrfs snapshot"; exit 1; }
  if [[ $(btrfs property get -ts -- "$SNAP" ro 2>/dev/null) == 'ro=true' ]]; then
    ok "$SNAP is read-only"
  elif ((APPLY)); then
    doing "make $SNAP read-only"; btrfs property set -ts -- "$SNAP" ro true
    [[ $(btrfs property get -ts -- "$SNAP" ro) == 'ro=true' ]] || { conflict "it is still writable"; exit 1; }
  else
    missing "make $SNAP read-only"; finished; exit 0
  fi
  info "btrfs has no hold: root can make this writable again. Only a copy on another machine is out of its reach"
  echo "HELD btrfs $(printf %s "$SNAP" | base64 -w0) $(printf %s "$TAG" | base64 -w0)"
fi
finished
"""

RELEASE_BODY = r"""
section "Release $TAG from $SNAP"
if [[ $SNAP == *@* ]]; then
  command -v zfs >/dev/null || { conflict "zfs is not on this host"; exit 1; }
  if ! zfs holds -H -- "$SNAP" 2>/dev/null | cut -f2 | grep -qxF -- "$TAG"; then
    ok "$TAG no longer holds $SNAP"
  elif ((APPLY)); then
    doing "release"; zfs release -- "$TAG" "$SNAP"; ok "released"
  else
    missing "release $TAG from $SNAP"; finished; exit 0
  fi
else
  info "btrfs: the snapshot stays read-only. Making it writable or deleting it is a separate, deliberate step"
fi
echo "RELEASED $(printf %s "$SNAP" | base64 -w0)"
finished
"""


def hold_script(snapshot: str, tag: str, create: bool = False) -> str:
    return (head() + APPLY_ONLY + f'SNAP={shlex.quote(snapshot)} TAG={shlex.quote(tag)} CREATE={1 if create else 0}\n' + HOLD_BODY)


def release_script(snapshot: str, tag: str) -> str:
    return (head() + APPLY_ONLY + f'SNAP={shlex.quote(snapshot)} TAG={shlex.quote(tag)}\n' + RELEASE_BODY)


# ── firewall ─────────────────────────────────────────────────────────
QUARANTINE_BODY = r"""
section "Quarantine $IP"
if ! command -v nft >/dev/null; then
  if ((APPLY == 0)); then missing "nftables is not installed: --apply installs it first"; finished; exit 0; fi
  @NEED@
  command -v nft >/dev/null || { conflict "nft is not on this host, and could not be installed"; exit 1; }
fi
peer=$(run_peer)
if [[ -n $peer ]] && overlaps "$IP" "$peer"; then
  conflict "$IP covers $peer, the address StorageForge reaches this host from: this would cut it off"; exit 1
fi
if fence_has "$IP"; then ok "$IP is already dropped"; fi
if ((APPLY == 0)); then doing "would drop all traffic from $IP$( ((SECONDS_FOR)) && echo " for $SECONDS_FOR s")"; finished; exit 0; fi
fence_ready
fence_add "$IP" "$SECONDS_FOR"
fence_has "$IP" || { conflict "$IP is not in the set after adding it"; exit 1; }
if ((SECONDS_FOR)); then fence_remember "$IP" "$(($(date +%s) + SECONDS_FOR))"; else fence_remember "$IP" 0; fi
ok "$IP is dropped"
echo "QUARANTINED $IP"
finished
"""

UNQUARANTINE_BODY = r"""
section "Lift the quarantine on $IP"
command -v nft >/dev/null || { conflict "nft is not on this host"; exit 1; }
if ! fence_has "$IP"; then ok "$IP is not dropped"
elif ((APPLY == 0)); then missing "lift $IP"; finished; exit 0
else
  doing "lift $IP"
  nft delete element inet storageforge_fence "$(fence_set "$IP")" "{ $IP }"
  fence_has "$IP" && { conflict "$IP is still in the set"; exit 1; }
fi
if ((APPLY)); then fence_remember "$IP" ""; echo "LIFTED $IP"; fi
finished
"""

# Everything but the controller is cut, established connections included: an attacker's open SMB session must not survive.
# Applying arms a dead man's switch first, and only --confirm, which has to reach the host through the new rules, stops it.
AIRGAP_BODY = r"""
ACTION=report
for a in "$@"; do case $a in --apply) ACTION=engage ;; --confirm) ACTION=confirm ;; --disarm) ACTION=disarm ;; *) echo "unknown option: $a" >&2; exit 2 ;; esac; done
APPLY=0; [[ $ACTION == report ]] || APPLY=1
section "Emergency airgap"
if ! command -v nft >/dev/null; then # asked for in an emergency, so it gets what it needs, while the host can still reach a mirror
  if [[ $ACTION == report ]]; then missing "nftables is not installed: --apply installs it first"; finished; exit 0; fi
  @NEED@
  command -v nft >/dev/null || { conflict "nft is not on this host, and could not be installed"; exit 1; }
fi
engaged=0; nft list table inet storageforge_airgap >/dev/null 2>&1 && engaged=1
case $ACTION in
  disarm)
    if ((engaged)); then doing "remove the airgap"; nft delete table inet storageforge_airgap; fi
    systemctl stop sf-airgap-rollback.timer 2>/dev/null || :
    nft list table inet storageforge_airgap >/dev/null 2>&1 && { conflict "the airgap table is still there"; exit 1; }
    ok "airgap off"; echo "AIRGAP off"; exit 0 ;;
  confirm)
    ((engaged)) || { conflict "the airgap is not engaged: it may have rolled itself back"; exit 1; }
    systemctl stop sf-airgap-rollback.timer
    ok "still reachable through the airgap: the rollback is cancelled"; echo "AIRGAP on"; exit 0 ;;
esac
peer=$(run_peer)
keep=("${CONTROLLERS[@]}"); [[ -n $peer ]] && keep+=("$peer")
((${#keep[@]})) || { conflict "I cannot tell which address StorageForge reaches this host from: not cutting the network"; exit 1; }
v4=() v6=()
for k in "${keep[@]}"; do if [[ $k == *:* ]]; then v6+=("$k"); else v4+=("$k"); fi; done
join() { local IFS=,; echo "$*"; }
rules() {
  echo 'table inet storageforge_airgap {'
  for c in input:saddr output:daddr; do
    echo "  chain ${c%:*} {"
    echo "    type filter hook ${c%:*} priority -300; policy drop;"
    if [[ $c == input:* ]]; then echo '    iif "lo" accept'; else echo '    oif "lo" accept'; fi
    ((${#v4[@]})) && echo "    ip ${c#*:} { $(join "${v4[@]}") } accept"
    ((${#v6[@]})) && echo "    ip6 ${c#*:} { $(join "${v6[@]}") } accept"
    echo '  }'
  done
  echo '  chain forward {'
  echo '    type filter hook forward priority -300; policy drop;'
  echo '  }'
  echo '}'
}
info "would keep only: ${keep[*]}"
rules | nft -c -f - || { conflict "nft rejected the rules"; exit 1; }
ok "nft accepts the rules"
if ((engaged)); then ok "the airgap is engaged"; echo "AIRGAP on"; exit 0; fi
if [[ $ACTION == report ]]; then missing "airgap: --apply cuts everything but the addresses above"; finished; exit 0; fi
command -v systemd-run >/dev/null || { conflict "systemd-run is missing: no way to undo this if it locks StorageForge out, so it does not start"; exit 1; }
systemd-run --quiet --unit=sf-airgap-rollback --on-active="$ROLLBACK" --timer-property=AccuracySec=5s nft delete table inet storageforge_airgap
doing "cut the network (rolls itself back in $ROLLBACK unless confirmed)"
rules | nft -f -
echo "AIRGAP pending"
"""


def quarantine_script(ip: str, seconds: int) -> str:
    return head(FENCE_LIB, PEER_LIB) + PACKAGES + APPLY_ONLY + f'IP={shlex.quote(ip)} SECONDS_FOR={int(seconds)}\n' + QUARANTINE_BODY.replace('@NEED@', need_line('nftables').strip())


def unquarantine_script(ip: str) -> str:
    return head(FENCE_LIB) + APPLY_ONLY + f'IP={shlex.quote(ip)}\n' + UNQUARANTINE_BODY


def airgap_script(controllers=(), rollback: str = '10min') -> str:
    return head(PEER_LIB) + PACKAGES + bash_array('CONTROLLERS', controllers) + f'ROLLBACK={shlex.quote(rollback)}\n' + AIRGAP_BODY.replace('@NEED@', need_line('nftables').strip())


# ── the emergency brake ──────────────────────────────────────────────
# Installed on the host, so a trip does not wait for the controller, and run by hand through the runner with the same flags.
# Its steps run in this order: what is lost by waiting comes first, and a btrfs snapshot cannot be taken once it is read-only.
BRAKE_SCRIPT = r"""#!/usr/bin/env bash
# storageforge-brake: written by StorageForge. With no --apply it says what it would do. Every step reports its outcome.
set -u
export LC_ALL=C
if ((EUID == 0)) || [[ -z ${SF_SEC_ROOT:-} ]]; then export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; fi
@ROOTS@@FENCE_LIB@@PEER_LIB@
APPLY=0 TARGET= CLIENT= PID= REASON= ACTIONS=triage,quarantine,snapshot,freeze MINUTES=0
for a in "$@"; do case $a in
  --apply) APPLY=1 ;;
  --path=*) TARGET=$(base64 -d <<<"${a#*=}") || TARGET= ;;
  --client=*) CLIENT=${a#*=} ;;
  --pid=*) PID=${a#*=} ;;
  --reason=*) REASON=$(base64 -d <<<"${a#*=}") || REASON= ;;
  --actions=*) ACTIONS=${a#*=} ;;
  --minutes=*) MINUTES=${a#*=} ;;
  *) echo "unknown option: $a" >&2; exit 2 ;;
esac; done
wants() { [[ ,$ACTIONS, == *,$1,* ]]; }
step() { echo "STEP $1 $2 ${3:-}"; [[ $2 != failed ]] || FAILED=1; }
FAILED=0 stamp=$(date -u +%Y%m%d-%H%M%S)-$$
[[ -z $TARGET || $TARGET == /* ]] || { echo "not an absolute path" >&2; exit 2; }
[[ $PID =~ ^[0-9]*$ ]] || { echo "bad pid" >&2; exit 2; }
[[ -z $CLIENT || $CLIENT =~ ^[0-9A-Fa-f:.]+(/[0-9]+)?$ ]] || { echo "bad address" >&2; exit 2; }
[[ $MINUTES =~ ^[0-9]+$ ]] || { echo "bad duration" >&2; exit 2; }

if wants triage; then
  dir=$FORENSICS/$stamp
  if ((APPLY == 0)); then step triage skipped "would save connections, sessions and processes to $dir"
  elif mkdir -p "$dir" && chmod 0700 "$FORENSICS" "$dir"; then
    { printf 'at %s\nreason %s\npath %s\nclient %s\npid %s\n' "$stamp" "$REASON" "$TARGET" "$CLIENT" "$PID"; } >"$dir/incident.txt"
    timeout 5 ss -tnp >"$dir/sockets.txt" 2>&1
    timeout 5 ps auxww >"$dir/processes.txt" 2>&1
    if command -v smbstatus >/dev/null; then timeout 5 smbstatus >"$dir/smbstatus.txt" 2>&1; fi
    if command -v ausearch >/dev/null; then timeout 5 ausearch --input-logs -k @KEY@ -ts recent >"$dir/audit.txt" 2>&1 </dev/null; fi
    if [[ -n $PID && -d /proc/$PID ]]; then
      for f in cmdline environ maps; do cp "/proc/$PID/$f" "$dir/proc-$f" 2>/dev/null; done
      ls -l "/proc/$PID/fd" >"$dir/proc-fd.txt" 2>&1
      if command -v gcore >/dev/null; then timeout 20 gcore -o "$dir/core" "$PID" >/dev/null 2>&1; fi
    fi
    chattr -R +i "$dir" 2>/dev/null
    step triage ok "$dir"
  else
    step triage failed "cannot write $dir"
  fi
fi

if wants quarantine; then
  vip=
  if [[ -n $CLIENT && -r $CONF/vip.list ]]; then
    while read -r v; do [[ -n $v ]] && overlaps "$CLIENT" "$v" && vip=$v; done <"$CONF/vip.list"
  fi
  peer=$(run_peer)
  if [[ -z $CLIENT ]]; then step quarantine skipped "no client address is known for this event"
  elif [[ -n $vip ]]; then step quarantine skipped "$CLIENT is on the exempt list ($vip)"
  elif [[ -n $peer ]] && overlaps "$CLIENT" "$peer"; then step quarantine skipped "$CLIENT is how StorageForge reaches this host"
  elif ! command -v nft >/dev/null; then step quarantine failed "nft is not on this host"
  elif ((APPLY == 0)); then step quarantine skipped "would drop $CLIENT"
  elif fence_ready && fence_add "$CLIENT" "$((MINUTES * 60))" && fence_has "$CLIENT"; then
    if ((MINUTES)); then fence_remember "$CLIENT" "$(($(date +%s) + MINUTES * 60))"; else fence_remember "$CLIENT" 0; fi
    step quarantine ok "$CLIENT"; echo "QUARANTINED $CLIENT"
  else
    step quarantine failed "could not add $CLIENT to the set"
  fi
fi

fstype= source= mnt=
if [[ -n $TARGET ]]; then read -r fstype source mnt < <(findmnt -rno FSTYPE,SOURCE,TARGET -T "$TARGET" 2>/dev/null | head -n 1); fi

if wants snapshot; then
  case $fstype in
    zfs)
      if ((APPLY == 0)); then step snapshot skipped "would take and hold $source@sf-incident-$stamp"
      elif zfs snapshot -- "$source@sf-incident-$stamp" && zfs hold -- sf-incident "$source@sf-incident-$stamp"; then
        step snapshot ok "$source@sf-incident-$stamp"
        echo "HELD zfs $(printf %s "$source@sf-incident-$stamp" | base64 -w0) $(printf sf-incident | base64 -w0)"
      else step snapshot failed "could not snapshot and hold $source"; fi ;;
    btrfs)
      snap=$mnt/.sf-incident-$stamp
      if ((APPLY == 0)); then step snapshot skipped "would take read-only $snap"
      elif btrfs subvolume snapshot -r -- "$mnt" "$snap" >/dev/null; then
        step snapshot ok "$snap"
        echo "HELD btrfs $(printf %s "$snap" | base64 -w0) $(printf sf-incident | base64 -w0)"
      else step snapshot failed "could not snapshot $mnt"; fi ;;
    '') step snapshot skipped "no path was given, or it is not on a mount" ;;
    *) step snapshot skipped "$fstype has no snapshots" ;;
  esac
fi

if wants freeze; then
  case $mnt in
    '') step freeze skipped "no path was given, or it is not on a mount" ;;
    /|/usr|/usr/*|/boot|/boot/*|/etc|/etc/*|/var|/var/lib|/var/log) step freeze skipped "$mnt runs this host: it stays writable. Stop the share instead" ;;
    *)
      if ((APPLY == 0)); then step freeze skipped "would make $mnt read-only"
      elif [[ $fstype == zfs ]]; then
        if zfs set readonly=on -- "$source"; then step freeze ok "$source is read-only"; else step freeze failed "could not set $source read-only"; fi
      elif err=$(mount -o remount,ro -- "$mnt" 2>&1); then step freeze ok "$mnt is read-only"
      else step freeze failed "${err:-could not remount $mnt read-only}: writers may still hold it"; fi ;;
  esac
fi
exit "$FAILED"
"""


def brake_program() -> str:
    return (BRAKE_SCRIPT.replace('@ROOTS@', ROOTS).replace('@FENCE_LIB@', FENCE_LIB).replace('@PEER_LIB@', PEER_LIB).replace('@KEY@', CANARY_KEY))


def brake_args(path: str = '', client: str = '', pid: int = 0, reason: str = '', actions=BRAKE_ACTIONS, minutes: int = 0, apply: bool = False) -> list[str]:
    args = ['--apply'] if apply else []
    if path:
        args.append(f'--path={b64(path)}')
    if client:
        args.append(f'--client={client}')
    if pid:
        args.append(f'--pid={int(pid)}')
    if reason:
        args.append(f'--reason={b64(reason)}')
    args += [f'--actions={",".join(actions)}', f'--minutes={int(minutes)}']
    return args


# ── the sentinel: watches decoys and the clock, reports, and pulls the brake if armed ─
SENTINEL_SCRIPT = r"""#!/bin/bash
# storageforge-sentinel: written by StorageForge. Watches its decoy files and the clock.
set -u
export LC_ALL=C
if ((EUID == 0)) || [[ -z ${SF_SEC_ROOT:-} ]]; then export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; fi
@ROOTS@ARMED=0 ACTIONS=triage,quarantine,snapshot,freeze MINUTES=60 REPORT_URL= CLOCK_EVERY=30
# shellcheck disable=SC1091
. "$CONF/sentinel.conf"
EVENTS=$STATE/events.tsv
b64() { printf %s "$1" | base64 -w0; }
send() {
  [[ -n $REPORT_URL && -r $CONF/report.header ]] && command -v curl >/dev/null || return 0
  local ca=(); [[ -r /etc/storageforge/report-ca.pem ]] && ca=(--cacert /etc/storageforge/report-ca.pem)
  curl -fsS -m 5 ${ca[@]+"${ca[@]}"} -H @"$CONF/report.header" -H 'Content-Type: application/json' \
    --data-binary "{\"lines\":[\"${1//$'\t'/\\t}\"]}" "$REPORT_URL/api/security/report" >/dev/null 2>&1 &
}
emit() { # kind summary detail
  local line
  line=$(printf 'ev\t%s\t%s\t%s\t%s\t%s' "$(cat /proc/sys/kernel/random/uuid)" "$1" "$(date +%s)" "$(b64 "$2")" "$(b64 "${3:-}")")
  printf '%s\n' "$line" >>"$EVENTS"
  send "$line"
  if (($(stat -c %s "$EVENTS") > 1048576)); then tail -n 1000 "$EVENTS" >"$EVENTS.new" && mv -f "$EVENTS.new" "$EVENTS"; fi
}
client_of() { # smbd runs one process per client, so its pid finds the address. NFS is served by the kernel, and has no such pid
  local peer
  peer=$(ss -tnpH 2>/dev/null | awk -v t="pid=$1," 'index($0, t) && $4 ~ /:(445|139)$/ {print $5; exit}')
  peer=${peer%:*}; peer=${peer#[}; peer=${peer%]}; echo "${peer#::ffff:}"
}
who_did() { # path: "pid client", from the audit log, or else from Samba's list of open files
  local pid=
  if command -v ausearch >/dev/null; then
    pid=$(timeout 5 ausearch --input-logs -k @KEY@ -f "$1" -ts recent --raw 2>/dev/null | grep -a 'type=SYSCALL' | tail -n 1 | sed -n 's/.* pid=\([0-9]*\) .*/\1/p')
  fi
  if [[ -z $pid ]] && command -v smbstatus >/dev/null; then
    pid=$(timeout 5 smbstatus -L 2>/dev/null | awk -v f="${1##*/}" 'index($0, f) && $1 ~ /^[0-9]+$/ {print $1; exit}')
  fi
  [[ -n $pid ]] && echo "$pid $(client_of "$pid")"
}
trip() { # event path. In its own process with stdin closed: finding out who did it is slow, must not hold up the next event,
  # and the loop's stdin is the stream of events, which any program here that reads stdin (ausearch does) would eat
  local pid= client= out rc last
  read -r pid client < <(who_did "$2"; echo)
  [[ -z $pid ]] || emit canary_source "$2 was changed by pid $pid${client:+ from $client}" "path_b64=$(b64 "$2");client=$client;pid=$pid"
  ((ARMED)) || return 0
  exec 9>"$STATE/brake.lock"
  flock 9                                             # one at a time, and a burst of trips from one client is one brake
  last=$STATE/brake.last.${client:-unknown}
  [[ -e $last && $(($(date +%s) - $(stat -c %Y "$last"))) -lt 60 ]] && return 0
  touch "$last"
  out=$("$SBIN/storageforge-brake" --apply "--path=$(b64 "$2")" "--client=$client" "--pid=$pid" "--reason=$(b64 "decoy $2 changed")" "--actions=$ACTIONS" "--minutes=$MINUTES" 2>&1); rc=$?
  emit brake_ran "the brake ran on $2 (exit $rc)" "$(tail -c 8000 <<<"$out")"
}
clock_loop() { # wall clock against uptime: this catches date -s and a forged NTP answer, which NTP's own status would not
  local now up boot last
  last=$(($(date +%s) - $(cut -d. -f1 /proc/uptime)))    # from the start: a jump in the first half minute must not become the baseline
  while sleep "$CLOCK_EVERY"; do
    now=$(date +%s); up=$(cut -d. -f1 /proc/uptime); boot=$((now - up))
    if ((boot - last > 60 || last - boot > 60)); then
      emit clock_jump "the clock moved $((boot - last)) s against uptime" "from=$last;to=$boot"
    fi
    last=$boot
  done
}
paths=$STATE/watch.paths test=$STATE/sentinel-test
: >"$paths"
[[ -e $test ]] || : >"$test"
printf '%s\n' "$test" >>"$paths"
while read -r line; do
  [[ -n $line ]] || continue
  p=$(base64 -d <<<"$line")
  if [[ -e $p ]]; then printf '%s\n' "$p" >>"$paths"; else emit canary_tripped "$p is gone" "path_b64=$line;event=GONE"; fi
done <"$CONF/canaries.list"
clock_loop &
clock=$!
trap 'kill "$clock" 2>/dev/null' EXIT
emit sentinel_started "watching $(($(wc -l <"$paths") - 1)) decoy(s), armed=$ARMED"
declare -A seen=()
inotifywait -m -q --format '%e|%w%f' -e modify,attrib,move_self,delete_self --fromfile "$paths" |
while IFS='|' read -r ev f; do
  now=$(date +%s)
  ((now - ${seen[$f]:-0} >= 60)) || continue          # one write is many events
  if [[ $f == "$test" ]]; then emit sentinel_test "the test file was touched" "ns=$(date +%s%N)"; continue; fi
  seen[$f]=$now
  emit canary_tripped "$f was changed ($ev)" "path_b64=$(b64 "$f");event=$ev"     # the alarm first: it waits for nothing
  trip "$ev" "$f" </dev/null &
done
emit watcher_stopped "inotifywait stopped" ""
exit 1
"""

FENCE_PROGRAM = r"""#!/usr/bin/env bash
# storageforge-fence: written by StorageForge. Puts the quarantine table and its addresses back after a reboot.
set -eu
export LC_ALL=C
if ((EUID == 0)) || [[ -z ${SF_SEC_ROOT:-} ]]; then export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; fi
@ROOTS@@FENCE_LIB@
fence_ready
[[ -r $CONF/quarantine.list ]] || exit 0
now=$(date +%s)
while read -r ip until; do
  [[ -n ${ip:-} ]] || continue
  if ((until == 0)); then fence_add "$ip" 0
  elif ((until > now)); then fence_add "$ip" "$((until - now))"
  fi
done <"$CONF/quarantine.list"
"""

SENTINEL_UNIT = f"""[Unit]
Description=StorageForge sentinel (watches decoy files and the clock)
After=network-online.target

[Service]
Type=simple
ExecStart={SENTINEL}
Restart=always
RestartSec=5
KillMode=control-group

[Install]
WantedBy=multi-user.target
"""

FENCE_UNIT = f"""[Unit]
Description=StorageForge quarantine table
Before=network-pre.target smbd.service nfs-server.service
Wants=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart={FENCE}

[Install]
WantedBy=multi-user.target
"""

# Decoys start with their format's real magic bytes, then random data, at sizes that differ: a tool that skips files
# full of zeros or all the same size still walks into them.
INSTALL_BODY = r"""
APPLY=0 REMOVE=0 TEST=0
for a in "$@"; do case $a in --apply) APPLY=1 ;; --uninstall) APPLY=1 REMOVE=1 ;; --test) TEST=1 ;; *) echo "unknown option: $a" >&2; exit 2 ;; esac; done
LIST=$CONF/canaries.list HASHES=$STATE/canaries.sha256

if ((TEST)); then
  section "Sentinel test"
  [[ -f $STATE/sentinel-test ]] || { conflict "the sentinel is not installed here"; exit 1; }
  systemctl is-active -q sf-sentinel.service 2>/dev/null || [[ -n ${SF_SEC_ROOT:-} ]] || { conflict "sf-sentinel.service is not running"; exit 1; }
  before=$(grep -ac $'\tsentinel_test\t' "$STATE/events.tsv" 2>/dev/null) || before=0
  start=$(date +%s%N)
  date >>"$STATE/sentinel-test"
  for _ in $(seq 1 100); do
    n=$(grep -ac $'\tsentinel_test\t' "$STATE/events.tsv" 2>/dev/null) || n=0
    if ((n > before)); then ms=$((($(date +%s%N) - start) / 1000000)); ok "the sentinel saw it in $ms ms"; echo "LATENCY $ms"; exit 0; fi
    sleep 0.1
  done
  conflict "the sentinel did not react within 10 s"; exit 1
fi

if ((REMOVE)); then
  section "Remove the sentinel"
  systemctl disable --now sf-sentinel.service 2>/dev/null || :
  systemctl disable --now sf-fence.service 2>/dev/null || :
  rm -f "$UNITS/sf-sentinel.service" "$UNITS/sf-fence.service" "$SBIN/storageforge-sentinel" "$SBIN/storageforge-brake" "$SBIN/storageforge-fence" \
    "$CONF/sentinel.conf" "$CONF/report.header" "$CONF/vip.list" "$AUDIT" "$MANAGED/security.sha256" "$STATE/watch.paths" "$STATE/sentinel-test"
  command -v augenrules >/dev/null && { augenrules --load >/dev/null 2>&1 || info "augenrules could not reload: the old rules stay until the next restart of auditd"; }
  if [[ -r $HASHES ]]; then
    while read -r line sha; do
      p=$(base64 -d <<<"$line")
      if [[ ! -e $p ]]; then continue; fi
      if [[ $(sha256sum -- "$p" | cut -d' ' -f1) == "$sha" ]]; then rm -f -- "$p"; ok "removed the decoy $p"
      else info "$p changed since it was written, so it stays: look at it"; fi
    done <"$HASHES"
  fi
  rm -f "$LIST" "$HASHES"
  systemctl daemon-reload 2>/dev/null || :
  [[ -s $CONF/quarantine.list ]] && info "addresses stay dropped until lifted or rebooted: $CONF/quarantine.list"
  ok "removed; events and forensics stay in $STATE and $FORENSICS"
  finished; exit 0
fi

section "What the sentinel needs"
@NEEDS@
command -v curl >/dev/null && ok "curl: events are reported at once" || info "no curl: events arrive with the next scan or measurement"
[[ -n $REPORT_URL_VALUE ]] && ok "reports go to $REPORT_URL_VALUE" || info "no report URL is set: events arrive with the next scan or measurement"

section "Decoys"
if ((APPLY)); then mkdir -p "$CONF" "$STATE" "$MANAGED" "$SBIN" "$UNITS"; chmod 0755 "$STATE"; touch "$HASHES"; fi
new_hashes=
for line in "${DECOYS[@]}"; do
  p=$(base64 -d <<<"$line"); dir=${p%/*}
  known=$(awk -v l="$line" '$1 == l {print $2}' "$HASHES" 2>/dev/null) || known=
  if [[ ! -d $dir ]]; then conflict "$dir is not there"; continue; fi
  if [[ -L $p ]] || { [[ -e $p ]] && [[ -z $known ]]; }; then conflict "$p exists and is not one of mine: it stays, and is not watched"; continue; fi
  if [[ -f $p ]] && { ((REARM == 0)) || [[ $(sha256sum -- "$p" | cut -d' ' -f1) == "$known" ]]; }; then
    ok "$p"
    new_hashes+="$line $known"$'\n'; echo "CANARY $line $known $(stat -c %s -- "$p")"; continue
  fi
  if ((APPLY == 0)); then missing "write the decoy $p"; continue; fi
  tmp=$(mktemp "$dir/.sf.XXXXXX")
  case ${p##*.} in
    docx|xlsx|pptx|zip) printf 'PK\003\004\024\000\006\000' >"$tmp" ;;
    pdf) printf '%%PDF-1.7\n%%\342\343\317\323\n' >"$tmp" ;;
    doc|xls) printf '\320\317\021\340\241\261\032\341' >"$tmp" ;;
    kdbx) printf '\003\331\242\232\147\373\113\265' >"$tmp" ;;
  esac
  head -c "$((16384 + RANDOM))" /dev/urandom >>"$tmp"
  chown --reference="$dir" "$tmp" 2>/dev/null || :
  # as writable as the folder it is in: a decoy whoever can change the files here cannot change would never trip
  if (((8#$(stat -c %a -- "$dir")) & 2)); then chmod 0666 "$tmp"; else chmod 0664 "$tmp"; fi
  mv -f -- "$tmp" "$p"
  sha=$(sha256sum -- "$p" | cut -d' ' -f1)
  doing "wrote $p"
  new_hashes+="$line $sha"$'\n'; echo "CANARY $line $sha $(stat -c %s -- "$p")"
done
if ((APPLY == 0)); then
  section "Service"
  [[ -f $UNITS/sf-sentinel.service ]] && ok "the sentinel is installed" || missing "the sentinel: --apply installs it"
  info "armed: $ARMED_VALUE (when armed, a trip runs: $ACTIONS_VALUE)"
  finished; exit 0
fi
# a decoy no longer asked for: off if unchanged, and otherwise it is someone's file now
while read -r line sha; do
  [[ -n ${line:-} ]] || continue
  case " ${DECOYS[*]} " in *" $line "*) continue ;; esac
  p=$(base64 -d <<<"$line")
  if [[ -f $p && $(sha256sum -- "$p" | cut -d' ' -f1) == "$sha" ]]; then rm -f -- "$p"; doing "removed the old decoy $p"; else info "$p changed, so it stays"; fi
done <"$HASHES"
printf '%s' "$new_hashes" >"$HASHES"
printf '%s\n' "${DECOYS[@]}" >"$LIST"
chmod 0644 "$LIST"; chmod 0600 "$HASHES"
: >"$STATE/sentinel-test"

section "Service"
install -m 0755 /dev/null "$SBIN/storageforge-sentinel"
cat >"$SBIN/storageforge-sentinel" <<'SF_SENTINEL'
@SENTINEL@SF_SENTINEL
install -m 0755 /dev/null "$SBIN/storageforge-brake"
cat >"$SBIN/storageforge-brake" <<'SF_BRAKE'
@BRAKE@SF_BRAKE
install -m 0755 /dev/null "$SBIN/storageforge-fence"
cat >"$SBIN/storageforge-fence" <<'SF_FENCE'
@FENCE@SF_FENCE
cat >"$CONF/sentinel.conf" <<SF_CONF
ARMED=$ARMED_VALUE
ACTIONS=$ACTIONS_VALUE
MINUTES=$MINUTES_VALUE
REPORT_URL=$REPORT_URL_VALUE
SF_CONF
chmod 0644 "$CONF/sentinel.conf"
printf '%s\n' ${VIPS[@]+"${VIPS[@]}"} >"$CONF/vip.list"
chmod 0644 "$CONF/vip.list"
if [[ -n $TOKEN_VALUE ]]; then
  (umask 077; printf 'Authorization: Bearer %s\n' "$TOKEN_VALUE" >"$CONF/report.header")
fi
@REPORT_CA@
if command -v auditctl >/dev/null; then
  mkdir -p "${AUDIT%/*}"
  {
    for line in "${DECOYS[@]}"; do
      p=$(base64 -d <<<"$line")
      case $p in *[[:space:]]*) ;; *) [[ -f $p ]] && echo "-w $p -p wa -k @KEY@" ;; esac    # audit rules cannot hold a space: inotify still watches it
    done
    for f in /etc/fstab /etc/samba/smb.conf /etc/exports; do [[ -e $f ]] && echo "-w $f -p wa -k sf_config"; done
    echo "-w $SBIN/storageforge-run -p wa -k sf_runner"
    echo "-w $SBIN/storageforge-sentinel -p wa -k sf_runner"
    echo "-w $SBIN/storageforge-brake -p wa -k sf_runner"
  } >"$AUDIT"
  durable "$AUDIT"
  if command -v augenrules >/dev/null && augenrules --load >/dev/null 2>&1; then ok "audit rules loaded"
  else missing "audit rules are written but did not load: is auditd running?"; fi
fi
cat >"$UNITS/sf-sentinel.service" <<'SF_UNIT'
@SENTINEL_UNIT@SF_UNIT
cat >"$UNITS/sf-fence.service" <<'SF_UNIT'
@FENCE_UNIT@SF_UNIT
sha256sum "$SBIN/storageforge-sentinel" "$SBIN/storageforge-brake" "$SBIN/storageforge-fence" "$UNITS/sf-sentinel.service" "$UNITS/sf-fence.service" >"$MANAGED/security.sha256"
chmod 0644 "$MANAGED/security.sha256"
durable "$CONF/sentinel.conf" "$UNITS/sf-sentinel.service" "$UNITS/sf-fence.service"
reload_systemd
systemctl enable --now sf-fence.service 2>&1 && ok "quarantine table on"
systemctl enable sf-sentinel.service 2>&1
systemctl restart sf-sentinel.service
sleep 1
if systemctl is-active -q sf-sentinel.service; then ok "sentinel running, armed: $ARMED_VALUE"; else conflict "the sentinel did not stay up: journalctl -u sf-sentinel.service"; exit 1; fi
finished
"""


def install_script(*, decoys, armed: bool, actions, minutes: int, report_url: str, token: str, vips, report_ca: str | None = None, rearm: bool = False) -> str:
    needs = need_line('inotify-tools') + need_line('nftables') + need_line('auditd')
    ca = (f"mkdir -p /etc/storageforge\ncat >/etc/storageforge/report-ca.pem <<'SF_CA'\n{report_ca}SF_CA\nchmod 0644 /etc/storageforge/report-ca.pem\n" if report_ca else '')
    body = INSTALL_BODY
    for k, v in (('@NEEDS@', needs.rstrip()), ('@SENTINEL@', SENTINEL_SCRIPT), ('@BRAKE@', brake_program()),
                 ('@FENCE@', FENCE_PROGRAM.replace('@ROOTS@', ROOTS).replace('@FENCE_LIB@', FENCE_LIB)),
                 ('@SENTINEL_UNIT@', SENTINEL_UNIT), ('@FENCE_UNIT@', FENCE_UNIT), ('@REPORT_CA@', ca), ('@KEY@', CANARY_KEY), ('@ROOTS@', ROOTS)):
        body = body.replace(k, v)
    return (head() + PACKAGES + f'AUDIT={shlex.quote(AUDIT_RULES)}\nif ((EUID != 0)); then AUDIT=${{SF_SEC_ROOT:-}}$AUDIT; fi\n' + bash_array('DECOYS', [b64(d) for d in decoys]) + bash_array('VIPS', vips)
            + f'REARM={1 if rearm else 0} ARMED_VALUE={1 if armed else 0} ACTIONS_VALUE={shlex.quote(",".join(actions))} MINUTES_VALUE={int(minutes)}\n'
            + f'REPORT_URL_VALUE={shlex.quote(report_url)} TOKEN_VALUE={shlex.quote(token)}\n' + body)


# ── mandatory access control ─────────────────────────────────────────
RELABEL_BODY = r"""
section "SELinux type of $TARGET"
command -v semanage >/dev/null || { conflict "semanage is not here: it comes with policycoreutils-python-utils"; exit 1; }
[[ -e $TARGET ]] || { conflict "$TARGET is not there"; exit 1; }
current=$(stat -c %C -- "$TARGET" | cut -d: -f3)
if [[ $current == "$TYPE" ]]; then ok "$TARGET is $TYPE"; finished; exit 0; fi
if ((APPLY == 0)); then missing "$TARGET is $current: --apply registers $TYPE and relabels"; finished; exit 0; fi
doing "semanage fcontext for $TARGET"
semanage fcontext -a -t "$TYPE" "$TARGET(/.*)?" 2>/dev/null || semanage fcontext -m -t "$TYPE" "$TARGET(/.*)?"
doing "restorecon $TARGET"
relabel_tree "$TARGET"
[[ $(stat -c %C -- "$TARGET" | cut -d: -f3) == "$TYPE" ]] || { conflict "$TARGET still is not $TYPE"; exit 1; }
ok "$TARGET is $TYPE"
finished
"""

BOOLEAN_BODY = r"""
section "SELinux boolean $NAME"
command -v setsebool >/dev/null || { conflict "setsebool is not here"; exit 1; }
current=$(getsebool "$NAME" | awk '{print $NF}')
if [[ $current == "$VALUE" ]]; then ok "$NAME is $VALUE"; finished; exit 0; fi
if ((APPLY == 0)); then missing "$NAME is $current: --apply sets it $VALUE"; finished; exit 0; fi
doing "setsebool -P $NAME $VALUE"
setsebool -P "$NAME" "$VALUE"
[[ $(getsebool "$NAME" | awk '{print $NF}') == "$VALUE" ]] || { conflict "$NAME did not change"; exit 1; }
ok "$NAME is $VALUE"
finished
"""


def relabel_script(path: str, se_type: str) -> str:
    return head() + APPLY_ONLY + f'TARGET={shlex.quote(path)} TYPE={shlex.quote(se_type)}\n' + RELABEL_BODY


def boolean_script(name: str, value: str) -> str:
    return head() + APPLY_ONLY + f'NAME={shlex.quote(name)} VALUE={shlex.quote(value)}\n' + BOOLEAN_BODY


# ── AIDE and Lynis: slow, so they run on their own and the next measurement reads the result ─
TOOL_BODY = r"""
section "$TITLE"
command -v "$NEEDS" >/dev/null || { if ((APPLY)); then @NEED@ else missing "$NEEDS: --apply installs it"; finished; exit 0; fi; }
if systemctl is-active -q "$UNIT.service" 2>/dev/null; then ok "already running"; finished; exit 0; fi
if ((APPLY == 0)); then doing "would start it in the background: the next measurement reads the result"; finished; exit 0; fi
mkdir -p "$STATE"
tmp=$(mktemp "$STATE/.$UNIT.XXXXXX")
cat >"$tmp" <<'SF_JOB'
#!/usr/bin/env bash
set -u
export LC_ALL=C PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
STATE=$1
conf=(); for f in /etc/aide/aide.conf /etc/aide.conf; do [[ -r $f ]] && conf=(--config="$f") && break; done
@JOB@
SF_JOB
chmod 0700 "$tmp"; mv -f "$tmp" "$STATE/$UNIT.sh"
systemd-run --quiet --collect --unit="$UNIT" -p Nice=19 -p IOSchedulingClass=idle "$STATE/$UNIT.sh" "$STATE"
ok "started: the next measurement reads the result"
finished
"""

AIDE_INIT = r"""start=$(date +%s)
if command -v aideinit >/dev/null; then aideinit -y -f >/dev/null 2>&1; rc=$?
else aide ${conf[@]+"${conf[@]}"} --init >/dev/null 2>&1; rc=$?
  if ((rc == 0)); then mv -f /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz; rc=$?; fi
fi
printf 'init %s %s\n' "$start" "$rc" >"$STATE/aide.last"
"""

AIDE_CHECK = r"""start=$(date +%s)
out=$(aide ${conf[@]+"${conf[@]}"} --check 2>&1); rc=$?
printf 'check %s %s\n' "$start" "$rc" >"$STATE/aide.last"
printf '%s\n' "$out" | grep -aE '^ *(Added|Removed|Changed) (entries|files):|^(added|removed|changed): /|^f[-+!~ ]+: /' | head -n 200 >>"$STATE/aide.last"
"""

LYNIS_RUN = r"""lynis audit system --quick --no-colour --cronjob --report-file "$STATE/lynis-report.new" >/dev/null 2>&1
if [[ -s $STATE/lynis-report.new ]]; then chmod 0644 "$STATE/lynis-report.new"; mv -f "$STATE/lynis-report.new" "$STATE/lynis-report.dat"; fi
"""


def tool_script(tool: str, watch=()) -> str:
    job, title, need, what, unit = {
        'aide-init': (AIDE_INIT, 'Make the AIDE baseline', 'aide', 'aide', 'sf-aide'),
        'aide-check': (AIDE_CHECK, 'Check files against the AIDE baseline', 'aide', 'aide', 'sf-aide'),
        'lynis': (LYNIS_RUN, 'Lynis audit', 'lynis', 'lynis', 'sf-lynis'),
    }[tool]
    if watch and tool.startswith('aide'):              # extra paths, on the command line of aide itself. Validated by the controller, then quoted
        rules = ''.join(f'{shlex.quote(p + " p+i+n+u+g+s+b+sha256")} ' for p in watch)
        job = job.replace('aide ${conf[@]+"${conf[@]}"} --', f'aide ${{conf[@]+"${{conf[@]}}"}} $(for r in {rules}; do printf -- "--before=%s\\n" "$r"; done | tr "\\n" " ") --')
    body = TOOL_BODY.replace('@JOB@', job).replace('@NEED@', need_line(what).strip() + ';')
    return (head() + PACKAGES + APPLY_ONLY + f'TITLE={shlex.quote(title)} NEEDS={shlex.quote(need)} UNIT={shlex.quote(unit)}\n' + body)


# ── reading changed files: fed over stdin, never trusting a name ─────
ENTROPY_PY = r"""
import base64, collections, math, os, sys
n = 0
for line in sys.stdin:
    if n >= 2000:
        break
    n += 1
    raw = line.strip()
    try:
        path = base64.b64decode(raw, validate=True)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except (OSError, ValueError):
        continue
    try:
        st = os.fstat(fd)
        if not (st.st_mode & 0o170000 == 0o100000):
            continue
        data = os.read(fd, 4096)
    except OSError:
        continue
    finally:
        os.close(fd)
    if len(data) < 512:
        continue
    c = collections.Counter(data)
    h = -sum(v / len(data) * math.log2(v / len(data)) for v in c.values())
    print('E', raw, f'{h:.4f}', data[:16].hex(), st.st_size, sep='\t')
"""


def entropy_script() -> str:
    return ('#!/usr/bin/env bash\n# Written by StorageForge. Only reads the first 4 KiB of the files it is given.\nset -eu\n'
            'export LC_ALL=C\ncommand -v python3 >/dev/null || { echo "NO python3"; exit 0; }\n'
            f'exec nice -n 19 python3 -I -c {shlex.quote(ENTROPY_PY)}\n')


DIFF_SCAN = r"""#!/usr/bin/env bash
# Written by StorageForge. Only reads: a detection is reported, never touched.
set -u
export LC_ALL=C
command -v clamscan >/dev/null || { echo "NO clamscan"; exit 0; }
list=$(mktemp); out=$(mktemp); trap 'rm -f "$list" "$out"' EXIT
n=0
while IFS= read -r line; do
  p=$(base64 -d <<<"$line" 2>/dev/null) || continue
  [[ -f $p && ! -L $p ]] || continue
  printf '%s\n' "$p" >>"$list"; n=$((n + 1))
done
start=$(date +%s)
if ((n)); then nice -n 19 clamscan --no-summary --infected --stdout --file-list="$list" >"$out" 2>/dev/null; rc=$?; else rc=0; fi
echo "SCANNED $n $rc $(($(date +%s) - start))"
while IFS= read -r line; do
  [[ $line == *' FOUND' ]] || continue
  sig=${line% FOUND}; path=${sig%: *}; sig=${sig##*: }
  printf 'found\t%s\t%s\n' "$(printf %s "$path" | base64 -w0)" "$(tr -cd 'A-Za-z0-9._:+-' <<<"$sig")"
done <"$out"
"""


# ── the clean room: a snapshot mounted where no share and no program can use it ─
CLEANROOM_BODY = r"""
APPLY=0 REMOVE=0
for a in "$@"; do case $a in --apply) APPLY=1 ;; --remove) APPLY=1 REMOVE=1 ;; *) echo "unknown option: $a" >&2; exit 2 ;; esac; done
section "Clean room at $MNT"
if ((REMOVE)); then
  if mountpoint -q -- "$MNT"; then umount -- "$MNT"; doing "unmounted"; fi
  rmdir -- "$MNT" 2>/dev/null || :
  ok "no clean room here"; finished; exit 0
fi
if mountpoint -q -- "$MNT"; then ok "already mounted"; echo "CLEANROOM $MNT"; finished; exit 0; fi
if [[ $SNAP == *@* ]]; then
  zfs list -H -t snapshot -o name -- "$SNAP" >/dev/null 2>&1 || { conflict "$SNAP does not exist"; exit 1; }
else
  [[ -d $SNAP ]] || { conflict "$SNAP does not exist"; exit 1; }
fi
if ((APPLY == 0)); then missing "mount $SNAP read-only, with no programs or devices, at $MNT"; finished; exit 0; fi
mkdir -p -m 0700 -- "$MNT"
if [[ $SNAP == *@* ]]; then
  mount -t zfs -o ro,noexec,nodev,nosuid -- "$SNAP" "$MNT"
else
  mount --bind -- "$SNAP" "$MNT"
  mount -o remount,bind,ro,noexec,nodev,nosuid -- "$MNT"
fi
mountpoint -q -- "$MNT" || { conflict "it did not mount"; exit 1; }
touch -- "$MNT/.sf-write-test" 2>/dev/null && { rm -f -- "$MNT/.sf-write-test"; umount -- "$MNT"; conflict "the mount is writable: taken down again"; exit 1; }
ok "mounted read-only: it is not shared with anyone, and nothing here is reachable until you share it"
echo "CLEANROOM $MNT"
finished
"""


def cleanroom_script(snapshot: str, mount: str) -> str:
    return head() + f'SNAP={shlex.quote(snapshot)} MNT={shlex.quote(mount)}\n' + CLEANROOM_BODY


# ── compliance baseline: only what it can then verify ────────────────
COMPLIANCE_BODY = r"""
section "Packages ($PROFILE)"
@NEEDS@
section "Kernel settings"
want=$(mktemp); trap 'rm -f "$want"' EXIT
cat >"$want" <<'SF_SYSCTL'
@SYSCTL@SF_SYSCTL
bad=0
while IFS=' =' read -r k v; do
  [[ -n $k ]] || continue
  have=$(sysctl -n "$k" 2>/dev/null) || { info "$k does not exist here"; continue; }
  if [[ $have == "$v" ]]; then ok "$k = $v"; else bad=1; missing "$k is $have, should be $v"; fi
done <"$want"
FILE=/etc/sysctl.d/99-storageforge-security.conf
if ((APPLY)) && { ((bad)) || [[ ! -f $FILE ]]; }; then
  doing "write $FILE"
  install -m 0644 "$want" "$FILE"; durable "$FILE"
  sysctl -q -p "$FILE" || { conflict "sysctl refused part of $FILE"; }
fi
section "Default umask"
UM=/etc/profile.d/storageforge-umask.sh
if [[ -r $UM ]] && grep -qx "umask $UMASK_VALUE" "$UM"; then ok "umask $UMASK_VALUE for logins"
elif ((APPLY)); then doing "write $UM"; printf 'umask %s\n' "$UMASK_VALUE" >"$UM"; chmod 0644 "$UM"; durable "$UM"; ok "umask $UMASK_VALUE for new logins"
else missing "umask $UMASK_VALUE for logins"; fi
section "Audit rules for storage configuration"
AR=/etc/audit/rules.d/storageforge-compliance.rules
if command -v auditctl >/dev/null; then
  if ((APPLY)); then
    mkdir -p "${AR%/*}"
    { for f in /etc/fstab /etc/samba/smb.conf /etc/exports /etc/ssh/sshd_config; do [[ -e $f ]] && echo "-w $f -p wa -k sf_config"; done
      echo '-w /usr/local/sbin/storageforge-run -p wa -k sf_runner'; } >"$AR"
    durable "$AR"
    if command -v augenrules >/dev/null && augenrules --load >/dev/null 2>&1; then ok "rules loaded"; else missing "rules are written but did not load: is auditd running?"; fi
  elif auditctl -l 2>/dev/null | grep -q 'sf_config'; then ok "rules are loaded"
  else missing "audit rules: --apply writes and loads them"; fi
fi
section "Mandatory access control"
if command -v getenforce >/dev/null; then
  mode=$(getenforce)
  # Turning this on from a script can stop services that were quietly relying on it being off. It is the operator's call.
  if [[ $mode == Enforcing ]]; then ok "SELinux is enforcing"; else conflict "SELinux is $mode. Check the denials, then: setenforce 1, and SELINUX=enforcing in /etc/selinux/config"; fi
elif command -v aa-status >/dev/null && aa-status --enabled 2>/dev/null; then ok "AppArmor is enabled"
else conflict "neither SELinux nor AppArmor is on"; fi
section "Quarantine table"
if nft list table inet storageforge_fence >/dev/null 2>&1; then ok "present"
elif ((APPLY)); then doing "create it"; fence_ready && ok "created"
else missing "the quarantine table: --apply creates it"; fi
section "File integrity baseline"
if [[ -e /var/lib/aide/aide.db.gz || -e /var/lib/aide/aide.db ]]; then ok "AIDE has a baseline"
else missing "no AIDE baseline: use Make the AIDE baseline, it takes a while"; fi
echo "Not touched by this script: decoys, retention holds and the sentinel have their own deploys."
finished
((PROBLEMS == 0))
"""


COMPLIANCE_ARGS = r"""APPLY=0 BUNDLE= WAIVE=
while (($#)); do
  case $1 in
    --apply) APPLY=1 ;;
    --dry-run) APPLY=0 ;;
    --offline-bundle) BUNDLE=${2:?--offline-bundle needs the path of a bundle}; shift ;;
    --waive) WAIVE="$WAIVE ${2:?--waive needs a section: sysctl, umask, auditd, mac, fence or aide}"; shift ;;
    --export-cert) echo "there is no certificate: a check passing is not a control met, and only an auditor can attest. StorageForge can export signed evidence instead" >&2; exit 2 ;;
    -h|--help) sed -n '/^# Usage/,/^$/p' "$0"; exit 0 ;;
    *) echo "unknown option: $1 (try --help)" >&2; exit 2 ;;
  esac
  shift
done
waived() { [[ " $WAIVE " == *" $1 "* ]]; }
if [[ -n $BUNDLE ]]; then
  [[ -r $BUNDLE ]] || { echo "cannot read $BUNDLE" >&2; exit 1; }
  if ((APPLY)); then
    work=$(mktemp -d); tar -C "$work" -xzf "$BUNDLE"
    case $(pm) in
      apt-get) dpkg -i --force-confold "$work"/*.deb ;;
      dnf|yum|zypper) rpm -Uvh --replacefiles --replacepkgs "$work"/*.rpm ;;
      pacman) pacman -U --noconfirm --needed "$work"/* ;;
    esac
    rm -rf "$work"
  fi
fi
"""


def compliance_script(profile: str, host: str) -> str:
    from .scriptkit import one_line
    needs = ''.join(need_line(w) for w in ('auditd', 'aide', 'lynis', 'nftables', 'chrony', 'inotify-tools'))
    sysctl = ''.join(f'{k} = {v}\n' for k, v in SYSCTLS.items())
    body = COMPLIANCE_BODY.replace('@NEEDS@', needs.rstrip()).replace('@SYSCTL@', sysctl)
    for section, name in (('Kernel settings', 'sysctl'), ('Default umask', 'umask'), ('Audit rules for storage configuration', 'auditd'), ('Mandatory access control', 'mac'), ('Quarantine table', 'fence'), ('File integrity baseline', 'aide')):
        body = body.replace(f'section "{section}"\n', f'section "{section}"\nif waived {name}; then info "waived on the command line"; else\n', 1)
    for start, end in (('section "Default umask"', None), ('section "Audit rules for storage configuration"', None), ('section "Mandatory access control"', None), ('section "Quarantine table"', None), ('section "File integrity baseline"', None), ('echo "Not touched by this script', None)):
        body = body.replace(start, 'fi\n' + start, 1)
    usage = ('# Usage: sf-init-compliance.sh [--apply] [--dry-run] [--offline-bundle PATH] [--waive SECTION]...\n'
             '#   With no flags it only reports. --waive skips a section: sysctl, umask, auditd, mac, fence or aide.\n'
             '#   --offline-bundle installs from a bundle made by StorageForge, for a host with no route to a mirror.\n\n')
    return (head(FENCE_LIB) + usage + PACKAGES + f'# sf-init-compliance.sh for {one_line(host)}: {one_line(profile)}. Sets a baseline; the score comes from measuring afterwards.\n'
            + COMPLIANCE_ARGS + f'PROFILE={shlex.quote(profile)} UMASK_VALUE={UMASK}\n' + body)
