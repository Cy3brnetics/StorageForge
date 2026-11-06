"""Change plan steps for firewalls, networks, hardening and workloads. Registered with changes.py, so they are checked, reported
first, deployed and audited like every other step, and each has a Bash function and an Ansible rendering from its first day.

The firewall writer is one program, storageforge-fwrules, that the script shows in full and installs on --apply. It works out
what the host runs (firewalld, ufw, nftables, iptables) and writes the rule in that system's own way, so the host's firewall
still lists it, and `ufw status` still tells the truth. Docker's published ports go through DOCKER-USER, which is the only
place a rule can stop them.

A step that could cut StorageForge off carries a rollback timer: the change is journalled, a systemd timer undoes it, and
only a second signed run from the controller (which can only happen if the path still works) stops the timer.
"""
from __future__ import annotations

import ipaddress
import re
import shlex

from . import changes
from .changes import F

SMB, NFS, ISCSI = '445,139', '2049,111,20048', '3260'
SERVICE_PORTS = {'smb': SMB, 'nfs': NFS, 'iscsi': ISCSI}
SSHD_KEYS = ['PermitRootLogin', 'PasswordAuthentication', 'PermitEmptyPasswords', 'X11Forwarding', 'AllowTcpForwarding', 'AllowAgentForwarding', 'MaxAuthTries', 'MaxSessions',
             'LoginGraceTime', 'ClientAliveInterval', 'ClientAliveCountMax', 'LogLevel', 'TCPKeepAlive', 'Compression', 'UseDNS']
RUNTIMES = ['docker', 'podman', 'libvirt', 'incus']

changes.CHECKS.update({
    'port': re.compile(r'\d{1,5}([:-]\d{1,5})?'),
    'ports': re.compile(r'\d{1,5}([:-]\d{1,5})?(,\d{1,5}([:-]\d{1,5})?){0,31}'),
    'cidr': re.compile(r'[0-9a-fA-F:.]{2,45}(/\d{1,3})?'),
    'cidrs': re.compile(r'[0-9a-fA-F:.]{2,45}(/\d{1,3})?(,[0-9a-fA-F:.]{2,45}(/\d{1,3})?){0,63}'),
    'iface': re.compile(r'[A-Za-z0-9_][A-Za-z0-9_.@:-]{0,14}'),
    'sysctl': re.compile(r'[a-z0-9_]+(\.[A-Za-z0-9_-]+){1,8}'),
    'word': re.compile(r'[A-Za-z0-9_.:+,/@=-]{1,200}'),
    'wgkey': re.compile(r'[A-Za-z0-9+/]{42,43}='),
    'image': re.compile(r'[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}'),
    'publish': re.compile(r'[0-9a-fA-F:.\[\]/,tcpud]{1,400}'),
    'binds': re.compile(r'/[A-Za-z0-9_./@+=-]*:/[A-Za-z0-9_./@+=-]*(:[a-zA-Z,]+)?(,/[A-Za-z0-9_./@+=-]*:/[A-Za-z0-9_./@+=-]*(:[a-zA-Z,]+)?){0,31}'),
    'lines': re.compile(r'[^\0]{1,8000}'),
})

ACTION = F('action', 'choice', 'What to do', options=['allow', 'deny'], required=True)
PROTO = F('proto', 'choice', 'Protocol', options=['tcp', 'udp'], required=True)
ROLLBACK = F('rollback', 'number', 'Undo by itself after this many minutes unless StorageForge can still reach the host', placeholder='10')

# ── what runs on the host ───────────────────────────────────────────
FWRULES = r"""#!/usr/bin/env bash
# storageforge-fwrules: written by StorageForge. Writes firewall rules a plan asked for, in whichever firewall this host runs.
set -u
export LC_ALL=C PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
DIR=${SF_FW_DIR:-/etc/storageforge/firewall}
JOURNAL=$DIR/journal
UNIT=sf-fw-rollback
SHARES=storageforge_shares
RULES=storageforge_rules
TAG() { printf 'sf-rule-%s' "$1"; }

backend() {
  if command -v firewall-cmd >/dev/null && [[ $(firewall-cmd --state 2>/dev/null) == running ]]; then echo firewalld; return; fi
  if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q '^Status: active'; then echo ufw; return; fi
  # a native nftables ruleset: a table iptables-nft does not own, and not one of ours
  if command -v nft >/dev/null && nft list tables 2>/dev/null | grep -vE "^table (ip|ip6) (filter|nat|mangle|raw|security)$|storageforge" | grep -q .; then echo nftables; return; fi
  if command -v iptables-save >/dev/null && iptables-save 2>/dev/null | grep -qE '^-A|^:[A-Z]+ DROP'; then echo iptables; return; fi
  if command -v nft >/dev/null; then echo nftables; return; fi
  if command -v iptables >/dev/null; then echo iptables; return; fi
  echo none
}

docker_user() { command -v iptables >/dev/null && iptables -S DOCKER-USER >/dev/null 2>&1; }
family_of() { [[ $1 == *:* ]] && echo 6 || echo 4; }
ipt() { local fam=$1; shift; if [[ $fam == 6 ]]; then ip6tables "$@"; else iptables "$@"; fi; }

# ── nftables ────────────────────────────────────────────────────────
nft_match() { # proto port src iface
  local m=()
  [[ $4 != - ]] && m+=(iifname "\"$4\"")
  if [[ $3 != - ]]; then if [[ $(family_of "$3") == 6 ]]; then m+=(ip6 saddr "$3"); else m+=(ip saddr "$3"); fi; fi
  m+=("$1" dport "${2/:/-}")
  printf '%s ' "${m[@]}"
}
nft_drop_chains() { # hook: base chains that drop by default and would stop an allow from a table of ours
  nft list chains 2>/dev/null | awk -v h="$1" '/^table /{fam=$2; tab=$3} /chain /{ch=$2} $0 ~ "hook " h " " && /policy drop/ {print fam, tab, ch}' \
    | grep -vE "^(ip|ip6) (filter|nat|mangle|raw|security) |storageforge" || true
}
nft_has() { nft list ruleset 2>/dev/null | grep -qF "comment \"$(TAG "$1")\""; }
nft_ensure() { # id action proto port src iface hook
  local id=$1 action=$2 proto=$3 port=$4 src=$5 iface=$6 hook=$7 c
  nft_has "$id" && return 0
  c=$(TAG "$id")
  if [[ $action == deny ]]; then
    nft -f - <<SF_NFT || return 1
table inet $RULES {
  chain $hook {
    type filter hook $hook priority -150; policy accept;
    $(nft_match "$proto" "$port" "$src" "$iface")drop comment "$c"
  }
}
SF_NFT
    return 0
  fi
  local any=0 fam tab ch
  while read -r fam tab ch; do
    [[ -n $fam ]] || continue
    any=1
    # shellcheck disable=SC2046
    nft insert rule "$fam" "$tab" "$ch" $(nft_match "$proto" "$port" "$src" "$iface")accept comment "\"$c\"" || return 1
  done < <(nft_drop_chains "$hook")
  if ((!any)); then # nothing here drops it: keep a counted rule, so `has` can answer and the map can see it was asked for
    nft -f - <<SF_NFT || return 1
table inet $RULES {
  chain $hook {
    type filter hook $hook priority -150; policy accept;
    $(nft_match "$proto" "$port" "$src" "$iface")counter comment "$c"
  }
}
SF_NFT
  fi
}
nft_remove() { # id
  local c fam tab ch handle table chain line; c=$(TAG "$1")
  while read -r fam tab; do
    while read -r ch; do
      [[ -n $ch ]] || continue
      while read -r handle; do
        [[ -n $handle ]] && nft delete rule "$fam" "$tab" "$ch" handle "$handle"
      done < <(nft -a list chain "$fam" "$tab" "$ch" 2>/dev/null | sed -n "s/.*comment \"$c\".* # handle \([0-9]*\)$/\1/p")
    done < <(nft list table "$fam" "$tab" 2>/dev/null | awk '/^[[:space:]]*chain /{print $2}')
  done < <(nft list tables 2>/dev/null | awk '{print $2, $3}')
}

# ── iptables, and Docker's published ports ──────────────────────────
ipt_spec() { # chain proto port src iface tag
  local spec=(-p "$2")
  if [[ $1 == DOCKER-USER ]]; then spec+=(-m conntrack --ctorigdstport "${3/-/:}" --ctdir ORIGINAL); else spec+=(--dport "${3/-/:}"); fi
  [[ $4 != - ]] && spec+=(-s "$4")
  [[ $5 != - ]] && spec+=(-i "$5")
  spec+=(-m comment --comment "$6")
  printf '%s\n' "${spec[@]}"
}
ipt_target() { if [[ $1 == deny ]]; then echo DROP; elif [[ $2 == DOCKER-USER ]]; then echo RETURN; else echo ACCEPT; fi; }
ipt_chain() { if [[ $1 == forward ]]; then if docker_user; then echo DOCKER-USER; else echo FORWARD; fi; else echo INPUT; fi; }
ipt_has() { local fam; for fam in 4 6; do command -v ip6tables >/dev/null || [[ $fam == 4 ]] || continue; ipt "$fam" -S 2>/dev/null | grep -qF "$(TAG "$1")" && return 0; done; return 1; }
ipt_ensure() { # id action proto port src iface hook
  local id=$1 action=$2 proto=$3 port=$4 src=$5 iface=$6 hook=$7 chain fams=(4) fam spec=()
  ipt_has "$id" && return 0
  chain=$(ipt_chain "$hook")
  if [[ $src != - ]]; then fams=("$(family_of "$src")"); elif command -v ip6tables >/dev/null && ip6tables -S "$chain" >/dev/null 2>&1; then fams=(4 6); fi
  mapfile -t spec < <(ipt_spec "$chain" "$proto" "$port" "$src" "$iface" "$(TAG "$id")")
  for fam in "${fams[@]}"; do ipt "$fam" -I "$chain" 1 "${spec[@]}" -j "$(ipt_target "$action" "$chain")" || return 1; done
}
ipt_remove() { # id
  local fam line words
  for fam in 4 6; do
    { [[ $fam == 4 ]] || command -v ip6tables >/dev/null; } || continue
    while IFS= read -r line; do
      [[ -n $line ]] || continue
      read -r -a words <<<"${line/-A /-D }"
      words=("${words[@]//\"/}")
      ipt "$fam" "${words[@]}"
    done < <(ipt "$fam" -S 2>/dev/null | grep -F "$(TAG "$1")" || true)
  done
}

# ── firewalld and ufw keep their own rules across a reboot ──────────
fwd_rule() { # action proto port src
  local r=rule fam
  if [[ $4 != - ]]; then fam=ipv4; [[ $(family_of "$4") == 6 ]] && fam=ipv6; r+=" family=\"$fam\" source address=\"$4\""; fi
  r+=" port port=\"${3/:/-}\" protocol=\"$2\" $([[ $1 == allow ]] && echo accept || echo drop)"
  printf '%s' "$r"
}
ufw_args() { # action proto port src iface tag
  local a=("$1")
  [[ $5 != - ]] && a+=(in on "$5")
  a+=(proto "$2" from "$([[ $4 != - ]] && echo "$4" || echo any)" to any port "${3/-/:}" comment "$6")
  printf '%s\n' "${a[@]}"
}
ufw_has() { ufw status 2>/dev/null | grep -qF "# $(TAG "$1")"; }
ufw_remove() { # id
  local n
  while n=$(ufw status numbered 2>/dev/null | grep -F "# $(TAG "$1")" | sed -n 's/^\[ *\([0-9]*\)\].*/\1/p' | sort -rn | head -n 1); [[ -n $n ]]; do
    ufw --force delete "$n" >/dev/null || return 1
  done
}

# ── one rule, in whichever firewall this is ─────────────────────────
has() { # id action proto port src iface hook
  local b; b=$(backend)
  if [[ $7 == forward ]] && docker_user; then ipt_has "$1"; return; fi
  case $b in
    firewalld) firewall-cmd --permanent --query-rich-rule="$(fwd_rule "$2" "$3" "$4" "$5")" >/dev/null 2>&1 ;;
    ufw) ufw_has "$1" ;;
    nftables) nft_has "$1" ;;
    iptables) ipt_has "$1" ;;
    *) return 1 ;;
  esac
}
ensure() { # id action proto port src iface hook
  local b args=(); b=$(backend)
  if [[ $7 == forward ]] && docker_user; then ipt_ensure "$@"; return; fi
  case $b in
    firewalld)
      if [[ $6 != - ]]; then echo "firewalld ties interfaces to zones: put $6 in a zone, and leave the interface off this rule" >&2; return 2; fi
      if [[ $7 != input ]]; then echo "firewalld has no forward rule of this kind: use a policy object by hand" >&2; return 2; fi
      local r; r=$(fwd_rule "$2" "$3" "$4" "$5")
      firewall-cmd --quiet --permanent --add-rich-rule="$r" && firewall-cmd --quiet --add-rich-rule="$r" ;;
    ufw)
      ufw_has "$1" && return 0
      if [[ $7 != input ]]; then echo "ufw rule for forwarded traffic: use the route form by hand" >&2; return 2; fi
      mapfile -t args < <(ufw_args "$2" "$3" "$4" "$5" "$6" "$(TAG "$1")")
      # ufw takes the first match, so a deny has to come before the allows already there
      if [[ $2 == deny ]]; then ufw insert 1 "${args[@]}" >/dev/null 2>&1 || ufw "${args[@]}" >/dev/null; else ufw "${args[@]}" >/dev/null; fi ;;
    nftables) nft_ensure "$@" ;;
    iptables) ipt_ensure "$@" ;;
    *) echo "no firewall tool on this host: install nftables first" >&2; return 2 ;;
  esac
}
remove() { # id action proto port src iface hook
  local b; b=$(backend)
  if [[ $7 == forward ]] && docker_user; then ipt_remove "$1"; return; fi
  case $b in
    firewalld) local r; r=$(fwd_rule "$2" "$3" "$4" "$5"); firewall-cmd --quiet --permanent --remove-rich-rule="$r"; firewall-cmd --quiet --remove-rich-rule="$r" ;;
    ufw) ufw_remove "$1" ;;
    nftables) nft_remove "$1" ;;
    iptables) ipt_remove "$1" ;;
  esac
}

# ── what comes back after a reboot ──────────────────────────────────
keep() { mkdir -p "$DIR/rules"; printf '%s\n' "$*" >"$DIR/rules/$1"; }
forget() { rm -f "$DIR/rules/$1"; }

# ── share fences: only these clients may reach these ports ──────────
write_fences() {
  local f name ports clients iface
  {
    echo "table inet $SHARES {"
    echo '  chain input {'
    echo '    type filter hook input priority -190; policy accept;'
    echo '    iifname "lo" return'
    for f in "$DIR"/fences/*; do
      [[ -e $f ]] || continue
      read -r name ports clients iface <"$f"
      local c4=() c6=() c
      IFS=, read -r -a all <<<"$clients"
      for c in "${all[@]}"; do if [[ $(family_of "$c") == 6 ]]; then c6+=("$c"); else c4+=("$c"); fi; done
      local dport; dport=$(printf '{ %s }' "${ports//,/, }")
      dport=${dport//:/-}
      echo "    # $name"
      [[ $iface != - ]] && echo "    iifname != \"$iface\" meta l4proto { tcp, udp } th dport $dport drop"
      if ((${#c4[@]})); then echo "    meta nfproto ipv4 meta l4proto { tcp, udp } th dport $dport ip saddr != { $(IFS=,; echo "${c4[*]}" | sed 's/,/, /g') } drop"
      else echo "    meta nfproto ipv4 meta l4proto { tcp, udp } th dport $dport drop"; fi
      if ((${#c6[@]})); then echo "    meta nfproto ipv6 meta l4proto { tcp, udp } th dport $dport ip6 saddr != { $(IFS=,; echo "${c6[*]}" | sed 's/,/, /g') } drop"
      else echo "    meta nfproto ipv6 meta l4proto { tcp, udp } th dport $dport drop"; fi
    done
    echo '  }'
    echo '}'
  } >"$DIR/shares.nft.new"
  nft -c -f "$DIR/shares.nft.new" || { rm -f "$DIR/shares.nft.new"; return 1; }
  mv -f "$DIR/shares.nft.new" "$DIR/shares.nft"
  load_fences
}
load_fences() { # replaced in one go, so nothing is unfenced in between
  [[ -r $DIR/shares.nft ]] || return 0
  { echo "table inet $SHARES {}"; echo "delete table inet $SHARES"; cat "$DIR/shares.nft"; } | nft -f -
}
drop_fences_if_empty() {
  if ! compgen -G "$DIR/fences/*" >/dev/null; then
    nft delete table inet "$SHARES" 2>/dev/null
    rm -f "$DIR/shares.nft"
    return 0
  fi
  return 1
}

# ── the rollback timer ──────────────────────────────────────────────
arm() { # minutes: undoes what is in the journal, unless `confirm` stops it first
  systemctl list-timers --all --no-legend 2>/dev/null | grep -q "$UNIT.timer" && return 0
  systemd-run --quiet --unit="$UNIT" --on-active="$1min" --timer-property=AccuracySec=5s "$0" revert >/dev/null
  echo "FW-ROLLBACK armed $1"
}
note() { mkdir -p "$DIR"; printf '%s\n' "$*" >>"$JOURNAL"; }   # a line of shell that undoes one change
confirm() { systemctl stop "$UNIT.timer" 2>/dev/null; systemctl reset-failed "$UNIT.service" "$UNIT.timer" 2>/dev/null; rm -f "$JOURNAL"; echo 'FW-ROLLBACK confirmed'; }
revert() {
  [[ -r $JOURNAL ]] || exit 0
  tac "$JOURNAL" | while IFS= read -r line; do bash -c "$line" || echo "could not undo: $line" >&2; done
  rm -f "$JOURNAL"
  echo 'FW-ROLLBACK reverted'
}

cmd=${1:-}; [[ $# -gt 0 ]] && shift
case $cmd in
  backend) backend ;;
  has) has "$@" ;;
  ensure) ensure "$@" && keep "$@" ;;
  remove) remove "$@"; forget "$1" ;;
  boot) # after a reboot: nftables and iptables forget what is not in their own files
    for f in "$DIR"/rules/*; do [[ -e $f ]] || continue; read -r -a a <"$f"; ensure "${a[@]}"; done
    load_fences ;;
  fence-has) [[ -r $DIR/fences/$1 ]] && [[ $(cat "$DIR/fences/$1") == "$1 $2 $3 $4" ]] && nft list table inet "$SHARES" >/dev/null 2>&1 ;;
  fence-set) mkdir -p "$DIR/fences"; printf '%s %s %s %s\n' "$1" "$2" "$3" "$4" >"$DIR/fences/$1"; write_fences ;;
  fence-del) rm -f "$DIR/fences/$1"; drop_fences_if_empty || write_fences ;;
  arm) arm "$@" ;;
  note) note "$@" ;;
  confirm) confirm ;;
  revert) revert ;;
  *) echo "usage: storageforge-fwrules backend|has|ensure|remove|fence-has|fence-set|fence-del|arm|note|confirm|revert" >&2; exit 2 ;;
esac
"""

FWRULES_UNIT = """[Unit]
Description=StorageForge firewall rules asked for by change plans
After=network-pre.target nftables.service iptables.service ufw.service firewalld.service docker.service
Wants=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/storageforge-fwrules boot

[Install]
WantedBy=multi-user.target
"""

CONFIRM_SCRIPT = '#!/usr/bin/env bash\n# Written by StorageForge. Reaching the host to run this is the proof the change did not cut it off.\nset -u\n/usr/local/sbin/storageforge-fwrules confirm\n'

BASH = r"""
# ── firewall, network, hardening and workload steps ─────────────────
fw_tool() { # the program that writes rules. A report uses a throwaway copy, so it changes nothing here
  [[ -n ${FW:-} ]] && return 0
  local to
  if ((APPLY)); then to=/usr/local/sbin/storageforge-fwrules; else to=$(mktemp); fi
  cat >"$to.new" <<'SF_FWRULES'
@FWRULES@SF_FWRULES
  chmod 0755 "$to.new"; mv -f "$to.new" "$to"
  FW=$to
  if ((APPLY)) && [[ -d /run/systemd/system ]]; then
    cat >/etc/systemd/system/storageforge-fwrules.service <<'SF_FWUNIT'
@FWUNIT@SF_FWUNIT
    reload_systemd >/dev/null 2>&1 || true
    systemctl enable -q storageforge-fwrules.service 2>/dev/null || true
  fi
}
fw_id() { printf '%s' "$*" | sha256sum | cut -c1-12; }
fw_need_nft() { # a host with no firewall tool at all gets nftables, as a share fence and a deny both need one
  command -v nft >/dev/null && return 0
  if ((!APPLY)); then missing "nftables is not installed: --apply installs it"; return 1; fi
  doing "install nftables"
  local m; for m in apt-get dnf yum zypper pacman; do command -v "$m" >/dev/null && break; done
  case $m in
    apt-get) DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=120 install -y -qq nftables >/dev/null 2>&1 ;;
    dnf|yum) "$m" install -y -q nftables >/dev/null 2>&1 ;;
    zypper) zypper -nq install nftables >/dev/null 2>&1 ;;
    pacman) pacman -S --needed --noconfirm nftables >/dev/null 2>&1 ;;
  esac
  command -v nft >/dev/null || { conflict "nftables did not install"; return 1; }
}
# arm MINUTES UNDO: journal how to undo this, and start the timer. The plan's next signed run stops the timer.
fw_arm() { [[ -n $1 ]] || return 0; "$FW" note "$2"; "$FW" arm "$1"; }

t_fw_rule() { local action=$1 proto=$2 port=$3 src=${4:--} iface=${5:--} hook=${6:-input} state=${7:-present} roll=${8:-} id
  fw_tool
  id=$(fw_id "$action" "$proto" "$port" "$src" "$iface" "$hook")
  [[ $("$FW" backend) != none ]] || fw_need_nft || return 0
  info "this host runs $("$FW" backend)"
  if [[ $state == absent ]]; then
    if ! "$FW" has "$id" "$action" "$proto" "$port" "$src" "$iface" "$hook"; then ok "the rule is not there"; return 0; fi
    act "remove the rule" || return 0
    fw_arm "$roll" "$FW ensure $id $action $proto $port $src $iface $hook"
    if "$FW" remove "$id" "$action" "$proto" "$port" "$src" "$iface" "$hook"; then ok "removed"; else conflict "could not remove the rule"; fi
    return 0
  fi
  if "$FW" has "$id" "$action" "$proto" "$port" "$src" "$iface" "$hook"; then ok "the rule is there"; return 0; fi
  act "$action $proto/$port from $([[ $src == - ]] && echo anywhere || echo "$src")" || return 0
  fw_arm "$roll" "$FW remove $id $action $proto $port $src $iface $hook"
  if "$FW" ensure "$id" "$action" "$proto" "$port" "$src" "$iface" "$hook"; then ok "the rule is in place"; else conflict "the firewall refused the rule"; fi
}

t_fw_fence() { local name=$1 service=$2 ports=$3 clients=$4 iface=${5:--} state=${6:-present} roll=${7:-}
  fw_tool
  fw_need_nft || return 0
  case $service in smb) ports=445,139 ;; nfs) ports=2049,111,20048 ;; iscsi) ports=3260 ;; esac
  if [[ $state == absent ]]; then
    [[ -r /etc/storageforge/firewall/fences/$name ]] || { ok "no fence named $name"; return 0; }
    act "take down fence $name" || return 0
    if "$FW" fence-del "$name"; then ok "fence $name is down"; else conflict "could not take down fence $name"; fi
    return 0
  fi
  if "$FW" fence-has "$name" "$ports" "$clients" "$iface"; then ok "ports $ports already take only $clients"; return 0; fi
  act "only $clients may reach ports $ports$([[ $iface == - ]] || echo " and only on $iface")" || return 0
  fw_arm "$roll" "$FW fence-del $name"
  if "$FW" fence-set "$name" "$ports" "$clients" "$iface"; then ok "fence $name is up"; else conflict "nft refused the fence"; fi
}

net_manager() {
  if command -v nmcli >/dev/null && [[ $(nmcli -t -f RUNNING general 2>/dev/null) == running ]]; then echo nm
  elif systemctl is-active -q systemd-networkd 2>/dev/null; then echo networkd
  else echo none; fi
}
# Would touching this interface take the path StorageForge came in on? Its own session says where from.
net_is_ssh_path() { [[ -n ${SSH_CONNECTION:-} ]] || return 1; [[ $(ip -o route get "${SSH_CONNECTION%% *}" 2>/dev/null) == *" dev $1 "* ]]; }
net_guard() { # interface rollback
  [[ -n $1 && -n $2 ]] && return 0
  if [[ -n $1 ]] && net_is_ssh_path "$1"; then conflict "this session comes in through $1: stage a rollback timer, or this could cut the host off for good"; return 1; fi
}

t_net_bridge() { local name=$1 ports=$2 address=$3 roll=$4 mgr first=${2%%,*}
  mgr=$(net_manager)
  if ip link show "$name" >/dev/null 2>&1; then ok "$name exists"; return 0; fi
  net_guard "$first" "$roll" || return 0
  if [[ $mgr == none ]]; then conflict "no NetworkManager or systemd-networkd running: a bridge would not survive a reboot. Set it up by hand"; return 0; fi
  act "create bridge $name with $mgr$([[ -n $ports ]] && echo " over ${ports//,/ }")$([[ -n $address ]] && echo " at $address")" || return 0
  fw_tool
  if [[ $mgr == nm ]]; then
    local undo="nmcli connection delete sf-$name" u
    for u in ${ports//,/ }; do undo+="; nmcli connection delete sf-$name-$u; nmcli device connect $u"; done
    fw_arm "$roll" "$undo"
    try nmcli connection add type bridge ifname "$name" con-name "sf-$name" ipv4.method "$([[ -n $address ]] && echo manual || echo disabled)" ${address:+ipv4.addresses "$address"} ipv6.method disabled || return 0
    local p; for p in ${ports//,/ }; do try nmcli connection add type bridge-slave ifname "$p" master "$name" con-name "sf-$name-$p" || return 0; done
    try nmcli connection up "sf-$name" || return 0
    # a port has to be brought up too, or nothing moves until the next reboot, when it would all happen at once with nobody watching
    for p in ${ports//,/ }; do try nmcli connection up "sf-$name-$p" || return 0; done
  else
    fw_arm "$roll" "rm -f /etc/systemd/network/10-sf-$name.netdev /etc/systemd/network/10-sf-$name.network /etc/systemd/network/10-sf-$name-*.network; networkctl reload; ip link del $name"
    printf '[NetDev]\nName=%s\nKind=bridge\n' "$name" >"/etc/systemd/network/10-sf-$name.netdev"
    { printf '[Match]\nName=%s\n[Network]\nDHCP=no\nLinkLocalAddressing=no\n' "$name"; [[ -n $address ]] && printf 'Address=%s\n' "$address"; } >"/etc/systemd/network/10-sf-$name.network"
    local q; for q in ${ports//,/ }; do printf '[Match]\nName=%s\n[Network]\nBridge=%s\n' "$q" "$name" >"/etc/systemd/network/10-sf-$name-$q.network"; done
    durable /etc/systemd/network; networkctl reload || true
  fi
  ok "bridge $name"
}

t_net_vlan() { local parent=$1 vid=$2 address=$3 roll=$4 name="$1.$2" mgr
  mgr=$(net_manager)
  if ip link show "$name" >/dev/null 2>&1; then ok "$name exists"; return 0; fi
  ip link show "$parent" >/dev/null 2>&1 || { later "$parent is not on this host"; return 0; }
  if [[ $mgr == none ]]; then conflict "no NetworkManager or systemd-networkd running: a VLAN would not survive a reboot. Set it up by hand"; return 0; fi
  act "create VLAN $vid on $parent with $mgr$([[ -n $address ]] && echo " at $address")" || return 0
  fw_tool
  if [[ $mgr == nm ]]; then
    fw_arm "$roll" "nmcli connection delete sf-$name"
    try nmcli connection add type vlan ifname "$name" dev "$parent" id "$vid" con-name "sf-$name" ipv4.method "$([[ -n $address ]] && echo manual || echo disabled)" ${address:+ipv4.addresses "$address"} ipv6.method disabled || return 0
  else
    # a VLAN is named by its parent's .network, so a drop-in beside whichever file manages the parent (netplan's too) makes it last
    local unit; unit=$(networkctl status "$parent" 2>/dev/null | sed -n 's/^ *Network File: //p' | head -n 1)
    [[ -n $unit ]] || { conflict "systemd-networkd does not manage $parent: set this VLAN up by hand"; return 0; }
    local dropin=/etc/systemd/network/${unit##*/}.d
    fw_arm "$roll" "rm -f /etc/systemd/network/20-sf-$name.netdev /etc/systemd/network/20-sf-$name.network $dropin/sf-$name.conf; networkctl reload; ip link del $name"
    printf '[NetDev]\nName=%s\nKind=vlan\n[VLAN]\nId=%s\n' "$name" "$vid" >"/etc/systemd/network/20-sf-$name.netdev"
    { printf '[Match]\nName=%s\n[Network]\nDHCP=no\nLinkLocalAddressing=no\n' "$name"; [[ -n $address ]] && printf 'Address=%s\n' "$address"; } >"/etc/systemd/network/20-sf-$name.network"
    mkdir -p "$dropin"; printf '[Network]\nVLAN=%s\n' "$name" >"$dropin/sf-$name.conf"
    durable /etc/systemd/network "$dropin"; networkctl reload || true
    networkctl reconfigure "$parent" 2>/dev/null || true
    ip link show "$name" >/dev/null 2>&1 || { sleep 2; ip link show "$name" >/dev/null 2>&1; } || { conflict "$name did not appear"; return 0; }
  fi
  ok "VLAN $name"
}

t_net_mtu() { local iface=$1 mtu=$2 roll=$3 now
  now=$(cat "/sys/class/net/$iface/mtu" 2>/dev/null) || { conflict "$iface is not on this host"; return 0; }
  if [[ $now == "$mtu" ]]; then ok "$iface is already at MTU $mtu"; return 0; fi
  net_guard "$iface" "$roll" || return 0
  act "change $iface from MTU $now to $mtu" || return 0
  fw_tool
  fw_arm "$roll" "ip link set $iface mtu $now"
  try ip link set "$iface" mtu "$mtu" || return 0
  if command -v nmcli >/dev/null && [[ $(net_manager) == nm ]]; then
    local con; con=$(nmcli -g GENERAL.CONNECTION device show "$iface" 2>/dev/null)
    [[ -n $con ]] && nmcli connection modify "$con" 802-3-ethernet.mtu "$mtu" 2>/dev/null
  fi
  ok "$iface at MTU $mtu until the network is next configured$([[ $(net_manager) == nm ]] && echo ', and in its connection')"
}

t_sysctl_set() { local key=$1 value=$2 file=/etc/sysctl.d/90-storageforge-plan.conf have
  have=$(sysctl -n "$key" 2>/dev/null) || { conflict "$key does not exist on this host"; return 0; }
  if [[ $have == "$value" ]] && grep -qsxF "$key = $value" "$file"; then ok "$key = $value, and it stays across a reboot"; return 0; fi
  act "set $key to $value (it is $have)" || return 0
  { [[ -e $file ]] && grep -vE "^${key}[[:space:]]*=" "$file"; printf '%s = %s\n' "$key" "$value"; } >"$file.new"
  mv -f "$file.new" "$file"; chmod 0644 "$file"; durable "$file"
  try sysctl -q -w "$key=$value" && ok "$key = $value"
}

t_sshd_option() { local key=$1 value=$2 roll=$3 dir=/etc/ssh/sshd_config.d file conf=/etc/ssh/sshd_config have err
  file=$dir/90-storageforge.conf
  have=$(sshd -T 2>/dev/null | awk -v k="$(tr 'A-Z' 'a-z' <<<"$key")" '$1 == k {print $2; exit}')
  if [[ ${have,,} == "${value,,}" ]]; then ok "$key is $value"; return 0; fi
  grep -qiE '^[[:space:]]*Include[[:space:]].*sshd_config\.d' "$conf" 2>/dev/null || { conflict "$conf does not include sshd_config.d: change $key there by hand"; return 0; }
  act "set $key to $value (it is ${have:-unset})" || return 0
  fw_tool
  mkdir -p "$dir"
  local before=$file.storageforge-$STAMP; [[ -e $file ]] && cp -a "$file" "$before"
  fw_arm "$roll" "if [ -e $before ]; then mv -f $before $file; else rm -f $file; fi; systemctl reload sshd 2>/dev/null || systemctl reload ssh"
  { [[ -e $file ]] && grep -viE "^${key}[[:space:]]" "$file"; printf '%s %s\n' "$key" "$value"; } >"$file.new"
  mv -f "$file.new" "$file"; chmod 0644 "$file"
  err=$(mktemp)       # not a fixed name in /tmp, where another account could have made it first (SF-65)
  if ! sshd -t 2>"$err"; then
    if [[ -e $before ]]; then mv -f "$before" "$file"; else rm -f "$file"; fi
    local said; said=$(cat "$err"); rm -f "$err"
    conflict "sshd -t rejected it, so it was put back: $said"; return 0
  fi
  rm -f "$err"
  durable "$file"
  systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || { conflict "sshd did not reload"; return 0; }
  ok "$key = $value"
}

t_umask_set() { local value=$1 file=/etc/profile.d/storageforge-umask.sh
  if [[ -r $file ]] && grep -qx "umask $value" "$file"; then ok "new logins get umask $value"; return 0; fi
  act "set umask $value for logins" || return 0
  printf 'umask %s\n' "$value" >"$file"; chmod 0644 "$file"; durable "$file"
  ok "new logins get umask $value"
}

t_selinux_boolean() { local name=$1 value=$2 have
  command -v getsebool >/dev/null || { conflict "this host has no SELinux tools"; return 0; }
  have=$(getsebool "$name" 2>/dev/null | awk '{print $NF}')
  [[ -n $have ]] || { conflict "no boolean named $name"; return 0; }
  if [[ $have == "$value" ]]; then ok "$name is $value"; return 0; fi
  act "set $name to $value" || return 0
  try setsebool -P "$name" "$value" && ok "$name = $value, across reboots"
}

t_selinux_relabel() { local path=$1 type=$2 now
  command -v semanage >/dev/null || { conflict "semanage is not installed"; return 0; }
  [[ -e $path ]] || { later "$path does not exist yet"; return 0; }
  now=$(stat -c %C -- "$path" 2>/dev/null)
  if [[ $now == *":$type:"* ]] && semanage fcontext -l -C 2>/dev/null | grep -qF "$path"; then ok "$path is $type, and registered"; return 0; fi
  act "label $path as $type" || return 0
  semanage fcontext -a -t "$type" "$path(/.*)?" 2>/dev/null || try semanage fcontext -m -t "$type" "$path(/.*)?" || return 0
  try relabel_tree "$path" && ok "$path is $type"
}

t_apparmor_local() { local profile=$1 rules=$2 file err
  file=/etc/apparmor.d/local/$profile
  command -v apparmor_parser >/dev/null || { conflict "this host has no apparmor_parser"; return 0; }
  [[ -r /etc/apparmor.d/$profile ]] || { conflict "no AppArmor profile named $profile"; return 0; }
  if [[ -r $file ]] && [[ $(cat "$file") == "$rules" ]]; then ok "$file already says this"; return 0; fi
  act "write $file" || return 0
  local before; before=$(mktemp); cp -a "$file" "$before" 2>/dev/null
  mkdir -p /etc/apparmor.d/local
  printf '%s\n' "$rules" >"$file"
  err=$(mktemp)       # as at t_sshd_option (SF-65)
  if ! apparmor_parser -Q -K "/etc/apparmor.d/$profile" >"$err" 2>&1; then
    if [[ -s $before ]]; then cp -a "$before" "$file"; else rm -f "$file"; fi
    local said; said=$(tail -n 3 "$err"); rm -f "$err"
    conflict "apparmor_parser rejected it, so it was put back: $said"; return 0
  fi
  rm -f "$err"
  try apparmor_parser -r "/etc/apparmor.d/$profile" && ok "$profile reloaded with these paths"
}

t_apparmor_mode() { local profile=$1 mode=$2
  command -v aa-enforce >/dev/null || { conflict "aa-enforce is not installed (apparmor-utils)"; return 0; }
  if aa-status 2>/dev/null | awk -v m="$mode" 'index($0, "profiles are in " m) {s = 1; next} /profiles are in/ {s = 0} s' | grep -qF "$profile"; then ok "$profile is in $mode mode"; return 0; fi
  act "put $profile in $mode mode" || return 0
  case $mode in enforce) try aa-enforce "/etc/apparmor.d/$profile" >/dev/null ;; complain) try aa-complain "/etc/apparmor.d/$profile" >/dev/null ;; esac && ok "$profile is in $mode mode"
}

t_chrony_nts() { local servers=$1 dir file line all
  command -v chronyc >/dev/null || { later "chrony is not installed"; return 0; }
  if [[ -d /etc/chrony/conf.d ]]; then dir=/etc/chrony/conf.d; else dir=/etc/chrony.d; fi
  file=$dir/storageforge-nts.conf
  all=$(for line in ${servers//,/ }; do printf 'server %s iburst nts\n' "$line"; done)
  if [[ -r $file ]] && [[ $(cat "$file") == "$all" ]]; then ok "NTS sources are set"; return 0; fi
  act "use NTS time sources: ${servers//,/ }" || return 0
  mkdir -p "$dir"
  local conf=/etc/chrony/chrony.conf; [[ -r $conf ]] || conf=/etc/chrony.conf
  grep -qsE "^[[:space:]]*(confdir|include)[[:space:]]+$dir" "$conf" || printf '\nconfdir %s\n' "$dir" >>"$conf"
  printf '%s\n' "$all" >"$file"; chmod 0644 "$file"; durable "$file"
  if systemctl restart chronyd 2>/dev/null || systemctl restart chrony 2>/dev/null; then ok "chrony restarted with NTS sources"; else conflict "chrony did not restart"; fi
}

t_wg_peer() { local iface=$1 key=$2 allowed=$3 state=${4:-present}
  command -v wg >/dev/null || { conflict "this host has no wg command"; return 0; }
  wg show "$iface" public-key >/dev/null 2>&1 || { conflict "no WireGuard interface named $iface"; return 0; }
  local have now; have=$(wg show "$iface" peers | grep -cxF "$key" || true)
  now=$(wg show "$iface" allowed-ips | awk -v k="$key" '$1 == k {$1 = ""; sub(/^ /, ""); print}' | tr ' ' ',')
  if [[ $state == absent ]]; then
    if ((have == 0)); then ok "that peer is not on $iface"; return 0; fi
    act "revoke the peer on $iface" || return 0
    try wg set "$iface" peer "$key" remove
  else
    if ((have)) && [[ $now == "$allowed" ]]; then ok "that peer is on $iface with $allowed"; return 0; fi
    act "peer on $iface allowed $allowed" || return 0
    try wg set "$iface" peer "$key" allowed-ips "$allowed"
  fi
  if command -v wg-quick >/dev/null && [[ -e /etc/wireguard/$iface.conf ]]; then wg-quick save "$iface" >/dev/null 2>&1 || info "could not save /etc/wireguard/$iface.conf: this lasts until the interface next restarts"; fi
  ok "done: $iface"
}

t_workload_action() { local runtime=$1 name=$2 action=$3 state
  command -v "${runtime/libvirt/virsh}" >/dev/null || { conflict "$runtime is not on this host"; return 0; }
  case $runtime in
    docker|podman)
      state=$("$runtime" inspect -f '{{.State.Status}}' "$name" 2>/dev/null) || { conflict "no container named $name"; return 0; }
      case $action in
        start) [[ $state == running ]] && { ok "$name is running"; return 0; } ;;
        stop) [[ $state != running ]] && { ok "$name is stopped"; return 0; } ;;
        snapshot) conflict "containers have no snapshot here: snapshot the dataset their volumes are on"; return 0 ;;
      esac
      act "$action $name" || return 0
      try "$runtime" "$action" "$name" >/dev/null && ok "$action: $name" ;;
    libvirt)
      state=$(virsh domstate "$name" 2>/dev/null | head -n 1) || { conflict "no VM named $name"; return 0; }
      case $action in
        start) [[ $state == running ]] && { ok "$name is running"; return 0; }; act "start $name" || return 0; try virsh start "$name" >/dev/null ;;
        stop) [[ $state != running ]] && { ok "$name is stopped"; return 0; }; act "shut down $name" || return 0; try virsh shutdown "$name" >/dev/null ;;
        restart) act "reboot $name" || return 0; try virsh reboot "$name" >/dev/null ;;
        snapshot) act "snapshot $name" || return 0; try virsh snapshot-create-as "$name" "sf-$STAMP" --atomic >/dev/null ;;
      esac && ok "$action: $name" ;;
    incus)
      state=$(incus list -f csv -c s "$name" 2>/dev/null | head -n 1) || { conflict "no instance named $name"; return 0; }
      [[ -n $state ]] || { conflict "no instance named $name"; return 0; }
      case $action in
        start) [[ $state == RUNNING ]] && { ok "$name is running"; return 0; } ;;
        stop) [[ $state != RUNNING ]] && { ok "$name is stopped"; return 0; } ;;
      esac
      act "$action $name" || return 0
      if [[ $action == snapshot ]]; then try incus snapshot create "$name" "sf-$STAMP"; else try incus "$action" "$name"; fi && ok "$action: $name" ;;
  esac
}

t_workload_remove() { local runtime=$1 name=$2
  command -v "${runtime/libvirt/virsh}" >/dev/null || { conflict "$runtime is not on this host"; return 0; }
  case $runtime in
    docker|podman)
      "$runtime" inspect "$name" >/dev/null 2>&1 || { ok "no container named $name"; return 0; }
      act "remove container $name, keeping its volumes" || return 0
      try "$runtime" rm -f "$name" >/dev/null && ok "removed: its volumes are still there" ;;
    libvirt)
      virsh dominfo "$name" >/dev/null 2>&1 || { ok "no VM named $name"; return 0; }
      act "stop and undefine $name, keeping its disks" || return 0
      virsh destroy "$name" >/dev/null 2>&1 || true
      try virsh undefine "$name" --nvram >/dev/null 2>&1 || try virsh undefine "$name" >/dev/null
      ok "undefined: its disks are still there" ;;
    incus)
      incus info "$name" >/dev/null 2>&1 || { ok "no instance named $name"; return 0; }
      act "delete instance $name" || return 0
      try incus delete -f "$name" && ok "deleted $name" ;;
  esac
}

t_container() { local runtime=$1 name=$2 image=$3 publish=$4 binds=$5 restart=${6:-unless-stopped} network=$7 have args p
  command -v "$runtime" >/dev/null || { later "$runtime is not installed"; return 0; }
  if have=$("$runtime" inspect -f '{{.Config.Image}}' "$name" 2>/dev/null); then
    if [[ $have == "$image" ]]; then ok "$name exists, from $image"; else conflict "$name exists, from $have and not $image: remove it first, this step will not replace a container"; fi
    return 0
  fi
  args=(run -d --name "$name" --restart "$restart" --label storageforge.managed=true)
  for p in ${publish//,/ }; do args+=(-p "$p"); done
  for p in ${binds//,/ }; do args+=(-v "$p"); done
  [[ -n $network ]] && args+=(--network "$network")
  info "$runtime ${args[*]} $image"
  act "start $name from $image" || return 0
  try "$runtime" "${args[@]}" "$image" >/dev/null && ok "$name is started"
}

t_vm() { local name=$1 disk=$2 vcpus=${3:-2} ram=${4:-2048} network=${5:-default} variant=${6:-generic} bridge=$7
  command -v virt-install >/dev/null || { later "virt-install is not installed"; return 0; }
  if virsh dominfo "$name" >/dev/null 2>&1; then ok "$name is defined"; return 0; fi
  [[ -r $disk ]] || { later "$disk is not there"; return 0; }
  local net="network=$network"; [[ -n $bridge ]] && net="bridge=$bridge"
  info "virt-install --import --name $name --disk $disk --vcpus $vcpus --memory $ram --network $net --osinfo $variant --graphics spice,listen=127.0.0.1 --noautoconsole"
  act "define and start VM $name from $disk" || return 0
  try virt-install --import --name "$name" --disk "$disk,bus=virtio" --vcpus "$vcpus" --memory "$ram" --network "$net,model=virtio" --osinfo "$variant" --graphics spice,listen=127.0.0.1 --noautoconsole >/dev/null \
    && ok "$name is running, and its console only listens on this machine"
}

t_zfs_rollback() { local dataset=$1 snapshot=$2
  command -v zfs >/dev/null || { conflict "this host has no zfs command"; return 0; }
  zfs list -H -t snapshot "$dataset@$snapshot" >/dev/null 2>&1 || { conflict "no snapshot $dataset@$snapshot"; return 0; }
  local behind; behind=$(zfs list -H -t snapshot -S creation -o name "$dataset" | sed "/@$snapshot\$/q" | grep -cv "@$snapshot\$" || true)
  info "$behind newer snapshot(s) would go with it: zfs rollback -r destroys them"
  act "roll $dataset back to @$snapshot" || return 0
  try zfs snapshot "$dataset@sf-before-rollback-$STAMP" || return 0
  try zfs rollback -r "$dataset@$snapshot" && ok "$dataset is back at @$snapshot"
}
""".replace('@FWRULES@', FWRULES).replace('@FWUNIT@', FWRULES_UNIT)


# ── checks against the index ────────────────────────────────────────
def _nets(text: str):
    out, bad = [], []
    for part in filter(None, (text or '').split(',')):
        try:
            out.append(ipaddress.ip_network(part, strict=False))
        except ValueError:
            bad.append(part)
    return out, bad


def _ports_ok(text: str) -> list[str]:
    bad = []
    for part in (text or '').split(','):
        ends = re.split('[:-]', part)
        if not all(e.isdigit() and 0 < int(e) < 65536 for e in ends) or (len(ends) == 2 and int(ends[0]) > int(ends[1])):
            bad.append(part)
    return bad


def _infra(conn, h):
    from . import inframeasure
    return inframeasure.reading(conn, h['name'])


def _net(conn, h):
    from . import netfacts
    return netfacts.reading(conn, h['name'])


def _controller_ips(conn, h) -> list[str]:
    from . import security
    try:
        return security._controller_ips(conn, h['name'])
    except Exception:
        return []


def _ssh_port(h) -> int:
    return int(h.get('ssh_port') or 22)


def _covers(port_text: str, port: int) -> bool:
    for part in port_text.split(','):
        ends = re.split('[:-]', part)
        if ends[0].isdigit() and (int(ends[0]) == port or (len(ends) == 2 and ends[1].isdigit() and int(ends[0]) <= port <= int(ends[1]))):
            return True
    return False


def _check_fw_rule(conn, c, h, p, say):
    _, bad = _nets(p['source'])
    if bad:
        say('crit', f'not an address or network: {bad[0]}')
    if _ports_ok(p['port']):
        say('crit', f'not a port or range: {p["port"]}')
    m = _infra(conn, h)
    if not m:
        say('note', f'the firewall on {h["name"]} has not been read, so this is not compared with its rules. The script looks when it runs')
    elif not (m.get('firewall') or {}).get('readable'):
        say('note', f'the firewall on {h["name"]} could not be read: the script looks when it runs')
    else:
        say('ok', f'{h["name"]} runs {", ".join(m["firewall"]["backends"]) or "no firewall"}, last read from a measurement')
    if p['action'] == 'deny' and p['state'] != 'absent' and p['proto'] == 'tcp' and _covers(p['port'], _ssh_port(h)) and p['hook'] != 'forward':
        ctrl = _controller_ips(conn, h)
        nets, _ = _nets(p['source'])
        hit = not nets or not ctrl or any(ipaddress.ip_address(a) in n for a in ctrl for n in nets if ipaddress.ip_address(a).version == n.version)
        if hit:
            say('crit' if not p['rollback'] else 'warn', f'this blocks SSH from where StorageForge comes in ({", ".join(ctrl) or "address not known"})' + ('' if p['rollback'] else ': stage a rollback timer, or this cuts the host off'))
    if p['action'] == 'allow' and not p['source'] and p['hook'] != 'forward':
        say('warn', f'opens {p["proto"]}/{p["port"]} to every address on every interface')
    if p['hook'] == 'forward':
        say('note', 'for published container ports: goes in DOCKER-USER where the host has it, matched on the published port')


def _check_fw_fence(conn, c, h, p, say):
    from . import security
    nets, bad = _nets(p['clients'])
    if bad:
        say('crit', f'not an address or network: {bad[0]}')
    if not p['ports'] and p['service'] == 'custom':
        say('crit', 'a custom fence needs its ports')
    if p['ports'] and _ports_ok(p['ports']):
        say('crit', f'not a list of ports: {p["ports"]}')
    if not nets and p['state'] != 'absent':
        say('crit', 'a fence needs at least one client network')
    m = _infra(conn, h)
    ports = SERVICE_PORTS.get(p['service']) or p['ports'] or ''
    if m and p['state'] != 'absent':
        connected = {x['client'] for x in m.get('storage_clients') or [] if _covers(ports, x['port'])}
        cut = sorted(a for a in connected if not any(_in(a, n) for n in nets))
        if cut:
            say('warn', f'{len(cut)} client(s) connected now would be cut off: {", ".join(cut[:6])}')
        elif connected:
            say('ok', f'all {len(connected)} connected client(s) are inside the fence')
    elif not m:
        say('note', 'who is connected has not been read: nothing can say who this would cut off')
    for vip in security.vip_list(conn):
        vnet = ipaddress.ip_network(vip, strict=False)
        if nets and not any(n.version == vnet.version and n.overlaps(vnet) for n in nets):
            say('warn', f'{vip} is on the exempt list and is outside this fence')
    say('note', 'its own nftables table, ahead of any other firewall: it only ever takes away, so a client inside still needs the host firewall to let it in')


def _in(addr, net) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return ip.version == net.version and ip in net


def _check_iface(conn, h, name, say, what='interface', roll=''):
    net = _net(conn, h)
    if not net:
        say('note', f'the network of {h["name"]} has not been read: the script looks when it runs')
        return None
    names = {i['name']: i for i in net.get('interfaces') or []}
    if name not in names:
        say('crit', f'{name} is not an {what} on {h["name"]} at the last scan')
        return None
    return names[name]


def _check_ssh_path(conn, h, iface: dict | None, roll: str, say):
    if not iface:
        return
    addr = h.get('ssh_host')
    if addr and any(a.get('ip') == addr for a in iface.get('addresses') or []):
        if roll:
            say('warn', f'{iface["name"]} carries the address StorageForge reaches this host on: the rollback timer undoes it if the path is lost')
        else:
            say('crit', f'{iface["name"]} carries the address StorageForge reaches this host on: stage a rollback timer')


def _check_net_bridge(conn, c, h, p, say):
    net = _net(conn, h)
    names = {i['name'] for i in (net or {}).get('interfaces') or []}
    if p['name'] in names:
        say('ok', f'{p["name"]} already exists')
    elif net:
        say('ok', f'creates bridge {p["name"]}')
    if p['address']:
        _, bad = _nets(p['address'])
        if bad:
            say('crit', f'not an address: {bad[0]}')
        _address_clash(conn, h, p['address'], say)
    for port in filter(None, (p['ports'] or '').split(',')):
        _check_ssh_path(conn, h, _check_iface(conn, h, port, say), p['rollback'], say)


def _address_clash(conn, h, address, say):
    """Duplicate addresses against everything scanned."""
    from . import infragraph
    ip = address.split('/')[0]
    owner = infragraph._peers(conn).get(ip)
    if owner:
        say('crit', f'{ip} is already held by {owner}')


def _check_net_vlan(conn, c, h, p, say):
    _check_iface(conn, h, p['parent'], say, 'interface')
    if not 1 <= int(p['vlan_id']) <= 4094:
        say('crit', 'a VLAN id is 1 to 4094')
    if p['address']:
        _, bad = _nets(p['address'])
        if bad:
            say('crit', f'not an address: {bad[0]}')
        _address_clash(conn, h, p['address'], say)


def _check_net_mtu(conn, c, h, p, say):
    iface = _check_iface(conn, h, p['iface'], say)
    if not 576 <= int(p['mtu']) <= 9216:
        say('crit', 'an MTU is 576 to 9216')
    _check_ssh_path(conn, h, iface, p['rollback'], say)
    if iface and iface.get('mtu') == int(p['mtu']):
        say('ok', f'{p["iface"]} is already at {p["mtu"]}')


def _check_sshd(conn, c, h, p, say):
    if p['key'] == 'PermitRootLogin' and p['value'].lower() == 'no' and (h.get('ssh_user') or '') == 'root':
        say('crit', 'StorageForge scans this host as root: this cuts the scan off')
    if p['key'] in ('PasswordAuthentication', 'PermitRootLogin', 'AllowTcpForwarding') and not p['rollback']:
        say('warn', 'this changes how people get in. A rollback timer undoes it if StorageForge cannot get back in')
    say('note', 'sshd -t checks the result, and a rejected change is put back')


def _check_sysctl(conn, c, h, p, say):
    say('note', f'in /etc/sysctl.d/90-storageforge-plan.conf, and applied now')


def _check_nothing(conn, c, h, p, say):
    say('note', 'the script looks when it runs')


def _check_selinux_boolean(conn, c, h, p, say):
    from . import security
    m = security.measurement(conn, h['name'])
    if m and not m.get('selinux'):
        say('crit', f'{h["name"]} does not run SELinux')
    if p['name'] in ('nfs_export_all_rw', 'nfs_export_all_ro') and p['value'] == 'off':
        say('warn', 'on by default on the RHEL family, and turning it off can stop exports')


def _check_relabel(conn, c, h, p, say):
    from . import security
    m = security.measurement(conn, h['name'])
    if m and not m.get('selinux'):
        say('crit', f'{h["name"]} does not run SELinux')
    if not p['type'].endswith('_t'):
        say('crit', f'{p["type"]} is not an SELinux type')


LATERAL = ('/etc/shadow', '/root/.ssh', '/etc/ssl/private', '/root/')


def _check_apparmor_local(conn, c, h, p, say):
    from . import security
    m = security.measurement(conn, h['name'])
    if m and not (m.get('apparmor') or {}).get('enabled'):
        say('crit', f'{h["name"]} does not run AppArmor')
    if re.search(r'^\s*(?!deny\b).*(/etc/\*\*|/root/\*\*|/\*\*)', p['rules'], re.M):
        say('warn', 'a rule here opens a path a confined storage daemon should not reach: /etc, /root or everything')
    say('note', 'apparmor_parser checks it first, and a rejected change is put back')


def _check_wg(conn, c, h, p, say):
    nets, bad = _nets(p['allowed'])
    if bad:
        say('crit', f'not a network: {bad[0]}')
    if any(n.prefixlen == 0 for n in nets):
        say('warn', 'this peer may route everything through this host')
    m = _infra(conn, h)
    if m and p['iface'] not in {w['name'] for w in (m.get('access') or {}).get('wireguard') or []} and (m.get('access') or {}).get('wireguard') is not None:
        say('warn', f'{p["iface"]} was not seen at the last reading')


def _workload(conn, h, runtime, name):
    from . import workloads
    return next((w for w in workloads.listing(conn, h['name'])['workloads'] if w['runtime'] == runtime and w['name'] == name), None)


def _check_workload_action(conn, c, h, p, say):
    w = _workload(conn, h, p['runtime'], p['name'])
    if not w:
        say('note', f'{p["name"]} was not in the last reading: the script looks when it runs')
    elif p['action'] == 'stop' and w.get('state') != 'running':
        say('ok', f'{p["name"]} is already stopped')


def _check_workload_remove(conn, c, h, p, say):
    from . import security
    w = _workload(conn, h, p['runtime'], p['name'])
    say('note', 'the volumes or disks stay: nothing but the definition goes')
    if w:
        points = {(m.get('on') or {}).get('mount') for m in w.get('mounts') or []} - {None}
        held = [r for r in security.hold_rows(conn, h['name']) if r['status'] != 'released']
        if points and held:
            say('warn', f'it uses {", ".join(sorted(points))}, and {h["name"]} has retention holds: check they still cover what you keep')


def _publish_parts(text: str) -> list[tuple[str, int]]:
    """'127.0.0.1:8080:80/tcp' or '8080:80' → (bind address, host port)."""
    out = []
    for part in filter(None, (text or '').split(',')):
        spec = part.split('/')[0]
        fields = spec.rsplit(':', 2)
        bind, host_port = ('0.0.0.0', fields[0]) if len(fields) == 2 else (fields[0].strip('[]'), fields[1]) if len(fields) == 3 else ('0.0.0.0', fields[0])
        if host_port.isdigit():
            out.append((bind, int(host_port)))
    return out


def _check_container(conn, c, h, p, say):
    from . import security
    net = _net(conn, h)
    busy = {x['port'] for x in (net or {}).get('listeners') or []}
    for bind, port in _publish_parts(p['publish']):
        if port in busy:
            say('crit', f'something already listens on {port} on {h["name"]}')
        if bind not in ('127.0.0.1', '::1'):
            say('warn', f'publishes {port} to every network on {h["name"]}. ufw and firewalld do not stop this: add a firewall rule with hook "forward", or bind it to 127.0.0.1')
    held = {(r.get('snapshot') or '').split('@')[0] for r in security.hold_rows(conn, h['name']) if r['status'] != 'released'}
    for bind in filter(None, (p['binds'] or '').split(',')):
        src = bind.split(':')[0]
        where, fs = c.mount_at(src)
        if fs in ('nfs', 'nfs4', 'cifs', 'smb3'):
            say('warn', f'{src} is on a network filesystem ({where}): databases and locks on it often fail')
        if not any(d and (src == '/' + d or src.startswith('/' + d + '/') or src.startswith(d)) for d in held):
            say('note', f'nothing holds a snapshot of {src}: it has no retention hold')


def _check_vm(conn, c, h, p, say):
    where, _ = c.mount_at(p['disk'])
    if where:
        say('ok', f'its disk sits on {where}')
    say('note', 'its console listens on 127.0.0.1 only. Reach it through an SSH tunnel')
    if p['bridge']:
        say('warn', 'bridged: the host firewall does not see this guest\'s traffic')


def _check_zfs_rollback(conn, c, h, p, say):
    say('warn', 'destroys what was written since that snapshot, and any newer snapshots. A snapshot is taken first')


# ── Ansible ─────────────────────────────────────────────────────────
def _shell(name: str, cmd: str, changed='changed') -> dict:
    return {'name': name, 'ansible.builtin.shell': {'cmd': cmd, 'executable': '/bin/bash'}, 'register': 'sf_out', 'changed_when': f"'{changed}' in sf_out.stdout"}


def _helper_tasks() -> list[dict]:
    return [{'name': 'storageforge-fwrules', 'ansible.builtin.copy': {'dest': '/usr/local/sbin/storageforge-fwrules', 'mode': '0755', 'content': FWRULES}}]


def _rule_id(p: dict) -> str:
    import hashlib
    return hashlib.sha256(f'{p["action"]} {p["proto"]} {p["port"]} {p["source"] or "-"} {p["iface"] or "-"} {p["hook"] or "input"}'.encode()).hexdigest()[:12]


def _ansible_fw_rule(t):
    p = t['params']
    args = ' '.join(shlex.quote(x) for x in (_rule_id(p), p['action'], p['proto'], p['port'], p['source'] or '-', p['iface'] or '-', p['hook'] or 'input'))
    if p['state'] == 'absent':
        body = f'if storageforge-fwrules has {args}; then storageforge-fwrules remove {args} && echo changed; fi'
    else:
        body = f'if ! storageforge-fwrules has {args}; then storageforge-fwrules ensure {args} && echo changed; fi'
    return _helper_tasks() + [_shell(changes.title(t), 'export PATH=$PATH:/usr/local/sbin; ' + body)]


def _ansible_fw_fence(t):
    p = t['params']
    ports = SERVICE_PORTS.get(p['service']) or p['ports']
    q = shlex.quote
    if p['state'] == 'absent':
        body = f'[ -r /etc/storageforge/firewall/fences/{q(p["name"])} ] && storageforge-fwrules fence-del {q(p["name"])} && echo changed'
    else:
        args = ' '.join(q(x) for x in (p['name'], ports, p['clients'], p['iface'] or '-'))
        body = f'if ! storageforge-fwrules fence-has {args}; then storageforge-fwrules fence-set {args} && echo changed; fi'
    return _helper_tasks() + [_shell(changes.title(t), 'export PATH=$PATH:/usr/local/sbin; ' + body)]


def _ansible_bash(fn: str, args: tuple):
    """What has no good module: the same function the script runs, with the same report-first look at the host."""
    def render(t):
        q = shlex.quote
        p = t['params']
        call = ' '.join(q(str(p.get(a) if not isinstance(p.get(a), bool) else ('1' if p[a] else ''))) for a in args)
        body = re.search(rf'^{fn}\(\) \{{.*?^\}}$', BASH, re.M | re.S)[0]
        return _shell(changes.title(t), ('APPLY=1; STAMP=$(date +%Y%m%d-%H%M%S); ok() { echo "ok: $*"; }; missing() { echo "missing: $*"; }; conflict() { echo "conflict: $*" >&2; exit 1; }; info() { :; }\n'
                                         'act() { echo "changed: $*"; }; try() { "$@" || { conflict "failed: $*"; return 1; }; }; later() { conflict "$*"; }; durable() { sync; }; FW=/bin/true\n'
                                         'fw_arm() { :; }; fw_tool() { :; }\n' + body + f'\n{fn} {call}\n'))
    return render


def _ansible_sysctl(t):
    p = t['params']
    return {'name': changes.title(t), 'ansible.posix.sysctl': {'name': p['key'], 'value': p['value'], 'sysctl_file': '/etc/sysctl.d/90-storageforge-plan.conf', 'state': 'present', 'reload': True}}


def _ansible_umask(t):
    return {'name': changes.title(t), 'ansible.builtin.copy': {'dest': '/etc/profile.d/storageforge-umask.sh', 'mode': '0644', 'content': f'umask {t["params"]["value"]}\n'}}


def _ansible_boolean(t):
    p = t['params']
    return {'name': changes.title(t), 'ansible.posix.seboolean': {'name': p['name'], 'state': p['value'] == 'on', 'persistent': True}}


def _ansible_relabel(t):
    p = t['params']
    return [{'name': changes.title(t), 'community.general.sefcontext': {'target': f'{p["path"]}(/.*)?', 'setype': p['type'], 'state': 'present'}},
            {'name': f'restorecon {p["path"]}', 'ansible.builtin.command': {'argv': ['restorecon', '-R', '--', p['path']]}}]


def _ansible_container(t):
    p = t['params']
    module = 'community.docker.docker_container' if p['runtime'] == 'docker' else 'containers.podman.podman_container'
    spec = {'name': p['name'], 'image': p['image'], 'state': 'started', 'restart_policy': p['restart'] or 'unless-stopped', 'labels': {'storageforge.managed': 'true'}}
    if p['publish']:
        spec['published_ports' if p['runtime'] == 'docker' else 'publish'] = p['publish'].split(',')
    if p['binds']:
        spec['volumes' if p['runtime'] == 'docker' else 'volume'] = p['binds'].split(',')
    if p['network']:
        spec['networks' if p['runtime'] == 'docker' else 'network'] = [{'name': p['network']}] if p['runtime'] == 'docker' else p['network']
    return {'name': changes.title(t), module: spec}


def _ansible_vm(t):
    p = t['params']
    net = f'bridge={p["bridge"]}' if p['bridge'] else f'network={p["network"] or "default"}'
    argv = ['virt-install', '--import', '--name', p['name'], '--disk', f'{p["disk"]},bus=virtio', '--vcpus', p['vcpus'] or '2', '--memory', p['ram_mb'] or '2048', '--network', f'{net},model=virtio',
            '--osinfo', p['os_variant'] or 'generic', '--graphics', 'spice,listen=127.0.0.1', '--noautoconsole']
    return {'name': changes.title(t), 'ansible.builtin.command': {'argv': argv}, 'args': {'creates': f'/etc/libvirt/qemu/{p["name"]}.xml'}}


# ── the registrations ───────────────────────────────────────────────
def _when(state, text):
    return f'Remove: {text}' if state == 'absent' else text


changes.register('fw-rule', {'group': 'Firewall', 'label': 'Firewall rule', 'fields': [
    ACTION, PROTO, F('port', 'port', 'Port or range', required=True, placeholder='445 or 8000-8100'), F('source', 'cidr', 'From (anywhere if empty)', placeholder='10.0.20.0/24'),
    F('iface', 'iface', 'Only on interface'), F('hook', 'choice', 'Traffic', options=['input', 'forward'], default='input'), F('state', 'choice', 'Add or remove', options=['present', 'absent'], default='present'), ROLLBACK],
    'help': 'Written in whichever firewall the host runs, so that firewall still lists it. Use forward for a port a container publishes: only that stops it.'},
    ('action', 'proto', 'port', 'source', 'iface', 'hook', 'state', 'rollback'),
    lambda p: _when(p['state'], f'{p["action"].capitalize()} {p["proto"]}/{p["port"]}' + (f' from {p["source"]}' if p['source'] else '') + (f' on {p["iface"]}' if p['iface'] else '') + (' for published ports' if p['hook'] == 'forward' else '')),
    _check_fw_rule, _ansible_fw_rule)

changes.register('fw-fence', {'group': 'Firewall', 'label': 'Fence a share to its clients', 'fields': [
    F('name', 'label', 'Fence name', required=True, placeholder='finance'), F('service', 'choice', 'What', options=['smb', 'nfs', 'iscsi', 'custom'], required=True),
    F('ports', 'ports', 'Ports, for custom', placeholder='445,139'), F('clients', 'cidrs', 'Clients allowed', placeholder='10.0.20.0/24,10.0.99.10/32'), F('iface', 'iface', 'Only on interface'),
    F('state', 'choice', 'Add or remove', options=['present', 'absent'], default='present'), ROLLBACK],
    'help': 'Everyone else is dropped on these ports, ahead of any other firewall, so a wrong firewall rule elsewhere cannot widen it. Loopback is never fenced.'},
    ('name', 'service', 'ports', 'clients', 'iface', 'state', 'rollback'),
    lambda p: _when(p['state'], f'Fence {p["service"]} ({p["name"]}) to {p["clients"] or "nobody"}' + (f' on {p["iface"]}' if p['iface'] else '')),
    _check_fw_fence, _ansible_fw_fence)

changes.register('net-bridge', {'group': 'Network', 'label': 'Create a bridge', 'fields': [
    F('name', 'iface', 'Bridge', required=True, placeholder='br0'), F('ports', 'word', 'Interfaces to put in it', placeholder='eth1'), F('address', 'cidr', 'Address', placeholder='10.0.5.1/24'), ROLLBACK],
    'help': 'With NetworkManager or systemd-networkd. Moving the interface StorageForge comes in on needs a rollback timer.'},
    ('name', 'ports', 'address', 'rollback'), lambda p: f'Create bridge {p["name"]}' + (f' over {p["ports"]}' if p['ports'] else ''), _check_net_bridge, _ansible_bash('t_net_bridge', ('name', 'ports', 'address', 'rollback')))

changes.register('net-vlan', {'group': 'Network', 'label': 'Create a VLAN', 'fields': [
    F('parent', 'iface', 'On interface', required=True), F('vlan_id', 'number', 'VLAN id', required=True), F('address', 'cidr', 'Address'), ROLLBACK]},
    ('parent', 'vlan_id', 'address', 'rollback'), lambda p: f'Create VLAN {p["vlan_id"]} on {p["parent"]}', _check_net_vlan, _ansible_bash('t_net_vlan', ('parent', 'vlan_id', 'address', 'rollback')))

changes.register('net-mtu', {'group': 'Network', 'label': 'Change MTU', 'fields': [F('iface', 'iface', 'Interface', required=True), F('mtu', 'number', 'MTU', required=True, placeholder='9000'), ROLLBACK]},
    ('iface', 'mtu', 'rollback'), lambda p: f'MTU {p["mtu"]} on {p["iface"]}', _check_net_mtu, _ansible_bash('t_net_mtu', ('iface', 'mtu', 'rollback')))

changes.register('sysctl-set', {'group': 'Hardening', 'label': 'Kernel setting', 'fields': [F('key', 'sysctl', 'Setting', required=True, placeholder='fs.protected_hardlinks'), F('value', 'word', 'Value', required=True, placeholder='1')]},
    ('key', 'value'), lambda p: f'Set {p["key"]} to {p["value"]}', _check_sysctl, _ansible_sysctl)

changes.register('sshd-option', {'group': 'Hardening', 'label': 'SSH server setting', 'fields': [F('key', 'choice', 'Setting', options=SSHD_KEYS, required=True), F('value', 'word', 'Value', required=True), ROLLBACK],
    'help': 'In sshd_config.d. sshd -t checks it, and a rejected change is put back.'},
    ('key', 'value', 'rollback'), lambda p: f'SSH: {p["key"]} {p["value"]}', _check_sshd, _ansible_bash('t_sshd_option', ('key', 'value', 'rollback')))

changes.register('umask-set', {'group': 'Hardening', 'label': 'Default umask', 'fields': [F('value', 'mode', 'Umask', required=True, placeholder='027')]},
    ('value',), lambda p: f'Default umask {p["value"]}', _check_nothing, _ansible_umask)

changes.register('selinux-boolean', {'group': 'Hardening', 'label': 'SELinux boolean', 'fields': [F('name', 'name', 'Boolean', required=True), F('value', 'choice', 'Value', options=['on', 'off'], required=True)]},
    ('name', 'value'), lambda p: f'SELinux {p["name"]} {p["value"]}', _check_selinux_boolean, _ansible_boolean)

changes.register('selinux-relabel', {'group': 'Hardening', 'label': 'SELinux label', 'fields': [F('path', 'path', 'Path', required=True), F('type', 'name', 'Type', required=True, placeholder='samba_share_t')],
    'help': 'Registers the type with semanage, so it survives a relabel, then runs restorecon.'},
    ('path', 'type'), lambda p: f'Label {p["path"]} {p["type"]}', _check_relabel, _ansible_relabel)

changes.register('apparmor-local', {'group': 'Hardening', 'label': 'AppArmor local rules', 'fields': [F('profile', 'name', 'Profile', required=True, placeholder='usr.sbin.smbd'), F('rules', 'lines', 'Rules', required=True, placeholder='/srv/pool/dataset/** rwk,')],
    'help': 'In /etc/apparmor.d/local, so a package update keeps them. Checked with apparmor_parser first.'},
    ('profile', 'rules'), lambda p: f'AppArmor rules for {p["profile"]}', _check_apparmor_local, _ansible_bash('t_apparmor_local', ('profile', 'rules')))

changes.register('apparmor-mode', {'group': 'Hardening', 'label': 'AppArmor mode', 'fields': [F('profile', 'name', 'Profile', required=True), F('mode', 'choice', 'Mode', options=['enforce', 'complain'], required=True)]},
    ('profile', 'mode'), lambda p: f'AppArmor {p["profile"]} {p["mode"]}', _check_nothing, _ansible_bash('t_apparmor_mode', ('profile', 'mode')))

changes.register('chrony-nts', {'group': 'Hardening', 'label': 'NTS time sources', 'fields': [F('servers', 'word', 'Servers', required=True, placeholder='time.cloudflare.com,nts.netnod.se')],
    'help': 'What the clock guard asks for: time that cannot be forged in transit.'},
    ('servers',), lambda p: f'NTS time from {p["servers"]}', _check_nothing, _ansible_bash('t_chrony_nts', ('servers',)))

changes.register('wg-peer', {'group': 'Network', 'label': 'WireGuard peer', 'fields': [
    F('iface', 'iface', 'Interface', required=True, placeholder='wg0'), F('pubkey', 'wgkey', 'Public key', required=True), F('allowed', 'cidrs', 'Allowed addresses', required=True, placeholder='10.8.0.2/32'),
    F('state', 'choice', 'Add or revoke', options=['present', 'absent'], default='present')]},
    ('iface', 'pubkey', 'allowed', 'state'), lambda p: _when(p['state'], f'WireGuard peer on {p["iface"]}: {p["pubkey"][:8]}…'), _check_wg, _ansible_bash('t_wg_peer', ('iface', 'pubkey', 'allowed', 'state')))

changes.register('workload-action', {'group': 'Workloads', 'label': 'Start, stop or snapshot', 'fields': [
    F('runtime', 'choice', 'Runtime', options=RUNTIMES, required=True), F('name', 'name', 'Name', required=True), F('action', 'choice', 'Action', options=['start', 'stop', 'restart', 'snapshot'], required=True)]},
    ('runtime', 'name', 'action'), lambda p: f'{p["action"].capitalize()} {p["runtime"]} {p["name"]}', _check_workload_action, _ansible_bash('t_workload_action', ('runtime', 'name', 'action')))

changes.register('workload-remove', {'group': 'Workloads', 'label': 'Remove a workload', 'destructive': True, 'fields': [
    F('runtime', 'choice', 'Runtime', options=RUNTIMES, required=True), F('name', 'name', 'Name', required=True)],
    'help': 'Takes away the container or VM definition. Volumes and disks stay.'},
    ('runtime', 'name'), lambda p: f'Remove {p["runtime"]} {p["name"]}', _check_workload_remove, _ansible_bash('t_workload_remove', ('runtime', 'name')))

changes.register('container', {'group': 'Workloads', 'label': 'Run a container', 'fields': [
    F('runtime', 'choice', 'Runtime', options=['docker', 'podman'], required=True), F('name', 'name', 'Name', required=True), F('image', 'image', 'Image', required=True, placeholder='docker.io/library/nginx:1.27'),
    F('publish', 'publish', 'Ports to publish', placeholder='127.0.0.1:8080:80/tcp'), F('binds', 'binds', 'Folders to mount', placeholder='/tank/app:/data:Z'), F('restart', 'choice', 'Restart', options=['', 'no', 'always', 'unless-stopped', 'on-failure'], default=''),
    F('network', 'name', 'Network')]},
    ('runtime', 'name', 'image', 'publish', 'binds', 'restart', 'network'), lambda p: f'Run {p["image"]} as {p["name"]} on {p["runtime"]}', _check_container, _ansible_container)

changes.register('vm', {'group': 'Workloads', 'label': 'Define a VM from a disk', 'fields': [
    F('name', 'name', 'Name', required=True), F('disk', 'path', 'Disk image', required=True), F('vcpus', 'number', 'vCPUs', placeholder='2'), F('ram_mb', 'number', 'Memory, MiB', placeholder='2048'),
    F('network', 'name', 'libvirt network', placeholder='default'), F('os_variant', 'name', 'OS variant', placeholder='debian13'), F('bridge', 'iface', 'Or a bridge')],
    'help': 'virt-install --import, with the console on loopback. Installing an OS from an ISO or cloud image is not built.'},
    ('name', 'disk', 'vcpus', 'ram_mb', 'network', 'os_variant', 'bridge'), lambda p: f'VM {p["name"]} from {p["disk"]}', _check_vm, _ansible_vm)

changes.register('zfs-rollback', {'group': 'ZFS', 'label': 'Roll back to a snapshot', 'destructive': True, 'fields': [F('dataset', 'dataset', 'Dataset', required=True), F('snapshot', 'name', 'Snapshot', required=True)]},
    ('dataset', 'snapshot'), lambda p: f'Roll {p["dataset"]} back to @{p["snapshot"]}', _check_zfs_rollback, _ansible_bash('t_zfs_rollback', ('dataset', 'snapshot')))

changes.EXTRA_BASH[:] = [BASH]
