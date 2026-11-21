"""Plan steps for bonds, addresses, routes and DHCP, written in whatever the host configures its network with: netplan,
NetworkManager, systemd-networkd or ifupdown (docs/change-plans.md).

The script works out which one runs (netplan first, as it writes for networkd or NetworkManager itself), writes the change in
that system's own files or connections, so the host still shows it and a reboot keeps it, and applies it now. Each change is
a file or a connection of its own where the system allows, so taking it away again never touches what the host's admin wrote.
What another file already says is not edited: the step says which file it is in and leaves it to a person.

A change that could cut the path StorageForge comes in on carries the rollback timer of steps_infra.py: the change is
journalled, a systemd timer puts it back after the minutes given, and only a second signed run from the controller (which
can only happen while the path still works) stops the timer. Without a timer, such a change is refused on the host.
"""
from __future__ import annotations

import ipaddress
import re
import shlex

from . import changes
from .changes import F
from .steps_infra import BASH as INFRA_BASH, ROLLBACK, _address_clash, _check_iface, _check_ssh_path, _controller_ips, _net, _nets

BOND_MODES = ['active-backup', '802.3ad', 'balance-rr', 'balance-xor', 'broadcast', 'balance-tlb', 'balance-alb']
IFACE = re.compile(r'[A-Za-z0-9_][A-Za-z0-9_.@-]{0,14}')
STATE = F('state', 'choice', 'Add or remove', options=['present', 'absent'], default='present')

# Uses act, try, later, durable, fw_tool, fw_arm, net_guard and net_is_ssh_path of the change script. No apostrophes: the
# script text is checked for values that could end a quoted word.
BASH = r"""
# ── network: bonds, addresses, routes and DHCP ──────────────────────
nw_backend() {
  if command -v netplan >/dev/null && compgen -G "/etc/netplan/*.yaml" >/dev/null; then echo netplan
  elif command -v nmcli >/dev/null && [[ $(nmcli -t -f RUNNING general 2>/dev/null) == running ]]; then echo nm
  elif systemctl is-active -q systemd-networkd 2>/dev/null; then echo networkd
  elif [[ -r /etc/network/interfaces ]] && command -v ifup >/dev/null; then echo ifupdown
  else echo none; fi
}
nw_said() { case $1 in netplan) echo netplan ;; nm) echo NetworkManager ;; networkd) echo systemd-networkd ;; ifupdown) echo ifupdown ;; *) echo "nothing that keeps it" ;; esac; }
nw_name_ok() { [[ $1 =~ ^[A-Za-z0-9_][A-Za-z0-9_.@-]{0,14}$ ]]; }
nw_tag() { printf "%s" "$*" | tr -c "A-Za-z0-9_.-" "-"; }
nw_v() { if [[ $1 == *:* ]]; then echo 6; else echo 4; fi; }
nw_none() { conflict "nothing on this host keeps network settings across a reboot (no netplan, NetworkManager, systemd-networkd or ifupdown): set it up by hand"; }
nw_other() { conflict "$1 says so in $2, which is not a file of StorageForge: change it there by hand"; }
# the route to where this SSH session comes from, and whether a destination covers it
nw_client() { [[ -n ${SSH_CONNECTION:-} ]] && echo "${SSH_CONNECTION%% *}"; }
nw_int() { local a b c d; IFS=. read -r a b c d <<<"$1"; echo $(( (a << 24) | (b << 16) | (c << 8) | d )); }
# nw_covers NETWORK ADDRESS: 0 if the address is inside. IPv4 in bash; IPv6 by python3 where there is one, or taken as inside
nw_covers() { local net=${1%/*} len=${1#*/} m
  [[ $1 == */* ]] || len=32
  if [[ $net == *:* || $2 == *:* ]]; then
    [[ $net == *:* && $2 == *:* ]] || return 1
    command -v python3 >/dev/null || return 0
    python3 -c "import ipaddress, sys; sys.exit(0 if ipaddress.ip_address(sys.argv[2]) in ipaddress.ip_network(sys.argv[1], strict=False) else 1)" "$1" "$2" 2>/dev/null; return
  fi
  ((len == 0)) && return 0
  m=$(( (0xFFFFFFFF << (32 - len)) & 0xFFFFFFFF ))
  (( ($(nw_int "$net") & m) == ($(nw_int "$2") & m) ))
}

# a route that covers where this session comes from could send the reply elsewhere
nw_route_guard() { local cl; cl=$(nw_client)
  [[ -n $cl && -z $2 ]] && nw_covers "$1" "$cl" || return 0
  conflict "this session comes from $cl, inside $1: stage a rollback timer, or this could cut the host off for good"; return 1
}

# ── netplan ─────────────────────────────────────────────────────────
NP_DIR=/etc/netplan
np_type() { local t v
  if command -v netplan >/dev/null; then
    for t in ethernets bonds bridges vlans wifis; do v=$(netplan get "$t.$1" 2>/dev/null) || continue; [[ -n $v && $v != null ]] && { echo "$t"; return 0; }; done
  fi
  if [[ -d /sys/class/net/$1/bonding ]]; then echo bonds; elif [[ -d /sys/class/net/$1/bridge ]]; then echo bridges; elif [[ -r /proc/net/vlan/$1 ]]; then echo vlans; else echo ethernets; fi
}
# np_head IFACE: the first lines of a netplan file that says something about IFACE
np_head() { printf "network:\n  version: 2\n  %s:\n    \"%s\":\n" "$(np_type "$1")" "$1"; }
# np_write FILE TEXT ROLLBACK: a netplan file of StorageForge, checked by netplan generate, then applied; the timer undoes it
np_write() { local f=$1 text=$2 roll=$3 bak= out
  fw_tool
  if [[ -e $f ]]; then bak=$f.storageforge-$STAMP; cp -a "$f" "$bak"; fi
  if [[ -n $bak ]]; then fw_arm "$roll" "mv -f $bak $f; netplan apply"; else fw_arm "$roll" "rm -f $f; netplan apply"; fi
  install -d -m 0755 "$NP_DIR"
  (umask 077; printf "%s\n" "$text" >"$f.new"); mv -f "$f.new" "$f"; chmod 0600 "$f"
  if ! out=$(netplan generate 2>&1); then
    if [[ -n $bak ]]; then mv -f "$bak" "$f"; else rm -f "$f"; fi
    conflict "netplan generate refused it, so it is taken out again: $(tail -n 2 <<<"$out" | tr "\n" " ")"; return 1
  fi
  durable "$f"; try netplan apply
}
np_remove() { local f=$1 roll=$2
  fw_tool
  cp -a "$f" "$f.storageforge-$STAMP"; fw_arm "$roll" "mv -f $f.storageforge-$STAMP $f; netplan apply"
  rm -f "$f"; durable "$NP_DIR"; try netplan apply
}
np_other() { local f; for f in "$NP_DIR"/*.yaml; do [[ -e $f && $f != */90-storageforge-* ]] || continue; grep -qF -- "$1" "$f" 2>/dev/null && { echo "$f"; return 0; }; done; return 1; }

# ── NetworkManager ──────────────────────────────────────────────────
nm_con() { nmcli -g GENERAL.CONNECTION device show "$1" 2>/dev/null | head -n 1; }
nm_get() { nmcli -g "$2" connection show "$1" 2>/dev/null | tr -d "\\\\"; }
nm_has() { [[ ", $1, " == *", $2, "* ]]; }
# nm_change IFACE ROLLBACK UNDO-SETTINGS -- SETTINGS: modify the connection on IFACE, reapply it, and journal the way back
nm_change() { local iface=$1 roll=$2 con undo=() set=() u
  shift 2; while [[ $# -gt 0 && $1 != -- ]]; do undo+=("$1"); shift; done; shift; set=("$@")
  con=$(nm_con "$iface"); [[ -n $con ]] || { conflict "NetworkManager has no connection on $iface: set it up by hand"; return 1; }
  fw_tool
  printf -v u "nmcli connection modify %q" "$con"; printf -v u "%s%s; nmcli device reapply %q" "$u" "$(printf " %q" "${undo[@]}")" "$iface"
  fw_arm "$roll" "$u"
  try nmcli connection modify "$con" "${set[@]}" || return 1
  try nmcli device reapply "$iface"
}

# ── systemd-networkd ────────────────────────────────────────────────
nd_unit() { networkctl status "$1" 2>/dev/null | sed -n "s/^ *Network File: //p" | head -n 1; }
# nd_dropin IFACE NAME TEXT ROLLBACK: a drop-in beside the file that manages IFACE, reloaded and reconfigured; the timer undoes it
nd_dropin() { local iface=$1 name=$2 text=$3 roll=$4 unit dir
  unit=$(nd_unit "$iface"); [[ -n $unit && $unit != n/a ]] || { conflict "systemd-networkd does not manage $iface: set it up by hand"; return 1; }
  dir=/etc/systemd/network/${unit##*/}.d
  fw_tool
  fw_arm "$roll" "rm -f $dir/$name; networkctl reload; networkctl reconfigure $iface"
  mkdir -p "$dir"; printf "%s\n" "$text" >"$dir/$name"; durable "$dir"
  networkctl reload || true; try networkctl reconfigure "$iface"
}
nd_drop_off() { local iface=$1 f=$2 roll=$3
  fw_tool
  cp -a "$f" "/run/sf-undo-${f##*/}-$STAMP"; fw_arm "$roll" "mv -f /run/sf-undo-${f##*/}-$STAMP $f; networkctl reload; networkctl reconfigure $iface"
  rm -f "$f"; durable "${f%/*}"; networkctl reload || true; try networkctl reconfigure "$iface"
}
nd_dhcp() { local unit f; unit=$(nd_unit "$1"); [[ -n $unit && -e $unit ]] || return 0   # the DHCP= that wins: the last of the file and its drop-ins
  for f in "$unit" /etc/systemd/network/"${unit##*/}".d/*.conf; do [[ -e $f ]] && grep -h "^DHCP=" "$f"; done | tail -n 1; }
nd_ours() { local unit; unit=$(nd_unit "$1"); [[ -n $unit ]] && ls "/etc/systemd/network/${unit##*/}.d/$2" 2>/dev/null; }
nd_other() { local unit f; unit=$(nd_unit "$1"); [[ -n $unit && -e $unit ]] || return 1
  for f in "$unit" /etc/systemd/network/"${unit##*/}".d/*.conf; do [[ -e $f && ${f##*/} != sf-* ]] || continue; grep -qE -- "$2" "$f" && { echo "$f"; return 0; }; done; return 1; }

# ── ifupdown ────────────────────────────────────────────────────────
IF_D=/etc/network/interfaces.d
if_sourced() { grep -Eqs "^[[:space:]]*source(-directory)?[[:space:]]+/etc/network/interfaces\.d" /etc/network/interfaces; }
if_other() { local f; for f in /etc/network/interfaces "$IF_D"/*; do [[ -e $f && ${f##*/} != sf-* ]] || continue; grep -qE -- "$1" "$f" && { echo "$f"; return 0; }; done; return 1; }
# if_file NAME TEXT ROLLBACK UNDO-NOW: a file of StorageForge in interfaces.d; the timer takes it out and runs UNDO-NOW
if_file() { local f=$IF_D/$1 text=$2 roll=$3 now=$4
  if_sourced || { conflict "/etc/network/interfaces does not read $IF_D (source $IF_D/*): add that line by hand first"; return 1; }
  fw_tool
  fw_arm "$roll" "rm -f $f; $now"
  mkdir -p "$IF_D"; printf "%s\n" "$text" >"$f"; durable "$f"
}
IF_ROUTES=/etc/storageforge/net/routes
if_route_hook() { # ifupdown has no place for a route of its own: a hook puts back the routes of an interface each time it comes up
  [[ -x /etc/network/if-up.d/storageforge-routes ]] && return 0
  mkdir -p /etc/network/if-up.d "${IF_ROUTES%/*}"
  cat >/etc/network/if-up.d/storageforge-routes <<"SF_HOOK"
#!/bin/sh
# Written by StorageForge: the routes change plans asked for, put back each time their interface comes up.
[ -r /etc/storageforge/net/routes ] || exit 0
while read -r dev dst via metric; do
  [ "$dev" = "$IFACE" ] || continue
  ip route replace "$dst" via "$via" dev "$dev" ${metric:+metric "$metric"} 2>/dev/null || true
done </etc/storageforge/net/routes
SF_HOOK
  chmod 0755 /etc/network/if-up.d/storageforge-routes
}

# ── the steps ───────────────────────────────────────────────────────
t_net_address() { local iface=$1 addr=$2 state=${3:-present} roll=$4 b live=0 tag f where k
  nw_name_ok "$iface" || { conflict "$iface is not an interface name"; return 0; }
  ip link show "$iface" >/dev/null 2>&1 || { later "$iface is not on this host"; return 0; }
  ip -o addr show dev "$iface" 2>/dev/null | grep -qF " $addr " && live=1
  b=$(nw_backend); tag=$(nw_tag "$iface-$addr"); k=ipv$(nw_v "$addr")
  case $b in
    netplan) f=$NP_DIR/90-storageforge-addr-$tag.yaml; [[ -e $f ]] && where=ours || where=$(np_other "$addr") ;;
    nm) nm_has "$(nm_get "$(nm_con "$iface")" "$k.addresses")" "$addr" && where=ours ;;
    networkd) f=sf-address-$tag.conf; [[ -n $(nd_ours "$iface" "$f") ]] && where=ours || where=$(nd_other "$iface" "^Address=${addr//./\\.}$") ;;
    ifupdown) f=sf-addr-$tag; [[ -e $IF_D/$f ]] && where=ours || where=$(if_other "address[[:space:]]+${addr%/*}(/|[[:space:]]|$)") ;;
    *) nw_none; return 0 ;;
  esac
  if [[ $state == absent ]]; then
    if ((!live)) && [[ -z ${where:-} ]]; then ok "$iface does not have $addr"; return 0; fi
    [[ -z ${where:-} || $where == ours ]] || { nw_other "$addr on $iface" "$where"; return 0; }
    net_guard "$iface" "$roll" || return 0
    act "take $addr off $iface, with $(nw_said "$b")" || return 0
    if [[ ${where:-} == ours ]]; then
      case $b in
        netplan) np_remove "$f" "$roll" || return 0 ;;
        nm) nm_change "$iface" "$roll" "+$k.addresses" "$addr" -- "-$k.addresses" "$addr" || return 0 ;;
        networkd) nd_drop_off "$iface" "$(nd_ours "$iface" "$f")" "$roll" || return 0 ;;
        ifupdown) fw_tool; cp -a "$IF_D/$f" "/run/sf-undo-$f-$STAMP"; fw_arm "$roll" "mv -f /run/sf-undo-$f-$STAMP $IF_D/$f; ip addr add $addr dev $iface"; rm -f "$IF_D/$f" ;;
      esac
    fi
    ip -o addr show dev "$iface" 2>/dev/null | grep -qF " $addr " && ip addr del "$addr" dev "$iface"
    ok "$addr is off $iface"
    return 0
  fi
  if ((live)) && [[ -n ${where:-} ]]; then ok "$iface has $addr, and $(nw_said "$b") keeps it"; return 0; fi
  act "give $iface $addr, with $(nw_said "$b")" || return 0
  if [[ -z ${where:-} ]]; then
    case $b in
      netplan) np_write "$f" "$(np_head "$iface"; printf "      addresses: [\"%s\"]\n" "$addr")" "$roll" || return 0 ;;
      nm) local m; m=$(nm_get "$(nm_con "$iface")" "$k.method")
          if [[ $m == disabled || $m == link-local || $m == ignore ]]; then nm_change "$iface" "$roll" "-$k.addresses" "$addr" "$k.method" "$m" -- "+$k.addresses" "$addr" "$k.method" manual || return 0
          else nm_change "$iface" "$roll" "-$k.addresses" "$addr" -- "+$k.addresses" "$addr" || return 0; fi ;;
      networkd) nd_dropin "$iface" "$f" "$(printf "[Network]\nAddress=%s" "$addr")" "$roll" || return 0 ;;
      ifupdown) if_file "$f" "$(printf "iface %s %s static\n    address %s" "$iface" "$([[ $k == ipv6 ]] && echo inet6 || echo inet)" "$addr")" "$roll" "ip addr del $addr dev $iface" || return 0 ;;
    esac
  fi
  ip -o addr show dev "$iface" 2>/dev/null | grep -qF " $addr " || try ip addr add "$addr" dev "$iface" || return 0
  ok "$iface has $addr"
}

t_net_route() { local dst=$1 via=$2 dev=$3 metric=$4 state=${5:-present} roll=$6 b live=0 tag f where k v to cl
  v=$(nw_v "$dst"); k=ipv$v
  [[ -n $dev ]] || dev=$(ip -o route get "$via" 2>/dev/null | sed -n "s/.* dev \([^ ]*\).*/\1/p")
  [[ -n $dev ]] || { conflict "no interface reaches $via: name the interface"; return 0; }
  nw_name_ok "$dev" || { conflict "$dev is not an interface name"; return 0; }
  ip -"$v" -o route show to exact "$dst" 2>/dev/null | grep -qE " via ${via//./\\.} .*dev $dev( |$)" && live=1
  b=$(nw_backend); tag=$(nw_tag "$dev-$dst-$via"); to=$dst
  [[ $dst == 0.0.0.0/0 || $dst == ::/0 ]] && to=default
  case $b in
    netplan) f=$NP_DIR/90-storageforge-route-$tag.yaml; [[ -e $f ]] && where=ours || where=$(np_other "$via") ;;
    nm) nm_has "$(nm_get "$(nm_con "$dev")" "$k.routes")" "$dst $via${metric:+ $metric}" && where=ours ;;
    networkd) f=sf-route-$tag.conf; [[ -n $(nd_ours "$dev" "$f") ]] && where=ours || where=$(nd_other "$dev" "^Gateway=${via//./\\.}$") ;;
    ifupdown) grep -qsx -- "$dev $dst $via${metric:+ $metric}" "$IF_ROUTES" && where=ours ;;
    *) nw_none; return 0 ;;
  esac
  if [[ $state == absent ]]; then
    if ((!live)) && [[ -z ${where:-} ]]; then ok "there is no route to $dst via $via"; return 0; fi
    [[ -z ${where:-} || $where == ours ]] || { nw_other "the route to $dst via $via" "$where"; return 0; }
    nw_route_guard "$dst" "$roll" || return 0
    act "remove the route to $dst via $via on $dev, with $(nw_said "$b")" || return 0
    if [[ ${where:-} == ours ]]; then
      case $b in
        netplan) np_remove "$f" "$roll" || return 0 ;;
        nm) nm_change "$dev" "$roll" "+$k.routes" "$dst $via${metric:+ $metric}" -- "-$k.routes" "$dst $via${metric:+ $metric}" || return 0 ;;
        networkd) nd_drop_off "$dev" "$(nd_ours "$dev" "$f")" "$roll" || return 0 ;;
        ifupdown) fw_tool; fw_arm "$roll" "echo $dev $dst $via $metric >>$IF_ROUTES; ip route replace $dst via $via dev $dev"
                  grep -vx -- "$dev $dst $via${metric:+ $metric}" "$IF_ROUTES" >"$IF_ROUTES.new" || true; mv -f "$IF_ROUTES.new" "$IF_ROUTES" ;;
      esac
    fi
    ((live)) && ip -"$v" route del "$dst" via "$via" dev "$dev" 2>/dev/null
    ok "the route to $dst via $via is gone"
    return 0
  fi
  if ((live)) && [[ -n ${where:-} ]]; then ok "the route to $dst via $via is there, and $(nw_said "$b") keeps it"; return 0; fi
  nw_route_guard "$dst" "$roll" || return 0
  act "route $dst via $via on $dev${metric:+ (metric $metric)}, with $(nw_said "$b")" || return 0
  if [[ -z ${where:-} ]]; then
    case $b in
      netplan) np_write "$f" "$(np_head "$dev"; printf "      routes:\n        - to: \"%s\"\n          via: \"%s\"\n" "$to" "$via"; [[ -n $metric ]] && printf "          metric: %s\n" "$metric")" "$roll" || return 0 ;;
      nm) nm_change "$dev" "$roll" "-$k.routes" "$dst $via${metric:+ $metric}" -- "+$k.routes" "$dst $via${metric:+ $metric}" || return 0 ;;
      networkd) nd_dropin "$dev" "$f" "$(printf "[Route]\nDestination=%s\nGateway=%s" "$dst" "$via"; [[ -n $metric ]] && printf "\nMetric=%s" "$metric")" "$roll" || return 0 ;;
      ifupdown) fw_tool; fw_arm "$roll" "grep -vx -- \"$dev $dst $via${metric:+ $metric}\" $IF_ROUTES >$IF_ROUTES.new; mv -f $IF_ROUTES.new $IF_ROUTES; ip route del $dst via $via dev $dev"
                if_route_hook; printf "%s\n" "$dev $dst $via${metric:+ $metric}" >>"$IF_ROUTES"; durable "$IF_ROUTES" ;;
    esac
  fi
  ip -"$v" route replace "$dst" via "$via" dev "$dev" ${metric:+metric "$metric"} 2>/dev/null || ip -"$v" -o route show to exact "$dst" | grep -qF " via $via " || { conflict "ip route replace $dst via $via dev $dev failed"; return 0; }
  ok "route to $dst via $via on $dev"
}

t_net_dhcp() { local iface=$1 family=${2:-ipv4} state=${3:-on} roll=$4 b want4= want6= f m4 m6 cur tag on
  nw_name_ok "$iface" || { conflict "$iface is not an interface name"; return 0; }
  ip link show "$iface" >/dev/null 2>&1 || { later "$iface is not on this host"; return 0; }
  on=false; [[ $state == on ]] && on=true
  [[ $family == ipv6 ]] || want4=$on; [[ $family == ipv4 ]] || want6=$on
  b=$(nw_backend); tag=$(nw_tag "$iface")
  case $b in
    netplan) f=$NP_DIR/90-storageforge-dhcp-$tag.yaml
             cur=$(cat "$f" 2>/dev/null || true)
             if { [[ -z $want4 ]] || grep -q "dhcp4: $want4" <<<"$cur"; } && { [[ -z $want6 ]] || grep -q "dhcp6: $want6" <<<"$cur"; }; then ok "netplan has DHCP $state for $family on $iface"; return 0; fi ;;
    nm) local con; con=$(nm_con "$iface"); [[ -n $con ]] || { conflict "NetworkManager has no connection on $iface: set it up by hand"; return 0; }
        m4=$(nm_get "$con" ipv4.method); m6=$(nm_get "$con" ipv6.method)
        if { [[ -z $want4 ]] || [[ ($want4 == true && $m4 == auto) || ($want4 == false && $m4 != auto) ]]; } && { [[ -z $want6 ]] || [[ ($want6 == true && ($m6 == auto || $m6 == dhcp)) || ($want6 == false && $m6 != auto && $m6 != dhcp) ]]; }; then ok "NetworkManager has DHCP $state for $family on $iface"; return 0; fi ;;
    networkd) cur=$(nd_dhcp "$iface")
              f=$(case $family-$state in ipv4-on) echo ipv4 ;; ipv6-on) echo ipv6 ;; both-on) echo yes ;; *) echo no ;; esac)
              if [[ $cur == "DHCP=$f" ]]; then ok "systemd-networkd has DHCP=$f on $iface"; return 0; fi ;;
    ifupdown) f=sf-dhcp-$tag
              if [[ $state == on && -e $IF_D/$f ]]; then ok "ifupdown has DHCP on $iface"; return 0; fi
              if [[ $state == off && ! -e $IF_D/$f ]] && ! if_other "^[[:space:]]*iface[[:space:]]+${iface}[[:space:]]+inet6?[[:space:]]+(dhcp|auto)" >/dev/null; then ok "ifupdown has no DHCP on $iface"; return 0; fi
              local other; other=$(if_other "^[[:space:]]*iface[[:space:]]+${iface}[[:space:]]") && [[ -n $other ]] && { nw_other "how $iface gets its address" "$other"; return 0; } ;;
    *) nw_none; return 0 ;;
  esac
  net_guard "$iface" "$roll" || return 0
  act "DHCP $state for $family on $iface, with $(nw_said "$b")" || return 0
  case $b in
    netplan) np_write "$f" "$(np_head "$iface"; [[ -n $want4 ]] && printf "      dhcp4: %s\n" "$want4"; [[ -n $want6 ]] && printf "      dhcp6: %s\n" "$want6")" "$roll" || return 0 ;;
    nm) local set=() undo=() has
        if [[ -n $want4 ]]; then has=$(nm_get "$con" ipv4.addresses); undo+=(ipv4.method "$m4"); set+=(ipv4.method "$([[ $want4 == true ]] && echo auto || { [[ -n $has ]] && echo manual || echo disabled; })"); fi
        if [[ -n $want6 ]]; then has=$(nm_get "$con" ipv6.addresses); undo+=(ipv6.method "$m6"); set+=(ipv6.method "$([[ $want6 == true ]] && echo auto || { [[ -n $has ]] && echo manual || echo disabled; })"); fi
        nm_change "$iface" "$roll" "${undo[@]}" -- "${set[@]}" || return 0 ;;
    networkd) nd_dropin "$iface" sf-dhcp.conf "$(printf "[Network]\nDHCP=%s" "$f")" "$roll" || return 0 ;;
    ifupdown) if [[ $state == on ]]; then
                if_file "$f" "$(printf "auto %s\n" "$iface"; [[ -n $want4 ]] && printf "iface %s inet dhcp\n" "$iface"; [[ -n $want6 ]] && printf "iface %s inet6 auto\n" "$iface")" "$roll" "ifdown $iface; ifup $iface" || return 0
                try ifup "$iface" || return 0
              else
                fw_tool; cp -a "$IF_D/$f" "/run/sf-undo-$f-$STAMP"; fw_arm "$roll" "mv -f /run/sf-undo-$f-$STAMP $IF_D/$f; ifup $iface"
                ifdown "$iface" 2>/dev/null || true; rm -f "$IF_D/$f"
              fi ;;
  esac
  ok "DHCP $state for $family on $iface"
}

t_net_bond() { local name=$1 ports=$2 mode=${3:-active-backup} address=$4 dhcp=$5 roll=$6 b p arr=() have
  nw_name_ok "$name" || { conflict "$name is not an interface name"; return 0; }
  IFS=, read -ra arr <<<"$ports"
  ((${#arr[@]})) || { conflict "a bond needs at least one interface"; return 0; }
  for p in "${arr[@]}"; do nw_name_ok "$p" || { conflict "$p is not an interface name"; return 0; }; done
  if [[ -d /sys/class/net/$name/bonding ]]; then
    have=$(cat "/sys/class/net/$name/bonding/slaves" 2>/dev/null)
    for p in "${arr[@]}"; do [[ " $have " == *" $p "* ]] || { conflict "bond $name exists without $p (it has ${have:-no ports}): change it by hand"; return 0; }; done
    ok "bond $name exists over ${have// /, } ($(cut -d" " -f1 "/sys/class/net/$name/bonding/mode" 2>/dev/null))"; return 0
  fi
  ip link show "$name" >/dev/null 2>&1 && { conflict "$name exists and is not a bond"; return 0; }
  for p in "${arr[@]}"; do
    ip link show "$p" >/dev/null 2>&1 || { later "$p is not on this host"; return 0; }
    net_guard "$p" "$roll" || return 0
    [[ -n $(ip -o link show "$p" | sed -n "s/.* master \([^ ]*\) .*/\1/p") ]] && { conflict "$p is in $(ip -o link show "$p" | sed -n "s/.* master \([^ ]*\) .*/\1/p") already"; return 0; }
  done
  b=$(nw_backend)
  [[ $b == none ]] && { nw_none; return 0; }
  act "create bond $name ($mode) over ${arr[*]}$([[ -n $address ]] && echo " at $address")$([[ -n $dhcp ]] && echo ", by DHCP"), with $(nw_said "$b")" || return 0
  fw_tool
  case $b in
    netplan) local f=$NP_DIR/90-storageforge-bond-$(nw_tag "$name").yaml text q=() other
             for p in "${arr[@]}"; do
               other=$(np_other "\"$p\"" || np_other "$p:") || true
               if [[ -n $other ]] && grep -A3 -E "^[[:space:]]*\"?$p\"?:" "$other" | grep -q "addresses"; then nw_other "addresses of $p" "$other"; return 0; fi
               q+=("\"$p\"")
             done
             text=$(printf "network:\n  version: 2\n  ethernets:\n"; for p in "${arr[@]}"; do printf "    \"%s\":\n      dhcp4: false\n      dhcp6: false\n" "$p"; done
                    printf "  bonds:\n    \"%s\":\n      interfaces: [%s]\n      parameters:\n        mode: \"%s\"\n        mii-monitor-interval: 100\n" "$name" "$(IFS=,; echo "${q[*]}" | sed "s/,/, /g")" "$mode"
                    [[ -n $address ]] && printf "      addresses: [\"%s\"]\n" "$address"; [[ -n $dhcp ]] && printf "      dhcp4: true\n"; true)
             np_write "$f" "$text" "$roll" || return 0 ;;
    nm) local undo="nmcli connection delete sf-$name"
        for p in "${arr[@]}"; do undo+="; nmcli connection delete sf-$name-$p; nmcli device connect $p"; done
        fw_arm "$roll" "$undo"
        try nmcli connection add type bond ifname "$name" con-name "sf-$name" bond.options "mode=$mode,miimon=100" \
          ipv4.method "$([[ -n $dhcp ]] && echo auto || { [[ -n $address ]] && echo manual || echo disabled; })" ${address:+ipv4.addresses "$address"} ipv6.method disabled || return 0
        for p in "${arr[@]}"; do try nmcli connection add type bond-slave ifname "$p" master "$name" con-name "sf-$name-$p" || return 0; done
        try nmcli connection up "sf-$name" || return 0
        for p in "${arr[@]}"; do try nmcli connection up "sf-$name-$p" || return 0; done ;;
    networkd) local d=/etc/systemd/network
        fw_arm "$roll" "rm -f $d/05-sf-$name.netdev $d/05-sf-$name.network $d/05-sf-$name-*.network; networkctl reload; ip link del $name; for p in ${arr[*]}; do networkctl reconfigure \$p; done"
        printf "[NetDev]\nName=%s\nKind=bond\n[Bond]\nMode=%s\nMIIMonitorSec=100ms\n" "$name" "$mode" >"$d/05-sf-$name.netdev"
        { printf "[Match]\nName=%s\n[Network]\nLinkLocalAddressing=no\n" "$name"; [[ -n $address ]] && printf "Address=%s\n" "$address"; printf "DHCP=%s\n" "$([[ -n $dhcp ]] && echo ipv4 || echo no)"; } >"$d/05-sf-$name.network"
        for p in "${arr[@]}"; do printf "[Match]\nName=%s\n[Network]\nBond=%s\n" "$p" "$name" >"$d/05-sf-$name-$p.network"; done
        durable "$d"; networkctl reload || true
        for p in "${arr[@]}"; do networkctl reconfigure "$p" 2>/dev/null || true; done ;;
    ifupdown) command -v ifenslave >/dev/null || [[ -e /etc/network/if-pre-up.d/ifenslave ]] || { conflict "ifupdown makes bonds with ifenslave, which is not installed (package ifenslave)"; return 0; }
        for p in "${arr[@]}"; do if other=$(if_other "^[[:space:]]*iface[[:space:]]+${p}[[:space:]]"); then nw_other "$p" "$other"; return 0; fi; done
        if_file "sf-bond-$(nw_tag "$name")" "$(printf "auto %s\niface %s inet %s\n" "$name" "$name" "$([[ -n $dhcp ]] && echo dhcp || { [[ -n $address ]] && echo static || echo manual; })"
            [[ -n $address ]] && printf "    address %s\n" "$address"; printf "    bond-slaves %s\n    bond-mode %s\n    bond-miimon 100\n" "${arr[*]}" "$mode")" "$roll" "ifdown $name" || return 0
        try ifup "$name" || return 0 ;;
  esac
  ok "bond $name"
}
"""


# ── checks against the index ────────────────────────────────────────
def configured(conn, h) -> dict:
    """What the host's network files say (netfacts, read at the last scan): {'manager', 'interfaces': {name: {...}}}, or {}."""
    return (_net(conn, h) or {}).get('config') or {}


def _say_config(conn, h, iface, say):
    cfg = configured(conn, h)
    if not cfg:
        return None
    mine = (cfg.get('interfaces') or {}).get(iface)
    if cfg.get('manager') in (None, 'none'):
        say('crit', f'{h["name"]} has no netplan, NetworkManager, systemd-networkd or ifupdown at the last scan: nothing would keep this across a reboot')
    elif mine:
        say('note', f'{iface} is set up in {mine.get("source") or cfg["manager"]} ({cfg["manager"]}); the step writes a file of its own beside it')
    return mine


def _ip(text):
    try:
        return ipaddress.ip_interface(text) if '/' in text else ipaddress.ip_address(text)
    except ValueError:
        return None


def _check_net_address(conn, c, h, p, say):
    a = _ip(p['address'])
    if not a or '/' not in p['address']:
        say('crit', f'{p["address"]} is not an address with its prefix, such as 10.0.5.2/24')
        return
    iface = _check_iface(conn, h, p['iface'], say)
    mine = _say_config(conn, h, p['iface'], say)
    live = bool(iface) and any(x.get('ip') == str(a.ip) for x in iface.get('addresses') or [])
    if p['state'] == 'absent':
        if iface and not live and not (mine and p['address'] in mine.get('addresses', [])):
            say('ok', f'{p["iface"]} does not have {p["address"]}: nothing to do')
            return
        if str(a.ip) == h.get('ssh_host'):
            say('crit' if not p['rollback'] else 'warn', f'StorageForge reaches {h["name"]} on {a.ip}' + (': the rollback timer puts it back if the path is lost' if p['rollback'] else ': stage a rollback timer'))
        if mine and p['address'] in mine.get('addresses', []):
            say('warn', f'{mine.get("source")} sets {p["address"]}: the script takes off only an address a step of StorageForge set, and says so for this one')
        return
    if live:
        say('ok', f'{p["iface"]} has {p["address"]} already' + ('' if mine and p['address'] in mine.get('addresses', []) else ': the script checks it is kept across a reboot'))
        return
    _address_clash(conn, h, p['address'], say)


def _check_net_route(conn, c, h, p, say):
    dst, via = _ip(p['dst']), _ip(p['via'])
    if not dst or '/' not in p['dst']:
        say('crit', f'{p["dst"]} is not a network such as 10.9.0.0/16 (0.0.0.0/0 for the default route)')
        return
    if not via or '/' in p['via']:
        say('crit', f'{p["via"]} is not a gateway address')
        return
    if dst.version != via.version:
        say('crit', 'the network and the gateway are not of the same IP version')
        return
    if p['iface']:
        _check_iface(conn, h, p['iface'], say)
        _say_config(conn, h, p['iface'], say)
    net = _net(conn, h)
    for r in (net or {}).get('routes') or []:
        if (r.get('dst') == str(dst.network) or (r.get('dst') == 'default' and dst.network.prefixlen == 0)) and r.get('via') == str(via) and r.get('family') == dst.version:
            if p['state'] != 'absent':
                say('ok', f'the route to {p["dst"]} via {p["via"]} is there already: the script checks it is kept across a reboot')
            break
    else:
        if p['state'] == 'absent' and net:
            say('ok', f'there is no route to {p["dst"]} via {p["via"]} at the last scan')
    ctrl = _controller_ips(conn, h)
    hit = [x for x in ctrl if _ip(x) and _ip(x).version == dst.version and _ip(x) in dst.network]
    if hit and not p['rollback']:
        say('crit', f'StorageForge comes in from {", ".join(hit)}, inside {p["dst"]}: stage a rollback timer, or a wrong gateway cuts the host off')
    elif hit:
        say('warn', f'StorageForge comes in from {", ".join(hit)}, inside {p["dst"]}: the rollback timer puts the routes back if the path is lost')


def _check_net_dhcp(conn, c, h, p, say):
    iface = _check_iface(conn, h, p['iface'], say)
    _say_config(conn, h, p['iface'], say)
    _check_ssh_path(conn, h, iface, p['rollback'], say)
    if p['state'] == 'off' and iface and not any(x.get('scope') == 'global' for x in iface.get('addresses') or []):
        say('warn', f'{p["iface"]} has no other address at the last scan: with DHCP off it has none')
    elif p['state'] == 'on':
        say('note', 'the address DHCP gives may differ from the one it has now')


def _check_net_bond(conn, c, h, p, say):
    net = _net(conn, h)
    names = {i['name']: i for i in (net or {}).get('interfaces') or []}
    ports = [x for x in (p['ports'] or '').split(',') if x]
    if not ports:
        say('crit', 'a bond needs at least one interface')
    for port in ports:
        if not IFACE.fullmatch(port):
            say('crit', f'{port} is not an interface name')
            return
    if p['name'] in names:
        if names[p['name']].get('kind') == 'bond':
            say('ok', f'bond {p["name"]} exists already')
        else:
            say('crit', f'{p["name"]} exists and is not a bond')
        return
    if p['address']:
        _, bad = _nets(p['address'])
        if bad or '/' not in p['address']:
            say('crit', f'not an address with its prefix: {p["address"]}')
        else:
            _address_clash(conn, h, p['address'], say)
    if p['address'] and p['dhcp']:
        say('warn', 'both an address and DHCP: the bond gets both')
    for port in ports:
        iface = _check_iface(conn, h, port, say)
        if iface and iface.get('master'):
            say('crit', f'{port} is in {iface["master"]} already')
        _check_ssh_path(conn, h, iface, p['rollback'], say)
        if iface and any(x.get('scope') == 'global' for x in iface.get('addresses') or []) and not (p['address'] or p['dhcp']):
            say('warn', f'{port} has an address and the bond is given none: it is lost')
    if p['mode'] == '802.3ad':
        say('note', '802.3ad needs the switch ports set up as one LACP group, or the bond passes no traffic')


def _ansible(fn: str, args: tuple):
    def render(t):
        q = shlex.quote
        p = t['params']
        call = ' '.join(q(str(p.get(a) if not isinstance(p.get(a), bool) else ('1' if p[a] else ''))) for a in args)
        helpers = ''.join(re.search(rf'^{name}\(\) \{{.*?^\}}$', INFRA_BASH, re.M | re.S)[0] + '\n' for name in ('net_is_ssh_path', 'net_guard'))
        head = ('set -u; APPLY=1; STAMP=$(date +%Y%m%d-%H%M%S); ok() { echo "ok: $*"; }; missing() { echo "missing: $*"; }; conflict() { echo "conflict: $*" >&2; exit 1; }\n'
                'info() { echo "$*"; }; act() { echo "changed: $*"; }; try() { "$@" || { conflict "failed: $*"; return 1; }; }; later() { conflict "$*"; }; durable() { sync; }\n'
                'fw_arm() { :; }; fw_tool() { :; }\n')
        return {'name': changes.title(t), 'ansible.builtin.shell': {'cmd': head + helpers + BASH + f'\n{fn} {call}\n', 'executable': '/bin/bash'},
                'register': 'sf_out', 'changed_when': "'changed' in sf_out.stdout"}
    return render


def _reg(kind, spec, args, title_of, check_of):
    changes.register(kind, spec, args, title_of, check_of, _ansible('t_' + kind.replace('-', '_'), args))


_reg('net-bond', {'group': 'Network', 'label': 'Create a bond', 'fields': [
    F('name', 'iface', 'Bond', required=True, placeholder='bond0'), F('ports', 'word', 'Interfaces to put in it', required=True, placeholder='eth1,eth2'),
    F('mode', 'choice', 'Mode', options=BOND_MODES, default='active-backup'), F('address', 'cidr', 'Address', placeholder='10.0.5.2/24'),
    F('dhcp', 'bool', 'Address by DHCP'), ROLLBACK],
    'help': 'With netplan, NetworkManager, systemd-networkd or ifupdown, whichever the host uses. Moving the interface StorageForge comes in on needs a rollback timer.'},
    ('name', 'ports', 'mode', 'address', 'dhcp', 'rollback'), lambda p: f'Create bond {p["name"]} ({p["mode"]}) over {p["ports"]}', _check_net_bond)

_reg('net-address', {'group': 'Network', 'label': 'Add or remove an address', 'fields': [
    F('iface', 'iface', 'Interface', required=True), F('address', 'cidr', 'Address with its prefix', required=True, placeholder='10.0.5.2/24'), STATE, ROLLBACK],
    'help': 'Kept in a file or setting of its own, in whatever the host uses. An address another file sets is not taken off: the step names the file.'},
    ('iface', 'address', 'state', 'rollback'), lambda p: f'{"Take" if p["state"] == "absent" else "Give"} {p["iface"]} {p["address"]}' + (' off' if p['state'] == 'absent' else ''),
    _check_net_address)

_reg('net-route', {'group': 'Network', 'label': 'Add or remove a route', 'fields': [
    F('dst', 'cidr', 'To network (0.0.0.0/0 for the default route)', required=True, placeholder='10.9.0.0/16'), F('via', 'cidr', 'Via gateway', required=True, placeholder='10.0.5.1'),
    F('iface', 'iface', 'On interface (the one that reaches the gateway if empty)'), F('metric', 'number', 'Metric'), STATE, ROLLBACK],
    'help': 'A route that covers where StorageForge comes in from needs a rollback timer: a wrong gateway would cut the host off.'},
    ('dst', 'via', 'iface', 'metric', 'state', 'rollback'),
    lambda p: f'{"Remove the route" if p["state"] == "absent" else "Route"} {p["dst"]} via {p["via"]}' + (f' on {p["iface"]}' if p['iface'] else ''), _check_net_route)

_reg('net-dhcp', {'group': 'Network', 'label': 'DHCP on an interface', 'fields': [
    F('iface', 'iface', 'Interface', required=True), F('family', 'choice', 'For', options=['ipv4', 'ipv6', 'both'], default='ipv4'),
    F('state', 'choice', 'On or off', options=['on', 'off'], default='on'), ROLLBACK],
    'help': 'The address can change, so the interface StorageForge comes in on needs a rollback timer. With systemd-networkd, on for one family sets DHCP= to that family only.'},
    ('iface', 'family', 'state', 'rollback'), lambda p: f'DHCP {p["state"]} for {p["family"]} on {p["iface"]}', _check_net_dhcp)

changes.EXTRA_BASH.append(BASH)
