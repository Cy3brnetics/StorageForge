#!/bin/sh
# Limit what the StorageForge containers can reach: SSH to your hosts and the ports alerts use, nothing else.
# Run as root on the Docker host, after `docker compose up` (the sf0 bridge must exist):
#   sudo ./docker/egress-firewall.sh                 # allow tcp 22 and 443 out of sf0
#   sudo STORAGEFORGE_EGRESS_PORTS="22 2222 443 2586" ./docker/egress-firewall.sh
#   sudo STORAGEFORGE_BRIDGE=sfdemo0 ./docker/egress-firewall.sh   # another bridge gets its own rules
#   sudo ./docker/egress-firewall.sh --remove
# Rules live in a chain per bridge (SF-EGRESS-<bridge>), hooked into Docker's DOCKER-USER chain (which Docker never
# flushes) for traffic to other machines, and into INPUT for traffic to the Docker host itself (its LAN, VPN and
# bridge addresses), which DOCKER-USER never sees.
# They are not persistent: re-run at boot (a systemd unit or your firewall's hook) or save them with your distro's tool.
# Traffic inside the compose network (proxy -> app) and replies to browsers are not affected.
# Re-running builds the new rules in a second chain and hooks it in before the old one is unhooked, so a bridge is
# never left unfiltered, not even when something fails halfway.
set -eu
BRIDGE=${STORAGEFORGE_BRIDGE:-sf0}
PORTS=${STORAGEFORGE_EGRESS_PORTS:-22 443}
LEGACY=SF-EGRESS        # the one chain every bridge shared before 2026-10-29

[ "$(id -u)" -eq 0 ] || { echo "run as root (sudo $0)" >&2; exit 1; }
case $BRIDGE in ''|-*|*[!A-Za-z0-9_.-]*) echo "not a bridge name: $BRIDGE" >&2; exit 2 ;; esac
[ "${#BRIDGE}" -le 15 ] || { echo "not a bridge name (15 characters at most): $BRIDGE" >&2; exit 2; }
for p in $PORTS; do     # all checked before any rule changes
  case $p in *[!0-9]*|'') echo "not a port: $p" >&2; exit 2 ;; esac
  [ "$p" -ge 1 ] && [ "$p" -le 65535 ] || { echo "not a port: $p" >&2; exit 2; }
done

hook() {   # -C|-I|-D chain: the two jumps into it, out to other machines and to this host
  op=$1
  if [ "$op" = -D ]; then
    while "$ipt" -D DOCKER-USER -i "$BRIDGE" ! -o "$BRIDGE" -j "$2" 2>/dev/null; do :; done
    while "$ipt" -D INPUT -i "$BRIDGE" -j "$2" 2>/dev/null; do :; done
  elif [ "$op" = -C ]; then
    "$ipt" -C DOCKER-USER -i "$BRIDGE" ! -o "$BRIDGE" -j "$2" 2>/dev/null
  else
    "$ipt" -I INPUT -i "$BRIDGE" -j "$2"
    "$ipt" -I DOCKER-USER -i "$BRIDGE" ! -o "$BRIDGE" -j "$2"
  fi
}

drop() {   # chain: flushed and deleted, unless a jump to it is left (the legacy chain, used by another bridge)
  "$ipt" -S 2>/dev/null | grep -q -- " -j $1\$" && return 0
  "$ipt" -F "$1" 2>/dev/null || true
  "$ipt" -X "$1" 2>/dev/null || true
}

apply() {   # $1 = iptables or ip6tables
  ipt=$1
  command -v "$ipt" >/dev/null 2>&1 || return 0
  "$ipt" -n -L DOCKER-USER >/dev/null 2>&1 || { echo "$ipt: no DOCKER-USER chain (is Docker running with $ipt?)"; return 0; }
  a=SF-EGRESS-$BRIDGE b=SF-EGRESS-$BRIDGE-b
  if hook -C "$a"; then new=$b old=$a; else new=$a old=$b; fi
  if [ "$MODE" = apply ]; then
    "$ipt" -N "$new" 2>/dev/null || "$ipt" -F "$new"      # nothing jumps to it yet
    "$ipt" -A "$new" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
    "$ipt" -A "$new" -p udp --dport 53 -j RETURN      # DNS to the host's resolver
    "$ipt" -A "$new" -p tcp --dport 53 -j RETURN
    # IPv6 needs ICMPv6 to the host (neighbor discovery finds the gateway); IPv4's ARP never passes iptables
    [ "$ipt" = ip6tables ] && "$ipt" -A "$new" -p ipv6-icmp -j RETURN
    for p in $PORTS; do "$ipt" -A "$new" -p tcp --dport "$p" -j RETURN; done
    "$ipt" -A "$new" -j REJECT
    hook -I "$new"
  else
    hook -D "$new"
    drop "$new"
  fi
  hook -D "$old"
  hook -D "$LEGACY"
  drop "$old"
  drop "$LEGACY"
  if [ "$MODE" = remove ]; then echo "$ipt: removed for $BRIDGE"; return 0; fi
  echo "$ipt: $BRIDGE may open tcp ${PORTS} (and DNS), to other machines and to this host; everything else is rejected"
}

MODE=apply
[ "${1:-}" = --remove ] && MODE=remove
apply iptables
apply ip6tables
