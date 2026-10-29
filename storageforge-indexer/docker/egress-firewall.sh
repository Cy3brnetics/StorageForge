#!/bin/sh
# Limit what the StorageForge containers can reach: SSH to your hosts and the ports alerts use, nothing else.
# Run as root on the Docker host, after `docker compose up` (the sf0 bridge must exist):
#   sudo ./docker/egress-firewall.sh                 # allow tcp 22 and 443 out of sf0
#   sudo STORAGEFORGE_EGRESS_PORTS="22 2222 443 2586" ./docker/egress-firewall.sh
#   sudo ./docker/egress-firewall.sh --remove
# Rules live in their own chain (SF-EGRESS) hooked into Docker's DOCKER-USER chain, which Docker never flushes.
# They are not persistent: re-run at boot (a systemd unit or your firewall's hook) or save them with your distro's tool.
# Traffic inside the compose network (proxy -> app) and replies to browsers are not affected.
set -eu
BRIDGE=${STORAGEFORGE_BRIDGE:-sf0}
PORTS=${STORAGEFORGE_EGRESS_PORTS:-22 443}
CHAIN=SF-EGRESS

[ "$(id -u)" -eq 0 ] || { echo "run as root (sudo $0)" >&2; exit 1; }
for p in $PORTS; do
  case $p in *[!0-9]*|'') echo "not a port: $p" >&2; exit 2 ;; esac
done

apply() {   # $1 = iptables or ip6tables
  ipt=$1
  command -v "$ipt" >/dev/null 2>&1 || return 0
  "$ipt" -n -L DOCKER-USER >/dev/null 2>&1 || { echo "$ipt: no DOCKER-USER chain (is Docker running with $ipt?)"; return 0; }
  while "$ipt" -D DOCKER-USER -i "$BRIDGE" ! -o "$BRIDGE" -j "$CHAIN" 2>/dev/null; do :; done
  "$ipt" -F "$CHAIN" 2>/dev/null || true
  "$ipt" -X "$CHAIN" 2>/dev/null || true
  [ "$MODE" = remove ] && { echo "$ipt: removed"; return 0; }
  "$ipt" -N "$CHAIN"
  "$ipt" -A "$CHAIN" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
  "$ipt" -A "$CHAIN" -p udp --dport 53 -j RETURN      # DNS to the host's resolver
  "$ipt" -A "$CHAIN" -p tcp --dport 53 -j RETURN
  for p in $PORTS; do "$ipt" -A "$CHAIN" -p tcp --dport "$p" -j RETURN; done
  "$ipt" -A "$CHAIN" -j REJECT
  "$ipt" -I DOCKER-USER -i "$BRIDGE" ! -o "$BRIDGE" -j "$CHAIN"
  echo "$ipt: $BRIDGE may open tcp ${PORTS} (and DNS); everything else out of it is rejected"
}

MODE=apply
[ "${1:-}" = --remove ] && MODE=remove
apply iptables
apply ip6tables
