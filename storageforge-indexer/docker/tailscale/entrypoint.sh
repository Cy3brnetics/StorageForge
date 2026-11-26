#!/bin/sh
# The stack's own place on a tailnet (docker-compose.yml, service tailscale). It shares the StorageForge container's network,
# as the remote-node tunnel does, so:
#   - the web UI is served on the tailnet at https://<hostname>.<tailnet>.ts.net (tailscale serve, a tailnet certificate),
#     passed to the proxy like any browser, so the proxy's limits and headers still apply;
#   - the server reaches tailnet addresses (100.64.0.0/10) over the tailnet, and everything else (the LAN) the way it always
#     did: no subnet routes, no exit node and no tailnet DNS are taken, so a LAN host stays on the LAN and service names resolve;
#   - from the tailnet, only the web UI comes in: the server's own plain-HTTP port and anything else listening beside it are
#     dropped on tailscale0.
# With no key and no tailnet state from before, it joins nothing and waits. The key: STORAGEFORGE_TS_AUTHKEY, or a file
# mounted at /run/ts-authkey (STORAGEFORGE_TS_AUTHKEY_FILE in docker-compose.yml). It is only needed the first time: the node
# is kept in the sf-tailscale volume. To leave the tailnet, remove the node in the admin console and that volume.
set -eu

STATE=${TS_STATE_DIR:-/var/lib/tailscale}
SOCK=${TS_SOCKET:-/tmp/tailscaled.sock}
NAME=${STORAGEFORGE_TS_HOSTNAME:-storageforge}
UPSTREAM=${STORAGEFORGE_TS_UPSTREAM:-https+insecure://proxy:8443}   # the proxy's certificate is self-signed: the tailnet one is in front
KEYFILE=${TS_AUTHKEY_PATH:-/run/ts-authkey}

say() { echo "tailscale: $*"; }
idle() { while :; do sleep 3600; done; }

key=''
if [ -r "$KEYFILE" ] && [ -s "$KEYFILE" ]; then
  key=$(tr -d ' \t\r\n' < "$KEYFILE")
fi
[ -n "$key" ] || key=$(printf '%s' "${STORAGEFORGE_TS_AUTHKEY:-}" | tr -d ' \t\r\n')

if [ -z "$key" ] && [ ! -s "$STATE/tailscaled.state" ]; then
  say "no key (STORAGEFORGE_TS_AUTHKEY or STORAGEFORGE_TS_AUTHKEY_FILE): not joining a tailnet"
  idle
fi
case $NAME in ''|-*|*[!A-Za-z0-9-]*) say "not a host name: $NAME"; exit 2 ;; esac

# A tun device puts tailscale0 in this network, which is what lets the server reach tailnet hosts. Without one the UI is still
# served (tailscaled answers it itself), but connections out to tailnet addresses would go the LAN way and fail.
tun=tailscale0
if [ ! -c /dev/net/tun ]; then
  mkdir -p /dev/net 2>/dev/null || :
  mknod /dev/net/tun c 10 200 2>/dev/null || :
fi
if [ ! -c /dev/net/tun ]; then
  tun=userspace-networking
  say "no /dev/net/tun here: the web UI is served on the tailnet, but this server cannot reach tailnet hosts through it"
fi

TS_DEBUG_FIREWALL_MODE=nftables tailscaled --statedir="$STATE" --socket="$SOCK" --tun="$tun" &   # not legacy iptables, whatever the host runs
daemon=$!
trap 'kill "$daemon" 2>/dev/null' TERM INT
i=0
until [ -S "$SOCK" ]; do
  i=$((i + 1))
  [ "$i" -le 30 ] || { say "tailscaled did not start"; exit 1; }
  kill -0 "$daemon" 2>/dev/null || { say "tailscaled exited"; exit 1; }
  sleep 1
done

if [ "$tun" = tailscale0 ]; then
  # Before anything can arrive: from the tailnet, replies to what the server opened, and the web UI. Nothing else.
  # One nftables table for IPv4 and IPv6, in this (the server's) network only. If it cannot be put in place, the server is
  # not put on the tailnet at all: its plain-HTTP port would be open there.
  if ! nft -f - <<'SF_NFT'
add table inet storageforge_tailnet
flush table inet storageforge_tailnet
table inet storageforge_tailnet {
  chain input {
    type filter hook input priority -10; policy accept;
    iifname "tailscale0" ct state established,related accept
    iifname "tailscale0" tcp dport 443 accept
    iifname "tailscale0" drop
  }
}
SF_NFT
  then
    say "could not put the firewall table on tailscale0 (nft failed, see above): not joining the tailnet, so the server's own ports stay off it"
    kill "$daemon" 2>/dev/null || :
    exit 1
  fi
fi

set -- --hostname="$NAME" --accept-dns=false --accept-routes=false --netfilter-mode=off
[ -z "$key" ] || set -- "$@" --authkey="$key"
if ! tailscale --socket="$SOCK" up "$@"; then
  say "could not join the tailnet: check the key (it may have expired or been used already)"
  kill "$daemon" 2>/dev/null || :
  exit 1
fi
key=''
say "joined as $NAME ($(tailscale --socket="$SOCK" ip -4 2>/dev/null || echo 'no IPv4 yet'))"

if tailscale --socket="$SOCK" serve --bg --https=443 "$UPSTREAM"; then
  say "web UI on the tailnet: https://$NAME.<your tailnet>.ts.net"
else
  say "the web UI is not served on the tailnet: turn on MagicDNS and HTTPS certificates in the Tailscale admin console, then restart this container"
fi

wait "$daemon"
