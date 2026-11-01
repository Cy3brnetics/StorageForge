#!/bin/sh
# The tunnel container: makes its host key once, runs sshd, and drops every session when a node is revoked. Removing a
# key stops new logins only; a tunnel already up would stay up. Reconnecting costs the other nodes a few seconds.
set -eu
umask 022
KEY=/var/lib/sf-tunnel/ssh_host_ed25519_key
GEN=/run/sf-tunnel-keys/generation
[ -s "$KEY" ] || ssh-keygen -q -t ed25519 -N '' -C storageforge-tunnel -f "$KEY"
start() { /usr/sbin/sshd -D -e -f /etc/ssh/sshd_config & listener=$!; }
stop_all() {   # by number: this sh has no kill -1
  for p in /proc/[0-9]*; do
    p=${p#/proc/}
    [ "$p" = $$ ] || kill -s "$1" "$p" 2>/dev/null || true
  done
}
seen=$(cat "$GEN" 2>/dev/null || echo 0)
start
while sleep 5; do
  now=$(cat "$GEN" 2>/dev/null || echo 0)
  if [ "$now" != "$seen" ]; then
    seen=$now
    stop_all TERM
    sleep 1
    stop_all KILL
    sleep 1
    start
  elif ! kill -0 "$listener" 2>/dev/null; then
    start
  fi
done
