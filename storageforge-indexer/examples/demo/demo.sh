#!/bin/sh
# End-to-end demo: vault-generated key → SSH target → scan → graph → UI.
set -eu
cd "$(dirname "$0")/../.."
C="docker compose -f docker-compose.yml -f examples/demo/compose.demo.yml"
./docker/init-secrets.sh >/dev/null
$C up -d --build storageforge
SF="$C exec -T storageforge storageforge-index"
$SF vault pubkey --name demo >/dev/null 2>&1 || $SF vault generate --name demo >/dev/null
export DEMO_AUTHORIZED_KEY="$($SF vault pubkey --name demo)"
$C up -d --build target
$SF vault bindings | grep -q ' target ' || $SF vault bind --key demo --host target --user scan --actions scan,checksum
$SF graph import --blueprint /dev/stdin < examples/atlas/blueprint.json   # read-only rootfs: pipe, don't copy
sleep 2
$SF scan --host target --checksum --include-fstype overlay   # the demo target is a container
$SF search "*.cr2" --size-gt 1MB || true
$SF audit tail --limit 8
if ! $SF user list | grep -q '^demo '; then
  DEMO_PASSWORD=$(openssl rand -base64 18)
  printf '%s\n' "$DEMO_PASSWORD" | $SF user add demo >/dev/null
  echo "UI: http://127.0.0.1:${STORAGEFORGE_HTTP_PORT:-8080}  user: demo  password: $DEMO_PASSWORD"
else
  echo "UI: http://127.0.0.1:${STORAGEFORGE_HTTP_PORT:-8080}  user: demo (reset with: $SF user passwd demo)"
fi
