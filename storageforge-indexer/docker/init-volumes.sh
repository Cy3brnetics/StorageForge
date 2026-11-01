#!/bin/sh
# One-shot compose service (init-secrets): fills the secret volumes on first deploy, so a stack manager with no shell
# on the host can deploy the repo as it is. Runs at deploy time, not build time: a secret made in the Dockerfile would
# be in the image's layers, and the same in every container made from it.
#   /secrets/app    uid 10001: vault_secret, session_secret, tls_cert
#   /secrets/proxy  uid 101:   tls_cert, tls_key
# Existing files are never overwritten. A missing one comes from /seed (./secrets, made by docker/init-secrets.sh) when
# it is there, and is generated otherwise.
set -eu
umask 077
APP=/secrets/app PROXY=/secrets/proxy SEED=/seed

log() { printf 'init-secrets: %s\n' "$*" >&2; }

# only with docker-compose.remote.yml: what the app writes and the tunnel reads, and what the tunnel keeps and shows the app
if [ -d /secrets/tunnel-keys ]; then
  chown 10001:10001 /secrets/tunnel-keys; chmod 0755 /secrets/tunnel-keys
  chown -R 10002:10002 /secrets/tunnel-host; chmod 0755 /secrets/tunnel-host
fi
new_secret() { openssl rand -base64 48 | tr -d '\n'; }

if [ ! -s "$APP/vault_secret" ]; then
  if [ -s "$SEED/vault_secret" ]; then
    cp "$SEED/vault_secret" "$APP/vault_secret"; log "vault_secret copied from ./secrets"
  elif [ -e /app/data/index.db ]; then
    # a new secret could not unlock this vault, and would hide that the real one is what is missing
    log "error: sf-data has a database but no vault secret was found. Put the original in ./secrets/vault_secret"; exit 64
  else
    new_secret > "$APP/vault_secret"; log "vault_secret created. Back it up: without it the vault cannot be decrypted"
  fi
fi
# After a reset, ./secrets/vault_secret is the old client's: their keys, for anyone with their archive
if [ -e "$APP/reset_at" ] && [ -s "$SEED/vault_secret" ] && [ "$(cat "$SEED/vault_secret")" != "$(cat "$APP/vault_secret")" ]; then
  log "error: ./secrets/vault_secret is the secret from before the reset. Delete it (the archive has a copy), then start again"; exit 64
fi
if [ ! -s "$APP/session_secret" ]; then
  if [ -s "$SEED/session_secret" ]; then cp "$SEED/session_secret" "$APP/session_secret"
  else new_secret > "$APP/session_secret"; fi
fi

if [ ! -s "$PROXY/tls_cert" ] || [ ! -s "$PROXY/tls_key" ]; then
  if [ -s "$SEED/tls_cert" ] && [ -s "$SEED/tls_key" ]; then
    cp "$SEED/tls_cert" "$SEED/tls_key" "$PROXY/"; log "tls_cert copied from ./secrets"
  else
    short=$(hostname -s 2>/dev/null || hostname)          # the host's: this service runs on the host network
    sans="DNS:localhost,IP:127.0.0.1,IP:::1,DNS:$short,DNS:$short.local,DNS:$short.lan"
    # the address of the default route; connecting a UDP socket sends nothing
    addr=$(python -c 'import socket; s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.connect(("192.0.2.1", 9)); print(s.getsockname()[0])' 2>/dev/null || true)
    for n in $addr ${STORAGEFORGE_TLS_NAMES:-}; do
      case $n in
        *:*) sans="$sans,IP:$n" ;;                     # IPv6
        *[!0-9.]*) sans="$sans,DNS:$n" ;;              # a name
        *) sans="$sans,IP:$n" ;;                       # IPv4
      esac
    done
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 825 \
      -subj "/CN=StorageForge on $short" -addext "subjectAltName=$sans" \
      -addext "basicConstraints=critical,CA:FALSE" -addext "extendedKeyUsage=serverAuth" \
      -keyout "$PROXY/tls_key" -out "$PROXY/tls_cert" 2>/dev/null
    log "tls_cert created for: $(echo "$sans" | sed 's/DNS://g; s/IP://g; s/,/, /g')"
    log "add names with STORAGEFORGE_TLS_NAMES, delete the volume's tls_cert and deploy again"
  fi
  log "$(openssl x509 -in "$PROXY/tls_cert" -noout -fingerprint -sha256)"
fi
cp "$PROXY/tls_cert" "$APP/tls_cert"                      # the public half only; the key stays with the proxy

chown -R 10001:10001 "$APP"
chown -R 101:101 "$PROXY"
chmod 0500 "$APP" "$PROXY"
chmod 0400 "$APP"/* "$PROXY"/*
