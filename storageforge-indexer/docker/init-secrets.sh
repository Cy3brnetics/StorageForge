#!/bin/sh
# Create ./secrets/vault_secret, ./secrets/session_secret and a self-signed TLS certificate for docker compose.
# The directory is 0700 and the files 0640 with your group: other host users cannot read them even if the directory's
# mode is loosened. The containers (uid 10001, and 101 for nginx) read them through that group (compose group_add,
# STORAGEFORGE_SECRETS_GID, written to .env when it is not 1000). Existing files are never overwritten.
# The certificate names this machine's hostname and LAN addresses; add more with STORAGEFORGE_TLS_NAMES="nas.home 10.0.0.9".
# Delete secrets/tls_cert and secrets/tls_key and run this again to make a new one.
set -eu
cd "$(dirname "$0")/.."
umask 077
mkdir -p secrets keys
chmod 0700 secrets
# keys/ is mounted for the one-shot key import: the container (uid 10001) lists it through your group. Key files in it
# need group read too (chmod 0640 keys/*); ssh-keygen makes them 0600.
chmod 0750 keys
[ -s secrets/vault_secret ] || { openssl rand -base64 48 | tr -d '\n' > secrets/vault_secret; echo "created secrets/vault_secret"; }
[ -s secrets/session_secret ] || { openssl rand -base64 48 | tr -d '\n' > secrets/session_secret; echo "created secrets/session_secret"; }
if [ ! -s secrets/tls_cert ] || [ ! -s secrets/tls_key ]; then
  short=$(hostname -s 2>/dev/null || hostname)
  sans="DNS:localhost,IP:127.0.0.1,IP:::1,DNS:$short,DNS:$short.local,DNS:$short.lan"
  full=$(hostname -f 2>/dev/null || true)
  case $full in *.*) sans="$sans,DNS:$full" ;; esac
  # this machine's addresses, without Docker's own bridges (docker0, br-<id>, sf0, sf1...)
  addrs=$(ip -o addr show scope global 2>/dev/null | awk '$2 !~ /^(docker|br-|veth)/ && $2 !~ /^sf[0-9]+$/ { sub(/\/.*/, "", $4); print $4 }')
  [ -n "$addrs" ] || addrs=$(hostname -I 2>/dev/null) || addrs=""
  for n in $addrs ${STORAGEFORGE_TLS_NAMES:-}; do
    case $n in
      *:*) sans="$sans,IP:$n" ;;                     # IPv6
      *[!0-9.]*) sans="$sans,DNS:$n" ;;              # a name
      *) sans="$sans,IP:$n" ;;                       # IPv4
    esac
  done
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 825 \
    -subj "/CN=StorageForge on $short" -addext "subjectAltName=$sans" \
    -addext "basicConstraints=critical,CA:FALSE" -addext "extendedKeyUsage=serverAuth" \
    -keyout secrets/tls_key -out secrets/tls_cert 2>/dev/null
  echo "created secrets/tls_cert for: $(echo "$sans" | sed 's/DNS://g; s/IP://g; s/,/, /g')"
  echo "  browsers warn once; compare the fingerprint before accepting it, or import secrets/tls_cert as trusted:"
  openssl x509 -in secrets/tls_cert -noout -fingerprint -sha256 | sed 's/^/  /'
fi
chmod 0640 secrets/vault_secret secrets/session_secret secrets/tls_cert secrets/tls_key
gid=$(id -g)
if [ "$gid" != 1000 ] && ! grep -q '^STORAGEFORGE_SECRETS_GID=' .env 2>/dev/null; then
  echo "STORAGEFORGE_SECRETS_GID=$gid" >>.env; echo "wrote STORAGEFORGE_SECRETS_GID=$gid to .env (the group that can read secrets/)"
fi
echo "Back up secrets/vault_secret. Without it the vault cannot be decrypted."
echo "After 'docker compose up', create a web account: docker compose exec storageforge storageforge-index user add admin"
echo "Then open https://$(hostname -s 2>/dev/null || hostname):${STORAGEFORGE_HTTPS_PORT:-8443}"
