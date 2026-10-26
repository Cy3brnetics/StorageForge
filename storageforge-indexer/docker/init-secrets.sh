#!/bin/sh
# Create ./secrets/vault_secret and ./secrets/session_secret for docker compose.
# The directory is 0700 so other host users cannot reach the files; the files are 0644 so the
# container user (uid 10001) can read the bind-mounted secret. Existing files are never overwritten.
set -eu
cd "$(dirname "$0")/.."
umask 077
mkdir -p secrets keys
chmod 0700 secrets
[ -s secrets/vault_secret ] || { openssl rand -base64 48 | tr -d '\n' > secrets/vault_secret; echo "created secrets/vault_secret"; }
[ -s secrets/session_secret ] || { openssl rand -base64 48 | tr -d '\n' > secrets/session_secret; echo "created secrets/session_secret"; }
chmod 0644 secrets/vault_secret secrets/session_secret
echo "Back up secrets/vault_secret. Without it the vault cannot be decrypted."
echo "After 'docker compose up', create a web account: docker compose exec storageforge storageforge-index user add admin"
