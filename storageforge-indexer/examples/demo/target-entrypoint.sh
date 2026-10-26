#!/bin/sh
set -eu
# AUTHORIZED_KEY is the vault's public key (storageforge-index vault pubkey --name demo)
if [ -n "${AUTHORIZED_KEY:-}" ]; then
  printf '%s\n' "$AUTHORIZED_KEY" > /home/scan/.ssh/authorized_keys
  chown scan:scan /home/scan/.ssh/authorized_keys && chmod 600 /home/scan/.ssh/authorized_keys
fi
exec /usr/sbin/sshd -D -e
