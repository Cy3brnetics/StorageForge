#!/bin/sh
# StorageForge container entrypoint: validate the environment, migrate, unlock the vault, then exec.
#   docker run … storageforge serve          → API + UI
#   docker run … storageforge vault list     → any storageforge-index subcommand
#   docker run … storageforge sh             → anything else is exec'd as-is
set -eu
umask 077

log() { printf 'entrypoint: %s\n' "$*" >&2; }
die() { log "error: $*"; exit 64; }

DATA=${STORAGEFORGE_DATA_DIR:-/app/data}
RUNTIME=${STORAGEFORGE_RUNTIME_DIR:-/run/storageforge}
IMPORT_DIR=${STORAGEFORGE_IMPORT_DIR:-/run/secrets/ssh-import}

case "${1:-serve}" in
  scan|search|changes|dupes|hosts|export-markdown|report|vault|audit|graph|canvas|blueprint|migrate|serve|healthcheck|user|-*) ;;
  *) exec "$@" ;;
esac

# 1. privileges: never root, no setuid escalation possible
[ "$(id -u)" -ne 0 ] || die "refusing to run as root; run with --user 10001:10001"

# 2. secrets: from env or *_FILE (Docker/compose secrets). Values are never printed.
length_of() {  # $1 = variable name; prints the secret length without exposing it
  eval "v=\${$1:-}"; eval "f=\${$1_FILE:-}"
  if [ -n "$v" ]; then printf %s "$v" | wc -c
  elif [ -n "$f" ]; then [ -r "$f" ] || die "$1_FILE=$f is not readable by uid $(id -u): run docker/init-secrets.sh, and set STORAGEFORGE_SECRETS_GID to the group of secrets/ if it is not 1000"; tr -d '\r\n' < "$f" | wc -c
  else echo 0; fi
}
[ "$(length_of STORAGEFORGE_VAULT_SECRET)" -ge 32 ] \
  || die "set STORAGEFORGE_VAULT_SECRET or STORAGEFORGE_VAULT_SECRET_FILE (≥ 32 characters; openssl rand -base64 48)"
if [ "${1:-serve}" = serve ]; then
  [ "$(length_of STORAGEFORGE_SESSION_SECRET)" -ge 32 ] \
    || die "set STORAGEFORGE_SESSION_SECRET or STORAGEFORGE_SESSION_SECRET_FILE (≥ 32 characters; openssl rand -base64 48)"
fi

# 3. persistent data: writable, owned by us, private
[ -d "$DATA" ] && [ -w "$DATA" ] || die "$DATA must be a volume writable by uid $(id -u)"
[ "$(stat -c %u "$DATA")" = "$(id -u)" ] || die "$DATA is owned by uid $(stat -c %u "$DATA"); expected $(id -u)"
chmod 0700 "$DATA"
# SQLite sorts big scan diffs in temp files; the 64 MiB /tmp tmpfs is far too small for millions of rows
mkdir -p "$DATA/home" "$DATA/ssh" "$DATA/tmp"
chmod 0700 "$DATA/home" "$DATA/ssh" "$DATA/tmp"
for f in "$DATA"/index.db "$DATA"/index.db-wal "$DATA"/index.db-shm "$DATA"/ssh/known_hosts; do
  [ -e "$f" ] && chmod 0600 "$f"
done

# 4. runtime dir for ephemeral ssh-agent sockets: must be memory-backed and private
[ -d "$RUNTIME" ] && [ -w "$RUNTIME" ] || die "$RUNTIME must exist and be writable (mount a tmpfs there)"
fstype=$(awk -v d="$RUNTIME" '$2 == d { t = $3 } END { print t }' /proc/mounts)
case "$fstype" in
  tmpfs|ramfs) ;;
  *) [ "${STORAGEFORGE_ALLOW_DISK_RUNTIME:-0}" = 1 ] \
       || die "$RUNTIME is '${fstype:-not a mount}', not tmpfs. Mount one: --tmpfs $RUNTIME:mode=0700,uid=10001" ;;
esac
chmod 0700 "$RUNTIME"
find "$RUNTIME" -mindepth 1 -maxdepth 1 -name 'agent-*' -exec rm -rf {} + 2>/dev/null || true

# 5. schema, then the vault (creates it on first start, verifies the secret afterwards)
storageforge-index migrate >&2
storageforge-index vault init >&2 || die "the vault secret does not unlock the existing vault"

# 6. optional one-shot key import from a read-only mount (file name = key name)
if [ -d "$IMPORT_DIR" ] && [ -n "$(ls -A "$IMPORT_DIR" 2>/dev/null)" ]; then
  if touch "$IMPORT_DIR/.rw-probe" 2>/dev/null; then
    rm -f "$IMPORT_DIR/.rw-probe"; log "warning: $IMPORT_DIR is writable; mount it read-only (:ro)"
  fi
  storageforge-index vault import-dir "$IMPORT_DIR" >&2 || log "warning: some keys in $IMPORT_DIR were not imported"
fi

log "ready: data=$DATA runtime=$RUNTIME ($fstype)"
exec storageforge-index "$@"
