---
id: GM-15
status: open
severity: high
effort: S
area: "[[Docker, Nginx and Infrastructure]]"
tags: [finding, docker, keys, secrets, demo, gemini-audit]
found: 2026-10-29
---
# GM-15 Docker keys import fails silently on 0700 permissions and demo target has empty scan password

## Location
- `docker/init-secrets.sh:10-12, 38`
- `docker-compose.yml:16, 36, 43`
- `docker/entrypoint.sh:67-72`
- `examples/demo/Dockerfile.target:4-5`
- `examples/demo/compose.demo.yml:14-21`
- `secrets/api_token`

## Mechanics & Root Cause
### 1. Silent Failure of One-Shot SSH Key Import (`./keys`)
1. `docker/init-secrets.sh:10-11` sets `umask 077` and runs `mkdir -p secrets keys`. It never runs `chmod` on `keys/`, leaving `./keys` on the host with mode `0700` (`drwx------`) owned by the host user (`1000:1000`).
2. `docker-compose.yml:43` bind-mounts `./keys:/run/secrets/ssh-import:ro` into the `storageforge` container, which runs as `10001:10001` with `cap_drop: [ALL]` and `group_add: ["${STORAGEFORGE_SECRETS_GID:-1000}"]`.
3. Because `./keys` has mode `0700` (no group `r-x` permissions), UID `10001` receives `Permission denied` (`EACCES`) when trying to list `/run/secrets/ssh-import`.
4. In `docker/entrypoint.sh:67`:
   ```sh
   if [ -d "$IMPORT_DIR" ] && [ -n "$(ls -A "$IMPORT_DIR" 2>/dev/null)" ]; then
   ```
   `ls -A "$IMPORT_DIR" 2>/dev/null` fails with `Permission denied`, discards `stderr`, and outputs `""`, silently skipping the key import with zero log output!
5. Furthermore, lines 68-70 (`if touch "$IMPORT_DIR/.rw-probe" 2>/dev/null; then rm -f "$IMPORT_DIR/.rw-probe"`) attempt to create a file inside the user's keys directory on every startup instead of inspecting `/proc/mounts`.

### 2. `examples/demo/Dockerfile.target` Sets Empty Password on `scan` and Bakes Host Keys into Image
1. In `examples/demo/Dockerfile.target:4-5`:
   ```dockerfile
   RUN apk add --no-cache openssh-server findutils util-linux coreutils \
    && adduser -D -s /bin/sh scan && passwd -u scan >/dev/null 2>&1 || true \
    && ssh-keygen -A \
   ```
   On Alpine Linux (BusyBox), `adduser -D scan` creates `scan:!:` in `/etc/shadow`. Running `passwd -u scan` strips the `!`, setting the password hash to **empty (`scan::...`)** rather than `*` (`usermod -p '*'`).
2. `ssh-keygen -A` runs during `docker build`, baking the SSH host private keys into the image layers rather than generating them in `target-entrypoint.sh`.

### 3. Legacy World-Readable `secrets/api_token` (`0644`)
`/home/archie/Projects/storageforge/storageforge-indexer/secrets/api_token` exists on disk with mode `0644` (`-rw-r--r--`), because `init-secrets.sh:38` only runs `chmod 0640` on the 4 current secret files.

## Impact
The documented `./keys` auto-import workflow fails silently on every deployment initialized with `init-secrets.sh`; the demo target container has a passwordless `scan` account and static image-baked SSH host keys; and stale `secrets/api_token` remains world-readable.

## Remediation
1. In `docker/init-secrets.sh`, run `chmod 0750 keys` and `chmod 0640 secrets/*` (and delete `secrets/api_token`).
2. In `docker/entrypoint.sh:67`, log a clear warning if `[ -d "$IMPORT_DIR" ] && [ ! -r "$IMPORT_DIR" ]`, and check `/proc/mounts` for `ro` instead of `touch "$IMPORT_DIR/.rw-probe"`.
3. In `examples/demo/Dockerfile.target`, set `scan`'s shadow password field to `*` (`sed -i 's/^scan:!:/scan:*:/' /etc/shadow`) and move `ssh-keygen -A` into `target-entrypoint.sh`.

## Done when
- [ ] `./keys` is `0750` (with `0640` key files) and `entrypoint.sh` warns when `$IMPORT_DIR` is unreadable.
- [ ] `Dockerfile.target` locks `scan`'s password hash to `*` and generates host keys at container start.
