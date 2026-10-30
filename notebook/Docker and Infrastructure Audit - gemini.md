---
date: 2026-10-29
tags: [audit, docker, nginx, infrastructure, gemini-audit]
---
# Docker and Infrastructure Audit - gemini

Detailed security, configuration, and operational audit of all container images, Compose files, proxy configurations, and host/container helper scripts in `storageforge-indexer/`.

## Audited Files
1. `storageforge-indexer/Dockerfile` (multi-stage `build`, `test`, and `runtime` targets)
2. `storageforge-indexer/docker-compose.yml` (`storageforge` and `proxy` services)
3. `storageforge-indexer/.dockerignore`
4. `storageforge-indexer/docker/entrypoint.sh`
5. `storageforge-indexer/docker/init-secrets.sh`
6. `storageforge-indexer/docker/nginx.conf`
7. `storageforge-indexer/docker/egress-firewall.sh`
8. `storageforge-indexer/docker/build-requirements.in`, `requirements.lock`, `requirements-postgres.lock`
9. `storageforge-indexer/examples/demo/Dockerfile.target`, `target-entrypoint.sh`, `compose.demo.yml`, `demo.sh`
10. `storageforge-indexer/secrets/`

---

## Container Architecture & Trust Boundaries

```
 Browser / Operator (LAN)
        │  HTTPS :8443 (TLS 1.2 / 1.3, self-signed EC P-256 cert)
        ▼
 ┌──────────────────────────────────────────────────────────┐
 │ proxy (nginxinc/nginx-unprivileged:1.27-alpine, uid 101) │
 │  • read_only: true, cap_drop: [ALL], no-new-privileges   │
 │  • Sets X-Forwarded-For: $remote_addr, Proto: https      │
 └──────────────────────────┬───────────────────────────────┘
                            │ HTTP :8080 on bridge network `sf` (sf0)
                            ▼
 ┌──────────────────────────────────────────────────────────┐
 │ storageforge (python:3.13-slim-bookworm, uid 10001)      │
 │  • read_only: true, cap_drop: [ALL], no-new-privileges   │
 │  • /app/data (sf-data volume), /app/backups (sf-backups) │
 │  • /run/storageforge (16m tmpfs, mode 0700, ssh-agent)   │
 │  • /run/secrets/{vault_secret,session_secret} (gid 1000) │
 │  • /run/secrets/ssh-import (bind mount of ./keys:ro)     │
 └──────────────────────────┬───────────────────────────────┘
                            │ Outbound SSH (:22) + Alert Webhooks (:443)
                            ▼
                Scanned / Enrolled LAN Hosts
```

---

## Key Infrastructure Findings

### 1. Silent Failure of `./keys` One-Shot SSH Key Import ([[GM-15 Docker keys import fails silently on 0700 permissions and demo target has empty scan password|GM-15]])
- **Where**: `docker/init-secrets.sh:10-11`, `docker-compose.yml:43`, `docker/entrypoint.sh:67`
- **Mechanism**: `init-secrets.sh` sets `umask 077` and runs `mkdir -p secrets keys`, creating `./keys` as `0700` owned by UID `1000`. Unlike Docker `secrets:` files, `./keys` is bind-mounted as a directory (`/run/secrets/ssh-import:ro`). Because `storageforge` runs as UID `10001` with `group_add: [1000]` and `cap_drop: [ALL]`, the lack of group `r-x` bits (`0750`) causes `ls -A "$IMPORT_DIR" 2>/dev/null` in `entrypoint.sh:67` to fail with `Permission denied` and silently skip importing keys.

### 2. Demo Target Image Empty Password & Baked-In Host Keys ([[GM-15 Docker keys import fails silently on 0700 permissions and demo target has empty scan password|GM-15]])
- **Where**: `examples/demo/Dockerfile.target:4-5`, `examples/demo/compose.demo.yml:14-21`
- **Mechanism**:
  - `adduser -D -s /bin/sh scan && passwd -u scan` in Alpine BusyBox unlocks `scan` by setting its `/etc/shadow` password hash to empty (`scan::...`) instead of `*`.
  - `ssh-keygen -A` runs during `docker build`, baking the SSH host private keys into the image layers instead of generating them at container startup in `target-entrypoint.sh`.
  - `target` in `compose.demo.yml` runs with full default root capabilities, no `no-new-privileges`, and no resource limits.

### 3. `docker/entrypoint.sh` Bypasses & Destructive Pre-`restore` Execution ([[GM-16 Entrypoint bypasses on global flags and destructive pre-restore initialization|GM-16]])
- **Where**: `docker/entrypoint.sh:17-24, 35, 60, 63-75`
- **Mechanism**:
  - Running `docker compose run --rm storageforge restore <file> --yes` matches line 18 and runs `migrate`, `vault init`, and `vault import-dir` **before** `restore`, which aborts if `index.db` is corrupted or overwrites newly imported keys if `index.db` was empty.
  - Passing global flags before `serve` (e.g. `--db postgresql://... serve`) bypasses the `STORAGEFORGE_SESSION_SECRET` check (`[ "${1:-serve}" = serve ]` is false) and runs `migrate`/`vault init` without `--db`.
  - Running `docker run ... storageforge storageforge-index <cmd>` matches `*) exec "$@"` at line 20 before the non-root check (`line 24`) and secret/tmpfs checks.
  - Line 60 (`find "$RUNTIME" ... -name 'agent-*' -exec rm -rf {} +`) deletes live `ssh-agent` sockets if any CLI subcommand is invoked in a container sharing `/run/storageforge`.

### 4. `X-Forwarded-For` Spoofing Across Shared Networks & Multi-Hop Breakage ([[GM-17 Proxy header spoofing on shared Docker networks and broken multi-hop X-Forwarded-For|GM-17]])
- **Where**: `docker-compose.yml:25, 48`, `examples/demo/compose.demo.yml:10, 21`, `docker/nginx.conf:37`
- **Mechanism**:
  - `storageforge` listens on `0.0.0.0:8080` on the same bridge networks (`sf` and `demo`) used to reach target SSH hosts, while `ProxyFix(x_for=1)` trusts `X-Forwarded-For` from any peer connecting to `:8080`.
  - `nginx.conf:37` overwrites `X-Forwarded-For` with `$remote_addr`, which breaks `STORAGEFORGE_PROXY_HOPS > 1` when an external reverse proxy sits in front of `proxy`.

### 5. Host Egress Firewall (`docker/egress-firewall.sh`) Bypasses & Fail-Open Crash ([[GM-18 Egress firewall fails open on bridge switch or invalid port and misses host INPUT chain|GM-18]])
- **Where**: `docker/egress-firewall.sh:16-18, 24-36`
- **Mechanism**:
  - `DOCKER-USER` only filters routed `FORWARD` traffic; connections from `sf0` to any IP address assigned to the Docker host itself traverse the `INPUT` chain and bypass `SF-EGRESS`.
  - Using a single global chain `SF-EGRESS` across bridges causes running `STORAGEFORGE_BRIDGE=sfdemo0 ./docker/egress-firewall.sh` to flush `SF-EGRESS` and crash on `iptables -N SF-EGRESS`, leaving `sf0` with an empty chain (fail-open).

### 6. 825-Day TLS Certificate Lifetime, Nginx IPv6/Ciphers, and Skipped Container Tests ([[GM-24 TLS 825-day cert rejected by modern browsers, nginx IPv6 and cipher gaps, and skipped tests in Dockerfile|GM-24]])
- **Where**: `docker/init-secrets.sh:30`, `docker/nginx.conf:19, 23, 33`, `Dockerfile:28-33`
- **Mechanism**:
  - `openssl req ... -days 825` exceeds the 398-day maximum certificate lifetime enforced by all modern browsers (`ERR_CERT_VALIDITY_TOO_LONG`).
  - `Dockerfile` `test` stage runs as `root` (`uid 0`) and omits `git`, silently skipping 4 tests including `test_runner_verifies_signature_and_blocks_replay_and_wrong_host`.
  - `secrets/api_token` remains on disk with world-readable `0644` permissions.

---

Back to [[Home]]
