---
id: GM-11
status: open
severity: high
effort: M
area: "[[API, Auth and Security]]"
tags: [finding, security, auth, api, gemini-audit]
found: 2026-10-29
---
# GM-11 Missing password confirmation on remote execution and security-critical routes

## Location
- `storageforge_index/server.py:665, 696, 999, 1093-1132, 1157`

## Mechanics & Root Cause
Several high-privilege routes either execute commands as `root` on remote hosts or mutate security-critical configuration without `@password_confirmed`:
1. **`POST /api/deploy/jobs/<jid>/browse` (`server.py:1105`) and `POST /api/deploy/jobs/<jid>/<verb>` for `dryrun`, `log`, `snapshots` (`server.py:1096`)**:
   - Line 1096 exempts `verb in ('dryrun', 'log', 'snapshots')` from `password_stale()`, and `api_deploy_job_browse` has no `password_confirmed` check at all.
   - Yet both `jobs.run_now` and `jobs.browse` sign a payload with `storageforge-signing` and invoke `sudo -n /usr/local/sbin/storageforge-apply` as `root` on the target host (`deploy.run(..., mode='apply')`). In particular, `dryrun` executes the full backup/sync command pipeline (with `-n`) as `root` and connects over SSH to peer hosts, while `browse` lists arbitrary directory trees inside snapshots as `root`.
2. **`PUT /api/deploy/settings` (`server.py:1118`) and `POST /api/deploy/settings/test` (`server.py:1127`)**:
   - Modifies `report_url` (which is embedded into deployed job scripts) and outbound webhook/SMTP/ntfy/gotify alert targets without `@password_confirmed` (also tracked in `docs/audit-2026-10-29.md` as `A1`).
3. **`POST /api/hostkey/confirm` (`server.py:696`)**:
   - Permanently records operator trust for an SSH host key in `host_key_confirmations` and appends it to `known_hosts` without `@password_confirmed`.
4. **`GET /api/deploy/setup-script` (`server.py:999`)**:
   - Mutates vault state on a `GET` request without `@password_confirmed` by calling `deploy.ensure_keys()`, which generates and stores `storageforge-signing` and `storageforge-deploy` in the vault.
5. **`POST /api/keys` (`server.py:665`) and `POST /api/backups` (`server.py:1157`)**:
   - Generates new SSH keys in the vault or triggers full database backups on disk without `@password_confirmed`.

## Impact
An attacker with access to an unattended browser or stolen session cookie (after the 10-minute re-auth window has expired) can still trust rogue SSH host keys, reconfigure alert webhooks and `report_url`, generate vault keys, and trigger root `storageforge-apply` runs (`dryrun`, `browse`) on enrolled hosts.

## Remediation
1. Add `@password_confirmed` to `POST /api/hostkey/confirm`, `PUT /api/deploy/settings`, `POST /api/deploy/settings/test`, `POST /api/keys`, `POST /api/backups`, and `dryrun` in `api_deploy_job_action`.
2. Do not generate vault keys inside `GET /api/deploy/setup-script` unless keys already exist or a `@password_confirmed` `POST` initializes them.

## Done when
- [ ] All security-sensitive and remote-execution endpoints enforce `@password_confirmed`.
