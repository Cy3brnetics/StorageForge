---
id: GM-16
status: open
severity: high
effort: S
area: "[[Docker, Nginx and Infrastructure]]"
tags: [finding, docker, entrypoint, restore, cli, gemini-audit]
found: 2026-10-29
---
# GM-16 Entrypoint bypasses on global flags and destructive pre-restore initialization

## Location
- `docker/entrypoint.sh:17-25, 27-38, 53-60, 63-75`

## Mechanics & Root Cause
`docker/entrypoint.sh` has five logic and security flaws in how it dispatches commands and initializes state:

1. **`restore` Runs `migrate`, `vault init`, and `vault import-dir` Against the Old/Corrupted Database BEFORE Restoring (`entrypoint.sh:18, 63-75`)**:
   - When an operator runs the documented restore command (`docker compose run --rm storageforge restore /app/backups/... --yes`), `restore` matches the `case` statement at line 18.
   - Before `exec storageforge-index restore ...` runs at line 75, lines 63–72 execute `storageforge-index migrate`, `storageforge-index vault init`, and `storageforge-index vault import-dir`!
   - If `/app/data/index.db` is corrupted (the main reason to run `restore`), `migrate` or `vault init` fails and aborts the container **before `restore` is ever reached**.
   - If `/app/data/` is empty, `entrypoint.sh` creates a new database, initializes a fresh vault, and imports `./keys` into it—and then `restore` immediately renames that database to `.pre-restore` and replaces it with the backup (losing the imported keys and never verifying that `STORAGEFORGE_VAULT_SECRET` unlocks the restored backup).
2. **Global CLI Flags (`--db`, `--version`, `--help`) Break `entrypoint.sh` (`entrypoint.sh:19, 35, 63-64`)**:
   - Passing `--db postgresql://... serve` matches `-*` at line 19, but `[ "${1:-serve}" = serve ]` at line 35 is **false** (since `$1` is `--db`), bypassing the `STORAGEFORGE_SESSION_SECRET` check (`lines 35-38`) and running `migrate` and `vault init` (`lines 63-64`) without the `--db` argument!
3. **Explicit `storageforge-index` Prefix Bypasses All Checks (`entrypoint.sh:17-24`)**:
   - Running `docker compose run --rm storageforge storageforge-index <cmd>` does not match lines 18–19 and immediately runs `exec "$@"` at line 20—before the root check (`line 24`), secret validation, and volume checks.
4. **Running One-Off CLI Commands Destroys Active `ssh-agent` Sockets (`entrypoint.sh:60`)**:
   - Line 60 (`find "$RUNTIME" -mindepth 1 -maxdepth 1 -name 'agent-*' -exec rm -rf {} +`) runs on every subcommand invocation. If a user runs a CLI command sharing `/run/storageforge`, it deletes active `ssh-agent` sockets currently in use by a running scan or deploy!
5. **Empty `$@` Invocation Fails at Line 75**:
   - Lines 17 and 35 default `${1:-serve}`, but line 75 executes `exec storageforge-index "$@"` with empty `$@`, failing with `error: the following arguments are required: cmd`.

## Impact
Database restore via `docker compose run --rm storageforge restore ...` fails when `index.db` is corrupted or discards imported keys when `index.db` is empty; passing `--db` bypasses session secret enforcement.

## Remediation
1. At the top of `entrypoint.sh`: strip a leading `storageforge-index` argument (`[ "${1:-}" = "storageforge-index" ] && shift`) and default empty args (`[ $# -eq 0 ] && set -- serve`).
2. Move `[ "$(id -u)" -ne 0 ]` before the `case` dispatch (or enforce it for all storageforge commands).
3. For `--help`, `-h`, `--version`, and `healthcheck`, `exec storageforge-index "$@"` immediately without touching the database or `/run/storageforge`.
4. For `restore`, skip pre-restore `migrate`, `vault init`, and `vault import-dir`.
5. Only clean `agent-*` in `$RUNTIME` when starting `serve`.

## Done when
- [ ] `entrypoint.sh` handles `restore`, `--help`/`--version`, `healthcheck`, empty `$@`, and leading `storageforge-index` cleanly.
