# Operations

## Configuration

Everything is set with environment variables. In Docker, put them in `.env` next to `docker-compose.yml`; compose passes the ones it lists.

### Server

| Variable | Default | Purpose |
| :--- | :--- | :--- |
| `STORAGEFORGE_DB` | `~/.local/share/storageforge/index.db` (`/app/data/index.db` in the image) | SQLite path or `postgresql://…` URL |
| `STORAGEFORGE_DATA_DIR` | `~/.local/share/storageforge` (`/app/data`) | `known_hosts`, SSH home, SQLite temp files |
| `STORAGEFORGE_VAULT_SECRET` / `_FILE` | required | Unlocks the vault; at least 32 characters |
| `STORAGEFORGE_VAULT_NEW_SECRET` | | The new secret for `vault rotate-secret` |
| `STORAGEFORGE_SESSION_SECRET` / `_FILE` | random per start | Signs session cookies; at least 32 characters |
| `STORAGEFORGE_LISTEN`, `STORAGEFORGE_PORT` | `127.0.0.1`, `8080` (`0.0.0.0` in the image) | Where `serve` listens |
| `STORAGEFORGE_COOKIE_SECURE` | `0` (`1` in compose) | `Secure` `__Host-` cookie; needs HTTPS |
| `STORAGEFORGE_PROXY_HOPS` | `0` (`1` in compose) | Trust `X-Forwarded-For` from this many proxies (`2` with another proxy in front of the stack's) |
| `STORAGEFORGE_PROXY_HOST` | none (`proxy` in compose) | Believe those headers only on requests from this host (name or address), not from anything else that can reach the app |
| `STORAGEFORGE_SCAN_INTERVAL` | off (`6h` in compose) | Rescan bound hosts this often (`90m`, `6h`, `1d`) |
| `STORAGEFORGE_SCAN_WORKERS` | `4` | Hosts scanned at once; further scan jobs wait for a free worker |
| `STORAGEFORGE_INCLUDE_FSTYPES` | | Comma list of normally skipped filesystem types the server's scans walk (e.g. `overlay`) |
| `STORAGEFORGE_RUNTIME_DIR` | `/run/storageforge`, else `$XDG_RUNTIME_DIR` | tmpfs for agent sockets; its path must be short (Unix socket limit) |
| `STORAGEFORGE_BACKUP_DIR` | `<data>/backups` (`/app/backups`) | Where backups go |
| `STORAGEFORGE_BACKUP_HOUR` | `3` | Local hour for the nightly backup and prune |
| `STORAGEFORGE_BACKUP_KEEP` | `14` | Essentials backups kept |
| `STORAGEFORGE_BACKUP_FULL_KEEP` | `0` | Full backups kept nightly (0: on demand only) |
| `STORAGEFORGE_CHANGE_DAYS` | `90` | Days of file change history kept |
| `STORAGEFORGE_CHANGE_MAX_ROWS` | `2000000` | Most change rows kept, oldest scans dropped first |
| `STORAGEFORGE_FILLS_UP_DAYS` | `14` | Alert when a mount's 30-day trend fills it within this many days |
| `STORAGEFORGE_LARGE_DELETE` | `10000` | Alert when one scan finds this many files gone |
| `STORAGEFORGE_DISK_WARN_PCT`, `STORAGEFORGE_DISK_CRIT_PCT` | `90`, `95` | How full a filesystem is before it raises an alert |
| `STORAGEFORGE_ACCESS_LOG` | `changes` | `all`, `changes` (writes, 429s and 5xx) or `off` |
| `STORAGEFORGE_REPORT_CA_FILE` | `/run/sf-secrets/tls_cert` in compose | Certificate deployed jobs trust for an `https` report URL |

### Container and scripts

| Variable | Default | Purpose |
| :--- | :--- | :--- |
| `STORAGEFORGE_HTTPS_BIND`, `STORAGEFORGE_HTTPS_PORT` | `0.0.0.0`, `8443` | Where the proxy is published |
| `STORAGEFORGE_SECRETS_GID` | `1000` | Group that can read `keys/`; `init-secrets.sh` writes it to `.env` when yours differs |
| `STORAGEFORGE_SECRETS_DIR` | `./secrets` | Mounted read-only into the `init-secrets` service; it copies what the secret volumes are missing from here |
| `STORAGEFORGE_KEY_IMPORT_DIR` | `./keys` | Mounted read-only; each file is imported as a key at start |
| `STORAGEFORGE_TLS_NAMES` | | Extra names and addresses for the self-signed certificate; used when it is created |
| `STORAGEFORGE_ALLOW_DISK_RUNTIME` | `0` | Let the entrypoint start when the runtime dir is not tmpfs (not recommended) |
| `STORAGEFORGE_EGRESS_PORTS`, `STORAGEFORGE_BRIDGE` | `22 443`, `sf0` | For `docker/egress-firewall.sh` |

## Health

`storageforge-index healthcheck` probes `/healthz`; the image's `HEALTHCHECK` uses it. From inside the container or when signed in, `/healthz` also reports the version, database, vault state, worker and user count.

## Backups

Every night at `STORAGEFORGE_BACKUP_HOUR` (the host's local time; compose mounts `/etc/localtime`), the server writes an **essentials** backup and keeps the newest 14. It also does this at start-up when the newest one is more than a day old.

An essentials backup is a fresh database holding everything a rescan cannot rebuild. It is a few MB.

| In essentials | Left out |
| :--- | :--- |
| encrypted keys and bindings, web users, the hosts list, host designs | the file index, folders, scan history and the graph: the next scans rebuild them |
| change plans, move plans, storage tasks | deploy and job run history |
| settings (report URL, alert channels, planner options) | open alerts: re-checked on the next run |
| deploy access, what is deployed where, deployed jobs with their token hashes (so their reports are still accepted) | web sessions: everyone signs in again |
| confirmed host keys, the audit log | |

`backup.ESSENTIAL` and `backup.REBUILDABLE` name every table, and `tests/test_consistency.py` fails when a migration adds a table to neither. A **full** backup is SQLite's online copy of everything, as large as the database.

```bash
docker compose exec storageforge storageforge-index backup            # essentials now
docker compose exec storageforge storageforge-index backup --full     # everything
docker compose exec storageforge storageforge-index backup list
```

`POST /api/backups` makes one over HTTP, up to 6 per hour; the **Audit** tab shows the newest backup and can make one. Set a host and folder there (or `PUT /api/backups/target`) to copy each backup off this machine, using the key bound to that host for deploys; a failed copy raises an alert. Backups are SQLite only; with PostgreSQL use its own tools. To rebuild on another machine, see [Disaster recovery](disaster-recovery.md).

### Restore

Stop the server, restore, start it again:

```bash
docker compose stop storageforge
docker compose run --rm storageforge restore /app/backups/storageforge-essentials-20261027-030000.db --yes
docker compose start storageforge
```

Images built before 2026-10-29 don't recognise `restore` and the other newer subcommands in `docker compose run` (see the [audit](audit-2026-10-29.md#container)). Rebuild the image, or add `--entrypoint storageforge-index` after `--rm`. A restore keeps the current database beside it as `index.db.pre-restore-<time>`. After restoring an essentials backup, rescan to rebuild the index.

Backups live in the `sf-backups` volume on this machine. To keep copies elsewhere, add a Moves **mirror** step from `/var/lib/docker/volumes/storageforge_sf-backups/_data` to another host.

## Certificates

The self-signed certificate lasts 825 days. An alert opens 30 days before the end and goes critical at 7. To replace it, delete it from its volume and deploy again:

```bash
docker compose run --rm --no-deps --entrypoint sh init-secrets -c 'rm -f /secrets/proxy/tls_cert /secrets/proxy/tls_key'
docker compose up -d
```

To use your own, put `tls_cert` and `tls_key` in `./secrets` before that second command. Either way, deploy your jobs again afterwards if they report over `https`, because each one trusts the certificate it was deployed with.

## Retiring a host

StorageForge has no way to remove a host yet. To stop using one:

1. Remove what you deployed to it, from the **Deploy** tab.
2. Stop scanning it: `storageforge-index vault unbind` (see the [CLI reference](cli-reference.md)).

Its index, graph entries and design stay, so it still shows up in search.

## Retention

After every scan, and every night, StorageForge removes:

- file change history older than `STORAGEFORGE_CHANGE_DAYS`, and the oldest scans' history beyond `STORAGEFORGE_CHANGE_MAX_ROWS` (the newest scan's changes on each host always stay);
- unreadable-folder lists from all but each host's latest scan;
- finished scan jobs older than 90 days.

`storageforge-index prune --vacuum` also shrinks the database file. It rewrites the whole file and locks it while it runs.

## Logs

The app logs to stderr (`docker compose logs storageforge`), rotated by Docker at 10 MB × 5. Scan jobs log as `[job N] …`. The request log follows `STORAGEFORGE_ACCESS_LOG`. The audit log is in the database: **Audit** in the UI, or `storageforge-index audit tail`.

On hosts: `/var/log/storageforge/run.log` (signed runs), `/var/log/storageforge/` (move scripts), `journalctl -u 'sf-job-*'` and `journalctl -u 'sf-task-*'`.

## Upgrading

```bash
git pull
docker compose up -d --build
```

Migrations run on start (`storageforge-index migrate`). Most are quick. Schema 12 rewrites `file_records` once: on an 11.9-million-entry index it took about 8 minutes and needed about as much free space as that table; run `prune --vacuum` afterwards to give the space back. The server is unavailable while a migration runs.

## Updating dependencies

The base image is pinned by digest and Python packages by hash. To move them forward, skipping releases younger than two weeks:

```bash
docker buildx imagetools inspect python:3.13-slim-bookworm | sed -n 's/^Digest: *//p'     # new digest for PYTHON_IMAGE in the Dockerfile
uv pip compile pyproject.toml docker/build-requirements.in --universal --python-version 3.13 --generate-hashes --no-header --exclude-newer "$(date -d '14 days ago' +%F)" -o docker/requirements.lock
uv pip compile pyproject.toml docker/build-requirements.in --extra postgres --universal --python-version 3.13 --generate-hashes --no-header --exclude-newer "$(date -d '14 days ago' +%F)" -o docker/requirements-postgres.lock
```

## PostgreSQL

Build with `--build-arg EXTRAS=postgres` and set `STORAGEFORGE_DB=postgresql://user@host/storageforge`. With PostgreSQL the scanner uses up to 8 writers and `COPY`.

## Tests

```bash
pip install -e .                                  # without Flask, the server tests error instead of running
python3 -m unittest discover -s tests -v
docker build --target test .
```

`.forgejo/workflows/ci.yml` runs the suite on both databases, plus ruff and shellcheck, on every push. It needs Forgejo Actions and a runner.

`tests/test_platform.py` covers the vault, bindings, the audit chain, a real ephemeral `ssh-agent`, the graph and canvas, and the HTTP API with auth and CSP. `tests/test_indexer.py` covers units, patterns, the stream parser, pool math, mount planning, payload parsers, reports and real local scans. `tests/test_tasks.py` covers storage tasks and their scripts.

The same suite runs against PostgreSQL when `STORAGEFORGE_TEST_PG` names a server it may create databases on (each test gets a fresh one, dropped afterwards). The backup tests are skipped there, since backups are of SQLite databases:

```bash
docker run -d --rm --name sf-test-pg -e POSTGRES_USER=sf -e POSTGRES_PASSWORD=sftest -p 127.0.0.1:55432:5432 postgres:16-alpine
STORAGEFORGE_TEST_PG=postgresql://sf:sftest@127.0.0.1:55432/postgres python3 -m unittest discover -s tests
```
