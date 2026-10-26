# StorageForge

A containerized storage platform: an encrypted SSH key vault, agentless file indexing over SSH, sub-second search across every host, a force-directed storage graph with Obsidian `.canvas` export, and Markdown architecture reports.

- **Nothing to install on targets.** It uses the system `ssh` client and POSIX tools that are already there (`find`, `findmnt`, `lsblk`, `df`, optionally `zpool` and `sha256sum`).
- **Keys never touch disk in plaintext.** They are encrypted with AES-256-GCM under an Argon2id-derived key, and each task loads its key into a private, short-lived `ssh-agent` on tmpfs.
- **Streaming and incremental.** NUL-delimited `find` output is parsed in 1 MiB chunks, and each scan is diffed against the last one in a single transaction.
- **Few dependencies:** `cryptography` ≥ 44, plus Flask, Flask-Login, Flask-Limiter and waitress for the web UI. PostgreSQL needs `psycopg` 3; YAML blueprints need PyYAML.

## Quick start (Docker)

```bash
./docker/init-secrets.sh                      # creates secrets/vault_secret and secrets/session_secret
docker compose up -d --build                  # UI and API on http://127.0.0.1:8080
docker compose exec storageforge storageforge-index user add admin              # web UI account (prompts for a password)
docker compose exec storageforge storageforge-index vault generate --name fleet   # prints the public key
#   … add that public key to ~scan/.ssh/authorized_keys on your hosts, then:
docker compose exec storageforge storageforge-index vault bind --key fleet --host 10.0.20.0/24 --user scan
docker compose exec storageforge storageforge-index scan --host 10.0.20.5
```

To import an existing key over stdin (it is never written to the container filesystem):

```bash
docker compose exec -T storageforge storageforge-index vault add --name nas --key-file - < ~/.ssh/id_ed25519
```

`examples/demo/demo.sh` runs the whole flow against a disposable SSH target container: it generates a vault key, binds it, scans over SSH with checksums, imports the atlas blueprint and opens the UI.

```bash
pip install .                    # without Docker: python3 -m storageforge_index …
pip install '.[postgres,yaml]'   # optional extras
```

## Security model

| Concern | Design |
| :--- | :--- |
| Keys at rest | Envelope encryption. `STORAGEFORGE_VAULT_SECRET` → Argon2id (t=3, 64 MiB, p=4, random salt) → KEK, which is never stored. The KEK wraps a random 256-bit DEK per key; the DEK encrypts the OpenSSH private key with AES-256-GCM. Associated data binds every ciphertext to its row's UUID and purpose, so a ciphertext swapped between rows fails to decrypt. A GCM-encrypted verifier detects a wrong secret. |
| Weak keys | RSA below 3072 bits is refused. Passphrase-protected keys are accepted with `--passphrase-env` and stored decrypted inside the vault. |
| Secret rotation | `vault rotate-secret` rewraps every DEK and the audit key under a new KEK in one transaction. Key ciphertexts never change. |
| Runtime | Plaintext is decrypted with `update_into` into an `mlock`ed `bytearray`. It is written to `ssh-add -` from that buffer, then zeroed. The agent (`ssh-agent -D -a`) listens on a socket in a fresh 0700 directory on the tmpfs `/run/storageforge`, with a key lifetime limit. It is killed and the directory removed when the task ends. `ssh` runs with `-F /dev/null`, `IdentityAgent=<socket>`, `BatchMode`, password auth off and a persistent `known_hosts` (trust on first use). |
| Host mapping | `key_bindings` maps keys to an exact host or IP, a glob (`*.tailnet.ts.net`) or a CIDR, with a user, port and allowed actions (`scan`, `checksum`). The most specific match wins: host, then glob, then longest prefix, then priority. |
| Audit | Every connection, scan result, denial and vault change is appended to `audit_log`. Each entry carries an HMAC-SHA256 over the previous entry's hash, with a random MAC key wrapped by the KEK. Triggers reject UPDATE, DELETE (and TRUNCATE on PostgreSQL). `audit verify` detects an edited, deleted or reordered row even if the triggers were bypassed. |
| API | Local accounts. Flask-Login manages sessions and Werkzeug hashes passwords (scrypt); StorageForge has no auth code of its own. The session cookie is signed with `STORAGEFORGE_SESSION_SECRET`, `HttpOnly`, `SameSite=Strict`, and `Secure` when `STORAGEFORGE_COOKIE_SECURE=1`. Sessions last 12 hours. Changing or disabling an account signs out its sessions. State-changing routes accept only `application/json`, so a cross-site form cannot reach them. Every sign-in attempt is audited. Flask-Limiter throttles failed sign-ins: 10 per minute and 50 per hour per client IP, and 5 per minute and 20 per hour per username. After that `/api/login` answers `429` with `Retry-After`. Successful sign-ins don't count, and counters reset when the server restarts. Behind a reverse proxy, set `STORAGEFORGE_PROXY_HOPS=1` so limits and the audit log see the real client IP from `X-Forwarded-For`. Strict CSP (`'self'` only), `nosniff`, `frame-ancestors 'none'`, `no-store`, 4 KiB body cap. Served by waitress. The UI builds the DOM with `textContent` only. |
| Container | Non-root uid 10001, read-only root filesystem, `cap_drop: ALL`, `no-new-privileges`, tmpfs runtime and `/tmp` (`noexec,nosuid,nodev`), 2 CPU / 1 GiB / 256 PID limits, memlock raised for `mlock`. Secrets come from compose secret files, and the port is published on loopback only. |

Python cannot promise that no other copy of a secret exists in memory: the environment variable and import paths are ordinary immutable objects. The design minimizes how long plaintext lives and never writes it to disk. It does not claim zero copies. Put TLS in front of the API with a reverse proxy.

## Commands

```bash
# Index a host (repeat --host for several). Key auth only; never prompts.
storageforge-index scan --host 10.0.20.5 --user root --key ~/.ssh/id_ed25519

# Show what would be walked and the exact find commands, without writing anything
storageforge-index scan --host nas-02 --user backup --key ~/.ssh/nas --dry-run

# Search across every indexed host
storageforge-index search --name "*.cr2" --host node-01 --size-gt 100MB
storageforge-index search "IMG_2019*" --under /mnt/storage_array/photos --sort size --desc
storageforge-index search "*invoice*2024*" --type f --newer-than 90d --format json

# What changed in the last scan, duplicates, hosts
storageforge-index changes --host node-01
storageforge-index scan --host node-01 --user root --key ~/.ssh/id --checksum   # hash size-collision candidates
storageforge-index dupes --min-size 50MB
storageforge-index hosts

# Architecture report from the index, optionally overlaid with a StorageForge blueprint
storageforge-index export-markdown --host atlas --blueprint atlas-blueprint.json -o atlas.md

# Architecture report from saved payloads, with no index and no SSH
storageforge-index report --blueprint blueprint.json --fstab fstab --df df-h.txt --zpool-status zpool.txt -o report.md
storageforge-index report --lsblk lsblk.json --df df.txt --zpool-status zpool.txt --hostname nas-02

# Vault, audit, graph and server
storageforge-index vault init | status | list | bindings
storageforge-index vault generate --name fleet [--type ed25519|rsa]
storageforge-index vault add --name nas --key-file ~/.ssh/id_ed25519 [--passphrase-env VAR]
storageforge-index vault bind --key fleet --host '*.tail4c2e.ts.net' --user scan --actions scan,checksum
storageforge-index vault resolve --host nas-02.tail4c2e.ts.net
STORAGEFORGE_VAULT_NEW_SECRET=… storageforge-index vault rotate-secret
storageforge-index audit tail | verify
storageforge-index scan --host nas-02          # no --key: uses the vault binding through an ephemeral agent
storageforge-index blueprint atlas.json        # design intent overlaid on the graph after each scan
storageforge-index graph build | stats
storageforge-index graph import --blueprint atlas.json --df df.txt --zpool-status zpool.txt
storageforge-index canvas -o storage.canvas    # Obsidian JSON Canvas
storageforge-index serve --listen 127.0.0.1 --scan-interval 6h
storageforge-index user add | passwd | disable | enable | remove | list
```

Sizes accept `100MB` (decimal), `100MiB` or `100M` (binary, as `df` and `find` print them). Ages accept `90m`, `36h`, `7d`, `2w` and `1y`.

The database defaults to `~/.local/share/storageforge/index.db`. Use `--db postgresql://user@host/storageforge` or set `STORAGEFORGE_DB` instead.

## Graph and Obsidian canvas

The graph is rebuilt per host after every scan, from the index plus any stored blueprint.

| Node | Example id | Edges |
| :--- | :--- | :--- |
| Host | `host:atlas` (external targets have no owning host) | `CONTAINS` pools and standalone filesystems |
| StoragePool | `pool:atlas:tank` | `CONTAINS` datasets and arrays' filesystems |
| Filesystem | `fs:atlas:tank/media` | `MOUNTED_AT` mount points, `REPLICATES_TO` sync and backup targets |
| MountPoint | `mnt:atlas:/mnt/storage_array/media` | `MOUNTED_AT` bind mounts |
| Symlink | `link:atlas:/var/media` | `SYMLINK_TO` the mount holding its target, or another link |

Health colours follow the 3-2-1 rules: 🟢 protected, 🟡 local-only, 🔴 broken or offline, grey for no data. Pools and hosts take the worst health of what they contain.

The UI at `/` is a dependency-free canvas force simulation with charge, springs, collision and gravity:
- drag to pan, scroll to zoom, drag a node to move it (it stays where you drop it; shift-drag lets it spring back, and "Show all" releases every pinned node)
- click a node for details and connections; double-click it to focus on its 1–3 hop neighbourhood
- search files from the header, export `.canvas`, queue scans, and read or verify the audit log

`canvas` and `/api/canvas` write JSON Canvas 1.0. There is one group per host, columns run Host → Pool → Filesystem → Mount → Symlink, and external targets sit in their own group. Obsidian colour presets are 4 for green, 3 for yellow and 1 for red. See [`examples/storageforge-network.canvas`](examples/storageforge-network.canvas).

## API

| Method | Path | |
| :--- | :--- | :--- |
| GET | `/healthz` | database, vault, worker and user-count status (no auth; used by `HEALTHCHECK`) |
| POST | `/api/login`, `/api/logout`; GET `/api/me` | session |
| GET | `/api/hosts`, `/api/graph[?host=]`, `/api/canvas[?host=]` | topology |
| GET | `/api/search?q=&host=&size_gt=&type=&under=&limit=` | file search |
| POST | `/api/scan` `{"host": "…"}` | queue a vault-backed scan (one at a time; duplicates collapse) |
| GET | `/api/planner/hosts` | scanned hosts and saved designs |
| GET | `/api/planner/design?host=&source=saved\|scan` | a design: the saved one, or built from the latest scan plus saved intent |
| PUT | `/api/planner/design` | save a `storageforge/v1` blueprint (2 MiB cap) and rebuild the host's graph |
| GET | `/api/keys` | vault keys (public halves only) and host bindings |
| POST | `/api/keys` `{"name": "…", "type": "ed25519" or "rsa"}` | generate a key inside the vault |
| POST | `/api/keys/install` `{"key", "host", "port", "user", "password", "bind", "checksum"}` | `ssh-copy-id` the public key with the host password, verify key login, optionally bind it for scans (10 per minute per user) |
| GET | `/api/jobs`, `/api/audit[?limit=]`, `/api/audit/verify` | jobs and audit |

All other `/api/*` routes need a session. Sign in with `POST /api/login` `{"username": "…", "password": "…"}`, which sets the `sf_session` cookie; `POST /api/logout` ends it, and `GET /api/me` returns the signed-in user.

```bash
storageforge-index user add alice                 # prompts twice, or reads one line from stdin
storageforge-index user add bot --password-env BOT_PW
storageforge-index user passwd alice | disable alice | enable alice | remove alice
storageforge-index user list
```

Passwords need at least 12 characters. An account that hits the failed sign-in limit is locked for up to an hour, even with the right password. Restart the server to clear it sooner.

## Planner

`/planner` is the StorageForge design tool, served by the same app and signed in with the same account. It has these views:

- **Devices:** block devices, partition tables and filesystems.
- **Mounts:** the mount tree with conflict checks, and generated `/etc/fstab` and systemd units.
- **Links:** symlinks and bind mounts, with health checks and boot ordering.
- **Topology:** disks, pools and mounts as a diagram.
- **RAID calculator.**
- **Protection:** the 3-2-1 grid.
- **Export:** Bash, Ansible, systemd, JSON/YAML blueprint and ASCII tree.

Pick a host in the rail:

- **A scanned host with no saved design** opens as a design built from its latest scan. This includes real disks, partitions, UUIDs, btrfs subvolumes (also through LUKS), mdadm/ZFS/multi-device btrfs pools, mount options, remote mounts, bind mounts and problem symlinks. Protection rows start as "None" because a scan cannot see sync, snapshot or backup policy. `/tmp`, `/var/tmp` and `/var/cache` start as ephemeral.
- **Save design** stores it as the host's `storageforge/v1` blueprint and rebuilds its graph, so reports and the graph pick up your tiers, protection, exports and planned links. A host that has never been scanned gets its graph from the design alone.
- **Refresh from latest scan** rebuilds the hardware from the newest scan and keeps what only you know. That means disk and pool tiers, encryption notes, protection rows (rows for things that disappeared stay listed), exports, manual links and remotes the scan didn't see.
- Unsaved edits are kept per host in the browser until you save. The built-in example host "atlas" still works signed out.

The graph header links to the planner, and a host node's **Open in planner** jumps straight to it. The planner is served under the same CSP, with one relaxation, `style-src-attr 'unsafe-inline'`, for its inline-sized bars. It uses system fonts, because web fonts are blocked by the CSP.

Scans cannot detect a btrfs RAID profile, so multi-device btrfs pools import as `single`. Set the real level in the planner before trusting its capacity and fault-tolerance numbers.

## Installing keys from the web UI

The **Keys** tab replaces the generate → copy → `authorized_keys` → bind steps:

1. **Generate** creates an ed25519 or RSA-4096 key inside the vault. The private half never leaves it.
2. **Install on a host** takes a host, port, user and that user's SSH password. It then:
   - logs in with the key through an ephemeral agent, and if that already works it skips the copy, so `authorized_keys` never gets a duplicate line;
   - otherwise runs `ssh-copy-id -f` with only the public key. The password reaches `ssh` through the `storageforge-askpass` helper's environment (`SSH_ASKPASS_REQUIRE=force`, no tty), never through argv or disk. Only one password attempt is made (`NumberOfPasswordPrompts=1`), and only password prompts are answered;
   - logs in with the key again to confirm it works, and then, if asked, adds a host binding for `scan` (and `checksum`).
3. **Scan now** on a binding queues a scan.

Host keys are trusted on first use into the same `known_hosts` that scans use. Every generate, install attempt and bind is audited with the signed-in user, and the password is never logged. Any signed-in user can do this; there are no roles yet.

The host must allow password login once for `ssh-copy-id`. Afterwards you can turn `PasswordAuthentication` off.

## Container files

| File | Purpose |
| :--- | :--- |
| `Dockerfile` | `build` stage (venv), `test` stage (runs the suite: `docker build --target test .`), slim `runtime` with `openssh-client`, `sqlite3` and `tini`, uid 10001, `HEALTHCHECK` |
| `docker-compose.yml` | Hardened service, secrets, `sf-data` volume, tmpfs mounts, resource limits, loopback port |
| `docker/entrypoint.sh` | Refuses root, checks secret lengths, checks volume ownership and that the runtime dir is tmpfs, tightens permissions, migrates, creates or verifies the vault, imports keys from a read-only mount, then `exec`s |
| `docker/init-secrets.sh` | Generates the vault secret and session secret |
| `examples/demo/` | Disposable SSH target and an end-to-end script |

For PostgreSQL, build with `--build-arg EXTRAS=postgres` and set `STORAGEFORGE_DB=postgresql://…`. The PostgreSQL DDL is written but has not yet been run against a live server.

## Indexer architecture

```text
 target host (no agent)                         indexer
 ──────────────────────                         ───────
 ssh ControlMaster (one TCP session, multiplexed)
   ├─ inventory: hostname, os-release, lsblk -J, findmnt -J, zpool status, df
   ├─ find /       -xdev -prune(other mounts, excludes) -printf NUL-records ─► reader 1 ─┐ 20k-row batches
   ├─ find /home   …                                                         ─► reader 2 ─┤ bounded queues
   └─ find /mnt/x  …                                                         ─► reader N ─┘ (back-pressure)
                                                                                           │ routed by mount
                                                     writer pool ◄─────────────────────────┘
                                                     SQLite: 1 writer · PostgreSQL: up to 8 (one connection each)
                                                       stage rows (executemany / COPY) → index stage
                                                       → diff vs file_records → apply + FTS + change log
                                                       → commit (one transaction per mount)
```

| Module | Role |
| :--- | :--- |
| `remote.py` | SSH wrapper (`BatchMode`, `ControlMaster`, `accept-new` host keys, always `sh -c` so fish/csh login shells are fine), inventory probe, `find` builder |
| `stream.py` | NUL-record streaming parser; non-UTF-8 names stay searchable as `\xNN` escapes |
| `scanner.py` | Mount planning, parallel reader threads, writer pool, checksum pass |
| `db.py` | Migrations, staging, set-based diff, dialect helpers |
| `search.py` | Pattern classification and query builder |
| `payloads.py`, `analysis.py`, `report.py`, `capacity.py` | Report inputs, checks, Markdown renderer, pool and power math |

### Guardrails

| Risk | How it is handled |
| :--- | :--- |
| Pseudo filesystems | `proc`, `sysfs`, `devtmpfs`, `cgroup*`, `overlay`, `squashfs`, `autofs` and similar mounts are skipped. `/proc`, `/sys`, `/dev` and `/run` are pruned by path too. |
| Noise directories | `.git`, `node_modules`, `.Trash*`, `__pycache__`, `.snapshots` and `.zfs` are pruned by name. Add your own with `--exclude-name` and `--exclude-path`. |
| Symlink loops | `find -P` never follows symlinks, so a loop is recorded as two links rather than walked. Reports flag loops explicitly (ELOOP). |
| Bind mounts and recursive binds | Mounts sharing a `maj:min` whose `fs_root` nests inside an already planned mount are recorded as `bind-alias` and not walked twice. Every other mount point below a walk root is pruned, which also stops `-xdev` from descending into same-device binds. |
| Network mounts | NFS, SMB, rclone, sshfs and similar mounts are skipped by default (index them on their source host). Use `--include-network` to walk them. Automount points are never triggered. |
| Partial or failed walks | ssh exit 255, a truncated record stream, or `find` exiting 1 with no output aborts that mount's diff, so nothing is deleted. Unreadable directories (`find` exit 1 with output) are counted and reported. |
| Mass deletion | If more than `--max-delete-ratio` (default 50%) of a mount's 1,000+ entries vanish, the diff is refused and the index is left intact. |
| Subtree scans | `--path /srv/data` diffs only that subtree. Deletions are scoped to it, so siblings are never removed. |
| Load on the target | `find` and `sha256sum` run under `nice -n 10` and `ionice -c3` when available. Disable with `--no-nice`. |

### Incremental sync

Rows are keyed by `(mount_id, parent_path, filename)`. After a walk is staged, three set operations run in one transaction:

1. **Deleted:** indexed rows (in scope) missing from the walk. They are logged to `file_changes`, removed from FTS and deleted.
2. **Modified:** same key, different size, mtime, mode, owner, symlink target or type. The checksum is cleared when content may have changed.
3. **Added:** new keys are inserted with `first_seen_scan_id` set, and FTS is updated.

Added entries are logged only after a mount's first scan, so the first index does not write a million-row change log. Directory mtime changes update the row but are not logged as modifications.

## Schema

The full DDL is in `storageforge_index/migrations/{sqlite,postgres}/`: `001_initial.sql` for the indexer, and [`002_vault_audit_graph.sql`](storageforge_index/migrations/sqlite/002_vault_audit_graph.sql) for `vault_meta`, `ssh_keys`, `key_bindings`, `audit_log`, `graph_nodes`, `graph_edges`, `blueprints` and `scan_jobs`. The CLI applies migrations automatically; each file also runs on its own with `sqlite3` or `psql`.

| Table | Purpose |
| :--- | :--- |
| `hosts` | `host_id`, `hostname`, `ip_address`, `os_info`, `last_scanned_at`, plus the SSH target used and the last inventory (`lsblk`, `zpool status`, `findmnt`, `df`) as JSON |
| `mounts` | `mount_id`, `host_id`, `mount_point`, `filesystem_type`, `total_bytes`, `used_bytes`, plus source, options, `maj:min`, `fs_root`, scan state (`indexed`, `skipped`, `bind-alias`, `gone`) and skip reason |
| `file_records` | `file_id`, `mount_id`, `parent_path`, `filename`, `extension`, `file_size_bytes`, `is_directory`, `is_symlink`, `symlink_target`, `mode_permissions`, `owner_uid`, `group_gid`, `modified_at`, `checksum_hash` |
| `scans`, `file_changes` | Scan history and per-scan added, modified and deleted entries |
| `file_fts` (SQLite) | FTS5 external-content table with the trigram tokenizer over `filename` |
| `v_files` | View with `hostname`, `mount_point` and `full_path` for ad-hoc SQL |

Indexes include `(filename)`, `(parent_path)`, `(file_size_bytes)`, `(extension, file_size_bytes)`, `(modified_at)` and a partial index on `checksum_hash`. PostgreSQL adds `lower(filename)`, `pg_trgm` GIN indexes on `filename` and `parent_path`, and `text_pattern_ops` on `parent_path` for prefix queries under any collation.

### How a pattern is answered

| Pattern | SQLite | PostgreSQL |
| :--- | :--- | :--- |
| `*.cr2` | `extension = 'cr2'` (B-tree, with size from the same index) | same |
| `report.pdf` | `filename = … COLLATE NOCASE` | `lower(filename) = lower(…)` |
| `IMG_2019*` | `filename LIKE 'IMG_2019%'` (B-tree prefix range) | `filename ~* '^IMG_2019.*$'` (trigram GIN) |
| `*raw*2019*` | FTS5 trigram `LIKE` for candidates, then exact `GLOB` | `filename ~* …` (trigram GIN) |
| `--under /mnt/x` | `parent_path` B-tree range | `parent_path LIKE '/mnt/x/%'` (`text_pattern_ops`) |

## Measured performance

These numbers come from a local scan (no SSH hop) of `/usr` with a warm page cache: 1,172,684 entries totalling 23.3 GiB, on SQLite 3.54, Python 3.14 and NVMe.

| Step | Time |
| :--- | ---: |
| Remote walk and parse (stream) | 5.2 s (225k entries/s) |
| First index, total (stage, insert, FTS, commit) | 18.0 s |
| Rescan with no changes (walk and full diff) | 8.3 s |
| `search "*.so"` (7,604 hits) | 26 ms |
| `search "*python3*config*"` (trigram) | 3 ms |
| `search --path-contains …` (full parent_path scan, no match) | 78 ms |
| Index size | 459 MiB (≈ 410 bytes per entry, including indexes and FTS) |

Over SSH, throughput is usually bound by the remote disk walk and the link. One multiplexed connection with four parallel `find` streams keeps several mounts busy at once.

## Reports

`export-markdown` and `report` render the **StorageForge Architecture Report** with these sections:

1. Executive summary: identity, capacity (raw, usable, allocated, free) in TiB and TB, key findings, ASCII topology map
2. Node and disk inventory: drives, partition layout with alignment, pools and arrays, datasets, filesystems and mount flags with fstab identifiers
3. Symlink and bind-mount hierarchy: health checks and boot-order stages
4. 3-2-1 protection matrix, using the StorageForge dashboard rules
5. Economics: parity and reserve overhead, power and thermal budget

YAML front matter carries the headline numbers so other tools can parse the report. See [`reports/atlas-architecture-report.md`](reports/atlas-architecture-report.md), generated from [`examples/atlas`](examples/atlas).

## Tests

```bash
python3 -m unittest discover -s tests -v
```

`tests/test_platform.py` covers vault round trips, wrong-secret refusal, tampered and swapped ciphertexts, rotation, binding specificity, the audit chain under tampering, loading a key into a real ephemeral `ssh-agent`, graph building, `.canvas` validity (including no overlapping cards), and the HTTP API with auth and CSP. `tests/test_indexer.py` covers units and patterns, the stream parser (newlines in names, truncation, tiny reads), pool math against the dashboard, mount planning (bind aliases, pruning), payload parsers, report generation, and real local scans: incremental diff, subtree safety and the mass-delete guard. The PostgreSQL code path has not been run against a live server yet.
