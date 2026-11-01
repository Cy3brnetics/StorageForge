# Database

StorageForge runs on SQLite (default; WAL, FTS5 trigram) or PostgreSQL (`COPY`, `pg_trgm`). SQL is written once with `:named` parameters and the PostgreSQL connection rewrites them; the few dialect differences (timestamps, `IS DISTINCT FROM`, JSONB, full-text upkeep) go through helpers in `db.py`.

## Migrations

The DDL is in `storageforge_index/migrations/{sqlite,postgres}/`. The CLI and the container entrypoint apply new ones automatically (`storageforge-index migrate`), and each file also runs on its own with `sqlite3` or `psql`. `schema_version` records what is applied.

| Migration | Adds |
| :--- | :--- |
| `001_initial` | `hosts`, `mounts`, `scans`, `file_records`, `file_fts`, `file_changes`, `v_files` |
| `002_vault_audit_graph` | `vault_meta`, `ssh_keys`, `key_bindings`, `audit_log`, `graph_nodes`, `graph_edges`, `blueprints`, `scan_jobs` |
| `003_users` | `users` |
| `004_scan_denied` | `scan_denied` (unreadable folders) |
| `005_edge_owner` | which design owns a graph edge |
| `006_move_plans` | `move_plans` |
| `007_git_repos` | `git_repos` |
| `008_docker` | `docker_hosts` |
| `009_change_plans` | `change_plans` |
| `010_deployments` | `deploy_access`, `deploy_runs`, `deployed`, `jobs`, `job_runs`, `alerts`, `settings` |
| `011_storage_tasks` | `storage_tasks` |
| `012_directories` | `directories`; `file_records` rewritten to point at it by `dir_id` |
| `013_web_sessions` | `web_sessions` (server-side sessions, hashed ids) |
| `014_host_identity` | host key and machine-id pinning on `hosts` |
| `015_host_key_confirmations` | `host_key_confirmations` *(in progress)* |
| `027_key_origin` | where each vault key came from: `generated`, `imported` or `unknown` |

## The index

| Table | Purpose |
| :--- | :--- |
| `hosts` | `hostname`, `ip_address`, `os_info`, `last_scanned_at`, the SSH target used, pinned identity, and the last inventory (`lsblk`, `zpool status`, `findmnt`, `df`) as JSON |
| `mounts` | per host: mount point, type, size and use, source, options, `maj:min`, `fs_root`, scan state (`indexed`, `skipped`, `bind-alias`, `gone`) and skip reason |
| `directories` | `dir_id`, `mount_id`, `path`: each folder once, so file rows don't repeat it |
| `file_records` | `mount_id`, `dir_id`, `filename`, `extension`, size, type flags, symlink target, mode, owner, group, mtime, `checksum_hash`, `first_seen_scan_id` |
| `scans`, `file_changes` | scan history, and per-scan added, modified and deleted entries |
| `file_fts` (SQLite) | FTS5 external-content table, trigram tokenizer over `filename` |
| `v_files` | view with `hostname`, `mount_point`, `parent_path` and `full_path` for ad-hoc SQL |

Indexes include `UNIQUE (dir_id, filename)`, `(filename)`, `(file_size_bytes)`, `(extension, file_size_bytes)`, `(modified_at)`, `(mount_id, first_seen_scan_id)`, a partial index on `checksum_hash`, and `directories (path)`. PostgreSQL adds `lower(filename)`, `pg_trgm` GIN indexes on `filename` and `directories.path`, and `text_pattern_ops` on `directories.path`. How searches use them is in [Scanning and search](scanning-and-search.md#search).

```sql
-- the 20 largest files on one host
SELECT full_path, file_size_bytes FROM v_files WHERE hostname = 'nas-02' ORDER BY file_size_bytes DESC LIMIT 20;
```

## Everything else

| Table | Purpose |
| :--- | :--- |
| `vault_meta`, `ssh_keys`, `key_bindings` | the encrypted vault, keys and host bindings |
| `audit_log` | the append-only, HMAC-chained log; triggers refuse `UPDATE` and `DELETE` |
| `users`, `web_sessions` | accounts and server-side sessions |
| `blueprints` | one saved design per host (`storageforge/v1`) |
| `graph_nodes`, `graph_edges` | the graph, rebuilt per host after each scan or design save |
| `scan_jobs` | queued, running and finished scans from the web UI and scheduler |
| `scan_denied`, `git_repos`, `docker_hosts` | what scans found besides files |
| `change_plans`, `move_plans`, `storage_tasks` | saved plans |
| `deploy_access`, `deploy_runs`, `deployed` | hosts set up for deploys, run history and output, what is deployed where with its hash |
| `jobs`, `job_runs` | deployed move steps (token hashes, not tokens) and their runs |
| `alerts`, `settings` | open problems; key/value settings (report URL, alert channels, planner options) |

The PostgreSQL DDL mirrors SQLite's; the test suite runs against both (`STORAGEFORGE_TEST_PG`, see operations).
