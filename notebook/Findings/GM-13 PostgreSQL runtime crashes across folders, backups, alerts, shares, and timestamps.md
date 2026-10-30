---
id: GM-13
status: open
severity: high
effort: M
area: "[[Scanner, Database and Analytics]]"
tags: [finding, database, postgres, crashes, gemini-audit]
found: 2026-10-29
---
# GM-13 PostgreSQL runtime crashes across folders, backups, alerts, shares, and timestamps

## Location
- `storageforge_index/server.py:579-585, 1157-1165, 1199-1204`
- `storageforge_index/backup.py:41-44` (`_sqlite_path()`)
- `storageforge_index/folders.py:37-39, 107-116` (`duplicate_folders()`, `cold_folders()`)
- `storageforge_index/alerts.py:171-172` (`drift()`)
- `storageforge_index/shares.py:107` (`id_check()`)
- `storageforge_index/access.py:79-91` (`status()`)
- `storageforge_index/migrations/postgres/001_initial.sql:25, 26, 74`

## Mechanics & Root Cause
Because PostgreSQL is not exercised in automated tests (`EQ-01`), five distinct runtime crashes and type mismatches exist when running against `STORAGEFORGE_DB=postgresql://...`:

1. **Uncaught `SystemExit` in `POST /api/backups` (`server.py:1157-1165`, `backup.py:41-44`)**:
   ```python
   # backup.py:41-44
   def _sqlite_path(db: Database) -> str:
       if db.dialect != 'sqlite':
           raise SystemExit('backups of a PostgreSQL database are pg_dump\'s job: pg_dump -Fc storageforge > storageforge.dump')
       return db.path
   ```
   - Unlike `GET /api/backups` (`server.py:1154`, which checks `if db.dialect == 'sqlite'`) and `nightly_once()` (`server.py:274`, which catches `(Exception, SystemExit)`), `POST /api/backups` (`server.py:1163`) calls `backup.create(db, ...)` unconditionally.
   - Because `SystemExit` inherits from `BaseException` rather than `Exception`, Flask's `@web.errorhandler(Exception)` (`server.py:393`) does not catch it, terminating the Waitress worker/server!
2. **`UndefinedFunction: operator does not exist: boolean = integer` in `folders.py:39, 109`**:
   ```python
   # folders.py:37-39 & 107-109
   cur = conn.execute(f"""SELECT f.mount_id, d.path, f.filename, f.file_size_bytes, f.is_directory
                          FROM file_records f JOIN directories d ON d.dir_id = f.dir_id JOIN mounts m ON m.mount_id = f.mount_id JOIN hosts h ON h.host_id = m.host_id
                          WHERE f.is_symlink = 0 AND m.scan_state = 'indexed' {hsql}""", {'host': host})
   ```
   - In `migrations/postgres/001_initial.sql:74`, `file_records.is_symlink` is `BOOLEAN` (unlike SQLite where `0`/`1` is `INTEGER`), causing PostgreSQL to reject `WHERE f.is_symlink = 0` with `operator does not exist: boolean = integer`.
3. **`TypeError: '>' not supported between instances of 'datetime.datetime' and 'int'` in `folders.py:116`**:
   ```python
   # folders.py:115-116
   acc = tree.setdefault((mid, parent), [0, 0, 0])
   acc[0] = max(acc[0], mtime or 0)
   ```
   - `cold_folders()` selects `f.modified_at` (`TIMESTAMPTZ` in PostgreSQL, returned by `psycopg` as `datetime.datetime`) without `epoch()` and compares it against `acc[0]` (initialized to `0`) and `cutoff` (`float`).
4. **`TypeError: the JSON object must be str, bytes or bytearray, not dict` in `alerts.py:172` and `shares.py:107`**:
   - In PostgreSQL, `hosts.inventory_json` is `JSONB`, which `psycopg` automatically deserializes into a Python `dict`.
   - Unlike `access.py:85` (`inv if isinstance(inv, dict) else json.loads(inv or '{}')`), `alerts.py:172` (`json.loads(inv or '{}')`) and `shares.py:107` (`json.loads(conn.scalar('SELECT inventory_json FROM hosts WHERE host_id = :h', {'h': h['id']}) or '{}')`) call `json.loads()` unconditionally.
5. **Unconverted `TIMESTAMPTZ` (`datetime.datetime`) in API Responses (`server.py:584, 1200`, `access.py:90`)**:
   - `GET /api/hosts` (`last_scanned_at`), `GET /api/planner/hosts` (`last_scanned_at`), and `GET /api/access` (`finished_at`) pass raw `TIMESTAMPTZ` columns to `jsonify()`, which Flask serializes as RFC 2822 strings (`"Thu, 29 Oct 2026 ..."`), breaking frontend epoch arithmetic (`h.last_scanned_at * 1000 -> NaN`).

## Impact
On PostgreSQL deployments, the Cleanup tab (`/api/folders/cold`, `/api/folders/duplicates`), Alerts evaluation (`alerts.drift`), Shares check (`shares.check`), and Backup creation (`POST /api/backups`) all crash with unhandled exceptions or `SystemExit`, and host scan timestamps fail to parse in the UI.

## Remediation
1. Change `raise SystemExit(...)` in `backup._sqlite_path()` to `raise ValueError(...)` and guard `POST /api/backups` when `db.dialect != 'sqlite'`.
2. In `folders.py:39, 109`, change `WHERE f.is_symlink = 0` to `WHERE NOT f.is_symlink`, and wrap `mtime` in `epoch(mtime)` at line 116.
3. In `alerts.py:172` and `shares.py:107`, check `inv if isinstance(inv, dict) else json.loads(inv or '{}')`.
4. Wrap `last_scanned_at` and `finished_at` in `epoch(...)` in `server.py:584, 1200` and `access.py:90`.

## Done when
- [ ] All five PostgreSQL incompatibilities are resolved and tested against PostgreSQL in CI.
