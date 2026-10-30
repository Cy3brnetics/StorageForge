---
id: GM-25
status: open
severity: low
effort: S
area: "[[Scanner, Database and Analytics]]"
tags: [finding, concurrency, cache, backup, db, gemini-audit]
found: 2026-10-29
---
# GM-25 Thread-safety races in folder_cache, backup.create, and SQLite nested tx

## Location
- `storageforge_index/server.py:326-331, 527-538, 1167-1191` (`folder_cache`, `api_login()`, `api_logout()`)
- `storageforge_index/backup.py:51-86` (`create()`)
- `storageforge_index/db.py:83-96` (`Conn.tx()`)

## Mechanics & Root Cause
1. **`folder_cache` Stale Poisoning & Race Condition (`server.py:1167-1191`)**:
   ```python
   folder_cache: dict = {}

   @web.get('/api/folders/cold')
   @login_required
   def api_folders_cold():
       host = request.args.get('host') or None
       years = arg_num('years', 2.0, 0.1, 100.0, float)
       min_size = parse_size(request.args.get('min_size') or '1GiB')
       key = ('cold', host, years, min_size, conn().scalar('SELECT max(scan_id) FROM scans'))
       if key not in folder_cache:
           folder_cache.clear()
           folder_cache[key] = folders.cold_folders(conn(), host, years, min_size, limit=200)
       return jsonify(folder_cache[key])
   ```
   - `api_folders_cold` and `api_folder_dupes` key `folder_cache` on `conn().scalar('SELECT max(scan_id) FROM scans')`. Because `db.begin_scan()` inserts a new row into `scans` with `status='running'` at the **start** of a scan (before `apply_diff` commits new files), querying `/api/folders/cold` or `/api/folders/duplicates` while a scan is running caches the **old** index state under the **new** `scan_id`. Once the scan finishes, `max(scan_id)` does not change, serving stale results until the next scan!
   - Furthermore, both routes share a single `folder_cache` dict and call `folder_cache.clear()` without a lock before assigning `folder_cache[key] = ...` and returning `folder_cache[key]`. Because `checks.js:121` calls `/api/folders/cold` and `/api/folders/duplicates` concurrently via `Promise.all(...)`, they evict each other and can raise `KeyError` under concurrent Waitress threads.
2. **`backup.create()` Same-Second Filename Collision (`backup.py:51-86`)**:
   - `stamp = dt.datetime.now().strftime('%Y%m%d-%H%M%S')` uses 1-second resolution without a lock. Two concurrent calls to `POST /api/backups` (or a manual backup coinciding with `nightly_once`) write to the same `.db.part` file simultaneously.
3. **Nested `with conn.tx():` Fails on SQLite (`db.py:83-96`)**:
   - On PostgreSQL, `with self.raw.transaction():` supports nested transactions via `SAVEPOINT`. On SQLite (`isolation_level=None`), `Conn.tx()` unconditionally executes `self.raw.execute('BEGIN IMMEDIATE')`, so any nested `with conn.tx():` raises `sqlite3.OperationalError: cannot start a transaction within a transaction`.
4. **Session Cookie Permanence & Server-Side `auth_at` (`server.py:326-331, 527-538`)**:
   - `api_login()` never sets `session.permanent = True`, so Flask's `PERMANENT_SESSION_LIFETIME` is not applied as a `Max-Age` attribute on the `Set-Cookie` header, and `auth_at` is stored only in the signed client cookie rather than in `web_sessions`.

## Impact
Stale folder cleanup caches after scans, `KeyError` or `.db.part` collisions under concurrent requests, and `OperationalError` if any helper nests `conn.tx()` on SQLite.

## Remediation
1. Key `folder_cache` on `SELECT max(scan_id) FROM scans WHERE status <> 'running'`, keep up to N entries instead of `.clear()`, and guard with a `threading.Lock`.
2. Guard `backup.create()` with a lock (or unique temp file name), and support `SAVEPOINT` nesting in `Conn.tx()` on SQLite when `self.raw.in_transaction` is true.
3. Set `session.permanent = True` in `api_login()` and require `json_body()` on `POST /api/logout`.

## Done when
- [ ] Concurrent requests to `/api/folders/*` and `/api/backups` are thread-safe and cache invalidation tracks completed scans (`status <> 'running'`).
