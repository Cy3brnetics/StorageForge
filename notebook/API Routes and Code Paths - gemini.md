---
date: 2026-10-29
tags: [audit, api, routes, code-paths, gemini-audit]
---
# API Routes and Code Paths - gemini

Complete inventory and security/code-path matrix of all **85 HTTP routes** in `storageforge_index/server.py` (`serve()`), their authentication and re-authentication decorators, request body size limits, synchronous vs. background execution profile, and downstream module code paths.

## Global Request Pipeline (`server.py:310-570`)

1. **`ProxyFix` (`server.py:321-322`)**: Enabled when `STORAGEFORGE_PROXY_HOPS > 0` (`x_for=proxy_hops, x_proto=proxy_hops`). Trusts `X-Forwarded-For` from any peer connecting to port `8080` (see [[GM-17 Proxy header spoofing on shared Docker networks and broken multi-hop X-Forwarded-For|GM-17]]).
2. **`enforce_request_size()` (`@web.before_request`, `server.py:451-458`)**:
   - Default max request body: `MAX_BODY = 64 * 1024` (64 KiB).
   - Planner max request body (`request.path.startswith('/api/planner/')`): `MAX_PLANNER_BODY = 2 * 1024 * 1024` (2 MiB).
3. **`security_headers()` (`@web.after_request`, `server.py:460-478`)**:
   - Sets `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'`.
   - Sets `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: same-origin`, `Cache-Control: no-store` (for `/api/` and `/login`).
4. **Authentication & Re-Confirmation (`server.py:345-380`)**:
   - `@login_required` (Flask-Login): Verifies `sf_session` cookie and checks `users.load_session(conn(), session.get('sid'))` against `web_sessions`.
   - `@password_confirmed`: Checks `not password_stale()` (`time.time() - session.get('auth_at', 0) <= 600` seconds). Returns `403 {"error": "Confirm your password to continue", "reauth": true}` when stale.

---

## Complete Route Matrix (85 Endpoints)

### 1. Public / Unauthenticated Routes (3)

| Method & Route | Line | Auth | Rate Limit | Execution & Downstream Code Path | Audit Notes |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `GET /healthz` | `:573` | None | `@limiter.exempt` | `SELECT 1` -> `{"status": "ok"}` | Starves if all 8 Waitress threads block ([[GM-12 Waitress 8-thread pool exhaustion via synchronous 6-hour restore and deploy endpoints\|GM-12]]) |
| `GET /login` | `:499` | None | `@limiter.exempt` | Redirects to `/` if authenticated; serves `static/login.html` | Safe |
| `POST /api/login` | `:513` | None | `10/m;50/h` IP, `5/m;20/h` IP+/24, `100/d` user | `users.authenticate()` -> `users.begin_session()` -> `audit('auth.login')` | Global 24h user lockout & `audit_log` DoS ([[GM-19 Global account lockout DoS and unauthenticated audit_log flooding on login\|GM-19]]) |

### 2. Machine-Signed Callback Route (1)

| Method & Route | Line | Auth | Rate Limit | Execution & Downstream Code Path | Audit Notes |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `POST /api/jobs/report` | `:1134` | Ed25519 / HMAC token (`jobs.verify_report`) | `120 per minute` per IP | `jobs.record_report()` -> `alerts.evaluate(db)` -> `audit('job.report')` | Verifies per-host token derived from `storageforge-signing` + `machine_id` |

### 3. Session & UI Shell Routes (5)

| Method & Route | Line | Auth | `@password_confirmed` | Execution & Downstream Code Path | Audit Notes |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `POST /api/logout` | `:533` | `@login_required` | No | `users.end_session()` -> `session.clear()` | Does not call `json_body()` ([[GM-25 Thread-safety races in folder_cache, backup.create, Vault._UNLOCKED, and SQLite nested tx\|GM-25]]) |
| `POST /api/auth/confirm` | `:541` | `@login_required` | N/A (sets `auth_at`) | Rate-limited (`10/m;50/h` IP, `5/m;20/h` user); `users.verify_password()` -> `session['auth_at'] = time()` | Sets client cookie `auth_at` |
| `GET /api/me` | `:552` | `@login_required` | No | Returns `{username, confirmed_for}` | Safe |
| `GET /` | `:560` | `@login_required` | No | Serves `static/index.html` | Safe |
| `GET /planner` | `:565` | `@login_required` | No | Serves `static/planner.html` | Safe |

### 4. Host Index, Graph, Search, Duplicates & Reports Routes (13)

| Method & Route | Line | Auth | `@password_confirmed` | Execution & Downstream Code Path | Audit Notes |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `GET /api/hosts` | `:579` | `@login_required` | No | Queries `hosts` + `mounts`, `v.bindings()`, `app.jobs` | Raw `last_scanned_at` breaks PG ([[GM-13 PostgreSQL runtime crashes across folders, backups, alerts, shares, and timestamps\|GM-13]]) |
| `GET /api/graph` | `:590` | `@login_required` | No | `graph.load(conn(), host)` | Safe |
| `GET /api/canvas` | `:595` | `@login_required` | No | `canvas.dumps(graph.load(...))` | Safe |
| `GET /api/audit` | `:602` | `@login_required` | No | `AuditLog(db, conn(), None).tail(limit)` | Safe |
| `GET /api/audit/verify` | `:608` | `@login_required` | No | `Vault.unlock()` -> `AuditLog.verify()` + `unkeyed()` | Safe |
| `POST /api/scan` | `:625` | `@login_required` | **No** | Enqueues background scan in `app.start_scan(host, opts)` | Un-rate-limited, no `@password_confirmed` ([[GM-11 Missing password confirmation on remote execution and security-critical routes\|GM-11]]) |
| `GET /api/jobs` | `:648` | `@login_required` | No | Returns in-memory `app.jobs` scan job list | Polled every 2.5s by UI while scanning |
| `GET /api/search` | `:704` | `@login_required` | No | `search.run_search(db, conn(), q)` | Unhandled PG regex error on bad `[...]` ([[GM-23 Inventory section parser collisions, missing mountinfo superblock options, and capacity edge cases\|GM-23]]) |
| `GET /api/duplicates` | `:723` | `@login_required` | No | `search.run_dupes(conn(), host, min_size, limit)` | Inner query ignores `host` filter ([[GM-23 Inventory section parser collisions, missing mountinfo superblock options, and capacity edge cases\|GM-23]]) |
| `GET /api/changes` | `:731` | `@login_required` | No | `search.run_changes(conn(), host, scan_id, limit)` | Safe |
| `GET /api/report` | `:741` | `@login_required` | No | `payloads.node_from_index()` -> `report.render_report()` | Safe (`html.escape` used throughout) |
| `GET /api/folders/duplicates` | `:1169` | `@login_required` | No | `folders.duplicate_folders()` via `folder_cache` | PG crash (`is_symlink = 0`, [[GM-13 PostgreSQL runtime crashes across folders, backups, alerts, shares, and timestamps\|GM-13]]); cache race ([[GM-25 Thread-safety races in folder_cache, backup.create, Vault._UNLOCKED, and SQLite nested tx\|GM-25]]) |
| `GET /api/folders/cold` | `:1181` | `@login_required` | No | `folders.cold_folders()` via `folder_cache` | PG crash (`is_symlink = 0` & `mtime`, [[GM-13 PostgreSQL runtime crashes across folders, backups, alerts, shares, and timestamps\|GM-13]]); cache race ([[GM-25 Thread-safety races in folder_cache, backup.create, Vault._UNLOCKED, and SQLite nested tx\|GM-25]]) |

### 5. Vault Keys, Host Keys & Scan Access Routes (10)

| Method & Route | Line | Auth | `@password_confirmed` | Execution & Downstream Code Path | Audit Notes |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `GET /api/keys` | `:653` | `@login_required` | No | `v.list_keys()` + `v.bindings()` | Safe |
| `GET /api/keys/<name>/pubkey` | `:659` | `@login_required` | No | `v.public_key(name)` | Safe |
| `POST /api/keys` | `:665` | `@login_required` | **No** | `v.generate_key(name, ktype, comment)` | Mutates vault without `@password_confirmed` ([[GM-11 Missing password confirmation on remote execution and security-critical routes\|GM-11]]) |
| `POST /api/keys/install` | `:674` | `@login_required` | **Yes** | Sync SSH (up to 60s): `key_login_works()` -> `require_confirmed()` -> `install_public_key()` -> `v.bind()` | **Polls with `accept-new` BEFORE `require_confirmed`!** ([[GM-04 Key install probes host with accept-new before host key confirmation\|GM-04]]) |
| `POST /api/hostkey/confirm` | `:696` | `@login_required` | **No** | `hostkeys.confirm(conn(), host, port, fp)` | Trusts SSH host key without `@password_confirmed` ([[GM-11 Missing password confirmation on remote execution and security-critical routes\|GM-11]]) |
| `GET /api/access` | `:740` | `@login_required` | No | `access.status(conn(), host, limit)` | Raw `finished_at` on PG ([[GM-13 PostgreSQL runtime crashes across folders, backups, alerts, shares, and timestamps\|GM-13]]) |
| `GET /api/access/script` | `:745` | `@login_required` | No | `access.setup_script()` / `access.remove_script()` | Safe |
| `POST /api/access/grant` | `:750` | `@login_required` | **Yes** | Sync SSH (up to 60s): `access.grant()` -> `sudo_run()` | Hardcodes port `22` in `validate()` ([[GM-20 Deploy enroll and sudo_run fail without existing scan key binding or on non-default SSH ports\|GM-20]]) |
| `POST /api/access/revoke` | `:761` | `@login_required` | **Yes** | Sync SSH (up to 60s): `access.revoke()` -> `sudo_run()` | Hardcodes port `22` in `validate()` ([[GM-20 Deploy enroll and sudo_run fail without existing scan key binding or on non-default SSH ports\|GM-20]]) |
| `GET /api/fs/browse` | `:835` | `@login_required` | No | `fsmap.browse(conn(), host, path)` | Safe (index-only) |

### 6. Plans (Moves, Changes, Shares, Tasks), Docker & Git Routes (31)

| Method & Route | Line | Auth | `@password_confirmed` | Execution & Downstream Code Path | Audit Notes |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `GET /api/moves/hosts` | `:772` | `@login_required` | No | `moves.hosts(conn())` | Safe |
| `GET /api/moves/size` | `:777` | `@login_required` | No | `moves.folder_size(conn(), host, path)` | Safe |
| `POST /api/moves/check` | `:782` | `@login_required` | No | `moves.check(conn(), json_body())` | Safe |
| `POST /api/moves/script` | `:787` | `@login_required` | No | `moves.script(conn(), json_body())` | Embeds `scriptkit.PREAMBLE` ([[GM-02 Remote command injection in scriptkit host relay\|GM-02]], [[GM-21 Move plan verify_step ignores rsync exit code and shares fstab preservation triggers false drift\|GM-21]]) |
| `GET /api/moves` | `:792` | `@login_required` | No | `moves.list_plans(conn())` | Safe |
| `POST /api/moves` | `:797` | `@login_required` | No | `moves.save_plan(conn(), json_body(), actor)` | Safe |
| `GET /api/moves/<pid>` | `:804` | `@login_required` | No | `moves.get_plan(conn(), pid)` | Safe |
| `PUT /api/moves/<pid>` | `:809` | `@login_required` | No | `moves.save_plan(conn(), json_body(), actor, pid)` | Safe |
| `DELETE /api/moves/<pid>` | `:816` | `@login_required` | **Yes** | `moves.delete_plan(conn(), pid)` | Safe |
| `GET /api/moves/<pid>/script` | `:823` | `@login_required` | No | Returns downloadable `.sh` script | Embeds `scriptkit.PREAMBLE` ([[GM-02 Remote command injection in scriptkit host relay\|GM-02]]) |
| `GET /api/git` | `:830` | `@login_required` | No | `gitrepos.listing(conn(), host)` | Safe |
| `GET /api/shares` | `:842` | `@login_required` | No | `shares.overview(conn(), host)` | Crashes on PG in `_uid_warnings` (`json.loads(dict)`, [[GM-13 PostgreSQL runtime crashes across folders, backups, alerts, shares, and timestamps\|GM-13]]) |
| `POST /api/shares` | `:847` | `@login_required` | No | `shares.save_share(conn(), ...)` | Safe |
| `DELETE /api/shares` | `:855` | `@login_required` | No | `shares.delete_share(conn(), ...)` | Destructive delete lacks `@password_confirmed` |
| `POST /api/shares/script` | `:863` | `@login_required` | No | `shares.script(conn(), host)` | Preserved fstab line triggers false drift ([[GM-21 Move plan verify_step ignores rsync exit code and shares fstab preservation triggers false drift\|GM-21]]) |
| `GET /api/shares/<host>/script` | `:869` | `@login_required` | No | Downloadable shares `.sh` script | Same as above |
| `GET /api/tasks` | `:876` | `@login_required` | No | `tasks.overview(conn(), host)` | Safe |
| `POST /api/tasks/check` | `:881` | `@login_required` | No | `tasks.check_one(conn(), json_body())` | `HOST_RE` allows leading `-` ([[GM-08 Leading-hyphen hostnames allow rsync and ssh option injection in tasks and remote\|GM-08]]) |
| `POST /api/tasks` | `:886` | `@login_required` | No | `tasks.save_task(conn(), json_body(), actor)` | `HOST_RE` allows leading `-` ([[GM-08 Leading-hyphen hostnames allow rsync and ssh option injection in tasks and remote\|GM-08]]) |
| `PUT /api/tasks/<tid>` | `:893` | `@login_required` | No | `tasks.save_task(conn(), json_body(), actor, tid)` | Same as above |
| `DELETE /api/tasks/<tid>` | `:900` | `@login_required` | **Yes** | `tasks.delete_task(conn(), tid)` | Safe |
| `GET /api/tasks/<tid>/script` | `:907` | `@login_required` | No | `tasks.script_for_id(conn(), tid)` | Safe |
| `GET /api/tasks/host/<host>/script` | `:915` | `@login_required` | No | `tasks.host_script(conn(), host)` | Safe |
| `GET /api/changes/types` | `:923` | `@login_required` | No | `changes.type_catalog()` | Safe |
| `POST /api/changes/check` | `:928` | `@login_required` | No | `changes.check(conn(), json_body())` | Safe |
| `POST /api/changes/script` | `:933` | `@login_required` | No | `changes.script(conn(), json_body())` | `owner_mode` group clobber & symlink issue ([[GM-09 Change plan perms task clobbers descendant groups and follows symlinks as root\|GM-09]]) |
| `POST /api/changes/ansible` | `:938` | `@login_required` | No | `changes.ansible(conn(), json_body())` | Safe |
| `GET /api/changes/plans` | `:943` | `@login_required` | No | `changes.list_plans(conn())` | Safe |
| `POST /api/changes/plans` | `:948` | `@login_required` | No | `changes.save_plan(conn(), json_body(), actor)` | Safe |
| `GET /api/changes/plans/<pid>` | `:955` | `@login_required` | No | `changes.get_plan(conn(), pid)` | Safe |
| `PUT /api/changes/plans/<pid>` | `:960` | `@login_required` | No | `changes.save_plan(conn(), json_body(), actor, pid)` | Safe |
| `DELETE /api/changes/plans/<pid>` | `:967` | `@login_required` | **Yes** | `changes.delete_plan(conn(), pid)` | Safe |
| `GET /api/changes/plans/<pid>/script` | `:974` | `@login_required` | No | Downloadable `.sh` change script | Same as `POST /api/changes/script` |
| `GET /api/changes/plans/<pid>/ansible` | `:981` | `@login_required` | No | Downloadable `.yml` playbook | Safe |
| `GET /api/docker` | `:988` | `@login_required` | No | `docker.listing(conn(), host)` | Safe |
| `GET /api/docker/usage` | `:993` | `@login_required` | No | `docker.users_of(conn(), host, path)` / `usage()` | Safe |

### 7. Deployments, Jobs, Snapshots, Alerts & Backups Routes (18)

| Method & Route | Line | Auth | `@password_confirmed` | Execution & Downstream Code Path | Audit Notes |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `GET /api/deploy` | `:999` | `@login_required` | No | `deploy.access()`, `deploy.list_runs()`, `jobs.overview()`, `alerts.list_alerts()`, `alerts.drift()` | Crashes on PG in `alerts.drift` ([[GM-13 PostgreSQL runtime crashes across folders, backups, alerts, shares, and timestamps\|GM-13]]) |
| `GET /api/deploy/setup-script` | `:1006` | `@login_required` | **No** | `deploy.setup_for_download()` / `remove_script()` | Mutates vault by generating signing+deploy keys on `GET`! ([[GM-11 Missing password confirmation on remote execution and security-critical routes\|GM-11]]) |
| `POST /api/deploy/access` | `:1012` | `@login_required` | **Yes** | Sync SSH: `deploy.enroll()` / `deploy.revoke()` | Fails without `'scan'` binding or non-22 port ([[GM-20 Deploy enroll and sudo_run fail without existing scan key binding or on non-default SSH ports\|GM-20]]) |
| `POST /api/deploy/adopt` | `:1023` | `@login_required` | **Yes** | Sync SSH (up to 1800s): `deploy.adopt()` | **No host validation; binds `*` / CIDR even on failure!** ([[GM-05 Deploy adopt lacks hostname validation and binds arbitrary vault patterns\|GM-05]]) |
| `POST /api/deploy/probe` | `:1030` | `@login_required` | **Yes** | Sync SSH: `deploy.probe()` | Blocks thread |
| `GET /api/deploy/runs/<rid>` | `:1036` | `@login_required` | No | `deploy.get_run(conn(), rid)` | Safe |
| `POST /api/deploy/moves/<pid>` | `:1044` | `@login_required` | **Yes** | Sync SSH (up to 1800s/step): `deploy.deploy_moves()` | Blocks Waitress thread ([[GM-12 Waitress 8-thread pool exhaustion via synchronous 6-hour restore and deploy endpoints\|GM-12]]) |
| `POST /api/deploy/changes/<pid>` | `:1054` | `@login_required` | **Yes** | Sync SSH (up to 1800s/host): `deploy.deploy_changes()` | Blocks Waitress thread ([[GM-12 Waitress 8-thread pool exhaustion via synchronous 6-hour restore and deploy endpoints\|GM-12]]) |
| `POST /api/deploy/shares` | `:1064` | `@login_required` | **Yes** | Sync SSH (up to 1800s/host): `deploy.deploy_shares()` | Blocks Waitress thread ([[GM-12 Waitress 8-thread pool exhaustion via synchronous 6-hour restore and deploy endpoints\|GM-12]]) |
| `POST /api/deploy/tasks` | `:1074` | `@login_required` | **Yes** | Sync SSH (up to 1800s/host): `deploy.deploy_tasks()` | **Prepends `RUNNER_UPDATE` without `#!`, breaking systemd `ExecStart`!** ([[GM-03 Deployed tasks fail under systemd with 203 EXEC due to missing shebang\|GM-03]]) |
| `POST /api/deploy/jobs` | `:1084` | `@login_required` | **Yes** | Sync SSH (up to 1800s): `jobs.deploy_from_protection()` | Emits `jobscript.py` with 4 bugs ([[GM-10 Four broken code paths in jobscript backup and snapshot execution\|GM-10]]) |
| `POST /api/deploy/jobs/<jid>/<verb>` | `:1093` | `@login_required` | **Only if `verb not in ('dryrun','log','snapshots')`** | Sync SSH (up to 600s): `jobs.action()` | `dryrun` executes root job without `@password_confirmed` ([[GM-11 Missing password confirmation on remote execution and security-critical routes\|GM-11]]) |
| `POST /api/deploy/jobs/<jid>/browse` | `:1105` | `@login_required` | **No** | Sync SSH: `jobs.browse()` as root on host | Root execution without `@password_confirmed` ([[GM-11 Missing password confirmation on remote execution and security-critical routes\|GM-11]]) |
| `POST /api/deploy/jobs/<jid>/restore` | `:1112` | `@login_required` | **Yes** | Sync SSH (**up to 6 hours!**): `jobs.restore()` | **Root `tar -xpf -` extracts device nodes!** ([[GM-01 Restore unpack as root allows device nodes and TOCTOU\|GM-01]], [[GM-12 Waitress 8-thread pool exhaustion via synchronous 6-hour restore and deploy endpoints\|GM-12]], [[GM-22 Cross-host restore drops pack error output, lacks runner lock, and leaves empty directories\|GM-22]]) |
| `GET /api/deploy/settings` | `:1121` | `@login_required` | No | `alerts.get_settings(conn(), masked=True)` | Safe |
| `PUT /api/deploy/settings` | `:1126` | `@login_required` | **No** | `alerts.save_settings(conn(), json_body())` | **Leaks masked tokens on URL change!** No `@password_confirmed` ([[GM-06 Alert settings leak secret tokens on URL change and allow SSRF via IPv4-mapped IPv6 and DNS rebinding\|GM-06]], [[GM-11 Missing password confirmation on remote execution and security-critical routes\|GM-11]]) |
| `POST /api/deploy/settings/test` | `:1135` | `@login_required` | **No** | `alerts.send_test(db, conn(), channel)` | **SSRF via `::ffff:127.0.0.1` & DNS rebinding!** ([[GM-06 Alert settings leak secret tokens on URL change and allow SSRF via IPv4-mapped IPv6 and DNS rebinding\|GM-06]]) |
| `POST /api/deploy/groups` | `:1242` | `@login_required` | **Yes** | Starts background thread `run_deploy_group` | Good async pattern (unlike single deploy/restore endpoints) |
| `GET /api/deploy/groups/<gid>` | `:1262` | `@login_required` | No | Polls in-memory `deploy_groups[gid]` | Safe |
| `GET /api/backups` | `:1150` | `@login_required` | No | `backup.listing()` | Safe |
| `POST /api/backups` | `:1157` | `@login_required` | **No** | `backup.create(db, ...)` | **Raises uncaught `SystemExit` on PostgreSQL!** Negative `keep` deletes backups ([[GM-13 PostgreSQL runtime crashes across folders, backups, alerts, shares, and timestamps\|GM-13]], [[GM-25 Thread-safety races in folder_cache, backup.create, Vault._UNLOCKED, and SQLite nested tx\|GM-25]]) |

### 8. Storage Architecture Planner Routes (4)

| Method & Route | Line | Auth | `@password_confirmed` | Execution & Downstream Code Path | Audit Notes |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `GET /api/planner/hosts` | `:1196` | `@login_required` | No | Queries `hosts` + `blueprints` | Raw `last_scanned_at` breaks PG ([[GM-13 PostgreSQL runtime crashes across folders, backups, alerts, shares, and timestamps\|GM-13]]) |
| `GET /api/planner/blueprint` | `:1204` | `@login_required` | No | `blueprint.from_index()` + `blueprint.merge_intent()` | Unescaped fields into `planner.js` `innerHTML` where `scrub()` is a no-op ([[GM-07 Planner scrub is a no-op and innerHTML sinks lack escaping\|GM-07]]) |
| `PUT /api/planner/design` | `:1221` | `@login_required` | No | `graph.store_blueprint()` -> `graph.rebuild_host()` | Calls `blueprint.check_text(bp)` |
| `POST /api/planner/changes` | `:1234` | `@login_required` | No | `fromdesign.plan()` -> `changes.check()` | Safe |

---

Back to [[Home]]
