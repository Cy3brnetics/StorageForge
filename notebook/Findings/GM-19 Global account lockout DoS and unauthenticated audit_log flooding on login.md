---
id: GM-19
status: open
severity: medium
effort: S
area: "[[API, Auth and Security]]"
tags: [finding, security, auth, dos, audit-log, gemini-audit]
found: 2026-10-29
---
# GM-19 Global account lockout DoS and unauthenticated audit_log flooding on login

## Location
- `storageforge_index/server.py:132-134, 490-492, 505-525` (`api_login()`, `limited()`)
- `storageforge_index/users.py:19, 33-34, 48-63` (`authenticate()`)
- `storageforge_index/vault.py:456-472` (`AuditLog.append()`)

## Mechanics & Root Cause
1. **24-Hour Global Account Lockout (`LOGIN_LIMIT_PER_ACCOUNT = '100 per day'`)**:
   - In `server.py:517`, `@limiter.limit(LOGIN_LIMIT_PER_ACCOUNT, key_func=login_username, deduct_when=failed, on_breach=limited)` keys a `100 per day` limit solely on `user:<username>` across all IPs.
   - An unauthenticated party sending 100 failed login requests for `admin` (e.g. 50 from two `/24` networks, or waiting 1 hour from a single IP, or spoofing `X-Forwarded-For` per [[GM-17 Proxy header spoofing on shared Docker networks and broken multi-hop X-Forwarded-For|GM-17]]) locks the legitimate `admin` user out from **every IP address** for 24 hours.
2. **Empty Password Skips `DUMMY_HASH` `scrypt` Work While Deducting Quota (`server.py:523`)**:
   - Line 523 evaluates `user = users.authenticate(conn(), name, password) if name and password else None`.
   - When `password` is `""`, `users.authenticate()` is skipped completely (taking microseconds instead of ~50ms of `scrypt` work), yet the route still returns `401`, which triggers `deduct_when=failed` (`r.status_code == 401`) and increments the victim's `100 per day` lockout counter!
3. **Unbounded Append-Only `audit_log` Writes on Unauthenticated Login Failures & Rate-Limit Breaches (`server.py:508-510, 525`)**:
   - Every failed login (`audit('login-failed', ...)`) and every rate-limit breach (`on_breach=limited` -> `audit('login-rate-limited', ...)`) writes a hash-chained row into `audit_log`.
   - `AuditLog.append()` acquires an exclusive write transaction (`BEGIN IMMEDIATE` / `pg_advisory_xact_lock`), hashes the chain, and inserts into `audit_log`, which has `BEFORE DELETE` triggers and is **never pruned by `db.prune()`**.

## Impact
Trivial 24-hour denial of service against the `admin` account, timing oracle on empty vs non-empty passwords, and database write-lock contention / disk growth via unauthenticated login floods.

## Remediation
1. Scope login rate limits by `(client_ip_or_subnet, username)` rather than a global IP-agnostic per-username 24h block (or bypass the global bucket for IPs that have previously authenticated a valid session).
2. Return `400 Bad Request` before rate-limit deduction when `username` or `password` is empty, and enforce a maximum password length (e.g. `256` chars) before running `scrypt`.
3. Rate-limit or coalesce unauthenticated `login-failed` / `login-rate-limited` writes to the append-only database `audit_log`.

## Done when
- [ ] Unauthenticated requests from untrusted IPs cannot globally lock out `admin` across all IPs for 24h or flood `audit_log` without bound.
