---
id: GM-12
status: open
severity: high
effort: M
area: "[[API, Auth and Security]]"
tags: [finding, availability, waitress, server, gemini-audit]
found: 2026-10-29
---
# GM-12 Waitress 8-thread pool exhaustion via synchronous 6-hour restore and deploy endpoints

## Location
- `storageforge_index/server.py:672, 745, 1007, 1023, 1093, 1105, 1111, 1327` (`waitress_serve(..., threads=8)`)
- `storageforge_index/jobs.py:446, 463, 475-496` (`action()`, `browse()`, `restore()`, `timeout=6 * 3600`)
- `storageforge_index/deploy.py:284, 323, 550` (`enroll()`, `run(..., timeout=1800)`, `adopt()`)
- `docker/nginx.conf:39-40` (`proxy_read_timeout 6h; proxy_send_timeout 6h;`)

## Mechanics & Root Cause
`server.py:1327` starts Waitress with a small 8-thread worker pool (`threads=8`), while `docker/nginx.conf:39-40` configures a global `6h` proxy timeout on `location /`:
```python
# server.py:1327
waitress_serve(app, host=host, port=port, threads=8, ident='StorageForge')
```
While batch deployments via `POST /api/deploy/start` (`server.py:1061`) run asynchronously in a background thread via `deploy.start_group()`, all individual job actions, snapshot restores, snapshot browsing, key installations, and deploy enrollments execute **synchronously inside the HTTP request thread**:
- `POST /api/deploy/jobs/<jid>/restore` (`server.py:1111` -> `jobs.py:495`): blocks the Waitress worker thread for up to **6 hours (`21600s`)**!
- `POST /api/deploy/jobs/<jid>/<verb>` (`run`, `dryrun`, `verify`, `cutover`, `pause`, `resume`, `log`, `snapshots`) and `POST /api/deploy/jobs/<jid>/browse` (`server.py:1093, 1105` -> `deploy.run()`): each blocks a worker thread for up to **30 minutes (`1800s`)** (`deploy.py:324`).
- `POST /api/deploy/adopt` (`server.py:1023` -> `deploy.adopt()`): blocks for up to **30 minutes (`1800s`)**.
- `POST /api/keys/install`, `POST /api/access/grant`, `POST /api/deploy/access`: block for **60–90 seconds**.

At the same time, the web UI polls `/api/jobs` and `/api/deploy/groups/<gid>` every 1.5–4 seconds (`app.js`), and Docker runs `HEALTHCHECK CMD ["storageforge-index", "healthcheck"]` against `/healthz` every 30 seconds (`timeout=5s`, `retries=3`).

## Impact
If 8 long-running calls (`restore`, `run`, `verify`, `dryrun`, `browse`, or stalled SSH connections) are active concurrently, all 8 Waitress threads are occupied. The entire web UI freezes, and `/healthz` times out after 3 retries (90 seconds), causing Docker to mark the `storageforge` container `unhealthy`!

## Remediation
1. Run long-lived operations (`restore`, `jobs.action` for `run`/`verify`/`cutover`) in background worker threads via `deploy.start_group()` and poll their progress via `/api/deploy/groups/<gid>` or `/api/deploy/runs/<id>`.
2. Increase Waitress `threads` (e.g. `threads=32`) and scope nginx's `proxy_read_timeout 6h;` strictly to long-running endpoints if any remain synchronous.

## Done when
- [ ] Restore and job-action endpoints execute asynchronously via `deploy_runs` or do not starve `/healthz` and UI polling threads.
