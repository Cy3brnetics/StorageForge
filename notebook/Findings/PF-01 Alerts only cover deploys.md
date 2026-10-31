---
id: PF-01
status: done
severity: high
effort: M
area: "[[Alerts and monitoring]]"
tags: [finding, partial]
found: 2026-10-29
---
# PF-01 Alerts only cover deploys

## What exists
`alerts.py` keeps an `alerts` table, re-evaluates every 5 minutes (`ALERT_TICK`, `server.py:126`) and pushes open/resolved events to ntfy, Gotify or a webhook. The plumbing (dedupe by key, resolve when gone, SSRF-checked senders) is solid.

## What is missing
`alerts.problems()` (`alerts.py:218`) has exactly four sources: failed jobs, stale jobs, failed verifies, and drift. None of these raise an alert:

| Problem | Already known where |
| :-- | :-- |
| A scan job failed, or a host hasn't scanned in N intervals | `scan_jobs.status`, `hosts.last_scanned_at` |
| A mount went offline (`scan_state = 'gone'`) | `mounts` |
| A filesystem is over 90% (or a threshold) | `mounts.used_bytes/total_bytes`, `analysis.use_pct` |
| A ZFS pool or md array is degraded or resyncing | `analysis.py:247` already writes a **crit** finding for this |
| A backup in the 3-2-1 matrix is past its age | `analysis.py:147` |
| The nightly StorageForge backup failed | audit log `backup.create failed` (`server.py:274`) |
| A git repo has a single copy / is behind | `git_repos` |

So the most serious things StorageForge can see (a degraded pool) show only when someone opens the report.

## Suggested approach
1. Turn `problems()` into a list of small source functions, each returning `{key: (kind, ref, title, message, level)}`; keep the existing four as the first sources.
2. Add `scan_problems(conn)` (failed/overdue scans, gone mounts), `capacity_problems(conn, pct)` and `analysis_problems(conn)`, which runs the existing report-node findings and lifts every `crit` into an alert.
3. Make thresholds settings (`alerts.full_pct`, `alerts.scan_overdue_factor`) in the existing settings form, plus a per-kind on/off.
4. Call `alerts_wake.set()` at the end of each scan job, as job reports already do.

## Done when
- [ ] A failed scan, a degraded pool and a 95% full mount each open an alert and send one notification
- [ ] They resolve on their own after the next good scan
- [ ] Tests cover each new source

Related: [[PF-02 Protection matrix ignores deployed jobs]], [[PF-04 Disk health and scrubs]], [[PF-05 Capacity history]]

## Done 2026-10-30
Scan failures, gone mounts, full disks, unhealthy pools, device errors, backups and the certificate now raise alerts (`alerts.scan_problems`, `backup_problems`, `cert_problems`). "A backup job is late" still depends on [[PF-02 Protection matrix ignores deployed jobs]].
