---
id: PF-05
status: done
severity: medium
effort: M
area: "[[Alerts and monitoring]]"
tags: [finding, roadmap]
found: 2026-10-29
---
# PF-05 Capacity history

Roadmap item #4 from the 10-27 audit. **Not started.**

## What exists
`mounts.total_bytes` and `mounts.used_bytes` (`migrations/sqlite/001_initial.sql`), updated in place by each scan. `scans` keeps one row per scan forever ("scan summaries are tiny and stay", `db.py:258`).

## What is missing
No history: the previous value is overwritten, so there is no trend and no "full in N days".

## Suggested approach
1. Migration 016: `mount_usage (host_id, mount_point, scan_id, at, used_bytes, total_bytes)`, one row per real mount per scan. Small: tens of rows per scan.
2. Retention in `db.prune`: keep everything for 90 days, then one row per day per mount.
3. `capacity.forecast(points)`: least-squares slope over the last 30 days, return days until 100% (None when flat or shrinking).
4. API `GET /api/capacity?host=` and a sparkline on mount boxes in the topology; the report's section 5 gets a "fills up in" column.
5. Add `mount_usage` to `backup.REBUILDABLE` (the consistency test will insist).

## Done when
- [ ] Mount boxes show a 30-day sparkline
- [ ] "Full in about N days" appears when the trend is up, and feeds an alert under [[PF-01 Alerts only cover deploys|PF-01]]

## Progress 2026-10-30
`mount_usage`, `capacity.forecast`, `GET /api/capacity`, an alert and a report section. The sparkline is in the Cleanup tab, not on the topology mount boxes as first suggested.
