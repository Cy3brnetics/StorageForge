---
id: PF-23
status: done
severity: medium
effort: S
area: Scheduler
verified: read
tags: [finding, audit-2026-10-31]
found: 2026-10-31
---
# PF-23 Task types that cannot work as written

**Medium** · effort S · Scheduler · Read in the code, not run · part of [[Audit 2026-10-31]]

## What exists
- `scan` runs `storageforge-index scan` on the client host, where it isn't installed, so it can only fail. Scanning from the server is what `hosts.scan_interval` already does.
- `shares` takes its host from `task_ref`, which can differ from the host the schedule installs on.
- `task`, `change` and `move` aren't tied to the schedule's host. A plan naming another host runs where it is scheduled. Tasks only print a note on mismatch (`tasks.py:897-898`).
- On PostgreSQL, `scans.started_at` is `TIMESTAMPTZ`, so `last_scan >= run_start - 60` raises `TypeError` and the report is lost (`scheduler.py:696-698`; SQLite stores an integer). No PostgreSQL run was done in this audit.

## Evidence
- `scheduler.py:511-558`, `migrations/postgres/001_initial.sql:53`

## Why it matters
Silent failures, and in the worst case a plan applied to a host it wasn't reviewed for.

## Suggested approach
Remove `scan`, or make it a server-side schedule. Validate on save that the referenced plan names only this host, and resolve references to ids rather than free text. Use `epoch()` for the timestamp.

## Done when
- [x] Saving a mismatched schedule is refused
- [x] The scheduler tests pass on PostgreSQL

## Fixed
2026-10-31, in `6a5a990`. `scan` is refused on save, and a plan, task or share for another host is refused on save and on deploy. The timestamp now uses `epoch()`, not run on PostgreSQL. References are still free text, so this stays in progress. Test: `test_a_schedule_stays_on_its_own_host`.

## Finished
2026-10-31, `cc5b207`. References are stored as ids on save. The scheduler tests pass on PostgreSQL, after fixing a fixture that had kept them from running there at all (`ced94b5`).
