---
id: PF-24
status: done
severity: medium
effort: M
area: Scheduler
verified: read
tags: [finding, audit-2026-10-31]
found: 2026-10-31
---
# PF-24 Verified says less than it sounds like

**Medium** · effort M · Scheduler · Read in the code, not run · part of [[Audit 2026-10-31]]

## What exists
A run becomes `verified` from the host's own exit code and from an index that predates the run, because verification happens before any rescan and `auto_rescan` is queued afterwards. `paths_must_not_exist` therefore checks yesterday's files. `paths_must_exist` can only warn, so it never fails. With no index for the host, the checks are skipped with a warning and the run still passes. A root-level path is compared as `//name`, because the query builds `d.path || '/' || f.filename`.

## Evidence
- `scheduler.py:574-584`, `:618-620`, `:656-692`, `server.py:2054-2056`

## Why it matters
The panel's status and the 3-2-1 view suggest independent proof. A compromised or broken host can report success, and state checks may pass on old data. An operator trusts backups that were never confirmed.

## Suggested approach
Name it honestly (`reported ok`), and keep `verified` for checks run on index data newer than the run. Verify after the rescan finishes. Offer signed or task-specific evidence, like the restore tests or `verify_copy`, for backups.

## Done when
- [x] `verified` requires a scan newer than the run

## Fixed
2026-10-31. New status `reported`. `verified` needs a finished scan newer than the run, and `verify_pending` runs after each scan. `paths_must_exist` now fails rather than warns. Root-level paths compare correctly. Tests: `VerifiedMeansCheckedTests`.
