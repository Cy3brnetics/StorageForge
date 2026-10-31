---
id: PF-19
status: done
severity: high
effort: S
area: Scheduler
verified: proven
tags: [finding, audit-2026-10-31]
found: 2026-10-31
---
# PF-19 Deleting a deployed schedule orphans a root cron job

**High** · effort S · Scheduler · Proven: ran it · part of [[Audit 2026-10-31]]

## What exists
Moves and tasks refuse deletion while deployed. Schedules don't. Once the row is gone, the uninstall path fails too, because `deploy_items_for` looks the schedule up first.

## Evidence
- `server.py:1881-1885` compared with `:1226` and `:1486`
- Proof: delete answered 200. The uninstall answered 500 `internal error: LookupError`. Drift then says "the schedule was deleted since it was deployed: uninstall it", which the app can no longer do.

## Why it matters
A job keeps running as root on the host forever, with no token to report and no row to see it through. The only way out is by hand on the host. In a security incident, this is what someone deletes in a hurry.

## Suggested approach
Refuse deletion while deployed, with the same 409 text the other kinds use. Handle a missing row in uninstall, as jobs do with `deleted plan`. Clean up existing orphans from the `deployed` table.

## Done when
- [x] Delete answers 409 while deployed
- [x] An orphan can be uninstalled from the UI

## Fixed
2026-10-31, in `8d3c73e`. Delete answers 409 while deployed. Already orphaned schedules can be uninstalled from a new section on the Deploy tab, checked in the browser up to the deploy access refusal; no real host was involved. Tests: `test_a_deployed_schedule_cannot_be_deleted`, `test_a_schedule_already_deleted_can_be_uninstalled`.
