---
id: PF-21
status: done
severity: medium
effort: S
area: Scheduler
verified: proven
tags: [finding, audit-2026-10-31]
found: 2026-10-31
---
# PF-21 Drift and dry-run checks ignore the plan a schedule runs

**Medium** · effort S · Scheduler · Proven: ran it · part of [[Audit 2026-10-31]]

## What exists
`schedule_hash` covers the schedule's own fields and not the task, plan or share design it runs.

## Evidence
- `scheduler.py:307-309`, `server.py:1692-1695`, `alerts.py:276-285`
- Proof: editing the change plan left the schedule's hash unchanged.

## Why it matters
Edit a plan after a schedule was deployed: no drift is shown, while the host keeps running the older script. The check "the dry run you read must still describe what this applies" passes after the plan changed, which is the case it exists to stop.

## Suggested approach
Hash the generated script, without the token. The `script_sha` idea is already used for deploy runs.

## Done when
- [x] Editing the underlying plan raises drift and refuses a stale apply

## Fixed
2026-10-31, in `6a5a990`. `schedule_hash` now includes the hash of what the schedule runs. Every deployed schedule shows as changed once. Test: `test_the_hash_covers_what_a_schedule_runs`.
