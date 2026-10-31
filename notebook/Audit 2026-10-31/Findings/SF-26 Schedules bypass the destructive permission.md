---
id: SF-26
status: done
severity: high
effort: S
area: Scheduler
verified: proven
tags: [finding, audit-2026-10-31]
found: 2026-10-31
---
# SF-26 Schedules bypass the destructive permission

**High** · effort S · Scheduler · Proven: ran it · part of [[Audit 2026-10-31]]

## What exists
`/api/deploy/start` calls `need('deploy.destructive')` only when the request body says `destructive`. A schedule keeps the same switch in `config.destructive`, which `plans.edit` can set, and the script then gets `--apply --destructive`.

## Evidence
- `scheduler.py:253` and `scheduler.py:526`, `server.py:1677-1678`
- Proof: a custom role with `plans.edit` and `deploy.apply` but no `deploy.destructive` got 403 deploying a plan destructively, then saved a schedule whose script args are `['--apply', '--destructive']`.

## Why it matters
Partition and format tasks can run with no one holding the permission meant to guard them. They also run again on every cron tick, with no person watching. Concepts rule 10 calls this "three locks", and one of them is gone.

## Suggested approach
Refuse `config.destructive` for schedules. Destructive work is one-off and belongs in a change plan a person applies. If a real use case appears, require `deploy.destructive` on save and on deploy, and limit the schedule to a single run.

## Done when
- [x] A schedule cannot produce `--destructive` without the permission
- [x] The proof above is a regression test

## Fixed
2026-10-31, in the working tree, not committed yet: add the commit here. Saving `config.destructive` is refused for everyone, and scripts never get `--destructive`. **A host already deployed with it keeps its old script until redeployed**; its hash no longer matches, so it shows as changed. Test: `test_a_schedule_cannot_be_destructive`.
