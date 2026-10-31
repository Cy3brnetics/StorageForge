---
id: SF-25
status: done
severity: high
effort: S
area: Scheduler
verified: proven
tags: [finding, audit-2026-10-31]
found: 2026-10-31
---
# SF-25 Scheduler routes skip the fresh password and preflight

**High** · effort S · Scheduler · Proven: ran it · part of [[Audit 2026-10-31]]

## What exists
Concepts rule 13 says anything that runs on a host from the web UI needs a password typed in the last 5 minutes. Every scheduler write route skips that, including the one that runs a schedule over SSH. The run route also skips `preflight.blockers`, which `/api/deploy/start` applies.

## Evidence
- `server.py:1856-1970`: no `@password_confirmed` or `password_stale()` on create, update, delete, pause, token or run.
- Proof: with a stale password, `/api/deploy/start` answered 403 and `/api/scheduler/schedules/<id>/run` answered 200. The local branch was the one exercised; the SSH branch has the same missing check, read from the code.

## Why it matters
A stolen or unattended browser session can install and run root commands on every enrolled host without the password check that protects the same action on the Deploy tab.

## Suggested approach
Add `@password_confirmed` to all scheduler writes. Route `run` through the same function as `/api/deploy/start`, so permission, preflight and digest checks live in one place.

## Done when
- [x] `test_commands_on_hosts_need_the_password_again` (`tests/test_platform.py:1667`) covers the scheduler routes

## Fixed
2026-10-31, in `8d3c73e`. All scheduler writes now need a fresh password, and the run route applies `preflight.blockers`. The run route still has its own copy of the deploy steps rather than sharing one function with `/api/deploy/start`. `test_commands_on_hosts_need_the_password_again` was left as is; the new tests are `test_scheduler_writes_need_a_fresh_password` and `test_running_a_schedule_applies_preflight`.
