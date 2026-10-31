---
id: PF-20
status: done
severity: high
effort: M
area: Scheduler
verified: proven
tags: [finding, audit-2026-10-31]
found: 2026-10-31
---
# PF-20 Pausing a schedule does not stop it

**High** · effort M · Scheduler · Proven: ran it · part of [[Audit 2026-10-31]]

## What exists
Pause sets a database flag. The host's cron entry and `paused: false` in its config stay as they were until someone deploys again. The UI toast says "Schedule paused". Paused schedules are also excluded from alert evaluation, so failures go quiet at the same moment.

## Evidence
- `scheduler.py:466-472`, `alerts.py:453`, `static/scheduler.js:225-226`
- Proof: pause answered 200 and started no deploy.
- That the host keeps running is read from the install script, because no host was involved.

## Why it matters
Someone pauses a job because it is hurting something, is told it worked, and it runs again on schedule while alerts stay silent.

## Suggested approach
Make pause a real deploy that updates the host, with its progress shown. If that can't reach the host, say so and keep the state as "pause pending". Keep alerting until the host has confirmed.

## Done when
- [x] Pausing removes the cron entry on the host, tested in the lab

## Fixed
2026-10-31. Pause and resume start a deploy to the hosts holding the schedule, or answer `host_pending` when one has no deploy access, and alerts keep watching until the host has it. Tested with mocks, **not on a host**. Test: `test_pausing_reaches_the_host`.
