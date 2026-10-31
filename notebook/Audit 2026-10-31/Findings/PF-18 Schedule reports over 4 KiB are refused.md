---
id: PF-18
status: open
severity: high
effort: S
area: Scheduler
verified: proven
tags: [finding, audit-2026-10-31]
found: 2026-10-31
---
# PF-18 Schedule reports over 4 KiB are refused

**High** · effort S · Scheduler · Proven: ran it · part of [[Audit 2026-10-31]]

## What exists
The app's body limit is 4 KiB, and only the planner routes raise it. `/api/scheduler/report` doesn't, yet the runner posts the task's whole output and the server has code to store 256 KiB.

## Evidence
- `server.py:162`, `:521-524`, `schedscript.py:280`, `scheduler.py:828`
- Proof: 1 KiB output answered 200, 8 KiB answered 413.
- `send_report` only prints the failure, with no retry. The next scan picks up `runs.jsonl`, which holds only the last 4 KiB.
- The scheduler's tests post short output, so they pass.

## Why it matters
The headline feature, server-side verification on completion, fails for any job that prints more than a screenful: rsync, a change plan, a share deploy. Their result arrives only at the next scan, without the head of the output, and `output_must_match` is then checked against a truncated tail.

## Suggested approach
Add the route to `body_limit` with a 512 KiB limit. Have the runner cap what it sends and mark it truncated. Retry from a spool file, or at least rely on the scan path deliberately and say so in the UI.

## Done when
- [ ] A 200 KiB report is stored, with a test
