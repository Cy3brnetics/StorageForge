---
id: SF-39
status: open
severity: high
effort: S
area: Permissions
verified: read
tags: [finding, audit-2026-10-31]
found: 2026-10-31
---
# SF-39 Task command blocks are a root shell without schedules.command

**High** · effort S · Permissions · Read in the code, not run · part of [[Audit 2026-10-31]]

## What exists
Found while fixing [[PF-26 Scheduler design duplicates what tasks already do|PF-26]]. Storage tasks have a block type `command`, whose value is code on purpose. Saving one needs only `plans.edit`, and deploying needs only `deploy.apply`.

## Evidence
- `tasks.py:120`, `:453`, `:618`
- `tests/test_platform.py` skips this block in the hostile-values test because of that.

## Why it matters
[[SF-24 Command schedules are a root shell behind plans.edit|SF-24]] put arbitrary schedule commands behind `schedules.command`. A task command block gives an operator the same root shell, so that permission doesn't yet hold, and a schedule of type `task` runs it on a timer too.

## Suggested approach
Require the same permission, renamed `hosts.command` or similar, to save, change or deploy a task holding a command block. Check it in `/api/deploy/start` and for schedules of that task as well. Check other generators for the same escape, such as job pre and post hooks.

## Done when
- [ ] An account with `plans.edit` and `deploy.apply` alone can't save or deploy a command block
