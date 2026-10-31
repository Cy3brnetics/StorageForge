---
id: SF-35
status: in-progress
severity: low
effort: S
area: Scheduler
verified: read
tags: [finding, audit-2026-10-31]
found: 2026-10-31
---
# SF-35 Client runner file handling

**Low** · effort S · Scheduler · Read in the code, not run · part of [[Audit 2026-10-31]]

## What exists
- `last.json` holds the complete output and `runs.jsonl` the last 4 KiB, both mode 0644 in a 0755 folder, so any local user can read them.
- `runs.jsonl` grows without limit, and the server keeps `schedule_runs` forever: `db.prune` has no rule for it.
- The lock opens `/run/lock/sf-sched-<id>.lock` with `w+` as root. That directory is world-writable on many distros, so only the kernel's `protected_symlinks` and `protected_regular` settings stand in the way of a planted link.
- `w+` also truncates the file before reading it, so policy `replace` never finds the PID and never replaces anything.

## Evidence
- `schedscript.py:186-199`, `:265-300`, `db.py` `prune`
- Read from the code and not run.

## Why it matters
Output may hold secrets and is exposed locally. Long-lived schedules slowly fill disks on both ends. `replace` is a setting that does nothing.

## Suggested approach
Make output 0640 with the scan group, as `health.py` does. Rotate `runs.jsonl` and add a prune rule. Open the lock with `O_NOFOLLOW` under a root-owned folder such as `/run/storageforge`, read before truncating, and record the PID separately.

## Done when
- [ ] Output is not world-readable
- [ ] A `replace` test kills the older run

## Progress
2026-10-31, through PF-26: `runs.jsonl` holds no output and rotates at 600 lines, `last.out` is root only, and locks moved to the private `/run/storageforge`. `replace` is tested. Still open: `schedule_runs` has no prune rule on the server.
