---
id: PF-26
status: open
severity: medium
effort: L
area: Scheduler
verified: read
tags: [finding, audit-2026-10-31]
found: 2026-10-31
---
# PF-26 Scheduler design duplicates what tasks already do

**Medium** · effort L · Scheduler · Read in the code, not run · part of [[Audit 2026-10-31]]

## What exists
Storage tasks already have timers, locks, run records and signed installs, using systemd where available. The scheduler adds a second path with cron and a Python runner, plus a second cron parser that is a verbatim copy.
- It writes `/etc/cron.d` even where no cron daemon runs, and not every supported image has one (Arch and minimal images often don't), so a schedule can install cleanly and never fire.
- The runner needs Python 3.9+ for `zoneinfo`, and the only preflight data doesn't check that. The project's targets otherwise need only POSIX tools and bash, and the lab includes Alpine.
- Its install script defaults to `MODE=install`, breaking rule 1 of the docs: with no flags a script only reports (proof: `MODE=install` in the generated script).

## Evidence
- `scheduler.py:45-110` and `schedscript.py:42-104`, `scheduler.py:1011`, `schedscript.py:1-24`
- `docs/concepts.md`, CONTRIBUTING: "Scripts look before they act".
- `tests/lab/` has no scheduler case on the distros (searched for `scheduler` and `schedules`).

## Why it matters
Two systems to secure and keep in step, and hosts where schedules silently don't fire. Most findings in this audit are this module missing protections the older paths already earned.

## Suggested approach
Decide before fixing details. **Recommended:** build the scheduler as a layer over tasks' install path: generate one systemd timer or cron line, in bash, with the same helpers, and keep this module's useful parts (the panel, run history, verification). Default to report mode. Add the module to the lab.

## Done when
- [ ] One install path for timed work
- [ ] The no-flags run of the script changes nothing
