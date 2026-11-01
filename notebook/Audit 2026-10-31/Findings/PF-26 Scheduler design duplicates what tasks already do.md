---
id: PF-26
status: done
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
- [x] One install path for timed work
- [x] The no-flags run of the script changes nothing

## Decision
2026-10-31: **one generated bash runner per schedule, and no Python on hosts.** A systemd timer fires it where there is systemd, and cron wakes it each minute elsewhere. The server's `parse_cron` is the only parser: it writes the expanded times into the runner and the `OnCalendar` line.

- **Why not keep Python and patch it:** that was the smallest change, but every host would still need Python 3.9, and it is the only thing StorageForge deploys that does. Alpine and older RHEL would stay broken, and the cron parser would stay duplicated.
- **Why not build on the task install path directly:** `TASK_TAIL` assumes systemd and has no retries, windows, reports or other users. The runner uses the same patterns (`flock`, `runs.jsonl`, curl with a header file, the shape of the units) instead.
- **What stays:** the panel, run history, verification, the table and the API.
- **Cost:** two ways to wake, and a bash JSON writer. Hosts need `flock` and `timeout`, and `curl` to report directly. Without `curl` a run arrives with the next scan.

## Fixed
2026-10-31, in `9326d72`. Tests in `RunnerTests` and `InstallScriptTests` run the real script under bash with a stand-in `curl`. Added lab cases `schedule-timer` and `backup-copy`, **which have not been run**, so the systemd, cron and `runuser` paths are unproven on real hosts. This finding stays in progress only for that lab run.

## Finished
2026-10-31. Lab cases `schedule-timer` (sf-ubuntu, sf-rocky) and `schedule-cron` (sf-alpine) pass in `reports/lab-2026-10-31-1618.md` (344 passed, 0 failed, 4 known). Timer, report, pause reaching the host and uninstall all worked. Moving a host from the old Python runner was **not** in the lab, which never had it. "One install path" stands as decided in the Decision above: the runner and timers are separate from tasks, sharing their patterns.
