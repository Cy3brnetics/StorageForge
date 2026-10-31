---
id: PF-22
status: done
severity: medium
effort: M
area: Scheduler
verified: read
tags: [finding, audit-2026-10-31]
found: 2026-10-31
---
# PF-22 Scheduler settings that do nothing

**Medium** · effort M · Scheduler · Read in the code, not run · part of [[Audit 2026-10-31]]

## What exists
The form and the docs offer settings the runner ignores or undoes:
- `nice`, `ionice_class`, `ionice_priority`, `catchup`: stored and shown, used nowhere in `schedscript.py`.
- `jitter_sec`: cron runs `run <id>` without `--jitter`, so it applies only under the daemon, which nothing installs.
- `timezone`: the server computes `next_run` in it, but the cron entry has no `CRON_TZ`, so it fires in the host's zone, and `in_window` uses the host's local time.
- `user`: anything but root can't read its own config (mode 0600, root), so the job errors out before running and sends no report.

## Evidence
- `scheduler.py:208-218`, `:970-974`, `:1079`, `schedscript.py:116`, `:180`, `static/scheduler.js:354-367`, `docs/plans-and-scripts.md:166-170`
- Read from the code and not run on a host.

## Why it matters
A big rsync set to idle I/O runs at normal priority. A 02:00 job in the wrong zone hits business hours. Stale alerts fire on a wrong clock. A non-root schedule never runs at all, and the only sign is a stale alert later.

## Suggested approach
Implement each in the runner or delete it from the form and docs. A setting that does nothing is worse than none. Add `CRON_TZ`, and make the config readable by the chosen user while keeping the token out of that file.

## Done when
- [x] Each setting has a test, or is gone

## Fixed
2026-10-31. `nice`, `ionice`, jitter, timezone, window and `user` now work; `catchup` is gone. Cron wakes the runner each minute (`--if-due`), since not every cron has `CRON_TZ`. Cron stays root and the runner drops to `user`, so the token stays root-only. Not run on a host. Policy `replace` can now read its PID too, the last point of SF-35. Tests: `test_settings_reach_the_runner`, `test_an_unknown_user_is_a_failed_run`.
