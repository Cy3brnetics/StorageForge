---
id: SF-24
status: done
severity: high
effort: M
area: Scheduler
verified: proven
tags: [finding, audit-2026-10-31]
found: 2026-10-31
---
# SF-24 Command schedules are a root shell behind plans.edit

**High** · effort M · Scheduler · Proven: ran it · part of [[Audit 2026-10-31]]

## What exists
`task_type: command` puts `task_ref` into the task script unquoted, by design, and that script runs as root from cron. The permission needed to write it is `plans.edit`, described as "Create and edit plans, tasks, shares and designs". Separately, `config.env` accepts any variable name for every task type, including `BASH_ENV`, `LD_PRELOAD` and `PATH`.

## Evidence
- `scheduler.py:550-556`, env at `scheduler.py:224-229`, applied at `schedscript.py:216-218`
- Saved and returned unchanged in the proofs for [[SF-23 Run local executes schedules on the server|SF-23]] and [[SF-30 Read-only accounts can read schedule secrets|SF-30]].

## Why it matters
Everything else in StorageForge checks typed fields before they reach a script, and concepts rule 3 says values reach Bash as data. This feature opts out of that. A reviewer who reads a storage task sees safe blocks, while `BASH_ENV` in its schedule still runs code first as root. It also makes [[SF-26 Schedules bypass the destructive permission|SF-26]] and every other scheduler gap more dangerous.

## Suggested approach
Add a separate permission, `schedules.command`, marked high risk and not in any built-in role except admin. Check it on create, on update, and on deploy of a command schedule. Allow env names from a short list, or refuse `LD_*`, `BASH_ENV`, `ENV`, `PATH`, `PYTHON*`, `IFS` and `GIT_*`. Show the exact command in the dry run.

## Done when
- [x] A plans.edit account cannot save a command schedule
- [x] `BASH_ENV` and `LD_PRELOAD` are refused with a clear message

## Fixed
2026-10-31, in `6a5a990`. New high-risk `schedules.command`, admin only by default, checked on create, update, run and deploy. Unsafe env names are refused on save and dropped from older rows. The dry run shows the command. Tests: `test_commands_need_their_own_permission`, `test_env_cannot_change_what_runs`.
