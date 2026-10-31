---
id: SF-23
status: done
severity: critical
effort: S
area: Scheduler
verified: proven
tags: [finding, audit-2026-10-31]
found: 2026-10-31
---
# SF-23 Run local executes schedules on the server

**Critical** · effort S · Scheduler · Proven: ran it · part of [[Audit 2026-10-31]]

## What exists
`POST /api/scheduler/schedules/<id>/run` with `{"local": true}` writes the schedule's script to a temp file and runs it with `/bin/bash` inside the StorageForge process. The Schedule panel has a **Run local** button for it. A `command` schedule is whatever text the user typed.

## Evidence
- `storageforge_index/server.py:1923-1955`, `static/scheduler.js:233-236`
- Proof: an `operator` whose password was last typed long ago created a command schedule and ran it. Answer 200, output `uid=1000 secret=seen-by-script env=from-config`. The script ran as the server's user and saw a variable planted in the server's environment.
- `tests/test_scheduler.py:422-430` asserts this behaviour as correct.

## Why it matters
An operator, or any custom role with `plans.edit` and `deploy.apply`, becomes the StorageForge server. That account can then read `/run/sf-secrets/vault_secret` and `session_secret` (same user, `docker-compose.yml:47-48`), so it can decrypt every SSH key in the vault and forge a session for any account. Roles exist to stop exactly this. Each run also holds one of 8 web threads for up to `timeout_sec` (10 days, or forever at 0).

## Suggested approach
Remove the `local` branch and the button. The server is not a managed host. Keep `storageforge-index schedule run` in the CLI, since anyone there already has a shell. If a local run is ever needed, make it a named action that takes no script text, with an empty environment.

## Done when
- [x] `local` is gone from the route and the UI
- [x] A test asserts that a schedule cannot run anything on the server

## Fixed
2026-10-31, in the working tree, not committed yet: add the commit here. The local branch and the **Run local** button are gone. `storageforge-index schedule run` stays in the CLI. Test: `test_a_schedule_never_runs_on_the_server`.
