---
id: SF-34
status: done
severity: medium
effort: M
area: Deploy
verified: read
tags: [finding, audit-2026-10-31]
found: 2026-10-31
---
# SF-34 Task timers rewrite the root runner on every run

**Medium** · effort M · Deploy · Read in the code, not run · part of [[Audit 2026-10-31]]

## What exists
Each signed script starts with `RUNNER_UPDATE`, which installs its own embedded copy of `storageforge-run` when the file differs. A storage task installs that whole script as its timer's program (`$0`), so the update runs on every timer tick, using whatever version was embedded when the task was deployed. The uncommitted change stops it installing an empty file, which is a good fix, but the cause remains.

## Evidence
- `deploy.py:170-178`, and the `task-keeps-runner` entry removed from `tests/lab/tiers.py`
- Read from the code and not run on a host. The lab found the zero-byte form of this bug.

## Why it matters
An old task quietly rolls the security-critical runner back to its older version each time it fires, undoing fixes. After **Remove deploy access**, a surviving timer puts the runner file back too, although the sudoers entry and signers are gone, so it can't be used.

## Suggested approach
Strip the header when installing a task (`RUNNER_UPDATE` belongs to the deploy, not the task). Refuse to install a runner older than the current one by adding a version line and comparing it. Keep the new `[ -s ]` guard.

## Done when
- [x] A timer run never writes to the runner path, with a test

## Fixed
2026-10-31. The header skips the update when `$0` is under `/usr/local/lib/storageforge/`. **Tasks already installed keep the old header until redeployed.** No version check against an older runner was added. Test: `test_an_installed_copy_leaves_the_runner_alone`.
