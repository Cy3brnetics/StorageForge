---
id: EQ-04
status: open
severity: medium
effort: S
area: Tests
verified: read
tags: [finding, audit-2026-10-31]
found: 2026-10-31
---
# EQ-04 Safety tests do not reach the new generators

**Medium** · effort S · Tests · Read in the code, not run · part of [[Audit 2026-10-31]]

## What exists
288 tests pass (3 skipped), yet many bugs here sit in exactly what they don't cover:
- `test_no_generator_lets_a_value_run_as_code` lists changes, tasks, moves, jobs and shares, but not scheduler install scripts or `confirm.py`. CONTRIBUTING requires new generators to be added.
- The body limit, a stale password, the destructive switch, delete while deployed: no tests.
- `test_scheduler` runs the local path and treats it as a feature.
- Task scripts are written with `{task_script}` inside `<<'EOF_TASK'`, so a value holding a line `EOF_TASK` ends the heredoc early. It isn't tested and needs checking once `command` is restricted.
- `tests/lab/` has no scheduler or Git Inspector cases (searched for `scheduler`, `git/status` and `git/sync`).

## Evidence
- `tests/test_platform.py:2013-2045`, `tests/test_scheduler.py:422-440`, `scheduler.py:1069-1071`

## Why it matters
Green CI gives more confidence than it has earned for the riskiest module. `test_every_route_is_listed` is the model to copy: it catches new routes by walking the URL map.

## Suggested approach
Add table-driven route tests: for every route, assert permission, whether it wants a fresh password, whether it is audited, and method safety. Add the scheduler to the hostile-values test and shellcheck. Use random heredoc delimiters.

## Done when
- [ ] A new route without a declared password and audit rule fails CI
