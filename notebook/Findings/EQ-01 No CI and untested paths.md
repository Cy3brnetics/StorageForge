---
id: EQ-01
status: in-progress
severity: high
effort: M
area: "[[Operations and engineering]]"
tags: [finding, testing]
found: 2026-10-29
---
# EQ-01 No CI and untested paths

## What exists
105 unittest tests across `test_indexer.py`, `test_platform.py`, `test_tasks.py`, `test_consistency.py`. They are good tests: they assert rules (every route needs a session, every table is in a backup list), not just happy paths.

## What is missing
- **No CI.** No workflow file anywhere in the repo, so nothing runs the suite on commit.
- **Server tests vanish without Flask.** On the host, 23 of 105 error with `ModuleNotFoundError: flask` and the run still looks like "1 failure"-ish noise. Tests should either run in the image or skip with a clear reason.
- **T1 still fails** where the read-only scan access is installed (`test_unreadable_folders_and_duplicate_folders`).
- **PostgreSQL never runs** (O7 from 10-27, M-05 from 10-26): 15 migrations are written twice and only the SQLite ones are exercised.
- **No browser tests** for about 3.7k lines in `planner.js`, `topology.js`, `tasks.js` and `app.js`, including the planner's capacity math ([[EQ-02 Two capacity engines]]).
- `analysis.py` has no test that imports it directly.

## Suggested approach
1. `make test` (or a `scripts/test.sh`) that runs the suite inside the built image: `docker compose run --rm --entrypoint python storageforge -m unittest discover -s tests`. Same command locally and in CI.
2. A CI workflow (Forgejo Actions) with two jobs: SQLite, and Postgres via a service container with `STORAGEFORGE_DB=postgresql://...`.
3. Fix T1: force the plain `find` in that test (env var or monkeypatch of the tool path).
4. A small Playwright smoke test: log in, open each tab, open the planner, no console errors.

## Done when
- [ ] Every push runs the full suite against SQLite and PostgreSQL
- [ ] A missing dependency fails the run instead of erroring 23 tests

## Progress 2026-10-30
The suite passes on SQLite and PostgreSQL, and `.forgejo/workflows/ci.yml` is written, but has not run yet: it needs Forgejo Actions and a runner. The browser JavaScript is still untested.

Later on 2026-10-30: planner capacity math now has a test. Still needs a Forgejo runner, which only the owner can set up, and browser tests.

2026-10-31: the suite passed on SQLite and PostgreSQL by hand (364 tests), including new browser smoke tests (`2215bfc`). Only the Forgejo runner is left, which only the owner can set up.
