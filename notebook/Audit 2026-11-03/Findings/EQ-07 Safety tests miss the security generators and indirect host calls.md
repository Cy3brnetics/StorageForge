---
id: EQ-07
status: in-progress
severity: low
effort: S
area: Tests
verified: read
tags: [finding, audit-2026-11-03]
found: 2026-11-03
---
# EQ-07 Safety tests miss the security generators and indirect host calls

**Low** · S · Tests · Read · part of [[Audit 2026-11-03]]

## What exists
Two walk tests hold the project's rules, and neither reaches the new security code. The runner's own refusals are only partly tested. This audit found no bug behind any of these gaps, so today's code is fine, but nothing keeps it that way.

## Evidence
- `test_no_generator_lets_a_value_run_as_code` (`tests/test_platform.py:2089`) covers `changes`, `tasks`, `moves`, `jobs`, `shares` and `clamav`. It doesn't include `secscripts` or `secplus`. [[Project invariants]] gives being in this test as the check. `test_security.py:927` tests decoy names only.
- `test_no_get_runs_on_a_host` (`tests/test_route_rules.py`) searches each view's own source for `RUNS_ON_HOST`, which doesn't name `security._run`, or anything that goes through `security.*` or `secplus.*`. A new GET calling `security.measure` would pass.

- `test_runner_checks_machine_id_and_claims_nonces_once` (`tests/test_platform.py:1863`) directly tests a replay and a wrong machine. A search of `tests/` for the refusal messages found no direct test for a forged key, an altered script or args, or the wrong namespace, and none for an old request.

For this audit, a one-off script put a hostile value through the main `secscripts` generators, and a call graph checked the GETs. Forged requests were put through the real runner. All were clean, and none of those scripts is in the repo.

## Why it matters
These are the tests that make a class of bug impossible to add by accident, and the newest and most privileged scripts sit outside them.

## Suggested approach
Add `secscripts` and `secplus` generators to the walk. Replace the source search with a test that patches `deploy.run`, `deploy.raw` and `Transport` to fail, then calls every GET route. Add the forged-request cases to the runner's test: the audit's table on [[Audit 2026-11-03]] lists them, and each ran correctly when tried. Untested as suite tests.

## Done when
- [x] Each new generator appears in the walk, and removing the quoting from one makes the test fail
- [x] A GET route added for the test that reaches `deploy.run` through a helper makes the test fail
- [x] Each forged-request case in that table is a test that the runner refuses it and the script doesn't run

**Fix:** in the working tree on 2026-11-03, not committed, so this is `in-progress` until a commit can be recorded here. `SecurityGenerators`, `ForgedRequests` and a GET walk that really calls every route are in the suite. Each main check was also removed by hand to confirm its test fails.
