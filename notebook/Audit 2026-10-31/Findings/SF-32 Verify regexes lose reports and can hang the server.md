---
id: SF-32
status: done
severity: medium
effort: S
area: Scheduler
verified: proven
tags: [finding, audit-2026-10-31]
found: 2026-10-31
---
# SF-32 Verify regexes lose reports and can hang the server

**Medium** · effort S · Scheduler · Proven: ran it · part of [[Audit 2026-10-31]]

## What exists
`output_must_match` and `output_must_not_match` are saved without compiling them, then run with `re.search` over up to 256 KiB of output, inside the report request.

## Evidence
- `scheduler.py:247-248`, `:590`, `:600`
- Proof: the pattern `(` saved without complaint. A **failed** run's report then answered 500 with `PatternError`, and zero runs were stored, so the failure disappeared.
- A slow pattern such as `(a+)+$` against crafted output is read from the code and was not run. There is no timeout. The waitress pool has 8 threads, and the output comes from the host.

## Why it matters
A typo in a form silently loses every failure report for that schedule, and alerts never fire. A slow pattern with attacker-influenced output can tie up web threads.

## Suggested approach
Compile on save and refuse invalid patterns. Prefer a fixed-string match. If regex stays, run it in a subprocess with a time limit, or use a linear-time engine. Store the run first, then verify, so that a verification crash can never lose a report.

## Done when
- [x] An invalid pattern is refused on save
- [x] A verification error still stores the run

## Fixed
2026-10-31. Patterns are compiled on save, run in a child process with a 2 second limit, and a verification error is a failed check on a stored run. Tests: `test_patterns_are_checked_and_cannot_lose_a_report`, `test_a_slow_pattern_is_stopped`.
