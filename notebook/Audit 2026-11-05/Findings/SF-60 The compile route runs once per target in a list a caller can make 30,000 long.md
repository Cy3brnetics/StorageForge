---
id: SF-60
status: done
severity: medium
effort: S
area: Network language
verified: proven
tags: [finding, audit-2026-11-05]
found: 2026-11-05
---
# SF-60 The compile route runs once per target in a list a caller can make 30,000 long

**Medium** · S · Network language · Proven · part of [[Audit 2026-11-05]]

## What exists
`POST /api/dsl/compile` takes a network-language text and a `targets` list, and compiles the text once for each name in the list. The list is not checked for length or for repeats: `["nftables", "nftables", ...]` compiles the whole text again for every entry, and the answer keeps only the last of each name. The route needs only `devices.view`, which the built-in `viewer` role holds, and it has no rate limit. Its body limit is 512 KiB (`MAX_LONG_TEXT`), so a request can hold a 2,000-statement text (the parser's cap, `MAX_STATEMENTS`) and about 30,000 target names.

## Evidence
`routes_network.py:200-201`: `wanted = body.get('targets') or list(rostranspiler.TARGETS)` then `out = {t: rostranspiler.emit(stmts, t) for t in wanted}`. `emit` raises for a name that is not one of the ten targets, so the only way to make the loop long is to repeat valid names.

Ran `/tmp/sfaudit/a/probe_api.py` (`test_c_compile_targets`) against the real route on a throwaway SQLite database, signed in as a `viewer`, with a 2,000-statement text of plain filter rules:

| targets in the list | time |
| --: | --: |
| 1 | 0.04 s |
| 200 | 1.04 s |
| 2,000 | 9.35 s |

The cost is linear, about 4.7 ms for each repeat. A body with 30,000 repeats of `"nftables"` and that text is 516,022 bytes, under the 524,288 limit, so one request would hold a worker for roughly two minutes (extrapolated from the table, not run to the end).

## Why it matters
Any account that may see devices can keep a server thread busy for minutes with one small request, and repeat it. The other routes the audit timed spent a second or less (see [[SF-52 One long log line holds the whole server for a second or more|SF-52]]). It breaks nothing and leaks nothing, so Medium and not High.

## Suggested approach
Accept `targets` only as a list of at most ten strings, each one of `rostranspiler.TARGETS`, de-duplicated, and answer 400 otherwise. Also refuse a non-list (`targets: 5` and a dict currently reach the loop as other types). Keep the 512 KiB body limit, which is right for the text.

## Done when
- [x] A `targets` list longer than the ten known names, or with repeats or a non-string, answers 400
- [x] A test posts a 2,000-statement text with 5,000 repeats of one target and sees 400 in well under a second
- [x] The commit is written here

## Fixed
2026-11-06, in `6452a81`. The route takes `targets` only as a list of at most ten different known names and answers 400 otherwise. A repeated name is refused, not quietly merged. Unit-tested, with the test seen to fail on the old code. Not lab-tested.
