---
id: EQ-02
status: done
severity: medium
effort: S
area: "[[Operations and engineering]]"
tags: [finding, design]
found: 2026-10-29
---
# EQ-02 Two capacity engines

## What exists
- Python: `capacity.py` pool formulas and `analysis.py` 3-2-1 and link checks, used by the report and graph. Its docstring: "The pool formulas match the StorageForge dashboard's RAID calculator so a report and the dashboard agree".
- JavaScript: `planner.js` `raidzEff`, `btrfsAlloc`, `calcEngine` (lines 250-337) and `protStatus`, `copies321`, `linkHealth`, `analyze` (338-428).

## Risk
They agree today because someone checked. Nothing will notice when one changes. A RAIDZ padding fix in one place means the planner and the report give different usable sizes for the same design.

## Suggested approach
Shared test vectors, not a rewrite: `tests/vectors/capacity.json` with about 20 cases (layout, disk sizes, recordsize, ashift → usable bytes) and `analysis.json` for 3-2-1 rows. A Python test runs them through `capacity.py`; a tiny Node script (no framework, `node tests/vectors/check.mjs`) imports the planner functions and runs the same file. Both in CI ([[EQ-01 No CI and untested paths|EQ-01]]).

Longer term: have the planner ask `POST /api/capacity/calc` instead, once the planner needs the server anyway (it already does for designs).

## Progress 2026-10-30
Shared cases in `tests/vectors/capacity.json`, run through both engines, in CI too. They agree on all 22.
