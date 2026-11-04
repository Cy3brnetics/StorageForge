---
tags: [audit-rules, tracking]
updated: 2026-11-03
---
# Audit history

**The next audit's baseline is `d78881b`**. Audit everything since.

| Date | Audit | Kind | Baseline | Head | Tree included | Findings |
| :-- | :-- | :-- | :-- | :-- | :-- | :-- |
| 2026-10-28 | `security-audit-2026-10-28.md` | Security | start | not recorded | not recorded | SF-01 to SF-22 |
| 2026-10-29 | `docs/audit-2026-10-29.md` | Docs against code | not recorded | not recorded | not recorded | |
| 2026-10-29 | [[Audit 2026-10-29 - features]] | Features | not recorded | `bc12d9c` | yes | PF-01 to PF-16, EQ-01 to EQ-03 |
| 2026-10-29 to 30 | [[Review of Gemini audit 2026-10-29]] | Security and bugs, external | not recorded | `68a6d73` | yes | GM-01 to GM-25 |
| 2026-10-31 | [[Audit 2026-10-31]] | Security and new features | `68a6d73` | `82b0eb0` | **yes** | SF-23 to SF-39, PF-18 to PF-27, EQ-04, EQ-05 |
| 2026-11-01 | [[Audit 2026-11-01]] | Remote nodes, snapshot engine, site isolation | `7855063` | `31fc091` | clean | SF-40 to SF-43, PF-28 to PF-30, EQ-06 |
| 2026-11-03 | [[Audit 2026-11-03]] | Unsigned scripts and auth on new routes | `31fc091` | `d78881b` | clean | SF-44 to SF-51, PF-31 to PF-33, EQ-07 to EQ-09 |

## Not code audits
These don't move the baseline.
- `vuln-report-storageforge-0.2.0-combined-2026-10-31.md`: Grype and Trivy over the container image. See [[SF-38 Container scan report is committed but not triaged]].

## Why the tree matters
The 10-31 audit read uncommitted changes in 10 files. **If those are committed, the commit still counts as new since `82b0eb0`**: diff it, but the review of them is in [[EQ-05 Uncommitted lab fixes need a lab run]].

## Follow-ups to check next time
- Whether the findings of [[Audit 2026-10-31]] were fixed, and whether the fixes hold
- The areas it did not review: the rest of `changes.py`, `tasks.py` and `moves.py` diffs, `fromdesign.py`, `engine.py`, `capacity.py`, `protection.py`, and the lab scripts
- `git` use in `_SURVEY_BASH`: it was missed for several audits, so check other old host scripts for tools that read config from places users control
- The focused audit of 2026-11-03 did not do the life-cycle walks. Still unreviewed since `31fc091`: `steps_infra.py`, `whatif.py`, `reach.py`, most of `mapdesign.py`, and most of `security.py`, `secplus.py` and `secscripts.py`, on PostgreSQL and in the lab
