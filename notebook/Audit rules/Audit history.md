---
tags: [audit-rules, tracking]
updated: 2026-10-31
---
# Audit history

**The next audit's baseline is the newest row's Head.** Audit everything since.

| Date | Audit | Kind | Baseline | Head | Tree included | Findings |
| :-- | :-- | :-- | :-- | :-- | :-- | :-- |
| 2026-10-28 | `security-audit-2026-10-28.md` | Security | start | not recorded | not recorded | SF-01 to SF-22 |
| 2026-10-29 | `docs/audit-2026-10-29.md` | Docs against code | not recorded | not recorded | not recorded | |
| 2026-10-29 | [[Audit 2026-10-29 - features]] | Features | not recorded | `bc12d9c` | yes | PF-01 to PF-16, EQ-01 to EQ-03 |
| 2026-10-29 to 30 | [[Review of Gemini audit 2026-10-29]] | Security and bugs, external | not recorded | `68a6d73` | yes | GM-01 to GM-25 |
| 2026-10-31 | [[Audit 2026-10-31]] | Security and new features | `68a6d73` | `82b0eb0` | **yes** | SF-23 to SF-39, PF-18 to PF-27, EQ-04, EQ-05 |

## Not code audits
These don't move the baseline.
- `vuln-report-storageforge-0.2.0-combined-2026-10-31.md`: Grype and Trivy over the container image. See [[SF-38 Container scan report is committed but not triaged]].

## Why the tree matters
The 10-31 audit read uncommitted changes in 10 files. **If those are committed, the commit still counts as new since `82b0eb0`**: diff it, but the review of them is in [[EQ-05 Uncommitted lab fixes need a lab run]].

## Follow-ups to check next time
- Whether the findings of [[Audit 2026-10-31]] were fixed, and whether the fixes hold
- The areas it did not review: the rest of `changes.py`, `tasks.py` and `moves.py` diffs, `fromdesign.py`, `engine.py`, `capacity.py`, `protection.py`, and the lab scripts
- `git` use in `_SURVEY_BASH`: it was missed for several audits, so check other old host scripts for tools that read config from places users control
