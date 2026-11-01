---
id: SF-38
status: in-progress
severity: medium
effort: M
area: Operations
verified: read
tags: [finding, audit-2026-10-31]
found: 2026-10-31
---
# SF-38 Container scan report is committed but not triaged

**Medium** · effort M · Operations · Read in the code, not run · part of [[Audit 2026-10-31]]

## What exists
`vuln-report-storageforge-0.2.0-combined-2026-10-31.md` is raw scanner output for image `storageforge:0.2.0`. Grype reports 5 critical and 84 high; Trivy reports 4 critical and 66 high. Nothing in the repo says which matter.

## Evidence
- Lines 13 and 2742 of the report.
- Critical entries in the Grype section name glibc, SQLite and OpenSSH. Mostly marked no fix available in Debian 12. These are the scanners' claims, and this audit didn't test whether any is reachable.

## Why it matters
The OpenSSH client entry (CVE-2026-60002, use-after-free when a server changes host key during a rekey) deserves the first look, because StorageForge's whole job is to run that client against hosts that might be compromised. The report also dates quickly, and at 390 KB of markdown no one will read it in review.

## Suggested approach
Triage by reachability into a short table: package, used by us or not, decision. Rebuild on a current base image and rescan. Move raw output out of git, for example into CI artifacts, and keep only the triage.

## Done when
- [x] Each critical has a written decision
- [ ] CI fails on new reachable criticals

## Progress
2026-10-31, in `d3424a1`. Triage in [[Container scan triage 2026-10-31]]: the report describes an older Debian 12 image. The raw file left git and is ignored. **Open:** a fresh scan, and the CI check.

## Progress
2026-10-31. Fresh Trivy scan in [[Container scan triage 2026-10-31]]: no criticals, one high. CI job written in `7443e46`, with an empty `.trivyignore`. **It has never run: there is no runner yet**, so that box stays open.

## Progress
2026-11-01. Rescan in [[Container scan triage 2026-10-31]]: no criticals from Trivy or Grype. The CI job had a path bug (see [[EQ-01 No CI and untested paths]]); its commands now work by hand, exit 0 on criticals and exit 1 when pointed at highs. The box stays open until it runs on a runner.
