---
id: SF-27
status: open
severity: high
effort: M
area: Git
verified: proven
tags: [finding, audit-2026-10-31]
found: 2026-10-31
---
# SF-27 Git commands run code planted in a repository

**High** · effort M · Git · Proven: ran it · part of [[Audit 2026-10-31]]

## What exists
Every Git command StorageForge runs on a host uses `git -c safe.directory='*'`. That switches off Git's protection against repositories owned by someone else. `git status` then honours the repository's own `core.fsmonitor`, which is a program to run. The scan survey runs `git status` on every repository `find` turns up, so no person has to do anything. The Git Inspector also runs on any `path` a user sends, without checking that it is a known repository.

## Evidence
- `gitrepos.py:53` (survey, since `0cfd47b` on 10-26, which earlier audits missed), `:277`, `:471`, `:603`, `:762` (new)
- Proof: a throwaway local repository with `core.fsmonitor` pointing at a marker script. `GET /api/git/status` ran the script (`hook ran`).
- Not run on a real host or across two users. That the survey path fires the same way, and that `safe.directory='*'` defeats the ownership check, come from reading the script and Git's documented behaviour.

## Why it matters
Any local user on a scanned host can create a repository and get code run as the scan account at the next scan. That account can read names across the disks through the capability-bearing `find`, and can read every file if it was set up with a privileged login. On an account with sudo, it is root. The scan account is meant to be read-only.

## Suggested approach
Pass neutralising options on every call: `-c core.fsmonitor=false -c core.hooksPath=/dev/null -c core.sshCommand= -c protocol.ext.allow=never -c diff.external= -c core.pager=cat`. `core.fsmonitor=false` stopped the proof when tried by hand; the other options were not tried. Better still, read what can be read without running Git in the repository (`HEAD`, refs, config parsed as text). Drop `safe.directory='*'` for repositories not owned by the scan user, or report them as not inspected. Check `path` against `git_repos` for that host.

## Done when
- [ ] The fsmonitor proof no longer fires, for survey, status, history and commit
- [ ] An unknown path is refused
