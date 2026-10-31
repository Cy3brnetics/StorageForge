---
id: SF-28
status: done
severity: medium
effort: S
area: Git
verified: proven
tags: [finding, audit-2026-10-31]
found: 2026-10-31
---
# SF-28 Git routes reach the server itself with host=localhost

**Medium** · effort S · Git · Proven: ran it · part of [[Audit 2026-10-31]]

## What exists
`open_host_transport` treats the names `local` and `localhost` as "run here", with no vault binding and no check that this is a host StorageForge manages.

## Evidence
- `gitrepos.py:223-229`
- Proof: `GET /api/git/status?host=localhost&path=<repo>` ran on the server. `path=/etc` answered `not a git repository`, so it also tells a caller whether a folder is a repository on the server. Used in [[SF-27 Git commands run code planted in a repository|SF-27]]'s proof.

## Why it matters
An account with `git.live`, a permission marked low risk, can run Git in any server folder. With a repository it can write to on the server, that becomes code execution there.

## Suggested approach
Delete the local branch from the web path. If the CLI needs it, pass it as an explicit argument the routes cannot set.

## Done when
- [x] `host=localhost` answers 404 unless localhost is an enrolled host

## Fixed
2026-10-31, in the working tree, not committed yet: add the commit here. Loopback names answer 404 unless a key is bound to that exact name. Test: `test_git_routes_do_not_reach_the_server`.
