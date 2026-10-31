---
id: SF-29
status: done
severity: medium
effort: M
area: Git
verified: proven
tags: [finding, audit-2026-10-31]
found: 2026-10-31
---
# SF-29 Git Inspector breaks the scan-key and audit rules

**Medium** · effort M · Git · Proven: ran it · part of [[Audit 2026-10-31]]

## What exists
Four rules slip in one feature:
1. `fetch`, `pull` and `sync` change hosts using the binding meant for read-only scans.
2. Only `push` asks for a fresh password, though `pull` changes a working copy and runs its hooks.
3. `status`, `history` and `commit` run commands on hosts and are not audited at all. The audit of `sync` is inside `except Exception: pass`.
4. They answer GET, and `status` writes to the database. `server.py:1795` states the opposite rule: "POST: it runs a command on the host, so no GET can trigger it".

## Evidence
- `gitrepos.py:315`, `:561`, `:572-578`, `server.py:1331-1404`
- Proof: `sync` with a stale password answered 200 for fetch and 403 for push. Zero `git.*` audit rows after a status call.
- `max=-1` reaches `git log -n -1`, which has no limit (`server.py:1379`; answered 200).
- Each call unlocks the vault, which runs Argon2, with no rate limit (`gitrepos.py:234`).

## Why it matters
Concepts rule 14, "everything is audited", and rule 13 are not true for this feature. Scan keys stop being read-only in practice, so a stolen scan key can do more than the docs say if Git credentials exist on the host.

## Suggested approach
Make `git.sync` a signed deploy run, which brings password, audit, run history and the correct binding. Make `status` POST only. Audit all four, and let an audit failure fail the action. Clamp `max` to 1-200 and rate limit by account.

## Done when
- [x] No Git command that changes a host uses a `scan` binding
- [x] Every Git route writes one audit row

## Fixed
2026-10-31, in `85f805a`. Sync is a signed run as the owner of the repository's config, with hooks off. All actions need a fresh password. Status, history and commit are POST only, limited to 60 a minute per account, with `max` clamped to 1-200 and one audit row per call. Sync now **needs deploy access**, and hosts without `runuser` refuse a repository owned by someone else. The scan-to-deploy binding fallback is gone. Tests: `test_git_routes_follow_the_rules`, `test_sync_runs_no_hooks`.
