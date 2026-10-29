---
date: 2026-10-29
tags: [audit]
scope: storageforge-indexer, working tree on master at bc12d9c plus uncommitted work
---
# Feature audit, 2026-10-29

**Question asked:** which features are only partly built, and which work but should be built better?

**Not covered here:** security (see `security-audit-2026-10-28.md`) and code-vs-docs consistency (see `docs/audit-2026-10-29.md`). Items from those audits that are still open are tracked in [[Carried over]] rather than repeated.

## Method
- Mapped every API route in `server.py` against every `/api/...` call in `static/*.js`, and every CLI subcommand against both.
- Followed each roadmap item from the 10-27 audit (section 5) into the code to see how far it got.
- Read the scheduler, alerts, backup, blueprint, planner export and cleanup code paths end to end.
- Grepped for TODO/FIXME/stub markers: there are none, so every gap below was found by comparing features with each other, not from comments.
- Ran `python3 -m unittest discover -s tests` on the host: 105 tests, 1 failure (the known T1), 23 errors. All 23 errors are `ModuleNotFoundError: flask`, so the server tests did not run in a bare checkout (see [[EQ-01 No CI and untested paths]]).

## Summary

The core (scan, index, search, plans, deploy) is complete and consistent. The gaps are where newer features were not wired back into older ones: StorageForge now deploys backups and snapshots itself but its 3-2-1 view is still typed by hand, and it knows a pool is degraded but only alerts on deploy jobs.

### Partly built
| # | Finding | Severity | Effort |
| :-- | :-- | :-- | :-- |
| [[PF-01 Alerts only cover deploys\|PF-01]] | Alerts and notifications cover deploy jobs and drift only, not scans, disks, pools or backups | **High** | M |
| [[PF-02 Protection matrix ignores deployed jobs\|PF-02]] | The 3-2-1 matrix is typed by hand, even for backups and snapshots StorageForge deployed and watches | **High** | M |
| [[PF-03 Backup and snapshot detection\|PF-03]] | Scans don't detect restic, borg, snapper, sanoid, btrbk or ZFS snapshots (roadmap #2, not started) | Medium | L |
| [[PF-04 Disk health and scrubs\|PF-04]] | No SMART data or last-scrub date; tasks can start a scrub, nothing reads the result (roadmap #3) | Medium | M |
| [[PF-05 Capacity history\|PF-05]] | Mount usage is overwritten each scan, so there is no trend or "full in N days" (roadmap #4) | Medium | M |
| [[PF-06 Move progress from scans\|PF-06]] | Hand-run move scripts record `.done` and `.cutover` on the host, but scans never read them (roadmap #1, half done) | Medium | S |
| [[PF-07 Backups have no UI and stay on the same volume\|PF-07]] | Backups: API with no UI, kept on the database's own volume, none at all on PostgreSQL | Medium | M |
| [[PF-08 No way to retire a host\|PF-08]] | A host, its index and its key bindings can't be removed; the Keys tab is list-only | Medium | M |
| [[PF-09 Accounts are CLI-only and have no roles\|PF-09]] | No password change or user admin in the UI; no roles | Medium | M |
| [[PF-10 Cleanup cache holds one result\|PF-10]] | Cold and duplicate folders share a one-entry cache and evict each other; nothing is precomputed | Low | S |
| [[PF-11 File history and content dupes are CLI-only\|PF-11]] | 90 days of file changes and checksum duplicates are stored but only reachable from the CLI | Medium | M |
| [[PF-12 Storage tasks lag the other plan types\|PF-12]] | Tasks: no CLI, no running-container warning | Low | S |
| [[PF-13 Planner export is a second script generator\|PF-13]] | The planner writes its own Bash/Ansible in the browser, outside the checked, deployable Changes pipeline | **High** · done | M |
| [[PF-14 Reports and canvas predate newer features\|PF-14]] | Markdown report and Obsidian canvas have nothing on git, shares, Docker, moves, tasks or deploys | Low | M |
| [[PF-15 Moves and Git QoL\|PF-15]] | Moves can't be duplicated or exported; Git archiving is one repo at a time with a fixed noise list | Low | S |
| [[PF-16 One scan worker and one global schedule\|PF-16]] | One scan at a time across all hosts, one interval for all of them | Medium | M |

### Engineering quality
| # | Finding | Severity | Effort |
| :-- | :-- | :-- | :-- |
| [[EQ-01 No CI and untested paths\|EQ-01]] | No CI; server tests skip silently without Flask; PostgreSQL and the 3.7k lines of browser JS untested | **High** | M |
| [[EQ-02 Two capacity engines\|EQ-02]] | Capacity and 3-2-1 math exist twice (Python and planner JS), kept equal by hand | Medium | S |
| [[EQ-03 Large modules\|EQ-03]] | `server.py` is one 1.3k-line closure; generated Bash lives in Python strings | Low | L |

## Top three
1. [[PF-13 Planner export is a second script generator|PF-13]]: it is the one path that can `wipefs` a disk without the checks the rest of the app insists on.
2. [[PF-01 Alerts only cover deploys|PF-01]] and [[PF-02 Protection matrix ignores deployed jobs|PF-02]] together: the data is already in the database, and they turn StorageForge from a map into a monitor.
3. [[EQ-01 No CI and untested paths|EQ-01]]: every other item is safer to build once the full suite runs on each commit.
