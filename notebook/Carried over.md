---
tags: [tracking]
updated: 2026-10-30
---
# Carried over

Status of items from earlier audits, checked against the code on 2026-10-29. Security items (SF-xx) are tracked in `security-audit-2026-10-28.md` and only listed here when they overlap a feature finding.

## From the 10-27 audit (QoL, gaps, next features)
| Item | Status | Where now |
| :-- | :-- | :-- |
| B1 planner drops share fields | done | `planner.js:1027` keeps `raw` |
| B2 duplicate deployed shares | done | `merge_shares` |
| B3 one host, two scan names | done | `App.canonical`, `server.py:193` |
| B4 rescan burst on restart | done | `due_hosts`, `server.py:242` |
| O1 database backup | partly | [[PF-07 Backups have no UI and stay on the same volume]] |
| O2 memory limit | done | compose sets 2 GiB |
| O3 pruning | done | `db.prune` |
| O4 pinned dependencies | done | `docker/requirements*.lock` |
| O5 commit the work | partly | several commits since; the working tree again has 19 modified and 5 new files |
| O6 noisy request log | done | `STORAGEFORGE_ACCESS_LOG` |
| O7 PostgreSQL untested | done | `STORAGEFORGE_TEST_PG` runs the whole suite |
| U1 tab groups | done | vertical rail grouped Inspect, Plan, Inventory, Admin (`index.html:136`) |
| U2 state in the URL hash | done | `app.js:848` |
| U3 long link lists, unreadable link targets | not checked | |
| U4 Cleanup precomputed | partly | cache fixed ([[PF-10 Cleanup cache holds one result]]); nothing is precomputed |
| U5 remote edges in the graph | not checked | |
| U6 reports cover new features | open | [[PF-14 Reports and canvas predate newer features]] |
| U7 Moves duplicate/export | open | [[PF-15 Moves and Git QoL]] |
| U8 Git ignore list, bulk archive | open | [[PF-15 Moves and Git QoL]] |
| Roadmap 1 move progress | partly | [[PF-06 Move progress from scans]] |
| Roadmap 2 backup detection | open | [[PF-03 Backup and snapshot detection]] |
| Roadmap 3 disk health | open | [[PF-04 Disk health and scrubs]] |
| Roadmap 4 capacity history | open | [[PF-05 Capacity history]] |
| Roadmap 5 notifications | done | [[PF-01 Alerts only cover deploys]] |
| Roadmap 6 per-host schedules | open | [[PF-16 One scan worker and one global schedule]] |
| Roadmap 7 roles | open | [[PF-09 Accounts are CLI-only and have no roles]] |

## From the 10-29 consistency audit (`docs/audit-2026-10-29.md`)
| Item | Status | Evidence |
| :-- | :-- | :-- |
| C1 entrypoint subcommands | done | |
| B1 essentials backup tables | done | |
| S1 loopback host becomes a local scan | done | `cli.scans_here` |
| S2 BrokenPipeError unreachable | done | handler now comes first |
| P1 tasks CLI | open | [[PF-12 Storage tasks lag the other plan types]] |
| P2 tasks container warning | open | [[PF-12 Storage tasks lag the other plan types]] |
| P3 one feature, three names | open | |
| A1 settings without password check | done | `api_deploy_settings` calls `password_stale()` on PUT |
| T1 test fails with scan access installed | open | reproduced 2026-10-29 |

## Security items that overlap feature work
- SF-02 flat authorization → [[PF-09 Accounts are CLI-only and have no roles]]
- SF-17 planner scripts unescaped → [[PF-13 Planner export is a second script generator]] (the script half is gone: the planner writes no Bash or Ansible now)
