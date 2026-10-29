---
tags: [roadmap]
updated: 2026-10-29
---
# Roadmap

The findings in the order that makes each step easier than the last. Effort: S under a day, M a few days, L a week or more.

## Now: make change safe
1. [[EQ-01 No CI and untested paths]] (M): one test command that runs in the image, CI on SQLite and PostgreSQL. Everything after this is safer.
2. ~~[[PF-13 Planner export is a second script generator]]~~ done 2026-10-29. Follow-up: [[PF-17 Changes has no pool tasks]] (M).
3. [[EQ-02 Two capacity engines]] (S): shared test vectors, run in the new CI.

## Next: from map to monitor
4. [[PF-01 Alerts only cover deploys]] (M): scan failures, gone mounts, full disks, degraded pools. Uses data already stored.
5. [[PF-02 Protection matrix ignores deployed jobs]] (M): fill 3-2-1 from deployed jobs; unlocks "backup is late" alerts.
6. [[PF-06 Move progress from scans]] (S): one scan section.
7. [[PF-10 Cleanup cache holds one result]] (S): small fix, visible every time Cleanup opens.

## Then: lifecycle and admin
8. [[PF-08 No way to retire a host]] (M)
9. [[PF-07 Backups have no UI and stay on the same volume]] (M)
10. [[PF-09 Accounts are CLI-only and have no roles]] (M): password change first; roles before a second user.
11. [[PF-12 Storage tasks lag the other plan types]] (S)

## Later: new data
12. [[PF-05 Capacity history]] (M)
13. [[PF-04 Disk health and scrubs]] (M)
14. [[PF-03 Backup and snapshot detection]] (L)
15. [[PF-16 One scan worker and one global schedule]] (M)
16. [[PF-11 File history and content dupes are CLI-only]] (M)

## Whenever
- [[PF-14 Reports and canvas predate newer features]] (M)
- [[PF-15 Moves and Git QoL]] (S)
- [[EQ-03 Large modules]] (L): best done just before a big change to `server.py` or a script generator.
