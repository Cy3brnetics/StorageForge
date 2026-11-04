---
tags: [roadmap]
updated: 2026-11-01
---
# Roadmap

The findings in the order that makes each step easier than the last. Effort: S under a day, M a few days, L a week or more.

## Now: make change safe
1. [[EQ-01 No CI and untested paths]] (M): CI is written and its commands pass by hand on both databases (2026-11-01); it has never run on a runner, which the owner must set up.
2. ~~[[PF-13 Planner export is a second script generator]]~~ done 2026-10-29. Follow-up: ~~[[PF-17 Changes has no pool tasks]]~~ done 2026-11-01: designs use the ZFS and LVM tasks.
3. ~~[[EQ-02 Two capacity engines]]~~ done 2026-10-30.

## Next: from map to monitor
4. ~~[[PF-01 Alerts only cover deploys]]~~ done 2026-10-30.
5. ~~[[PF-02 Protection matrix ignores deployed jobs]]~~ done 2026-10-30.
6. ~~[[PF-06 Move progress from scans]]~~ done 2026-10-30.
7. ~~[[PF-10 Cleanup cache holds one result]]~~ done (GM-25).

## Then: lifecycle and admin
8. ~~[[PF-08 No way to retire a host]]~~ done 2026-10-31.
9. ~~[[PF-07 Backups have no UI and stay on the same volume]]~~ done 2026-10-31.
10. ~~[[PF-09 Accounts are CLI-only and have no roles]]~~ done 2026-10-30.
11. ~~[[PF-12 Storage tasks lag the other plan types]]~~ done 2026-10-30.

## Later: new data
12. ~~[[PF-05 Capacity history]]~~ done 2026-10-30.
13. [[PF-04 Disk health and scrubs]]: built 2026-10-30; not yet run against real disks. This machine has them; the read needs the owner's sudo password.
14. ~~[[PF-03 Backup and snapshot detection]]~~ done 2026-10-31.
15. ~~[[PF-16 One scan worker and one global schedule]]~~ done 2026-10-30.
16. ~~[[PF-11 File history and content dupes are CLI-only]]~~ done 2026-10-30.

## Whenever
- ~~[[PF-14 Reports and canvas predate newer features]]~~ done 2026-10-31.
- ~~[[PF-15 Moves and Git QoL]]~~ done 2026-10-30.
- [[EQ-03 Large modules]] (L): best done just before a big change to `server.py` or a script generator.
- [Ransomware Defense & Host Security Engines](../archive/roadmaps/ransomware-defense-roadmap.md): Phased roadmap for immutable snapshots, canary tripwires, SELinux/AppArmor MAC, firewalls (nftables/iptables), auditd, Falco, AIDE, and Lynis hardening.
