---
id: PF-04
status: open
severity: medium
effort: M
area: "[[Alerts and monitoring]]"
tags: [finding, roadmap]
found: 2026-10-29
---
# PF-04 Disk health and scrubs

Roadmap item #3 from the 10-27 audit. **Not started**, but half of the pieces exist.

## What exists
- Change plans can start a btrfs scrub (`changes.py:781 t_scrub`), and storage tasks have a `scrub` block and a "Weekend scrub" template (`tasks.py:105,137`).
- `zpool status` is collected, so ZFS scrub results are in the inventory already; `analysis.py:247` suggests "run a scrub, check SMART".

## What is missing
- Nothing reads `btrfs scrub status` or `btrfs device stats` back, so a scrub StorageForge started has no visible result.
- No SMART data at all (`smartctl -j -a`).
- The ZFS last-scrub line is in the inventory but not shown or checked.

## Suggested approach
1. New scan section `@@health`: `btrfs device stats -c` and `btrfs scrub status -R` per btrfs mount, and `smartctl -j -a` per disk. All three need root, so add them to the read-only scan access as narrow sudoers rules with fixed arguments, like the existing rsync rule (`access.py`); skip the section quietly where the rule isn't installed.
2. Parse into `disk.health = {smart: ok|warn|fail, reallocated, pending, temp, power_on_hours}` and `pool.last_scrub`.
3. Show a dot on disk boxes in the topology; add findings to `analysis.py` (`crit` for SMART fail or device errors, `warn` for no scrub in 35 days); [[PF-01 Alerts only cover deploys|PF-01]] then alerts on them.

## Done when
- [ ] A disk with reallocated sectors shows as warn in the topology and raises an alert
- [ ] Each btrfs/ZFS pool shows when it was last scrubbed and with how many errors
