---
id: PF-03
status: done
severity: medium
effort: L
area: "[[Data protection]]"
tags: [finding, roadmap]
found: 2026-10-29
---
# PF-03 Backup and snapshot detection

Roadmap item #2 from the 10-27 audit. **Not started.**

## What exists
The remote scan collects these sections (`remote.py`): `access btrfs df findmnt hostname ids ip jobs lsblk lvs machineid managed mountinfo nfs os smb zpool`. Bare git repos are found by walking the index, which is the same trick restic/borg detection needs.

## What is missing
Nothing finds protection that StorageForge didn't deploy:
- restic repos (`config`, `data/`, `index/`, `keys/`, `snapshots/`) and borg repos (`README` marker + `config`)
- `zfs list -t snapshot` counts and newest snapshot age; sanoid/syncoid configs
- snapper configs (`/etc/snapper/configs/*`), timeshift, btrbk configs, btrfs read-only subvolumes
- rsnapshot roots not made by StorageForge

## Suggested approach
1. Index-side detection first (no new scan sections): a `protection_repos` pass after each scan, like `gitrepos.py`, finding restic/borg repos and rsnapshot roots by their marker files. Record path, tool, size, newest file time as "last".
2. Then one new `@@snapshots` scan section: `zfs list -H -p -t snapshot -o name,creation`, `snapper --jsonout list` (when installed), `btrfs subvolume list -r -s`. Read-only commands, no new sudoers rule except for snapper.
3. Feed both into the overlay from [[PF-02 Protection matrix ignores deployed jobs|PF-02]] as `source: 'detected'`.

## Done when
- [x] A restic repo on any scanned host shows as a backup target for the datasets it lives beside (or is marked "unmatched")
- [x] ZFS and btrfs snapshot counts and newest age show in the matrix

## Progress 2026-10-30
Restic, borg and rsnapshot from the index; ZFS and btrfs snapshots. Not done: reading snapper configs into the matrix (they are collected only), timeshift, btrbk, sanoid. A detected repo fills empty rows on its host as a guess and never counts as offsite.

2026-10-31, `cc5b207`: snapper configs with their subvolumes, sanoid datasets, timeshift and btrbk now reach the matrix. Fixture tests only: the lab has none of these tools. The first Done when box was met on 10-30.
