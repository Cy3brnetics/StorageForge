---
id: PF-03
status: open
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
- [ ] A restic repo on any scanned host shows as a backup target for the datasets it lives beside (or is marked "unmatched")
- [ ] ZFS and btrfs snapshot counts and newest age show in the matrix
