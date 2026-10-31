---
id: PF-17
status: in-progress
severity: medium
effort: M
area: "[[Plans and the planner]]"
tags: [finding, follow-up]
found: 2026-10-29
---
# PF-17 Changes has no pool tasks

Follow-up from [[PF-13 Planner export is a second script generator|PF-13]].

## What exists
Since PF-13 the planner turns a design into change-plan tasks. `fromdesign.plan()` lists everything without a task type under "By hand".

## What is missing
Change plans can partition one disk (one partition), format, add a device to an existing btrfs pool and convert its profile. They can't:
- create a ZFS pool or dataset (`zpool create`, `zfs create`, `zfs set mountpoint`)
- create a multi-device btrfs filesystem (`mkfs.btrfs -d raid1 /dev/a /dev/b`)
- create an mdadm array or LVM volume group and volumes
- lay out more than one partition on a disk
- add bind mounts or hard links

The old planner Bash script did all of these (unchecked). A design that needs them now stops at "By hand".

## Suggested approach
Add task types to `changes.TYPES`, each with its check, Bash function and Ansible task like the existing ones: `zpool-create` (destructive, confirm every member), `zfs-dataset`, `btrfs-mkfs` (multi-device, destructive), `md-create`, `lvm-create`, `bind-mount` (a `mount` with `bind` and a path source), and a `partitions` field on `partition` for more than one partition. Then teach `fromdesign.py` to emit them instead of listing them.

## Done when
- [ ] A design with a new mirrored ZFS pool stages a `zpool-create` task that is checked, needs every member device confirmed, and only runs with `--apply --destructive`

## Progress 2026-10-30
Changes now has ZFS pool and dataset tasks and LVM volume group and volume tasks. `fromdesign.plan()` still lists them under "By hand": wiring designs to these tasks is what is left. mdadm has no tasks yet.

Later on 2026-10-30: designs now stage `zfs-pool`, `zfs-dataset`, `lvm-vg`, `lvm-vg-extend` and `lvm-lv`. Still by hand: mdadm, multi-device btrfs, several partitions on a disk, bind mounts. Those need new destructive task types, which should be run on the lab VMs as they are written.
