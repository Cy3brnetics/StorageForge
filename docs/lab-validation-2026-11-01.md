# Lab validation, 2026-11-01

End-to-end validation of storage orchestration in the [KVM lab](kvm-lab.md), aimed at edge cases, state reconciliation and recovery. It ran at commit `d00b287`, built from a clean worktree, on `sf-ctl`, `sf-ubuntu` (ZFS), `sf-fedora` (btrfs raid1, SELinux enforcing) and `sf-rocky10` (LVM thin, XFS). Spare disks were attached for the provisioning tests. No product code was changed.

## Status after retest

The findings below describe `d00b287`. A retest of the high-severity ones ran later the same day, on the `fix/lab-validation-high` branch, built on `1038054`. Merge `fix/recovery-gaps` (`a0a25d1`) had fixed four of them in the meantime, and that branch fixes the fifth.

| # | Finding | Fixed by | Retest in the lab |
| :--- | :--- | :--- | :--- |
| 1 | Empty default reinstall script | `a0a25d1` | After a blank rescan, the default script uses the last populated version and says so |
| 2 | Export file lost on power loss | This branch | 3 of 3 crashes straight after a deploy kept the file and its exports |
| 3 | Job deploy stalls survivor SSH | `a0a25d1` | 64 SSH checks in a 333-second outage, none failed, 0.2 s at worst. Deploy stops in 12 s with a clear conflict, and deploying again after the server returns works |
| 4 | Runner keeps the old host key | `a0a25d1` | Rekey, rescan and redeploy are enough, with no cleanup on the runner. Until then the job refuses, as it should |
| 5 | Design save rejected | `a0a25d1` | Saving with a deployed rsnapshot job returns 200, and the job still shows on its row |

`a0a25d1` also addresses findings 6 to 12 and 15 in part or in full, but they weren't retested here, apart from one result: **a scan during a dead NFS outage was still running after 312 seconds**, so finding 6 needs another look.

## Summary

| Area | Result |
| :--- | :--- |
| Multi-phase plans | **Confirmed.** False alarms in both the checker and the deploy report, although the plan applies correctly |
| btrfs raid1 | **Confirmed in part.** Whole disks give no tasks. Partition members are formatted separately. No pool is created either way |
| ZFS properties | **Saved and restored from the design.** Scans can't see them, so drift goes unnoticed and a refresh erases them |
| Dead NFS server | **Confirmed.** Survivor SSH stops answering during job deploys, and scans block for the whole outage |
| Export file after power loss | **New.** A file reported as deployed was 0 bytes after a crash |
| `hosts rekey` | **Confirmed.** The job runner's `known_hosts` is never cleared |
| Stale mounts | **Confirmed.** Share deploys fail until the mount is cleared by hand |
| Rescan of a wiped host | **Confirmed.** The default script comes up empty, and `--id` recovers everything |
| Saving a design after deploy | **Confirmed.** Rejected with HTTP 400 on the source host of a job |
| Sparse restore | **Confirmed, and wider than reported.** Lost on ZFS as well as btrfs |

## Findings

Ordered by how much damage each can do.

| # | Severity | Finding | Where |
| :--- | :--- | :--- | :--- |
| 1 | High | The default reinstall script is empty after a blank rescan | `hostconfig.py:333`, `cli.py:441` |
| 2 | High | Export file lost on power failure | `shares.py:699` |
| 3 | High | Job deploy stalls survivor SSH while an NFS server is dead | `jobs.py:277` |
| 4 | High | Job runner keeps the old host key after rekey, so backups stop | `jobscript.py:203`, `cli.py:601` |
| 5 | High | Saving a design fails on hosts with deployed jobs | `protection.py:39,45`, `blueprint.py:26` |
| 6 | Medium | Scan hangs for the whole NFS outage, despite its 90-second limit | `remote.py:462` |
| 7 | Medium | Restore loses sparseness | `jobscript.py:740,747` |
| 8 | Medium | Share deploy can't recover a stale mount | `shares.py` mount step |
| 9 | Medium | The planner formats btrfs pool partitions separately | `fromdesign.py` new-partition branch |
| 10 | Medium | Plan checker ignores devices added earlier in the plan | `changes.py:620,668,729,857` |
| 11 | Medium | Deploy report raises the same false conflicts | `changes.py:1108` |
| 12 | Medium | Scans don't read ZFS properties, so refresh erases them | `payloads.py:91` |
| 13 | Low | Obsolete script references | See scenario 2 |
| 14 | Low | Restore group stays `null`, so `finished_at` never appears | `deploy.py:573` |
| 15 | Low | Config summary says "0 mounts" on a ZFS host with mounted datasets | `hostconfig.py:338` |

## Scenario results

### 1. Multi-phase planning

One 12-task plan added partitions on `sf-rocky10` and `sf-ubuntu`, then formatted, mounted and built an LVM group and a ZFS mirror on them.

- **Check on a clean index:** 4 critical alarms, all false: `/dev/vdc2`, `/dev/vdc3`, `/dev/vdf1` and `/dev/vdf2` "not seen by the last scan". There were also 2 warnings, one about a label the same plan creates.
- **Deploy report:** `failed`, with 3 false conflicts saying each is "not a block device". The UI offers only a red **Apply anyway** at this point.
- **Apply:** all 12 tasks succeeded in a single run, so a split and an intermediate rescan aren't technically needed. The false alarms just push people towards one, or towards overriding a real warning.
- **Wrong preview:** the report showed the second partition at the same offset as the first (1 to 1025 MiB). Apply correctly used 1025 to 2049 MiB.
- **Re-check after apply:** the checker gives 15 critical alarms on the finished plan, though a rerun changes nothing and passes.

### 2. btrfs and ZFS provisioning

**btrfs raid1**

| Design | Plan |
| :--- | :--- |
| Two whole disks in a raid1 pool | No tasks. "Create it by hand, rescan, then plan the rest" |
| Two partitions in a raid1 pool | Formats each one separately, then says to create the pool by hand |

Applying the second gave two independent one-device filesystems, both labelled `qapool`, with different UUIDs. A later `mkfs.btrfs` by hand has to overwrite them.

A hand-written plan does work: format one disk, mount it, add the second, then convert. The result was verified as raid1 for data, metadata and system. The checker still gives false critical alarms on it (twice "raid1 needs 2 devices; this filesystem has 1"), because it ignores the device added earlier in the plan.

**Obsolete references**

- `disaster-recovery.md:94` tells readers to use "the planner's build script", which `fromdesign.py` says was replaced.
- `index.html:125` and `moves.js:66` still mention `storage-setup.sh` to users.
- `blueprint.py:23` and the comment on `api_planner_save` in `server.py` still mention build scripts.

**ZFS properties**

`tank` already has `compression=lz4` and `atime=off`, which made the first attempt a false pass: the dataset simply inherited them. The retest set the parent to `off` and `on`.

| Step | Result |
| :--- | :--- |
| Saved design | Records both properties |
| Deploy | `zfs set` runs, and both show as `local` |
| Destroy the dataset, plan again from the saved design | Both restored as `local` |
| Change them on the host, rescan, plan again | **No tasks: the drift goes unnoticed** |
| Refresh from scan, then save | **Both properties are gone from the design** |
| Reinstall script | Lists the dataset without properties. Importing an intact pool keeps them, but the script can't recreate them |

### 3. Dead NFS server

`sf-ubuntu` was powered off with `sf-rocky10` and `sf-fedora` as clients. Mounts were `hard`, as deployed.

| Measure on `sf-rocky10`, 222-second outage | Result |
| :--- | :--- |
| SSH while idle | 0.2 s at worst |
| SSH during a job deploy | **Two 30-second timeouts and an 18-second stall** |
| `daemon-reload` during that deploy | **90 seconds**, against 0.3 s normally, with `systemd-fstab-generator` in D state |
| Job deploy, report stage | 3 s, succeeded |
| Job deploy, apply stage | 138 s, succeeded, so slow but not hung |
| `df` | Timed out on every attempt in the first run |
| Scan of the survivor | Blocked until the server returned, then failed. 916 s in a 932-second outage, and 220 s in the 222-second one |
| Share deploy with the server dead | Not finished after 60 s. It ended `failed` for the server and `ok` for the clients |

**Recovery after a clean sync:** port 2049 answered 15.6 s after power-on, and the mount worked 1.1 s later. Clients needed no action, except that one kernel thread stayed in D state for some time.

**Recovery without a sync:** the first run powered the server off about 40 seconds after a successful share deploy. `/etc/exports.d/storageforge.exports` came back at **0 bytes**, so nothing was exported and clients got "Permission denied". Recovery never happened without a redeploy. This was seen once, and the synced rerun kept its 194 bytes. `own_file` writes in place with no sync or atomic rename, and other deployed config may be exposed the same way.

**Rekey:** `sf-rocky10`'s host keys were regenerated.

- Before rekey, scans and deploys were correctly refused, and they named the fix.
- `hosts rekey`, a rescan and a job redeploy all succeeded.
- The job on `sf-fedora` still failed: `rsync failed (exit 5): Host key verification failed`. Its `/var/lib/storageforge/known_hosts` still held the old key, and nothing reports this at deploy time.
- `ssh-keygen -R 10.77.0.23 -f /var/lib/storageforge/known_hosts` on the runner fixed it.

**Stale mount:** the export was recreated with a new filesystem ID, giving `Stale file handle` on the client.

- The report said only `missing  not mounted`, and it passed.
- Apply failed: `mount.nfs4: Stale file handle`.
- The scan of that host still reported `ok`.
- `umount -f -l /mnt/qa-stale` fixed it, and the next deploy passed.

### 4. Reinstall and rescan

`sf-rocky10`'s root disk was replaced with a fresh image, keeping its data disks. After `hosts rekey` and a rescan:

| Version | Mounts | `/srv/thin` in the script |
| :--- | :--- | :--- |
| 11, newest (blank) | 0 | **No: the default script does nothing and reports "no conflicts"** |
| 9, populated | 3 | Yes |

`config script sf-rocky10 --id 9`, then `--apply`, activated LVM and restored the fstab lines and mounts, including the seed data on `/srv/thin`. Accounts already existed on the fresh image. A rescan then made the default script correct again.

A blank version doesn't look like an error anywhere, and someone who trusts the default loses the recovery path. Versions also age out after 30, so repeated scans of a blank host would eventually remove the good one.

### 5. Saving after deployment

With rsnapshot and copy jobs deployed, saving an unchanged design gave:

```text
HTTP 400: design.protection[2].deployed[0] has a line break, control character or one of < > " `
```

The text is `job rsnapshot sf-ubuntu:/tank/media -> sf-fedora:/data/backups/qa-rs`, which the server wrote itself. The `>` in the job name fails its own check. `sf-rocky10` and `sf-fedora` saved without error in this run, since `sf-ubuntu` was the only one with a `job …` row in its design. The protection matrix only lists mirror and rsnapshot jobs, so `sf-fedora`'s copy job added no such row.

The rejection was seen through the API, and the page wasn't clicked. The planner page sends `deployed` back as well (`planner.js:500`), so **Save design** should fail the same way.

Related: the rsnapshot folder on `sf-fedora` marked `/`, `/home`, `/var`, `/data/media` and `/data/snaps` as backed up, while the job actually backs up `sf-ubuntu`.

### 6. Sparse restore

A 1 GiB sparse file with two small writes, restored from rsnapshot. All checksums matched.

| Target | Source | Backup | Restored | True disk use |
| :--- | :--- | :--- | :--- | :--- |
| btrfs, `compress=zstd` | 8 KiB | 43 KiB | **1 GiB by `du`** | 32 MiB, 8,195 extents |
| ZFS, `lz4` | 43 KiB | 8 KiB | 43 KiB | 43 KiB |
| ZFS, compression off | 288 KiB | not measured | **1.02 GiB** | 1.02 GiB |

The backup keeps the holes. The restore loses them on every filesystem, because `pack` and `unpack` use `tar` without `-S`. ZFS with `lz4` only looks fine because compression absorbs the zeros, and btrfs's real cost is hidden the same way. On an uncompressed target, the restore could fill the disk.

**Clean-up:** a two-task change plan moved the file out and sent the emptied `.restored-<time>` folder to the trash, on both targets, with no false alarms. Size and checksum were unchanged.

`restorecon -Rv` on `sf-fedora` relabelled from `unlabeled_t` to `default_t`. The source folder had the same label, so that comes from this lab's `/data` paths having no policy, not from the restore.

## Limits of this validation

- Everything went through the API and CLI, not by clicking through the web UI. The planner designs for btrfs were hand-written JSON in the shape the planner sends.
- The export file loss was seen once. The other outage timings come from one or two runs.
- Only NFSv4.2 `hard` mounts and a powered-off server were tested. SMB, `soft` mounts and network partitions were not.
- Only `rsnapshot` restores were tested.
- The lab's own scripts handle key installation after a reinstall.
