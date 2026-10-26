---
report: storageforge-architecture
schema_version: 1
system: atlas
scope: single-host
generated_at: 2026-10-26T21:09:36Z
as_of: 2026-10-26
nodes: [atlas]
capacity_bytes:
  raw: 145126849331200
  usable: 95269026838020
  allocated: 72273444156208
  free: 22995582681812
protection: {protected: 4, local_only: 2, critical: 3, excluded: 1}
findings: {critical: 7, warning: 7}
power_watts: {idle: 54.5, active: 98.5}
---

# StorageForge Architecture Report: atlas

> Generated 2026-10-26T21:09:36Z · data as of 2026-10-26 · scope: single-host · 7 critical and 7 warning findings

## 1. Executive Summary & Topology Blueprint

### 1.1 System identity

| Node | Node ID | IP address | Operating system | Last scanned | Inputs |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `atlas` | `node-ece8f46b` | — | — | not scanned (design input) | StorageForge blueprint (storageforge/v1, generated 2026-10-26); zpool status (1 pool); /etc/fstab (15 entries); df (16 filesystems) |

### 1.2 Capacity

| Metric | Binary | Decimal | Notes |
| :--- | ---: | ---: | :--- |
| Raw capacity | 131.99 TiB | 145.13 TB | 12 local block devices |
| Usable capacity | 86.65 TiB | 95.27 TB | 65.6% of raw after parity, mirrors, padding and reserves |
| Allocated | 65.73 TiB | 72.27 TB | 75.9% of usable (from df) |
| Free headroom | 20.91 TiB | 23.00 TB | usable − allocated |
| Remote / mesh (attached) | 46.00 TiB | 50.58 TB | network mounts, not counted above |

### 1.3 Key findings

1. 🔴 **/dev/sdi1 is misaligned (starts at sector 63)**. The start is not a multiple of the 4096-byte physical sector, so 4K writes become read-modify-write cycles. Recreate the partition at 1 MiB (sector 2048).
2. 🔴 **symlink /home/ops/Archive**. Target is on /mnt/archive, which is disconnected (NetBird)
3. 🔴 **symlink /opt/app/current**. Circular symlink /opt/app/current → /opt/app/releases/live → /opt/app/current (ELOOP)
4. 🔴 **symlink /opt/app/releases/live**. Circular symlink /opt/app/releases/live → /opt/app/current → /opt/app/releases/live (ELOOP)
5. 🔴 **tank/vm protection is critical**. Replication lagging 6 h 40 min; backup not validated for 116 days.
6. 🔴 **md0 (cold) protection is critical**. Replication target unreachable.
7. 🔴 **legacy protection is critical**. Single copy: no snapshots, sync or backup.
8. 🟡 **/dev/sdi uses MBR on a 3 TB disk**. MBR addresses 2 TiB with 512-byte sectors; 746.52 GiB is unreachable. Back up, then convert with `sgdisk -g`.
9. 🟡 **`discard` on spinning disk /dev/sdi1**. TRIM has no effect on a hard drive and some SATA bridges error on it. Remove the option.
10. 🟡 **Pool tank: scsi-SSEAGATE_ST20000NM002D_ZVT04431K reports errors (R/W/C 0/0/2)**. Run a scrub, check SMART and cabling, then `zpool clear` once the cause is known.
11. 🟡 **Root filesystem is on a single device**. `/` lives on /dev/nvme0n1 with no mirror. Snapshots cover bad upgrades, not drive failure; keep the offsite backup validated or mirror the root.
12. 🟡 **/mnt/legacy is 90% full**. 191.00 GiB available. Filesystems fragment and slow down as they fill; copy-on-write ones (ZFS, btrfs) suffer first.
13. 🟡 **Remote target office-nas archive is disconnected**. SMB3 via NetBird: everything under /mnt/archive is unavailable.
14. 🟡 **bind /var/lib/docker**. /var/lib/docker already holds data; the bind mount hides it until it is migrated
15. 🔵 **ZFS snapshot space is not in the allocated figure**. `df` reports each dataset's referenced data only. Use `zfs list -o space` for snapshot usage.

### 1.4 Topology map

Flow: physical device or remote target → pool / RAID → partition or dataset → mount point → link.

```text
atlas  (node-ece8f46b)
├── [FAST TIER]
│   ├── nvme0n1  Samsung SSD 990 PRO 2TB [NVMe PCIe Gen4 x4] 1.82 TiB
│   │   ├── p1   vfat                 1.00 GiB → /boot/efi
│   │   └── p2   btrfs                1.82 TiB
│   │       ├── @ → /
│   │       │   ├── ⇠ /opt/app/current (symlink)  ✗ broken
│   │       │   └── ⇠ /opt/app/releases/live (symlink)  ✗ broken
│   │       ├── @home → /home
│   │       ├── @var_log → /var/log
│   │       └── @snapshots → /.snapshots
│   ├── nvme1n1  WD_BLACK SN850X 4000GB [NVMe PCIe Gen4 x4] 3.64 TiB
│   │   ├── p1   xfs                  3.00 TiB → /mnt/fast_scratch
│   │   │   ├── ⇇ /var/lib/docker (bind)  ! warning
│   │   │   └── ⇇ /var/lib/containerd (bind)
│   │   ├── p2   f2fs               400.00 GiB → /mnt/burst
│   │   └── p3   zfs_member         254.02 GiB → tank (cache)
│   └── nvme2n1  INTEL SSDPEK1A118GA (Optane P1600X) [NVMe PCIe Gen3 x4] 110.28 GiB
│       └── p1   zfs_member          32.00 GiB → tank (log)
├── [MASS TIER]
│   ├── sda      Seagate Exos X20 ST20000NM002D [SAS 12Gb/s] 18.19 TiB
│   │   └── whole disk → pool tank
│   ├── sdb      Seagate Exos X20 ST20000NM002D [SAS 12Gb/s] 18.19 TiB
│   │   └── whole disk → pool tank
│   ├── sdc      Seagate Exos X20 ST20000NM002D [SAS 12Gb/s] 18.19 TiB
│   │   └── whole disk → pool tank
│   ├── sdd      Seagate Exos X20 ST20000NM002D [SAS 12Gb/s] 18.19 TiB
│   │   └── whole disk → pool tank
│   ├── sde      Seagate Exos X20 ST20000NM002D [SAS 12Gb/s] 18.19 TiB
│   │   └── whole disk → pool tank
│   ├── sdf      Seagate Exos X20 ST20000NM002D [SAS 12Gb/s] 18.19 TiB
│   │   └── whole disk → pool tank
│   ├── sdg      WDC WD80EFZZ (Red Plus 8TB) [SATA 6Gb/s] 7.28 TiB
│   │   └── 1    linux_raid_member    7.28 TiB → md0 (data)
│   ├── sdh      WDC WD80EFZZ (Red Plus 8TB) [SATA 6Gb/s] 7.28 TiB
│   │   └── 1    linux_raid_member    7.28 TiB → md0 (data)
│   ├── sdi      ST3000DM008 (Barracuda 3TB) [SATA 6Gb/s] 2.73 TiB
│   │   └── 1    ext4                 2.00 TiB → /mnt/legacy
│   ├── tank  zfs raidz2  usable 72.64 TiB
│   │   ├── data: sda sdb sdc sdd sde sdf
│   │   ├── log (SLOG): nvme2n1p1
│   │   ├── cache (L2ARC): nvme1n1p3
│   │   ├── tank → /mnt/storage_array
│   │   ├── tank/media → /mnt/storage_array/media  [recordsize=1M compression=zstd]
│   │   │   ├── ⇠ /var/media (symlink)
│   │   │   └── ⇔ /mnt/storage_array/media/movies/Arrival (2016).mkv (hardlink)
│   │   ├── tank/photos → /mnt/storage_array/photos  [recordsize=1M compression=zstd]
│   │   │   └── ⇠ /home/ops/Pictures/RAW (symlink)
│   │   ├── tank/vm → /mnt/storage_array/vm  [recordsize=64K compression=lz4]
│   │   └── tank/backups → /mnt/storage_array/backups  [recordsize=1M compression=zstd]
│   └── md0  mdadm raid1  usable 6.80 TiB
│       ├── data: sdg1 sdh1
│       └── ext4 → /mnt/cold
└── [REMOTE / MESH]
    ├── sdj      LIO-ORG vmstore (iSCSI LUN 0) [iSCSI LUN · 10GbE] 2.00 TiB
    │   └── 1    xfs                  2.00 TiB → /mnt/iscsi_vm
    │       └── ⇠ /srv/vm-images (symlink)
    ├── nas-02.tail4c2e.ts.net:/export/archive  NFSv4.2 via Tailscale → /mnt/remote_nfs
    ├── b2:atlas-offsite  S3 (rclone) via Internet · TLS → /mnt/remote_s3
    └── //office-nas.nb.internal/archive  SMB3 via NetBird → /mnt/archive  ✗ disconnected
        └── ⇠ /home/ops/Archive (symlink)  ✗ broken
```

Legend: `⇠` symlink · `⇇` bind mount · `⇔` hard link · `✗` broken or offline.

## 2. Node & Disk Inventory

### 2.1 `atlas`

#### Drives

| Device | Model | Serial | Interface | Media | Capacity | Sectors (L/P) | Table | Tier | Role |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `/dev/nvme0n1` | Samsung SSD 990 PRO 2TB | `S6Z2NJ0W412345A` | NVMe PCIe Gen4 x4 | NVMe | 1.82 TiB · 2.00 TB | 512/4096 | GPT | Fast NVMe/SSD | btrfs, vfat |
| `/dev/nvme1n1` | WD_BLACK SN850X 4000GB | `23174M800123` | NVMe PCIe Gen4 x4 | NVMe | 3.64 TiB · 4.00 TB | 512/4096 | GPT | Fast NVMe/SSD | f2fs, tank, xfs |
| `/dev/nvme2n1` | INTEL SSDPEK1A118GA (Optane P1600X) | `PHOC2140009X118B` | NVMe PCIe Gen3 x4 | NVMe | 110.28 GiB · 118.41 GB | 512/512 | GPT | Fast NVMe/SSD | tank |
| `/dev/sda` | Seagate Exos X20 ST20000NM002D | `ZVT04410K` | SAS 12Gb/s | HDD | 18.19 TiB · 20.00 TB | 512/4096 | GPT | Mass HDD | whole-disk member of tank |
| `/dev/sdb` | Seagate Exos X20 ST20000NM002D | `ZVT04417K` | SAS 12Gb/s | HDD | 18.19 TiB · 20.00 TB | 512/4096 | GPT | Mass HDD | whole-disk member of tank |
| `/dev/sdc` | Seagate Exos X20 ST20000NM002D | `ZVT04424K` | SAS 12Gb/s | HDD | 18.19 TiB · 20.00 TB | 512/4096 | GPT | Mass HDD | whole-disk member of tank |
| `/dev/sdd` | Seagate Exos X20 ST20000NM002D | `ZVT04431K` | SAS 12Gb/s | HDD | 18.19 TiB · 20.00 TB | 512/4096 | GPT | Mass HDD | whole-disk member of tank |
| `/dev/sde` | Seagate Exos X20 ST20000NM002D | `ZVT04438K` | SAS 12Gb/s | HDD | 18.19 TiB · 20.00 TB | 512/4096 | GPT | Mass HDD | whole-disk member of tank |
| `/dev/sdf` | Seagate Exos X20 ST20000NM002D | `ZVT04445K` | SAS 12Gb/s | HDD | 18.19 TiB · 20.00 TB | 512/4096 | GPT | Mass HDD | whole-disk member of tank |
| `/dev/sdg` | WDC WD80EFZZ (Red Plus 8TB) | `VK1A2B3C` | SATA 6Gb/s | HDD | 7.28 TiB · 8.00 TB | 512/4096 | GPT | Mass HDD | md0 |
| `/dev/sdh` | WDC WD80EFZZ (Red Plus 8TB) | `VK1A9Q7D` | SATA 6Gb/s | HDD | 7.28 TiB · 8.00 TB | 512/4096 | GPT | Mass HDD | md0 |
| `/dev/sdi` | ST3000DM008 (Barracuda 3TB) | `Z5059XYZ` | SATA 6Gb/s | HDD | 2.73 TiB · 3.00 TB | 512/4096 | MBR | Mass HDD | ext4 |
| `/dev/sdj` | LIO-ORG vmstore (iSCSI LUN 0) | `iqn.2024-03.lan.nas02:vmstore` | iSCSI LUN · 10GbE | Network LUN | 2.00 TiB · 2.20 TB | 512/4096 | GPT | Remote / mesh | xfs |

#### Partition layout

| Partition | Start | Size | Aligned | Filesystem | Label | Mount / membership |
| :--- | ---: | ---: | :--- | :--- | :--- | :--- |
| `/dev/nvme0n1p1` | 2048 s | 1.00 GiB · 1.07 GB | ✅ 1 MiB | vfat | `EFI` | /boot/efi |
| `/dev/nvme0n1p2` | 2099200 s | 1.82 TiB · 2.00 TB | ✅ 1 MiB | btrfs | `atlas-root` | @→/, @home→/home, @var_log→/var/log, @snapshots→/.snapshots |
| `/dev/nvme1n1p1` | 2048 s | 3.00 TiB · 3.30 TB | ✅ 1 MiB | xfs | `scratch` | /mnt/fast_scratch |
| `/dev/nvme1n1p2` | 6442452992 s | 400.00 GiB · 429.50 GB | ✅ 1 MiB | f2fs | `burst` | /mnt/burst |
| `/dev/nvme1n1p3` | 7281313792 s | 254.02 GiB · 272.75 GB | ✅ 1 MiB | zfs_member | `tank-l2arc` | tank (cache) |
| `/dev/nvme2n1p1` | 2048 s | 32.00 GiB · 34.36 GB | ✅ 1 MiB | zfs_member | `tank-slog` | tank (log) |
| `/dev/sdg1` | 2048 s | 7.28 TiB · 8.00 TB | ✅ 1 MiB | linux_raid_member | `cold-a` | md0 (data) |
| `/dev/sdh1` | 2048 s | 7.28 TiB · 8.00 TB | ✅ 1 MiB | linux_raid_member | `cold-b` | md0 (data) |
| `/dev/sdi1` | 63 s | 2.00 TiB · 2.20 TB | ❌ no | ext4 | `legacy` | /mnt/legacy |
| `/dev/sdj1` | 2048 s | 2.00 TiB · 2.20 TB | ✅ 1 MiB | xfs | `vmstore` | /mnt/iscsi_vm |

#### Pools & arrays

| Pool | Type | Layout | Data members | Log / cache | Usable | Fault tolerance | Health |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `tank` | zfs | zfs raidz2 · 1×6-wide | sda sdb sdc sdd sde sdf | log:nvme2n1p1 cache:nvme1n1p3 | 72.64 TiB · 79.86 TB | 2 drives | ONLINE · scrub repaired 128K in 14:22:07 with 0 errors on Sun Oct 12 14:46:09 2026 |
| `md0` | mdadm | mdadm raid1 · 2 members | sdg1 sdh1 | — | 6.80 TiB · 7.48 TB | 1 drive | not reported |

#### Datasets & subvolumes

| Dataset / subvolume | Mountpoint | Properties | Encryption |
| :--- | :--- | :--- | :--- |
| `@` | `/` | btrfs on /dev/nvme0n1p2 | — |
| `@home` | `/home` | btrfs on /dev/nvme0n1p2 | — |
| `@var_log` | `/var/log` | btrfs on /dev/nvme0n1p2 | — |
| `@snapshots` | `/.snapshots` | btrfs on /dev/nvme0n1p2 | — |
| `tank/media` | `/mnt/storage_array/media` | recordsize=1M, compression=zstd, sync=standard | aes-256-gcm |
| `tank/photos` | `/mnt/storage_array/photos` | recordsize=1M, compression=zstd, sync=standard | aes-256-gcm |
| `tank/vm` | `/mnt/storage_array/vm` | recordsize=64K, compression=lz4, sync=always | aes-256-gcm |
| `tank/backups` | `/mnt/storage_array/backups` | recordsize=1M, compression=zstd, sync=standard | aes-256-gcm |

#### Filesystems & mount points

| Mount point | FS | Source | fstab identifier | Mount flags | Size | Used | Use% |
| :--- | :--- | :--- | :--- | :--- | :--- | ---: | ---: |
| `/` | btrfs | `/dev/nvme0n1p2` | `UUID=ee69b530-f3f6-40b1-ad7e-42649e1a9598` | `subvol=@,noatime,compress=zstd:3,discard=async,space_cache=v2,ssd` | 1.90 TiB | 412.00 GiB | 22% |
| `/.snapshots` | btrfs | `/dev/nvme0n1p2` | `UUID=ee69b530-f3f6-40b1-ad7e-42649e1a9598` | `subvol=@snapshots,noatime,compress=zstd:3,discard=async,space_cache=v2,ssd` | 1.90 TiB | 412.00 GiB | 22% |
| `/boot/efi` | vfat | `/dev/nvme0n1p1` | `UUID=0DB2-989C` | `umask=0077,nofail` | 1022.00 MiB | 92.00 MiB | 9% |
| `/home` | btrfs | `/dev/nvme0n1p2` | `UUID=ee69b530-f3f6-40b1-ad7e-42649e1a9598` | `subvol=@home,noatime,compress=zstd:3,discard=async,space_cache=v2,ssd` | 1.90 TiB | 412.00 GiB | 22% |
| `/mnt/archive` | cifs | `//office-nas.nb.internal/archive` | `//office-nas.nb.internal/archive` | `_netdev,x-systemd.automount,credentials=/etc/samba/office.cred,uid=1000,vers=3.1.1` | — | — | — |
| `/mnt/burst` | f2fs | `/dev/nvme1n1p2` | `UUID=c559f543-91cd-4a22-aa30-878d5c6f383b` | `noatime,lazytime,compress_algorithm=zstd,atgc,gc_merge,nofail` | 400.00 GiB | 133.00 GiB | 33% |
| `/mnt/cold` | ext4 | `/dev/md0` | `UUID=c3814337-3ab7-464a-a36e-45cf431ea688` | `noatime,nofail` | 7.20 TiB | 5.10 TiB | 74% |
| `/mnt/fast_scratch` | xfs | `/dev/nvme1n1p1` | `UUID=bb7fcf22-b593-46a5-af78-f7533f5f4b88` | `noatime,inode64,logbsize=256k,nofail` | 3.00 TiB | 1.10 TiB | 35% |
| `/mnt/iscsi_vm` | xfs | `/dev/sdj1` | `UUID=aee5ed84-f358-43ef-ab33-cfe322c8272c` | `_netdev,nofail,noatime` | 2.00 TiB | 1.20 TiB | 59% |
| `/mnt/legacy` | ext4 | `/dev/sdi1` | `UUID=34ba0334-3236-42f8-aa7f-c92cb3499a37` | `defaults,discard` | 2.00 TiB | 1.70 TiB | 90% |
| `/mnt/remote_nfs` | nfs4 | `nas-02.tail4c2e.ts.net:/export/archive` | `nas-02.tail4c2e.ts.net:/export/archive` | `_netdev,x-systemd.automount,noatime,vers=4.2` | 44.00 TiB | 31.00 TiB | 70% |
| `/mnt/remote_s3` | rclone | `b2:atlas-offsite` | `b2:atlas-offsite` | `_netdev,x-systemd.automount,vfs_cache_mode=writes,config=/etc/rclone/rclone.conf,allow_other` | — | — | — |
| `/mnt/storage_array` | zfs | `tank` | `tank (zfs mountpoint)` | — | 15.00 TiB | 256 KiB | 0% |
| `/mnt/storage_array/backups` | zfs | `tank/backups` | `tank/backups (zfs mountpoint)` | — | 19.00 TiB | 3.80 TiB | 20% |
| `/mnt/storage_array/media` | zfs | `tank/media` | `tank/media (zfs mountpoint)` | — | 57.00 TiB | 42.00 TiB | 74% |
| `/mnt/storage_array/photos` | zfs | `tank/photos` | `tank/photos (zfs mountpoint)` | — | 24.00 TiB | 8.90 TiB | 37% |
| `/mnt/storage_array/vm` | zfs | `tank/vm` | `tank/vm (zfs mountpoint)` | — | 18.00 TiB | 2.60 TiB | 15% |
| `/var/log` | btrfs | `/dev/nvme0n1p2` | `UUID=ee69b530-f3f6-40b1-ad7e-42649e1a9598` | `subvol=@var_log,noatime,compress=zstd:3,discard=async,space_cache=v2,ssd` | 1.90 TiB | 412.00 GiB | 22% |

## 3. Symbolic Link & Mount Binding Hierarchy

| Source path (link) | Target path | Mount type | Backing mount | Health | Check |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `/var/media` | `/mnt/storage_array/media` | Soft symlink | `/mnt/storage_array/media` | 🟢 OK | Resolves on /mnt/storage_array/media |
| `/var/lib/docker` | `/mnt/fast_scratch/docker` | Bind mount | `/mnt/fast_scratch` | 🟡 Warning | /var/lib/docker already holds data; the bind mount hides it until it is migrated |
| `/var/lib/containerd` | `/mnt/fast_scratch/containerd` | Bind mount | `/mnt/fast_scratch` | 🟢 OK | Needs /mnt/fast_scratch mounted first (x-systemd.requires-mounts-for) |
| `/home/ops/Pictures/RAW` | `/mnt/storage_array/photos/raw` | Soft symlink | `/mnt/storage_array/photos` | 🟢 OK | Resolves on /mnt/storage_array/photos |
| `/home/ops/Archive` | `/mnt/archive/2019` | Soft symlink | `/mnt/archive` | 🔴 Broken | Target is on /mnt/archive, which is disconnected (NetBird) |
| `/opt/app/current` | `/opt/app/releases/live` | Soft symlink | `/` | 🔴 Broken | Circular symlink /opt/app/current → /opt/app/releases/live → /opt/app/current (ELOOP) |
| `/opt/app/releases/live` | `/opt/app/current` | Soft symlink | `/` | 🔴 Broken | Circular symlink /opt/app/releases/live → /opt/app/current → /opt/app/releases/live (ELOOP) |
| `/mnt/storage_array/media/movies/Arrival (2016).mkv` | `/mnt/storage_array/media/downloads/Arrival (2016).mkv` | Hard link | `/mnt/storage_array/media` | 🟢 OK | Same filesystem (/mnt/storage_array/media) |
| `/srv/vm-images` | `/mnt/iscsi_vm/images` | Soft symlink | `/mnt/iscsi_vm` | 🟢 OK | Resolves on /mnt/iscsi_vm |

### 3.1 Boot sequence and ordering dependencies

Each stage mounts only after every mount it depends on. Bind mounts carry `x-systemd.requires-mounts-for=<source>`; network mounts wait for `network-online.target`.

1. Stage 0: `/`
2. Stage 1: `/.snapshots` (after /); `/boot/efi` (after /); `/home` (after /); `/mnt/archive` (after /, network-online.target); `/mnt/burst` (after /); `/mnt/cold` (after /); `/mnt/fast_scratch` (after /); `/mnt/iscsi_vm` (after /, network-online.target); `/mnt/legacy` (after /); `/mnt/remote_nfs` (after /, network-online.target); `/mnt/remote_s3` (after /, network-online.target); `/mnt/storage_array` (after /, zfs-import.target); `/var/log` (after /)
3. Stage 2: `/mnt/storage_array/backups` (after /mnt/storage_array, zfs-import.target); `/mnt/storage_array/media` (after /mnt/storage_array, zfs-import.target); `/mnt/storage_array/photos` (after /mnt/storage_array, zfs-import.target); `/mnt/storage_array/vm` (after /mnt/storage_array, zfs-import.target); `/var/lib/containerd` (after /, /mnt/fast_scratch); `/var/lib/docker` (after /, /mnt/fast_scratch)

### 3.2 Link warnings

- 🟡 `/var/lib/docker` → `/mnt/fast_scratch/docker`: /var/lib/docker already holds data; the bind mount hides it until it is migrated.
- 🔴 `/home/ops/Archive` → `/mnt/archive/2019`: Target is on /mnt/archive, which is disconnected (NetBird).
- 🔴 `/opt/app/current` → `/opt/app/releases/live`: Circular symlink /opt/app/current → /opt/app/releases/live → /opt/app/current (ELOOP).
- 🔴 `/opt/app/releases/live` → `/opt/app/current`: Circular symlink /opt/app/releases/live → /opt/app/current → /opt/app/releases/live (ELOOP).

## 4. Resilience & Data Protection Matrix (3-2-1 Health Audit)

| Dataset / Path | Tier | Replication / Sync | Snapshot Retention | Offsite Backup Target | Protection Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `/` | Fast NVMe/SSD | None | snapper: hourly 24 · daily 7 · pre/post pacman | restic → B2 (offsite, restic AES-256; validated 2026-10-24) | 🟢 Protected |
| `/home` | Fast NVMe/SSD | Rsync Scheduled (nas-02 nightly 02:30) | snapper: hourly 12 · daily 14 | restic → B2 (offsite, restic AES-256; validated 2026-10-24) | 🟢 Protected |
| `/mnt/storage_array/media` | Mass HDD | Active Sync (syncoid → nas-02/media, lag 12 min) | sanoid: daily 30 · monthly 6 | None | 🟡 Local Only |
| `/mnt/storage_array/photos` | Mass HDD | Active Sync (syncoid → nas-02/photos, lag 9 min) | sanoid: hourly 24 · daily 30 · monthly 12 | restic → B2 (offsite, ZFS native + restic; validated 2026-10-19) | 🟢 Protected |
| `/mnt/storage_array/vm` | Mass HDD | Lagging (syncoid → nas-02/vm, lag 6 h 40 min) | sanoid: frequent 4 · hourly 48 | PBS → pbs-02 (offsite, PBS AES-256-GCM; validated 2026-07-02) | 🔴 Critical |
| `/mnt/storage_array/backups` | Mass HDD | Active Sync (zfs send → nas-02, lag 31 min) | sanoid: daily 14 · weekly 8 | age → S3 Glacier IR (offsite, age X25519; validated 2026-10-01) | 🟢 Protected |
| `/mnt/cold` | Mass HDD | Disconnected (rsync → office-nas) | None | None | 🔴 Critical |
| `/mnt/fast_scratch` | Fast NVMe/SSD | None | None | None | ⚪ Excluded |
| `/mnt/legacy` | Mass HDD | None | None | None | 🔴 Critical |
| `/mnt/iscsi_vm` | Remote / mesh | None | zvol snapshots on nas-02: daily 7 | PBS → pbs-02 (same site, PBS AES-256-GCM; validated 2026-10-20) | 🟡 Local Only |

**Status rationale**

- `@ (root)` (🟢 Protected): snapshots plus offsite backup validated 2 d ago.
- `@home` (🟢 Protected): snapshots plus offsite backup validated 2 d ago.
- `tank/media` (🟡 Local Only): no backup target.
- `tank/photos` (🟢 Protected): snapshots plus offsite backup validated 7 d ago.
- `tank/vm` (🔴 Critical): replication lagging 6 h 40 min; backup not validated for 116 days.
- `tank/backups` (🟢 Protected): snapshots plus offsite backup validated 25 d ago.
- `md0 (cold)` (🔴 Critical): replication target unreachable.
- `fast_scratch` (⚪ Excluded): Ephemeral scratch space, intentionally unprotected.
- `legacy` (🔴 Critical): single copy: no snapshots, sync or backup.
- `iscsi_vm` (🟡 Local Only): backup is on the same site.

Rules: 🟢 needs snapshots plus an offsite backup validated within 30 days and healthy replication. 🔴 means lagging or disconnected replication, a backup not validated for 90 days, or no snapshot and no backup. Everything else is 🟡.

## 5. Storage Economics & Operational Overhead

### 5.1 Parity & reserve overhead

| Volume | Layout | Raw | Parity / mirror | Padding & slop | FS reserve & waste | Usable | Efficiency |
| :--- | :--- | ---: | ---: | ---: | ---: | ---: | ---: |
| `tank` | zfs raidz2 · 1×6-wide | 109.14 TiB | 36.38 TiB | 128.00 GiB | 0 B | 72.64 TiB | 66.6% |
| `md0` | mdadm raid1 · 2 members | 14.55 TiB | 7.28 TiB | 0 B | 488.85 GiB | 6.80 TiB | 46.7% |
| `/dev/nvme0n1p1` | vfat single device | 1.00 GiB | 0 B | 0 B | 0 B | 1.00 GiB | 100.0% |
| `/dev/nvme0n1p2` | btrfs single device | 1.82 TiB | 0 B | 0 B | 0 B | 1.82 TiB | 100.0% |
| `/dev/nvme1n1p1` | xfs single device | 3.00 TiB | 0 B | 0 B | 0 B | 3.00 TiB | 100.0% |
| `/dev/nvme1n1p2` | f2fs single device | 400.00 GiB | 0 B | 0 B | 0 B | 400.00 GiB | 100.0% |
| `/dev/sdi1` | ext4 single device | 2.00 TiB | 0 B | 0 B | 0 B | 2.00 TiB | 100.0% |
| **Total** | — | **130.91 TiB** | **43.66 TiB** | **128.00 GiB** | **488.85 GiB** | **86.65 TiB** | **66.2%** |

Unallocated or unaddressable space outside any volume: 824.81 GiB · 885.63 GB. Partition sizes are counted as usable before filesystem metadata; ZFS figures assume 128 KiB records.

### 5.2 Power & thermal budget

| Drive class | Count | Idle W / drive | Active W / drive | Idle total | Active total | Devices |
| :--- | ---: | ---: | ---: | ---: | ---: | :--- |
| NVMe SSD · PCIe Gen4 | 2 | 3.5 | 8.0 | 7.0 W | 16.0 W | nvme0n1 nvme1n1 |
| NVMe SSD · PCIe Gen3 | 1 | 2.5 | 6.0 | 2.5 W | 6.0 W | nvme2n1 |
| 3.5" HDD · enterprise helium | 6 | 5.5 | 9.5 | 33.0 W | 57.0 W | sda sdb sdc sdd sde sdf |
| 3.5" HDD · NAS / desktop | 3 | 4.0 | 6.5 | 12.0 W | 19.5 W | sdg sdh sdi |
| Network LUN (powered at its target) | 1 | 0.0 | 0.0 | 0.0 W | 0.0 W | sdj |
| **Total** | 13 | — | — | **54.5 W** | **98.5 W** | — |

- Heat load: 186 BTU/h idle, 336 BTU/h under load (W × 3.412).
- Annual energy at 75% idle / 25% active: 65.5 W average, 574 kWh/year, about €172/year at €0.30/kWh.
- Spin-up surge: 210 W on the 12 V rail if every hard drive starts at once. Enable staggered spin-up on the HBA or backplane.
- Drive power excludes the host, HBA, fans and the remote targets. Figures are class averages from datasheets, not measurements; replace them with wall readings when you have them.

## Appendix B. Method

- Binary units (KiB, MiB, GiB, TiB = 2¹⁰ … 2⁴⁰ bytes) come first, decimal units (KB … TB = 10³ … 10¹² bytes) second. Drive labels use decimal; `df -h`, `lsblk` and ZFS use binary.
- RAIDZ usable space includes allocation padding for 128 KiB records and the 1/32 slop reservation (capped at 128 GiB). mdadm arrays include ext4 root reserve and inode tables where ext4 is used.
- Allocated space counts each filesystem once, even when several subvolumes or bind mounts expose it.
- Protection status follows the StorageForge dashboard rules and uses the "as of" date above.
