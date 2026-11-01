# KVM lab

`examples/lab` builds seven disposable VMs, picked at random from 14 configs across distros and filesystems, runs StorageForge on one of them, and tests the rest for real. It runs on a libvirt host, and a normal test run doesn't touch it. The [lab README](../storageforge-indexer/examples/lab/README.md) covers what each VM holds, what the lab needs and what Destroy removes.

```bash
examples/lab/lab.sh install-launcher   # adds "StorageForge Lab" to the desktop menu
examples/lab/lab.sh up                 # pick and build 7: about 5 minutes with base images cached
examples/lab/lab.sh up --seed 500277455   # the same 7 as an earlier build
examples/lab/lab.sh up --pick sf-ctl,sf-fedora,sf-arch   # exactly these configs
examples/lab/lab.sh test --all         # tiers 0-5 and a report: about 30 minutes
examples/lab/lab.sh down               # remove it all
```

## The 14 configs

Every build has `sf-ctl` and `sf-alpine`, the only config without systemd, plus 5 at random, with at least two btrfs hosts and one each of ZFS, LVM and SELinux. The seed is printed, saved and written in the report, and Destroy forgets it, so the next Up picks again. `examples/lab/roles.conf` says what each config can do, and tests choose hosts from that. A check with no suitable host in a build shows as skip.

| Config | Distro | Storage |
| :--- | :--- | :--- |
| `sf-ctl` | Debian 13 | Runs StorageForge and ntfy |
| `sf-fedora` | Fedora 44 | btrfs raid1, btrfs root |
| `sf-suse` | openSUSE Leap 16 | Nested btrfs subvolumes, a child subvolume with no mount, mdadm raid1 |
| `sf-arch` | Arch | btrfs root, LUKS with f2fs, mergerfs |
| `sf-bookworm` | Debian 12 | btrfs raid10 with quotas |
| `sf-tumbleweed` | openSUSE Tumbleweed | btrfs raid1c3, no-copy-on-write subvolume, reflinks |
| `sf-leap15` | openSUSE Leap 15.6 | btrfs single data with dup metadata, deep nesting, a spare disk; XFS |
| `sf-ubuntu` | Ubuntu 24.04 | ZFS raidz1 and a second pool, Docker |
| `sf-jammy` | Ubuntu 22.04 | ZFS mirror |
| `sf-rocky` | Rocky Linux 9 | LVM with XFS and a snapshot, Podman |
| `sf-rocky10` | Rocky Linux 10 | LVM thin with XFS |
| `sf-alma9` | AlmaLinux 9 | mdadm raid5 with XFS |
| `sf-alma10` | AlmaLinux 10 | LVM on LUKS, with ext4 and XFS |
| `sf-alpine` | Alpine 3.24 | vfat and exFAT, OpenRC |

## Test tiers

| Tier | File | Checks |
| :--- | :--- | :--- |
| 0: Smoke | `tests/lab/test_tier0.py` | Each VM, its storage layout and seed data, and StorageForge and ntfy on `sf-ctl`. Reads only, and it's what **Test** runs. |
| 1: Scan | `tests/lab/tiers.py` | Filesystems, package manager, init system, topology and containers on each VM, and the index compared with the seed manifests, with and without scan access |
| 2: Deploy | `tests/lab/gauntlet.py` | Scan access, deploy access, shares, jobs, change plans, storage tasks, drift, the deploy engine and removal, on each VM that can run them |
| 3: Cross-host | `tests/lab/tiers.py` | NFS, SMB, rsnapshot and restore, moves and cutover, and btrfs send, comparing file hashes on the receiving VM |
| 4: Failure | `tests/lab/tiers.py` | A degraded pool, a full disk, a host going offline, drift, a changed host key, and signed requests that are replayed, expired, tampered with or meant for another machine |
| 5: Btrfs | `tests/lab/tiers.py` | Profiles and child subvolumes through a real scan, reflinks, no-copy-on-write, plan tasks, full and incremental sends between hosts, a broken receive, adding a device, converting a profile, a full disk, a read-only filesystem and a pulled disk |

`lab.sh test --all`, or **Full test** in the panel, resets the lab around the tiers that change VMs, and writes `reports/lab-<date>.md` with a table per distro. Reports aren't committed. Tiers 1, 3, 4 and 5 run against the real Docker stack on `sf-ctl` through its API. Tier 2 runs on the libvirt host, on a throwaway database. `lab.sh gauntlet` runs tier 2 alone.

A check listed in `KNOWN` in `tiers.py` still fails, but shows as `known` and doesn't fail the run. In tiers 1, 3, 4 and 5, it shows as `fixed?` once it starts passing, which means the line should go.

## Tested distributions

Every config went through every tier in at least one of four builds on 2026-10-31, at commit `2b27ab0` with the lab's own changes uncommitted. The last build, seed `500277455`, had 337 passed, 0 failed, 5 known and 1 skipped. The first three builds used earlier versions of the tests, so their failures led to the fixes and findings below.

| Config | Scans | Deploys |
| :--- | :--- | :--- |
| Debian 12, Debian 13 | Yes | Yes |
| Ubuntu 22.04 | Yes | Yes, except `zfs set` and mounting SMB (below) |
| Ubuntu 24.04 | Yes | Yes, except mounting SMB (below) |
| Fedora 44, Arch | Yes | Yes |
| openSUSE Leap 15.6, Leap 16, Tumbleweed | Yes | Yes, except sharing a folder under an unlabelled one on Leap 16 (below) |
| Rocky Linux 9 | Partial until scan access is set up | Yes |
| Rocky Linux 10 | Yes | Yes, except mounting SMB (below) |
| AlmaLinux 9, AlmaLinux 10 | Yes | Yes |
| Alpine 3.24 | Yes | Refused with a clear message: it has no bash or systemd |

### Known failures

- **Converting a btrfs profile with no unallocated space:** on `sf-tumbleweed` the kernel aborts with `ENOSPC` and the filesystem goes read-only, while the task has already reported that the balance started.
- **Disk-full alerts on btrfs RAID:** the alert divides used by total, but `df` counts used against used plus available. `/srv/pool/backups` at 99% by `df` read as 85%, below the 90% threshold, so no disk alert opened.
- **SMB share under an unlabelled folder on SELinux:** the deploy labels only the shared folder. If the folder above it has no label, `smbd` fails `canonicalize_connect_path` and clients get `BAD_NETWORK_NAME`. This was seen on `sf-fedora`, and the same `mount error(2)` came from a share on `sf-suse`.
- **SMB mounts on some cloud kernels:** Ubuntu's stock kernels have no `nls_utf8`, which the mount's `iocharset=utf8` needs, and Rocky 10's image has no `cifs`. The deploy installs only `cifs-utils`.
- **`zfs set` on Ubuntu 22.04:** the task passes `--`, which this ZFS release rejects with `cannot open '--'`.
- **Verify on a newer SSH client:** a job's verify counts every output line as a differing file, including the post-quantum warning a new client prints for an older server.
- **Podman's overlay folder:** without scan access, it counts as a failed mount, so the scan is partial.
- **mergerfs:** the scan records the source as `1:2`, not the branch folders.

## What the lab can't test

- **ZFS send between hosts in every build:** it needs both ZFS configs, and most builds pick one, so it usually shows as skip.
- **`yum`-only systems:** those distros are end-of-life.
- **PostgreSQL:** the lab runs StorageForge on SQLite.
- **The web UI itself:** the tests use its API, not its pages.
- **Enterprise Linux at 1 GB:** those configs have 2 GB, because `dnf` is killed for lack of memory at 1 GB once EPEL is enabled.
