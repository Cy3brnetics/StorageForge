# KVM lab

`examples/lab` builds seven disposable VMs across distros and filesystems, runs StorageForge on one of them, and tests the rest for real. It runs on a libvirt host, and a normal test run doesn't touch it. The [lab README](../storageforge-indexer/examples/lab/README.md) covers what each VM holds, what the lab needs and what Destroy removes.

```bash
examples/lab/lab.sh install-launcher   # adds "StorageForge Lab" to the desktop menu
examples/lab/lab.sh up                 # build everything: about 5 minutes with base images cached
examples/lab/lab.sh test --all         # tiers 0-4 and a report: about 25 minutes
examples/lab/lab.sh down               # remove it all
```

## Test tiers

| Tier | File | Checks |
| :--- | :--- | :--- |
| 0: Smoke | `tests/lab/test_tier0.py` | Each VM, its storage layout and seed data, and StorageForge and ntfy on `sf-ctl`. Reads only, and it's what **Test** runs. |
| 1: Scan | `tests/lab/tiers.py` | Filesystems, package manager, init system, topology and containers on each VM, and the index compared with the seed manifests, with and without scan access |
| 2: Deploy | `tests/lab/gauntlet.py` | Scan access, deploy access, shares, jobs, change plans, storage tasks, drift, the deploy engine and removal, on each VM that can run them |
| 3: Cross-host | `tests/lab/tiers.py` | NFS, SMB, rsnapshot and restore, moves and cutover, and btrfs send, comparing file hashes on the receiving VM |
| 4: Failure | `tests/lab/tiers.py` | A degraded pool, a full disk, a host going offline, drift, a changed host key, and signed requests that are replayed, expired, tampered with or meant for another machine |

`lab.sh test --all`, or **Full test** in the panel, resets the lab around the tiers that change VMs, and writes `reports/lab-<date>.md` with a table per distro. Reports aren't committed. Tier 1, 3 and 4 run against the real Docker stack on `sf-ctl` through its API. Tier 2 runs on the libvirt host, on a throwaway database. `lab.sh gauntlet` runs tier 2 alone.

A check listed in `KNOWN` in `tiers.py` still fails, but shows as `known` and doesn't fail the run. In tiers 1, 3 and 4, it shows as `fixed?` once it starts passing, which means the line should go.

## Tested distributions

From the run on 2026-10-31, at commit `cf5fe03` with uncommitted fixes in the working tree:

| VM | Distro | Scans | Deploys |
| :--- | :--- | :--- | :--- |
| `sf-ctl` | Debian 13 | Yes | Yes |
| `sf-ubuntu` | Ubuntu 24.04 | Yes | Yes |
| `sf-fedora` | Fedora 44 | Yes | Yes, with one failure not yet explained (below) |
| `sf-rocky` | Rocky Linux 9 | Partial until scan access is set up | Yes, with one failure not yet explained (below) |
| `sf-suse` | openSUSE Leap 16 | Yes, except a child subvolume (below) | Yes |
| `sf-arch` | Arch Linux | Yes | Yes |
| `sf-alpine` | Alpine 3.24 | Yes | Refused with a clear message: it has no bash or systemd |

### Still open

**Known failures:**
- **Child subvolumes (GM-14):** files in a btrfs child subvolume with no mount of its own aren't indexed.
- **Rootful Podman:** a scan user for whom `podman ps` works sees only its own, empty, container list, even when `sudo podman` is allowed.
- **Podman's overlay folder:** without scan access, it counts as a failed mount, so the scan is partial.
- **mergerfs:** the scan records the source as `1:2`, not the branch folders.

**Not explained yet:**
- An rsnapshot job from `sf-arch` to `sf-rocky` failed with rsync exit 11. The destination may have run out of space.
- A btrfs snapshot in a storage task on `sf-fedora` failed with `Read-only file system`. It passed in earlier runs.

## What the lab can't test

- **ZFS send between hosts:** only one VM has ZFS, so sends go between its two pools.
- **`yum`-only systems:** those distros are end-of-life.
- **PostgreSQL:** the lab runs StorageForge on SQLite.
- **The web UI itself:** the tests use its API, not its pages.
- **Low memory on Rocky:** `sf-rocky` has 2 GB, because `dnf` is killed for lack of memory at 1 GB once EPEL is enabled.
