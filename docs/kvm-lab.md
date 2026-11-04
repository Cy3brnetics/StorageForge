# KVM lab

`examples/lab` builds seven disposable VMs, picked at random from 14 configs across distros and filesystems, runs StorageForge on one of them, and tests the rest for real. It runs on a libvirt host, and a normal test run doesn't touch it. The [lab README](../storageforge-indexer/examples/lab/README.md) covers what each VM holds, what the lab needs and what Destroy removes.

```bash
examples/lab/lab.sh install-launcher   # adds "StorageForge Lab" to the desktop menu
examples/lab/lab.sh up                 # pick and build 7: about 5 minutes with base images cached
examples/lab/lab.sh up --seed 500277455   # the same 7 as an earlier build
examples/lab/lab.sh up --pick sf-ctl,sf-fedora,sf-arch   # exactly these configs
examples/lab/lab.sh test --all         # tiers 0-11 and 13 and a report: over an hour
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

## Appliances

Three server hypervisor/storage configs install from their vendors' ISOs, with nobody at the console. They need more memory and a larger download, so only `--pick` builds them:

| Config | System | Storage | RAM |
| :--- | :--- | :--- | :--- |
| `sf-pve` | Proxmox VE 9.2 | LVM thin root, ZFS mirror `tank` registered as guest storage | 2 GB |
| `sf-truenas` | TrueNAS 25.10 | ZFS mirror `tank` | 4 GB |
| `sf-xcp` | XCP-ng 8.3, nested Xen | Local ext storage repository | 3 GB |

Routers and the machines behind them join a running build with `lab.sh up --join sf-mikrotik,sf-openwrt,sf-wan-host,sf-lan-client,sf-dmz-server`, on isolated WAN, LAN and DMZ networks with no route out. Only tier 12 uses them. There's no free pfSense or Cisco image the lab can install unattended, so neither is here: see [what has been tested on what](network-devices.md#what-has-been-tested-on-what).

| Config | System | Interfaces / Network | RAM |
| :--- | :--- | :--- | :--- |
| `sf-mikrotik` | MikroTik RouterOS 7.25 CHR | mgmt (10.77.0.30), wan, lan1, dmz | 256 MB |
| `sf-openwrt` | OpenWrt 25.12 x86 | mgmt (10.77.0.31), wan, lan1, dmz | 256 MB |
| `sf-wan-host` | Alpine 3.24, the outside | mgmt (10.77.0.34), wan | 384 MB |
| `sf-lan-client` | Alpine 3.24, behind the LAN | mgmt (10.77.0.35), lan1 | 384 MB |
| `sf-dmz-server` | Alpine 3.24, answers on 80 and 443 | mgmt (10.77.0.36), dmz | 384 MB |

```bash
examples/lab/lab.sh up --pick sf-pve,sf-truenas,sf-xcp,sf-bookworm
examples/lab/lab.sh appliances
```

`provision/appliance.py` drives each installer: Proxmox's answer file in a container, XCP-ng's inside its initrd, and TrueNAS's own install function over the serial console, then its API. `sf-pve` gets the no-subscription repository and `sudo`, as [Proxmox needs](appliances.md#proxmox-ve). XCP-ng needs nested virtualization on the libvirt host.

To run a lab beside one already running, set `SFLAB_INSTANCE=1`, up to 9. It has its own network (10.78.0.0/24 for 1), pool, state and VM tag, so its `down` can't touch the other. Only the base images are shared. Two labs can't hold the same config, because libvirt names VMs. The panel only drives the first lab.

The build above ran on 2026-11-01 with the work uncommitted, as instance 1 beside another lab: tiers 0, 2 and 8 passed, with tier 2 at 98 passed, 0 failed. Tier 2 ran NFS, SMB, jobs, tasks, change plans, drift and removal on `sf-pve` against `sf-bookworm`. It didn't run with `sf-ctl`, so tiers 1 and 3 to 7 haven't run against an appliance.

## Test tiers

| Tier | File | Checks |
| :--- | :--- | :--- |
| 0: Smoke | `tests/lab/test_tier0.py` | Each VM, its storage layout and seed data, and StorageForge and ntfy on `sf-ctl`. Reads only, and it's what **Test** runs. |
| 1: Scan | `tests/lab/tiers.py` | Filesystems, package manager, init system, topology and containers on each VM, and the index compared with the seed manifests, with and without scan access |
| 2: Deploy | `tests/lab/gauntlet.py` | Scan access, deploy access, shares, jobs, change plans, storage tasks, drift, the deploy engine and removal, on each VM that can run them |
| 3: Cross-host | `tests/lab/tiers.py` | NFS, SMB, rsnapshot and restore, moves and cutover, and btrfs send, comparing file hashes on the receiving VM |
| 4: Failure | `tests/lab/tiers.py` | A degraded pool, a full disk, a host going offline, drift, a changed host key, and signed requests that are replayed, expired, tampered with or meant for another machine |
| 5: Btrfs | `tests/lab/tiers.py` | Profiles and child subvolumes through a real scan, reflinks, no-copy-on-write, plan tasks, full and incremental sends between hosts, a broken receive, adding a device, converting a profile, a full disk, a read-only filesystem and a pulled disk |
| 6: Sync engine | `tests/lab/tiers.py` | Routes with one pinned host key, a route lost during a run, dedup and reflinks, the volume lock, btrfs and ZFS snapshot streams, the room check and duperemove, between real hosts |
| 7: Remote nodes | `tests/lab/tiers.py` | The tunnel container, and hosts that can't be dialled: the install script, adopting, signed deploys and scans through the tunnel, reconnecting, what a stolen key can't do, revoking and removal |
| 8: Appliances | `tests/lab/tiers.py` | Proxmox, TrueNAS and XCP-ng, when the build has them: a scan as an ordinary user, the platform it finds, whether deploys are allowed, ZFS pools, and XCP-ng's storage repository before and after scan access |
| 9: Security | `tests/lab/tiers_platform.py` | Holds on real ZFS and btrfs, the cool-off, two admins, the offline key, the clock guard, decoys, the armed brake, Samba and NFS attribution, the airgap and its timer, quarantine, blast radius and the clean room, SELinux, AppArmor and the baseline |
| 10: Infrastructure | `tests/lab/tiers_platform.py` | What scans read against each VM, nothing invented, a capture proving nothing is probed, a failed collector, a port ufw looks like it blocks, every firewall giving the same model, workloads on each runtime, change tracking, redacted exports, and whether a quarantine reaches a published port |
| 11: Changes | `tests/lab/tiers_platform.py` | Firewall rules on ufw, nftables and firewalld, a published port's fix, a fence across a reboot, a timer undoing a cut SSH path, reach against real connections, what-if against the next reading, a design, hardening steps, WireGuard, a placeholder, retention, YARA, a playbook, packages and Falco |
| 12: Network appliances | `tests/lab/tiers_network.py` | Real RouterOS and OpenWrt on isolated WAN, LAN and DMZ networks, with real machines behind them: reading over SSH, an interactive terminal, Telnet and a password; the path query and exposure against real curl; a rule changed on the router flipping both; the language given to real nft and iptables-restore; a change kept, and a change that cuts StorageForge off and the router putting itself back; the scanner sending nothing when off, then found and heard when on. Only when the build has the routers: `lab.sh up --join sf-mikrotik,sf-openwrt,sf-wan-host,sf-lan-client,sf-dmz-server` |
| 13: Features | `tests/lab/tiers_features.py` | Every feature no other tier reached: file changes, capacity, duplicates, cold data, containers, Git, host configs and the reinstall script applied, canvas, reports, file map, planner, keys added by hand, the vault and accounts through real sign-ins, the activity log, backups copied and restored, audit tampering, snapshot jobs, ClamAV on the EICAR file, LXC and Incus, the map's views, stale dry runs, scan schedules and quiet hours, every read-only command and route, every page in a browser, retiring a host, and site reset |

`lab.sh test --all`, or **Full test** in the panel, runs tiers 0 to 11 and 13, resets the lab around the tiers that change VMs, and writes `reports/lab-<date>.md` with a table per distro. Reports aren't committed. Tiers 1, 3, 4, 5, 9, 10, 11 and 13 run against the real Docker stack on `sf-ctl` through its API. Tiers 2 and 8 run on the libvirt host, on a throwaway database. `lab.sh gauntlet` runs tier 2 alone and `lab.sh appliances` runs tier 8 alone.

Tiers 9 to 11 last ran on 2026-11-03, with the work uncommitted, on `--pick sf-ctl,sf-ubuntu,sf-fedora,sf-rocky,sf-suse,sf-alpine,sf-bookworm`: all tiers gave 441 passed, 0 failed and 3 skipped. The skips were ZFS send and the sync engine's ZFS stream, which need two ZFS hosts, and appliances, which need `--pick`. The other configs have not run tiers 9 to 11.

[`tests/feature_map.py`](../storageforge-indexer/tests/feature_map.py) lists every feature with its unit tests and lab checks, and `test_feature_map.py` fails if a feature, web route or command has none. A feature the lab can't verify has to say why. The [test audit](test-audit-2026-11-03.md) has the coverage and what the new checks found.

Tiers 0 to 11 and 13 last ran on 2026-11-03, with the work uncommitted, on the same seven configs: 482 passed, 0 failed and 3 skipped. Tier 13 has not run on the other seven configs or on appliances.

A check listed in `KNOWN` in `tiers.py` still fails, but shows as `known` and doesn't fail the run. In tiers 1, 3, 4 and 5, it shows as `fixed?` once it starts passing, which means the line should go.

## Tested distributions

Every config went through every tier in at least one of four builds on 2026-10-31, at commit `2b27ab0` with the lab's own changes uncommitted. The last build, seed `500277455`, had 337 passed, 0 failed, 5 known and 1 skipped. The first three builds used earlier versions of the tests, so their failures led to the fixes and findings below.

The known failures from those builds were fixed and rechecked on 2026-11-01, on two `--pick` builds of the configs they affected. The second, `sf-ctl,sf-ubuntu,sf-fedora,sf-suse,sf-alpine,sf-bookworm,sf-alma9`, had 346 passed, 0 failed, 0 known and 1 skipped. Other configs last ran on 2026-10-31.

| Config | Scans | Deploys |
| :--- | :--- | :--- |
| Debian 12, Debian 13 | Yes | Yes |
| Ubuntu 22.04, Ubuntu 24.04 | Yes | Yes |
| Fedora 44, Arch | Yes | Yes |
| openSUSE Leap 15.6, Leap 16, Tumbleweed | Yes | Yes |
| Rocky Linux 9, Rocky Linux 10 | Yes | Yes |
| AlmaLinux 9, AlmaLinux 10 | Yes | Yes |
| Alpine 3.24 | Yes | Refused with a clear message: it has no bash or systemd |

## What the lab can't test

- **ZFS send between hosts in every build:** it needs both ZFS configs, and most builds pick one, so it usually shows as skip.
- **`yum`-only systems:** those distros are end-of-life.
- **PostgreSQL:** the lab runs StorageForge on SQLite. CI runs the unit tests on PostgreSQL instead, apart from those about SQLite files and the command line tests that drive one.
- **Real updates:** what a mirror holds changes daily, so no tier can state the result. Update scripts run against stand-ins.
- **Outside services and hardware:** Tailscale, PagerDuty and a physical FIDO2 token.
- **The web UI, partly:** tier 13 opens every page and tab in Chromium on real data, when `playwright` is installed where the tier runs. Otherwise that check shows as skip. Actions in the UI are the browser tests' job, on local data.
- **ClamAV's memory rule:** its script refuses under 2 GiB, and the lab's largest VMs report about 1.7 GiB. Tier 13 checks the refusal, then hides the real figure from that one check to test the rest.
- **Enterprise Linux at 1 GB:** those configs have 2 GB, because `dnf` is killed for lack of memory at 1 GB once EPEL is enabled.
