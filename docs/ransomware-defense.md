# Ransomware defense

The **Security** panel: decoy files that raise the alarm, retention holds that take two people or a long wait to release, a host-side emergency brake, and a reading of each host's defenses. The plan it comes from is the [roadmap](../ransomware-defense-roadmap.md); this page is what exists.

Two rules hold it together.

- **Every number was measured.** What has not been measured says *not measured*. A host nobody has looked at is **Not known**, never fine. The page says "Nothing wrong found" only when every host was read in the last day, with a sentinel running, decoys armed and a hold verified.
- **A row means it happened.** A hold, quarantine or decoy is recorded after a signed run on the host confirmed it. A run that fails changes nothing and shows you its output.

Everything that changes a host offers **Show script**, **Dry run** and **Apply**, goes through `storageforge-run`, and asks for a fresh password.

## What it protects against, and what it does not

| Threat | What happens |
| :--- | :--- |
| Ransomware on a workstation encrypting a share | It walks into a decoy. The sentinel sees the write at once and reports it. If armed, the host drops the client, snapshots and freezes, without waiting for the controller |
| Encryption of folders with no decoy | The next scan's change rate, ransom-note names and renamed files raise an alert. This is after the fact: as soon as the next scan, no sooner |
| A stolen admin password used to release a hold | Releasing waits out a cool-off or needs a second admin. The request raises an alert at once, so you can abort it |
| A stolen admin account making a second admin to approve itself | An account does not count until it is older than the cool-off |
| `date -s` or forged NTP to expire holds early | Expiry is kept on the controller's clock, so the host's cannot end it. A jump also stops releases on that host until someone clears it |
| Moving the **controller's** clock to end a cool-off | Measured against boot time: cool-offs stop until someone clears it. **Not** covered across a restart of StorageForge |
| Someone quietly releasing holds or replacing decoys | Each measurement compares them with what was recorded, and raises an alarm |

**What this does not stop: an attacker with root on the host.** A ZFS hold stops `zfs destroy`, including from a script or by mistake, but root can `zfs release` first, and a btrfs snapshot can be made writable. Root can also stop the sentinel. You would see it: the alarm on the next measurement, and an alert when readings stop. But seeing it is all this does. **The only thing out of reach of root on a host is a copy on another machine**, so keep [offsite backups](disaster-recovery.md) that hosts cannot delete. "WORM" in this project means *guarded*, not *impossible*.

Also true:

- **Attribution is best effort.** smbd runs one process per client, so a process id gives an address. NFS is served by the kernel, so an NFS client cannot be identified: the event says so and nobody is dropped.
- **An armed sentinel acts on one changed file.** A user or sync tool touching the wrong file cuts off that client and may freeze the share. That is why it starts disarmed. Put machines that must not be cut off on the exempt list.
- **Decoys only see changes.** A tool that reads and exfiltrates does not trip them, and neither do backups and indexers, which is the point.
- **Compliance readings are not an audit.** They map checks to controls they help with. They are not a certification, and control references should be reviewed against the standard you are held to.
- **Hosts can lie.** What a host reports can raise an alarm, and nothing more: it cannot clear one, release a hold or disarm anything.

## How it works

```text
 host                                                   StorageForge
┌────────────────────────────────────┐                 ┌─────────────────────────────┐
│ decoys ──inotify──► sentinel ──────┼── event ───────►│ /api/security/report (token)│
│                       │ armed?     │  or next scan   │        │                    │
│                       ▼            │  or measurement │        ▼                    │
│               storageforge-brake   │                 │ security_events ─► alerts   │
│  triage, drop, snapshot, freeze    │                 │                             │
│ storageforge-run ◄─────────────────┼── signed ───────┤ measure, hold, quarantine…  │
└────────────────────────────────────┘                 └─────────────────────────────┘
```

The brake is on the host, so it does not depend on the controller or the network. Its steps run in this order: save what is only in memory, drop the client, snapshot and hold, then make the filesystem read-only. The snapshot comes before the freeze because a btrfs snapshot cannot be taken of something read-only. It will not freeze a filesystem the host itself runs on.

A **measurement** is a read-only signed run. It happens when you ask, and every 6 hours for hosts with a sentinel or holds. Scans carry events too, so nothing is lost if the sentinel could not report.

## Panels

| Panel | What it does |
| :--- | :--- |
| **Overview** | Each host and every reason it is not fine, alarms, damage since an incident, the brake, the clean room |
| **Holds** | Holds and whether they are still on the host, who can release them, what is waiting, the offline key, the clock guard |
| **Decoys** | Which folders get decoys, arming, deploy and test. **Test it** writes to a file only the sentinel watches, and times the reaction |
| **Access control** | SELinux or AppArmor as found, storage booleans, mount labels against policy, recent denials, relabel. It will not turn SELinux on for you |
| **Firewall** | Quarantine, the exempt list, the airgap |
| **Behaviour** | Change rate against the host's own past, ransom names, renamed files, entropy of changed files, ClamAV on changed files |
| **Integrity** | AIDE and Lynis, run in the background and read by the next measurement |
| **Compliance** | Readings against a chosen standard, and the baseline script |

## Getting started on a host

1. Set up [deploy access](deployments.md) and scan the host.
2. **Overview → Measure now.** See what is actually there.
3. **Decoys:** choose folders, **Dry run**, then **Save and deploy**, then **Test it**. Leave it disarmed at first.
4. **Settings → Report URL**, so a trip reaches you in seconds rather than at the next scan.
5. **Holds:** **Make the offline key**, print it, and lock it away. Then hold a snapshot.
6. **Firewall:** list machines that must never be cut off. Deploy again so hosts get the list.
7. When a few weeks show no false alarms, consider arming it.

## Releasing a hold

| Situation | What happens |
| :--- | :--- |
| Past its date | Released when you ask. Never by itself: an expired hold stays on the host until someone asks |
| One established admin | Waits out the cool-off (24 h by default; it can be raised but not shortened from the UI), then runs by itself. Anyone can abort it until then |
| Two or more established admins | Waits for a second admin, and runs when approved. If that admin goes away, it falls back to the cool-off |
| Legal hold | As above, but it must be named as a legal hold when asking |
| Clock guard tripped | Nothing releases until someone clears it. Not even the offline key |
| Offline key | Skips the wait and the second admin for one release, and raises an alarm. Replacing the key waits out the same timelock |

## Not built

The roadmap goes further than this. None of the following exists, and none of it is shown as if it did.

Share-level CIDR fencing and the client matrix · credential and identity anomaly detection · Falco rules and alerts (the panel only says whether Falco is installed) · YARA and its editor · the playbook designer and custom dashboards · canvas badges · retention tier policies · waivers and custom compliance profiles · staging Lynis findings into change plans · signed compliance certificates and PDF exports · offline package bundles · FIDO2 step-up · per-dataset entropy thresholds · the rollback preview and expiry heatmap · the WebSocket stream · the banner on every page (alerts cover this for now) · SMS and PagerDuty as such (alerts go through the ntfy, Gotify and webhook channels).

## What has been tested, and how

| How | Covers |
| :--- | :--- |
| `tests/test_security.py` | The controller driving its scripts really running, with stand-ins for `zfs` and `systemctl`; real `nft` in a network namespace; the real sentinel on real inotify; real Python on real files |
| `tests/test_browser_smoke.py` | Every panel in Chromium under the real CSP |
| By hand, 2026-11-02: as root in a privileged Debian 12 container | Real btrfs on a loop device, real nftables, real inotify, real auditd: decoys, a trip, the armed brake down to a real `remount,ro`, holds, the clean room, quarantine, the exempt list, airgap, uninstall |
| By hand, 2026-11-02: PostgreSQL 16 | The migration and the controller's queries |

**Not yet tested:** real **ZFS** (stand-in only), real **SELinux** or **AppArmor** hosts, attribution with real **Samba** clients, the airgap's rollback timer under real systemd, and the whole path through a real signed deploy. None of this has been through the [KVM lab](kvm-lab.md). Do that before relying on it, and especially before arming a sentinel.
