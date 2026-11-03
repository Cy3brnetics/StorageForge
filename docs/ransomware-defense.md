# Ransomware defense

The **Security** panel: decoy files that raise the alarm, retention holds that take two people or a long wait to release, a host-side emergency brake, and a reading of each host's defenses. The plan it comes from is the [roadmap](../ransomware-defense-roadmap.md); this page is what exists.

Two rules hold it together.

- **Every number was measured.** What has not been measured says *not measured*. A host nobody has looked at is **Not known**, never fine. The page says "Nothing wrong found" only when every host was read in the last day, with a sentinel running, decoys armed and a hold verified.
- **A row means it happened.** A hold, quarantine or decoy is recorded after a signed run on the host confirmed it. A run that fails changes nothing and shows you its output.

Everything that changes a host offers **Show script**, **Dry run** and **Apply**, goes through `storageforge-run`, and asks for a fresh password.

## What it protects against, and what it does not

| Threat | What happens |
| :--- | :--- |
| A stolen account on a share | With sampling on, one user on many shares at once, or from several networks at once, raises an alarm within a minute |
| Ransomware on a workstation encrypting a share | It walks into a decoy. The sentinel sees the write at once and reports it. If armed, the host drops the client, snapshots and freezes, without waiting for the controller |
| Encryption of folders with no decoy | The next scan's change rate, ransom-note names and renamed files raise an alert. This is after the fact: as soon as the next scan, no sooner |
| A stolen admin password used to release a hold | Releasing waits out a cool-off or needs a second admin. The request raises an alert at once, so you can abort it |
| A stolen admin account making a second admin to approve itself | An account does not count until it is older than the cool-off |
| `date -s` or forged NTP to expire holds early | Expiry is kept on the controller's clock, so the host's cannot end it. A jump also stops releases on that host until someone clears it |
| Moving the **controller's** clock to end a cool-off | Measured against boot time: cool-offs stop until someone clears it. **Not** covered across a restart of StorageForge |
| This machine's clock itself drifting | When most hosts differ from it by the same amount, it says so instead of blaming them, and cool-offs stop. Past 10 minutes, hosts refuse signed runs |
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
| **Compliance** | Readings against a chosen standard or your own profile, waivers, drift, a plan to re-converge, and the baseline script |
| **Retention** | Tier policies, a legal freeze, what a rollback would change, expiry days, signed evidence |
| **Fencing** | Each share's declared clients, what the firewall allows, who is connected, and how long a client stays dropped |
| **Identity** | Who is connected to Samba, sampled each minute. Off until you turn it on |
| **Falco and YARA** | Rules as data, alerts as alarms, matches in the Malware list, thresholds and scan filters |
| **Playbooks** | If this happens, do that. A new one only says what it would do |
| **Dashboard** | Your own tiles, each from a real reading |
| **Timeline** | Alarms, actions and drops in one line, narrowed to a client, user or dataset |
| **Hardware keys** | FIDO2: a touch before releasing a hold, using the offline key, or the airgap |

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

## Things worth knowing

- **A waiver hides a finding from the count, with a reason, a name and an end date.** It still shows, and when it ends the finding counts again.
- **The targets are ours.** No standard sets a Lynis score or a number of hold days. Those are StorageForge's suggestions, and your own profile can change them.
- **Identity is sampled.** It sees what is connected at that moment, each minute, and nothing that came and went between. It cannot see how much was read: that takes per-file auditing, which is not built. It writes down who connected from where on the host, so it starts off.
- **Falco sees one event at a time.** "Many renames fast" cannot be a Falco rule: that is what the change rate between scans is for. Only named fields of an alert are read: its output text can hold a command line.
- **Playbooks need StorageForge up and the host reachable.** An armed sentinel acts on the host by itself, with neither. A playbook's first look starts from now, so old alarms do not fire it.
- **A fence only ever takes away.** A client inside still needs the host firewall to let it in. It does not cover a published container port.
- **Evidence is not a certificate.** It is a signed record of what was measured and done, and checks with `ssh-keygen -Y verify`. Only an auditor can attest.
- **Freezing btrfs is weaker than ZFS.** Read-only stops writes and does not stop `btrfs subvolume delete`.
- **A hardware key is only offered over HTTPS or on localhost,** by the browser. Enrolling one makes the touch required on that account.

## Not built

The roadmap goes further than this. None of the following exists, and none of it is shown as if it did.

Fanotify watchers · a simulator for Falco rules against recorded sessions · off-hours read volume by user (it needs `vfs_full_audit`) · a visual drag-and-drop subnet matrix (fences are typed) · a visual builder for playbooks beyond the form · SMS as such (it goes through a webhook) · FIDO2 at sign-in (only for guarded actions) · local mirror discovery (a host uses the mirrors it is already set up for).

These will not be built, because they cannot work or would claim too much: the Samba VSS trap, cryptographic shred, compliance certificates, a *SECURE* banner, and the WebSocket stream. See the [roadmap's corrections](../ransomware-defense-roadmap.md).

## What has been tested, and how

| How | Covers |
| :--- | :--- |
| `tests/test_security.py` | The controller driving its scripts really running, with stand-ins for `zfs` and `systemctl`; real `nft` in a network namespace; the real sentinel on real inotify; real Python on real files |
| `tests/test_browser_smoke.py` | Every panel in Chromium under the real CSP |
| By hand, 2026-11-02: as root in a privileged Debian 12 container | Real btrfs on a loop device, real nftables, real inotify, real auditd: decoys, a trip, the armed brake down to a real `remount,ro`, holds, the clean room, quarantine, the exempt list, airgap, uninstall |
| By hand, 2026-11-02: PostgreSQL 16 | The migration and the controller's queries |

| [KVM lab](kvm-lab.md) tier 9 | On real ZFS, btrfs, SELinux and AppArmor, through real signed deploys: holds, the cool-off, two admins, the offline key, the clock guard, decoys, the armed brake down to a real read-only remount, Samba and NFS attribution, the airgap and its timer, blast radius, the clean room, the baseline |
| KVM lab tier 11 | Retention policies, a freeze, a rollback preview, YARA, a playbook on a real trip, package checks and a bundle, Falco from its repository with a real `chattr -i`, identity sampling from real `smbstatus`, evidence checked with `ssh-keygen`, a plan that re-converges a failing check, and waivers |
| `tests/test_browser_smoke.py` | FIDO2 enrollment and touch through Chromium's virtual authenticator, dashboards and every panel |

The lab runs StorageForge on SQLite. A real Windows client has not been used: the Samba client is Linux. No physical FIDO2 token has been used. A playbook has run in the lab only in the mode that says what it would do: the live path is tested with the real brake script and stand-ins.
