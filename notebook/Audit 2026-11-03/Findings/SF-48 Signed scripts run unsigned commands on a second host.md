---
id: SF-48
status: in-progress
severity: medium
effort: L
area: Send and receive steps
verified: read
tags: [finding, audit-2026-11-03]
found: 2026-11-03
---
# SF-48 Signed scripts run unsigned commands on a second host

**Medium** · L · Send and receive steps · Read · part of [[Audit 2026-11-03]]

## What exists
ZFS and btrfs send steps in plans and tasks need to act on the receiving machine. The signed script on the sending host logs in over SSH with that host's own root key and runs `sudo -n` there. The receiving host sees a plain command: no signature, no nonce, no `storageforge-run`, and no run record.

## Evidence
`scriptkit.py:88` defines `dest_cmd`, which ends in `ssh -p "$port" ... -- "$login" "$line"`. The commands it carries include `btrfs receive` and `zfs receive` (`changes.py:1533`, `:1589`), `mkdir` (`changes.py:1532`) and `btrfs subvolume delete` for retention (`tasks.py:861`, `:878`).

`dest_host` is free text in the plan: `this host, or nas-02, or root@10.0.0.9` (`changes.py:62`). A name no scan knows gets only a warning (`changes.py:816`). The plan's check also says plainly that root logs in with its own key (`changes.py:466`), so this is known behaviour.

Read, not run: it needs two machines with root keys set up between them, which is lab work. Unknown: how many real deploys rely on it.

**Why this doesn't break the deploy-key promise:** it uses the host's own key rather than the deploy key, and only if someone set one up. The values are quoted, and each command is fixed by the step type. But the promise that deploys run only signed scripts does not hold for the receiving machine.

## Why it matters
Someone with `plans.edit` and `deploy.apply` can direct root commands at a machine by typing its name, and the machine doesn't have to be enrolled. Retention deletes subvolumes there. The audit row and run record name only the sending host, so nothing on the receiving side says what asked for it. It also needs a root-to-root SSH trust between storage hosts, which is what ransomware moving between machines would want.

## Suggested approach
Have the controller run each side as its own signed run on an enrolled host, with the stream passed between them by a forced-command job key, as `storageforge-job --serve` already does for rsync. That gives the receiver a signature and a record, and removes the root-to-root key. Until then, warn more strongly, and record `dest_host` in the audit detail. Untested.

## Done when
- [x] The docs state this exception and why, in `docs/security.md`. The signed receiving run itself is not built
- [x] The audit row names the receiving host (`second_hops`)
- [ ] A lab tier exercises a send between two enrolled hosts with no root key between them

**Partly fixed,** in the working tree on 2026-11-03, not committed. Done: the interim steps above, for plans, tasks and task schedules, and a plain warning in the check. **Not done:** running the receiver as its own signed run, which removes the root-to-root key. That is the real fix, a week's work, and it needs the lab, because it changes how data moves between hosts. Until then the unsigned second hop remains.
