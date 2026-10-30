# Concepts

## The pieces

```text
           hosts (no agent)                               StorageForge
 ┌──────────────────────────────┐   ssh, key from vault   ┌─────────────────────────────────────────────┐
 │ find, findmnt, lsblk, df,    │ ◄────────────────────── │ scanner ─► index (SQLite or PostgreSQL)     │
 │ zpool, git, docker (read)    │                         │              │                              │
 │                              │                         │   design ◄───┴──► graph, topology, reports  │
 │ storageforge-run   (deploys) │ ◄── signed scripts ──── │   plans: changes · moves · shares · tasks   │
 │ storageforge-job   (jobs)    │ ── run reports ───────► │     └► check against the index              │
 └──────────────────────────────┘                         │     └► script (download) or deploy (signed) │
                                                          └─────────────────────────────────────────────┘
```

| Piece | What it is | Where it lives |
| :--- | :--- | :--- |
| **Vault** | SSH private keys, encrypted with a key derived from `STORAGEFORGE_VAULT_SECRET` | `ssh_keys`, `key_bindings`, `vault_meta` |
| **Binding** | Which key and user reach which host, glob or CIDR, and what for (`scan`, `checksum`, `deploy`) | `key_bindings` |
| **Scan** | One read-only walk of a host: inventory, then every file on every eligible mount | `scans`, `hosts`, `mounts` |
| **Index** | Every file and folder the scans found, kept current by diffing each scan against the last | `directories`, `file_records`, `file_changes` |
| **Design** | A host's `storageforge/v1` blueprint: what the scan found plus what only you know (tiers, protection, exports, links) | `blueprints` |
| **Graph** | Hosts, pools, filesystems, mount points and symlinks with 3-2-1 health, rebuilt from index and design | `graph_nodes`, `graph_edges` |
| **Plan** | An ordered list of steps on one or more hosts: a change plan, a move plan, a host's shares, or a task | `change_plans`, `move_plans`, `blueprints`, `storage_tasks` |
| **Deploy** | A plan run on its hosts through `storageforge-run`, which runs only scripts StorageForge signed | `deploy_runs`, `deployed`, `jobs` |
| **Audit log** | Every connection, scan, sign-in, plan save and deploy, chained with an HMAC | `audit_log` |

## The flow

1. **Scan.** StorageForge connects with a bound vault key and reads the host. Nothing is written there.
2. **Look.** The topology, graph, search and inventory panels answer from the index. They never connect to a host.
3. **Design.** Mark tiers, protection, exports and planned links on the topology or in the planner, then **Save design**. The design survives rescans: hardware comes back from the scan, intent stays.
4. **Plan.** Stage changes, moves, shares or a task. Each one is checked against the index as you edit.
5. **Act.** Download the script and run it yourself, or **Deploy** it. Either way it reports first and changes things only when asked.
6. **Rescan.** The next scan shows the result, and flags *drift* if something deployed was changed by hand.

## The rules

Every feature follows the same rules. When adding one, follow them too; the [audit](audit-2026-10-29.md) lists the places that don't yet.

**Reading**

1. **Scans only read.** A scan runs `find`, `findmnt`, `lsblk`, `df` and friends under `nice`/`ionice`. Changing a host is always a separate, explicit step.
2. **Views answer from the index.** Browsing, checks, search, the Docker and Git panels, and the planner never open an SSH connection. Anything created since the last scan shows up after the next one.
3. **A failed walk deletes nothing.** A truncated stream, an SSH error, or more than half of a mount vanishing at once leaves the index as it was.

**Planning**

4. **Checks before scripts.** Every plan type has a check that walks it in order against the index (later steps see what earlier ones create) and returns `ok`, `warn` or `crit` per step.
5. **Your intent is yours.** Anything the scan cannot know (tiers, protection, exports, links, layout) is kept across rescans and **Refresh from latest scan**.
6. **Identifiers are safe words.** Text in designs and plans may not hold control characters or `< > " \``, and names (devices, pools, datasets, subvolumes) hold only what their tools accept, so nothing typed can break out of a generated script line or a page.

**Changing**

7. **Report first.** A generated script run with no options only reports, in the same words everywhere: `ok` (already so), `missing` (would change) and `conflict` (blocked). Changing things needs a mode flag:

   | Script | Flag that changes things | Extra lock |
   | :--- | :--- | :--- |
   | `changes-<plan>.sh` | `--apply` | `--destructive` for partition, format and add-device |
   | `shares-<host>.sh` | `--apply` | |
   | `<move plan>.sh` | `--run`, `--verify`, `--cutover`, `--install` | `--cutover` only after a clean verify |
   | `task-<name>.sh` | `--run`, `--install`, `--uninstall` | |

   `--apply` makes a host match a description (converges); `--run` performs an action (repeats).
8. **Idempotent.** Every step looks before it acts, so a rerun after a failure picks up where it stopped.
9. **Nothing is deleted.** Trash goes to `.storageforge-trash/<date>/` on the same filesystem; a moved source becomes `<name>.migrated-<date>`; a folder turned into a subvolume leaves its original in the trash; fstab and `smb.conf` are backed up before each edit and restored if verification fails.
10. **Destructive means three locks.** Drive tasks need the device typed twice in the plan, `--destructive` on the command line, and the device not being mounted, swapped on, or part of RAID, LVM or LUKS.
11. **Every script runs anywhere.** `--host [user@]host` copies the script to that machine and runs it there with sudo. Your SSH agent is forwarded only with `--forward-agent`.

**Trust**

12. **Secrets never touch disk in plaintext.** Keys are decrypted into locked memory and handed to a short-lived `ssh-agent` on tmpfs. Passwords for one-off setup steps (key install, scan access, deploy access) go to one SSH session through an askpass helper and are never stored or logged.
13. **Commands on hosts need a fresh password.** Anything that runs on a host from the web UI asks for your password again unless you typed it in the last 5 minutes.
14. **Everything is audited.** The audit log is append-only and hash-chained; `audit verify` finds an edited, deleted or reordered row.
15. **A name proves nothing.** Hosts are pinned to their SSH host keys and machine id. A machine claiming an indexed name is refused, and a signed deploy runs only on the machine it was signed for.

## Health colours

The graph and topology colour every node by the 3-2-1 rule:

| Colour | State | Meaning |
| :--- | :--- | :--- |
| 🟢 | protected | Snapshots and a validated offsite copy |
| 🟡 | local-only | A single site, or a stale copy |
| 🔴 | broken | Broken link, offline target, failed pool |
| grey | unknown | No protection data yet |

Pools and hosts take the worst state of what they contain. A scan cannot see sync, snapshot or backup policy, so a freshly scanned host is grey until its design says otherwise.

## Names used in these pages

| Term | Meaning |
| :--- | :--- |
| **Changes** | Staged change plans (folders, btrfs, mounts, drives). The CLI calls them `plan`, because `changes` already lists file changes between scans. The API is `/api/changes`. |
| **Moves** | Move plans: rsync, rsnapshot and git-mirror steps between folders |
| **Shares** | NFS and SMB exports in a host's design |
| **Tasks** | Small block-built programs that run on one host, by hand or on a timer |
| **Jobs** | The steps of a move plan once deployed, run by `storageforge-job` from systemd timers |
| **Runner** | `storageforge-run`, which verifies and runs signed scripts as root on a host |
