# StorageForge

A containerized storage platform: an encrypted SSH key vault, agentless file indexing over SSH, sub-second search across every host, a force-directed storage graph with Obsidian `.canvas` export, and Markdown architecture reports.

- **Nothing to install on targets.** It uses the system `ssh` client and POSIX tools that are already there (`find`, `findmnt`, `lsblk`, `df`, optionally `zpool` and `sha256sum`).
- **Keys never touch disk in plaintext.** They are encrypted with AES-256-GCM under an Argon2id-derived key, and each task loads its key into a private, short-lived `ssh-agent` on tmpfs.
- **Streaming and incremental.** NUL-delimited `find` output is parsed in 1 MiB chunks, and each scan is diffed against the last one in a single transaction.
- **Few dependencies:** `cryptography` ≥ 44, plus Flask, Flask-Login, Flask-Limiter and waitress for the web UI. PostgreSQL needs `psycopg` 3; YAML blueprints need PyYAML.

![Topology view](../docs/images/topology.jpg)

**Full documentation is in [`../docs/`](../docs/README.md):** [getting started](../docs/getting-started.md), [concepts and rules](../docs/concepts.md), [web UI](../docs/web-ui.md), [planner](../docs/planner.md), [scanning and search](../docs/scanning-and-search.md), [plans and scripts](../docs/plans-and-scripts.md), [deployments](../docs/deployments.md), [security](../docs/security.md), [operations](../docs/operations.md), and the [CLI](../docs/cli-reference.md), [API](../docs/api-reference.md) and [database](../docs/database.md) references. This README is the summary.

## Quick start (Docker)

```bash
docker compose up -d --build                  # creates the secrets and a self-signed certificate; UI and API on https://<this machine>:8443
docker compose exec storageforge storageforge-index user add admin              # web UI account (prompts for a password)
docker compose exec storageforge storageforge-index vault generate --name fleet   # prints the public key
#   … add that public key to ~scan/.ssh/authorized_keys on your hosts, then:
docker compose exec storageforge storageforge-index vault bind --key fleet --host 10.0.20.0/24 --user scan
docker compose exec storageforge storageforge-index scan --host 10.0.20.5
```

To import an existing key over stdin (it is never written to the container filesystem):

```bash
docker compose exec -T storageforge storageforge-index vault add --name nas --key-file - < ~/.ssh/id_ed25519
```

`examples/demo/demo.sh` runs the whole flow against a disposable SSH target container: it generates a vault key, binds it, scans over SSH with checksums, imports the atlas blueprint and opens the UI.

```bash
pip install .                    # without Docker: python3 -m storageforge_index …
pip install '.[postgres]'   # optional extras
```

## Security model

| Concern | Design |
| :--- | :--- |
| Keys at rest | Envelope encryption. `STORAGEFORGE_VAULT_SECRET` → Argon2id (t=3, 64 MiB, p=4, random salt) → KEK, which is never stored. The KEK wraps a random 256-bit DEK per key; the DEK encrypts the OpenSSH private key with AES-256-GCM. Associated data binds every ciphertext to its row's UUID and purpose, so a ciphertext swapped between rows fails to decrypt. A GCM-encrypted verifier detects a wrong secret. |
| Weak keys | RSA below 3072 bits is refused. Passphrase-protected keys are accepted with `--passphrase-env` and stored decrypted inside the vault. |
| Secret rotation | `vault rotate-secret` rewraps every DEK and the audit key under a new KEK in one transaction. Key ciphertexts never change. |
| Runtime | Plaintext is decrypted with `update_into` into an `mlock`ed `bytearray`. It is written to `ssh-add -` from that buffer, then zeroed. The agent (`ssh-agent -D -a`) listens on a socket in a fresh 0700 directory on the tmpfs `/run/storageforge`, with a key lifetime limit. It is killed and the directory removed when the task ends. `ssh` runs with `-F /dev/null`, `IdentityAgent=<socket>`, `BatchMode`, password auth off and a persistent `known_hosts` (trust on first use). |
| Host identity | A host's name is what it reports, so it proves nothing. Each indexed host is pinned to the SSH host keys verified at its address. A scan of another machine that claims an indexed name (or the same short name) is refused and audited, and the real host's address, data and deploys are untouched. Deploy requests also carry the host's `/etc/machine-id`, so a request runs on no other machine, even one with the same short name. Signed runs keep `storageforge-run` up to date on hosts. After reinstalling or moving a host: `storageforge-index hosts rekey <name>`, then scan it. |
| Host mapping | `key_bindings` maps keys to an exact host or IP, a glob (`*.tailnet.ts.net`) or a CIDR, with a user, port and allowed actions (`scan`, `checksum`). The most specific match wins: host, then glob, then longest prefix, then priority. |
| Audit | Every connection, scan result, denial and vault change is appended to `audit_log`. Each entry carries an HMAC-SHA256 over the previous entry's hash, with a random MAC key wrapped by the KEK. Triggers reject UPDATE, DELETE (and TRUNCATE on PostgreSQL). `audit verify` detects an edited, deleted or reordered row even if the triggers were bypassed. |
| API | Local accounts. Flask-Login manages sessions and Werkzeug hashes passwords (scrypt); StorageForge has no auth code of its own. The session cookie is signed with `STORAGEFORGE_SESSION_SECRET`, `HttpOnly`, `SameSite=Strict`, and `Secure` (as `__Host-sf_session`) when `STORAGEFORGE_COOKIE_SECURE=1`, which compose sets. A session ends 30 minutes after sign-in; each user can raise their own to as much as 8 hours in the header's Session menu. The app and planner pages and their scripts are served only with a valid session; without one they redirect to a separate `/login` page, and an open page empties itself and goes there as soon as its session ends (signed out, expired, or ended from the CLI), so nothing loaded earlier stays on screen. Sessions are also kept server-side (only a hash of their id is stored), so signing out ends that session even for a copied cookie; `storageforge-index user signout <name>` ends all of them, as do changing or disabling the account. Anything that runs commands on hosts (deploys, job runs and cutovers, restores, key install, scan and deploy access) asks for the password again, which then stays confirmed for 5 minutes; so does changing the session length. State-changing routes accept only `application/json`, so a cross-site form cannot reach them. Every sign-in attempt is audited. Flask-Limiter throttles failed sign-ins: 10 per minute and 50 per hour per client IP, 5 per minute and 20 per hour per username from one network (/24 or /64, so a stranger cannot lock the owner out), and 100 per day per username from anywhere. Hitting a limit is audited. After that `/api/login` answers `429` with `Retry-After`. Successful sign-ins don't count, and counters reset when the server restarts. Behind a reverse proxy, set `STORAGEFORGE_PROXY_HOPS=1` so limits and the audit log see the real client IP from `X-Forwarded-For`. Strict CSP (`'self'` only), `nosniff`, `frame-ancestors 'none'`, `no-store`, 4 KiB body cap, list sizes clamped. `/healthz` gives only `{"status"}` unless asked from inside the container or by a signed-in user. Alert URLs may not point at loopback, link-local (cloud metadata) or multicast addresses, redirects are not followed, a stored ntfy/Gotify token is dropped when its server changes, and the test button reports only HTTP status codes. ssh and other child processes never see `STORAGEFORGE_*` variables. Served by waitress. The UI builds the DOM with `textContent` only. |
| Container | Non-root uid 10001, read-only root filesystem, `cap_drop: ALL`, `no-new-privileges`, tmpfs runtime and `/tmp` (`noexec,nosuid,nodev`), 2 CPU / 2 GiB / 256 PID limits, memlock raised for `mlock`. Secrets come from compose secret files. The app's own port is not published; only the nginx proxy is, on 8443 on every interface so the LAN can reach it (`STORAGEFORGE_HTTPS_BIND=127.0.0.1` keeps it on this machine). |

Python cannot promise that no other copy of a secret exists in memory: the environment variable and import paths are ordinary immutable objects. The design minimizes how long plaintext lives and never writes it to disk. It does not claim zero copies. The compose stack puts nginx in front with a self-signed certificate for the LAN; StorageForge is not meant to face the internet.

## Commands

```bash
# Index a host (repeat --host for several). Key auth only; never prompts.
storageforge-index scan --host 10.0.20.5 --user root --key ~/.ssh/id_ed25519

# Show what would be walked and the exact find commands, without writing anything
storageforge-index scan --host nas-02 --user backup --key ~/.ssh/nas --dry-run

# Search across every indexed host
storageforge-index search --name "*.cr2" --host node-01 --size-gt 100MB
storageforge-index search "IMG_2019*" --under /mnt/storage_array/photos --sort size --desc
storageforge-index search "*invoice*2024*" --type f --newer-than 90d --format json

# What changed in the last scan, duplicates, hosts
storageforge-index changes --host node-01
storageforge-index scan --host node-01 --user root --key ~/.ssh/id --checksum   # hash size-collision candidates
storageforge-index dupes --min-size 50MB
storageforge-index hosts

# Architecture report from the index, optionally overlaid with a StorageForge blueprint
storageforge-index export-markdown --host atlas --blueprint atlas-blueprint.json -o atlas.md

# Architecture report from saved payloads, with no index and no SSH
storageforge-index report --blueprint blueprint.json --fstab fstab --df df-h.txt --zpool-status zpool.txt -o report.md
storageforge-index report --lsblk lsblk.json --df df.txt --zpool-status zpool.txt --hostname nas-02

# Vault, audit, graph and server
storageforge-index vault init | status | list | bindings
storageforge-index vault generate --name fleet [--type ed25519|rsa]
storageforge-index vault add --name nas --key-file ~/.ssh/id_ed25519 [--passphrase-env VAR]
storageforge-index vault bind --key fleet --host '*.tail4c2e.ts.net' --user scan --actions scan,checksum
storageforge-index vault resolve --host nas-02.tail4c2e.ts.net
STORAGEFORGE_VAULT_NEW_SECRET=… storageforge-index vault rotate-secret
storageforge-index audit tail | verify
storageforge-index scan --host nas-02          # no --key: uses the vault binding through an ephemeral agent
storageforge-index blueprint atlas.json        # design intent overlaid on the graph after each scan
storageforge-index graph build | stats
storageforge-index graph import --blueprint atlas.json --df df.txt --zpool-status zpool.txt
storageforge-index canvas -o storage.canvas    # Obsidian JSON Canvas
storageforge-index serve --listen 127.0.0.1 --scan-interval 6h
storageforge-index user add | passwd | disable | enable | remove | signout | list

# Plans, inventory and maintenance (see docs/cli-reference.md for every option)
storageforge-index plan list | types | check | script | ansible | import
storageforge-index moves list | check | script | import
storageforge-index shares check | script <host>
storageforge-index deploy status | setup-script | alerts
storageforge-index folders | git | docker | access status | access script
storageforge-index hosts rekey <name>          # after reinstalling a host
storageforge-index backup [--full] | backup list | restore FILE --yes | prune [--vacuum]
```

The full command reference is in [`docs/cli-reference.md`](../docs/cli-reference.md).

Sizes accept `100MB` (decimal), `100MiB` or `100M` (binary, as `df` and `find` print them). Ages accept `90m`, `36h`, `7d`, `2w` and `1y`.

The database defaults to `~/.local/share/storageforge/index.db`. Use `--db postgresql://user@host/storageforge` or set `STORAGEFORGE_DB` instead.

## Graph and Obsidian canvas

The main page opens on the **Topology** view, a schema-designer canvas. Each host is a frame; each disk, pool and remote is a table whose rows are the partitions, subvolumes, datasets and mount points under it, and lines join rows across tables (a member partition's FK row to its pool, a mount point to the links and exports inside it, an export to the client mounting it). Scroll to pan, Ctrl+scroll to zoom, drag a table or a host by its heading, collapse tables, and find anything from the toolbar. Table positions save with the design; **Auto-layout** forgets them. The view is drawn from the host's design, the same one the planner edits. Select a box to edit what the operator owns: device and pool tiers, 3-2-1 protection on a mount point (snapshots, sync, backup target, offsite), and links and exports. Hardware and layout come from the scan. To set a backup target, drag one mount point onto another, on the same host or a different one. **Save design** stores the design and rebuilds the graph, and the mount health dots update. **Graph** switches to the force-directed view.

Right-click almost anything for its actions:

| Where | Menu |
| :--- | :--- |
| Topology box | edit, show in graph, tier, protection, move, export, link, the changes staged on it (edit or unstage), every change that can be staged there, copy path, device or UUID |
| Host heading | scan now, add a link or export, deploy shares, review staged changes, open in the planner |
| Graph node | details, focus, center, unpin, edit in the topology, browse folders, largest files, move from here |
| Folder in the browser | open, largest files, rename, trash, permissions, link to it, turn into a subvolume, snapshot, copy to another disk, copy path |
| Search result | show its folder, largest files there, rename, trash, permissions, copy its folder to another disk, copy path |
| Staged change, Moves step | edit, reorder, duplicate, remove (and swap source and destination for a step) |

The menu key and Shift+F10 open it on the focused box. Text fields, links and Shift+right-click keep the browser's own menu.

The graph is rebuilt per host after every scan, from the index plus any stored blueprint.

| Node | Example id | Edges |
| :--- | :--- | :--- |
| Host | `host:atlas` (external targets have no owning host) | `CONTAINS` pools and standalone filesystems |
| StoragePool | `pool:atlas:tank` | `CONTAINS` datasets and arrays' filesystems |
| Filesystem | `fs:atlas:tank/media` | `MOUNTED_AT` mount points, `REPLICATES_TO` sync and backup targets |
| MountPoint | `mnt:atlas:/mnt/storage_array/media` | `MOUNTED_AT` bind mounts |
| Symlink | `link:atlas:/var/media` | `SYMLINK_TO` the mount holding its target, or another link |

Health colours follow the 3-2-1 rules: 🟢 protected, 🟡 local-only, 🔴 broken or offline, grey for no data. Pools and hosts take the worst health of what they contain.

The UI at `/` is a dependency-free canvas force simulation with charge, springs, collision and gravity:
- drag to pan, scroll to zoom, drag a node to move it (it stays where you drop it; shift-drag lets it spring back, and "Show all" releases every pinned node)
- click a node for details and connections; double-click it to focus on its 1–3 hop neighbourhood
- search files from the header, export `.canvas`, queue scans, and read or verify the audit log

`canvas` and `/api/canvas` write JSON Canvas 1.0. There is one group per host, columns run Host → Pool → Filesystem → Mount → Symlink, and external targets sit in their own group. Obsidian colour presets are 4 for green, 3 for yellow and 1 for red. See [`examples/storageforge-network.canvas`](examples/storageforge-network.canvas).

## API

| Method | Path | |
| :--- | :--- | :--- |
| GET | `/healthz` | database, vault, worker and user-count status (no auth; used by `HEALTHCHECK`) |
| POST | `/api/login`, `/api/logout`; GET `/api/me` | session |
| GET | `/api/hosts`, `/api/graph[?host=]`, `/api/canvas[?host=]` | topology |
| GET | `/api/search?q=&host=&size_gt=&type=&under=&limit=` | file search |
| POST | `/api/scan` `{"host": "…"}` | queue a vault-backed scan (up to `STORAGEFORGE_SCAN_WORKERS` hosts at once; duplicates collapse) |
| GET | `/api/planner/hosts` | scanned hosts and saved designs |
| GET | `/api/planner/design?host=&source=saved\|scan` | a design: the saved one, or built from the latest scan plus saved intent |
| PUT | `/api/planner/design` | save a `storageforge/v1` blueprint (2 MiB cap) and rebuild the host's graph |
| PUT | `/api/planner/example` `{"show": false}` | remove (or restore) the built-in example host for everyone |
| GET | `/api/planner/activity?host=` | staged changes, moves, shares, deployed jobs, drift and unreadable folders on a host |
| GET | `/api/keys` | vault keys (public halves only) and host bindings |
| POST | `/api/keys` `{"name": "…", "type": "ed25519" or "rsa"}` | generate a key inside the vault |
| POST | `/api/keys/install` `{"key", "host", "port", "user", "password", "bind", "checksum"}` | `ssh-copy-id` the public key with the host password, verify key login, optionally bind it for scans (10 per minute per user) |
| GET | `/api/jobs`, `/api/audit[?limit=]`, `/api/audit/verify` | jobs and audit |
| | `/api/changes`, `/api/moves`, `/api/shares`, `/api/tasks`, `/api/deploy/…` | plans and deployments: see [`docs/api-reference.md`](../docs/api-reference.md) for all of them |

This is a selection; [`docs/api-reference.md`](../docs/api-reference.md) lists every route. All `/api/*` routes except `/api/login` and `/api/jobs/report` (which takes a job's bearer token) need a session. Sign in with `POST /api/login` `{"username": "…", "password": "…"}`, which sets the session cookie (`__Host-sf_session` with `STORAGEFORGE_COOKIE_SECURE=1`, else `sf_session`); `POST /api/logout` ends it, and `GET /api/me` returns the signed-in user.

```bash
storageforge-index user add alice                 # prompts twice, or reads one line from stdin
storageforge-index user add bot --password-env BOT_PW
storageforge-index user passwd alice | disable alice | enable alice | remove alice
storageforge-index user list
```

Passwords need at least 12 characters. After 20 failed sign-ins in an hour from one network, an account is locked from that network for up to an hour, even with the right password. After 100 failures in a day from anywhere, it is locked everywhere for up to a day. Restart the server to clear either sooner.

## Planner

`/planner` is the StorageForge design tool, served by the same app and signed in with the same account. It has these views:

- **Overview:** capacity, 3-2-1 protection and every guardrail. For a real host it also lists what the rest of StorageForge holds for it: staged changes, data moves, designed shares and their check results, deployed backup/sync/snapshot jobs and their state, drift, and folders the last scan could not read. Each row links to that panel on the main page.
- **Devices:** block devices, partition tables and filesystems.
- **Mounts:** the mount tree with conflict checks, and generated `/etc/fstab` and systemd units.
- **Links:** symlinks and bind mounts, with health checks and boot ordering.
- **Topology:** disks, pools and mounts as a diagram.
- **RAID calculator.**
- **Protection:** the 3-2-1 grid.
- **Export:** Bash, Ansible, systemd, JSON/YAML blueprint and ASCII tree. These build a host from bare disks. To change a running host, stage the change in **Changes** and run it from **Deploy** instead.

Pick a host in the rail:

- **A scanned host with no saved design** opens as a design built from its latest scan. This includes real disks, partitions, UUIDs, btrfs subvolumes (also through LUKS), mdadm/ZFS/multi-device btrfs pools, mount options, remote mounts, bind mounts and problem symlinks. Protection rows start as "None" because a scan cannot see sync, snapshot or backup policy. `/tmp`, `/var/tmp` and `/var/cache` start as ephemeral.
- **Save design** stores it as the host's `storageforge/v1` blueprint and rebuilds its graph, so reports and the graph pick up your tiers, protection, exports and planned links. A host that has never been scanned gets its graph from the design alone.
- **Refresh from latest scan** rebuilds the hardware from the newest scan and keeps what only you know. That means disk and pool tiers, encryption notes, protection rows (rows for things that disappeared stay listed), exports, manual links and remotes the scan didn't see.
- Unsaved edits are kept per host in the browser until you save.
- The rail's **In StorageForge** links open the main page on that host's Changes, Moves, Deploy, Docker, Git, Cleanup or Access panel (`/#host=nas-02&tab=changes`).

The built-in example host "atlas" is a full design to explore; edits to it stay in your browser. Like every page, the planner needs a sign-in. Once you have real hosts, **Remove example host** hides it from the planner for every user, and the planner opens your first host instead. **Show example host** brings it back.

The graph header links to the planner, and a host node's **Open in planner** jumps straight to it. The planner is served under the same CSP, with one relaxation, `style-src-attr 'unsafe-inline'`, for its inline-sized bars. It uses system fonts, because web fonts are blocked by the CSP.

Scans read each btrfs filesystem's RAID profile from `/sys/fs/btrfs`. Where that cannot be read, a multi-device btrfs pool imports as `single`: set the real level in the planner before trusting its capacity and fault-tolerance numbers.

## Unreadable folders and read-only scan access

Scans run as an ordinary user, so `find` cannot open folders like `/root`, `/etc/ssl/private` or another user's home folder. Each scan records which folders it could not read. The **Access** tab lists them per host, and topology host headers show an "N unreadable" badge.

To fix it without scanning as root, set up read-only scan access. The script gives the scan user private copies of `find` and `sha256sum` that carry `CAP_DAC_READ_SEARCH`, the approach restic documents for backup users. The copies live in `/usr/local/lib/storageforge`, owned by root and executable only by the `storageforge-scan` group. They can list and checksum every file. They cannot write, change ownership or run anything as root, and programs they start do not inherit the capability. Scans use the copies when they work and fall back to the plain tools otherwise.

There are three ways to run the script:

- **Access tab → Set up read-only access.** StorageForge runs the script once over SSH with sudo. It uses either the scan user's sudo password (connecting with its vault key) or an admin account's password. The password goes only to that one SSH session and is never stored.
- **Run it yourself:** `storageforge-index access script --host nas-02 | ssh admin@nas-02 sudo sh`
- **Remove it:** use the same commands with `--remove`.

The script needs `setcap`, which comes in `libcap2-bin` on Debian and in `libcap` on RHEL. Inside Docker or LXC, the capability must be allowed in the container's bounding set. If it is not, the script says so and leaves nothing behind.

## Staged changes: folders, btrfs, mounts and drives

Change plans work like an Ansible playbook for storage: an ordered list of tasks, each on one host. Stage them from the topology view. Every box has a **Plan a change** section, and **Browse folders** on a mount lists its folders with indexed sizes, each with its own actions. Staged subvolumes and mounts appear as dashed boxes, and other staged tasks mark the box they touch. Then review, reorder, check and download the plan in the **Changes** tab.

| Group | Tasks |
| :--- | :--- |
| Files and folders | create folder, rename or move (same filesystem), move to trash, symlink, owner and permissions |
| btrfs | create subvolume (optionally without copy-on-write), snapshot, turn a folder into a subvolume, add a device to a pool, convert profile (balance), scrub |
| Mounts | add a mount (fstab), change mount options, unmount |
| Drives | partition a disk (GPT, one partition), format, set the filesystem label |

**Check** goes through the plan in order, from the index, so later tasks see what earlier ones create. It flags:

- a missing source, or a destination that already exists;
- a rename that crosses filesystems (use Moves for that);
- btrfs tasks on another filesystem;
- formatting a mounted device, a pool member or the OS disk;
- profiles that need more devices than the pool has;
- mounts over folders that already hold files;
- running containers using the path;
- tasks that undo each other.

**Bash script** (`changes-<plan>.sh`, in the style of `storage-setup.sh`):

```bash
./changes-plan.sh                               # report: ok (already so), missing (would change), conflict (blocked)
sudo ./changes-plan.sh --apply                  # make the changes in order; stops at the first failure
sudo ./changes-plan.sh --apply --destructive    # also partition, format and add devices to pools
./changes-plan.sh --host rocks@10.42.0.3 --apply
```

Every task looks before it acts, so reruns are safe. fstab is backed up before each edit, and the backup is restored if `findmnt --verify` rejects the result. Nothing is deleted: trashed paths go to `.storageforge-trash/<date>/` at the top of their filesystem or subvolume (so it stays a rename), and a folder turned into a subvolume leaves its original there. Drive tasks have three locks:

1. the device typed twice in the plan;
2. `--destructive` on the command line;
3. a refusal to touch anything that is mounted, swapped on, or part of RAID, LVM or LUKS.

**Ansible playbook** (`changes-<plan>.yml`): the same tasks with standard modules (`ansible.builtin.file`, `ansible.posix.mount`, `community.general.parted` and `filesystem`, and `command` for btrfs). The inventory lines from the last scans are at the top. Drive tasks run only with `-e storageforge_destructive=true`.

On the CLI: `storageforge-index plan list|types|check|script|ansible|import`.

Scans also read each btrfs filesystem's data and metadata profiles and its label from `/sys/fs/btrfs`, so a multi-device pool shows as e.g. "btrfs raid1/raid1 · 4 devices", with usable space worked out from the profile. Its subvolumes and their mount points are listed under the pool.

Change plans also create ZFS pools and datasets and LVM volumes, and send btrfs and ZFS snapshots to other hosts. See [Plans and scripts](../docs/plans-and-scripts.md).

## Moving data: plans and rsync scripts

The **Moves** tab plans where data goes. Each step takes a folder on one scanned host to a folder on another, or on the same host, using one of five methods (the fifth, `git`, is in [Git repositories](#git-repositories-and-archives)):

| Method | What the script does |
| :--- | :--- |
| copy | rsync the folder across. The source is left alone. |
| move | Copy, `--verify`, then `--cutover`: the source is renamed to `<name>.migrated-<date>` (never deleted). On the same host, a symlink is left at the old path. |
| mirror | `--install` writes a systemd timer that keeps the copy in sync. It can also remove files that are gone from the source (`--delete-after`). |
| rsnapshot | `--install` writes an rsnapshot config and timers for rotating hard-linked snapshots. |

You pick folders with a browser that shows each folder's indexed size, or use **Move from here…** on a mount point in the topology. **Check** answers from the index without touching any host. It reports:

- how much each step transfers and roughly how long it takes;
- free space on each destination mount, summed across steps;
- planned mounts that aren't mounted yet;
- destinations that would land on the root filesystem;
- source and destination folders that overlap;
- folders the scan couldn't read;
- files that are already at the destination.

**Download script** writes a Bash script in the style of `storage-setup.sh`:

```bash
./plan.sh                  # report: sources, destination mounts, free space, SSH and sudo (read-only)
./plan.sh --dry-run        # what rsync would transfer
sudo ./plan.sh --run       # copy; resumable, safe to rerun
sudo ./plan.sh --verify    # compare (add --checksum to read every byte)
sudo ./plan.sh --cutover   # finish move steps after a clean verify
sudo ./plan.sh --install   # mirror and rsnapshot timers
./plan.sh --host rocks@10.42.0.3 --run   # run it on that machine (copies itself over, uses sudo there)
```

Each step runs on its destination host and pulls from the source over SSH, using `rsync -aHAX --numeric-ids`. A step stops if its destination mount isn't mounted, so nothing lands on the root filesystem. Every run is logged to `/var/log/storageforge/`.

To read every file on the source, the script uses `sudo rsync` there. Only rsync's sending (read-only) side is needed, so allow just that:

```bash
echo 'rocks ALL=(root) NOPASSWD: /usr/bin/rsync --server --sender *' | sudo tee /etc/sudoers.d/storageforge-rsync
```

Timers run as root without your SSH agent, so for mirror and rsnapshot steps root on the destination needs its own key on the source. `--install` checks this.

The CLI has the same commands: `storageforge-index moves list|check|script ID -o plan.sh|import plan.json`.

## Git repositories and archives

Scans still skip what is inside `.git`, but they now record the `.git` entry itself, which marks a working copy. Bare repositories are found too: a folder holding `HEAD`, `config`, `objects/` and `refs/`. After the file walk, one SSH call asks the host's git about each repository (read-only, with a 20 s timeout each). It records the branch, last commit, first commit, branch and tag count, remotes, uncommitted changes, and how far it is ahead of or behind its upstream.

Repositories with the same first commit hold the same history, so copies are matched however they are named. The **Git** tab gives each repository one state:

| State | Meaning |
| :--- | :--- |
| uncommitted | The working copy has uncommitted changes. |
| unpushed | It has commits its upstream doesn't have. |
| behind | Another copy has newer commits. |
| single copy | No other scanned machine has this history. |
| copied | Another scanned machine has this history. |
| archived | A bare copy exists on another machine. |

**Archive to…** adds a `git` step to Moves. The step keeps a `git clone --mirror` on the destination, refreshed by `--run`, or on a timer after `--install`. `--verify` checks that every branch and tag points at the same commit as the source. On the CLI: `storageforge-index git`.

## Docker and compose stacks

After the file walk, each scan asks the host's container engine what is there. It tries Docker, then Podman, either directly (the scan user is in the `docker` group) or through `sudo -n`. It records every container's name, image, state, compose labels and mounts; every volume with its size; and Docker's data directory.

It then reads the compose files the index found (`docker-compose.yml`, `compose.yaml`, and so on) and keeps only services, images and volume definitions. Environment sections, `.env` files and passwords in volume options are never stored.

The **Docker** tab lists each host's stacks:

| State | Meaning |
| :--- | :--- |
| running | Every container in the stack is running. |
| partly running | Some of its containers are running. |
| stopped | Its containers exist but none is running. |
| stored | A compose file on disk that nothing was deployed from. |

Each stack shows its containers and the host folders and volumes they use. The tab also lists unused volumes with their sizes, and flags containers that mount the Docker socket (that gives root-equivalent control of the host).

Managers that run in a container record each stack's folder as they see it from inside their own container. Dockhand records `/app/data/stacks/…`, for example. Those paths are translated to host paths through the manager's own mounts, so stacks from Dockhand, Portainer, Komodo and Dockge point at their real folders.

**Which containers use a folder?** answers from the index, and mount boxes in the topology show how many containers use them. A Moves step whose source or destination is used by a running container gets a warning naming the stacks to stop first. On the CLI: `storageforge-index docker [--host H] [--path P]`.

## Deploying NFS and SMB shares

Shares you add to a host's design can be deployed. Scanned shares are only reported. **+ Export** (or **Share this…** on a mount point) opens the share wizard:

1. **Folder**: browse the server's file system from the index. Each folder shows the disk or network mount it lives on, mounts below it, shares already there and shares other designs mount there; the side list shows every mount of the host with its free space.
2. **Access**: NFS (one rule per client or subnet, with presets and one-click subnets of the scanned hosts, and crossmnt when filesystems are mounted inside) or SMB (users and read-only).
3. **Clients**: where each client mounts it, picked by browsing that client's own file system.
4. **Review**: what will happen, then **Save** into the design and **Deploy**.

Every step is checked against the index as you go: system and pseudo paths, re-exporting a network mount, folders not in the index, duplicate names and paths, nested exports, filesystems inside the share, and per client a mount point that already holds a disk or another share, sits inside a network mount, is a system folder, or would hide files. Each share can list **Mount on** clients. **Deploy shares** on the host checks the design, then downloads `shares-<host>.sh`. Without `--apply` the script only reports.

With `sudo ./shares-<host>.sh --apply`, it does the following on the server:

- installs the NFS server or Samba if missing (apt, dnf, zypper or pacman);
- writes its own `/etc/exports.d/storageforge.exports` and `/etc/samba/storageforge.conf`, and adds one include line to `smb.conf` (after a backup);
- checks the config with `testparm`;
- labels SMB folders `samba_share_t` when SELinux is enforcing;
- opens firewalld or ufw for the listed clients;
- starts the services;
- reports Samba accounts that still need `smbpasswd -a`.

On each client it installs the mount helper, keeps SMB credentials in a 0600 file (asking for them once), appends an fstab line with `_netdev,nofail,x-systemd.automount` after a backup, and mounts the share.

NFS shares must name their clients, such as a subnet. Existing fstab lines are never changed. On the CLI: `storageforge-index shares check|script <host>`.

**Shares** on the topology toolbar (or **Manage shares…** on a host's menu) lists every share on the hosts in view: its folder, who may use it, who mounts it, its state and any check problems. Edit or remove designed shares from there; removing a deployed share takes it down at the next deploy. Shares only the scan knows are read-only.

## Storage tasks: rsync, snapshots and other jobs from blocks

The **Tasks** view (next to Topology and Graph) builds small programs from blocks and runs them on one host, by hand or on a systemd timer. Drag blocks from the palette, or click one to add it at the end or into the selected slot. Each block shows its fields; collapse it to a one-line sentence. Ctrl+Z undoes.

| Group | Blocks |
|---|---|
| Guards | Require mounted, Require free space, Require host up |
| Control | If (mounted, exists, free below, weekday, day of month, host up, command succeeds) with then/else, Try with a fallback, Stop |
| Copy | Copy with rsync (copy or mirror, one side may be another host), Rotating backup (dated hard-linked folders, keep N), Verify copy |
| Snapshots | btrfs snapshot, Prune btrfs snapshots, ZFS snapshot, Prune ZFS snapshots |
| Services | Docker compose stop/start/restart, systemd unit stop/start/restart |
| Other | Make folder, btrfs scrub, Run command, Wait, Log |

"If the task fails" blocks run after a failure. Templates cover nightly mirrors, snapshot rotations, rotating backups and stop-snapshot-start.

Each block is checked against the index while you edit. The check covers paths, btrfs and ZFS targets, overlapping copies, and free space at the destination. It also catches a destination on a data disk with no guard: if that disk is missing, the copy fills the system disk. A mirror whose source disk could be unmounted gets the same warning, since it would empty the copy. Those warnings come with a one-click "Add Require mounted" fix.

**Script** shows `task-<name>.sh`. Run plainly, it is read-only: it checks the guards and prints each command it would run. `--run` runs it. `--install` copies it to `/usr/local/lib/storageforge/tasks` and adds `sf-task-<name>.service`, plus a `.timer` when the task has a schedule. `--uninstall` removes them. Runs take a lock, so they never overlap, and leave `/var/lib/storageforge/tasks/<name>.last`.

**Deploy** does the same from the web UI, through the signed deploy runner: Dry run, Install, Run now or Uninstall. A task moved to another host is uninstalled from the old one.

## Cold data

The **Cleanup** tab also lists folders whose newest file is older than a cutoff, 2 years by default. Each folder shows its size, and **Move…** starts a Moves step, for example to cold storage. Only the outermost cold folder is listed.

## Duplicate folders

The **Copies** tab and `storageforge-index folders` find folders that are likely copies, using only the index. Two folders match when they hold the same file names and sizes in the same subfolder layout. Renamed copies still match. Only the outermost copy is listed. Copies on the same host count as reclaimable space; copies across hosts are often backups. System paths, `node_modules` and similar are skipped unless you pass `--include-system`. To confirm the files are identical, run a `--checksum` scan and then `dupes`.

## Installing keys from the web UI

The **Keys** tab replaces the generate → copy → `authorized_keys` → bind steps:

1. **Generate** creates an ed25519 or RSA-4096 key inside the vault. The private half never leaves it.
2. **Install on a host** takes a host, port, user and that user's SSH password. It then:
   - logs in with the key through an ephemeral agent, and if that already works it skips the copy, so `authorized_keys` never gets a duplicate line;
   - otherwise runs `ssh-copy-id -f` with only the public key. The password reaches `ssh` through the `storageforge-askpass` helper's environment (`SSH_ASKPASS_REQUIRE=force`, no tty), never through argv or disk. Only one password attempt is made (`NumberOfPasswordPrompts=1`), and only password prompts are answered;
   - logs in with the key again to confirm it works, and then, if asked, adds a host binding for `scan` (and `checksum`).
3. **Scan now** on a binding queues a scan.

Host keys are trusted on first use into the same `known_hosts` that scans use. Every generate, install attempt and bind is audited with the signed-in user, and the password is never logged. Any signed-in user can do this; there are no roles yet.

The host must allow password login once for `ssh-copy-id`. Afterwards you can turn `PasswordAuthentication` off.

**Scanning the Docker host itself.** The container reaches other machines through the host, but connections to the host's own address arrive from the Docker network on the `sf0` bridge. A host firewall that only allows SSH from the LAN drops them, and `ssh-copy-id` or scans fail with "Connection timed out". With ufw, allow it once:

```bash
sudo ufw allow in on sf0 to any port 22 proto tcp
```

## Backups, retention and logs

Every night at 03:00 (the host's local time, `STORAGEFORGE_BACKUP_HOUR`) the server writes an **essentials** backup to the `sf-backups` volume (`/app/backups`) and keeps the last 14 (`STORAGEFORGE_BACKUP_KEEP`). The same happens at start-up if the newest backup is more than a day old.

An essentials backup holds everything a rescan cannot rebuild: the encrypted SSH keys and bindings, web users, the hosts list, host designs, change and move plans, storage tasks, settings (report URL, alert channels), deploy access, what is deployed where and its jobs, confirmed host keys, and the audit log. It is a few MB. It leaves out the file index and graph (the next scans rebuild them), run history, open alerts (re-checked on the next run) and web sessions (everyone signs in again). `backup.ESSENTIAL` and `backup.REBUILDABLE` list every table, and a test fails when a migration adds a table to neither.

A **full** backup is SQLite's online copy of everything, taken while the server runs. Set `STORAGEFORGE_BACKUP_FULL_KEEP=2` to also take one nightly. These are as large as the database (several GB with a big index).

```bash
docker compose exec storageforge storageforge-index backup            # essentials now
docker compose exec storageforge storageforge-index backup --full     # everything
docker compose exec storageforge storageforge-index backup list
docker compose stop storageforge
docker compose run --rm storageforge restore /app/backups/storageforge-essentials-20261027-030000.db --yes
docker compose start storageforge
```

Images built before 2026-10-29 don't recognise `restore` and the other newer subcommands in `docker compose run`. Rebuild the image, or add `--entrypoint storageforge-index` after `--rm`.

A restore keeps the current database beside the new one as `index.db.pre-restore-<time>`. Backups never contain the vault secret, on purpose: a backup together with its secret would be the keys. Keep the vault secret safe somewhere else (`docker compose exec storageforge cat /run/sf-secrets/vault_secret`).

The backups volume lives on this machine. To keep copies elsewhere, add a Moves **mirror** step from `/var/lib/docker/volumes/storageforge_sf-backups/_data` to another host.

**Retention.** After every scan, and every night, StorageForge removes:

- file change history older than 90 days (`STORAGEFORGE_CHANGE_DAYS`), and the oldest scans' history beyond 2,000,000 rows (`STORAGEFORGE_CHANGE_MAX_ROWS`). The newest scan's changes on each host always stay;
- unreadable-folder lists from all but each host's latest scan;
- finished scan jobs older than 90 days.

Run `storageforge-index prune --vacuum` once to shrink the database file. It rewrites the whole file and locks it while doing so. Run it after upgrading to schema 12 (below) to give the freed space back.

**Schema 12: directories.** Each folder path is now stored once, in `directories`, and `file_records` points to it by `dir_id`. Before, the full path was repeated in every row and in two indexes. On an index of 11.9 million entries this took the database from 7.7 GB to 3.3 GB after `prune --vacuum`, and the change log from 6.3 million rows to 98,000. Folder queries got much faster: `search --under /mnt` from 23 s to 27 ms, and a `IMG_2019*` name search from 330 ms to 18 ms. On that index the migration took about 8 minutes and the vacuum 2. The migration runs on the first start after upgrading. It rewrites `file_records`, which takes a few minutes and needs about as much free space as that table, and the server is unavailable while it runs. It also drops change-log rows from earlier bulk imports (below).

**Request log.** By default (`STORAGEFORGE_ACCESS_LOG=changes`) only requests that change something, rate-limit hits and server errors are logged. Use `all` to log every request (the old behaviour), or `off`.

**Scheduling.** Hosts are scanned when their last scan job is older than `STORAGEFORGE_SCAN_INTERVAL`, checked every 10 minutes, so restarting the container doesn't rescan everything. A host is always queued under its indexed hostname, whether it was named by IP, alias or hostname.

## Container files

| File | Purpose |
| :--- | :--- |
| `Dockerfile` | `build` stage (venv), `test` stage (runs the suite: `docker build --target test .`), slim `runtime` with `openssh-client`, `sqlite3` and `tini`, uid 10001, `HEALTHCHECK` |
| `docker-compose.yml` | Hardened service, secrets, `sf-data` volume, tmpfs mounts, resource limits; an unprivileged, read-only nginx serves it over TLS on port 8443 |
| `docker/nginx.conf` | TLS 1.2/1.3, HSTS, http→https redirect, `X-Forwarded-For` replaced (not appended) |
| `docker/entrypoint.sh` | Refuses root, checks secret lengths, checks volume ownership and that the runtime dir is tmpfs, tightens permissions, migrates, creates or verifies the vault, imports keys from a read-only mount, then `exec`s |
| `docker/init-volumes.sh` | The one-shot `init-secrets` service: on first deploy, fills the `sf-secrets` and `sf-tls` volumes with the vault secret, session secret and a self-signed certificate for the host's name and address (`STORAGEFORGE_TLS_NAMES` adds more). Never overwrites; takes anything missing from `./secrets` first |
| `docker/init-secrets.sh` | Optional, on the host: makes the same files in `./secrets` for `init-secrets` to copy, with every LAN address in the certificate. Also sets up `keys/` for the key import (`STORAGEFORGE_SECRETS_GID`, written to `.env` when your group is not 1000) |
| `docker/egress-firewall.sh` | Optional, run as root: lets the containers open only SSH and alert ports (`STORAGEFORGE_EGRESS_PORTS`, default `22 443`) out of the `sf0` bridge, to other machines and to the Docker host itself (`STORAGEFORGE_BRIDGE` for another bridge, each with its own rules); `--remove` undoes it |
| `docker/requirements*.lock` | Every Python dependency pinned with hashes; the image installs with `--require-hashes` |
| `examples/demo/` | Disposable SSH target and an end-to-end script |

### Updating dependencies

The base image is pinned by digest and Python packages by hash. To move them forward (the cutoff skips releases younger than two weeks):

```bash
docker buildx imagetools inspect python:3.13-slim-bookworm | sed -n 's/^Digest: *//p'     # new digest for the Dockerfile's PYTHON_IMAGE
uv pip compile pyproject.toml docker/build-requirements.in --universal --python-version 3.13 --generate-hashes --no-header --exclude-newer "$(date -d '14 days ago' +%F)" -o docker/requirements.lock
uv pip compile pyproject.toml docker/build-requirements.in --extra postgres --universal --python-version 3.13 --generate-hashes --no-header --exclude-newer "$(date -d '14 days ago' +%F)" -o docker/requirements-postgres.lock
```

For PostgreSQL, build with `--build-arg EXTRAS=postgres` and set `STORAGEFORGE_DB=postgresql://…`. The test suite runs against it too (see [Tests](#tests)).

## Indexer architecture

```text
 target host (no agent)                         indexer
 ──────────────────────                         ───────
 ssh ControlMaster (one TCP session, multiplexed)
   ├─ inventory: hostname, os-release, lsblk -J, findmnt -J, zpool status, df
   ├─ find /       -xdev -prune(other mounts, excludes) -printf NUL-records ─► reader 1 ─┐ 20k-row batches
   ├─ find /home   …                                                         ─► reader 2 ─┤ bounded queues
   └─ find /mnt/x  …                                                         ─► reader N ─┘ (back-pressure)
                                                                                           │ routed by mount
                                                     writer pool ◄─────────────────────────┘
                                                     SQLite: 1 writer · PostgreSQL: up to 8 (one connection each)
                                                       stage rows (executemany / COPY) → index stage
                                                       → diff vs file_records → apply + FTS + change log
                                                       → commit (one transaction per mount)
```

| Module | Role |
| :--- | :--- |
| `remote.py` | SSH wrapper (`BatchMode`, `ControlMaster`, `accept-new` host keys, always `sh -c` so fish/csh login shells are fine), inventory probe, `find` builder |
| `stream.py` | NUL-record streaming parser; non-UTF-8 names stay searchable as `\xNN` escapes |
| `scanner.py` | Mount planning, parallel reader threads, writer pool, checksum pass |
| `db.py` | Migrations, staging, set-based diff, dialect helpers |
| `search.py` | Pattern classification and query builder |
| `payloads.py`, `analysis.py`, `report.py`, `capacity.py` | Report inputs, checks, Markdown renderer, pool and power math |

### Guardrails

| Risk | How it is handled |
| :--- | :--- |
| Pseudo filesystems | `proc`, `sysfs`, `devtmpfs`, `cgroup*`, `overlay`, `squashfs`, `autofs` and similar mounts are skipped. `/proc`, `/sys`, `/dev` and `/run` are pruned by path too. |
| Noise directories | `.git`, `node_modules`, `.Trash*`, `__pycache__`, `.snapshots` and `.zfs` are pruned by name. Add your own with `--exclude-name` and `--exclude-path`. |
| Symlink loops | `find -P` never follows symlinks, so a loop is recorded as two links rather than walked. Reports flag loops explicitly (ELOOP). |
| Bind mounts and recursive binds | Mounts sharing a `maj:min` whose `fs_root` nests inside an already planned mount are recorded as `bind-alias` and not walked twice. Every other mount point below a walk root is pruned, which also stops `-xdev` from descending into same-device binds. |
| Network mounts | NFS, SMB, rclone, sshfs and similar mounts are skipped by default (index them on their source host). Use `--include-network` to walk them. Automount points are never triggered. |
| Partial or failed walks | ssh exit 255, a truncated record stream, or `find` exiting 1 with no output aborts that mount's diff, so nothing is deleted. Unreadable directories (`find` exit 1 with output) are counted and reported. |
| Mass deletion | If more than `--max-delete-ratio` (default 50%) of a mount's 1,000+ entries vanish, the diff is refused and the index is left intact. |
| Subtree scans | `--path /srv/data` diffs only that subtree. Deletions are scoped to it, so siblings are never removed. |
| Load on the target | `find` and `sha256sum` run under `nice -n 10` and `ionice -c3` when available. Disable with `--no-nice`. |

### Incremental sync

Rows are keyed by `(dir_id, filename)`. A `dir_id` is one folder on one mount in `directories`. After a walk is staged, its folders are added to `directories`, and three set operations run in one transaction:

1. **Deleted:** indexed rows (in scope) missing from the walk. They are logged to `file_changes`, removed from FTS and deleted.
2. **Modified:** same key, different size, mtime, mode, owner, symlink target or type. The checksum is cleared when content may have changed.
3. **Added:** new keys are inserted with `first_seen_scan_id` set, and FTS is updated.

Added entries are logged only after a mount's first scan, so the first index does not write a million-row change log. A later scan that adds more than 50,000 entries to one mount, such as a new disk or a restored folder, counts them in the scan summary but does not list them one by one. Directory mtime changes update the row but are not logged as modifications. Folders left with no entries are removed from `directories`.

## Schema

The full DDL is in `storageforge_index/migrations/{sqlite,postgres}/`: `001_initial.sql` for the indexer, and [`002_vault_audit_graph.sql`](storageforge_index/migrations/sqlite/002_vault_audit_graph.sql) for `vault_meta`, `ssh_keys`, `key_bindings`, `audit_log`, `graph_nodes`, `graph_edges`, `blueprints` and `scan_jobs`. The CLI applies migrations automatically; each file also runs on its own with `sqlite3` or `psql`.

| Table | Purpose |
| :--- | :--- |
| `hosts` | `host_id`, `hostname`, `ip_address`, `os_info`, `last_scanned_at`, plus the SSH target used and the last inventory (`lsblk`, `zpool status`, `findmnt`, `df`) as JSON |
| `mounts` | `mount_id`, `host_id`, `mount_point`, `filesystem_type`, `total_bytes`, `used_bytes`, plus source, options, `maj:min`, `fs_root`, scan state (`indexed`, `skipped`, `bind-alias`, `gone`) and skip reason |
| `directories` | `dir_id`, `mount_id`, `path`: each folder path once, so file rows don't repeat it |
| `file_records` | `file_id`, `mount_id`, `dir_id`, `filename`, `extension`, `file_size_bytes`, `is_directory`, `is_symlink`, `symlink_target`, `mode_permissions`, `owner_uid`, `group_gid`, `modified_at`, `checksum_hash` |
| `scans`, `file_changes` | Scan history and per-scan added, modified and deleted entries |
| `file_fts` (SQLite) | FTS5 external-content table with the trigram tokenizer over `filename` |
| `v_files` | View with `hostname`, `mount_point`, `parent_path` and `full_path` for ad-hoc SQL |

Indexes include `UNIQUE (dir_id, filename)`, `(filename)`, `(file_size_bytes)`, `(extension, file_size_bytes)`, `(modified_at)`, `(mount_id, first_seen_scan_id)` and a partial index on `checksum_hash`, plus `directories (path)`. PostgreSQL adds `lower(filename)`, `pg_trgm` GIN indexes on `filename` and `directories.path`, and `text_pattern_ops` on `directories.path` for prefix queries under any collation.

### How a pattern is answered

| Pattern | SQLite | PostgreSQL |
| :--- | :--- | :--- |
| `*.cr2` | `extension = 'cr2'` (B-tree, with size from the same index) | same |
| `report.pdf` | `filename = … COLLATE NOCASE` | `lower(filename) = lower(…)` |
| `IMG_2019*` | `filename LIKE 'IMG_2019%'` (B-tree prefix range) | `filename ~* '^IMG_2019.*$'` (trigram GIN) |
| `*raw*2019*` | FTS5 trigram `LIKE` for candidates, then exact `GLOB` | `filename ~* …` (trigram GIN) |
| `--under /mnt/x` | `directories.path` B-tree range | `directories.path LIKE '/mnt/x/%'` (`text_pattern_ops`) |

## Measured performance

These numbers come from a local scan (no SSH hop) of `/usr` with a warm page cache: 1,172,684 entries totalling 23.3 GiB, on SQLite 3.54, Python 3.14 and NVMe.

| Step | Time |
| :--- | ---: |
| Remote walk and parse (stream) | 5.2 s (225k entries/s) |
| First index, total (stage, insert, FTS, commit) | 18.0 s |
| Rescan with no changes (walk and full diff) | 8.3 s |
| `search "*.so"` (7,604 hits) | 26 ms |
| `search "*python3*config*"` (trigram) | 3 ms |
| `search --path-contains …` (full folder-path scan, no match) | 78 ms |
| Index size | 459 MiB (≈ 410 bytes per entry, including indexes and FTS) |

Over SSH, throughput is usually bound by the remote disk walk and the link. One multiplexed connection with four parallel `find` streams keeps several mounts busy at once.

## Reports

`export-markdown` and `report` render the **StorageForge Architecture Report** with these sections:

1. Executive summary: identity, capacity (raw, usable, allocated, free) in TiB and TB, key findings, ASCII topology map
2. Node and disk inventory: drives, partition layout with alignment, pools and arrays, datasets, filesystems and mount flags with fstab identifiers
3. Symlink and bind-mount hierarchy: health checks and boot-order stages
4. 3-2-1 protection matrix, using the StorageForge dashboard rules
5. Economics: parity and reserve overhead, power and thermal budget

YAML front matter carries the headline numbers so other tools can parse the report. See [`reports/atlas-architecture-report.md`](reports/atlas-architecture-report.md), generated from [`examples/atlas`](examples/atlas).

## Tests

```bash
python3 -m unittest discover -s tests -v
```

`tests/test_platform.py` covers vault round trips, wrong-secret refusal, tampered and swapped ciphertexts, rotation, binding specificity, the audit chain under tampering, loading a key into a real ephemeral `ssh-agent`, graph building, `.canvas` validity (including no overlapping cards), and the HTTP API with auth and CSP. `tests/test_tasks.py` covers storage tasks: normalising, checks and generated scripts. `tests/test_consistency.py` keeps hand-kept lists in step: the container entrypoint against the CLI's subcommands, and the backup table lists against the schema. `tests/test_indexer.py` covers units and patterns, the stream parser (newlines in names, truncation, tiny reads), pool math against the dashboard, mount planning (bind aliases, pruning), payload parsers, report generation, and real local scans: incremental diff, subtree safety and the mass-delete guard.

The same suite runs against PostgreSQL when `STORAGEFORGE_TEST_PG` names a server it may create databases on (each test gets a fresh one, dropped afterwards). The backup tests are skipped there, since backups are of SQLite databases:

```bash
docker run -d --rm --name sf-test-pg -e POSTGRES_USER=sf -e POSTGRES_PASSWORD=sftest -p 127.0.0.1:55432:5432 postgres:16-alpine
STORAGEFORGE_TEST_PG=postgresql://sf:sftest@127.0.0.1:55432/postgres python3 -m unittest discover -s tests
```
