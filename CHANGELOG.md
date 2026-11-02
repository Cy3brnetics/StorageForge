# Changelog

Newest first. Versions are not tagged yet: everything so far is 0.2.0.

## Unreleased

### Fixed
- **Lab reports include tiers 6 and 7.** They ran, but a failure there never reached the report or its result.
- **Scans find ZFS pools and LVM volumes as an ordinary user on Debian-based hosts.** `zpool` and `lvs` were off that user's `PATH`, so pools came back empty with no error.
- **A failed move no longer reports success.** Move scripts printed "copied", recorded the step and exited 0 when rsync or git failed, so scheduled moves counted as good runs. Cutover and timer failures now count too.
- **A saved host check no longer blocks deploys.** Five minutes after a signed check, every deploy to that host was refused with a false clock error.
- **Fewer false "stale" alerts.** Weekday-only, monthly and other uneven schedules are judged by their longest wait.
- **Scans leave running deploys alone,** and failed log fetches no longer trigger more of them.
- **Retiring a host** no longer removes another host's binding through a shared private address, no longer blocks `reset`, and says what stays on the machine.
- **Smaller fixes from the audit's second pass.** A failed scan of an unknown name stops alerting after 7 days, command schedule scripts are private on their host (after the next deploy), failed rotating backups no longer leave folders behind for good, share options are read as whole words, planner volumes sized in bytes can be staged, and Git handles non-UTF-8 paths.
- **Checksum scans reach files with non-UTF-8 names.** The host was asked for the escaped form of the name, which does not exist, so those files never got a checksum.
- **An unreadable job schedule no longer fails the Deploy tab.** One calendar string that passed validation could make `/api/deploy` answer 400.
- **Smaller audit fixes.** Move and change locks no longer fall back to `/tmp`, a schedule's `verify` refuses another schedule's run, schedule windows must be real times, filtered log pages no longer come up short on fetched logs, and the folder cache evicts its oldest entry rather than all of them.
- **No abort at exit.** A background thread writing to stderr as the process ended could kill it with exit 134, on a server shutting down and in test runs that had otherwise passed. Those writes now stop before Python finalizes.
- **`*.tar.gz` finds files.** A search for a two-dot suffix looked in the extension column, which holds only `gz`, and silently found nothing. So did suffixes with a space or over 16 characters.
- **A failed schedule deploy no longer stops the host's reports.** Run now changed the report token before the host had it, so a host it never reached got 401 on every report. A new token now works beside the old one until the host reports with it or the deploy ends well. This also covers an apply that fails after writing the token.
- **A command schedule's script downloads take `plans.edit`**, as reading the command does. `plans.scripts` alone showed what the schedule view masks.
- **Retiring a remote node's host cuts its tunnel.** Its key stayed authorized, and the machine kept its address on this server.
- **Snapshot discovery passes over a capability `find` that cannot run**, instead of reporting no snapshots.
- **Plain HTTP tells ports apart.** Browsers send no `Sec-Fetch-Site` there, so a page on another port of the same host could post with the session cookie.
- **Job reports of up to 16 KiB are accepted.** A long non-ASCII message went over the 4 KiB limit, and the run only arrived with the next scan.
- **`reset` installs `STORAGEFORGE_VAULT_NEW_SECRET`** in a secret file it can write, rather than leaving the old secret for the server to refuse.
- **The remote nodes list** writes `authorized_keys` only when it changed, and probes nodes together, so a hung node can't hold a web worker for seconds per node.
- **Remote node addresses** run out with an error at 65535 instead of wrapping onto node 1's.

### Added
- **One-click system updates.** **Deploy > System updates** installs operating system updates on every host set up for deploys at once, with apt, dnf, yum, zypper or pacman, and shows what is pending and which hosts wait for a reboot. It never reboots, keeps local config files, and skips TrueNAS, XCP-ng and XenServer. See [Deployments](docs/deployments.md#system-updates).
- **Rebuilding onto new disks.** The planner builds a btrfs pool of several devices in one plan, ZFS pools and datasets get back the properties set on them, and [Disaster recovery](docs/disaster-recovery.md#rebuild-onto-new-drives) gives the order to do it in. Found by a drill that wiped two of three hosts.
- **Proxmox, TrueNAS and XCP-ng.** Scans recognise them. Deploys work on Proxmox, and on TrueNAS, XCP-ng and XenServer they are refused before anything changes, because an upgrade replaces those systems. Scans index XCP-ng's storage repositories, skip Proxmox's `/etc/pve`, and warn when Proxmox's paid repository would stop package installs. See [Proxmox, TrueNAS and XCP-ng](docs/appliances.md).
- **Appliances in the lab.** `sf-pve`, `sf-truenas` and `sf-xcp` install unattended from vendor ISOs, by `--pick`, with a new tier 8. `SFLAB_INSTANCE` runs a second lab beside the first.
- **A warning when sudo takes no password.** Deploy access and scan access setup check for passwordless sudo first. When the account has it, the result says the password you typed was not checked, and, when the scan user's own sudo was used, that its scan key has full root on that host. The audit log records it too.
- **ClamAV on hosts.** The **Malware** tab deploys a ClamAV scan to a host on a timer, under its own read-only account with no network. It only reports: detections arrive with the next scan of the host and raise an alert. **Quarantine** checks the file with ClamAV again and moves it to a root-only folder, and **Restore** moves it back; both need `deploy.destructive` and a recent password. This is the first feature that installs software on a host's behalf for scanning, and only on hosts you deploy it to. See [Scanning and search](docs/scanning-and-search.md#clamav).
- **Sites and reset, for moving to a new client.** A database now knows which site it is: the name shows in the web UI, and `restore` refuses another site's backup, because a backup holds that site's SSH keys. `reset --site-name NAME` puts the old site in an archive outside the new site's reach and starts over with a new database, vault and vault secret. It refuses while a server runs, while jobs or deploy access remain on the old machines (`--abandon-deployed` overrides), or while `./keys` still holds keys.
- **Several sites on one machine.** `docker/sf-site` makes and runs one isolated compose stack per client, each with its own database, vault, secrets, certificate, port and network. `sf-site audit` reports keys and machines shared between sites, a key another site uses is refused on import, and sharing raises an alert.
- **Scripts name their site.** Generated move, change, share, task, job, schedule and reinstall scripts carry a `# Site:` line on named sites.
- **Keys added by hand show up.** Scans read `authorized_keys` for root and accounts with UID 1000 and up. `hosts keys` lists them against the vault, `hosts allow-key` accepts one, and generate-only sites raise an alert for the rest.
- **`sf-site overview`** shows every site's hosts, last scan, open alerts and last backup, in the terminal or as a static HTML file.
- **Generate-only vaults.** `vault policy generate-only` refuses imported keys, so a key cannot be reused across clients; sites made by `reset` start this way. `vault list` and the UI show each key's origin.
- **Remote nodes.** Hosts StorageForge can't reach can dial in over a reverse SSH tunnel, then scan and deploy like any other host. The tunnel is off unless you add `docker-compose.remote.yml`, and it opens one port that carries forwarded connections only. See [Remote nodes](docs/remote-nodes.md).
- **Import existing rsnapshot and snapper jobs.** Scans now read rsnapshot configs, whatever they are called, with their cron lines and timers, and snapper configs. **Deploy > Existing snapshot jobs** lists them, and **Look as root** finds what the scan account can't read. An imported job stays on its own config and schedule. StorageForge shows its state from the snapshots and log it leaves, raises alerts, fills the 3-2-1 matrix, and can run it, pause it, change retention and restore from it, using the right tool for the job. **Forget** only stops tracking.
- **Snapshot tool by filesystem.** **New snapshot job** suggests snapper on btrfs and rsnapshot on ext4, xfs and similar, and creates snapper configs. Plan checks refuse rsnapshot on filesystems without hard links, such as vfat and exfat cards.
- **Sync engine for deployed jobs.** All of it is per step and off by default, and needs a redeploy of the plan:
  - **Routes:** a job tries its source over the LAN first, then a ZeroTier, NetBird or Tailscale address, optionally bound to the interface, checks the same host key on all of them, and moves route when one drops during a run. The bandwidth limit applies on mesh routes only.
  - **Pre-transfer dedup:** files already at the destination under another name are hashed (SHA-256 or BLAKE3), checked and made from local data with a reflink, optional hard link or local copy, so they do not cross the network. Same-host jobs reflink from the source. Needs `python3` on both hosts.
  - **Snapshot streams:** mirror steps can use `btrfs send` or `zfs send` with temporary read-only snapshots, removed once the copy's id checks out.
  - **Room check:** data and metadata headroom before a large transfer.
  - **duperemove** on a timer in the run window, with what it freed logged to the job's index.

### Security
- **A planner or dry-run account could run root commands on a host.** `POST /api/deploy/start` with `mode: report, run: true` ran the script for real on `deploy.report` alone, and `remove: true, run: true` skipped the `hosts.command` check. `task_type: "Command"` got past that check when saving a schedule. Now `run` needs `mode: apply` and refuses `remove`, the check reads the type as it will be saved, and pausing an installed schedule that changed since its deploy takes `hosts.command` if it now holds commands.
- **Schedule environment variables are for command schedules only.** On a plan or task they could change a program its script calls (`RSYNC_RSH`, `TAR_OPTIONS`). Existing rows keep theirs on record, and no longer deploy them.
- **State-changing requests must come from this origin.** A page on another port of the same host counts as the same site, so `SameSite=Strict` let it post forms here.

### Changed
- **Files map speed.** Opening a folder in the Graph view takes about 50 ms instead of up to 2.7 s on a 5.5M-file index, because listings and folder comparison share one folder index kept until the next scan. Changing the size, host or System files filter no longer re-reads every file to redraw the copy lines, and selecting a card with everything already open no longer redraws the map. A folder still being read shows a Loading card.
- **Faster views on large indexes.** Opening Topology no longer scans every file record to detect backups (1.9 s to 6 ms per design on 5.5M files). The Files map's folder comparison is ready at startup and after each scan. Topology renders once for a page load's background answers, and the Structure layout is only worked out when shown, with a grid in place of comparing all node pairs.
- **Every deployed job now takes `.storage.lock` on its destination volume.** Copies and mirrors share it; rsnapshot and git take it alone and wait up to an hour, then fail with exit 75 and raise the usual job alert. `storageforge-job with-lock <folder> -- <command>` puts your own timers under the same lock. This applies once a plan is redeployed.
- Copy, move and mirror runs print JSON state events and post them to `POST /api/jobs/state`. They use `rsync --no-inc-recursive` so the percentage is real, which takes more memory on very large trees.

### Security
- **Backup copies on another host are encrypted**, with a key from the vault secret. They hold password hashes and alert tokens. `restore` takes them as they are. Without the vault secret, no copy is made.
- Invite and reset links die when their role comes to allow more. A reset link also dies when its account is replaced or changes, and a new link cancels the last one. **Open links made before this update stop working: make them again.**
- `backups.manage` and `settings.manage` are marked high risk. A retired host can't still have schedules. A job's `.git` link can't point outside its source.
- A Git repository can no longer run code as the scan account through its own config. Git runs with those settings off, and `git status` runs only in repositories the scan account owns; others show **Not checked**. Git routes take only repositories a scan found.
- **Git sync needs deploy access.** Sync is now a signed run, as the repository's owner, with hooks off and a fresh password for every action. Git status, history and commit are POST only, rate limited and audited.
- The log fetch after a failed task refuses odd task names and no longer copies all of `/var/log/messages`.
- A task's timer no longer rewrites the deploy runner. **Redeploy existing tasks**: copies already installed keep doing it until then.
- Raw commands need a new high-risk permission, `hosts.command`, to write or deploy: command schedules, a task's **Run command** blocks and **command succeeds** conditions, and a move step's pre and post commands. Only `admin` has it by default, so operators who use them need a custom role. A move's `docker compose -p <name> stop` and `start` hooks stay open to `plans.edit`, and anyone can take commands off a host. Env variables that change what runs (`PATH`, `LD_*`, `BASH_ENV` and others) are refused.
- Downloading a schedule's install script no longer rotates its token: the file carries none, and that host reports through scans. A failed deploy no longer ends the old token. Reports never go to an address taken from a request's Host header: set a report URL, or runs arrive with the next scan.
- Bad or slow verify patterns can no longer lose a report or hold a web thread, and repeated report nonces are ignored.
- **Schedules no longer run on the StorageForge server.** The **Run local** button and `{"local": true}` are gone: they let an operator run commands where the vault secret lives. Use `storageforge-index schedule run` from a shell on the server.
- Creating, changing, pausing, running or deleting a schedule, and rotating its token, now asks for a fresh password. Running one also applies the deploy preflight.
- Schedules can no longer run destructive steps, which bypassed `deploy.destructive`. A schedule deployed with them keeps its old script until redeployed: it shows as changed on the Deploy tab.
- A schedule installed on a host can't be deleted until it is uninstalled. Ones already deleted get an **Uninstall** button on the Deploy tab.
- Git routes no longer run on the server when given `host=localhost`. Loopback names need a key bound to them, like any host.
- Accounts that can't edit schedules no longer see their commands or env values. Run output needs `logs.view`. Alert addresses in `/api/deploy` need `settings.manage`.
- `viewer` can no longer download a schedule's install script (which also minted a report token), its cron line or a host configuration bundle. These now need `plans.scripts`.

### Added
- **btrfs health beyond df.** Scans now read chunk allocation, every profile in use and missing devices, without new rights. Alerts and findings cover almost no unallocated space, running out of metadata (writes fail with "no space" while df shows room), a missing device, a filesystem gone read-only, mixed profiles and raid5/6 metadata. The report has a btrfs table.
- **btrfs upkeep tasks:** reclaim free space (filtered balance), replace a device, remove a device, grow to fill a device, restore a subvolume from a snapshot (the current one is kept beside it), and turn on quotas. A **btrfs reclaim space** storage block and a **Monthly btrfs tidy** template.
- **Rerun the read-only scan access setup** for the rest: errors per device and kind, newest snapshot date, space only the snapshots hold (with quotas on) and compression savings (with `compsize` installed, measured weekly).

### Fixed
- **A rebuild no longer gets an empty script.** A scan of the blank new install became the newest configuration, so the reinstall script had nothing to do and said "no conflicts". It now uses the last version from before the reinstall and says so.
- **A deploy no longer locks you out of a client whose NFS server is down.** `systemctl daemon-reload` blocks on such a mount and every new SSH login waits behind it. Share, job, move, task, change and reinstall scripts now check first and stop with a conflict.
- **Scans finish while an NFS server is down.** `findmnt` and `df` called statfs on the dead mount and never returned, so the scan job stayed running. They are bounded now, a walk blocked on such a mount is stopped after 5 minutes without removing anything from the index, and automounted NFS shares let go after 10 idle minutes.
- **Survivors reconnect to a rebuilt host.** Jobs check the key StorageForge pinned, so deploying again after a rekey is enough, and a share deploy lets go of a stale mount.
- **Restores keep sparse files sparse.** A restored 1 GiB sparse file took 1 GiB on btrfs.
- **Change plan checks count what earlier tasks make:** partitions, added btrfs devices and new labels no longer read as missing.
- **A design with jobs deployed can be saved.** The job names filled in on load held `->`, which the save refused.
- **Scans no longer fail with "FOREIGN KEY constraint failed"** when a host mounts from, or backs up to, a host that has no graph yet, as when a new install scans several hosts at once. The scan's data was saved, but the job showed as failed and the host's graph was not updated. Scan the host again to update it.
- Scanning a host by name while its first scan, queued by address, is still running now joins that scan. It used to add a failed job saying the host was already being scanned.
- **Converting a btrfs profile no longer risks a read-only filesystem.** With too little unallocated space, the script reclaims half-empty chunks first, and stops without converting if that frees too little. The plan check warns, and the Ansible step refuses.
- Disk alerts on btrfs RAID match `df`: used against used plus available, not against the raw total.
- An SMB share under a folder with no SELinux label works: the deploy labels the folders above it. **Redeploy existing shares.**
- SMB client deploys and reinstall scripts install the kernel modules a cloud image leaves out (`cifs`, `nls_utf8`).
- `zfs set` works on Ubuntu 22.04's ZFS, which rejected `--`.
- A job's verify no longer counts ssh warnings as differing files, and a failed rsync is reported as such. **Redeploy existing jobs.**
- Podman's overlay folder is skipped as image layers, so it no longer makes a scan partial.
- A scan records mergerfs's branch folders as its source, not `1:2`.
- **Files in nested btrfs subvolumes are now indexed.** A subvolume inside a scanned mount, without a mount of its own, was silently left out, along with all its files. The next scan adds them. Read-only snapshots stay out.
- Single-device btrfs filesystems now get the same scrub and device error checks as pools. Their results were dropped, so expect new scrub warnings on hosts with the collector.
- File map: faster, kept until the index or ignore list changes. Ignore lists are no longer capped at 4 KiB, and saving one no longer holds the request while graphs rebuild.
- Schedule runs are pruned to the newest 200 per schedule.
- **The backup copy to another host** now goes through the signed runner. As written it could not get past the deploy key's forced command.

### Changed
- **Schedules run from a bash script, without Python.** A systemd timer fires it, or cron where there is no systemd. With no flags the install script only reports. **Redeploy every schedule:** the old Python runner stays in charge on a host until then, and redeploying removes it.
- **A schedule's `verified` now means a scan newer than the run agrees.** Until that scan a run is `reported`. A required path that's missing now fails the check instead of warning. Output no longer goes in the world-readable `runs.jsonl`, so runs picked up by a scan have none.
- **Schedules:** pausing and resuming now update the host, and alerts keep watching until it has. Reports up to 512 KiB are accepted (they were refused above 4 KiB). Drift and dry-run checks notice a change to the plan a schedule runs, so **every deployed schedule shows as changed once after this update: redeploy it.** `nice`, `ionice`, jitter, timezone, window and `user` now take effect; `catchup` and the `scan` task type are gone. A plan or task made for another host can't be scheduled on this one. Cron now wakes the runner every minute and the runner decides.

### Added
- **Invite links and permissions:** admins create single-use, expiring links that let someone make their own account with a role chosen in advance, and password reset links replace email. Roles now bundle about 30 permissions in groups. `viewer`, `operator` and `admin` stay as they were and cannot be edited, there is a new built-in `search` role that can only search files, and admins can create custom roles. Nobody can grant more than they hold.
- **Graph view, Files map:** Graph now opens on an expandable node map of every host's files, from the index. Tick cards and copy them to any folder on any host by clicking it or dragging onto it, or move, sync, snapshot, rename, trash or change owner. Copies and syncs go in the Moves plan and draw as blue lines, and copy steps can now take single files. Lines show what is already joined: copies, symlinks, bind mounts, shares, jobs and backups. Each line lands on the deepest open card, so it follows down as you expand, and cards show how much under them is duplicated. **Duplicates** shows only the folders with copies, where you can trash the extras: the last copy of anything cannot be staged. The force-directed graph is still there under **Structure**.
- **Ignored paths:** system folders, packaged apps in `/opt`, rsnapshot rotations (`daily.0`), container layers and StorageForge's own trash stay out of the file map, and dangling symlinks in those places no longer turn a host red. Add your own with **Ignored…** or **Ignore this link** from the topology or graph, or start a line with `!` to show something again.
- **Unified Task Scheduler & Client Runner:** A scheduler that can schedule any task StorageForge can do (Storage task block pipelines, Change plans, Move/Sync plans, Host inventory scans, and Commands). Tasks can be scheduled with standard 5-field cron expressions or aliases (`@daily`, `@hourly`, etc.), with rich configuration options (execution windows, concurrency policies `skip`/`queue`/`replace`, timeouts, retries with backoff, nice/ionice priorities, environment variables, and alerting). Execution can run via native cron files (`/etc/cron.d/`) or a lightweight client daemon/runner (`storageforge-scheduler`). Client execution reports back via bearer tokens to `/api/scheduler/report`, where the server conducts comprehensive post-execution verification (authenticity, exit code, required/forbidden output regex patterns, mount integrity, free space thresholds, and filesystem path existence against the StorageForge index). Management is provided via REST APIs (`/api/scheduler/*`) and CLI (`storageforge-index schedule`).
- **Disk health:** rerun the read-only scan access setup to install an hourly collector for SMART and btrfs errors. The scan account gets no new rights; scans read its report. Failing disks, pool errors and overdue scrubs raise alerts and show in the topology and report.
- **Backups found by scans:** restic, borg and rsnapshot folders, ZFS and btrfs snapshots and snapper configs now show in the 3-2-1 matrix, marked as detected.
- **Capacity history:** each scan records how full every mount is. The Cleanup tab shows 30-day trends and "full in about N days", which can raise an alert.
- **File changes and identical files in the Cleanup tab,** and an alert when one scan finds many files gone.
- **Report sections** for deployed jobs with their last runs, storage tasks, open alerts and drift, capacity trend, shares, unreadable folders, git repositories and containers.
- **Backups in the web UI**, with an optional copy of each backup to another host over SSH. A failed copy raises an alert.
- **Roles and accounts in the web UI:** change your own password, and admins can add, disable and remove accounts. `viewer` browses and searches, `operator` also plans, scans and deploys, `admin` also handles keys, accounts and settings. Existing accounts stay admins.
- **Retire a host** from its menu or with `hosts remove`, and remove keys and bindings from the Keys tab.
- **Per-host scan schedules:** a host can have its own interval and quiet hours, from its menu in the topology.
- **Designs stage pool tasks:** a new ZFS pool, ZFS datasets, a new LVM volume group and its volumes now become change-plan tasks instead of "by hand" notes.
- **3-2-1 matrix from what is deployed:** mirror and rsnapshot jobs and scheduled storage tasks fill the sync, snapshot and backup cells with their last good run. Typed values stay where nothing covers a dataset, and hosts can be marked offsite.
- **Move progress:** a move script run by hand now shows "copied" and "cut over" on its steps after the next scan.
- **Moves:** Duplicate and Export JSON. **Git:** select repositories and archive them together, and hide or show paths per host.
- **Storage tasks on the CLI:** `tasks list`, `check`, `script` and `import`.
- Storage task checks warn when a running container uses a block's source or destination.
- Shared test cases keep the planner's and the report's capacity numbers the same.
- **Shares manager in the topology:** a Shares button lists every share on the hosts in view, with access, client mounts, state and check problems, and opens designed shares to edit or remove. Editing and removing now find a share by its identity instead of its list position, which could change after a rescan and hit the wrong share. Wizard edits keep SMB settings and per-client mount options, a deployed share can be removed from the design, and saving a second copy of a share is refused.
- **Deploy run tracking and scan confirmation:** Scans verify completion records of deploy scripts (`/var/lib/storageforge/run/runs.jsonl`) and storage tasks (`/var/lib/storageforge/tasks/`) by matching run nonces, confirming actual host outcomes. If a run or task failed, StorageForge automatically runs a signed read-only log fetch over deploy access once per problem to capture runner and journal logs.
- **Deploy cancel and retry:** Running deploys can be stopped in the UI (with a Force stop option to terminate running SSH processes), and failed or interrupted deploys offer a Retry failed hosts button.
- **Stale dry run protection:** Applying a plan passes the dry run's group ID to ensure the plan was not modified after review.
- **Host configuration history and reinstall scripts:** each scan saves a host's fstab, crypttab, mdadm, NFS and Samba files, mounts, accounts and cross-mount symlinks when they change, with passwords removed. The new Rebuild tab and `storageforge-index config` show versions and what changed, and export a script that mounts every drive and subvolume on a fresh install, plus a `.tar.gz` to keep elsewhere. `STORAGEFORGE_CONFIG_EXPORT_DIR` writes that bundle every night.
- **Parallel scans:** up to `STORAGEFORGE_SCAN_WORKERS` hosts (default 4) scan at once, so a large or hung host no longer holds up the rest.
- **KVM lab:** `examples/lab` builds seven disposable VMs, picked at random from 14 configs across distros and filesystems, with a local control panel to create, reset and destroy them, StorageForge running on one VM, a demo that fills it with scans, shares, jobs and an alert, and test tiers including btrfs in depth, with a report per distro ([KVM lab](docs/kvm-lab.md)).
- **ZFS change tasks:** create a pool, create a dataset with properties, snapshot, scrub.
- **LVM change tasks:** create a volume group, add a device to one, create, grow and snapshot a logical volume.
- **Send over the network:** `btrfs-send` and `zfs-send` change tasks, and `btrfs_send` and `zfs_send` storage task blocks that send only the changes since the last shared snapshot, with "btrfs replication" and "ZFS replication" templates.
- **Alerts** for failed scans, missing mounts, nearly full filesystems, unhealthy pools and device errors, failed or old backups, and an expiring HTTPS certificate.
- CI for Forgejo Actions, ruff settings, `.env.example`, and guides for disaster recovery, troubleshooting and target hosts.

### Fixed
- **Container vulnerabilities:** the runtime image moved from Debian 12 to Debian 13 and installs Debian's security updates at build time. It no longer carries apt, perl, bash, tar, gzip, util-linux, PAM, Kerberos, ncurses or the sqlite3 shell, none of which it uses; `docker compose exec storageforge sh` still works. The ssh client is built from OpenSSH 10.6p1 because Debian 13's 10.0 has unpatched holes, so DSA host keys no longer work, as with any OpenSSH from 10.0. The proxy moved from nginx 1.27 to 1.30 pinned by digest, with its Alpine packages updated and curl removed. Grype on the runtime image: 5 critical and 84 high before, 0 critical and 13 high after.
- **Smoother Deploy tab:** Deploy panel polling updates output in-place preserving card expansion and scroll position; active deploys resume polling across tab reloads; the reporting settings form is kept across reloads; and deploy access removal uses a secure inline form instead of a plain-text prompt.
- An apply from the web UI rescans the hosts it ran on, so the other tabs show the result instead of waiting up to 6 hours for the next scan.
- A change plan that finished applying is no longer staged and moves to "Already ran" in the picker: deploy tracking ID matching is type-coerced, local drafts preserve clean state across reloads rather than forcing dirty state, and plans whose changes already exist on hosts offer one-click unstaging and mark as ran. Editing a plan makes it a plan to run again; one that skipped drive tasks stays unfinished and says so.
- An apply that left `missing` steps shows as `incomplete` instead of a green `ok`, for every kind of deploy, and a later scan keeps it that way.
- Share, change and move scripts run by hand end with "N step(s) not finished" instead of `done` when an apply left `missing` steps.
- A shares apply that left steps on the server is no longer marked as deployed.
- Move plans deployed as jobs are grouped under "Deployed as jobs" in the picker, until they are edited.
- Open tabs reload once the rescan after an apply ends.
- A refused deploy no longer fails with an internal error when it writes to the audit log.
- The git survey finds repositories when the host runs it with `dash`, instead of reporting none.
- `jobs.py` used f-string syntax that only Python 3.12 and later accept, though `pyproject.toml` promises 3.10.
- Two vault key derivations at once could hang, leaving deploys stuck and later scans failing with "Not enough memory to derive key" until a restart. They now run one at a time.
- A restart now marks unfinished deploy runs as failed, as it already did for scan jobs, instead of leaving them shown as running.
- `scan --host 127.0.0.1 --port 2222` scanned this machine instead of the SSH server on that port.
- Piping CLI output into a command that stops reading, such as `head`, no longer shows a traceback.
- Operations described a web backup button that does not exist.
