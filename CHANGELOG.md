# Changelog

Newest first. Versions are not tagged yet: everything so far is 0.2.0.

## Unreleased

### Added
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
- **Deploy run tracking and scan confirmation:** Scans verify completion records of deploy scripts (`/var/lib/storageforge/run/runs.jsonl`) and storage tasks (`/var/lib/storageforge/tasks/`) by matching run nonces, confirming actual host outcomes. If a run or task failed, StorageForge automatically runs a signed read-only log fetch over deploy access once per problem to capture runner and journal logs.
- **Deploy cancel and retry:** Running deploys can be stopped in the UI (with a Force stop option to terminate running SSH processes), and failed or interrupted deploys offer a Retry failed hosts button.
- **Stale dry run protection:** Applying a plan passes the dry run's group ID to ensure the plan was not modified after review.
- **Host configuration history and reinstall scripts:** each scan saves a host's fstab, crypttab, mdadm, NFS and Samba files, mounts, accounts and cross-mount symlinks when they change, with passwords removed. The new Rebuild tab and `storageforge-index config` show versions and what changed, and export a script that mounts every drive and subvolume on a fresh install, plus a `.tar.gz` to keep elsewhere.
- **Parallel scans:** up to `STORAGEFORGE_SCAN_WORKERS` hosts (default 4) scan at once, so a large or hung host no longer holds up the rest.
- **KVM lab:** `examples/lab` builds seven disposable VMs across distros, with a local control panel to create, reset and destroy them.
- **ZFS change tasks:** create a pool, create a dataset with properties, snapshot, scrub.
- **LVM change tasks:** create a volume group, add a device to one, create, grow and snapshot a logical volume.
- **Send over the network:** `btrfs-send` and `zfs-send` change tasks, and `btrfs_send` and `zfs_send` storage task blocks that send only the changes since the last shared snapshot, with "btrfs replication" and "ZFS replication" templates.
- **Alerts** for failed scans, missing mounts, nearly full filesystems, unhealthy pools and device errors, failed or old backups, and an expiring HTTPS certificate.
- CI for Forgejo Actions, ruff settings, `.env.example`, and guides for disaster recovery, troubleshooting and target hosts.

### Fixed
- **Smoother Deploy tab:** Deploy panel polling updates output in-place preserving card expansion and scroll position; active deploys resume polling across tab reloads; the reporting settings form is kept across reloads; and deploy access removal uses a secure inline form instead of a plain-text prompt.
- An apply from the web UI rescans the hosts it ran on, so the other tabs show the result instead of waiting up to 6 hours for the next scan.
- A change plan that finished applying is no longer staged and moves to "Already ran" in the picker. Editing it makes it a plan to run again; one that skipped drive tasks stays unfinished and says so.
- An apply that left `missing` steps shows as `incomplete` instead of a green `ok`, for every kind of deploy.
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
