# Changelog

Newest first. Versions are not tagged yet: everything so far is 0.2.0.

## Unreleased

### Added
- **ZFS change tasks:** create a pool, create a dataset with properties, snapshot, scrub.
- **LVM change tasks:** create a volume group, add a device to one, create, grow and snapshot a logical volume.
- **Send over the network:** `btrfs-send` and `zfs-send` change tasks, and `btrfs_send` and `zfs_send` storage task blocks that send only the changes since the last shared snapshot, with "btrfs replication" and "ZFS replication" templates.
- **Alerts** for failed scans, missing mounts, nearly full filesystems, unhealthy pools and device errors, failed or old backups, and an expiring HTTPS certificate.
- CI for Forgejo Actions, ruff settings, `.env.example`, and guides for disaster recovery, troubleshooting and target hosts.

### Fixed
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
