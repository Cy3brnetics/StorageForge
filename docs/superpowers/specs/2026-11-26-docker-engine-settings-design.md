# Docker engine settings: seen and changed from the Workloads page

Date: 2026-11-26. Asked for by the owner: "docker config setting like where containers are stored should be visible/configurable in
the webui". Approved the same day with the owner's answer on moving data: "stop docker, rsync files, then edit and restart".

## Intent

Where Docker keeps its containers and images, and the few daemon settings that matter for storage and operation, should be visible per
host and changeable through a change plan, like everything else.

## What exists

The Docker scan (`runtimes/docker.py`) already asks the engine for its data directory (`DockerRootDir`, or Podman's `Store.GraphRoot`)
and stores it as `root_dir`. Nothing shows it, nothing reads `/etc/docker/daemon.json`, and the only step that writes daemon.json is
`runtime-install`, which writes log limits once when the file is absent (`steps_runtime.py`).

## Goals

- **Read**, in the existing engine probe: from `docker info`, the storage driver, logging driver, cgroup driver, registry mirrors,
  live-restore, and the data directory (already read); and `/etc/docker/daemon.json` when readable (capped at 64 KiB), keeping only
  the keys this feature knows (`data-root`, `storage-driver`, `log-driver`, `log-opts`, `registry-mirrors`, `live-restore`,
  `default-address-pools`) so nothing else in the file reaches the database. For Podman: `graphRoot` and the driver from
  `podman info` (read-only).
- **Show**, on the Workloads page: the panel of a `docker` or `podman` runtime node lists these settings, each marked "set in
  daemon.json" or "default", and how old the reading is.
- **Change**, with a new plan step `docker-daemon` (group Workloads), offered from that panel as **Edit engine settings…** through the
  same review-and-save flow as the other actions. Fields: `data_root` (path), `log_driver` (choice: json-file, local, journald, syslog,
  none), `log_max_size` (e.g. 10m), `log_max_file` (number), `live_restore` (choice: unchanged, on, off), `registry_mirrors` (URLs),
  `storage_driver` (choice: unchanged, overlay2, btrfs, zfs, fuse-overlayfs), `move_data` (bool, default on when data_root changes).
  Empty means "leave as it is".
- **The step's script:** read the current daemon.json (or `{}`), merge only the given keys (with `python3 -c` or `jq` if present,
  else refuse with a conflict rather than hand-edit JSON), validate the result with `dockerd --validate --config-file NEW`, back up the
  old file beside it (`daemon.json.storageforge-STAMP`), write it, `systemctl restart docker`, and check `docker info` reports the new
  values. Report mode prints the diff of daemon.json and what would happen.
- **Moving the data directory** (owner's answer): when `data_root` changes and `move_data` is on: check the target has room for the
  current data (`du` of the old root against `df` of the target) and is empty or absent; stop docker (`docker.socket` and `docker`),
  `rsync -aHAX --numeric-ids --info=progress2 OLD/ NEW/`, write the new daemon.json, start docker, confirm `docker info` shows the new
  root and the containers that were running are running again. The old folder is kept, and the report says how to remove it later. If
  rsync fails, daemon.json is not changed and docker is started on the old root.
- **Checks** (from the index): the target is not inside the old root or vice versa; a warning when the target is on the system disk
  or a network filesystem; a warning that a restart stops containers without live-restore (listing how many are running); a crit for
  Podman hosts (not writable in this version) and for hosts where Docker is managed by something else (Docker Desktop, snap).

## Non-goals

- Editing Podman's `storage.conf` or containers.conf (read-only this round).
- Every daemon.json key: only the list above; others are left as they are and never shown.
- Rootless Docker.

## Approaches

- *A plan step that merges keys into daemon.json (picked)*: one place to change it, reviewable, keeps the rest of the file.
- *Writing the whole daemon.json from a form*: simpler, but would drop keys the operator set by hand.
- *A systemd drop-in with dockerd flags*: conflicts with daemon.json when both set a key (dockerd refuses to start), so no.

## Left to the builder

Where the new read is stored (a column beside `root_dir` with a migration for SQLite and PostgreSQL, or inside an existing JSON
column), the exact panel layout, and the Ansible export (same rules as the other steps: every helper defined).
