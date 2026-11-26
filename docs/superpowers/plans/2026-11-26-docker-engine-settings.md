# Docker Engine Settings Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Show each host's Docker (and Podman) engine settings on the Workloads page, and change Docker's through a `docker-daemon`
plan step that can move the data directory (stop, rsync, edit, restart).

**Architecture:** Extend the engine probe in `runtimes/docker.py` with a settings section, store it beside `root_dir`, expose it in
`GET /api/workloads` hosts, show it in the runtime panel of `static/workloads.js`, and add `steps_dockerd.py` with the step and its
script; the panel's button goes through `WL.onAction` (Task 7's review-and-save).

**Tech Stack:** Python 3.10+, generated Bash, vanilla JS, unittest, Playwright.

**Spec:** `docs/superpowers/specs/2026-11-26-docker-engine-settings-design.md`

## Global Constraints

- Only the keys `data-root`, `storage-driver`, `log-driver`, `log-opts`, `registry-mirrors`, `live-restore`, `default-address-pools` are read from daemon.json into the database; anything else in the file is never stored or shown.
- The step merges only the keys given into daemon.json, keeping every other key; it never hand-edits JSON in bash (python3 or jq, else a conflict).
- Validate with `dockerd --validate --config-file NEW` before writing; back up the old file as `daemon.json.storageforge-STAMP`.
- Moving data: check room and an empty/absent target; stop `docker.socket` and `docker`; `rsync -aHAX --numeric-ids OLD/ NEW/`; only then write daemon.json; start docker; confirm `docker info` shows the new root. rsync failure: daemon.json unchanged, docker started on the old root. The old folder is kept.
- Generated bash rules as in the Workloads plan (quoted words from changes.CHECKS, report mode changes nothing, each change behind `act`, the Ansible export defines every helper it calls, `not_on_pve`-style silent no-ops are a defect).
- UI: DOM APIs only, tokens.css colours, keyboard reachable.

## Review Focus

- A daemon.json that is not valid JSON on the host: the step refuses with a conflict naming the file, changes nothing.
- A host whose daemon.json is unreadable to the scan user: the panel says "not read", not "default".
- Docker stopped mid-move by a failed rsync: docker comes back on the old root and running containers with a restart policy come back.
- A `data_root` that is the current root (no change): no stop, no rsync, no restart.
- Podman host: settings shown, no Edit button, and the step refuses with a crit.

---

### Task 9: Read and show engine settings

**Files:**
- Modify: `storageforge_index/runtimes/docker.py` (probe after `@@root`; `parse_engine`; the store and `listing()` row ~382), a migration adding `settings_json` (TEXT, nullable) to the engine table in both SQLite and PostgreSQL schemas (follow the newest existing migration)
- Modify: `storageforge_index/workloads.py` (`hosts[]` gains `engine_settings`)
- Modify: `storageforge_index/static/workloads.js` (runtime panel for docker/podman)
- Test: `tests/test_docker_settings.py`

**Interfaces:**
- Produces: probe section `@@settings` holding one line of `docker info --format '{{json .}}'` reduced in the probe to `{Driver, LoggingDriver, CgroupDriver, LiveRestoreEnabled, RegistryConfig.Mirrors}` (use `--format` with those fields only, not the full JSON), then `@@daemonjson` with the file's text when readable (`sudo -n cat` if the engine is reached through sudo; skip above 64 KiB; `@@daemonjson-unreadable` marker otherwise); `parse_engine` returns `settings: {'storage_driver', 'log_driver', 'cgroup_driver', 'live_restore', 'registry_mirrors', 'daemon_json': {only the allowed keys} | None, 'daemon_json_read': bool}`; `hosts[].engine_settings` = that dict plus `root_dir`.

- [ ] **Step 1: Write failing tests:** `parse_engine` on captured probe text gives the settings; a daemon.json holding `"hosts": [...]`, `"tlskey": "/x"` and `"data-root": "/srv/docker"` keeps only `data-root`; invalid JSON in daemon.json → `daemon_json: None`, `daemon_json_read: True` and a `daemon_json_error` string; the unreadable marker → `daemon_json_read: False`; Podman text gives `storage_driver` and graph root; listing hosts carry `engine_settings` after storing a scan through the existing store path; the migration applies on SQLite (and PostgreSQL where the suite runs it).
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement**, and in workloads.js the runtime panel for docker/podman: a definition list of root dir, storage driver, log driver and options, live-restore, registry mirrors, cgroup driver, each value marked "set in daemon.json" when the key is there, else "default"; "daemon.json not read" when `daemon_json_read` is false; the reading's age.
- [ ] **Step 4: Run** focused tests, `node --check`, ruff, light block → PASS.
- [ ] **Step 5: Commit** `feat(docker): read the engine's settings and show them on the Workloads page`.

### Task 10: The `docker-daemon` step and Edit engine settings

**Files:**
- Create: `storageforge_index/steps_dockerd.py` (registered from `changes.py` like the others)
- Modify: `storageforge_index/static/workloads.js` (button on a docker runtime panel → `WL.onAction({type: 'docker-daemon', host, params: {}})`; the review form asks for the fields)
- Test: `tests/test_steps_dockerd.py`; extend `tests/test_browser_workloads.py` with one walk (open a docker runtime, Edit engine settings…, set log max size, Save → a plan with one `docker-daemon` task)

**Interfaces:**
- Consumes: `hosts[].engine_settings` (Task 9) in the check.
- Produces: step `docker-daemon`, fields `data_root` path, `move_data` bool default true, `log_driver` choice `['', 'json-file', 'local', 'journald', 'syslog', 'none']`, `log_max_size` text matching `^[0-9]+[kmg]$`, `log_max_file` number 1–100, `live_restore` choice `['', 'on', 'off']`, `registry_mirrors` text (space-separated https URLs), `storage_driver` choice `['', 'overlay2', 'btrfs', 'zfs', 'fuse-overlayfs']`; at least one set (else normalize ValueError). Bash `t_docker_daemon`.

- [ ] **Step 1: Write failing tests:** normalize refuses all-empty and a bad size; check: Podman host → crit; data_root inside the current root (or the reverse) → crit; target on the root filesystem (from the index's mounts) → warn; running containers without live-restore → warn naming the count; data_root equal to the current root → note "no move needed". Script (`bash -n`; report run with stubs for `docker`, `dockerd`, `systemctl`, `rsync`, `python3` real, temp dirs via `SF_DOCKER_ETC`): report prints the merged daemon.json diff and changes nothing; apply (through the Ansible export, as the Proxmox tests do) merges keys keeping an unknown key `"hosts"`, writes the backup, calls `dockerd --validate` before writing and `systemctl restart docker`; invalid JSON on disk → conflict, file unchanged; with a move: the stub log order is `systemctl stop docker.socket docker`, `rsync ... OLD/ NEW/`, write, `systemctl start docker`; a failing rsync stub → daemon.json unchanged and `systemctl start docker` still called; unchanged data_root → no stop and no rsync.
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement** per the Global Constraints; room check `du -sx OLD` vs `df --output=avail` of the target's nearest existing parent; refuse a non-empty target.
- [ ] **Step 4: Run** focused tests, the browser class once (`tests/run.py heavy -k BrowserWorkloads -j 1`), ruff, light and medium blocks → PASS.
- [ ] **Step 5: Commit** `feat(docker): change the engine's settings and move its data with a docker-daemon plan step`; add a CHANGELOG line and a paragraph to `docs/workloads-page.md`.
