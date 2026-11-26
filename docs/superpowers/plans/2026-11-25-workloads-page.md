# Workloads Page Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A standalone `/workloads` page drawing every container and VM as a mind map (fleet → host → runtime → workload), with a
side panel of actions and a create wizard, every action ending in a change plan; plus Proxmox VE create and manage steps (`qm`/`pct`
over SSH) and the guards that keep generic VM and LXC steps off Proxmox nodes.

**Architecture:** Backend: a Proxmox node read in the infrastructure scan, an `is_proxmox` helper, refusals in existing steps, a new
`steps_proxmox.py` with four plan steps registered through `changes.register`. Frontend: `workloads.html` + `workloads.js` (tree on the
shared `canvas.js`), `workloadwiz.js` (wizard built from `GET /api/changes/types`), field rendering lifted out of `openTask` into
`stepfields.js` so both use one copy.

**Tech Stack:** Python 3.10+ (Flask), generated Bash run by the signed runner, vanilla JS (DOM APIs only, no framework), unittest,
Playwright for the browser test.

**Spec:** `docs/superpowers/specs/2026-11-25-workloads-page-design.md`

All paths below are under `storageforge-indexer/` unless they start with `docs/` or are repo-root files (`CHANGELOG.md`, `roadmap.md`).

## Global Constraints

- Nothing on the page changes a host directly: every action is one plan step, checked with `POST /api/changes/check`, saved with `POST /api/changes`.
- Generic `vm-create`, `vm-iso`, `vm`, `vm-define`, `lxc`, `incus` give a crit on a Proxmox VE host, and their scripts refuse at run time when `/etc/pve` exists.
- No secret on a command line, in a plan, a script or a log: the `pve-ct` root password is a vault secret name (field kind `secret`), delivered on stdin like `rclone-mount`'s.
- Generated bash: values only as shlex-quoted words that passed `changes.CHECKS`; `set -euo pipefail` is in force; report mode (`APPLY=0`) changes nothing and says what an apply would do (`missing "..."`); `act "..." || return 0` before each change.
- Page and route: `/workloads` via `app_page('workloads.html')` (login and `hosts.view` handled there); the page needs `workloads.view` and says so when it is missing.
- UI: DOM APIs only (`el()`, `text()`, no `innerHTML` with data), colours from `tokens.css` variables, works in light and dark; every node and action reachable by keyboard; tree has `role="tree"` / `role="treeitem"` with `aria-expanded`.
- User-facing text: plain full sentences, specific, no jargon, like the existing step help.
- Tests: run from `storageforge-indexer/tests` with `PYTHONPATH=..`; the suite at most `-j 6`, one suite at a time; no docker, no real network, never `secrets/`, `keys/` or `data/`.
- Commits end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Review Focus

- A Proxmox node whose scan predates the new read (no `proxmox_node`): pickers fall back to free text, checks say "not read yet, the script checks when it runs", nothing crashes. → Task 1 and Task 4 tests.
- The same guest seen twice on a Proxmox node (`runtime: lxc` named by VMID and `runtime: proxmox`): the page shows it once, under proxmox. → Task 6 test (`dedupe`).
- A VMID that exists by the time the script runs (made in the Proxmox UI after the scan): `pve-vm`/`pve-ct` refuse with a conflict, never overwrite. → Task 4 and 5 script tests with a stubbed `qm`/`pct` reporting the VMID present.
- A workload name with spaces or shell metacharacters reaching an action: refused by the field check before any script is made. → Task 3 test.
- A fleet with no workload reading for a host: the host node says "not read" and links to its scan, never "nothing runs here". → Task 6 test.

---

### Task 1: Proxmox detection and the node read

**Files:**
- Modify: `storageforge_index/inframeasure.py` (the `sec proxmox` block near line 85; the section list near line 23; the parse at ~414)
- Modify: `storageforge_index/wlmanaged.py:78` (use the new helper's rule)
- Create: `storageforge_index/pvenode.py`
- Modify: `storageforge_index/workloads.py` (`listing()`, the `hosts.append` line)
- Test: `tests/test_pvenode.py`

**Interfaces:**
- Produces: `pvenode.is_proxmox(reading: dict | None) -> bool` (true when `'pve' in wl_units.markers` or `qm` or `pct` in `tools`, or `platform` starts with `proxmox`); `pvenode.is_proxmox_host(conn, host: str) -> bool` (reads `inframeasure.reading`); `pvenode.parse_node(lines: list[str]) -> dict` returning `{'storages': [{'name', 'type', 'active': bool, 'content': [str], 'total_kib': int|None, 'used_kib': int|None}], 'isos': [{'storage', 'volid', 'size'}], 'templates': [{'storage', 'volid', 'size'}]}`; reading key `proxmox_node`; listing `hosts[]` gains `'proxmox': bool` and `'runtimes': [str]` (runtimes the host can run, from `tools`: docker, podman, libvirt (virsh), incus, lxc (lxc-ls), proxmox).

- [ ] **Step 1: Write the failing tests** in `tests/test_pvenode.py`: `test_parse_node_reads_storages_isos_and_templates` with captured lines in the new section's format (below) asserting two storages (`local` dir active content `['iso','vztmpl','backup']`, `local-lvm` lvmthin content `['images','rootdir']`), one iso `local:iso/debian-13.iso`, one template `local:vztmpl/debian-13-standard_13.0-1_amd64.tar.zst`; `test_parse_node_drops_what_it_cannot_read` (garbage line ignored, no raise); `test_is_proxmox` for markers, tools and neither; `test_listing_says_proxmox_and_runtimes` using the `Fleet` fixture from `test_tasks.py`, storing an infra reading with `tools: ['qm','pct','lxc-ls']` for one host and asserting `hosts[i]['proxmox'] is True` and `'proxmox' in hosts[i]['runtimes']`.
- [ ] **Step 2: Run** `python -m unittest test_pvenode` → FAIL (no module).
- [ ] **Step 3: Implement.** Section output format, one tab-separated record per line, emitted only when `has pvesm`:
  `s\tNAME\tTYPE\tSTATUS\tTOTAL\tUSED` from `pvesm status` (skip header); `t\tNAME\tCONTENT` from `pvesm status --content X` is costly, so read content types from `/etc/pve/storage.cfg` (`dir: local` / `\tcontent iso,vztmpl,backup`) with awk; `i\tVOLID\tSIZE` from `pvesm list NAME --content iso` and `v\tVOLID\tSIZE` for `--content vztmpl`, for each storage whose content holds it, each `head -n 200`. New section name `proxmox_node` (add to the list at line 23), parsed with `pvenode.parse_node` at line ~414.
- [ ] **Step 4: Run** `python -m unittest test_pvenode test_wlmanaged` (whichever wlmanaged tests exist: `grep -l wlmanaged tests/test_*.py`) → PASS.
- [ ] **Step 5: Commit** `feat(workloads): read a Proxmox VE node's storages, ISOs and templates, and say which runtimes each host can run`.

### Task 2: Guards on Proxmox nodes, and plain LXC actions

**Files:**
- Modify: `storageforge_index/steps_infra.py` (`RUNTIMES` line 25, `workload-action` registration ~1419, `_check_workload_action` ~1164, `t_workload_action` ~751, `vm` registration ~1434 check)
- Modify: `storageforge_index/steps_vm.py` (`_check` ~362, `t_vm_create`), `storageforge_index/steps_vmiso.py`, `storageforge_index/steps_kvm.py` (`vm-define` check), `storageforge_index/steps_workloads.py` (`lxc`, `incus`, `managed-workload-remove` checks and scripts)
- Test: `tests/test_pve_guards.py`

**Interfaces:**
- Consumes: `pvenode.is_proxmox_host(conn, host)`.
- Produces: `steps_infra.ACTION_RUNTIMES = ['docker', 'podman', 'libvirt', 'incus', 'lxc']`, `steps_infra.REMOVE_RUNTIMES = ['docker', 'podman', 'libvirt', 'incus']`; a bash helper `not_on_pve() { [[ -e ${SF_PVE_DIR:-/etc/pve} ]] && { conflict "this is a Proxmox VE node: use the Proxmox VE steps, so Proxmox knows about it"; return 1; }; return 0; }` in `steps_infra`'s bash, called first in each generic create function and in the lxc branches as `not_on_pve || return 0`.

- [ ] **Step 1: Write failing tests:** for each of `vm-create`, `vm-iso`, `vm`, `vm-define`, `lxc`, `incus` on a host whose reading has `tools: ['qm','pct']`, `changes.check` gives a crit containing `Proxmox VE node`; the same steps on a plain host give no such crit; `workload-action` with runtime `lxc` and `managed-workload-remove` runtime `lxc` give the crit on a Proxmox host and none elsewhere; `workload-remove` refuses runtime `lxc` (ValueError from normalize: not an option); a `workload-action` lxc `stop` script passes `bash -n` and, run as a report with `lxc-info` stubbed to print `State: RUNNING` and `SF_PVE_DIR` pointed at a missing path, prints `stop` with `missing`/would and no `command not found`; with `SF_PVE_DIR` at an existing temp dir it prints the Proxmox conflict. A `workload-action` with name `a;rm -rf /` is refused by normalize.
- [ ] **Step 2: Run** `python -m unittest test_pve_guards` → FAIL.
- [ ] **Step 3: Implement** the split lists, the crit (text: `this is a Proxmox VE node: use Create a Proxmox VM or Create a Proxmox container (or the Proxmox action and remove steps), so Proxmox knows about it`), the lxc branch in `t_workload_action` (state from `lxc-info -n NAME -s`; start `lxc-start -n`; stop `lxc-stop -n`; restart `lxc-stop -r -n` ; force-off `lxc-stop -k -n`; snapshot `lxc-snapshot -n`), and `not_on_pve` in each generic create script.
- [ ] **Step 4: Run** `python -m unittest test_pve_guards test_vm test_vmiso test_workload_steps test_infra_steps` (use the existing test modules for those steps: `grep -l "vm-create\|'lxc'\|workload-action" tests/test_*.py`) → PASS.
- [ ] **Step 5: Commit** `feat(workloads): generic VM and LXC steps refuse a Proxmox VE node; plain LXC start, stop and snapshot`.

### Task 3: `pve-action` and `pve-remove`

**Files:**
- Create: `storageforge_index/steps_proxmox.py`
- Modify: `storageforge_index/changes.py` (import it with the other step modules, near line 2099; add its bash to `EXTRA_BASH` as the others do)
- Test: `tests/test_steps_proxmox.py`

**Interfaces:**
- Consumes: `pvenode.is_proxmox_host`, `changes.register`, `steps_infra._ansible_bash` (or the module's equivalent), the `_workload(conn, h, runtime, name)` lookup in steps_infra.
- Produces: step kinds `pve-action` (fields `kind` choice `qemu|lxc`, `vmid` number 100–999999999, `name` name, `action` choice `start|shutdown|stop|reboot|snapshot`, `snapshot` name, optional, required when action is snapshot) and `pve-remove` (destructive, `confirm_of: 'name'`, fields `kind`, `vmid`, `name`, `purge` bool default true); bash `t_pve_action KIND VMID NAME ACTION SNAP` and `t_pve_remove KIND VMID NAME PURGE`; group `'Proxmox VE'`.

- [ ] **Step 1: Write failing tests:** both kinds appear in `changes.TYPES` with group `Proxmox VE`; on a non-Proxmox host the check gives crit `not a Proxmox VE node`; on a Proxmox host with guest 101 `web` running in the reading, `pve-action` start says `ok ... already running` in the check, and a VMID absent from the reading gives a note that the script looks when it runs; `pve-remove` of a running guest gives a crit `stop it first`; `pve-remove` whose name differs from the reading's name for that VMID gives a crit; the script passes `bash -n`; report runs with stub `qm`/`pct` (`qm status 101` → `status: running`, `qm config 101` → `name: web`) print the would-do line and no `command not found`; an apply-mode run where the stub says the name is `other` prints a conflict and never calls `qm destroy` (stub logs its argv to a file; assert `destroy` absent).
- [ ] **Step 2: Run** `python -m unittest test_steps_proxmox` → FAIL.
- [ ] **Step 3: Implement.** Map actions: qemu `start|shutdown|stop|reboot` → `qm ACTION VMID`, snapshot → `qm snapshot VMID SNAP`; lxc the same verbs through `pct` (`pct shutdown`, `pct stop`, `pct reboot`, `pct snapshot`). Remove: read the name (`qm config VMID | awk '/^name:/{print $2}'`, `pct config` → `hostname:`), refuse unless equal to NAME and status is stopped, then `qm destroy VMID --purge` (`--purge` only when PURGE=1). Each change behind `act`.
- [ ] **Step 4: Run** `python -m unittest test_steps_proxmox test_platform test_feature_map` → PASS (test_platform has sample values per field kind; add any new kind there).
- [ ] **Step 5: Commit** `feat(proxmox): start, stop, snapshot and remove Proxmox VE guests through qm and pct`.

### Task 4: `pve-ct`

**Files:**
- Modify: `storageforge_index/steps_proxmox.py`
- Test: `tests/test_steps_proxmox.py`

**Interfaces:**
- Consumes: `proxmox_node` from the reading (Task 1).
- Produces: step kind `pve-ct`, fields: `vmid` number optional, `hostname` name required, `template` text required (a volid `STORAGE:vztmpl/FILE` or a bare template name for `pveam download`), `storage` name required (rootfs), `disk_gb` number default 8, `cores` number default 1, `memory_mb` number default 512, `bridge` iface default `vmbr0`, `ip` text default `dhcp` (`dhcp` or CIDR), `gateway` text optional, `ssh_key` pubkey optional, `password_secret` secret optional, `unprivileged` bool default true, `onboot` bool, `start` bool. Bash `t_pve_ct` with positional args in that order.

- [ ] **Step 1: Write failing tests:** check on a Proxmox host whose `proxmox_node` lacks the named storage → crit naming the storages it has; storage without `rootdir` content → crit; template volid not in `templates` → warn "will be downloaded with pveam" for a bare name, crit for a volid on a storage that lacks it; no `proxmox_node` in the reading → note "not read yet" and no crit; `ip` `10.0.0.5/24` without gateway → warn; `ip` `nonsense` → normalize ValueError; `password_secret` named → `secretstore` lists it for an apply (`changes.prepare`/`items` as `rclone-mount`'s test does) and the script holds the name only; script `bash -n`; report with stub `pct` (`pct status 105` exits 2 = absent) and `pvesh get /cluster/nextid` → `105` prints `would create container 105`; with `pct status 105` succeeding (exists) an apply prints a conflict and the stub log has no `create`.
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement.** `pct create VMID TEMPLATE --hostname H --storage S --rootfs S:DISK --cores C --memory M --net0 name=eth0,bridge=B,ip=IP[,gw=G] --unprivileged 1|0 [--onboot 1] [--ssh-public-keys FILE]` with the key written to a 0600 temp file; password via `--password` is argv, so instead create without it and then set it with `pct exec VMID -- chpasswd` fed from the secret file on stdin (`secret NAME` gives the path). A bare template name: `pveam update` once, `pveam download STORAGE NAME` into the first storage with `vztmpl` content (from the node's `pvesm status --content vztmpl` at run time). Start with `pct start` when `start` is set.
- [ ] **Step 4: Run** `python -m unittest test_steps_proxmox test_platform` → PASS.
- [ ] **Step 5: Commit** `feat(proxmox): create a Proxmox VE container with pct, the root password from the vault`.

### Task 5: `pve-vm`

**Files:**
- Modify: `storageforge_index/steps_proxmox.py`; `storageforge_index/steps_vm.py` only to expose the download-and-verify part of `t_vm_create` as a shared bash function if it is not one already (e.g. `sf_vm_fetch URL SUMS_URL DEST`), changing nothing in `vm-create`'s behaviour
- Test: `tests/test_steps_proxmox.py`

**Interfaces:**
- Consumes: `steps_vm.IMAGES` (catalog keys), `sf_vm_image` bash (key → url, sums url, osinfo).
- Produces: step kind `pve-vm`, fields: `vmid` optional, `name` vmname required, `source` choice `iso|image` required, `iso` text (volid `STORAGE:iso/FILE`, when source is iso), `image` choice from `IMAGES` keys (when source is image), `storage` name required (disks), `disk_gb` default 32, `cores` default 2, `memory_mb` default 2048, `bridge` default `vmbr0`, `ostype` choice `l26|win11|other` default `l26`, `user` name default `admin` and `ssh_key` pubkey (image only, cloud-init), `onboot` bool, `start` bool. Bash `t_pve_vm`.

- [ ] **Step 1: Write failing tests:** source `iso` without `iso` → normalize ValueError; `image` with `iso` set → ValueError; storage without `images` content → crit; iso volid absent from `isos` → crit; image source without `ssh_key` → warn "no way to log in"; script `bash -n`; report with stub `qm`, `pvesh` prints `would create VM 106 from debian13`; apply where `qm status 106` succeeds → conflict, stub log has no `create`; an apply-mode run with a stubbed `curl` serving a file whose sha does not match the stub SUMS → conflict and no `qm` call after the download (assert the stub log).
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement.** ISO: `qm create VMID --name N --memory M --cores C --net0 virtio,bridge=B --scsihw virtio-scsi-single --scsi0 S:DISK --ide2 ISO,media=cdrom --boot order='scsi0;ide2' --ostype T --agent 1`. Image: fetch and verify into `$(mktemp -d)`, then `qm create ... --scsi0 S:0,import-from=FILE` (fall back to `qm importdisk` when `qm help create` lacks `import-from`), `qm resize VMID scsi0 DISKG`, `--ide2 S:cloudinit`, `--ciuser U --sshkeys KEYFILE --ipconfig0 ip=dhcp`, `--serial0 socket --vga serial0`; temp dir removed on exit. `onboot`, `start` as in Task 4.
- [ ] **Step 4: Run** `python -m unittest test_steps_proxmox test_vm test_platform` → PASS.
- [ ] **Step 5: Commit** `feat(proxmox): create a Proxmox VE VM from an ISO on the node or a checked cloud image`.

### Task 6: The page and the tree

**Files:**
- Create: `storageforge_index/static/workloads.html`, `storageforge_index/static/workloads.js`, `storageforge_index/static/workloads.css`
- Modify: `storageforge_index/server.py` (route next to `/logs` ~863), `storageforge_index/static/index.html:31` (a top-bar link `<a id="toworkloads" class="btn" href="/workloads">Workloads</a>`), `storageforge_index/static/security.html`, `manage.html`, `logs.html`, `planner.html` top bars if they repeat the links (match what each has for Security)
- Test: `tests/test_workloads_page.py` (Python: route, permission, and the tree model through a small JS-free check: see Step 1)

**Interfaces:**
- Consumes: `GET /api/workloads` (`{workloads, hosts}` with `hosts[].proxmox`, `hosts[].runtimes` from Task 1).
- Produces: in `workloads.js`, `wlTree(listing) -> node` where node is `{id, kind: 'fleet'|'host'|'runtime'|'stack'|'workload'|'connections', label, data, children}`; ids `host:NAME`, `rt:NAME:RUNTIME`, `stack:NAME:RUNTIME:PROJECT`, `wl:NAME:RUNTIME:NAME`; `wlLayout(root, folded:Set) -> Map(id → {x, y})`; `wlSelect(id)` opens the panel; `WL.actions` hook that Task 7 fills: `WL.onAction = (step) => void`, `WL.onNew = ({host, runtime}) => void`.

- [ ] **Step 1: Write failing tests:** `GET /workloads` with a logged-in admin → 200 and the body contains `workloads.js`; a user without `workloads.view` (use the role fixtures `test_security.Base` offers) gets the page but `GET /api/workloads` is 403; `test_feature_map` passes with the new route (it is called by this test). Browser coverage is Task 8.
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement.** Tree rules: hosts sorted by name, runtimes in the order docker, podman, libvirt, incus, lxc, proxmox; on a host with `proxmox: true`, drop `runtime: lxc` entries whose name is a VMID that a `runtime: proxmox` entry has (dedupe); compose containers grouped under a `stack` node by their `stack` field; `source: 'api'` entries go under their host when it is in `hosts`, else under a `connections` node (one child per `managed_by`/connection name), marked read-only; a host with neither `containers_read_at` nor `measured_at` shows a single child "not read yet: scan it" linking `/#/topo?host=NAME`; a runtime in `hosts[].runtimes` with no workloads still appears (for **+ New**). Layout: tidy left-to-right tree, column per depth (240 px), each leaf 44 px tall, parents centred on their children; folded subtrees count as one leaf. Hosts start folded when there are more than 12. Drawing: SVG paths for edges, absolutely positioned DOM cards for nodes inside the transformed layer, pan and zoom with `canvas.js` like `mapview.js` does. Accessible tree: the cards are `role="treeitem"` in a `role="tree"` container in DOM order, with `aria-level`, `aria-expanded`, roving `tabindex`; ArrowUp/Down move, Right unfolds or enters, Left folds or goes to parent, Enter opens the panel, `+` opens New on a host or runtime. Filter box filters by name, host, runtime or state (case-insensitive substring); non-matches fade (`opacity: .3`), ancestors of matches stay. URL hash `#folded=...&q=...&sel=...` kept with `history.replaceState`. Panel: details as listed in the spec, the reading's age, findings, and buttons per action (Task 7 wires them; here they call `WL.onAction` with the step object `{type, host, params}`): docker/podman → `workload-action` start/stop/restart, `image-update` when in a stack, `workload-remove`; libvirt → `workload-action` start/stop/force-off/snapshot, `vm-edit`, `vm-snapshot`, `workload-remove`; incus → `workload-action`, `workload-remove`; lxc → `workload-action`, `managed-workload-remove`; proxmox → `pve-action` start/shutdown/stop/reboot/snapshot, `pve-remove`; read-only entries → none, with the sentence from the spec. A `managed` warning (not for proxmox runtime) shows above the buttons.
- [ ] **Step 4: Run** `python -m unittest test_workloads_page test_feature_map test_security` → PASS; open no browser here.
- [ ] **Step 5: Commit** `feat(workloads): a Workloads page drawing every container and VM as a tree of hosts and runtimes`.

### Task 7: Shared step fields, the wizard and panel actions

**Files:**
- Create: `storageforge_index/static/stepfields.js`, `storageforge_index/static/workloadwiz.js`
- Modify: `storageforge_index/static/changes.js` (`openTask` ~111 uses `stepFields`), `storageforge_index/static/index.html` (load `stepfields.js` before `changes.js`), `storageforge_index/static/workloads.html` (load `stepfields.js`, `workloadwiz.js`)
- Test: `tests/test_browser_drafts.py` and the other browser tests that open a task form keep passing (Task 8 runs them)

**Interfaces:**
- Consumes: `GET /api/changes/types` (`{types: {kind: {group, label, help, fields: [{name, kind, label, required, default, options, placeholder}], destructive, confirm_of}}}`), `WL.onAction`, `WL.onNew`, `pvenode` data via `hosts[]`.
- Produces: `stepFields(spec, values, {host, pickPath}) -> {nodes: Element[], read: () => params, controls}` (exactly the field-to-input logic now inside `openTask`, including bool, choice, the `vm-create` spec picker and the archive path browse); `wizOpen({host, runtime})`; `reviewStep(step) -> Promise` showing the check items and the Save as a plan button.

- [ ] **Step 1:** Lift the field rendering out of `openTask` into `stepFields` with no behaviour change; `openTask` calls it. Run the existing browser tests that open task forms (`grep -l openTask\|stageform tests/test_browser_*.py`) → PASS.
- [ ] **Step 2:** Wizard kinds per runtime (create steps only): docker/podman → `container`, `stack`; libvirt → `vm-create`, `vm-iso`, `vm`; incus → `incus`; lxc → `lxc`; proxmox → `pve-vm`, `pve-ct`. On a host with `proxmox: true` offer only the proxmox ones; elsewhere never the proxmox ones; offer only runtimes in `hosts[].runtimes` (plus docker and podman with a note that the step installs nothing: `runtime-install` exists for that). Pages: What (kind), Where (host, then the step's location fields: `storage`, `pool`, `path`-kind fields, `template`, `iso`), then field groups from this map, falling back to one "Settings" page: resources = `cores, vcpus, memory_mb, ram_mb, disk_gb, disk`; network = `bridge, network, ip, gateway, publish`; access = `user, ssh_key, key, password_secret`; everything else = "Settings". Required first, optional under a "More" `<details>`. On Proxmox steps, `storage`, `iso` and `template` are `<select>`s from `proxmox_node` (storages filtered by content `images`/`rootdir`/`iso`/`vztmpl` as fits), with a free-text fallback when the reading lacks it.
- [ ] **Step 3:** Review: `POST /api/changes/check` with `{name: 'workloads: <title>', tasks: [step]}` (match the body `changes.normalize` expects; read `changes.prepare`); render items crit/warn/note as `sharewiz.js` does; crit disables Save. Save: `POST /api/changes` with the same body, then show "Saved as plan N" with a link `/#/topo/changes?plan=N` (use whatever route `router.js` gives the Changes tab; open the plan there). Destructive steps show the typed-confirmation field their spec asks for (`confirm_of`). Panel actions use the same `reviewStep`.
- [ ] **Step 4: Run** `node --check` on the three JS files, and `python -m unittest test_feature_map test_source_hygiene` → PASS.
- [ ] **Step 5: Commit** `feat(workloads): a create wizard and panel actions built from the plan steps, ending in a checked plan`.

### Task 8: Browser test, docs, roadmap

**Files:**
- Create: `tests/test_browser_workloads.py` (class `BrowserWorkloads`, modelled on `test_browser_drafts.py`)
- Modify: `tests/blocks.py` (add `'test_browser_workloads.BrowserWorkloads'` to the heavy list), `docs/` user guide (new `docs/workloads-page.md`, linked from `docs/README.md`), `CHANGELOG.md`, `roadmap.md` (section 6: a row for the page and the Proxmox steps, "built, not lab-tested"; section 1: a lab tier note for a Proxmox VE VM in the KVM lab)
- Test: the browser test itself

- [ ] **Step 1: Write the browser test** with fixture workloads on three hosts (one docker host with a stack of two containers, one libvirt host with a running and a stopped VM, one Proxmox host with guests 101 qemu and 200 lxc and a duplicate `lxc` entry `200`): the page shows 3 hosts; the Proxmox host has one `proxmox` branch and no `lxc` branch; folding a host hides its children; typing `db` in the filter fades non-matches; keyboard: focus the tree, ArrowDown to a workload, Enter opens the panel with its name; clicking Stop on the running VM shows the check and Save makes a plan (assert `GET /api/changes` has it with one `workload-action` task); **+ New** on the Proxmox host offers `pve-vm` and `pve-ct` only, and walking `pve-ct` to Review with the fixture storages saves a plan.
- [ ] **Step 2: Run** only this class: `python tests/run.py heavy -k BrowserWorkloads -j 1` (with `PYTHONPATH` set) → PASS. If Playwright is not installed it skips; say so in the report.
- [ ] **Step 3: Write the docs:** what the page shows, how to read the tree, that every action is a plan, the Proxmox steps (that guests show up in the Proxmox web UI, root SSH needed, the generic steps refuse a Proxmox node), what is not lab-tested.
- [ ] **Step 4: Run** `python tests/run.py light -j 6` then `python tests/run.py medium -j 6` → 0 failed.
- [ ] **Step 5: Commit** `test(workloads): the page in a browser; docs and roadmap for the Workloads page and the Proxmox VE steps`.
