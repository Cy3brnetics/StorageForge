# Workloads page: a mind map of containers and VMs, with a create wizard

Date: 2026-11-25. Asked for by the owner: "a more mindmap style management interface for docker podman lxc and kvm/proxmox etc, same
kinda wiz for creating vms/containers", on "its own dedicated page not in the topo".

## Intent

One place to see and manage every container and VM in the fleet, whatever runs it (Docker, Podman, plain LXC, Incus, libvirt/KVM,
Proxmox VE), drawn as a mind map: fleet → host → runtime → workload. From any node you can act on it or create something new under
it, through a step-by-step wizard like the share wizard. Today the same facts are split between the Infrastructure tab (a table), the
Map (workloads inside host frames, among networks and listeners) and change-plan forms you have to know to look for.

## Goals

- A standalone page, `/workloads`, beside `/planner`, `/manage`, `/security` and `/logs`, with its own link in the top bar of the main
  page. Not a layer of the Map or the Topology; those stay as they are.
- A left-to-right tree on the shared pan-and-zoom canvas (`static/canvas.js`): a root "fleet" node, one node per host, one per runtime
  present on that host, one per workload. Branches fold and unfold; a large fleet starts with hosts folded.
- Each workload node shows its name, state (running, stopped, other) and the little that tells it apart (vCPUs and memory for a VM,
  image for a container, VMID for a Proxmox guest, "managed by X" when something else manages it).
- Selecting a node opens a side panel: details (from `GET /api/workloads`), findings, and the actions that apply to it.
- Every action goes through a change plan (owner's answer, 2026-11-25): the page builds the step, checks it (`POST /api/changes/check`)
  and shows the report; saving makes a plan (`POST /api/changes`), and applying it is the existing deploy (report, then apply, signed
  runner, audit). Nothing on this page changes a host directly.
- A create wizard, opened from **+ New** on the page, on a host node, or on a runtime node (host and runtime then picked already). It
  is built from the plan-step definitions (`GET /api/changes/types`), the way the share wizard builds protocol forms from its drivers,
  so a new step kind shows up in the wizard without new UI.
- Proxmox VE create and manage, through `qm` and `pct` over SSH in the plan scripts (owner's answer, 2026-11-25), so whatever is made
  appears in the Proxmox web UI as if made there.
- Keyboard access to every node and action: arrow keys move through the tree, Enter opens the panel, and the tree is also a real list
  (`role="tree"`/`treeitem`) for screen readers. The 2026-11-04 audit faulted the Map for having none (UX finding on map keyboard
  access); this page must not repeat it.

## Non-goals

- Editing networks, storage pools or firewall rules from this page (the Map, Planner and Changes have those).
- Live metrics (CPU graphs, logs streaming). The page reads the index, like every other view, and says how old each reading is.
- Proxmox through its API for writes. The API stays read-only (`apipve.py`).
- Cluster-level Proxmox actions (HA groups, migration between nodes, replication jobs). One node at a time, as `qm`/`pct` on that node.
- Unattended OS installs (already deferred in `steps_vmiso.py` for want of an answer file with a vault secret).

## Anti-goals (would make it a failure even if it works)

- Any action that changes a host without a plan and its report.
- Making something on a Proxmox host that Proxmox does not know about: the generic `vm-create`, `vm-iso`, `vm`, `lxc` and `incus`
  steps must refuse a Proxmox VE host, and the wizard must not offer them there.
- A second, divergent copy of a step's form. The wizard renders the same field specs `openTask` (changes.js) does.
- A page that hides what it could not read: a host with no workload reading says "not read", not "nothing runs here".

## What exists (2026-11-25, branch dev-0.6.0)

Read side, all in `workloads.listing()` behind `GET /api/workloads`: Docker and Podman (rootful from scans, rootless per user), libvirt
domains with disks and snapshots, Incus instances, plain LXC (`lxc-ls`, detail: False), Proxmox guests read over SSH with `qm`/`pct`
(`inframeasure.py`) and, separately, through the API. Each entry has host, runtime, kind (container, vm, instance), name, state, mounts,
networks, ports, findings, and `managed_by` when something else manages it.

Write side, plan steps registered with `changes.register`:

| Runtime | Create | Act on one |
| :-- | :-- | :-- |
| Docker, Podman | `container`, `stack` | `workload-action` (start, stop, restart, force-off, snapshot), `workload-remove`, `image-update` |
| libvirt/KVM | `vm-create` (cloud image), `vm-iso`, `vm` (from a disk), `vm-define` | `workload-action`, `workload-remove`, `vm-edit`, `vm-snapshot`, `vm-revert`, `vm-send` |
| Incus | `incus` | `workload-action`, `workload-remove` |
| LXC | `lxc` | none: `RUNTIMES` in steps_infra.py is docker, podman, libvirt, incus |
| Proxmox VE | none | none |

`openTask(type, host, preset)` in `static/changes.js` renders any step's fields into a form today; the Map already calls it (for
example "Deploy a stack…"). Standalone pages are `app_page('x.html')` routes in `server.py` loading `session.js`, `kernel.js`,
`chrome.js` and their own script, as `/manage` does.

## Approaches considered

1. **Rendering the page.**
   - *SVG tree on the shared canvas (picked).* Same pan, zoom and keys as Topology, Map and the Files map; a tidy left-to-right tree
     layout is simple and stable. The canvas DOM is paired with a hidden-free accessible tree so keyboard and screen readers work.
   - *A collapsible indented outline styled as a map.* Cheap and accessible, but it is a list, not the mind map the owner asked for.
   - *A force-directed graph.* Looks most like a mind map but moves on every refresh and is hard to scan with a hundred workloads.
2. **The wizard.**
   - *Generic, from step specs (picked).* One wizard that groups a step's fields into pages (what, where, resources, network and
     storage, review), with per-step hints only where a step needs them (the image catalog for `vm-create`, the spec picker). New
     step kinds work without UI work.
   - *One hand-written wizard per runtime.* Nicer per kind, but five forms to keep in step with five step specs.
3. **Proxmox writes** (owner picked SSH, 2026-11-25).
   - *`qm`/`pct` in plan scripts over SSH (picked).* Same path as every other step: signed runner, report first, audit. `qm`/`pct` write
     `/etc/pve`, so guests appear in the Proxmox web UI, cluster-wide. Needs root SSH on the node, which the owner's node allows over
     Tailscale.
   - *The Proxmox API with a write token.* No SSH, but the first step that would run from the StorageForge container rather than on a
     host, and a write token kept in the vault.

## The design

### Backend

- `GET /workloads` → `app_page('workloads.html')`. `app_page()` already handles login and requires `hosts.view`; the page also needs
  `workloads.view` (what `GET /api/workloads` requires, `permissions.py`), and says so plainly when the user lacks it.
- No new read API: the page uses `GET /api/workloads` (all hosts), `GET /api/changes/types`, `POST /api/changes/check`,
  `POST /api/changes`. If `/api/workloads` lacks something the page needs (which runtimes a host *can* run, so an empty runtime branch
  can offer **+ New**), add it to the listing's `hosts` entries, read from the index (installed packages, `has` lines in the
  infrastructure measurement), never from a live probe.
- **Proxmox VE detection:** build on what exists: the scan's `platform` from `pveversion` (`remote.py`) and the `pve` flag
  `wlmanaged.annotate` computes (the pve marker, or `qm`/`pct` among the tools). Lift that into one helper, `is_proxmox(conn, host)`,
  used by the steps' checks and by the listing (`hosts[].proxmox: true`). Not `pve-manager` in packages: `pkglist` keeps only packages
  installed on purpose.
- **A new scan read on Proxmox VE nodes** (my call, from the review: nothing in the index holds this today). In the `sec proxmox` part of
  `inframeasure.py`, add `pvesm status` (each storage: name, type, enabled, active, total, used, and its content types from
  `/etc/pve/storage.cfg` or `pvesm status --content X`), `pvesm list STORAGE --content iso` and `--content vztmpl` for each storage that
  holds them (capped, like the other lists), and the node's bridges (already read by the network scan: reuse, don't re-read). Parsed
  into `proxmox_node: {storages: [...], isos: [...], templates: [...]}` with tests, like the other sections. The wizard's pickers and the
  steps' checks use it; when a reading is missing or old, the field is free text and the script checks at run time. The next free VMID
  and the templates `pveam` could download are not read: the script asks `pvesh get /cluster/nextid` when it runs, and `pveam` downloads a
  named template that is not there yet.
- **New plan steps** (new module `steps_proxmox.py`, registered from `changes.py` like the others, group `Proxmox VE`):
  - `pve-vm`: create a QEMU VM with `qm create` (VMID optional: next free from `pvesh get /cluster/nextid`; name, cores, memory,
    storage, disk size, bridge, OS type, start on boot, start now). Its system comes from one of two sources (my call, from the
    review): an ISO already on a storage of the node (`local:iso/x.iso`, picked from the new read), attached as the CD; or a cloud
    image from the same catalog `vm-create` uses (`steps_vm.py`), downloaded on the node into a temporary file, checked against the
    catalog's checksum exactly as `vm-create` checks it, imported with `qm set --scsi0 STORAGE:0,import-from=FILE` (or `qm importdisk` on
    an older release), with a cloud-init drive holding one login user and its SSH public key, then the temporary file deleted. Never
    reuses a VMID that exists.
  - `pve-ct`: create an LXC container with `pct create` from a template in a storage's `vztmpl` content (download with `pveam` when
    named but absent), unprivileged by default, hostname, cores, memory, rootfs storage and size, bridge, IP (dhcp or a CIDR and
    gateway), SSH public key, start on boot, start now. Root password, if any, only as a vault secret on stdin (as `rclone-mount`
    does), never on the command line.
  - `pve-action`: start, shutdown (clean), stop (hard), reboot, snapshot (`qm snapshot`/`pct snapshot` with a name), for a VMID and
    kind (qemu or lxc).
  - `pve-remove`: destructive; `qm destroy`/`pct destroy` with `--purge`, refused unless the VMID's name matches the name given (a
    typed confirmation, like the other destructive steps) and the guest is stopped.
  - Each: report first (what it would run, and what the node has now), `--apply` to do it, checks against the index (the VMID exists
    or not, the storage and bridge exist on that node, the name is free), Ansible output like the others (`_ansible_bash`).
- **Refusals:** `vm-create`, `vm-iso`, `vm`, `vm-define`, `lxc` and `incus` add a crit in their check on a Proxmox VE host: "this is a
  Proxmox VE node: use Create a Proxmox VM / container, so Proxmox knows about it". The generated script also refuses at run time when
  `/etc/pve` exists, in case the index is stale.
- **Plain LXC actions:** `RUNTIMES` in `steps_infra.py` serves both `workload-action` and `workload-remove`; split it, and add `lxc`
  to `workload-action` only, with an `lxc` branch in `t_workload_action` (start, stop, restart, force-off via `lxc-start` and
  `lxc-stop [-k]`; snapshot via `lxc-snapshot`). Not to `workload-remove`, whose promise is "the definition goes, volumes and disks stay":
  `lxc-destroy` deletes the root filesystem. Removing a plain LXC container from the page uses the existing destructive
  `managed-workload-remove` (runtime `lxc`), which destroys a managed container and its rootfs.
- **Proxmox nodes and plain LXC** (my call, from the review): Proxmox ships `lxc-ls`, so its `pct` containers are also read as
  `runtime: lxc`, named by VMID. On a Proxmox node the page hides the `lxc` entries that are `pct` guests (the `proxmox` branch shows
  them), and `workload-action`, `managed-workload-remove` and `lxc` refuse runtime `lxc` there with a crit pointing at the `pve-*`
  steps, the same way the generic create steps refuse.
- **"Managed by Proxmox VE"** (my call): `wlmanaged.annotate` marks every Proxmox guest `managed: {by: 'Proxmox VE', level: 'warn'}`.
  That stays as it is for the Infrastructure tab and the findings. On this page the warning is shown before an action only when the
  step is not a `pve-*` step: `pve-action` and `pve-remove` *are* Proxmox's own tools, so Proxmox stays in charge. The `pve-*` steps'
  checks do not repeat the warning.
- **Guests seen only through an API** (`apiviews.annotate_workloads` adds Proxmox guests read through the API, and Xen Orchestra,
  TrueNAS and panel workloads, `source: 'api'`): shown under their host when it is an indexed host, otherwise under a branch of their
  own, "Seen through connections", one node per connection. They are read-only on this page (my call): the `pve-*` steps need SSH to the
  node, and the step checks read `workloads.listing()`, which does not hold API entries. Their panel says so and, for a Proxmox guest
  whose node is also an indexed host, points at the node's own entry.

### The page (`static/workloads.html`, `static/workloads.js`, `static/workloads.css`)

```
 [ StorageForge ]  Workloads                      [+ New ▾]  filter: ____  [fold all]
                         ┌─ docker ─┬─ immich (stack, 4 running)
                         │          └─ jellyfin ● running
          ┌─ nas-01 ─────┼─ kvm ────┬─ db-vm ● running  2 vCPU 4 GB
          │              │          └─ test-vm ○ stopped
 fleet ───┤              └─ lxc ────── pihole ● running
          └─ pve-01 ─────── proxmox ┬─ 101 web ● running (qemu)
                                    └─ 200 dns ○ stopped (lxc)
                                                       ┌──────────────┐
                                                       │ db-vm        │
                                                       │ libvirt · vm │
                                                       │ running, 3 h │
                                                       │ [Stop] [Snap]│
                                                       │ [Edit] [Del] │
                                                       └──────────────┘
```

- Layout: a tidy tree (each subtree's height is the sum of its children's, leaves spaced evenly), computed in JS, drawn as SVG lines
  with DOM node cards (as Topology does), panned and zoomed by `canvas.js`. Positions are computed, not saved.
- Compose stacks are one node with their containers as children; a container in no stack hangs off the runtime directly.
- Filter box: by name, host, runtime or state; matching nodes and their ancestors stay, others fade. Fold state and the filter are kept
  in the URL hash (like `router.js` does for the main page) so Back and a copied link work.
- Side panel for a workload: what the listing has (state, image or disks, vCPUs, memory, mounts and the mount each sits on, networks,
  ports, findings, managed by, how old the reading is), then the actions that apply, each opening the review (below). For a host: its
  runtimes and **+ New**. For a runtime: **+ New** of that runtime.
- A workload whose `managed` says something else manages it (Portainer, Komodo, Dockhand…) shows that warning before any action, as
  the existing checks already say; Proxmox guests follow the rule under Backend.
- Empty and unread: a host with no reading says so and links to its scan; a runtime the host can run but has nothing in still shows,
  with **+ New**.

### The wizard (`static/workloadwiz.js`)

- Step 1 **What**: pick a kind. The list is the step kinds that create something, filtered to what the chosen host can run (no
  generic VM or LXC kinds on Proxmox VE; no Proxmox kinds elsewhere). Opened from a node, host and runtime are already set.
- Step 2 **Where**: the host (if not set), and the step's location fields (pool, storage, folder) with pickers where the step's field
  kind has one (`pickPath` for paths).
- Step 3 onward: the step's remaining fields, grouped by a small per-kind map (resources, network, storage, access), falling back to one
  page of "everything else" for a kind with no map. Required fields first; optional ones under "more".
- Last step **Review**: `POST /api/changes/check` with the one step; show the report's items (crit, warn, note) as the share wizard does;
  crit blocks saving. **Save as a plan** creates a plan with this one step (`POST /api/changes`) and links to it in Changes/Deploy, where
  report and apply happen as today. No "add to a plan" in this version (my call, from the review): the only unsaved plan is the main
  page's browser-local draft, and writing into it from another page could be overwritten by that page.
- Field rendering is shared with `openTask`: lift the field-to-input part of `openTask` into a function both call, rather than copying
  it.

### Actions from the panel

Each action makes exactly one step (`workload-action`, `workload-remove`, `vm-edit`, `vm-snapshot`, `pve-action`, `pve-remove`,
`image-update`), shows the check, and offers Save as a plan, the same last step as the wizard. Destructive ones say so and need the
typed confirmation their step already asks for.

## Tests

- Python: the new `proxmox_node` scan read parsed from captured `pvesm` output.

- Python: each new step's normalize and check (refusals included), its generated script with `bash -n`, and a report run with `qm`,
  `pct`, `pvesh` and `pveam` stubbed (the share-driver tests show the pattern); the generic steps refusing a Proxmox VE host; LXC in
  `workload-action`; the `/workloads` route and its permission, added to `test_feature_map`'s entry points.
- Browser (heavy block, as the other pages' tests are): the page draws a fleet from fixture workloads, folds and unfolds, filters,
  keyboard moves and opens the panel, and the wizard reaches Review and saves a plan for a container and for a Proxmox VM.
- Not testable here: real `qm`/`pct` applies (no Proxmox node in the test environment). The KVM lab can run a Proxmox VE VM later;
  note it in the roadmap as a lab tier.

## Left to the builder

- Node card styling within `tokens.css`/`components.css`; the exact tree spacing; icons per runtime (plain SVG, as the rail has).
- The per-kind field grouping map for the wizard.
- Splitting `steps_proxmox.py` if it grows past the size of the other step modules.
