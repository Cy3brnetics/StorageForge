# Web UI

The main page (`/`) has three views in the header (**Topology**, **Graph** and **Tasks**) and a rail of panels on the right. Every page except `/login` needs a session; an open page clears itself and returns to the sign-in page when the session ends.

The header also holds the host filter, file search, a link to the [Planner](planner.md), **Export .canvas**, the session length menu and **Sign out**.

## Topology

![Topology view](images/topology.jpg)

The topology is a schema-designer canvas built from each host's design. Each host is a frame. Each disk, pool and remote is a table whose rows are its partitions, subvolumes, datasets and mount points. Lines join rows across tables: a member partition to its pool, a mount point to the links and exports inside it, an export to the client mounting it.

- Scroll to pan, Ctrl+scroll to zoom, drag a table or host frame by its heading.
- **Fit**, **Auto-layout** (forgets saved positions) and **Collapse all** are in the toolbar, with a box finder.
- Table positions are saved with the design.
- Staged subvolumes and mounts appear as dashed boxes; other staged changes mark the box they touch. A banner offers **Review** when changes are staged.

Select a box to edit what you own: device and pool tiers, encryption notes, 3-2-1 protection on a mount point (snapshots, sync, backup target, offsite), links and exports. Hardware and layout come from the scan. To set a backup target, drag one mount point onto another, on the same host or a different one. **Save design** stores the design and rebuilds the graph.

![A selected pool](images/topology-details.jpg)

### Context menus

Right-click almost anything. The menu key and Shift+F10 open the menu on the focused box; Shift+right-click keeps the browser's own menu.

![Context menu on a mount point](images/context-menu.jpg)

| Where | Menu |
| :--- | :--- |
| Topology box | edit, show in graph, tier, protection, move from here, share this, link into this, back up or snapshot with a task, largest files, browse folders, every change that can be staged there, the changes already staged on it, copy path, device or UUID |
| Host heading | scan now, add a link or export, deploy shares, review staged changes, open in the planner |
| Graph node | details, focus, center, unpin, edit in the topology, browse folders, largest files, move from here |
| Folder in the browser | open, largest files, rename, trash, permissions, link to it, turn into a subvolume, snapshot, copy to another disk, copy path |
| Search result | show its folder, largest files there, rename, trash, permissions, copy its folder to another disk, copy path |
| Staged change, Moves step | edit, reorder, duplicate, remove (and swap source and destination for a step) |

## Graph

![Graph view](images/graph.jpg)

A force-directed view of the same data: hosts, pools, filesystems, mount points and symlinks, coloured by 3-2-1 health (see [Concepts](concepts.md#health-colours)).

- Drag the background to pan, scroll to zoom, drag a node to pin it where you drop it. Shift-drag lets it spring back; **Show all** releases every pinned node.
- Click a node for details; double-click to focus on its neighbourhood (1–3 hops, set by **Focus**).
- **Export .canvas** writes an Obsidian JSON Canvas of the graph, or of one host when the host filter is set.

| Node | Example id | Edges |
| :--- | :--- | :--- |
| Host | `host:atlas` | `CONTAINS` pools and standalone filesystems |
| StoragePool | `pool:atlas:tank` | `CONTAINS` datasets and arrays' filesystems |
| Filesystem | `fs:atlas:tank/media` | `MOUNTED_AT` mount points, `REPLICATES_TO` sync and backup targets |
| MountPoint | `mnt:atlas:/mnt/storage_array/media` | `MOUNTED_AT` bind mounts |
| Symlink | `link:atlas:/var/media` | `SYMLINK_TO` the mount holding its target, or another link |

## Tasks

![Tasks view](images/tasks.jpg)

The block editor for [storage tasks](plans-and-scripts.md#storage-tasks). The palette on the left holds the blocks; click one to add it at the end or into the selected slot, or drag it into place. Each block shows its fields and is checked against the index while you edit; collapse it to a one-line sentence. Ctrl+Z undoes. **Script** shows the generated `task-<name>.sh`, and **Deploy** installs or runs it on the host.

## Panels

The rail on the right opens panels in the inspector. The first panel, **Details**, describes the selection or summarises health across every host.

### Inspect

| Panel | What it does |
| :--- | :--- |
| **Details** | The selected box or node, or node counts, health totals and everything that needs attention |
| **Search** | Results of the header search (`/` focuses it). Selecting one focuses its mount. See [search patterns](scanning-and-search.md#search). |

![Search results](images/search.jpg)

### Plan

| Panel | What it does |
| :--- | :--- |
| **Changes** | [Staged change plans](plans-and-scripts.md#staged-changes): review, reorder, **Check**, **Bash script**, **Ansible playbook**, **Deploy** |
| **Moves** | [Move plans](plans-and-scripts.md#data-moves): steps, **Check**, **Download script**, **Deploy** |
| **Deploy** | [Deploy access](deployments.md) per host, deployed jobs and shares, drift, recent deploys, reporting and alert settings |

![Changes panel after Check](images/changes.jpg)

![Moves panel](images/moves.jpg)

![Deploy panel](images/deploy.jpg)

### Inventory

| Panel | What it does |
| :--- | :--- |
| **Docker** | Each host's [compose stacks](scanning-and-search.md#docker-and-compose-stacks), their containers and the folders and volumes they use; unused volumes; containers that mount the Docker socket |
| **Git** | [Repositories](scanning-and-search.md#git-repositories) the scans found, matched across hosts by history, with **Archive to…** |
| **Rebuild** | Each host's saved configuration: mounts, subvolumes, shares, accounts, symlinks and config files, with what changed in each version. Downloads the reinstall script or a bundle. See [rebuilding a host](disaster-recovery.md#rebuild-a-host-after-reinstalling-it). |
| **Cleanup** | Duplicate folders (same names, sizes and layout) and cold data (newest file older than a cutoff), each with **Move…** |
| **Access** | Folders the last scan could not read, and [read-only scan access](scanning-and-search.md#unreadable-folders-and-read-only-access) to fix it |

![Cleanup panel](images/cleanup.jpg)

![Access panel](images/access.jpg)

### Admin

| Panel | What it does |
| :--- | :--- |
| **Scans** | Queue a scan of a bound host, or **Scan all hosts**, and follow recent scan jobs |
| **Keys** | Generate a key in the vault, install it on a host with its password once, list keys and bindings, **Scan now** per binding |
| **Audit** | The newest audit entries, and **Verify chain** |

![Keys panel](images/keys.jpg)

![Audit panel](images/audit.jpg)

## Deep links

The main page reads `#host=<name>&tab=<panel>`, for example `/#host=nas-02&tab=changes`. The planner's **In StorageForge** links use this to open a host's Changes, Moves, Deploy, Docker, Git, Cleanup or Access panel.

## Passwords for host commands

Anything that runs a command on a host from the web UI (key install, scan access, deploy access, deploys, job runs and cutovers, restores) and changing your session length asks for your password again unless you typed it in the last 5 minutes. Read-only job actions (dry run, log, list snapshots) do not.
