# Web UI

For a guided tour of every feature, see the [feature guide](features/README.md).

The main page (`/`) has five views in the header (**Topology**, **Graph**, **Tasks**, **Map** and **Scan**) and a rail of 18 panels on the right. Every page except `/login` needs a session; an open page clears itself and returns to the sign-in page when the session ends.

The header also holds the host filter, file search, the security chip, links to the [Planner](planner.md) and to [Manage](#other-pages), **Export .canvas** (in Topology and Graph, the two views it exports), the session length menu and **Sign out**. The chip says in a line where the [security posture](ransomware-defense.md) stands (*Security: nothing wrong found*, *needs a look*, *incident* or *not known*), with the reason under it, and a click opens the **Security** panel. Accounts that may not view security do not see it.

Which view is for what: **Topology** is where you edit what you own, **Graph** is for exploring how hosts, pools and mounts relate and where copies of files are (look here, edit in Topology), **Tasks** builds storage tasks from blocks, **Map** shows networks, listeners, firewalls and workloads and who can reach what, and **Scan** shows what the network scanner found. Hovering a view's button says the same.

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

The view has two modes. **Files** is a map of a host's folders from the index, with lines between folders holding copies: **Browse** or **Duplicates**, size, host and **System files** filters, and an ignore list. See [the file map](features/views.md#files). **Structure** is described below.

![Graph view](images/graph.jpg)

**Structure** is a force-directed view of the same data: hosts, pools, filesystems, mount points and symlinks, coloured by 3-2-1 health (see [Concepts](concepts.md#health-colours)).

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

## Map

What hosts report, drawn as an infrastructure map: each host a frame holding its interfaces, listeners and workloads, joined through subnets and placeholders. Dashed means inferred; the colour of a listener is who can reach it, per configuration. It has its own panel beside it for the selected node, a path query, a what-if and saved designs, so **Details** in the rail is not used here.

- **Look at** picks a preset (**Network**, **Flow**, **Workloads**, **Storage only**, **Security** or **Custom**), and the checkboxes under **Layers** (Storage, Network, Services, Firewall, Workloads, Access, Placed by hand) stack layers on their own. Picking a layer by hand makes the preset **Custom**.
- Group by host, subnet or runtime; filter by name, address or port; show this-machine-only ports, container networks and devices nearby; show only what others can reach.
- **What changed** lists the differences between readings, and its slider goes back to an earlier one. Storage is not kept, so going back shows the other layers as they stood.
- A list longer than the page shows says how many it leaves out (*+3 more*), and the same button shows the rest.
- From the keyboard, every node is a button in reading order, each host's header followed by what is in its frame: Enter shows a node's details, Enter on a host's header closes or opens it, and Space on a header shows its details.
- Exports: JSON, Mermaid, DOT, SVG, draw.io, Obsidian canvas, PNG as drawn, and PDF through the browser's print.
- **What if** answers in sentences, worst first, each starting with how much it matters (Danger, Careful, Note, Fine), and says when nothing else is affected. The technical lines are under **Details**.
- Zoom with the − and + buttons, the percentage to go back to 100%, and **Fit to screen**; `-`, `+`, `0` and `F` do the same while the map has focus. The **Legend** says in words what each colour and line style means, and each port carries a word (LAN, ANY and so on) beside its colour.

The map's layers, the paths through routers and the security mode are described in [Infrastructure map](infrastructure-map.md#on-the-map). Firewall rules and exposure need `security.view`; the map itself needs `map.view`.

## Scan

What the opt-in network scanner found. It is off until someone turns it on and names private networks (a /20 at most), and it is the one thing in StorageForge that sends packets to find out what exists. Results are grouped by the range that was scanned, in the order the ranges were named, with anything outside them last and a range that found nothing saying so. A machine StorageForge manages links to its own pages, anything else is *not managed* with **Add as a device**, and a host or port that is new since the scan before is marked, with what has gone listed at the end. See [the network scanner](network-devices.md#the-network-scanner). **Details** in the rail is not used here either.

## Panels

The rail on the right opens panels in the inspector: 18 of them in five groups. It is one tab stop: Up and Down move between the panels, Home and End go to the first and the last, and Enter or Space opens the one that has focus. A panel that is about one host (the Security panels that need one, the Infra views, what a scan changed) has its own host picker when none is chosen, starting on the host with the most to look at, and choosing sets the page's host. A skip link at the top of the page, the first thing Tab reaches, goes to the view or to the panel. **Security** and the settings panels (**Audit**, which holds accounts, roles, invites, backups and your password, **Keys**, **Scans**, **Access** and **Logs**) open with the whole page, and the button in any panel's header (⤢) gives that panel the whole page too, which the browser remembers for that panel. Hiding the panel gives the view its room back. The first panel, **Details**, describes the selection or summarises health across every host. It belongs to Topology and Graph: in Tasks, Map and Scan it says where to go instead.

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
| **Schedule** | [Unified task scheduler](plans-and-scripts.md#unified-task-scheduler): cron jobs on client hosts with comprehensive server-side verification, SSH deploy, on-demand runs and verification inspector |
| **Deploy** | [Deploy access](deployments.md) per host, deployed jobs and shares, drift, recent deploys, reporting and alert settings |

![Changes panel after Check](images/changes.jpg)

![Moves panel](images/moves.jpg)

![Deploy panel](images/deploy.jpg)

### Estate

| Panel | What it does |
| :--- | :--- |
| **Docker** | Each host's [compose stacks](scanning-and-search.md#docker-and-compose-stacks), their containers and the folders and volumes they use; unused volumes; containers that mount the Docker socket |
| **Git** | [Repositories](scanning-and-search.md#git-repositories) the scans found, matched across hosts by history, with **Archive to…**, bulk archiving of selected repositories, and a per-host hide list |
| **Rebuild** | Each host's saved configuration: mounts, subvolumes, shares, accounts, symlinks and config files, with what changed in each version. Downloads the reinstall script or a bundle. See [rebuilding a host](disaster-recovery.md#rebuild-a-host-after-reinstalling-it). |
| **Infra** | Workloads, exposure, network and firewall of each host, as they were last read: containers, VMs and instances; what listens and who can reach it; interfaces and routes; firewall rules. **Measure now**, for accounts that may manage security, reads a host again. Needs `security.view` for exposure and firewall, `map.view` for network. See [Infrastructure map](infrastructure-map.md) |
| **Cleanup** | Duplicate folders (same names, sizes and layout) and cold data (newest file older than a cutoff), each with **Move…** |
| **Malware** | [ClamAV](scanning-and-search.md#clamav) on the hosts you deployed it to: what it detected, and **Quarantine** |
| **Access** | Folders the last scan could not read, and [read-only scan access](scanning-and-search.md#unreadable-folders-and-read-only-access) to fix it |

![Cleanup panel](images/cleanup.jpg)

![Access panel](images/access.jpg)

### Security

| Panel | What it does |
| :--- | :--- |
| **Security** | [Ransomware defense](ransomware-defense.md): the posture of every host on top, then sixteen sub-panels grouped by what you are doing: **Prepare** (Holds, Retention, Access control, Firewall, Hardware keys), **Detect** (Decoys, Behaviour, Integrity, Falco and YARA, Identity), **Respond** (Fencing, Playbooks, Timeline) and **Prove** (Compliance, Dashboard). See [its panels](ransomware-defense.md#panels) |

### Admin

| Panel | What it does |
| :--- | :--- |
| **Scans** | Queue a scan of a bound host, or **Scan all hosts**, and follow recent scan jobs |
| **Keys** | Generate a key in the vault, install it on a host with its password once, list keys and bindings, **Scan now** per binding |
| **Logs** | What each host's journal said, as the last scan collected it: a time range (last hour, day, 7 or 30 days, or from and to), a bar chart of lines by level and hour with the same numbers as a list, a list of when each host was last collected (or that it never was), and filters by host, level, unit (a list of the units stored) and text that apply as you type, **Older**, and export as a file. The range and filters are in the URL (`range`, `from`, `to`, `lhost`, `level`, `unit`, `q`), and a host's Details has a link to its logs. Nothing streams: a line arrives with the scan that reads it, and a host that could not be read says why. Times are in your time zone, with the UTC form on hover. Also [`storageforge-index hostlogs`](cli-reference.md) |
| **Audit** | The newest audit entries and **Verify chain**. Also your own password, backups, and for admins [accounts, invite links and roles](features/administration.md#accounts-and-sign-in). |

![Keys panel](images/keys.jpg)

![Audit panel](images/audit.jpg)

## Other pages

| Page | What it is |
| :--- | :--- |
| `/planner` | The [storage design tool](planner.md): devices, mounts, links, RAID, protection and export. **Planner** in the header. Its rail, like `/manage`'s, leads to the main page's **Changes**, **Moves** and **Schedule** |
| `/manage` | The [management planner](network-devices.md#the-management-planner), **Manage** in the header. **Fleet** is every host and device and how it stands; **Devices** are routers, switches and firewalls; **Compose** writes the one network language, shows what each target makes of it, and **Stage in Changes** turns a Linux host's rules into steps there, or **Check** reports on a device before **Apply**; **Changes** is what was reported, applied, confirmed and rolled back; **Traffic** is interface counters over time, with a way to the Scan view |
| `/search` | File search on a page of its own, with a host picker |
| `/login`, `/enroll` | Sign-in, and the page an invite or reset link opens |

The planner, `/manage` and `/search` show the same security chip as the main page, with the links between the pages and **Sign out**: in the planner's page header and rail, in `/manage`'s rail and in the search page's header.

## Keyboard

| Key | What it does |
| :--- | :--- |
| `/` | Focus the file search. Not while typing in a field, not with a dialog open, and not with Ctrl, Alt or Meta held, so a path or a password with a slash in it arrives whole |
| `\` | Show or hide the rail's panel, under the same rules |
| Up, Down, Home, End | In the rail of panels: move between the panels, and Enter or Space opens one |
| Esc | Clear the graph focus or the file map's selection, unless a field or dialog has the key. In a dialog it closes the dialog; the share wizard asks first when something was changed |
| Menu, Shift+F10 | Open the context menu on the focused box or block, except in a text field, which keeps the browser's own |
| Ctrl or Cmd+Z, with Shift to redo | Undo in the Tasks editor |
| `+` `=` `-` `0` `f` | On the topology canvas: zoom in, zoom out, back to 100%, fit. Enter or Space selects a focused row, Esc clears the selection |
| Arrows, Home, End, Esc | In an open context menu |
| Left and Right arrows | On the panel's resize grip |
| Ctrl or Cmd+K | The command palette: type to filter, arrows to move, Enter to run, Esc to close. It lists the shortcuts and a *Go to* entry for every view and panel your account may open. Works from inside a field |
| `?` | The list of shortcuts, from the same registry |

## Git Inspector

**▾ Inspect** on a repository in the **Git** panel opens a drawer along the bottom of the page with **Status**, **Sync**, **Commits** and **Changelog** tabs. See [Git](features/discovery.md#git).

## Deep links

Every place in the main page is in its URL: `/#/<view>/<panel>?host=<name>`, for example `/#/graph/changes?host=nas-02`. `<view>` is `topo`, `graph`, `tasks`, `map` or `scan`. Copy the address from one browser and it opens on the same view, panel and host in another, and **Back** and **Forward** go where you were: each view, panel and host you choose is a step in the history. A link inside the page changes the hash and does not reload it. The planner's **In StorageForge** links use this to open a host's Changes, Moves, Deploy, Docker, Git, Cleanup or Access panel. The old form, `#host=<name>&tab=<panel>`, still works and is rewritten as the new one. `<panel>` is one of `details`, `search`, `changes`, `moves`, `schedule`, `deploy`, `docker`, `infra`, `git`, `rebuild`, `copies` (Cleanup), `malware`, `access`, `security`, `jobs` (Scans), `keys`, `hostlogs` (Logs) or `audit`.

The map says what it shows in the same address: `/#/map/details?mode=security`, or `layers=network,firewall` when no preset fits, and `filter=`. The old `#view=map&layers=…&mode=…` and `#view=scan` work too. Security's sub-panel is `sec=`, as in `/#/topo/security?host=nas-02&sec=firewall`.

The planner keeps its place the same way, `/planner#/devices?host=nas-02` (the old `#devices@nas-02` still opens), and so does `/manage`, `/manage#/compose` (and `#/devices?device=gw`, with the old `#device=gw`).

## Unsaved work

Compose's text, the steps staged on the map, change plans and the planner's designs are kept in this browser as you work, for your account only, so a reload does not lose them. A design edited in Topology, a task and a move plan are not kept anywhere until you save them: the page asks before it closes with one of them unsaved, and if your session ends first, the sign-in page says which work was kept and which could not be. **Load what it runs** in Compose asks before it replaces text you wrote.

## Passwords for host commands

Anything that runs a command on a host from the web UI (key install, scan access, deploy access, deploys, job runs and cutovers, restores) and changing your session length asks for your password again unless you typed it in the last 5 minutes. Read-only job actions (dry run, log, list snapshots) do not. The question is the same dialog on every page: on the planner and `/manage` it opens in place, and the change goes on once the password is right. A command to a host that has not been seen before first shows its SSH key to compare with the machine's own, and nothing is sent until you say they match.

## Preferences

**Preferences**, in the user menu, the header and the palette, sets the theme (system, light or dark), the density (comfortable or compact) and reduced motion. They are kept in this browser for your account only, and nothing is sent to the server. The planner's own theme button still overrides the theme on that page.

## First run

On an install with no hosts yet, the main page shows a checklist: enrol a host, run the first scan, set up a backup alert. Each item opens the panel that does it and says *Done* or *To do*. It goes away when you dismiss it (remembered for your account) or when every item is done.

## Long lists and small screens

A list that shows only its first rows says how many it leaves out and has a **Show N more** button that opens the rest in place and reads **Show fewer** after; it works from the keyboard and is announced to screen readers. Health dots and status words carry a shape or a sign (✓, !, ✕) as well as a colour. At 1000 pixels wide and below, Planner, Manage, Session and Preferences fold behind a **More** button in the header.

