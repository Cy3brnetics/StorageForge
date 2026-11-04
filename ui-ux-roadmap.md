# UI and UX roadmap

How the screens should change, in order. [roadmap.md](roadmap.md) says what features are left to build and [progress.md](progress.md) says what is built. This page is about the screens that carry them: how they are organised, how they behave, and how the planner grows to match the rest of the platform. The evidence, with a number for each finding, is the [UI audit of 2026-11-04](docs/audit-2026-11-04-ui.md), and `UX-nn` below refers to it. **This page decides what to do about the audit, and the audit doesn't.**

Checked against the code on 2026-11-04.

## How to read this

The phases run in order because each makes the next cheaper, but any phase can stop at any item without harming the others, as in the main roadmap. Days are rough guesses and none has been measured. Each phase ends with an **Exit** that a test or a person can check. An item marked *needs API* wants a server change. The rest use endpoints that exist today.

| Phase | Days | What you get |
| :--- | :--- | :--- |
| 0. Small and sure | 6 to 8 | The rail, planner focus, "offsite" and the copy fixed, with tests holding them |
| 1. One kernel | 15 to 19 | One `api()`, one dialog, one vocabulary, one place for shortcuts; no native dialogs; the security banner on every page |
| 2. Routes and workspaces | 22 to 28 | URLs that mean something; Security and Settings with room; one Plan; a map you can reach by keyboard |
| 3. The planner grows | 35 to 45 | Design a host that doesn't exist yet and see what it means for shares, networks, workloads, security and logs; one review |
| 4. Map, Compose, Scan, Logs | 26 to 32 | A map with space, an editor for the network language, Scan and Logs as real views |
| 5. Polish and scale | 8 to 12 | Preferences, `Ctrl+K`, a first-run checklist, colour never alone, long lists |

All of it is about 110 to 145 days. **A first cut of about 45 to 50 days** is phase 0, phase 1, and steps 3a, 3b, 3c and 3h: no known defects, one kernel, and a planner that can design a host and say who could reach its shares. If you do only one thing, do phase 0.

## Principles

They settle arguments about the screens, the way [concepts](docs/concepts.md) does for the code.

1. **Say what is known.** *Not measured*, *inferred* and *out of sight* stay. Every new view shows where its facts came from and how old they are.
2. **One pipeline.** Anything that changes a machine goes through the same report, check and apply component. No screen grows its own variant.
3. **Wide work gets wide space.** Consoles and editors (security, settings, the map, Compose) are workspaces. The rail is for glanceable state and small forms.
4. **Reachable without a mouse, and by a screen reader, or it isn't done.** The target is WCAG 2.2 AA, and tests hold it.
5. **No third-party code and no build step.** The strict CSP stays. Native ES modules and one stylesheet are enough.
6. **Nothing streams.** The main roadmap says StorageForge builds no live log viewer, and that holds here: Logs stays "as of each host's last scan", and refresh is by scan.

## 0. Small and sure (about 6 to 8 days)

Defects with no design decision in them. Each is an afternoon or less, and each leaves a test behind.

| Item | Audit | Detail |
| :--- | :--- | :--- |
| **The `/` shortcut stops eating typing** | UX-40, 41 | Guard it the way the backslash shortcut already is (not in a text field, not with Ctrl, Alt or Meta held) and also not under an open dialog. Do this first, because it is a few lines and today it swallows slashes in paths and in passwords. A test types `/mnt/x` into a field and `pa/ss` into **Confirm your password** and expects both to arrive. The same rule goes on the `Menu` key and `Shift+F10`, which open the app's menu from inside a text field today, the backslash shortcut learns to leave an open dialog alone, and Escape in the share wizard and the Shares manager asks first when something was edited |
| **The rail says what it hides** | UX-01 | A visible overflow cue (a fade and a chevron, or a scrollbar), the group labels at a size that can be read, and the Inspect and Plan groups collapsible. At 1366×768 a person can tell there is more, and Security and Logs are one click away |
| **A quieter header** | UX-02 | `Export .canvas` becomes a secondary button shown only where it applies (Topology and Graph), so the header has no primary button competing with the navigation |
| **Planner focus** | UX-18 | Keep focus and caret across `render()` by field id. A test tabs out of an edited field and expects the next one |
| **"Offsite" from data** | UX-32 | `copies321()` reads `backup.offsite` and the host's offsite mark, never a name. Unknown reads "not stated". The Status pill and the 3-2-1 column agree |
| **Say what is cut** | UX-13 | "+3 more", with a way to see them, in Details and in the map's lists |
| **Copy that fits the screen** | UX-14, 09 | A Details hint for each mode; one name for the map's Storage; Compose's button says Check or Stage; the banner always reads "Security: …" and shows its detail without a hover |
| **Scan by what was scanned** | UX-29 | Group by the configured ranges, anything else under "other", IPv6 safe |
| **Contrast tokens** | UX-19 | `--faint` to 4.5:1, the rail's group labels at 10 px with no opacity, the light theme's Access badge |
| **A latest-wins guard** | UX-12 | Search, Logs, Infra and Scan, using Security's `turn` pattern as a helper |
| **No Scanner stub** | UX-28 | Remove the `/manage` view that only links to the Scan tab |
| **The Web UI page** | UX-39 | Five views, 18 panels, the planner and Manage |

**Exit:** typing `/mnt/x` into a text field types it, and a password with a slash can be typed into **Confirm your password**; at 1366×768 the rail shows there is more; Tab out of an edited planner field lands on the next one; `tank/media` in the example no longer reads offsite with no backup target; every text token passes AA; `docs/web-ui.md` lists every view and panel. Each of these is a check in `tests/test_browser_smoke.py`.

## 1. One kernel (about 15 to 19 days)

Everything after this is cheaper once the three pages share what they should share.

| Item | Audit | Detail |
| :--- | :--- | :--- |
| **One `api()`** | UX-23 | 401, re-authentication, host-key confirmation, the error shape and a latest-wins option in one module. The planner and `/manage` re-authenticate in place, and their own wrappers and dialogs go |
| **One dialog component** | UX-10 | `confirmDialog` lists what will happen, has a danger style, and asks for the name to be typed for what cannot be undone (retiring a host, deleting a plan). `formDialog` takes what `prompt()` asks today: scan interval, quiet hours, keep counts, `user@host`. All 39 native calls go |
| **Announce and show busy** | UX-11 | A live-region helper and a busy state for buttons and lists, used by every save, dry run and load |
| **One vocabulary** | UX-22, 25 | A tokens file and a components file (button, pill, chip, card, field, table, dialog, toast) with a type and spacing scale. `style.css`, `planner.css` and `manage.css` keep layout only. Old class names are aliased first, so pages move one at a time |
| **One time policy** | UX-16 | Local time with the UTC form on hover, or the reverse, from one formatter, and one bytes formatter |
| **Shared chrome** | UX-09, 03 | One top bar (brand, site, host, the security banner, session, the links into Plan) on `/`, `/planner`, `/manage` and `/search` |
| **One place for shortcuts** | UX-40, 41, 20 | A small registry where every global shortcut declares itself, with one rule for "someone is typing" (text fields, open dialogs, modifier keys) applied to all of them (the `/`, backslash, `Menu`, `Shift+F10`, Escape and Ctrl+Z handlers move into it), so the next shortcut cannot repeat UX-40. The `?` overlay in phase 5 is generated from it |
| **Native modules** | UX-23 | `type="module"` under the current CSP, file by file, with a global shim while it is half done. The `typeof f === 'function'` guards go as each file moves |
| **Safer work in progress** | UX-15 | Compose and the map's staged steps survive a reload; one "unsaved" rule for every editor; the expired-session page keeps what can be kept and says what could not |

**Exit:** a search finds no `confirm(`, `alert(` or `prompt(` in `static/`; `/planner` and `/manage` show the security banner; every page uses one `api()`; the planner can re-authenticate without leaving; a test fails when a page defines its own fetch wrapper; no global shortcut is registered outside the shortcut registry.

## 2. Routes and workspaces (about 22 to 28 days)

| Item | Audit | Detail |
| :--- | :--- | :--- |
| **A router** | UX-08 | `#/view/panel?host=…` with `hashchange`, so Back works, a copied URL lands where it was copied, and the `location.reload()` in the Scan view goes. The planner's `#view@host` becomes one of the routes. Old links keep working |
| **A rail that matches what is in it** | UX-05, 20 | Regroup as **Inspect** (Details, Search), **Plan** (Changes, Moves, Schedule, Deploy), **Estate** (Docker, Infra, Git, Rebuild, Storage hygiene), then **Security** and **Settings** as workspaces. Panels become real `tabpanel`s, the rail takes arrow keys, and there is a skip link |
| **Security is a workspace** | UX-04 | Full width, with the posture line on top, which is what today's Overview becomes. A first grouping of the other 15 sub-panels, to check against how they are used: *Prepare* (Holds, Retention, Access control, Firewall, Hardware keys), *Detect* (Decoys, Behaviour, Integrity, Falco and YARA, Identity), *Respond* (Fencing, Playbooks, Timeline) and *Prove* (Compliance, Dashboard). When posture is *Incident* the page leads with blast radius, quarantine and the brake. The rail keeps a summary and a link |
| **Settings is a workspace** | UX-04, 05 | Accounts, roles, invites, your password, backups, the audit log, keys, scan access and scans, with fields at a readable width |
| **The planners under one roof** | UX-03 | One **Plan** workspace with *Design* (today's planner), *Network and devices* (today's `/manage`), *Changes*, *Moves*, *Schedule* and *History*. `/planner` and `/manage` stay as entry routes. One name for each, and one way into Changes |
| **The map by keyboard** | UX-17 | A first step: every node a button in reading order, Enter opens its details, Enter on a host expands it, and `role="img"` goes. The list twin and the rest of the overhaul are in phase 4 |
| **A host picker where it is needed** | UX-07 | A panel that needs a host carries its own picker, and opens on the host with the most findings rather than saying "pick a host at the top of the page" |
| **Decide the canvases** | UX-06 | See *Decisions*. Whichever way it goes, one line in the UI says which view to use for what |

**Exit:** a URL copied from one host's Firewall panel opens the same panel in another browser; Back returns to the previous panel; Security opens full width; every field in Settings shows its label and a readable value; every map node can be selected from the keyboard; the rail passes a keyboard and landmark check.

## 3. The planner grows (about 35 to 45 days)

The planner designs storage only. The platform now knows networks, shares, workloads, security and logs, and the planner should show what a design means for each of them, then hand a checked plan to the pipeline that already exists. Each step is useful alone, and most use endpoints that exist. The table in the [audit](docs/audit-2026-11-04-ui.md#the-planner) shows what the platform knows against what the planner shows.

| Step | Audit | What it adds |
| :--- | :--- | :--- |
| **3a. Design what isn't there yet** | UX-31 | Add, edit and remove a planned disk, partition, pool, remote mount and export. Planned things are drawn dashed, as the map draws ghosts. A pool is created from the RAID calculator's answer, and a partition editor sees free space. The change plan covers the task types that exist and the rest stays under *By hand*. ZFS and mdadm pools as steps wait for `pooldef` in [roadmap.md](roadmap.md) §2 |
| **3b. Shares as first-class** | UX-31 | A Shares view: designed and found shares together, the share wizard and its checks embedded, deploy state, and the clients that mount each one |
| **3c. The network lens** | UX-34 | *Reachable from* on every export and remote, naming the deciding rule and what is out of sight (`/api/map/reach`, `/api/map/exposure`). A Network tab with the host's interfaces, bridges, VLANs, MTU and routes (`/api/network`), and validated forms that stage the `net-*` and `fw-rule` steps with the map's ghost preview and conflict list. Where Traffic is on, the interface rates behind a mount. Warnings such as "this NFS export is open to any address" |
| **3d. The workloads lens, and placement advice** | UX-35 | Which containers and VMs sit on each mount (`/api/workloads`); a dependency preview before an edit ("changing `/mnt/x` touches 3 containers and a VM"); guardrails for the placement advice the main roadmap promises (a database on bulk storage, a bind mount on a network filesystem, a Docker root on a slow disk, a stateful stack beside its own backups); service drop-ins from services found on the host, not a fixed list |
| **3e. The security lens** | UX-33, 36 | Every protection cell says *observed*, *declared* or *simulated*, and a what-if mode never saves. New columns for retention tier, hold, immutability, decoys and quarantine reach (`/api/map/coverage`), with *not measured* wherever nothing was read, and links to Security for the action |
| **3f. The health lens** | UX-37 | *Related log lines* on a device, pool or mount, as a link into Logs with the unit or device filled in; the capacity trend as a sparkline on Overview |
| **3g. Compare and adopt** | UX-38 | Per object: missing, different, extra, not read, as the map's design compare does. Adopt one object from the scan instead of refreshing everything. A list of saved versions, restorable (*needs API*) |
| **3h. One review** | UX-38 | The planner's change plan, the map's what-if, `/manage`'s report and Security's dry run become one **Change review** component: plain-language steps (the planner's `taskLabel`), destructive marks, exposure and conflict lists, and, for a step that could cut StorageForge off, the rollback timer and the warning `/manage` gives today, then Stage. The `localStorage` relay to Changes goes |
| **3i. One design document or two** | UX-03 | See *Decisions*. Depends on 3a to 3h |

**Exit:** on a design for a host that does not exist yet, add three disks, make a raidz1 pool from the calculator, add a dataset and an NFS share, see who could reach the share and which containers would sit on it, stage the checked plan, and open it in Changes with the same wording, without leaving the planner until the deploy.

## 4. Map, Compose, Scan and Logs (about 26 to 32 days)

| Item | Audit | Detail |
| :--- | :--- | :--- |
| **A map with room** | UX-26, 17 | The toolbar becomes three groups (what to look at, what to show, filter) and an Export menu, so the canvas gets the screen. A selected node's details move to the shared Details panel and the staging forms into a drawer. A list twin of the same data, which is also how a 200-host fleet is read. Time travel and the redaction switch stay |
| **The map's planning tools say what they do** | UX-27 | What-if steps in plain words; staging forms check their fields before asking the server; staged steps survive a reload; the three requests behind a load run together |
| **Design mode that starts from what was read** | UX-27 | A form editor and a "start from what was read" button (*needs API*), with compare, stage and export as today |
| **Compose as an editor** | UX-28 | Line numbers, highlighting for the language, unsupported lines marked in the margin, snippets and a form for the common rules (allow, forward, NAT). A diff against what the target runs now in place of the overwrite, saved drafts, the what-if prefilled from the rules written, and *paths that must stay open or stay blocked* checked on every edit (*needs API*). One change history for devices and hosts, from one request |
| **Scan as a table and a diff** | UX-29 | A table or grid, sort and filter, a diff against the last scan with the new and gone listed, and an action on every unmanaged machine. Scan results as map placeholders and scanner findings through alerts are in [roadmap.md](roadmap.md) §6 |
| **Logs as a view** | UX-30, 37 | A full-width view with a time range, a per-host freshness list, filters that apply as you type, the query in the URL, UTC or local on a switch, and entry points from a host, an alert, a mount and a device. Counts by level and hour need *a small API*. Still no tail and no stream |

**Exit:** the whole map can be operated from the keyboard; Compose marks the line that cannot be written for the target; every host in a scan has an action; a link from a failing disk opens Logs filtered to it.

## 5. Polish and scale (about 8 to 12 days)

| Item | Audit | Detail |
| :--- | :--- | :--- |
| **Preferences** | UX-25 | Theme (auto, light, dark) and density (comfortable, compact), remembered per browser |
| **Find and jump** | | `Ctrl+K` to any host, panel or common action, built on the router; a `?` overlay generated from the shortcut registry |
| **First run** | | The empty states become a checklist: scan access, a key, a first scan, a deploy |
| **Colour is never alone** | UX-21 | A shape, pattern or icon with every status colour in the canvases |
| **Long lists** | | Windowed rendering for Logs, the map's list and the Scan table, checked at the roadmap's synthetic 200 hosts and 2,000 workloads |
| **Tablet** | | The header collapses to a bar and a menu below 1000 px, so it stops taking 245 px at 390 px |

**Exit:** `Ctrl+K` reaches any host or panel in a few keystrokes; density and theme persist; the browser test draws the synthetic fleet inside its budget.

## Needs a feature from roadmap.md

| Step here | Needs |
| :--- | :--- |
| 3a, ZFS and mdadm pools as steps | `pooldef` and `netdef` (§2) |
| 3d, placement advice | Placement advice, "the differentiator" (§3) |
| 4, Compose with positions | A rule at a position, `place-before` (§6) |
| 4, Scan | Scan results as map placeholders, scanner findings through alerts (§6) |
| 4, the map | The map extras under *Later*: force-directed and rack layouts, custom icons, per-role views |

## Not audited

The Files map, Git, Docker, Rebuild and the folder browser were not read (see the audit's scope). They ride along with phases 1 and 2, which give them the shared dialogs, tokens and routes, and a short follow-up audit should read them.

## Will not be built

A framework, a build step, a CDN or any third-party script, because the strict CSP and the offline promise are features. A live log tail or any push channel, for the reason the main roadmap gives. Telemetry about how the UI is used. A mobile-first redesign: this is a tool for a desk, or a tablet in a server room, and phase 5 only stops it breaking. A dashboard builder: the Security dashboard stays a fixed set of tiles.

## Decisions still open

| Decision | Recommendation |
| :--- | :--- |
| **One shell, or keep three pages?** | One shell with routed workspaces, reached in steps: shared chrome in phase 1, then the router and the Plan workspace in phase 2. The three pages stay as entry routes. A big-bang rewrite is not on the table |
| **Native modules?** | Yes, under the current CSP, one file at a time. No bundler |
| **What becomes of Graph, Structure?** | Keep **Files**, which nothing else does. Retire **Structure** once the map's Storage layer has time travel and a focus-by-hops view, so decide after phase 4 |
| **Names** | **Plan** for the workspace, **Design** for the storage tool, **Network and devices** for the other; drop "Manage" |
| **One design document, or two?** | Two documents share a word: the storage blueprint, and the map's design (hosts, networks, workloads, firewall). They should become one per host with sections, with the planner as its editor and the map showing it as ghosts. That is server work, so first ship 3a to 3h on the two as they are |
| **An accessibility target** | WCAG 2.2 AA, stated in [concepts](docs/concepts.md) and held by a check in `test_browser_smoke.py` |
