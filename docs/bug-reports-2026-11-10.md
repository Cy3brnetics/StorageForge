# StorageForge Bug Reports & UX Defects (2026-11-10)

This document collects and details six verified bug reports, architectural gaps, and UI/UX issues identified during interactive testing and exploration.

> **Fixed in 0.5.1 (2026-11-11).** These reports were written before the fixes, and three of the causes they name turned out wrong when checked against the code and the live install. See the [changelog](../CHANGELOG.md) for what was done:
> - **4:** the `PermissionError` was not `mkdir` on a folder that exists. `/app` is mode 0700 for uid 10001, and the shell was root with every capability dropped, so it could not look inside. Run the CLI as the app user.
> - **5:** on the live fleet the folder comparison found 46 copies across hosts. They were sorted after 313 same-host ones and cut at 100. There were also no checksums at all: web scans never asked for them. And a file copied after one host's checksum pass never got its twin hashed.
> - **6:** not kernel modules or `daemon-reload`. The client's fstab already failed `findmnt --verify` over an unplugged USB disk's line, before the share's line was added.

---

## 1. Scanned NFS Share Context Menu "Edit…" Shows Read-Only Details Instead of Launching Share/Edit Wizard

### Summary
In the **Topology** view, right-clicking a scanned NFS export (`EXP · NFS · <path>`) and clicking **"Edit…"** selects the box and displays static read-only text in the Inspector Details sidebar (*"Found by the scan in this host's NFS exports. Change it on the host; the next scan picks it up."*). There are no editable inputs, no way to modify rules/options, and no way to launch or adopt the share into the Share Wizard (`sharewiz`), despite the context menu promising an edit action.

### Steps to Reproduce
1. Navigate to the **Topology** view (`/#/topo/details`).
2. Locate a host with an NFS share discovered via scan (e.g. node `EXP · NFS · /mnt/storage` under *Links & exports*).
3. Right-click the export node to open the context menu.
4. Click **"Edit…"**.
5. Observe the right-hand **Details** panel.

### Current Behavior
* The context menu displays **"Edit…"**.
* Clicking **"Edit…"** opens the sidebar showing:
  > *"Found by the scan in this host's NFS exports. Change it on the host; the next scan picks it up."*
  > *Mounted by: <client-list>*
* No fields can be edited and no wizard is launched.

### Expected Behavior
Clicking **"Edit…"** should launch the Share Wizard (or an Edit Wizard equivalent to `sharewiz`) pre-populated with the share's existing scan configuration, allowing the user to modify:
1. **Folder / Path:** Browse and update the exported directory path.
2. **Protocol & Access Rules:** Protocol (NFS/SMB), NFS version (`NFSv4.2` / `NFSv3`), share name, client IP/subnet rules, and export options (`rw`, `ro`, squash).
3. **Client Mounts:** Configure which client hosts mount the share and specify their mount targets.
4. **Review & Save/Deploy:** Run pre-flight validation checks, stage/adopt the share into the host's blueprint design (`doc.bp.exports`), and allow *"Save only"* or *"Save and deploy"*.

### Technical Locations
* `storageforge-indexer/storageforge_index/static/topology.js`:
  * `boxMenu()` (~line 843): Unconditionally labels the action as `Edit…` for any non-planned box (`n.planned ? 'Details' : 'Edit…'`), even when `n.kind === 'export'` is scan-only (`r.fromScan && !r.designed`).
  * Inspector Details renderer (~line 795): Renders only static read-only text when `n.kind === 'export' && n.ref.fromScan && !n.ref.designed`.
* `storageforge-indexer/storageforge_index/static/sharewiz.js`:
  * `smRow()` (~line 397): Hides the Edit button entirely for `scanOnly` exports (`scanOnly ? null : act('Edit', ...)`).
  * `openShareWizard()`: Starts at step 1 if `share` is passed, but lacks a clean pathway to adopt scanned exports into the blueprint design.

### Severity / Priority
* **Severity:** Medium (Usability / Functional Gap)

---

## 2. Audit Panel (`/#/topo/audit`) Prompts for Password Re-auth on Tab Load, but Cancelling Still Displays Audit Logs

### Summary
When an administrator navigates to the Audit tab (`/#/topo/audit`), the browser displays a modal prompting the user to *"Confirm your password"*. If the user clicks **Cancel**, the password prompt closes, but the audit log entries are still loaded and displayed in full. This creates a broken, half-functional user experience where authentication appears to be enforced, but cancellation bypasses the gate.

### Steps to Reproduce
1. Sign in as an administrator (account with `users.manage` and `audit.view` permissions).
2. Wait 5 minutes after logging in (or ensure the re-auth window has expired so `auth_at` is older than `REAUTH_WINDOW` / 300s).
3. In the main navigation / Topology view, click the **Audit** tab (or navigate directly to `/#/topo/audit`).
4. A dialog appears: *"Confirm your password: Running commands on your hosts (and changing how long sessions last) needs your password again..."*.
5. Click **Cancel**.
6. Observe the screen.

### Current Behavior
* The password dialog disappears with an error logged internally.
* The audit log entries (`#audit`) load completely and remain visible and browsable.
* The UI is in a disjointed state: the password prompt was presented as if required to view the page, but cancelling allows the user to see the audit logs anyway.

### Root Cause
1. In `storageforge-indexer/storageforge_index/static/app.js` (`loadAudit()`), `loadAudit()` immediately triggers `loadUsers()`.
2. `loadUsers()` eagerly requests `GET /api/users` to populate `#userscard`.
3. In `storageforge-indexer/storageforge_index/routes_accounts.py`, `GET /api/users` is decorated with `@password_confirmed`. When called after the 5-minute window, the server returns `403 {"error": "...", "reauth": true}`.
4. The fetch wrapper in `storageforge-indexer/storageforge_index/static/kernel.js` catches the 403 and pops the modal dialog.
5. `GET /api/audit` does **not** require `@password_confirmed` and runs concurrently. When the user clicks Cancel, only the `loadUsers()` promise rejects, while `loadAudit()` succeeds and populates the log list.

### Expected Behavior / Resolution Options
* **Recommended Fix:** Remove `@password_confirmed` from read-only `GET /api/users` (retain it on mutations: `POST /api/users`, `PUT /api/users/<name>`, `DELETE /api/users/<name>`, and `POST /reset-link`). Opening the Audit tab will load smoothly without popping an intrusive password modal just to view logs.
* **Alternative (Strict Gate):** If the entire panel must be protected, gate the tab navigation: if `confirmPassword()` fails or is cancelled, do not call `GET /api/audit`, clear the panel contents, and redirect or show a locked state.

### Severity / Priority
* **Severity:** Medium (Security UX / Consistency)

---

## 3. Estate "Cleanup" Panel is Overloaded — Needs Sub-panel Segmentation

### Summary
The **Cleanup** panel under **Estate** (`/#/topo/copies`) displays five disparate and data-heavy sections within a single continuous scroll: Duplicate Folders, Capacity Trends, Recent Scan Changes, Identical Checksum Files, and Cold Data. This creates excessive visual clutter, makes finding specific cleanup tasks difficult, and causes significant scroll fatigue.

### Steps to Reproduce
1. Navigate to the **Topology** view (`/#/topo`).
2. In the sidebar rail under the **Estate** group, click the **Cleanup** tab (`/#/topo/copies`).
3. Scroll through `#tab-copies`.
4. Observe that duplicate analysis, historical capacity graphs, scan changelogs, and cold storage candidates are all vertically stacked into a single narrow panel.

### Current Implementation Details
* Template: `storageforge-indexer/storageforge_index/static/index.html` (`#tab-copies`):
  * `#copyform` & `#copiesbox` (Duplicate folder detector)
  * `<h3>Capacity trend</h3>` & `#trendbox`
  * `<h3>What changed in the last scan</h3>` & `#changedbox`
  * `#dupesection` & `#dupesbox` (Checksum-based identical files)
  * `#coldform` & `#coldbox` (Cold data cutoff detector)
* Logic: `storageforge-indexer/storageforge_index/static/checks.js` (`loadCopies()`):
  * Concurrently calls `loadTrends()`, `loadChanged()`, `loadDupes()`, and duplicates queries, rendering everything at once into all five containers.

### Expected Behavior / Recommended Architecture
Introduce a segmented sub-navigation bar at the top of the Cleanup panel (matching the existing `.seg.sm` pattern used by Security `#sec-subnav` and Git Inspector `#gitdrawer-nav`), dividing the data into focused sub-panels:
1. **Sub-panel 1: Duplicates**
   * Duplicate folders (`#copyform`, `#copiesbox`)
   * Identical files from checksum scans (`#dupesection`, `#dupesbox`)
2. **Sub-panel 2: Cold Data**
   * Untouched folder search (`#coldform`, `#coldbox`)
   * Actions to stage data moves (*Move…*)
3. **Sub-panel 3: Trends & Changes** (or Storage Activity)
   * Capacity trend analysis (`#trendbox`)
   * Changes detected in the latest scan (`#changedbox`)

### Severity / Priority
* **Severity:** Low (UI / Usability Enhancement)

---

## 4. Cannot Enable `console` Permission in UI, and Suggested CLI Command Fails with `PermissionError` on `/app/data`

### Summary
When attempting to connect to a host via the web Console, the connection is blocked with the error: *"a binding matches <host> but does not allow 'console'. Add one with: storageforge-index vault bind --actions console..."*. However:
1. The Web UI provides no way to grant the `console` action (neither in the Key Installation form nor in the Bindings list).
2. Running the exact command advised by the UI in the container terminal crashes with `PermissionError: [Errno 13] Permission denied: '/app/data'`.

### Steps to Reproduce
1. Navigate to the **Keys** panel (`/#/topo/keys`) and install an SSH key onto a host with *"Bind this key for scans on this host"*.
2. Navigate to the **Console** view for that host (`/#/console`).
3. Select *"SSH over LAN (<IP>)"* and click **Connect**.
4. Observe the red error text:
   > *"a binding matches 10.42.0.100 but does not allow "console". Add one with: storageforge-index vault bind --actions console --key <name> --host <host|glob|cidr> --user <user>"*
5. Open a terminal inside the container to execute the suggested command:
   ```bash
   storageforge-index vault bind --action console --key Archie --host 10.42.0.100 --user archie
   ```
6. Observe the crash:
   ```text
   Traceback (most recent call last):
     File "/usr/local/lib/python3.13/pathlib/_local.py", line 722, in mkdir
       os.mkdir(self, mode)
   PermissionError: [Errno 13] Permission denied: '/app/data'
   ...
   File ".../storageforge_index/db.py", line 145, in __init__
       Path(self.path).parent.mkdir(parents=True, exist_ok=True)
   PermissionError: [Errno 13] Permission denied: '/app/data'
   ```

### Root Cause
1. **Missing UI Action:** In `storageforge-indexer/storageforge_index/static/index.html`, `#installform` only offers checkboxes for `bind` (scan) and `checksum`. In `storageforge-indexer/storageforge_index/server.py` (`api_key_install`), `actions = 'scan,checksum' if body.get('checksum') else 'scan'` hardcodes the actions, completely omitting `console` (even though `vault.py` supports it).
2. **CLI Directory Creation Bug:** In `storageforge-indexer/storageforge_index/db.py` (`Database.__init__` line 145):
   ```python
   Path(self.path).parent.mkdir(parents=True, exist_ok=True)
   ```
   When the database already exists at `/app/data/index.db`, calling `mkdir(parents=True, exist_ok=True)` on an existing directory where the executing shell user lacks write permissions to `/app` raises `PermissionError` under Python 3.13.

### Expected Behavior
1. In the Web UI Key Install form, provide a checkbox: `[x] Allow terminal/console access on this host` (binding the `console` action alongside `scan`).
2. Provide an edit control on existing key bindings to toggle `console` without needing CLI access.
3. In `db.py`, guard the directory creation with `if not Path(self.path).parent.exists():`.

### Severity / Priority
* **Severity:** High (Feature Blocker)

---

## 5. Duplicate Detection Fails to Find Cross-Host Duplicates in Both Graph (Files Map) and Browse/Cleanup Views

### Summary
When searching for or viewing duplicates across multiple hosts in both the **Graph View (Files Map)** and the **Browse / Cleanup Views**, the application fails to detect duplicate files or duplicate folders located across different hosts. It properly identifies and draws relationships for backup jobs (`k-job` / `k-backup`), but inter-host duplicate links (`k-copies`) and folder pairs never show up.

### Steps to Reproduce
1. Ensure at least two hosts are scanned and indexed with identical files or duplicate folder structures (e.g., Host A and Host B both hold identical folders/files).
2. Navigate to **Graph** view and open the **Files** sub-view (`/#/graph` -> `Files`).
3. Set the view mode to **"Browse"** or **"Duplicates"**, and set the scope dropdown to *"Across hosts"* or *"All copies"*.
4. Alternatively, navigate to **Estate** -> **Cleanup** (`/#/topo/copies`) and check duplicate folders / identical files.
5. Observe that backup jobs and relations between hosts are displayed, but duplicate links (`k-copies`) connecting Host A and Host B are completely absent.

### Root Cause
1. **SQL Host Filter Restricts the Subquery:** In `storageforge-indexer/storageforge_index/filemap.py` (`file_groups`) and `storageforge-indexer/storageforge_index/search.py` (`run_dupes`), when a host filter is present (`host`), `{hsql}` is applied inside the `HAVING count(*) > 1` subquery:
   ```sql
   WHERE x.checksum_hash IS NOT NULL AND x.file_size_bytes >= :min {hsql}
   GROUP BY x.checksum_hash HAVING count(*) > 1
   ```
   This requires the hash to appear more than once on *that host alone*. If a file on Host A only duplicates a file on Host B, `count(*) > 1` evaluates to `False`, dropping all cross-host duplicates.
2. **In-Memory Folder Twins Filter Discards Remote Mounts:** In `storageforge-indexer/storageforge_index/folders.py` (`duplicate_folders`), `mounts` is populated only with the target host's mounts when `host` is set. When iterating `index.items()`, any directory fingerprint from a remote host's mount is skipped (`if mid not in mounts: continue`).
3. **Frontend Browse Node Assignment:** In `storageforge-indexer/storageforge_index/static/filemap.js`, lazily loaded folders in Browse mode do not assign `.folder` from `FM.folderBy`, preventing `fmFilesOf()` from finding duplicate records and drawing amber lines between host cards.

### Expected Behavior
1. Checksums and folder fingerprints must be matched globally across all indexed hosts, restricting only the outer display results to the selected host if a filter is active.
2. Yellow/amber dashed duplicate lines (`.ln.across`) should connect cards across host columns whenever folders or files share identical contents.

### Severity / Priority
* **Severity:** High (Core Feature Broken)

---

## 6. Race / Ordering Bug in Share Mount Script Causes `findmnt --verify` Conflict on First Run, Self-Resolving on Second Run

### Summary
Deploying an NFS or SMB share mount to a client host (e.g. `cachyos-x8664`) fails on the first attempt with:
`conflict findmnt --verify complains about /etc/fstab; the backup is /etc/fstab.storageforge-<timestamp>`
However, running the exact same deployment a second time succeeds (`ok fstab line` -> `ok mounted`).

### Steps to Reproduce
1. Configure an NFS or SMB share on a server (e.g. `thinkingrock01` sharing `/mnt/data01`).
2. Add a client mount for `cachyos-x8664` at `/mnt/net/data01-tr01`.
3. In the **Deploy** tab, start the share deployment and click **Apply**.
4. Observe the failure on the first run (`conflict findmnt --verify complains about /etc/fstab`).
5. Run the deployment a second time.
6. Observe that the second run passes and successfully mounts the share.

### Root Cause
In `storageforge-indexer/storageforge_index/shares.py` (`client_mount` lines 898-920):
1. **Asymmetric Validation:**
   * When `/etc/fstab` already has the expected line (`if [[ $have == "$line" ]]`), the script marks it `ok "fstab line"` and **does not** run `findmnt --verify`.
   * When `/etc/fstab` does not have the line, it appends it and immediately runs `findmnt --verify --tab-file /etc/fstab`.
2. **Missing Module / Reload Timing:**
   * On modern systemd/Linux distributions (such as CachyOS/Arch), running `findmnt --verify` immediately after appending to `fstab` triggers errors if:
     * Kernel filesystem modules (`nfs4`, `cifs`) have not been loaded or probed yet.
     * `reload_systemd` (`systemctl daemon-reload`) has not yet informed systemd of the updated mount table.
3. **Partial State Left Behind:**
   * When `findmnt --verify` fails on line 915, it outputs `conflict`, but does **not** roll back `/etc/fstab`.
   * Because the line remains in `/etc/fstab`, the **second run** takes the `[[ $have == "$line" ]]` path, skips `findmnt --verify`, and successfully executes `mount_share "$t"`.

### Expected Behavior / Recommended Fix
1. Probe the filesystem module (e.g. `modprobe nfs4`) before invoking `findmnt --verify`.
2. Run `reload_systemd` before verification so systemd generator units are active.
3. Capture the diagnostic stderr output from `findmnt` so failures are understandable, and cleanly restore the backup file if verification fails rather than leaving partial edits.

### Severity / Priority
* **Severity:** High (Intermittent / First-Run Deployment Failure)
