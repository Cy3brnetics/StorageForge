# Backend consolidation survey, 2026-11-26

A read of the whole backend looking for one thing: places where two or more features each carry their own implementation of the same job and could share one. It is the evidence behind the [0.7.0 roadmap](../roadmap-0.7.0.md), whose item numbers (`BE-nn`) head the sections below.

**Scope.** Branch `t3/combine-backends` at `a9bdc3a` (0.6.1). All of `storageforge-indexer/storageforge_index` (about 230 modules and 90,000 lines) and the three Rust crates (`wire`, `enclave`, `agent`). The web UI's JavaScript was not read.

**Method.** The modules were split into nine areas (platform APIs, network devices, shares and file movement, the change engine and its steps, the agent and logs, the Toolbox and workloads, keys and overlays, the web and CLI layer, security and the map). One reader per area listed candidates with the lines of every copy. A second reader per area then tried to refute each: it opened every cited line, looked for the differences the first had missed, and said what would break. A tenth reader swept the package for small helpers defined many times and compared the Rust crates; **its candidates were not checked by a second reader** and are marked *unchecked*. Nothing was run: this is a reading.

**Result.** 107 candidates. The second readers found the duplication real in all but three and worth combining in about two thirds. Their most common correction was size: the first readers' estimates of lines removed were two to five times too high, because most copies differ in a message, an error type or a default that has to stay. Ten candidates turned out to hide a bug in one copy that the others don't have; those are the roadmap's 0.6.2.

Each section gives the copies, what the second reader corrected, and the smallest first commit it named. Paths are relative to `storageforge-indexer`.

## 0.6.2: What the survey found broken

### BE-01. A certificate that changes, or a connection that loses its pin, in the middle of a platform read stops the read for every platform. Today six readers record it as a skipped line and store the rest as a good reading

**Survey record `api3`**: One guarded reading loop for every platform reader, so a changed certificate or an unpinned connection is never swallowed as a skipped line

Copies:

- storageforge_index/apixo.py:253-271 CALLS table + loop: feature gate, client.get, parse, `skipped.append(f'{feature}: {exc}'[:200])`
- storageforge_index/apitruenas.py:330-357 the same CALLS table + loop for JSON-RPC
- storageforge_index/apipangolin.py:219-229 the same loop as an inline tuple
- storageforge_index/apidockhand.py:170-175 INVENTORY table and :242-255 the same loop per environment
- storageforge_index/apipbs.py:124-147 and :148-153 the same loop per datastore and per job kind
- `return objs, list(dict.fromkeys(skipped))` nine times: apipve.py:192, apipbs.py:154, apipdm.py:109, apixo.py:282, apitruenas.py:368, apidockhand.py:259, apiportainer.py:233, apikomodo.py:240, apipangolin.py:237
- `except (CertificateChanged, NotPinned): raise` before `except ApiError` only at apipve.py:156, apipbs.py:117 and :130, apidockhand.py:212 and :247
- the same pattern WITHOUT that guard: apipve.py:181, apipbs.py:103 and :152, apipdm.py:100, apixo.py:270 and :280, apitruenas.py:349, :362, :366, apiportainer.py:225 and :231, apikomodo.py:234, apipangolin.py:228 and :233
- cap counting written four ways: apipve.py:184-189 (MAX_BACKUPS), apipbs.py:125-142 (MAX_SNAPSHOTS), apipdm.py:103-107, apitruenas.py:199/214/354-356 ('cut'), apipangolin.py:182-190 (_pages)
- storageforge_index/apiread.py:68-75 only an exception that escapes read() is recorded as a failure; otherwise store_objects replaces the last good objects and read_ok = 1

The second reader (M, medium risk): The bug is real and I confirmed the mechanism: CertificateChanged and NotPinned subclass ApiError (apiconn.py:91-102), Client._once reconnects and re-checks the pin on every request (:617-618, :549-553), and the unguarded `except ApiError` sites turn it into a skipped line. All cited guarded/unguarded line numbers are correct. Worse than the finder says: with Xen Orchestra, Pangolin or Portainer a change right after the read-back makes EVERY later call fail into 'skipped', read() returns an empty list, apiread.store_objects (apiread.py:34) deletes all objects of the last good read and sets read_ok = 1 with no cert_offered, contradicting the module docstring ('the objects of the last good read stay'). The same swallow exists in the read-backs (apireadback.py:139, apikomodo.py:188/199/209, apiportainer.py:174/181/194, apixo.py:246, apidockhand.py:221/226), which the finder put under another candidate. Corrections: (1) TrueNAS is not affected: WsClient checks the certificate once in _open and keeps one socket (apiconn.py:801-803), so its three unguarded sites cannot see CertificateChanged mid-read. (2) The collector is not the smallest fix and does not cover read-backs; a client-side sticky flag fixes the whole class in about 8 lines without touching nine readers. (3) LOC estimate 110 is high: each site shrinks from 4-5 lines to 1-2 with a lambda; expect 30-45 net after the helper. (4) Cap accounting is not one behaviour: PBS stops REQUESTING once the cap is hit and slices (apipbs.py:125-142, counts across namespaces, message 'snapshot limit of N reached'); PVE and PDM only break the inner loop and keep fetching every remaining storage/datastore (apipve.py:184-187, apipdm.py:103-105), spending budget; TrueNAS caps inside the parser with limit N+1 (apitruenas.py:194-199, :347); Pangolin caps pages (apipangolin.py:182-190). A shared capped() must not silently pick one. No test asserts any cap wording (grep of tests/test_api*.py), so wording can be unified; tests do assert prefixes of error lines ('local volumes:' test_apidockhand.py:89, 'store1 groups:' test_apipbs.py:74, exact lists at test_apipve.py:108, test_apipbs.py:89, test_apipdm.py:60). (5) Per-call policies the helper must allow: silent drop for Ceph (apipve.py:158), PBS config failure continues with config = {} (apipbs.py:103-105), XO backup-logs post-processing inside the try (apixo.py:273-281), Komodo parse inside the loop body.

First commit: Bug fix first, no reader edits: in storageforge_index/apiconn.py have Client._connect remember the CertificateChanged it raises (self.fatal = exc); in storageforge_index/apiread.py read(), after apireadback.readback() and again after mod.read(), `if client.fatal: raise client.fatal` inside the existing try so record_failure stores cert_offered and the last good objects stay. Add one test in tests/test_apiconn.py (or test_apixo.py) using tests/apifake.py that swaps the certificate after the read-back and asserts state 'certificate-changed' and unchanged platform_objects. The Reading collector is a second, separate, purely cosmetic commit per reader.

### BE-02. A Xen Orchestra host with no address is no longer matched to whichever scanned host has no address either

**Survey record `api6`**: One resolver from a platform's node, environment, site or URL to the scanned host it is, in place of five hand-written name and address matchers

Copies:

- storageforge_index/apiviews.py:19-24 _hosts(): full name and short name, lower-cased; :27-33 host_of_node()
- storageforge_index/apidockhand.py:263-274 host_of_environment(): _hosts + its own by_ip map + name/short/IP lookup written twice on :272-273
- storageforge_index/apixo.py:286-295 _host_map(): _hosts + its own by_ip map, built WITHOUT the `if ip` filter the Dockhand copy has (:290 vs apidockhand.py:269)
- storageforge_index/apipangolin.py:241-257 site_hosts(): the name/short lookup again, written twice on :254-255
- storageforge_index/apiconn.py:225-231 host_for(): matches hostname, ssh_host, ip_address and short name against the URL's host
- outside the cluster, the same map: storageforge_index/graph.py:345 (peers: name, short name, ip), storageforge_index/jobs.py:774 (hostname, ssh_host, ip_address), storageforge_index/notifications.py:58-59 known_hosts()

The second reader (S, medium risk): The five in-cluster matchers exist as cited and the XO defect is real: apixo.py:290 builds by_ip with (ip or '') and no `if ip` filter, and :294 looks up (address or ''), so an XO host with no name match and no address resolves to whichever scanned host has an empty ip_address (the Dockhand copy at apidockhand.py:269 has the filter). The N+1 is real and larger than stated: host_of_environment runs two queries (_hosts and by_ip) per CONTAINER via panel_containers (apidockhand.py:290), and panel_containers runs once each for compare, workloads and map_nodes, and workloads() runs on every Workloads listing through apiviews.managed_by_host (workloads.py:127). Corrections: (1) 'Every platform gains matching by ssh_host' is a behaviour change, not a consolidation; ssh_host is a connect address/alias, and only apiconn.host_for matches it today. Keep it out of the first commits. (2) The matchers are not symmetric and a single find() must keep each rule: _hosts-based callers shorten the CANDIDATE (v.split('.')[0]) so 'nas1.lan' matches host 'nas1'; host_for shortens the HOST name only, so 'nas1' matches host 'nas1.lan' but not the reverse, and it returns the first row in table order that matches by any key, while the others try name, then short, then ip across all hosts. Shortening an IP candidate ('10.0.0.5' -> '10') already happens in the Dockhand and Pangolin copies and would match a host literally named '10'; preserve or fix deliberately. (3) Pangolin has no address to match and resolves local sites to row['host'] first; Dockhand resolves socket environments to row['host'] first; host_of_node's single-node fallback is unrelated to name matching and should stay where it is. (4) graph.py:345, jobs.py:774 and notifications.py:58 are outside the cluster, build differently shaped maps (graph includes ip and `if k`; notifications is full-name only) and should not be pulled in. (5) LOC removal is closer to 15-20 than 45. Risk is medium, not low: this decides which host a container or VM is attributed to, which feeds wlmanaged's 'managed by' warnings before plan steps.

First commit: Two tiny commits. First, in storageforge_index/apixo.py:290 add `if ip` to the by_ip comprehension and guard the lookup so an empty address is not looked up (bug fix, add a case to tests/test_apixo.py with a scanned host that has no ip_address). Second, in storageforge_index/apidockhand.py make panel_containers resolve each environment once (a dict env ref -> host built before the container loop) instead of calling host_of_environment per container; results identical, queries drop from 2 per container to 2 per environment. The shared HostIndex comes after these.

### BE-03. An NVMe over TCP share formats a disk only when `blkid` says it is blank (exit 2), as iSCSI and NBD do. Today any probe that prints nothing, a read error included, is taken as blank

**Survey record `shares4`**: The three block-disk share kinds (iSCSI, NBD, NVMe over TCP) each implement the sparse image file, the blank-disk format decision and the one-client rule; share one implementation.

Copies:

- storageforge_index/share_iscsi.py:66-76 image: create sparse, grow, refuse to shrink
- storageforge_index/share_nbd.py:68-78 nbd_image: the same three cases with other wording
- storageforge_index/share_nvme.py:134-141 image: create only, never grows (says so), no shrink check
- storageforge_index/share_iscsi.py:246-258 blkid -p exit status 2 means blank, then mkfs, then TYPE and UUID checks
- storageforge_index/share_nbd.py:154-165 the same decision by blkid exit status inside the client helper
- storageforge_index/share_nvme.py:214-218 formats when blkid prints nothing, without telling exit status 2 from an error
- storageforge_index/share_iscsi.py:348-350, storageforge_index/share_nbd.py:318-320, storageforge_index/share_nvme.py:331-334: the same more-than-one-client crit in Python
- storageforge_index/share_iscsi.py:361-365, storageforge_index/share_nbd.py:340-343, storageforge_index/share_nvme.py:351-354: the same format note per mount
- storageforge_index/share_nbd.py:219-232 and storageforge_index/share_nvme.py:259-272: the same oneshot helper-script unit (ExecStart helper start / ExecStop helper stop)
- storageforge_index/share_nbd.py:196-199 and storageforge_index/share_nvme.py:249: module loaded now and at boot via a modules-load.d file

The second reader (S, high risk): Confirmed: share_nvme.py:214 runs `mkfs.$FORMAT` whenever `blkid -p` prints nothing, with no look at the exit status. iSCSI (share_iscsi.py:246-254) and NBD (share_nbd.py:154-163) format only on exit 2 and treat any other failure as an error. blkid also prints nothing on an ambivalent probe (exit 8) or a usage or read error (exit 4), so NVMe can format a disk that holds conflicting signatures. That is the one part worth doing, and it is a bug fix, not a neutral refactor.

The rest is weaker than described:
- Image functions differ on purpose and in every message: iSCSI says GiB and uses act ("would: ..."); NBD says GB, adds resize advice and chowns to the nbd-server user; NVMe never resizes by design (share_nvme.py:138) and can export a real device. A shared disk_image needs a grow flag, a unit word and message variants; little is removed.
- Embedding differs: NBD writes its helper with `declare -f nbd_run` plus %q variables; NVMe uses a quoted heredoc (nvme_client_sh); iSCSI decides at deploy time and bakes the UUID into a unit. A shared function must be embeddable both ways and must not use ok, conflict or act, because the helper runs at boot without StorageForge. iSCSI's version does use act and conflict, so iSCSI cannot share the same function.
- Changing helper or unit text sets changed=1 and restarts the unit on the next deploy. That unmounts and remounts every NBD and NVMe disk in use, once per host after upgrade. The finder did not mention this.
- Helper units differ: NBD runs `$helper start`, timeout 120, [Install] only when automount is on, and uses start instead of enable; NVMe runs `/bin/bash "$script" start`, timeout 90, always enabled.
- After formatting, iSCSI also requires TYPE and UUID to be well-formed (not-a-filesystem conflict); NBD mounts by device when there is no UUID; NVMe fails when there is no UUID.
- Python: the three more-than-one-client messages have different wording and different zero-mount handling (iSCSI warns, NVMe is crit, NBD nothing); NBD's default format is ext4. A BlockDriver base class removes about 10 lines and has to keep three texts.

Realistic removal is 20 to 30 lines; the value is the mkfs rule.

First commit: A fix confined to one file, since no behaviour-preserving change removes the bug: in nvme_client_sh (share_nvme.py:214) take the exit status of `blkid -p`, format only on status 2 with FORMAT not none, and fail with a message on any other non-zero status, as share_nbd.py:154-163 does. Add a case to tests/test_share_nvme.py with a fake blkid that exits 8 and one that exits 4. Say in the commit that the helper text changes, so each NVMe mount restarts once on the next deploy. Extract a shared blank-disk function for NBD and NVMe only after that.

### BE-04. The tunnel, overlay, restore-test and Toolbox steps reload systemd through `reload_systemd`, so a dead hard NFS or CIFS mount can't make them block logins

**Survey record `steps9`**: One systemd unit writer for steps: write if different, reload safely, enable, start or restart, confirm it stayed up

Copies:

- storageforge_index/steps_tunnels.py:55-66 tun_unit_stop and tun_unit_start (already reused by steps_overlay, see steps_overlay.py:46)
- storageforge_index/rclone.py:119-131 the same write-if-different, reload, enable/restart inside rc_mount_unit; rclone.py:134-140 rc_drop_unit
- storageforge_index/steps_restoretest.py:109-120 service and timer written if different, reload, enable --now; :88-91 removal
- storageforge_index/steps_toolbox.py:174-179 and :376-377 a socket drop-in written and removed with its own reload
- scriptkit.py:65-77 reload_systemd exists because a plain daemon-reload blocks logins when a hard NFS/CIFS mount is dead; rclone uses it (rclone.py:123, 139) while steps_tunnels.py:57 and 62, steps_restoretest.py:90 and 117, steps_toolbox.py:179 and 377 call systemctl daemon-reload directly

The second reader (S, medium risk): The bug half is real and confirmed: reload_systemd (scriptkit.py:65-77) is in HELPERS, which the change script includes (changes.py:1122), yet steps_tunnels.py:57 and :62, steps_restoretest.py:90 and :117, and steps_toolbox.py:179 and :377 call 'systemctl daemon-reload' directly. steps_overlay inherits it through tun_unit_start. A dead hard NFS/CIFS mount makes those steps block logins, which the helper exists to prevent.

The 'one unit writer' half is weaker than stated:
- rc_mount_unit (rclone.py:119-131) gates each write with act, uses durable, restarts only if already enabled and active, and tests the mountpoint; tun_unit_start (steps_tunnels.py:59-66) is called after act by its caller, never reports, and waits six times SF_TUNNEL_WAIT; restoretest (steps_restoretest.py:109-120) writes a script, a service and a timer under one 'changed' flag and enables the timer; toolbox writes a drop-in under /etc/systemd/system/$sock.d with no SF_UNIT_DIR. A shared sf_unit_put/sf_unit_up with flags for each saves about 15 lines, not 45.
- steps_toolbox.py:128 and :353 use "${sc[@]}" daemon-reload (an array that may hold other flags): leave those alone.
- Export heads do not define reload_systemd except rclone's stub (rclone.py:217). Any step that starts calling it needs the same stub in its export head (steps_tunnels.py:192, steps_overlay.py:400, steps_restoretest.py:175-182, steps_workloads.ANSIBLE_HEAD used by toolbox), or the playbook fails with 'command not found'.
- reload_systemd calls conflict (counts a problem and, in exports, exits 1). Existing callers show both styles: 'reload_systemd || return 0' (moves.py:1189) and 'reload_systemd >/dev/null 2>&1 || true' (steps_infra.py:343, changes.py:1230). Pick per site: a tunnel that cannot reload should stop before 'systemctl enable', not continue silently.

Risk is medium, not low: it changes when a step stops, and tests fake systemctl via PATH while reload_systemd reads the real /proc/self/mounts and stats real network mounts on the machine running the suite.

First commit: Not behaviour-preserving by intent; smallest fix: in storageforge_index/steps_tunnels.py replace the two 'systemctl daemon-reload >/dev/null 2>&1 || true' (lines 57, 62) with 'reload_systemd || return 1' in tun_unit_start and 'reload_systemd || true' in tun_unit_stop, and add 'reload_systemd() { systemctl daemon-reload; }' to the export heads at steps_tunnels.py:192 and steps_overlay.py:400. Tests: tests/test_tunnels.py, tests/test_overlay_steps.py, tests/test_tunnel_exposure.py. restoretest and the toolbox drop-in follow as separate commits; the shared writer is optional after that.

### BE-05. A network scan left `running` by a restart is closed as interrupted at start, as deploys, change runs and file scans are

**Survey record `webcore12`**: One place for controller background work: restart clean-up, periodic loops and the after-work alert pass.

Copies:

- restart clean-up in four places for four tables: server.py:301-303 deploy_runs, engine.py:270-272 deploy_groups (called at server.py:304), server.py:305-307 scan_jobs, server.py:3186-3190 scans
- netscan.py:152 inserts network_scans rows as 'running' and nothing closes them after a restart (no UPDATE of network_scans outside netscan.py:180), so server.py:1170 and netscan.py:237 skip them forever
- ten hand-written daemon loops with the same try / errlog.trace / sleep body: server.py:323-332, 334-350, 517-534, 536-543, 3234-3241, 3244-3250; selfupdate.py:132-143; agentingest.py:126; netconsole.py:287; rotate_keys.py:160
- server.py:339-345 chains seven tick() functions (security, inframeasure, netdevice, netscan, agentguard, apiread, and secplus through security), each with its own due bookkeeping
- the after-work block (close, guard for a deleted database, alerts.evaluate, trace) at server.py:431-439 and netscan.py:185-195

The second reader (S, low risk): Confirmed: restart clean-up is split between App.__init__ (server.py:300-307: deploy_runs, engine.close_interrupted, scan_jobs) and serve() (server.py:3186-3190: scans), and no code closes a network_scans row left 'running' (the only UPDATE is netscan.py:180, in the scan's own finally). Corrections. (1) 'skip them forever' overstates it: netscan._running is an in-process semaphore, so new scans start after a restart, and netscan.py:237 and server.py:1170 simply pass over the stale row; the visible defect is that the runs list (netscan.py:206) shows that scan as running until it ages out past KEEP_RUNS. It is a small real bug and the one concrete gain here. (2) The scans clean-up is in serve() and not in App.__init__ on purpose or by accident, but tests build App directly: moving it into App.__init__ changes what every test App does at start and prints to stderr. Keep it where it runs. (3) The loops are not one shape: _alerts waits on an Event twice with a first wait of 30 s, _nightly sleeps to a wall-clock hour after a conditional first run, warm() waits on scan_done, _schedule sleeps min(interval, tick), _security sleeps 60 s first, selfupdate takes a stop event. An every() helper with first_after/wake/stop covers perhaps four of ten and saves three lines each. Not worth a module. (4) The seven tick() calls in _security run in a fixed order in one try: one that raises skips the rest that minute. A TICKS list that traps each separately changes that (arguably for the better); say so if done. (5) The after-work block differs (getattr with defaults for test doubles in netscan; scan_done/alerts_wake set only in server). About 15 lines removed.

First commit: A bug-fix commit, not a refactor: storageforge_index/netscan.py gains close_interrupted(conn) (UPDATE network_scans SET status = 'failed', finished_at, error = 'interrupted by restart' WHERE status = 'running'), called next to engine.close_interrupted at server.py:304, with a test in tests/test_bughunt_network.py. The loop helper and TICKS list are left out.

### BE-06. One host's malformed agent manifest no longer stops the agent's disk, file and scan alerts for every host

**Survey record `agentlogs9`**: One place answers 'which agents are running' and 'which plugins does a host's manifest name'

Copies:

- storageforge_index/sfagent.py:483-489 plugins_of(): manifest FROM agent_deliveries, json.loads, names
- storageforge_index/agentwatch.py:85-92 _with_plugin(): the same read and parse, for all hosts
- storageforge_index/agentscan.py:159-160 the same read and parse inline (unguarded json.loads)
- storageforge_index/agentdisks.py:112, agentfiles.py:286, agentscan.py:153 SELECT host FROM agents WHERE enabled = 1 AND state = 'running'
- storageforge_index/agentwatch.py:99-100, 124-125, 142-143, 154-156 and agentguard.py:116-117 the same predicate plus 'fingerprint IS NOT NULL', five more times
- storageforge_index/agentdisks.py:29, agentfiles.py:38, agentscan.py:25, agentwatch.py:41 LABEL = 'reported by agent' four times (agentmonitor.py:118 writes the literal)
- storageforge_index/agentdisks.py:36-48, agentscan.py:30-41, sfagent.py:466-502 the same per-host row read + 'insert a blank row if missing, then UPDATE SET k = :k' helper three times

The second reader (S, low risk): Seen: the manifest read is at sfagent.py:483-489 (guarded), agentwatch.py:85-92 (all hosts) and agentscan.py:159 (unguarded json.loads, which raises on a malformed manifest and takes all three agent-plugin sources with it through the agentplugins.problems trap). The 'enabled = 1 AND state = running' predicate appears 8 times in 5 files. LABEL = 'reported by agent' is defined four times and written as a literal at agentmonitor.py:118.

Corrections:
- Wrong home. sfagent.py imports vault, remote, runner and deploy (sfagent.py:41-45). agentdisks, agentfiles, agentscan and agentwatch import only .db and agentaction today. Put the helpers in agentwatch.py or a small agentrows.py, and never where agenttunnel or agentreceiver would import them (tests/test_agent_receiver.py:384-393 forbids sfagent there).
- Only three of the eight predicates are the plain form (agentdisks.py:112, agentfiles.py:286, agentscan.py:153, which also selects mode). The four in agentwatch and the one in agentguard add fingerprint IS NOT NULL, endpoint IS NOT NULL, joins to hosts and agent_peers, and their own columns and ordering. An options-taking running() for those is longer than the SQL it replaces. Share a WHERE-fragment constant at most.
- upsert_row over three tables (agents, agent_disks, agent_inventory) with different keys and seed columns is a generic SQL builder that saves about 3 lines per site; sfagent._save also validates state. Skip it.
- agentscan's manifest read is per monitoring host inside a loop; a plugins_by_host(conn) read once is also one query fewer per host.

About 15 lines removed, not 40.

First commit: In storageforge_index/agentwatch.py: make LABEL the single definition and add plugins_by_host(conn) -> {host: set(names)} built from _with_plugin's guarded parse. agentdisks, agentfiles and agentscan import LABEL from it (check for an import cycle: agentwatch imports agentplugins lazily inside problems(), so a top-level import from the plugin modules is safe). agentscan.py:159 and sfagent.plugins_of use plugins_by_host. Touches agentwatch.py, agentscan.py, agentdisks.py, agentfiles.py, sfagent.py.

### BE-07. Retiring a host removes everything it owns: its security readings, ban history, graph snapshots, waivers, retention policies and per-host settings are left behind today. A test lists every table with a host column and fails when retire names neither it nor an exception

**Survey record `secmap11`**: One declaration of what a host owns, used by retire (and later by reset and host rename) instead of a hand-kept list of tables and settings keys.

Copies:

- storageforge_index/retire.py:39-53: hard-coded deletes for deploy_access, graph_nodes, clamav_detections, clamav_runs, five security_* tables, security_timelock_queue, host_log_lines, host_log_status, scan_jobs, host_design_sections
- storageforge_index/retire.py:49: settings prefixes security.host, security.clock, security.profile, security.persistence, security.aide.last, security.autoscan, all in the form '<prefix>:<lowercase host>'
- storageforge_index/secplus.py:28 and 293-303: drift is stored under 'security.drift.' + host (dot, original case), so retire never removes it
- storageforge_index/secplus.py:36 and 700, 720: 'security.identity.' + host, also never removed
- storageforge_index/security.py:88-97 clock_key, host_key, profile_key versus secplus.py:187, 236, 2057 writing the same style of key with inline f-strings
- Per-host tables written elsewhere and not in retire.py: security_waivers and security_retention_policies (secplus.py:75, 407), security_ban_history (secplus.py:1659), security_readings (secplus.py:146), graph_snapshots (infragraph.py:383)
- storageforge_index/backup.py:33-57 ESSENTIAL and REBUILDABLE: a second hand-kept list of the same tables

The second reader (S, medium risk): The leak is real: retire.py:39-53 does not touch security_readings, security_ban_history, graph_snapshots, security_waivers or security_retention_policies (all have a host column and no foreign key to hosts: migrations/sqlite/036_security_more.sql, 034_map.sql), nor the settings keys 'security.drift.<host>' and 'security.identity.<host>' (secplus.py:28, 36, 293-303), which use a dot and the host's original case where retire deletes '<prefix>:<lowercase host>'. No test covers any of these. Corrections: (1) a registry that 'each module registers into' makes retire depend on every module having been imported; a static table in retire.py plus a test that reads the migrations gives the same guarantee with no import-order rule. (2) security_waivers and security_retention_policies use host '*' for all hosts; lower(host) = lower(name) leaves those alone, which is right, but a host-specific waiver is an operator's decision and deleting it on retire should be decided, not assumed. (3) graph_snapshots is what at_time reads to show the past; deleting on retire removes the host from time travel. Probably wanted, but a choice. (4) backup.py ESSENTIAL/REBUILDABLE classify whole tables for backup, not per-host ownership; checking them 'by the same test' means a second, different assertion (every table in exactly one list). (5) retire also has rules that are not table rows: key_bindings matched by pattern (hostname, ssh_host, not IP), the still_on_host note from deploy_access state, the sqlite FTS delete, remotes.retired; these stay as code. (6) design_versions and the audit log are deliberately kept. Because retire cannot be undone, the first commit must not delete anything new.

First commit: storageforge_index/retire.py: move the inline table names and settings prefixes into two module constants (HOST_TABLES, HOST_SETTINGS) with identical SQL and order; add a test in tests/test_audit_fixes.py that lists every table with a host or hostname column in migrations/sqlite and requires each to be in HOST_TABLES or in an explicit KEPT dict with a reason, with security_readings, security_ban_history, graph_snapshots, security_waivers, security_retention_policies entered in KEPT as 'gap, to decide'. Later commits, one per table or key, move entries from KEPT to deleted, and add the drift and identity keys in their existing dotted form (no key migration needed: delete 'security.drift.' + hostname as stored).

### BE-08. A workload managed through a platform API is named by the platform's title (Portainer), as label evidence names it, not by the connection kind (portainer)

**Survey record `api10`**: One table of container panels (name, image pattern, label prefixes, unit names, compose folders, API kind) in place of four partial lists with different coverage

Copies:

- storageforge_index/wlmanaged.py:22 LABEL_MANAGERS: Komodo, Portainer, Coolify, Dockhand, Dockge by label prefix
- storageforge_index/wlmanaged.py:28 PANEL_UNITS: the same five by systemd unit prefix
- storageforge_index/workloads.py:14 PANELS: seven by image regex (adds Dokploy and CasaOS), used at :58
- storageforge_index/runtimes/docker.py:380-386 _manager(): six by compose folder (has CasaOS, lacks Dokploy), imported by wlmanaged.py:20
- storageforge_index/runtimes/docker.py:30 the label-keeping regex restates the label prefixes ('what says who runs a container (wlmanaged.py)')
- storageforge_index/wlread.py:47 the unit grep restates the unit names
- storageforge_index/wlmanaged.py:87-90 names an API-managed workload by connection kind ('portainer', from apiviews.py:251) while label evidence names it 'Portainer' (:46)
- the panel view functions shared by three API kinds live in the Dockhand module: apidockhand.py:277-348, imported by apiportainer.py:23 and apikomodo.py:24

The second reader (M, medium risk): The four partial lists exist as cited (wlmanaged.py:22 and :28, workloads.py:14, runtimes/docker.py:380-386, restated in runtimes/docker.py:29-30 and wlread.py:47), and the naming mismatch is real: wlmanaged.py:89 names an API-managed workload by connection kind ('portainer', from apiviews.managed_by_host) while label evidence says 'Portainer'. Corrections: (1) LOC removal is not 30; the lists total about 6 lines and a table plus five lookup helpers is longer. This is a consistency change with net growth. (2) Do NOT generate wlread.py:47 or KEEP_LABELS from the table. wlread's line is a literal inside a shell script that runs on scanned hosts; generating it interpolates table data into a remote script, and KEEP_LABELS decides which container labels are stored at all (runtimes/docker.py:218). Keep both literal and add a test that every table prefix is covered by them. (3) 'Dokploy and CasaOS recognised by labels/units/folders' cannot come from consolidation: nobody has their label prefixes or unit names; the table would hold empty entries. That gain needs research per panel, separately. (4) Match semantics differ per column and must stay: image is a case-insensitive regex search anywhere; labels and units are startswith; compose folder is a substring test on recorded_dir + dir joined (runtimes/docker.py:431) with a default of 'compose'. (5) Precedence differs between the lists: labels go Komodo, Portainer, Coolify, Dockhand, Dockge; images go Dockhand, Portainer, Komodo, ...; folders go Dockhand, Komodo, Portainer, Dockge, CasaOS, Coolify. A container carrying two panels' labels (for example dockhand.* and komodo.*) changes owner if one table order is used; each lookup needs its own order or the order must be chosen and tested. (6) tests/test_apiportainer.py:108 and tests/test_apidockhand.py:125 assert the lowercase kind in apiviews.managed_by(...)['panel'], so that field must stay the kind; only the display name in wlmanaged._m should change, which also changes the warn_before dedupe key at wlmanaged.py:130 (intended). (7) Moving panel_containers/compare/workloads/map_nodes/problems from apidockhand to an apipanel.py is a safe pure move (no test calls them on apidockhand directly; apiportainer.py:23 and apikomodo.py:24 re-export them) but is independent of the table and removes nothing.

First commit: One-line user-visible fix first: in storageforge_index/wlmanaged.py:89 name the manager by the platform title (apiconn.KINDS[am['panel']]['title'], falling back to am['panel']) while leaving w['api']['platform'] as the kind; add a case to tests/test_workload_managed.py. Then, as a second commit, a leaf panels.py table read by wlmanaged.LABEL_MANAGERS/PANEL_UNITS, workloads.PANELS and runtimes/docker._manager with each lookup keeping its current order, plus a test that wlread's unit grep and KEEP_LABELS cover every table entry.

### BE-09. A plan run as root with `SF_SECRET_DIR` set delivers a secret to the folder its steps then read. Today delivery uses the fixed folder and the tunnel and overlay steps read the variable's

**Survey record `steps3`**: One implementation of 'a step reads a vault secret on the host': name rule, directory, missing-secret message and check notes

Copies:

- Name rule, two variants: secretstore.py:33 and steps_secretfile.py:20 and changes.py:211 CHECKS['secret'] = [A-Za-z0-9][A-Za-z0-9._-]{0,63}; steps_tailscale.py:19, steps_tunnels.py:32, steps_overlay.py:34 = [A-Za-z0-9_.-]{1,64} (a leading dot, dash or underscore passes)
- secretstore.py:171-173 plan_secrets silently skips a name that fails secretstore.NAME, so a name the step check accepted is not delivered
- SECRET_DIR constant five times: secretstore.py:34, steps_tailscale.py:22, steps_tunnels.py:35, steps_overlay.py:38, steps_pools.py:24
- Bash lookup of the file, three behaviours: root ignores SF_SECRET_DIR at rclone.py:61, steps_proxmox.py:81, netshares.py:192, steps_secretfile.py:27-28, steps_restoretest.py:123-124; any user including root honours it at steps_tunnels.py:69 and 114, steps_overlay.py:70 and 234; no override at steps_tailscale.py:30 and steps_pools.py:223
- Missing-secret message three times: steps_tunnels.py:43-46 tun_secret_missing, steps_pools.py:223-229 luks_key, steps_tailscale.py:58-61 inline
- Python check text repeated: 'is not a secret name' at steps_tailscale.py:82, steps_tunnels.py:168 and 179, steps_overlay.py:277, steps_pools.py:532; the send-secret note at steps_tunnels.py:160-163, steps_overlay.py:282-284, steps_tailscale.py:93-94, steps_pools.py:537-539
- secretstore.py:156-159 secret_fields() special-cases 'a field called secret of kind name' because five steps did not use kind 'secret'

The second reader (M, medium risk): Confirmed: SECRET_DIR is defined six times, not five (also cli.py:1106); NAME has two rules; the bash lookup has three behaviours (tunnels/overlay honour SF_SECRET_DIR even as root at steps_tunnels.py:69,114 and steps_overlay.py:70,234, while sf_secrets_in at secretstore.py:249 writes to the fixed directory as root, so a root run with the variable set delivers to one place and reads from another).

Corrections:
- 'a leading dot, dash or underscore passes' is wrong for saved plans: those fields are kind 'name', and changes.CHECKS['name'] (changes.py:208) is checked first in normalize (changes.py:328) and requires a first character of [A-Za-z0-9_]. Only a leading underscore survives both and is then silently skipped by plan_secrets (secretstore.py:172).
- The finder lists five steps with F('secret','name'); there are more: steps_secretfile.py:105, steps_restoretest.py:189, rclone.py:229, and three LUKS steps (steps_pools.py:652, 661, 670).
- Real bug the finder missed: luks-add-key's second field is F('new_secret', 'name', ...) (steps_pools.py:671). secret_fields() (secretstore.py:159) matches kind 'secret' or a field literally named 'secret', so new_secret is never delivered with the plan; t_luks_add_key then stops with 'no key at ...' unless the operator ran vault send-secret by hand. Switching that field to kind 'secret' fixes it.
- Changing kind 'name' to 'secret' moves the rejection from a check finding to a ValueError in normalize (changes.py:328-329). tests/test_pool_steps.py:440 asserts the crit text 'a:b is not a secret name: letters, digits, . _ and -' from the check; it will fail (the plan no longer normalizes). Same for any UI flow that shows the check finding. plan_hash is over params only (changes.py:940-946), so hashes do not move.
- rclone.py:31 NAME is a different thing (remote name, 41 chars, no dot): do not fold it in.
- luks_key (steps_pools.py:221-229) has no SF_SECRET_DIR override at all and insists on tmpfs; tailscale has no override either. A shared sf_secret that honours the override for non-root changes what those two accept under test.
- Tests setting SF_SECRET_DIR: test_overlay_steps, test_steps_proxmox, test_toolbox_restore, test_netfs_rclone, test_secretstore, test_bughunt_rest_c, test_tunnel_exposure, test_share_rclone. With the root-ignores rule applied to tunnels/overlay, test_overlay_steps and test_tunnel_exposure fail when the suite runs as root.

Size is M (eleven modules of Bash and Python plus eight test files), not S. LOC estimate of 60 is about right.

First commit: Python constants only, no generated text changes: steps_tailscale.py, steps_tunnels.py, steps_overlay.py, steps_pools.py and cli.py import SECRET_DIR from secretstore instead of redefining the same string; steps_secretfile.py imports NAME from secretstore (same pattern as its own at :20). Second commit, a behaviour fix on its own: steps_pools.py:671 F('new_secret', 'secret', ...) so the plan delivers it, with a test in tests/test_secretstore.py that plan_secrets returns both names for luks-add-key.

### BE-10. A stored secret can't silently replace a credential of another kind that holds the same name: `secret-add`, `headscale-key` and the device-credentials route check first, and a re-sealed secret keeps its policy

**Survey record `keysnet5`**: One credential-store API with kinds, so every writer of device_credentials goes through the same name, policy and collision rules

Copies:

- storageforge_index/secretstore.py:127-128 make refuses a name that any row holds; apiconn.py:255-256 add does the same check with its own SQL
- storageforge_index/cli.py:1379-1380 secret-add and overlaykeys.py:233-234 headscale_key do remove_credential + store_credential with no check; routes_network.py:108 stores with no check. vault.py:710 deletes any row of that name, so each of these silently replaces an API token or a device password that has the same name
- overlaykeys.py:234 stores with no policy and no made: a policy already on that secret is dropped
- the marker 'secret' is a literal in cli.py:1380 and overlaykeys.py:234, a constant in secretstore.py:35
- raw SQL on the table outside vault.py: apiconn.py:266, 365, 369, 399; secretstore.py:88, 115, 127, 140
- 'given' secrets have no web route: routes_secrets.py:36-51 only generates; routes_secrets.py:66-71 rotates without a value, which secretstore.py:344-345 refuses for a given secret
- secret-name pattern, strict form in six places (secretstore.py:33, vault.py:688, overlaykeys.py:35, netshares.py:43, steps_secretfile.py:20, changes.py:209) and a looser form in five (cli.py:1105, steps_tailscale.py:19, steps_overlay.py:34, steps_tunnels.py:32, steps_pools.py:25) that the vault then refuses

The second reader (M, medium risk): Seen: store_credential (vault.py:709-711) deletes any row of that name inside its transaction; only secretstore.make (127-128) and apiconn.add (255-256) check first. So cli secret-add (1379-1380), overlaykeys.headscale_key (233-234) and POST /api/devices/credentials (routes_network.py:108) replace whatever holds the name, across kinds, and headscale-key reseals without policy or made (policy lost). The v.remove_credential calls before store_credential in cli and overlaykeys are redundant (store deletes anyway). Missed: (1) the web device-credential route accepts any username including the literal 'secret' and any name including 'api-KIND-NAME', and DELETE /api/devices/credentials/<name> (routes_network.py:117) removes a step secret or an API token by name without touching secret_deliveries or platform_connections: the same hole on the delete side. (2) kind_of() cannot be exact: 'secret' is a username marker, 'api' is a name prefix (apiconn.secret_name), and a device login whose user is really called 'secret' is already indistinguishable from a step secret; clone.py:413 also filters on username = 'secret' in raw SQL. (3) Replacing a same-named device credential through the route is today's only way to change a device password: keep replace within kind 'device'. (4) secret-add replacing a secret does not carry secret_deliveries semantics or the old 'made' (kind/length of a generated secret become origin 'given'): decide, do not preserve by accident. (5) cli.py:1402-1403 (secret-policy) is another writer and already uses secretstore.made_of. (6) The proposal mixes consolidation with two new web features (store a given secret, rotate with a given value) and with unifying the name pattern across ten step modules: split them off. The loose pattern in cli/steps_tailscale/steps_overlay/steps_tunnels/steps_pools is confirmed (allows leading '.', '-', '_'), harmless today because the vault refuses such names on store and plan_secrets skips them. Net code removed is near zero; the gain is the bug class.

First commit: secretstore.py: add put_given(v, conn, name, value, policy=KEEP) that refuses when a row of that name exists with username != USERNAME, and otherwise reseals keeping the existing policy when none is given. cli secret-add and overlaykeys.headscale_key call it (secret-add passes its policy explicitly, so its behaviour on a secret is unchanged; headscale-key stops dropping the policy). Files: storageforge_index/secretstore.py, cli.py, overlaykeys.py, plus one test each in tests/test_secretstore.py and tests/test_overlay_steps.py. The device route and apiconn are later commits.

## 0.6.3: Shared primitives

### BE-11. One splitter for the `@@section` output of host and device scripts (netfacts, OpenWrt, pfSense, the infrastructure reading)

**Survey record `netdev4`**: The '@@name' section splitter for a remote script's output is copied in netfacts, openwrt and pfsense, and again in inframeasure, security, remote and the Docker reader.

Copies:

- storageforge_index/netfacts.py:39-47 _sections
- storageforge_index/openwrt.py:34-42 sections: identical body, different allowed-name tuple
- storageforge_index/pfsense.py:36-44 sections: identical body again
- storageforge_index/inframeasure.py:224-232 _sections: same loop, returns lists of lines
- storageforge_index/security.py:293-302 _sections: same loop, any [a-z_0-9]+ name, None unless 'end' and 'now' present
- storageforge_index/remote.py:500-511 parse_sections: same idea, strips the name, drops the last section
- storageforge_index/runtimes/docker.py:100-112 _sections: same with a tab-separated head
- storageforge_index/openwrt.py:218-219 and pfsense.py:366-367: the same 'end' not in s -> 'the reading was cut short' check; netfacts.py:188 'complete'

The second reader (S, low risk): Four of the seven are true copies: netfacts.py:39-47, openwrt.py:34-42 and pfsense.py:36-44 are byte-identical apart from the name tuple, and inframeasure.py:224-232 is the same loop returning lists instead of joined+stripped text. The other three are different functions and should stay out: security.py:293-302 accepts any [a-z_0-9]+ name by regex (no allow-list) and returns None unless both 'end' and 'now' are present; remote.py:501-511 strips the header name, does not strip the body, keeps lines before the first header in the first buffer and intentionally never flushes the last section; runtimes/docker.py:100-112 splits a tab-separated head, carries the rest of the header line into the body and does flush the last section. Folding those in needs flags for strip, tab heads, regex names, drop-last and require — a function with more switches than body. Also missed: openwrt.parse (openwrt.py:217-220) splits the same text twice on purpose, once with ALL_SECTIONS and once through netfacts.parse with the narrower netfacts.SECTIONS, so each caller must keep passing its own tuple (with the narrow list, OpenWrt-only headers stay as body text of the preceding section; that is today's behaviour and must not change). The 'cut short' checks differ in outcome (ValueError in openwrt/pfsense, 'complete': False in netfacts, None in inframeasure) and stay at the call sites. remote.py is a poor home for it (a 500+ line transport/inventory module with its own, different parse_sections); netfacts.py is already imported by openwrt and inframeasure and is the natural owner. Saving is about 20 lines, not 45.

First commit: One commit: make netfacts.py own `split_sections(text, names, lines=False)` (current body; lines=True returns the lists), have netfacts._sections, openwrt.sections, pfsense.sections and inframeasure._sections become one-line calls with their own tuples (keep the four names so tests and callers such as openwrt.parse/pfsense.parse and any test importing them keep working). Files: storageforge_index/netfacts.py, openwrt.py, pfsense.py, inframeasure.py. Tests: tests/test_props_parsers.py, tests/test_routers.py OpenWrtReading/PfSenseReading, tests/test_infra.py Network, tests/test_netconfig.py Damaged. Leave security, remote and runtimes/docker untouched.

**Survey record `secmap7`**: One splitter for the '@@section' output format that every host script prints.

The second reader (S, low risk): Confirmed: netfacts.py:39-47, openwrt.py:34-42 and pfsense.py:36-44 are character-for-character the same apart from the name set; inframeasure.py:224-232 is the same loop returning line lists. Those four are worth one function. The other two should stay out of the first step: security._sections (security.py:293-302) accepts any @@[a-z_0-9]+ header and returns None unless 'end' and 'now' exist; remote.parse_sections (remote.py:501-511) is a different algorithm, not the same loop: it matches line[2:].strip() (tolerates trailing spaces and CR, the others do not), does not strip the joined text (the three text splitters call .strip()), stores a section only when the next header arrives so the last one is dropped, and is shared with agentscan.py:56-58 which joins chunked parts. A single function with names/lines/require/drop_unfinished plus strip-or-not and header-strip-or-not is six switches for six callers. Real saving is about 20 lines, not 45. scriptkit is the script generator; a parser sits more naturally in netfacts (openwrt already imports netfacts.SECTIONS) or a small module of its own.

First commit: One function split_sections(text, names, lines=False) (body of netfacts._sections) in storageforge_index/netfacts.py or a new sectionfmt.py; netfacts._sections, openwrt.sections, pfsense.sections and inframeasure._sections become one-line calls keeping their names. security._sections and remote.parse_sections untouched. tests/test_props_parsers.py, tests/test_routers.py, tests/test_appliances.py, tests/test_infra.py cover it.

### BE-12. One module for SSH wire strings and key fingerprints, in place of copies in eight modules. Signature checking keeps its own refusals

**Survey record `agentlogs5`**: One module for SSH wire strings, key fingerprints and SSHSIG parsing

Copies:

- storageforge_index/sfagent.py:229-232 fingerprint(public_line)
- storageforge_index/vault.py:215-217 fingerprint(public_line): identical body
- storageforge_index/scansign.py:118-120 fingerprint(key_line): identical body
- storageforge_index/remote.py:51-57 key_fingerprint(b64): same hash, validate=True, None on bad input
- storageforge_index/agentmonitor.py:176 the same expression inline
- storageforge_index/deploy.py:62-63, agenttunnel.py:284-285, sshcerts.py:48-49, sshca.py:40-41 _s(b) = struct.pack('>I', len(b)) + b, four times (enclave.py:626 a fifth)
- storageforge_index/agenttunnel.py:275-281 _string(blob, at) and scansign.py:96-104 _ssh_string(buf, at): the same length-prefixed reader
- storageforge_index/agenttunnel.py:288-316 verify_batch parses the SSHSIG blob field by field; scansign.py:107-115 signer_key parses the same header; deploy.py:66-75 sshsig() writes it

The second reader (S, low risk): Seen: fingerprint() bodies are identical at sfagent.py:229-232, vault.py:215-217 and scansign.py:118-120, and inline at agentmonitor.py:176. remote.key_fingerprint (remote.py:51-57) differs: it takes bare base64, uses validate=True and returns None; the others take a key line, decode leniently and raise. _s() is at deploy.py:62, agenttunnel.py:284, sshcerts.py:48 and sshca.py:40, plus enclave.py:626 under the name _string.

Drop the SSHSIG-parse part:
- scansign.signer_key (scansign.py:107-115) is deliberately a lax extractor: it reads only the key field so the caller knows which host key to hand to ssh-keygen, which does the verifying. agenttunnel.verify_batch (agenttunnel.py:288-316) is a full strict verifier returning a bool. Making signer_key strict would start rejecting signatures ssh-keygen accepts (other hash, trailing data); making the shared parser lax weakens the receiver.
- The two readers raise different texts ('cut short' vs 'the signature is cut short'). No test asserts either, but scansign's reaches users.

Constraints the finder half-stated:
- tests/test_agent_receiver.py:384-393 runs the receiver in a subprocess and asserts that vault, enclave, remote, runner, deploy, sfagent, server, scanner and changes are never imported. agenttunnel may import a new sshwire.py only if that module imports stdlib alone. That rules out putting the shared fingerprint in remote.py or vault.py.
- Leave enclave.py's copy alone.

With the parser dropped this is about 15 lines removed, not 45, and low risk. Fingerprints are stored strings (agents.fingerprint, host_key_confirmations); the function body is unchanged, so they do not move.

First commit: New storageforge_index/sshwire.py, stdlib only, with put(b) and fingerprint_of_line(line), bodies copied exactly. sfagent.fingerprint, vault.fingerprint and scansign.fingerprint become re-exports of it, so every existing caller name keeps working, and agentmonitor.py:176 calls it. Replace _s in deploy.py, sshcerts.py and sshca.py with sshwire.put. Leave agenttunnel.py, remote.key_fingerprint and enclave.py as they are in this commit.

**Survey record `keysnet2`**: One SSH primitives module for the wire string helpers, the SHA256 fingerprint and SSHSIG verification

The second reader (S, low risk): Partly wrong evidence. Writers: five identical two-liners, but enclave.py:626 is named _string (not _s) while agenttunnel.py:275 _string is a READER: same name, opposite jobs in two modules. Readers are not interchangeable: sshca.py:44 _first_string(blob) returns (value, rest) and raises CertificateError('not a public key'); enclave.py:630 raises ValueError('short'); agenttunnel.py:275 ValueError('cut short'); scansign.py:96 ValueError('the signature is cut short') and is the only one that turns struct.error into ValueError (a host chooses those bytes). A shared take() must raise ValueError and sshca must wrap it. Fingerprint: toolbox.py:645 is NOT the two-line body, it shells out to ssh-keygen -l and raises CatalogError (it validates the key, the hash does not): leave it. Real copies are vault.py:215, sfagent.py:229, scansign.py:118; sshcerts already imports vault.fingerprint. remote.key_fingerprint takes bare base64 with validate=True and returns None. Verify: the three ssh-keygen -Y verify callers differ in principal ('storageforge', 'sfnet', per-signer name), in error handling (toolbox swallows OSError/Timeout to None, scansign and sfnet let them raise), timeouts, and toolbox needs find-principals first plus an lru_cache keyed on the signers text; sfnet.py:442 also emits the same command as generated host-side Python, which cannot share. The claimed gain 'sfnet gains the namespace restriction' is nil: verify already passes -n DIRECTORY_NS, and ssh-keygen refuses a signature made for another namespace; namespaces= on the line only matters when one allowed-signers file serves several namespaces. sshca.py, sfnet.py and nebulaca.py import nothing from the package on purpose (pure format modules); a stdlib-only sshfmt keeps that. Realistic saving about 30 lines; the sshsig_verify helper saves little and is the part most likely to change behaviour.

First commit: Fingerprint only: sfagent.fingerprint and scansign.fingerprint become re-exports of vault.fingerprint (names kept, same bytes out, same exceptions). Files: storageforge_index/sfagent.py, scansign.py. Second commit: new stdlib-only storageforge_index/sshfmt.py with put() and take() (ValueError), used by deploy, sshcerts, sshca (wrapping into CertificateError), enclave, agenttunnel, scansign with their private names kept as aliases.

**Survey record `x2`** (*unchecked*): The SSH wire-format helpers (length-prefixed string, its reader, the SHA256 key fingerprint, SSHSIG signing and checking) written in eight Python modules become one module.

Copies:

- struct.pack('>I', len(b)) + b defined five times with identical bodies: agenttunnel.py:284 _s, deploy.py:62 _s, sshca.py:40 _s, sshcerts.py:48 _s, enclave.py:626 _string
- Bounded reader defined four times: agenttunnel.py:275 _string, enclave.py:630 _take_string, scansign.py:96 _ssh_string, sshca.py:44 _first_string
- 'SHA256:' + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip('=') in five places: remote.py:57, scansign.py:120, sfagent.py:232, vault.py:217, agentmonitor.py:176 (vault.py:215 and sfagent.py:229 have identical function bodies)
- SSHSIG built in deploy.py:66 sshsig; parsed and checked by hand in agenttunnel.py:288 verify_batch (the signed-data line of deploy.py:69 is repeated at agenttunnel.py:312); parsed again in scansign.py:108
- tests/test_agent_tunnel.py:200 reaches into deploy._s to build a fingerprint

Proposal: storageforge_index/sshwire.py: string(b), take_string(buf, at), fingerprint(blob or 'type base64' line), sshsig_sign(key, message, namespace), sshsig_parse(armored) returning (key blob, namespace, hash, signature), sshsig_verify_ed25519(public, message, armored, namespace). deploy.sshsig and agenttunnel.verify_batch become one-line callers; each keeps its own namespace constant and size limit.

What must survive: Signature checking is a security boundary: verify_batch refuses trailing bytes, a non-empty reserved field, any hash but sha512 and any key type but ed25519, and caps the armor at 4096 bytes; the shared parser must keep every refusal. The readers raise different errors (ValueError vs returning None) that callers catch. Fingerprints are stored in the database and compared as text, so the form must not change by one character.

### BE-13. One reader of a host's pinned keys in `known_hosts`, in place of four `ssh-keygen -F` parsers

**Survey record `shares11`**: Reading a host's pinned SSH keys from known_hosts is parsed in five places, and the key fingerprint is computed in four.

Copies:

- storageforge_index/remote.py:65-80 known_host_keys: ssh-keygen -F, skips comments and @cert-authority/@revoked lines, returns fingerprints
- storageforge_index/scansign.py:123-135 known_host_lines: same call, own host:port naming, skips only comments, does not pass child_env
- storageforge_index/sshcerts.py:177-188 host_public_key: same call, skips # and @, picks by key type
- storageforge_index/jobs.py:159-168 pinned_key: same call, skips only comments, keeps everything after the first word
- storageforge_index/hostkeys.py:56-59: the same three-field line parse on a scratch known_hosts
- storageforge_index/remote.py:51-57 key_fingerprint; storageforge_index/scansign.py:118-120 fingerprint; storageforge_index/vault.py:215-217 fingerprint; storageforge_index/agentmonitor.py:176 inline
- storageforge_index/receiving.py:305-313 _pins depends on jobs.pinned_key; storageforge_index/shares.py:706-711 with_keys reads pinned keys a third way (hosts.host_keys column)

The second reader (S, medium risk): Confirmed: four `ssh-keygen -F` parsers (remote.py:65-80, scansign.py:123-135, sshcerts.py:177-188, jobs.py:159-168) and four fingerprint computations (remote.py:51-57, scansign.py:118-120, vault.py:215-217, agentmonitor.py:176 inline).

Corrections:
- hostkeys.py:56-59 is not a fifth copy: it reads a scratch known_hosts file that ssh just wrote, with no ssh-keygen -F and no markers possible. It already uses key_fingerprint. Leave it.
- shares.py:706-711 reads a database column, not known_hosts; out of scope.
- The marker gap is real. jobs.pinned_key and scansign.known_host_lines skip only `#` lines, so an `@revoked` or `@cert-authority` line gives shifted fields ("storageforge-source HOST TYPE KEY", or `host type` as the key). It fails closed: ssh rejects the malformed pin and the signature check does not match. But receiving._pins (receiving.py:305-313) treats any non-empty result as "has a pin", so a host with only a marker line passes that check and fails later with a worse message. Dropping marker lines is a behaviour change for such files only.
- scansign.known_host_lines differs in more ways than listed: it defaults to ~/.ssh/known_hosts, returns [] when the file is missing, tests `port == 22` (None is not handled), does not strip brackets, passes no child_env (STORAGEFORGE_* variables reach ssh-keygen), uses a 15 s timeout and does not catch OSError or TimeoutExpired. The others return empty on those errors.
- Fingerprints: key_fingerprint validates base64 and returns None; scansign.fingerprint, vault.fingerprint and the agentmonitor inline raise (binascii.Error, IndexError) on bad input. Callers at vault.py:603 and 638 and scansign.py:218, 221 and 265 use the result as a string, so a None would be stored or printed. Keep the raising behaviour in thin wrappers or check each caller.
- Tests patch jobs.pinned_key by name (tests/test_sends.py:95, 755, 1058, 1190), so that function must stay in jobs.

Realistic removal is about 30 lines.

First commit: Add remote.pinned_lines(host, port, known_hosts=None) -> [(type, base64)] with the rule known_host_keys already uses (skip `#` and `@` lines, child_env, known_hosts_name, 10 s timeout, empty on error). Make remote.known_host_keys and sshcerts.host_public_key views of it; both already apply exactly this rule, so nothing changes. Files: storageforge_index/remote.py, storageforge_index/sshcerts.py. Tests: tests/test_sshcerts.py, tests/test_rotate_keys.py. Move jobs.pinned_key and scansign.known_host_lines in a second commit that states the marker-line change and adds a test with an @revoked line.

**Survey record `x10`** (*unchecked*): The four readers of known_hosts and the ssh command lines assembled outside remote.py use remote.py's.

Copies:

- 'ssh-keygen -F name -f known_hosts' run and parsed four times: remote.py:65 known_host_keys, jobs.py:160 pinned_key, scansign.py:123 known_host_lines, sshcerts.py:177 host_public_key
- They differ: scansign.py:128 builds the name itself ('[host]:port', no strip of brackets) where the others call remote.known_hosts_name (remote.py:60); scansign.py:129 runs without child_env() and without catching a timeout; only remote.py:75 skips '@cert-authority' and '@revoked' lines, so jobs.py:167 and scansign.py:133 would take a revoked line's fields as a key
- The same ssh argv twice, word for word: cli.py:1124-1128 and overlaykeys.py:58-62 (its docstring: 'from the same options vault send-secret takes'), with the host and login checks before it repeated too (cli.py:1110-1116, overlaykeys.py:53-57)
- The pinned-key option set ('-F /dev/null', StrictHostKeyChecking=yes, UserKnownHostsFile=known_hosts_path(), GlobalKnownHostsFile=/dev/null, ConnectTimeout=10) written out in access.py:239-242, keyinstall.py:101-104, console.py:347-349, nettransport.py:262-265 beside remote.py:153-175 Transport.argv

Proposal: remote.known_host_entries(host, port, known_hosts) -> [(type, base64)] with the marker and comment skipping, on which known_host_keys, pinned_key, known_host_lines and host_public_key are three-line views. remote.pinned_options(port, known_hosts) for the shared option words. overlaykeys._ssh becomes the one builder for the two CLI commands. Password and console callers keep their own authentication options and tty flags.

What must survive: Host-key pinning is the security boundary here. The password-carrying callers (access.py, keyinstall.py) must keep NumberOfPasswordPrompts=1 and strict checking; hostkeys.py:48 and preflight.py:153 use StrictHostKeyChecking=no with no authentication on purpose (they only fetch a key) and must not be folded in. scansign falls back to ~/.ssh/known_hosts when given none; the others do not.

### BE-14. One pair of functions for *is this path under that folder* and *which mount holds this path*

**Survey record `shares12`**: Two functions answer 'is this path under that folder', and two check 'a whole number in a range'.

Copies:

- storageforge_index/moves.py:283-284 _under and storageforge_index/remote.py:103-106 is_under: the same test (they differ only for a relative path under '/'); 69 uses of _under and 49 of is_under across the package; storageforge_index/copies.py:30-32 and storageforge_index/fsmap.py:12 import one or both
- storageforge_index/shares.py:134-141 _whole (raises outside the range), storageforge_index/moves.py:120-124 _whole (clamps into the range), storageforge_index/netshares.py:150-157 the same check inline, storageforge_index/tasks.py:216

The second reader (S, low risk): Two unrelated items; only the first is worth doing.

Path test:
- moves.py:283-284 _under and remote.py:103-106 is_under differ only when root is '/' and the path does not start with '/'. The counts are off: I find 19 uses of _under (moves.py, fsmap.py, tasks.py) and 41 of is_under, not 69 and 49.
- The difference is reachable in principle: mount_of(host, path) with an empty or relative path matches the root mount today and would not with is_under. Callers I saw validate with _path first, but check every mount_of and _under caller before aliasing.
- moves.py does not import remote today (it imports site, and deploy and jobs lazily); the alias adds that import. remote does not import moves, so there is no cycle.

Whole number:
- The four are not one function. moves._whole (moves.py:120-124) clamps silently and prefixes "step N:"; shares._whole (shares.py:134-141) raises with a range message; netshares.clean (netshares.py:150-157) is inline with the field label and a range from f.options; tasks.py:216-221 is inline with spec min and max and prints "between 0 and None" when max is unset.
- A whole(value, what, lo, hi, clamp=False) in scriptkit saves about 8 lines across four call shapes and puts a clamp flag on a validator; the texts are user-facing and asserted in tests. Skip it.

Net removal is about 3 lines. The gain is one definition of path containment.

First commit: In storageforge_index/moves.py import is_under from .remote and reduce _under to `return root == '/' or is_under(path, root)`, which keeps today's answer for every input including a relative path under '/'. Files: moves.py only. Tests: tests/test_indexer.py, tests/test_filemap.py, tests/test_bughunt_plans.py. Replacing the 19 _under call sites and dropping the root special case can follow once each mount_of caller is shown to pass an absolute path.

**Survey record `toolwork11`**: 'Is this path under that root' and 'which mount is this path on' are implemented in several modules and inlined about 25 times; one pair of functions should serve all.

The second reader (S, low risk): Confirmed: remote.is_under (remote.py:103-106, already used ~49 times), moves._under (283-284) identical to runtimes/docker._under (451-452), deepest-mount logic in moves.mount_of (287-289), workloads.sits_on (23-31) and agentfiles._mount_for (91-99); 25 inline hits of startswith(x.rstrip('/') + '/'). Corrections: (1) the inline form is already correct for root '/' ('/'.rstrip('/') + '/' == '/'), so the 'root mount bug class' is mostly not present; the real variation is whether 'path == root' is included - several inline sites mean 'strictly inside' on purpose and must be read one by one, not replaced mechanically. (2) remote.py is the SSH module; agentfiles serves the agent path, so do not make agentfiles import remote - put the pure functions in a small paths.py and let remote re-export is_under. (3) The only semantic difference between the named copies is a relative path against root '/': remote.is_under False, moves/docker _under True; sits_on already rejects non-absolute paths. (4) The SQL filters differ on purpose (scan_state <> 'gone' with lower(hostname) vs = 'indexed' with exact hostname; moves accepts 'indexed' and 'skipped' from an in-memory host dict) and stay at the call sites; return shapes differ (dict, row tuple, mount dict). Gain is small (about 20 lines) and no user-visible change.

First commit: Add storageforge_index/paths.py with is_under(path, root) (remote's stricter rule) and deepest(items, path, key); remote.is_under becomes an import of it; delete moves._under and runtimes/docker._under in favour of it after checking their callers pass absolute paths (docker.usage already filters src.startswith('/')). Files: storageforge_index/paths.py, remote.py, moves.py, runtimes/docker.py. Tests: tests/test_copies.py, tests/test_workload_capture.py plus a small property test for trailing slash, '/', and /tank vs /tank2.

**Survey record `x11`** (*unchecked*): 'Is this path under that folder' and 'which mount holds this path', written inline 23 times, become two functions.

Copies:

- Three definitions: remote.py:103 is_under, moves.py:283 _under, runtimes/docker.py:451 _under (the last two identical)
- Inline 'p == root or p.startswith(root.rstrip('/') + '/')' 20 more times in 14 files: agentfiles.py:96, changes.py:380,838, scheduler.py:840, security.py:1738,1749, steps_archive.py:349,401, tbstorage.py:77, infragraph.py:647, apiviews.py:208, shares.py:341-342
- Longest-prefix 'the mount of a path' loop five times: changes.py:380, graph.py:246, workloads.py:29, runtimes/docker.py:306, secplus.py:1695
- They disagree on the root: moves._under and changes.py:380 treat root '/' as covering everything explicitly; remote.is_under and most inline copies rely on rstrip, and runtimes/docker.py:306 excludes '/' on purpose

Proposal: paths.under(path, root) and paths.mount_of(path, mounts) in db.py's neighbour or scriptkit; remote.is_under becomes the one definition and the two _under copies import it.

What must survive: Some callers use the check to refuse a destructive step (steps_archive.py:349,401: destination inside source), so the '/' case and trailing slashes must behave exactly as now at each site. changes.py:667 and infragraph.py:639 want 'strictly inside', not 'equal or inside'.

### BE-15. One fstab octal decoder, and the design versions' size text from `capacity.fmt_bin`

**Survey record `steps11`**: One fstab line parser and one byte formatter in Python

Copies:

- storageforge_index/payloads.py:158-159 _unoctal and hostconfig.py:124-125 _unoctal: the same function
- storageforge_index/payloads.py:162-172 parse_fstab and hostconfig.py:113-121 parse_fstab_lines: same split, differing in options as list vs string, 'pass', 'line', and the control-character skip
- Binary size formatting three times: capacity.py:17-28 _fmt/fmt_bin, moves.py:608-613 _fmt (imported by changes.py:26), design_versions.py:175-180 _size

The second reader (S, low risk): Confirmed, and small. payloads._unoctal (payloads.py:158-159) and hostconfig._unoctal (hostconfig.py:124-125) are the same function; hostconfig already imports from payloads (hostconfig.py:29), so there is no cycle.

Corrections on the formatters: the finder's description is wrong. capacity._fmt (capacity.py:17-24) prints no decimals for B and KiB (i < 2) and 'digits' decimals from MiB up; design_versions._size (design_versions.py:175-180) does exactly the same with two decimals. So _size(n) == capacity.fmt_bin(n, 2) for every value below 1024 PiB (fmt_bin also knows EiB, and returns 'n/a' for None where _size would raise). That swap is exact. moves._fmt (moves.py:608-613) is different: one decimal from KiB up and None/0 become '0 B'; fmt_bin(n, 1) would print '1 KiB' where moves prints '1.0 KiB', and that text goes into generated scripts and check messages (changes.py:26 imports it). Leave moves._fmt alone or add an explicit parameter; do not route it through fmt_bin as proposed.

fstab parsers: payloads.parse_fstab (payloads.py:162-172) strips the comment then splits, returns options as a list and 'pass'; hostconfig.parse_fstab_lines (hostconfig.py:113-121) returns options as a string, target_raw, the exact line, and skips a line holding control characters. parse_fstab has one production caller (cli.py:1073, 1088) plus tests; parse_fstab_lines one (hostconfig.py:253). A superset parser with two thin views saves about five lines and would make the control-character skip apply to the cli path too (a behaviour change for payloads' caller unless made optional). Marginal.

Realistic removal about 10-12 lines, not 25.

First commit: storageforge_index/hostconfig.py: delete its _unoctal and import payloads._unoctal (rename to unoctal in payloads.py, keep the old name as an alias). storageforge_index/design_versions.py: _size becomes 'return capacity.fmt_bin(n, 2)'. Tests: tests/test_hostconfig.py, tests/test_props_parsers.py, tests/test_props_capacity.py. Leave moves._fmt and the two fstab parsers as they are.

**Survey record `x6`** (*unchecked*): Byte formatting and size parsing done by hand in a dozen modules use capacity.fmt_bin and capacity.parse_size.

Copies:

- The shared one: capacity.py:17 _fmt, :27 fmt_bin, :44 parse_size
- Three more formatters: canvas.py:24 _bin (always one decimal, '—' for None), moves.py:608 _fmt (one decimal), design_versions.py:175 _size (same rule as capacity._fmt, written again)
- About 20 inline 'x / 2**30 ... GiB' with five different precisions: alerts.py:447,450, clone.py:251-252,385,420, changes.py:800, tasks.py:451,469,480, steps_kvm.py:632, steps_vm.py:394, steps_vmiso.py:183, scheduler.py:844
- Size parsing again: changes.py:690 and :702 and steps_storage.py:314 (float(p['size'][:-1]) * 1024 ** ('KMGTP'.index(...) + 1) three times), placement.py:34 _bytes, runtimes/docker.py:127-134 SIZE_RE, UNITS, _size
- GiB defined again: health.py:80, osoffer.py:21 (capacity.py:14 has it)

Proposal: capacity stays the home. Add capacity.gib(n, digits) for the fixed-unit sentences, and capacity.suffix_size('10G') for the plan grammar of changes and steps_storage. canvas, moves and design_versions call fmt_bin with their digits. runtimes/docker keeps its own table (docker prints 'kB' as 1000, which parse_size reads as 1000 too, but 'GB' vs 'GiB' rules must be compared first).

What must survive: Wording in reports, alerts and exported designs changes by a decimal place; design_versions text is stored and diffed, so its output must stay byte-identical. capacity._fmt prints 'n/a' for None where canvas prints '—'. Integer division (// 2**30) sites round down on purpose when they compare against a need.

### BE-16. One module for reading platform JSON answers: the envelope loaders, list filters, bounded scalar readers and date normaliser copied in eight API modules

**Survey record `api5`**: One answer-parsing module for platform JSON (envelope loaders, list filters, bounded scalar coercers, date normaliser) in place of copies in eight modules

Copies:

- `_load` + `_list` byte-identical in five files: apixo.py:107-118, apitruenas.py:112-123, apidockhand.py:87-98, apiportainer.py:79-90, apikomodo.py:81-92
- `_data` (the 'data' of an envelope) three times: apipve.py:24-29, apireadback.py:26-32, apipangolin.py:83-89 (variant: data must be a dict)
- `_items`: apipve.py:58-62 and apipangolin.py:92-97 (variant: a named key plus pagination.total)
- the scalar coercers _s/_i/_f/_b live in the Proxmox VE reader (apipve.py:32-55) and are imported from it by apipbs.py:18, apipdm.py:20, apixo.py (via import), apidockhand.py:27, apiportainer.py:24, apikomodo.py:25, apipangolin.py:26
- `_when` lives in apitruenas.py:126-138 and is imported by apidockhand.py:113
- `doc = _load(text); doc = doc if isinstance(doc, dict) else {}` repeated: apixo.py:126-127, apiportainer.py:94-95 and :100-101, apikomodo.py:110-111, apidockhand.py:103-104, apitruenas.py:174-175
- bounded list-of-strings idiom repeated: apixo.py:178, apidockhand.py:144 and :157, apitruenas.py:242 and :256, apikomodo.py:114

The second reader (S, low risk): Confirmed by reading: _load and _list are byte-identical in apixo.py:107-118, apitruenas.py:112-123, apidockhand.py:87-98, apiportainer.py:79-90, apikomodo.py:81-92; _data is identical in apipve.py:24-29 and apireadback.py:26-32; apipangolin.py:83-97 is a genuine variant (data must be a dict; _items takes a key and returns a third value, pagination total) and must stay a separate function or an explicit option. _s/_i/_f/_b are imported from apipve by eight modules (apixo imports them directly at :24, not 'via import'). No test and no module outside api*.py references any of these private names (grepped tests/ and storageforge_index/), so re-exports from apipve 'for one release' are unnecessary; just update the eight import lines. No import cycle: the new module imports only json/re/datetime. Realistic removal about 50 lines (four extra _load/_list copies, one extra _data), not 75; the 'as_dict' and bounded-list idioms are one-liners whose replacement is optional and I would leave them. Keep _when's semantics exactly ($date ms, ISO with optional zone, epoch seconds below 2^40) and do not merge the ms heuristic from apixo/apikomodo into it. Do not substitute payloads._b/_i.

First commit: Add storageforge_index/apiparse.py holding _s, _i, _f, _b, _data, _items (moved verbatim from apipve.py:24-62), _load, _list (from apixo.py:107-118) and _when (from apitruenas.py:126-138), same names. Change only import lines and delete the local copies in apipve.py, apipbs.py, apipdm.py, apireadback.py, apixo.py, apitruenas.py, apidockhand.py, apiportainer.py, apikomodo.py; apipangolin.py changes only its _b/_i/_s import and keeps its own _data/_items.

**Survey record `x12`** (*unchecked*): The API adapters' identical JSON loaders and the bounded readers of untrusted values move into one module.

Copies:

- _load (json.loads or None on ValueError, TypeError, RecursionError) identical in five files: apidockhand.py:87, apikomodo.py:81, apiportainer.py:79, apitruenas.py:112, apixo.py:107
- _list (the document as a list of dicts, and whether it was cut) identical in the same five: apidockhand.py:94, apikomodo.py:88, apiportainer.py:86, apitruenas.py:119, apixo.py:114
- _data identical in apipve.py:24 and apireadback.py:26; apipangolin.py:83 the same with one more condition; apipve.py:58 _items is _list over _data
- parse_version identical in apipbs.py:25, apipdm.py:25, apipve.py:65
- apipve's private _s, _i, _b (apipve.py:32-56) are imported across modules already: apiguide.py:27 'from .apipve import _b, _i, _s'
- _text coercers of the same shape: accessproxies.py:28 and tunnels.py:45 (identical but for the limit argument), overlays.py:82, agentdisks.py:32

Proposal: storageforge_index/apiparse.py: load(text), rows(text), data(text), text(v, most), whole(v), flag(v). The adapters keep their parse_* functions and field names. apipve stops being the place other modules import private names from.

What must survive: Pure functions over untrusted text; the RecursionError catch must stay. accessproxies._text treats '***' as absent (a blanked credential) and overlays._text does not: that stays a parameter, not a default.

### BE-17. The three Proxmox readers share one version parser

**Survey record `api8`**: The Proxmox trio shares its identical version parser, backup-verification finding and snapshot cap through one Proxmox module

Copies:

- parse_version identical three times: apipve.py:65-68, apipbs.py:25-28, apipdm.py:25-28
- the api-backup-verify finding three times with the same key: apipve.py:203-206, apipbs.py:183-186, apipdm.py:114-117
- MAX_SNAPSHOTS = 5000 and its counting loop: apipbs.py:20 and :125-142, apipdm.py:22 and :103-107; MAX_BACKUPS apipve.py:20 and :184-189
- snapshot ref key `store/type/id/time` built separately: apipbs.py:144-146 and apipdm.py:108
- the verification sub-object read twice with different strictness: apipve.py:133-135 (any string up to 20) and apipbs.py:75-77 (only 'ok' or 'failed')
- 90 percent full finding twice: apipve.py:208-209 (literal 0.9) and apixo.py:367-369 (FULL_SR)
- apipdm.problems (apipdm.py:112) lacks the `now` parameter the other eight problems() take

The second reader (S, low risk): Only one item is a true duplicate: parse_version is identical in apipve.py:65-68, apipbs.py:25-28 and apipdm.py:25-28. apipbs and apipdm already import private helpers from apipve (and apipdm imports parse_snapshots from apipbs), so no new apiproxmox.py is needed for it; an import does it. Everything else is superficial: (1) the api-backup-verify finding shares its key and kind but filters different object kinds ('backup' in PVE, 'snapshot' in PBS/PDM), lists different identifiers (volid in PVE, ref in the others) and has three title wordings; a helper with those three parameters is as long as the body. Note a pre-existing collision worth knowing, not introduced by this: the key is api-backup-verify:NAME for all three, keyed by connection name, which is unique, so no clash. (2) MAX_SNAPSHOTS loops are semantically different (PBS stops requesting and slices across namespaces with 'snapshot limit of N reached'; PDM and PVE break the inner loop and keep requesting, 'more than N ...: the rest was not read'). (3) Snapshot refs have different prefixes (store[/ns] versus remote/store). (4) Verify strictness (PVE any string up to 20, PBS only ok/failed) is a behaviour decision; problems() only tests == 'failed' in both, so it changes stored data, not findings. (5) The 90 percent findings differ in kind, key, title, detail and null rule (PVE `disk is not None` and ratio > 0.9, XO requires truthy physical_usage); a shared full_problem would take six parameters and must not change keys that carry mute/snooze state. (6) apipdm.problems lacking `now` is harmless: apiread.problems (apiread.py:104) calls every problems() with three positional arguments. Realistic removal about 8 lines, not 35. Do not create a module for this; if candidate 1 later creates apiproxmox.py for the shared read-back, parse_version can move there then.

First commit: In storageforge_index/apipbs.py and storageforge_index/apipdm.py delete the local parse_version and add it to the existing `from .apipve import ...` line (the name stays importable as apipbs.parse_version / apipdm.parse_version for tests/test_props_parsers.py and callers); optionally add `now: float | None = None` to apipdm.problems for a uniform signature.

### BE-18. One parser for the *ports to publish* text, with one record shape, behind the what-if, the Terraform export and the firewall step

**Survey record `toolwork4`**: The 'ports to publish' text ([ip:]host:container[/proto]) and the binds text are parsed by six separate functions; one parser with one record shape replaces them.

Copies:

- storageforge_index/wlexport.py:40-50 _publish -> {ip, external, internal, protocol}
- storageforge_index/whatif.py:101-110 _publish_parts -> {host_ip, host_port, port, proto} (int() without a digit check)
- storageforge_index/mapdesign.py:189-198 _ports_tf -> tuples (int() without a digit check)
- storageforge_index/steps_infra.py:1207-1216 _publish_parts -> (bind, host_port) only
- storageforge_index/steps_workloads.py:546-555 incus_ports -> {bind, published, target, proto} + problems (regex, range-checked)
- storageforge_index/steps_workloads.py:474-488 _ports_of (compose short/long form) -> {bind, published, target, proto}
- storageforge_index/runtimes/docker.py:137-145 _ports (engine inspect) -> {host_ip, host_port, port, proto}
- binds: wlexport.py:53-59 _binds vs mapdesign.py:219-221 inline split vs steps_workloads.py:451-457 compose binds
- the reverse (record -> text) twice: wlcapture.py:83-85 and wlcapture.py:127-129, plus toolbox.py:1089-1090 publish()

The second reader (S, low risk): Four functions parse the same step field: wlexport.py:40-50, whatif.py:101-110, mapdesign.py:189-198, steps_infra.py:1207-1216; incus_ports (steps_workloads.py:546-555) is a fifth, stricter one. Not the same input, keep apart: steps_workloads._ports_of (compose YAML short/long form, published may be a range or empty), runtimes/docker._ports (engine inspect JSON), toolbox.publish (catalog port dict with bind/host/container keys). The two wlcapture formatters (wlcapture.py:83-85, 127-129) are a real identical pair. Differences missed: steps_infra accepts a single field ('8080' -> host port 8080 on 0.0.0.0) and silently drops non-digits, the other three ignore one field; wlexport's 3-field branch still int()s unchecked. The field regex (steps_infra.py:40, '[0-9a-fA-F:.\[\]/,tcpud]{1,400}') lets 'ab:cd' through, so int() can raise ValueError in whatif/mapdesign/wlexport; the routes catch ValueError as a 400 in most places, so the visible defect is an 'invalid literal for int()' message rather than a proven 500. Record shapes differ in type too (wlexport/whatif ints, incus_ports strings): map at the edge. Do not make incus_ports the shared parser as-is: its regex refuses IPv6 binds that the container step accepts. Binds: wlexport._binds (read_only flag) vs mapdesign inline ('ro' in mode[0] is a substring test) vs steps_infra's bind.split(':')[0] - a small real trio. loc ~30.

First commit: Add parse_publish(text) -> (records, problems) next to incus_ports in storageforge_index/steps_workloads.py (IPv4/bracketed IPv6 bind, digit and 1-65535 checks, no exception), and switch whatif._publish_parts and mapdesign._ports_tf to thin adapters over it that keep their present return shapes; valid input yields identical output, invalid parts are skipped instead of raising. Files: storageforge_index/steps_workloads.py, whatif.py, mapdesign.py. Tests: tests/test_design_exports.py, tests/test_workload_steps.py. wlexport and steps_infra follow in a second commit (steps_infra's single-field case decided on purpose).

### BE-19. One function hides a network-language secret in compiled output

**Survey record `netdev8`**: Hiding a DSL secret (a WireGuard private-key) in compiled output is written four times.

Copies:

- storageforge_index/netdevice.py:422-428 _redacted: replaces each SECRET_ATTRS value in compiled['text'] with '<hidden>'
- storageforge_index/routes_network.py:208-213: the same triple loop inline, also over got['files']
- storageforge_index/netdevice.py:496: a regex over SECRET_ATTRS replacing the value with '***' in a refused RouterOS line
- storageforge_index/rostranspiler.py:243 Stmt.text() prints '<hidden>' for the same attributes
- storageforge_index/netdevice.py:411 a fifth walk over SECRET_ATTRS to decide whether the source may be stored

The second reader (S, low risk): Two of the cited sites are the same operation: netdevice.py:422-428 (_redacted, text only) and routes_network.py:208-213 (inline, text and files). Those should be one function. The other three are not copies of it: netdevice.py:496 redacts a single compiled RouterOS line by attribute name with a regex and the marker '***', and has no stmts in scope (the applier only receives `compiled`), so it cannot call a redact(compiled, stmts) without a signature change — leave it, or at most share the attribute-name alternation; rostranspiler.py:242 hides by key while printing a statement, not by value replacement; netdevice.py:411 is a one-line any() that a `secrets_of(stmts)` would make marginally clearer. No test asserts '***' for this path, and '<hidden>' is asserted for the others, so keep both markers as they are. A caution the finder did not raise: both value-replace copies do text.replace(value, '<hidden>'), which also rewrites any other occurrence of the same string in the output; sharing the function preserves that, do not 'improve' it in the same commit. Making the shared function cover compiled['files'] is harmless for netdevice.report since only 'native' (text) is stored, but report must keep returning a string for 'native'. Saving about 8 lines; the value is one place to extend when SECRET_ATTRS grows.

First commit: One commit: in storageforge_index/rostranspiler.py add `secrets_of(stmts) -> list[str]` and `redact_text(text, stmts) -> str`; netdevice._redacted becomes `rostranspiler.redact_text(compiled['text'], stmts)`, routes_network.py:208-213 uses it for got['text'] and each got['files'] value, and netdevice.py:411 becomes `bool(rostranspiler.secrets_of(stmts))`. Line 496 untouched. Tests: tests/test_routers.py Language/Devices/Api, tests/test_props_netlang.py, tests/test_bughunt_rest_b.py Devices.

### BE-20. The folder fingerprint's hash terms are written once, for the per-mount index and the per-subtree compare

**Survey record `shares9`**: The folder fingerprint (same names and sizes in the same layout) is computed by two copies of the same algorithm, one per mount and one per subtree.

Copies:

- storageforge_index/folders.py:166-197 dir_index: accumulate hash((name, size)) per folder, then fold children into parents deepest first with hash(('dir', sum, count)) and hash((name, fp))
- storageforge_index/copies.py:308-354 tree_prints: the same accumulate and fold, its docstring says 'as folders.dir_index makes them for a whole mount', with one stated difference
- storageforge_index/folders.py:23 and storageforge_index/copies.py:34: M64 defined twice

The second reader (S, low risk): Confirmed: folders.py:172-197 and copies.py:318-351 use the same three hash expressions and the same deepest-first fold; M64 is defined at folders.py:23 and copies.py:34.

Corrections:
- The stated gain is already guarded: tests/test_copies.py:738-752 compares tree_prints with folders.dir_index for the same folder. Sharing removes the chance of drift, but it is not unprotected today.
- Removal is about 10 to 15 lines, not 40. Only the fold is cleanly shareable.
- The row loops differ: dir_index also totals raw bytes and entries per dir_id before the symlink skip, caches the accumulator per run of rows, skips rows whose folder is unknown, and keys by (mount, path). It is the hot loop over every file record, so leave it inline.
- The folds differ in bookkeeping: tree_prints builds kids and the largest file (`best`) in the same pass, and first inserts missing ancestors up to root (copies.py:331-336). A shared fold needs a per-child hook or must return the visit order so tree_prints can do its extras in a second pass.
- The keys differ (tuple vs string), so the fold needs depth, parent and name accessors, or dir_index folds per mount.

Worth it mainly for one definition of the three hash expressions.

First commit: In storageforge_index/copies.py import M64 from folders and delete copies.py:34; add to folders.py three one-line functions for the hash expressions (file term, folder print, child term) and use them in tree_prints only, leaving dir_index's hot loop inline with a comment that points at them. Files: folders.py, copies.py. Tests: tests/test_copies.py (FolderCopiesFound, TrashCheck), tests/test_props_folders.py.

### BE-21. One query lists the first-level folders under a path with their sizes, for Moves and the file map

**Survey record `shares10`**: Listing the first-level folders under a path with their sizes is written three times.

Copies:

- storageforge_index/moves.py:318-347 browse: GROUP BY d.path over the subtree, rolled up to the first path segment, plus mounts directly below
- storageforge_index/fsmap.py:173-190 browse: the same query and the same roll-up loop, then fsmap's own extras (shares, planned mounts, crumbs)
- storageforge_index/fsmap.py:143-153 _add_mounts_below vs storageforge_index/moves.py:342-345: mounts below the path, two versions
- storageforge_index/folders.py:108-126 MountDirs.children: the same answer from the kept folder index

The second reader (S, low risk): Confirmed: moves.py:328-340 and fsmap.py:180-190 are the same GROUP BY d.path query and the same roll-up loop, followed by the same query for the folders directly at the path. About 12 lines come out, not 35.

Corrections:
- Placement is wrong. fsmap imports from moves at module top (fsmap.py:12), so a shared function in fsmap that moves.browse calls is an import cycle unless imported lazily. Put it in moves.py beside _subtree_sql and let fsmap import it, as it already imports _subtree_sql, mount_of and subtree.
- The mount handling is not two versions of one thing. moves.py:342-345 lists only mounts directly below, skips state 'gone', and replaces the child with {'entries': None, 'mount': fstype}. fsmap._add_mounts_below also lists the first folder on the way to deeper mounts, adds mounts_inside, uses a mount row and does not skip gone mounts. Keep both.
- moves.browse raises ValueError for an unknown host; fsmap.browse raises LookupError. The routes depend on which.
- MountDirs.children is already used by fsmap.listing (fsmap.py:132) when the kept index is there; server.py:1790 chooses. It reads the kept index, not the tables, so it is a different source and not a third copy to fold in. Letting the Moves picker use the index is a separate feature.

First commit: Add first_level(conn, m, path) -> {name: {name, bytes, entries}} to storageforge_index/moves.py (the body of lines 328-340), call it from moves.browse and from fsmap.browse (replacing fsmap.py:180-190), and leave both mount passes and both return shapes as they are. Files: moves.py, fsmap.py. Tests: tests/test_filemap.py, tests/test_feature_routes.py, tests/test_indexer.py.

### BE-22. One `ufw` opener for the NFS and SMB script and the other share kinds

**Survey record `shares7`**: shares.py and netshares.py each have their own firewall opener for firewalld and ufw; keep one.

Copies:

- storageforge_index/shares.py:920-937 open_fw LABEL PORTS CLIENTS SERVICES...: firewalld by service name, ufw per port and client
- storageforge_index/netshares.py:196-211 open_port LABEL PORT/PROTO CLIENTS: firewalld by port, ufw per client; the ufw grep and allow lines are the same text
- storageforge_index/shares.py:919 cidrs is used by both

The second reader (S, low risk): Confirmed: the ufw branches of shares.py:929-935 and netshares.py:203-209 are the same grep and allow lines, with a port list in one and a protocol in the other. The firewalld branches do different jobs (services vs one port). About 8 to 10 lines come out, not 15.

Differences to keep:
- firewalld messages: open_fw prints "firewalld allows $s" with no label; open_port prints "firewalld allows $port/$proto ($label)".
- open_fw runs add-service then reload joined by `;` (reload runs even when the add failed) and its query does not use -q; open_port joins with `&&`. Under `set -e` these differ when an add fails.
- open_fw is TCP only; open_port defaults to tcp when no protocol is given.
- Layout: open_fw and cidrs are in the shares.py frame (single-quoted strings); open_port is in netshares.BASH, which must hold no apostrophe (it uses double quotes for the same grep). The shared piece has to be written apostrophe-free if it lives in netshares.BASH. Both are only ever in the shares script, so there is no caller outside.
- The stated gain (one place to add firewalld source rules) is a later feature.

Share the ufw loop only.

First commit: Extract ufw_allow LABEL PORT PROTO CLIENTS (the cidrs call, the `any` default and the per-client grep/allow/missing lines, with messages unchanged) next to cidrs in storageforge_index/shares.py, and call it from open_fw (once per port, proto tcp) and from netshares.open_port. The firewalld branches stay as they are. Tests: tests/test_indexer.py (Shares), tests/test_share_drivers_together.py, tests/test_share_gluster.py.

### BE-23. SQLite-or-PostgreSQL spellings (`ts`, `jsonp`) live on the connection, and the agent's writes into scan tables stop calling `Database.sync_mounts` with a stand-in for `self`

**Survey record `webcore10`**: Dialect helpers move onto Conn so modules stop re-deriving SQLite-or-PostgreSQL SQL fragments.

Copies:

- db.py:157-168 ts, distinct, jsonp, boolean live on Database, not on Conn
- agentscan.py:69-74 class _Dialect re-implements ts, and agentscan.py:94 calls Database.sync_mounts(dialect, conn, ...) with that stand-in passed as self
- agentscan.py:90 and agentmonitor.py:115: jsonp written out by hand ('CAST(:inv AS jsonb)')
- agentfiles.py:110-111: ts written out by hand as a lambda; agentfiles.py:222: a boolean parameter chosen by dialect
- server.py:433 and netscan.py:190: the same three-part test (not sqlite, or :memory:, or the file still exists) before alerts.evaluate
- row locking by dialect in two forms: mapdesign.py:302 FOR UPDATE, vault.py:967 and 1076 pg_advisory_xact_lock

The second reader (S, low risk): Confirmed as described. agentscan._Dialect (agentscan.py:69-74) exists only so Database.sync_mounts can be called unbound with a stand-in as self (agentscan.py:94), which breaks the day sync_mounts touches any other attribute of self: a real bug class. jsonp is hand-written at agentscan.py:90 and agentmonitor.py:115, ts at agentfiles.py:110-111. Corrections: Database.boolean is a DDL column type ('INTEGER'/'BOOLEAN'); agentfiles.py:222 needs a parameter VALUE (0 vs False), which is a different helper, so do not present it as the same thing. The deleted-database test differs between its two copies: netscan.py:189 uses getattr(db, ...) with defaults because it is handed test doubles, server.py:433 uses self.scan_db directly; a Database.still_there() method changes what a double must provide. mapdesign FOR UPDATE and the vault advisory locks are two different mechanisms (row lock vs named lock) and are not duplicates; leave them. sync_mounts has exactly two callers (scanner.py:486 as a method, agentscan.py:94). About 15-20 lines removed.

First commit: storageforge_index/db.py: add ts, distinct and jsonp to Conn (they need only conn.dialect) and make the Database methods delegate; have sync_mounts use conn.ts. Then storageforge_index/agentscan.py: delete _Dialect, call conn.ts/conn.jsonp and a module-level or still-method sync_mounts with the real Database-free signature; agentmonitor.py:115 and agentfiles.py:110-111 use conn.jsonp/conn.ts. SQL text identical; run the suite on both dialects.

**Survey record `agentlogs4`**: The agent's writes into scan-owned tables use the scan's own Database code instead of copies made for a bare Conn

The second reader (S, low risk): Seen: agentscan._Dialect (agentscan.py:69-74) exists only so Database.sync_mounts can be called unbound with a stand-in self (agentscan.py:94). That is fragile: sync_mounts uses only self.ts today, and the first other self attribute it uses breaks monitoring-only hosts at run time only. The jsonb cast is hand-written at agentscan.py:90 and agentmonitor.py:115, to_timestamp at agentfiles.py:110, and the mount_usage INSERT at agentscan.py:95-98 is db.py:402-405 word for word. Conn already carries .dialect (db.py:65-67), so ts/jsonp on Conn is clean.

Overstated parts:
- save_inventory: upsert_host's UPDATE (db.py:279-281) writes ip, ssh_*, host_keys and machine_id in one statement after the identity check; apply_monitoring writes three columns. They are not the same write. Leave them.
- FTS helpers forget_file/add_file: db.py:483-486, db.py:540-542 and retire.py:30-33 are set-based statements over temp tables or a host join. agentfiles._apply_index is the only single-row user, so a helper would have one caller.
- agentfiles._epoch is not db.epoch: it never returns None, parses ISO strings and falls back to now. It has one call site (agentfiles.py:216). Replacing it changes behaviour for a NULL started_at.

Realistic removal is about 15 lines, not 50. Moving two methods to Conn does not touch SQL text, so risk is low; both dialects still need a run.

First commit: Add ts(expr) and jsonp(expr) to Conn in storageforge_index/db.py and make Database.ts and Database.jsonp delegate to the same logic. Make sync_mounts a staticmethod taking conn (or have it use conn.ts), then delete agentscan._Dialect and use conn.ts/conn.jsonp at agentscan.py:89-94, agentmonitor.py:115 and agentfiles.py:110. Touches db.py, agentscan.py, agentmonitor.py, agentfiles.py and any caller of sync_mounts in scanner.py. Second commit: Database.record_usage(conn, host_id, at) for the mount_usage insert.

**Survey record `x16`** (*unchecked*): SQLite-or-PostgreSQL choices written outside db.py use the helpers Database already has.

Copies:

- db.py:157-171 has ts(), distinct(), jsonp() and boolean on Database, but Conn carries only .dialect, so modules holding a Conn re-derive them
- jsonb cast twice: agentmonitor.py:115 and agentscan.py:90 (cast = ':inv' if conn.dialect == 'sqlite' else 'CAST(:inv AS jsonb)'), which is db.py:163 jsonp
- to_timestamp twice: agentfiles.py:111 and agentscan.py:73-74 (a copy of db.py:157 ts)
- Boolean literal by dialect: agentfiles.py:222; NOCASE filename prefilter by dialect: protection.py:113 and runtimes/docker.py:290; FOR UPDATE by dialect: mapdesign.py:302, vault.py:967, vault.py:1076

Proposal: Move the expression helpers to Conn (ts, jsonp, distinct, false, for_update, nocase_eq), with Database delegating; the eight sites call them.

What must survive: backup.py:75, reset.py:43,229,258 and server.py:480-2788 branch on the dialect for what the feature is (a file backup exists only for SQLite), not for SQL spelling; they stay. The NOCASE prefilter is a performance choice tied to an index and its string of names is built with chr(39): keep the exact SQL.

### BE-24. One function for a host's short name, and one host-name pattern

**Survey record `webcore8`**: One host-identity module for canonical names, known-host checks and short-name matching.

Copies:

- server.py:353-360 App.canonical and deploy.py:281-286 canonical: the same query, except that the server's ignores a self-reported IP of a host with no ssh_host and breaks ties by last scan
- runner.py:118-122 connect_address: the reverse lookup, name to scanned address
- security.py:100-105 known_host (ValueError), sshcerts.py:98-103 _known_host (LookupError), clamav.py:346-348: canonical plus the same SELECT 1 FROM hosts check, three times with two error types
- moves.py:54-56 host_slug and db.py:37-38 short_name: the same regular expression, with a comment in db.py saying so; fsmap.py:93-95 same_host is a third rule (first label only); moves.py:277-280 find_host a fourth
- tasks.py:31 and scheduler.py:43: the same HOST_RE; scriptkit.py:10 and keyinstall.py:21: the same, different, host pattern

The second reader (S, medium risk): Confirmed: moves.host_slug (moves.py:54-56) and db.short_name (db.py:37-38) are the same expression, kept apart only because db.py cannot import moves; security.known_host and sshcerts._known_host are the same check with ValueError vs LookupError and different texts; clamav.py:346-348 a third with a third text ('has not been scanned' without quotes). Corrections. (1) The two canonical queries must NOT be merged: App.canonical (server.py:353-360) adds 'AND ssh_host IS NOT NULL' to the ip_address arm and orders by last_scanned_at, with a comment saying why (a just-rekeyed host keeps its IP so its key binding still matches); deploy.canonical has 51 call sites across the package. hostid can hold both under two names, nothing more. (2) known_host also refuses an empty name ('not name or'), _known_host does not; texts and error types are what routes answer (400 vs 404). A shared function needs the error class and text passed in, which leaves little saved. (3) The 'same HOST_RE' claim is half right: tasks.py:31 is unanchored and used with fullmatch plus an extra startswith('-') check; scheduler.py:43 is anchored with ^...$ ('$' also matches before a trailing newline, so check how it is called before swapping); scriptkit.HOST_RE and keyinstall.HOST are identical. (4) same_host, host_slug and find_host are three different rules on purpose or by drift and all three share a defect worth reporting on its own: they compare the first dot-label, so two IPv4 addresses with the same first octet match (same_host('10.42.0.3', '10.1.1.9') is True; host_slug of both is '10'). scheduler.check_target and ingest_scan_schedules rely on these. Consolidating without fixing spreads it; fixing changes matching. Removal is about 20 lines.

First commit: New dependency-free storageforge_index/hostid.py with short(name) (the shared expression); moves.host_slug and db.short_name become aliases of it; keyinstall.HOST becomes scriptkit.HOST_RE. Files: hostid.py, moves.py, db.py, keyinstall.py. canonical, known-host checks and same_host are left alone.

### BE-25. One reader of a host's JSON-lines run log, for confirmations, jobs and schedules

**Survey record `steps8`**: One host-side 'record the run and report it to the controller' kit for the job program, the schedule runner and the security programs

Copies:

- Append to runs.jsonl, chmod 0644, trim 600 to 500: storageforge_index/jobscript.py:629-631, schedscript.py:96-98, scriptkit.py:97 recv_tail with :105-106; append without trim at deploy.py:165-166 and tasks.py:1291-1292
- Bearer header in a temp file, optional --cacert /etc/storageforge/report-ca.pem, curl post: jobscript.py:365-368 (emit), jobscript.py:633-640 (report), schedscript.py:101-112, secscripts.py:630 (sentinel send), secplus.py:611
- JSON string escaping for a posted body, two ways: jobscript.py:44 jesc() and schedscript.py:105 a sed/awk pipeline
- Controller side, the 'JSON object per line, skip bad lines' loop four times: confirm.py:33-41, confirm.py:70-78, jobs.py:746-750, scheduler.py:1079-1088

The second reader (S, low risk): Partly real; the proposal is larger than the duplication.

- Trim: the 600-to-500 line appears at jobscript.py:631, schedscript.py:98 and scriptkit.py:97 (recv_tail). jobscript already includes RECEIVE_KIT by text (jobscript.py:57, 973), so it can call recv_tail today with no new kit.
- deploy.py:165-166 and tasks.py:1291-1292 append without trimming. tasks' file is /var/lib/storageforge/tasks/runs.jsonl (tasks.py:1209), the same file recv_record trims at scriptkit.py:106, so it is bounded only when a receive happens on that host. deploy's /var/lib/storageforge/run/runs.jsonl is never trimmed. Real but slow growth (one short line per run).
- The curl posts are not one shape. jobscript reads a token file and builds the header (jobscript.py:366, 636) with a python3 fallback; schedscript builds a body file with captured output and removes files by trap; the sentinel and secplus (secscripts.py:628-632, secplus.py:608-613) use a pre-written $CONF/report.header, no token read, 5 s timeout, and the sentinel backgrounds the call. A single sf_report URL TOKEN_FILE BODY_FILE does not fit the last two without changing how the header reaches the host.
- There are three JSON escapers, not two: jesc (jobscript.py:40, not :44), recv_esc (scriptkit.py:96) and the sed/awk pipeline (schedscript.py:105). They escape different things (jesc turns tab into space and keeps \n; recv_esc drops all control characters; the pipeline is for multi-line output) because the fields differ.
- Python ingesters: confirm.py:33-41 and :70-78 are identical loop heads; jobs.py:746-750 does not strip or test for '{'; scheduler.py:1079-1088 catches Exception around int() conversions too. A jsonl_dicts(text) generator fits all four if it yields only dicts and each caller keeps its own field tests.

The Bash report kit would touch three installed programs and the token path for about 15 lines saved: not worth it. The Python generator and reuse of recv_tail are. Realistic removal about 20 lines.

First commit: Python only: add jsonl_dicts(text) to storageforge_index/confirm.py (strip, skip lines not starting with '{', skip ValueError, yield dicts only) and use it at confirm.py:33-41 and :70-78, jobs.py:746-750 and scheduler.py:1079-1088. Files: confirm.py, jobs.py, scheduler.py. Tests: tests/test_confirm.py, tests/test_scheduler.py, tests/test_sync_engine.py. A separate later commit can make jobscript.py:631 call recv_tail.

### BE-26. A test reads the protocol constants written once in Python and once in Rust and fails when they differ

**Survey record `x5`** (*unchecked*): Protocol constants written once in Python and once in Rust get one test that reads both sources and fails when they differ.

Copies:

- MAX_FRAME = 1 << 20 three times: wire/src/lib.rs:17, agenttunnel.py:37, enclave.py:35
- Tunnel: PROLOGUE agenttunnel.py:34 and agent/src/tunnel.rs:56; PROTOCOL_NAME agenttunnel.py:33 and wire/src/noise.rs:32; TAG and MAX_HANDSHAKE_PAYLOAD agenttunnel.py:36-38 and noise.rs:34-36; CHUNK agenttunnel.py:39 and tunnel.rs:65
- Batches: MAX_BATCH and MAX_RECORDS agentreceiver.py:58-59 and agent/src/tunnel.rs:60-61; NS_BATCH agenttunnel.py:35 and agent/src/sig.rs:25
- agentctl: OPS sfagent.py:56 and agent/src/request.rs:43 (12 names each); REFUSED = 97 sfagent.py:59 and request.rs:38; magic line 'STORAGEFORGE-AGENTCTL 1' in sfagent.py and request.rs:31; NS_REQUEST and NS_MANIFEST sfagent.py:52-53 and sig.rs:21-23; AGENT_USER and ROOT_GROUPS sfagent.py:50,54 and agent/src/host.rs:15,20
- Enclave: NOISE_NAME and NOISE_PROLOGUE enclave.py:39-40 and enclave/src/main.rs:43-44; port 7000 enclave_vm.py:44 and main.rs:46
- Only one static check exists: tests/test_agent_tunnel.py:28-47 compares the IK handshake bytes with wire/src/noise_vector.txt. grep finds no test naming 'storageforge-agent-tunnel-v1', 'storageforge-enclave-v3', 'storageforge-agent-batch' or either Noise name; the rest is caught only by tests that run built Rust programs
- The inventory scan's section names exist in remote.py INVENTORY_SCRIPT and agent/scan/inventory.scan (its header says 'the same names and in the same form'), with no static check

Proposal: tests/test_wire_constants.py: a table of (Python module.NAME, Rust file, const name) pairs; it reads each Rust const with a regex, evaluates shifts and string literals, and asserts equality, plus an NX handshake vector beside the IK one. It needs no cargo build, so it runs in every suite. Nothing moves; each side keeps its constant.

What must survive: Adds a test only. The regex over Rust source must fail loudly when a constant is renamed, not skip it. Some pairs are near-misses that must stay apart: hostlogs.FIELDS (8 names) and agent/src/journal.rs:40 FIELDS (9, with _TRANSPORT) are different lists.

### BE-27. Kernel lines from netconsole and pstore are built by one `hostlogs` function, and the side-source status row is written in one place

**Survey record `agentlogs7`**: Kernel lines from netconsole and pstore are built by one hostlogs function, and the 'side source' status row is written in one place

Copies:

- storageforge_index/netconsole.py:92-97 scrub(_text(message)), skip empty, sha256 key[:32], dict with unit None, ident 'kernel', pid/uid/comm/exe/seqnum None
- storageforge_index/pstore.py:91-96 the same scrub, the same skip, the same key hashing, the same twelve-field dict
- storageforge_index/netconsole.py:85-89 '<N>' priority prefix parse; pstore.py:41,89-90 _KMSG '<N>' priority prefix parse (& 7)
- storageforge_index/hostlogs.py:275 INSERT INTO host_log_status ... 'side' ... ON CONFLICT DO NOTHING; pstore.py:114 the identical statement
- storageforge_index/netconsole.py:93 and pstore.py:91 both reach into hostlogs._text and hostlogs.MESSAGE_CHARS (private names)

The second reader (S, low risk): Seen: the twelve-field dict, the scrub(_text(...)) call and the sha256(...)[:32] key are the same at netconsole.py:93-97 and pstore.py:91-96, and the 'side' INSERT is identical at hostlogs.py:275 and pstore.py:114. Both modules reach into the private hostlogs._text.

The proposed kernel_line() that 'strips an optional <N> prefix and [timestamp]' would change behaviour:
- pstore strips '[  12.345] ' with or without a priority prefix (_KMSG and _STAMP, pstore.py:41-42). netconsole strips no timestamp, and for plain packets takes a priority only from the single digit <0-7> (netconsole.py:85). Sharing the prefix parsing changes stored netconsole messages, and <13> would start being read as a priority.
- Key order differs: netconsole hashes the raw message before scrubbing, pstore hashes the scrubbed one. A helper taking an identity string cannot serve pstore unless pstore scrubs first. Take the identity as a function of the scrubbed message, or return the scrubbed text and let the caller hash it.
- line_key is stored and dedupes re-reads; any change to the hash input duplicates lines.
- pstore.py:114 is still needed when hostlogs.store is not called (no lines), so ensure_side_status has two real callers.

Removal is about 8 lines, not 20. Small, but it removes the cross-module use of a private name.

First commit: Add hostlogs.kernel_line(key_hex, at_us, priority, message), which only builds the dict, and hostlogs.ensure_side_status(conn, host, now). netconsole and pstore keep their own prefix parsing, scrub call and key hashing and call these two. Touches storageforge_index/hostlogs.py, netconsole.py and pstore.py.

### BE-28. The agent's record queue has one *forget these records* and one batch size

**Survey record `agentlogs2`**: One drain of the agent_records queue for log lines, plugin readings and wipe reports

Copies:

- storageforge_index/agentingest.py:42-60 SELECT ... FROM agent_records WHERE plugin='logs' ORDER BY record_id LIMIT 500, json.loads with fallback, group by host, DELETE in chunks of 200
- storageforge_index/agentplugins.py:75-94 same SELECT with plugin IN (...), same json.loads fallback, same try/except errlog.trace per record, identical chunked DELETE line (agentplugins.py:94 == agentingest.py:60)
- storageforge_index/agentguard.py:140-153 same SELECT for plugin='agent' kind='wipe', json.loads fallback, DELETE one row at a time
- storageforge_index/agentingest.py:28 and agentplugins.py:57 RECORDS_PER_TICK = 500 defined twice
- storageforge_index/agentingest.py:117-123 take_once() calls the three drains one after another

The second reader (S, medium risk): Seen: agentingest.py:42-60 and agentplugins.py:75-94 share the select, the decode and a chunked DELETE that is the same line in both; RECORDS_PER_TICK = 500 is defined in both; agentguard.py:140-153 is a third loop.

Differences the finder missed:
- Budgets are separate today: wipe reports LIMIT 50, logs 500, readings 500, and wipe reports are drained first (agentingest.py:119). One drain with one limit ordered by record_id would let a flood of log lines starve wipe reports and readings. Keep per-class limits and the order.
- Bad JSON is handled differently: logs and wipe treat it as {} and go on (a wipe report with unreadable JSON is still acted on, with 'it gave no reason'); agentplugins drops the record without calling a taker. A shared 'bad JSON becomes {}' rule would call takers with {}.
- The wipe loop has no error trap, and it is worse than stated: take_reports runs first in take_once, so one raising record aborts the whole tick (no lines, no readings), every 5 seconds, until someone deletes the row. But putting it under the generic 'trace and delete' policy silently loses a tamper report on a transient failure. That is a security decision for the owner, not a refactor.
- Logs are taken per host in a batch (one store, one sequence-gap pass), not per record, so the proposed handler(host, plugin, kind, ...) signature does not fit them. The wipe taker needs a Database, because wipe() opens its own connection, where the others take a conn.
- Confirmed: unknown kinds of a known plugin are deleted (done.append comes before the taker lookup), and rows of plugins outside the IN list stay.

Honest removal is about 20 lines, not 45.

First commit: Extract only the identical parts: forget(conn, record_ids) (the chunked DELETE at agentingest.py:60 and agentplugins.py:94) and a single RECORDS_PER_TICK, placed in storageforge_index/agentplugins.py (agentingest already imports it) or a new stdlib-only agentqueue.py. Use it from agentingest.take_lines and agentplugins.take. Leave agentguard.take_reports untouched in this commit. Touches agentingest.py and agentplugins.py.

### BE-29. The Proxmox steps share their VMID lookup and their new-VMID check

**Survey record `toolwork10`**: The Proxmox steps repeat the node check, the VMID lookup and the storage-content check per step; guest_check already exists and should be the single entry for all four steps.

Copies:

- node check three times: storageforge_index/steps_proxmox.py:248-250, 318-320, 402-404
- VMID lookup in workloads.listing three times: steps_proxmox.py:254, 324, 412
- VMID range three times: steps_proxmox.py:252, 327, 415; 'already taken / no VMID given' block twice: 323-330 vs 411-418
- storage exists + holds the content type: steps_proxmox.py:351-358 (_storage_check, rootdir) vs 423-429 (inline, images)
- proxmox_node reading fetched twice: steps_proxmox.py:331-335 and 419-421

The second reader (S, low risk): Confirmed inside one module: node check at steps_proxmox.py:248-250, 318-320, 402-404; the workloads.listing VMID lookup at 254, 324, 412; the 'already taken / range / no VMID given' block is identical at 323-330 and 411-418; storage content check 351-358 (rootdir, inside _storage_check which also checks templates) vs 423-429 (images, inline). Corrections: the title's 'guest_check should be the single entry for all four steps' is the wrong shape - guest_check wants the VMID present and of the right kind/name, the two create steps want it absent; small helpers (as the proposal body says) are right. Differences to keep: guest_check compares str(x.get('vmid')) == str(vmid) after int(), the create steps compare against p['vmid'] as a string and check the range only when no guest holds the id (elif); the three node messages name qm+pct / pct / qm and point at different generic steps; the storage 'such as' hint and noun differ ('container disks'/'VM disks'). The inactive-storage warning exists only for containers (359-360); adding it to check_vm is a behaviour change and belongs in its own commit. Saving ~15 lines.

First commit: In storageforge_index/steps_proxmox.py add _guest_at(conn, host, vmid) (the listing lookup) and _new_vmid(conn, h, p, say) (the identical block at 323-330 / 411-418) and call them from guest_check, check_ct and check_vm; messages unchanged. Tests: tests/test_steps_proxmox.py, tests/test_pve_guards.py.

### BE-30. One function returns all containers of a host (scan stacks and rootless Podman), for Workloads and the Toolbox adapters

**Survey record `toolwork9`**: 'All containers of a host' is assembled by hand in several places (scan stacks plus rootless Podman from the reading); one function should return the flat list and every consumer should use it.

Copies:

- storageforge_index/workloads.py:150-159 containers_of(): stacks of docker.listing + reading['podman_rootless']
- storageforge_index/tbadapters.py:287-298 context(): the same two loops, projecting name/image/state/labels/how
- storageforge_index/workloads.py:131-134 and 101-103: the same merge inside listing()/from_infra()
- scan-only consumers that therefore miss rootless Podman: apidockhand.py:307, steps_dockerd.py:442, steps_workloads.py:612-616 (stack name clash check), runtimes/docker.py:455-469 usage()
- host filter typed twice: workloads.py:124-126 and 164-166
- engine socket list three times: workloads.py:13 SOCKETS, wlmanaged.py:82, runtimes/docker.py:432
- panel name tables four times: workloads.py:14 PANELS (image), wlmanaged.py:22 LABEL_MANAGERS (labels), wlmanaged.py:28 PANEL_UNITS (units), runtimes/docker.py:382-383 _manager (folders); wlmanaged.py:20 imports the private docker._manager

The second reader (S, low risk): Only two true copies: workloads.containers_of (workloads.py:150-159) and tbadapters.context (tbadapters.py:287-298). workloads.listing/from_infra (131-134, 101-103) build a different record (_container with mounts, volumes, stack, user) and are not the same job. Corrections: (1) the proposed home, runtimes/docker.py, creates an import cycle: inframeasure imports runtimes.docker at module level (inframeasure.py:18) and the function needs inframeasure.reading. Keep it in workloads.py, which already imports both; tbadapters must import workloads lazily (inframeasure imports tbadapters at line 17). (2) tbadapters.context is given the reading as an argument (it runs in the refresh after a reading), so the helper must take reading= and not re-read it. (3) containers_of has 12 callers (exposure, reach, security, secplus, whatif, infragraph) that take docker records without a 'how' key; do not change what it returns, add a sibling. (4) docker.listing(conn, host) filters by exact hostname or ip_address (docker.py:447), workloads.listing by lower-case name or short name: a 'hosts_matching' helper would change which rows match if applied to docker.listing. (5) The scan-only readers are correct as they are for their question (steps_dockerd counts containers of the daemon being restarted; steps_workloads.py:612-616 checks compose projects of one engine; apidockhand compares with a Docker API) - no change there. (6) The PANELS merge is not a consolidation: four tables keyed on different evidence (image regex, label prefix, unit prefix, folder substring) with different members and first-match order (docker._manager maps '/data/compose/' and '/opt/stacks'); a dict of dicts is not less code. The socket tuple is typed three times (workloads.py:13, wlmanaged.py:82, docker.py:432) and can be one constant. Saving ~10 lines.

First commit: In storageforge_index/workloads.py add containers_with_how(conn, host, reading=None) yielding (container, how) for the scan stacks and the rootless Podman of the reading; containers_of returns [c for c, _ in ...]; tbadapters.context (storageforge_index/tbadapters.py) builds its five-key projection from it via a function-local import. Tests: tests/test_toolbox_adapters.py, tests/test_workload_managed.py. Optional same commit: docker.SOCKETS used by workloads.py, wlmanaged.py:82 and docker.py:432.

### BE-31. One place answers *which plugins does a host's manifest name*, and the label `reported by agent` is defined once

Survey record `agentlogs9` again: see its first appearance above.

### BE-32. One function turns a typed host name into the scanned host, behind the three known-host checks, each keeping its own error

**Survey record `secmap12`**: One function that turns a typed host name or address into the scanned host, in place of the lookups each module wrote.

Copies:

- storageforge_index/deploy.py:281-286 canonical: by name, then ssh_host, then reported IP, in that order
- storageforge_index/security.py:100-105 known_host: canonical plus existence check, ValueError
- storageforge_index/sshcerts.py:98-103 _known_host: the same, LookupError with different words
- storageforge_index/clamav.py:345-348: the same, inline
- storageforge_index/toolbox.py:1002-1005 host_name: its own SQL (name or ssh_host or ip, ORDER BY host_id, no preference order)
- storageforge_index/mapdesign.py:78: name or ssh_host, not IP; hostconfig.py:240, console.py:62, retire.py:22: lower(hostname) only; clone.py:42-46 _host; fsmap.py:124, 177; shares.py:291; placement.py:208; snapjobs.py:705

The second reader (S, low risk): Narrower than claimed. True copies of 'canonical, then must exist': security.known_host (security.py:100-105, ValueError, repr and [:80]), sshcerts._known_host (sshcerts.py:98-103, LookupError 'no host named ...'), clamav.deploy_items (clamav.py:345-348, ValueError, no repr). toolbox.host_name (toolbox.py:1002-1005) is the same match set with ORDER BY host_id in place of canonical's name > ssh_host > ip order, so for an address shared by two hosts, or a name equal to another host's ssh_host, it can pick a different host than a deploy would; that is a real inconsistency worth removing. The rest of the finder's list are not this job: hostconfig.py:240, console.py:62, retire.py:22 select other columns by name only and on purpose (retire.py:35-36 explains why not the IP); mapdesign.py:78 is name or ssh_host and returns 'not scanned' as data, not an error; clone._host goes through changes.hosts/find_host and returns a dict; fsmap.py:124/177, shares.py:291, placement.py:208, snapjobs.py:705 are error lines of their own lookups. deploy.canonical is called from about a hundred places and returns its input when nothing matches; that contract must not change. Errors: ValueError becomes 400, LookupError 404, and the three wordings differ; tests assert 'has not been scanned' substrings for other modules (tests/test_copies.py:467, test_tasks.py:159), none for 'no host named'. Changing toolbox.host_name's order is a behaviour change (only visible with clashing addresses) and should be its own commit with a test. 40 lines removed is high; about 10.

First commit: deploy.known(conn, host) -> hostname or None (canonical plus the existence check). security.known_host, sshcerts._known_host and clamav.deploy_items call it and keep their own exception type and text. Files: storageforge_index/deploy.py, security.py, sshcerts.py, clamav.py. Separate later commit: toolbox.host_name uses it (order changes to canonical's), with a test for two hosts sharing an address.

**Survey record `x9`** (*unchecked*): Finding a host's row by name and reading its inventory, written as raw SQL in 48 modules with four matching rules, becomes two functions.

Copies:

- 'FROM hosts WHERE' 79 times in 48 files: by exact hostname 27 times in 16 files, by lower(hostname) 33 times in 25 files, 'OR ssh_host = :h' 6 times, by host_id 9 times
- 'SELECT inventory_json FROM hosts ...' 17 times with three matching rules: exact (agentdisks.py:95, agentfiles.py:60,71, apitruenas.py:374, sfagent.py:442), lower (blueprint.py:164, agentmonitor.py:56, snapjobs.py:88, steps_services.py:62), lower-or-ssh_host (preflight.py:79), host_id (alerts.py:426, changes.py:359, placement.py:40, scriptkit.py:428, steps_storage.py:36, steps_pools.py:323, shares.py:255)
- The JSON column is decoded by db.loads (db.py:117, used 70 times in 27 files) and also by 16 hand-written copies of '(inv if isinstance(inv, dict) else json.loads(inv or '{}')) or {}': access.py:117, agentmonitor.py:57, apitruenas.py:377, changes.py:360, graph.py:352, moves.py:653, placement.py:41, payloads.py:754, protection.py:108, sfagent.py:443, steps_pools.py:324, steps_storage.py:37, clone.py:281, netfacts.py:214, shares.py:711
- Existing partial helpers that each do one of the rules: security.py:100 known_host, deploy.py:281 canonical, snapjobs.py:87 _inventory, clone.py:42 _host
- 'SELECT ssh_port FROM hosts WHERE hostname = :h' four times, three other spellings once each

Proposal: In db.py (or a small hosts.py): inventory(conn, host_or_id) -> dict and host_row(conn, name, columns) with one stated matching rule (case-insensitive name, optionally the SSH address). The 16 inline decoders call db.loads. security.known_host and deploy.canonical stay as the callers' named checks, built on host_row.

What must survive: The matching rules are not interchangeable: an exact match after deploy.canonical() is deliberate in some callers, and adding 'OR ssh_host' lets an address select a host, which matters where the caller authorises by host name. host_id callers must stay by id. No stored format changes.

### BE-33. One lookup for *the interface that carries this address*, and one list of the controller's addresses

**Survey record `netdev7`**: 'Does SSH from the controller still get in' is answered three different ways for a device change, a plan what-if and a firewall step check, each finding the management interface with its own copy of the same lookup.

Copies:

- storageforge_index/netdevice.py:389-393 cuts_off: finds iif by address, takes only the first controller IP, family 'ip' fixed, calls exposure.kernel_path before/after
- storageforge_index/whatif.py:198-210 _ssh_path and 229-236 _ssh_verdict: every controller IP, ip6-aware, calls exposure._input_path (which also handles ufw/firewalld front ends)
- storageforge_index/steps_infra.py:945-950 _check_fw_rule: no model at all, compares the step's source nets with the controller IPs
- interface-carrying-this-address lookup: netdevice.py:389, whatif.py:216, whatif.py:234, steps_infra.py:1010, reach.py:249
- controller IP wrappers: netdevice.py:359-364 -> steps_infra.py:912-917 -> security.py:1141 (two try/except shims around one function)

The second reader (S, low risk): Only the small pieces are duplicates; the three answers are different questions and the proposed ssh_cut should not replace them. The interface-carrying-this-address lookup is a true five-site copy (netdevice.py:389, whatif.py:216 and :234, steps_infra.py:1010 in a slightly different shape, reach.py:249), and netdevice._controller_ips (359-364) is a try/except shim around steps_infra._controller_ips (912-917), itself a try/except shim around security._controller_ips. But: (1) the two model-based checks use different inputs and different truth tables. cuts_off uses the device row's address and port and reports a cut when before == 'accept' and after != 'accept'; whatif uses hosts.ssh_host/ssh_port and reports when before != 'drop' and after == 'drop', after folding every non-accept result (including firewalld's 'unknown') into 'drop', and returns 'unknown' when backends is empty — cuts_off does not treat empty backends as unknown. Merging them changes one side's answers. (2) 'takes only the first controller IP' is mostly moot: security._controller_ips returns the route source for one address (it returns at the first candidate that works, security.py:1150-1153), so there is normally one entry; the IPv6 gain exists only when the device address is IPv6. (3) steps_infra._check_fw_rule is a pre-deploy parameter check that deliberately works with no reading and decides crit/warn by the rollback flag; giving it a model answer means re-implementing where storageforge-fwrules lands a rule, which whatif._apply_fw_rule already does for the plan what-if — a second copy, not fewer. Scope this to the helper extraction: size S, risk low, about 10 lines saved.

First commit: One commit: add `iface_of(net, addr) -> dict | None` to storageforge_index/exposure.py and use it at netdevice.py:389, whatif.py:216 and :234 and reach.py:249 (each caller keeps taking ['name'] or the dict as it does now); delete netdevice._controller_ips and import steps_infra._controller_ips directly (it already swallows exceptions and takes {'name': ...}). No verdict logic moves. Tests: tests/test_bughunt_network.py CutsOff, tests/test_whatif_sentences.py, tests/test_route_rules.py, tests/test_network_steps.py Checks.

### BE-34. The device adapters take their gateway list and their mask-to-prefix from `netfacts`

**Survey record `netdev5`**: Every device adapter hand-builds the same network, interface, firewall, chain and counter records that netfacts and firewall.py define for a Linux host; give them constructors as firewall._rule already is for rules.

Copies:

- interface record with the same ten keys written out six times: storageforge_index/netfacts.py:170-174, routeros.py:125-128, openwrt.py:121-122, pfsense.py:280-281, cisco.py:351-352, snmp.py:73-74
- 'gateways': sorted({r['via'] for r in routes if r['dst'] == 'default' and r['via']}) five times: netfacts.py:180, routeros.py:151, openwrt.py:137, pfsense.py:290, cisco.py:354
- net record {interfaces, routes, gateways, neighbours, listeners, dns, unreadable, complete}: netfacts.py:179-188, routeros.py:151-154, pfsense.py:290-293, cisco.py:354-355, snmp.py:150-159
- firewall skeleton {readable, backends, policies, chains, rules, nat, zones, notes}: firewall.py:409, routeros.py:244-246, pfsense.py:211-213, cisco.py:358, snmp.py:160; chain dict {backend, table, name, hook, prio, policy, family}: routeros.py:245, pfsense.py:212, cisco.py:360-361, whatif.py:70 and 91, routes_network.py:240
- counter record {iface, rx_bytes, tx_bytes, rx_drop, tx_drop, rx_error, tx_error}: netfacts.py:135-153, routeros.py:287-291, cisco.py:286-302, snmp.py:75; openwrt.py:247-253 reshapes /proc/net/dev into fake RouterOS column names to reuse routeros.counters
- listener rows with a seen-set and scope: netfacts.py:79-92, openwrt.py:150-164, pfsense.py:345-361 (pfsense computes scope by hand at 359 instead of netfacts.bind_scope, so it never says 'link')
- subnet from address+prefix in a try/except: openwrt.py:130-134 and 193-198, pfsense.py:114, 138, 379-384; dotted netmask to prefix: cisco.py:213, snmp.py:113, netconfig.py:289; MAC normalising: snmp.py:50-54, cisco.py:246-247, routeros.py:126
- cisco.py:203 imports routeros._vlans; openwrt.py:247 imports routeros.counters: helpers already borrowed across drivers

The second reader (M, medium risk): The repeated shapes are there as cited (interface dict with the ten keys in netfacts.py:170-174, routeros.py:125-128, openwrt.py:121-122, pfsense.py:280-281, cisco.py:351-352, snmp.py:73-74; the gateways expression five times; the blank counter dict in cisco.py:291 and snmp.py:75; the fw skeleton and chain dicts). But the saving is overstated: these are single long literal lines, and a constructor call naming the same fields is about as long, so iface()/route()/chain() mostly move characters around; 90 lines removed is closer to 25-35. What the finder missed between copies: listener ordering differs per adapter (netfacts sorts by port,proto,addr; openwrt by port,proto; routeros and pfsense by port only) and the result is stored JSON compared in tests, so a shared listener() must not sort; pfsense's dedupe key holds the port as a string and its scope test is by prefix ('127.', '::1') and never says 'link' — switching to netfacts.bind_scope changes stored scope words that exposure reads, and would also need '*' handled (bind_scope on '*'); routeros listeners are fixed 'any' with 'process' and optional 'only_from'; snmp sets 'complete': bool(iface_list or sys_name) and 'gateways': [] with routes unreadable; openwrt only recomputes gateways inside the ubus fallback; neighbour caps are applied in different places (inline [:500] in routeros, inside parse_arp in openwrt, MAX_NEIGHBOURS in netfacts) so a net() that caps again is harmless but one that is the only cap is not equivalent for parse_arp callers. Counters: netfacts._counters skips a link unless both byte counts are ints (strict), routeros.counters coerces anything to 0 (tolerant), cisco/snmp mutate a blank dict in place — 'the same tolerant handling' for netfacts would turn a skipped interface into a zero sample, which traffic.rates would read as a counter reset; keep netfacts strict. cisco and pfsense interface rows carry extra keys (logical, descr, switchport, nat_side, vrf, zone) and cisco's fw has 'interface_acls'; constructors must pass extras through. Mask-to-prefix: cisco.py:213 and snmp.py:113 are the same expression, but netconfig._with_prefix (netconfig.py:286) returns an 'addr/prefix' string and is a different helper. Risk is medium rather than low because every one of these dicts lands in host_network.data_json / security_measurements and tests compare whole records. Worth doing only in the narrow form: shared helpers for what is a true expression copy (gateways_of(routes), blank_counter(iface), prefix_of_mask(mask), vlan ranges now borrowed as routeros._vlans by cisco.py:203, and the generic counters builder openwrt.py:247 borrows from routeros). Skip net(), listener() and fw() constructors.

First commit: One commit adding helpers to storageforge_index/netfacts.py (no new module yet): `gateways_of(routes)` used at netfacts.py:180, routeros.py:151, openwrt.py:137, pfsense.py:290, cisco.py:354; and `prefix_of_mask(mask) -> int | None` used at cisco.py:213 and snmp.py:113. Pure expression moves, no key, default or ordering changes. Tests: tests/test_routers.py RouterOsReading, OpenWrtReading, PfSenseReading, OpnSense26Reading, CiscoReading; tests/test_props_parsers.py; tests/test_infra.py Network.

## 0.6.4: One script kit

### BE-35. One builder for the Ansible task that runs a step's Bash function (`shell_task`, `bash_fn`, `words_of`), in place of about 27 copies. The exported text stays the same byte for byte

**Survey record `steps1`**: One builder for the Ansible export of a step that runs its Bash function, replacing about 27 per-module copies

Copies:

- storageforge_index/steps_desktop.py:143-153 _ansible(fn,args,with_conn): head + bash() + fn call, register sf_out
- storageforge_index/steps_netconsole.py:156-163 same shape, own head
- storageforge_index/steps_overlay.py:400-413 HEAD constant + _ansible(fn,args,args_of)
- storageforge_index/steps_osinstall.py:478-487 same, head differs by doing()/later()
- storageforge_index/steps_mac.py:98-104, steps_offline.py:77-85, steps_tunnels.py:192-202, steps_sshca.py:242-254, steps_tailscale.py:103-110, steps_secretfile.py:94-101, steps_restoretest.py:175-182, steps_runtime.py:376-383, steps_vmiso.py:214-221, steps_vm.py:428-435, rclone.py:213-221, steps_toolbox_b.py:212-221, steps_toolbox.py:473-481, steps_clone.py:257-267 and 338-346: the same task dict each time
- storageforge_index/steps_proxmox.py:222-242 ANSIBLE_HEAD + ansible_of(fn,args,destructive); steps_workloads.py:720-733 a second ANSIBLE_HEAD + ansible_of; steps_dockerd.py:452-458 imports the proxmox head
- storageforge_index/steps_pools.py:589-602, steps_network.py:501-512, steps_kvm.py:689-698, steps_infra.py:1290-1306: same again, each with its own head
- Five spellings of 'params to words': changes.py:1105-1106, steps_overlay.py:408, steps_pools.py:593, steps_tailscale.py:108, steps_secretfile.py:99
- Four copies of 'cut one bash function out of a text by regex': steps_pools.py:594, steps_network.py:507, steps_infra.py:1296-1298, steps_proxmox.py:229 (and a fifth by string index at steps_storage.py:432-433)
- steps_network.py:515-516 and steps_pools.py:606-607: local _reg wrappers that exist only to pass _ansible('t_' + kind, args)
- Destructive gate only in some copies: present at steps_proxmox.py:239-240, steps_pools.py:600-601, steps_workloads.py:783; absent for destructive kinds md-array (steps_md.py:107), vm-revert (steps_kvm.py:727 via _shell), workload-remove and zfs-rollback (steps_infra.py:1451-1453, 1468-1469 via _ansible_bash), os-install and os-remove (steps_osinstall.py:494-508)

The second reader (L, medium risk): Confirmed by reading every cited exporter: the task dict (name, ansible.builtin.shell cmd+executable, register sf_out, changed_when) is the same each time, with a per-module head. changes.ansible() and _ansible_task() (changes.py:1839-1842, 2082-2090) add no central gate, so the gate exists only where a module writes it.

Destructive gate: I rendered every registered destructive kind statically. Ungated today: workload-remove, zfs-rollback, os-install, os-remove, md-array, vm-revert, AND a seventh the finder missed: tool-data-remove (steps_toolbox.py:499), whose head even forces 'DESTRUCTIVE=1; CUR_DESTRUCTIVE=1' (steps_toolbox.py:470). No export head implements the CUR_DESTRUCTIVE test in act() (act is always 'echo changed:'), so the when: is the only gate; these seven run on a plain ansible-playbook. The playbook header (changes.py:2098-2099) promises otherwise. Gated correctly: zfs-add/replace/attach, md-add/replace/grow, luks-format, managed-workload-remove, pve-remove, partition-edit/delete, drive-wipe, secure-delete.

Differences the finder missed or understated:
- 'params to words' is not one rule. desktop/osinstall/toolbox use str(p.get(a) or '') (bool True becomes 'True', not '1'); pools/network/kvm/infra use str(p.get(a)) for non-bools (None becomes the word 'None'); overlay/proxmox/workloads/sshca map bools to '1'/''. changes.script() itself (changes.py:1105) passes raw values and also handles a == 'mkfs'. A single words() must be shown equal per module before it replaces a copy.
- pools and network heads start with 'set -u'; no other head does. info() prints 'echo "$*"' there (no 'info:' prefix), 'info: $*' in overlay/tunnels, silent elsewhere.
- steps_infra._ansible_bash cuts ONE function out of BASH (not the whole text) and returns a LIST for wg-forward (_helper_tasks() + [task]); the builder must allow list results and a per-function FW= value.
- steps_kvm and steps_pools define need() in the head with different message text; services' conflict() does not exit and its skip() is silent while proxmox's skip() prints.
- render signature differs: (t) vs (t, conn); _ansible_task picks by whether args_of is registered (changes.py:1842), so a builder returning (t, conn=None) is safe only if every non-args_of caller tolerates one argument.
- steps_infra already has _shell(name, cmd, changed) at steps_infra.py:1255 doing the dict part.
- Tests execute exported cmd text (tests/test_bughunt_storage.py:58-107, tests/test_md_services.py:286-292), so head text is behaviour, not decoration.

What would break if averaged: changed_when flips where doing() is silent vs 'changed:' (desktop, osinstall, vm, vmiso vs proxmox, workloads, clone); a services export would start failing the play on a conflict; pools/network functions would lose set -u.

Size: 27 modules and 14 test files with load-bearing head variants is L if done in one go; it is safely incremental (one module per commit).

First commit: Two commits, kept apart. (1) Pure refactor, byte-identical output: add changes.shell_task(name, cmd, changed='changed') (the dict steps_infra._shell at steps_infra.py:1255 already builds) and changes.bash_fn(text, name) (the regex used at steps_pools.py:594, steps_network.py:507, steps_proxmox.py:229, steps_infra.py:1296); use them in steps_infra.py, steps_pools.py, steps_network.py, steps_proxmox.py only. Verify by diffing changes.ansible() output for one plan per kind before and after. (2) The bug fix, announced as a behaviour change: in changes._ansible_task (changes.py:1841-1842), after the EXTRA exporter returns, add tags ['destructive'] and the storageforge_destructive when: to every returned task that has no 'when' if TYPES[k]['destructive']; this gates workload-remove, zfs-rollback, os-install, os-remove, md-array, vm-revert and tool-data-remove without touching their modules. Add one test that walks every destructive kind and asserts the when:.

**Survey record `toolwork2`**: Every steps_* module writes its own Ansible shell-task renderer and its own copy of the ok/missing/conflict/act/try shim; one renderer and one shim replace about 27 copies.

The second reader (L, medium risk): Confirmed by reading: steps_workloads.py:720-733, steps_toolbox.py:470-481, steps_toolbox_b.py:212-221, steps_kvm.py:689-698, steps_vm.py:428-435, steps_vmiso.py:214-221, steps_proxmox.py:222-242, steps_dockerd.py:452-457, plus overlay, tunnels, infra, network, pools, services, offline, clone, runtime, rclone. 'sf_out.stdout' occurs in 30 modules. The return dict and the word rendering are true copies; the shim is NOT one thing typed 27 times, it is about 12 independent behaviours: doing() prints 'changed:' (workloads, proxmox, clone, runtime) vs is silent (vm, vmiso, toolbox_b) vs is absent (kvm, overlay, tunnels, offline, rclone, infra); info() silent / echo "$*" (network, pools, offline) / 'info: $*' (overlay, tunnels) and because changed_when is "'changed' in stdout" an echoing info() can flip the result; conflict exits except steps_services.py:165/231; try() absent in offline, rclone, services, clone; later() absent in overlay, tunnels, runtime; durable() absent in kvm, vm, vmiso, proxmox, tunnels; need() has two different texts (steps_kvm.py:694 vs steps_pools.py:597); set -u only in network and pools; NOT_ON_PVE_BASH + STAMP present in workloads/kvm/vm/vmiso/infra and absent in proxmox/toolbox_b; fw_arm/fw_tool stubs differ between infra and network. Corrections to the finder: (1) the 'None' word variant is in six modules, not four: also steps_network.py:505 and steps_pools.py:593. (2) the conn-less fallback differs: steps_toolbox gives ['refused','written without the index'], steps_toolbox_b gives four words, steps_services gives ['','',''], steps_clone gives [''], steps_overlay gives [] - these are positional ABIs of each Bash function. (3) render signatures differ (render(t) vs render(t, conn=None)); changes.py:1842 picks by presence of args_of, so the shared helper must keep both call shapes. (4) steps_infra and steps_network extract single functions by regex and steps_infra can return a list (helper tasks + task) - they do not fit a single ansible_shell(fn, args, bash=...) signature. (5) steps_proxmox adds tags/when, steps_toolbox prepends steps_runtime.BASH + steps_workloads.BASH. A single ANSIBLE_SHIM with ~11 keyword options is a configuration language, not a simplification; composing named fragments (CORE, DOING_CHANGED, DOING_SILENT, LATER, DURABLE, PVE) is safer. Realistic first-pass saving is about 60-80 lines, 220 only after every module is converted.

First commit: Byte-preserving: in storageforge_index/changes.py add shell_task(t, cmd) -> {'name': title(t), 'ansible.builtin.shell': {'cmd': cmd, 'executable': '/bin/bash'}, 'register': 'sf_out', 'changed_when': "'changed' in sf_out.stdout"} and words_of(p, args) with the bool->'1'/'' and falsy->'' rule; use both in the modules that already render exactly that way (steps_workloads.py, steps_proxmox.py, steps_dockerd.py, steps_overlay.py) and shell_task only in steps_toolbox.py, steps_toolbox_b.py, steps_kvm.py, steps_vm.py, steps_vmiso.py. Heads untouched, so the exported text is identical. Second commit: the six str(None) modules move to words_of after checking tests/test_kvm.py, test_vm.py, test_vm_iso.py, test_network_steps.py, test_pool_steps.py.

**Survey record `x1`** (*unchecked*): The Ansible shell-task prelude and task dict that 24 step modules each write out become one function in scriptkit.

Copies:

- All paths are relative to storageforge-indexer
- grep 'APPLY=1; ... ok() {' finds 26 copies in 24 modules, e.g. steps_mac.py:101, steps_tailscale.py:106, steps_restoretest.py:178, steps_pools.py:595, steps_overlay.py:400 (HEAD), steps_tunnels.py:192 (HEAD), steps_proxmox.py:222 (ANSIBLE_HEAD), steps_workloads.py:720
- 23 modules define a top-level _ansible with 23 distinct bodies of 7 to 19 lines (steps_clone.py:113, steps_mac.py:98, steps_tunnels.py:196, steps_overlay.py:404, steps_pools.py:589, rclone.py:213 ...)
- The task dict {'name', 'ansible.builtin.shell': {'cmd', 'executable': '/bin/bash'}, 'register': 'sf_out', 'changed_when': "'changed' in sf_out.stdout"} is written in 26 files; steps_infra.py:1255 _shell already is that helper, used only there
- The parameter-to-words rule (bool becomes '1' or '') is written 10 times: steps_tailscale.py:109, steps_overlay.py:408, steps_pools.py:593 ...
- The copies have drifted: info() is ':' in 19 heads and 'echo "$*"' in 4; later(), durable(), need(), set -u and STAMP are each present in some heads only

Proposal: scriptkit.ansible_shell(title, bash, fn, words, *, helpers=(), destructive=False, changed='changed'), with one ANSIBLE_HEAD that defines every helper (ok, missing, conflict, info, act, try, later, durable, need, STAMP), and scriptkit.words(params, args) for the bool rule. Each step module keeps its BASH body, its argument tuple and any extra words from the database (steps_overlay's args_of, steps_clone's script text). steps_infra._shell moves there.

What must survive: The heads differ on purpose in places and by accident in others; each must be decided: info() silent or printed (printing changes Ansible output and could match 'changed' in sf_out.stdout if an info line contains that word), 'set -u' only in steps_network and steps_pools, the pvenode.NOT_ON_PVE_BASH prefix in steps_kvm, steps_vm, steps_vmiso, steps_workloads and steps_infra, the 'destructive' tag in steps_pools, and steps_clone's changed_when on 'installed'. The playbook text is an exported format users may have saved; golden tests compare it.

### BE-36. One builder for the head of those tasks, used first where the heads are already identical

**Survey record `keysnet11`**: One Ansible wrapper for Bash-backed plan steps (four copies in this cluster, 27 in the package)

Copies:

- storageforge_index/steps_tailscale.py:103-110 _ansible with the head inline at :106-107
- storageforge_index/steps_tunnels.py:192-202 HEAD and _ansible
- storageforge_index/steps_overlay.py:400-412 HEAD and _ansible (adds durable, args_of, and steps_tunnels.BASH)
- storageforge_index/steps_sshca.py:242-254 HEAD and _ansible (adds STAMP, fw_arm, fw_tool)
- storageforge_index/steps_secretfile.py:94-100 the same again
- grep 'APPLY=1; ' finds 27 definitions across the package (rclone.py:216, steps_desktop.py:148, steps_mac.py:101, steps_netconsole.py:159, steps_offline.py:81, steps_osinstall.py:483, steps_runtime.py:379, steps_proxmox.py:222, steps_workloads.py:720 and more)

The second reader (M, low risk): Seen: 27 'APPLY=1; ' lines in 25 files, in at least 13 distinct spellings. More variants than the finder listed, all of which the builder must select: info() silent (most), info() printing 'info: $*' (tunnels, overlay), info() printing bare '$*' (two modules); conflict() that does not exit plus skip() (two); skip() that prints (one ANSIBLE_HEAD); a 'set -u; ' prefix (two); STAMP; pvenode.NOT_ON_PVE_BASH prepended (five); durable(), fw_arm(), fw_tool(), doing(), later(); two heads with no info() at all; one with act/try on the same line. Some sharing already exists and must not be broken: steps_dockerd.py:454 imports steps_proxmox.ANSIBLE_HEAD lazily because of import order with changes.py, and steps_toolbox.py:478 and steps_workloads.py:731 share another ANSIBLE_HEAD. A helper in changes.py is imported by every step module while changes.py imports them at its bottom: build it so it needs nothing from the step modules. Argument conversion differs in three ways (tailscale: bool -> '1'/'', else str(value or ''); tunnels: str(value or '') so False becomes '' and True becomes 'True'; secretfile: `is True`/`is False`): each must be kept per caller or shown equal for that step's field types. Callable signatures differ (render(t), render(t, conn=None), render(t, conn)). Only 4 test lines contain the head text, so the exported playbook is barely pinned: compare exports for every step type before and after. Belongs to the plan-steps cluster, as the finder says; do it there once, not here for five.

First commit: changes.py: add ansible_head(info='quiet'|'say', stamp=False, durable=False, extra='') that returns exactly today's text for the commonest spelling, and use it only in the modules whose head is that spelling byte for byte (the 8 identical 'info() { :; }' heads, including steps_tailscale.py:106-107), with a test that the head of each converted module is unchanged. No change to argument conversion or to the task dict.

Survey record `x1` again: see its first appearance above.

### BE-37. Every destructive step's Ansible export carries the destructive gate. Some exports have none today, because each module writes its own

Survey record `steps1` again: see its first appearance above.

### BE-38. One definition of the secrets folder and the secret-name rule, and one Python check for a step's `secret` field

Survey record `steps3` again: see its first appearance above.

**Survey record `keysnet6`**: One host-side kit for steps that read a delivered secret file, and one Python check and note for their 'secret' field

The second reader (M, medium risk): Seen: the conflict/missing pair is one template in steps_tailscale.py:58-62, steps_tunnels.py:43-46 and steps_pools.py:223-229 (differing only in the noun); three rules for the directory (fixed path in tailscale and luks_key; SF_SECRET_DIR always in tunnels/overlay; SF_SECRET_DIR only when not root in secretstore, secretfile, proxmox, netshares, rclone, restoretest). Corrections: (1) The plan-hash worry is unfounded: changes.plan_hash (changes.py:945-946) hashes the tasks only, not EXTRA_BASH. (2) The claim that an apply brings the secret 'for all of them' is false for LUKS key change: secretstore.secret_fields (secretstore.py:156-159) delivers a field of kind 'secret' or a field literally named 'secret'; steps_pools.py:671 declares F('new_secret', 'name', ...), so new_secret is NOT brought by the apply and its send-secret note is still the truth. A shared note that says 'the plan run brings it' would be wrong there (and whether new_secret should be delivered is a separate bug to decide first). (3) The Ansible exports do not include secretstore.BASH: every _ansible builds HEAD + the module's own BASH (steps_tailscale.py:109, steps_tunnels.py:200, steps_overlay.py:410, steps_secretfile.py:100). Functions moved into secretstore.BASH would be undefined in exported playbooks unless each export adds the kit; and secretstore.BASH ends with a statement that runs at source time ('((APPLY && ${SECRETS_STDIN:-0})) && sf_secrets_in'), so the kit must be a separate constant from that line. In an export nothing arrives on stdin, so send-secret remains the right instruction there. (4) steps_secretfile's sentence is different on purpose (conflict only on apply, mentions the runner stdin) and steps_tailscale has a second, different 'then it needs the auth key' line at :39 and removes the file once Running. (5) tests/test_pool_steps.py, tests/test_apipve.py and the lab scripts assert these sentences. (6) Moving tunnels/overlay to the not-as-root rule for SF_SECRET_DIR breaks any test or lab run that sets SF_SECRET_DIR as root; moving tailscale/luks from the fixed path to the not-as-root rule is safe. Bash saving is small (about 15 lines); the Python check/note helpers save about 20.

First commit: Python only, no script text touched: secretstore.secret_ok(p, say, field='secret') with the existing sentence and the existing per-module pattern passed in, used by steps_tailscale._check, steps_tunnels._check_cloudflared/_check_newt and steps_overlay._secret_ok; one SECRET_DIR constant imported from secretstore by cli, steps_overlay, steps_pools, steps_tailscale, steps_tunnels. Notes and Bash stay as they are until the new_secret delivery question and the export question are answered.

### BE-39. One checked download for VM images: `os-install` and `vm-iso` call `sf_vm_fetch` instead of carrying its body

**Survey record `steps6`**: One 'VM from a downloaded image' kit: the checked download and the libvirt check preamble

Copies:

- Download-and-check, three copies: storageforge_index/steps_vm.py:119-135 sf_vm_fetch (already reused by steps_proxmox.py:197); inline at steps_osinstall.py:260-272 (same lines, in a module that already calls sf_vm_image at :222); inline at steps_vmiso.py:117-125
- Catalog-to-case generator twice, same line: steps_vm.py:262-264 and steps_vmiso.py:150-152
- Check preamble (PVE refusal, reading present, virsh present, stale, name taken, pool exists and has room, placement, bridge warning, network exists): steps_vm.py:369-407 and steps_vmiso.py:159-191 line for line; a third, shorter form at steps_kvm.py:465-475 _libvirt_ready
- steps_proxmox.py:226-229 cuts sf_vm_image and sf_vm_fetch out of steps_vm.bash() by regex for its export

The second reader (S, low risk): Confirmed. steps_osinstall.py:261-272 is sf_vm_fetch (steps_vm.py:119-135) line for line with 'return 0' in place of 'return 1'; the script and the os-install export (steps_osinstall.py:485 includes steps_vm.bash()) already carry sf_vm_fetch, and $sum/$have are not read after line 272, so the call is a drop-in. The two _catalog_case functions (steps_vm.py:262-264, steps_vmiso.py:150-152) differ only in the table. The check preambles match through the pool lookup.

Differences to keep:
- vmiso's download (steps_vmiso.py:117-125) is not the same as sf_vm_fetch before the fetch: with no checksum given it downloads the list and picks the newest file by pattern (viso_pick), setting file, sum and url. After that the fetch block is the same, with "$file" in messages where sf_vm_fetch says $(basename "$url"); those are equal only when file is the URL's basename. vmiso must pass the resolved sum so sf_vm_fetch does not re-read the list.
- The vm-iso export (steps_vmiso.py:214-221) does not include steps_vm.bash(); it would need sf_vm_fetch cut in as steps_proxmox.py:229 does, or the playbook meets 'command not found'.
- steps_vmiso BASH writes printf "%s\n"; sf_vm_fetch uses printf '%s\n'. Both texts are in the same change script already, so the apostrophe rule does not block the call, only a move of the function.
- Check text differs and may be pinned: virsh message ('install libvirt (and virt-install, qemu-img) there first' vs 'install libvirt (a runtime-install step) first'), the free-space sentence ('its disks can grow to N GiB' vs '... with the ISO beside it', need + 2), DEFAULTS vs literals, and vm-create alone handles ISOLATED before the network lookup.
- steps_kvm._libvirt_ready (steps_kvm.py:465-475) is a different contract: no PVE refusal, a warn (not crit) and a different sentence when there is no reading, None return. Leave it out; folding it in needs three flags for twelve lines.

Realistic removal about 40-45 lines, not 70.

First commit: storageforge_index/steps_osinstall.py only: replace lines 261-272 with 'sf_vm_fetch "$url" "$sum" "$sums" "$base" || return 0'. Same messages, same files written, same outcome; script and export already contain the function. Tests: tests/test_osinstall.py, tests/test_osinstall_more.py.

**Survey record `toolwork5`**: vm-create, vm-iso and the VM steps of steps_kvm repeat the same libvirt pre-check in Python and the same prelude and download-and-verify in Bash; one shared VM kit in steps_vm serves all of them.

The second reader (M, medium risk): Confirmed: the Python pre-check (steps_vm.py:373-381, steps_vmiso.py:163-171, steps_kvm.py:465-475), pool/space/placement (steps_vm.py:385-396 vs steps_vmiso.py:174-185), the Bash tools loop and exists-and-ours block, the pool dir lookup, the osinfo fallback, _catalog_case, and the download-and-verify block inlined at steps_vmiso.py:117-125 against sf_vm_fetch (steps_vm.py:119-135). Differences missed: (1) sf_vm_fetch returns 1 on failure and names files by basename of the URL; the vmiso inline copy returns 0 from the step function and names $file - the caller must turn the status into 'return 0' and messages change only in wording. vm-iso resolves file+sum itself via viso_pick before the download, so it would call sf_vm_fetch with a non-empty SUM (the sums-URL branch is then unused). (2) virsh-missing texts differ ('install libvirt (and virt-install, qemu-img) there first' / '(a runtime-install step) first' / 'install libvirt there first'); tests/test_vm.py:150 only asserts 'no virsh'. (3) kvm's _libvirt_ready warns and returns None with a possibly None host (steps_kvm.py:467), vm/vmiso crit and stop - a 'strict' flag is needed as the finder says. (4) space check: vm sums data disks, vmiso adds 2 GiB and words it differently. (5) steps_vmiso.BASH uses double-quoted awk/sed ("NR == 2 {print \$4}") where steps_vm uses single quotes; a kit string must be valid in both embeddings, and steps_vmiso.bash() substitutes "$SF_VM_NS" textually. (6) the whole-plan script concatenates every module's Bash so the kit is present there, but each single-step Ansible export (steps_vm.py:428, steps_vmiso.py:214, steps_kvm.py:689, steps_proxmox.py:226-229) must carry it explicitly; steps_proxmox extracts sf_vm_image/sf_vm_fetch by regex today and would break silently if the functions are renamed or re-indented. The kvm network check (steps_kvm.py:673-681) parses a nics list and checks 'active', not the same job as the vm/vmiso network check - leave it out. loc ~60.

First commit: One implementation of the checksum path: in storageforge_index/steps_vmiso.py replace the inlined .part/.ok download block (lines 117-125) with 'sf_vm_fetch "$url" "$sum" "" "$base" || return 0', and make steps_vmiso._ansible prepend the sf_vm_fetch function taken from steps_vm (expose it as a named constant steps_vm.FETCH_BASH and use that constant in steps_proxmox._vm_helpers too instead of the regex). Files: storageforge_index/steps_vm.py, steps_vmiso.py, steps_proxmox.py. Tests: tests/test_vm_iso.py, tests/test_vm.py, tests/test_steps_proxmox.py.

### BE-40. One reading of a scan's package list, and one table of package names per package manager for the generated scripts and the reinstall plan

**Survey record `steps7`**: One package-manager layer in the generated scripts: detect, test availability, install

Copies:

- storageforge_index/scriptkit.py:452-475 PACKAGES: pm(), apt_install (lock timeout, update-then-retry), install_pkg (EPEL fallback), need_cmd
- storageforge_index/steps_runtime.py:47 detection again (adds apk, image and transactional modes), :56-68 rt_avail, :69-77 rt_install: same commands, no apt update retry, no EPEL
- storageforge_index/rclone.py:45-58 rc_install: its own detection and four install lines, no dpkg lock timeout
- storageforge_index/steps_infra.py:348-359 fw_need_nft: its own detection and four install lines
- storageforge_index/pkglist.py:248-253 here_pm and :275-287 install_these (adds rpm-ostree, transactional-update, apt-rpm, never-remove rules)
- storageforge_index/access.py:46-50 a fifth install ladder; preflight.py:30 and remote.py:379 the detection loop again in probes
- The scan's 'packages' text is parsed twice in Python: scriptkit.py:429-434 package_check and preflight.py:81-85 facts_from_scan
- changes.py:1203-1206 need() only reports, with a package name that is the Debian one (e.g. 'need xz xz-utils' at steps_archive.py:192)

The second reader (M, medium risk): The ladders exist at every cited place. Corrections to the evidence:
- 'rclone and the runtime install do not wait for the dpkg lock today' is half wrong. rt_install has -o DPkg::Lock::Timeout=120 (steps_runtime.py:71) and so does fw_need_nft (steps_infra.py:354). Only rc_install (rclone.py:53) lacks it. What rt_install and fw_need_nft lack is the apt-get update retry; rc_install has that.
- tb_package already calls rt_os and the rt_* functions (steps_toolbox.py:156); it is not a separate ladder.
- scriptkit.PACKAGES is used by many more scripts than listed: clamav.py:337, jobs.py:306, reinstall.py, secscripts.py (five scripts), secplus.py (three), snapjobs.py:718, shares.py, updates.py:142. A change to pm()/install_pkg() changes the text of all of them, including installed programs.
- rclone.LIB is shared with netshares (netshares.py:195 'the rclone library speaks this'), so rc_install runs in scripts that do not contain steps_runtime.BASH. The common layer has to live in scriptkit and be included by both.
- steps_workloads.ANSIBLE_HEAD (steps_workloads.py:723) stubs fw_need_nft for exports, and steps_runtime.BASH is pasted into toolbox exports (steps_toolbox.py:478): a new dependency on PACKAGES must be added to those heads too, or a playbook meets 'command not found'.
- rt_os honours RT_ROOT for tests and sets RT_MODE (image, transactional), which changes what rt_install is allowed to do; pkglist.here_pm maps the same facts to different manager names (rpm-ostree, transactional, apt-rpm) and prefers apt-get only with dpkg-query. These are three different detection contracts, not one with omissions.
- EPEL enabling in install_pkg is keyed on five package names; it is already effectively opt-in.
- access.py:46-50 and the probes run before any StorageForge text is on the host: correctly excluded.

Worth doing as a narrow layer (one multi-package install function with the lock timeout and stale-list retry, used by rc_install, fw_need_nft and rt_install), not as a merged detection. Realistic removal about 30-40 lines.

First commit: Python only, no generated text: scriptkit.package_facts(inv) -> (have set, pm) parsing the scan's 'packages' text once; scriptkit.package_check (scriptkit.py:429-434) and preflight.facts_from_scan (preflight.py:81-85) call it. Keep preflight's 'pm is None when there is no text, else default none' rule. Files: storageforge_index/scriptkit.py, storageforge_index/preflight.py. Tests: tests/test_preflight.py, tests/test_tasks.py.

**Survey record `secmap9`**: One package-name registry and one package-manager detection snippet for every generated script.

The second reader (S, low risk): Partly real. True duplicates of scriptkit.NEEDS: reinstall.TOOLS rows btrfs, nfs, nfs4, cifs, smb3, fuse.sshfs and both reinstall.SERVERS rows (reinstall.py:23-40) hold exactly the command and the apt/dnf/pacman/zypper names NEEDS has, in the same order need_line emits (I compared each value). The rest of reinstall.TOOLS/LAYERS (xfs, f2fs, exfat, ntfs, LUKS, mergerfs, mdadm, lvm, zfs) is not in NEEDS. What does not fit one table: clamav.PACKAGE_NAMES values are two packages per manager ('clamav clamav-freshclam', 'clamav clamav-update') and need_cmd installs one name and tests one command; clone.tools_for returns package names with no command, takes pm values 'transactional' (not a NEEDS key) and has the zfsutils-linux-on-apt-only rule and parted/dosfstools/e2fsprogs with no NEEDS entry; secplus._tools_map is already generated from NEEDS, so it is a second generator, not a second table, and moving it is cosmetic. A fact the finder missed: NEEDS carries separate yum values, but need_line passes only apt, dnf, pacman, zypper and need_cmd uses the dnf name for yum (scriptkit.py:445-461), so 'virtiofsd' yum = 'qemu-kvm-common' is used by package_check's message and secplus.pkg_for but never by need_cmd: the preview can name a different package than the script installs. The package-manager loops (preflight.py:30, rclone.py:48, steps_infra.py:352, steps_runtime.py:47 with apk, remote.py:379, pkglist.py:251-257) are one line each, differ in what they set or print and in the manager list, and several run before any helper is loaded; replacing them changes script bytes for no gain. Leave them. Any change to emitted text moves deploy digests (clamav.py:340-341), so restrict the work to table lookups that produce identical bytes.

First commit: scriptkit.need_tuple(what) -> (command, apt, dnf, pacman, zypper), used by need_line; reinstall.py builds its btrfs, nfs/nfs4, cifs/smb3, fuse.sshfs TOOLS rows and both SERVERS rows from it. Generated scripts stay byte-identical; assert that in the commit by comparing reinstall's script text before and after for a fixture. Files: storageforge_index/scriptkit.py, reinstall.py. Tests: tests/test_recovery.py, tests/test_hostconfig.py, tests/test_props_scripts.py. Do not touch clamav, clone, pkglist or the pm loops.

### BE-41. The share drivers take their *make the share folder* step from the driver helper set

**Survey record `shares5`**: Every share driver repeats the same few bash steps (make the share folder, start or restart its unit, say whether the mount is up); add them to the driver helper set.

Copies:

- Folder exists or mkdir -p, eight copies: storageforge_index/share_nvme.py:135, share_iscsi.py:67, share_nbd.py:113, share_s3.py:58-60, share_rclone.py:96-97, share_sftp.py:45, share_webdav.py:62, share_virtiofs.py:164
- Unit restart-if-changed then enable --now with the same conflict text: storageforge_index/share_sftp.py:126-129, share_iscsi.py:284-287, share_gluster.py:180, share_nbd.py:235-237, share_nvme.py:274-278, share_webdav.py:98-101, share_s3.py:102-106, share_rclone.py:126-129
- Mounted verdict (timeout mountpoint, sleep 2 retry in some): storageforge_index/share_sftp.py:130, share_iscsi.py:288, share_gluster.py:182, share_virtiofs.py:212, share_nbd.py:239-241, share_nvme.py:280-282, rclone.py:131
- sshfs unit ExecStop fusermount line storageforge_index/share_sftp.py:119 duplicates storageforge_index/rclone.py:112

The second reader (S, low risk): The repetition is real, but the copies are less uniform than the finder says and the saving is about 20 to 25 lines, not 60.

- Folder line: byte-identical in share_sftp.py:45, share_webdav.py:62, share_nbd.py:113, share_nvme.py:135 and share_virtiofs.py:164. iSCSI uses act ("would: mkdir -p" in a report); share_rclone says "cache folder"; S3 is an if/elif. A shared share_dir covers the five identical ones without changing a message.
- Unit start: four variants, not one. sftp, iSCSI and gluster: restart `|| true`, then enable --now. WebDAV: a failed restart is a conflict ("did not start again"). S3 and NVMe: is-active first, else enable. NBD: start instead of enable when automount is off. virtiofs (share_virtiofs.py:207-209): tests mountpoint, not is-active, and has a separate is-enabled repair. Gluster at line 180 is the sftp form.
- Mounted verdict: sftp and iSCSI retry after 2 s; NBD retries and prints "mounted from $dev"; gluster, virtiofs and NVMe do not retry; rc_mount_unit prints "$target is mounted".
- The fusermount ExecStop line in share_sftp.py:119 and rclone.py:112 is unit text; sharing it buys one line. Leave it.
- None of these helpers touch unit text, so nothing restarts. The "did not start" texts are barely asserted in tests (one hit).

Do share_dir and mounted_or. A unit_up with three mode flags is not clearer than the two lines it replaces; unify the failed-restart handling only as a deliberate behaviour change.

First commit: Add share_dir PATH to netshares.BASH (storageforge_index/netshares.py:190) with exactly the text of the five identical copies, and call it from share_sftp.py:45, share_webdav.py:62, share_nbd.py:113, share_nvme.py:135 and share_virtiofs.py:164. Output is byte-identical. Tests: tests/test_share_sftp.py, test_share_webdav.py, test_share_nbd.py, test_share_nvme.py, test_share_virtiofs.py, test_share_drivers_together.py.

### BE-42. The rclone-served share kinds share their secret-key list and their mount report

**Survey record `shares3`**: The three rclone-served share kinds (WebDAV, S3, rclone serve) and the rclone-mount plan step each write their own serve unit, login file and client mount preamble; move these into rclone.LIB.

Copies:

- storageforge_index/share_webdav.py:81-102 serve unit text, restart-if-changed, enable, running verdict
- storageforge_index/share_s3.py:85-106 the same unit shape and start logic for `rclone serve s3`
- storageforge_index/share_rclone.py:114-130 the same again, parameterised by serve_as
- storageforge_index/share_webdav.py:68-77 htpasswd from a vault secret into a root-only file; storageforge_index/share_s3.py:67-78 keys into a root-only env file; storageforge_index/share_rclone.py:44-72 rcs_access does both forms
- storageforge_index/share_webdav.py:123-129, storageforge_index/share_s3.py:126-131, storageforge_index/share_rclone.py:150-155, storageforge_index/rclone.py:152-157: the same report-mode block (rclone installed / unit is there / is mounted) four times
- storageforge_index/share_webdav.py:147-149, storageforge_index/share_s3.py:133-136, storageforge_index/rclone.py:159-162: the same rc_config result handling and crypt remote naming before rc_mount_unit
- storageforge_index/share_webdav.py:32-41 webdav_prune, storageforge_index/share_s3.py:110-113, storageforge_index/share_rclone.py:34-43 rcs_drop_files: three prune loops
- storageforge_index/share_webdav.py:175-198 and storageforge_index/share_s3.py:153-171: the same port(), port range check, TLS pair check and plain-HTTP warning in Python; storageforge_index/share_webdav.py:215-218, storageforge_index/share_s3.py:178-182, storageforge_index/rclone.py:194-198: the same crypt_secret checks
- storageforge_index/rclone.py:176-177 and storageforge_index/share_rclone.py:25-26: the secret option key list twice

The second reader (M, medium risk): The cited copies exist, and the listed differences are accurate (NoNewPrivileges only in WebDAV; RestartSec 10/10/15; share_rclone swallows a failed restart; S3 env file without durable or chmod 700).

Missed:
- Any change to unit text restarts the service on the next deploy: unit_file returns changed, then `systemctl restart`. A shared rc_serve_unit must reproduce each of the three bodies byte for byte (header comment, After= line, quoting of --cert, flag order) or every WebDAV, S3 and rclone-serve share on every host restarts once after upgrade. The same holds for rc_mount_unit and client remounts.
- The three unit bodies really differ: S3 has `After=network-online.target local-fs.target`, unquoted --cert/--key and --config before --addr; WebDAV quotes the path and puts --htpasswd before the extras; share_rclone builds its body in pieces with an optional EnvironmentFile. One writer needs about 10 parameters. The start-or-restart tail is the better target than the body.
- The report-mode block is not the same four times: S3 tests is-active before restart and reports `ok running` only when not applying (share_s3.py:102-106); share_rclone prints "mounted" where the others print "$t is mounted"; its info text names the secret; rclone.py uses `command -v rclone`, the drivers use rc_bin.
- rclone.LIB is concatenated into share_webdav.BASH, share_s3.BASH and share_rclone.BASH, and shares.py:702 joins all driver bash, so LIB appears three times in every shares script. Additions triple; include LIB once (in netshares.BASH or the frame) before growing it.
- LIB also runs inside the Ansible shell task (rclone.py:213) with a stub head that has no doing, unit_file, own_file or secret. Functions that call netshares helpers cannot live in LIB; serve-side helpers belong in a share-only string.
- Python: port() is identical in both, but the TLS model is not (WebDAV: cert and key given means TLS; S3: a `tls` boolean plus cert_file and key_file) and the texts differ, so check_tls_pair saves little. The crypt checks have three wordings and tests assert texts.
- SECRET_KEYS: rclone.py:176-177 inline and share_rclone.py:25-26 are the same tuple; trivial and safe to share.

Realistic removal is 60 to 90 lines.

First commit: Two small commits with no change to script output. First: rclone.py exports SECRET_KEYS and uses it at line 176; share_rclone.py imports it and drops its own tuple. Second: add rc_mount_report UNIT TARGET WHAT to rclone.LIB (the three-line report block, with the mounted wording passed in) and call it from rclone.py:152-157, share_webdav.py:123-129 and share_s3.py:126-131 only, leaving share_rclone's variant. Tests: tests/test_netfs_rclone.py, tests/test_share_webdav.py, tests/test_share_s3.py, tests/test_share_drivers_together.py.

### BE-43. One compression codec table for Moves, the job program and the archive step

**Survey record `steps4`**: One compression codec table and one Bash codec kit for Moves, storageforge-job and the archive step

Copies:

- sf_idle defined twice, same body: storageforge_index/jobscript.py:66-70 and steps_archive.py:77-85
- Round-trip verified compressor, three copies: jobscript.py:71-88 sf_compress_verified_stream, moves.py:921-933 archive_compress_cmd, steps_archive.py:115-128 sf_remote_compress_cmd (the last two are the same text but for the function name)
- Verify a file or stream per codec: moves.py:916-920 archive_verify_file, jobscript.py:89-96 sf_verify_stream_stdin, steps_archive.py:130-146 sf_verify_archive_file
- Codec command lines a fourth time, in Python: steps_archive.py:430-444
- Codec tables in Python twice: steps_archive.py:25-37 CODECS, CODEC_EXT, CODEC_TOOL vs moves.py:33 ARCHIVE_CODECS and moves.py:66-72 archive_path (ext by if/else); cli.py:2081 repeats the list; jobs.py:390-427 tests 'xz-extreme' by string to pick the tool
- tar create flags differ between copies: steps_archive.py:87-92 adds --acls --xattrs on GNU tar, moves.py:938 does not

The second reader (M, medium risk): Confirmed: sf_idle is defined three times, not two (jobscript.py:66, moves.py:831, steps_archive.py:77). moves.py:921-933 archive_compress_cmd and steps_archive.py:115-128 sf_remote_compress_cmd are the same text except the final printf quoting ('%s' vs "%s", because the archive step obeys the no-apostrophe rule). Codec tables: moves.ARCHIVE_CODECS (moves.py:33), steps_archive.CODECS/CODEC_EXT/CODEC_TOOL (steps_archive.py:25-37), the literal list at cli.py:2081, and string tests on 'xz-extreme' at jobs.py:390-427 and cli.py:1946.

Corrections:
- 'Round-trip verified compressor, three copies' is two copies and a cousin. jobscript's sf_compress_verified_stream (jobscript.py:71-88) is a function that runs locally with sf_idle and $TMPD; the other two PRINT a self-contained snippet to send over ssh to a host that has no kit. They cannot be one function; at most they share the per-codec command strings.
- The three host programs have different quoting regimes: steps_archive BASH is apostrophe-free by rule, moves uses apostrophes freely, jobscript is a static installed program. A shared kit must be written apostrophe-free, which changes the text (and digest) of every generated Moves script once.
- steps_archive's verify handles .tar.gz/.tar.bz2/.7z by file extension (steps_archive.py:130-146); moves' and jobscript's take only a codec. A shared sf_codec_verify needs both forms.
- moves' tar (moves.py:938) honours onefs and excludes and has no --acls --xattrs; the archive step adds them on GNU tar. That is a content difference in the archive, a decision for the owner, not a refactor.
- The Python Ansible fourth copy (steps_archive.py:430-444) goes away with the second candidate, not this one.

Realistic removal is about 50-60 lines, not 110: the orchestration around each copy stays. The Python table is the cheap, safe half; the Bash kit across an installed program is the risky half.

First commit: Python only, no generated text changes: move CODECS, CODEC_EXT and CODEC_TOOL into scriptkit.py (or keep in steps_archive and import) with a 'streams' flag (False for 7z-ultra); moves.ARCHIVE_CODECS becomes the streaming subset derived from it; moves.archive_path reads the ext from the table; cli.py:2081 uses the table for choices; jobs.py:390-427 asks CODEC_TOOL[codec] instead of comparing with 'xz-extreme'. Files: storageforge_index/scriptkit.py, steps_archive.py, moves.py, jobs.py, cli.py. Tests: tests/test_archive.py, tests/test_sync_engine.py.

### BE-44. One Bash kit for what Moves, `storageforge-job` and the archive step all carry: the idle wrapper, the rsync compression probe and the compress-and-verify command

**Survey record `shares1`**: A Moves plan is executed by two separate bash engines (the hand-run plan script and the deployed storageforge-job); give both one shared engine library.

Copies:

- All paths are relative to
- storageforge_index/moves.py:846-869 rsync_args: base flags -aHAXS, selinux filters, partial-dir, onefs/checksum/delete/bwlimit/excludes/only/dirsonly/keepold/singlefile
- storageforge_index/jobscript.py:580-610 rsync_cmd: the same flag list and the same option order, rebuilt from job conf variables
- storageforge_index/moves.py:836-845 rsync_compress_flags vs storageforge_index/jobscript.py:589-596: identical zstd/level probing
- storageforge_index/moves.py:831-835 sf_idle vs storageforge_index/jobscript.py:66-70 vs storageforge_index/steps_archive.py:77-80: same function three times
- storageforge_index/moves.py:1190-1228 rsnapshot config and per-level timers vs storageforge_index/jobscript.py:655-668 rsnapshot_conf and storageforge_index/jobs.py:235-272 units()
- storageforge_index/moves.py:892-914 git_step (clone --mirror, remote update --prune, ref compare) vs storageforge_index/jobscript.py:749-750 and verify_job at 796
- storageforge_index/moves.py:1113-1130 cutover_step (.migrated-<date> rename) vs storageforge_index/jobscript.py:882-885 cutover_job
- storageforge_index/moves.py:872-880 dst_guard vs storageforge_index/jobscript.py:612 dst_guard
- storageforge_index/moves.py:1162-1188 and 1234-1254 mirror and git service+timer text vs storageforge_index/jobs.py:235-272
- storageforge_index/tasks.py:686 and 703: a third copy of the rsync base flag list for the task language

The second reader (M, medium risk): Only a small core is true duplication; most of the cited pairs are parallel features with different contracts, and the 250-line estimate is about 30 to 40 in practice.

Identical or near-identical (seen):
- sf_idle: byte-identical at moves.py:831-835, jobscript.py:66-70, steps_archive.py:77-85.
- zstd/level probing: moves.py:836-845 (rsync_compress_flags MODE) and jobscript.py:589-596 (inline on $COMPRESS) are the same logic.
- rsync base flags and SELinux filters: moves.py:848, jobscript.py:584, tasks.py:686 and 703, plus the rsnapshot long args in moves.py:1195 and jobscript.py:662.

Not shareable as claimed:
- git verify: jobscript.py:796 verify_job is an rsync dry run. The job has no ref compare, no ls-remote check and no dry run; jobs.units() makes no verify unit for git. Only the clone/update pair is parallel, and the job adds `remote set-url` for routes, another URL form (storageforge-deploy@) and tee to a log.
- cutover: the job refuses a remote source (jobscript.py:892), moves does `ssh sudo -n mv` and writes $STATE/$i.cutover, which moves.progress reads. Shared core is about 3 lines.
- dst_guard: opposite check order, and different reporting (conflict text vs stderr with exit 3 chosen by the caller).
- rsnapshot config: moves writes a persistent /etc/rsnapshot.d file with --protect-args, the sudo rsync wrapper and every retain line; the job writes a run-time temp file with --delete --delete-excluded, -xr filters, SSHO, .storageforge-snap excludes and only retain counts above 0.
- units: moves bakes rsync/git/rsnapshot words into ExecStart through sd_words (RandomizedDelaySec 10min, unit sf-move-PLAN-N); jobs.units() only runs JOBBIN (5min). Nothing here is the same text.
- rsync_args vs rsync_cmd: moves has --protect-args, --human-readable, sudo rsync-path, global CHECKSUM, TIMER_BUILD; the job has --timeout=120 on routes and the .storageforge-snap/.storage.lock/.sf-dedup excludes; bwlimit and compress are in opposite order.

Wrong gains:
- The bug at docs/bug-hunt-2026-11-25.md:345 is already fixed (TIMER_BUILD, moves.py:859 and 1163) and came from install-time baking that only moves has; a shared library would not have prevented it.
- "The hand-run rsnapshot step gains receiver-side filters" is a behaviour change, and not needed: without --delete-excluded the -x filters already apply to both sides (comment at jobscript.py:582).

Constraints the finder missed: steps_archive.BASH goes into the change-plan script, which must hold no apostrophe (steps_archive.py:74), so a library shared with it must be apostrophe-free. Any edit to JOB_SCRIPT makes every host's storageforge-job differ from the deployed file until redeployed.

Keep it to: sf_idle, rsync_compress_flags, and one constant for the base flags and filters. Do not merge units, rsnapshot config, git or cutover.

First commit: New storageforge_index/syncengine.py with an apostrophe-free ENGINE string holding sf_idle and rsync_compress_flags MODE (appends to RS). Embed it in moves.SCRIPT_BODY and jobscript.JOB_SCRIPT, delete their two sf_idle copies and moves' rsync_compress_flags, and replace jobscript.py:589-596 with `rsync_compress_flags "$COMPRESS"` at the same position so the argument order is unchanged. Files: storageforge_index/syncengine.py (new), moves.py, jobscript.py. Covered by tests/test_sync_engine.py (Engine, Portable) and tests/test_archive.py.

**Survey record `shares2`**: The tar-and-compress archive pipeline with round-trip verification is written three times; keep one.

The second reader (M, medium risk): The duplication is real, but in two shapes, and the finder missed the cleanest pair.

- Self-contained snippet string: moves.py:920-932 archive_compress_cmd and steps_archive.py sf_remote_compress_cmd (about lines 104-117) are character-identical except `printf '%s'` vs `printf "%s"`. The finder cited steps_archive 77-143 without naming this.
- Function form: jobscript.py:71-88 sf_compress_verified_stream has the same codec table but uses sf_idle, mktemp under $TMPD and return instead of exit. It is also the forced-command `compress` verb (jobscript.py:175), so its name and behaviour are an interface between hosts running different deployed versions.
- steps_archive's local path is a third shape: no fifo verify. It compresses to the part file and verifies the file afterwards, and supports 7z.

Differences missed:
- steps_archive adds --acls --xattrs on GNU tar (sf_tar_create_flags); moves.py:940 and jobscript.py:190-197 use only --numeric-owner --sparse. A shared archive_tar_cmd must not silently change what existing archive kinds contain; decide it on purpose.
- "Never overwrite an existing archive is in each copy" is wrong. moves refuses and uses `mv -n` (moves.py:1002, 1025). The job's archive branch (jobscript.py:755-786) has no such refusal and uses `mv -f`. steps_archive returns ok when the file exists. A shared archive_land would change one of them.
- moves and the job write $part.sha through tee | sha256sum; steps_archive does so only on the remote-compressor path.
- The snippet runs `nice -n 19 sh -c` on a host with nothing installed; the job form uses ionice through sf_idle.
- The library must be apostrophe-free because steps_archive.BASH is in the change-plan script.

Realistic removal is about 40 to 60 lines (the snippet, sf_idle, the verify-by-codec case), not 150. Leave archive_step, the job's archive branch and t_archive as separate callers.

First commit: Move the snippet generator into one apostrophe-free bash string (for example ARCHIVE_KIT in storageforge_index/steps_archive.py, or in syncengine.py beside sf_idle) under one name, embed it in moves.SCRIPT_BODY and steps_archive.BASH, and delete moves.py:920-932 and steps_archive's sf_remote_compress_cmd, renaming the two call sites in each file. The text sent over ssh stays byte-identical. Files: steps_archive.py, moves.py. Tests: tests/test_archive.py (ArchiveStepsAndOffloadTests), tests/test_sync_engine.py.

Survey record `steps4` again: see its first appearance above.

### BE-45. One function stages tasks as a named change plan, with the clash rule chosen by the caller

**Survey record `secmap10`**: One helper to stage tasks as a named change plan, with the clash rule chosen by the caller.

Copies:

- storageforge_index/secplus.py:319-321 stage_plan: look the plan up by lower(name), replace its tasks (6 callers: 363, 390, 555, 1752, 1772, 2014)
- storageforge_index/routes_infra.py:291-293: the same replace, written inline
- storageforge_index/routes_infra.py:162-166 and routes_network.py:259-262: look up by name, append to the existing tasks
- storageforge_index/changes.py:979-981 save_plan raises 'a plan named ... already exists' when no id is passed: tbfeeds.py:141, 159, sshcerts.py:356, sfnetwork.py:363, notifications.py:200, 230 pass none, so staging the same thing twice fails
- storageforge_index/toolbox.py:1308, 1338 use toolbox._plan_name to make the name unique instead

The second reader (S, low risk): Confirmed: replace at secplus.py:319-321 and inline at routes_infra.py:291-293; append at routes_infra.py:162-166 and routes_network.py:259-262; unique-suffix at toolbox.py:1292-1296; refuse (changes.save_plan's own rule, changes.py:979-981) elsewhere. Corrections: (1) the claimed fix is overstated. sshcerts.py:335/356 and sfnetwork.py:362 put a to-the-second timestamp in the name, so a second staging does not clash; they are already 'unique' by construction and need no change. Only tbfeeds.py:141 and 159 ('Lift bouncer VIP bans on <host>', 'Push quarantine to <tool> on <host>') and notifications.py:200/230 ('Fix: <label>', 'Undo: <label>') can fail on a repeat, and for notifications that refusal sits inside a conn.tx() together with record(): changing it to replace or unique changes what the notification history says, so leave it as 'refuse' until decided. No test asserts the 'already exists' text for these callers. (2) Other name lookups exist that the finder did not list and that must not be folded in blindly: scheduler.py:703, osoffer.py:168, clone.py:460. (3) toolbox._plan_name truncates base to 74 before the suffix and returns the name, which toolbox then also uses for record_install; the helper must return the final name as well as the id for that caller, or toolbox keeps its function. (4) The lookup-then-save pairs are not atomic today (lookup outside save_plan's tx); a helper is the place to fix that but that is a behaviour change, keep it out of the first commit. (5) 'replace' on a plan that has run keeps its plan_id, and get_plan derives ran_at from id and body, so replace semantics already interact with run history; unchanged by a pure move.

First commit: changes.stage(conn, name, tasks, actor, on_clash='replace'|'append') in storageforge_index/changes.py, returning the plan id; secplus.stage_plan becomes a one-line call (its six callers unchanged), and routes_infra.py:162-166, 291-293 and routes_network.py:259-262 call it with their present rule. toolbox, tbfeeds, sshcerts, sfnetwork, notifications untouched. Tests: tests/test_security.py, tests/test_infra.py, tests/test_bughunt_network.py.

### BE-46. One function forgets a deployed unit's mark, and one connection helper for the after-deploy hooks

**Survey record `webcore2`**: One helper builds the install, uninstall, run-now and report items of a host-installed unit and its deployed-table mark.

Copies:

- tasks.py:873-896 mark(host, gone) hook plus the report / --run / --install / --uninstall item shapes and the loop that uninstalls from hosts the task moved away from
- scheduler.py:1355-1385 the same mark(host, gone) hook and the same four item shapes and moved-host loop
- scheduler.py:1414-1423 forget(host) hook: a third copy of open-connection, DELETE FROM deployed, close
- clamav.py:351-366 run / report / apply-or-uninstall items with a mark hook
- security.py:1027-1046 report / apply-or-uninstall items with a done hook
- jobs.py:558-566 done hook: mark_deployed or DELETE FROM deployed
- DELETE FROM deployed written by hand at tasks.py:878, scheduler.py:1362 and 1420, clamav.py:360, security.py:1035, jobs.py:564, receiving.py:372, changes.py:996 while deploy.py:679 mark_deployed is the only shared half
- tasks.py:901-918 and scheduler.py:1434-1440 installed(): the same {ref: [{host, hash, at, by}]} read of deploy.deployed

The second reader (S, low risk): Seen: eight hand-written DELETE FROM deployed, and the connect/try/finally/close hook body at tasks.py:873-884, scheduler.py:1355-1372 and 1414-1423, clamav.py:356-365, security.py:1031-1046, jobs.py:558-566. Corrections. (1) The finder's assumption is wrong: engine.py:102 calls on_ok when status is in deploy.FINISHED = ('ok', 'incomplete') (deploy.py:51), not only on success. So the scheduler hooks' early return on status != 'ok' is load-bearing (an 'incomplete' schedule deploy neither marks nor promotes the pending token), while tasks, clamav, security and jobs do mark on 'incomplete'. A shared hook must take this as a parameter, not unify it. (2) tasks.installed (tasks.py:901-918) is NOT the same as scheduler.installed: it rewrites refs '<id>-<slug>' to the task's current slug from storage_tasks. Only scheduler.installed is the plain grouping. (3) unit_items is not worth it: the four shapes differ per module. Report args are [] (tasks, clamav, security, orphan) vs ['--report'] (scheduler); install flag is --install (tasks, scheduler) vs --apply (clamav, security); run-now carries no on_ok in tasks and clamav but carries mark() in scheduler (token promotion); tasks adds _send_time and one_off; clamav and security use ref=<host> on the item but mark ref 'clamav'/'security'; tasks loops over a list of retired refs, scheduler over one. A helper with that many switches is longer than the code it replaces. (4) receiving.py:372 and changes.py:996 are not hooks of this shape (changes deletes for every host by ref). Real removal is about 30 lines, not 90; the gain is one place that cannot forget to close the connection.

First commit: storageforge_index/deploy.py: add forget_deployed(conn, host, kind, ref=None) (ref None deletes every row of the kind for the host) and a context manager for the hook connection; use them in tasks.py:878, scheduler.py:1362 and 1420, clamav.py:360, security.py:1035, jobs.py:564 with the SQL text unchanged. No change to item shapes, to the status checks, or to either installed().

### BE-47. The Ansible export of `md-array` runs the step's own Bash function instead of a second implementation of it

**Survey record `steps2`**: The hand-written Ansible twins of storage, md and archive steps run the step's own Bash function instead of a second implementation

Copies:

- storageforge_index/steps_storage.py:106-140 wipe_dev() in Bash (shred, dd fallback, blkdiscard, nvme) vs steps_storage.py:437-448 _ansible_wipe_snippet() in Python: same methods, no dd fallback, no 'need' check
- storageforge_index/changes.py:1909 and 1921 call steps_storage._ansible_wipe_snippet for partition and format
- storageforge_index/steps_storage.py:430-434 _ansible_guards() finds dev_guard by scanning vars(changes) for a string
- storageforge_index/steps_storage.py:406-506 _ansible_edit, _ansible_part_delete, _ansible_drive_wipe, _ansible_secure_delete: each re-implements t_partition_edit, t_partition_delete, t_drive_wipe, t_secure_delete (steps_storage.py:106-330)
- storageforge_index/steps_md.py:90-108 _ansible builds mdadm --create, mdadm.conf and mkfs by hand, beside t_md_array at steps_md.py:31-88
- storageforge_index/steps_archive.py:423-466 _ansible_archive rebuilds the tar/zstd/xz/7z pipelines of t_archive (steps_archive.py:156-300) with no remote round-trip verify (ver_cmd = '' at :431)

The second reader (M, high risk): Confirmed: steps_storage.py:406-506, steps_md.py:90-108 and steps_archive.py:423-466 are second implementations of t_partition_edit/t_partition_delete/t_drive_wipe/t_secure_delete, t_md_array and t_archive. _ansible_guards (steps_storage.py:430-434) does find dev_guard by scanning vars(changes) for a string. steps_pools.py:594 is the precedent that the approach works (it already cuts devs_guard and dev_guard out of changes.CHANGE_BODY_3 for an export).

Missed by the finder:
- Helpers the Bash functions need from the change script, by static scan: steps_storage needs act, conflict, dev_guard, human, later, need, try; steps_md needs devs_guard, mkfs_dev, need, try, act and STAMP; steps_archive needs human, later, need, try, act and t_trash (the only existing export-side t_trash is the toolbox one, steps_toolbox.py:470, which is a different implementation from the script's). The head must carry all of these, not only need/later/dev_guard.
- _ansible_edit (partition-edit) has no dev_guard and no changed_when at all; _ansible_drive_wipe has no changed_when; the built-in partition/format wipe tasks (changes.py:1909, 1921) run _ansible_wipe_snippet with no dev_guard and no set -e. So the gap is wider than 'no dd fallback'.
- The twins signal change with "'unchanged' not in stdout"; the Bash functions say 'changed:' through act. changed_when flips form.
- Tests pin the twin text and execute it: tests/test_md_services.py:286-292 rewrites 'c=/etc/mdadm.conf' inside the exported cmd; tests/test_bughunt_storage.py:58-71 runs the drive-wipe/partition-delete cmd and calls steps_storage._ansible_secure_delete directly, asserting stderr 'not a block device'. These must be rewritten, not just kept green.
- t_md_array refuses on a kernel without md_mod and backs up mdadm.conf with $STAMP; the twin does neither. The archive twin ignores the worker round-trip verify (ver_cmd = '' at :431) and writes the .sha256 before mv -n, so a lost race leaves a checksum for a file it did not write.
- All of these kinds need the destructive gate; md-array has none today (see the first candidate).

Risk is high, not medium: these are the wipe/partition/array steps, the exported text is executed by tests, and a playbook that ran before can now refuse (stricter guards). Depends on the builder from the first candidate.

First commit: One kind only, after the builder exists: md-array. steps_md.py registers changes' builder with t_md_array, head = base report helpers + STAMP + need + try + later + devs_guard, dev_guard and mkfs_dev cut from changes.CHANGE_BODY_3 by bash_fn, plus the destructive gate; delete steps_md._ansible; rewrite tests/test_md_services.py:281-295 to stub mdadm/blkid on PATH instead of string-replacing the cmd. Files: storageforge_index/steps_md.py, tests/test_md_services.py. Not behaviour-preserving by nature (the export gains the guard); there is no behaviour-preserving first step other than the builder itself.

## 0.6.5: Platform APIs, network devices and the Toolbox

### BE-48. One platform registry and module contract, so Proxmox VE, PBS and PDM stop being a special case beside the six registered platforms

**Survey record `api1`**: One platform registry and one module contract, so Proxmox VE, PBS and PDM stop being a hard-coded special case beside the six registered platforms

Copies:

- storageforge_index/apiread.py:16 READERS = {'pve','pbs','pdm'} table, then falls back to apiguide.PLATFORMS at :21
- storageforge_index/apiguide.py:238-258 PLATFORMS + register() for truenas/xo/dockhand/portainer/komodo/pangolin only
- storageforge_index/apiconn.py:47-72 KINDS and :73-77 REFUSED, a third and fourth table keyed by the same kind
- storageforge_index/apiguide.py:219-220 SCOPE_HINTS for the Proxmox trio; the others carry scope_hint inside GUIDE (read at :229)
- storageforge_index/apiguide.py:129-180 steps(): `if kind in PLATFORMS: module.steps()` else inline pve/pbs/pdm branches
- storageforge_index/apiguide.py:190-204 action_steps(): same split
- storageforge_index/apireadback.py:131-141 readback(): `if kind in PLATFORMS` else the inline Proxmox permission read
- storageforge_index/apiviews.py:16 PROXMOX tuple; :184, :197, :217-223, :235 branch on it instead of calling module hooks

The second reader (M, medium risk): All cited sites check out (apiread.py:16-21, apiguide.py:129-130/190-191/219-220/238-258, apireadback.py:131-141, apiconn.py:47-77, apiviews.py:16). Corrections: (1) LOC estimate of 60 is wrong: this is almost entirely a move (GUIDES entries ~60 lines, steps ~50, action_steps ~15, Proxmox readback/judge ~60). Real deletions are READERS, three `if kind in PLATFORMS` branches and SCOPE_HINTS: about 10-15 lines net, likely net positive once apiproxmox.py has a header. (2) The 'kind in one table and not another' bug class is NOT removed: KINDS stays in apiconn (correctly, the client must not import readers) and stays a second table keyed by kind; apiguide.kinds() does apiconn.KINDS[k] for every GUIDES key and would KeyError on a mismatch. A one-assert test (set(KINDS) == set(GUIDES)) removes that class far cheaper. (3) Moving REFUSED into each module's GUIDE is wrong: check_token_id (apiconn.py:163) uses it at connection-add time, before any reader is imported, and apiconn must not import readers; REFUSED and REFUSED_USERS must stay in apiconn. (4) apireadback.judge(kind, paths, ...) is the Proxmox privilege-map judge and is called directly by tests (17 direct apireadback calls in tests/test_apireadback.py, 10 apiguide calls in tests/test_apiguide.py, plus tests/test_props_parsers.py); every other module's judge has a different signature, so 'judge' cannot be part of the uniform contract, only readback(client,row). (5) Module contract mismatch the finder missed: registered modules take steps(user, token, scope, expire) and action_steps(action, spec, user) (no token argument), but the Proxmox action_steps text needs the token name (tid = user@pve!token) and steps needs both `expire` and the derived `when`; the contract has to grow a token parameter or Proxmox loses it. (6) apiguide.register() imports each module eagerly at import time; if apipve/apipbs/apipdm become registered, apipbs and apipdm import from apipve at module top, fine, but apiguide._q/_names/GuideError must be imported lazily inside functions as the six do, or there is an import cycle. (7) GUIDES order (pve, pbs, pdm first) drives the connect screen; register order must keep it. (8) apiviews.PROXMOX guards at :184, :223, :235 are currently redundant (none of the three modules defines map_nodes/compare/workloads) and become load-bearing the moment those hooks appear, so this candidate must not be combined with candidate 2 in one commit.

First commit: One commit, no behaviour change: in storageforge_index/apiguide.py add 'pve','pbs','pdm' to a single kind->module map used only for reader lookup (e.g. READER_MODULES = {'pve':'apipve','pbs':'apipbs','pdm':'apipdm', **PLATFORMS}) and make storageforge_index/apiread.py reader() read that one map (delete READERS), keeping the lazy import and ModuleNotFoundError fallback. Add a test in tests/test_apiguide.py asserting set(apiconn.KINDS) == set(apiguide.GUIDES) == set of reader kinds. Leave steps/readback branches for a later commit.

### BE-49. One guarded reading loop for every platform reader (the collector behind BE-01), with one way to count a capped list

Survey record `api3` again: see its first appearance above.

### BE-50. The read-back's token notes (disabled, no expiry, expired) come from one helper

**Survey record `api4`**: The read-back's shared steps (permission probes, token-in-use expiry, action allowances, token notes) become helpers in apireadback rather than five hand-written variants

Copies:

- probe-and-record written four ways: apiportainer.py:184-200, apidockhand.py:203-222, apikomodo.py:185-200, apipangolin.py:202-207
- probes that treat ANY ApiError (timeout, 5xx, budget) as 'not permitted': apikomodo.py:185-189 (`admin = False`), apidockhand.py:218-222 (`users_visible = False`), apiportainer.py:191-195; the others use `except Refused` (apiportainer.py:187, :199, apipangolin.py:199, :206, apidockhand.py:206)
- token default `{'expire': None, 'enable': None}` then try/except ApiError around the expiry lookup: apixo.py:243-247, apitruenas.py:315-322, apidockhand.py:223-227; bare default at apiportainer.py:164, apipangolin.py:208, apikomodo.py:211
- find the token in use in the platform's own key list: apikomodo.py:99-106, apixo.py:141-148, apidockhand.py:111-118, apitruenas.py:317-320
- milliseconds-to-seconds expiry heuristic duplicated: apikomodo.py:105 and apixo.py:147 (`exp // 1000 if exp and exp > 1 << 33`)
- allowed-by-actions set written five times: apireadback.py:69, apiportainer.py:150, apikomodo.py:166, apixo.py:221, apitruenas.py:295
- token notes block duplicated inside one file: apireadback.py:91-101 (judge) and :113-121 (verdict)
- 'the token belongs to X, not Y' note: apiportainer.py:202-203 and apitruenas.py:324-325; apixo.py:249 stores 'user' but never compares

The second reader (S, medium risk): Mostly not duplication; only two pieces survive. (1) Probes: the finder mislabels three sites. apiportainer.py:191-195 is a READ-feature probe (can containers be listed on the first Docker environment); a 502 from a down Docker endpoint correctly means 'containers not readable' and only produces a 'short' feature, never an under-reported privilege, so `except ApiError` is right there. apidockhand.py:218-222 users_visible feeds only extra_read (apidockhand.py:194-195), which is listed and is not a finding, so it cannot under-report 'over'. The single privilege probe where any error under-reports is apikomodo.py:185-189 (admin = False), which does drop the critical 'admin' over entry. That is one bug at one site, not a class. Narrowing it to Refused is risky: tests/apifake.py answers 403 for a non-admin ListUsers (test_apikomodo.py:34), but that fake was written from source reading and the guide is labelled 'not lab-tested'; if a real Komodo answers 400/500 for a non-admin, every non-admin Komodo read-back would then fail outright and the connection would be unreadable. Needs a lab fact before changing. (2) token_in_use: the four finders match on different things (XO compares x['id'] to the SECRET itself in memory, apixo.py:145; Dockhand tokenPrefix; Komodo the key id; TrueNAS a parsed integer) and normalise differently (Dockhand None/'' -> 0 then _when; Komodo 0 means never; TrueNAS parse_keys). A generic helper saves about 2 lines each and pulls a secret comparison into shared code. Folding 'the ms rule' into apitruenas._when would change _when for values between 2^33 and 2^40, which it returns as seconds today. Skip. (3) allowed_privs: five one-liners, replaced by five one-line calls; no gain, and Dockhand/Pangolin do not compute it at all. (4) token notes: apireadback.py:91-101 and :113-121 are a true duplicate (judge adds the privsep note first, verdict appends 'unknown' notes last); a private _token_notes(token, now) removes about 7 lines safely. (5) owner note for XO is a new behaviour, not a consolidation, and risks false notes: XO's token_id is documented as 'name or email' (apiconn.py:58) while parse_me returns name-or-email (apixo.py:128). readback_json key names and the rotation gate (apiconn.py:357-362) are untouched by (4). Realistic removal: about 7 lines, not 70.

First commit: In storageforge_index/apireadback.py extract _token_notes(token, now) (disabled, no expiry, expired, in that order) and call it from judge() after its privsep note and from verdict() before its 'unknown' notes; note order and text unchanged, covered by tests/test_apireadback.py. The Komodo admin probe is a separate bug-fix commit that must wait for a real Komodo answer to a non-admin ListUsers.

### BE-51. One resolver from a platform's node, environment or site to the scanned host it is, without a query per object

Survey record `api6` again: see its first appearance above.

### BE-52. One table of container panels (name, image pattern, label prefixes, unit names, API kind) in place of four partial lists

Survey record `api10` again: see its first appearance above.

### BE-53. The OpenWrt and pfSense appliers share one rollback-timer base

**Survey record `netdev1`**: The OpenWrt and pfSense/OPNsense appliers plant the same shell rollback timer, and the RouterOS and Cisco appliers run the same line-by-line apply loop; give each pair one base class.

Copies:

- storageforge_index/netdevice.py:517-536 OpenWrtApply.plant: set -e, mkdir -m 700 /tmp/sf-<cid>, copy config, heredoc back.sh (sleep N, restore, reload, touch rolled), chmod, start in background, echo planted, raise unless 'planted'
- storageforge_index/netdevice.py:567-587 PfApply.plant: the same script skeleton line for line, only the snapshot/restore/reload lines and the launcher (nohup + echo $! vs start-stop-daemon -m -p) differ
- storageforge_index/netdevice.py:548-552 vs 600-604: confirm (kill pid, rm -rf dir) and alive ('echo ok') duplicated
- storageforge_index/netdevice.py:538-546 vs 589-598: apply = one script ending in 'echo applied', raise unless 'applied'
- storageforge_index/netdevice.py:484-499 RouterOsApply.apply and 649-658 CiscoApply.apply: for each non-empty line run it, test a refusal regex, raise DeviceError naming the line, collect output
- storageforge_index/netdevice.py:457 RouterOsApply.REFUSED vs storageforge_index/routeros.py:42 parse_terse: two different lists of RouterOS refusal words (cisco already shares cisco.ERROR, cisco.py:18)
- storageforge_index/netdevice.py:512-515 and 565: the SF-55 directory rule is explained once and referred to from the copy

The second reader (S, medium risk): Half of this survives. The shell-timer pair is real (netdevice.py:517-536 vs 567-587): the skeleton is shared (set -e, mkdir -m 700, heredoc back.sh with sleep/restore/reload/touch rolled, chmod, launch, echo planted, raise 'could not plant the rollback'), and alive() is identical. Differences a base class must keep as hooks: OpenWrt makes a second directory (mkdir {dir}/config) and uses cp -a of a tree; pf resolves $c via CONF both in the outer script and again inside back.sh, and removes /tmp/config.cache; launcher differs (start-stop-daemon -S -b -m -p writes the pid itself vs nohup ... & plus echo $! > pid); OpenWrt confirm also runs pkill -f back.sh. tests/test_routers.py RollbackFolder (1467-1510) runs both plant scripts under /bin/sh with cp/nohup/start-stop-daemon shimmed, sets applier.dir after construction and asserts mode 0700, 'sleep 60' in back.sh and DeviceError 'could not plant' — so the hooks must read self.dir at plant time, not in __init__. The two apply() bodies are NOT alike beyond the final 'applied' test (uci revert on failure with message 'the router refused it' vs read+merge+base64 upload with 'the firewall refused it'; test_routers.py:459 and test_bughunt_network.py:98 call them directly) and should not be templated. The LineApply half is not worth it: the shared part is a 5-line loop, and the copies differ in everything around it (RouterOS pre-prints the filter table when place-before=N is present, rewrites place-before to [find comment=...], redacts SECRET_ATTRS in the message, says 'the router refused'; Cisco appends run('end'), uses a re.M anchored regex, says 'IOS refused'). Three hooks to share five lines adds code. The REFUSED vs parse_terse word lists (netdevice.py:457, routeros.py:42) do different jobs: one judges a command's answer, the other judges whether a table print is readable; the reader lacks 'failure', 'invalid value', 'input does not match' on purpose-or-by-luck and widening it would make a table with those words in a comment unreadable. Naming both constants in routeros.py is fine but saves nothing. Realistic saving is about 15-20 lines, not 60. Also note tests/test_routers.py:1360 patches netdevice.APPLIERS with mock.patch.dict and tests name netdevice.OpenWrtApply/PfApply/RouterOsApply/CiscoApply: the classes must stay importable from netdevice.

First commit: One commit in storageforge_index/netdevice.py only: add a private `_ShellTimerApply` base holding plant() (script skeleton built from four class-level hooks: snapshot lines, restore lines, launcher lines, and nothing else), alive(), and the 'planted' check with the same DeviceError text; OpenWrtApply and PfApply subclass it and keep their own __init__, apply() and confirm() untouched. Verify by diffing the generated script text of both classes before and after for cid=42, secs=60 (must be byte-identical), then tests/test_routers.py RollbackFolder, Devices, OpnSense26Change and tests/test_bughunt_network.py OpenWrtRefusal, LateConfirm. Leave RouterOsApply and CiscoApply alone.

### BE-54. The SSH password environment and options are written once, and `netdevice.session` builds its transport from one table

**Survey record `netdev3`**: netdevice.session builds a transport in five near-identical branches, and the SSH password (askpass) environment and options are written out four times across nettransport, keyinstall and access.

Copies:

- storageforge_index/netdevice.py:151-160, 164-172, 173-178, 185-191, 192-196: five try/yield/finally/close blocks; the cli-vs-direct choice is duplicated for password auth and for agent auth
- storageforge_index/netdevice.py:154-156 Telnet branch sends `terminal length 0` by hand although PROFILES['cisco'].setup (nettransport.py:61) already sends it in _ready()
- storageforge_index/netdevice.py:148 and 212-214: the vault credential release is written twice (session and the SNMP read)
- storageforge_index/nettransport.py:269-270 and 501-502,517: SSH_ASKPASS env and 'PubkeyAuthentication=no, PreferredAuthentications=password,keyboard-interactive, NumberOfPasswordPrompts=1' in NetworkTransport and again in DirectTransport
- storageforge_index/keyinstall.py:103-108 and storageforge_index/access.py:239-244: the same options and the same env dict again

The second reader (S, medium risk): Both parts are real, with corrections. Askpass: the four env keys (SSH_ASKPASS, SSH_ASKPASS_REQUIRE, DISPLAY, STORAGEFORGE_ASKPASS_SECRET) are identical at nettransport.py:270, :502, keyinstall.py:107 and access.py:243, but the surrounding env is deliberately different: the two transports start from remote.child_env() (the whole process env minus STORAGEFORGE_*), keyinstall and access build a minimal env of only PATH and a throwaway HOME. A helper must return just the four keys for the caller to merge; it must not return a full env. The helper cannot live in remote.py as proposed: askpass_path() is in keyinstall.py and keyinstall imports from remote (keyinstall.py:16), so put `askpass_env(password)` and `PASSWORD_AUTH_OPTS` in keyinstall next to askpass_path (nettransport already imports from there lazily). The three -o options are in a different order in nettransport (Pubkey, Preferred, Number) than in keyinstall/access (Preferred, Pubkey, Number, then ConnectTimeout); ssh does not care, but keep each site's surrounding options (StrictHostKeyChecking=yes, known hosts, ConnectTimeout) where they are. DirectTransport also strips BatchMode=yes and inserts before '--'; NetworkTransport chooses StrictHostKeyChecking yes/accept-new on the same `if password`; both stay local. session(): the branches are less alike than 'five near-identical': Telnet takes user positionally with no known_hosts/legacy and never calls require_confirmed; password-cli calls enable for cisco; agent-cli does NOT call enable at all (no enable secret exists without a stored credential) — a factory that 'moves enable into the platform entry' would start sending `enable` on key auth and fail with 'enable was refused/wants a password'; cli branches yield t.run (default timeout = command_timeout), direct branches yield a lambda that passes timeout explicitly; direct uses _login() for the RouterOS user suffix while NetworkTransport appends the suffix itself. Do not remove the Telnet `terminal length 0` in the same change: it is sent after enable, while PROFILES['cisco'].setup runs in _ready() before enable; it is probably redundant on IOS but there is no test that proves the pager stays off across enable (tests/test_nettransport.py:394 only checks the SSH path), and this is a live-device path. The vault release duplication (netdevice.py:148 vs 212-214) is 3 lines and passes the same platform value; fine to share. Realistic saving about 20-25 lines.

First commit: Commit 1 (credential plumbing only): add `askpass_env(password) -> dict` (the four keys) and `PASSWORD_AUTH_OPTS` (the three -o pairs, as a flat list) to storageforge_index/keyinstall.py and use them at keyinstall.py:103-108, access.py:239-244, nettransport.py:269-270 and :501-502/:517, keeping each site's base env and other options. Tests: tests/test_keyinstall.py, tests/test_nettransport.py (RealSshTerminal, Credentials, Legacy). Commit 2, separately: in netdevice.session() collapse the four SSH branches to one `t, run = ...` followed by a single try/yield/finally, keeping the Telnet branch, the enable-only-with-a-stored-credential rule and require_confirmed exactly where they are.

### BE-55. A what-if over a firewall lays the new rules onto the machine's real chains the same way for a device change and for the planner

**Survey record `netdev6`**: Laying DSL statements over a read firewall model for a what-if is done twice, with only the device copy mapping rules onto the machine's real chains.

Copies:

- storageforge_index/netdevice.py:374-388 cuts_off: to_model_rules(stmts, max order, existing), then maps table 'filter'/chain 'input' onto the device's own base chain for that hook, then sorts rules by order; ignores NAT
- storageforge_index/routes_network.py:237-241 api_dsl_whatif: the same to_model_rules call with the same max-order expression, the same sort, adds NAT, invents chains only when the host has none, and does no chain mapping (so on an nftables or OpenWrt host the added rule sits in a chain kernel_path may not walk)
- storageforge_index/rostranspiler.py:1064-1087 shadowed_notes and 1090-1128 to_model_rules each rebuild the same by_chain index and place-before insertion
- storageforge_index/whatif.py:39-78 _apply_fw_rule: a third 'put this rule into the model where it would land', per backend, for plan steps
- storageforge_index/routes_network.py:47-58 tasks_of turns the same statements into fw-rule steps that whatif then models through that third path

The second reader (M, medium risk): Confirmed: netdevice.py:374-388 and routes_network.py:237-241 make the same to_model_rules call with the same max-order expression and the same sort, and only cuts_off remaps table/chain onto the model's base chain by hook. exposure.kernel_path (exposure.py:178-189) indexes rules by (table, chain), and to_model_rules stamps every added rule backend 'routeros', table 'filter' (rostranspiler.py:1116), so in /api/dsl/whatif an added input rule only takes effect where the host happens to have a chain (filter, input) — the finder's point holds for fw4 (table fw4), cisco (table 'acl') and most nftables hosts. Missed and worse: the last hop in reach.query uses exposure._input_path (reach.py:300), and on a ufw host ufw_path only walks rules with backend == 'ufw' (exposure.py:201); firewalld takes its own zone path too. So on ufw/firewalld hosts the added rules are not seen at all, and base-chain mapping alone does not fix that — a shared overlay needs to know the front end, which is exactly what whatif._apply_fw_rule does for plan steps. This makes the route half a behaviour change with real design work, not a consolidation: size M. Other differences to keep: the route invents chains with backend 'dsl' and family None and sets backends ['dsl'] for a firewall-less host, cuts_off instead answers cuts: None when an input rule has no chain and silently drops unplaceable forward/output rules; the route merges NAT, cuts_off must not; the route computes shadowed_notes for every machine while report() only does for routeros (netdevice.py:403-407). shadowed_notes and to_model_rules do rebuild the same by_chain index (rostranspiler.py:1066-1070 vs 1096-1100), and shadowed_notes calls to_model_rules once per statement, a 6-line duplicate worth a private helper. Savings about 10-15 lines; the value is the correctness fix, which needs fixtures per backend.

First commit: Behaviour-preserving commit: in storageforge_index/rostranspiler.py add `_by_chain(existing)` used by shadowed_notes and to_model_rules, and `place_on_base_chains(chains, rules) -> (mapped, unplaced_hook | None)` holding the loop now at netdevice.py:377-387; netdevice.cuts_off calls it and keeps its own 'no chain to land in' answer. routes_network.py is not touched in this commit. Tests: tests/test_bughunt_network.py CutsOff, tests/test_routers.py Language/Devices, tests/test_props_netlang.py. A second commit, with new fixtures for fw4, nftables, ufw and firewalld hosts, then switches /api/dsl/whatif to the helper.

### BE-56. Exposure classifies VPN interfaces with the overlay naming table, by name only: a WAN address behind carrier-grade NAT stays WAN

**Survey record `keysnet8`**: Exposure classifies VPN interfaces with the overlay naming table instead of its own prefix list

Copies:

- storageforge_index/exposure.py:24 VPN_NAMES = ('wg', 'tun', 'tap', 'tailscale', 'nebula', 'zt', 'netbird') and :242 name.startswith(VPN_NAMES)
- storageforge_index/overlays.py:33-36 INTERFACES: the table of record, also sf0, ts0, wt0, nm-*, ziti0, ovpn*, ipsec/vti/xfrm, and :39-57 network_of with the tool's own account of its interface and the 100.64.0.0/10 rule
- console.py:71-81 and infragraph.py:170 already use overlays.network_of

The second reader (S, medium risk): Seen: exposure.py:24 VPN_NAMES with startswith at :242, against overlays.INTERFACES with fullmatch. This is not a behaviour-preserving merge and the risk is understated. (1) The CGNAT rule must not come along: network_of(name, address) calls any interface with an address in 100.64.0.0/10 'overlay'. On a host whose uplink is behind carrier-grade NAT (many mobile and satellite ISPs) that is the WAN interface; exposure would move its listeners from 'lan' to 'vpn', the less-reachable direction the module docstring calls the costly error (ORDER vpn 2 < lan 3, and exposure.py:275 keeps a vpn class from being widened). Pass no address, or only consult `known` for addresses a tool claimed as its own. The finder's 'vpn is a narrower claim than lan' argues against the change, not for it. (2) Name matching narrows as well as widens: startswith('tun') today catches tunl0/tun-anything, 'tap' any tap*, 'zt' anything, 'netbird'/'nebula' any suffix; the table needs (tun|tap)\d+, zt[0-9a-z]{6,13}, nebula\d*. Those move vpn -> lan (the safe direction). New vpn: sf0, ts0, wt0, nm-*, ziti*, ovpn*, ipsec/vti/xfrm, and whatever a tool reading names. (3) _iface_class(iface) is called from _interfaces(net) (exposure.py:299), which has no infra: `known` has to be threaded through _interfaces and its callers, it is not 'already there'. (4) An interface has several addresses; 'first address' is arbitrary. (5) tests/test_infra.py:181 asserts a 'vpn' level; network_of lowercases names, VPN_NAMES does not. Removes about 2 lines; the value is agreement between the security view and the console.

First commit: exposure._iface_class: replace `name.startswith(VPN_NAMES)` with `overlays.network_of(name) is not None` (name only, no address, no known map), delete VPN_NAMES, and add table-driven cases to tests/test_infra.py for wg0, tun0, tailscale0, wt0, ziti0, vti0, tunl0 (now lan) and an eth0 holding 100.64.x.y (must stay lan). Files: storageforge_index/exposure.py, tests/test_infra.py. Threading `known` from the tool readings is a second commit.

### BE-57. One adapter kit for the Toolbox's container, unit and program adapters, in place of three sets

**Survey record `toolwork1`**: The Toolbox adapters a, b and c each define their own container, unit and program adapter and their own unit/version probe; one adapter kit replaces them.

Copies:

- storageforge_index/tbadapters.py:116-139 UptimeKuma: container detect, tag-as-version, health tile (copy 1)
- storageforge_index/tbadapters_a.py:101-138 ContainerTool (copy 2, adds sidecar 'parts')
- storageforge_index/tbadapters_c.py:157-184 ContainerTool (copy 3, adds 'Installed by' tile)
- storageforge_index/tbadapters_b.py:343-387 Tool (copy 4: units + container + program in one class)
- storageforge_index/tbadapters_a.py:160-178 UnitTool vs storageforge_index/tbadapters_c.py:134-154 UnitTool: same detect/status over a different reading key
- storageforge_index/tbadapters_c.py:76-90 CliTool vs tbadapters_b.py:373-374 'program' branch of Tool
- unit probe three ways: tbadapters_a.py:40-44 (is-active/is-enabled loop), tbadapters_b.py:44-45 (systemctl show), tbadapters_c.py:38-42 (loop again)
- version probe three ways: tbadapters_a.py:45-48, tbadapters_b.py:46-48 tbv(), tbadapters_c.py:27-37; parsed by read_access a:73-76, read_versions b:125-134, read_c c:58-59
- health rule differs by accident: 'code == 200' at tbadapters.py:134, tbadapters_a.py:131-134, tbadapters_c.py:180-181 but '200 <= code < 400' at tbadapters_b.py:378-379
- image tag parse differs: tbadapters.py:125-127 and tbadapters_a.py:116 vs the "'/' not in tag[1]" guard at tbadapters_b.py:359-360 and tbadapters_c.py:169-171
- registration three ways: tbadapters.py:258-263 (merge dicts a, b), tbadapters.py:76-83 READERS, tbadapters_c.py:225-228 (mutates tbadapters at import)

The second reader (L, medium risk): Duplication confirmed: four container adapters (tbadapters.py:116-139, tbadapters_a.py:101-138, tbadapters_c.py:157-184, tbadapters_b.py:343-387), two UnitTools, CliTool vs b's program branch, three unit probes, three version probes, three registration styles. Corrections: (1) The claimed user-visible bug is misattributed. tbadapters_a.py:116 strips the path first (rsplit('/',1)[-1]) so localhost:5000/x gives None there; only UptimeKuma (tbadapters.py:125-127) shows '5000/x'. So the tag-parser bug is in one adapter, not in 'a/core'. (2) Differences missed: a picks the main container (sf-<name>, else first without storageforge.part) while b and c take cs[0]; b's Tool with image=None matches by label only (not by the sf-<name> container name that _containers accepts); b's 'running' is any(container running) OR any unit active, a/c use the main container only; a's UnitTool detects on a version line alone (unit None, tile 'installed, and no unit runs it yet', level warn), c's UnitTool requires a unit and shows the Version tile only when present; c's unit tile label is '<unit>.service', a's is the full unit name, b's is one tile per unit sorted; c keeps the whole version line (shown to the user), a/b keep a number; b metrics is {'running'}, a/c is {'containers'}. (3) Merging the shell probes changes the on-host measurement script and the stored reading shape (toolbox.access_a / units / versions / c): a uses 'systemctl cat' + is-active per unit with full names incl. templates (openvpn-server@server.service), b uses one 'systemctl show' with bare names and adds '.service' in Python, c prints bare names. That half is the risky part and saves little. (4) Health rule: HEALTH probe uses curl -L (tbadapters.py:49) so 200 is what a/c/core see after redirects; b's 2xx-3xx is only different for 204/206 or a redirect loop; choosing one is a behaviour change either way and must be stated in the commit. (5) c's import-time mutation of tbadapters (tbadapters_c.py:225-228) vs a/b merged at tbadapters.py:258-263: real, harmless. loc estimate 170 is plausible only if the shell probes are merged too; the Python-only part is roughly 70-90.

First commit: Python only, no shell and no reading-shape change: in storageforge_index/tbadapters.py add _container_found(ctx, tool, image, main_rule) (using a's tag parser, which is the correct superset) and _container_tiles(found, code, ok_rule); make UptimeKuma (tbadapters.py), ContainerTool in tbadapters_a.py and ContainerTool in tbadapters_c.py call them, each keeping its own ok rule (code == 200), its sidecar tile (a) and its 'Installed by' tile (c). Leave tbadapters_b.Tool alone in this commit. Only visible change: UptimeKuma no longer reports a registry port as a version. Tests: tests/test_toolbox_adapters.py, tests/test_toolbox_catalog_a.py, tests/test_toolbox_entries_c.py.

### BE-58. One permission gate for staging a tool, a bundle and a role profile, and a refused staging is audited on all three

**Survey record `toolwork6`**: Staging one tool, a bundle and a role profile are three parallel paths (and three copies of the permission gate in the routes); a single tool should be a bundle of one.

Copies:

- storageforge_index/toolbox.py:1299-1309 stage(): preview, unsigned gate, crit-except-secret gate, save_plan, record_install
- storageforge_index/tbbundles.py:358-385 stage_bundle(): the same four gates and save, over a list
- storageforge_index/toolbox.py:1327-1342 stage_remove() vs tbbundles.py:388-418 stage_bundle_remove(): same tool-remove / tool-data-remove tasks and the same UPDATE to remove-staged
- route gate copy 1: storageforge_index/routes_toolbox.py:186-195 (custom entry needs hosts.command; accept_unsigned needs hosts.command + fresh password)
- route gate copy 2: routes_toolbox.py:315-331 (bundle)
- route gate copy 3: routes_toolbox.py:388-400 (host profile; its comment says 'the same bar as staging a tool or a bundle')
- audit on failure exists for tool and bundle (routes_toolbox.py:201, 337) and is missing for bundle remove (351-352) and profile stage (403-404)
- plan naming shared only through a private name: toolbox._plan_name used at tbbundles.py:368, 412 and tbadapters.py:502

The second reader (S, medium risk): The route gate is truly copied three times (routes_toolbox.py:186-195, 315-331, 388-400) and the failed-staging audit is missing for bundle remove (351-352) and profile stage (403-404): worth one helper. The backend merge ('a single tool is a bundle of one') is not worth doing and is not behaviour-preserving: toolbox.stage is 8 lines; going through preview_bundle would add a 'Dependency order' note, prefix every report line with the tool name, rename the runtime-install note ('shared container runtime for ...'), change the plan name ('Toolbox: install X on H' vs 'Toolbox bundle: ...'), run order_entries (which strips and dedups ids) and the port-conflict pass, and return a different shape; stage() also takes method/inputs/exposure/bind/allow_from directly while bundles read them from a params dict via _tool_params. stage_remove raises LookupError when nothing is installed (-> 404), stage_bundle_remove skips and raises CatalogError (-> 400). Confirmed: stage_remove has no 'removed'/'remove-staged' guard (toolbox.py:1327-1342) while tbbundles.py:401 has; that is a two-line fix in stage_remove, not a reason to merge. Gate details to keep: the single route checks custom-entry before accept_unsigned and does it inside the try; the bundle route resolves entries from the bundle definition when 'entries' is None; the profile route reads them from host_profile; all use toolbox.find(str(tid).strip()). abort(403) raises an HTTPException that must keep passing through the except clauses. _plan_name is used from tbbundles.py:368, 412 and tbadapters.py:502 - renaming it public is fine. Realistic saving ~25 lines, not 80.

First commit: In storageforge_index/routes_toolbox.py add _stage_gate(tool_ids, accept) that performs exactly the two existing checks (custom entry -> hosts.command 403; accept_unsigned -> hosts.command 403 then password_stale()) and returns the stale response or None; call it from the three POST handlers with the same entry lists they compute today. No backend change, no response change. Tests: tests/test_toolbox_routes.py, tests/test_toolbox_bundles.py, tests/test_route_rules.py. Second commit: audit 'failed' for bundle remove and profile stage.

## 0.6.6: Hosts, keys and credentials

### BE-59. One vault-key signer behind deploys, the agent, SSH certificates and overlay keys

**Survey record `keysnet1`**: One vault-key signer instead of four copies of 'look up the key by name, sign in the enclave or decrypt-sign-wipe'

Copies:

- All paths are relative to storageforge-indexer
- storageforge_index/deploy.py:268-278 _signer: SELECT key_id by name, decrypt_key, EnclaveKey returned as is, else load_ssh_private_key + wipe
- storageforge_index/sfagent.py:216-226 _signer: the same body line for line, only the key name, the task ('sign') and the error class differ
- storageforge_index/sshcerts.py:69-87 signer: same lookup and same EnclaveKey/else branch, wraps the result as an SSH signature blob
- storageforge_index/overlaykeys.py:83-100 signer: same lookup and branch, returns the bare 64-byte signature plus the public bytes
- storageforge_index/routes_infra.py:539 reaches into deploy._signer (a private name) to sign the sfnet directory

The second reader (S, medium risk): Seen: deploy.py:268-278 and sfagent.py:216-226 are the same body; sshcerts.py:69-87 and overlaykeys.py:83-100 share the inner sign(). What the finder got wrong or missed: (1) a third caller of the private deploy._signer exists, secplus.py:581 (evidence export), which also calls key.public_key().public_bytes(OpenSSH): the returned object must keep public_key() returning a cryptography public key, not only sign(). (2) The 'sfagent passes task sign, the others none' difference does not matter for signing: EnclaveKey.sign (vault.py:319-322) hardcodes task 'sign' in the enclave request and ignores self.task, which only runner.ephemeral_agent reads. So no task parameter is needed, and adding one would suggest a distinction that does not exist. (3) deploy/sfagent look the key up without 'disabled_at IS NULL', but decrypt_key (vault.py:669-672) filters it anyway and raises VaultError('key N is missing or disabled'); sshcerts/overlaykeys filter in the lookup and raise their own CAError/VaultError sentence. A shared helper changes which exception a disabled signing key raises unless each caller maps it. tests/test_sshcerts.py:254 asserts 'there is no SSH CA yet: make it under Keys'. (4) Two tests patch.object(deploy, '_signer'): the name must stay as a wrapper. (5) The local branch differs in lifetime: deploy/sfagent keep a loaded Ed25519PrivateKey for the request, the CAs decrypt per signature; sfagent.py:571/692 and deploy.request sign once per object, so decrypt-per-sign is acceptable but is one more KEK open per signature. (6) sshcerts' ed25519 type check (sshcerts.py:76) has no equivalent in the others. Honest saving is about 25 lines, not 40. Do not merge the keys themselves (deploy signing, agent signing, SSH CA, Nebula CA stay four vault keys).

First commit: vault.py: add Vault.signing_key(key_id) that does only the shared tail (decrypt_key; return the EnclaveKey as is, else load_ssh_private_key and wipe). deploy._signer and sfagent._signer keep their own name lookup and error sentence and call it; sshcerts.signer and overlaykeys.signer call it inside their sign(). No change to lookups, filters, error classes or callers (routes_infra.py:539 and secplus.py:581 untouched). Files: storageforge_index/vault.py, deploy.py, sfagent.py, sshcerts.py, overlaykeys.py.

### BE-60. One builder of the operator-login SSH command for `send-secret`, `nebula-issue` and `headscale-key`

**Survey record `keysnet3`**: One 'run this on a host over ssh' helper for the operator-login path (send-secret, nebula-issue, headscale-key)

Copies:

- storageforge_index/cli.py:1112-1129 _send_secret: host and login patterns, ssh_user lookup from hosts, argv with BatchMode/ConnectTimeout, -o options, -i key with IdentitiesOnly, user@host target
- storageforge_index/overlaykeys.py:51-63 _ssh: the same lines; its docstring says 'from the same options vault send-secret takes'
- cli.py:1130-1131 builds 'sudo -n sh -c ...' by hand with the atomic .part + mv write; overlaykeys.py:43-44 WRITE and :66 _as_root do the same with shlex.quote
- cli.py:1140 and overlaykeys.py:70 _tail: the same last-300-characters of stderr
- patterns copied: cli.py:1112,1116 inline vs overlaykeys.py:28-29 HOST, LOGIN

The second reader (S, low risk): Seen: cli.py:1112-1129 and overlaykeys.py:51-63 build the same argv from the same patterns; overlaykeys' docstring admits it. Differences missed: (1) headscale_key does NOT use 'sudo -n sh -c': headscale_command (overlaykeys.py:187-201) returns 'sudo -n ' + individually quoted words, so run_as_root(script) fits only two of the three callers. (2) cli iterates args.ssh_option bare (cli.py:1125), overlaykeys uses 'or []'. (3) Failure shape differs: cli prints and returns 2/1, overlaykeys raises KeyError_ with its own sentences ('a host name or address, please' vs cli's combined 'a secret name, and a host name or address, please'). (4) cli validates and releases the credential (v.credential, a policy/audit event with the enclave) between the checks and the ssh call: the helper must not reorder that, and the argv must be buildable before the release without running anything. (5) cli's remote script is hand-quoted with apostrophes and embeds args.name; it is safe only because SECRET_NAME was matched first. cli.SECRET_NAME (cli.py:1105) is the loose form that allows a leading '.' or '-'; the vault refuses those names at store time, so no reachable bug, but the shared write_file should take the strict name. (6) send-secret does mkdir -p plus chmod 700 of the directory and mode 600 by umask; WRITE does cd (no mkdir), keeps a .sf-before copy and chmods 644: two different scripts, so only the transport (argv, _as_root, _tail) is truly shared, about 15-20 lines. overlaykeys takes run= for tests; cli calls subprocess.run directly.

First commit: cli._send_secret builds its argv with overlaykeys._ssh(conn, args) (catching KeyError_ and printing it, return 2) and uses overlaykeys._tail for the stderr tail; its remote script, the credential release, the audit entry and secretstore.delivered stay as they are. Files: storageforge_index/cli.py only. Moving the three helpers to opssh.py is a later rename.

### BE-61. One *log in with a named vault key* helper for rotation, key install and sudo access

**Survey record `keysnet4`**: One 'log in with a named vault key and run a command' helper, and one password-login (askpass) helper

Copies:

- storageforge_index/rotation.py:71-84 _run: key_id by name, ephemeral_agent(decrypt_key), Transport(isolated=True, strict=True, known_hosts=known_hosts_path()), run, close
- storageforge_index/keyinstall.py:45-61 key_login_works: the same sequence with task 'access'
- storageforge_index/access.py:209-217 and 225-234: the same block twice inside sudo_run, differing in which key and user
- storageforge_index/rotation.py:101-105 _login_works duplicates keyinstall.key_login_works
- password login through the askpass helper, env and option list rebuilt each time: keyinstall.py:100-111, access.py:239-246, nettransport.py:269-270 and 502-517
- strict known_hosts option triple repeated: keyinstall.py:101-102, access.py:239-240, hostkeys.py:48-49

The second reader (M, medium risk): Seen: rotation.py:71-84, keyinstall.py:45-61, access.py:209-217 and 225-234 all do decrypt_key -> ephemeral_agent -> Transport(isolated=True, strict=True, known_hosts=known_hosts_path()) -> close. Differences missed: (1) access does not call t.run: it takes t.argv(sudo) and runs subprocess.run itself with the password on stdin and env=child_env(), so the helper must yield the Transport, not run a command. (2) access passes no connect_timeout, rotation and keyinstall pass 10. (3) access's first block has a key_id from the binding (no name lookup); only the second looks up by name. (4) rotation._login_works is not a duplicate of keyinstall.key_login_works: it takes an already unlocked vault, task 'rotate', runs 'echo ok' and maps RotationError; key_login_works unlocks its own vault and uses task 'access'. Pointing rotation at keyinstall would change the enclave task counter and unlock twice. (5) Tests patch by module attribute: patch.object(keyinstall, 'Transport'), patch.object(rotation, '_run'), patch.object(access.subprocess, 'run'), patch.object(access, 'askpass_path'), patch('storageforge_index.keyinstall.askpass_path'), patch.object(deploy/runner, 'ephemeral_agent'). A helper in runner.py that constructs Transport and ephemeral_agent there makes those patches miss; either keep the names resolved in the calling module or change the tests in the same commit. (6) Password half: only keyinstall.py:100-111 and access.py:239-246 are the same (minimal env of PATH/HOME=scratch/askpass, same seven -o options). nettransport.py:269-270 and 502-517 start from child_env(), use -tt, accept-new when there is no password, and splice the options into an existing argv before '--': they share three option strings and four env keys, not a helper. hostkeys.py:48-49 is correctly excluded. There are 13 ephemeral_agent call sites in the package; this covers 4. Saving about 30-35 lines, not 60.

First commit: access.py only: fold the two identical blocks in sudo_run (lines 209-217 and 225-234) into one local function _sudo_over_key(v, key_id, user, port, ttl) that returns the CompletedProcess; names Transport, ephemeral_agent and subprocess stay resolved in access, so its existing patches keep working. Then, separately, a keyinstall.password_ssh_env(work, password) used by keyinstall.install_public_key and access.sudo_run.

### BE-62. The KEK rotation walks its sealed tables from one list, for the local vault and the enclave

**Survey record `keysnet10`**: The KEK rotation walks its sealed tables from one list instead of six hand-written loops

Copies:

- storageforge_index/vault.py:791-796, 797-801, 802-805: local rotation, the same open-DEK/seal/UPDATE loop for ssh_keys, device_credentials and enclave_stepup
- storageforge_index/vault.py:842-845, 846-848, 849-851: the enclave rotation, the same three loops with e.rewrap in place of open+seal
- vault.py:808-812 and 852-855: the same UPDATE vault_meta statement twice
- enclave_stepup.py:29 COLS and vault.py:802 name the same columns of enclave_stepup separately
- the same local-or-enclave fork for sealing a new row: vault.py:610-628 (_store_key) and 696-707 (store_credential)

The second reader (S, high risk): Seen exactly as described: vault.py:791-805 and 842-851 are the same three loops twice, with open_into+seal in one and e.rewrap in the other; only vault.py, enclave.py and enclave_stepup.py touch wrapped_dek, and the migrations define exactly these three tables, so no sealed table is missed today. Differences to keep: the local path stamps rotated_at with int(time.time()) per row, the enclave path with one `now`; enclave_stepup has no rotated_at; the return value is len(rows) of ssh_keys only; the local path must wipe `new` on any failure and swap self._kek only after the transaction; the enclave path's abort and commit-then-unmark order sits outside the loops and must not move. The proposed _write_meta is weaker than claimed: the two UPDATE vault_meta statements take their verifier and audit-key values from different sources (sealed locally vs returned by rotate_begin), so it saves about four lines and puts the single most critical statement behind a helper: leave it. The later '_seal_new' idea is also not symmetrical (the enclave branch of store_credential returns and cross-checks the policy text, vault.py:698-701). Saving about 15-20 lines; the value is the single list. Tests that cover it are named correctly; nothing patches these internals.

First commit: vault.py only: a module constant SEALED_TABLES of (table, id column, uuid column, stamps rotated_at) and one method _rewrap_rows(rewrap, now) -> number of ssh_keys rows, called inside the existing transaction of both rotations with a local closure (open_into + seal under the new KEK) and an enclave closure (_asked(e.rewrap, ...)). Table and column names come only from the constant (they are interpolated into SQL). The vault_meta updates, marking, abort and commit stay where they are.

### BE-63. Remembering a host key a person confirmed is one function for the Keys page and monitoring-only adoption

**Survey record `agentlogs6`**: Pinning a host key a person confirmed is done by one function for both the Keys page and monitoring-only adoption

Copies:

- storageforge_index/hostkeys.py:83-102 confirm(): known_host_keys lookup, refuse when another key is pinned, append to known_hosts, DELETE + INSERT host_key_confirmations
- storageforge_index/agentmonitor.py:171-188 _pin(): the same lookup, the same refusal, the same append, the same DELETE + INSERT (docstring: 'as Keys -> Confirm pins one a person compared')
- storageforge_index/agentmonitor.py:186-187 and hostkeys.py:100-101 the INSERT INTO host_key_confirmations statement twice

The second reader (S, medium risk): Seen: hostkeys.py:83-102 and agentmonitor.py:171-188 have the same shape, and the DELETE + INSERT into host_key_confirmations is the same pair of statements.

Differences to keep:
- confirm() runs _check(host, port) (HOST regex, no leading '-', port range) before anything else; _pin does not, because the address comes from the hosts row.
- confirm() fetches the known_hosts line from a live key scan only when nothing is pinned, and it is whatever key type the host presents. _pin builds the line itself with known_hosts_name() and hard-codes ssh-ed25519. A pin(line) helper must not make confirm() call offered() when a key is already pinned; pass the line lazily or let the caller do the pinned check.
- Error types and wording differ (ValueError vs MonitoringError; 'is not the key StorageForge holds for' vs 'holds another host key for'). No test or static file matches either text (grepped), but the routes map the two types to different statuses.
- _pin returns the fingerprint; confirm returns a dict.

About 8 lines are removed. The value is one place for the known_hosts append and the confirmation row, which every SSH connection trusts.

First commit: Extract only the tail: hostkeys.remember(conn, address, port, fingerprint, actor), the DELETE + INSERT into host_key_confirmations. Call it from hostkeys.confirm and agentmonitor._pin. Touches storageforge_index/hostkeys.py and storageforge_index/agentmonitor.py. The known_hosts append and the refusal stay in each caller until a second commit.

### BE-64. The name rules copied between modules (secret name, Unix login, machine id, hex digest) are defined once

**Survey record `x8`** (*unchecked*): The name grammars copied between modules (vault secret name, send-secret name, Unix login, host name, machine id, hex digest) are defined once and imported.

Copies:

- r'[A-Za-z0-9][A-Za-z0-9._-]{0,63}' nine times: secretstore.py:33 NAME, netshares.py:43 ('as secretstore.NAME' in its comment), overlaykeys.py:35, changes.py:209 ('secretstore.NAME' in its comment), steps_secretfile.py:20, vault.py:688, server.py:242, users.py:17, apiguide.py:28
- A second grammar for the same secret name, r'[A-Za-z0-9_.-]{1,64}', seven times: cli.py:1105 SECRET_NAME, steps_pools.py:25 SECRET, steps_overlay.py:34, steps_tunnels.py:32, steps_tailscale.py:19, share_virtiofs.py:21, tbadapters_c.py:62. It accepts a leading '.' or '-' (so '..'), which the vault's grammar refuses
- Unix login r'[a-z_][a-z0-9_.-]{0,31}' five times: cli.py:1116, overlaykeys.py:29, share_sftp.py:19, steps_secretfile.py:21, steps_runtime.py:30; three more variants in keyinstall.py:22, sshcerts.py:41, steps_sshca.py:31
- Host or address: scriptkit.py:10 HOST_RE and keyinstall.py:21 HOST identical; tasks.py:31 and scheduler.py:43 identical but for anchors; overlaykeys.py:28 and cli.py:1110 a third form
- Machine id or nonce r'[0-9a-f]{32}' eleven times (deploy.py:84,87, sfagent.py:62,242, server.py:2380,2402,2412,2446, hostlogs.py:193, remote.py:637, clamav.py:39); r'[0-9a-f]{64}' five times; the UUID pattern three times (clamav.py:38, jobs.py:46, security.py:40)

Proposal: storageforge_index/names.py with SECRET, LOGIN, HOST_OR_ADDRESS, LOGIN_AT_HOST, HEX32, SHA256_HEX, UUID and small predicates (is_secret_name ...). Modules import the pattern and keep their own error sentences. The send-secret family is pointed at SECRET after checking no stored plan holds a name the stricter grammar refuses.

What must survive: These are input validators in front of shell text and file paths (the secret name becomes /run/storageforge/secrets/NAME in cli.py:1131). Tightening the loose secret-name grammar could refuse a plan that validates today; users.py's USERNAME and server.py's KEY_NAME share the pattern by coincidence and should keep their own names. The three login variants differ on capitals and a leading digit and are not obviously the same rule.

### BE-65. `security.py` and `secplus.py` share a host-action module instead of one reaching into the other's private functions

**Survey record `secmap4`**: Give security.py and secplus.py one shared host-action base and one route helper instead of two modules that reach into each other's private functions.

Copies:

- storageforge_index/security.py:100-152 known_host, clean_path, clean_text, _b64text, _mode, _result, _run, _act: the preview/report/apply plumbing
- storageforge_index/secplus.py uses security._result 10 times, _int 9, _run 6, _mode 6, _b64text 5, _act 4, plus _latest_scans, _save_measurement, _record_hold, _full (for example secplus.py:246, 257, 1836-1843, 1859-1862)
- storageforge_index/security.py:450-452 _secplus() lazy import used 23 times (for example 446, 510, 913, 1958): a cycle between the two halves
- storageforge_index/routes_security.py:18-23 and routes_secplus.py:20-24: the same audit() closure; must_host at routes_security.py:28, routes_secplus.py:30 and routes_infra.py:17
- storageforge_index/tbfeeds.py:162-164 repeats security._mode; routes_secplus.py also calls security._run/_result/_mode directly
- storageforge_index/clamav.py:345-348 and sshcerts.py:98-103 repeat security.known_host
- storageforge_index/security.py:1922-1962 problems and secplus.py:306-316 problems; security.py:877-915 tick and secplus.py:2074-2103 tick: chained by hand

The second reader (M, low risk): Confirmed: secplus.py uses security._result 10, _int 9, _run 6, _mode 6, _b64text 5, _act 4, _latest_scans 2, _record_hold 1, _full 1, _save_measurement 1; routes_secplus.py:224/353/403/413/414 use _mode, _int, _run, _result; tbfeeds.py:162-164 repeats _mode inline; the audit() closure is identical at routes_security.py:18-23 and routes_secplus.py:20-24; must_host is identical in three route files. Corrections: (1) it does not remove the import cycle. security.py calls _secplus() 23 times for parse_sessions, parse_falco, parse_threats, after_measure, std_for, waived, velocity_limits, record_ban, next_tier, mark_avc, persistence_drift as well as tick and problems; a list of callables covers two of those. Drop that claim, or treat it as a later, separate step. (2) The finder's worry about tests monkeypatching security._run is unfounded: no test patches _run, _act, _result or _mode. The real test coupling is security._save_measurement (44 uses across about 20 test files), so that name must stay importable from security. (3) routes_clamav does not fit the shared audited(): its audit rows are not built from a result dict (routes_clamav.py:29-67 pass their own outcome and detail). Leave it out. (4) clamav.py:345-348 raises ValueError without repr or truncation ('{host} has not been scanned'), security.known_host uses repr and [:80], sshcerts._known_host raises LookupError 'no host named': three wordings and two HTTP codes, see the host-resolver candidate. (5) inframeasure.measure does not use _result at all; it returns its own {'ok': False, 'error': output[-500:]} shape, so 'every host action takes the same shape' would be a behaviour change there, not a move. (6) ctx.step_up is set inside routes_secplus.register (line 48) and read at routes_security.py:16; server.py:1714 registers secplus first for that reason. Moving audited/must_host to ctx must not move step_up unless it moves to where ctx is built.

First commit: New storageforge_index/hostaction.py holding known_host, clean_path, clean_text, b64text, mode_of, int_or, result, run, act moved verbatim from security.py:100-152 (and _int); security.py re-binds every old name (known_host = hostaction.known_host, _mode = hostaction.mode_of, ...) so no caller or test changes. Second commit: secplus.py, routes_secplus.py and tbfeeds.py:162-164 switch to the public names. Third: ctx.audited and ctx.must_host for routes_security, routes_secplus, routes_infra only. No change to decorators, registration order, deploy kind or tick/problems chaining.

### BE-66. One store for host readings (security, infrastructure, device, package), in place of raw SQL in ten modules

**Survey record `secmap6`**: One measurement store and one 'read hosts that are due' loop for the security, infrastructure, device and package readings.

Copies:

- storageforge_index/security.py:515-526 _save_measurement and measurement: the store for table security_measurements, private to security.py
- storageforge_index/inframeasure.py:443 and netdevice.py:242-243 and secplus.py:1843 call security._save_measurement for kinds 'infra', 'device', 'packages'
- Raw SQL on the same table: alerts.py:527, console.py:69, infragraph.py:323, 333, 394, tbfeeds.py:183, netdevice.py:120, 258, inframeasure.py:488, security.py:902
- Case rule differs: security.py:522 matches lower(host), security.py:902 and inframeasure.py:488 and infragraph.py:394 match host exactly
- storageforge_index/security.py:485-501 measure and inframeasure.py:430-457 measure: known_host, signed report run, 'cut short' refusal, parse, save
- storageforge_index/security.py:899-908, inframeasure.py:477-496, netdevice.py:267-282, apiread.py:79-94: four copies of 'for each target, skip if read less than N seconds ago, try, errlog.trace, count', chained by hand at server.py:339-344

The second reader (S, low risk): Half real. The store half is real: security._save_measurement/measurement (security.py:515-526) is a private store used by inframeasure.py:443, netdevice.py:242-243, secplus and 44 call sites in about 20 test files, with raw SQL on the table in alerts.py:527, console.py:69, infragraph.py:323/333/394, tbfeeds.py:183, netdevice.py:120/258, inframeasure.py:488, security.py:828/902. The loop half is not one loop. Only security.tick and inframeasure.tick read 'due' from security_measurements; netdevice.tick uses list_devices()' last_read_at and a per-device off list; apiread.tick uses apiconn.listing()' read_at, skips certificate states, catches only apiconn.ApiError without errlog.trace, and counts every attempt, not successes. Target sets, readiness checks (deploy.ready, row state), the clock_ok gate and counting all differ; a run_due(db, targets, read_one) would be five lines of shared try/except and four adapters. Drop it. The measure() pair is also not shared: security.measure calls freeze_clock on a refused run, ingests events and returns _result(); inframeasure.measure returns its own error shape with output[-500:]. Case rule: writes delete by exact host, measurement() reads by lower(host); every writer passes a canonical name (known_host or the device name), so I found no present bug, only a latent one (two rows differing in case would make measurement() return either). Note infragraph.py:394 uses ORDER BY measured_at DESC LIMIT 1 on an exact match and handles dict or str (PostgreSQL JSON); a shared get() must keep the loads handling. 'stale' is computed in measurement() and must stay there. Net lines removed are few; the value is ending the reach into a private name.

First commit: storageforge_index/readings.py with save(conn, host, kind, at, via, data) and get(conn, host, kind) moved verbatim from security.py:515-526; security._save_measurement and security.measurement stay as aliases (44 test call sites); inframeasure.py:443, netdevice.py:242-243 and secplus call readings.save. Then console.py:69 and infragraph.py:394 use readings.get, and one last_at(conn, host, kind) replaces security.py:902 and inframeasure.py:488. No tick loop changes.

## 0.6.7: Plans, jobs, alerts and routes

### BE-67. One named-plan store behind move plans, change plans and storage tasks, each keeping its own errors

**Survey record `webcore5`**: One named-plan store for move plans, change plans and storage tasks, with one set of CRUD routes and CLI commands.

Copies:

- moves.py:628-688, changes.py:955-996, tasks.py:307-344: list, get, save and delete written three times over tables of the same shape (id, name, body_json, created_at, updated_at, updated_by); the save functions are line for line the same apart from table and wording
- server.py:1574-1637 moves routes, 1797-1845 tasks routes, 1858-1893 and 2174-2185 changes routes: the same GET/PUT/DELETE handler with the same audit rows and the same script-download response
- cli.py:283-311 cmd_moves, 314-344 cmd_tasks, 380-413 cmd_plan: list / import / check / script written three times, each with its own copy of the write-to-file block (305-310, 338-343, 406-412) although cli.py:1028 _write exists
- scheduler.py:324-328 and 675-689: name-or-id lookup into the same three tables
- copy exists only for moves (moves.py:663-667, server.py:1608-1618)

The second reader (S, low risk): Confirmed: moves.save_plan (moves.py:670-685), changes.save_plan (changes.py:976-991) and tasks.save_task (tasks.py:324-341) are the same statement for statement apart from table, id column, noun and the normalize call (changes: normalize(prepare(conn, body))). Error texts differ and must stay: 'a plan named' vs 'a task named', 'no move plan #', 'no change plan #', 'no task #'. list and get are NOT the same: each selects different columns (changes.list_plans has no updated_by) and adds different fields (steps/deployed_at/progress; tasks/ran_at; slug/host/schedule/blocks/hash), so the store can share only the row read. Routes are not worth a generic register_plan_routes: moves has a separate POST route and a copy route, tasks has one GET+POST route whose GET returns types, categories, templates, schedules and installed; moves and tasks check hosts.command on the new body AND the saved one, changes do not; delete guards differ (deployed jobs under ref f'p{plan_id}', tasks.installed by slug, none for changes); tasks script is a POST of an unsaved body and audits name, changes has script|ansible with two mime types; file names differ ('<slug>.sh', 'task-<slug>.sh', 'changes-<slug>.sh'). A generic registrar would need a flag for each. CLI: the write block is in four places, not three (cli.py:305-310, 338-343, 373-377 cmd_shares, 406-412), and cli.py:1028 _write is NOT a drop-in: it does not chmod 0755 and treats '-' as a file name. The check printers differ per kind and stay. scheduler.py:324-328 covers two tables; tasks are resolved by _resolve_task, which also matches the slug. Copy for changes and tasks is a new feature (changes would re-run prepare). Removal is about 50-60 lines, not 200.

First commit: New storageforge_index/planstore.py with save(conn, table, id_col, noun_exists, noun_missing, name, body_json, actor, row_id) holding the clash check, the tx, UPDATE and INSERT ... RETURNING; moves.save_plan, changes.save_plan and tasks.save_task call it with their own normalize and their exact error texts. Separate commit in storageforge_index/cli.py: _write_script(text, output, executable=True) replacing the four blocks.

### BE-68. One table of deployable kinds replaces the if-chains over deploy kind in the server and over task type in the scheduler

**Survey record `webcore1`**: One registry of deployable kinds replaces eleven if-chains over deploy kind and schedule task type.

Copies:

- server.py:2244-2277 deploy_items_for: if-chain over jobs/shares/changes/tasks/schedules/updates/clamav/security, each loading its object and calling X.deploy_items
- server.py:2279-2288 need_for_commands: same kinds, has_raw_hooks / has_command / holds_commands
- server.py:2290-2300 second_hops and 2302-2313 send_receivers: same kinds again
- server.py:2329-2350 deploy_digest: same kinds again (plan_hash, design_hash, task_hash, schedule_hash, digest)
- server.py:2420 hard-coded tuple of retryable kinds, a sixth copy of the kind list
- scheduler.py:331-346 _target_hash: if-chain over task/change/move/shares calling the same hash functions
- scheduler.py:355-368 second_hops and sends, 375-385 holds_commands, 388-400 check_target: task-type chains again
- scheduler.py:692-741 generate_task_script: task-type chain; lines 702-716 repeat the name-to-plan-id lookup that _plan_id (324-328) already is
- routes_scheduler.py:88-96 and 122-135: the ready / preflight / start_group sequence of server.py:2371-2389 written twice more

The second reader (M, medium risk): Seen: storageforge_index/server.py:2244-2350 has five chains over the same kinds plus the tuple at 2420; scheduler.py:331-400 and 692-741 have five more over task types. Corrections. (1) Deploy kinds and schedule task types are two different axes and only partly map: schedule type 'move' runs moves.script with --run, deploy kind 'jobs' runs jobs.deploy_items; they share only the loader and jobs.plan_hash. The scheduler resolves by name OR id (_plan_id, and _resolve_task also matches the slug), server.py by int id only; schedule scripts are built with owner=f's{id}'. So scheduler chains cannot become lookups in the same entries beyond load+digest+holds_commands; 'scan' and 'command' types have no deploy kind. (2) server.py helpers are closures over actor(), need(), alerts.get_setting and db, and every kind takes different options (paused, destructive, run, remove, rearm), so the registry is a dict of small functions, not a uniform interface. LOC removed is nearer 60-90 than 220. (3) Each chain catches differently and that is behaviour: deploy_digest returns None on LookupError, second_hops/send_receivers also swallow TypeError and ValueError, need_for_commands returns silently on LookupError, scheduler._target_hash returns 'missing' and holds_commands returns False. (4) The tuple at 2420 is not a pure duplicate: it gives the text 'only plans and designs can be retried' for group kinds that were never deployables (job-action, restore), before deploy_items_for is called. (5) A shared deployables.start() changes behaviour in three routes and is not a refactor: the scheduler run route audits 'scheduler.run' with the host (not 'deploy.start'), has no stale-dry-run check, hard-codes stop_on_failure=True instead of updates.group_options, and lets receiving.NotEnrolled (a ValueError, receiving.py:39) fall to on_error as 400 with no 'denied' audit row, where /api/deploy/start answers 409 with one; the pause route has no preflight, no deploy audit row, and answers 200 with host_pending. Keep those out of the first commits. (6) generate_task_script's inline lookups raise 'change plan "x" not found' / 'move plan "x" not found' while _plan_id raises 'plan "x" not found': text changes if merged (no test in tests/test_scheduler.py pins it that I found).

First commit: storageforge_index/scheduler.py only: make generate_task_script (702-716) call _plan_id, giving _plan_id a noun argument so both error texts stay as they are. Second commit, storageforge_index/server.py only: a module-level table {kind: (load, digest, holds_commands, second_hops, receivers)} read by need_for_commands, second_hops, send_receivers, deploy_digest and the retry tuple, leaving deploy_items_for and all three start routes untouched.

### BE-69. The route modules take *audit and answer* and the script download from the shared route context

**Survey record `webcore6`**: A route kit in ctx replaces per-module audit-and-answer helpers, hand-written error mapping and script-download responses.

Copies:

- routes_security.py:18-23 and routes_secplus.py:20-24: the same audit(action, res) helper, character for character
- routes_clamav.py:13-15 answer(), routes_git.py:24-38 git_call(), routes_logrules.py:26-35 save_with_audit(): three more local versions of run, audit ok or failed, answer 200 or 409
- the same two lines inline at routes_network.py:146-147 and 183-185, routes_infra.py:439-445, routes_secplus.py:184-185, routes_secrets.py:75-80
- server.py:784-800 on_error already answers ValueError and VaultError with 400 and LookupError with 404, yet 49 route blocks catch LookupError only to return 404 and 9 catch ValueError only to return 400 (for example server.py:1605, 1826, 1877, 1892; routes_scheduler.py:71, 101, 112, 139, 157, 171, 187, 198; routes_workloads.py:21-24, 60-63; routes_logrules.py:29-32, 51-54, 74-77)
- about 50 domain exception classes, mapped to statuses by hand per route: apiconn.ApiError to 502 or 409, ConnError to 400 or 409 (routes_apiconn.py:59, 79, 91, 93, 107, 128, 148, 151), CatalogError nine times, EnclaveError six times
- eleven script downloads build the same Response with text/x-shellscript and Content-Disposition: server.py:1634, 1750, 1842, 2182, 2218, 2702, 2727; routes_scheduler.py:169, 185; routes_secplus.py:173; routes_infra.py:304

The second reader (M, medium risk): Confirmed: the audit(action, res, **detail) helper is the same in routes_security.py:18-23 and routes_secplus.py:20-24; 11 text/x-shellscript responses; LookupError handlers number server.py 41, routes_toolbox.py 14, routes_scheduler.py 8, routes_logrules.py 3, routes_workloads.py 3, routes_secrets.py 2, routes_git.py 1. Corrections. (1) The other 'local versions' are not the same helper: routes_clamav.answer() writes NO audit row; routes_git.git_call audits failures too, marks LookupError as 'denied' and turns any other exception into 502; routes_logrules.save_with_audit audits only on success with a picked detail. Only security and secplus merge as is. (2) http_status as a class attribute cannot carry the mapping: the same exception is answered with different statuses per route (ApiError 502 or 409, ConnError 400 or 409), and several answers add fields the pages read. Drop that part. (3) Removing pass-through handlers is not free: a local 'except LookupError' also catches KeyError and IndexError raised anywhere inside the block (a missing dict key in a domain function answers 404 today) while on_error (server.py:797) sends those to 500 with a trace; and handlers that wrap several statements stop the route before a later audit row, which raising also does, so order is kept, but each of the ~70 blocks needs reading. Many are not pass-through (they return 409 for another exception in the same try, e.g. routes_scheduler.py:61-71 with StillDeployed). (4) on_error logs nothing for 400/404, so no log difference; connections close in teardown_appcontext either way. (5) Downloads differ in mimetype (application/yaml for ansible) and file name rule; ctx.download must take both. Estimate nearer 120 lines than 260, most of it from the handler removal, which carries the risk.

First commit: storageforge_index/server.py: add ctx.audited(action, res, **detail) with the exact body of routes_security.py:18-23 and ctx.download(text, filename, mimetype='text/x-shellscript'); delete the two local audit() helpers in routes_security.py and routes_secplus.py and use ctx.download at the 11 sites. No try/except is removed in this commit.

**Survey record `x13`** (*unchecked*): The helpers each routes module defines inside register() (audit-and-answer, must_host, rp) and the repeated 'except ... jsonify(error=str(exc))' move to the shared route context.

Copies:

- audit(action, res, **detail) identical: routes_security.py:18 and routes_secplus.py:20
- must_host identical three times: routes_infra.py:17, routes_secplus.py:30, routes_security.py:28
- rp identical: routes_secplus.py:34 and routes_enclave.py:70 (its comment: 'as routes_secplus.py names this site')
- '200 if res.get('ok') else 409' seven times in five files; 'request.args.get('host') or None' 36 times in ten files
- 'jsonify(error=str(exc)), 400|404|409' 82 times in ten files, 44 of them in server.py

Proposal: ctx (the object server.py already hands to every register) gains audit_result(action, res, **detail), must_host(), host_arg() and rp(); a decorator or one errorhandler per domain error class (DeployError, VaultError, ApiError ...) with its status replaces the try/except blocks whose only job is that mapping.

What must survive: API response shapes and status codes are what the web UI and tests read: each exception class must keep the status it has today at each route, and routes that add fields to the error body or audit before answering keep their own block. server.py:784 already has a catch-all errorhandler whose behaviour for these classes would change.

### BE-70. Deployed jobs and imported snapshot jobs share their listing parser and their after-action update

**Survey record `webcore11`**: Deployed jobs and imported snapshot jobs share one backend interface for actions, browse and restore.

Copies:

- jobs.py:606-623 action and snapjobs.py:409-417 action: the same pause/resume flag update and the same parse of snapshots output, after an is_imported branch at jobs.py:608
- jobs.py:633-639 and snapjobs.py:443-448: the ls output parser, line for line
- jobs.py:642-646 _snap_args and snapjobs.py:420-424 _snapshot_dir: the same checks with drift ('..' anywhere in the path vs as a path part; lowercase-only snapshot names vs any case)
- jobs.py:626-628, 649-652, 662-668: three more is_imported branches for browse, restore_target and restore; snapjobs.py:496-499 imports jobs.get back
- the restore target name '<original>.restored-<time>' built at jobs.py:659 and snapjobs.py:483

The second reader (S, low risk): Confirmed: the ls line parser is the same six lines at jobs.py:633-637 and snapjobs.py:443-447, and the pause/resume flag update plus the snapshots sort is the same at jobs.py:617-621 and snapjobs.py:411-415. Corrections. (1) The dispatch already exists: jobs.action, browse, restore_target and restore each branch once on snapjobs.is_imported(j). Wrapping that in a two-class interface adds code; only the shared helpers are worth taking. About 15 lines removed, not 40. (2) The stated user-visible gain is false. Relaxing jobs._snap_args to the path-part rule does not let a file named 'a..b' be browsed from a deployed job: the host side refuses it at jobscript.py:909, rel_ok() { [[ $1 != *..* && $1 != /* ]] || die "bad path"; }, so the controller would accept and the host would fail with a worse message until every host's storageforge-job is changed and redeployed. Keep the controller rule as strict as the host rule; do not unify the path checks. (3) The snapshot-name rules must stay apart: deployed is [a-z]+\.\d+, rsnapshot imported is [A-Za-z][\w-]*\.\d+, snapper is \d+. (4) The imported action also calls _note_runs after snapshots; deployed jobs check cutover/dedupe preconditions first. The '.restored-<time>' suffix is one f-string on two differently derived originals.

First commit: storageforge_index/jobs.py and snapjobs.py: move the ls-output parser into one function (parse_entries(output)) and the after-action tail into one (set paused flag, parse snapshots), both in snapjobs.py or a small shared spot that does not add an import cycle (snapjobs already imports jobs.get lazily). _snap_args and _snapshot_dir stay as they are.

### BE-71. The controller's restart clean-up and its periodic loops are started from one place

Survey record `webcore12` again: see its first appearance above.

### BE-72. Alert sources are separate functions, and one that raises no longer stops every alert from opening, resolving or being pushed

**Survey record `agentlogs3`**: Alert sources become one registry with per-source isolation, and the three copies of the 'no good run' rule become one

Copies:

- storageforge_index/alerts.py:551-554 problems(): one dict literal unioning 23 modules' problems(); any one raising aborts evaluate() for every alert
- storageforge_index/agentplugins.py:100-107 the only place a source is isolated with try/except errlog.trace
- storageforge_index/agentwatch.py:116-120 nests agentaction.problems and agentplugins.problems; storageforge_index/security.py:1960-1962 nests secplus and apiconn; apiconn.py:894-895 nests apireadback and apiread
- storageforge_index/alerts.py:587-593 task stale: time.time() - last_good > 2 * per + 3600
- storageforge_index/alerts.py:609-617 schedule stale: same rule, same shape
- storageforge_index/jobs.py:792-796 job stale: same 2 * per + 3600 rule
- storageforge_index/logmonitor.py:16 KINDS hard-codes which alert kinds are 'about logs', a second list of what sources emit

The second reader (M, medium risk): Seen: alerts.py:551-554 is one dict union, and server.py:326-329 traps the exception per tick, so one raising source means no alert opens, resolves or is pushed until it is fixed. The 2*per+3600 rule is at alerts.py:590, alerts.py:612 and twice in jobs.py:793-796.

The finder missed the main hazard of copying the agentplugins.problems pattern: evaluate() resolves every open alert whose key is missing from problems() and pushes 'Resolved: ...' (alerts.py:659-665). Today a raising source aborts the tick, so nothing is falsely resolved. If a failing source is skipped, all its open alerts, security crit ones included, are resolved and announced as resolved, then reopened and pushed again when the source recovers. That also clears snoozes and acknowledgements, because the row is deleted and reinserted. agentplugins.problems (agentplugins.py:100-107) has this flaw already for the disks, files and scan sources. The registry must keep a failed source's open alerts as they are. That needs each source to declare its kinds or key prefixes, so that part of the proposal is required, not optional.

Other corrections:
- alerts.problems(conn) is called directly by about 20 tests (test_copies, test_sites, test_api*, test_snapjobs, test_sshcerts); keep its signature and return shape.
- The drift block reads and extends an earlier entry under the same key (prev = now.get(key)), so it has to run after the sources, as it does now.
- The task rule falls back to last_start when there is no good run, the schedule rule to latest['started_at'], and the job rule to deployed_at with a separate never-ran state. A shared overdue() is a one-line comparison; it saves almost nothing, and the fallbacks stay with the callers.
- An 'alert-source-failed:{name}' item is a new kind that shows up in the center, in history and in mutes.
- logmonitor.KINDS is a view filter, not a second list of sources; a test can check it, deriving it gains nothing.

This is a net addition of code. It is worth it for the fault isolation, not for lines removed; the estimate of 60 removed is wrong.

First commit: Move the three inline blocks of storageforge_index/alerts.py:555-617 into private functions _job_problems(conn), _task_problems(conn) and _schedule_problems(conn) in alerts.py, and have problems() union them in the same order, with drift still applied after them. No try/except and no registry yet. Touches alerts.py only. Isolation comes in a second commit together with the 'keep the open alerts of a failed source' rule and a test for it.

### BE-73. A failed schedule is pushed once, through the alert state machine with its mute and its history, not a second time at level `failed`

**Survey record `agentlogs1`**: Every push notification goes through the one alert state machine instead of three callers posting to channels directly

Copies:

- storageforge_index/alerts.py:621-674 evaluate(): the only path that records history, honours mutes/snooze, escalates and resolves
- storageforge_index/alerts.py:594-617 problems() already yields schedule-failed:{sid} and schedule-stale:{sid} for the same runs
- storageforge_index/scheduler.py:1037-1054 a finished schedule run calls alerts.send() itself, level 'failed' (not a level send() knows), no alert row, no notification_events row, no mute check, errors swallowed
- storageforge_index/secplus.py:1530-1532 playbook 'notify' step calls alerts.send() directly with extra kind 'playbook'
- storageforge_index/server.py:2617 test button calls alerts.send() directly (legitimate, but a third caller of the raw sender)
- storageforge_index/alerts.py:261-311 send(): level map knows only crit/warn/ok; routed() at 249-258 matches routes on level, so 'failed' matches only 'any' routes

The second reader (M, high risk): The facts hold: scheduler.py:1046-1054 sends with level 'failed' (alerts.send knows crit/warn/ok, so priority 3, PagerDuty 'warning', and routed() matches only 'any' routes), writes no alerts or notification_events row, checks no mute and swallows errors. alerts.problems() (alerts.py:594-617) raises schedule-failed:{sid} for the same run, so a failed latest run is pushed twice. secplus.py:1531 and server.py:2617 are the other two raw callers.

The proposed push(key, ...) does not work as described:
- evaluate() resolves every open alert whose key is not in problems() (alerts.py:659-665) and pushes 'Resolved: ...'. A playbook 'notify' is a one-off event with no condition behind it, so a row for it would be resolved and announced as resolved on the next tick. It needs a notification_events row plus a send, not an alerts row.
- The same happens for schedules whenever ingest and problems() disagree: a paused schedule (problems() skips it), or a failed run that is not the latest. scheduler.py:1104 ingests runs found by a scan ('scan:{host}'), which can be old ones.
- evaluate() holds alerts._lock and opens its own connection. A push from the request thread doing the same DELETE+INSERT on alerts without that lock races it.
- routes_scheduler.py:227-230 already sets alerts_wake after ingest_report, so evaluate() runs moments later. The direct send is redundant for a failed latest run; deleting it is simpler than adding a push API.

Behaviour that changes, and that the owner has to decide:
- notify_on is not honoured by problems(): a schedule with notify_on=[] still gets the crit schedule-failed alert, which cannot be muted.
- The alert key is per schedule, not per run. Today every failed run pushes; through the state machine a second failure in a row is silent because the alert is already open.
- The direct push carries the last 500 characters of output and the title 'StorageForge Schedule Alert: ...'; the evaluate one carries only the verify summary or exit code.
- The webhook payload loses the schedule and run_id keys.

No test asserts the schedule push or the playbook send (grep for 'Schedule Alert' and alerts.send in tests finds only test_alerts.py and test_security.py calling send directly). The loc estimate of 40 is high: about 15 lines go, and code is added for event-type announcements.

First commit: Pure refactor: add alerts.announce(conn, title, message, level, extra), which is get_setting(conn, 'alerts') plus send(), and call it from storageforge_index/scheduler.py:1046-1054, storageforge_index/secplus.py:1531 and storageforge_index/server.py:2617 with the same arguments as today, including 'failed'. Touches alerts.py, scheduler.py, secplus.py, server.py. Follow-up commits, each a visible change: (1) the scheduler passes 'crit'; (2) announce() writes a notification_events row; (3) drop the scheduler's direct send once the owner has decided what notify_on means.

### BE-74. Queries that list their columns twice use one connection method that returns dictionaries

**Survey record `x14`** (*unchecked*): Queries that list their columns twice (once in SELECT, once in dict(zip(...))) use one Conn method that returns dicts.

Copies:

- dict(zip(keys, row)) 50 times in 32 files, e.g. deploy.py:657,666,675, alerts.py:681, jobs.py:761, clamav.py:524,540, agentconsole.py:90, agentreceiver.py:227, agentwatch.py:73
- Seven modules define their own _row(r) for it: netdevice.py:53, agentdisks.py:36, agentscan.py:30, apiconn.py:190, secretstore.py:87, engine.py:222, toolbox.py:849
- Conn has execute, all and scalar only (db.py:75-83)
- agentscan.py:73-74 repeats db.py:157-158 Database.ts word for word

Proposal: Conn.dicts(sql, params) and Conn.one(sql, params) in db.py, naming keys from the cursor's description (the same on sqlite3 and psycopg). Callers whose keys differ from the column names write 'AS key' in the SQL or keep their zip.

What must survive: PostgreSQL folds unquoted column aliases to lower case and SQLite keeps the case written, so mixed-case keys need quoting or must stay as zips. Several _row helpers also decode JSON columns or turn 0/1 into bool; those keep their function and only lose the zip.

### BE-75. The forty places that print a moment as `YYYY-MM-DD HH:MM` use one function that says which clock it is

**Survey record `x7`** (*unchecked*): The forty places that print a moment as 'YYYY-MM-DD HH:MM' use one function that decides the clock and says which it is.

Copies:

- Four small functions with the same job: cli.py:51 when (UTC, unlabelled, '—'), console.py:522 stamp (UTC, labelled), reportextra.py:12 _when (server local time, 'never'), loganomaly.py:253 _when (local), site.py:129 (local, '-')
- Local time, unlabelled, in alert and notice text: alerts.py:436,500,562, agentwatch.py:135,138,152,163, security.py:1928,1931, notifications.py:278, rotate_keys.py:155, pstore.py:147, agentfiles.py:301, confirm.py:98,115
- UTC unlabelled: hostconfig.py:463, cli.py:1557,1711,1773; UTC labelled: report.py:200, remotes.py:261, reinstall.py:297
- cli.py mixes both in one program: :52 UTC, :433 and :1514 local
- Script headers each format 'now' their own way: moves.py:740, changes.py:1118, tasks.py:825, shares.py:693, reset.py:224 (dt.datetime.now()), jobs.py:374, receiving.py:226, pkglist.py:500 (time.strftime)

Proposal: storageforge_index/when.py (or two functions in scriptkit): moment(ts, none='never', seconds=False) and now_text(), with one rule for the clock, named in the text. The five local helpers go; callers pass their own word for 'no time'.

What must survive: Every changed site changes text a person or a test reads; alert messages are stored and deduplicated by content in places, so a changed time form can re-raise an open alert once. The server in a container runs in UTC, so local and UTC agree there and differ on a workstation install: tests that pin TZ will show which sites move. The CLI's '—' and the report's 'never' must stay per caller.

## 0.6.8: Shares, archives and quarantine

### BE-76. The Ansible exports of the partition, wipe, secure-delete and archive steps run the steps' own Bash functions

Survey record `steps2` again: see its first appearance above.

### BE-77. The three rclone-served share kinds write their serve unit and login file through `rclone.LIB`, each unit's text unchanged

Survey record `shares3` again: see its first appearance above.

### BE-78. The three block-disk share kinds share the sparse image file, the blank-disk decision and the one-client rule

Survey record `shares4` again: see its first appearance above.

### BE-79. One file quarantine for ClamAV detections and threat kills. The threat copy gains the resolved-path check it lacks today

**Survey record `secmap5`**: One file-quarantine implementation for ClamAV detections and for threat kills.

Copies:

- storageforge_index/clamav.py:29 and secscripts.py:26: QUARANTINE = '/var/lib/storageforge/quarantine' defined twice
- storageforge_index/clamav.py:203-253 QUARANTINE_BODY: symlink and realpath checks, system-path refusal, hard-link note, meta file (b64, mode, owner, signature, sha256, at), mv, chmod 000, prints 'QUARANTINED <qid> <sha>'
- storageforge_index/secscripts.py:256-272 inside threat_kill_script: a second hand-written copy of the same move and the same meta format, without the realpath check
- storageforge_index/clamav.py:609-624 quarantine: parses QUARANTINED and writes clamav_detections state='quarantined'
- storageforge_index/secplus.py:261-273 kill_threat: parses the same marker and writes the same clamav_detections columns with its own UPDATE and INSERT
- storageforge_index/secplus.py:1485-1493 run_actions: a third INSERT into clamav_detections before calling clamav.quarantine; clamav.py:485 add_found is the intended way in

The second reader (M, medium risk): Confirmed: QUARANTINE is defined at clamav.py:29 and secscripts.py:26; the move-and-meta block at secscripts.py:256-272 is a hand copy of clamav.py:245-252 with the same six meta keys; secplus.py:261-273 and 1485-1493 write clamav_detections directly. The threat copy has no realpath check (clamav.py:216-217), so a path whose parent folder is a symlink is moved from wherever it resolves; security.clean_path only rejects '/../'. That is a real gap worth closing. Differences the finder missed or got wrong: (1) add_found is not a safe 'intended way in' for secplus.run_actions. add_found calls _on_new_detections (clamav.py:408-424), which records a malware_detected security event and, when response_mode is 'confirm', queues a playbook run; run_actions is the playbook executor, so routing its insert through add_found would raise a new event and could queue another run for the file it is already handling. It also de-duplicates on (path_b64, signature) while the secplus code looks up by (host, path, state='open'). record_detection must be a quiet insert with the secplus lookup rule. (2) The two scripts are built on different heads: clamav uses ACTION_HEAD with @QUAR@/@QID@/@B64@ substitution and decodes $path and $q itself; secscripts uses ROOTS, where QUAR is prefixed by $SF_SEC_ROOT for tests (secscripts.py:36-38). A shared bash function must take QUAR, q, path, signature as arguments and not assume either head. (3) Behaviour on an existing $q/file differs: clamav answers 'already in quarantine' and re-prints QUARANTINED, or conflicts; the threat path silently does nothing. (4) System path: clamav exits 1 with a conflict unless SYSTEM=1; the threat path prints info and still finishes ok, because the kill already succeeded. That must stay: failing the script after a successful kill would make kill_threat report an error. Same for a failed realpath check: it has to be 'info, not moved', not exit 1. (5) clamav's body also re-checks with clamscan, reports hard links and handles processes holding the file open (fuser, KILLED marker); none of that belongs in the shared function. Only lines 245-252 (sha, mkdir, meta, mv, chmod, marker) are common. (6) deploy kind differs: 'clamav-action' vs 'security' (through security._run); keep both. (7) Generated script text changes, so clamav digests and any test that compares script text will move.

First commit: Python side only, no script change: add clamav.mark_quarantined(conn, detection_id, qid, sha, actor) (the UPDATE at clamav.py:621-622) and clamav.open_detection(conn, host, path, signature) -> id (the lookup-or-quiet-insert at secplus.py:1485-1491, no events), and use them in clamav.quarantine, secplus.kill_threat and secplus.run_actions; secscripts.QUARANTINE = clamav.QUARANTINE. Files: storageforge_index/clamav.py, secplus.py, secscripts.py. Second commit, separately reviewed: one bash function for the sha/meta/mv/chmod/marker lines used by both scripts, and the realpath check added to the threat path as a skip-with-info.

### BE-80. One package-manager layer in the generated scripts: detect, wait for the lock, retry the update, install

Survey record `steps7` again: see its first appearance above.

## 0.6.9: The Rust programs and the secure channels

### BE-81. The agent's plugin programs take their bounded file read, disk list, clock and hex from the agent library

**Survey record `x15`** (*unchecked*): The agent's plugin programs take their bounded file read, disk list, clock and hex from the agent library, not from a copy each.

Copies:

- fn read(path) -> String with File::open, take(N), read_to_string four times, differing only in N: bin/plugin-disks.rs:30 (64 KiB), bin/plugin-files.rs:60 (4 MiB), bin/plugin-health.rs:26 (1 MiB), bin/plugin-network.rs:21 (16 MiB)
- The whole-disk filter over /sys/block twice with the same eight prefixes and the same 32-character, 64-entry limits: host.rs:210 Host::disks and bin/plugin-disks.rs:40 disks; a third, looser one at bin/plugin-health.rs:35 (three prefixes, 512 entries)
- pub fn now() identical: pluginside.rs:113 and supervise.rs:377
- fn hex identical: identity.rs:55 and journal.rs:50 (and enclave/src/main.rs:338 in the other crate)

Proposal: hostread::read_capped(path, most) and hostread::whole_disks(root) in the agent library; pluginside::now and one pub(crate) hex. Plugins keep their own limits as arguments.

What must survive: host.rs's disks decides which devices storageforge-agentctl hands to the container and the plugin's copy decides which it then reads: they must stay the same list, which is the point. plugin-health's looser list feeds a different report (it wants dm- and md devices) and should stay separate or take a flag. plugin-scan.rs:39 read() opens with open_plain (no symlinks) and returns Option; it is not the same function. Plugin binaries are signed with the release key, so their digests change.

### BE-82. The two Python Noise implementations (the agent tunnel and the enclave channel) share one symmetric state, cipher and framing

**Survey record `x3`** (*unchecked*): The two Python Noise implementations (the agent tunnel's IK and the enclave channel's NX) share one symmetric state, cipher and framing.

Copies:

- HKDF with identical body: agenttunnel.py:150 _hkdf and enclave.py:138 _Noise.hkdf
- mix_hash identical: agenttunnel.py:186 and enclave.py:134; mix_key and decrypt_and_hash the same but for where the counter lives: agenttunnel.py:189-200 and enclave.py:143-151
- Nonce built twice: agenttunnel.py:166 (b'\0\0\0\0' + struct.pack('>Q', n)) and enclave.py:148 (b'\0\0\0\0' + n.to_bytes(8, 'big'))
- Framing twice: agenttunnel.py:129-147 read_exact, read_frame, write_frame; enclave.py:219, 293, 318-322 do the same inline with their own MAX_FRAME (enclave.py:35, agenttunnel.py:37)
- agenttunnel.Cipher refuses the last nonce (agenttunnel.py:164); enclave.py's [AESGCM, count] pairs (enclave.py:198, 237) have no such check

Proposal: storageforge_index/noise.py holding Symmetric(protocol_name, prologue), Cipher, read_exact, read_frame, write_frame, MAX_FRAME and TAG. agenttunnel keeps the IK message pattern, admit and Session; enclave keeps the NX pattern, the pin check of the responder's static key and its request/response layer.

What must survive: This is the channel that carries the vault's secrets and the channel agents enroll over. The NX side resets n in mix_key and counts only when a key is set; the IK side holds the count in Cipher. Error types differ (TunnelError, EnclaveError) and callers match on them. The Rust vector (wire/src/noise_vector.txt) holds only the IK side; the NX side is checked only against a running enclave program.

### BE-83. The enclave takes its Noise primitives from the `wire` crate instead of its own copy

**Survey record `x4`** (*unchecked*): The enclave's own copy of the Noise primitives in main.rs is replaced by the ones in the wire crate.

Copies:

- hmac256 is the same function at enclave/src/main.rs:104 and wire/src/noise.rs:75
- X25519 with the small-order refusal: enclave/src/main.rs:113 x25519 and wire/src/noise.rs:84 dh; public half: main.rs:122 and noise.rs:93
- Handshake state: enclave/src/main.rs:128-177 Noise (new, mix_hash, hkdf, mix_key, encrypt_and_hash) and wire/src/noise.rs:162-215 Symmetric, the hkdf bodies identical line for line (main.rs:150, noise.rs:181)
- Per-direction cipher and nonce: enclave/src/main.rs:179-207 Channel and wire/src/noise.rs:105-156 Cipher
- The enclave depends on storageforge-wire without the 'noise' feature (enclave/Cargo.toml) and uses only read_frame, write_frame, FrameError, MAX_FRAME (main.rs:38)
- wire/src/noise.rs:32 fixes PROTOCOL_NAME to IK, so the NX side cannot use Symmetric as it stands

Proposal: wire::noise makes Symmetric and Cipher usable for any pattern: Symmetric::new(protocol_name, prologue) and pub(crate)-to-pub for mix_hash, mix_key, encrypt_and_hash, decrypt_and_hash, split. The enclave turns on the 'noise' feature and keeps its NX responder steps, its Refusal mapping and its lock-down counting.

What must survive: The enclave is the smallest trusted program in the project and its image is signed and reproducible: a changed dependency feature changes the binary and its digest. wire's Cipher refuses at u64::MAX and returns NoiseError; the enclave returns Option and counts a bad frame towards lock-down. The enclave's Noise has no decrypt_and_hash (the responder of NX never needs it). No stored format changes; the wire bytes must stay identical, which only the Python client against a built enclave proves today.

## Looked at and left apart

Candidates the second reader refused, with its reasons. The roadmap's *Will not be combined* table has one line for each.

### `api2`. Proxmox guests, storage and datastores reach the map, the Workloads list and the comparison through the same reader hooks every other platform uses

The fork exists as cited (apiviews.py:40-95, 101-126 vs 127-137, 169-181 vs 182-194, 195-210, 217-224), but the two paths do not do the same job and the per-connection hook shape cannot carry the Proxmox one: (1) Join key. The generic path joins a platform workload to a scanned one by (host, name, runtime) (apiviews.py:128-129) and attaches map nodes by name (wl:HOST:docker::NAME). Proxmox joins by (host, vmid) (:107, :116) because guest names are not unique and vmid is the identity; the row also carries 'vmid'. Routing Proxmox through the generic join would mis-pair or collapse same-named guests. (2) The Proxmox logic is cross-connection by design: guests() sorts all connections' objects so a direct reading beats one through PDM (:51), annotate_workloads removes the earlier PDM row (:117-118), map_extra dedupes by dict overwrite (:170), and compare() groups by scanned host across connections, then compare_connection filters by connection name (:218). A per-connection workloads()/compare() hook cannot express that; apiviews would keep a dedupe step, a group-by-host step and a vmid join, i.e. the same code plus a hook layer. The 90-line removal estimate is not reachable; I expect net growth. (3) The claimed gain is backwards: the Proxmox compare already reports four fields (name, state, memory within 1 MiB, type; :78-86) versus the generic path's single 'state' differs with a different null rule (both sides must be non-empty, :131); moving Proxmox onto the generic path would lose fields unless the generic path is rewritten. (4) managed_by differs on purpose: 'proxmox' and kind 'instance' for lxc (:122-124) versus the connection kind (:137). (5) apiviews.managed_by_host() consumes platform_workloads() and is called from workloads.listing (workloads.py:127); adding Proxmox to platform_workloads adds per-view work for every listing, harmless functionally (runtime filter) but not free. (6) The storage map block (:195-210) finds the STORED_ON mount from the graph's MountPoint nodes (g['nodes']); the map_nodes hook receives (conn,row,objects,hosts,layers), not the graph, so it would have to re-query mounts or emit blind edges. (7) tests/test_apipve.py:116 and tests/test_apipdm.py:78,86 call apiviews.compare(conn) directly with its cross-connection shape; response keys 'guests'/'datastores' are read by the web UI. The module docstring (apiviews.py:1-10) states the Proxmox side-by-side is a deliberate special relationship with the qm/pct scan. The only defensible fragment is trivial: give apipbs a compare() returning {'datastores': compare_mounts(...)} and drop the pbs branch in compare_connection; about 3 lines saved, not worth a commit on its own.

### `api7`. One 'API beside SSH' comparison builder (outer join by key, seen_by, differs, why) in place of five per-platform loops

The loops share a vocabulary (seen_by, differs, why) but not a structure, and a shared beside() would need as many parameters as each loop has lines. Differences the finder flattened: (1) apixo.py:310-319 is not a keyed 1:1 outer join: one SR maps to MANY mounts (one per pool host), differs entries carry an extra 'host' key per mount, rows carry mounted_on, and leftovers come from pop(); (2) apiviews.py:73-93 compares four fields with four different rules (string equality with '' default, memory within 1 MiB and only when both present, type only when ssh has a kind, api 'status' against ssh 'state') and sorts keys by (len, text); (3) apitruenas.py:390-398 merges the api-only and ssh-only cases into one branch and omits 'why' on matched rows; (4) apidockhand.py:308-318 adds 'stack' only on rows the API saw and has a separate scanned: False group shape with a group-level 'why'; (5) the state rule differs between copies: apiviews.py:131 (annotate_workloads) reports a difference only when BOTH states are non-empty, the compare loops use (a or '') != (s or ''), so one helper changes one of them. Row shapes are a web API read by the connection page. size_differs is a one-line expression used twice (apixo.py:315, apipbs.py:175). The mounts query is not the same query three times: apixo adds LIKE '/run/sr-mount/%' and selects sizes; apipbs matches hostname exactly and selects four columns; workloads._mounts_of (workloads.py:18-20) matches lower(hostname) and returns only (mount_point, filesystem_type). The 'deepest mount' at apiviews.py:208-210 works on graph nodes, not rows; workloads.sits_on rejects non-absolute paths and returns a dict without sizes. I checked the '/' case: apipbs's startswith(m.rstrip('/') + '/') does match everything under '/', same as sits_on. Expected net removal is at or below zero, and cross-module coupling (apipbs and apixo importing workloads, which imports wlmanaged/wlread/runtimes) is added. Not worth doing.

### `api9`. HTTP and WebSocket clients share one admission gate (closed, read-only, budget, rate) and TrueNAS results stop being serialised to text only to be parsed again

The four checks are restated (apiconn.py:568-574 and :792-799), but the proposal as written would change behaviour on the read-only boundary: in Client.request the rate turn and the sent count are INSIDE the retry loop (:580-581), once per attempt and per followed redirect, while the closed/ReadOnly/budget checks run once before it; in WsClient.call they run once. An _admit() that also takes the rate turn and counts, as proposed, either stops throttling and counting HTTP retries and redirects or double counts. Restricted to the three pre-checks it saves about 4 lines, and the two ReadOnly messages differ ('METHOD PATH needs' versus 'METHOD needs'), with 'is read-only' asserted by regex in tests/test_apiconn.py:190 and ReadOnly raised-type asserted in test_apitruenas.py:159-161 and test_apiportainer.py:93-95. The 'four transport wraps' are not the same: two catch http.client.HTTPException as well (:546, :630), messages differ ('did not answer: ' versus ': '), and one must close the connection first. The json.dumps round trip in apitruenas (six sites) is deliberate: the module contract is 'each parse_ function takes the JSON text of one result and never raises' (apitruenas.py:20-21), which keeps every parser fuzzable with hostile text the same way as the HTTP readers (tests/test_props_parsers.py); a call_text() on the client would only move the json.dumps, since the client must decode the envelope to match ids and errors. WsClient.get raising is by design. Gain about 5 lines against a change to the gate that decides whether a write leaves the process. Not worth doing.

### `netdev2`. What a device platform is lives in five places (PLATFORMS, APPLIERS, CLI PROFILES, emitter targets and if-platform branches); make it one registry entry per driver.

The tables exist as cited, but they are not five copies of one thing. nettransport.PROFILES is keyed by prompt profile, not platform (it has 'generic', which is no platform; opnsense uses the pfsense profile) and is read by CliSession.__init__ for any caller, so it cannot fold into a device registry. rostranspiler.TARGETS/EMITTERS are emit targets, six of which are Linux back ends with no device; routes_network.rostranspiler_target (37-44) already reads PLATFORMS for devices. What is left is PLATFORMS (6 rows) + APPLIERS (5 rows) + four small branches (default port at :93, cisco enable at :154/:167, openwrt zones at :354, routeros shadowed notes at :403). Replacing those with a dataclass carrying collect/collect_direct/applier/needs_enable/strip_config/compile_extras/report_notes hooks adds more lines than it removes (the claimed 40 removed is not credible), and 'adding a platform becomes one entry' is not true: it still needs an adapter module, an emitter and an applier class. The claimed bug class is overstated: for an snmp device report() calls compile_for -> rostranspiler.emit(stmts,'snmp') which raises DslError (rostranspiler.py:1038) before any change row is written, so apply()/_settle()/confirm() can never reach APPLIERS['snmp']; session() is never entered for snmp because read() branches first, so the missing PROFILES['snmp'] is also unreachable. facts_of running openwrt.strip_secrets on every platform (netdevice.py:254) is an SF-62 migration scrub; its regex only matches uci 'a.b.c=' lines so it is a no-op on other configs, and cisco configs are scrubbed at collect time. Things that would break: tests/test_routers.py:1360 does mock.patch.dict(netdevice.APPLIERS, {'routeros': Applier}); routes_network.py:32,40,85 index PLATFORMS as dict-of-dicts with ['target'] and ['label']; PLATFORMS is defined at the top of the file and the applier classes 450 lines below, so an 'applier' field needs the table moved or late binding. If anything is taken from this, take only: an explicit 'this device is read-only' DeviceError in report() for a platform with no applier (clearer than the DslError about targets), and nothing else.

### `netdev9`. A device reading and a host scan each write host_network and traffic samples with their own SQL.

The two statements (DELETE + INSERT into host_network) are written twice (netfacts.py:198-199, netdevice.py:240-241) and that is the whole of the duplication: two lines. The copies differ around it: netfacts.survey opens its own conn.tx() for just those two statements, netdevice.store runs them inside a larger transaction with the hosts upsert, two measurements and the network_devices update, so a shared save() must not open a transaction and must not call traffic.record inside (traffic.record opens its own tx, traffic.py:36, and both callers call it after their transaction); the counters come from different places (data['counters'] kept inside data_json for hosts, facts['counters'] stripped from the 'device' measurement for devices) and netfacts guards on `host and data.get('counters')` after a second query for the hostname. A helper that only wraps the two statements saves nothing. The inframeasure.empty() half is based on a wrong reading: netdevice.py:233-234 is not a restatement of inframeasure.parse's keys. It already omits proxmox_node, toolbox, every wlread key, and access.ip_forward/overlays/proxies/tunnels, and uses 'wireguard': [] and 'netbird': False where the host reader gives None/bool-from-tools, plus its own 'device' key. Readers cope with .get(). Generating it from inframeasure would change what is stored for every device (new keys, or None vs [] for wireguard, which readers may treat as 'not read' vs 'none'), for no removed code. Calling security._save_measurement from two modules is ordinary reuse of a private name, not duplication.

### `netdev10`. Untrusted XML from a device or a scan is guarded by three separate loaders with different rules.

Three small loaders exist (pfsense.py:47-55, netscan.py:80-88, runtimes/guests.py:24-29), each 5-8 lines, but they differ in every parameter a shared one would need: the size cap, whether empty input is an error, whether DOCTYPE is allowed (nmap -oX really does start with <!DOCTYPE nmaprun>, so netscan must allow it), three different error texts (tests/test_props_parsers.py:220 asserts 'does not parse' across modules), and guests._xml returns None instead of raising because one bad domain must not fail the reading. A shared function with limit, what, allow_doctype and raise-or-None flags is about as long as the three bodies; net saving is a handful of lines, not 12. The security argument is also wrong: an entity can only be declared with the literal token '<!ENTITY' (XML allows no whitespace or split inside the markup-declaration open), including parameter entities and those in an internal subset, so netscan's substring test already refuses every entity declaration; there is no 'split oddly' bypass. All three therefore enforce the same effective rule (no entity declarations, size cap), with netscan correctly tolerating a bare DOCTYPE. netdevice.merge_config already reuses pfsense.load_xml where the input is the same kind of document. No bug class is removed.

### `netdev11`. The DSL's Linux targets (nftables, iptables, firewalld, ufw, networkd, NetworkManager) are preview-only emitters in Python, while what is actually deployed to a Linux host is written by separate bash writers in the plan steps.

This is two different products that overlap in subject, not parallel implementations of one job. The observation that they disagree on names is true (to_nftables writes table 'storageforge_dsl', rostranspiler.py:427, and networkd files 50-<name>; the steps write inet storageforge_rules and 10-sf-<name>, steps_infra.py:427-429), and the Linux emitters are reached in the app only from /api/dsl/compile (routes_network.py:207). But 'preview-only' is wrong: tests/lab/tiers_netlang.py:51 runs emit() for these targets in the lab, and tests/test_bughunt_rest_b.py:165-170 and test_props_netlang ShellTargets pin their output — they are a tested whole-ruleset translation a person can run by hand. The step writers are a different thing by design: signed, idempotent insert-if-missing by tag with journalled undo and a rollback timer, one port per step, and tasks_of (routes_network.py:47-58) accepts only plain accept/drop/reject tcp/udp input/forward rules with a dst-port and place-before in (None,'0'); everything else (jump chains, address lists, NAT, src-port, connection-state, negations, ranges of sources) has no step. Rendering the compile preview from step scripts would cover a small subset, would put signed deploy script text behind a preview API, and would change pinned emitter output. Nothing here can be combined without crossing the boundary between 'translate a rule set' and 'stage an idempotent signed change', which the design keeps apart (the /api/dsl/stage route already tells the user what was left out via `left`). If the mismatch bothers the owner, the fix is a sentence in the compile response for Linux targets saying that Deploy stages plain rules through fw-rule steps in StorageForge's own table and that this text is a hand-run translation — a product decision, not a consolidation, and it removes no code (the claimed 120 lines would not be removed).

### `shares6`. NFS and SMB are hard-coded in shares.py beside a driver registry that serves the other nine kinds; make them the first two drivers.

The split exists as described (netshares.py:117 refuses the keys; three-way branches at shares.py:357, 492, 514-525; the script tail at 1219-1235). It is a boundary the design holds on purpose, not parallel copies of one job, and the proposal removes almost no code.

- NFS and SMB are aggregate: one server_nfs writes one exports file for all shares and one open_fw call covers them; server_smb writes one smb.conf include. Drivers are per share. Client mounts go through /etc/fstab lines with a marker (client_mount, client_cleanup, WANT_LINES); driver mounts are systemd units cleaned by driver_units_cleanup, which itself excludes NFS and SMB (netshares.py:240).
- Takeover of the host's own exports and smb.conf sections, rules per client, SMB lines and id_check have no place in the Driver contract. They would become driver hooks used by exactly two drivers, so the branches move instead of going away.
- Protocol values differ in kind: drivers store drv.key; NFS and SMB store version strings ('NFSv4.2', 'SMB3'; shares.py:492). payloads.share_key (payloads.py:714-720), graph.py:113-122, reinstall.py:434-442 and secplus.py:1997 read those literals. Scanned shares, which no design owns, carry 'NFS' and 'SMB' too.
- The script's E_RULES and E_SMB arrays and the design hash are stored state: a changed hash marks every deployed design as not deployed.
- The finder's own stated gain is "none directly", at L size and high risk, for about 100 lines moved.

If the branches bother anyone, a cheaper step is one function in shares.py for the three-way lookup of needs_server/needs_client (lines 357 and 438).

### `shares8`. rclone.LIB carries its own package installer and its own vault-secret path lookup, parallel to scriptkit.PACKAGES and netshares' secret helper.

The parallel code exists (rclone.py:45-60 vs scriptkit.py:452-476; rc_secret at rclone.py:61 is identical to pve_secret at steps_proxmox.py:81), but the proposal adds code instead of removing it.

- rclone.LIB runs in three contexts: the shares script (has PACKAGES and netshares.BASH), the change-plan script (no PACKAGES; changes.py assembles EXTRA_BASH), and the Ansible shell task (rclone.py:210-216) whose stub head defines only ok, missing, conflict, info, act, durable and reload_systemd. LIB therefore has to stay self-contained. "Call install_pkg when it is defined" keeps the old loop as the fallback and adds a branch: no lines removed, two install paths to test.
- PACKAGES contains apostrophes (`tr '\n' ' '`, scriptkit.py:474), and change-plan bash must hold none (rclone.py:42, steps_archive.py:74 and seven other step modules). It cannot simply be prepended to the plan script.
- rc_install installs two packages in one command and checks rc_bin, including /usr/bin/rclone when PATH lacks it; install_pkg takes one package and need_cmd tests `command -v`. The messages differ too.
- Secrets: rc_secret returns the path whether or not the file exists, and rc_config relies on that for its "not on this host" text; netshares secret prints nothing when the file is missing. secretstore.BASH is in the plan and shares scripts but not in the Ansible task, so a shared sf_secret_path there breaks the Ansible form. Three one-line functions are not worth a new cross-script dependency.
- rclone.py:50 is dead: it assigns the value pkgs already has. Delete that one line on its own.

If the gain wanted is surviving a held dpkg lock, add `-o DPkg::Lock::Timeout=120` to the two apt-get calls in rc_install.

### `steps5`. Security hardening actions go through the plan steps that already exist, instead of a second set of one-off scripts

The four pairs exist as described (secscripts.py:941-968 vs steps_infra.py:519-536; secscripts.py:1153-1173 vs steps_infra.py:479-486 and 512-517). But they are not doing the same job, and the proposal crosses a boundary kept on purpose.

- security.remediate_mac (security.py:1111-1126) runs through security._act (security.py:146-152): three modes (preview returns the script text, dry-run, apply), a result shape the security view reads, its own ref ('boolean:<name>', 'relabel:<path>') and audit kind, an allow-list (EXPECTED_BOOLEANS, SE_TYPES) and a refusal for /, /etc, /usr and so on. Staging a one-step plan through changes.deploy_items replaces all of that with plan storage, plan checks, the destructive/accept machinery and a different output format. That is a new feature path, not a merge.
- The one-off scripts verify after the change and exit 1 (secscripts.py:953, 966) and exit 1 when the tool is missing; the steps 'return 0' after conflict and do not re-read. t_selinux_relabel also treats a missing path as 'later', the script as a conflict.
- The compliance script writes the whole sysctl set as one file and loads it with sysctl -p, and it is a self-contained download (--offline-bundle); t_sysctl_set edits one key per call in another file. Inlining step functions into it needs act/try/durable/later with the step semantics inside a script that has its own report helpers: more text, not less.
- The 99-vs-90 drop-in point is real but the finder overstates it: secplus.reconverge_tasks (secplus.py:369-381) emits sysctl-set with the same values as sx.SYSCTLS, so the two files agree in the product's own flow. They disagree only when an operator's sysctl-set step contradicts the applied profile, where the profile winning at boot is arguably intended. t_sysctl_set then says 'it stays across a reboot' wrongly. tests/lab/tiers_platform.py:470-473 and :1091 pin the 99 file name.

Net removal would be about 30 lines of Bash against a changed security UI contract. Not worth doing as proposed.

### `steps10`. Built-in step types join the registry the other 70 use, and the side registries become fields of one step record

The two dispatch systems exist as described (changes.py:266-268, 511-514, 1839-1842; ARGS literal at 1016-1031; 136 types of which 100 are registered). But the bug class named as the gain does not exist today: I compared the hard-coded case list in run() (changes.py:1821: partition, partition-add, format, btrfs-add, btrfs-replace, btrfs-remove, zfs-pool, lvm-vg, lvm-vg-extend) with the built-in kinds whose TYPES entry has destructive True, and they are the same nine. Registered kinds go through @DESTRUCTIVE@ from TYPES (changes.py:1123). The destructive hole that does exist is in the Ansible exporters (first candidate), and this refactor does not fix it.

What would break or cost:
- The built-in Bash lives in CHANGE_BODY_3 together with dev_guard, devs_guard, mkfs_dev and run(). steps_pools.py:594 cuts functions out of changes.CHANGE_BODY_3 by name, and steps_storage._ansible_guards (steps_storage.py:432) scans vars(changes) for the string holding dev_guard(). Moving built-ins to steps_builtin_*.py breaks both unless the helpers stay put.
- The generated script must stay byte-equal for built-in steps or every deployed plan shows as changed once (digest in deploy.mark_deployed); EXTRA_BASH order decides which definition of a repeated helper wins, and steps_infra.py:1471 resets the list ('EXTRA_BASH[:] = [BASH]').
- Outside readers of the registries: wlmanaged.install mutates EXTRA[kind]['check'] (wlmanaged.py:142-151); server.py:1854 serves changes.TYPES as JSON; clone.py:305, toolbox.py:456-467 and 1253, cli.py:388, secretstore.py:168, steps_sshca.py:250 (changes.ARGS), steps_vm.py:275-292 and mapdesign.py:34 (changes.CHECKS) read them directly.
- _check_task for built-ins is one function with shared closures (parent_ok and friends, changes.py:516 onward to about 916); splitting it into per-kind check functions is a rewrite of about 400 lines of working code, which is where the risk is, and the 120-line removal estimate is optimistic (the dict of titles and the if-chain become as many small functions).

The finder's own note says it is worth doing only with the Ansible builder and has no visible gain. I agree with the second half: not worth doing as a whole.

### `steps12`. One frame for the downloadable scripts: option loop shell, --host hand-off, root check, lock and log

The resemblance is real but each frame differs in almost every line, so a shared frame() becomes a template with one parameter per line:
- Initial variables and modes: changes 'MODE=check; ONLY=; HOST=; DESTRUCTIVE=0; ACCEPTED=' (changes.py:1150); shares MODE=report; moves six modes and CHECKSUM; tasks MODE=report with --run/--install/--uninstall; pkglist and reinstall use APPLY=0 with no MODE.
- Help: changes and shares use sed -n '2,/^set -euo/p' (changes.py:1159, shares.py:867); moves the same through usage(); tasks sed -n '2,12p' (tasks.py:950); pkglist and reinstall sed -n '/^# Usage/,/^$/p' (pkglist.py:236, reinstall.py:45).
- Unknown option text: 'unknown option: $1 (try --help)' in changes/shares/moves, 'unknown option: $1' in tasks, 'unknown option $1 (see --help)' in pkglist/reinstall. --host message differs too ('needs [user@]host', 'needs user@host', 'needs a name').
- --forward-agent exists in changes, shares, moves, tasks; not in pkglist or reinstall. --secrets-stdin only in changes and shares.
- Root rule: the same line in changes, shares, pkglist, reinstall; moves has a mode regex and another sentence (moves.py:802-804); tasks has its own.
- Lock and log: changes locks only on apply and exports LVM_SUPPRESS_FD_WARNINGS; moves locks for every mode but check and logs for run/cutover/install only (moves.py:812-818); the others have neither.
- Order: changes puts HELPERS before REMOTE with RECEIVE_KIT and SEND_KIT between (changes.py:1122); moves HELPERS, two functions, REMOTE; pkglist and reinstall REMOTE, PATH export, root check, then HELPERS; tasks rewrites REMOTE with .replace('sf-move','sf-task') (tasks.py:830).

A frame honouring all of that removes perhaps 20 lines net, changes the text and digest of every generated script (deployed plans show as changed once), and puts six user-facing downloads behind one function whose tests are spread over five files. The finder's own estimate is 'about ten lines per script' with no user-visible gain. Not worth doing.

### `agentlogs8`. One reader for a host's stored inventory and its text sections, instead of each module fetching inventory_json and re-parsing a section

The fetch-and-decode one-liner is repeated (sfagent.py:443-444, agentmonitor.py:59-60, agentfiles.py:62 and 73, agentdisks.py:95), and the amd64/arm64 map is written three times (sfagent.py:346 and 427, agentmonitor.py:102). The section parsers the proposal wants to merge are not copies:
- pkglist.py:120 parses the raw scan output and maps through ARCH to Debian names; it does not read hosts.inventory_json. sfagent.host_arch also falls back to inv['pkglist']['arch'] (amd64/arm64 form), which the proposal's arch(inv) leaves out.
- agentfiles.users accepts any 'u' line with three or more fields and a numeric uid, caps the name at 64 characters and seeds uid 0. hostconfig.parse_accounts needs exactly six fields, the _NAME regex and a numeric gid. Delegating drops accounts with unusual names or short lines from the who-changed-it display.
- agentfiles.managed_paths takes every '/path: OK|FAILED' line as a path set. alerts.drift takes only ': FAILED$' lines that are not 'open or read', plus TIMER, LINE-MISSING and sha256sum lines, grouped by '## section'. They answer different questions.
- host_os looks the host up case-insensitively through deploy.canonical; the others match exactly.

What is left is inventory(conn, host) and one arch constant: about 8 lines across five modules, in a new module. Not worth a module of its own. agentdisks, agentfiles and agentscan import only .db on purpose.

### `agentlogs10`. One loader for the release's agent artifacts (agentctl, Windows agentctl, plugin descriptor, plugin program, image signature)

The functions exist as cited, but they load different files with different checks, and the shared part (where the folders are) is already one function, agenttunnel.plugins_dir(), used by all three plugin readers.
- agentctl_program: ELF magic, 32 MiB, raises AgentError with a build hint. release_plugin: descriptor plus signature pair, 16 KiB, operator/ fallback, returns the signer. program_of: size and sha256 against the descriptor, raises TunnelError. A table of (path, magic, cap) covers only the first; the other two keep their own logic.
- agentmonitor._windows_agentctl is unreachable: setup() raises NO_WINDOWS at agentmonitor.py:144-145 before the os_family branches, and register() refuses windows at agentmonitor.py:108-109. It is one of the two 'copies' of the magic/cap loader. It also joins an unvalidated arch string from the inventory into a path. Deleting it, or leaving it for planned Windows support, is the owner's call; either way it is not a reason for a loader table.
- The two name rules do differ (sfagent.py:347 regex vs agenttunnel.py:354 replace('-','').isalnum(), which allows upper case, non-ASCII alphanumerics and any length; neither admits '/' or '.'). program_of only sees descriptors that release_plugin already accepted, so the lax one is not reachable with a bad name today. Tightening it is a one-line change that needs no new module.
- A new module imported by agenttunnel lands in the receiver process and must be stdlib-only.

Net removal would be near zero.

### `agentlogs11`. Readers of the open alerts share one row shape (level, host, quiet) instead of three SELECTs with different columns

There are three SELECTs over alerts (alerts.py:677-682, notifications.py:102/129, logmonitor.py:20-30), but they are small and differ on purpose.
- list_alerts has three callers (cli.py:424, reportextra.py:34, server.py:2207), orders by last_at with a limit, and can include resolved rows (no caller passes include_resolved). center() reads all open rows and then runs fix_for() and _last_plan() per item, which are extra queries. An open_items() built on it must skip those or /api/deploy and the report get slower.
- logmonitor._alerts filters by kind in SQL, drops rows without a host, groups per host and sorts by its own rank. Going through _item() adds a mutes query to compute fields it does not show.
- The 'mark computed in three places' is not three copies: server.py:1166-1173 is one six-subquery statement that builds a different mark (scan, job, network ids too); notifications.summary builds another from center(); site.py:133 is a bare count for the backup page.
- The stated gain (CLI and report show level, host, muted) is a feature. It is done by adding two columns to list_alerts' SELECT, not by merging readers.

About 5 lines would go.

### `agentlogs12`. Route modules share one 'refused' mapping and one audited-write wrapper

The pattern is real and wider than cited: 'except LookupError' appears 41 times in server.py, 14 in routes_toolbox, 8 in routes_scheduler, 3 each in routes_logrules and routes_workloads. But each instance is a two-line except clause inside a try that stays where it is. A ctx.refused(exc) swaps one one-liner for another and removes nothing. The estimate of 80 lines does not hold.
- The four helpers are not the same thing: routes_notifications.refused maps to 404/400; routes_agent.refused maps to 404/409 and adds a 'code' field the UI reads; routes_network.refused is a Flask errorhandler for three module exception types (always 400); routes_toolbox.bad takes the status from the caller.
- routes_scheduler's handlers interleave other exceptions (StillDeployed gives 409) and put the audit call inside the try with per-route detail built from the result.
- ctx.audited writing 'denied' rows everywhere is a behaviour change to audit_log, a hash-chained table, not a consolidation. with_audit in routes_notifications also carries a comment saying denials are logged there deliberately.
- A global Flask errorhandler for LookupError would be wrong: KeyError and IndexError from bugs would become 404s carrying str(exc).
- ctx is a SimpleNamespace built at server.py:1153, so a helper is easy to add; the gain is still absent.

The only true duplication is inside routes_logrules.py: the same LookupError/ValueError block at lines 27-32, 50-55 and 71-76.

### `agentlogs13`. One LIKE-escaping and text-filter helper for history searches

Seen: the same three replaces at logbook.py:37-38, search.py:153-154 and security.py:937; notifications.py:295-296 does it with '!' as the escape character. That is about 3 lines of real duplication.
- notifications.history cannot use logbook._where as it stands: _where compares host exactly (notifications uses lower(host) = :h), wraps columns in lower(CAST(c AS TEXT)), writes ESCAPE '\', and has since/until/status handling that history does not use. notifications also truncates q to 200 characters and lowercases it itself.
- The three sites already differ in the ESCAPE clause: logbook and security write ESCAPE '\' on both dialects, search.py:193 writes it only for SQLite, notifications writes ESCAPE '!' on both. All work today. Unifying means touching SQL in four modules on two dialects for no visible gain.
- logbook._like also lowercases and wraps in %; search.like_escape and security.py:937 do neither (prefix patterns). A shared helper needs the contains flag, and the callers keep most of their line.

### `toolwork3`. Terraform and Puppet are written twice, once from a change plan (wlexport) and once from a design (mapdesign); the design already becomes plan tasks, so one exporter can serve both.

The helper duplication is real (_hcl == _hstr at mapdesign.py:179-181 / wlexport.py:117-118; _pp == _pq; _slug ~ _id; _ports_tf ~ _publish). The exporters themselves are not two copies of one job and the proposed direction (wlexport absorbs mapdesign) loses things: (1) Safety: mapdesign's Puppet uses array-form exec commands with every argument quoted by _pp (mapdesign.py:249-262) and tests/test_design_exports.py:64-65 asserts an injection attempt stays quoted; wlexport's Puppet builds shell-string commands by f-string (wlexport.py:300-316: 'virt-install ... --name {name}', 'incus launch {image} {name}'), relying on changes.normalize having validated the plan. Design docs are only str()-coerced (mapdesign.py:54-57), so routing them through wlexport would be a quoting regression. (2) wlexport.model() calls changes.normalize(plan) (wlexport.py:66), which validates and can raise on design values that the design exporter accepts today. (3) mapdesign's per-host provider alias is correct; wlexport emits one provider for hosts[0] and a comment (wlexport.py:183-187) - the better implementation is the one proposed for deletion. (4) The stated user gain is wrong: a design workload is only 'container' or 'vm' (mapdesign.py:53-57), so design exports cannot 'gain stacks, Incus, LXC, vm-create, vm-iso'. (5) tests/test_design_exports.py:44 asserts 'podman container pod' in the left-out comment; wlexport exports podman through the docker provider. (6) Resource ids change (r_ vs w_ prefix, docker_image resources added), host URI changes ssh://host -> ssh://root@host: destroy/create for anyone who applied the file. Net code change is close to zero because fw-rule, net-bridge, net-vlan, aliasing and the podman carve-out all have to be added to wlexport.

### `toolwork7`. toolbox.preview and toolbox.install_words each resolve a catalog entry for a host (entry, trust, override, method, resolved ports and bind, image verification); one resolver should feed both the preview and the script-time words.

The overlap exists but is about 10 lines per side (find, trust refused, override_row/load_override, resolve, management-bind rule, image_verification_words: toolbox.py:1202-1229 vs 1352-1380) and the two sides differ on purpose in every other respect: preview raises CatalogError/LookupError, accepts an unsaved row, auto-chooses a method through choose() with host facts and refuses appliances; install_words never raises, returns ['refused', why], takes the method as pinned and adds the three pins (entry sha 1357, unsigned acceptance 1359-1362, override sha 1365-1366). A Resolved object with optional pins makes the trust checks parameters that a caller could omit, which is the wrong direction for the script-time boundary. made() (toolbox.py:1166-1183) and the word lists are different outputs from the same inputs, not duplicates. The cited divergence is nearly unreachable: set_override refuses any override with problems (toolbox.py:991-993), so a stored override with problems only arises if the override schema tightens after it was saved; in that case preview keeps the partly parsed override and stages override sha '' (toolbox.py:1263), and install_words then refuses because the stored row's sha is not '' - but steps_toolbox.check_install (436-449) calls install_words at plan check, so the mismatch already shows as a crit before apply. Estimated saving is ~15 lines, not 45.

### `toolwork8`. deploy.run and deploy.raw each build the signed SSH run from scratch (refusal, readiness, nonce, vault binding, signed request, ephemeral agent, transport, deploy_runs row, audit); one session helper should own that.

The shared sequence is real (deploy.py:461-484 vs 559-582) and the drift list is accurate: run stores the host as given (439) and raw the canonical name (570); run maps NoBinding to DeployError (473-474), raw lets it propagate; agent ttl=timeout+60 (479) vs default (578); _host_turn with waiting line and cancel (401-415) vs a silent _lock (574). Differences the finder missed, which make one context manager awkward: (1) error contract - run never raises: the row is inserted BEFORE the refusal/readiness checks and every failure is written into the row (the 'never leave a run running' rule at 539-547); raw raises to its caller and performs refusal/readiness BEFORE inserting a row, so a refused raw run leaves no row. (2) run adopts a queued row (run_id=) and records script_sha and timeout_s; raw records neither. (3) stderr=STDOUT vs PIPE; raw stores mode 'apply' but computes status with run_status(rc, 'report', ''). (4) raw passes no args and has no sign_as or require_ready. (5) raw is itself a generator context manager; wrapping its yield in another context manager that also owns Transport close and the audit line changes which exceptions the caller's body can see. The truly common part is about 8 lines (resolve binding, request, ephemeral_agent, Transport, Popen). The three SELECT column lists (654-676) are three different projections on purpose (history omits output, which can be megabytes; output omits actor and times): a single RUN_COLUMNS would change returned keys. Saving ~15 lines on the path that signs every host change.

### `toolwork12`. Which folders are system folders that must never be given to a container (:Z) or used as a data root is listed in five places with different contents.

The five lists exist (toolbox.py:903, steps_workloads.py:530, steps_dockerd.py:20, fsmap.py:22-23, clamav.py:37) but they answer five different questions and a single base tuple cannot satisfy 'only ever longer': fsmap.SYSTEM_DIRS is used by shares.py:316/446, steps_archive.py:39 and steps_storage.py:25, where /srv, /opt, /mnt and /media are ordinary share/archive/mount targets - adding the stack list's members there would refuse valid paths; the Toolbox list is prefix-based and must keep /srv/x and /opt/x allowed while refusing everything under /var; the dockerd list is exact-match and embedded in signed Bash as a case pattern (steps_dockerd.py:380) and intentionally includes /opt and /srv but not /mnt or /media (a data root on /mnt/disk is the normal case, and /mnt itself is arguably fine to refuse but is a behaviour change); /var/log is only in fsmap; clamav's is 'where a detection is an OS file'. The common core is about 16 names, so a shared base plus per-feature extras removes no code (the 20-line estimate is not there) and couples features that are kept apart on purpose. The one real defect is separate from the lists: relabel_findings (steps_workloads.py:533-543) only does rstrip('/'), so '/./etc', '//etc' or '/srv/../etc' with :Z pass, and the stack list lacks /lib64 and /lib32.

### `keysnet7`. One reader toolkit and one dispatch table for overlays, tunnels and access proxies

The duplication exists but is thinner than described and the copies differ where it counts. _text: tunnels.py:45-46 and accessproxies.py:28-29 are the same rule (ints accepted, '***' dropped); overlays.py:82-83 is a different rule (strings only, '***' kept). JSON: overlays._loaded vs accessproxies._json differ in the envelope key ('network' vs 'tool', stored in scan results) and in retries. YAML: three different contracts: tunnels._yaml returns (doc, envelope) with the text "not this tool's configuration" and must not scrub; accessproxies._yaml returns None with no envelope and scrubs; overlays.nebula has its own sentence ('not a Nebula configuration') and an extra shape test. Size sentences differ too ('larger than a configuration file should be' vs 'more than it should ever print') and the caps differ (256 KiB vs 4 MiB). Dispatch: overlays.READERS (overlays.py:514) cannot drive parse_overlays: it is keyed by reader name ('headscale', 'strongswan') while the error envelope needs the network ('tailscale', 'ipsec'), and it has no zerotier entry at all although parse_overlays reads zerotier with three sections. The three loops also decide 'skip' differently: overlays on the first section (ipsec on the last), proxies on any section, tunnels per tool with the running flag and synthetic rows for tools that run with nothing to read, plus the OpenVPN PKI attachment. One read_all would need a mode per caller. What is left to share is about 20-25 lines behind four parameters, not 70, across parsers that property tests (tests/test_props_parsers.py) pin as never raising. The one real gain (access-proxy JSON tolerating a bracketed warning line) is a three-line change inside accessproxies._json and needs no shared module.

### `keysnet9`. One issued-certificate ledger and CA front for the SSH CA and the Nebula CAs

This is a parallel life cycle, not duplicated code: there is nothing to delete. sshcerts keeps rows in ssh_certificates keyed by a random 62-bit serial with pruning, a KRL version counter and a MAX_LISTED cap (sshcerts.py:139-153, 272-295); overlaykeys keeps a list inside one settings value keyed by fingerprint, revokes by NAME (every running certificate of that name, overlaykeys.py:149-158) and enforces one address per name by scanning the list (136-138). A common table would need both identities, both revoke semantics and the address-uniqueness scan, so each side keeps its own code and a ledger module is added on top: net lines go up, with a migration in both migrations/sqlite and migrations/postgres, a backfill of the nebula_cas setting, and backup.py's table list (it names ssh_certificates) to extend. The finder's own estimate of 60 lines removed is not supported by anything in the two files. The real defects it found are worth fixing on their own and are small: (a) overlaykeys.issue and revoke do read-modify-write of the whole setting outside a transaction (alerts.set_setting is DELETE then INSERT), so two concurrent issues lose one and the address check can be raced; (b) 'issued' is never pruned; (c) Nebula CA and host-certificate expiry have no notification (only the plan check at steps_overlay.py:377-381). The Keys-page routes for Nebula are a feature, to be requested as one.

### `webcore3`. One host report channel for jobs, schedules and the security sentinel: token, bearer route, host-side post and scan fallback.

The four-line Bearer preamble is repeated at server.py:2657-2660, 2672-2675, routes_scheduler.py:219-223, routes_security.py:57-60: that much is real. The rest is parallel, not duplicate, and sits on the only session-less routes. Differences missed: jobs.job_for_token rejects tokens longer than 200 characters and removed jobs; scheduler.schedule_for_token rejects tokens shorter than 16 and WRITES on lookup (promotes the pending hash); security.report_host scans settings rows with compare_digest. The ownership check after it differs (body['job'] string compare, int(schedule_id) compare, none for the sentinel because the token names the host). After-ingest differs (wake only if new; enqueue a rescan; wake on dropped). Host side: three different timeouts (5 s state, 20 s job report, 30 s schedule, 5 s sentinel in the background with &), the sentinel's header file is written once at install (secscripts.py:891) while the others build a temp header per post, the schedule posts a body file with the output spliced in, only jobs have the python3 fallback. One Bash sf_report changes every generated script, which changes clamav/security digests (they hash the install script) and marks every deployed unit as changed. Scan fallbacks share only 'for line: json.loads': duplicate detection is by run_uuid (jobs), by nonce OR started_at (schedules), by host+task+started_at with an UPDATE branch (confirm.py), and host ownership is checked three ways. The two future-date limits (600 s, 3600 s) guard different things (a forged ok vs a parked next_run_at, with a further 300 s clamp at scheduler.py:1001). The user-visible gains listed are new features (tasks posting reports, sentinel pending token), not consolidation. Honest removal is about 15 lines. If anything: a ctx.bearer() helper returning the token string, in server.py, used by the four routes, with each lookup and each 401 text left as is.

### `webcore4`. One calendar module for cron and systemd OnCalendar parsing, period and conversion.

These are parsers for two different grammars, and the one shared piece (scriptkit.longest_gap) is already shared. jobs._calendar_values reads OnCalendar fields ('1..7', '0/6', seconds fractions, Monday=0) and never raises to the caller; scheduler._parse_field reads cron fields ('1-7', '*/6', month and day names, Sunday=0 and 7) and raises ValueError, which is the save-time validator. Merging them yields one module holding two parsers, no fewer lines. The 'three lists of named calendar times' are UI presets and defaults of three features (tasks.SCHEDULES with labels, jobs.LEVEL_CAL/VERIFY_CAL/DEDUPE_CAL per level), not copies. tasks.SCHEDULE_RE is a character whitelist for shell safety, not a parser. The alias tables map to different targets (scheduler: alias to cron line; snapfind.py:100: alias to a named period, without @yearly). The one concrete proposal, replacing snapfind.cron_calendar with scheduler.period, is wrong as stated: scheduler.parse_cron requires a day to match BOTH day-of-month and day-of-week (scheduler.py:176 and the docstring at 1165), while real cron, which is what an imported rsnapshot line runs under, fires when EITHER matches if both are restricted; real crontab lines also carry forms parse_cron refuses. And entry['calendar'] is stored as a string that jobs.period reads, so it needs a new field or a conversion, and it changes when existing imported jobs alert as late. That is a behaviour change to decide on its own, not a consolidation.

### `webcore7`. One audited-operation layer so the CLI and the web write the same audit rows under one actor format.

The divergences are real (three actor formats; cli.py:125-133 and 1687-1691 repeat 'unlock, else plain chain'; web saves audit and CLI saves do not; web clone save checks accepted risks, cli.py:939 does not; cli 'schedule run' at 1791-1826 runs the task script on the controller with the schedule's env while the web route deploys it to the host). But this is a feature and a set of behaviour decisions, not a consolidation: it adds code and audit rows, it removes almost none (the 80 lines are not there to remove). What would break or change: Vault(db, conn).unlock() on every CLI save reads STORAGEFORGE_VAULT_SECRET or asks the key enclave, so 'moves import' gains a vault/enclave round trip and, with an enclave, a counted operation; f'cli:{$USER}' and vault.actor_name() (getpass.getuser) can name different users under sudo or in a container, and the value is stored in updated_by and in 'cli'-keyed audit rows that existing logs and tests/test_enclave_release.py style fixtures use; thin shared functions for save_plan etc. would pull the route's has_raw_hooks/need() ordering apart from the audit row (the route audits after the permission check, with its own detail keys). The clone accepted-risk gap and the two meanings of 'schedule run' are findings to raise with the owner on their own. The only refactor here that preserves behaviour is tiny and lives in cli.py alone: one _audited(db, conn, action, outcome, host, **detail) doing the unlock-else-plain choice for _audit_plain_scan and cmd_user, and one cli_actor() used where f'cli:{os.environ.get("USER", "?")}' is written eight times, returning that same string.

### `webcore9`. One vault-backed SSH session context manager replaces the binding, agent and Transport setup written at each call site.

The sequence 'decrypt_key, ephemeral_agent, Transport(..., known_hosts, isolated=True)' does recur, but it is two to four lines per site and the sites differ in almost every argument, so one vault_session(...) needs a parameter for each difference and removes perhaps 20-30 lines, not 90, on the path every private key takes. Differences seen: runner.py passes _for_scans(vault.decrypt_key(key_id)) with NO task label and wraps the key, the others pass 'deploy', 'git', 'access', 'rotate', 'device'; access.py, keyinstall.py and rotation.py do not resolve a binding at all (key looked up by name from ssh_keys, user and port from the caller) and get the vault passed in already unlocked; strict=True and connect_timeout=10 only in access/keyinstall/rotation; ttl is 60, 120, TIMEOUT+30, timeout+60, max(600, timeout+60) or default; netdevice.py:186 picks NetworkTransport and may override the user with the device's username; deploy.py:468 holds _track(nonce) and _host_turn or _lock around the vault unlock and builds the signed request between resolve and the agent; deploy.py:576-584 does not close in the same shape; gitrepos refuses loopback names first; NoBinding is mapped to DeployError, DeviceError, an audited 'denied' row plus re-raise, or a skip, per caller. Certificates for deploys, git and access is a new behaviour (and the cert context needs the audit log and purpose), not a result of merging. The one true duplicate is inside runner.py: checksum_catchup (152-156) and scan_via_vault (208-213) open the same cert + agent + Transport + scan signing. If a slice is wanted, a private context manager in storageforge_index/runner.py for just those two, with each caller keeping its own audit rows and its try/finally, and tests/test_scan_signs.py, test_scansign.py, test_sshcerts.py and test_indexer.py as the check.

### `secmap1`. One design store and one design pipeline for the storage blueprint, the map design and saved versions (finishes roadmap 3i / section 10.1).

The two stores, two compare engines and two design-to-plan paths exist as cited (graph.py:325-338, mapdesign.py 106-175 and 271-346, design_versions.py:24-34/124-138/246-274, server.py:3105-3142). But this is not a consolidation: it is roadmap step 3i itself. ../roadmap.md line 96 says '3i only if decided' and requires 'the 3i answers in 10.1 confirmed again, and its migration, before it runs'; line 353 lists map alternatives, whole-document restore and editor cutover as open product work. It needs a stored-format migration in both dialects, a new API shape, a lab run and an owner checkpoint, so it must not ride in on a combine-backends branch. Finder's details that are wrong or thin: (1) the two compare engines do different jobs and cannot be one: design_versions.compare is document vs document and returns sentences; mapdesign.compare is document vs live readings and has an 'unknown' bucket ('unread stays unread, never counted as missing'). (2) to_tasks = fromdesign.plan + mapdesign.missing_tasks is not a plain concatenation: fromdesign.plan raises LookupError for an unscanned host (server.py:3111 turns it into 409) while mapdesign reports an unscanned host as 'missing' and still emits tasks. (3) mapdesign._actual matches name or ssh_host, graph.stored_blueprint matches short names via LIKE, server.py:3073 matches hostname exactly: three host-match rules a single load(host) would have to choose between. (4) map_designs is keyed by design name and holds many hosts with a 200 kB limit per fleet; edit_member's stale-write check depends on host_design_inputs position 1, a view, not on a per-host row. What is a genuine, safe duplicate inside the cluster: server.py:3116-3138 (api_planner_save) repeats design_versions._blueprint (validation, as_typed, check_text, host rule) and design_versions.apply (keep layout, store, rebuild graph or build planned host) line for line. Small difference: _blueprint deep-copies, the route mutates the request body and then audits counts from it; apply returns the same {'nodes','edges'} shape the route calls 'rebuilt'.

### `secmap2`. One writer for graph_nodes and graph_edges instead of graph.save (storage layer) and infragraph.rebuild (every other layer).

The two writers share a five-step outline (graph.py:273-303, infragraph.py:402-420) but almost every statement differs, so a merged replace() would be flags, not shared code; the finder's own estimate is 40 lines and I count closer to zero net. Differences beyond those the finder listed: infra's upsert does not update the host column on conflict, storage's does; storage writes health and leaves layer/confidence/first_seen to column defaults, infra writes layer/confidence/first_seen and never health; storage's stale-node filter is 'host = h AND layer = storage' computed against keep = nodes whose host is this host, infra's is against all built ids; storage's edge delete carries the built_by IS NULL legacy rule. graph.save has four callers (graph.py:375, cli.py:1578, design_versions.py:137, server.py:3137), two of them for planned hosts with no scan. The claimed gain, 'the storage layer gets a timeline for free', is false: graph_snapshots is keyed by host only (migrations/sqlite/034_map.sql) and _snapshot (infragraph.py:377-388) diffs against the newest row for that host. graph.rebuild_host calls save and then infragraph.rebuild (graph.py:375-378), so storage and infra snapshots under one host key would alternate and each would diff against the other's key set: every rebuild would record everything as removed and added, and KEEP_SNAPSHOTS=200 would be used up at twice the rate. at_time (infragraph.py:504-520) takes the single newest snapshot per host as the whole picture and would show only whichever layer wrote last. _fingerprint also hashes all props except three names; storage props are not written with change detection in mind, and the storage nodes dict includes other hosts' placeholder nodes. Storage time travel needs a schema change (an owner or layer column on graph_snapshots, both dialects) and is a feature tied to the 'Retire Graph, Structure' ledger line, not a refactor.

### `secmap3`. One Obsidian canvas writer and one export registry for the storage graph and the map.

Two canvas writers exist, but they are not the same job and merging adds code. mapexport.canvas is five lines (mapexport.py:152-157). canvas.to_canvas cannot take the map's graph: it indexes COLUMNS[n['kind']] and SIZE[n['kind']] (canvas.py:12-13, five storage kinds only) and ICON[n['health']] / HEATH_TEXT in node_text, so any NIC, Listener, Subnet etc. raises KeyError; mapexport.ORDER lists some forty kinds. Extending to_canvas to them is new layout and new text for every kind. Missed differences: (1) ids: the map canvas uses raw node ids and 'e<i>' edge ids, the storage canvas uses sha1[:16]; deleting mapexport.canvas changes every id in an existing map canvas, which is the re-import breakage the finder warns about, in the other direction. (2) output format: canvas.dumps uses indent='\t', ensure_ascii=False; mapexport uses indent=1 plus a trailing newline. (3) redaction 'for free' is not: /api/canvas adds canvas.extras (share and compose stack cards read from shares and docker, server.py:1227) which never pass through mapexport.redact, and redact replaces ids before hashing, fine, but node_text builds text from props the walker only scrubs for host names, IPv4/IPv6 and MACs. (4) access: /api/map/export goes through map_graph(), which hides firewall and exposure behind security.view and writes a map.export audit row; /api/canvas has its own rule and file name (storageforge-<host>.canvas). (5) canvas._bin is not capacity.fmt_bin: it prints one decimal for every unit including bytes ('512.0 B') and an em dash for None. Tests: tests/test_platform.py:896-918 and tests/test_feature_routes.py:158 pin the storage canvas; I found no test that pins the map canvas.

### `secmap8`. One table of filesystem facts: which filesystem types are network or pseudo, which mount points belong to the OS, and which mount options the kernel adds.

The lists exist where cited, but most are different facts that share words, and the stated bug is not one. (1) The 'drift already present' claim is wrong in effect: fromdesign._opts is applied to both the designed and the scanned side (fromdesign.py:201) so blueprint.py:100's prefix match cannot produce a false 'option changed'; and no real mount option other than rw and relatime starts with those strings. The promised user-visible gain does not exist. (2) I diffed the sets. Pseudo: fsmap.VIRTUAL equals remote.PSEUDO_FS | TMP_FS except 'fuse.lxcfs'; agentscan.PSEUDO lacks six of them. Network: placement.NETFS and steps_dockerd.NETWORK_FS are strict subsets of remote.NETWORK_FS, each missing a different seven or eight (placement keeps 'fuse.rclone', dockerd drops it; dockerd keeps 'sshfs','afs','lustre'); fsmap.NETWORK is a type->protocol map with 'virtiofs', which remote does not have; alerts.NO_USAGE_FS mixes tmpfs, iso9660 and five network types and is about 'usage is meaningless', not 'network'. (3) The OS mount lists answer different questions: hostconfig SYSTEM_TARGETS/RUNTIME_ROOTS/OS_TARGETS (what a rebuild skips), blueprint.SKIP_PROTECT (boot partitions left out of 3-2-1), changes.OS_MOUNTS (refuse destructive steps), clamav.SYSTEM_PATHS (mirrored in bash at clamav.py:219 and again at secscripts.py:259), steps_dockerd.SYSTEM_DIRS (has /opt), steps_workloads.SYSTEM_DIRS (has /srv), secplus.py:1131 (SQL literal). steps_archive.py:39 and steps_storage.py:25 already derive from fsmap.SYSTEM_DIRS, which is the pattern the finder proposes. (4) Kernel options: hostconfig's list decides what goes into a rebuilt fstab line, clone.GEOMETRY what is wrong on another disk, fromdesign's what counts as a difference; a union would change each. A sixteen-module change through scan walking, destructive-step refusals and quarantine guards to save about 60 lines of constants, with no bug fixed, is not worth the risk. Two small true duplicates remain: _bare at clone.py:146-147 and fromdesign.py:41-42, and fsmap.VIRTUAL vs remote.PSEUDO_FS.

### `secmap13`. One byte-size formatter and one timestamp formatter for reports, exports and comparisons.

Only one of the four size helpers is a duplicate. design_versions._size (design_versions.py:175-180) has exactly capacity._fmt's rule (no decimals below MiB, two above) and can be capacity.fmt_bin. The others cannot be reproduced by passing digits, as the finder suggests: canvas._bin (canvas.py:24-32) prints one decimal for every unit, bytes and KiB included ('512.0 B', '1.5 KiB'), where capacity prints '512 B' and '2 KiB' whatever digits is, and returns an em dash for None; moves._fmt (moves.py:606-611) prints no decimals for B only, one for KiB, and treats None as 0. Using fmt_bin(n, 1) changes canvas card text and move-plan text. The four timestamp helpers are one line each and differ in three ways at once: UTC (cli.py:51-52) vs local time; the empty value ('never', '-', an em dash, none at all in loganomaly, which would format epoch 0); and falsy vs 'is not None' as the empty test. A shared when(ts, none, utc) saves no lines. Nothing here is a bug class.

