# Progress

Where the build stands. [roadmap.md](roadmap.md) says what's left, and the plans these rows come from are in [the archive](archive/roadmaps/). **Done** means the roadmap's definition of done (§2), including the KVM lab. Code that passes unit tests but has not been in the lab is **Built, not lab-tested**.

Last updated: 2026-11-05.

## Now

Built and through the KVM lab, apart from what each row says.

## Infrastructure map

| Phase | State |
| :--- | :--- |
| M1 Network, M2 Services and Firewall, M3 Containers and VMs | Done: tier 10. Incus, LXC and Proxmox guests are parsed and unit-tested, not lab-tested |
| M4 Map UI foundations | Done, except the [listed](docs/infrastructure-map.md#not-built) layouts and colour rules |
| M5 Placeholders, manual nodes, change tracking | Done: tiers 10, 11 |
| M6 Path query, what-if, plan actions | Done for firewall, network, WireGuard and container steps: tier 11. Stacks, LXC and catalog tools aren't built: see the [roadmap](roadmap.md) |
| M7 Access and Security layers | WireGuard done: tier 11. Tailscale, proxies and identity providers are parsed and unit-tested, not lab-tested |
| M8 Design mode | Done: tier 11. Terraform and Puppet exports render and hold values as data, and have not been applied by those tools |
| M9 Scale and integrations | Later, as the roadmap says. A synthetic 200 hosts and 2,000 workloads draws within limits in the browser test |

## Expanded networking

| Phase | State |
| :--- | :--- |
| 1 Transports, 2 RouterOS, 3 OpenWrt, 6 Language, 7 Multi-hop, 8 Lab and tier 12, 9 Scanner and traffic, Management planner | Done: tier 12, on real RouterOS 7.25 and OpenWrt 25.12. Old SSH ciphers have not met a device that needs them. Language output for firewalld and ufw is unit-tested only |
| 4 pfSense and OPNsense, 5 Cisco | Built, not lab-tested: no free image. Written against published formats and a simulated shell |

## Ransomware defense

Corrections stand: no VSS trap, no cryptographic shred, no certificates, no WebSocket stream. See [the page](docs/ransomware-defense.md).

| Work | State |
| :--- | :--- |
| Holds, quorum, clock guard, decoys, brake, attribution, airgap, quarantine, blast radius, clean room, SELinux, AppArmor, baseline | Done: tier 9, on real ZFS, btrfs and SELinux |
| Firewall writer, share fences, Lynis and booleans as steps, NTS | Done: tier 11, across ufw, nftables and firewalld |
| Retention policies, freeze, rollback preview, YARA, packages, bundles, Falco, identity, evidence, re-converge, waivers | Done: tier 11 |
| Playbooks | Dry run on a real trip: tier 11. Acting by itself: unit-tested with the real brake script |
| Dashboards, custom profiles, ban tiers, alert routes, PagerDuty | Unit and browser tests. PagerDuty has not reached the real service |
| FIDO2 step-up | Chromium's virtual authenticator. No physical token |

## Host logs

| Work | State |
| :--- | :--- |
| Scans collect host journals; the Logs tab, `hostlogs` on the CLI, `/api/hostlogs` and the `hostlogs.view` permission | Built, committed on 2026-11-04. Its unit tests have run since and pass (see the log, 2026-11-06). Lab tier 14 is written and has not run, so it is not lab-tested |
| `/api/hostlogs/counts` and `/api/hostlogs/units` | Built and unit-tested on 2026-11-06. The Logs view that uses them is UI phase 4, not started |

## Log

- 2026-11-02: baseline 807 tests passing, 4 skipped. Clock and boolean fixes landed by the owner as `db53dcb`.
- 2026-11-02: Stage 0 to 2 code from the earlier session picked up: 847 tests.
- 2026-11-03: final code: 940 unit tests pass on SQLite (4 skipped) and on PostgreSQL (42 skipped). KVM lab tiers 0 to 11: 441 passed, 0 failed, 3 skipped, on 7 of the 14 configs.
- 2026-11-03: [test audit](docs/test-audit-2026-11-03.md): every feature mapped to a test and a lab check, or a stated reason. 1043 tests on SQLite (4 skipped) and PostgreSQL (78 skipped). KVM lab tiers 0 to 11 and 13: 482 passed, 0 failed, 3 skipped, on 7 of the 14 configs.
- 2026-11-04: expanded networking, the management planner and the audit of 2026-11-03: 1243 tests on SQLite (7 skipped) and PostgreSQL (80 skipped). KVM lab tiers 0 to 13: 511 passed, 0 failed, 5 skipped, on 7 of the 14 configs plus a real RouterOS, a real OpenWrt and three machines behind them.
- 2026-11-04: the open branches were brought together. Every branch, local and remote, is in `dev-expanded-networking`, which is ahead of `main` and not behind it. The host logs work, which had not been committed, was committed on it. No tests have run since.
- 2026-11-04: [UI audit](docs/audit-2026-11-04-ui.md): 41 findings, from a read of the web UI and a pass through it in a real browser. None is fixed yet.
- 2026-11-04: baseline of the merged branch before the release work, at `36d8eb5`: 1286 tests passing on SQLite, 5 skipped, in 593 s. PostgreSQL was not run.
- 2026-11-05: phase 0 of the UI roadmap is done: 14 of the 41 findings, three of them in part, each with a browser or unit test that fails on the old code. The full suite on SQLite after it: 1321 tests passing, 5 skipped, in 598 s (the baseline above was 1286). PostgreSQL has not been run since.
- 2026-11-05: phase 1 of the UI roadmap is done but for native modules (held back, see the roadmap's B6) and the list component: one `api()` for the four pages, 39 native dialogs replaced, one palette, one shortcut registry, the security chip on every page, one time and size formatter, busy buttons, and drafts that survive a reload. The browser file is 69 tests and passes; `test_ui_kernel.py` (12), `test_ui_contrast.py` (6) and `test_docs_web_ui.py` (4) read the scripts and stylesheets as text. The full suite has not been re-run whole since the figure above, except once at 1473 tests with 6 failures that were then fixed (see below).
- 2026-11-05: phase 2 of the UI roadmap is built in a lighter form (see the roadmap's row for what is not): a router with Back and copied URLs, the rail as a tab list, Security and the settings panels with the whole page, the map by keyboard, a host picker where a panel needs one. The browser file is 91 tests and passes; `test_ui_kernel.py` (12), `test_ui_contrast.py` (6) and `test_docs_web_ui.py` (4) pass.
- 2026-11-05: scan payloads are signed on the host and checked before use (`5916ce1`), at the owner's request: 17 tests in `test_scansign.py` pass on SQLite and PostgreSQL, the lab stage `scan-signed` is written and has not run. The full SQLite suite at that point was 1473 tests with 6 failures, all of them consistency checks and one race in a browser test that the commit fixed; it has not been run again whole.
- 2026-11-05: SF-48 is built: each side of a send is a signed run with a key of its own and no root key between the hosts, merged in `4d8b083` from a child branch. `test_sends.py` (93 tests, 1 skipped), `test_audit_2026_11_03.py` (48), `test_feature_map.py` (9), `test_storage_ops.py` (24) and `test_route_rules.py` (5) pass on SQLite. KVM lab tier 16 is written and has not run, and tiers 3 and 5 and `demo.py` were changed to send with no root key and have not run either. SF-46's walk test is in.

What the lab found that unit tests had not:

- `print as-value` prints nothing over RouterOS's SSH, which the roadmap had as the way to read it.
- RouterOS serializes a port as `80.000000`.
- RouterOS redraws its prompt with bare carriage returns, which read as no prompt at all, so its terminal and Telnet both timed out. The simulated shell never did this.
- `iptables-restore` doesn't take shell quoting, so any rule with a comment was refused.
- fw4 lets a port forward through with `ct status dnat`, which read as a rule nobody understood, and made a real forward unknown.
- nmap needed two libraries the image removes on purpose, which only a real scan in the real image showed.
- A held snapshot inside a share failed the next SMB deploy on an SELinux host.
- The airgap and quarantine refused to run on a host with no nftables.
- A clock jump in a sentinel's first 30 seconds became its baseline, and was never reported.
- A host with no `ss` reported no listeners, rather than that they could not be read.
- With Docker and ufw, the firewall reading ran past its size limit, and so read as unreadable. It now reads table by table, and leaves out what `iptables-save` covers.
- Podman 5 failed the whole inspect when a container had no healthcheck, so containers came back with no detail.
- `chcon` stopped on a dangling symlink inside a share.
- A bridge over a NetworkManager interface did nothing until the next reboot, when it would all have happened at once.
- A what-if missed an SSH cut on a host with no firewall, and any change to the interface StorageForge comes in on.
- PNG export was blocked by the page's own CSP, found by the browser test.
- PostgreSQL could not build a scan design holding ZFS properties, found by running the suite there.
- 2026-11-05: partial security audit ([Audit 2026-11-05](notebook/Audit%202026-11-05/Audit%202026-11-05.md)): SF-52 to SF-55, all fixed in `b7c34bd` and `26bd037` with tests. SF-52 was worse than first measured: one 4,000-character line took up to 154 s. The audit was done before UI phases 3 to 5 because the working windows kept running out; it did not reach most of `security.py`, `secplus.py`, `secscripts.py`, `traffic.py`, `routes_network.py` and the second half of `receiving.py`, and gives no verdict.
- 2026-11-06: three small agents built the host log counts and units routes with lab tier 14, lab tier 17 with the export validators and CI file check, and the "Show N more" list component; merged in `f6e1d15`. Full unit suite on SQLite: 1532 tests, 9 skipped, in 697 s, OK. On PostgreSQL: 1532 tests, 88 skipped, in 2252 s, two failures, both browser tests that wait on a timer (`test_choosing_a_host_is_a_step_in_the_history`, `test_the_planner_asks_for_the_password_in_place_and_goes_on`): they pass alone twice and in the SQLite run, the PostgreSQL run was three times slower, and their waits were made longer. Browser file after that: 96 tests OK in 98 s. `ruff` clean, `node tests/vectors/check.mjs` exit 0, the wiki builds (38 pages). `shellcheck` is not installed on this machine, so it has not run. The KVM lab has not run: tiers 14, 16 and 17 and the `scan-signed` stage are written, not run.
- 2026-11-06: second round of the audit by three readers (network and emitters, security modules and signed scans, UI kernel and generated scripts under shellcheck 0.11: 2,048 warning-level hits across 166 scripts, none a real bug): 16 findings, seven Medium, no High or Critical. Fixed with a failing-first test each: SF-60 to SF-65, SF-70, SF-71, SF-73 to SF-75, SF-80. SF-72 is open: the ZFS receive is hardened in `3de010a`, and a hostile-stream lab run (tier 16) must confirm it and decide the btrfs side. Not reached: parts of `secscripts.py`, `secplus.py`, `routes_secplus.py`, `deploy.py`, the view scripts beyond a grep, most of `server.py`. Built the same day: saved design versions, the Logs view, what-if sentences, the palette, preferences, first-run checklist, tablet header. Unit tests only, not lab-tested.
- 2026-11-06: the final full runs of the build before the lab (all merges in, `40a2622`): SQLite 1,628 tests in 828 s with 5 failures; PostgreSQL 1,628 tests (88 skipped) in 1,942 s with 3. Causes: two stale expectations (the viewer write-probe did not list the read-only compare route; the ZFS receive test expected the old flags), two browser tests that raced (the wide-panel test clicked a rail button before the page had restored the panel; the host-history test did not wait for its control), and one real bug found by a flaky test: the new Logs view wrote the last applied search text back into a field being typed in (`7719e2c`). Only the three test files and `hostlogsview.js` changed after the run, and the touched files were re-run: browser smoke 96 OK three times in a row (about 100 s), the new browser files, kernel, contrast, docs, source hygiene, feature map, route and role tests all OK, ruff clean. **The two full suites were not re-run after those fixes.** Two browser tests (`test_the_planner_asks_for_the_password_in_place_and_goes_on` and `test_choosing_a_host_is_a_step_in_the_history`) still failed once in the 14-minute SQLite run on this machine, and pass alone and in the PostgreSQL run: they are timing-sensitive under load.
- 2026-11-06 (step 4, the release run): **unit suites** at `98cc667`: SQLite 1,628 tests in 775 s and PostgreSQL 1,628 (88 skipped) in 2,012 s, one error each, the same Logs browser test (`test_a_custom_range_has_two_ends…`, an 8 s wait after a navigation and reload). Fixed in `31fda48` (30 s waits, and the Back test now waits for the month's list to go); `test_browser_*.py` then ran 137 tests four times: OK, OK, one Back race, OK, and the Back race was the fixed one. **The full suites were not re-run after that fix.** Ruff clean, `node tests/vectors/check.mjs` 0, `shellcheck --severity=error` over `docker/*.sh` and `examples/demo/*.sh` clean (0.11, in the /tmp venv), wiki 38 pages.
- 2026-11-06 (step 4, the KVM lab): the existing lab of seven configs (sf-ctl, sf-ubuntu, sf-fedora, sf-rocky, sf-suse, sf-alpine, sf-bookworm) plus the router set (sf-mikrotik, sf-openwrt, sf-wan-host, sf-lan-client, sf-dmz-server). `lab.sh test --all` was cut off at tier 9 by a restart of the harness, so tiers were finished by hand in groups, and the final report is `reports/lab-2026-11-06-2241.md` (not committed: `reports/` is ignored): **561 passed, 3 failed, 0 known failures, 11 skipped**. Three things went wrong on the way, and all three were in the lab or its tests, not in the product: the golden controller on sf-ctl was the build from before this release (tiers 14 and 16 first ran against it and 404ed; `lab.sh controller` and `lab.sh snapshot` fixed that, and tiers 3, 5, 14, 16 and 17 were re-run after), the new `scan-signed` stage read the key without `sudo` (`22b7890`), the tier dispatch ran `tiers_platform.tier14` after tier 14 because of my merge (`77a2e3c`), and tier 14 counted `sudo`'s own log line and filled the container's temp space (`58ba253`).
  - **Passed in the lab:** the signed scan stage on all seven hosts (gauntlet 213 passed, 0 failed); tier 3 and 5 btrfs sends; tier 14 host logs on all six systemd hosts and the host with no journald (read, secrets removed, caps, limited); tier 17 firewalld on sf-fedora and ufw on sf-ubuntu; tiers 0 to 13 otherwise unchanged, with the failures below.
  - **Failed, 3:** (1) `send-from-the-timer-unit` and (2) `send-failure-reaches-the-sender` on sf-fedora (tier 16): a signed send started from its systemd unit fails at `ssh` with "Permission denied" (`/usr/sbin/ssh`, line 345 of the task script) while the same send started through the API passes. sf-fedora is SELinux enforcing. **Cause not found**: `ausearch` showed no denial afterwards and the task folder had been cleaned up by the test. It is in the SF-48 receiving path, so it is for the owner, not a small fix. (3) `workload-libvirt` on sf-ubuntu (tier 10): `qemu-img: not found` on the VM; the image lacks the package, a gap in the lab and not in the product.
  - **Skipped, 11:** the ZFS send checks (tier 16 and tier 3: one ZFS host in this build, so a send between hosts cannot run; SF-72's ZFS flags are therefore **not lab-tested**), appliances (needs `up --pick`), `transport-cisco-pfsense` and `ui-pages` (none in this build).
  - Tier 16 is otherwise **passing**: the key runs only verbs, a replayed nonce, a corrupt stream and a cut-off stream are refused, the scan user gets nothing, the receiver has a record of its own.
- 2026-11-06: **Step 5 was not done**: the lab is not green and the owner has not accepted the SF-48 timer-unit failure. No version bump, no merge to `main`, no tag.
