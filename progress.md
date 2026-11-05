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
| Scans collect host journals; the Logs tab, `hostlogs` on the CLI, `/api/hostlogs` and the `hostlogs.view` permission | Built, and committed on 2026-11-04 as it stood. Its unit tests exist, and neither they nor the lab have run since |

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
- 2026-11-05: phase 1 of the UI roadmap is done but for native modules (held back, see the roadmap's B6) and the list component: one `api()` for the four pages, 39 native dialogs replaced, one palette, one shortcut registry, the security chip on every page, one time and size formatter, busy buttons, and drafts that survive a reload. The browser file is 69 tests and passes; `test_ui_kernel.py` (12), `test_ui_contrast.py` (6) and `test_docs_web_ui.py` (4) read the scripts and stylesheets as text. The full suite has not been re-run since phase 0.
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
