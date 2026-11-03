# Progress

Where the build of the [Infrastructure Platform Roadmap](infrastructure-platform-roadmap.md) and the [Ransomware Defense Roadmap](ransomware-defense-roadmap.md) stands. **Done** means the roadmap's definition of done (§2), including the KVM lab. Code that passes unit tests but has not been in the lab is **Built, not lab-tested**.

Last updated: 2026-11-03.

## Now

Built and through the KVM lab, apart from what each row says.

## Infrastructure map

| Phase | State |
| :--- | :--- |
| M1 Network, M2 Services and Firewall, M3 Containers and VMs | Done: tier 10. Incus, LXC and Proxmox guests are parsed and unit-tested, not lab-tested |
| M4 Map UI foundations | Done, except the [listed](docs/infrastructure-map.md#not-built) layouts and colour rules |
| M5 Placeholders, manual nodes, change tracking | Done: tiers 10, 11 |
| M6 Path query, what-if, plan actions | Done for firewall, network, WireGuard and container steps: tier 11. Stacks, LXC and catalog tools need the Workload and Toolbox roadmaps |
| M7 Access and Security layers | WireGuard done: tier 11. Tailscale, proxies and identity providers are parsed and unit-tested, not lab-tested |
| M8 Design mode | Done: tier 11. Terraform and Puppet exports render and hold values as data, and have not been applied by those tools |
| M9 Scale and integrations | Later, as the roadmap says. A synthetic 200 hosts and 2,000 workloads draws within limits in the browser test |

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

## Log

- 2026-11-02: baseline 807 tests passing, 4 skipped. Clock and boolean fixes landed by the owner as `db53dcb`.
- 2026-11-02: Stage 0 to 2 code from the earlier session picked up: 847 tests.
- 2026-11-03: final code: 940 unit tests pass on SQLite (4 skipped) and on PostgreSQL (42 skipped). KVM lab tiers 0 to 11: 441 passed, 0 failed, 3 skipped, on 7 of the 14 configs.

What the lab found that unit tests had not:

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
