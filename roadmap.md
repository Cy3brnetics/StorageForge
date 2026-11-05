# Roadmap

The final roadmap before release 0.4.0: what's left, in one place. It brings together what used to be separate lists: this page, the UI and UX roadmap, the notebook's roadmap, the findings still marked in progress, and the screen findings of the UI audit. [progress.md](progress.md) says what has been built and lab-tested. The finished and superseded roadmaps, which now include the [UI and UX roadmap](archive/roadmaps/ui-ux-roadmap.md), are in [archive/roadmaps](archive/roadmaps/), and they hold the detail behind each item here: formats, field lists and reasoning. **This page decides what's next, and they don't.**

Checked against the code on 2026-11-04.

## How to read this

**Done** means through the KVM lab, as [progress.md](progress.md) defines it. Days are rough guesses carried over from the old roadmaps, and none has been measured. A finding is `SF`, `PF`, `EQ` or `UX` and a number, as in the notebook's [audit rules](notebook/Audit%20rules/Audit%20rules.md). Everything under **0.4.0** is in the release. Everything under **After 0.4.0** is not, and each section there can stop at any item without harming the others. The **Status** columns are the ledger: whoever finishes an item writes the commit that finished it.

## The release: 0.4.0

The steps, in order. Each one ends with the branch in a state that could be merged.

| Step | State |
| :--- | :--- |
| **1. Bring the open branches together** | Done 2026-11-04. Every branch, local and remote, is in `dev-expanded-networking`. That is the same line as `origin/dev`, plus the commits made that day (host logs, the UI audit, this roadmap). It is ahead of `main` and not behind it, so it merges as a fast-forward. The old local `dev` is behind the line and sits in a worktree holding an earlier draft of the audit fixes that the line has since replaced. It was left alone |
| **2. Finish the release scope** | Open: section A |
| **3. One full security audit, then a bugfix round** | Open. After step 2, because the audit has to read the new code |
| **4. Tests, then the KVM lab** | Open: the unit suites on SQLite and PostgreSQL, the browser test, lab tiers 0 to 13 and the new ones section A adds |
| **5. Merge to `main` as 0.4.0** | Open: the version, the changelog heading, the merge and a local tag. Pushing to either remote is a separate step and needs the owner's say |

**The rules for the release**

1. Nothing is called *done* or *lab-tested* without a lab pass. What can't be tested (no image, no hardware, an outside service) ships labelled *not lab-tested*, in the docs, in the UI where it shows, and in the release notes.
2. The audit follows the [audit rules](notebook/Audit%20rules/Audit%20rules.md): the severity ladder, effort, *proven* or *read*, and numbers carried on from `SF-52`, `PF-34`, `EQ-10` and `UX-42`.
3. Before the lab run, every High and Medium finding is fixed or carries a written decision. A Low is fixed when it takes under a day.
4. The version, the changelog heading, the merge and the tag come last.
5. An owner item that is still open at release goes in the release notes.

**Decisions taken for 0.4.0.** These are the defaults the release run takes. Change one before phase 2 of the UI starts, or not at all.

- One app shell with routed workspaces, reached in steps: shared chrome first, then the router and the Plan workspace. `/planner` and `/manage` stay as entry routes.
- Native ES modules under the current CSP, one file at a time, no bundler.
- Names: **Plan** for the workspace, **Design** for the storage tool, **Network and devices** for the other. "Manage" goes.
- WCAG 2.2 AA is the target, stated in [concepts](docs/concepts.md) and held by checks in `test_browser_smoke.py`.
- **Not in 0.4.0:** one design document in place of the storage blueprint and the map's design (UI step 3i), because it changes a stored format and needs a migration and a lab run. Retiring Graph, Structure, which waits until the map's Storage layer has time travel and a focus view.
- **EQ-03 stays parked,** for the reason recorded on 2026-11-01: splitting `server.py` right before a lab run is churn and merge risk with nothing gained. It is picked up only if the audit finds it blocks a fix.

**What only the owner can do**

| Item | Needed for |
| :--- | :--- |
| Set up a Forgejo runner | EQ-01 and SF-38: the CI file has never run on one |
| Run the disk-health collector on this machine's real disks (it needs sudo here) | PF-04 |
| An image or a device for pfSense, OPNsense or Cisco | Lab-testing them. Without one they ship labelled |
| Say when to push `main`, the tag, `dev` and the GitHub mirror, which is twelve commits behind `origin/main` | Step 5 stops short of pushing |

## A. Before 0.4.0

### A1. Close out what's built

Each is a claim that hasn't been proved or a known gap in something shipped.

| Item | Why it matters | For 0.4.0 | Status |
| :--- | :--- | :--- | :--- |
| **SF-48: the receiving host of a send** | Signed scripts still run root commands on the receiving host with no signature there. It's named in the audit row, warned about in the check and listed in [security.md](docs/security.md) | Build it. Each side of a send becomes its own signed run on an enrolled host, with the stream between them carried by a forced-command job key, as `storageforge-job --serve` does for rsync. Add a lab tier: a send between two enrolled hosts with no root key between them. About a week | open |
| **pfSense, OPNsense and Cisco on real devices** | Reading and rollback have only met published formats and a simulated shell | No image or device, so it ships labelled *not lab-tested*, unless one turns up | open |
| **Old SSH ciphers on a device that needs them** | Built and unit-tested, with nothing old enough in the lab | Same | open |
| **firewalld and ufw output from the network language** | Unit-tested. nft and iptables-restore took theirs for real, and these two should as well | Lab: apply the compiled output on a firewalld host and a ufw host, and read it back | open |
| **Incus, LXC and Proxmox guests; Tailscale, proxies, identity providers** | Parsed and unit-tested, not lab-tested | Lab, where the lab has the platform (it has a Proxmox image). The rest ships labelled | open |
| **Terraform and Puppet exports** | They render, and no tool has applied them | Run them through the tools' own validators where they can be installed (`terraform validate`, `puppet parser validate`). Applying them is out of reach, so they ship labelled | open |
| **PagerDuty and FIDO2** | PagerDuty has not reached the real service. FIDO2 has only met Chromium's virtual authenticator | An outside service and a physical token, so both ship labelled | open |

### A2. Host logs

Built and committed on 2026-11-04 as it stood in the working tree. Neither its unit tests nor the lab have run since.

| Item | For 0.4.0 | Status |
| :--- | :--- | :--- |
| **Its tests** | Run them, and fix what fails. The consistency tests that list routes, permissions and CLI subcommands were already updated for it | open |
| **A lab tier** | Real distros: the `systemd-journal` group, a host with no journald saying so, secret removal on real lines, the 30-day and row caps, and the scan-access script run again | open |
| **The Logs view** | UI phase 4 (UX-30): a time range, per-host freshness, entry points from a host, an alert, a mount and a device. Still no tail and no stream | open |

### A3. Findings still in progress

The notebook has 18 findings marked in progress. Twelve say *fixed in the working tree on 2026-11-03, not committed*: that work was committed in `a267227`. Each was marked done in the notebook on 2026-11-04 (`418856d`), with its test seen to pass and the commit written in its note. They are `SF-44`, `SF-45`, `SF-47`, `SF-49`, `SF-50`, `SF-51`, `PF-31`, `PF-32`, `PF-33`, `EQ-07`, `EQ-08` and `EQ-09`. The other six:

| Finding | What's left | Who | Status |
| :--- | :--- | :--- | :--- |
| **SF-48** | See A1 | the release run | in progress, on branch `t3/2ea1b266` |
| **SF-46** operators can apply legal holds | A test that every route ending in `apply_hold` takes the same permission, walked as a list and not one route at a time | the release run | in progress, on branch `t3/2ea1b266` (`ca2eacb`), not merged |
| **SF-38** container scan | CI fails on a new reachable critical. The job exists, and has never run | the owner | open |
| **EQ-01** no CI | A runner, so every push runs the suite on SQLite and PostgreSQL | the owner | open |
| **PF-04** disk health | The collector run against real disks: a disk with reallocated sectors shows warn and raises an alert, and each pool shows its last scrub. It ships labelled *not run against real disks* until then | the owner | open |
| **EQ-03** large modules | Parked, as above | | parked |

### A4. UI and UX

All six phases of the [UI and UX roadmap](archive/roadmaps/ui-ux-roadmap.md), about 110 to 145 days from the [UI audit of 2026-11-04](docs/audit-2026-11-04-ui.md) (41 findings), in order, except the two items under *Decisions taken*. The detail of each item is in that document. This is the ledger.

| Phase | Days | What it holds | Status |
| :--- | :--- | :--- | :--- |
| **0. Small and sure** | 6 to 8 | The `/` shortcut that eats typing, and the other keyboard handlers (UX-40, 41), the rail that hides Security and Logs (UX-01), the header (UX-02), planner focus (UX-18), "offsite" from data (UX-32), "+N more" (UX-13), copy that fits the screen (UX-14, 09), Scan by what was scanned (UX-29), contrast tokens (UX-19), a latest-wins guard (UX-12), the Scanner stub (UX-28), the Web UI page (UX-39) | done on 2026-11-05: `7f749d1`, `eb6b9f6`, `0e3e7d6`, `84a7775`, `5d194bc`, `607fd65`, `ac79c0f`. Three parts moved on: collapsible rail groups (UX-01) to phase 2, the security chip on `/planner` and `/manage` (UX-09) to phase 1, and the other lists that cut their rows without saying (UX-13) to phase 1's list component |
| **1. One kernel** | 15 to 19 | One `api()`, one dialog in place of 39 native calls, announce and busy, one vocabulary of tokens and components, one time policy, shared chrome with the security banner on every page, one place for shortcuts, native modules, safer work in progress | open |
| **2. Routes and workspaces** | 22 to 28 | A router, a rail that matches what is in it, Security and Settings as workspaces, the planners under one Plan roof, the map by keyboard, a host picker where it is needed | open |
| **3. The planner grows** | 35 to 45 | Steps 3a to 3h: design what isn't there yet, Shares, the network lens, the workloads lens with placement guardrails, the security lens, the health lens, compare and adopt, one Change review | open |
| **4. Map, Compose, Scan, Logs** | 26 to 32 | A map with room, what-if in plain words, Design mode from what was read, Compose as an editor, Scan as a table and a diff, Logs as a view | open |
| **5. Polish and scale** | 8 to 12 | Preferences, `Ctrl+K`, a first-run checklist, colour never alone, long lists, a tablet header | open |

Some of it waits, and is not in 0.4.0:

- 3a: ZFS and mdadm pools as plan steps wait for `pooldef` (B1). Until then a planned pool of those kinds stays under *By hand*.
- 3d: only the placement guardrails that can be worked out from what `/api/workloads` already reads ship. Dataset-tuning advice waits for the workloads stage (B2).
- 4: a rule at a position in Compose waits for `place-before`, and scan results as map placeholders and scanner findings through alerts wait too (B5).
- Four items need a small API: saved versions of a design (3g), "start from what was read" for Design mode, paths that must stay open or blocked in Compose, and counts by level and hour for Logs.

### A5. The security audit and the bugfix round (step 3)

One full audit of the whole application, with the new surface first, written up as the notebook's other audits are. Read first: everything added since the audit of 2026-11-03, which is the network devices and their SSH and Telnet transports, device credentials, the one network language and its compilers, the scanner, traffic, the management planner, host logs, the signed receiving run, and the UI kernel, router and workspaces (the router parses the URL, and the shortcut registry takes keystrokes). Then the rest of the application against the [security checklist](notebook/Audit%20rules/Security%20checklist.md) and the [project invariants](notebook/Audit%20rules/Project%20invariants.md), a sample of the findings marked done, a fresh container scan, a dependency review, and the generated scripts under `shellcheck`. Then the bugfix round: every High and Medium, each with a regression test, then the Lows that take under a day.

### A6. Tests and the lab (step 4)

- The unit suites on SQLite and PostgreSQL. The last full figures are in [progress.md](progress.md).
- The browser test, extended with the checks the UI audit asks for: every rail item reachable at 1366×768, focus kept after Tab in the planner, tab stops to the content, a slash typed into a field and into **Confirm your password**, every map node reachable by keyboard, and no console error on any page.
- `ruff`, `shellcheck` over the generated scripts, and the wiki build (`python3 docs/build-wiki.py --out DIR`).
- The KVM lab, tiers 0 to 13 on the 7 of 14 configs as before, with the new tiers A1 and A2 add. Results go in [progress.md](progress.md).

### A7. The release (step 5)

`pyproject.toml` and `__version__` go from 0.3.2 to 0.4.0. The changelog's *Unreleased* heading becomes `0.4.0` with the date, with a new *Unreleased* above it, and its upgrade notes say what a host needs (the scan-access script run again) and what a role needs (`hostlogs.view` and `security.sentinel` are not granted to custom roles). Then [progress.md](progress.md), a fast-forward of `dev-expanded-networking` into `main`, and a local tag `v0.4.0`. Pushing is the owner's call.

## After 0.4.0

Everything below is open and not in the release.

### B1. Change engine: what's left (Stage 3)

The firewall writer, share fences and security findings as steps are done.

| Item | Detail |
| :--- | :--- |
| **Secret store** | Generic secrets in the vault, generated, shown once, delivered through the runner's stdin, with a rotation path. Device passwords are sealed this way already. [Detail](archive/roadmaps/infrastructure-platform-roadmap.md#stage-3-change-engine-18-to-22-days) |
| **`runtime-install`** | The four runtimes across distros, rootless setup, and a preflight that says present, installable or blocked. [Detail](archive/roadmaps/infrastructure-platform-roadmap.md#71-runtime-install) |
| **`pooldef` and `netdef`** | Storage pools and networks as plan steps, with bridge changes under the rollback timer |
| **Catalog engine** | Schema, signature, override layer, install methods, risk labels, and uninstall that keeps data. [Detail](archive/roadmaps/infrastructure-platform-roadmap.md#8-the-catalog) |

**Exit:** install a runtime on a bare VM from a plan. The report changes nothing, a changed plan gets 409, and a bridge change that cuts SSH rolls itself back.

### B2. Workloads (Stage 4, about 13 to 15 days)

Running a container, defining a VM from an existing disk, and start, stop and remove are done.

- **`stack` and `lxc` steps,** each carrying its firewall rule and labels.
- **Image updates,** with rollback on a failed healthcheck.
- **VMs from templates:** cloud images and ISOs, checksums, cloud-init with the deploy key, so a new VM can be scanned from its first boot.
- **Lifecycle:** snapshot, clone, resize and console over an SSH tunnel.
- **Placement advice, which is the differentiator:** a pool on a dataset tuned for its use, databases off the bulk pool, warnings for bind mounts on network filesystems, and a warning when data sits where no hold or offsite copy reaches.
- **MAC at deploy:** `:Z` labels, the `svirt_image_t` fix as a plan step, AppArmor pool paths.
- **Read side:** Podman Quadlets, and adopting a workload by capturing it as compose, Quadlet, libvirt XML or Incus YAML, with drift against the capture.

[Workload roadmap](archive/roadmaps/workload-platform-roadmap.md) for field lists, and the [merged plan](archive/roadmaps/infrastructure-platform-roadmap.md#7-workloads-in-detail) where they differ.

### B3. Toolbox (Stage 5, about 32 to 40 days)

The largest piece, and nothing of it exists. Needs the catalog engine and secret store from B1. It can be cut at any entry.

- **Adapters and GUI levels:** `detect`, `status`, `actions`, `links`, `metrics` over a measurement.
- **Wave 1 entries,** panels first, since they prove the catalog cheaply: Cockpit, Dockge, then Portainer, Komodo, Dockhand, Dokploy, Incus UI. Then WireGuard and Caddy with full panels, CrowdSec, Trivy, restic with restore tests.
- **Bundles** with one report, shared secrets, one firewall change set, and rollback of the whole bundle.
- **Feeds:** Trivy findings and CrowdSec decisions into the existing alerts and quarantine view, with bans reconciled so quarantine doesn't fight the bouncer.

A tool without a passing lab run is labelled *not lab-tested* in the catalog. [Toolbox roadmap](archive/roadmaps/toolbox-catalog-roadmap.md) and [the merged plan](archive/roadmaps/infrastructure-platform-roadmap.md#8-the-catalog).

### B4. Depth (Stage 7: what's left)

Compliance depth, retention depth, YARA, incident evidence and clean room are done.

- Quiesced snapshots: `qemu-guest-agent`, stop-snapshot-start for stateful stacks, with the method recorded.
- Incidents that include workloads touching affected paths, and a clean room that boots a VM or container from a pre-incident snapshot.
- Externally-managed detection, and a warning before changing such a workload.
- Compliance readings for CIS Docker, Podman and libvirt-style checks, and auditd rules for runtime sockets and config.
- Terraform, OpenTofu and Puppet export for workloads, with round-trip tests. Designs have this already.

### B5. Network and map: what's left

- **The language:** a rule at a position (`place-before`). RouterOS appends, so a rule below a final drop does nothing, and the what-if says so.
- **Scan results as map placeholders.** The Scan tab links to the map, but they're separate drawings.
- **Scanner findings through alerts:** what's new since the last scan.
- **Traffic on Linux hosts.** Monitoring covers devices only.
- **Deeper reads:** Cisco zone-based firewall and VRFs, OSPF and BGP state, wireless clients.
- **From the map:** moving, cloning or resizing a VM, restricting a service's bind address, putting a listener behind a proxy, rotating a peer's key.
- **`bridge`-family firewall rules** for bridged VMs, which bypass a quarantine's hooks. The map says so.
- **REST adapters: only if a device needs one.** SSH reads everything on all four platforms, and a second way in is a second thing to secure.

### B6. The two UI items held back

One design document in place of the storage blueprint and the map's design, with the planner as its editor and the map showing it as ghosts (step 3i, which needs a migration), and retiring Graph, Structure once the map's Storage layer can do what it does.

## Later, when something asks for it

Each needs its own decision, not a slot on a calendar.

| Item |
| :--- |
| Zero trust and secrets: Pomerium, OpenZiti, Cloudflare Tunnel, Teleport, SSH CA, OpenBao |
| Provisioning: Packer, PXE, Forgejo, registry mirror, image-update watcher, DNS and DHCP panels |
| Live migration, fleet placement, k3s or Talos, Helm export |
| NetBox and Grafana exports, read-only SNMP. Windows guests |
| Credential and identity anomalies, which need a new collector and a design first |
| Offline package bundles and local mirrors, with the registry mirror |
| Expiry heatmap, decoy personas and distribution, fanotify watchers, AppArmor profile editor, role-based hardening profiles, custom AIDE watchlist |
| Map extras: force-directed and rack layouts, custom icons and colour rules, per-role default views, map tiles on dashboards |
| Role profiles (default tools per host role) and per-host exclusions |

## Will not be built

The Samba VSS trap, cryptographic shred, compliance certificates and a WebSocket event stream, because they can't work or would claim too much: see [ransomware defense](docs/ransomware-defense.md). StorageForge stays agentless and builds no live log viewer: scans collect host journals for searching later ([Host logs](docs/api-reference.md)), and nothing tails or streams them. It isn't a replacement for NetBox, LibreNMS or Zabbix. The UI adds no framework, build step, CDN or third-party script, no telemetry about how it is used, no mobile-first redesign and no dashboard builder.

## Decision still open

**How much of B1 to B3 belongs in StorageForge?** The merged plan recommended releasing after the map, then deciding on the change engine onwards from how it's used. They'd make it a deploy platform as well as a map. The other [decisions it assumed](archive/roadmaps/infrastructure-platform-roadmap.md#12-decisions-to-confirm) stand, except that routers and switches are now read directly. Releasing 0.4.0 first is that recommendation, taken.
