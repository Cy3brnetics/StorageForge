# Infrastructure Platform Roadmap: Map, Workloads, Toolbox and Security

One plan for growing StorageForge from a map of storage into a map of the infrastructure around it, and a safe way to change that infrastructure: networks, firewalls, containers, VMs and the sysadmin tools that run on them.

It merges three drafts (Infrastructure Map, Workload Platform, Toolbox Catalog) and the [ransomware defense roadmap](ransomware-defense-roadmap.md), and checks them against the code as of `7302691` plus the uncommitted clock and SELinux-boolean fixes in the working tree. Where a draft and the code disagreed, the code won: see [What changed from the drafts](#3-what-changed-from-the-drafts). [Appendix A](#appendix-a-where-each-draft-phase-went) shows where every draft phase went, and [Appendix B](#appendix-b-where-each-security-phase-went) does the same for the security phases.

Status: **[progress.md](progress.md) says what has been built and lab-tested since this was written.** When this was written: planned, except the security work in [§9.1](#91-what-exists-today), which was built but not yet lab-tested. Today StorageForge also reads Docker and Podman containers, their mounts and volumes ([discovery](docs/features/discovery.md#docker-and-podman)), and deploys signed scripts ([deployments](docs/deployments.md)). When a stage ships, what it really does goes in a page under `docs/`, and this file stays the plan, as [Ransomware defense](docs/ransomware-defense.md) already does for security.

---

## 1. The idea

Every feature in the three drafts is one step of a loop StorageForge already runs for storage:

```text
     SEE                     PLAN                       CHANGE                  CONFIRM
 scan + measurement  ──►  stage a step, check it  ──►  report, then apply  ──►  next scan agrees
 (read only, indexed)     against the index            signed, audited          drift if it stops agreeing
        │                        ▲                                                    │
        ▼                        │                                                    │
       MAP  ─────────────────────┘ ◄──────────────────────────────────────────────────┘
```

So this is one product with four faces, not four products:

| Face | What it adds to the loop |
| :--- | :--- |
| **Map** | How the facts are seen, and where a plan can start |
| **Workloads** | New facts (containers, VMs) and new plan steps (deploy, lifecycle) |
| **Toolbox** | Plan steps packaged as data (catalog entries and bundles), and a way back to each tool's UI |
| **Security** | Measurements that raise alarms, holds and containment that act through the same signed runs, and the audits every other face reports through |

**What makes it StorageForge.** Portainer, Cockpit, Proxmox and NetBox each do a part of this better on their own, and this plan does not try to replace them. What none of them can answer is what spans storage, network and workload together:

- What lives on `tank/vm`, who can reach it, and is it covered by a snapshot and an offsite copy?
- If I move this folder, which containers and VMs break?
- This port looks blocked by `ufw`. Is it really?

A feature that does not get better from knowing the storage and the host's real state gets a **link** to the tool that does it, not a panel. That is the test for scope.

### Non-goals

- No Kubernetes or Swarm orchestration, no replacing Portainer, Komodo, Cockpit or Proxmox, and no CMDB.
- No agent and no new listeners. Agentless SSH and the signed runner, as now.
- No probing. Nothing here sends a packet to find out what exists: no nmap, ping sweeps, ARP or port scans.
- No import of scripts or `.tf` files into plans. Exports go one way. Capturing a *running* workload as a definition is a different thing, and is in scope.
- No silent internet exposure. Going public is always its own reported step.
- No re-implementing a tool's UI.
- No security theatre. No certificates or scores that claim more than a reading, and nothing that says *secure* with nothing measured ([§9.3](#93-what-will-not-be-built)).

---

## 2. The rules this plan is held to

The [rules every feature follows](docs/concepts.md#the-rules) apply unchanged. These are the ones this work leans on, and what each means here:

| Rule | Here |
| :--- | :--- |
| Scans only read; views answer from the index | The map, reach queries, what-if and tool tiles never open SSH at view time. They read the index |
| Checks before scripts | Every new step type has a check against the index that returns `ok`, `warn` or `crit`, later steps seeing earlier ones |
| Your intent is yours | Layouts, pins, annotations, manual nodes and overrides survive every rescan |
| Report first, same words | Every generated script reports `ok`, `missing`, `conflict` with no flags; only a mode flag changes anything |
| Nothing is deleted | Removing a tool keeps its volumes. Deleting a VM or volume is destructive: three locks, and quorum on a held dataset |
| Values reach Bash as data | Every new field kind joins `test_no_generator_lets_a_value_run_as_code` |
| A name proves nothing | A placeholder promoted to a host goes through normal enrollment and key pinning |

The [ransomware audit](docs/audit-2026-11-02-ransomware-defense.md) found the first version of that roadmap was a mock-up with 694 passing tests. A plan this size invites the same failure, so every stage has this **definition of done**:

1. **It reaches a host.** Anything that claims to change a host goes through `deploy.run`, and a test proves it ran.
2. **Every number was measured.** Unknown says *not measured*, a command that failed says *not readable*, and neither ever reads as fine or empty.
3. **A row means it happened.** An install, firewall rule or hold is recorded only after a signed run confirmed it.
4. **Tests run the real script.** Stand-ins only at the tool boundary, as in `tests/test_security.py`. A test that asserts a literal the code itself wrote proves nothing.
5. **It works in the browser under the real CSP.** Every panel is in `test_browser_smoke.py`. DOM APIs only, no `innerHTML`, no inline handlers.
6. **The chores are done.** Both databases, a migration for SQLite and PostgreSQL, tables in `backup.ESSENTIAL` or `backup.REBUILDABLE`, routes in the route-rule and permission tables, a `CHANGELOG` entry.
7. **It has a page saying what it does not do,** with a "Not built" list and a "tested how" table, and has been **through the KVM lab**. A stage is not finished on stand-ins.

---

## 3. What changed from the drafts

### 3.1 Overlaps merged into one thing

| The drafts had | This plan has | Why |
| :--- | :--- | :--- |
| Panels Catalog (W6) and Toolbox Catalog (T1): two formats, two tables, `/api/panels` and `/api/toolbox` | **One catalog.** A management panel is an entry with `category: panel` | Same engine, same rules |
| Three exposure audits: `/api/map/exposure`, `/api/toolbox/exposure`, `/api/security/workloads/exposure` | **One exposure engine,** read by the map, the Toolbox and Security | One answer to "who can reach this" |
| Containers and VMs collected in W1 and W2, again in M3 | Workloads collect, the map only draws | Scanned once |
| New `map_nodes` and `map_edges` | **Extend `graph_nodes` and `graph_edges`** | The map draft asked for both. One graph is what makes reports, health dots and the map agree |
| New `map_designs` table for intended topology | **Extend the `storageforge/v1` design** and the `fromdesign` path | Designs, overlays on rescans and the change-plan bridge already exist |
| `toolbox_installs` beside `deployed` and `deploy_runs` | Installs are `deployed` rows of kind `tool`, with status in `tool_status` | Pending and drift alerts already read `deployed` |
| Workload drift (W2) and map change tracking (M5) | **One graph diff per scan,** feeding the alerts that exist | One timeline |
| Security work bunched in W8, M7 and a separate roadmap | Each risk is handled in the stage that introduces it (§5.2) | A step that publishes a port must carry its firewall rule from its first day |
| Four separate gauntlets, 42 checks in all | Exit checks per stage (§10) | So a check gates the work it proves |

### 3.2 Corrections: claims the code does not support

| The drafts said | What is true | What this plan does |
| :--- | :--- | :--- |
| `planner.py`, `reports.py`, `iac/`, `runtimes/`, `netmap.py` as modules to touch | None of them exist. The planner is `static/planner.js` with `blueprint.py` and `fromdesign.py`; the staged plan engine is `changes.py`; reports are `report.py` | Modules named here are real, or marked **new** |
| `canvas.py` is the map's UI | It is the Obsidian `.canvas` exporter. The interactive views are `static/topology.js` and the Graph view | New `static/mapview.js`. `canvas.py` gains the new layers as one more export |
| Bash and IaC export are all new | `changes.py` already writes a Bash script and an Ansible playbook for every task type | Every new step type has both renderers from its first day. Only Terraform and Puppet are new |
| Generated secrets go "in the key vault" | `vault.py` stores **SSH keys only** | New secret store first (Stage 3) |
| Privileged reads need a new capability profile on the scan user | Scan access is `CAP_DAC_READ_SEARCH` on private copies of `find` and `sha256sum`. Widening it would break what makes it safe | Privileged reads use the existing **measurement**, a read-only signed run (§4.2). No new privilege model |
| "The runner applies an allowlist of commands per step type" | `storageforge-run` verifies a signature and runs the script as root | Dropped. The boundary is what gets signed, plus plan checks and permissions. Do not claim otherwise in the UI |
| The Report "checks the tool's URL is reachable from where the operator is" | Cannot be done: the CSP has `connect-src 'self'`, and reports run on the host | The exposure engine states which networks can reach it, labelled *per configuration* |
| Controller fetches catalog updates, checksums and images | The optional egress firewall limits the controller to SSH and alert ports | **All downloads happen on the target host,** inside the signed script. The catalog ships in the package |
| Depends on ransomware Phases 3, 4, 5 and 8 as designed | Built: quarantine, exempt list, airgap, MAC reading and relabel, AIDE and Lynis, compliance readings, sentinel, brake, clean room, holds. **Not built:** share CIDR fencing, a multi-backend firewall engine, Falco rules, custom dashboards, canvas badges, waivers, offline bundles | Dependencies below name only what exists. The firewall writer and tile grid are scheduled here |
| The brake and quarantine still need extending to workload traffic | The fence already has `input` and `forward` hooks, which should catch published ports. An `inet` forward hook will likely not see VMs bridged at L2 | Lab test in Stage 2, and a `bridge`-family table if it fails |
| A libvirt and LXC adapter covers hypervisors | **Proxmox runs neither through `virsh` nor plain `lxc`.** It is `qm` and `pct`, and the [appliances page](docs/appliances.md#limits) says guests are not listed | Read-only `proxmox` adapter added. No lifecycle there: Proxmox does that |
| Runtime and catalog steps can target any managed host | Deploys are **refused on TrueNAS and XCP-ng**, and Alpine has no bash or systemd | Those are scan-only; layers needing a signed read say *not readable*. No install is offered |
| React Flow as a rendering option | No build step, no framework, no npm, and a strict CSP | Out. See §6.1 |
| "Dockploy" | The project is **Dokploy** | Fixed |
| A Terraform Podman provider is available | Not verified as maintained | Podman stays Quadlet through Bash and Ansible until one is checked |
| `create-vm.sh` as a pattern in the project | It is not in the repo | The lessons from it are kept in §7.3 |

Already true and reused as is: the 409 on a plan changed since its dry run (`server.py`), secrets over the runner's stdin (`deploy.run(data=...)`), the rollback-timer pattern (`secscripts.py`, airgap), `scriptkit.NEEDS` and `PACKAGES` for multi-distro installs, the alert channels, and role-based permissions.

---

## 4. Architecture

```text
 UI          Map (mapview.js)  ·  Workloads panel  ·  Toolbox panel  ·  Changes, Deploy, Security (exist)
              │ reads the index only                         │ stages steps
 ─────────────┼──────────────────────────────────────────────┼────────────────────────────────────
 API         routes_map.py   routes_workloads.py   routes_toolbox.py      (never more in server.py)
              │                                              │
 Core        graph.py + new layers                   changes.TYPES + new step types
             exposure.py · reach.py (new)            catalog.py (new) · secrets in vault.py
             runtimes/ (new, from docker.py)         renderers: Bash, Ansible; later Terraform, Puppet
              │ facts                                        │ signed scripts
 ─────────────┼──────────────────────────────────────────────┼────────────────────────────────────
 Hosts       scan session      measurement (signed, read)    deploy.run (report, then apply)
             as the scan user  for what needs root           storageforge-run, audit log
```

### 4.1 Plugging into what exists

| Need | Goes through |
| :--- | :--- |
| A new plan step | `changes.TYPES`: fields, title, `_check_task`, `ARGS`, a `t_<name>` Bash function and an Ansible step. Forms are built from `TYPES`, so most need no JavaScript |
| Long-running repeatable work | `tasks.py` and `jobs.py` |
| Multi-distro installs | `scriptkit.NEEDS` and `PACKAGES` |
| Preflight (`/dev/kvm`, cgroups, conflicts) | `preflight.py` |
| New routes | A new `routes_*.py` with `register(web, ctx)`, and entries in `test_route_rules.py` |
| Alerts | `alerts.py` and its channels |
| Host-and-kind tracking | `deployed`, `deploy_runs` |

`changes.py` is 1,900 lines and `server.py` 2,300. The [EQ-03 finding](notebook/Findings/EQ-03%20Large%20modules.md) says to split them only "with a big change to those files". This is it. **Stage 0** makes `TYPES` accept registrations from other modules, so workload and catalog steps can live in their own files. It is deliberately not the wider `server.py` split: new routes simply go elsewhere.

### 4.2 Scan or measurement: where each fact comes from

| Fact | Read by | Needs root? |
| :--- | :--- | :--- |
| Interfaces, addresses, routes, neighbours, bridges (`ip -j`, `bridge -j`) | Scan | No |
| DNS, network config files (`resolv.conf`, networkd, NetworkManager, netplan) | Scan | No, mostly |
| Listeners, port and bind address (`ss -H -tuln`) | Scan | No |
| Listeners, **owning process** (`ss -p`) | Measurement | Yes |
| Firewall rules (`nft -j list ruleset`, `firewall-cmd`, `ufw`, `iptables-save`) | Measurement | Yes |
| Docker and Podman (`docker.py`, directly or through `sudo -n`) | Scan, as now | Depends on the host |
| Other users' rootless Podman, `virsh` system domains, `incus`, `qm`, `pct` | Measurement | Yes |
| Tool status: API on loopback, CLI JSON | Measurement, via the tool's adapter | Varies |

Why this split: a scan stays as safe as it is today, and measurement already exists, is signed and audited, runs every 6 hours for hosts with a sentinel or holds, and is stored per kind in `security_measurements`. The 6-hour schedule has to widen to hosts that use these layers. A host without deploy access still gets the unprivileged layers, and says plainly what it could not read. A failed command degrades that layer on that host and never fails a scan.

Never collected: process arguments, environment values, `.env` files, private keys or tokens. Env variable *names* only.

### 4.3 Runtime adapters

`docker.py` becomes `runtimes/` (**new**), one adapter per runtime, all returning the same records: `workload`, `volume_mount`, `network_attach`, `port_publish`, `security_context`.

| Adapter | Detect | Discover | Lifecycle |
| :--- | :--- | :--- | :--- |
| `docker` | `docker info` | `inspect`, compose labels | Yes |
| `podman` | `podman info` | `inspect`, pods, Quadlet units, rootless per user with linger | Yes |
| `incus` | `incus info` | `incus list --format json`, profiles, pools | Yes |
| `lxc`, `lxd` | `lxc-ls`, `lxc info` | Instances, config | Read only (legacy) |
| `libvirt` | `virsh version` | `dumpxml`, pools, networks | Yes |
| `proxmox` | Platform detection, as now | `qm`, `pct`, guest config | **Read only.** Links to Proxmox |

Today's `docker.py` format has name, image, state, labels, mounts and restart policy. It must gain image digest, networks, published ports, user, capabilities, `privileged`, security options and healthcheck.

### 4.4 The graph

`graph.KINDS` and `RELS` gain each layer's kinds. `graph_nodes` and `graph_edges` have a `CHECK` on both, so this needs a table rebuild on SQLite. Rebuildable: a rescan repopulates them.

- New columns or `props_json` keys: `layer`, `evidence` (source host, source kind, command), `confidence` (`certain`, `confirmed`, `inferred`, `manual`), `first_seen`, `last_seen`.
- `health` stays what it is: the 3-2-1 colour. A firewall has no 3-2-1 state, so a non-storage node leaves it `unknown` and carries layer state in its props, such as an exposure level. Do not overload it.
- `REPLICATES_TO` and share edges already cross hosts; network edges follow the same way.

| Layer | Nodes | Edges | Stage |
| :--- | :--- | :--- | :--- |
| **Storage** (exists) | Host, StoragePool, Filesystem, MountPoint, Symlink | CONTAINS, MOUNTED_AT, SYMLINK_TO, REPLICATES_TO | now |
| **Network** | NIC, Bond, Bridge, VLAN, Subnet, Gateway, Route, DNS | ATTACHED_TO, MEMBER_OF, TAGGED, ROUTES_VIA, RESOLVES_VIA | 1 |
| **Services** | Listener, Unit, Share | LISTENS_ON, EXPOSES, SERVED_BY, CLIENT_OF | 1 |
| **Firewall** | FirewallPolicy, Chain or Zone, RuleGroup, NATMapping, FenceSet | APPLIES_TO, ALLOWS, DENIES, FORWARDS, NATS_TO | 1 |
| **Workloads** | Runtime, Container, Pod, Stack, Instance, VM, VirtualNetwork, VirtualDisk | RUNS_ON, ATTACHED_TO, PUBLISHES, BACKED_BY, and MOUNTS into the storage layer | 1 |
| **Tools** | Tool, Panel | MANAGES, DEPLOYED_BY | 5 |
| **Access** | VPNNetwork, Peer, IdentityProvider, ProxyRoute | PEERS_WITH, ROUTES_THROUGH, AUTHENTICATES, FRONTS | 5 |
| **Security** | Badges, not nodes: MAC mode, decoy, hold, quarantine, finding | | 2 |

**How edges are made,** most to least certain:

| Confidence | How | Drawn |
| :--- | :--- | :--- |
| `certain` | Within a host: interface to bridge to VM NIC, mount to dataset, listener to process, rule to interface | Solid |
| `confirmed` | Across hosts, by address or config: a share mount or route next-hop names an address another scanned host holds; WireGuard peer public keys match | Solid |
| `inferred` | Same subnet and gateway; `ip neigh` entries. Unscanned devices become **placeholders**, never full nodes, with **Promote to host** | Dashed, labelled |
| `manual` | The operator placed it: switch, modem, access point. Labelled "manual, not verified" | Distinct style |

Every edge can answer "why does this exist, and who said so?"

**Change tracking.** Each scan stores a graph hash and a diff against the last one (`graph_snapshots`). That one diff drives the timeline, "changed since" filters, workload drift, and alerts such as *new listener on `0.0.0.0:2375`*.

### 4.5 The exposure engine

`exposure.py` (**new**) is the first piece of real analysis in the plan and the one everything else leans on. For each listener or published port it works out: bind address, then host firewall, then runtime NAT (`DOCKER-USER`, firewalld zones, `iptables=false`), then which of the host's networks can reach it.

The result is a level (`loopback`, `management`, `lan`, `vpn`, `any`), the rule that decided it, and a list of **what it could not model**. Every answer is labelled *per configuration*. Unreadable rules give `unknown`, never `closed`.

The rule parser reduces nftables, firewalld, ufw and iptables-nft to one model, and bridged VMs are reported as bypassing the host's INPUT rules, because they do. `reach.py` (Stage 6) extends this to "can A reach B?".

---

## 5. Delivery

Stages are in dependency order. **Stages 1 and 2 change nothing on any host,** and are worth releasing by themselves.

```text
 0 Groundwork ─► 1 Facts ─► 2 See ─► 3 Change engine ─┬─► 4 Workloads ─┐
                              │                       └─► 5 Toolbox ───┼─► 6 Plan from the map ─► 7 Depth
                              └──────── exposure is used by 3, 4, 5, 6 ┘
```

Days are carried over from the drafts or are new rough guesses. **None has been measured,** and the first attempt at the ransomware roadmap, planned the same way, was a mock-up, so read them as relative size. Total: roughly 140 to 170 working days. The three infrastructure drafts added up to about 135 to 165, but they had no Stage 0, secret store or firewall writer, and this plan defers zero trust and catalog waves 2 and 3. The security roadmap's own 41 to 50 days are mostly spent: the days here are only what it has left.

### 5.1 Stages

#### Stage 0: Groundwork (5 to 7 days)
What the rest stands on, and it is not new features.
- **Land the uncommitted clock and boolean fixes** ([§9.1](#91-what-exists-today)).
- **Add a security lab tier and run it,** which [its page](docs/ransomware-defense.md#what-has-been-tested-and-how) says has not happened: the whole signed path, real ZFS, real SELinux and AppArmor, Samba attribution with real clients, and **the airgap's rollback timer under real systemd**, which Stage 3 reuses for bridge changes.
- **Own up to the compliance thresholds.** `security.STANDARDS` gives each standard a `target_lynis` and `min_worm_days`, such as 86 for PCI-DSS. Those standards set no Lynis score, so the UI must call these StorageForge's suggestions and let them be changed, or drop them.
- **Get CI running on a real runner** ([EQ-01](notebook/Findings/EQ-01%20No%20CI%20and%20untested%20paths.md) says this was not proved as of its last entry).
- `changes.TYPES` takes registrations. `docker.py` moves to `runtimes/docker.py` with no behaviour change.
- Lab: add `libvirt` and `incus` abilities and a nested-virt config, firewall variety (`ufw`, `firewalld`, plain nftables), and tier stubs.

**Exit:** a full lab report, with anything found fixed or recorded.

#### Stage 1: Facts (16 to 18 days)
Everything is read-only and shows up as plain lists before there is a map.
- Docker and Podman full inventory, Podman pods, Quadlets and rootless (W1).
- libvirt, Incus and Proxmox discovery; legacy LXC and LXD read-only; disk images resolved to datasets (W2).
- Network, services and firewall collection and the rule parser (M1, M2).
- Graph layers and evidence, link resolution for `certain` and `confirmed`. Detection of panels by image, port and unit.
- Workloads panel replaces Docker, with per-runtime tabs.

**Answers:** *what lives on `tank/vm`?* for VMs too. *What breaks if I move this folder?* for all runtimes.

#### Stage 2: See (27 to 33 days)
The map, and the first release of this work.
- `mapview.js`: layers, hosts as frames with semantic zoom, auto layout, pin and save, search and filter, evidence popovers, hover trace, legend, light and dark (M1, M3, M4).
- `exposure.py` and the one-click exposure view. **Read-only security audits:** published ports vs firewall, MAC and sVirt state, Docker socket exposure, VNC and SPICE listen addresses (M2, W8 read parts).
- **Security badges on the map,** from data measurements already hold: holds and expiry, decoys, MAC mode, quarantined clients.
- **Share client view,** read-only: each share's declared clients, what the firewall really allows, and who is connected on storage ports.
- Placeholders, manual nodes, annotations, Promote to host (M5).
- Graph diffs, timeline, drift alerts (M5). Adopt a workload, capture as compose, Quadlet, libvirt XML or Incus YAML, drift against the capture (W1, W2).
- Exports: SVG, PNG, Mermaid, DOT, JSON, `.canvas`, print-to-PDF; redaction presets. draw.io if it stays cheap.
- Test whether the quarantine fence covers bridged VMs and published ports.

**Exit:** *"a port `ufw` looks like it blocks is shown as reachable, with the rule that decides it."* **Release here.** Read-only, useful alone, and it tests the facts on real networks before anything acts on them.

#### Stage 3: Change engine (18 to 22 days)
What every later step needs. Nothing a user asked for by name, all of it load-bearing.
- **Secret store.** `vault.py` gains generic secrets with the same envelope encryption. Generated, shown once, delivered through the runner's stdin (`deploy.run(data=...)`), and never in a plan, log, report, `deploy_runs` output or export. Rotation path.
- **Catalog engine** (§8): schema, signature, override layer, install methods, risk labels, uninstall that keeps data (T1, W6).
- **Firewall writer.** Staged rule add and remove for each backend with rollback, including `DOCKER-USER`. This is the "firewall engine" the other drafts assumed.
- **Share-level CIDR fencing and interface binding,** the writer's first users: SMB and NFS ports tied to declared clients, and to chosen interfaces on multi-homed hosts. A plan step, so a wrong subnet shows in the Report.
- **Security findings become steps:** SELinux booleans, Lynis findings (sysctl, SSH, umask) as Changes tasks with Bash and Ansible, rather than one-off buttons.
- **`runtime-install`** (W3): the four runtimes across distros, rootless setup, preflight (§7.1) that says *present*, *installable* or *blocked, host is offline*.
- **`pooldef` and `netdef`**, with bridge changes under the tested rollback timer (W3).

**Exit:** install a runtime on a bare VM from a plan. Report changes nothing. A changed plan gets 409. A bridge change that cuts SSH rolls itself back.

#### Stage 4: Workloads (13 to 15 days)
- `container`, `stack`, `lxc` steps, each carrying its firewall rule and labels. Image update with rollback on a failed healthcheck (W5).
- VM templates, cloud-image and ISO paths, checksums, cloud-init with the deploy key, so a new VM can be scanned from first boot (W4, §7.2).
- Lifecycle: start, stop, snapshot, clone, resize, console over an SSH tunnel; delete through the destructive gate.
- **Placement advice,** the differentiator: pool on a dataset tuned for its use, databases off the bulk pool, warnings for bind mounts on network filesystems, VM disks kept in a dataset with a snapshot job, and a warning when data sits where no hold or offsite copy reaches.
- MAC at deploy: `:Z` labels, `svirt_image_t` fix as a plan step, AppArmor pool paths.

#### Stage 5: Toolbox (32 to 40 days)
- **Adapters and GUI levels:** `detect`, `status`, `actions`, `links`, `metrics` over measurement (T2, §8.3).
- **Wave 1 entries,** §8.4. Panels first, since they prove the catalog cheaply: Cockpit, Dockge, then Portainer, Komodo, Dockhand, Dokploy, Incus UI (W6). Then WireGuard with a full panel, Caddy with a full panel, CrowdSec, Trivy, restic with restore tests, Prometheus and Grafana (T3 to T6).
- **Bundles** with one Report, shared secrets, one firewall change set, and rollback of the whole bundle (T8).
- **Access layer** on the map (M7).
- Trivy findings and CrowdSec decisions feed the existing alerts and quarantine view. Quarantine must not fight the bouncer: bans reconcile.

The largest stage, and it can be cut at any entry without harming the rest. **A tool without a passing lab run is labelled *not lab-tested* in the catalog,** so the list cannot quietly claim more than was proved.

#### Stage 6: Plan from the map (14 to 17 days)
- `reach.py`: *can A reach B?*, with the deciding rule and blind spots, evaluated from observed rules and routes (M6).
- What-if: `POST /api/map/whatif` draws staged steps as a ghost layer with reachability and exposure diffs and conflict checks. Duplicate IPs, port clashes, and **anything that would cut StorageForge's own SSH path** blocked unless a rollback timer is staged (M6).
- Context actions per node (§6.3), each creating a normal staged step (M6).
- Intended vs actual: designs gain planned VLANs, VMs and containers, and the compare lists what is missing, extra or different (M8).

It comes this late on purpose: a what-if is only credible once the facts have met real networks and the steps it previews exist. It must be proved against real connection tests (§10).

#### Stage 7: Depth (15 to 20 days)
- **Terraform and OpenTofu** export (libvirt, Docker, Incus, Proxmox providers) and **Puppet**, with round-trip tests. Externally-managed detection and a warning before changing such a workload (W7).
- Quiesced snapshots: `qemu-guest-agent`, stop-snapshot-start for stateful stacks, with the method recorded.
- Incidents include workloads touching affected paths; the clean room boots a VM or container from a pre-incident snapshot on an isolated network.
- Compliance readings for CIS Docker, Podman and libvirt-style checks, auditd rules for runtime sockets and config (W8).
- **Compliance depth:** waivers with a reason, approver and expiry; custom profiles built on a standard; a daily drift reading; re-converge as a staged plan.
- **Retention depth:** tier policies by dataset tag or path, pool-wide legal freeze, rollback preview from a held snapshot.
- **Detection depth:** YARA beside ClamAV on changed files with rule files as data; per-dataset entropy and change-rate thresholds; AVC noise filters; progressive ban tiers. Every threshold is tuned against what a host has actually reported.
- **Incident export:** a signed record of what was measured and done, stating that it is evidence and not an attestation.

#### Later, when something asks for it
Each needs its own decision, not a slot on a calendar.

| Item | From |
| :--- | :--- |
| Zero trust and secrets: Pomerium, OpenZiti, Cloudflare Tunnel, Teleport, SSH CA, OpenBao | T7 |
| Provisioning: Packer, PXE, Forgejo, registry mirror, image-update watcher, DNS and DHCP panels | T9 |
| Live migration, fleet placement, k3s or Talos, Helm export | W9 |
| NetBox and Grafana exports; read-only SNMP or LLDP | M9 |
| Falco storage rules, as a catalog entry plus an adapter into the alerts | Security 5 |
| Credential and identity anomalies. Needs a decision first, see §12 | Security 3 |
| Playbook designer, custom tile dashboards, a status banner on every page (alerts cover this for now) | Security 8 |
| Offline package bundles and local mirrors, with the registry mirror | Security 8 |
| FIDO2 step-up; expiry heatmap; decoy personas and distribution; fanotify watchers; context-mapping matrix; AppArmor profile editor; role-based hardening profiles; custom AIDE watchlist | Security 1 to 6 |
| Large-fleet rendering, once a real fleet shows the need | M9 |
| Map extras: force-directed and rack layouts, custom icons and colour rules, per-role default views, map tiles on dashboards | M4 |
| Role profiles (default tools per host role) and per-host exclusions | T8 |

### 5.2 Where each security concern lands

| Concern | Stage |
| :--- | :--- |
| Land and lab-test the security work that exists | 0 |
| See exposure, MAC state, socket and console exposure, security badges, share clients | 2 |
| Share fencing; booleans and Lynis findings as steps | 3 |
| Firewall rule stages with the step that publishes a port | 3, 4 |
| Secrets generated, vaulted, shown once | 3 |
| Risk labels and mitigations (socket proxy, loopback bind) | 3, 5 |
| Generated VM consoles bind to loopback; labels on bind mounts | 4 |
| Brake and quarantine cover workload traffic | 2 tests it, 3 fixes it |
| Quiesced snapshots, recovery, compliance and retention depth, YARA, auditd | 7 |
| Falco, identity anomalies, playbooks | Later |

---

## 6. The UI

### 6.1 Rendering (decided)

The app is plain JavaScript with no build step, no npm dependencies and `script-src 'self'`. `static/topology.js` shows that a canvas of about 1,150 lines works here.

**Write `static/mapview.js` in the same style, with SVG and DOM APIs.** Start with simple deterministic layouts: layered for network, nested frames for workloads, as `canvas.py` does. If real graphs defeat that, vendor one file (ELK for layout only) into `static/`. No framework.

**The Topology and Map stay separate.** Topology edits designs: one kind of thing, with tables and rows. Map is derived from facts: many kinds, read-mostly. The existing **Graph** view is what the map replaces, once the Storage layer can do all it does.

### 6.2 Where it goes

- A **Map** view in the header, beside Topology, Graph and Tasks.
- **Security** stays as it is in the rail, and does not get a second copy of exposure: its Firewall panel reads the same engine.
- **Workloads** in the rail replaces **Docker**, with *Containers*, *VMs*, *Stacks* and *Templates*. **Toolbox** beside it: *Catalog*, *Installed*, *Bundles*. Steps land in **Changes**, runs in **Deploy**, as everything else does.
- Deep links extend the existing hash: `/#host=nas-01&tab=workloads&panel=vms`, `/#host=gw-01&tab=toolbox&tool=wireguard`, `/#view=map&layers=network,firewall&host=gw-01`.
- A tool's own UI opens in a new tab, never an iframe: the CSP has no `frame-src` allowance for it, and that should stay so.

### 6.3 On the map

**Modes:** Network, Flow, Workloads, Storage, Security, Custom. A layer can be shown alone or stacked.

**Objects:**

| Object | Shows |
| :--- | :--- |
| Host | OS, role, scan age, runtimes, firewall backend, MAC mode, VPN membership, what could not be read |
| Interface | Addresses, MAC, MTU, state, speed, VLANs, bridge, byte delta between scans |
| Firewall | Backend, default policies, rules grouped by purpose; expands to exact rules in order |
| Listener | Port, bind address, process and unit, exposure badge |
| Container or VM | State, image or template, resources, mounts to datasets, networks, ports, security context |
| Edge | Type, evidence, when seen, last change |

**Actions** (Stage 6). Each creates a normal staged step:

| Select | Offered |
| :--- | :--- |
| Empty space on a host | Deploy a container, stack, VM, instance or catalog tool |
| NIC or bridge | Create a bridge or VLAN, attach a workload, change MTU (rollback timer) |
| Listener | Restrict the bind, add a rule, put it behind the proxy, close it |
| Firewall | Add allow or deny, fence to a subnet, show impact |
| Edge | Allow A to reach B on a port, remove this exposure, add a VPN route |
| Container or VM | Move, change network, snapshot, clone, resize, stop, remove (destructive gate) |
| VPN peer | Add, revoke, rotate, change routes |
| Placeholder | Promote to host |

**Honesty in the UI:** activity shown comes from byte-counter deltas between scans, labelled as such, never live. Reach and what-if results say *per configuration*, how old the facts are, and what could not be modelled. Exports can redact IPs, hostnames and MACs, and using them is audited.

---

## 7. Workloads in detail

### 7.1 Runtime install

| Runtime | Debian, Ubuntu | RHEL family, Fedora | openSUSE, Arch | After install |
| :--- | :--- | :--- | :--- | :--- |
| Docker | `docker.io` or the CE repo, compose plugin | CE repo, compose plugin | `docker`, `docker-compose` | `daemon.json`: log limits, optional `userns-remap`, iptables mode |
| Podman | `podman`, `buildah`, `skopeo`, `uidmap`, `passt` | same, `container-selinux` | `podman`, `buildah`, `skopeo` | `subuid` and `subgid`, linger, `podman.socket` |
| Incus | `incus` | `incus` (COPR or EPEL) | `incus` | `incus admin init --preseed`, pool on a chosen dataset |
| KVM, libvirt | `qemu-kvm`, `libvirt-daemon-system`, `virtinst`, `ovmf`, `swtpm` | `qemu-kvm`, `libvirt`, `virt-install`, `edk2-ovmf`, `swtpm` | `qemu`, `libvirt`, `virt-install`, `edk2-ovmf` | modular daemons, pool and network from the plan |

**Preflight** (read-only, shown first): `vmx` or `svm`, `/dev/kvm`, nested virt; cgroup v2, user namespaces, `subuid`, kernel modules (`overlay`, `br_netfilter`, `vhost_net`); conflicts such as Docker beside Podman, an existing `br0`, another hypervisor; room for the runtime root; `nocow` advice for VM images on btrfs; ZFS and btrfs driver choice.

**Definitions as steps:** `pooldef` (libvirt dir, ZFS or LVM pool, Incus pool, runtime root, tied to a known dataset) and `netdef` (bridge, libvirt NAT or isolated, Incus bridge, runtime network).

### 7.2 Step types

| Step | Report shows |
| :--- | :--- |
| `runtime-install` | Packages, units, config files |
| `pooldef`, `netdef` | What is created, and what path could be cut |
| `container` | Resolved digest, mounts, ports, labels, the generated `docker run` or Quadlet |
| `stack` | Rendered compose, diff vs live, volumes to create |
| `lxc` | Image fingerprint, profile merge, devices |
| `vm` | The exact `virt-install`, disk path and size, NIC, graphics, checksum result |
| `tool` | Chosen install method and why, risk labels, exposure, firewall changes, hardening |
| `tool-action` | The adapter action as a script: revoke peer, add route, unban, run restore test |

VM templates are data:

```yaml
name: rocky10
aliases: [rocky]
source:
  iso: Rocky-10-latest-x86_64-minimal.iso
  checksum_url: https://download.rockylinux.org/pub/rocky/10/isos/x86_64/CHECKSUM
os_variant: rocky10          # validated against osinfo-query on the host
defaults: { vcpus: 2, ram_mb: 2048, disk_gb: 30, disk_format: qcow2, bus: virtio }
firmware: uefi               # or bios, or uefi-secure + tpm
graphics: { type: spice, listen: 127.0.0.1 }
```

The library: Debian, Ubuntu, Rocky, Alma, Fedora, Arch, openSUSE, Alpine; Proxmox VE, TrueNAS and OPNsense for labs. Per-host defaults (`iso_dir`, `pool`, `network`) live in host settings. **Cloud images are preferred:** verified image, backing-file overlay, cloud-init with the deploy key, hostname and static IP. ISOs remain for installers with no cloud image, with kickstart, preseed or autoinstall. Operators can clone and save templates. Every template exports to a standalone script; scripts are never imported back.

Secrets in scripts: a downloaded script, which must still run alone (`--host`), generates its secret on the host or asks for it. It never contains one.

### 7.3 Defaults a generated VM must not copy

From reviewing a typical hand-written `create-vm.sh`:

| Common in such scripts | Risk | Generated default |
| :--- | :--- | :--- |
| `--graphics vnc,listen=0.0.0.0` | Unauthenticated console for the whole network | `listen=127.0.0.1`, via SSH tunnel; the Report flags any other listener |
| Network named but never checked | Fails late | Preflight checks it exists |
| Hard-coded ISO dir and pool | Not portable | Per-host settings, checked |
| ISO with no checksum | Tampered or corrupt installer | Verified before attach |
| Guessed `--os-variant` | Wrong guest tuning | Validated with `osinfo-query`, warning on fallback |
| No firmware or TPM options | Weaker guests | Template fields, UEFI for modern distros |
| No autostart or guest agent | Does not return after a reboot; cannot quiesce | Optional autostart, `qemu-guest-agent` channel |

### 7.4 Security specifics

- **libvirt:** confirm sVirt is active (`svirt_t` categories or `libvirt-<uuid>` profiles). Flag `unconfined` VMs, images without `svirt_image_t`, and pools missing from `/etc/apparmor.d/local/abstractions/libvirt-qemu`.
- **Docker, Podman:** bind-mount labels, `container-selinux`, `label=disable`, `apparmor=unconfined`, `spc_t`, custom seccomp.
- **Incus, LXC:** `security.privileged`, `security.nesting`, idmap, raw overrides.
- **Management plane:** offer a socket proxy and rootless sockets, flag port `2375`, never publish the Docker API without mutual TLS, prefer `qemu+ssh://`.
- **Bridged VMs** bypass host INPUT rules. The Report says so, offers bridge-family rules or `nwfilter`, and isolated networks are the default for untrusted guests.
- AVC denials join the existing MAC panel, tagged by workload.

### 7.5 Export

One plan model, several renderers, read straight from the plan and never from each other.

| Target | Artifact | When |
| :--- | :--- | :--- |
| **Bash** | Standalone script, and what Apply runs | From each step's first day |
| **Ansible** | Playbook with `community.docker`, `containers.podman`, `community.libvirt` | From each step's first day, as `changes.py` does now |
| **Native** | Compose, Quadlet, libvirt XML, Incus YAML | Stage 2 capture |
| **Terraform, OpenTofu** | `main.tf`, variables. `dmacvicar/libvirt`, `kreuzwerker/docker`, `lxc/incus`, `bpg/proxmox` | Stage 7 |
| **Puppet** | Manifests and Hiera data | Stage 7 |

Exports are idempotent, hold secrets only by reference (vault key, `sops`, env or Hiera eyaml), and are for the operator's own pipeline. Apply inside the product always uses the signed runner.

---

## 8. The catalog

### 8.1 An entry

Signed YAML, data and not code:

```yaml
id: headscale
name: Headscale
category: vpn
summary: Self-hosted Tailscale control server
install:
  methods:                       # safest first; the operator can override
    - { kind: quadlet, image: ghcr.io/juanfont/headscale, digest: sha256:..., rootless: true }
    - { kind: compose, file: headscale.compose.yml }
    - { kind: package, debian: headscale, rhel: headscale }
    - { kind: binary,  url: ..., sha256: ..., signature: ... }
requires:   { ports: [8080/tcp], volumes: [config, data], caps: [], runtimes: [podman, docker, host] }
exposure:   { default: loopback, public_optional: true, behind: reverse-proxy }
secrets:    [ { name: admin_api_key, generate: true } ]
firewall:   { allow: [{ port: 443/tcp, from: any, optional: true }] }
mac:        { selinux: container_t, apparmor: default, notes: "mount :Z" }
health:     { url: http://127.0.0.1:8080/health, expect: 200 }
backup:     { paths: [data], consistency: stop-snapshot }
gui:
  native:   { url_template: "https://{host}/admin", sso: none, port: 8080 }
  panel:    { level: status+actions, adapter: headscale }
upgrade:    { strategy: recreate, rollback_on_unhealthy: true }
risk:       [ holds-credentials ]
compliance: [ cis-docker-5.x ]
```

### 8.2 Rules for every entry

1. **Pinned and verified.** Images by digest; binaries by checksum and signature. Upgrades are reported, never silent.
2. **Least exposure.** Binds to loopback or the management network. Going public is a separate step with its firewall rule and TLS route.
3. **Least privilege.** Rootless where it works, no socket mount without the proxy option, capabilities dropped, read-only root where possible.
4. **Risk labels** in the Report: *mounts the Docker socket* (root-equivalent), *privileged*, *host network*, *publishes 80/443*, *runs as root*, *holds credentials*, *listens on the internet*. Each has a mitigation where one exists.
5. **Secrets** generated, stored, shown once, never in plans, logs or exports.
6. **Data stays** on uninstall. Removing it uses the destructive gate, and quorum on a held dataset.
7. **Targets managed hosts only,** never the StorageForge server, and refused where deploys are.
8. **Overlap is flagged:** a second panel on the same Docker socket warns and marks what it manages as *externally managed*.
9. **Audited:** install, upgrade, config change, removal.

**Trust.** Built-in entries ship in the package, so they are as trusted as the code. User entries are signed by a vault key under a new namespace (`storageforge-catalog`), never the deploy signer's. Unsigned ones need an explicit override and show a banner. **A custom entry is root on the host by another name,** so writing or signing one takes `hosts.command`. Overrides change ports, volumes, tags and exposure without a fork, and survive catalog updates.

### 8.3 Tying back to a GUI

| Level | What it is |
| :--- | :--- |
| `none` | Nothing to show |
| `link` | Opens the tool's own UI from `url_template`, in a new tab |
| `sso-link` | Same, already signed in once an identity provider is deployed. No OIDC? Forward-auth in front |
| `status` | Read-only tile: version, health, last check, key counts |
| `status+actions` | Tile, plus safe actions that become plan steps |
| `full` | A StorageForge panel, for CLI-only tools where the integration adds value |

**Adapters** are small modules with up to five functions: `detect`, `status`, `actions`, `links`, `metrics`. They run during measurement, on the host, calling loopback or CLI JSON. The panel reads the index and shows the age. Read-only by default: anything that changes state is an action creating a plan step. Credentials are vault references. A failed adapter says *status unavailable* and blocks nothing.

### 8.4 Which tools, and when

**Wave 1** is what Stage 5 commits to. **Wave 2** follows only once wave 1 has lab runs; each entry is small then. **Wave 3** is the "Later" list.

| Category | Wave 1 | Wave 2 | Wave 3 |
| :--- | :--- | :--- | :--- |
| Panels | Cockpit (+machines, +podman), Dockge, Portainer CE, Komodo, Dockhand, Dokploy, Incus UI | virt-manager connection strings | |
| VPN, overlay | **WireGuard** (full panel: peers, QR, handshake age, rotation) | Headscale, Tailscale, NetBird | OpenVPN, strongSwan, Netmaker |
| Reverse proxy, TLS | **Caddy** (full panel: sites, upstreams, certs) | Traefik, nginx Proxy Manager, step-ca | |
| Identity | | Authelia, Authentik, LLDAP | Keycloak, Kanidm, FreeIPA, Samba AD |
| Intrusion, scanning | **CrowdSec** (bans in the quarantine view), **Trivy** (findings into workloads) | fail2ban, Grype, OpenSCAP, Suricata | Zeek, Wazuh, Falco |
| Monitoring | Prometheus + node_exporter, Grafana (with a StorageForge dashboard) | Loki, Uptime Kuma, Beszel, Netdata | |
| Logging, grabbers | | Vector or Promtail (grabber), Loki or VictoriaLogs (querier), Dozzle (container logs) | Fluent Bit |
| Backup | **restic** (panel, restore test), restore-test automation | Kopia, Borg, PBS as a VM template | |
| Network services | | Chrony with NTS, Pi-hole, AdGuard, Unbound, CoreDNS | dnsmasq |
| Zero trust | | | Pomerium, OpenZiti, Cloudflare Tunnel, Boundary, Teleport, SSH CA |
| Secrets | | Vaultwarden, sops + age | OpenBao, Vault |
| Provisioning | | | Packer, PXE, Forgejo, Zot, Harbor, Renovate, external Ansible, Puppet and Terraform runners |
| Storage-facing apps | | MinIO or Garage, Nextcloud, Syncthing, Jellyfin: dataset, snapshot and share wired at deploy | |

**Not new entries, because they exist:** ntfy, Gotify and webhooks are alert channels. SMART and disk health are `health.py`. rsync, rsnapshot and btrfs send are jobs. Samba and NFS are shares. ClamAV, AIDE and Lynis are in Security. Bring these into the catalog only where a deploy adds something.

**Log grabbers and querying tools:** StorageForge itself is not a log aggregation server, runs no log ingestion listener, and stores no log streams in its index. Following the scope rule (§1), log grabbers and collectors (Vector, Promtail) deploy on managed hosts as catalog entries with read-only bind mounts to `/var/log/journal` or container log directories, shipping to an aggregator/querier (Loki, VictoriaLogs). Operators query logs through Grafana links or tiles. For quick container-only log tailing and querying without a central cluster, Dozzle deploys as a lightweight catalog tool linked directly from the Workloads panel. StorageForge's own host log inspection remains strictly bounded to signed measurement reads for incident triage (e.g. recent unit journal slices or auditd events).

### 8.5 Bundles

An ordered list of entries with shared parameters: one plan, one Report, one Apply, the whole bundle rolled back on failure. Identity comes before what uses it. One firewall change set. Clashes, such as two tools wanting 443, are conflicts. A summary lists everything exposed.

| Bundle | Contents | Stage |
| :--- | :--- | :--- |
| **Private access** | WireGuard + Caddy (+ Authelia once in wave 2) | 5 |
| **Container host** | Podman rootless + Caddy + Dockge + Trivy + node_exporter | 5 |
| **Hypervisor** | libvirt + Cockpit + WireGuard + restic | 5 |
| **Observability** | Prometheus + Grafana + node_exporter (+ Loki + Vector in wave 2) | 5 |
| **Backup and recovery** | restic + restore test + a held dataset | 5 |
| **Hardened homelab** | Private access + CrowdSec + restic (+ Chrony, Uptime Kuma later) | 5 |
| **Zero-trust gateway** | Authentik + Pomerium or OpenZiti + step-ca | Later |

---

## 9. Security

This is what remains of the [ransomware defense roadmap](ransomware-defense-roadmap.md), which this section replaces as the plan. [Ransomware defense](docs/ransomware-defense.md) says what exists and what it protects against. **The limit stands throughout: none of this stops an attacker with root on the host. Only a copy on another machine is out of reach.** "WORM" here means *guarded*, not *impossible*.

### 9.1 What exists today

Everything below offers show script, dry run and apply, and runs signed. **None of it has been through the KVM lab,** which is why Stage 0 comes first.

| Layer | Built | Still to do | Stage |
| :--- | :--- | :--- | :--- |
| **1 Holds, clock, quorum** | ZFS holds and btrfs read-only snapshots confirmed by signed runs, legal holds, cool-off or second admin, offline key, host and controller clock guards, `zfs allow` readings | Tier policies, pool-wide freeze, rollback preview | 7 |
| | | Expiry heatmap, FIDO2 | Later |
| **2 Decoys** | Decoys, inotify sentinel, auditd attribution, arming, **Test it** timing, host-side brake | Personas, distribution, fanotify | Later |
| **3 MAC** | SELinux and AppArmor as found, booleans, labels against policy, denials, relabel | Booleans as staged steps | 3 |
| | | AVC noise filter | 7 |
| | | Identity anomalies, context matrix, profile editor | Later |
| **4 Firewall** | Quarantine for IPv4 and IPv6, exempt list, airgap with rollback timer | Client view | 2 |
| | | Multi-backend writer, share fencing, interface binding | 3 |
| | | Ban tiers | 7 |
| **5 Behaviour** | Change rate against the host's own past, ransom names, renames, entropy with file-header check, whether Falco is installed | Per-dataset thresholds | 7 |
| | | Falco rules | Later |
| **6 Integrity** | AIDE and Lynis, run in the background and read by the next measurement | Findings as staged steps | 3 |
| | | Waivers | 7 |
| | | Role profiles, watchlist | Later |
| **7 Malware** | ClamAV on changed files and on a deployed timer, quarantine and restore (`clamav.py`) | YARA with rules as data | 7 |
| **8 Incident** | Overview, brake, damage since an incident, clean room for snapshots | Workloads in incidents and clean room, incident export | 7 |
| | | Playbook designer | Later |
| **Provisioning** | `scriptkit.NEEDS` and `PACKAGES` across apt, dnf, yum, zypper and pacman, including EPEL | Offline bundles, mirrors | Later |
| **Compliance** | Readings against CIS L1 and L2, NIST 800-53, HIPAA, PCI-DSS, SOC 2, ISO 27001 and CMMC L2, and a report-first baseline script | Waivers, custom profiles, drift, re-converge | 7 |

**The edits now in the working tree, uncommitted, with tests:**

- **A wrong clock on this machine no longer blames the fleet.** Hosts are compared only with the controller, so one running 515 s behind reported every host as wrong. Now, when most measured hosts differ by the same amount, Security says this machine's clock looks wrong, and cool-offs stop. Clearing it frees hosts frozen only for differing from it; a host whose own clock jumped stays frozen.
- **`nfs_export_all_rw` and `_ro` are shown but not judged.** They are on by default on the RHEL family, and turning them off can stop exports.

Both came from looking at a real fleet, not from a test or the old roadmap, which is the argument for Stage 0 on its own.

### 9.2 Corrections to the old roadmap

Do not implement these as it describes them.

| It said | What is true |
| :--- | :--- |
| Intercept `vssadmin delete shadows` at Samba (VSS trap) | **Impossible.** It acts on the Windows client's own shadow copies through its local service. Nothing crosses SMB. Decoys and change detection catch these clients |
| "Immutable", "kernel-level WORM" | Root can `zfs release` a hold and make a btrfs snapshot writable. These guard against mistakes, scripts and stolen web logins |
| Memory triage preserves AES keys | Rarely. When a workstation encrypts a share, keys are on the workstation. Triage saves connections, processes and sometimes a core dump: evidence, not a decryption route |
| Entropy bands: compressed is 7.2 to 7.6 | On a 4 KiB sample, compressed data reads about 7.9 or higher, the same as ciphertext. A known file header has to clear a file |
| Brake: freeze, then snapshot | A read-only btrfs filesystem cannot be snapshotted. The order is triage, drop, snapshot, freeze |
| Sub-500 ms, microsecond reaction | Never measured. **Test it** gives the real figure for a host |
| `nfs_export_all_rw` should be off | On by default on the RHEL family, and turning it off can stop exports |
| Each standard has a target Lynis score | The standards set no such score. See Stage 0 |
| Detect stolen credentials from enumeration within 30 seconds | A 6-hourly measurement cannot see that. It would need `vfs_full_audit` and a reporter on the host, so it is a new collector with its own privacy questions |
| Falco installs as a distro package | It comes from its vendor's repository, so it is a catalog entry |
| FastAPI, `doctor.py`, `deployments.py`, `planner.py`, `reports.py` | Flask. None of those modules exist |

### 9.3 What will not be built

| Item | Why |
| :--- | :--- |
| Samba VSS trap | Cannot work (§9.2) |
| Cryptographic shred | Overwriting does nothing on copy-on-write filesystems, and it breaks *nothing is deleted*. Quarantine and restore instead |
| Compliance certificates | A check passing is not a control met. Only an auditor can attest |
| A *SECURE* banner | The panel says *nothing wrong found* only when every host was read in the last day, with a sentinel running, decoys armed and a hold verified |
| WebSocket event stream | The app polls, and alerts carry urgent events. Not worth a second transport |
| SMS and PagerDuty as such | They go through the webhook, ntfy and Gotify channels |

### 9.4 Where security and infrastructure meet

This is the reason to keep them in one plan. Each row is something neither could do alone.

| Together | What it gives | Stage |
| :--- | :--- | :--- |
| Holds and decoys + the map | See which datasets, and so which VMs and containers, have no hold or decoy | 2 |
| Quarantine + exposure engine | One answer to who can reach what, including what a fence blocks | 2 |
| Exempt list + the map | Warn when a hypervisor, DNS server or the controller could be cut off by an armed sentinel | 2 |
| Brake + workload networks | Containment that also covers bridged VMs and containers | 2 tests, 3 fixes |
| Holds + placement advice | Warn at deploy when data lands where no hold or offsite copy reaches | 4 |
| Decoys + volumes | Decoys in container volumes and shares, not only shares | 4 |
| Quarantine + CrowdSec | Bans from either show in one view and reconcile | 5 |
| Clock guard + Chrony with NTS | A catalog entry that fixes what the clock guard complains about | 5 wave 2 |
| Blast radius + workload index | An incident lists the workloads touching affected paths | 7 |
| Clean room + VM deploy | Boot a VM or container from a pre-incident snapshot on an isolated network | 7 |

---

## 10. Proving it

The [KVM lab](docs/kvm-lab.md) is the proving ground, and tests go through the API. Tiers 0 to 8 exist. Add **tier 9: Security** for Stage 0, **tier 10: Infrastructure (read)** for Stages 1 and 2 and **tier 11: Workloads and tools** for Stages 3 to 6.

| Stage | Exit check |
| :--- | :--- |
| **0** | On real ZFS, btrfs, SELinux and AppArmor hosts, through a real signed deploy: hold and release, decoys and a trip, the armed brake down to a real read-only remount, the clean room |
| **0** | `date -s "+30 days"` on a host: the clock guard freezes releases there and alerts. A second host's good reading does not clear it. A slow controller is named as the controller |
| **0** | One admin: release waits out the cool-off and alerts, and can be aborted. Two established admins: the second must approve. The offline key skips the wait once and raises an alarm |
| **0** | A real Samba client trips a decoy: the client is identified and dropped, and an exempt client is not. An NFS client says it cannot be identified |
| **0** | Airgap under real systemd: the rollback timer brings a host back if not confirmed |
| **0** | Encrypt files on a share: blast radius matches what was really changed, and the clean room mounts a pre-incident snapshot that verifies clean |
| **0** | The baseline script on bare Rocky, Ubuntu and openSUSE: report first, packages resolve, and a second run reports `ok` |
| **1** | On each distro: known Docker, rootless Podman, Incus and libvirt workloads all found, with correct mounts, ports and labels. Disk images resolve to their dataset |
| **1** | A lab with `br0`, two VLANs, three VMs, containers, nftables, WireGuard and NFS: every interface, membership, listener, port, peer and mount is on the graph, **nothing invented** |
| **1** | **Passive guarantee:** capture traffic on the lab network during a scan. The only new connection is the SSH session. No ICMP sweep, no port probe, no ARP scan |
| **1** | nftables, firewalld, ufw and iptables-nft give the same rule model. Unreadable says *not readable*, not empty. Alpine, TrueNAS and XCP-ng state which layers are missing |
| **1** | A failed collector degrades one layer and never fails the scan |
| **2** | Publish a container port on a `ufw` host: the map says reachable from the LAN, and names the rule |
| **2** | Unscanned neighbours are dashed placeholders. Promoting one enrolls it and turns its edges solid |
| **2** | Add a listener, stop a container, edit a rule, rescan: the diff is exactly those. The timeline scrubs back |
| **2** | Each export renders. A redacted export holds no IP, hostname or MAC, checked by searching the output |
| **2** | Trip a decoy: does the brake cut bridged-VM and container traffic? Record the answer, fix in 3 if not |
| **3** | Bare VM to working runtime from a plan. Report changes nothing, changed plan gets 409 |
| **3** | A deliberately bad bridge change cuts SSH, and the timer brings it back |
| **3** | A tampered, unsigned or digest-mismatched entry is refused with the reason |
| **3** | Secrets: search `deploy_runs`, plans, logs and every export for a generated secret's value. None |
| **4** | `rocky10`, `debian13` and a cloud image create VMs with the deploy key, scan on first boot, second run is a no-op. Proxmox template boots under nested KVM |
| **4** | No generated VM has a non-loopback console. A template that sets one is flagged, and the export carries the same value |
| **4** | SELinux host: a bind mount without `:Z` fails with an AVC, shown tagged by workload, and the generated fix passes. AppArmor host: a VM in a custom pool path is flagged before it fails |
| **4** | Stage a port's fix: external access stops, loopback still works |
| **5** | Each wave 1 entry on each suitable distro: installs, passes health, recognised by the next scan, uninstalls with data intact, and exposes nothing the plan did not stage |
| **5** | WireGuard between two VMs: handshake, panel shows it, revoking drops traffic |
| **5** | Simulated SSH brute force: CrowdSec's ban appears in the quarantine view and nftables; unban from the GUI |
| **5** | A vulnerable image's finding reaches the workload view and gives a plan that fixes it |
| **5** | restic backup, restore test passes. Corrupt the repo: the test fails loudly |
| **5** | "Private access" deploys in order. A forced failure in step 3 rolls the whole bundle back |
| **5** | Stopping a tool shows *unavailable* and never breaks a scan |
| **6** | A table of allowed and blocked flows, including NAT and bridged VMs, **matches real connection tests** run by the harness, with the probes in the test and never in the product |
| **6** | A step that would cut the SSH path is flagged. After Apply, the next scan agrees with the overlay |
| **6** | Deploy half an intended topology: compare lists exactly the other half |
| **7** | Each plan exports to Terraform, Puppet and Ansible. On a clean host, the result equals the Bash apply, with a no-change second run |
| **7** | Snapshot a running VM and a stateful stack with quiesce, restore into the clean-room network, data matches |
| Any | A synthetic 200-host, 2,000-workload graph stays usable. Run from Stage 2; **results decide** whether to vendor layout or add virtualised rendering |

---

## 11. Data, API and permissions

### 11.1 Tables

Reused and extended: `graph_nodes`, `graph_edges`, `blueprints`, `change_plans`, `deploy_runs`, `deployed`, `alerts`, `audit_log`, `settings`, and the `security_*` tables from migrations 031 and 032, including `security_measurements`. New migrations start at **033**.

| Table | Holds | Backup |
| :--- | :--- | :--- |
| `runtimes` | Host, kind, version, rootless, user, root dir, socket, scanned at | Rebuildable |
| `workloads` | Host, runtime, kind, name, state, image and digest, `managed_by`, last seen | Rebuildable |
| `workload_mounts` | Workload, source, target, kind, mode, dataset | Rebuildable |
| `workload_networks` | Workload, network, MAC, IP, ports, listen address | Rebuildable |
| `workload_security` | Workload, MAC mode and label, privileged, caps, seccomp, user, findings | Rebuildable |
| `workload_adopted` | Adoption, tags, captured definition. **Operator's intent, kept across scans** | Essential |
| `host_network` | Per host: interfaces, routes, firewall model, listeners as JSON, how read, error (as `docker_hosts` does) | Rebuildable |
| `graph_snapshots` | Scan, time, hash, diff. Pruned by `db.prune` | Rebuildable |
| `map_views`, `map_annotations`, `map_manual` | Saved views, notes, manual nodes and links | Essential |
| `workload_templates` | Kind, name, source, parameters, spec, checksum | Essential |
| `catalog_entries`, `catalog_overrides` | **User** entries and per-host overrides; built-ins come from the package | Essential |
| `tool_bundles` | User bundles | Essential |
| `tool_status` | Install ref, checked at, health, version, tiles, error | Rebuildable |
| `vault_secrets` | Name, wrapped DEK, ciphertext, origin, rotated at | Essential |
| `security_waivers` | Finding, reason, approver, expiry (Stage 7) | Essential |
| `security_profiles` | Custom compliance profiles (Stage 7) | Essential |
| `security_retention_policies` | Tier by dataset tag or path, days, grace (Stage 7) | Essential |

`docker_hosts` goes once `runtimes` and `workloads` serve everything it did, including plan checks that warn when a step touches a folder in use.

Designs gain sections for planned networks and workloads under the existing `storageforge/v1` document, or a `v2` with a migration if the shape demands it. Decide in Stage 6.

### 11.2 Routes

In `routes_map.py`, `routes_workloads.py` and `routes_toolbox.py`. **Guarded** means a password typed in the last 5 minutes.

| Method | Endpoint | What | Guarded |
| :--- | :--- | :--- | :---: |
| `GET` | `/api/map?layers=&hosts=&at=` | Graph for layers, hosts and time | No |
| `GET` | `/api/map/node/{id}`, `/api/map/edge/{id}` | Detail, evidence, history | No |
| `GET` | `/api/map/snapshots` | Timeline and diffs | No |
| `GET` | `/api/map/exposure?scope=` | **The one exposure answer** | No |
| `GET` | `/api/map/reach?from=&to=&port=&proto=` | Per-configuration reachability | No |
| `POST` | `/api/map/whatif` | Overlay for a draft plan. Reads only | No |
| `GET` | `/api/map/export?format=&redact=` | Export a view, audited | No |
| `GET, POST, DELETE` | `/api/map/views`, `/api/map/manual` | Saved views, manual nodes | Writes |
| `POST` | `/api/map/placeholders/{id}/promote` | Start enrollment | **Yes** |
| `GET` | `/api/workloads`, `/api/workloads/{id}`, `/api/workloads/drift` | Inventory, detail, drift | No |
| `GET` | `/api/hosts/{host}/runtimes` | Runtimes and preflight | No |
| `POST` | `/api/workloads/{id}/adopt`, `/capture` | Track it, generate a definition. Changes no host | No |
| `POST` | `/api/workloads/stage`, `/api/runtimes/stage` | Stage steps | **Yes** |
| `POST` | `/api/workloads/{id}/action` | Lifecycle, as a step | **Yes** |
| `DELETE` | `/api/workloads/{id}` | Destroy: destructive gate, quorum if held | **Yes** |
| `GET, POST` | `/api/templates` | Templates | Writes |
| `GET` | `/api/toolbox/catalog`, `/{id}`, `/bundles`, `/updates` | Entries, signature state, upgrades | No |
| `POST` | `/api/toolbox/catalog/validate` | Schema, signature, lint | No |
| `POST` | `/api/toolbox/catalog/sign` | Sign a user entry | **Yes** |
| `GET` | `/api/toolbox/installed`, `/{host}/{id}/status`, `/{host}/{id}/actions` | Installs, tiles, actions | No |
| `POST` | `/api/toolbox/stage`, `/bundles/stage`, `/{host}/{id}/actions/{action}` | Stage install, bundle or action | **Yes** |
| `GET` | `/api/changes/{id}/export?target=` | Export a plan. Extends what Changes does | No |

Changes, Deploy and the dry-run 409 are the existing routes, used unchanged. So are the `/api/security/...` routes in `routes_security.py`. Security reads exposure from `/api/map/exposure`, rather than having its own. Adding to them: waivers, profiles and retention policies in Stage 7, all guarded for writes.

### 11.3 Permissions

Added to `permissions.CATALOG`. Applying still takes the existing `deploy.apply` and `deploy.destructive`.

| Permission | Allows | High risk |
| :--- | :--- | :--- |
| `workloads.view` | See runtimes, workloads, templates, the catalog, installed tools | No |
| `workloads.edit` | Adopt, capture, stage workload and tool steps | Yes |
| `map.view` | The map's Network, Services and Workloads layers | No |
| `map.edit` | Saved views, annotations, manual nodes | No |

`security.view`, `security.manage` and `security.emergency` exist and keep their meaning. **Firewall rules, exposure and reach need `security.view`,** since they say how to get in. Writing or signing a custom catalog entry takes `hosts.command`, because it is root by another name.

---

## 12. Decisions to confirm

The drafts ended with 18 open questions, and the security merge adds two. Each has a recommendation, which this plan assumes, so **saying nothing means yes.** The ones in the first table are worth a real look; they change what gets built or who it is for.

| Decision | Recommendation | Why, and what changes otherwise |
| :--- | :--- | :--- |
| **How much of this belongs in StorageForge?** | Build through Stage 2 and release, then decide on 3 onwards from how it is used | Stages 1 and 2 extend the product's identity. Stages 3 to 5 make it a deploy platform, a bigger commitment to maintain: every catalog entry is software to keep current |
| **Wave 1 tools** | As in §8.4 | Add or swap freely. This is where users' needs should overrule the plan |
| **Privileged reads** | Through measurement, on any host with deploy access, with a per-host off switch | Firewall rules are sensitive. If it should be opt-in instead, the map starts emptier on existing hosts |
| **Connection data** (`ss` established) | Collect only on storage ports (445, 139, 2049), as counts and client addresses, for the share client view. Nothing else: use config and neighbours | Less inference, much less sensitive data. Revisit if cross-host edges come out too thin |
| **Identity anomaly detection** | Leave it out for now | It takes a new collector on each host that logs who opened what. If it matters to you, it moves up to Stage 7 and needs its own design |
| **Compliance thresholds** | Keep them as StorageForge's suggestions, clearly labelled and changeable | Dropping them leaves plainer readings. Keeping them unlabelled implies the standards demand those numbers, which they do not |

The rest:

| Question | Recommendation |
| :--- | :--- |
| Rendering | Own SVG and DOM, vendor ELK only if tests demand it (§6.1) |
| Switch and router data | Linux hosts only for now; manual nodes cover the rest. SNMP and LLDP later |
| Links on manual nodes | Yes: a URL and a free-text field. Cheap |
| Live status | "Last read N minutes ago" is enough. No health polling |
| Incus or LXD | Lifecycle on Incus; LXD and plain LXC read-only |
| Terraform or OpenTofu | Neutral HCL, tested with OpenTofu |
| Docker TCP and remote contexts | SSH only. No new listeners |
| Panel overlap | Warn and mark *externally managed* |
| Windows guests | Later. The ISO path allows it; virtio and unattended setup are not in Stage 4 |
| Catalog trust | Built-ins by package, user entries by operator key (§8.2) |
| Own panel or link | Link plus tiles where a tool has a good UI. Panels only for WireGuard, Caddy, restic and Trivy |
| Catalog hosting | In the package, updated with releases. A signed remote index only if entries must move faster than releases |
| Windows and macOS VPN clients | Standard config files and QR codes, no installers |
| Licensing | Prefer open licences: OpenBao over Vault. Teleport and Boundary stay out until asked for and reviewed |
| SIEM | Link to Wazuh or Graylog. Suricata and Falco alerts go through existing alerts, no new viewer |
| Log grabber and querying | Vector or Promtail (grabber), Loki or VictoriaLogs (querier) via Grafana; Dozzle for container logs | StorageForge stays agentless and builds no log viewer. The catalog packages shippers with read-only host log mounts pointing to a query backend. Bounded diagnostic log grabs (journald slices) remain limited to incident triage measurements |

---

## 13. Risks

| Risk | What keeps it in check |
| :--- | :--- |
| **Repeating the mock-up.** Scope this wide tempts UI first and hosts later | Definition of done (§2). Stages 1 and 2 are facts before any panel acts. Each stage has lab checks |
| **Wrong answers about exposure.** A false "not reachable" is worse than no feature | `unknown` not `closed`, *per configuration* everywhere, blind spots listed, and Stage 6 proved against real connections |
| **StorageForge locks itself out** of a host through a bridge or firewall change | Rollback timers (proved in Stage 0), and what-if blocks steps that cut the SSH path |
| **More root on more hosts.** A wider catalog is a wider supply chain | Pinned digests, risk labels, downloads visible in the script, custom entries gated by `hosts.command`, loopback by default |
| **Catalog rot.** Tools change; pinned entries age | Small wave 1, a *not lab-tested* label, CI checks of checksums, a scheduled upgrade report |
| **Sensitive data concentrated in one index.** Firewall rules and topology are a map for an attacker | `security.view` on those layers, redacted exports, no secrets or arguments collected, and audit |
| **Scan time and load.** More collectors on every scan | Short read-only commands, each with a timeout. Privileged reads move to measurement |
| **An armed sentinel cuts off the wrong client,** or freezes a share over one touched file | It starts disarmed, has an exempt list, and the map warns about infrastructure not on that list |
| **Security work assumed to work.** It has never been through the lab, and the first version was fake | Stage 0 comes before anything builds on it |
| **Scope eats the core.** Storage features stall | The test in §1, a release at Stage 2, and the decision there about continuing |

---

## Appendix A: Where each draft phase went

| Draft phase | Stage | Notes |
| :--- | :--- | :--- |
| **W1** Docker and Podman scan and import | 1, 2 | Adopt and capture in 2 |
| **W2** LXC, Incus, libvirt scan, drift | 1, 2 | Adds Proxmox read-only. Drift merged with M5 |
| **W3** Runtime install, pool and network definitions | 3 | |
| **W4** VM templates and deploy | 4 | |
| **W5** Container, stack, LXC deploy | 4 | |
| **W6** Panel catalog | 3 (engine), 5 (entries) | Merged with T1 |
| **W7** IaC export | Each stage (Bash, Ansible), 2 (native), 7 (Terraform, Puppet) | Ansible already exists |
| **W8** Security integration | 2, 3, 4, 7 | Spread across stages, §5.2 |
| **W9** Fleet and Kubernetes | Later | |
| **M1** Network layer | 1 (facts), 2 (view) | |
| **M2** Services and Firewall layers | 1 (facts), 2 (exposure) | |
| **M3** Containers and VMs layers | 2 | Draws W1 and W2 data |
| **M4** Map UI foundations | 2 | PDF is print-to-PDF |
| **M5** Placeholders, manual nodes, change tracking | 2 | |
| **M6** Path query and what-if | 6 | |
| **M7** Access and Security layers | 5 | |
| **M8** Design mode | 6 | Extends designs, no new table |
| **M9** Scale and integrations | Later | Scale is tested from Stage 2 |
| **T1** Catalog engine | 3 | Merged with W6 |
| **T2** Adapters and GUI levels | 5 | Runs in measurement |
| **T3** Access layer | 5, wave 2 | WireGuard, Caddy first |
| **T4** Defense tools | 5, wave 2 | CrowdSec, Trivy first |
| **T5** Monitoring | 5, wave 2 | Disk health already exists |
| **T6** Backup and restore tests | 5 | |
| **T7** Zero trust and secrets | Later | The secret store itself moves up to Stage 3 |
| **T8** Bundles and role profiles | 5 | Tile dashboards later |
| **T9** Provisioning and platform | Later | |

Also new, in no draft: lab run and CI (Stage 0), the secret store and firewall writer (Stage 3), the Proxmox adapter (Stage 1), and new permissions.

---

## Appendix B: Where each security phase went

| Old roadmap phase | Status | Rest goes to |
| :--- | :--- | :--- |
| **1** WORM, clock guard, quorum | Built, not lab-tested | 0 (test), 7 (tiers, freeze, preview), Later (FIDO2, heatmap) |
| **2** Decoys, VSS traps, auditd | Built, except VSS, which cannot work | 0, Later (personas, fanotify) |
| **3** MAC, credential anomalies | MAC built. Anomalies not built | 0, 3 (booleans as steps), 7 (AVC filter), Later (anomalies, editors) |
| **4** Firewall and fencing | Quarantine and airgap built. Fencing and multi-backend not | 0, 2 (client view), 3 (writer, fencing), 7 (ban tiers) |
| **5** Falco and entropy | Entropy and change rate built. Falco rules not | 0, 7 (thresholds), Later (Falco) |
| **6** AIDE and Lynis | Built, except staging findings and waivers | 0, 3 (findings), 7 (waivers), Later (role profiles) |
| **7** Malware and YARA | ClamAV, quarantine and restore built. YARA not. Shred dropped | 7 (YARA) |
| **8** Packages and compliance | Packages and readings built. Bundles and waivers not. Certificates dropped | 0 (thresholds), 7 (waivers, profiles, drift), Later (bundles) |
| **9** SOC, triage, clean room | Overview, triage, blast radius and clean room built. Playbooks and export not | 0, 7 (workloads, export), Later (playbooks, dashboards) |
