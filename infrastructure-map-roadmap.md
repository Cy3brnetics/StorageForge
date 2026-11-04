# Infrastructure Map: Layered Topology for Networks, Firewalls, Containers & VMs

A roadmap for extending the StorageForge topology and canvas from a **storage graph** (Host → Pool → Filesystem → Mount → Symlink) into a **full infrastructure map**: networking, firewalls, containers, VMs, VPNs, panels and the security controls around them. It is drawn from what the managed hosts actually report, and it doubles as the planning surface for deployments.

It builds on the existing graph (`graph.py`, `canvas.py`) and planner topology, and it is the visual layer for [Workload Platform Roadmap](workload-platform-roadmap.md), [Toolbox Catalog Roadmap](toolbox-catalog-roadmap.md) and [Ransomware Defense Roadmap](ransomware-defense-roadmap.md).

Status: **planned**. Nothing here is built yet.

---

## 1. Goals and Non-Goals

### 1.1 Goals
1. **One map, many layers**: switch between Storage (today), Network, Firewall, Workloads, Access (VPN/zero trust) and Security, or stack several at once.
2. **Built from hosts we are told to scan**, not from network sweeps. Because StorageForge has authenticated system access (SSH, read-only), it reports far more than a scanner can see: interfaces, bridges, VLANs, routes, firewall rulesets, listening sockets with owning processes, container and VM networks, MAC labels.
3. **Passive only**: the map never sends probe traffic. No nmap, ping sweeps, ARP scans or port scans. Everything comes from reading host state.
4. **Planning surface**: any node or edge can start a plan (add a container, open a port, create a bridge, attach a VM NIC). A **what-if overlay** previews the change on the map before the Report and Apply.
5. **Explainability**: click any edge to see *why* it exists and which host reported it (interface, rule, socket, mount, label).
6. **Customizable and exportable**: saved views, filters, layouts, annotations; export as SVG/PNG/PDF, Mermaid, draw.io and JSON.

### 1.2 Non-Goals
- No active discovery of devices StorageForge has no access to. Unscanned devices appear only as **inferred placeholders** (see §4.3) that the operator can promote to a managed host.
- No live packet capture, flow collection or traffic probing by default. Optional flow data from sources the hosts already keep (conntrack counters, nftables counters, interface byte counts) is read passively and shown as coarse activity, not as a monitoring product.
- Not a replacement for NetBox/CMDB. It can export to them later (§9).

### 1.3 How this differs from probe-based mappers
Tools like [Homelable](https://github.com/Pouzor/homelable) combine a hand-drawn canvas with network scanning (nmap needs `NET_RAW`) and live status checks. This map inverts that: nothing is drawn from a scan of the wire. The graph is derived from hosts the operator enrolled, so it has exact interface, rule and process detail, and nothing here probes the network. Operators can still place manual nodes for gear without access (switches, ISP modem, IoT).

---

## 2. Principles

| Principle | Meaning |
| :--- | :--- |
| **Derived, not drawn** | The graph is rebuilt from scan data. Layout and annotations are the operator's, the facts are the host's. |
| **Passive** | Reads host state over the existing single SSH session. No probes, no listeners. |
| **Evidence on every edge** | Each edge stores `source_host`, `source_kind` (interface, rule, socket, mount, label), `observed_at`, and a confidence level. |
| **Honest uncertainty** | Inferred links (§4.3) are drawn dashed and labelled. Confirmed links are solid. |
| **Plan from the map** | Selecting nodes offers valid actions as staged plan steps with a Report. |
| **Safe to share** | Exports can redact IPs, hostnames, MACs and secrets. Env values are never collected. |

---

## 3. Layers

Each layer adds node kinds and edge kinds to the existing graph. Layers can be shown singly, combined or filtered per view.

### 3.1 Layer catalogue
| Layer | Nodes | Edges | Main sources (read-only) |
| :--- | :--- | :--- | :--- |
| **Storage** (exists) | Host, StoragePool, Filesystem, MountPoint, Symlink | CONTAINS, MOUNTED_AT, SYMLINK_TO, REPLICATES_TO | existing scan |
| **Network** | NIC, Bond, Bridge, VLAN, Subnet, Gateway, Route, DNS, DHCP scope | ATTACHED_TO, MEMBER_OF, TAGGED, ROUTES_VIA, RESOLVES_VIA | `ip -j addr/link/route/neigh`, `bridge vlan`, networkd/NetworkManager/netplan files, `resolv.conf`, `/etc/hosts` |
| **Firewall** | FirewallPolicy, Chain/Zone, Rule (grouped), NAT mapping, Fence set | APPLIES_TO, ALLOWS, DENIES, FORWARDS, NATS_TO | `nft list ruleset -j`, `firewall-cmd`, `ufw status verbose`, `iptables-save`, libvirt `nwfilter`, Docker/Podman chains |
| **Services** | Listener (port + process), Unit, Share (SMB/NFS) | LISTENS_ON, EXPOSES, SERVED_BY, CLIENT_OF | `ss -tulpn`, systemd units, Samba/NFS config, existing share data |
| **Containers** | Runtime, Container, Pod, Stack, ContainerNetwork, Volume | RUNS_ON, MEMBER_OF, ATTACHED_TO, PUBLISHES, MOUNTS | Docker/Podman/Incus inspect output (see workload roadmap) |
| **VMs** | Hypervisor, VM, VirtualNetwork, VirtualDisk, Pool | RUNS_ON, ATTACHED_TO, BACKED_BY | `virsh dumpxml`, pools and networks, Incus VM config |
| **Access** (VPN / zero trust) | VPNNetwork, Peer, Route, Gateway, IdentityProvider, Proxy route | PEERS_WITH, ROUTES_THROUGH, AUTHENTICATES, FRONTS | `wg show`, Headscale/NetBird/Tailscale JSON, Caddy/Traefik config, tool adapters |
| **Security** | MACStatus, Canary, WORMHold, Quarantine entry, Finding | CONFINES, GUARDS, HOLDS, BLOCKS, AFFECTS | existing security panels, Lynis/AIDE/CVE data |
| **Panels & Tools** | Panel, Tool (catalog entry), HealthCheck | MANAGES, DEPLOYED_BY, MONITORS | catalog installs and adapters |

### 3.2 What the map shows for key objects
- **Host card**: OS, role, scan age, runtimes present, firewall backend, MAC mode, VPN membership, deploy-readiness.
- **Interface node**: IPs, MAC, MTU, state, speed, driver, VLAN tags, bridge membership, byte counters (delta between scans).
- **Firewall node**: backend, default policies, counts by chain, a grouped summary of rules by purpose (management, shares, published container ports, VPN). Expanding shows exact rules in order, with the one that matches a selected flow highlighted.
- **Listener node**: port, protocol, bind address, owning process and unit, and an **exposure badge** (loopback / management network / LAN / any address) calculated against the host's firewall.
- **Container/VM node**: state, image or template, resources, mounts to datasets, networks, published ports, security context.
- **Edge detail**: type, evidence, observed time, last change.

---

## 4. Derivation Engine

### 4.1 Collection (passive)
Extends the existing single-session scan with read-only commands: `ip -j`, `bridge`, `nft -j list ruleset` (or the backend's equivalent), `ss -H -tulpn`, `ss -H -tnp state established` summary (counts and remote endpoints only, optional), libvirt/Docker/Podman/Incus inspect JSON, `wg show` and VPN tool JSON, systemd unit lists. A failed command degrades that layer for that host, and it never fails the scan.

- **Privilege**: most reads work as the scan user. Some need extra access (`nft list ruleset` needs root or `CAP_NET_ADMIN`). The existing read-only-access mechanism is extended with a narrow, audited capability profile for these commands. Without it, the layer shows "not readable" rather than guessing.
- **No outbound traffic**: the scan never contacts third parties or other hosts on the operator's behalf.
- **Privacy**: collect process names and unit names, not command-line arguments (they can hold secrets). Container env values are excluded.

### 4.2 Link resolution (how edges are built)
1. **Intra-host (certain)**: interface → bridge → VM/container NIC, mount → dataset, listener → process, rule → interface.
2. **Cross-host by address (confirmed)**: host A's established connection or share mount names an IP that is an interface address of host B, which StorageForge also scans.
3. **Cross-host by configuration (confirmed)**: NFS/SMB client entries, WireGuard peer public keys that match another host's key, route next-hops that match another host's address, DNS and gateway entries.
4. **Same segment (inferred)**: two hosts with addresses in one subnet and the same gateway or VLAN are placed in one segment.
5. **Neighbour tables (inferred)**: `ip neigh` entries show devices a scanned host has talked to recently. These become placeholders, never full nodes.

### 4.3 Placeholders for unscanned things
Unscanned devices seen only as a gateway, a neighbour or a peer endpoint appear as **placeholder nodes**: dashed outline, with what is known (IP, MAC vendor, how it was seen) and a **Promote to host** action, which opens the enrollment flow. Operators can also place **manual nodes** (switch, modem, access point, IoT) and manual links, marked as "manual, not verified".

### 4.4 Change tracking
Each scan produces a graph snapshot diff: new/removed nodes and edges, changed firewall rules, new listeners, containers that appeared, address changes. This feeds a **Timeline** (scrub the map back to a previous scan), drift alerts, and the security panels ("a new listener appeared on `0.0.0.0:2375`").

---

## 5. The Map UI

### 5.1 Views and layout
- **Modes**: *Network* (L2/L3 segments and routing), *Flow* (what can reach what), *Workloads* (hosts with their VMs and containers nested), *Storage* (today's view), *Security*, and *Custom*.
- **Nesting**: a host is an expandable container holding its bridges, VMs and containers, and zooming in reveals interfaces, ports and mounts (semantic zoom, with detail hidden at low zoom to stay readable).
- **Auto layout**: layered hierarchy for network, force-directed for loose topologies, rack/grid for hardware. The operator can drag nodes and **pin** them, and positions persist per view.
- **Grouping**: by site, VLAN, subnet, role, tag, or runtime. Collapsed groups show an aggregate health.
- **Large fleets**: virtualised rendering, edge bundling, and "focus + context" (select a node to dim the rest).

### 5.2 Interaction
- **Hover trace** (as the planner topology does today): highlights the full path from drive to share to client, or from client to firewall rule to listener to container.
- **Path query**: pick two nodes and ask "can A reach B?" It evaluates the **observed rulesets and routes** and shows the first rule that allows or blocks it. This is analysis of configuration, not a probe. The result is labelled "per configuration" and notes anything it cannot model (for example a firewall on an unscanned device in the path).
- **Exposure view**: one click shades every listener by who can reach it, so "what is reachable from the LAN / the VPN / the internet gateway" is a single filter.
- **Badges and colouring**: health and 3-2-1 protection (existing), MAC status, immutable lock, canary, quarantine, drift, update-available, CVE count. Activity pulses use byte-counter deltas between scans, never live probing.
- **Context menus**: per node type, offering inspect, open its panel, **stage a plan step** (below), copy exports, pin, annotate.
- **Search and filter**: by name, IP, port, tag, layer, health and "changed since".
- **Annotations**: sticky notes, labels, regions and a free-text description per node (stored with the design, kept across scans).

### 5.3 Customization
- **Saved views** (layers, filters, grouping, layout, zoom) with sharing and per-role defaults.
- **Custom node icons and colour rules** ("colour containers by compose project", "highlight anything on VLAN 20").
- **Legend and theme controls**, light and dark, accessibility-safe palettes, and print layouts.
- **Dashboards**: embed a map view as a tile in the custom dashboards from the ransomware roadmap.
- **Deep links**: `/#view=network&host=gw-01`, `/#view=flow&from=nas-01&to=vm-web01`, `/#view=workloads&host=hv-01`, `/#view=security&filter=exposed`.

### 5.4 Exports
SVG, PNG, PDF (with legend and scan timestamps), Mermaid and Graphviz DOT (for docs), draw.io XML, and JSON (the graph model, for scripts). Redaction presets: hide IPs, hide hostnames, hide MACs, generic labels.

---

## 6. Planning From the Map

The map is where plans start, using the same Plan → Report → Apply flow.

### 6.1 Stage actions by node
| Select | Offered actions (each becomes a plan step) |
| :--- | :--- |
| Empty space on a host | Deploy a container, stack, VM, LXC instance or catalog tool here |
| NIC / bridge | Create bridge or VLAN, attach VM/container, change MTU (with the lockout-safe rollback timer) |
| Listener | Restrict bind address, add or tighten a firewall rule, put it behind the reverse proxy, close it |
| Firewall node | Add allow/deny, fence to a subnet, open a published port, move a rule, show impact |
| Edge (A→B) | "Allow A to reach B on port N", "Remove this exposure", "Add a VPN route" |
| Container / VM | Move to another host, change network, snapshot, clone, resize, stop, remove (destructive gate) |
| VPN peer | Add, revoke, rotate key, change allowed routes |
| Placeholder | Promote to managed host |

### 6.2 What-if overlay
Staging a step draws a **ghost layer** on the map: new nodes and edges in outline, removed ones struck through, changed firewall rules highlighted. The overlay includes:
- **Reachability diff**: which paths become allowed or blocked.
- **Exposure diff**: new listeners and the networks that can reach them.
- **Conflict checks**: duplicate IPs, port clashes, a bridge change that would cut the SSH path StorageForge itself uses (blocked unless a rollback timer is staged), a firewall change that would lock out the VPN.
- **Placement hints**: capacity, dataset suitability and snapshot/WORM coverage for the target host (reusing the storage-aware placement advice).

Because it is analysis of configuration, the overlay clearly states its limits, and the Report remains the source of truth before Apply.

### 6.3 Design mode
Operators can build an **intended topology** on a blank canvas (hosts not yet deployed, planned VLANs, planned VMs), save it as a design (as the planner already does for storage), and **compare intended vs actual** after deploys. A diff shows what is missing, extra or different. Designs export as Bash, Terraform, Puppet or Ansible through the plan exporters.

### 6.4 After Apply
After an Apply, the next scan updates the map, the diff confirms the change landed, and drift later shows if it changed again. Plans and map snapshots link in both directions.

---

## 7. Security and Safety

1. **Read-only by construction**: collectors are an allowlist of commands. They run through the existing scan session and never modify state.
2. **No wire probing**: the map code contains no scanner. Tests check that a scan opens no connections other than the SSH session.
3. **Sensitive data**: firewall rules, IPs and topology are sensitive. The map follows existing login and role rules, redacted exports are one click, and shared links need authentication.
4. **Rule-evaluation honesty**: path queries only claim what the scanned configuration shows and list their blind spots.
5. **No secret collection**: process arguments, environment values, VPN private keys and tokens are never read. Public keys and fingerprints only.
6. **Audit**: map exports, redaction use and staged actions are written to the hash-chained audit log.
7. **Placeholder safety**: a promoted host still requires the normal enrollment, key binding and consent steps.

---

## 8. Data Model & API

### 8.1 Graph model extension
Reuses the graph's `KINDS`/`RELS` pattern, adding kinds and relations per layer (§3.1). Every node and edge carries `layer`, `host`, `evidence_json`, `confidence` (`certain`/`confirmed`/`inferred`/`manual`), `first_seen`, `last_seen`.

### 8.2 Tables
- **`map_nodes`**: `id`, `kind`, `layer`, `host_name`, `label`, `attrs_json`, `confidence`, `first_seen`, `last_seen`, `placeholder`.
- **`map_edges`**: `id`, `kind`, `layer`, `src`, `dst`, `evidence_json`, `confidence`, `first_seen`, `last_seen`.
- **`map_snapshots`**: `id`, `scan_id`, `taken_at`, `graph_hash`, `diff_json` (versus the previous snapshot).
- **`map_views`**: `id`, `name`, `owner`, `layers_json`, `filters_json`, `grouping_json`, `layout_json`, `shared`.
- **`map_annotations`**: `id`, `view_id`, `target` (node/edge/region), `text`, `style_json`.
- **`map_manual`**: `id`, `kind`, `label`, `attrs_json`, `links_json` for manual nodes and links.
- **`map_designs`**: `id`, `name`, `graph_json`, `compared_at` for intended topologies.

### 8.3 Endpoints (`/api/map/...`)
| Method | Endpoint | Description | Guarded |
| :--- | :--- | :--- | :---: |
| `GET` | `/api/map?layers=&hosts=&at=` | Graph (nodes and edges) for chosen layers, hosts and snapshot time | No |
| `GET` | `/api/map/node/{id}` | Node detail, evidence and linked panels | No |
| `GET` | `/api/map/edge/{id}` | Edge evidence and history | No |
| `GET` | `/api/map/snapshots` | Snapshot list and diffs | No |
| `GET` | `/api/map/reach?from=&to=&port=&proto=` | Per-configuration reachability and the deciding rule | No |
| `GET` | `/api/map/exposure?scope=lan\|vpn\|any` | Listeners reachable from a scope | No |
| `POST` | `/api/map/whatif` | Overlay result for a draft plan (new/removed nodes, reach and exposure diffs, conflicts) | No |
| `POST` | `/api/map/placeholders/{id}/promote` | Start enrollment for a placeholder | **Yes** |
| `GET/POST/DELETE` | `/api/map/views` | Saved views | Yes for writes |
| `POST/DELETE` | `/api/map/manual` | Manual nodes and links | **Yes** |
| `GET` | `/api/map/export?format=svg\|png\|pdf\|mermaid\|dot\|drawio\|json&redact=` | Export a view | No |
| `GET/POST` | `/api/map/designs` and `/compare` | Intended topologies and diffs against actual | Yes for writes |

---

## 9. Delivery Phases

| Phase | Deliverables | Modules touched | Estimated effort |
| :--- | :--- | :--- | :---: |
| **M1** | **Network layer**<br>• Collect interfaces, bridges, VLANs, routes, DNS<br>• Intra-host and cross-host (address, config) link resolution<br>• Network view with auto layout, grouping, evidence popovers | `scanner.py`<br>`graph.py`<br>`canvas.py`<br>new `netmap.py` | **6–7 days** |
| **M2** | **Services and Firewall layers**<br>• Listeners with owning process<br>• Backend-agnostic ruleset parser (nftables, firewalld, ufw, iptables)<br>• Exposure badges and the exposure view | `scanner.py`<br>`shares.py`<br>`preflight.py` | **6–8 days** |
| **M3** | **Containers and VMs layers**<br>• Runtime and hypervisor nodes nested in hosts<br>• Container, bridge and VM networks, published ports, disks to datasets<br>• Workloads view | `docker.py` / `runtimes/`<br>`graph.py`<br>`canvas.py` | **5–6 days** |
| **M4** | **Map UI foundations**<br>• Semantic zoom, nesting, pinning, saved views<br>• Search, filters, annotations, legend, themes<br>• Exports (SVG/PNG/PDF/Mermaid/DOT/draw.io/JSON), redaction | web UI (`web-ui.md`)<br>`reports.py` | **7–8 days** |
| **M5** | **Placeholders, manual nodes and change tracking**<br>• Inferred placeholders and Promote to host<br>• Manual nodes and links<br>• Snapshot diffs, Timeline, drift alerts | `graph.py`<br>`changes.py`<br>`alerts.py` | **5–6 days** |
| **M6** | **Path query and what-if overlay**<br>• Rule and route evaluator with stated blind spots<br>• Ghost layer, reachability and exposure diffs, conflict checks<br>• Plan actions from the map (§6.1) | `planner.py`<br>`deploy.py`<br>`preflight.py` | **8–10 days** |
| **M7** | **Access and Security layers**<br>• VPN peers and routes, proxy routes, identity providers<br>• MAC, canary, WORM, quarantine and finding badges<br>• Security view with exposure filter | tool adapters<br>security panels | **5–6 days** |
| **M8** | **Design mode**<br>• Intended topologies, intended vs actual diff<br>• Export designs through the Bash/Terraform/Puppet/Ansible exporters | `fromdesign.py`<br>`blueprint.py`<br>`iac/` | **6–7 days** |
| **M9 (later)** | **Scale and integrations**<br>• Multi-site grouping, very large graph performance<br>• Optional exports to NetBox and Grafana panels | TBD | **TBD** |

Dependencies: M3 needs the runtime adapters from workload roadmap W1–W2. M6's plan actions need the plan step types from W3–W5. M7 needs the toolbox adapters (T2 onwards) and the security panels from the ransomware roadmap.

---

## 10. Verification (KVM Lab Gauntlet)

1. **Fidelity**: build a known lab (bridge `br0`, two VLANs, three VMs, Docker and Podman containers, nftables rules, a WireGuard tunnel, an NFS share). The generated map matches the known topology: every interface, bridge membership, listener, published port, peer and mount present, and nothing invented.
2. **Passive guarantee**: capture traffic on the lab network during a scan and confirm the only new connection is the SSH session from the server. No ICMP sweeps, no port probes, no ARP scans.
3. **Distro matrix**: network, firewall and listener collection works on Debian, Ubuntu, Fedora, Rocky, Alma, openSUSE and Arch. Alpine is partial (no bash or systemd), and the map says which layers are missing.
4. **Firewall backends**: nftables, firewalld, ufw and iptables-nft hosts all yield the same grouped rule model, and unreadable rulesets show "not readable" rather than empty.
5. **Exposure accuracy**: publish a container port on a host with `ufw`. The map shows it reachable from the LAN though `ufw` looks like it blocks it, and the staged fix flips the badge.
6. **Reachability evaluation**: a table of allowed and blocked flows (including NAT and bridge-forwarded VM traffic) matches real connection tests run by the lab harness.
7. **Inference honesty**: unscanned neighbours appear dashed as placeholders, never as confirmed nodes. Promoting one enrolls it and changes the edges to confirmed.
8. **Change tracking**: add a listener, stop a container, edit a rule, then rescan. The diff shows exactly those changes, and the timeline scrubs back correctly.
9. **What-if**: a staged step that would cut the SSH management path is flagged. A staged rule shows its reachability diff, and after Apply the next scan agrees with the overlay.
10. **Design compare**: deploy half of an intended topology. The compare view lists exactly the missing half.
11. **Exports**: each format renders, and the redacted export contains no IPs, hostnames or MACs.
12. **Scale**: a synthetic fleet of 200 hosts and 2,000 workloads stays interactive with semantic zoom and virtualised rendering.

---

## 11. Open Questions

1. **Rendering stack**: extend the current canvas, or move to a graph library (Cytoscape.js, React Flow, or D3 with ELK layout) for nesting and large graphs?
2. **Privileged reads**: is a narrow capability profile for `nft list ruleset` and `ss -p` acceptable by default, or opt-in per host?
3. **Established-connection data**: store only counts, or keep remote endpoints to help cross-host inference? (Recommendation: store them short-term, hashed in snapshots.)
4. **Switch and router data**: add read-only SNMP, LLDP and `lldpd` neighbour reading for gear we are told to scan, or keep it Linux hosts only?
5. **Manual nodes**: should they accept links to external documentation or inventory (asset tags, rack positions)?
6. **Live status**: is "last scanned N minutes ago" enough, or should services get an opt-in, passive health check that reads each tool's own status API?
