# Infrastructure map

The **Map** view: networks, firewalls, listeners, containers, VMs and VPNs across your hosts, drawn from what those hosts report. The **Infra** panel holds the same facts as lists. A plan is [the roadmap](../infrastructure-platform-roadmap.md); this page is what exists.

## How it knows

Nothing sends a packet to find out what exists. There is no scanner in here, by design.

| Fact | Read by | Needs root |
| :--- | :--- | :--- |
| Interfaces, addresses, routes, neighbours, bridges, DNS, listeners | The scan, as the scan user | No |
| Firewall rules, which process owns a listener, clients on storage ports | A signed read-only **measurement**, every 6 hours or when you ask | Yes |
| libvirt, Incus, LXC, Proxmox guests, other users' rootless Podman | The same measurement | Yes |
| WireGuard public keys and peers, Tailscale, proxy sites and upstreams | The same measurement. Never a private key, a preshared key or a password | Yes |
| Docker and Podman containers | The scan | Depends on the host |

A host with no deploy access gets the unprivileged layers, and says what it could not read. A command that fails makes that part **not readable**, which never reads as empty. Alpine, TrueNAS and XCP-ng say which layers they are missing. Turn the measurement off for one host through `POST /api/infra/settings`.

Every node and line says how it is known:

| Shown | Means |
| :--- | :--- |
| Solid | **Certain:** read on this host. **Confirmed:** across hosts, because an address or public key matches |
| Dashed | **Inferred:** the same subnet, or an entry in a neighbour table. Unscanned devices are placeholders, never hosts |
| Long dashes | **Placed by hand,** and never confirmed by a scan |

Select anything to see the evidence: which host said so, and from which command.

## Who can reach a port

The exposure engine works from the bind address, then the firewall, then Docker's NAT, then which of the host's networks can reach it. It reads nftables, firewalld, ufw and iptables into one model.

| Level | Means |
| :--- | :--- |
| This machine only | Bound to loopback |
| Blocked | The firewall drops it from every network this host is on |
| VPN only, Private networks, Any address | Who can reach it, widest network first |
| Unknown | Could not be worked out, and it says why |

A wrong "not reachable" is worse than no answer, so unreadable rules and rules it could not understand give **Unknown**, and never **Blocked**. A published Docker port goes through the forward chains, which is why ufw does not stop it, and the map shows that with the rule that decides.

**Can A reach B?** walks a packet's path: out of A, across anything between, into B, naming the first rule that decides it. It is worked out from the configuration and tested against nothing: anything between hosts that was not scanned is listed as a blind spot.

## Planning from it

Select something and stage a step. The **What this would do** panel draws it on the map, in outline, before anything is saved:

- Which listeners become reachable from further, or less far.
- Duplicate addresses and port clashes.
- Anything that would cut StorageForge's own SSH path. That counts as blocked unless a rollback timer is staged.

Then **Stage in Changes**, where it is an ordinary step with a Report and an Apply. The overlay is analysis of configuration, and the Report on the host has the last word.

| Step | Does |
| :--- | :--- |
| `fw-rule` | A rule in whichever firewall the host runs, so that firewall still lists it. `forward` is for published ports: it goes in `DOCKER-USER` |
| `fw-fence` | Only these clients may reach these ports, in a table ahead of any other firewall |
| `net-bridge`, `net-vlan`, `net-mtu` | With NetworkManager or systemd-networkd |
| `wg-peer` | Add or revoke a WireGuard peer |
| `container` | `docker run` or `podman run` with a fixed name. It will not replace an existing container |
| `vm` | `virt-install --import` from a disk you already have, with its console on loopback |
| `workload-action`, `workload-remove` | Start, stop, restart, snapshot. Removing keeps volumes and disks, and takes `--destructive` |

A step that could cut StorageForge off can carry a rollback timer. The script journals how to undo it and starts a systemd timer. Only a second signed run stops that timer, and that can only happen if the path still works.

## Designs

A design is what should be there: hosts, bridges, VLANs, containers, VMs and rules. **Compare** lists what is missing, what differs, and what is there that it does not name, against what scans found. What has not been read is **not known**, and is not counted as missing. **Stage what is missing** turns the gap into a plan.

Exports go one way: nothing is read back from a script. Bash and Ansible come from that plan. Terraform (`kreuzwerker/docker`, `dmacvicar/libvirt`) and Puppet (`puppetlabs-docker`, `puppetlabs-firewall`) are for your own pipeline, and StorageForge never runs them.

## On the map

- **Modes:** Network, Flow, Workloads, Storage, Security, Custom. Layers can be stacked.
- **Grouping:** by host, subnet or runtime. Double-click a frame to shut it. Far out, frames stay and their rows go.
- **Saved views** keep layers, filter, grouping and where you dragged things.
- **Timeline:** go back to an earlier reading. Storage is not kept: it shows the other layers as they stood.
- **Security mode** shows who can reach what, holds and decoys on mounts, and workloads no hold or decoy reaches. It warns when an armed sentinel could cut off a gateway, DNS server or hypervisor that is not on the exempt list.
- **Exports:** JSON, Mermaid, DOT, SVG, draw.io, Obsidian canvas, PNG, and PDF through the browser's print. Redacting them hides addresses, host names and MACs, and each export is audited.
- **Links:** `/#view=map&layers=network,firewall&mode=security`.

Firewall rules and exposure say how to get in, so they need `security.view`. The map itself needs `map.view`.

## Not built

The roadmap goes further than this.

- Deploying a stack, an LXC instance or a catalog tool from the map, or a VM from an ISO or cloud image. Those are the Workload Platform and Toolbox roadmaps.
- From the map: moving, cloning or resizing a VM, restricting a service's bind address, putting a listener behind a proxy, rotating a peer's key.
- `bridge`-family firewall rules for bridged VMs. A quarantine has `input` and `forward` hooks, and bridged VMs bypass both: the map says a bridged VM is outside host rules.
- Reading a rich firewalld rule beyond source, port and verdict. The others stay unmodelled, which gives **Unknown**.
- Reading netplan, NetworkManager or networkd files: what the kernel has is what is read. DHCP scopes as nodes, and activity from byte counters between scans.
- Force-directed and rack layouts, custom icons and colour rules, per-role default views, and map tiles on dashboards.
- Rendering for very large fleets, NetBox and Grafana exports, SNMP and LLDP.

## What has been tested, and how

| How | Covers |
| :--- | :--- |
| `tests/test_infra.py` | Real `ip` and `ss`, real `nft` and `iptables` in a throwaway network namespace, real Docker |
| `tests/test_platform_more.py` | The firewall writer against the real kernel, reach, what-if and designs |
| `tests/test_browser_smoke.py` | The panels and the map's modes in Chromium under the real CSP |
| [KVM lab](kvm-lab.md) tier 10 | What scans read against each VM. A capture on the VM during a scan: the only connection is SSH |
| KVM lab tier 11 | Rules on ufw, nftables and firewalld judged by real connections between VMs, a published port's fix, a fence across a reboot, the timer undoing a firewall rule and a bridge that each cut SSH, VLANs on networkd and NetworkManager across a reboot, the reach table against real connections, the overlay against the next reading, a half-deployed design, WireGuard confirmed by key, and a placeholder promoted to a host |

**Not tested:** Terraform and Puppet have not applied the exports: those are checked for structure and for values held as data. Incus, LXC, Proxmox guests, Tailscale, proxy routes and identity providers have parsers and unit tests, and have not met a real host in the lab. libvirt has been read in the lab, with a guest defined and not booted. No generated VM has been booted. Whether a quarantine reaches a bridged VM has not been measured, and the page says a bridged VM is outside host rules: the lab shows it does reach a published container port.
