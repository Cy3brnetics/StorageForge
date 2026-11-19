# Infrastructure map

The **Map** view: networks, firewalls, listeners, containers, VMs and VPNs across your hosts, drawn from what those hosts report. The **Infra** panel holds the same facts as lists. A plan is [the roadmap](../archive/roadmaps/infrastructure-platform-roadmap.md); this page is what exists.

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
| `wg-peer` | Add or revoke a WireGuard peer, with where to call it and a keepalive where it cannot call back |
| `wg-interface` | Make a WireGuard interface and its key pair on the host, or remove them. The private key is made on the host and never leaves it. An interface StorageForge did not make is left alone |
| `container` | `docker run` or `podman run` with a fixed name. It will not replace an existing container |
| `vm` | `virt-install --import` from a disk you already have, with its console on loopback |
| `os-install`, `os-boot`, `os-remove` | A second operating system on the host itself, beside the running one, and which of them starts. See [host migration](host-migration.md#a-second-system-beside-the-first) |
| `dux-install`, `desktop-profile` | A desktop for a user: Dux with a chosen compositor, and a profile of keys, window rules and displays kept on the server. See [host migration](host-migration.md#a-desktop-on-it) |
| `vm-create` | A new VM from a cloud image: the image checked against its publisher's checksum, copied to a new root disk, data disks, and a cloud-init login for your SSH key. Fields can come from a [VM spec](host-migration.md#creating-vms). Never writes over a disk or a VM that is there |
| `packages` | The packages another host was given on purpose, installed with the same package manager. Reports first, never removes a package, never adds a source |
| `workload-action`, `workload-remove` | Start, stop, restart, snapshot. Removing keeps volumes and disks, and takes `--destructive` |

A step that could cut StorageForge off can carry a rollback timer. The script journals how to undo it and starts a systemd timer. Only a second signed run stops that timer, and that can only happen if the path still works.

## StorageForge's own network

StorageForge can build a WireGuard network of its own between the hosts you choose, on the interface `sf0` and UDP port 51903. It needs no outside service. It is used through the API today; the page for it is not built.

1. `POST /api/sfnet` makes the network. It picks a range that no scanned host has an address or a route in, and never `100.64.0.0/10`, which Tailscale and NetBird use. Give `range` to choose one yourself, and `topology: "hub"` where hosts should meet only at a hub.
2. `POST /api/sfnet/members` with a `host` adds a scanned host. It gets one address for good. The other members call it at the address scans reach it at; give `endpoint` for another, or `reachable: false` for a host behind a NAT of its own, which then calls the others and keeps the path open.
3. `POST /api/sfnet/plan` saves a change plan. The first plan makes `sf0` and a key pair on each new member (`wg-interface`). Run it, and take a new infrastructure reading: the reading brings back each host's public key, and the host becomes active.
4. `POST /api/sfnet/plan` again writes the peers (`wg-peer`). Each host trusts a peer for that peer's one address and nothing more, so a host that is taken over cannot answer for another's address. After the next reading `GET /api/sfnet` shows, per host, which peers are confirmed by key.

What it holds to:

- **Private keys stay on their hosts.** The controller stores ranges, addresses and public keys. The step never prints the key, and its file is readable by root only.
- **A key is taken from a reading once.** If an active member later shows a different key, nobody is told to trust it. It is a critical notification, because either the interface was made again by hand or it is another machine.
- **A peer nobody asked for is a notification,** and the next plan revokes it.
- **A host that leaves** (`POST /api/sfnet/members/remove`) comes off every other member at the next plan and loses its interface and key. Its address is never given to another host.
- **Open the port.** Peers call UDP 51903; add a `fw-rule` step where a firewall is in the way.

Not built yet: the controller as a member (it runs in a container), key rotation through a plan, and the page.

## Designs

A design is what should be there: hosts, bridges, VLANs, containers, VMs and rules. **Compare** lists what is missing, what differs, and what is there that it does not name, against what scans found. What has not been read is **not known**, and is not counted as missing. **Stage what is missing** turns the gap into a plan.

Exports go one way: nothing is read back from a script. Bash and Ansible come from that plan. Terraform (`kreuzwerker/docker`, `dmacvicar/libvirt`) and Puppet (`puppetlabs-docker`, `puppetlabs-firewall`) are for your own pipeline, and StorageForge never runs them.

## On the map

- **The look is Topology's:** a dot grid, each host a dashed frame with its name on a ruled heading, each interface, network, port, workload or mount a row with its kind in letters at the left end. The tag's colour only repeats the family (network, service, workload, storage): who can reach a port is still the row's own colour and the word at its right end. The legend is shut until you open it.
- **Modes:** Network, Flow, Workloads, Storage only, Security, Custom. They are presets of the layers (Storage, Network, Services, Firewall, Workloads, Access, Placed by hand), which can also be stacked by hand; doing so makes the mode Custom.
- **Grouping:** by host, subnet or runtime. Double-click a frame to shut it. Far out, frames stay and their rows go.
- **Saved views** keep layers, filter, grouping and where you dragged things.
- **Timeline:** go back to an earlier reading. Storage is not kept: it shows the other layers as they stood.
- **Security mode** shows who can reach what, holds and decoys on mounts, and workloads no hold or decoy reaches. It warns when an armed sentinel could cut off a gateway, DNS server or hypervisor that is not on the exempt list.
- **Exports:** JSON, Mermaid, DOT, SVG, draw.io, Obsidian canvas, PNG, and PDF through the browser's print. Redacting them hides addresses, host names and MACs, and each export is audited.
- **Links:** `/#/map/details?mode=security`, or `/#/map/details?layers=network,firewall`; the older `/#view=map&layers=network,firewall&mode=security` works too.

Firewall rules and exposure say how to get in, so they need `security.view`. The map itself needs `map.view`.

## Not built

The roadmap goes further than this.

- Deploying a stack, an LXC instance or a catalog tool from the map, or a VM from an ISO or cloud image. Those are in the [roadmap](../roadmap.md).
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
