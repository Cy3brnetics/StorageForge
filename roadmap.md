# Roadmap

What's left to build, in one place. [progress.md](progress.md) says what has been built and lab-tested. The finished and superseded roadmaps are in [archive/roadmaps](archive/roadmaps/), and they hold the detail behind each item here: formats, field lists and reasoning. **This page decides what's next, and they don't.**

Checked against the code on 2026-11-04.

## How to read this

**Done** means through the KVM lab, as [progress.md](progress.md) defines it. Days are rough guesses carried over from the old roadmaps, and none has been measured. Each section can stop at any item without harming the others.

## 1. Close out what's built

Small, and worth doing first: each is a claim that hasn't been proved or a known gap in something shipped.

| Item | Why it matters |
| :--- | :--- |
| **SF-48: the receiving host of a send** | Signed scripts still run root commands on the receiving host with no signature there. It's named in the audit row, warned about in the check and listed in [security.md](docs/security.md). The real fix makes the receiver its own signed run, about a week's work |
| **pfSense, OPNsense and Cisco on real devices** | Reading and rollback have only met published formats and a simulated shell. They need a real device or an image the lab can use |
| **Old SSH ciphers on a device that needs them** | Built and unit-tested, with nothing old enough in the lab |
| **firewalld and ufw output from the network language** | Unit-tested. nft and iptables-restore took theirs for real, and these two should as well |
| **Incus, LXC and Proxmox guests; Tailscale, proxies, identity providers** | Parsed and unit-tested, not lab-tested |
| **Terraform and Puppet exports** | They render, and no tool has applied them |
| **PagerDuty and FIDO2** | PagerDuty has not reached the real service. FIDO2 has only met Chromium's virtual authenticator |

## 2. Change engine: what's left (Stage 3)

The firewall writer, share fences and security findings as steps are done.

| Item | Detail |
| :--- | :--- |
| **Secret store** | Generic secrets in the vault, generated, shown once, delivered through the runner's stdin, with a rotation path. Device passwords are sealed this way already. [Detail](archive/roadmaps/infrastructure-platform-roadmap.md#stage-3-change-engine-18-to-22-days) |
| **`runtime-install`** | The four runtimes across distros, rootless setup, and a preflight that says present, installable or blocked. [Detail](archive/roadmaps/infrastructure-platform-roadmap.md#71-runtime-install) |
| **`pooldef` and `netdef`** | Storage pools and networks as plan steps, with bridge changes under the rollback timer |
| **Catalog engine** | Schema, signature, override layer, install methods, risk labels, and uninstall that keeps data. [Detail](archive/roadmaps/infrastructure-platform-roadmap.md#8-the-catalog) |

**Exit:** install a runtime on a bare VM from a plan. The report changes nothing, a changed plan gets 409, and a bridge change that cuts SSH rolls itself back.

## 3. Workloads (Stage 4, about 13 to 15 days)

Running a container, defining a VM from an existing disk, and start, stop and remove are done.

- **`stack` and `lxc` steps,** each carrying its firewall rule and labels.
- **Image updates,** with rollback on a failed healthcheck.
- **VMs from templates:** cloud images and ISOs, checksums, cloud-init with the deploy key, so a new VM can be scanned from its first boot.
- **Lifecycle:** snapshot, clone, resize and console over an SSH tunnel.
- **Placement advice, which is the differentiator:** a pool on a dataset tuned for its use, databases off the bulk pool, warnings for bind mounts on network filesystems, and a warning when data sits where no hold or offsite copy reaches.
- **MAC at deploy:** `:Z` labels, the `svirt_image_t` fix as a plan step, AppArmor pool paths.
- **Read side:** Podman Quadlets, and adopting a workload by capturing it as compose, Quadlet, libvirt XML or Incus YAML, with drift against the capture.

[Workload roadmap](archive/roadmaps/workload-platform-roadmap.md) for field lists, and the [merged plan](archive/roadmaps/infrastructure-platform-roadmap.md#7-workloads-in-detail) where they differ.

## 4. Toolbox (Stage 5, about 32 to 40 days)

The largest piece, and nothing of it exists. Needs the catalog engine and secret store from section 2. It can be cut at any entry.

- **Adapters and GUI levels:** `detect`, `status`, `actions`, `links`, `metrics` over a measurement.
- **Wave 1 entries,** panels first, since they prove the catalog cheaply: Cockpit, Dockge, then Portainer, Komodo, Dockhand, Dokploy, Incus UI. Then WireGuard and Caddy with full panels, CrowdSec, Trivy, restic with restore tests.
- **Bundles** with one report, shared secrets, one firewall change set, and rollback of the whole bundle.
- **Feeds:** Trivy findings and CrowdSec decisions into the existing alerts and quarantine view, with bans reconciled so quarantine doesn't fight the bouncer.

A tool without a passing lab run is labelled *not lab-tested* in the catalog. [Toolbox roadmap](archive/roadmaps/toolbox-catalog-roadmap.md) and [the merged plan](archive/roadmaps/infrastructure-platform-roadmap.md#8-the-catalog).

## 5. Depth (Stage 7: what's left)

Compliance depth, retention depth, YARA, incident evidence and clean room are done.

- Quiesced snapshots: `qemu-guest-agent`, stop-snapshot-start for stateful stacks, with the method recorded.
- Incidents that include workloads touching affected paths, and a clean room that boots a VM or container from a pre-incident snapshot.
- Externally-managed detection, and a warning before changing such a workload.
- Compliance readings for CIS Docker, Podman and libvirt-style checks, and auditd rules for runtime sockets and config.
- Terraform, OpenTofu and Puppet export for workloads, with round-trip tests. Designs have this already.

## 6. Network and map: what's left

- **The language:** a rule at a position (`place-before`). RouterOS appends, so a rule below a final drop does nothing, and the what-if says so.
- **Scan results as map placeholders.** The Scan tab links to the map, but they're separate drawings.
- **Scanner findings through alerts:** what's new since the last scan.
- **Traffic on Linux hosts.** Monitoring covers devices only.
- **Deeper reads:** Cisco zone-based firewall and VRFs, OSPF and BGP state, wireless clients.
- **From the map:** moving, cloning or resizing a VM, restricting a service's bind address, putting a listener behind a proxy, rotating a peer's key.
- **`bridge`-family firewall rules** for bridged VMs, which bypass a quarantine's hooks. The map says so.
- **REST adapters: only if a device needs one.** SSH reads everything on all four platforms, and a second way in is a second thing to secure.

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

The Samba VSS trap, cryptographic shred, compliance certificates and a WebSocket event stream, because they can't work or would claim too much: see [ransomware defense](docs/ransomware-defense.md). StorageForge stays agentless and builds no log viewer, and it isn't a replacement for NetBox, LibreNMS or Zabbix.

## Decision still open

**How much of sections 2 to 4 belongs in StorageForge?** The merged plan recommended releasing after the map, then deciding on the change engine onwards from how it's used. They'd make it a deploy platform as well as a map. The other [decisions it assumed](archive/roadmaps/infrastructure-platform-roadmap.md#12-decisions-to-confirm) stand, except that routers and switches are now read directly.
