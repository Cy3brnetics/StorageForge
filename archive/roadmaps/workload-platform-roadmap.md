# Workload Platform: Container & VM Discovery, Management, Deployment & IaC Roadmap

> **Archived 2026-11-04.** A draft, merged into the Infrastructure Platform Roadmap. Part of it is built. What is left moved to the [roadmap](../../roadmap.md), and this keeps the detail.

A roadmap for turning StorageForge from a storage-aware *inventory* of containers into a place where an operator can **scan, import, install, set up, deploy and manage** workloads: Docker, Podman, LXC/LXD/Incus containers and KVM/libvirt virtual machines. It also covers **deploying other management panels** (Dockhand, Komodo, Dockge, Portainer, Dockploy, Cockpit and similar) and exporting everything as **Bash, Terraform, Puppet and Ansible** artifacts. It all runs through the existing **staging toolbox** (change plans, report-then-apply, signed deploys) and works alongside the MAC, firewall and host-hardening engines in the [Ransomware Defense Roadmap](ransomware-defense-roadmap.md).

Status: **planned**. Nothing here is built yet. Today StorageForge only *reads* Docker/Podman state (`docker.py`, [Docker and Podman inventory](../../docs/features/discovery.md#docker-and-podman)) and deploys signed scripts through `deploy.py`.

---

## 1. Goals and Non-Goals

### 1.1 Goals
1. **Scan and import** existing workloads into the index: Docker, Podman, LXC/LXD/Incus, and libvirt/KVM domains, with their storage, network and security context.
2. **Install and set up runtimes** on hosts that lack them, across distros, rootless where possible.
3. **Deploy workloads** (containers, compose stacks, VMs) from the same Plan → Report → Apply flow used for storage changes. Nothing runs without a visible, signed, dry-runnable script.
4. **Deploy management panels** from a catalog with one click, with sane hardening defaults. StorageForge keeps the ability to *read* stacks those panels already manage.
5. **Emit IaC**: every staged plan can be exported as Bash, Terraform, Puppet or Ansible, and a script like `create-vm.sh` or a Terraform document is a *rendering* of the plan, not an input to it.
6. **Stay inside the security model**: SELinux/AppArmor (sVirt, container labels), nftables/firewalld/ufw, auditd, compliance baselines and WORM-protected backup of workload data.

### 1.2 Non-Goals
- Not a Kubernetes/Swarm orchestrator. Single-host and small-fleet workloads only. Kubernetes is a later phase at most (§10).
- Not a replacement for Portainer, Komodo, Cockpit or Proxmox. StorageForge **installs and observes** them, and does what is storage-aware (volumes, snapshots, backups, placement) better than they do.
- No always-on agent. Same agentless SSH + signed-runner model as the rest of the product.
- No auto-destructive actions. Deleting a VM, volume or container always goes through the existing destructive-confirm gate.

### 1.3 Design Tenets (inherited)
Same as the ransomware roadmap: total visibility (scripts shown in plain text, diffed, downloadable), operator authority (dry-run and override everything), kernel-native primitives, and agentless signed execution via `/usr/local/sbin/storageforge-run`.

---

## 2. Architecture Overview

```text
┌──────────────────────────────────────────────────────────────────────────────────────────────┐
│  WEB UI: Workloads rail  (Containers · VMs · Stacks · Panels Catalog · Templates · IaC Export)│
├──────────────────────────────────────────────────────────────────────────────────────────────┤
│  PLAN / STAGING TOOLBOX  (existing: change plans → report → apply → verify → audit log)       │
│   new step types: runtime-install · container · stack · vm · lxc · panel · netdef · pooldef   │
├───────────────┬──────────────────┬──────────────────┬────────────────────────────────────────┤
│ Runtime       │ Workload Index   │ Template Engine  │ IaC Exporters                          │
│ Adapters      │ (scan + import)  │ (create-vm.sh →  │ Bash · Terraform · Puppet · Ansible    │
│ docker/podman │ containers, VMs, │ parameterised    │ (rendered from the same plan model)    │
│ lxc/incus     │ stacks, volumes, │ templates)       │                                        │
│ libvirt/virsh │ networks, panels │                  │                                        │
├───────────────┴──────────────────┴──────────────────┴────────────────────────────────────────┤
│  GUARDRAILS: MAC (sVirt/SELinux/AppArmor) · Firewall reconciler · Compliance · WORM backup   │
├──────────────────────────────────────────────────────────────────────────────────────────────┤
│  TARGET HOST (SSH, signed runner):  docker | podman | lxc/incus | libvirtd/qemu | panels     │
└──────────────────────────────────────────────────────────────────────────────────────────────┘
```

### 2.1 Runtime Adapter Interface
One adapter per runtime keeps the planner, UI and exporters runtime-agnostic.

| Adapter | Detect | Discover | Lifecycle | Notes |
| :--- | :--- | :--- | :--- | :--- |
| `docker` | `docker info` | `docker ps -a`, `inspect`, compose labels | create/start/stop/rm, `compose up/down` | Extends existing `docker.py` |
| `podman` | `podman info` | `podman ps -a`, `inspect`, quadlets, pods | same + `generate systemd` / **Quadlet** units | Rootless per-user; scan every user with linger |
| `lxc` / `incus` | `incus info` / `lxc-ls` | `incus list --format json`, profiles, storage pools | launch/start/stop/snapshot/delete | Prefer **Incus** on new installs; support legacy LXD and plain LXC |
| `libvirt` | `virsh version` | `virsh list --all`, `dumpxml`, pools, networks | `virt-install`, define/start/shutdown/undefine | Wraps scripts like `create-vm.sh` |

Every adapter returns the same normalized records: `workload`, `volume_mount`, `network_attach`, `port_publish`, `security_context`. Those records feed the existing graph so a VM disk image or container volume shows on the storage canvas next to the dataset it lives on.

---

## 3. Phase A: Scan & Import

### 3.1 What a scan learns
Added to the existing single SSH scan session (still read-only):

- **Runtimes present**: version, rootless vs rootful, storage driver and root dir, cgroup version, socket exposure.
- **Containers (Docker/Podman)**: image + digest, command, restart policy, env *names only* (values redacted by default), mounts, networks, published ports, user, capabilities, `privileged`, seccomp/AppArmor/SELinux label, healthcheck state, compose project/labels, Quadlet unit path.
- **LXC/Incus**: instances, type (container/VM), profiles, devices, storage pool and backing dataset, network, snapshots, `security.*` config.
- **libvirt**: domains (state, vCPU, RAM, autostart), disks (path, format, bus, backing chain), pools, networks (bridge/NAT), NICs (model, MAC), graphics (type, **listen address**), TPM/secure boot, snapshots.
- **Storage correlation**: each disk image, volume or bind mount is resolved to the pool/dataset/mount it sits on, so "what lives on `tank/vm`?" and "what breaks if I move this folder?" work for VMs and LXC as well as Docker.
- **Management panels**: detect Dockhand, Komodo, Dockge, Portainer, Dockploy, Cockpit, `virt-manager`/`libvirt-dbus` and Proxmox by container image, listening port and unit name (extends the existing Dockhand/Portainer/Komodo/Dockge path translation).

### 3.2 Import
Import turns discovered state into **managed, plan-able objects** without touching them.

- **Adopt** (read-only): a workload becomes a tracked object with history, tags and backups, no changes made.
- **Capture as definition**: generate a compose file, Quadlet unit, Incus profile/instance YAML, or libvirt XML + `virt-install` command from a running workload so it can be recreated, versioned, diffed and exported.
- **Drift detection**: later scans compare live state against the captured definition and report drift (changed image digest, added mount, new published port, VM NIC moved).
- **Secrets**: env values and `.env` files are never indexed. Detected secret-looking variables are flagged and offered a move to the key vault.

### 3.3 Deliverables
`workloads` index tables (§9), scan extension (`scanner.py`, `docker.py` → generalised `runtimes/`), Workloads inventory panel with per-runtime filters, "Capture definition" action, drift report.

---

## 4. Phase B: Runtime Install & Setup

Builds on the multi-distro package resolver in the ransomware roadmap (§4 there). **Install runtime** becomes a staged plan step with a report-first dry run.

| Runtime | Packages (Debian/Ubuntu) | Packages (RHEL/Rocky/Alma/Fedora) | Packages (openSUSE / Arch) | Post-install |
| :--- | :--- | :--- | :--- | :--- |
| Docker | `docker.io` or Docker CE repo, `docker-compose-plugin` | `docker-ce` repo, `docker-compose-plugin` | `docker`, `docker-compose` | enable `docker.service`, `daemon.json` (log limits, `userns-remap` optional, `iptables` mode) |
| Podman | `podman`, `buildah`, `skopeo`, `uidmap`, `slirp4netns`/`passt` | `podman`, `buildah`, `skopeo`, `container-selinux` | `podman`, `buildah`, `skopeo` | rootless: `subuid/subgid`, `loginctl enable-linger`, `podman.socket` |
| Incus / LXC | `incus` (Zesty/Zabbly repo) or `lxc` | `incus` (COPR/EPEL) or `lxc` | `incus`, `lxc` | `incus admin init --preseed` from a StorageForge-generated YAML, storage pool on a chosen dataset |
| KVM / libvirt | `qemu-kvm`, `libvirt-daemon-system`, `virtinst`, `libosinfo-bin`, `ovmf`, `swtpm` | `qemu-kvm`, `libvirt`, `virt-install`, `edk2-ovmf`, `swtpm` | `qemu`, `libvirt`, `virt-install`, `edk2-ovmf` | enable `libvirtd` / modular daemons, define storage pool + network from the plan |

### 4.1 Preflight checks (read-only, shown before any apply)
- CPU virtualization (`vmx`/`svm`), `/dev/kvm`, nested virt if the host is itself a VM.
- cgroup v2, user namespaces, `subuid` ranges, kernel modules (`overlay`, `br_netfilter`, `vhost_net`).
- Conflicts: Docker and Podman both installed, an existing `br0`, another hypervisor, firewall backend in use (see §8.2).
- Storage fit: runtime root (`/var/lib/docker`, `~/.local/share/containers`, VM pool) sits on a filesystem with enough space, and warns on ZFS/btrfs driver choice, copy-on-write on VM images (`chattr +C`/`nocow` advice for btrfs).

### 4.2 Pool and network definitions as plan steps
- `pooldef`: a libvirt dir/ZFS/LVM pool, an Incus storage pool, or a Docker/Podman root dir, tied to a dataset the storage planner already knows about.
- `netdef`: Linux bridge (`br0`), libvirt NAT/isolated/bridged network, Incus bridge, Docker/Podman network. Bridge changes use the existing connectivity-safe, rollback-timer pattern used for risky network edits, since `br0` setup over SSH can lock the operator out.

---

## 5. Phase C: Deploy Workloads

### 5.1 Plan step types
| Step | What it does | Dry-run (report) shows |
| :--- | :--- | :--- |
| `container` | Run one container from an image/definition | resolved image digest, mounts, ports, labels, generated `docker run`/Quadlet |
| `stack` | Compose project or Podman pod/Quadlet set | rendered compose, diff versus live, volumes to be created |
| `lxc` | Incus/LXC instance (container or VM) from image + profile | image fingerprint, profile merge, devices |
| `vm` | libvirt domain via `virt-install` from a template | the exact `virt-install` command, disk path/size, NIC, graphics, ISO checksum result |
| `panel` | Deploy a management panel from the catalog (§6) | compose/Quadlet, exposed ports, volumes, hardening applied |
| `runtime-install` | Phase B | packages, units, config files |

All steps use the existing two-stage deploy: **Report** read-only on every host, then **Apply** from that report, host by host, stop at first failure, 409 if the plan changed since the report, signed per machine and run, password typed within 5 minutes.

### 5.2 Template engine (the `create-vm.sh` model)
`create-vm.sh` is the pattern to productise: a distro keyword picks an ISO and `--os-variant`, with CPU/RAM/disk parameters and a pool and network. It becomes a **VM template**:

```yaml
# vm-template: rocky10
name: rocky10
aliases: [rocky]
source:
  iso: Rocky-10-latest-x86_64-minimal.iso
  checksum_url: https://download.rockylinux.org/pub/rocky/10/isos/x86_64/CHECKSUM
os_variant: rocky10          # validated against `osinfo-query os`
defaults: { vcpus: 2, ram_mb: 2048, disk_gb: 30, disk_format: qcow2, bus: virtio }
firmware: bios               # or uefi / uefi-secure + tpm
graphics: { type: spice, listen: 127.0.0.1 }   # see hardening note below
```

- **Parameters** (`distro`, `name`, `vcpus`, `ram_mb`, `disk_gb`) become plan fields. Per-host defaults (`iso_dir`, `pool`, `network`) live in host settings instead of being hard-coded at the top of a script.
- **Built-in template library**: Debian, Ubuntu, Rocky, Alma, Fedora, Arch, openSUSE, Alpine, plus Proxmox VE (nested virt), TrueNAS and OPNsense for homelab use.
- **Cloud-image path (preferred)**: download a cloud image, verify its checksum/signature, `qemu-img create -b` a backing-file overlay, and inject `cloud-init` user-data/meta-data (SSH key from the key vault, hostname, static IP) with `--cloud-init` or a NoCloud seed ISO. This gives unattended installs that install the keys StorageForge needs for scanning and deploy access.
- **ISO path**: kept for installers without cloud images (Proxmox, Windows). Supports kickstart/preseed/autoinstall injection.
- **User templates**: operators build or clone templates in the UI (parameters, ISO or image, defaults) and save them. Each template renders to a script like `create-vm.sh` on export. Scripts are never imported back in.

### 5.3 Hardening notes drawn from the sample script
Reviewing `create-vm.sh` shows defaults the generator must not copy:

| Sample behaviour | Risk | Generated default |
| :--- | :--- | :--- |
| `--graphics vnc,listen=0.0.0.0` | Unauthenticated console reachable from the whole network | `listen=127.0.0.1`, SPICE/VNC with password or via SSH tunnel; the plan report flags any non-loopback listener |
| `NETWORK="br0"` with comment "change to br0 later" | Comment and value disagree; a missing bridge fails late | Preflight checks the network exists before the script runs |
| Hard-coded `ISO_DIR`, `POOL` | Not portable between hosts | Per-host settings with preflight existence checks |
| ISO used with no checksum check | Tampered or corrupt installer | Verify against a pinned checksum or signature before attach |
| `proxmox` mapped to `--os-variant debian13` | Wrong guest tuning | Explicit variants with a validated `osinfo-query` lookup and a warning on fallback |
| No firmware/TPM/secure-boot options | Weaker guests | Template fields, defaulting to UEFI for modern distros |
| `--noautoconsole` with no autostart/guest-agent | VM doesn't return after reboot | Optional `autostart`, `qemu-guest-agent` channel |

### 5.4 Lifecycle & day-two
Start, stop (graceful then forced), reboot, pause, console link (SSH-tunnelled SPICE/VNC or serial), resize disk/CPU/RAM, snapshot/revert (qcow2 internal or ZFS/btrfs dataset snapshots), clone, live-migrate between registered hosts (shared storage or `--copy-storage-all`), image update (pull + recreate with rollback on failed healthcheck), and delete (destructive gate, with an offer to keep the disk).

### 5.5 Storage-aware placement (the differentiator)
Because StorageForge already indexes pools, datasets and capacity, deploy forms offer **placement advice**: put the VM pool on a dataset with `recordsize=64K`/`volblocksize` tuned for qcow2/zvols, keep databases off the pool that backs bulk media, warn when a container's bind mount sits on a network filesystem, and keep VM disks inside a dataset that already has a snapshot/backup job.

---

## 6. Phase D: Management Panel Catalog

A **Panels Catalog** deploys other management UIs as `panel` plan steps, using pinned image digests, generated Quadlet/compose files and sane defaults. After install, the existing scan recognises them and translates their stacks to host paths, so StorageForge stays the storage and security layer above whichever one the operator prefers.

| Panel | Manages | Runs as | Notes |
| :--- | :--- | :--- | :--- |
| **Dockhand** | Docker/compose | container | Socket access; offer a socket proxy |
| **Komodo** (core + periphery) | Docker, multi-server | containers + DB | Periphery agent on each host; DB (FerretDB/Mongo/Postgres) volume placed on a snapshotted dataset |
| **Dockge** | Compose stacks as files | container | Stacks dir mapped to a dataset StorageForge snapshots |
| **Portainer CE** | Docker/Podman/Swarm/K8s | container | Edge agent option for NAT'd hosts |
| **Dockploy** | PaaS-style app deploys | Swarm + containers | Needs Swarm init; flagged because it takes over ports 80/443 and the Docker daemon |
| **Cockpit** (+ `cockpit-machines`, `cockpit-podman`) | Host, libvirt VMs, Podman | system packages | Matches the existing KVM workflow ("Connect via Cockpit") |
| **virt-manager / virt-viewer** | libvirt | client-side | Generates connection strings, no server install |
| **Incus UI** | Incus | package/`incus config set core.https_address` | Bind to loopback or management VLAN only |
| **Proxmox VE / TrueNAS** | n/a (full platforms) | VM template (§5.2) | Deployed as VMs, not installed on the host |

Catalog rules:
- **Catalog entries are data, not code**: a signed YAML (image, digest, ports, volumes, required capabilities, risk notes, health URL). Entries are reviewable and diffable. Community entries can be added in a user catalog.
- **Risk labels** shown in the Report: *mounts the Docker socket* (root-equivalent), *privileged*, *publishes 80/443*, *needs host network*, *runs as root*. Each has a mitigation toggle where possible (socket proxy with read-only API subset, rootless Podman socket, loopback bind plus reverse proxy).
- **Exposure default**: loopback or management-VLAN only. Public exposure is an explicit step that also edits the firewall plan (§8.2) and offers a TLS reverse proxy (Caddy/Traefik/nginx) step.
- **Credentials**: first-run admin passwords are generated, stored in the key vault, and shown once. Never written to the plan or logs.
- **Uninstall**: removes containers and units, **keeps volumes by default**, lists exactly what it would delete first.

---

## 7. Phase E: IaC, Script & Config-Management Export

One internal plan model, several renderers. Every staged plan has an **Export** menu next to the existing "download script".

| Target | Artifact | Used for |
| :--- | :--- | :--- |
| **Bash** | Standalone signed-runner script, idempotent (`virsh dominfo` guard like `create-vm.sh`), `set -euo pipefail`, `--dry-run` | Default, and what Apply actually runs |
| **Terraform / OpenTofu** | `main.tf` + `variables.tf` + `terraform.tfvars` | libvirt (`dmacvicar/libvirt`), Docker (`kreuzwerker/docker`), Incus (`lxc/incus`), Podman, Proxmox (`bpg/proxmox`) providers |
| **Puppet** | Manifests/module: `package`, `service`, `file`, `exec` with `unless`, plus `docker`/`podman`/`libvirt` resources; Hiera data from host settings | Runtime install, host config, panel install |
| **Ansible** | Playbook/role (`community.docker`, `containers.podman`, `community.libvirt`) | Same targets, for shops that prefer it |
| **Compose / Quadlet / libvirt XML / Incus YAML** | Native definitions | Capture-as-definition outputs from §3.2 |

### 7.1 Principles
- **Single source of truth**: renderers read the plan, never each other. A consistency test (apply the Bash export, then `terraform plan` on the Terraform export shows no diff) lives in the lab suite.
- **Idempotent and re-runnable**: every generated artifact guards on existing state, like the `already exists` check in `create-vm.sh`.
- **Secrets by reference**: the exports reference vault keys, `sops`/environment variables or Hiera eyaml, and never embed secrets.
- **Export only**: StorageForge does not parse `.tf`, Puppet or shell files into plans. Exports are one-way artifacts. (Scanning running workloads and capturing their definitions, §3.2, is a separate feature.)
- **State awareness**: if a workload is already managed by Terraform/Puppet (detected via tags/labels or state files supplied by the user), StorageForge marks it **externally managed** and warns before changing it. That avoids fights between tools.
- **Signed delivery stays**: exported artifacts are for the operator's own pipeline. The in-product Apply still goes through the signed runner.

### 7.2 Bash generator shape (derived from `create-vm.sh`)
```bash
#!/bin/bash
set -euo pipefail
# generated by StorageForge plan #42 step 3 (vm: rocky10) — do not edit; re-export instead
NAME=rocky-web01 VCPUS=2 RAM_MB=4096 DISK_GB=40 POOL=home-kvm NETWORK=br0
preflight() { virsh net-info "$NETWORK" >/dev/null; virsh pool-info "$POOL" >/dev/null; \
              sha256sum -c <<<"$ISO_SHA256  $ISO"; }
virsh dominfo "$NAME" &>/dev/null && { echo "VM '$NAME' exists, nothing to do"; exit 0; }
[[ "${1:-}" == "--dry-run" ]] && PRINT="--print-xml --dry-run"
virt-install --name "$NAME" --vcpus "$VCPUS" --memory "$RAM_MB" \
  --disk pool="$POOL",size="$DISK_GB",format=qcow2,bus=virtio \
  --cdrom "$ISO" --os-variant "$OS_VARIANT" --network bridge="$NETWORK",model=virtio \
  --graphics spice,listen=127.0.0.1 --video virtio --channel unix,target_type=virtio,name=org.qemu.guest_agent.0 \
  --console pty,target_type=serial --noautoconsole ${PRINT:-}
```

---

## 8. Security Integration

Workload management must make a host *more* defensible, not less. These hooks tie directly into the [Ransomware Defense Roadmap](ransomware-defense-roadmap.md).

### 8.1 Mandatory Access Control
- **KVM/libvirt**: confirm **sVirt** is active (SELinux: per-VM `svirt_t` categories; AppArmor: `libvirt-<uuid>` profiles). The Report flags VMs running `unconfined`, disks whose image path lacks `svirt_image_t` (`semanage fcontext` fix generated as a change plan), and AppArmor profiles missing a custom pool path (`/etc/apparmor.d/local/abstractions/libvirt-qemu`).
- **Podman/Docker**: SELinux labels on bind mounts (`:z`/`:Z`), `container-selinux` installed, `--security-opt label=disable` and `apparmor=unconfined` flagged, `container_t` vs `spc_t`, custom seccomp profiles surfaced.
- **Incus/LXC**: AppArmor profile per instance, `security.privileged`, `security.nesting`, idmap isolation, raw LXC overrides flagged.
- AVC denials caused by workloads feed the existing MAC panel's AVC feed, tagged with the workload name.
- **Rootless first**: Podman rootless and Docker rootless modes are the default recommendation, and the Report explains what that changes.

### 8.2 Firewall reconciliation
Container runtimes and libvirt write their own netfilter rules, and that is a well-known way for published ports to bypass `ufw`/`firewalld` expectations.
- Detect the firewall backend (nftables native, firewalld, ufw, iptables-nft) and how Docker/Podman/libvirt/Incus integrate (`DOCKER-USER` chain, firewalld zones `docker`/`libvirt`, `iptables=false`).
- **Published-port audit**: list every container port reachable from outside (`-p 8080:80` binds `0.0.0.0` by default), mapped against the firewall fencing rules from the Storage Firewall panel. Offer: rebind to loopback/mgmt IP, add a `DOCKER-USER`/nftables rule, or move behind a reverse proxy.
- **Plan steps include the firewall change**: a `panel` or `container` step that publishes a port also stages the rule and the rollback, in the same Report.
- **Quarantine interplay**: the emergency brake (client IP drop, host airgap) must also cover workload networks, including bridge-forwarded VM and container traffic, and not only the host's INPUT chain.
- **VM networking**: bridged VMs (`br0`) bypass host INPUT rules, so the Report says so and offers `nwfilter`/ebtables/nftables bridge-family rules, with isolated networks as the safe default for untrusted guests.

### 8.3 Compliance and baseline
New checks in the Compliance Center (CIS Docker/Podman benchmarks, CIS-style libvirt checks, NIST 800-53 CM-7, PCI-DSS 2.2): Docker socket permissions and group membership, `userns-remap`/rootless, no privileged containers without waiver, image digest pinning, read-only root filesystems, resource limits, log driver limits, `libvirt` socket and TLS settings, VNC/SPICE listen addresses, and unmanaged VM consoles. `sf-init-compliance.sh` gains `--with-containers` and `--with-virt` modules, and waivers use the existing Waiver Manager.

### 8.4 Detection and audit
- `auditd` rules for `/var/run/docker.sock`, `/etc/docker`, `/etc/libvirt`, `virsh`/`podman`/`incus` execs, and Docker/Podman/Incus config files.
- Falco/eBPF ruleset additions: container shell spawn, mount of host paths into a new container, privileged container start, `docker.sock` mounted into a container, VM disk image modified outside QEMU.
- Every workload action is written to the existing hash-chained audit log, with the signed plan and its report.

### 8.5 Data protection and recovery
- **VM disks and container volumes inherit snapshot/WORM protection**: a workload's backing dataset is shown with its hold/retention status, and the deploy form warns when a workload's data sits on a pool with no immutable snapshots.
- **Application-consistent snapshots**: quiesce via `qemu-guest-agent` (`virsh domfsfreeze`), pause or `fsfreeze` for containers, and stop-snapshot-start for stacks flagged "stateful", and record the method used.
- **Ransomware blast radius**: an incident view includes workloads touching affected paths, and the clean-room recovery wizard can boot a VM or container from a pre-incident snapshot in an isolated network.
- **Quorum**: deleting a VM with a WORM-held disk, or removing a protected volume, follows the same adaptive quorum/timelock rules.

### 8.6 Management-plane hardening
- Docker socket exposure is the biggest risk: offer a socket proxy, rootless sockets, and never publish the Docker TCP API without mutual TLS (flag `2375`).
- `libvirt` remote access: prefer `qemu+ssh://`, and TLS only with client certs.
- StorageForge's own deploy user stays **non-root with a narrow sudoers**. Workload steps run through the runner with an allowlist of commands per step type, not a general shell.

---

## 9. API & Data Model

### 9.1 Endpoints (`/api/workloads/...`)
| Method | Endpoint | Description | Guarded |
| :--- | :--- | :--- | :---: |
| `GET` | `/api/workloads` | All workloads across hosts (filter by runtime, host, state, drift) | No |
| `GET` | `/api/workloads/{id}` | Detail: definition, mounts, networks, security context, backups | No |
| `GET` | `/api/hosts/{host}/runtimes` | Detected runtimes, versions, rootless state, preflight results | No |
| `POST` | `/api/workloads/{id}/adopt` | Track an existing workload (read-only) | No |
| `POST` | `/api/workloads/{id}/capture` | Generate compose/Quadlet/XML/Incus definition | No |
| `GET` | `/api/workloads/drift` | Live vs captured definitions | No |
| `GET` | `/api/runtimes/install/plan` | Report for installing a runtime on a host | No |
| `POST` | `/api/runtimes/install` | Stage `runtime-install` step into a plan | **Yes** |
| `GET` | `/api/templates` | VM/container/stack templates (built-in and user) | No |
| `POST` | `/api/templates` | Create or clone a user template | **Yes** |
| `POST` | `/api/workloads/stage` | Stage a `container`/`stack`/`lxc`/`vm` step into a plan | **Yes** |
| `POST` | `/api/workloads/{id}/action` | start/stop/restart/snapshot/resize (staged or immediate per policy) | **Yes** |
| `DELETE` | `/api/workloads/{id}` | Destroy workload (destructive gate, quorum if protected) | **Yes** |
| `GET` | `/api/panels/catalog` | Panels catalog with risk labels | No |
| `POST` | `/api/panels/stage` | Stage a `panel` install/uninstall step | **Yes** |
| `GET` | `/api/plans/{id}/export?target=bash\|terraform\|puppet\|ansible` | Render a plan to an IaC artifact | No |
| `GET` | `/api/security/workloads/exposure` | Published-port and socket exposure audit | No |
| `GET` | `/api/security/workloads/mac` | sVirt/container-label/AppArmor findings | No |

### 9.2 Tables
- **`runtimes`**: `host_name`, `kind` (`docker`/`podman`/`incus`/`lxc`/`libvirt`), `version`, `rootless`, `user`, `root_dir`, `socket`, `scanned_at`.
- **`workloads`**: `id`, `host_name`, `runtime_id`, `kind` (`container`/`stack`/`lxc`/`vm`/`panel`), `name`, `state`, `image_ref`, `image_digest`, `definition_yaml`, `managed_by` (`storageforge`/`compose`/`terraform`/`puppet`/`panel:<name>`/`unmanaged`), `adopted`, `last_seen`.
- **`workload_mounts`**: `workload_id`, `source_path`, `container_path`, `kind` (`bind`/`volume`/`disk`), `mode`, `mount_id` (link into storage index), `dataset`.
- **`workload_networks`**: `workload_id`, `network`, `mac`, `ip`, `published_ports_json`, `listen_addr`.
- **`workload_security`**: `workload_id`, `mac_mode`, `mac_label`, `privileged`, `capabilities_json`, `seccomp`, `user`, `findings_json`.
- **`workload_templates`**: `id`, `kind`, `name`, `source` (`builtin`/`user`), `params_json`, `spec_yaml`, `checksum`.
- **`panel_catalog`**: `id`, `name`, `spec_yaml` (signed), `risk_flags_json`, `version`, `user_defined`.
- **`iac_exports`**: `id`, `plan_id`, `target`, `rendered_sha256`, `created_at`, `actor`.

### 9.3 UI
Adds a **Workloads** section to the rail next to Inventory: *Containers*, *VMs*, *Stacks*, *Panels Catalog*, *Templates*, with Details/Plan/Export tabs on each workload. Existing **Docker** inventory becomes the *Containers* view with Podman/Incus tabs. Deep links: `/#host=nas-01&tab=workloads&panel=vms`, `…&panel=catalog`, `…&panel=templates`. The topology canvas shows VM/container nodes attached to their backing datasets, plus MAC and exposure badges.

---

## 10. Delivery Phases

| Phase | Deliverables | Modules touched | Estimated effort |
| :--- | :--- | :--- | :---: |
| **W1** | **Scan & Import (Docker/Podman)**<br>• Rootful + rootless Podman, Quadlet and pod discovery<br>• Normalized workload tables, storage correlation<br>• Adopt and capture-as-compose/Quadlet | `docker.py` → `runtimes/`<br>`scanner.py`<br>`db.py`/migrations | **4–5 days** |
| **W2** | **Scan & Import (LXC/Incus, libvirt/KVM)**<br>• Instance, pool, network, disk-chain discovery<br>• VM disks on the storage canvas<br>• Drift detection | `runtimes/`<br>`graph.py`<br>`canvas.py` | **5–6 days** |
| **W3** | **Runtime install & setup**<br>• Preflight + multi-distro install steps<br>• `pooldef`/`netdef` with lockout-safe bridge changes<br>• Rootless Podman/Docker setup | `reinstall.py`<br>`preflight.py`<br>`deploy.py` | **5–6 days** |
| **W4** | **VM templates & deploy (`create-vm.sh` productised)**<br>• Template engine, user templates, export as script<br>• Cloud-image + cloud-init path, ISO path with checksum<br>• Lifecycle actions, snapshots, console tunnel | `scriptkit.py`<br>`payloads.py`<br>`jobscript.py` | **6–7 days** |
| **W5** | **Container, stack & LXC deploy**<br>• `container`/`stack`/`lxc` plan steps, report/apply<br>• Image update with healthcheck rollback<br>• Storage-aware placement advice | `planner.py`<br>`deploy.py`<br>`moves.py` | **5–6 days** |
| **W6** | **Management panel catalog**<br>• Signed catalog + risk labels<br>• Dockhand, Komodo, Dockge, Portainer, Dockploy, Cockpit, Incus UI<br>• Socket proxy, loopback-default exposure, vaulted credentials | `blueprint.py`<br>`keyinstall.py`<br>`server.py` | **5–6 days** |
| **W7** | **IaC export**<br>• Bash (default), Terraform/OpenTofu, Puppet, Ansible renderers<br>• Export-consistency tests, externally-managed detection | `reportextra.py`<br>`fromdesign.py`<br>new `iac/` | **6–8 days** |
| **W8** | **Security integration**<br>• sVirt/container-label/AppArmor audit and fixes<br>• Published-port ↔ firewall reconciler<br>• CIS Docker/Podman/libvirt checks, auditd/Falco rules<br>• Workload-aware brake, snapshots and clean-room | `preflight.py`<br>`shares.py`<br>`protection.py`<br>`alerts.py` | **6–8 days** |
| **W9 (later)** | **Fleet & Kubernetes**<br>• Multi-host placement/migration<br>• k3s/Talos as a catalog target, Helm export | TBD | **TBD** |

Dependencies: W3 reuses the ransomware roadmap's Phase 8 package resolver. W8 depends on its MAC (Phase 3) and Firewall (Phase 4) engines, and can ship its read-only audits earlier than its fixes.

---

## 11. Verification (KVM Lab Gauntlet)

The existing [KVM lab](../../docs/kvm-lab.md) is the proving ground. Tests go through the API like the rest of the suite.

1. **Discovery**: on Debian, Ubuntu, Fedora, Rocky, Alma, openSUSE and Arch, install Docker, rootless Podman, Incus and libvirt. Create known workloads and assert the scan finds every one with correct mounts, ports and labels. Alpine is scanned only, since it has no bash or systemd.
2. **Nested KVM**: confirm a lab VM can run `virt-install` (nested virt) and a Proxmox template boots to an installer prompt.
3. **Runtime install**: bare VMs reach a working runtime from a staged plan. Report is read-only (no package changes between report and apply), and a changed plan is refused with 409.
4. **VM template**: `rocky10`, `debian13` and a cloud-image template create VMs with the key-vault SSH key injected, scan succeeds on first boot, and a second run is a no-op (idempotence).
5. **Hardening defaults**: no generated VM has a non-loopback VNC/SPICE listener. A user template that sets `listen=0.0.0.0` has it flagged in the Report, and the exported script and Terraform carry the same value.
6. **Panels**: each catalog panel deploys, passes its health URL, is recognised by the next scan, and uninstalls without deleting volumes.
7. **Firewall bypass test**: publish a container port on a `ufw`/`firewalld` host. The audit flags it, and the staged fix blocks external access while loopback still works.
8. **MAC**: on an SELinux host a bind mount without `:Z` fails with an AVC, which shows in the MAC panel tagged with the workload, and the generated fix passes. On an AppArmor host a VM with a disk in a custom pool path is flagged before it fails to start.
9. **IaC round trip**: each plan exports to Terraform, Puppet and Ansible. Applying the export to a clean lab host gives the same state as the Bash apply, with a no-change second run.
10. **Recovery**: snapshot a running VM and a stateful stack with the quiesce step, restore into the clean-room network, and verify the data matches.
11. **Brake**: trip a canary and verify that VM and container network traffic is cut along with host traffic, not only the host INPUT chain.

---

## 12. Open Questions

1. **Incus vs LXD**: support both at launch, or Incus only plus read-only legacy LXD?
2. **Terraform vs OpenTofu**: emit provider-neutral HCL and document both?
3. **Docker TCP/remote contexts**: scan-only over SSH, or allow managing remote Docker contexts? (Recommendation: SSH only, no new network listeners.)
4. **Panel overlap**: should "Deploy a panel" warn when a host already has another panel managing the same Docker socket? (Recommendation: yes, and mark as *externally managed*.)
5. **Windows guests**: virtio driver ISO and unattended-install support in W4, or later?
6. **Catalog trust model**: ship the catalog signed by the project, or let operators sign their own?
