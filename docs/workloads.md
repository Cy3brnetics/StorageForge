# Workloads

StorageForge runs workloads the way it changes anything else: each is a step of a change plan, checked against the index, reported first and run when the plan is deployed, through a signed run, into the audit log. This page covers what came in 0.5.11. All of it is built, not lab-tested: lab tier 28 (`tests/lab/tiers_workloads.py`, see [KVM lab](kvm-lab.md)) is written and has not run. The steps are in the plan editor under Workloads and VMs; adopting, drift and exports are API routes and fields of the Workloads list, with no buttons of their own yet.

What is here:

- [Compose stacks, LXC containers and Incus instances](#compose-stacks-lxc-containers-and-incus-instances), each with its labels and the firewall rule for what it publishes.
- [Image updates with rollback](#image-updates-with-rollback) on a failed healthcheck.
- [VMs from installer ISOs](#vms-from-installer-isos), for systems with no cloud image.
- [Placement advice](#placement-advice): tuned datasets, databases off the bulk pool, network filesystems, and data nothing protects.
- [MAC at deploy](#mac-at-deploy): `:Z` labels, the `svirt_image_t` fix and AppArmor pool paths.
- [The read side](#the-read-side-quadlets-adopting-a-workload-and-drift): Quadlets, adopting a workload by capturing it, and drift against the capture.
- [Quiesced stacks](#quiesced-stacks): stop, snapshot, start, with the method recorded.
- [Externally managed workloads](#externally-managed-workloads), told by what the host shows, with a warning before a step changes one.
- [Exports](#exports-terraform-opentofu-and-puppet): Terraform, OpenTofu and Puppet.

Running one container (`container`), VMs from cloud images (`vm-create`) and the VM steps are in [VMs on libvirt](vms.md) and [Cloning and migrating hosts](host-migration.md). Installing a runtime first is the `runtime-install` step in [Change plans](change-plans.md).

## Compose stacks, LXC containers and Incus instances

Three steps under **Workloads** in the plan editor. Each one leaves alone what StorageForge did not make: a stack of the same name run from another folder, an LXC container or an Incus instance of the same name, is a conflict and nothing more.

| Step | What it makes | Labels | Firewall rule |
| :--- | :--- | :--- | :--- |
| `stack` | A compose project from the file you give, kept in `/srv/stacks/NAME` (or the folder you name) and brought up with `docker compose`, `docker-compose`, `podman compose` or `podman-compose` | In `storageforge.yaml` beside the compose file, which compose merges in, so your file stays as you gave it. Every service gets `storageforge.managed=true` and `storageforge.stack=NAME` too | A deny and an allow per source in `DOCKER-USER`, for each port the stack publishes on an address other than loopback |
| `lxc` | A container from the LXC download template (images.linuxcontainers.org), always unprivileged | In `storageforge.labels` in the container folder: LXC has no labels of its own | On the host network, a fence on input for the ports you list. Behind `lxcbr0` nothing outside reaches it; bridged onto a LAN bridge, the host firewall does not see it, and the report says so |
| `incus` | An Incus container or VM, with its profiles, storage pool and network checked first | `user.*` keys on the instance (`user.storageforge.managed=true` marks the ones StorageForge made) | A fence on input for the ports its proxy devices listen on |

**Who may reach it.** The field *Only these may reach what it publishes* takes addresses and ranges. Left empty, the check warns about each port published to every network the host is on. Docker and Podman forward published ports past the host INPUT chain, so a ufw or firewalld rule does not stop them: the rule goes in `DOCKER-USER`, through the same `storageforge-fwrules` tool and with the same rule ids as a `fw-rule` step with hook *forward*. A host with no `DOCKER-USER` chain (Podman with netavark, for one) gets a conflict telling you to publish on one address instead, never a rule that does nothing.

**What the report shows.** For a stack: compose validating the file, the volumes it uses, the lines that change against the compose file deployed before, and whether the stack is already up from this file. For LXC: the distribution, release and network, and whether root needs subordinate ids (root gets `root:1000000:65536` in `/etc/subuid` and `/etc/subgid` when it has none). For Incus: what each profile brings, the image fingerprint when the image server answers, and the exact `incus init` line.

**What the check refuses.** A secret written into a compose file (an `environment` key such as `POSTGRES_PASSWORD` with a value): keep it in a [vault secret](secrets.md), write it to a file with a `secret-file` step, and point `env_file` at that file. A service built from source (this step runs images only). Labels starting `storageforge.`, and on Incus the `user.*` keys cloud-init reads (`user-data`, `vendor-data`, `meta-data`, `network-config`). Ports published to an Incus VM, which Incus forwards only in NAT mode with fixed addresses.

Removing: `workload-remove` takes away an Incus instance or a container, keeping volumes and disks. A stack is taken down with `docker compose down` in its folder by hand for now, and an LXC container with `lxc-destroy`: neither has a step yet.

## Image updates with rollback

The `image-update` step pulls what a stack's compose file or a systemd unit names, recreates what changed, and waits for it to be healthy. If it is not healthy in time, the images it ran before are put back under their names and it is recreated again.

- **A stack** (a compose project): found by its containers' compose labels, updated in the folder and with the files it was started from. *Only this service* limits it to one service.
- **A unit**: a Podman container run by a Quadlet or a unit file, found by the `PODMAN_SYSTEMD_UNIT` label Podman gives it; with Docker, name the container the unit runs. After the pull the unit is restarted, which recreates the container from its definition.
- **A container started by hand** has nothing to recreate it from with a new image and the same settings: adopt it as compose first (see the read side), deploy that as a stack, then update the stack.

**Healthy** means each container passes its healthcheck, or, where it has none, runs for 10 seconds without restarting, within the seconds given (120 by default, 10 to 3600). A container that exits, restarts or turns unhealthy fails it at once.

**Before anything changes,** each image in use is tagged `localhost/storageforge-rollback:<name>-<date>`: that tag is what is put back, and after a good update it stays, so you can go back by hand later (`docker tag` it to the name and recreate). When the pull brings nothing new the tags are taken away again and nothing is recreated. An image pinned by digest is never updated.

The report says which images it would pull and what healthy means, and pulls nothing.

## VMs from installer ISOs

The `vm-iso` step makes a VM that boots an installer, for systems with no cloud image: Proxmox VE, or an installer you prefer. Where there is a cloud image, `vm-create` is better: it boots ready, with a login for your key.

**The catalog:** Debian 13 (netinst), Ubuntu Server 24.04, Fedora Server 44 (netinst), Rocky Linux 10 and AlmaLinux 10 (minimal), Arch Linux, Alpine 3.24 (virt) and Proxmox VE 9. Each entry names the checksum list its publisher puts beside its ISOs, and the newest file of that release in the list is the one used, so a point release needs no change here. A custom ISO takes its https URL and its SHA-256 or SHA-512. TrueNAS and OPNsense are not in the catalog: TrueNAS keeps no stable checksum list, and OPNsense ships its installer compressed, which this step does not unpack.

**On apply:** the checksum list is read, the ISO downloaded once into `.storageforge-images` in the libvirt pool's folder and checked, an empty qcow2 disk made, and `virt-install` run with the ISO as the CD. Nothing already there is written over: a disk or a VM of that name is a conflict, and a VM StorageForge did not make is left alone.

**What it sets, that hand-written scripts often get wrong:** the console (SPICE or VNC) listens on 127.0.0.1 only, reached through an SSH tunnel or the console page; the network and the pool are checked before anything is made; the OS variant is checked against the host's osinfo database, with generic defaults and a note when the host does not know it; the guest agent channel is there, for snapshots that freeze the filesystems; firmware is BIOS, UEFI or UEFI with secure boot, and a TPM (swtpm) can be added. UEFI is refused when the host has no OVMF, and a TPM when it has no swtpm.

After the install, take the ISO out with `virsh change-media NAME <CD target> --eject --config`; the report names the command. Unattended installs (kickstart, preseed, autoinstall) are not built: their answer files carry a password or a key, which would have to come from the vault.

## Placement advice

Before a workload's data goes somewhere, the plan check says what the index knows of that place. It never stops a plan: placement is advice. It comes with `stack` (for each bind mount, by what the service is, and for a database with no bind mount, the engine's volume folder), `lxc` (the container folder), `vm-create` and `vm-iso` (the libvirt pool's folder), and from `GET /api/workloads/placement?host=&path=&use=vm|database|data` for a deploy form.

| Advice | When |
| :--- | :--- |
| **A dataset tuned for its use** | VM images on ZFS with a recordsize above 64K (qcow2 writes 64 KiB clusters), databases on ZFS above 16K; the recordsize is the dataset's own or the nearest parent's set on purpose, else ZFS's 128K. VM images or database files on btrfs with copy-on-write, unless the mount has `nodatacow` |
| **Databases off the bulk pool** | A database (by its image: PostgreSQL, MySQL, MariaDB, MongoDB, Redis, InfluxDB, ClickHouse, Elasticsearch and the like) on a pool of spinning disks or parity RAID (raidz, RAID 5, RAID 6) |
| **Bind mounts on network filesystems** | Data on NFS, SMB, sshfs, GlusterFS, Ceph and the like: a database there is a warning that it corrupts or stalls when the connection drops |
| **No hold or offsite copy reaches it** | Nothing snapshots the path (a snapshot job or task, or snapshots a scan saw), no retention hold covers its dataset, and no backup takes it to a host marked offsite. Snapshotted but never copied off the host is a note |

What it reads: the mounts, the disks and pools from `lsblk` and `zpool status`, the ZFS properties set on purpose, and the same facts as the 3-2-1 matrix (deployed mirror and rsnapshot jobs, storage tasks, and backups and snapshots a scan detected).

## MAC at deploy

SELinux and AppArmor keep a container or a VM from files that are not labelled or listed for it. StorageForge sets that at deploy, as part of the plan:

- **Bind mounts of a stack (`:Z` and `:z`).** On an SELinux host, the `stack` step's *SELinux label for its bind mounts* adds `:Z` (this stack alone) or `:z` (shared with other containers) to each bind mount, through `storageforge.yaml`, so the compose file stays as given. The check warns when the last security reading says SELinux is enforcing and a bind mount has neither, and refuses a label on a system folder (`/`, `/etc`, `/usr`, `/var`, `/home`, `/srv` and the like) or `:Z` on a home folder, which would take it from its owner.
- **VM disks under SELinux (the `svirt_image_t` fix).** The `vm-mac` step registers a folder of VM disks as `virt_image_t` with `semanage fcontext`, so a relabel keeps it, and runs `restorecon`. libvirt then gives each running VM its disks as `svirt_image_t` with categories of its own. Under `/var/lib/libvirt/images` the policy already does this; the step is for pools anywhere else.
- **VM disks under AppArmor (pool paths).** On an AppArmor host the same step adds two path rules to `/etc/apparmor.d/local/abstractions/libvirt-qemu`, which every VM profile includes. `apparmor_parser` checks the file first, through a profile that includes the abstraction as libvirt reads it, and the file is put back when it refuses. The profiles of running VMs are reloaded.

**Where it shows.** The infrastructure reading now holds the SELinux label of each libvirt pool folder and each folder a VM disk sits in, and the lines of the local libvirt-qemu abstraction. A VM whose disk folder is not `virt_image_t`, or on an AppArmor host is not under `/var/lib/libvirt/images` and not in the local abstraction, gets a finding on the Workloads page that names the `vm-mac` step for that folder.

## The read side: Quadlets, adopting a workload, and drift

**Podman Quadlets.** The infrastructure reading lists the Quadlet unit files of root (`/etc/containers/systemd`, `/usr/share/containers/systemd`) and of each account that lingers (`~/.config/containers/systemd`): for each, only the keys that say what runs (`Image`, `ContainerName`, `PublishPort`, `Volume`, `Network`, `Label`, `Pod`, `AutoUpdate` and a few more). `Environment`, `Secret` and `Exec` are never printed, as they can hold secrets. On the Workloads page a Podman container shows the Quadlet file that runs it (Podman labels it with its unit), and a Quadlet container with nothing running shows as *defined*.

**Adopting a workload** captures its definition from what the index read of it, and keeps it:

| Runtime | Captured as |
| :--- | :--- |
| Docker, Podman | A compose file (the default) or a Quadlet `.container` unit. Named volumes and networks already there are marked external, so compose uses them rather than making new ones |
| libvirt | Domain XML: CPU, memory, firmware, disks, NICs, graphics (always on 127.0.0.1, whatever the VM had), TPM, serial console and the guest agent channel. It passes `virt-xml-validate`, and holds the fields the reading keeps, not every device libvirt adds by itself |
| Incus | Instance YAML: type, profiles, devices and security keys |

A scan never reads environment values, so none are in a capture: the compose and Quadlet captures say to give them with an env file of your own. A container started by hand can be adopted as compose, deployed as a `stack` from that file, and then updated with `image-update`.

**Drift.** Each later reading is compared with the capture: the image and its digests, published ports, mounts, networks, privileges and added capabilities for a container; vCPUs, memory, firmware, disks, NICs and consoles for a VM; type, profiles, devices and security keys for an instance. The Workloads list puts the capture and its drift on each adopted workload, and `GET /api/workloads/captures` lists every capture as *same*, *drifted* (with what was added and removed) or *gone*.

| Route | What it does |
| :--- | :--- |
| `GET /api/workloads/capture?host=&runtime=&name=&format=` | The definition as it would be captured, saved nowhere |
| `POST /api/workloads/captures` | Adopts it: `{host, runtime, name, format, note}`. Needs `plans.edit`, and is in the audit log as `workload.adopt` |
| `GET /api/workloads/captures`, `GET /api/workloads/captures/ID` (`?raw=1` for the text) | Captures with their drift, and one capture |
| `DELETE /api/workloads/captures/ID` | Forgets a capture (`workload.forget`) |

## Quiesced stacks

The `stack-snapshot` step snapshots what a compose stack keeps, with the stack quiet while it happens. VMs already freeze their filesystems through the guest agent (`vm-snapshot`); this is the same for stacks.

- **What is snapshotted:** each ZFS dataset and btrfs subvolume holding a folder or volume its containers mount, once each. A ZFS snapshot is `DATASET@sf-STACK-DATE`; a btrfs one is read-only, in `.storageforge-snapshots/STACK-DATE` inside the subvolume. A mount on another filesystem is named in the report and left out; when nothing is on ZFS or btrfs the check refuses the step.
- **How it is quiesced:** *stop* (the default, and what a stateful stack needs) stops its containers, takes the snapshots and starts them again, whatever happened to the snapshots; *pause* freezes the processes instead, so the stack stays up but writes still in memory are not in the snapshot; *live* takes them as it runs, crash-consistent only, and the check warns when the stack has a database.
- **The method is recorded** with each snapshot: as the ZFS user property `storageforge:quiesce`, and as a line (date, stack, method, snapshots) in `/var/lib/storageforge/quiesce.log` on the host, besides the run output in the deploy log.

## Externally managed workloads

A panel, a unit or a hypervisor that manages a workload puts back what StorageForge changes, or fights it. StorageForge tells such a workload by what the host itself shows, puts it on the Workloads page (`managed`: who and how), and warns in the plan check before a step changes it.

| What shows it | Managed by |
| :--- | :--- |
| Container labels: Komodo, Portainer, Coolify, Dockhand, Dockge; a `managed-by` label (as Terraform modules and Helm-style tools set) | That tool |
| `PODMAN_SYSTEMD_UNIT`, or a `container-NAME.service` unit from `podman generate systemd` | systemd: the Quadlet or unit recreates it |
| The folder a compose project was started from: `/data/compose` (Portainer), `/opt/stacks` (Dockge) and the other panel folders the Docker page knows | That panel |
| A compose project anywhere else | compose, as a note: the next `compose up` there puts back what is changed |
| A panel running on the host with the container engine socket mounted (or its unit, such as `komodo-periphery`) | *possibly* that panel, as a note, for containers nothing else claims |
| A Proxmox VE host (`/etc/pve`, `qm`, `pct`) | Proxmox VE, for its guests and its LXC containers |
| libvirt metadata another tool wrote (oVirt, OpenStack Nova, or a namespace StorageForge does not know) | That tool |
| A configuration management agent on the host (Puppet, Chef, Salt, ansible-pull, CFEngine) | A note on every workload there that nothing else claims |

The steps that warn are `container`, `stack`, `lxc`, `incus`, `image-update`, `stack-snapshot`, `workload-action`, `workload-remove`, `vm-edit`, `vm-snapshot` and `vm-revert`. The warning says to change it in the tool that manages it, or to adopt it first. A workload made by a StorageForge step is not warned about. Platforms read through their own APIs come with the API connection kind, not from here.

## Exports: Terraform, OpenTofu and Puppet

`GET /api/changes/ID/export/terraform`, `.../opentofu` or `.../puppet` (with `plans.scripts`, into the audit log as `changes.export.TARGET`) writes the workload steps of a change plan as `main.tf` or a Puppet manifest, for your own pipeline. Each is read straight from the plan, never from the Bash script or from each other. Applying inside StorageForge always goes through the signed runner.

| Step | Terraform and OpenTofu | Puppet |
| :--- | :--- | :--- |
| `container` | `docker_image` and `docker_container` (kreuzwerker/docker) | `docker::run` (puppetlabs-docker) |
| `stack` | A `docker_container` for each compose service, with the stack labels | The compose file and `storageforge.yaml` as `file` resources, and `docker_compose` |
| `incus` | `incus_instance` (lxc/incus) with its config, root disk, NIC and proxy devices | `exec incus launch`, guarded by `incus info` |
| `lxc` | A comment: plain LXC has no provider | `exec lxc-create`, guarded by `lxc-info` |
| `vm-create`, `vm-iso`, `vm` | `libvirt_volume`, `libvirt_cloudinit_disk` and `libvirt_domain` (dmacvicar/libvirt), the console on 127.0.0.1 | `exec virt-install`, guarded by `virsh dominfo`, the console on 127.0.0.1 |

Terraform and OpenTofu take the same HCL; only the header and the commands it names differ. Each provider block points at the host its steps are on, and a plan with steps on several hosts says where to add an aliased provider. What has no counterpart is said in a comment where it would be: a firewall rule (`allow_from`, written by `storageforge-fwrules`), the cloud-init part of `vm-create` in Puppet, any step that is not a workload. No export holds a secret: the steps exported carry none, and a VM login key is a public key.

The round-trip tests read each export back and compare it with the plan. They check it with `tofu`, `terraform` or `puppet` where installed; on the build machine none are, and those checks skip. Applying an export on a lab host (OpenTofu with the libvirt provider, `puppet apply`) is roadmap section 1.3, not built here.
