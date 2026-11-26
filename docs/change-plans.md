# Change plans

A change plan is an ordered list of steps, each on one host: create a folder, add a pool device, join a tailnet, install a container runtime. It is saved in the database and changes nothing until it is deployed or its script is run. [Plans and scripts](plans-and-scripts.md#staged-changes) lists the storage steps; this page is how every plan goes from saved to applied, and the steps added in 0.5.9.

## From saved to applied

1. **Check.** The plan is read against the index in order, so a later step sees what an earlier one makes. Each step says what it would do, and flags what would block it (`crit`) or deserves a look (`warn`). Nothing reaches a host.
2. **Report.** Deploy → Dry run sends the plan's script to each host as a signed run without `--apply`. Every step looks and says `ok` (already so), `missing` (would change) or `conflict` (blocked), and changes nothing. The report is the preflight: it is what the host is now, not what the last scan said.
3. **Apply from the report.** Apply runs the same script with `--apply` (and `--destructive` for drive steps, which takes `deploy.destructive`). It is applied from the report you read: if the plan was changed after that report, the apply is refused with 409, *the plan changed since this dry run*, and nothing runs. Run the dry run again.
4. **Stop at the first conflict.** On each host the script stops at the first step that fails; the steps after it say they were skipped.

A step's secrets come with the apply, on the signed runner's standard input, and never in the plan or the script: see [Secrets for plan steps](secrets.md#how-a-step-gets-it). A report brings none.

The same script can be downloaded (`GET /api/changes/<id>/script`) and run by hand: `./changes-<plan>.sh` reports, `sudo ./changes-<plan>.sh --apply` applies, `--host user@host` runs it on another machine. A downloaded script never reads secrets from its standard input; it finds what `vault send-secret` wrote.

## runtime-install

*New in 0.5.9. Built, not lab-tested: its lab checks (tier 25) are written and have not run.*

Installs one container or VM runtime on a host: **Docker**, **Podman**, **Incus**, plain **LXC**, or **KVM with libvirt**. Fields: the runtime; where the packages come from (`distro`, the default, or `vendor` for Docker's own repository); rootless, and for which account.

### Where the packages come from

| Runtime | Debian, Ubuntu | Fedora | RHEL, Rocky, Alma | openSUSE | Arch |
| :--- | :--- | :--- | :--- | :--- | :--- |
| Docker | `docker.io`, and `docker-compose-v2` or `docker-compose` when there | `moby-engine`, `docker-compose` | blocked: these carry Podman, use the Docker repository | `docker`, `docker-compose` | `docker`, `docker-compose` |
| Docker, `vendor` | `docker-ce`, `docker-ce-cli`, `containerd.io`, `docker-buildx-plugin`, `docker-compose-plugin` from download.docker.com | the same | the same (the `rhel` or `centos` repository) | blocked | blocked |
| Podman | `podman`, `buildah`, `skopeo`, `uidmap`, and `passt` when there | `podman`, `buildah`, `skopeo`, `container-selinux`, `passt` | the same | `podman`, `buildah`, `skopeo` | the same, and `passt` |
| Incus | `incus` (Debian 13, Ubuntu 24.04; Debian 12 has it in bookworm-backports) | `incus` | `incus` from EPEL, which it enables | `incus` | `incus` |
| LXC | `lxc`, `uidmap` | `lxc`, `lxc-templates` | the same, from EPEL | `lxc` | `lxc` |
| libvirt | `libvirt-daemon-system`, `virtinst`, `qemu-system-x86` and `ovmf` (on arm64 `qemu-system-arm` and `qemu-efi-aarch64`), `swtpm` when there | `qemu-kvm`, `libvirt`, `virt-install`, `edk2-ovmf` (`edk2-aarch64`), `swtpm` | the same | `qemu-kvm`, `libvirt`, `virt-install`, `qemu-ovmf-x86_64`, `swtpm` | `qemu-base`, `libvirt`, `virt-install`, `dnsmasq`, `edk2-ovmf`, `swtpm` |

**Docker's repository** is added only when the key downloaded from download.docker.com is the one pinned in StorageForge: the file must hold exactly one key, and its fingerprint must be `9DC858229FC7DD38854AE2D88D81803C0EBFCD88` (Debian, Ubuntu) or `060A61C51B558A7F742B77AAC52FEB6B621E9F35` (Fedora, RHEL family), checked with `gpg`. Otherwise nothing is installed and the run says which key it found. The apt source is `signed-by` that key alone; the dnf repository file is written by the step with `gpgcheck=1` and that key. **No install script is ever fetched and run** (no `curl | sh`, no `get.docker.com`).

Image-based systems (rpm-ostree) and transactional ones with a read-only root are blocked: their packages are layered another way. A host with no package manager StorageForge knows is blocked.

### What the report says

For the runtime, one of three:

- **present**, with its version (`present: podman version 5.4.0`);
- **installable**, with the packages and where they come from;
- **blocked**, with why (`blocked: rocky carries Podman and not Docker: choose the Docker repository as the source, or Podman`).

And around it, what matters before installing:

| | |
| :--- | :--- |
| Containers | cgroup v2; the `overlay` and `br_netfilter` modules; for rootless, user namespaces (`user.max_user_namespaces`, `kernel.unprivileged_userns_clone`) and that the account exists; Docker beside Podman, and a `docker` that is Podman's shim; an existing `br0` for Incus and LXC |
| libvirt | `/dev/kvm`, or `vmx` and `svm` in the CPU; nested virtualization; VirtualBox loaded; an existing `br0`; copy-on-write advice for VM images on btrfs |
| Room | at least 2 GiB free under `/var/lib`, or blocked |
| Storage driver | Docker on btrfs or ZFS: which driver applies |

The report changes nothing on the host. It reads the package lists the host already has (`apt-cache policy`, `dnf -C`, `zypper --no-refresh`, `pacman -Si`) and does not refresh them; where they are not there it says the check waits for the apply, which refreshes them first.

### What an apply does after installing

| Runtime | Rootful | Rootless (for the account named) |
| :--- | :--- | :--- |
| Docker | `/etc/docker/daemon.json` with container logs kept to 3 files of 10 MB, only if there is none; `docker.service` enabled and started. The account is never added to the `docker` group, which is root on the host | not set up by this step: the check refuses it. Use Podman |
| Podman | `podman.socket` enabled | subordinate uids and gids (65536, after the last range given out), lingering, the account's own `podman.socket` |
| Incus | `incus.socket` enabled, and `incus admin init --minimal` when it has no storage pool (a pool in a folder, the bridge `incusbr0`) | the account joins the `incus` group, which gives it a project of its own and not the daemon (`incus-admin` would) |
| LXC | `lxc-net` enabled where it is a unit | subordinate ids, and 10 veth devices on `lxcbr0` in `/etc/lxc/lxc-usernet` |
| libvirt | the modular daemons (`virtqemud`, `virtnetworkd`, `virtstoragued` sockets) where the packages have them, `libvirtd` otherwise | the account joins `kvm`, for VMs of its own on `qemu:///session` |

Each of these is looked at first and done only when it is not so already, so a second apply says `present` and `ok` for each.

On Alpine (`apk`) the step installs the runtime packages, with no rootless service setup, which is manual there. Not built yet: removing a runtime, choosing the storage pool and network of a new Incus or libvirt from the plan (the `pooldef` and `netdef` steps), and rootless Docker.

## secret-file

Writes a vault secret to a file a service reads, with its owner and mode. See [Secrets for plan steps](secrets.md#the-secret-file-step).

## tool-install, tool-remove and tool-data-remove

The Toolbox steps (0.5.12). `tool-install` installs a catalog entry by one of its methods, and takes everything it runs from the catalog when the script is written, only from an entry that is still trusted and still the one staged; `tool-remove` takes away what an install made and keeps its data; `tool-data-remove` moves that data to the host trash, and is destructive. They are staged from the Toolbox panel rather than written by hand. See [Toolbox](toolbox.md#installing). Built, not lab-tested.
