# Cloning and migrating hosts

**Status: design, partly built.** Copy a scanned machine to another one in any direction: physical to VM, VM to physical, VM to VM, or physical to physical. Use it to test a change on a copy, or to move a machine onto other hardware or off it. The same choices apply in every direction. Built so far: the package list and its fixes, VMs from cloud images with VM specs, and copying a host onto any scanned target: its packages, accounts, share files, the layout of its data disks (btrfs, ZFS and LVM included) and user files, with snapshots before and after, and the data at risk accepted before anything is saved. A copy of a ZFS host onto a new VM has run end to end in the lab ([Lab run](#lab-run)). See [Phases](#phases) for what is not built.

## What was decided

| Question | Decision |
| :--- | :--- |
| Directions | All four: physical or VM, to physical or VM. One set of choices, and only the target's preparation differs |
| Where a new VM runs | Any scanned host with libvirt, managed like other workloads. The [KVM lab](kvm-lab.md) is for testing StorageForge and is not the target |
| What comes first | A rebuild from a recipe (distro, packages, config, accounts, storage layout, then user files), not a disk image |
| What a copy is for | Chosen each time: **test** (isolated, new identity, jobs off) or **migration** (same identity, final sync, cutover) |
| Which machines | Servers and desktops from the start. On desktops, home folders are the main user-files choice |

## Creating VMs

A VM is made by `vm-create`, a step of a change plan like any other: scan, plan, check, script, deploy. Nothing here creates a VM behind the plan's back.

1. **Measure the libvirt host** so StorageForge knows its pools, networks and VMs (its infrastructure reading).
2. **Stage the step:** **Create a VM here…** on the host in the web UI, or `storageforge-index vm create --host kvm-01 --name web-02 --spec server --image debian13 --key fleet`.
3. **Check it.** The check says whether libvirt is there, whether the pool and network exist, how much room the pool has, whether the name is taken, and whether the login key is in the vault.
4. **Run the script.** It reports unless `--apply`. With `--apply` it downloads the image once into `<pool>/.storageforge-images/`, checks it against the checksum its publisher lists (or the one you gave for your own image), copies it to `<name>-root.qcow2` and grows it, makes the data disks, writes a cloud-init seed with one login account for your SSH key, and runs `virt-install --import`. It prints the VM's address when it has one.
5. **Bind a vault key and scan the VM.** From then on it is a host like any other.

The script never writes over a disk or a seed file that is already there, and never touches a VM it didn't make: StorageForge marks the VMs it makes in their libvirt metadata.

### VM specs

A spec is a named set of field values: CPUs, memory, disk sizes, image, pool, network, firmware, CPU model, console, login account and key. A step that names a spec has its empty fields filled from it when the plan is saved. So a saved plan always says everything it will do, and changing a spec later changes no plan that was saved with it.

| Built in | Fields |
| :--- | :--- |
| `small` | 1 vCPU, 1 GiB, 10 GiB |
| `server` | 2 vCPUs, 4 GiB, 40 GiB |
| `desktop` | 4 vCPUs, 8 GiB, 60 GiB, UEFI, SPICE console on loopback, CPU passed through |
| `test-copy` | 2 vCPUs, 4 GiB, 40 GiB, on the isolated network `sf-isolated` |

Your own go beside them: `storageforge-index vm spec db --set vcpus=8 --set ram_mb=32768 --set data_disks=200,200 --set image=rocky9 --key fleet`, or `PUT /api/vm/specs/db`. They are kept in the settings, so essential backups hold them.

### Copying a host to a new VM

`storageforge-index vm clone web-01 --host kvm-01 --key fleet [--test]` saves the change plan for the VM: the catalog image for web-01's distro and version (Arch for its derivatives), named `web-01-copy`, from the `server` spec (or `test-copy` with `--test`), and one data disk for each of web-01's data filesystems, half again as large as what it holds. Run it, bind a key, scan the VM, then copy the host onto it as below.

## Copying a host onto another

`storageforge-index clone web-01 --to web-01-copy [--files none|structure|all|/srv/a,/home/ana] [--map /dev/sdb=/dev/vdb] [--migrate]`, or **Copy this host to…** on a host's menu in the web UI. The target is any scanned host: a new VM, or a machine with a fresh install. It saves ordinary plans, run in this order:

1. **A change plan on the target:**
   - **Snapshot before:** a libvirt snapshot of every disk when the target is a VM on a scanned libvirt host. Otherwise a btrfs, ZFS or LVM snapshot of its root, with `/home`, `/var`, `/srv`, `/opt`, `/root` and `/usr/local` when they are other subvolumes or volumes, or a critical risk when its root can't be snapshotted. Names carry the date and time.
   - **The source's packages, accounts and share files:** the `packages`, `accounts` and `config-files` steps. Packages leave out the kernel and the bootloader, which belong to the target's base install.
   - **The services it enables,** with the new `services` step: what the source enables and the target has is enabled and started there. It never disables, unmasks or installs a unit, and a unit the target lacks is listed. It always leaves out the base system's own units, first-boot setup, the network stack, guest tools, a firewall without its rules, boot and subscription units, and StorageForge's job timers. A test copy also leaves out timers and anything that sends data off the machine (backups, sync, mail); a migration takes them. OpenRC services come across by runlevel, less the base system's (`sysinit`, `boot`, `shutdown`).
   - **Its data disks, laid out again on the target's:** the source's layout is moved onto the target's disks and handed to the planner's design-to-plan step, so the steps are the planner's own, in its order:
     - partitions, and filesystems formatted and mounted by label with the source's options, plus `nofail`
     - btrfs pools, rebuilt with `format`, `btrfs-add` and `btrfs-balance` to the source's profile
     - a btrfs with subvolumes, mounted at `/mnt/<label>-top` while its subvolumes are made, then mounted where each was
     - ZFS pools on whole disks with the source's layout, properties and datasets
     - LVM volume groups and their volumes
     - mdadm arrays, with the new `md-array` step: made from the mapped disks, written to `mdadm.conf` so they assemble at boot, and formatted. The step stops before touching a disk when the running kernel has no md driver, and says which kernel package to install

     Every step that writes to a disk keeps its three locks. The plan fills in the confirm field, and only after the risk is ticked.
2. **A Moves plan for user files,** at the level chosen:
   - **structure:** folders with their owners and modes, and no files.
   - **all:** every data filesystem and `/home`, leaving out caches.
   - **chosen folders.**

   It copies and never deletes. A file it would overwrite is kept beside it as `<name>.sf-replaced-<date>`.
3. **A change plan with the snapshot after.**

Disks are mapped with `--map /dev/sdb=/dev/vdb`, a source disk to a target disk, or `--map /srv/data=/dev/vdb` for the disk under a mount. Without it, a VM's empty `sf-data` disks are taken in order. The target's system disk is refused. Some things aren't made, and are listed under **Not copied** with the reason:
- LUKS, whose key is yours to keep
- encrypted ZFS pools, and pools with log or cache devices
- a disk whose filesystems the scan couldn't read (Alpine's lsblk reports none)
- network mounts and bind mounts
- packages from no package source

### Data at risk

Before anything is saved, the plans are listed with every way they could lose or hide data, worst first:
- a disk to be formatted, with what the last scan saw on it
- a root that can't be snapshotted
- a share file that will be replaced (kept beside the new one)
- files of the same name that will be replaced (kept beside them)
- a target that isn't freshly installed

The account check also names every user whose ID differs on the target; no ID is ever changed.

**Web UI:** **Save the plans** stays disabled until each risk is ticked. When one destroys data, the target's name must be typed too.
**API:** `POST /api/clone` refuses (409) until every risk is named in `accept`, and the audit log records what was accepted.
**CLI:** prints the list.

At run time, formatting still needs `--apply --destructive` and the device typed in the plan.

## Directions

The source is always a scanned host. The target is one of two things:

- **A new VM** that StorageForge creates on a libvirt host from a cloud image.
- **A machine that already exists,** physical or virtual, with a fresh base OS installed and scanned. StorageForge doesn't install the base OS on bare metal (PXE is on the "later" list in the [roadmap](../roadmap.md)). You install it, add the scan key, and scan it, as for the [reinstall script](disaster-recovery.md).

| From → to | Target | Method | What differs |
| :--- | :--- | :--- | :--- |
| Physical → VM | New VM | Recipe; disk image later | Virtio drivers come with the image. Hardware-only packages are left out (below) |
| VM → physical | Existing machine | Recipe | Firmware, microcode and drivers are added for the real hardware. Guest tools are left out. Disks are chosen by hand (below) |
| VM → VM | New VM, or an existing one | **Copy as is:** disk images plus the libvirt definition the scan already reads; or the recipe, to change distro, release or hypervisor | Copy as is is the fastest and most exact: the disks are copied while the VM is shut down or from a snapshot, and the definition gets new disk paths, a new MAC address in test mode, and the target's network |
| Physical → physical | Existing machine | Recipe | Both sides have the hardware differences: firmware, drivers, disk mapping, interface names |

Copy as is works only between libvirt hosts at first. Proxmox guests are listed and never managed, as now, so a copy from or to Proxmox uses the recipe.

## Why a recipe and not a disk image

A recipe fits the rules in [Concepts](concepts.md#the-rules): scans read and change nothing, and plans are scripts that report first. It also works in all four directions, because it doesn't care what the hardware is. Most of it exists already. The [config history](disaster-recovery.md) keeps each host's fstab, crypttab, mdadm, exports, Samba and accounts, `reinstall.py` brings storage back on a fresh OS, the `vm` plan step imports a disk with `virt-install`, and the sync engine copies and verifies data between hosts. A recipe copy also comes out clean: the base is current and the disks are only as large as they need to be.

A disk image is the most faithful copy. It is also the riskiest to build, because it reads raw disks as root, needs a snapshot for a consistent copy, and needs the initramfs and drivers fixed before it boots. Writing one to bare metal would need the target booted into a live environment. It stays on the list as a later phase, apart from VM to VM, where the image is already a file.

## How it works

1. **Choose** the source, the target (a libvirt host for a new VM, or a scanned machine), the method, and a mode (test or migration).
2. **Choose what goes across.** Each level includes the ones before it:

   | Level | The target gets |
   | :--- | :--- |
   | Packages | The same distro and version, the packages installed on purpose, Flatpak and Snap apps |
   | Config | `/etc` files from the config history, accounts and groups (no passwords), enabled services, and the storage layout on the target's disks |
   | User files | **None**, **structure** (folders, owners and permissions, no contents), **chosen folders**, or **everything** |

   Any level can be used on its own against a target that is already set up: only packages, or only user files.
3. **Check.** One script reports what it would do: the base image or the base OS it found, the disk mapping, the packages that don't exist in that release, the hardware differences, the sources it won't add, and the room on the target. Nothing changes until it is run with `--apply`.
4. **Build.** A new VM boots a cloud image with cloud-init and the deploy key. An existing machine is reached as it is. Then each level is applied, and user files are copied with the sync engine.
5. **Scan the target.** It is scanned like any host, so the [config history](disaster-recovery.md) diff and `hosts packages --against` show what still differs from the source.

## A target that already exists

- **It must be freshly installed, or be told otherwise.** If its last scan shows data outside the system folders, the check is a conflict unless **merge** is chosen. Merge adds to the target and never removes or overwrites a file that differs, and it lists those files.
- **Disks are mapped, never guessed.** The check pairs each source filesystem or pool with a target disk by size and lists the pairs. Creating a filesystem on a real disk is a drive task, with the [three locks](security.md) that drive tasks already have. The system disk is never offered.
- **The base OS has to match.** Packages and config go only onto the same distro, or one in the same family with a warning (as with `hosts packages`). A different release is the way to upgrade during a move, and the check names each package that doesn't exist there.

## Hardware differences

The package script decides on the target, when it runs, because only the target knows what it is. It reads whether it's a VM (`systemd-detect-virt`), its CPU vendor, its graphics (PCI vendor IDs), whether it's a Raspberry Pi, its architecture and its x86-64 level. It says what it found, and every package it leaves out is listed with the reason.

| What | Going to a VM | Going to hardware |
| :--- | :--- | :--- |
| Kernel and bootloader | Left to the base install (`linux-*` kernels, `kernel-*`, GRUB, shim, systemd-boot, Limine, a Pi's kernel, bootloader and EEPROM tools) | The same: the copy never changes how the target boots |
| Firmware (`linux-firmware`, `*-firmware`, `firmware-*`) | Left out | Kept |
| CPU microcode | Left out: the VM's host loads it | Kept for the target's CPU vendor, and left out for the other one |
| Graphics drivers | NVIDIA, AMD and Intel drivers left out, as a VM has none of those GPUs | Kept only for a GPU the target has |
| Guest tools | `qemu-guest-agent` added on KVM, and `spice-vdagent` too for a desktop; `open-vm-tools` on VMware | Left out |
| Hardware tools and services | `smartmontools`, `fwupd`, `thermald`, `tlp`, sensors, `rasdaemon`, `mcelog` and `cpupower` left out, and their services off | Kept |
| Raspberry Pi packages and services (`raspi-*`, `rpi-*`, `libraspberrypi*`, `pi-bluetooth`, GPIO and camera libraries) | Left out, unless the target is a Pi. `rpi-imager` writes SD cards from any computer, so it stays | The same |
| CPU level | Packages from repositories built for x86-64-v3 or v4 (CachyOS) are refused on a CPU that lacks it, before anything is installed. The plan check says so too when the target's scan shows its level, and `vm clone` gives such a VM the host's CPU (`host-passthrough`) | The same |
| Architecture | Across architectures (a Pi's arm64 or armhf onto amd64), packages come by name, built for the target; names tied to the source's architecture (`libc6:arm64`) lose the tag. Programs not from a package (`/usr/local`, `/opt`, home folders) and container images built for the source's architecture are copied as they are and won't run: that's a warning in **Data at risk** | The same |
| Network interfaces | Not renamed: the copy keeps the target's own network setup, and never carries the source's | The same |

Raspberry Pi OS reports itself as `debian` (64-bit) or `raspbian` (32-bit), and `vm clone` starts both from the Debian image of the same release.

## Test mode: a copy that must not act like the original

A copy on the same LAN as its source can do harm. A copied backup job writes over the real host's backup target, and a copied address or hostname takes over the real machine's name. So in test mode, in every direction:

- a new VM runs on an isolated libvirt network with no route out, unless it is given one. A physical target can't be isolated by StorageForge, so the check says so and asks for a VLAN or a cable you choose
- the copy gets a new hostname, machine-id and SSH host keys, and a VM gets a new MAC address
- StorageForge jobs, rsnapshot, snapshot sends, cron and user timers are turned off, and the scheduler doesn't run them
- outbound mounts (NFS, SMB, sshfs) stay in fstab but are marked `noauto`, so the copy never writes to the real server
- the copy is labelled a copy of its source in the index, so alerts and the map don't count it as another copy for 3-2-1

## Migration mode

The target keeps the source's hostname and accounts, and its address once the source is retired. It ends with the existing [cutover](plans-and-scripts.md): a last delta sync with the source's writers stopped, the source renamed rather than wiped, and `hosts rekey` and a rescan. Hardware to hardware is the classic server move, VM to hardware takes a machine off a hypervisor, and VM to VM moves a guest between libvirt hosts.

## Snapshots before and after

Every run takes a snapshot of what it is about to change, and another when it finishes. These are on by default and can't be turned off in migration mode.

| When | Of what | Why |
| :--- | :--- | :--- |
| **Before**, on the target | Every filesystem the run writes to, on an existing machine; a new VM's disks after first boot | A way back to the state before the run |
| **Before**, on the source | The filesystems that user files are copied from | The copy reads from the snapshot rather than the live tree, so it is consistent. In migration mode it is also the source as it was at cutover |
| **After**, on the target | The same filesystems, once every step has passed | A known good copy, kept before people start changing it |

How each kind of storage is snapshotted:

| Storage | Snapshot |
| :--- | :--- |
| btrfs | A read-only subvolume snapshot (`btrfs subvolume snapshot -r`) |
| ZFS | A recursive snapshot (`zfs snapshot -r`) |
| LVM thin | A thin snapshot |
| LVM, not thin | A copy-on-write snapshot, sized by the check, which refuses if the volume group lacks the room |
| A libvirt VM | A disk-only external snapshot (`virsh snapshot-create-as --disk-only`), whatever filesystem is inside |
| ext4 or XFS on a plain partition | **None is possible.** The check says so for each filesystem, and offers a copy to another host with the sync engine first. Going on without one is a risk to accept by name (below) |

- Snapshots are named `sf-migrate-<run>-before` and `-after`, and get a [hold](ransomware-defense.md#releasing-a-hold) for 14 days by default. Neither the run nor any retention policy can prune them. Releasing one early is the usual release, with its cool-off or a second admin.
- The check works out the room each snapshot needs (a copy-on-write size, a thin pool's free space, how much the data is likely to change) and is a conflict if it isn't there.
- **What changed** compares the before and after snapshots (`zfs diff`, `btrfs subvolume find-new`, or the index's change list from scans of each) and goes into the run's report.
- **Roll back** returns the target to *before*, through the existing rollback preview. The preview first shows what would be thrown away: files changed or added since the snapshot, with counts and sizes.

## Where data can be lost, and the warnings

Each place a run could delete or overwrite data is listed below. Each one is a **risk** in the check, with the data named from the index (paths, sizes, file counts), not described in general terms. Nothing on this list happens silently.

| Risk | Where | Default |
| :--- | :--- | :--- |
| Creating a filesystem on a target disk | Config and storage, on an existing machine | Refused unless chosen. A drive task with its three locks, and the warning shows what the last scan found on that disk: label, filesystem, bytes used, top folders |
| No snapshot is possible | ext4 or XFS on a plain partition | Refused until accepted, or until the offered copy to another host is made |
| Config files replaced | `/etc` files that differ on the target | Each is kept as `<file>.sf-<run>` beside the new one, and listed with its diff |
| Packages removed to make room for others | Package installs | **Refused.** apt runs with `--no-remove`, and zypper and apk are simulated first; any removal is a conflict that names the packages |
| Files on the target that the source lacks | User files, **everything** | Kept. A mirror that removes them is a separate choice, with a count and the list |
| Files that differ in a merge | Merging into a machine that has data | Never overwritten, and listed |
| A disk image that already exists | VM to VM copy as is | Refused. The target path must be new |
| An account whose UID differs | Accounts | Its files are never chowned without asking. The check lists the account, both UIDs and how many files each owns |
| A target disk smaller than the data | Disk mapping | Refused before anything is written, never found out halfway through a copy |
| Rolling back | Roll back to *before* | The rollback preview, then confirmation |
| Releasing a migration snapshot | After the run | The usual hold release, with its cool-off |
| Writing a whole disk | Disk image to bare metal (phase 7) | The strongest warning there is: the whole disk, with every partition the scan saw on it |

**In the web UI** the check opens a **Data at risk** list above its other results, worst first, in plain sentences, as the map's what-if does now. **Apply** opens a dialog that lists every risk again and needs each one ticked. For a risk that destroys data (a new filesystem, a whole disk, a rollback), you also type the host name. The dialog can't be dismissed by Escape or by clicking outside it. A risk that comes up between the check and Apply, because the index changed, sends you back to the check (a 409, as for a changed plan).

**On the command line and in scripts,** `--apply` stops before the first step while any risk is open, and prints each one with an ID. Each risk is accepted with `--accept RISK-ID`, or with `--destructive` for drive tasks, as now. A script run by hand prints the same list before it acts.

**Afterwards,** the run's report lists every risk that was accepted, and by whom, and the audit log records it.

## Desktops

- Home folders are the main user-files choice. **Structure** gives each user their folders with nothing in them, which is enough to test a configuration change.
- Caches (`~/.cache`, browser caches, Flatpak's `~/.var/app/*/cache`, Steam libraries) are left out unless asked for.
- The display manager and desktop come across as packages. GPU passthrough isn't attempted.

## Arch and the AUR

Packages from the AUR (and any `pacman -U` of a downloaded file) come from no package source, so no package manager can install them on the clone. Phase 1 lists them apart and installs none. What a clone needs instead, from what one real CachyOS desktop showed on 2026-11-07 (40 AUR packages, paru and yay both present):

- **The built package is usually gone.** None of the 40 installed builds was still in `~/.cache/paru/clone`, `~/.cache/yay` or `/var/cache/pacman/pkg`. A cache can't be the main way.
- **AUR packages depend on each other.** 5 of the 40 were dependencies of others, so they go across together, in one `pacman -U`.
- **14 were `-git`, `-bin` or AppImage builds.** A `-git` version moves every day, though some carry their commit (`r5018.ga010adc904`). A `-bin` package repackages a vendor download, which may no longer exist.
- **Versions carry epochs** (`gtkmm 1:2.24.5-5`), which file names and comparisons have to keep.

The plan, in order of preference for each package:

1. **The exact build from a cache,** if one survives: the helper caches, `PKGDEST` in `makepkg.conf`, and `/var/cache/pacman/pkg`. It counts only if its version and build date match `pacman -Qi` on the source.
2. **Repackaged from the installed files** with `bacman` (pacman-contrib), run on the source by a signed script. That gives the files exactly as installed, including edited config, and needs no network. pacman-contrib may need installing first, and the script says so.
3. **Built on the clone from the AUR,** as an unprivileged build user (`makepkg` refuses root), at the AUR commit whose `pkgver-pkgrel` matches the source, or at the commit hash in a `-git` version. This needs the network, so it runs in the build stage, before a test clone is cut off.
4. **Listed for doing by hand,** with the reason.

Then `pacman -U` all of them at once. Locally built packages are unsigned, which pacman's default `LocalFileSigLevel` allows.

**Rolling releases drift.** A fresh Arch image is newer than the source, and an AUR build linked against older libraries can break on newer ones. By default a clone is pinned to the [Arch Linux Archive](https://archive.archlinux.org/) date of the source's last full upgrade, from `starting full system upgrade` in `/var/log/pacman.log`. With **current**, it gets today's packages instead.

**Arch derivatives have no cloud image.** CachyOS, EndeavourOS, Manjaro and Garuda clones start from the Arch image and need the derivative's repositories and keyring. That breaks phase 1's "sources are listed, never added", so for clones it is an explicit choice that shows each key's fingerprint before it is trusted. Two of them have their own catch:
- CachyOS's `x86-64-v3` and `v4` repositories need a VM CPU that has those instructions. The check refuses a libvirt host or CPU model without them, rather than building a VM that dies with *illegal instruction* on first boot.
- Manjaro holds packages back behind Arch, so its clones pin to Manjaro's branch, not to the Arch archive.
- The same goes for third-party repositories on plain Arch, such as Chaotic-AUR.

## Other package systems that need their own handling

Phase 1 reads apt, dnf and yum, zypper, pacman and apk. The rest fall into three groups.

**Where phase 1 reads the wrong thing today.** These need fixing before phase 2:

| System | Examples | The problem | What to read instead |
| :--- | :--- | :--- | :--- |
| Image-based, rpm-ostree or bootc | Fedora Silverblue, Kinoite, CoreOS, Bazzite and Universal Blue, RHEL image mode | `dnf` is there, but packages are layered onto an image | `/run/ostree-booted`, then the image reference and the layered packages from `rpm-ostree status --json`. The clone is that image plus the layers |
| Transactional | openSUSE MicroOS, Aeon, Kalpa, SLE Micro | `zypper` is there, but the root is read-only and changes go through `transactional-update` | The same zypper list, installed with `transactional-update pkg install` and a reboot |
| Read-only by design | SteamOS, Ubuntu Core | `pacman` is there, but its list is the vendor image; what the user added is Flatpaks or snaps | Recognise the platform. Copy only the apps, and say the base can't be cloned |
| apt on rpm | ALT Linux, PCLinuxOS | `apt-get` is there with no `apt-mark`, and the packages are rpms | `rpm -qa` as the list, installed with `apt-get` |
| Local `.deb` files, holds, backports, PPAs | Debian, Ubuntu | `apt-mark showmanual` includes debs that came from no source (as with the AUR), and loses holds and backports | `[installed,local]` from `apt list --installed`, `apt-mark showhold`, and the release each package came from (`-t bookworm-backports`). A PPA is a source plus a key |

**Declarative: copy the configuration, not a list.** These rebuild exactly from their own files, and do it better than any list:

| System | What to copy |
| :--- | :--- |
| NixOS | `/etc/nixos` or the flake with its `flake.lock`, then `nixos-rebuild`. For Nix on another distro, `nix profile list` and home-manager's config |
| Guix System | `config.scm` and `channels.scm` pinned with `guix describe`, then `guix system reconfigure` |

**Their own package managers:**

| System | Installed on purpose | Notes |
| :--- | :--- | :--- |
| Gentoo (Portage) | `/var/lib/portage/world` and `world_sets` | Built from source: USE flags, `package.*`, `make.conf` and overlays go too. `quickpkg` makes binary packages from the installed files, like `bacman`. `-march=native` needs a VM CPU model that matches |
| Void (xbps) | `xbps-query -m` | Its glibc and musl builds are different distros. `xbps-src` builds are local, like the AUR |
| Slackware | Every package in `/var/log/packages` | It doesn't track dependencies, so there is no "installed on purpose". SlackBuilds are local builds |
| Solus (eopkg) | `eopkg li` | |
| Alpine (apk) | Read already | A tag in `world` (`pkg@testing`) needs its tagged repository, and packages added with `--allow-untrusted` are local files |

**Outside any package manager, on every distro.** No package list records these, so they arrive as files or not at all. The clone's check lists each so nothing is lost without a word:
- `pipx`, `pip --user`, `npm -g`, `cargo install`, `go install`, Homebrew on Linux
- AppImages, and software unpacked into `/opt` or `/usr/local`
- container images (the workloads inventory already finds the containers)
- firmware and DKMS modules

## Phases

| Phase | What | State |
| :--- | :--- | :--- |
| 1 | **Package list**: collected by each scan, `hosts packages` to list and compare, a script that installs the same set with the same package manager. Across releases, versioned libraries are left out, and names the target's sources lack are listed, not tried | Built; collector lab-tested on 7 distros, install on apt |
| 1b | **Fixes to phase 1:** image-based, transactional and read-only systems, apt on rpm, Debian's local debs, holds and backports, AUR versions | Built, unit-tested, **not lab-tested** |
| 2 | **Targets:** new VMs from cloud images, with VM specs (`vm-create`, `vm create`, `vm clone`), and any scanned machine through `clone`, with a warning when it isn't freshly installed | Built; `vm-create` lab-tested |
| 2b | **The `packages` step:** another host's packages, as a plan step | Built, lab-tested on apt |
| 3 | **Config and storage:** the `accounts` and `config-files` steps, and the data disks' layout through the planner's design-to-plan step: partitions, filesystems, btrfs pools and subvolumes, ZFS pools and datasets, LVM, mdadm arrays (`md-array`) | Built; accounts, ZFS, btrfs raid1 and nested subvolumes, and an mdadm raid1 lab-tested. LVM not lab-tested |
| 3a | **Services:** the scan records enabled systemd units and OpenRC services, and the `services` step starts them on the copy | Built, lab-tested on systemd (Leap 16) and OpenRC (Alpine 3.24) |
| 3d | **Not built:** LUKS (its key is yours: by hand), other `/etc` files | Planned |
| 3b | **AUR and local builds:** cache, `bacman`, an AUR build at the matching commit; Arch Linux Archive pinning; derivative repositories and CPU levels | Planned |
| 3c | **Hardware differences:** kernels and bootloaders, firmware, microcode, GPU drivers, guest tools, hardware tools and services, Raspberry Pi packages, the CPU level and the architecture, decided on the target | Built. Lab-tested from real hardware (CachyOS, NVIDIA, x86-64-v3 packages) onto an Arch VM, with the CPU-level refusal on a v2 CPU. Going to hardware is unit-tested only |
| 4 | **User files:** none, structure, chosen folders or everything, through Moves with `dirs_only` and `keep_replaced` | Built; `all` lab-tested and verified by checksum |
| 4b | **Snapshots and risks:** before and after snapshots, the Data at risk list with its ticks and typed name, and `accept` in the API. Not built: holds on the clone snapshots, the before/after "what changed" report, `--accept` in the scripts | Built in part, **not lab-tested** |
| 5 | **Test and migration modes**: the isolation above, and cutover | Planned |
| 6 | **VM to VM copy as is**: disk images and the libvirt definition, between libvirt hosts | Planned |
| 7 | **Disk image from a physical host**: a block copy from a snapshot into qcow2, then fixed up to boot. To bare metal, through a live environment | Later |

## Lab run

On 2026-11-07, against a lab build of `sf-ctl`, `sf-ubuntu`, `sf-jammy`, `sf-bookworm`, `sf-fedora`, `sf-suse` and `sf-alpine`, with the work uncommitted:

- **The package list** was read on all seven: Debian 12 and 13, Ubuntu 22.04 and 24.04, Fedora 44, openSUSE Leap 16 and Alpine 3.24. The install script ran in report mode across releases, and `sf-jammy`'s list was applied to `sf-ubuntu`.
- **The whole copy**, onto a VM made by the `vm-create` step on the lab network:
  1. `vm-create` built it from the Ubuntu 22.04 cloud image, with two `sf-data` disks.
  2. A scan of the new VM.
  3. `clone sf-jammy --to sf-clonetest --files all`.
  4. The change plan with `--apply --destructive`. It installed `zfsutils-linux`, added two accounts with their IDs, and made the `vault` mirror with `compression=lz4` and `atime=off` and its two datasets.
  5. The Moves plan copied `/home` and `/vault` (1.1 GiB), and `--verify --checksum` matched every step. Running the change plan again found nothing to do.
- **A second whole copy, `sf-fedora` onto a new Fedora 44 VM** (btrfs root):
  1. Snapshots before of `/`, `/home` and `/var`.
  2. dnf packages and accounts.
  3. The btrfs raid1 pool rebuilt: format, add, then a balance to raid1 data and metadata.
  4. Its three subvolumes made and mounted.
  5. The files copied and verified by checksum, then the snapshots after.
- **The locks held:** a copy mapped onto a disk of the VM's now-mounted pool, run with `--apply --destructive` and the device typed again, stopped at "/dev/vdb is in use" and touched nothing.
- **Planned but not applied:** btrfs raid10 (`sf-bookworm`) and nested subvolumes (`sf-suse`). The mdadm array on `sf-suse` was listed as not copied, as it should be.
- **Not run:** LVM (no LVM host in that build), the libvirt snapshot (the VM's libvirt host wasn't scanned), copying share files that share something (every lab host has a stock `/etc/exports`), the migration mode's notes and cutover, and the web form.

- **A third round, for mdadm and services:**
  1. `sf-suse` was copied onto a new openSUSE Leap 16 VM: zypper packages, accounts, its whole-disk mdadm raid1 with ext4, and its nested btrfs.
  2. After a reboot the array assembled from `mdadm.conf`, in sync, and every mount came back by label.
  3. The files, including the array's, matched by checksum.
  4. With `chronyd` and `fstrim.timer` turned off on the VM, a test copy started `chronyd` and left the timer off. A migration also enabled the timer.
  5. On a new Alpine 3.24 VM, the OpenRC path added `chronyd` and `local` to the default runlevel and started them, installed the apk packages and added the accounts. A second run found nothing to do.

- **A fourth round, for hardware differences:**
  1. The package list of this workstation (CachyOS on a Ryzen with an NVIDIA GPU, 357 packages from `cachyos-v3`) was run in report mode on a new Arch VM.
  2. It left out 13 kernel and boot packages, the NVIDIA and AMD drivers, the firmware, the microcode and the hardware tools. It added `spice-vdagent` for the desktop, and confirmed the CPU runs x86-64-v3.
  3. With the VM's CPU model set to Nehalem (x86-64-v2), it refused before installing anything.

- **The final test: three Raspberry Pis (`rpi01docker`, `rpi02-docker`, `rpi03-docker`, arm64, Debian 13, Docker and NFS) onto three amd64 Debian 13 VMs on this machine,** on the lab's NAT network, so the copies, which serve the same NFS shares, can reach the Pis while the LAN can't reach them:
  1. Read-only scans of the Pis. `vm-create` made a VM for each, its login named after the Pi's first user (`rpi`, UID 1000) and its data disk sized from what the Pi holds.
  2. Docker's package source added on each VM by hand, as the report asked. NetBird was left out with `--skip netbird`: a test copy should not join the mesh VPN.
  3. The change plans installed 63 to 64 packages each, Docker 29.9.3 included, and left out 8 kernel and boot packages, the Raspberry Pi packages and the Pi firmware. They added `qemu-guest-agent` and `parted`, gave `rpi` its 17 groups, partitioned and formatted the data disks with the Pis' labels, mounted them, wrote the NFS exports and started Docker and the NFS server. NetBird stayed off.
  4. The files plans copied `/home` and the data filesystems: 8.3 and 10.6 GiB, and 146 GiB with 4.35 million hard-linked files on `rpi01docker`.

Bugs it found, all fixed:
- bash before 5.2 couldn't parse the `vm-create` step. A test now looks for that pattern in every script.
- `--forward-agent` never reached the host in Moves, change-plan, task and share scripts, because the shared SSH connection was opened without the agent.
- A failed `vm-create` left its disks behind, and `virt-install` didn't name the system libvirt.
- Copying across releases tried old versioned libraries such as `libssl3` and `gcc-12-base`.
- ZFS datasets weren't copied at all, since fstab doesn't name them, and a whole-disk system disk wasn't recognised.
- The scan missed the package sources of Debian cloud images (`mirror+file:`), and listed base snaps as apps.
- A btrfs root's snapshot left out `/home` and `/var`, its other subvolumes.
- Snapshot names carried only the date, so a second copy the same day took the first one's snapshot for its own.
- The btrfs top level was unmounted in the same plan that mounted it, so every re-run did both again.
- Saving the same copy twice in a minute failed.
- A stock `/etc/exports` of only comments was copied over the target's.
- A plan was made against a target scan older than an earlier copy onto its disks. That is now a critical risk.
- A whole disk in an md array wasn't seen as one, by the scan or by the planner, and nor would a whole-disk LUKS or LVM member be, so `sf-suse`'s array was missing from the topology too.
- `mdadm` takes no `--` before its devices: with it, the array was never made, and an array already there was never found.
- The Leap Minimal image's `kernel-default-base` has no md driver. The step now says so, and how to fix it, before touching a disk.
- The copy tried to install the source's kernel, which needs the target's own removed. Kernels and bootloaders are now left to the base install.
- A report on a target whose root isn't btrfs called its subvolume steps conflicts, because the btrfs they go on is only mounted by an earlier step.
- A Pi's boot partition, `/boot/firmware`, was taken for a data filesystem, and got a data disk of its own.
- The VM's login took UID 1000, which the Pi's own user has, so its accounts could not come across. `vm clone` now names the login after the source's first person.
- A fresh cloud image has no apt lists, so a report called 66 ordinary packages missing from the sources. A report now leaves that to `--apply`, which updates the lists first.
- The Debian cloud image has no `parted`. A copy now installs the tools its own steps run (`parted`, `mdadm`, `lvm2`, filesystem tools) with its packages, and a report knows an earlier step installs them.
- Four Pi packages from Raspberry Pi's repository slipped through (`userconf-pi`, `rpifwcrypto`, `libpam-chksshpwd`, `kms++-utils`), and a name the target's sources lack stopped the whole copy. It is now listed, and the rest go on.
- `stripe=8191`, from the geometry of the Pi's USB SSD, was copied into the new fstab. Disk geometry options are left out.
- The space check counted each name of a hard-linked file, wanting 277 GiB for a filesystem using 146. A copy now needs no more than its filesystem uses.
- `vm-create` gave the VM no channel for `qemu-guest-agent`, so the agent never started.
- A test copy started NetBird, Tailscale and other mesh VPNs and tunnels. They now stay off a test copy, like backups and mail.
- The package script stopped at the first firmware package on real hardware: a test that kept the package ended the classifying function with a failure, which `set -e` treats as fatal.
- `rpi-imager` was taken for a Pi-only package.
- `vm-create`: Leap 16 doesn't boot without a video device, so every serial-console VM now has one with no display. On Alpine, whose OpenSSH has no PAM, the locked account refused the SSH key and the image has no `sudo`. The account now has a password hash that matches no password, made for each VM, and cloud-init installs `sudo` on Alpine.

## The package list (phase 1)

Each scan now reads, as the scan user, and changes nothing:

| Package manager | Installed on purpose |
| :--- | :--- |
| apt | `apt-mark showmanual` |
| pacman | `pacman -Qqe`, with `pacman -Qqm` (AUR and local files) kept apart and never installed |
| dnf, yum | `repoquery --userinstalled` from the cache only, then `history userinstalled`, then every package as a last resort (shown as *every package*) |
| zypper | Every package less those in `/var/lib/zypp/AutoInstalled` |
| apk | `/etc/apk/world` |

It also reads Flatpak apps with their remote, Snaps with their confinement, and the package sources. Users, passwords, queries and fragments are taken out of source URLs before they are stored.

```bash
storageforge-index hosts packages web-01                      # the list
storageforge-index hosts packages web-01 --against web-02     # what each has that the other lacks; exit 1 if they differ
storageforge-index hosts packages web-01 --script -o pk.sh    # then on the new machine:
sudo ./pk.sh                       # reports what it lacks
sudo ./pk.sh --apply --skip steam  # installs; a name that won't install is tried on its own and reported
./pk.sh --host admin@new-box       # copies itself over and runs there with sudo
```

What the script won't do, and why:

- **Remove a package to make room for another.** apt runs with `--no-remove`, dnf without `--allowerasing`, pacman's `--noconfirm` answers no to removing a conflict, and zypper and apk are simulated first. A removal is a conflict that names the packages, and nothing is installed with it.
- **Translate names between package managers.** An apt list is refused on a dnf host, because a guessed mapping installs the wrong things. Debian to Ubuntu, or Fedora to Rocky, is allowed with a warning, and any name that doesn't exist there is reported.
- **Add package sources.** Each source brings a signing key, and trusting a key is the operator's decision. The script lists the source host's sources so they can be added first.
- **Install AUR packages, or Flatpaks from a remote the machine lacks.** It lists them.
