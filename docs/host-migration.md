# Cloning and migrating hosts

**Status: design, partly built.** Copy a scanned machine to another one in any direction: physical to VM, VM to physical, VM to VM, or physical to physical. Use it to test a change on a copy, or to move a machine onto other hardware or off it. The same choices apply in every direction. Built so far: the package list and its fixes (phases 1 and 1b), VMs from cloud images with VM specs (the new-VM half of phase 2), and the `packages` step that puts a host's packages on another one. See [Phases](#phases) for what is not built.

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

`storageforge-index vm clone web-01 --host kvm-01 --key fleet [--test]` saves two plans:

1. **The VM**, from the catalog image for web-01's distro and version (Arch for its derivatives), named `web-01-copy`, from the `server` spec, or `test-copy` with `--test`.
2. **Its packages:** a `packages` step on `web-01-copy`, from web-01's last scan. Its check is critical until the copy has been scanned, so it waits for step 5 above.

Config, accounts, storage layout and user files come in later phases.

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

These apply whenever one side is physical, and between two different physical machines:

| What | Going to a VM | Going to hardware |
| :--- | :--- | :--- |
| Firmware and microcode | Left out (`linux-firmware`, `intel-ucode`, `amd-ucode`, `*-microcode`) | Chosen from the target's CPU vendor and the devices its scan sees |
| Graphics drivers | Left out (`nvidia*`, proprietary DKMS modules). The VM gets a virtio GPU and SPICE on loopback | Kept only if the target has that GPU, and otherwise listed |
| Guest tools | Added (`qemu-guest-agent`, `spice-vdagent`) | Left out |
| Network interfaces | Renamed: `enp3s0` becomes `enp1s0` | Renamed, matched by order or by MAC address, chosen in the check |
| Hardware services | `fwupd`, `smartd`, `thermald`, `tlp` and sensor or RAID-controller tools left off | Kept |
| CPU level | The VM's CPU model must offer what the source's packages need (`x86-64-v3`, Gentoo's `-march=native`) | The target CPU must, too. The check refuses rather than building something that won't boot |
| Boot | Whatever the cloud image uses | Left to the base install. The copy never touches the bootloader |

The lists are a starting point, and the check shows each package it leaves out, so nothing is dropped without a word.

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
| 1 | **Package list**: collected by each scan, `hosts packages` to list and compare, a script that installs the same set with the same package manager | Built, unit-tested, **not lab-tested** |
| 1b | **Fixes to phase 1:** image-based, transactional and read-only systems, apt on rpm, Debian's local debs, holds and backports, AUR versions | Built, unit-tested, **not lab-tested** |
| 2 | **Targets:** new VMs from cloud images, with VM specs (`vm-create`, `vm create`, `vm clone`) | Built for new VMs, unit-tested against stand-in libvirt tools, **not lab-tested**. Existing scanned machines as targets, with the freshly-installed check and merge: planned |
| 2b | **The `packages` step:** another host's packages, as a plan step | Built, **not lab-tested** |
| 3 | **Config and storage**: the reinstall script given a *create* mode for blank disks (it never formats today), disk mapping under the drive-task locks, and enabled services | Planned |
| 3b | **AUR and local builds:** cache, `bacman`, an AUR build at the matching commit; Arch Linux Archive pinning; derivative repositories and CPU levels | Planned |
| 3c | **Hardware differences:** firmware, drivers, guest tools, interface renames and CPU level, each way | Planned |
| 4 | **User files**: none, structure, chosen folders or everything, through the sync engine | Planned |
| 4b | **Snapshots and risks:** before and after snapshots with holds, what changed, roll back, and the Data at risk list with its dialog and `--accept` | Planned. Its first piece, refusing package removals, is built |
| 5 | **Test and migration modes**: the isolation above, and cutover | Planned |
| 6 | **VM to VM copy as is**: disk images and the libvirt definition, between libvirt hosts | Planned |
| 7 | **Disk image from a physical host**: a block copy from a snapshot into qcow2, then fixed up to boot. To bare metal, through a live environment | Later |

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
