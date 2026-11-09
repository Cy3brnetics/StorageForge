# VMs on libvirt

StorageForge manages the VMs of a scanned libvirt host the way it changes anything else: each change is a step of a change plan. It is checked against the host's last infrastructure reading, reports first, and runs when the plan is deployed, through a signed run, into the audit log. Nothing on this page runs from a button straight away.

What is here:

- [The VM panel](#the-vm-panel): what a VM is and holds, and the buttons that stage a step.
- [Snapshots](#snapshots): disk-only by default, with the guest agent freezing the filesystems first; listing, reverting and deleting them.
- [Snapshots and backups on a schedule](#snapshots-and-backups-on-a-schedule): two task blocks.
- [Changing a VM](#changing-a-vm): vCPUs, memory, autostart and disks.
- [Networks and pools](#networks-and-pools): defining, changing and removing them.
- [Copying a VM to another libvirt host](#copying-a-vm-to-another-libvirt-host), as it is.

VMs made from cloud images (`vm-create`) are in [Cloning and migrating hosts](host-migration.md). A terminal on a VM, or its serial console, is the [Console](console.md).

## What it reads

A host with deploy access is measured every 6 hours, or with **Measure now**. For libvirt the reading holds:

- **Each VM:** its state and autostart, vCPUs and memory, firmware, machine type, CPU mode, TPM, serial console, and its disks with bus, format and whether each sits on a base image.
- **Its NICs and graphics,** and whether a guest agent channel is there and the agent answers (`connected` on a running VM).
- **Its snapshots:** name, when, parent, which is current, and whether it is disk-only (external) or internal.
- **Networks:** mode, bridge, address, DHCP range, up and at boot.
- **Pools:** kind, folder or source, room, up and at boot.

Graphics passwords and the XML of guests are never stored: only these fields are kept.

## The VM panel

**Infrastructure → Workloads**, then the name of a libvirt VM. The panel shows what the reading says of it, its disks and its snapshots. With `plans.edit` it has buttons, each opening the form of a plan step with the fields filled in:

| Button | Step |
| :--- | :--- |
| Start, Shut down, Restart, Force off | `workload-action` (force off is `virsh destroy`: as pulling the power) |
| Snapshot… | `vm-snapshot` |
| Revert…, Delete… on a snapshot | `vm-revert` (destructive), `vm-snapshot` with delete |
| Change… | `vm-edit` |
| Copy to another host… | the two steps of a copy (below) |
| Console | the [console](console.md) page, with `console.open` |
| Remove… | `workload-remove`: the definition goes, the disks stay |

Under the VMs of each libvirt host are its networks and storage pools, each with **Change…** and **Remove…**, and **New network…** and **New pool…**. The same data is `GET /api/workloads?host=` and `GET /api/workloads/libvirt?host=`.

## Snapshots

`vm-snapshot` takes or deletes one.

- **Disk-only by default.** Each disk gets an overlay file beside it, named after the snapshot, and the VM goes on writing there. This works on UEFI VMs, whose firmware variables are a raw file that an internal snapshot cannot hold, and it can freeze filesystems.
- **Freezing filesystems first.** With **Freeze filesystems first** on `auto`, a running VM whose guest agent answers has its filesystems frozen for the moment of the snapshot (`--quiesce`), so what was in flight is written first. Without an agent the snapshot is crash-consistent: as after a power cut. With `require`, the step refuses a VM whose agent does not answer. A VM that is off has nothing in flight. `vm-create` installs the agent when **Install the guest agent** is ticked. Elsewhere, install `qemu-guest-agent` in the guest; it needs the `org.qemu.guest_agent.0` channel, which `vm-create` and copies always add.
- **Internal snapshots,** with memory, when disk-only is off. The two kinds are not mixed on one VM: libvirt cannot delete an internal snapshot over overlays, or a disk-only one beside internal ones, so the step refuses the second kind.
- **Delete** merges a disk-only snapshot back into the disks: the restore point goes, the data stays. libvirt deletes disk-only snapshots from 9.0, oldest first, and refuses one that is not a leaf after a revert made a branch.

`vm-revert` goes back to a snapshot. It is destructive, so it runs only with `--apply --destructive`: what the disks hold since is lost. Going back to a disk-only snapshot takes a libvirt that does it: 12.9 does, while 10.0 (Ubuntu 24.04) and 9.0 (Debian 12) refuse. The step then says so and leaves the VM as it was; on such a host, take snapshots with memory (disk-only off) where you mean to go back to them. After a revert to a disk-only snapshot the VM is off, unless **Start it after** is ticked.

`workload-action`'s snapshot is disk-only too now, with the filesystems frozen when the agent answers.

## Snapshots and backups on a schedule

Two task blocks, in [Storage tasks](plans-and-scripts.md#storage-tasks):

- **VM snapshots** (`vm_snapshot`). A disk-only snapshot of each VM, named `<prefix>-YYYY-MM-DD_HHMMSS`, frozen first as above. **Keep** is how many of its own it keeps per VM; the oldest are deleted, which merges them back. A snapshot another prefix made (`nightly-db-…` for `nightly`), one named by hand, or one not of that form (`nightly-notes`) is never deleted. `*` takes every VM on the host.
- **Back up VMs** (`vm_backup`). A whole copy of each disk as qcow2, and the definition of the VM, in `<into>/<vm>/<date>/`, readable by root alone. A running VM is copied from a disk-only snapshot taken for the purpose and merged back after, so it keeps running. A disk on a base image is copied with its base, so a copy stands alone. **Keep** is how many copies per VM. A VM with a disk on a block device is backed up only while it is off.

The templates **VM snapshots** (nightly, keep 7) and **VM backups** (Sundays, onto a mounted disk, keep 4) start from these. The check warns when the backup folder is on a disk that is not guarded by **Require mounted**, or on the disk the VMs are on.

## Changing a VM

`vm-edit` changes only the fields given, and does nothing where the VM already is what they say:

- **vCPUs and memory.** Set in the definition, so they change when the VM next starts. With **Restart it** they change now: a clean shutdown (3 minutes at most, or the step says so and stops), then start.
- **Autostart:** on or off.
- **Add a disk:** a new qcow2 of that size beside the first disk, named `<vm>-<label>.qcow2`, on the next free `vdX`. A second run sees it attached and adds nothing. It never takes a file that is already there.
- **Grow a disk** to a size: `virsh blockresize` while it runs, `qemu-img resize` while it is off. A disk is never shrunk. The guest grows its partition and filesystem itself; cloud images do it at boot.
- **Detach a disk:** it goes from the VM, and the file stays.

## Networks and pools

`libvirt-network` makes a network, or changes it to what the fields say:

- **Kind:** `nat`, `route`, `isolated`, or `bridge` onto a host bridge.
- **Address and DHCP range.** The check refuses an address that overlaps another network of the host, and a range outside the network or covering the host address.
- **Changes.** One to a running network applies when it next starts. With **Restart it now**, it is stopped and started, and guests on it lose their network until they are restarted; the step names them. Its UUID is kept, so it is the same network.
- **Removal.** A network a VM uses is refused removal.

`libvirt-pool` makes a pool of a folder, an LVM volume group or a ZFS dataset that is there:

- **Moving a folder pool** to another folder works only while it holds no volumes.
- **Changing its kind or source** is refused: remove it, then make it again.
- **Removing a pool** undefines it. Its files, volume group or dataset stay, and one holding a disk of a VM is refused.

## Copying a VM to another libvirt host

**Copy to another host…** in the VM panel, `POST /api/vm/copy` (`/preview` to look first), or:

    storageforge-index vm copy web --from kvm1 --to kvm2 [--as web-copy] [--pool default] [--live] [--start] [--keep-macs]

This saves a change plan of two steps, made from the source's last reading.

**`vm-send`, on the source,** sends each disk through a send of its own. That is the same as btrfs and ZFS sends between hosts ([Sends between hosts](deployments.md#sends-between-hosts)):

- A signed run on the target says what it may receive and where.
- The source sends with a key that can do nothing else.
- Neither host needs a root key for the other.

Each disk arrives as a new file of its own, readable by root alone, written sparse. It is checked by SHA-256 on both ends, and an existing file is never written over. A disk on a base image is sent whole, as one qcow2 made beside it first, which takes room there. With **live**, a running VM is copied from a disk-only snapshot, frozen first when its agent answers, and the snapshot is merged back after, so the source keeps running. Otherwise the VM must be off. A rerun sends only what did not arrive.

**`vm-define`, on the target,** defines the VM on those files with `virt-install --import --print-xml` and `virsh define`. It takes the vCPUs, memory, firmware, machine type, CPU mode, disks with their bus and format, NICs, graphics on loopback, TPM and serial console that the plan says. Nothing of the source's XML crosses: a source cannot give the copy a host device or another file of the target.

- **MAC addresses.** The copy gets new ones, unless **Keep its MAC addresses** is ticked. Then the check warns that only one of the two may run on a network.
- **Networks.** A NIC on a network the target lacks goes onto `default`, or the one given.
- **CD-ROMs** are not copied, and are listed.
- **Copying beside the source.** The target may be the source itself, with another name: a copy beside it.

To move a VM, copy it, check the copy, then remove the source with `workload-remove`, which keeps its disks until you delete them.

## Lab run

Tier 18 of [the KVM lab](kvm-lab.md) (`tests/lab/tiers_kvm.py`) passed all 17 checks on 2026-11-09. Two lab VMs were libvirt hosts: `sf-ubuntu` (Ubuntu 24.04, libvirt 10.0) and `sf-bookworm` (Debian 12, libvirt 9.0), with a nested Alpine 3.24 guest made by `vm-create` with its guest agent. Each check reads virsh and the guest agent on the host, not StorageForge's report:

- **Pools:** the default pool made where there was none; a folder pool defined, moved while empty, refused a move while it held an image, and removed with the image left in its folder.
- **Networks:** a NAT network with DHCP defined, changed and restarted, and the same again was no change. A stopped default network was started by the network step.
- **Snapshots:** a disk-only snapshot, refused unless the guest agent answered, and it did. Going back to it was refused on libvirt 10.0 and 9.0, saying why, with the VM left running as it was. A snapshot with memory was reverted on 10.0, and a file written after it was gone. Deleting a disk-only snapshot merged it back.
- **Changes:** 2 vCPUs, 320 MiB, autostart, a disk added and the root disk grown to 2 GiB, all seen from inside the guest after the restart. The disk was then detached, with its file kept.
- **Tasks:** the VM snapshot block, run three times, kept its newest 2. The backup block made a whole qcow2 that `qemu-img check` passes, and the definition, at mode 600, while the VM ran and went back onto its own disks.
- **Copy:** a live copy from `sf-ubuntu` to `sf-bookworm`, each disk by a signed send, checked on both ends. It booted there holding a file written just before the copy, with its own MAC.
- **Power and removal:** force off and start; then both guests removed with their snapshots' metadata, and the network.

The runs found and fixed:

- Plain `virsh` in the workload steps not reaching the system libvirt.
- Pipes into `head` and `grep -q` that read as failures under `pipefail`.
- libvirt 9.0 padding its name lists.
- `vm-create` on an OS name older osinfo does not know.
- A VM with snapshots that could not be removed.

Not run in the lab:

- Going back to a disk-only snapshot where libvirt can (only on the workstation, with libvirt 12.9).
- UEFI guests, bridged and routed networks, and LVM and ZFS pools.
- A copy shut off, or of a disk on a block device.
