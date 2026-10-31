# KVM lab

Seven disposable VMs for testing StorageForge across distros and filesystems. It runs on the libvirt host, separate from StorageForge itself.

So far this builds the VMs, their storage layouts and seed data, the network, the snapshots and the control panel. StorageForge isn't installed on `sf-ctl` yet.

## Use it

```bash
examples/lab/lab.sh install-launcher   # adds "StorageForge Lab" to the desktop menu
python3 examples/lab/panel.py --open   # or start the panel directly
```

| Button | Command | What it does |
| :--- | :--- | :--- |
| **Up** | `lab.sh up` | Creates and starts the VMs, lays out their storage, adds seed data, then takes a `golden` snapshot. Safe to run again: it resumes VMs that aren't finished, except one whose storage layout failed partway, which needs Destroy. |
| **Reset** | `lab.sh reset` | Returns every VM to `golden`. |
| **Test** | `lab.sh test` | Checks the running lab against what it should hold. Reads only. |
| **Destroy** | `lab.sh down` | Removes the lab straight away with no confirmation, stopping any running command first. |

Also: `lab.sh status`, `lab.sh ssh <vm> [command]`, and `lab.sh snapshot` to retake `golden`. `lab.sh up <vm>...` creates only the named VMs and takes no snapshot.

## What it needs

libvirt with `qemu:///system`, `virt-install`, `qemu-img`, `xorriso`, write access to `/dev/kvm`, about 10 GB of free RAM and 30 GB of free disk. `up` checks all of these first.

| Item | Where | After Destroy |
| :--- | :--- | :--- |
| VM disks | `/mnt/ssd/Data/KVM/sflab` (`SFLAB_DIR`) | removed |
| Network | libvirt `sflab`, bridge `sflab0`, 10.77.0.0/24 | removed |
| Pool | libvirt `sflab` | removed |
| Keys, generated passwords | `~/.local/state/sflab` | removed |
| Base images | `/mnt/ssd/Data/KVM/sflab-images` (`SFLAB_IMAGES`) | kept, to make the next Up faster |
| Panel token | `~/.config/sflab/panel-token` | kept |

## Storage on each VM

| VM | Root | Data disks |
| :--- | :--- | :--- |
| `sf-ctl` | ext4 | none |
| `sf-ubuntu` | ext4 | ZFS: `tank` (raidz1) with `media`, `photos` and `backups`, and `backup` to send to. Docker container `sflab-web`. |
| `sf-fedora` | btrfs | btrfs raid1 over two disks, subvolumes mounted at `/data/media`, `/data/backups` and `/data/snaps` |
| `sf-rocky` | XFS | LVM `vgdata`: XFS on `data` at `/srv/data`, snapshot `data-snap`. Podman container `sflab-web`. |
| `sf-suse` | XFS | mdadm raid1 with ext4 at `/mnt/raid`. Btrfs with openSUSE's nested subvolumes: `@` at `/srv/btrfs`, `@/home` and `@/.snapshots` mounted inside it, and `@/var` left unmounted as a child reachable only through `@`. |
| `sf-arch` | btrfs | LUKS with f2fs at `/mnt/secure`, mergerfs at `/mnt/pool` over ext4 `/mnt/disk1` and `/mnt/disk2` |
| `sf-alpine` | ext4 | vfat at `/mnt/fat`, exFAT at `/mnt/exfat`. OpenRC, no systemd, and `apk`, which StorageForge doesn't know. |

The layouts are in `provision/<vm>.sh`, and `provision/layout.conf` lists what the tests expect mounted. NFS and Samba servers are left out so deploys can install them, except that Rocky's image already includes `nfs-utils`.

## Seed data

`provision/seed.py` builds the same data each time and `provision/seed-roots.conf` says where it goes, about 46 MB per full copy. The `full` profile has files duplicated across hosts and within one, a folder the `scan` user can't read, awkward names (Unicode, a newline, leading hyphens, bytes that aren't UTF-8), hardlinks, symlinks including a loop and a dangling one, a sparse file and a git repository. The `plain` profile is simple files, for filesystems that can't hold the rest.

The generator also writes a manifest with the type, size, mode and SHA-256 of every entry to `~/.local/state/sflab/manifests`, so tests compare a VM and its scans with values the VM had no part in.

## Accounts on each VM

| User | Sudo | Used for |
| :--- | :--- | :--- |
| `lab` | passwordless | the lab scripts and `lab.sh ssh` |
| `sfadmin` | with the password in `~/.local/state/sflab/admin-password` | Deploy's **Set up…** |
| `scan` | none | scans |

Leap's stock sudoers lists every user but asks for the root password, and root is locked, so `scan` still can't use sudo there.

## What Destroy can touch

It removes only VMs carrying the lab's libvirt metadata tag, the network if its bridge is `sflab0`, the pool if its path is the lab folder, and the folder if it holds the lab's marker file. It also leaves the folder alone if any other VM still uses a disk in it. `up` refuses to adopt a VM, pool or folder with the same name that isn't the lab's.

## Limits

- The VMs can reach your LAN through NAT, because deploys install packages. Don't treat the lab as a security boundary.
- The panel listens on `127.0.0.1` only. Its URL holds a token, so keep it private.
- To refresh a base image, delete it and its `.ok` file from the image folder.
