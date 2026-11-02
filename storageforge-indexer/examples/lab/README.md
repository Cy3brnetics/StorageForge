# KVM lab

Seven disposable VMs, picked at random from 14 configs, for testing StorageForge across distros and filesystems. It runs on the libvirt host, separate from StorageForge itself.

It builds the VMs, their storage layouts and seed data, the network, the snapshots and the control panel, runs StorageForge from this working tree on `sf-ctl`, and can fill it with a working demo.

See [KVM lab](../../../docs/kvm-lab.md) for the test tiers and results.

Proxmox, TrueNAS and XCP-ng join a build only through `--pick`, and install from ISOs: see [Appliances](../../../docs/kvm-lab.md#appliances).

## Use it

```bash
examples/lab/lab.sh install-launcher   # adds "StorageForge Lab" to the desktop menu
python3 examples/lab/panel.py --open   # or start the panel directly
```

| Button | Command | What it does |
| :--- | :--- | :--- |
| **Up** | `lab.sh up` | Picks 7 of the 14 configs, then creates and starts the VMs, lays out their storage, adds seed data, starts StorageForge on `sf-ctl`, then takes a `golden` snapshot. Safe to run again: it resumes VMs that aren't finished, except one whose storage layout failed partway, which needs Destroy. |
| **Reset** | `lab.sh reset` | Returns every VM to `golden`. |
| **Demo** | `lab.sh demo` | Resets the lab, then fills StorageForge through its own API. Takes about 3 minutes. |
| **Test** | `lab.sh test` | Checks the running lab against what it should hold. Reads only. |
| **Full test** | `lab.sh test --all` | Runs tiers 0-8, resetting around them, and writes `reports/lab-<date>.md`. Takes about 30 minutes, and changes the VMs while it runs. |
| **Destroy** | `lab.sh down` | Removes the lab straight away with no confirmation, stopping any running command first. |

Also: `lab.sh status`, `lab.sh ssh <vm> [command]`, and `lab.sh snapshot` to retake `golden`, and `lab.sh controller` to rebuild StorageForge from this tree and restart it on `sf-ctl`, keeping its data. `lab.sh up --seed N` repeats a build and `lab.sh up --pick a,b,c` builds exactly those configs. `lab.sh up <vm>...` creates only the named VMs of the current build and takes no snapshot.

## What it needs

libvirt with `qemu:///system`, `virt-install`, `qemu-img`, `xorriso`, Docker to build the images, write access to `/dev/kvm`, about 12 GB of free RAM and 30 GB of free disk. `up` checks all of these first.

| Item | Where | After Destroy |
| :--- | :--- | :--- |
| VM disks | `/mnt/ssd/Data/KVM/sflab` (`SFLAB_DIR`) | removed |
| Network | libvirt `sflab`, bridge `sflab0`, 10.77.0.0/24 | removed |
| Pool | libvirt `sflab` | removed |
| Keys, generated passwords | `~/.local/state/sflab` | removed |
| Docker images on this machine | `storageforge:*`, `storageforge-proxy:*`, ntfy | kept, to make the next Up faster |
| Base images | `/mnt/ssd/Data/KVM/sflab-images` (`SFLAB_IMAGES`) | kept, to make the next Up faster |
| Panel token | `~/.config/sflab/panel-token` | kept |

## Storage on each config

[KVM lab](../../../docs/kvm-lab.md#the-14-configs) lists all 14 and `roles.conf` says what each can do. These are the original seven:

| VM | Root | Data disks |
| :--- | :--- | :--- |
| `sf-ctl` | ext4 | none. StorageForge from the repo's `docker-compose.yml`, plus ntfy from `controller/compose.lab.yml`. |
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

## StorageForge and the demo

The panel shows the address and the password while `sf-ctl` is up: `https://10.77.0.10:8443`, user `demo`, password in `~/.local/state/sflab/ui-password`. The images are built on this machine and loaded onto `sf-ctl`. `sf-rocky` has 2 GB because `dnf` is killed for lack of memory at 1 GB once EPEL is enabled. `sf-ctl` has 2 vCPUs because `docker-compose.yml` limits StorageForge to 2.0 CPUs, and Docker refuses a limit above what the machine has.

`demo.py` leaves this in place:

| What | Where |
| :--- | :--- |
| Every host in the build scanned | `sf-rocky`, when picked, shows as partial, because `scan` can't read Podman's overlay folder |
| Deploy access | Five hosts, set up with the `sfadmin` sudo password. `sf-alpine` is refused, because it has no bash or systemd. |
| NFS share | The first ZFS host's data folder, mounted read-only on another host at `/mnt/lab-nfs` |
| SMB share | An SELinux host's data folder, mounted on another host at `/mnt/lab-smb`. Skipped if no other host's kernel can mount it. |
| rsnapshot job | From that SELinux host to a host whose repositories have rsnapshot, with one snapshot taken |
| btrfs send task | From one btrfs host to another, with one snapshot sent |
| One open alert | A ZFS mount 96% full, in the Deploy tab and at `http://10.77.0.10:8090/storageforge-lab` |

A few steps StorageForge leaves to an operator go over the lab's own SSH: installing login keys, adding the Samba account and its client credentials, and root's key for the btrfs send. The Samba account needs the Samba that the deploy installs, so the demo applies the SMB share, adds the account, and applies again.

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
