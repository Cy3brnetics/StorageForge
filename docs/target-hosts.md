# Target hosts

What StorageForge expects on the machines it scans and changes.

## To be scanned

Any Linux machine you can reach over SSH with a key. Nothing is installed.

| Needed | For |
| :--- | :--- |
| `find` (GNU), `lsblk`, `findmnt` | the file index and the disk layout |
| `sha256sum` | only for `--checksum` scans |
| `zpool`, `lvs`, `btrfs`, `docker` or `podman` | read when present, for pools, volumes and containers |

An ordinary user works, but it can only index what it can read. [Read-only scan access](scanning-and-search.md) fixes that without scanning as root.

## To run scripts and deploys

| Needed | For |
| :--- | :--- |
| `bash`, `flock`, `sudo` | every generated script |
| `systemd` | scheduled jobs and storage tasks |
| `rsync` | moves and copies; a deploy installs it if it is missing |
| `python3` | only for jobs with dedup, on both hosts; a deploy installs it if it is missing |
| `duperemove` | only for jobs with extent dedup; a deploy installs it if it is missing |
| `clamav` | only on hosts you deploy the ClamAV scan to; the deploy installs it |
| `b3sum` | only for jobs that hash with BLAKE3, on both hosts; install it yourself |
| `pv` | only to limit the bandwidth of a snapshot stream |
| `btrfs-progs`, `zfsutils-linux` or `zfs`, `lvm2`, `parted` | the tasks that use them; the script reports a conflict if one is missing |

Deploys can install packages for shares and jobs with apt, dnf, yum, zypper or pacman. The [KVM lab](kvm-lab.md#tested-distributions) lists the distributions these were tested on and what is still open. Run a plan's report first on a system you have not used it on.

## Sending snapshots between hosts

`btrfs-send`, `zfs-send` and their storage task blocks run as a signed run on each host, so **both hosts need [deploy access](deployments.md#setting-up-deploy-access)**. There is no SSH setup to do: a deploy gives each send a key of its own, and that key can do nothing but this send. No root key is needed between the hosts, and an older one made for sends can go. The sender must be able to reach the receiver at the address StorageForge scanned it at, on its SSH port.

Sending to the same machine, such as to a second pool, needs none of this: leave the host empty.

A receiving btrfs folder must be on btrfs. LVM has no equivalent of send: to copy an LVM snapshot, mount it and use a Moves step.
