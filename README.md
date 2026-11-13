# StorageForge

Map, plan and change the storage on a fleet of Linux machines from one place. StorageForge indexes every host over SSH with no agent, shows what it found as an editable topology, checks every plan against that index, and turns plans into scripts that report before they change anything.

![Topology view](docs/images/topology.jpg)

## Read this first: no promises

**It will probably work. Don't blame me if it doesn't.**

StorageForge logs in to your machines as root, partitions disks, makes and destroys filesystems, snapshots, sends and prunes data, rewrites `/etc/fstab`, firewall rules and SSH settings, and pushes configuration to routers. Every one of those can lose data or lock you out if something goes wrong, and things go wrong. It is tested on unit tests and a lab of throwaway VMs, not on your hardware, your distro's quirks or your network. The security audits found real bugs and were partial. A good part of the code was written with AI assistance. Several features have never met a real device or service, and the [changelog](CHANGELOG.md) lists which.

So:

- **It comes with no warranty of any kind,** express or implied: not that it works, not that it is fit for any purpose, and not that it won't break something. You use it entirely at your own risk.
- **Nobody who wrote or contributed to it is liable** for lost data, downtime, a machine you can't log in to, a firewall that shut you out, a broken router, a security incident, or anything else that follows from using it, however it happens.
- **Have backups you have actually restored from,** and a way into every machine and device that does not depend on StorageForge (a console, IPMI, physical access), before you let it change anything.
- **Try it on something disposable first.** Read every dry run and every script before you apply it; that is what they are for. Don't point it at production until you have watched it work on a copy.
- **It is for a LAN behind its TLS proxy,** run by people who know what the commands it shows will do. Don't put it on the internet.

If any of that is not acceptable, don't run it.

It is released under the [WTFPL](LICENSE) (Do What the Fuck You Want to Public License, version 2), with the no-warranty notice above written into the licence file as well.

## Why it exists

Storage on a few Linux machines tends to live in shell history, an old wiki page and one person's memory. The questions that matter are hard to answer from there: which data has only one copy, which containers use this folder, will this copy fit, and what happens if this disk is missing when the job runs?

Monitoring tools show how full a disk is. Backup tools copy what you point them at. Configuration tools apply what you describe, but they don't know what is on the disk. StorageForge joins those up: it keeps a searchable record of what every host holds, and checks each plan against that record before anything runs.

I built it because I wanted to use it, not because I wanted to maintain a storage tool. Please steal the idea, take whatever helps from the code and make a better one. Until someone does, I will keep developing this one.

## What it does

- **Finds files on every host.** Search by name, size, age, host or folder from the web UI or the CLI, and see what changed between scans, duplicate folders and cold data.
- **Maps the storage.** Disks, pools, datasets, mounts, links, shares and the copies between them, as an editable topology and a graph, with 3-2-1 protection health on each. It reads btrfs, ZFS, LVM, mdadm and LUKS layouts.
- **Designs hosts.** The planner covers devices, mounts, links, RAID capacity and protection, and exports Bash, Ansible, systemd and blueprint files.
- **Plans changes.** Folders, btrfs, ZFS and LVM tasks, mounts and drives, in order, like a playbook for storage.
- **Moves and protects data.** Copies, cutovers, mirrors, rsnapshot, git mirrors and snapshot sends. Existing rsnapshot and snapper jobs can be imported.
- **Deploys NFS and SMB shares**, for the server and each client.
- **Builds storage tasks from blocks**, with guards such as "require mounted", then runs them by hand or on a timer.
- **Shows Docker, Podman and Git inventory:** which containers use a folder, which repositories have unpushed work or only one copy.
- **Raises alerts** for failed jobs, drift, disk and pool health, and sends them to your alert channels.
- **Writes reports:** Markdown architecture reports and Obsidian `.canvas` exports.

## How it works

1. **Scan.** A bound vault key connects over SSH, and tools already on the host read it: `find`, `findmnt`, `lsblk`, `df`, plus `zpool`, `git` and `docker` when present. Scans change nothing and install nothing.
2. **Look.** Topology, search and the inventory panels answer from the index, without connecting to a host.
3. **Design.** Mark tiers, protection, exports and links. Your intent survives rescans.
4. **Plan.** Stage changes, moves, shares or a task. Each one is checked against the index as you edit.
5. **Act.** Download the script and run it yourself, or deploy it through a runner on the host that only runs scripts StorageForge signed. Run with no options, a script only reports `ok`, `missing` or `conflict`.
6. **Rescan.** The next scan shows the result, and flags drift if something deployed was changed by hand.

The rules every feature follows are in [Concepts](docs/concepts.md#the-rules), and the protections are in [Security](docs/security.md). In short: SSH keys are encrypted at rest and held in memory only for the length of a task, trash and cutovers rename instead of deleting, drive tasks have three separate locks, and the audit log is hash-chained.

## Install

**You need** a Linux machine with Docker and Compose v2 that can reach your hosts over SSH, and hosts with an SSH server. Nothing is installed on a host to scan it. [Install and set up](docs/install.md) is the full guide: settings, certificates, first admin, read-only and deploy access, the optional parts, upgrading and removing.

**1. Start it.**

```bash
git clone https://github.com/Cy3brnetics/StorageForge.git
cd StorageForge/storageforge-indexer
git checkout v0.5.2
docker compose up -d --build
```

**2. Keep the vault secret somewhere else.** Without it, the vault's SSH keys cannot be read, and backups never hold it.

```bash
docker compose exec storageforge cat /run/sf-secrets/vault_secret
```

**3. Make the first admin, then sign in.**

```bash
docker compose exec storageforge storageforge-index user add admin
```

Open `https://<this machine>:8443`. The certificate is self-signed: before you accept it, compare its fingerprint with `docker compose logs init-secrets`.

**4. Scan a host.** On the host, make an account `scan` with no password. Then generate a key in the vault and put its public half in `~scan/.ssh/authorized_keys` there, or use **Keys → Install on a host**. Then:

```bash
docker compose exec storageforge storageforge-index vault generate --name fleet
docker compose exec storageforge storageforge-index vault bind --key fleet --host 10.0.20.0/24 --user scan
docker compose exec storageforge storageforge-index scan --host 10.0.20.5
```

**5. When you want it to change things,** give the host read-only scan access (**Access**) and deploy access (**Deploy → Set up…**). Each asks for a sudo password once, for that session only.

To try it without touching a real host, `examples/demo/demo.sh` runs the whole flow against a disposable SSH target. Without Docker, see [Install and set up → Without Docker](docs/install.md#5-without-docker).

## Where it stands

- Version 0.5.0. Releases are tagged `vX.Y.Z`; see the [changelog](CHANGELOG.md).
- It is meant for a LAN behind its TLS proxy. Do not publish it on the internet. The one port that may face it is the optional [tunnel for remote nodes](docs/remote-nodes.md).
- The [KVM lab](docs/kvm-lab.md) tests scans and deploys on real VMs across Debian, Ubuntu, Fedora, Arch, openSUSE, Rocky Linux and AlmaLinux. Alpine can be scanned, but deploys are refused because it has no bash or systemd. The lab tests through the API, not the web pages. The release run of 2026-11-06 passed 561 of 564 checks, and the remaining failure and what has not met a real device or service are listed in the [changelog](CHANGELOG.md) and [progress.md](progress.md).
- The CI workflow is written and its commands pass by hand, but it has not run on a runner yet.

## Find your way around

| Where | What |
| :--- | :--- |
| [docs/](docs/README.md) | All documentation, starting with [install and set up](docs/install.md), [getting started](docs/getting-started.md) and [concepts](docs/concepts.md) |
| [storageforge-indexer/](storageforge-indexer/README.md) | The code |
| [StorageForge-Website/](StorageForge-Website/index.html) | The one-page project website, as static files |
| [CHANGELOG.md](CHANGELOG.md) | What changed |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Working on it |
| `notebook/` | Audit findings and the roadmap, as an Obsidian vault |
