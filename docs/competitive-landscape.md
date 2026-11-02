# StorageForge: Competitive Landscape & Similar Software

A comprehensive survey of software, architectures, and tools that overlap with, resemble, or solve adjacent problems to **StorageForge**.

---

## Executive Summary

**StorageForge** occupies a unique position in the systems administration, homelab, and fleet management ecosystem. It combines five distinct capabilities into a single, cohesive workflow:

1. **Agentless SSH Discovery & Walking:** Connects via vaulted keys using standard utilities (`lsblk`, `findmnt`, `df`, `find`, `zpool`, `btrfs`, `docker`, `git`) without requiring background daemons on managed hosts.
2. **Global Metadata & File Indexing:** Maintains a searchable index of files, sizes, ages, duplicate folders, and cold data, with scan-to-scan diff tracking.
3. **Storage Topology & 3-2-1 Protection Mapping:** Visualizes disks, partitions, LUKS containers, LVM/ZFS/Btrfs pools, mounts, and network shares with 3-2-1 backup health indicators.
4. **Declarative Planning & Dry-Run Execution:** Generates idempotent, report-first Bash/Ansible/systemd scripts with three-stage destructive safety locks and soft-delete trash mechanics.
5. **Host Rebuild & Disaster Recovery:** Preserves host storage configurations (fstab, crypttab, mdadm, shares, accounts) across 30 versions to regenerate a complete `reinstall.sh` rebuild script.

While no single open-source product today replicates this entire pipeline, dozens of tools address parts of it.

---

## 1. The Historical Government Precedent: EPICSHELTER

| System | Origin | Core Focus | Architecture |
| :--- | :--- | :--- | :--- |
| **EPICSHELTER** | NSA (Edward Snowden, Yokota Air Base, Japan) | Disaster recovery, fleet-wide file diffing, and bandwidth-optimized automated sync | Central master syncing distributed overseas intelligence field stations |

### What EPICSHELTER Was
Described by Edward Snowden in his 2019 memoir *Permanent Record* (and later referenced as the NSA's *Storage Modernization Program*), **EPICSHELTER** was an internal automated disaster recovery and backup system built for the National Security Agency.

At the time, overseas stations and field offices (such as Yokota in Japan or regional collection posts across the Pacific and Middle East) stored vast quantities of operational reports, intercepts, and intelligence on local file servers. If a physical site was destroyed, abandoned, or suffered hardware failure, that data risked being permanently lost because overseas sites lacked reliable multi-terabit pipes back to Fort Meade.

### Architectural Parallels to StorageForge
* **Continuous Scanning & State Diffing:** EPICSHELTER continuously walked local filesystem structures across remote facilities and indexed file metadata.
* **Differential Synchronization:** Instead of naive periodic bulk copies, the system compared local file inventories against what NSA headquarters already stored, queuing up *only* missing files for transmission across constrained network pipes.
* **Global Visibility Over Distributed Storage:** Building EPICSHELTER required mapping what data existed across all agency nodes—providing a unified, bird's-eye view of distributed storage silos.
* **Disaster Recovery as Primary Objective:** The goal was not merely live synchronization, but ensuring that any field station or server could be reconstituted from scratch if lost.

---

## 2. File Indexing, Search & Unstructured Data Management

Tools focused on scanning storage mounts, cataloging files into a central database, and finding cold data, duplicates, and sprawl.

### [Diskover](https://github.com/diskoverdata/diskover-community)
* **What it does:** An open-source and commercial data curation tool and file search engine powered by Elasticsearch.
* **Overlap:** Like StorageForge's indexer, Diskover crawls multiple storage mounts, indexes metadata, and exposes a web UI to search files, calculate directory sizes, identify duplicate files, and flag ROT (redundant, obsolete, trivial) cold data.
* **Differences:** Diskover is an analytics and search layer. It does not inspect physical disks, LVM volume groups, or ZFS vdevs; it does not plan changes or generate deployment scripts.

### [Robinhood Policy Engine](https://github.com/cea-hpc/robinhood)
* **What it does:** A heavy-duty filesystem auditing and policy-enforcement daemon used in High-Performance Computing (HPC) clusters (especially on Lustre and large POSIX mounts).
* **Overlap:** Continuously tracks filesystem metadata in a relational database (MySQL/MariaDB) to monitor capacity, detect stale files, and run batch actions.
* **Differences:** Purely CLI-driven, daemon-heavy, focused on automated file purging/tiering in petabyte clusters rather than homelab or general Linux fleet administration.

### [Starfish Storage](https://starfishstorage.com/) & [Komprise](https://www.komprise.com/) (Enterprise)
* **What they do:** Enterprise-grade unstructured data management software.
* **Overlap:** They map storage silos across heterogeneous NAS (NetApp, Isilon, Dell) and cloud object stores, catalog metadata, visualize age distributions, and orchestrate policy-based tiering and data moves.
* **Differences:** High-end proprietary enterprise solutions requiring dedicated virtual appliances, focused heavily on tiering to S3/Glacier rather than bare-metal Linux disk management.

### [git-annex](https://git-annex.branchable.com/)
* **What it does:** Manages large files with Git without committing the file contents into Git history, tracking which repository or machine holds which file.
* **Overlap:** Features the **`numcopies`** constraint—it tracks the physical distribution of files across independent remote machines over SSH and refuses to drop a copy unless a minimum redundancy threshold is verified.
* **Differences:** Decentralized CLI workflow focused on digital asset management, not system block devices or OS configuration.

---

## 3. Enterprise & Network Backup Systems

Systems designed to back up multiple endpoints to central storage, schedule retention policies, and manage client-server relationships.

### [Bacula](https://www.bacula.org/) & [Bareos](https://www.bareos.com/)
* **What they do:** The industry standard for open-source enterprise client/server backups. Bareos is a modern, community-driven fork of Bacula with a REST API and web UI.
* **Overlap:** Multi-host fleet coverage, centralized scheduling, director-storage-client architecture, verified catalog tracking, and offsite/3-2-1 compliance.
* **Differences:** Heavyweight architecture requiring persistent client daemons (`bacula-fd`) on every node, complex catalog databases, and focused on archive/restore rather than system storage topology design or live filesystem maintenance.

### [Syncthing](https://syncthing.net/)
* **What it does:** An open-source, continuous peer-to-peer file synchronization engine.
* **Overlap:** Ensures identical copies of folders exist across multiple machines; features versioning and file trash cans (`.stversions`).
* **Differences:** P2P synchronization daemon rather than a centralized fleet inspector. It syncs continuously in user-space and has no awareness of disks, partitions, RAID, or fstab.

### [UrBackup](https://www.urbackup.org/)
* **What it does:** Client/server backup system for Linux and Windows with web UI.
* **Overlap:** Central web interface managing backups for a fleet of hosts; uses Btrfs/ZFS copy-on-write to store space-efficient deduplicated file backups.
* **Differences:** Requires a client daemon; strictly a backup-appliance tool that creates snapshots/images, without infrastructure design or partition management.

### [Elkarbackup](https://www.elkarbackup.org/)
* **What it does:** A web-based management interface for **`rsnapshot`** and `rsync` on Linux.
* **Overlap:** Like StorageForge’s `rsnapshot` job import and runner, Elkarbackup centralizes rsnapshot schedules, multi-client SSH policies, and pre/post execution hooks into a web dashboard.
* **Differences:** Limited strictly to scheduling rsnapshot cron jobs.

### [BorgBackup / Borgmatic](https://torsion.org/borgmatic/) & [Restic / Backrest](https://github.com/garethgeorge/backrest)
* **What they do:** Deduplicating, encrypted chunk-based backup tools paired with modern web wrappers (Backrest, Vorta).
* **Overlap:** Deduplicated data movement, retention policies, and verification checks.
* **Differences:** Archive repositories; they do not map the host's underlying storage topology or correlate running Docker containers.

---

## 4. Bare-Metal Disaster Recovery & Rebuild Frameworks

Tools that snapshot system layouts to rebuild entire Linux machines from bare metal.

### [Relax-and-Recover (ReaR)](https://relax-and-recover.org/)
* **What it does:** The definitive open-source bare-metal disaster recovery framework for Linux (packaged in RHEL, SLES, Debian, Ubuntu).
* **Overlap:** ReaR snapshots the exact storage topology (`lsblk`, partition tables, LVM volume groups, software RAID, mount points, network interfaces) into a lightweight rescue image and Bash scripts, allowing a one-command bare-metal restore (`rear recover`).
* **Differences:** ReaR is an emergency bootable recovery tool (generating ISOs/PXE images), whereas StorageForge's `reinstall.sh` rebuild workflow is an agentless, continuously updated configuration export that reconstitutes running hosts while preserving data disks.

### [Clonezilla](https://clonezilla.org/) / [Mondo Rescue](http://www.mondorescue.org/)
* **What they do:** Disk-cloning and bare-metal imaging suites.
* **Differences:** Block-level bitstream copy utilities rather than metadata-aware management systems.

---

## 5. Linux Storage Administration & Web Consoles

Software providing graphical or browser-based management of Linux storage technologies (ZFS, Btrfs, LVM, mdadm, LUKS, Samba, NFS).

### [Cockpit](https://cockpit-project.org/) & [45Drives Houston](https://github.com/45Drives/cockpit-zfs)
* **What they do:** Red Hat’s official web console and 45Drives’ enterprise storage extensions (`cockpit-zfs`, `cockpit-file-sharing`, `cockpit-hardware`).
* **Overlap:** Clean, modern web GUI for managing ZFS pools, datasets, LVM volumes, LUKS encryption, physical drive bays, and NFS/Samba exports.
* **Differences:** Host-centric (manages one machine at a time). Lacks cross-host file indexing, 3-2-1 backup verification, change staging/diffing, or container volume correlation.

### [Rockstor](https://rockstor.com/)
* **What it does:** An open-source Linux NAS distribution built specifically around Btrfs.
* **Overlap:** Visual management of Btrfs pools, subvolumes, snapshots, replication between hosts, and container ("Rock-ons") share bindings.
* **Differences:** Turnkey NAS operating system (openSUSE based) rather than an agentless manager for arbitrary existing Linux fleets.

### [TrueNAS (SCALE/CORE)](https://www.truenas.com/) & [TrueCommand](https://www.truenas.com/truecommand/)
* **What they do:** Open-source ZFS storage appliance OS and its multi-system fleet management console.
* **Overlap:** Centralized multi-host storage dashboard with alerting, dataset replication, and snapshot management.
* **Differences:** Requires dedicated TrueNAS OS on every node; cannot manage general-purpose Debian, Ubuntu, Fedora, Arch, or Rocky Linux servers.

### [OpenMediaVault (OMV)](https://www.openmediavault.org/) & [Unraid](https://unraid.net/)
* **What they do:** Popular single-box homelab NAS management operating systems.
* **Differences:** Standalone single-server appliances; no multi-host SSH scanning, cross-fleet indexing, or pre-flight script generation.

### [Webmin](https://www.webmin.com/)
* **What it does:** Classic multi-server web administration tool.
* **Differences:** Imperative execution without dry-run safety locks or modern topology visualization.

---

## 6. StorageForge vs. Dedicated NAS OS Platforms & Hypervisors

A common architectural question is how StorageForge relates to full operating systems like **TrueNAS**, **OpenMediaVault (OMV)**, **Unraid**, and hypervisors like **Proxmox VE** or **XCP-ng**.

StorageForge operates in two complementary ways: **it provides the functional capabilities of a NAS OS on general Linux**, while simultaneously acting as a **"manager of managers" that talks directly to existing appliances**.

### Part 1: How StorageForge Compares as a Standalone "NAS Engine"
When pointed at standard, vanilla Linux installations (Debian, Ubuntu, Rocky Linux, Fedora, Arch), StorageForge gives administrators the core functionality that typically requires installing a dedicated NAS operating system:

| Functional Area | Dedicated NAS OS (TrueNAS, Unraid, OMV) | StorageForge on Standard Linux |
| :--- | :--- | :--- |
| **Filesystems & Pools** | Web GUI to create ZFS pools (TrueNAS) or Btrfs pools (Rockstor). | **Planner & Blueprints:** Stages and executes ZFS datasets, Btrfs subvolumes, LVM volume groups, mdadm RAID, and LUKS encryption. |
| **File Sharing (NFS / SMB)** | Configured locally on that specific machine. | **Cross-Host Share Deployment:** Generates, validates, and provisions `smb.conf` and `/etc/exports` for both the server and the mounting clients. |
| **Data Movement & Sync** | Built-in local replication tasks. | **Fleet Move Plans:** Orchestrates rsync, rsnapshot, git-mirrors, and ZFS/Btrfs snapshot sends across nodes. |
| **Disaster Recovery** | Single backup archive of that host's database. | **Automated Host Reconstitution:** Saves up to 30 configuration versions per host, generating an autonomous `reinstall.sh` script to recover storage, mounts, accounts, and shares. |

### Part 2: Talking to Existing NAS Appliances & Hypervisors
StorageForge connects to existing storage appliances and hypervisors over SSH **with no agents and no proprietary API keys** (see [docs/appliances.md](appliances.md)). During a scan, it detects the underlying operating system and adapts its permissions:

1. **TrueNAS (tested on TrueNAS Community Edition 25.10):**
   * **Scans & Indexing (Yes):** Reads all ZFS pools, vdev layouts, datasets, mounts, and indexes all file records into the central search engine.
   * **Deploys (Intentionally Refused):** TrueNAS enforces an immutable, read-only root filesystem (`/usr` is locked) and manages SMB/NFS configurations strictly through its internal `middlewared` SQLite database. To avoid fighting the appliance or having updates wipe manual changes, StorageForge indexes TrueNAS but leaves share and pool creation to TrueNAS's native UI.
2. **Proxmox VE (tested on 9.2):**
   * **Scans & Indexing (Yes):** Scans all local storage pools, datasets, and filesystems (skipping cluster configuration in `/etc/pve`).
   * **Deploys (Yes):** StorageForge can directly deploy network shares, scheduled data-move jobs, storage tasks, and change plans to Proxmox hosts once `sudo` is configured.
3. **XCP-ng / XenServer (tested on 8.3):**
   * **Scans & Indexing (Yes):** Scans storage repositories under `/run/sr-mount`.
   * **Deploys (Refused):** System updates replace the control domain base image.

### Part 3: The Architectural Shift — Appliance vs. Fleet Orchestrator

```text
┌────────────────────────────────────────────────────────────────────────┐
│                        StorageForge Central Web UI                     │
│    (Global Index · 3-2-1 Topology Graph · Change Planner · Rebuild)    │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │  SSH (No Agent)
         ┌─────────────────────────┼─────────────────────────┐
         ▼                         ▼                         ▼
  ┌──────────────┐          ┌──────────────┐          ┌──────────────┐
  │ TrueNAS Box  │          │  Proxmox VE  │          │ Ubuntu Node  │
  │ (ZFS Storage)│          │ (Hypervisor) │          │  (Docker)    │
  └──────────────┘          └──────────────┘          └──────────────┘
```

* **A NAS OS is an isolated appliance:** TrueNAS, Unraid, and OMV require complete ownership of a physical server. In an infrastructure with multiple storage boxes, hypervisors, and application nodes, administrators must log into multiple fragmented web dashboards.
* **StorageForge is a fleet-wide orchestrator:** It bridges heterogeneous systems. A single StorageForge instance can map a ZFS dataset hosted on TrueNAS, track an automated snapshot replication link to a Proxmox backup target, correlate which Docker containers on an Ubuntu worker node depend on that data, and evaluate whether the entire fleet satisfies the 3-2-1 backup rule.

### Part 4: What Dedicated NAS OS Platforms Have That StorageForge Does Not (Yet)
While StorageForge excels at fleet-wide topology, indexing, and change planning, traditional appliance operating systems provide several hyper-local and end-user features that StorageForge currently leaves out:

1. **Block Storage Target Protocols (iSCSI, Fibre Channel, NVMe-oF):**
   * *What they have:* TrueNAS, Synology DSM, and OpenMediaVault let you present raw block extents/zvols over the network (e.g. for VMware ESXi datastores or Proxmox shared LUNs).
   * *StorageForge:* Focuses strictly on filesystem-level mounts (NFS, SMB, local POSIX, bind mounts, and snapshot sends).
2. **End-User File Portals & Public Sharing:**
   * *What they have:* Synology File Station, QNAP File Station, or TrueNAS Nextcloud integration provide a browser-based "Google Drive" clone where non-technical users can upload, download, and create expiring public download links.
   * *StorageForge:* An administrative operations tool, not an end-user file consumption portal.
3. **Enterprise Directory Services & Granular ACL Editors:**
   * *What they have:* Deep Active Directory (AD) domain join, LDAP integration, Kerberos realm setup, and visual Windows/NFSv4 ACL permission matrices.
   * *StorageForge:* Restores UNIX user/group IDs (UID/GID $\ge 1000$) and exports basic share configurations, but leaves complex multi-tier domain controller integrations to dedicated identity managers.
4. **App Stores & Container Orchestration:**
   * *What they have:* 1-click app catalogs (TrueNAS SCALE Apps/Charts, Unraid Community Applications, Rockstor Rock-ons) that install Plex, Nextcloud, and databases with pre-configured storage mounts.
   * *StorageForge:* Discovers and maps Docker/Podman containers and their mounts, but does not deploy or manage container application lifecycles.
5. **Hardware Power & Physical Network Plumbing:**
   * *What they have:* Built-in GUI management for Uninterruptible Power Supplies (Network UPS Tools / NUT) to trigger graceful shutdowns during power failures, plus network interface bonding (LACP/802.3ad) and VLAN tagging.
   * *StorageForge:* Assumes underlying network and power infrastructure is handled by the host OS.
6. **Built-in Maintenance Schedulers:**
   * *What they have:* GUI schedulers for monthly ZFS pool scrubs, weekly SMART extended drive tests, and automatic email dispatch on degraded disks.
   * *StorageForge:* Monitors pool and disk health on scans and reports alerts, but leaves scrub execution to host cron/systemd timers.

---

### Part 5: Malware, Antivirus & Ransomware: ClamAV vs. Modern Solutions

How do storage systems defend against malware and ransomware, how widely is ClamAV used, and what does the industry consider a "better solution"?

#### How Many NAS Systems Use ClamAV?
Almost **every open-source and commercial NAS platform that advertises an antivirus feature relies on ClamAV under the hood**:

* **Synology DSM:** Its native "Antivirus Essential" package is a customized GUI wrapper around ClamAV.
* **QNAP QTS:** Its built-in free antivirus engine is ClamAV (with optional paid McAfee licenses).
* **OpenMediaVault (OMV):** Features an official `openmediavault-clamav` plugin to scan shares on a cron schedule.
* **TrueNAS (SCALE/CORE):** Does not bundle an antivirus in its base image, but provides official Docker/App containers running ClamAV.
* **Samba Integration:** Standard Linux Samba file servers implement ClamAV through the **`vfs_virusfilter`** (or legacy `vfs_clamav`) module, intercepting client read/write calls to scan files on-access via `clamd`.

#### The Problems with ClamAV on Large Storage Fleets
While ClamAV is the industry's default open-source scanner, systems administrators and enterprise storage engineers frequently avoid running it across multi-terabyte pools for several reasons:

1. **Catastrophic I/O and Resource Overhead:** ClamAV's signature database is massive. Running a recursive `clamscan` across 20TB–100TB of data can take days or weeks, pinning CPU cores at 100%, evicting filesystem cache, and degrading client throughput.
2. **Signature Blindness (Zero-Day Ransomware):** ClamAV is strictly signature-based. Modern polymorphic ransomware or novel encryptors will not match existing ClamAV virus signatures until hours or days after an outbreak has already finished encrypting files.
3. **Post-Mortem Detection:** Scheduled cron scans catch infected files *after* they have been written to the disk. By the time a nightly ClamAV scan flags an encrypted file, thousands of companion files may have already been permanently altered.

#### What Are the "Better Solutions"?
Modern enterprise storage platforms (NetApp, Cohesity, Rubrik, TrueNAS Enterprise) and security engineers rely on three modern paradigms that supersede traditional antivirus scanning:

##### 1. Immutable Snapshots & WORM (The Real Antivirus)
* **The Concept:** You cannot scan your way out of ransomware; you must make your filesystem impervious to unauthorized destruction.
* **How it works:** ZFS and Btrfs snapshots are read-only copy-on-write pointers. Even if a ransomware worm compromises a Windows desktop, connects to an SMB share with full write permissions, and encrypts every file, **it cannot encrypt or delete the read-only ZFS/Btrfs snapshots**.
* **Recovery:** Instead of paying a ransom or attempting file decryption, the administrator rolls back the dataset or clones the snapshot from 10 minutes prior to the attack, restoring petabytes in seconds.

##### 2. Ransomware Canaries & Decoy Tripwires
* **The Concept:** Placing bait files in shares to detect encryption before real data is compromised.
* **How it works:** Automated scripts or tools (like Huntress or Samba `vfs_full_audit` paired with canary monitors) place decoy files (e.g., `_AAAPasswords.docx`, `!README_Canary.pdf`) at the root and deep subfolders of SMB shares.
* **Action:** Legitimate users never touch canary files. The moment a ransomware process attempts to open, rename, or encrypt a canary file, the server immediately trips an alert, severs the client's SMB session, and locks the share.

##### 3. Behavioral Anomaly & Entropy Spike Detection (StorageForge Opportunity)
* **The Concept:** Detecting ransomware through file characteristics rather than static signatures.
* **How it works:** When ransomware encrypts files, two things happen:
  1. **Mass Modification / Renaming Surge:** A sudden spike where thousands of files are touched within minutes.
  2. **High Entropy:** Encrypted data looks like pure mathematical randomness (high Shannon entropy) compared to standard document or image structures.
* **Why StorageForge is Uniquely Poised for This:**
  * Because StorageForge already maintains a scan diff history (`file_changes` table recording every added, modified, or deleted file between scans), it can detect a sudden anomaly in modified file volume.
  * Instead of running brute-force ClamAV scans across hundreds of terabytes, an agentless system can perform **differential targeted scanning**: running lightweight YARA rules, entropy checks, or ClamAV *only against the files that changed since the last scan*.

---

## 7. Infrastructure-as-Code & Fleet Storage Automation

Tools that apply configuration management to Linux storage layers.

### [Ansible Linux System Roles: `storage`](https://github.com/linux-system-roles/storage)
* **What it does:** Declarative Ansible role maintained by Red Hat to configure local storage (partitions, LVM, Stratis, LUKS, RAID, filesystems).
* **Overlap:** Provides idempotent configuration of storage primitives; converges system state.
* **Differences:** Requires manual YAML authoring. Lacks a web UI, file indexing, topology graphing, container correlation, and automatic scan-based drift detection.

### [Stratis](https://stratis-storage.github.io/)
* **What it does:** A local storage management daemon created by Red Hat that unifies thin provisioning, XFS filesystems, and device pooling via `stratisd` and D-Bus.
* **Differences:** A host-level storage daemon rather than a fleet manager.

### [Linstor (LINBIT)](https://linbit.com/linstor/)
* **What it does:** Orchestrates block storage (LVM, ZFS) and distributed network replication (DRBD) across Linux clusters for Kubernetes or OpenStack.
* **Differences:** High-availability block replication engine for hyperconverged infrastructure, not a management UI for heterogeneous filesystems and backups.

---

## 8. Storage Health, Telemetry & Container Correlation

Tools handling specific components of StorageForge's telemetry and inventory capabilities.

### [Scrutiny (`AnalogJ/scrutiny`)](https://github.com/AnalogJ/scrutiny)
* **What it does:** Web UI and collector for S.M.A.R.T. disk health across multiple Linux hosts.
* **Overlap:** Central dashboard showing drive temperatures, wear indicators, reallocated sectors, and impending failures across a fleet.
* **Differences:** Focused strictly on disk hardware metrics, with no filesystem, dataset, or backup management.

### [Portainer](https://www.portainer.io/) / [Dockge](https://github.com/louislam/dockge)
* **What they do:** Container management web dashboards.
* **Overlap:** Mapping container bind mounts and volumes to host filesystem paths. StorageForge provides this from the reverse angle (mapping host storage paths to the containers and Git repos that depend on them).

### [NetBox](https://netboxlabs.com/)
* **What it does:** The standard open-source DCIM (Data Center Infrastructure Management) and IPAM tool.
* **Overlap:** High-level inventory of servers, hardware specifications, and network links.
* **Differences:** Models physical/cabling infrastructure; does not inspect internal OS storage structures or walk directory trees.

---

## Comprehensive Comparison Matrix

| Software / Project | Agentless SSH? | File & Metadata Index | Storage Topology (ZFS/Btrfs/LVM) | 3-2-1 Backup Health | Dry-Run Change Scripts | Host DR / Rebuild Script | Container Mount Inventory |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **StorageForge** | **Yes** | **Yes** | **Yes** | **Yes** | **Yes** | **Yes** | **Yes** |
| **EPICSHELTER (NSA)** | Proprietary | Yes | Unknown | Yes | No (Automated) | Yes | N/A |
| **TrueNAS (SCALE/CORE)** | No (Appliance) | No (Local search) | Yes (ZFS only) | Partial (Replication) | No (UI apply) | Config file | Yes (Apps) |
| **Proxmox VE** | Yes (SSH/API) | No | Yes (ZFS/LVM/Ceph) | Partial (PBS links) | No | Config archive | Yes (VM/LXC) |
| **Diskover** | No (FUSE/NFS/Agent) | Yes | No | No | No | No | No |
| **Cockpit / Houston** | Yes (SSH bridge) | No | Yes (Host only) | No | No (Instant apply) | No | No |
| **Rockstor** | No (Appliance) | No | Yes (Btrfs only) | Partial (Replication) | No | No | Yes (Rock-ons) |
| **ReaR (Relax-and-Recover)** | No (Local root) | No | Yes (Bare metal) | No | No | Yes (`rear recover`) | No |
| **git-annex** | Yes (SSH) | Yes (Tracked keys) | No | Yes (`numcopies`) | Yes (CLI flags) | No | No |
| **Bacula / Bareos** | No (Agent) | Yes (Catalog DB) | No | Yes (Schedules) | No | Partial (FD restore) | No |
| **Syncthing** | No (P2P Agent) | No (Sync index) | No | Partial (Copies) | No | No | No |
| **Ansible `storage`** | Yes | No | Yes (Declarative) | No | Yes (`--check`) | No | No |
| **Scrutiny** | No (Daemon/Collector)| No | Disks only (SMART) | No | No | No | No |
| **Portainer** | No (Agent/Socket) | No | Volumes only | No | No | No | Yes |

---

## Conclusion

StorageForge addresses a clear void in modern systems engineering:
* Enterprise platforms like **Komprise** or **Starfish** index files at scale, but ignore underlying Linux block devices and cost tens of thousands of dollars.
* Tools like **Cockpit** and **Houston UI** provide great storage GUIs, but are confined to single machines and lack file search or pre-flight script generation.
* Disaster recovery tools like **ReaR** and backup orchestrators like **Bacula** recover files or partitions, but don't give administrators a live, editable architectural canvas or container correlation.
* Leaked historical systems like **EPICSHELTER** pioneered the marriage of distributed metadata scanning, differential sync, and automated disaster recovery, but remained classified government defense software.

StorageForge unifies these concepts into an open, agentless tool for Linux administrators and homelabbers.
