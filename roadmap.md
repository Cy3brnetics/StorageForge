# Roadmap: 0.6.0

Everything not built on `main` as of 2026-11-16 (`01ece8f`, after 0.5.2), in one place. On that day the owner put all of it under 0.6.0: every test that can be written, every Toolbox entry, every way of connecting hosts (Tailscale, NetBird or whatever is needed), log monitoring, an optional agent, and everything else still open. [progress.md](progress.md) says what has been built and lab-tested. The 0.4.0 release roadmap is in the archive as [release-0.4.0-roadmap.md](archive/roadmaps/release-0.4.0-roadmap.md), with the other finished and superseded roadmaps in [archive/roadmaps](archive/roadmaps/). They hold the detail behind many items here: formats, field lists and reasoning. **This page decides what's next, and they don't.**

Checked against the code on 2026-11-16.

## How to read this

**Done** means through the KVM lab, as [progress.md](progress.md) defines it. A finding is `SF`, `PF`, `EQ` or `UX` and a number, as in the notebook's [audit rules](notebook/Audit%20rules/Audit%20rules.md). Each section can stop at any item without harming the others. The **Status** columns are the ledger: whoever finishes an item writes the commit that finished it. There are no time estimates on this page, by the owner's choice.

## Rules for the release

1. Nothing is called *done* or *lab-tested* without a lab pass. What can't be tested (no image, no hardware, an outside service) ships labelled *not lab-tested*, in the docs, in the UI where it shows, and in the release notes.
2. Every new feature brings its lab tier, or says in this ledger why it has none.
3. A secret a plan step needs comes from the vault and is never on a command line, in a plan, a script or a log, as the `tailscale` step does. A tool that can only take its key on a command line gets no join step until that is solved.
4. An audit to the [audit rules](notebook/Audit%20rules/Audit%20rules.md) reads the new surface before the lab run. Every High and Medium is fixed or carries a written decision. A Low is fixed when it is small.
5. The version, the changelog heading, the merge and the tag come last. Pushing to either remote is the owner's call.

## What only the owner can do

| Item | Needed for |
| :--- | :--- |
| Set up a Forgejo runner (it can run as a container, but registering it needs a token from your Forgejo) | EQ-01 and SF-38 on Forgejo |
| Run the disk-health collector on this machine's real disks (it needs sudo here) | PF-04 on real worn disks |
| Download pfSense CE once (Netgate's installer and store want an account), so its checksum can be pinned and `lab.sh` can take it from the image cache | pfSense in the lab |
| A Cisco account for Cisco Modeling Labs Free | Cisco in the lab |
| A PagerDuty account, if a free plan still exists | PagerDuty reaching the real service |
| A physical FIDO2 token | FIDO2 at step-up and at sign-in |
| A Cloudflare account, and an ngrok account | Cloudflare Tunnel and ngrok against the real services |
| A Windows evaluation VM | Samba attribution with a real Windows client, and the shadow-copy tripwire (section 11) |
| Say when to push `main`, the tag, `dev` and the GitHub mirror | The release |

## Decisions taken

| Decision | Taken |
| :--- | :--- |
| **StorageForge gets an optional agent** (section 11). Agentless over SSH stays the default and keeps every feature, per scan. Network devices and appliances stay agentless. This replaces the old *Will not be built* line "stays agentless and builds no live log viewer" | 2026-11-16, the owner |
| **SSH sets a host up, and manages the agent's container after.** The agent has no Docker socket or API | 2026-11-16, the owner |
| **One base image, with signed plugins per host,** not one build per machine. Anything unexpected in an agent's container wipes its access and stops it | 2026-11-16, the owner |
| **The shadow-copy tripwire is an agent feature** on Windows clients (section 11). The trap on the Samba server stays impossible | 2026-11-16, the owner |
| **Scans on an agent host are scripts carried in the scan plugin,** not signed requests: no code crosses the wire per scan, and only the release key, not the controller, decides what code runs. An operator's own plugin key is never stored on the controller | 2026-11-16, the owner |
| **The agent gets zero trust for what it says, and as little as works for what it can do** (section 11.2) | 2026-11-16, the owner |
| **Hosts may connect to the controller,** as many as the user enables, one host at a time: the agent and log push are switched on per host | 2026-11-16, the owner |
| **One central notification center** (section 12), most critical at the top, in place of a yes or no on log rules notifying: every source feeds it, some notifications can be ignored by the user and some cannot, and some carry a one-click fix | 2026-11-16, the owner |
| **Tailscale and NetBird both stay, and StorageForge's own encrypted network is the default** (section 2.1): data between hosts and the controller is encrypted even on the LAN, with no outside service needed | 2026-11-16, the owner |
| **A console on a monitoring-only host is SSH turned on for that session** through `storageforge-agentctl`, and off again after. (The owner was fine with a reverse shell too; SSH for the session keeps the agent from ever carrying a shell, as 11.2 wants) | 2026-11-16, the owner |
| **The agent is an extra layer on top of SSH, isolated from it** (section 11.2): SSH stays the base on every agent host; the agent holds nothing of SSH's, SSH depends on nothing of the agent's, and taking one gives nothing of the other | 2026-11-16, the owner |
| **A host with no container runtime gets Podman, after the user is told.** The SSH scan already reads whether Docker or Podman is there; installing the agent on a host with neither says Podman will be installed, then goes ahead | 2026-11-16, the owner |
| **The file index comes from SSH, the agent, or both.** With both on, each checks the other, and the agent offers deeper options and live monitoring. Monitoring-only hosts get it through the agent | 2026-11-16, the owner |
| **Every fix is shown prepared, then deployed, with a rollback.** No fix applies unseen: the prepared plan and its report come first, deploying takes the password, and a fix is offered only with a way back | 2026-11-16, the owner |
| **Critical notifications, configuration drift and security findings cannot be ignored:** they leave only when resolved, by an update or another step. Everything else can be snoozed or muted | 2026-11-16, the owner |
| **The StorageForge network carries only StorageForge-managed connections** (scans, the agent, deploys, `storageforge-agentctl`, the console). File transfers get encrypted tunnels of their own; the hosts' shares are not carried | 2026-11-16, the owner |
| **All of the change engine, Workloads and the Toolbox belong in StorageForge.** The [merged plan's other decisions](archive/roadmaps/infrastructure-platform-roadmap.md#12-decisions-to-confirm) stand, except that routers and switches are now read directly | 2026-11-16, the owner |
| **Control is done over SSH; automation and monitoring by the agent,** which runs under its own uid:gid. Change plans stay on SSH. The user that deploys and manages the agent is never in the `docker` group and uses `sudo` where it must, limited to the agent's verifier | 2026-11-16, the owner |

## Decisions still open

| Decision | Blocks |
| :--- | :--- |
| **One design document** in place of the storage blueprint and the map's design: the owner took the recommended answers in section 10.1 on 2026-11-16, to be checked again when 3i is reached | Section 10's step 3i, confirmed at 0.5.14 |

## Versions and checkpoints

0.6.0 is reached through versions from 0.5.3 up, each one a theme, in an order where each builds on the ones before. Every version ends releasable.

**Minor checkpoint: a commit.** One item of a version is done: its code, its unit tests passing on SQLite and PostgreSQL, its docs and its changelog line under *Unreleased*. It is committed on the working branch in the repo's style (`feat(area): …`, `fix(area): …`, a plain sentence saying what changed for the user) and the ledger's **Status** cell names the commit. Nothing is pushed.

**Major checkpoint: stop and tell the owner.** Work stops and the owner is told what was done, what was tested, what failed and what is needed, at:

1. the end of every version: the changelog heading, the version bump, a local tag; pushing is the owner's call
2. every KVM lab run, with its results
3. a decision from *Decisions still open*, or an item from *What only the owner can do*, that the next item needs
4. a finished security boundary: the agent's receiver, `storageforge-agentctl`, the trust model, the plugin signatures, a new join step's secret handling
5. a test that fails and is not understood, or a finding of High or Critical
6. before anything that cannot be undone: a migration that changes a stored format, a removal of a feature

| Version | Theme | Minor checkpoints, a commit each | Major checkpoints |
| :--- | :--- | :--- | :--- |
| **0.5.3** | What is on `main` and not released, and the lab's own gaps | The unreleased clock fixes and the Wolfi image · 1.2: appliances in the build, Playwright where tiers run, `qemu-img` on `sf-ubuntu`, one default build with every host the skipped checks need, SF-72's properties read back, `progress.md` brought up to date, `shellcheck` kept installed · 1.1: OPNsense in `images.conf`, `nodes.conf` and a tier | The lab run of every tier, with nothing skipped that a host could run · ask for the pfSense image, the Cisco account and the Windows VM · release |
| **0.5.4** | Logs: the holes, rules, and the notification center | Section 12: the notification center, ranking, what cannot be ignored, prepared fixes with rollback · Section 3, phase 0: prune by arrival, the per-host rate, journald's own fields, `__SEQNUM`, the 5-minute counts (from here on they build the baselines 0.5.7 needs) · phase 1: the rule engine, the built-in rules, matching without regex over host text, one alert per rule and host · 1.4: disk failures made in the lab to prove the rules | The log tier's lab run · release |
| **0.5.5** | Connections | 2.1: StorageForge's own WireGuard network, the default · the console names the network it found (fixes NetBird shown as Tailscale) · read and draw: Tailscale (`--json`), Headscale, NetBird, ZeroTier, Nebula, Netmaker, OpenVPN, strongSwan · join steps, each with its key from the vault: NetBird, ZeroTier, Nebula, Netmaker, OpenZiti · exposure through tunnels: Pangolin with its API token, Cloudflare Tunnel, frp, ngrok · Teleport, Boundary and Pomerium read · SSH CA · 1.3: Headscale, NetBird, ZeroTier and Pangolin servers on lab hosts | The StorageForge network's keys and peers, a security boundary · each join step's secret handling · the connections lab run · release |
| **0.5.6** | The agent: base, trust and the first plugins | 11.1: the `agent` stage of the `Dockerfile`, `sfagent`, `storageforge-agentctl` with its one sudoers line and the `docker` group refusal, Docker and Podman, rootless for the basic plugins, enrollment over pinned SSH · plugin format, release-key signatures, the signed manifest with its counter · 11.2: the receiver as its own process and database role, identity from the key, counters, quotas, provenance labels · 11.3: wipe and stop, from outside and inside · plugins: heartbeat, logs (section 3, phase 2: push), health, network · 11.6: the tamper and trust checks | Each boundary in 11.1 to 11.3 as it is finished · the agent's lab run · release |
| **0.5.7** | The agent's other plugins, and monitoring | Plugins: disks (PF-04's path), files (an index that updates itself, process attribution, hand edits, off-hours reads), scan (scripts carried in the plugin), sentinel reports, Toolbox status · monitoring-only hosts with `storageforge-agentctl` alone · Section 3, phase 3: anomalies on the counts since 0.5.4 · phase 4: the monitoring view · phase 5: netconsole and `pstore` | The console turned on for a session · the files plugin's privileges, which are root in effect · the lab run · release |
| **0.5.8** | Change engine | 5: the secret store with generated secrets and rotation · `runtime-install` with its preflight · pools: ZFS vdevs, disk replace and attach, md add, replace and grow, LUKS · networks: bonds, addresses, routes, DHCP, reading netplan, NetworkManager and networkd files | The secret store's boundary · 5's exit test in the lab · release |
| **0.5.9** | Workloads | 6: `stack` and `lxc` steps, Incus instances, image updates with rollback, VMs from ISOs, placement advice, MAC at deploy, Quadlets and adopting a workload, quiesced stacks, externally managed workloads, workload exports with round trips · 1.3: proxies and identity providers on lab hosts | The workloads lab run · release |
| **0.5.10** | Toolbox: the engine | 4.1: the catalog engine, signatures and overrides, install methods, risk labels, uninstall that keeps data · adapters and the GUI levels · the Toolbox view and deep links · the API and tables · custom entries | The catalog's signature boundary · the engine's lab run · release |
| **0.5.11** | Toolbox: the entries | 4.2, one commit per group: panels, VPN and overlay servers, zero trust and access, identity, reverse proxy and DNS, detection and scanning, monitoring, backup with restore tests, secrets, provisioning, storage-facing apps, offline mirrors · 4.1: bundles, role profiles, custom dashboards, feeds · 4.3: the built-in bundles | The gauntlet for each group as it lands · release |
| **0.5.12** | Windows, network and map, migration | 11: the Windows agent and the shadow-copy tripwire · 8: `place-before`, scan placeholders, scanner findings through alerts, deeper reads, actions from the map, `bridge`-family rules, map extras, NetBox, Grafana, SNMP and LLDP · 7: phases 3b, 3d, 4b, 5 and 7 · 1.1: pfSense and Cisco once the owner's items are in, the old-cipher device | The Windows VM run · the network devices' lab run · release |
| **0.5.13** | Security depth | 9: incidents with workloads, compliance readings, credential and identity anomalies, the Falco simulator, the builders, FIDO2 at sign-in, SMS, mirror discovery, the smaller items · SF-38 · EQ-03 if it no longer sits before a lab run · 1.3: playbooks acting for real, a bridged VM under quarantine, OpenTofu and Puppet applies, migration 1b and 4b | The physical FIDO2 token and PagerDuty, if the owner has them · the lab run · release |
| **0.5.14** | UI and UX | 10: phase 2's workspaces and one Plan workspace, phase 3's steps 3a to 3h one commit each, phase 4, phase 5's gaps, the components, retiring Graph and Structure, native modules · 3i only if decided | The 3i answers in 10.1 confirmed again, and its migration, before it runs · the browser and lab runs · release |
| **0.6.0** | The release | The audit of everything since 0.5.2, to the audit rules, and its bugfix round, a commit per finding · the full unit suites on both databases · the full lab | The audit's findings · the lab results · the release, with every *not lab-tested* label listed in the notes |

## 1. Tests and the lab

Everything that can be tested without the owner's items above.

### 1.1 Network devices

| Item | How | Status |
| :--- | :--- | :--- |
| **OPNsense** | The free `nano` image boots already installed on a serial console. Into `images.conf` and `nodes.conf` like the CHR and OpenWrt images, and a tier like RouterOS's: read, the network language, rollback | open |
| **pfSense CE** | Runs in KVM. The image is the owner's download (above), then the same tier as OPNsense | open |
| **Cisco** | CML-Free (free, a Cisco account): IOL, IOL-L2 and ASAv, up to five nodes at once. Its licence forbids the images outside CML, so CML runs as a lab VM and StorageForge connects to the devices inside it. IOS-XE (Cat8000v) and IOSv are not in the free tier. First check whether `cisco.py` is written for classic IOS, which IOL runs, or IOS-XE | open |
| **Old SSH ciphers** | A RouterOS 6.x CHR image, an OpenWrt release with an old dropbear, or an old distro cloud image | open |
| **Drop the "no free image" label** from `progress.md` and `tiers_network.py` for whatever of the above passes | | open |

### 1.2 Checks the lab skips today

| Item | Why it is skipped | Fix | Status |
| :--- | :--- | :--- | :--- |
| **Appliances:** Proxmox, TrueNAS, XCP-ng (`sf-pve`, `sf-truenas`, `sf-xcp`) | Defined in `nodes.conf` and `images.conf`, never in the default build ("use `up --pick`") | Run them. This also lab-tests **Proxmox guests**, still marked not lab-tested | open |
| **`ui-pages`** | Playwright is not installed where the tier runs | Install it there | open |
| **`workload-libvirt`** | No `qemu-img` on the `sf-ubuntu` image | Add it to that node's provisioning | open |
| **SF-72** | The ZFS receive's mountpoint was read back; the export and setuid properties were not. The btrfs side is undecided | Read both back in tier 16, and decide the btrfs side | open |
| **Builds without the right host** | `smb`, `snapjobs-snapper`, `btrfs-disk-pulled`, `compile-iptables`, `lxc-guests` and `incus-guests` skip when the build lacks a host that can run them | One default build that has an SMB client, a snapper host, a btrfs raid host, `iptables-restore`, a Debian-family host without Docker and a second one | open |
| **`progress.md` is behind** | It says tier 14, LXC and Incus are not lab-tested; the 0.5.0 changelog says they ran on 2026-11-08 | Bring it up to date | open |
| **The full unit suites** | Not re-run on SQLite and PostgreSQL after the last fixes of the 0.4.0 run | Re-run both, and keep `shellcheck` installed for the generated scripts | open |

### 1.3 Not lab-tested, and only free software is needed

| Item | How | Status |
| :--- | :--- | :--- |
| **Reverse proxies** | Caddy, nginx, Traefik and HAProxy installed on lab hosts, their routes read and drawn | open |
| **Identity providers** | Keycloak, Authentik, Authelia and LLDAP in containers | open |
| **Tailscale** | Headscale as the control server, real Tailscale clients, the `tailscale` step joining and leaving | open |
| **Terraform and Puppet exports** | OpenTofu and Puppet installed; validate, then apply: `puppet apply` on a lab host, OpenTofu with the libvirt provider | open |
| **Host migration phase 1b** | Image-based and transactional systems (Fedora CoreOS or bootc, MicroOS) as lab images | open |
| **Host migration phase 4b** | Snapshots before and after, and the data-at-risk list, in a lab copy | open |
| **Playbooks acting by themselves** | The live path on a real trip in the lab, not only the dry run | open |
| **A quarantine and a bridged VM** | Measure whether it reaches one. The map says it doesn't | open |
| **Every 0.6.0 feature** | Each section below brings its own tier | open |

### 1.4 Partly testable

| Item | What the lab can show | What only the owner can show |
| :--- | :--- | :--- |
| **Disk health (PF-04)** | QEMU's emulated NVMe reports SMART data, and `scsi_debug` and `dm-error` make real disk errors on demand, so the warn and alert path. The same failures, with `mdadm --fail` and `zpool offline`, make the kernel lines section 3's rules must catch | Real worn disks |
| **PagerDuty** | A local stand-in for its API | The real service |
| **FIDO2** | Chromium's virtual authenticator, as today | A physical token |

## 2. Connections

Every way of joining hosts to a private network or publishing them through a tunnel, so a site can use whichever it likes. Every entry gets the same five parts where they apply:

1. **Read:** a scan reads the tool's own status (JSON where the tool has it), and the map draws its peers and routes, confirmed or inferred.
2. **Join and leave:** a plan step, with the key from the vault under rule 3.
3. **Console:** SSH over that network, named for it. Today any address in 100.64.0.0/10 is called Tailscale (`console.py:72`), so a NetBird host is offered as "SSH over Tailscale". Moves already take any interface.
4. **Exposure:** a tunnel that publishes a service makes it public, even with no port open on the host or router, and the security view says so.
5. **Lab:** a self-hosted control server where one exists. A tool that needs an outside service ships labelled.

| Tool | What it is | What exists | What's needed | Status |
| :--- | :--- | :--- | :--- | :--- |
| **Tailscale** | Mesh VPN, outside control server | `tailscale` step, peers read from `tailscale status`, console route | Read `tailscale status --json` instead of the text; the console route named; lab through Headscale | built, not lab-tested |
| **Headscale** | Self-hosted Tailscale control server | Detected as a tool and a service | Read nodes, routes and pre-auth keys from its CLI or API; pre-auth keys made into the vault for the `tailscale` step | open |
| **NetBird** | Mesh VPN, self-hosted control server | Detected as a tool, `wt0` counted as a VPN interface, its service known | Read peers from its status; a `netbird` step with the setup key from the vault (first check that `netbird up` can read the key from a file); console route; lab with a self-hosted management server | open |
| **Netmaker** | Mesh VPN, self-hosted | Nothing | Read nodes and gateways; join with an enrollment key | open |
| **ZeroTier** | Mesh VPN, outside or self-hosted controller | Known as a service | Read `zerotier-cli -j` networks and peers; join and leave; lab with a self-hosted controller | open |
| **Nebula** | Mesh VPN with its own certificate authority | Its interface counted as a VPN | Read its config and peers; host certificates issued from a CA kept in the vault; a lighthouse as a role | open |
| **WireGuard** | Plain tunnels | `wg-peer` step, peers read and confirmed by key | Peer manager: add, revoke, QR code, handshake age (Toolbox entry, section 4) | built |
| **OpenVPN** | VPN with a PKI | Known as a service | Read status and clients; certificates and the CRL; client profiles | open |
| **strongSwan (IPsec)** | Site-to-site tunnels | Nothing | Read `swanctl` tunnels; site-to-site templates | open |
| **Pangolin** | Self-hosted tunnel and reverse proxy with login (Newt runs at the site) | Nothing | Detect Newt; read what the Pangolin server publishes through its API with a token in the vault, a new kind of connection since everything else goes over SSH; exposure "public through Pangolin at `<domain>`"; join with a site secret; lab with the server on a lab host | open |
| **Cloudflare Tunnel** | Tunnel to Cloudflare | `cloudflared` known as a service | Read its config and routes; exposure; the tunnel token in the vault. Needs a Cloudflare account, so labelled | open |
| **frp, ngrok** | Tunnels | Known as services | Read their configs; exposure. ngrok needs an account, so labelled | open |
| **OpenZiti** | Zero-trust overlay, self-hosted | Nothing | Read services and identities; join an identity from an enrollment token | open |
| **Teleport, HashiCorp Boundary** | Access proxies | Nothing | Read targets; targets made from the host inventory; Teleport's session recordings on a protected dataset | open |
| **Pomerium** | Identity-aware proxy | Its service known | Read routes and policies | open |
| **SSH CA** | Short-lived SSH certificates | Nothing | CA key in the vault, `TrustedUserCAKeys`, principals; issue and revoke | open |

### 2.1 StorageForge's own encrypted network (the default)

Decided 2026-11-16: data is encrypted even on the LAN, and the default needs no outside service. StorageForge builds a WireGuard network of its own between the controller and the hosts it is turned on for, from the `wg-peer` step that exists: a key pair per host made on the host (the private key never leaves it), public keys and addresses held by the controller, peers written by change plans, every peer confirmed by key on the next scan, a key rotated through a plan, a host removed by revoking its peer everywhere. Its own address range, chosen so it never meets Tailscale's or NetBird's 100.64.0.0/10. The console, Moves and the map name it as the StorageForge network. Tailscale and NetBird stay as choices for sites that already run them.

| Item | Status |
| :--- | :--- |
| The network as a setting per host, its address plan, and the peers as plan steps | open |
| Key pairs made on the hosts, rotation and revocation through plans | open |
| The controller as a peer (in Docker, a WireGuard interface for the container or the host's) | open |
| Scans, deploys, `storageforge-agentctl`, the console and the agent's tunnel over the StorageForge network where the host is on it. Sends, Moves and sync keep a tunnel of their own per transfer (the forced-command job keys and rsync over SSH, encrypted end to end); NFS and SMB shares are not carried | open |
| Lab: a host on the LAN reached only through it, a capture showing no clear text between two hosts, a key rotated and a peer revoked | open |

Deploying the servers (Headscale, NetBird's management, Pangolin, a ZeroTier controller, OpenZiti's controller) is a Toolbox entry each (section 4). This section is the hosts' side.

## 3. Log monitoring

Notifications from host logs, counts and anomalies, and logs that leave a host as they are written, so a host that locks up or is taken over has already sent what it logged.

What exists and is reused: `alerts.evaluate()` opens, refreshes and resolves alerts and notifies on each change, through ntfy, Gotify, a webhook or PagerDuty with routes by host and level, and `alerts_wake` can trigger it at once. Host logs are stored, scrubbed of secrets and searchable, with counts by level and hour. A log rule becomes one more source in `alerts.problems()`: open while its count over a window is over the threshold, resolved when it falls.

| Phase | What it holds | Status |
| :--- | :--- | :--- |
| **0. Holes in what is stored today** | Prune by arrival time (`collected_at`), not the host's timestamp: today a host can log 500,000 lines stamped up to a day ahead and push real lines out of `KEEP_ROWS`, and a line stamped older than `KEEP_DAYS` is deleted as it is stored. A per-host ingest rate, with going over it recorded, not paid for in old rows. Store the fields journald sets (`_UID`, `_COMM`, `_EXE`), since `SYSLOG_IDENTIFIER` is whatever the writer says. Keep `__SEQNUM` and its ID, to see lines deleted on the host. Counts per host, unit and level per 5 minutes, kept longer than the raw lines, starting at once because baselines need weeks of them | open |
| **1. Log rules** | Notifications go to the central notification center (section 12). A rule matches host, unit, program, lowest level and text, with a threshold over a window. Built-in rules for storage hosts: OOM kills, disk and controller I/O errors, filesystem errors (ext4, XFS, btrfs), ZFS or mdadm degraded, NFS or SMB not responding, failed units, segfaults, disk full; bursts of failed SSH and sudo logins off by default. Matched as lines arrive. No arbitrary regex over host text (SF-52): plain text and wildcards, or `google-re2`. One open alert per rule and host, so a flood is one alert | open |
| **2. Push ingest** | Hosts send journal lines as they are written, through the agent's logs plugin (section 11), to a receiver on the controller that resumes from the last line it has after a reboot. Per-host identity, size and rate limits, off the web threads. Each host's delay, gaps and signed or not shown. Hosts without the agent are polled over the SSH master connection every few seconds, which misses lockups | open, needs section 11's base |
| **3. Anomalies** | Volume against the same hour of the week over two to four weeks (median and spread, with a floor for quiet units). New kinds of line: a message with numbers, hex, addresses and paths blanked, hashed, flagged the first time a host logs it. Silence: a host or unit that normally logs and stops, which is how a lockup shows | open |
| **4. The monitoring view** | Per host: rate against baseline, open log alerts, new kinds of line, silent hosts, and ingest health (last line, delay, gaps, signed or not). To the patterns in [ACCESSIBILITY.md](ACCESSIBILITY.md). Logs entry points from an alert, a mount and a device | open |
| **5. netconsole** | Kernel messages over UDP straight from the kernel, which works when user space is dead, so panics and hard hangs reach the controller. `pstore` to read the last panic after a reboot | open |

**What it does not do:** prove a line is true. Signing proves a payload came from the host unchanged; root on the host can write, edit or delete anything not yet sent, and sign it. Sending lines as they are written shrinks that window to almost nothing, and gaps in `__SEQNUM` and silence show deletion afterwards. Forward Secure Sealing (`journalctl --setup-keys`, with the verify key on the controller) shows files altered on the host. It cannot stop deletion.

## 4. Toolbox

None of it exists. It needs the catalog engine and the secret store (section 5). The [Toolbox roadmap](archive/roadmaps/toolbox-catalog-roadmap.md) holds the entry format, the GUI levels, the API, the tables, the safety rules and the lab gauntlet; [the merged plan](archive/roadmaps/infrastructure-platform-roadmap.md#8-the-catalog) wins where they differ. A tool without a passing lab run is labelled *not lab-tested* in the catalog.

### 4.1 The engine

| Item | What | Status |
| :--- | :--- | :--- |
| **Catalog engine** | Entry schema, signatures (the project's for the official catalog, the operator's for their own), validation, the override layer that survives catalog updates, install methods in order of safety (rootless container, distro package, verified binary; Quadlet and compose), risk labels in the report, uninstall that keeps data | open |
| **Adapters** | `detect`, `status`, `actions`, `links`, `metrics`, read-only by default, over the existing SSH scan; an action is a staged plan step; credentials by vault reference only; a failed adapter says "status unavailable" and never blocks a scan | open |
| **GUI levels** | Link, SSO link, status tiles, panel with actions | open |
| **Toolbox view** | The rail item, host cards, deep links (`/#host=gw-01&tab=toolbox&tool=wireguard`) | open |
| **API and tables** | `/api/toolbox/...` (catalog, validate, sign, installed, status, stage, bundles, actions, updates, exposure); `toolbox_catalog`, `toolbox_installs`, `toolbox_status`, `toolbox_bundles`, `toolbox_overrides` | open |
| **Custom entries** | An editor with validation, a dry run and signing with the operator's key | open |
| **Bundles** | Ordering, shared secrets, one firewall change set, one report, rollback of the whole bundle | open |
| **Role profiles and per-host exclusions** | Default tools per host role (`edge`, `nas`, `hypervisor`) | open |
| **Custom dashboards** | Tool tiles in the dashboard grid | open |
| **Feeds** | Trivy findings and CrowdSec decisions into alerts and the quarantine view, with bans reconciled so quarantine doesn't fight the bouncer | open |

### 4.2 The entries

| Group | Entries | Status |
| :--- | :--- | :--- |
| **Panels** | Cockpit, Dockge, Portainer, Komodo, Dockhand, Dokploy, Incus UI | open |
| **VPN and overlay servers** | WireGuard with the peer manager, Headscale (with headscale-ui or headplane), NetBird's management, signal, relay and dashboard, Netmaker, a ZeroTier controller, Nebula's CA and lighthouse, OpenVPN with its PKI, strongSwan, Pangolin with Gerbil and Traefik | open |
| **Zero trust and access** | OpenZiti, Pomerium (policies from each entry's exposure), Cloudflare Tunnel, Teleport, HashiCorp Boundary, SSH CA | open |
| **Identity and SSO** | Authentik, Keycloak, Authelia, Kanidm, LLDAP, Samba AD DC, FreeIPA; OIDC clients registered for catalog panels | open |
| **Reverse proxy, TLS and DNS** | Caddy with generated routes, Traefik, nginx Proxy Manager, step-ca, Pi-hole, AdGuard Home, Unbound, CoreDNS, dnsmasq, Chrony with NTS | open |
| **Detection and scanning** | CrowdSec with the nftables bouncer, fail2ban, Suricata, Zeek, Trivy, Grype, OpenSCAP, Falco, Wazuh | open |
| **Monitoring and alerting** | Prometheus with node_exporter, Grafana with a StorageForge dashboard, Loki with Promtail or Alloy, Uptime Kuma, Beszel, Netdata, smartd and smartctl_exporter, ntfy, Gotify, Apprise | open |
| **Backup and recovery** | restic, Borg, Kopia, Proxmox Backup Server, automated restore tests to a scratch dataset with hashes compared | open |
| **Secrets** | OpenBao or Vault with quorum-style unseal, sops with age, Vaultwarden | open |
| **Provisioning and platform** | Packer, PXE, iPXE and netboot.xyz, Forgejo or Gitea, a registry mirror (Zot or Harbor) for airgapped installs, Renovate or an image-update watcher, DNS and DHCP panels, Ansible, Puppet and Terraform runners | open |
| **Storage-facing apps** | Samba, NFS, MinIO, Garage, Nextcloud, Syncthing, Jellyfin, each placed on a dataset with its snapshot and WORM policy, share fencing and canaries wired in | open |
| **Offline** | Package bundles and local mirrors, with the registry mirror | open |

### 4.3 Built-in bundles

Private access (WireGuard, Headscale or NetBird, Caddy, Authelia) · Hardened homelab (private access, CrowdSec, Chrony with NTS, Uptime Kuma, restic) · Container host (rootless Podman, Caddy, Komodo or Dockge, Trivy, node_exporter) · Hypervisor (libvirt, Cockpit, WireGuard, backup, smartd) · Observability (Prometheus, Grafana, Loki, ntfy, smartctl_exporter) · Zero-trust gateway (Authentik, Pomerium or OpenZiti, step-ca) · Backup and recovery (restic or Kopia, restore tests, a WORM dataset).

## 5. Change engine

Built since the last roadmap: storage pools of every kind as steps (`zfs-pool`, `md-array`, `lvm-vg`, `btrfs-add`, partitions and formats), bridges, VLANs and MTU (`net-bridge`, `net-vlan`, `net-mtu`), libvirt networks and pools, and secrets for plan steps (`vault secret-add`, `vault send-secret`).

| Item | What's left | Status |
| :--- | :--- | :--- |
| **Secret store** | Generic secrets generated, shown once, delivered through the runner's stdin, with a rotation path like `rotate` has for SSH keys | open |
| **`runtime-install`** | The four runtimes across distros, rootless setup, and a preflight that says present, installable or blocked. [Detail](archive/roadmaps/infrastructure-platform-roadmap.md#71-runtime-install) | open |
| **Pools: what's left** | Add a vdev to a ZFS pool, replace or attach a disk; add, replace and grow an md array; LUKS | open |
| **Networks: what's left** | Bonds, addresses, routes, DHCP; read netplan, NetworkManager and networkd files as well as what the kernel has | open |

**Exit:** install a runtime on a bare VM from a plan. The report changes nothing, a changed plan gets 409, and a bridge change that cuts SSH rolls itself back.

## 6. Workloads

Built: running a container, VMs from cloud images (`vm-create`), defining a VM, start, stop and remove, snapshots and revert, changing a VM (`vm-edit`), copying a VM to another host, VM backups on a schedule, the console.

| Item | What | Status |
| :--- | :--- | :--- |
| **`stack` and `lxc` steps** | Each carrying its firewall rule and labels; Incus instances too | open |
| **Image updates** | With rollback on a failed healthcheck | open |
| **VMs from ISOs** | Cloud images are built | open |
| **Placement advice** | A pool on a dataset tuned for its use, databases off the bulk pool, warnings for bind mounts on network filesystems, and a warning when data sits where no hold or offsite copy reaches | open |
| **MAC at deploy** | `:Z` labels, the `svirt_image_t` fix as a plan step, AppArmor pool paths | open |
| **Read side** | Podman Quadlets; adopting a workload by capturing it as compose, Quadlet, libvirt XML or Incus YAML, with drift against the capture | open |
| **Quiesced stacks** | Stop, snapshot, start for stateful stacks, with the method recorded (VMs already freeze through the guest agent) | open |
| **Externally managed** | Detect a workload something else manages, and warn before changing it | open |
| **Exports** | Terraform, OpenTofu and Puppet for workloads, with round-trip tests | open |

[Workload roadmap](archive/roadmaps/workload-platform-roadmap.md) for field lists, and the [merged plan](archive/roadmaps/infrastructure-platform-roadmap.md#7-workloads-in-detail) where they differ.

## 7. Clone and migrate hosts

From the phases in [host migration](docs/host-migration.md#phases).

| Phase | What's left | Status |
| :--- | :--- | :--- |
| **3b** | AUR and local builds: the cache, `bacman`, an AUR build at the matching commit; Arch Linux Archive pinning; derivative repositories and CPU levels | open |
| **3d** | LUKS (the key is the owner's, so by hand unless the vault holds it), other `/etc` files | open |
| **4b** | Holds on the clone's snapshots, the before-and-after "what changed" report, `--accept` in the scripts | open |
| **5** | Test and migration modes: isolation, and cutover | open |
| **7** | A disk image from a physical host: a block copy from a snapshot into qcow2, fixed up to boot; to bare metal through a live environment | open |

## 8. Network and map

| Item | What | Status |
| :--- | :--- | :--- |
| **`place-before`** | A rule at a position. RouterOS appends, so a rule below a final drop does nothing, and the what-if says so | open |
| **Scan results as map placeholders** | The Scan tab links to the map, but they are separate drawings | open |
| **Scanner findings through alerts** | What's new since the last scan | open |
| **Traffic on Linux hosts** | Monitoring covers devices only. Activity from byte counters between scans | open |
| **Deeper reads** | Cisco zone-based firewall and VRFs, OSPF and BGP state, wireless clients, rich firewalld rules beyond source, port and verdict, DHCP scopes as nodes | open |
| **From the map** | Deploy a stack, an LXC instance, a catalog tool or a VM; move, clone or resize a VM; restrict a service's bind address; put a listener behind a proxy; rotate a peer's key | open |
| **`bridge`-family firewall rules** | For bridged VMs, which bypass a quarantine's hooks | open |
| **Map extras** | Force-directed and rack layouts, custom icons and colour rules, per-role default views, map tiles on dashboards, rendering for very large fleets | open |
| **Integrations** | NetBox and Grafana exports, read-only SNMP, LLDP | open |
| **REST adapters** | Only if a device needs one. SSH reads everything on all four platforms, and a second way in is a second thing to secure | when needed |

## 9. Security and ransomware depth

| Item | What | Status |
| :--- | :--- | :--- |
| **Incidents with workloads** | Incidents that include workloads touching affected paths, and a clean room that boots a VM or container from a pre-incident snapshot | open |
| **Compliance readings** | CIS Docker, Podman and libvirt-style checks, and auditd rules for runtime sockets and config | open |
| **Credential and identity anomalies** | Needs a new collector and a design first | open |
| **Watchers** | fanotify watchers; off-hours read volume by user. Both through the agent's files plugin (section 11); without the agent, off-hours reads need `vfs_full_audit` | open |
| **Falco rule simulator** | Rules against recorded sessions | open |
| **Builders** | A visual drag-and-drop subnet matrix (fences are typed today); a visual playbook builder beyond the form | open |
| **FIDO2 at sign-in** | Only guarded actions use it today | open |
| **SMS** | Its own channel, not only through a webhook | open |
| **Local mirror discovery** | A host uses the mirrors it is already set up for | open |
| **Smaller items** | Expiry heatmap, decoy personas and distribution, AppArmor profile editor, role-based hardening profiles, custom AIDE watchlist | open |
| **EQ-03** large modules | Split `server.py` and the other large modules, when it no longer sits right before a lab run | parked |
| **SF-38** container scan in CI | CI fails on a new reachable critical. On GitHub it runs; Forgejo waits for a runner | open |

## 10. UI and UX

From the [UI and UX roadmap](archive/roadmaps/ui-ux-roadmap.md) and the [UI audit of 2026-11-04](docs/audit-2026-11-04-ui.md). What phases 0 to 5 built is in the [0.4.0 ledger](archive/roadmaps/release-0.4.0-roadmap.md#a4-ui-and-ux).

| Phase | What's left | Status |
| :--- | :--- | :--- |
| **2** | Security and Settings as workspaces with their own section navigation; Security leading with blast radius, quarantine and the brake when the posture is Incident; the rail keeping only a summary and a link for them; one Plan workspace holding Design, Network and devices, Changes, Moves, Schedule and History; collapsible rail groups (UX-01) | open |
| **3** | The planner grows, steps 3a to 3h: design what isn't there yet (disks, pools, remotes, exports), Shares, the network lens, the workloads lens with placement guardrails, the security lens, the health lens, compare and adopt (adopting one object from the scan is the part of 3g not built), one Change review | open |
| **3i** | One design document in place of the storage blueprint and the map's design, with the planner as its editor and the map showing it as ghosts; a migration and a lab run. Answers in 10.1 | provisional answers, confirmed at 0.5.14 |
| **4** | Design mode from what was read, Compose as an editor (with paths that must stay open or blocked), Scan as a table and a diff, "host or disk goes away" what-if steps | open |
| **5** | The planner's own status dots and theme toggle | open |
| **Components** | The card, table and pill components, page by page | open |
| **Retire Graph, Structure** | Once the map's Storage layer has time travel and a focus view | open |
| **Native ES modules** | One pass, leaf first, with a test of the load order; `kernel.js` and `chrome.js` first | open |

### 10.1 Step 3i: the answers taken for now

Today the storage blueprint is one per host (the planner, saved versions, laid over each scan), and the map's design is named, owned and covers many hosts (networks, workloads, firewall) with no versions. The owner took these recommended answers on 2026-11-16, and they are checked again with the owner when 3i is reached, before its migration runs.

| Question | Answer for now |
| :--- | :--- |
| Per host, or a named fleet design? | Per host with sections; fleet designs become versions or branches of a group of hosts, so alternatives are not lost |
| A host with a blueprint and several map designs: which wins? | The blueprint and the newest map design become the current document; the other map designs become saved versions of it |
| May a document describe a host not yet scanned? | Yes, as step 3a needs |
| Does the map keep editing, or only show? | Only show, as ghosts, and open the planner at the right section: one editor |
| Do versions cover the whole document? | Yes, with restoring one section as an option |
| Who may edit which section? | One edit permission for the whole document at first; per section only if someone needs it |
| Old formats and API? | `storageforge/v2`; v1 still imported; the old endpoints kept for one release; the old tables kept read-only for one release, so the migration can be rolled back |
| Which exports? | All of them from the one document, each saying which sections it leaves out |
| Connections, Toolbox entries and log rules as sections too? | Yes, decided now so the format does not change again |
| Retiring a host removes what? | Its document, and the host from any group design; saved versions kept until someone deletes them |

## 11. The agent

Optional, per host, by the owner's decision of 2026-11-16. A host without it keeps every feature, per scan. Routers, firewalls, switches and appliances stay agentless.

### 11.1 How it is put together

```text
controller ──SSH, signed deploys──► host: the agent's container made, changed, stopped (no Docker socket in the agent)
controller ──its own tunnel───────► agent: signed plugins, the host's signed manifest
agent      ──its own tunnel───────► controller: logs, health, file changes, heartbeats, scan output, all signed
```

| Part | What | Status |
| :--- | :--- | :--- |
| **Base image** | One image on every machine: a stage of the same `Dockerfile`, on the same pinned Wolfi base, scanned by Trivy and Grype in CI and signed. Read-only root filesystem, no package manager, no shell, no Docker socket, no plugins built in. x86-64 and arm64 | open |
| **Plugins** | Each feature is a plugin, and a host gets only the plugins its settings turn on. A plugin is signed: the project's release key for official ones, built and scanned in CI; the operator's own key for their own, trusted only when the operator says so, as Toolbox entries are. Each declares the mounts, capabilities and devices it needs | open |
| **The host's manifest** | Which plugins, at which hashes, with which privileges, for this host, signed by the controller with a fresh time and a counter, so an old manifest cannot be played back. The agent loads a plugin only when its signature and the manifest both match | open |
| **Delivery** | The controller sends plugins and the manifest straight to the agent over an encrypted tunnel of its own: through the tunnel container, with an agent key that is not the node's SSH tunnel key and reaches only the agent's receiver, or on the LAN a direct connection with both keys pinned, over the StorageForge network (2.1) where the host is on it. Never through the Docker API, and never inside an SSH session | open |
| **Lifecycle over SSH** | Installing, changing privileges when plugins change, updating, restarting and stopping the container are signed requests over SSH to `storageforge-agentctl`, on every host, which accepts agent operations and nothing else. A host with SSH control keeps `storageforge-run` for change plans beside it; a monitoring-only host gets only `storageforge-agentctl` | open |
| **Accounts** | The agent runs as its own account (`sfagent`, its own uid and gid), never root and never in the `docker` group or sudoers. The container's process runs as that uid. The user that deploys and manages the agent over SSH is never in the `docker` group either, since that group is root on the host: setup refuses to go on while it is, and says why. That user reaches the runtime only through `sudo -n /usr/local/sbin/storageforge-agentctl`, the one line sudoers allows it, and the verifier runs `docker` or `podman` itself after checking the request's signature | open |
| **Runtime** | Docker or Podman, whichever the host has. The basic plugins (heartbeat, logs, health, network) run rootless under Podman as `sfagent`, with no root runtime involved; reading the journal takes `sfagent` in `systemd-journal`, carried into the container (`--group-add keep-groups`). The disks and files plugins need host capabilities that a rootless runtime cannot grant, so they take a rootful runtime, and the process inside still runs as `sfagent` with only the declared capabilities Whether a host has one comes from the SSH scan, which reads both today. On a host with neither, installing the agent tells the user Podman will be installed, then installs it through the same signed request | open |
| **What the agent automates** | Its own schedules (scans, readings, SMART), buffering and resending, and the protective reactions in 11.2. All of it reads; none of it changes the host. Automation that changes data stays what it is today: deployed jobs on systemd timers run by `storageforge-job`, set up by a change plan over SSH | open |
| **Privileges follow plugins** | The container is made with the union of what its plugins declare, and nothing more. Removing a plugin takes its privileges away | open |
| **Enrollment** | During setup over the already pinned SSH connection, the agent makes its key pair and the controller reads the public half back over that connection and pins it | open |
| **Windows** | A native service, not a container, with the same plugin format, signatures and manifest. Monitoring only. Managed over OpenSSH for Windows | open |

### 11.2 Trust

The agent runs on a machine and a network that may be hostile, so it gets **no trust for what it says** and **as little as works for what it can do**. Those are two directions, and each has its own limits.

**The rule:** an agent reads its own host, speaks only about its own host, and causes action only against its own host, and only protective action. Anything that reaches further needs a second, independent witness or a person.

**From the agent to the controller: nothing it says is believed or obeyed**

| Limit | How | Status |
| :--- | :--- | :--- |
| **Its identity comes from its key, never from what it sends** | The controller works out the host from the pinned key the batch is signed with. A hostname, address or machine ID inside the payload is a claim and is ignored for routing. (The audit of 2026-11-01 found this kind of bug once: retire matched a host's *self-reported* address, M6) | open |
| **It can only write about itself** | Its batches add rows to its own host's data and nothing else: no other host's records, no plans, holds, alerts on other hosts, settings or accounts | open |
| **Its words never become code or markup** | As for scan output today: text from a host reaches a script only through the field checks, a query only as a parameter, a page only through `textContent` or `esc()` | open |
| **The receiver is a hostile-input boundary** | Its own process and account, separate from the web app, with a database role that can write only the ingest tables. Schema checked, sizes and rates limited per agent, parsing linear in the input (SF-52), malformed batches dropped and counted. One agent cannot starve the others or the web threads | open |
| **Storage cannot be pushed out** | Per-host quotas, pruning by arrival time (section 3, phase 0), so a flood from one agent costs only its own old rows and is recorded | open |
| **Batches are counted** | Each batch carries a counter and is signed. A gap means batches were deleted, a repeat means a replay; both are shown, and repeats are dropped | open |
| **Its actions affect only itself** | What an agent's report can trigger by itself is protective and aimed at the reporter: the shadow-copy tripwire drops *the address pinned for that client at enrollment*, never an address named in the message. An agent can accuse only itself | open |
| **Anything wider needs a second witness** | Freezing a share, or any action that touches other clients or hosts, needs an independent source to agree: the share host's own sentinel, a decoy hit, a scan over SSH. Otherwise it is an alert for a person | open |
| **Where data came from is shown** | Every reading is labelled *reported by agent* or *measured by scan*, and where both exist they are compared; a disagreement is an alert | open |
| **Lying is expected** | A taken-over agent can hide its host's problems or invent them. Inventing them is contained by the rows above. Hiding them is not preventable, and is why decoys on shares, scans over SSH, silence and counter gaps stay independent of it | open |

**From the controller to the agent: only what its plugins need, nothing that reaches elsewhere**

| Limit | How | Status |
| :--- | :--- | :--- |
| **No secrets but its own key** | No vault access, no other host's keys, no job keys, no tokens for outside services. Plugins and the manifest are not secret. Stealing everything an agent holds gives its own key, which is revoked, and its own host's data, which whoever holds the host already has | open |
| **Read-only on its host** | Every mount read-only. A taken-over agent can read its host and nothing more, so it cannot make that host worse than whoever took it already did | open |
| **A hardened container** | All capabilities dropped but the plugins' declared ones, `no-new-privileges`, the default seccomp profile or tighter, user namespace remapping where the plugins allow, no Docker socket | open |
| **Its network reaches the controller only** | Egress limited to the tunnel endpoint by a host firewall rule matched on the agent's cgroup, so it holds even with host networking for the network plugin | open |
| **Code comes only from the release key** | Scans are scripts carried in the scan plugin (decided 2026-11-16), so no executable crosses the wire per scan, and a taken-over controller can choose among signed plugins but not write one. An operator's plugin key is never stored on the controller: offline or on a hardware token | open |
| **Privilege needs a person** | A manifest that adds the disks or files plugin, or any privilege, takes an admin with re-authentication, and the audit log records it | open |
| **Short-lived sessions** | The pinned key only opens a session; session tokens expire and rotate, and revoking the key ends every session at once | open |
| **Mutual pinning, no trust on first use after setup** | The agent pins the controller's key at enrollment, as the controller pins the agent's. A key that changes is refused until a person accepts it | open |

**Isolated from SSH: an extra layer, not a way in to it**

SSH stays the base on every agent host, for control. The agent sits beside it and shares nothing with it, so whoever takes one has gained nothing towards the other.

| Limit | How | Status |
| :--- | :--- | :--- |
| **Its own key, used for nothing else** | Made by the agent at enrollment. Never the scan signing key, the host's SSH host key, the deploy key, a job key or a tunnel key of SSH's. Revoking it touches no SSH access, and revoking SSH access touches no agent key | open |
| **No SSH secrets in reach** | `sfagent` is in none of `storageforge-scan`, `storageforge-deploy` or the job accounts' groups. Every plugin's mounts mask `/etc/ssh`'s private keys, every `.ssh` folder, `/usr/local/lib/storageforge` (the scan signing key), `/run/storageforge/secrets` (secrets sent from the vault), the verifiers' nonce stores and the sudoers files, even for plugins that mount the host's root read-only | open |
| **It cannot reach SSH** | Its network rule allows the controller's endpoint only, so it cannot connect to the host's own `sshd` or any other host's; it runs no `ssh` client and has no `ssh` binary in its image | open |
| **SSH cannot be driven through it** | It carries no shell, no command and no SSH session. The controller's SSH work (scans without the agent, change plans, deploys, `storageforge-agentctl`, the console) never passes through the agent or waits on it | open |
| **Its own tunnel** | Through the tunnel container with a key of its own that reaches only its receiver, separate from the node's SSH tunnel key; or the StorageForge network (2.1) | open |
| **Its own receiver** | The ingest process on the controller has no vault access and cannot start an SSH connection. What an agent reports reaches SSH only through a person, or through the one narrow bridge in the rows above: a protective action against the reporter, carried out by the controller's own SSH, never by the agent | open |
| **Either one fails alone** | `sshd` stopped: the agent still reports, and says SSH is down. The agent stopped or wiped: scans, deploys and the console still work over SSH, and the notification center says the agent is gone | open |

**What stays trusted:** the controller is still the root of trust for the fleet, as it is today with SSH and signed deploys. The agent adds no authority to it, and takes the release key out of its hands for code.

**The file index from both.** SSH scans index files as they do today, and the agent's files plugin can too. With both on, each checks the other: a file the agent says changed that the next scan does not see, or a scan finding changes the agent never reported, is a disagreement in the notification center. A monitoring-only host gets its index from the agent alone.

### 11.3 Wipe and stop

Anything in a container that the manifest does not account for ends its access.

| Check | How |
| :--- | :--- |
| **From outside, over SSH** (the check that counts, since a container that has been taken over can lie about itself) | The running image's digest is the signed base's; `docker diff` shows nothing outside the plugin and buffer folders; the plugin files' hashes match the manifest; the container's mounts, capabilities and devices match it. On every scan and on a timer |
| **From inside** | At start and on a timer, the agent checks its loaded code and plugin files against the manifest, and refuses an unsigned plugin, one not in the manifest, or a stale manifest |
| **What happens** | The controller revokes the agent's key on its own side first, which an attacker cannot undo; the agent deletes its key and exits; the container is stopped over SSH and left stopped, whatever its restart policy; an alert opens. Only an admin re-enrolls it, with re-authentication, and the audit log records it |

### 11.4 Plugins

| Plugin | Gets | Privileges it declares | Status |
| :--- | :--- | :--- | :--- |
| **Heartbeat** | Silence noticed within seconds; buffering while the link is down | none | open |
| **Logs** | Journal lines as they are written (section 3, phase 2); OpenRC hosts' log files | the journal folders and `/etc/machine-id`, read-only | open |
| **Health** | CPU, memory, I/O latency, capacity, scrub and resilver progress | `/proc`, `/sys`, read-only, host PID | open |
| **Network** | Traffic and activity on Linux hosts (section 8); connections to shares, all the time, not sampled once a minute | host network | open |
| **Disks** | SMART on a schedule (PF-04), disk errors as they happen | the disk devices read-only, `CAP_SYS_RAWIO` | open |
| **Files** | A file index that updates itself (fanotify), deeper than a scan's (live changes, which process made them, per-folder watches), ransomware signs on every path, which process wrote what, hand edits to managed files at once, off-hours reads by user (section 9) | `CAP_SYS_ADMIN` and the host's mounts read-only: effectively root on the host, and the UI says so | open |
| **Scan** | The read-only scans, as scripts carried in the plugin and signed with it, for hosts that are monitoring only | the host's root read-only, to run the host's own tools such as `zfs`, with SSH's and StorageForge's secret paths masked (11.2) | open |
| **Sentinel reports** | The sentinel's events through the agent. The sentinel itself stays on the host, because its local actions need the host's root | none | open |
| **Toolbox status** | Status tiles that stay current (section 4) | per tool | open |
| **Shadow-copy tripwire (Windows)** | On a Windows client: process starts (Windows' process auditing with command lines, or Sysmon) for `vssadmin delete shadows`, `wmic shadowcopy delete`, PowerShell removing `Win32_ShadowCopy`, `wbadmin delete catalog` and `bcdedit … recoveryenabled no`, and shadow copies that vanish. The controller then drops that client from every share, snapshots, and freezes if armed, usually before encryption starts. Deleting shadow copies needs administrator rights, which can stop the agent first: its silence is the signal then, and the share's decoys stay the backstop. It detects and reports; it does not block the process, and StorageForge does not claim to be an EDR | Windows process events | open |

### 11.5 Hosts by mode

| Mode | SSH after setup | Agent |
| :--- | :--- | :--- |
| **SSH only** (today) | Scans, changes, console | none |
| **SSH and agent** | Control: change plans, deploys, console, the agent's lifecycle | Automation and monitoring: everything read, live, under `sfagent` |
| **Monitoring only** | The agent's lifecycle, through `storageforge-agentctl`, and nothing else | Everything read, live. No change plans, deploys, Moves, sends, console, clone, holds or quarantine: the UI shows them disabled with the reason, and adding SSH access later is an upgrade |

Host-to-host data (sends, Moves, sync) keeps its forced-command job keys, which are not the controller's SSH access.

### 11.6 Lab

| Check | Status |
| :--- | :--- |
| Each plugin on the distros of the lab, and on Alpine with OpenRC | open |
| A file written into a running agent's container: access wiped, container stopped and left stopped, alert opened | open |
| An unsigned plugin, a plugin not in the manifest, a plugin whose hash changed, and an old manifest played back: each refused | open |
| A stolen agent key used after revocation: refused | open |
| No Docker socket or API reachable from inside the container | open |
| A monitoring-only host: `storageforge-agentctl` refuses anything that is not an agent operation | open |
| The tunnel: an agent key reaches its own receiver and nothing else | open |
| A batch that names another host, or another host's address or machine ID: stored under the sender's own host, or refused | open |
| A tripwire report naming another client's address: only the reporter's pinned address is dropped | open |
| A share freeze asked for by one agent with no second witness: an alert, not a freeze | open |
| A flood from one agent: its own quota and old rows only; other agents and the web UI unaffected | open |
| The receiver's database role writing anything but the ingest tables: refused | open |
| The agent's container reaching anything but the tunnel endpoint, with host networking on: refused | open |
| Batches deleted or replayed in transit: the gap and the repeat shown, the repeat dropped | open |
| Agent and scan disagreeing about the same reading: an alert | open |
| The file index from both: a change made while the agent's plugin is held back, found by the scan and shown as a disagreement; and the other way round | open |
| Installing the agent on a host with no runtime: the user told, Podman installed, the agent running rootless | open |
| The agent reading the scan signing key, an SSH host key, a `.ssh` folder, `/run/storageforge/secrets` or the sudoers files, from every plugin including scan and files: refused | open |
| The agent connecting to the host's own `sshd`, or another host's: refused | open |
| The agent's key revoked: SSH scans and deploys unaffected. SSH access revoked: the agent unaffected | open |
| `sshd` stopped: the agent keeps reporting and says SSH is down. The agent wiped: scans, deploys and the console keep working | open |
| The agent's tunnel key: reaches the receiver only, never a node's forwarded `sshd` | open |
| Setup with the managing user in the `docker` group: refused, with the reason | open |
| The managing user running `docker` or `podman` directly, or anything through `sudo` but `storageforge-agentctl`: refused | open |
| The agent's process: runs as `sfagent`, not root, with no sudo and no `docker` group; the basic plugins rootless under Podman | open |
| Windows evaluation VM: the shadow-copy tripwire fires on each command above, and the share host drops the client | open, needs the owner's VM |

## 12. The notification center

Decided 2026-11-16: one place for everything that wants a person's attention, most critical at the top. It grows out of what exists: `alerts.py` opens, refreshes and resolves alerts, keeps their history, and pushes to ntfy, Gotify, a webhook or PagerDuty with routes by host and level.

| Item | What | Status |
| :--- | :--- | :--- |
| **Every source feeds it** | What `alerts.problems()` gathers today (jobs, schedules, tasks, drift, scans, backups, certificates, security, devices, the map), log rules (section 3), anomalies and silence, the agent's integrity and wipes (section 11), connections that went down (section 2), Toolbox feeds (section 4) | open |
| **Ranked** | Critical, then warning, then information; within a level, the newest first. Grouped by host and kind, with a count, so a flood is one row | open |
| **On every page** | A count of open critical notifications in the shared chrome, which opens the center; the center as a page of its own with filters by host, kind, level and state | open |
| **Ignorable or not** | Critical notifications, configuration drift and security findings cannot be muted, snoozed, dismissed or acknowledged away: they leave the list only when resolved, by an update or another step, and an acknowledgement (a name and a note) only says someone is on it. Everything else can be snoozed for a time or muted per host or rule. Muting and acknowledging go in the audit log | open |
| **Fixes** | A kind may carry a prepared fix that becomes a plan step: run a stale job now, restart a failed unit, re-converge drift, renew a certificate, apply an update, restart a stopped agent through `storageforge-agentctl`, re-run a scan. Every fix goes the same way: shown prepared, with its plan and report; deployed behind the password; with a rollback offered after. A fix is only offered when it has a way back: an undo step, or a snapshot taken before it. A fix never deletes data by itself (a full disk shows what is largest, it does not clear it) | open |
| **Channels** | Each route pushes from a level up (critical only to PagerDuty, say), and resolving is pushed when it is on, as today | open |
| **History** | Resolved, acknowledged and fixed notifications kept and searchable, with who did what | open |
| **Lab** | A failed unit fixed on a lab host: prepared, deployed, rolled back; a fix with no way back not offered; a critical notification, a drift and a security finding that cannot be muted or acknowledged away and leave only when resolved; a flood of one kind shown as one row | open |

## Will not be built

A shadow-copy trap on the Samba server (the deletion runs on the Windows client and never crosses SMB; the client-side tripwire is in section 11), cryptographic shred, compliance certificates, a *SECURE* banner and a WebSocket event stream, because they can't work or would claim too much: see [ransomware defense](docs/ransomware-defense.md). It isn't a replacement for NetBox, LibreNMS or Zabbix. The UI adds no framework, build step, CDN or third-party script, no telemetry about how it is used, no mobile-first redesign and no dashboard builder.

This list used to say StorageForge stays agentless and builds no live log viewer, and that the VSS trap cannot work. The first was changed by the decision to build an optional agent, and the second holds only for the server: see *Decisions taken*.
