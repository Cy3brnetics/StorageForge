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
| Sign the agent's four plugins with the release key (`storageforge-indexer/agent/plugins.sh sign`) | Any host being offered the agent's plugins |
| Sign the Toolbox catalog with the release key (its public half in `catalog/release_signers`, then sign `catalog/catalog.json`) | The packaged catalog being trusted, and any catalog update |
| Give CI the release key (`STORAGEFORGE_RELEASE_KEY`) and an `enclave/image/allowed_signers` file | The enclave image signed in CI |
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
| **The agent also runs as an LXC container,** beside Docker and Podman, from the same signed Wolfi image: unprivileged, through plain LXC, Incus or Proxmox's `pct`. A host that already has LXC and no Docker or Podman, Proxmox VE above all, gets the agent in LXC rather than having Podman installed | 2026-11-16, the owner |
| **Keys get a micro VM of their own** (section 14): the vault's keys live in a minimal VM with no network device at all, on the controller's host, reached only over vsock. Private keys never leave it; it signs, unwraps and decrypts on request and keeps its own limits | 2026-11-16, the owner |
| **The file index comes from SSH, the agent, or both.** With both on, each checks the other, and the agent offers deeper options and live monitoring. Monitoring-only hosts get it through the agent | 2026-11-16, the owner |
| **Every fix is shown prepared, then deployed, with a rollback.** No fix applies unseen: the prepared plan and its report come first, deploying takes the password, and a fix is offered only with a way back | 2026-11-16, the owner |
| **Critical notifications, configuration drift and security findings cannot be ignored:** they leave only when resolved, by an update or another step. Everything else can be snoozed or muted | 2026-11-16, the owner |
| **The StorageForge network carries only StorageForge-managed connections** (scans, the agent, deploys, `storageforge-agentctl`, the console). File transfers get encrypted tunnels of their own; the hosts' shares are not carried | 2026-11-16, the owner |
| **All of the change engine, Workloads and the Toolbox belong in StorageForge.** The [merged plan's other decisions](archive/roadmaps/infrastructure-platform-roadmap.md#12-decisions-to-confirm) stand, except that routers and switches are now read directly | 2026-11-16, the owner |
| **StorageForge may read and act through platform APIs** (all three Proxmox products: VE, Backup Server and Datacenter Manager; TrueNAS, Dockhand and the like, section 13), as an option beside SSH. Before a token is asked for, the user is shown the permissions it needs, and the recommendation is always the least that works: never root, an admin key or a full-access role | 2026-11-16, the owner |
| **Control is done over SSH; automation and monitoring by the agent,** which runs under its own uid:gid. Change plans stay on SSH. The user that deploys and manages the agent is never in the `docker` group and uses `sudo` where it must, limited to the agent's verifier | 2026-11-16, the owner |
| **No single point of failure: layers, fast rotation, and sensitive routes that move.** After the 0.5.4 image scan (Grype: ten findings in OpenSSL and Python with no fix published yet), the owner's direction: a flaw in one layer must not give up a release or the data, so a second layer of encryption on the service and a third where it helps, keys rotated faster than a stolen one is of use, and sensitive API paths that change like a 2FA code. Built in section 14 (*Layers*) | 2026-11-18, the owner |
| **The agent is written in Rust.** One static program, as the key enclave's is: no interpreter and no OpenSSL or Python in the agent's image for a scanner to find, memory safety in the part that runs on machines that may be hostile, and one file to sign and to hash. The controller and the web app stay Python (section 11.1, *Language*) | 2026-11-18, the owner |

## Decisions still open

| Decision | Blocks |
| :--- | :--- |
| **The compose bridge and the StorageForge network's interface are both called `sf0`** on the Docker host: rename the bridge default, or the interface | The controller's Docker host joining the StorageForge network |
| **One design document** in place of the storage blueprint and the map's design: the owner took the recommended answers in section 10.1 on 2026-11-16, to be checked again when 3i is reached | Section 10's step 3i, confirmed at 0.5.16 |

## Versions and checkpoints

0.6.0 is reached through versions from 0.5.3 up, each one a theme, in an order where each builds on the ones before. Every version ends releasable.

**Minor checkpoint: a commit.** One item of a version is done: its code, its unit tests passing on SQLite and PostgreSQL, its docs and its changelog line under *Unreleased*. It is committed on the working branch in the repo's style (`feat(area): …`, `fix(area): …`, a plain sentence saying what changed for the user) and the ledger's **Status** cell names the commit. Nothing is pushed.

**Major checkpoint: stop and tell the owner.** Work stops and the owner is told what was done, what was tested, what failed and what is needed, at:

1. the end of every version: the changelog heading, the version bump, a local tag; pushing is the owner's call
2. every KVM lab run, with its results
3. a decision from *Decisions still open*, or an item from *What only the owner can do*, that the next item needs
4. a finished security boundary: the agent's receiver, `storageforge-agentctl`, the trust model, the plugin signatures, a new join step's secret handling, the API connection kind, the key enclave
5. a test that fails and is not understood, or a finding of High or Critical
6. before anything that cannot be undone: a migration that changes a stored format, a removal of a feature

| Version | Theme | Minor checkpoints, a commit each | Major checkpoints |
| :--- | :--- | :--- | :--- |
| **0.5.3** | What is on `main` and not released, and the lab's own gaps | The unreleased clock fixes and the Wolfi image · 1.2: appliances in the build, Playwright where tiers run, `qemu-img` on `sf-ubuntu`, one default build with every host the skipped checks need, SF-72's properties read back, `progress.md` brought up to date, `shellcheck` kept installed · 1.1: OPNsense in `images.conf`, `nodes.conf` and a tier | The lab run of every tier, with nothing skipped that a host could run · ask for the pfSense image, the Cisco account and the Windows VM · release |
| **0.5.4** | Logs: the holes, rules, and the notification center | Section 12: the notification center, ranking, what cannot be ignored, prepared fixes with rollback · Section 3, phase 0: prune by arrival, the per-host rate, journald's own fields, `__SEQNUM`, the 5-minute counts (from here on they build the baselines 0.5.8 needs) · phase 1: the rule engine, the built-in rules, matching without regex over host text, one alert per rule and host · 1.4: disk failures made in the lab to prove the rules | The log tier's lab run · release |
| **0.5.5** | Key enclave | 14: the micro VM image (a minimal kernel and one static program, no network device, no shell), built reproducibly in CI and signed · the vsock protocol with its narrow set of operations · the vault's KEK and every private key moved inside, with the migration and its way back · SSH keys used through an `ssh-agent` the enclave serves, so they never leave it · the audit log's MAC key inside · secrets for plan steps released one request at a time, with policy and rate limits · step-up checked inside for the operations that need it · unlock, lock and restart · the fallback to today's vault where there is no KVM, labelled · the lab checks | The enclave, a security boundary · the stored-format migration of the vault, before it runs · the lab run · release |
| **0.5.6** | Connections | 2.1: StorageForge's own WireGuard network, the default · the console names the network it found (fixes NetBird shown as Tailscale) · read and draw: Tailscale (`--json`), Headscale, NetBird, ZeroTier, Nebula, Netmaker, OpenVPN, strongSwan · join steps, each with its key from the vault: NetBird, ZeroTier, Nebula, Netmaker, OpenZiti · exposure through tunnels: Pangolin (detect Newt and join; its API read comes at 0.5.10), Cloudflare Tunnel, frp, ngrok · Teleport, Boundary and Pomerium read · SSH CA · 1.3: Headscale, NetBird, ZeroTier and Pangolin servers on lab hosts · the owner's side quest of 2026-11-18, 7 phases 8 and 9: a second operating system installed over SSH with a one-time boot into it, Dux with a chosen compositor, and the desktop profile kept on the server | The StorageForge network's keys and peers, a security boundary · each join step's secret handling · the connections lab run · the second-OS install proven in throwaway UEFI VMs, with the fallback to the old system shown · release |
| **0.5.7** | The agent: base, trust and the first plugins | 11.1: the agent as a static Rust binary in a Cargo workspace with the enclave, the `agent` stage of the `Dockerfile`, `sfagent`, `storageforge-agentctl` with its one sudoers line and the `docker`, `lxd` and `incus-admin` group refusal, Docker and Podman, rootless for the basic plugins, LXC as the third runtime (plain LXC, Incus and Proxmox's `pct`, unprivileged, from the same image), enrollment over pinned SSH · plugin format, release-key signatures, the signed manifest with its counter · 11.2: the receiver as its own process and database role, identity from the key, counters, quotas, provenance labels · 11.3: wipe and stop, from outside and inside · plugins: heartbeat, logs (section 3, phase 2: push), health, network · 11.6: the tamper and trust checks | Each boundary in 11.1 to 11.3 as it is finished · the agent's lab run · release |
| **0.5.8** | The agent's other plugins, and monitoring | Plugins: disks (PF-04's path), files (an index that updates itself, process attribution, hand edits, off-hours reads), scan (scripts carried in the plugin), sentinel reports, Toolbox status · monitoring-only hosts with `storageforge-agentctl` alone · Section 3, phase 3: anomalies on the counts since 0.5.4 · phase 4: the monitoring view · phase 5: netconsole and `pstore` | The console turned on for a session · the files plugin's privileges, which are root in effect · the lab run · release |
| **0.5.9** | Change engine | 5: the secret store with generated secrets and rotation · `runtime-install` with its preflight · pools: ZFS vdevs, disk replace and attach, md add, replace and grow, LUKS · networks: bonds, addresses, routes, DHCP, reading netplan, NetworkManager and networkd files | The secret store's boundary · 5's exit test in the lab · release |
| **0.5.10** | API access | 13: the API connection kind (HTTPS client, the certificate pinned on first use, the token from the secret store, timeouts and rate limits, read-only by default) · the permission guide shown before a token is asked for, with the least each platform needs · the read-back of what a token can really do, and an over-privileged token as a security finding · one commit per platform: all three Proxmox products (VE, Backup Server, Datacenter Manager), TrueNAS, Xen Orchestra, Dockhand, Portainer, Komodo, Pangolin's API read · 1.3: `sf-pbs` and `sf-pdm` added to the lab as appliances, and tokens made and checked on `sf-pve`, `sf-pbs`, `sf-pdm`, `sf-truenas`, `sf-xcp` and the panels on a lab host | The API connection kind, a security boundary: the controller holding tokens for outside systems · the API lab run · release |
| **0.5.11** | Workloads | 6: `stack` and `lxc` steps, Incus instances, image updates with rollback, VMs from ISOs, placement advice, MAC at deploy, Quadlets and adopting a workload, quiesced stacks, externally managed workloads (read through 0.5.10's APIs where a platform is connected), workload exports with round trips · 1.3: proxies and identity providers on lab hosts | The workloads lab run · release |
| **0.5.12** | Toolbox: the engine | 4.1: the catalog engine, signatures and overrides, install methods, risk labels, uninstall that keeps data · adapters and the GUI levels · the Toolbox view and deep links · the API and tables · custom entries | The catalog's signature boundary · the engine's lab run · release |
| **0.5.13** | Toolbox: the entries | 4.2, one commit per group: panels, VPN and overlay servers, zero trust and access, identity, reverse proxy and DNS, detection and scanning, monitoring, backup with restore tests, secrets, provisioning, storage-facing apps, offline mirrors · 4.1: bundles, role profiles, custom dashboards, feeds · 4.3: the built-in bundles | The gauntlet for each group as it lands · release |
| **0.5.14** | Windows, network and map, migration | 11: the Windows agent and the shadow-copy tripwire · 2.1: hub forwarding, dual-stack IPv6 endpoints and signed head/route directory for roaming peers · 8: `place-before`, scan placeholders, scanner findings through alerts, deeper reads, actions from the map, `bridge`-family rules, map extras, NetBox, Grafana, SNMP and LLDP · 7: phases 3b, 3d, 4b, 5 and 7 · 1.1: pfSense and Cisco once the owner's items are in, the old-cipher device | The Windows VM run · the network devices' lab run · release |
| **0.5.15** | Security depth | 9: incidents with workloads, compliance readings, credential and identity anomalies, the Falco simulator, the builders, FIDO2 at sign-in, SMS, mirror discovery, the smaller items · SF-38 · EQ-03 if it no longer sits before a lab run · 1.3: playbooks acting for real, a bridged VM under quarantine, OpenTofu and Puppet applies, migration 1b and 4b | The physical FIDO2 token and PagerDuty, if the owner has them · the lab run · release |
| **0.5.16** | UI and UX | 10: phase 2's workspaces and one Plan workspace, phase 3's steps 3a to 3h one commit each, phase 4, phase 5's gaps, the components, retiring Graph and Structure, native modules · 3i only if decided | The 3i answers in 10.1 confirmed again, and its migration, before it runs · the browser and lab runs · release |
| **0.6.0** | The release | The audit of everything since 0.5.2, to the audit rules, and its bugfix round, a commit per finding · the full unit suites on both databases · the full lab | The audit's findings · the lab results · the release, with every *not lab-tested* label listed in the notes |

## 1. Tests and the lab

Everything that can be tested without the owner's items above.

### 1.1 Network devices

| Item | How | Status |
| :--- | :--- | :--- |
| **OPNsense** | The free `nano` image boots already installed on a serial console. Into `images.conf` and `nodes.conf` like the CHR and OpenWrt images, and a tier like RouterOS's: read, the network language, rollback | done: `5f8ddc2`, the 26.7 `nano` image as `sf-opnsense`. Tier 12 on 2026-11-17: read, a change kept, cut off and back by itself, all passed. What it found: `21d8738` (its rules were read from the wrong place) and `f352213` (no change could be applied) |
| **pfSense CE** | Runs in KVM. The image is the owner's download (above), then the same tier as OPNsense | open |
| **Cisco** | CML-Free (free, a Cisco account): IOL, IOL-L2 and ASAv, up to five nodes at once. Its licence forbids the images outside CML, so CML runs as a lab VM and StorageForge connects to the devices inside it. IOS-XE (Cat8000v) and IOSv are not in the free tier. First check whether `cisco.py` is written for classic IOS, which IOL runs, or IOS-XE | open |
| **Old SSH ciphers** | A RouterOS 6.x CHR image, an OpenWrt release with an old dropbear, or an old distro cloud image | open |
| **Drop the "no free image" label** from `progress.md` and `tiers_network.py` for whatever of the above passes | | done for OPNsense on 2026-11-17. pfSense and Cisco keep it until their images are here |

### 1.2 Checks the lab skips today

| Item | Why it is skipped | Fix | Status |
| :--- | :--- | :--- | :--- |
| **Appliances:** Proxmox, TrueNAS, XCP-ng (`sf-pve`, `sf-truenas`, `sf-xcp`) | Defined in `nodes.conf` and `images.conf`, never in the default build ("use `up --pick`") | Run them. This also lab-tests **Proxmox guests**, still marked not lab-tested | done on 2026-11-17: tiers 0, 2 (101 passed) and 8 (17 passed) on a second libvirt host, since the default build wants 24 GB. A real Proxmox guest on the map: `workload-proxmox`, run by hand against `sf-pve` joined to the main build. Not done: the appliances through tiers 1 and 3 to 7 with a controller |
| **`ui-pages`** | Playwright is not installed where the tier runs | Install it there | done: `56d1396`, 22 pages and tabs in Chromium on 2026-11-17 |
| **`workload-libvirt`** | No `qemu-img` on the `sf-ubuntu` image | Add it to that node's provisioning | done: `56d1396`, passed on 2026-11-17 |
| **SF-72** | The ZFS receive's mountpoint was read back; the export and setuid properties were not. The btrfs side is undecided | Read both back in tier 16, and decide the btrfs side | done for ZFS: `553bcc6`, `send-zfs-properties` passed on 2026-11-17. btrfs measured (`send-btrfs-setuid`): the copy keeps a root setuid file, the mount was not `nosuid`, and another account could reach it. Decided by the owner on 2026-11-17: a folder the receive makes is mode 0700, and one that was there keeps its mode. Built in 0.5.4 |
| **Builds without the right host** | `smb`, `snapjobs-snapper`, `btrfs-disk-pulled`, `compile-iptables`, `lxc-guests` and `incus-guests` skip when the build lacks a host that can run them | One default build that has an SMB client, a snapper host, a btrfs raid host, `iptables-restore`, a Debian-family host without Docker and a second one | done: `56d1396`. On 2026-11-17 `smb`, `snapjobs-snapper`, `btrfs-disk-pulled`, `compile-iptables`, `lxc-guests`, `incus-guests` and the ZFS sends between hosts all ran and passed |
| **`progress.md` is behind** | It says tier 14, LXC and Incus are not lab-tested; the 0.5.0 changelog says they ran on 2026-11-08 | Bring it up to date | done: `260a8cc` |
| **The full unit suites** | Not re-run on SQLite and PostgreSQL after the last fixes of the 0.4.0 run | Re-run both, and keep `shellcheck` installed for the generated scripts | partly: re-run on 2026-11-16 after `dce9e98`. PostgreSQL 1,925 pass (88 skip, SQLite-only). SQLite 1,924 pass, and `test_browser_logs.BrowserLogs` timed out waiting for its first log line under heavy parallel load (3 of 10 loaded runs; 12 of 12 quiet and 10 of 10 under CPU load alone, on this branch and on `7d3c96c`): not understood yet. `shellcheck` comes with the `test` extra since `9887236`, and its three tests run here |
| **Blocks and random tests** | Every test ran in one 16-minute process, and only on inputs someone wrote down | `tests/run.py` with light, medium and heavy blocks and `-j`; random tests (`test_props_*.py`); CI runs each block on both databases ([tests/README.md](storageforge-indexer/tests/README.md)) | done: `4fd6cff`; the bugs they found: `8b39384`, `a415dfd`, `fc1735d`, `98822af`, `ab6a4b2`; key install with a password tested: `dce9e98`. Unit only: no lab run |

### 1.3 Not lab-tested, and only free software is needed

| Item | How | Status |
| :--- | :--- | :--- |
| **Reverse proxies** | Caddy, nginx, Traefik and HAProxy installed on lab hosts, their routes read and drawn | written as tier 28 on 2026-11-20, not run |
| **Identity providers** | Keycloak, Authentik, Authelia and LLDAP in containers | written as tier 28 on 2026-11-20, not run |
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
3. **Console:** SSH over that network, named for it. Until 2026-11-18 any address in 100.64.0.0/10 was called Tailscale, so a NetBird host was offered as "SSH over Tailscale"; a route is now named by `overlays.network_of`. Moves already take any interface.
4. **Exposure:** a tunnel that publishes a service makes it public, even with no port open on the host or router, and the security view says so.
5. **Lab:** a self-hosted control server where one exists. A tool that needs an outside service ships labelled.

| Tool | What it is | What exists | What's needed | Status |
| :--- | :--- | :--- | :--- | :--- |
| **Tailscale** | Mesh VPN, outside control server | `tailscale` step, peers read from `tailscale status`, console route | Read `tailscale status --json` instead of the text; the console route named; lab through Headscale | built, not lab-tested. Since 2026-11-18 read from `tailscale status --json` (`overlays.tailscale`), with the text kept for a tailscale too old for it; relayed and direct peers told apart; the console route named. Open: the lab through Headscale |
| **Headscale** | Self-hosted Tailscale control server | Detected as a tool and a service | Read nodes, routes and pre-auth keys from its CLI or API; pre-auth keys made into the vault for the `tailscale` step | begun 2026-11-18: `headscale nodes list -o json` read on the server (`overlays.headscale`), every node drawn, a scanned host confirmed by address. Open: routes and pre-auth keys, keys made into the vault, the lab |
| **NetBird** | Mesh VPN, self-hosted control server | Detected as a tool, `wt0` counted as a VPN interface, its service known | Read peers from its status; a `netbird` step with the setup key from the vault (first check that `netbird up` can read the key from a file); console route; lab with a self-hosted management server | begun 2026-11-18: peers read from `netbird status --json` and drawn; the console offers "SSH over NetBird" (it was called Tailscale). Open: the `netbird` step, the lab |
| **Netmaker** | Mesh VPN, self-hosted | Nothing | Read nodes and gateways; join with an enrollment key | open |
| **ZeroTier** | Mesh VPN, outside or self-hosted controller | Known as a service | Read `zerotier-cli -j` networks and peers; join and leave; lab with a self-hosted controller | begun 2026-11-18: `zerotier-cli -j` info, networks and peers read (`overlays.zerotier`); its interface named in the console. Its peers have no address to match a host by, so none is drawn yet. Open: join and leave, the lab |
| **Nebula** | Mesh VPN with its own certificate authority | Its interface counted as a VPN | Read its config and peers; host certificates issued from a CA kept in the vault; a lighthouse as a role | open |
| **WireGuard** | Plain tunnels | `wg-peer` step, peers read and confirmed by key | Peer manager: add, revoke, QR code, handshake age (Toolbox entry, section 4) | built |
| **OpenVPN** | VPN with a PKI | Known as a service | Read status and clients; certificates and the CRL; client profiles | begun 2026-11-18: a server's status file read, each client with its address and the network behind it, drawn as peers. Open: certificates and the CRL, client profiles |
| **strongSwan (IPsec)** | Site-to-site tunnels | Nothing | Read `swanctl` tunnels; site-to-site templates | open |
| **Pangolin** | Self-hosted tunnel and reverse proxy with login (Newt runs at the site) | Nothing | Detect Newt; read what the Pangolin server publishes through its API, on the API connection kind of section 13; exposure "public through Pangolin at `<domain>`"; join with a site secret; lab with the server on a lab host | begun 2026-11-18: a running Newt is detected and drawn as a tunnel whose routes are kept at its server. Open: everything else |
| **Cloudflare Tunnel** | Tunnel to Cloudflare | `cloudflared` known as a service | Read its config and routes; exposure; the tunnel token in the vault. Needs a Cloudflare account, so labelled | begun 2026-11-18: `config.yml` read without its credential lines (`tunnels.cloudflared`), each hostname drawn as public on the map; a tunnel run from a token alone says its routes are at Cloudflare. Open: the security view's finding, the token in the vault |
| **frp, ngrok** | Tunnels | Known as services | Read their configs; exposure. ngrok needs an account, so labelled | begun 2026-11-18: `frpc.toml` and `frpc.ini`, and `ngrok.yml`, read without their credential lines and drawn as public. Open: the security view's finding |
| **OpenZiti** | Zero-trust overlay, self-hosted | Nothing | Read services and identities; join an identity from an enrollment token | open |
| **Teleport, HashiCorp Boundary** | Access proxies | Nothing | Read targets; targets made from the host inventory; Teleport's session recordings on a protected dataset | open |
| **Pomerium** | Identity-aware proxy | Its service known | Read routes and policies | open |
| **SSH CA** | Short-lived SSH certificates | Nothing | CA key in the vault, `TrustedUserCAKeys`, principals; issue and revoke | begun 2026-11-18: `sshca.py` builds user and host certificates (principals required, an end required, no extensions unless asked) and is handed a signer, so the CA key signs inside the key enclave; a real `sshd` accepts them and refuses a wrong principal, an expired one and another CA. Open: the CA as a vault key, `TrustedUserCAKeys` as a plan step, issuing from the console and for scans, revocation |

### 2.1 StorageForge's own encrypted network (the default)

Decided 2026-11-16: data is encrypted even on the LAN, and the default needs no outside service. StorageForge builds a WireGuard network of its own between the controller and the hosts it is turned on for, from the `wg-peer` step that exists: a key pair per host made on the host (the private key never leaves it), public keys and addresses held by the controller, peers written by change plans, every peer confirmed by key on the next scan, a key rotated through a plan, a host removed by revoking its peer everywhere. Its own address range, chosen so it never meets Tailscale's or NetBird's 100.64.0.0/10. The console, Moves and the map name it as the StorageForge network. Tailscale and NetBird stay as choices for sites that already run them.

| Item | Status |
| :--- | :--- |
| The network as a setting per host, its address plan, and the peers as plan steps | begun 2026-11-18: `sfnet.py` picks the range (never 100.64.0.0/10, nothing the site uses), gives each host one address for good, and works out each host's peers and the `wg-peer` steps from what a scan saw. Since 2026-11-18 it is stored (one setting, no secret in it) and offered through `/api/sfnet`: make the network, add and revoke members, and save the plan (`sfnetwork.py`). Open: the page |
| Key pairs made on the hosts, rotation and revocation through plans | begun 2026-11-18: the arithmetic of a rotation in two halves and of a revocation, and what a scan confirms by key (`sfnet.confirm`). Since 2026-11-18 `wg-peer` takes an endpoint, a keepalive and no addresses (a key known and carrying nothing, the first half of a rotation), and its script runs every step `sfnet.steps` asks for. Since 2026-11-18 the `wg-interface` step makes `sf0` and the key pair on the host (the private key never leaves it, and an interface StorageForge did not make is left alone), a reading takes the public key once, and a different key afterwards is a critical notification. Open: rotation as a plan (the arithmetic is there), and a lab run |
| The controller as a peer (in Docker, a WireGuard interface for the container or the host's) | open |
| Scans, deploys, `storageforge-agentctl`, the console and the agent's tunnel over the StorageForge network where the host is on it. Sends, Moves and sync keep a tunnel of their own per transfer (the forced-command job keys and rsync over SSH, encrypted end to end); NFS and SMB shares are not carried | open |
| Lab: a host on the LAN reached only through it, a capture showing no clear text between two hosts, a key rotated and a peer revoked | open |
| **Roaming, hub forwarding, dual-stack & signed head directory** (added 2026-11-22): hub forwarding step (`ip_forward` + forward rules so two NAT'd spokes meet at a hub), `[IPv6]` literal endpoints and dual-stack overlay support in `sfnet.py`/`sfnetwork.py`/`sfcontroller.py`, and a monotonic signed head/route directory (`seq`, expiry, hub/head pubkey + endpoints signed with `sshsig` by the controller's pinned key) pushed via SSH scans and pullable outbound by roaming peers from any reachable peer mirror | built 2026-11-23, not lab-tested (`sfnet.py`, `sfnetwork.py`, `steps_infra.py`): `wg-forward` hub step, `[IPv6]:port` endpoints and optional inner ULA `/64` overlay ranges (`sfnet.pick_v6_range`, `range6`) across `sfnet`/`sfnetwork`/`sfcontroller`, and `GET`/`POST /api/sfnet/directory` with `sshsig` monotonic `seq` + expiry verification and outbound roaming peer pull script (`sfnet.mirror_pull_script`). Open: lab run |

**State of 2.1 on 2026-11-20 (built, not lab-tested; `fed5650` to `85848e2`):** rotation through plans, the controller as a member (a link container, or a controller that runs on a member), StorageForge's own SSH connections over the network, and the page under Infrastructure. Lab tier 20 is written and has not run. **Open:** `storageforge-agentctl` and the agent's tunnel (0.5.7); a hub has no step that turns on forwarding, so two spokes cannot reach each other; the `sfnet` image target has not been built; the compose bridge is also called `sf0` on the Docker host, so that host cannot join until `STORAGEFORGE_BRIDGE` is changed (the owner's decision: rename the bridge default or the interface).

**SSH CA, and exposure through tunnels, on 2026-11-20 (built, not lab-tested; `125d6b4` to `d2e742c`):** the CA as a vault key, `ssh-ca-trust` and `ssh-ca-krl`, certificates for the console and scans per host, revocation, Keys → SSH certificates; tunnel findings in Exposure and Security, and the `cloudflare-tunnel` and `pangolin-site` steps. Lab tier 21 is written and has not run; its tunnel checks use stand-ins. The API can issue a certificate for a named SSH user and known host. **Open:** taking the key out of `authorized_keys` once certificates work, join steps for frp and ngrok (not asked for), Pangolin's API read (0.5.10).

**Join steps on 2026-11-20 (built, not lab-tested; `c10fc9c` to `0cbc4b2`):** `netbird`, `zerotier`, `nebula` (with its CA in the vault and a lighthouse role) and `openziti`; Headscale pre-auth keys into the vault and its routes read. Lab tier 22 is written and has not run; its server set-ups come from documentation alone. **No Netmaker step,** by rule 3. **Open:** a page or API for the Nebula CA and Headscale keys (CLI only), the CA signing inside a real enclave (not exercised), an OpenZiti controller in the lab. ZeroTier 1.16 and later builds its controller only under a non-commercial licence (`ZT_NONFREE=1`): whether the lab may use that build is the owner's decision, and tier 22 skips those checks without it.

**Readers on 2026-11-20 (built, not lab-tested; `7198d46` to `9b7bd3a`):** Nebula, Netmaker, strongSwan, OpenVPN's certificates and CRL, ZeroTier peers by node id or address, OpenZiti, Teleport, Boundary and Pomerium, drawn on the map, and the console names a network by what its tool said. Read checks are added to tier 22 and have not run; there is none for Netmaker, OpenZiti, Teleport or Boundary, whose servers the lab does not run. **Completed 2026-11-23:** OpenVPN `.ovpn` client profile templates (`overlays.openvpn_client_profile`), strongSwan `swanctl.conf` site-to-site templates (`overlays.strongswan_site_template`), Teleport/Boundary target generation from the scanned host inventory (`accessproxies.inventory_targets`), Teleport session recording ZFS/btrfs retention hold checks (`accessproxies.teleport_recording_check`), OpenVPN certificate and CRL expiry alerts, and public Pomerium route accounting in Exposure.

Deploying the servers (Headscale, NetBird's management, Pangolin, a ZeroTier controller, OpenZiti's controller) is a Toolbox entry each (section 4). This section is the hosts' side.

## 3. Log monitoring

Notifications from host logs, counts and anomalies, and logs that leave a host as they are written, so a host that locks up or is taken over has already sent what it logged.

What exists and is reused: `alerts.evaluate()` opens, refreshes and resolves alerts and notifies on each change, through ntfy, Gotify, a webhook or PagerDuty with routes by host and level, and `alerts_wake` can trigger it at once. Host logs are stored, scrubbed of secrets and searchable, with counts by level and hour. A log rule becomes one more source in `alerts.problems()`: open while its count over a window is over the threshold, resolved when it falls.

| Phase | What it holds | Status |
| :--- | :--- | :--- |
| **0. Holes in what is stored today** | Prune by arrival time (`collected_at`), not the host's timestamp: today a host can log 500,000 lines stamped up to a day ahead and push real lines out of `KEEP_ROWS`, and a line stamped older than `KEEP_DAYS` is deleted as it is stored. A per-host ingest rate, with going over it recorded, not paid for in old rows. Store the fields journald sets (`_UID`, `_COMM`, `_EXE`), since `SYSLOG_IDENTIFIER` is whatever the writer says. Keep `__SEQNUM` and its ID, to see lines deleted on the host. Counts per host, unit and level per 5 minutes, kept longer than the raw lines, starting at once because baselines need weeks of them | built: `1cbda49`. Lines kept by arrival, a rate per host (rows ÷ days, a day saved up) with the overflow recorded and counted, `_UID`, `_COMM`, `_EXE` and `__SEQNUM` with its ID stored, counts per host, unit, level and 5 minutes kept 400 days. Gaps in `__SEQNUM` are not read yet: a scan asks only for info and worse, so gaps are normal until lines are pushed (phase 2) |
| **1. Log rules** | Notifications go to the central notification center (section 12). A rule matches host, unit, program, lowest level and text, with a threshold over a window. Built-in rules for storage hosts: OOM kills, disk and controller I/O errors, filesystem errors (ext4, XFS, btrfs), ZFS or mdadm degraded, NFS or SMB not responding, failed units, segfaults, disk full; bursts of failed SSH and sudo logins off by default. Matched as lines arrive. No arbitrary regex over host text (SF-52): plain text and wildcards, or `google-re2`. One open alert per rule and host, so a flood is one alert | built: `acc6818`, in the Logs panel `73e916e`. Ten built-in rules; patterns are text with `*` and `\|`, no regex; one alert per rule and host; a program is who journald saw. Matched as each scan brings lines in, which is as they arrive until phase 2 pushes them |
| **2. Push ingest** | Hosts send journal lines as they are written, through the agent's logs plugin (section 11), to a receiver on the controller that resumes from the last line it has after a reboot. Per-host identity, size and rate limits, off the web threads. Each host's delay, gaps and signed or not shown. Hosts without the agent are polled over the SSH master connection every few seconds, which misses lockups | open, needs section 11's base |
| **3. Anomalies** | Volume against the same hour of the week over two to four weeks (median and spread, with a floor for quiet units). New kinds of line: a message with numbers, hex, addresses and paths blanked, hashed, flagged the first time a host logs it. Silence: a host or unit that normally logs and stops, which is how a lockup shows | open |
| **4. The monitoring view** | Per host: rate against baseline, open log alerts, new kinds of line, silent hosts, and ingest health (last line, delay, gaps, signed or not). To the patterns in [ACCESSIBILITY.md](ACCESSIBILITY.md). Logs entry points from an alert, a mount and a device | open |
| **5. netconsole** | Kernel messages over UDP straight from the kernel, which works when user space is dead, so panics and hard hangs reach the controller. `pstore` to read the last panic after a reboot | open |

**What it does not do:** prove a line is true. Signing proves a payload came from the host unchanged; root on the host can write, edit or delete anything not yet sent, and sign it. Sending lines as they are written shrinks that window to almost nothing, and gaps in `__SEQNUM` and silence show deletion afterwards. Forward Secure Sealing (`journalctl --setup-keys`, with the verify key on the controller) shows files altered on the host. It cannot stop deletion.

**Phases 3 to 5 on 2026-11-20 (built, not lab-tested):** anomalies (`0befc1e`), the monitoring view (`543a1a6`), netconsole and pstore (`c037102`); tier 14 checks written (`7212bf2`), not run, and the panic check runs only with `SFLAB_CRASH=1`. **Open:** pstore records are readable only by root; a kernel event can count twice in log rules (journal and netconsole). Plain netconsole lines with a priority prefix keep that level. The opt-in Compose override `docker-compose.netconsole.yml` publishes UDP.

## 4. Toolbox

None of it exists. It needs the catalog engine and the secret store (section 5). The [Toolbox roadmap](archive/roadmaps/toolbox-catalog-roadmap.md) holds the entry format, the GUI levels, the API, the tables, the safety rules and the lab gauntlet; [the merged plan](archive/roadmaps/infrastructure-platform-roadmap.md#8-the-catalog) wins where they differ. A tool without a passing lab run is labelled *not lab-tested* in the catalog.

### 4.1 The engine

| Item | What | Status |
| :--- | :--- | :--- |
| **Catalog engine** | Entry schema, signatures (the project's for the official catalog, the operator's for their own), validation, the override layer that survives catalog updates, install methods in order of safety (rootless container, distro package, verified binary; Quadlet and compose), risk labels in the report, uninstall that keeps data | built 2026-11-20, not lab-tested (`4ae52ca`, `d3b288d`); the packaged catalog shows as *packaged* until the release key signs it |
| **Adapters** | `detect`, `status`, `actions`, `links`, `metrics`, read-only by default, over the existing SSH scan; an action is a staged plan step; credentials by vault reference only, and an adapter that talks to a panel's API uses section 13's connection kind and permission guide; a failed adapter says "status unavailable" and never blocks a scan | built 2026-11-20, not lab-tested (`f90e471`); an SSO link falls back to a plain link until an identity provider entry exists (0.5.13) |
| **GUI levels** | Link, SSO link, status tiles, panel with actions | built 2026-11-20, not lab-tested (`4482e3e`) |
| **Toolbox view** | The rail item, host cards, deep links (`/#host=gw-01&tab=toolbox&tool=wireguard`) | built 2026-11-20, not lab-tested (`4482e3e`) |
| **API and tables** | `/api/toolbox/...` (catalog, validate, sign, installed, status, stage, bundles, profiles, dash, actions, updates, exposure); `toolbox_catalog`, `toolbox_installs`, `toolbox_status`, `toolbox_bundles`, `toolbox_profiles`, `toolbox_host_roles`, `toolbox_overrides` | built 2026-11-22, not lab-tested (`482c9e2`, `tbbundles.py`) |
| **Custom entries** | An editor with validation, a dry run and signing with the operator's key | built 2026-11-20, not lab-tested (`4482e3e`); signed on the operator's own machine, the controller only verifies |
| **Bundles** | Ordering, shared secrets, one firewall change set, one report, port-collision check, rollback of the whole bundle | built 2026-11-22, not lab-tested (`tbbundles.py`) |
| **Role profiles and per-host exclusions** | Default tools per host role (`edge`, `nas`, `hypervisor`, `container-host`) and per-host exclusions | built 2026-11-22, not lab-tested (`tbbundles.py`) |
| **Custom dashboards** | Tool tiles (`toolbox` and `tool:<id>`) in the dashboard grid | built 2026-11-22, not lab-tested (`tbadapters.py`, `secplus.py`) |
| **Feeds** | Trivy findings and CrowdSec decisions into alerts and the quarantine view, with bans reconciled so quarantine doesn't fight the bouncer | built (`06d85e3`, `tbfeeds.py`), not lab-tested |

**State on 2026-11-20:** WireGuard (with its peer manager), Cockpit and Uptime Kuma exist as the engine's own test entries. Lab tier 29 is written and has not run. **Completed 2026-11-23:** WireGuard peer config templates and pure-Python SVG QR code generation (`qrsvg.py`, `tbadapters.py`), Trivy/Grype CVE deltas on catalog updates and fleet scan summaries (`toolbox.cve_delta`, `toolbox.cve_summary`, `GET /api/toolbox/updates`), binary installs verifying detached minisign signatures or Cosign Sigstore bundles and extracting verified `.tar.gz` archive members, and container/Quadlet/compose installs (including sidecars) verifying each digest-pinned image with a catalog-pinned Cosign public key before writing units or starting stacks. Live tier 29 validation remains pending.

### 4.2 The entries

| Group | Entries | Status |
| :--- | :--- | :--- |
| **Panels** | Cockpit, Dockge, Portainer, Komodo, Dockhand, Dokploy, Incus UI | built 2026-11-23, not lab-tested (`catalog/*.yaml`, `tbadapters_a.py`) |
| **VPN and overlay servers** | WireGuard with the peer manager, Headscale (with headscale-ui or headplane), NetBird's management, signal, relay and dashboard, Netmaker, a ZeroTier controller, Nebula's CA and lighthouse, OpenVPN with its PKI, strongSwan, Pangolin with Gerbil and Traefik | built 2026-11-23, not lab-tested (`catalog/*.yaml`, `tbadapters_a.py`) |
| **Zero trust and access** | OpenZiti, Pomerium (policies from each entry's exposure), Cloudflare Tunnel, Teleport, HashiCorp Boundary, SSH CA | built 2026-11-23, not lab-tested (`catalog/*.yaml`, `tbadapters_a.py`) |
| **Identity and SSO** | Authentik, Keycloak, Authelia, Kanidm, LLDAP, Samba AD DC, FreeIPA; OIDC clients registered for catalog panels | built 2026-11-23, not lab-tested (`catalog/*.yaml`, `tbadapters_a.py`) |
| **Reverse proxy, TLS and DNS** | Caddy with generated routes, Traefik, nginx Proxy Manager, step-ca, Pi-hole, AdGuard Home, Unbound, CoreDNS, dnsmasq, Chrony with NTS | built 2026-11-23, not lab-tested (`catalog/*.yaml`, `tbadapters_b.py`) |
| **Detection and scanning** | CrowdSec with the nftables bouncer, fail2ban, Suricata, Zeek, Trivy, Grype, OpenSCAP, Falco, Wazuh | built 2026-11-23, not lab-tested (`catalog/*.yaml`, `tbadapters_b.py`) |
| **Monitoring and alerting** | Prometheus with node_exporter, Grafana with a StorageForge dashboard, Loki with Promtail or Alloy, Uptime Kuma, Beszel, Netdata, smartd and smartctl_exporter, ntfy, Gotify, Apprise | built 2026-11-23, not lab-tested (`catalog/*.yaml`, `tbadapters_b.py`) |
| **Backup and recovery** | restic, Borg, Kopia, Proxmox Backup Server, automated restore tests to a scratch dataset with hashes compared | built 2026-11-23, not lab-tested (`catalog/*.yaml`, `tbadapters_c.py`, `steps_restoretest.py`) |
| **Secrets** | OpenBao or Vault with quorum-style unseal, sops with age, Vaultwarden | built 2026-11-23, not lab-tested (`catalog/*.yaml`, `tbadapters_c.py`) |
| **Provisioning and platform** | Packer, PXE, iPXE and netboot.xyz, Forgejo or Gitea, a registry mirror (Zot or Harbor) for airgapped installs, Renovate or an image-update watcher, DNS and DHCP panels, Ansible, Puppet and Terraform runners | built 2026-11-23, not lab-tested (`catalog/*.yaml`, `tbadapters_c.py`) |
| **Storage-facing apps** | Samba, NFS, MinIO, Garage, Nextcloud, Syncthing, Jellyfin, each placed on a dataset with its snapshot and WORM policy, share fencing and canaries wired in | built 2026-11-23, not lab-tested (`catalog/*.yaml`, `tbadapters_c.py`, `tbstorage.py`) |
| **Offline** | Package bundles and local mirrors, with the registry mirror | built 2026-11-23, not lab-tested (`catalog/*.yaml`, `tbadapters_c.py`, `steps_offline.py`) |

### 4.3 Built-in bundles

Private access (WireGuard, Caddy, Authelia) · Hardened homelab (Private access, CrowdSec, Chrony with NTS, Uptime Kuma, restic) · Container host (Caddy, Komodo, Trivy, Uptime Kuma) · Hypervisor (Cockpit, WireGuard, Proxmox Backup Client, Uptime Kuma) · Observability (Cockpit, Chrony, Uptime Kuma) · Zero-trust gateway (step-ca, Authentik, OpenZiti) · Backup and recovery (restic, Borg). Built in `tbbundles.py`, not lab-tested.

## 5. Change engine

Built since the last roadmap: storage pools of every kind as steps (`zfs-pool`, `md-array`, `lvm-vg`, `btrfs-add`, partitions and formats), bridges, VLANs and MTU (`net-bridge`, `net-vlan`, `net-mtu`), libvirt networks and pools, and secrets for plan steps (`vault secret-add`, `vault send-secret`).

| Item | What's left | Status |
| :--- | :--- | :--- |
| **Secret store** | Generic secrets generated, shown once, delivered through the runner's stdin, with a rotation path like `rotate` has for SSH keys | built 2026-11-20, not lab-tested (`6d52a6b`, `b5e412b`); tier 25 written, not run. Open: restarting what uses a rotated secret, delivery to Ansible by stdin, whether rotating a sensitive secret needs a step-up (the owner's call) |
| **`runtime-install`** | The four runtimes across distros, rootless setup, and a preflight that says present, installable or blocked. [Detail](archive/roadmaps/infrastructure-platform-roadmap.md#71-runtime-install) | built 2026-11-20, not lab-tested (`daa35b7`); tier 25 written, not run. Alpine package installation is covered by the runner tests. Open: runtime removal and Alpine service setup |
| **Pools: what's left** | Add a vdev to a ZFS pool, replace or attach a disk; add, replace and grow an md array; LUKS | built 2026-11-20, not lab-tested (`5d8be48`); tier 26 and its `sf-pools` VM written, not run |
| **Networks: what's left** | Bonds, addresses, routes, DHCP; read netplan, NetworkManager and networkd files as well as what the kernel has | built 2026-11-20, not lab-tested (`9baa653`, `e5e368f`, `7779f37`); tier 26 written, not run |
| **Copies on other hosts** (the owner's request of 2026-11-19) | Duplicates across hosts are possible backups: a class of their own, never reclaimable or offered for the trash. The plan check names *the last copy* and *the copy on HOST would be the only one left*. Keep in sync prepares a Moves mirror plan; a deployed pair is kept in sync and no longer a duplicate. Pairs left are suggested, with one notification, and can be set aside | built, not lab-tested: `3aa6ee8`, `40b8cd2`, `9d48e09`, `587e360`; the lab check `copies-across-hosts` (tier 13) is written in `90815ae` and has not run. The `copies sync` CLI and the dialog prepare the same plan, including the option to keep replaced files. Preparation rejects a nested filesystem known to the index. Single-file mirrors now support distinct source and destination names. Plan preparation was tested on both databases and transfer with real rsync over a simulated SSH hop. Live-host validation remains open |

**Exit** (written as tiers 25 and 26 on 2026-11-20, not run): install a runtime on a bare VM from a plan. The report changes nothing, a changed plan gets 409, and a bridge change that cuts SSH rolls itself back.

## 6. Workloads

Built: running a container, VMs from cloud images (`vm-create`), defining a VM, start, stop and remove, snapshots and revert, changing a VM (`vm-edit`), copying a VM to another host, VM backups on a schedule, the console.

| Item | What | Status |
| :--- | :--- | :--- |
| **`stack` and `lxc` steps** | Each carrying its firewall rule and labels; Incus instances too | built 2026-11-20, not lab-tested (`841be70`); a destructive plan step (`cc0db81`) can now remove managed stack containers or an LXC container |
| **Image updates** | With rollback on a failed healthcheck | built 2026-11-20, not lab-tested (`38a2f77`) |
| **VMs from ISOs** | Cloud images are built | built 2026-11-20, not lab-tested (`dd72566`); unattended installs wait for an answer file with a vault secret; no TrueNAS or OPNsense ISO (no stable checksum list) |
| **Placement advice** | A pool on a dataset tuned for its use, databases off the bulk pool, warnings for bind mounts on network filesystems, and a warning when data sits where no hold or offsite copy reaches | built 2026-11-20, not lab-tested (`1c284bb`) |
| **MAC at deploy** | `:Z` labels, the `svirt_image_t` fix as a plan step, AppArmor pool paths | built 2026-11-20, not lab-tested (`dc22460`) |
| **Read side** | Podman Quadlets; adopting a workload by capturing it as compose, Quadlet, libvirt XML or Incus YAML, with drift against the capture | built 2026-11-20, not lab-tested (`8de9cee`); the Workloads panel (`565701d`) now exposes adoption, drift, definition downloads and plan exports; Podman paths tested only against stand-ins |
| **Quiesced stacks** | Stop, snapshot, start for stateful stacks, with the method recorded (VMs already freeze through the guest agent) | built 2026-11-20, not lab-tested (`fe4940c`), on ZFS or btrfs |
| **Externally managed** | Detect a workload something else manages, and warn before changing it | host-side detection built 2026-11-20 (`e92ca19`); Workloads also uses connected platform readings when identifying managed containers. Covered by the platform and workload tests, not lab-tested |
| **Exports** | Terraform, OpenTofu and Puppet for workloads, with round-trip tests | built 2026-11-20, not lab-tested (`d7fa31b`); validation skips where tofu, terraform or puppet is not installed |

Lab tier 28 (workloads, and 1.3's reverse proxies and identity providers) is written and has not run.

[Workload roadmap](archive/roadmaps/workload-platform-roadmap.md) for field lists, and the [merged plan](archive/roadmaps/infrastructure-platform-roadmap.md#7-workloads-in-detail) where they differ.

## 7. Clone and migrate hosts

From the phases in [host migration](docs/host-migration.md#phases).

| Phase | What's left | Status |
| :--- | :--- | :--- |
| **3b** | AUR and local builds: the cache, `bacman`, an AUR build at the matching commit; Arch Linux Archive pinning; derivative repositories and CPU levels | built 2026-11-22, not lab-tested (`ddceffb`) |
| **3d** | LUKS (the key is the owner's, so by hand unless the vault holds it), other `/etc` files | built 2026-11-22, not lab-tested (`ddceffb`) |
| **4b** | Holds on the clone's snapshots, the before-and-after "what changed" report, `--accept` in the scripts | built 2026-11-22, not lab-tested (`ddceffb`) |
| **5** | Test and migration modes: isolation, and cutover | built 2026-11-22, not lab-tested (`ddceffb`) |
| **7** | A disk image from a physical host: a block copy from a snapshot into qcow2, fixed up to boot; to bare metal through a live environment | built 2026-11-22, not lab-tested (`ddceffb`) |
| **8** | A second operating system installed over SSH, beside the one that is running (asked for by the owner on 2026-11-18). The host fetches the distribution's cloud image, checks it against the publisher's checksum, and copies it into unpartitioned space or onto a spare disk with a boot partition of its own; the running system's bootloader, boot partition and filesystems are not written to. The firmware gets one new boot entry, used once (`BootNext`): if the new system does not come up, the next restart is the old one, and making the new one the default is a step of its own after StorageForge has reached it. First boot is seeded with the user and SSH keys, the host name, the network settings read from the running system, the machine's SSH host keys (kept by default, made new on request) and the existing data filesystems at the same mount points. The clone steps then bring packages, accounts and config files. First version: UEFI only, no shrinking of a filesystem to make room | built 2026-11-18: `os-install`, `os-boot` and `os-remove` (`steps_osinstall.py`). Proven in a UEFI VM through the engine's own plan scripts on Fedora 44 and Rocky 10, with the return to the old system shown twice, once after a new system that would not start. Free space on the running system's own disk was proven the same day in a second VM (Ubuntu 24.04 beside Debian 13 on one disk), which found and fixed a fault: on a disk in use the kernel was not told of the new partitions. Since 2026-11-20 (`0af505d` to `0abe3c3`; unit and browser tests, not lab-tested): a static address, Secure Boot read with a refusal for a loader the firmware would not start, a plain refusal on BIOS, the `os-running` step and the page under Rebuild. Lab tier 23 (a UEFI node, `sf-uefi`) is written and has not run. Open: the tier 23 run, Secure Boot on a real machine, `always` and `never` in a VM, real hardware, a system installed since the last scan |
| **9** | A desktop on what phase 8 installed (asked for by the owner on 2026-11-18): Dux (duxlabs.dev) through its unattended installer, with the compositor and terminal chosen per host (niri, Hyprland, mango by the installer; Sway, labwc and Miracle by hand, as its own documentation says). The installer is a script fetched from its site, so the step records its SHA-256 and does not run one that differs (my recommendation, 2026-11-18; the owner has not answered). And a **desktop profile** kept on the server: keybindings, window rules and the display layout in one compositor-neutral form, written out as niri, Hyprland or Sway configuration per host, so a fleet has the same bindings whichever compositor a machine runs | built 2026-11-18: the profile and its checks, renderers for niri, Hyprland (Lua, 0.55 and later) and Sway, profiles kept on the server with a display layout per machine (`desktop.py`, `/api/desktop/profiles`), and the `dux-install` and `desktop-profile` steps (`steps_desktop.py`). The Dux step pins a release and the SHA-256 of that release's installer, not the site's script: that script is a bootstrap that fetches whatever is newest, so its hash would pin nothing (found 2026-11-18; the owner had not answered on pinning, and this is the stricter form of what was recommended). niri 26.04 and Hyprland 0.57 validate what is rendered for them in the tests; one VM run installed Dux v2.1.2 with niri on a Fedora that `os-install` had installed, and wrote a profile niri accepted. Since 2026-11-20: the page for profiles under Rebuild, browser-tested; Sway 1.12 accepted the rendering once in a container and the test runs where Sway is installed (`sway --validate` does not check the command inside a binding); Dux and the profile are a second plan that starts with `os-running`. Lab tier 23 is written and has not run. Open: a graphical session with the profile seen working, Hyprland and mango through the installer, other distributions, the tier 23 run |

## 8. Network and map

| Item | What | Status |
| :--- | :--- | :--- |
| **`place-before`** | A rule at a position. RouterOS appends, so a rule below a final drop does nothing, and the what-if says so | built 2026-11-22, not lab-tested (`1c0b021`) |
| **Scan results as map placeholders** | The Scan tab links to the map, but they are separate drawings | built 2026-11-22, not lab-tested (`9aaaff3`) |
| **Scanner findings through alerts** | What's new since the last scan | built 2026-11-22, not lab-tested (`9aaaff3`) |
| **Traffic on Linux hosts** | Monitoring covers devices only. Activity from byte counters between scans | built 2026-11-22, not lab-tested (`9aaaff3`) |
| **Deeper reads** | Cisco zone-based firewall and VRFs, OSPF and BGP state, wireless clients, rich firewalld rules beyond source, port and verdict, DHCP scopes as nodes | built 2026-11-22, not lab-tested (`4467a2b`) |
| **From the map** | Deploy a stack, an LXC instance, a catalog tool or a VM; move, clone or resize a VM; restrict a service's bind address; put a listener behind a proxy; rotate a peer's key | built 2026-11-22, not lab-tested (`4467a2b`) |
| **`bridge`-family firewall rules** | For bridged VMs, which bypass a quarantine's hooks | built 2026-11-22, not lab-tested (`1c0b021`) |
| **Map extras** | Force-directed and rack layouts, custom icons and colour rules, per-role default views, map tiles on dashboards, rendering for very large fleets | built 2026-11-22, not lab-tested (`4467a2b`) |
| **Integrations** | NetBox and Grafana exports, read-only SNMP, LLDP | built 2026-11-22, not lab-tested (`4467a2b`) |
| **REST adapters** | Only if a device needs one. SSH reads everything on all four platforms, and a second way in is a second thing to secure | when needed |

## 9. Security and ransomware depth

| Item | What | Status |
| :--- | :--- | :--- |
| **Incidents with workloads** | Incidents that include workloads touching affected paths, and a clean room that boots a VM or container from a pre-incident snapshot | built 2026-11-22, not lab-tested (`security.py`, `secscripts.py`) |
| **Compliance readings** | CIS Docker, Podman and libvirt-style checks, and auditd rules for runtime sockets and config | built 2026-11-22, not lab-tested (`cis-runtime`, `runtime_audit`, `runtime_cis`) |
| **Credential and identity anomalies** | Needs a new collector and a design first | built earlier (`secplus.identity_view`), extended with `vfs_full_audit` off-hours fallback |
| **Watchers** | fanotify watchers; off-hours read volume by user. Both through the agent's files plugin (section 11); without the agent, off-hours reads need `vfs_full_audit` | built 2026-11-22 (`agentfiles.py`, `secplus._offhours_reads`) |
| **Falco rule simulator** | Rules against recorded sessions | built 2026-11-22, not lab-tested (`secplus.simulate_falco`) |
| **Builders** | A visual drag-and-drop subnet matrix (fences are typed today); a visual playbook builder beyond the form | built 2026-11-22 (`static/securitymore.js`) |
| **FIDO2 at sign-in** | Only guarded actions use it today | built 2026-11-22, not lab-tested (`/api/login/webauthn/begin`, `/api/login/webauthn/finish`) |
| **SMS** | Its own channel, not only through a webhook | built 2026-11-22, not lab-tested (`alerts.py`) |
| **Local mirror discovery** | A host uses the mirrors it is already set up for | built 2026-11-22, not lab-tested (`secplus.discover_mirrors`) |
| **Smaller items** | Expiry heatmap, decoy personas and distribution, AppArmor profile editor, role-based hardening profiles, custom AIDE watchlist | built (`secplus.stage_apparmor`, `static/securitymore.js`) |
| **EQ-03** large modules | Split `server.py` and the other large modules, when it no longer sits right before a lab run | parked |
| **SF-38** container scan in CI | CI fails on a new reachable critical. On GitHub it runs; Forgejo waits for a runner | open |

## 10. UI and UX

From the [UI and UX roadmap](archive/roadmaps/ui-ux-roadmap.md) and the [UI audit of 2026-11-04](docs/audit-2026-11-04-ui.md). What phases 0 to 5 built is in the [0.4.0 ledger](archive/roadmaps/release-0.4.0-roadmap.md#a4-ui-and-ux).

| Phase | What's left | Status |
| :--- | :--- | :--- |
| **2** | Security and Settings as workspaces with their own section navigation; Security leading with blast radius, quarantine and the brake when the posture is Incident; the rail keeping only a summary and a link for them; one Plan workspace holding Design, Network and devices, Changes, Moves, Schedule and History; collapsible rail groups (UX-01) | open |
| **3** | The planner grows, steps 3a to 3h: design what isn't there yet (disks, pools, remotes, exports), Shares, the network lens, the workloads lens with placement guardrails, the security lens, the health lens, compare and adopt (adopting one object from the scan is the part of 3g not built), one Change review | open |
| **3i** | One design document in place of the storage blueprint and the map's design, with the planner as its editor and the map showing it as ghosts; a migration and a lab run. Answers in 10.1 | provisional answers, confirmed at 0.5.16 |
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
| **Language** | Rust, decided 2026-11-18. The agent is one static binary (musl, no dynamic libraries), in a Cargo workspace beside `storageforge-indexer/enclave`, sharing with it the framing, the size limits and the habit of refusing what no honest peer sends. Dependencies are pinned in `Cargo.lock` and audited in CI (`cargo audit`, `cargo deny`), and the build is reproducible as the enclave's is. `storageforge-agentctl`, the helper behind the one sudoers line, is Rust too: it runs as root, so it is the last place for a shell script. The receiver on the controller is part of the web app's side and stays Python, in its own process and database role (11.2) | built 2026-11-20, not lab-tested (`1c1403a` to `2d2b5ae`) |
| **Base image** | One image on every machine: a stage of the same `Dockerfile`, holding the agent's static binary and nothing it does not need: no interpreter, no OpenSSL, no libc to patch, so the scanners have the binary's own dependencies to read (from its embedded `cargo auditable` list) and little else. Scanned by Trivy and Grype in CI and signed. Read-only root filesystem, no package manager, no shell, no Docker socket, no plugins built in. x86-64 and arm64 | built 2026-11-20, not lab-tested (`1c1403a` to `2d2b5ae`): the `agent` stage of the `Dockerfile` |
| **Plugins** | Each feature is a plugin, and a host gets only the plugins its settings turn on. A plugin is signed: the project's release key for official ones, built and scanned in CI; the operator's own key for their own, trusted only when the operator says so, as Toolbox entries are. Each declares the mounts, capabilities and devices it needs. With the agent in Rust a plugin is a static executable of its own, not code loaded into the agent: the agent starts it as a child with only what it declared, and speaks to it over a pipe in the agent's framing, so a plugin that crashes or is taken over is not the agent. Official plugins are Rust in the same workspace; an operator's own may be any static executable that speaks the protocol | built 2026-11-20, not lab-tested (`1c1403a` to `2d2b5ae`): the format and the release-key check; no plugin of its own yet |
| **The host's manifest** | Which plugins, at which hashes, with which privileges, for this host, signed by the controller with a fresh time and a counter, so an old manifest cannot be played back. The agent loads a plugin only when its signature and the manifest both match | built 2026-11-20, not lab-tested (`1c1403a` to `2d2b5ae`): signed, with a counter, an older one refused |
| **Delivery** | The controller sends plugins and the manifest straight to the agent over an encrypted tunnel of its own: through the tunnel container, with an agent key that is not the node's SSH tunnel key and reaches only the agent's receiver, or on the LAN a direct connection with both keys pinned, over the StorageForge network (2.1) where the host is on it. Never through the Docker API, and never inside an SSH session | open |
| **Lifecycle over SSH** | Installing, changing privileges when plugins change, updating, restarting and stopping the container are signed requests over SSH to `storageforge-agentctl`, on every host, which accepts agent operations and nothing else. A host with SSH control keeps `storageforge-run` for change plans beside it; a monitoring-only host gets only `storageforge-agentctl` | built 2026-11-20, not lab-tested (`1c1403a` to `2d2b5ae`) |
| **Accounts** | The agent runs as its own account (`sfagent`, its own uid and gid), never root and never in the `docker` group or sudoers. The container's process runs as that uid. The user that deploys and manages the agent over SSH is never in the `docker` group either, since that group is root on the host: setup refuses to go on while it is, and says why. That user reaches the runtime only through `sudo -n /usr/local/sbin/storageforge-agentctl`, the one line sudoers allows it, and the verifier runs `docker` or `podman` itself after checking the request's signature | built 2026-11-20, not lab-tested (`1c1403a` to `2d2b5ae`) |
| **Runtime** | Docker or Podman, whichever the host has. The basic plugins (heartbeat, logs, health, network) run rootless under Podman as `sfagent`, with no root runtime involved; reading the journal takes `sfagent` in `systemd-journal`, carried into the container (`--group-add keep-groups`). The disks and files plugins need host capabilities that a rootless runtime cannot grant, so they take a rootful runtime, and the process inside still runs as `sfagent` with only the declared capabilities Whether a host has one comes from the SSH scan, which reads both today. On a host with neither, installing the agent tells the user Podman will be installed, then installs it through the same signed request. LXC is the third runtime: see the row below | built 2026-11-20, not lab-tested (`1c1403a` to `2d2b5ae`); Podman ran only against stand-ins |
| **LXC** | The same signed base image, run as an **unprivileged** system container, not a second build. Plain LXC (`lxc-oci`), Incus and Proxmox VE (9.1 and later make LXC containers from OCI images) all take it, so the image digest that Trivy, Grype and the signature cover is the one that runs. `storageforge-agentctl` drives `lxc-*`, `incus` or `pct`, whichever the host has, and the managing user is never in the `lxd` or `incus-admin` group, which are root on the host as `docker` is. The container: an idmapped uid range, with `sfagent` mapped to its own host uid; the root filesystem read-only; `lxc.cap.keep` holding only the plugins' declared capabilities; the default AppArmor and seccomp profiles or tighter; nesting off; no `/dev` beyond the plugins' declared devices; the host's paths as read-only bind mounts (`lxc.mount.entry`, Incus `disk` devices with `readonly=true`, `pct` mount points with `ro=1`), with SSH's and StorageForge's secret paths masked as in 11.2. Host PID and host network for the health and network plugins come from `lxc.namespace.keep`; whether Incus and `pct` can give each plugin what it declares is checked per plugin when this is built, and a plugin a runtime cannot serve is not offered there, with the reason shown. Chosen where the host has LXC and no Docker or Podman, which is every stock Proxmox VE host, so a Proxmox host is never asked to take Podman | built 2026-11-20, not lab-tested (`1c1403a` to `2d2b5ae`); LXC, Incus and `pct` ran only against stand-ins, their commands written from documentation |
| **What the agent automates** | Its own schedules (scans, readings, SMART), buffering and resending, and the protective reactions in 11.2. All of it reads; none of it changes the host. Automation that changes data stays what it is today: deployed jobs on systemd timers run by `storageforge-job`, set up by a change plan over SSH | open |
| **Privileges follow plugins** | The container is made with the union of what its plugins declare, and nothing more. Removing a plugin takes its privileges away | built 2026-11-20, not lab-tested (`1c1403a` to `2d2b5ae`) |
| **Enrollment** | During setup over the already pinned SSH connection, the agent makes its key pair and the controller reads the public half back over that connection and pins it | built 2026-11-20, not lab-tested (`1c1403a` to `2d2b5ae`) |
| **Windows** | A native service, not a container, with the same plugin format, signatures and manifest. Monitoring only. Managed over OpenSSH for Windows | built 2026-11-22, not lab-tested |

Open in 11.1: **Delivery** (the tunnel; 11.2 builds the receiver), Windows, and what [docs/agent.md](docs/agent.md#what-it-does-not-do-or-check-yet) lists: no check from outside or wipe (11.3), `.ssh` folders deeper than the masks reach, no size limit on the state folder, no memory or process limit under rootless Podman, `cargo audit` and `cargo deny` not in CI. Lab tier 24 is written and has not run.

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
| **Its actions affect only itself** | What an agent's report can trigger by itself is protective and aimed at the reporter: the shadow-copy tripwire drops *the address pinned for that client at enrollment*, never an address named in the message. An agent can accuse only itself | built 2026-11-22 (`agentaction.tripwire_drop`) |
| **Anything wider needs a second witness** | Freezing a share, or any action that touches other clients or hosts, needs an independent source to agree: the share host's own sentinel, a decoy hit, a scan over SSH. Otherwise it is an alert for a person | built 2026-11-22 (`agentaction.wider`, `agentaction.freeze_share`) |
| **Where data came from is shown** | Every reading is labelled *reported by agent* or *measured by scan*, and where both exist they are compared; a disagreement is an alert | open |
| **Lying is expected** | A taken-over agent can hide its host's problems or invent them. Inventing them is contained by the rows above. Hiding them is not preventable, and is why decoys on shares, scans over SSH, silence and counter gaps stay independent of it | open |

**From the controller to the agent: only what its plugins need, nothing that reaches elsewhere**

| Limit | How | Status |
| :--- | :--- | :--- |
| **No secrets but its own key** | No vault access, no other host's keys, no job keys, no tokens for outside services. Plugins and the manifest are not secret. Stealing everything an agent holds gives its own key, which is revoked, and its own host's data, which whoever holds the host already has | open |
| **Read-only on its host** | Every mount read-only. A taken-over agent can read its host and nothing more, so it cannot make that host worse than whoever took it already did | open |
| **A hardened container** | All capabilities dropped but the plugins' declared ones, `no-new-privileges`, the default seccomp profile or tighter, user namespace remapping where the plugins allow, no Docker socket. Under LXC: unprivileged only, never a privileged container, nesting off, and no LXC, Incus or Proxmox socket or API inside | open |
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

**State of 11.2 on 2026-11-20 (built, not lab-tested; `360b3b3` to `271e0b4`):** the tunnel, both keys pinned; the receiver as its own process and role, identity from the key, counters, quotas, provenance labels, notifications on silence and gaps; an agent's network limited to the receiver; privilege only with an admin. Tier 24's tunnel and receiver checks are written and have not run. **Open:** *its actions affect only itself* and *anything wider needs a second witness* hold only because no agent report triggers any action yet, and must be built before one does; *either one fails alone* needs a plugin to say sshd is down (11.4); the tunnel under LXC, Incus and `pct`, and on hosts without systemd or nft; the lab build publishing the agent image and starting the receiver.

### 11.3 Wipe and stop

Anything in a container that the manifest does not account for ends its access.

| Check | How |
| :--- | :--- |
| **From outside, over SSH** (the check that counts, since a container that has been taken over can lie about itself) | The running image's digest is the signed base's; `docker diff` (or, under LXC, a hash of the read-only root filesystem against the image's) shows nothing outside the plugin and buffer folders; the plugin files' hashes match the manifest; the container's mounts, capabilities and devices match it. On every scan and on a timer |
| **From inside** | At start and on a timer, the agent checks its loaded code and plugin files against the manifest, and refuses an unsigned plugin, one not in the manifest, or a stale manifest |
| **What happens** | The controller revokes the agent's key on its own side first, which an attacker cannot undo; the agent deletes its key and exits; the container is stopped over SSH and left stopped, whatever its restart policy; an alert opens. Only an admin re-enrolls it, with re-authentication, and the audit log records it |

**State of 11.3 on 2026-11-20 (built, not lab-tested; `f2bdf86`):** checked from outside over SSH, on a timer and after each scan; any finding revokes the key and stops the container for good; an agent that finds tampering wipes its own key. 11.2's *its actions affect only itself* and *anything wider needs a second witness* are built in the same commit. **Open:** the container itself compared under Incus and `pct` (only the agent's folders are), Podman's output as it really is.

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
| **Shadow-copy tripwire (Windows)** | On a Windows client: process starts (Windows' process auditing with command lines, or Sysmon) for `vssadmin delete shadows`, `wmic shadowcopy delete`, PowerShell removing `Win32_ShadowCopy`, `wbadmin delete catalog` and `bcdedit … recoveryenabled no`, and shadow copies that vanish. The controller then drops that client from every share, snapshots, and freezes if armed, usually before encryption starts. Deleting shadow copies needs administrator rights, which can stop the agent first: its silence is the signal then, and the share's decoys stay the backstop. It detects and reports; it does not block the process, and StorageForge does not claim to be an EDR | Windows process events | built 2026-11-22, not lab-tested (`agent/src/windows.rs`, `agentaction.py`, `agentplugins.py`) |

**State of 11.4 on 2026-11-20 (built, not lab-tested; `01a057a`):** heartbeat, logs (section 3 phase 2, with gaps in `__SEQNUM` read), health (with *SSH is down*, so 11.2's *either one fails alone* holds) and network. 11.6's rows for wipe, plugins, replay, the receiver role, one-sender actions and the second witness are unit tests (`eb90477`) and tier 24 checks, written and not run; the tripwire and freeze rows wait for those actions. **Open:** signing the four plugins with the release key (the owner: `agent/plugins.sh sign`), OpenRC log files, capacity of filesystems other than btrfs and ZFS scrub progress in health. The agent reads XZ-compressed journal fields with bounded decoder memory and output, covered by decoder tests.

**0.5.8 on 2026-11-20 (built, not lab-tested):** the disks (`d3b9348`), files (`cb7f901`, also section 9's Watchers), scan (`dab3cd6`) and sentinel (`bb8730a`) plugins; monitoring-only hosts (`21ec6e4`) and their console (`8114f06`). Tier 24 checks written (`e116f7f`), not run. **Completed 2026-11-23:** Toolbox status ingestion via the agent (`agentplugins.take_toolbox_status`), ransomware high-rate modification burst detection in the files plugin (`agentfiles.ransomware_signs`), mount usage and ZFS pool comparison in the scan plugin (`agentscan.py`), and secret policy scopes (`steps`, `hosts`, `platforms`, `sensitive`) in the Keys → Secrets UI (`static/secretsview.js`). **Open:** NVMe health needs `SYS_ADMIN`, which disks does not declare; files under LXC; a journal reader started with no resume point may skip a journal file that appears after it starts (to verify).

**Agent admin UI, 2026-11-23:** Administration shows agent records and supports registering and adopting monitoring-only Linux hosts. The browser test covers the page with setup and adoption stand-ins. Tier 24 remains the live enrollment check.

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
| No Docker socket or API reachable from inside the container, and under LXC no LXC, Incus or Proxmox socket or API | open |
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
| The agent as LXC on `sf-pve` through `pct`, and on an Incus host and a plain LXC host: the same image digest running, unprivileged, read-only root, only the declared capabilities, and Podman never offered on `sf-pve` | open |
| A file written into the LXC agent's root filesystem, a privileged container, nesting turned on, or the managing user in `lxd` or `incus-admin`: each found or refused, with access wiped where the agent was running | open |
| Each plugin under LXC: works, or is not offered with the reason shown | open |
| The agent reading the scan signing key, an SSH host key, a `.ssh` folder, `/run/storageforge/secrets` or the sudoers files, from every plugin including scan and files: refused | open |
| The agent connecting to the host's own `sshd`, or another host's: refused | open |
| The agent's key revoked: SSH scans and deploys unaffected. SSH access revoked: the agent unaffected | open |
| `sshd` stopped: the agent keeps reporting and says SSH is down. The agent wiped: scans, deploys and the console keep working | open |
| The agent's tunnel key: reaches the receiver only, never a node's forwarded `sshd` | open |
| Setup with the managing user in the `docker` group: refused, with the reason | open |
| The managing user running `docker` or `podman` directly, or anything through `sudo` but `storageforge-agentctl`: refused | open |
| The agent's process: runs as `sfagent`, not root, with no sudo and no `docker` group; the basic plugins rootless under Podman, and unprivileged under LXC | open |
| Windows evaluation VM: the shadow-copy tripwire fires on each command above, and the share host drops the client | open, needs the owner's VM |

## 12. The notification center

Decided 2026-11-16: one place for everything that wants a person's attention, most critical at the top. It grows out of what exists: `alerts.py` opens, refreshes and resolves alerts, keeps their history, and pushes to ntfy, Gotify, a webhook or PagerDuty with routes by host and level.

| Item | What | Status |
| :--- | :--- | :--- |
| **Every source feeds it** | What `alerts.problems()` gathers today (jobs, schedules, tasks, drift, scans, backups, certificates, security, devices, the map), log rules (section 3), anomalies and silence, the agent's integrity and wipes (section 11), connections that went down (section 2), Toolbox feeds (section 4) | built for what exists: everything `alerts.problems()` gathers, and log rules (`6ffb278`, `acc6818`). Anomalies, the agent, connections and Toolbox feeds join as they are built |
| **Ranked** | Critical, then warning, then information; within a level, the newest first. Grouped by host and kind, with a count, so a flood is one row | built: `6ffb278` |
| **On every page** | A count of open critical notifications in the shared chrome, which opens the center; the center as a page of its own with filters by host, kind, level and state | built: `18add94`. The count is in the header of every page; the center is the Notify panel of the main page, with filters by host, kind and level, and its history |
| **Ignorable or not** | Critical notifications, configuration drift and security findings cannot be muted, snoozed, dismissed or acknowledged away: they leave the list only when resolved, by an update or another step, and an acknowledgement (a name and a note) only says someone is on it. Everything else can be snoozed for a time or muted per host or rule. Muting and acknowledging go in the audit log | built: `6ffb278`. Security findings are every `security-*` kind, ClamAV detections, shared keys, an exposed listener and a device on Telnet |
| **Fixes** | A kind may carry a prepared fix that becomes a plan step: run a stale job now, restart a failed unit, re-converge drift, renew a certificate, apply an update, restart a stopped agent through `storageforge-agentctl`, re-run a scan. Every fix goes the same way: shown prepared, with its plan and report; deployed behind the password; with a rollback offered after. A fix is only offered when it has a way back: an undo step, or a snapshot taken before it. A fix never deletes data by itself (a full disk shows what is largest, it does not clear it) | built for one kind: `b03d89a`, on the `unit-state` step `dc37b17`. A service that keeps failing is restarted, and its way back stops it again; both are change plans, deployed in Changes behind the password. Not built: run a stale job, re-converge drift, renew a certificate, apply an update, restart an agent, re-run a scan. A job run and a scan cannot be taken back, so by this section's own rule they carry no fix until they have one |
| **Channels** | Each route pushes from a level up (critical only to PagerDuty, say), and resolving is pushed when it is on, as today | as before: routes by host and level. A muted or snoozed notification is not pushed, and what cannot be ignored always is: `6ffb278` |
| **History** | Resolved, acknowledged and fixed notifications kept and searchable, with who did what | built: `6ffb278`, searchable, with who did what |
| **Lab** | A failed unit fixed on a lab host: prepared, deployed, rolled back; a fix with no way back not offered; a critical notification, a drift and a security finding that cannot be muted or acknowledged away and leave only when resolved; a flood of one kind shown as one row | done on 2026-11-17, tier 14: a failed unit fixed, prepared, deployed and rolled back (`notify-fix-and-back`); no fix where there is no way back; a critical notification that cannot be snoozed (`logrule-md-degraded`); a flood as one row (`logrule-flood-is-one`). Drift and a security finding that cannot be muted are unit-tested, not lab-tested |

## 13. API access

Decided 2026-11-16: StorageForge may connect to a platform's own API as well as over SSH, for what SSH reads badly or not at all: Proxmox guests and their backups, TrueNAS apps, snapshots and replication, the stacks a Docker panel manages. SSH stays the default and keeps every feature it has today; an API connection is switched on per platform, by the user. Proxmox is covered in all three of its products: VE, Backup Server and Datacenter Manager. Today nothing uses an API ([appliances](docs/appliances.md#limits)).

**Least privilege, always shown.** Before a token is asked for, the connect screen shows what it needs: a dedicated user, the role or privileges, the scope (path, environment, datastore), an expiry, and the commands or clicks that make it, ready to copy. The recommendation is always the least that does the job. A read-only token is the default, and an action that needs more (a snapshot, a backup, a start or stop) says which extra privilege it needs, on which object, at the moment it is turned on, never before. StorageForge never recommends root, an admin key, a full-access role or a token scoped to everything when a narrower one works.

| Item | What | Status |
| :--- | :--- | :--- |
| **The connection kind** | An HTTPS client beside SSH: the platform's certificate pinned on first use, as SSH pins host keys, and a changed certificate refused until accepted; timeouts, rate limits and retries; plain HTTP refused. The token comes from the secret store (section 5), is never on a command line, in a plan, a log or a report, and never leaves the controller (rule 3) | built 2026-11-20, not lab-tested (`676c07a`); `root@pam` tokens and plain HTTP refused |
| **The permission guide** | Per platform and per feature: the least role and scope, why each privilege is needed, and how to make it. Shown on the connect screen, in the docs, and again when an action is turned on | built 2026-11-20, not lab-tested (`dc91d94`), for the three Proxmox products |
| **The read-back** | After a token is entered, and on every scan: read what the token can really do, where the platform can say (Proxmox's `/access/permissions`, TrueNAS's roles on the key's user), and compare with the guide. Less than needed says which feature will not work and what to add. More than needed is a security finding in the notification center (section 12), which by the decision cannot be muted, and leaves when the token is narrowed or replaced | built 2026-11-20, not lab-tested (`7b4acf3`) |
| **Expiry and rotation** | An expiry recommended on every token where the platform allows one; a warning before it lapses; replacing a token through the secret store's rotation path | built 2026-11-20, not lab-tested (`825c613`): a warning 30 days before a token lapses, critical in the last week; a new token checked against the platform before the old one is dropped |
| **Labels** | Every platform ships *not lab-tested* until its lab run passes, in the docs and on the connect screen | built 2026-11-20, not lab-tested (`06eb475`), on the connect screen and in docs/api-connections.md |

| Platform | What it adds | Least for reading (recommended) | Extra, only for an action that needs it | Status |
| :--- | :--- | :--- | :--- | :--- |
| **Proxmox VE** | Guests (VMs and LXC) with their config, state and disks; storage; backup jobs; cluster and Ceph state | A user `storageforge@pve` with no password, an API token with privilege separation on, and the token given `PVEAuditor` (only `*.Audit` privileges) on `/`, or on `/vms`, `/storage` and `/nodes` alone if the cluster's other paths should stay hidden | `VM.Snapshot` (and `VM.Snapshot.Rollback` to revert) on `/vms/<id>` or a pool; `VM.Backup` on the guest and `Datastore.AllocateSpace` on the target storage for a backup; `VM.PowerMgmt` to start and stop. A custom role per action, granted to the token, not the user | built 2026-11-20, not lab-tested (`1ef0635`). Ceph health is read and reported; a token narrowed to `/vms /storage /nodes` cannot read backup jobs (Sys.Audit on `/`), and the guide says so |
| **Proxmox Backup Server** | Datastores, backup groups and snapshots, verify and prune jobs, so "is it backed up" is read from the server | A token for a dedicated user with `DatastoreAudit` on `/datastore/<name>` | `DatastoreReader` on that datastore to restore-test; `DatastoreBackup` only if StorageForge itself sends backups | built 2026-11-20, not lab-tested (`1a192cc`). Backup groups and snapshots are read across visible namespaces |
| **Proxmox Datacenter Manager** | One view of many PVE clusters and PBS servers: remotes, their guests, storage and state, and guest migration between clusters. A fleet read through one token instead of one per cluster | A user `storageforge@pdm` with an API token, which starts with no permissions, given the built-in `Auditor` role scoped to the remotes StorageForge should see, not `/`. PDM has only built-in roles, so the narrowest built-in role and the narrowest path are the recommendation; the exact paths are checked when this is built. The guide says plainly that PDM holds its own tokens to every remote, so a PDM token reaches as far as PDM does, and connecting each PVE and PBS directly with its own narrower token is offered as the tighter choice | A role that may manage resources, only on the one remote, and only for a cross-cluster migration StorageForge prepares. Never `Administrator` | built 2026-11-20, not lab-tested (`0291cd0`); the remotes' own token secrets in its listing are dropped |
| **TrueNAS** | Pools, datasets, snapshots and their tasks, replication, shares, apps, alerts, all from the middleware rather than files `/usr` hides | A dedicated non-root user, a user-linked API key on it, and the user in a group whose privilege holds `READONLY_ADMIN`. Over HTTPS only: TrueNAS revokes a user-linked key sent over HTTP | A custom privilege of leaf roles only (`SNAPSHOT_WRITE` for snapshots, the replication roles to run a replication), never `FULL_ADMIN`. Leaf roles only, since mixing a meta-role with its own children has been reported to misbehave. The exact role names are checked against the 25.10 RBAC list when this is built | built 2026-11-20, not lab-tested (`f1bd4e8`); the snapshot action needs REPLICATION_ADMIN on 25.10; the WebSocket path and the roles field are taken from forum reports, not the docs |
| **Xen Orchestra (XCP-ng)** | Pools, VMs, storage repositories, backup jobs; the SRs that SSH scans see as partial | A token for a dedicated user with the Viewer role on the pools it should see | Operator on the objects an action touches | built 2026-11-20, not lab-tested (`ae35ef7`) |
| **Dockhand** | Environments, stacks, containers, images and volumes it manages, and which of them are externally managed (section 6) | A dedicated user with a role that only reads containers, images, volumes and stacks, scoped to the environments StorageForge should see. Whether its API tokens take a scope of their own is checked when this is built; until then the token is the user's rights, so the user is the boundary. A Hawser agent token is never used: it is the agent's connection, not an API key | Write on stacks, scoped to the one environment, to redeploy or update | built 2026-11-20, not lab-tested (`97c9fde`); there is no read-only token without an enterprise key, which is a finding |
| **Portainer** | Environments, stacks, containers | An access token for a dedicated user, which carries that user's rights: a read-only role (Business), or a standard user given only the environments it should see (Community). Never the admin's token | A role that may manage stacks, on the one environment | built 2026-11-20, not lab-tested (`1003005`); a Community Edition user is a finding; Kubernetes environments are not read |
| **Komodo** | Servers, stacks, deployments, builds | An API key and secret for a dedicated non-admin user with Read on the resources it should see | Execute on the stacks it may redeploy | built 2026-11-20, not lab-tested (`8f142ab`); a container is matched to its stack by name prefix |
| **Pangolin** | What the server publishes, at which domain, behind which login (exposure, section 2) | A key that only reads sites and resources, scoped to the organization | Nothing: StorageForge only reads | built 2026-11-20, not lab-tested (`6b3992c`), feeding the exposure view; no lab check (needs a public domain) |

**Not offered:** the Docker or Podman socket, or the Docker Engine API over TCP, since either is root on the host. StorageForge reads containers over SSH, and the agent has no socket (*Decisions taken*). Proxmox's `root@pam` and TrueNAS's root or `truenas_admin` keys are refused with the reason shown, not just warned about.

**Lab:** `sf-pbs` and `sf-pdm` join `sf-pve` as appliances (both are free ISOs, so they go in `images.conf` and `nodes.conf` beside it, and PDM is given `sf-pve` and `sf-pbs` as its remotes). On `sf-pve`, `sf-pbs`, `sf-pdm`, `sf-truenas` and `sf-xcp`, the guide's commands are run as written and the read-back finds the token exactly right; a token with one privilege too few fails only the feature that needs it, and says what to add; an admin token raises the security finding, which cannot be muted and leaves when the token is narrowed; a changed certificate is refused; nothing secret shows in a log or report. Dockhand, Portainer, Komodo and Pangolin as containers on a lab host, the same way.


**State on 2026-11-20:** lab tier 27 (with `sf-pbs` and `sf-pdm`) is written and has not run; its PDM token is made through PDM's API as root, since PDM documents no command for it. No action is carried out through any platform yet. **Part 2 (`825c613` to `46f7c29`):** the other six platforms and expiry; tier 27's second part is written (`tiers_api2.py`) and has not run. **Workloads UI, 2026-11-23:** Workloads shows the connection, API-only guests, and differences from SSH readings. The browser test checks the UI with fixture readings. No new lab tier for rendering; tier 27 covers the platform readers and its live run is pending. **Dockhand inventory, 2026-11-23:** Reads image and volume metadata per environment. Covered by HTTPS fixture tests; the tier 27 inventory check is written and its live run is pending. **TrueNAS snapshots, 2026-11-23:** The reader uses `pool.snapshot.query` with `SNAPSHOT_READ` on 25.10. Covered by TLS WebSocket fixture tests. The tier 27 snapshot check is written; its live run is pending.

## 14. Key enclave

Decided 2026-11-16: the vault's keys get one more layer. Today the KEK is derived from `STORAGEFORGE_VAULT_SECRET` inside the web app's process, and keys are decrypted there into `mlock`ed buffers ([security](docs/security.md#key-vault)). Python cannot promise no other copy exists, and whoever takes over the app's process can read its memory. The enclave moves the KEK, and every operation that needs a plaintext key, into a micro VM that is as small as it can be and has no way to reach a network.

```text
web app ──vsock, one request at a time──► key enclave (micro VM): KEK, private keys, audit MAC key
web app ◄──signatures, unwrapped secrets on approved requests only──┘   no NIC, no disk it can write, no shell
```

**What it protects against:** a taken-over web app, a SQL injection, a memory dump of the Python process, a stolen database or backup. The attacker gets ciphertexts and a vsock socket that answers a few narrow questions, under limits, with every answer in the audit log. **What it does not:** root on the controller's host can read a VM's memory. AMD SEV-SNP or Intel TDX would close that, and is an option for hardware that has it, not a promise. The docs and the UI say this plainly.

| Item | What | Status |
| :--- | :--- | :--- |
| **The VM** | Firecracker, or Cloud Hypervisor where Firecracker is unavailable. Both have minimal device models. The VM's only devices are vsock and a read-only initramfs. **No network device at all**: not a NIC blocked by a firewall, but none attached, so there is no internet, no LAN and no route to anything. No block device it can write, no shared folder (no virtio-fs or 9p), no balloon device, no serial console it reads input from. Memory is locked on the host side and never swapped; no core dumps | begun 2026-11-18: `enclave_vm.Supervisor` boots the image under QEMU's `microvm` with vsock as its one device (no network card, disk, shared folder, balloon or monitor), under QEMU's seccomp sandbox and with none of the server's environment. Since 2026-11-18 Firecracker runs it where it is installed (the owner's decision: Firecracker in the shipped image, QEMU for development and the lab), with `--no-api`, its own seccomp filter and nothing but `/dev/kvm`; the guest's vsock is a socket file in the runtime folder (`fc:PATH:PORT`). Not the jailer: it needs root, which the server's container does not have. Open: memory locked on the host side, the lab |
| **The image** | A kernel built for this alone: no modules (`CONFIG_MODULES=n`), no IP stack (`CONFIG_INET=n`, keeping only what vsock needs), no USB, no filesystems but the initramfs, lockdown on. PID 1 is one static program and the only file of note: no shell, no busybox, no package manager, no other user, no `/bin`. Built reproducibly in CI from pinned sources, scanned, signed with the release key, its hash recorded, so anyone can rebuild it and get the same bytes. x86-64 and arm64 | begun 2026-11-18 (`9b4223e`): `enclave/image/build.sh` builds it (Linux 6.18.64 on `tinyconfig`, 1.1 MB; an initramfs of one static file, 377 KB) from a compiler image pinned by digest and a kernel pinned by checksum, and two builds gave the same kernel bytes. It boots under QEMU's `microvm` with vsock as its one device and passes every enclave test there (`test_enclave.EnclaveImage`); as PID 1 it locks its memory or stops. Open: the CI build, the scan, the signature, arm64, and Firecracker in place of QEMU |
| **The protocol** | vsock only, one request at a time, a small fixed set of operations, each schema-checked and size-limited: unlock, lock, sign with key K, serve key K to an `ssh-agent` session, wrap and unwrap a DEK, compute and check the audit MAC, release secret S for plan step P, make and rotate a key. No operation exports a private key. Parsing is linear in the input, and a malformed request ends the session | begun: the program (`storageforge-indexer/enclave`, Rust) answers `status`, `unlock`, `lock`, `sign`, `generate` and `mac` over vsock or, for tests, a socket file; framed, size-limited, a malformed request ends the connection and five lock it down. Since 2026-11-18 also `import`, `seal`, `release`, `rotate-begin`, `rewrap`, `rotate-commit` and `rotate-abort`. Not yet: step-up, and a release bound to a named step and host |
| **SSH keys stay inside** | The controller's `ssh` talks to an `ssh-agent` socket that the enclave serves over vsock, for one task and with a lifetime, as the per-task agents do today. The private key signs inside the VM and never reaches the web app's memory | begun: `enclave.agent()` serves an agent socket for one key and one task, lists the public key and asks the enclave for each signature; tested with the real `ssh-add` and `ssh-keygen`. Since 2026-11-18 every task uses it when `STORAGEFORGE_ENCLAVE` is set: `Vault.decrypt_key` returns the row and the enclave's address instead of a key, and `runner.ephemeral_agent`, which scans, deploys, sends, the console, rotation and network devices all call, serves the socket from it. Open: the lab run |
| **Signing keys stay inside** | The agent's manifest key (11.1), the scan signing key's private half where the controller holds it, the StorageForge network's keys (2.1), the SSH CA (section 2) and the operator's catalog key when the operator chooses to keep it here rather than offline (section 4) | begun 2026-11-18: the deploy signing key signs requests and evidence bundles inside (`deploy._signer` returns a signer that asks the enclave), verified with `ssh-keygen -Y verify`. Open: the release key and plugin signatures, which do not exist yet |
| **Secrets that must leave** | A secret for a plan step, or an API token (section 13), has to reach whatever uses it. The enclave releases it only for a named request (this secret, this step, this host, or this platform), at most at a set rate, and logs each release. Releases of a secret marked sensitive need the step-up checked inside the VM (below) | begun 2026-11-18: device passwords and step secrets are sealed inside and released one request at a time, counted, at most 60 a minute for any one secret; what was sealed as a key cannot be released. Open: the release bound to a named step, host or platform, and each release in the audit log from inside |
| **Step-up checked inside** | For the operations that matter most (making or rotating a key, releasing a sensitive secret, unlocking), the enclave checks the re-authentication itself: the FIDO2 assertion against a public key it holds, or a password hash it holds. A taken-over web app cannot forge it | open |
| **Its own limits** | Rate limits per operation and per key, a ceiling on releases per hour, and a lock-down after repeated bad requests that only a person unlocking again lifts. The limits live inside, so the web app cannot change them | begun: unlocks 6 a minute, signatures 600 a minute per key, releases 60 a minute per secret, one request at a time, a 1 MiB frame, five malformed requests lock it down; `status` gives the counts. Open: alerts from the counts, limits per kind of task |
| **The audit log's key** | The MAC key never leaves; the enclave computes and checks the chain's MACs, and keeps the latest chain head, so truncating the log in the database is caught even by an attacker who holds the database | begun 2026-11-18: with the enclave configured the MAC key is never in the web app; `AuditLog` asks for each MAC, and a chain written partly by each side verifies from both. Open: the enclave keeping the chain head |
| **Unlock** | The vault secret goes into the enclave over vsock at start and is held only there: never in the web app's environment, which today it is. From the existing secret file, read once by a starter that then forgets it, or typed by a person at unlock. Sealing it to the host's TPM is an option | begun 2026-11-18: the first `Vault.unlock()` hands the secret to a locked enclave and later ones need none, so a web app without the secret works. A locked or absent enclave is a locked vault, with no fallback. Open: the starter that reads the secret file once and forgets it, typed unlock, and taking the secret out of the web app's environment. Since the remaining operations moved inside the web app never opens the KEK |
| **Stateless and restartable** | Ciphertexts stay in the database as today. A restarted enclave holds nothing until unlocked again. The VM is started and watched by the controller's supervisor; if it stops, operations that need keys fail closed and the notification center says so | begun 2026-11-18: `STORAGEFORGE_ENCLAVE=vm` has the server start and watch the VM, and the server does not start without it. A VM that stops is logged and audited (`enclave.down`), started again at the same address with a growing delay, and holds nothing until unlocked; in between every key operation fails closed. Only an image whose files match `SHA256SUMS` and the pinned digest is started, and not a different one after a crash. A stopped, locked or locked-down enclave is a `security-enclave` notification, which cannot be muted. Open: the lab |
| **Where it runs** | Beside the controller, through `/dev/kvm` passed to the container, with Firecracker's jailer (its own uid, chroot, seccomp, cgroups). On a host with no KVM (a VPS without nested virtualization), the vault works as today and the UI and the security view say the extra layer is not there | begun 2026-11-18: the runtime image holds Firecracker and the enclave image (built by the same script as `build.sh`, same `SHA256SUMS`), and `docker-compose.enclave.yml` passes `/dev/kvm` and its group to a container that stays unprivileged; run that way here, it unlocked, signed, and came back locked after a kill. A command that needs a key starts an enclave of its own. Open: the label in the UI and the security view where it is off, the jailer (needs root), the lab |
| **The migration** | Moving the vault's KEK and keys under the enclave changes nothing in the stored ciphertexts' format if it can be avoided; where it cannot, it is a migration with a way back, and a major checkpoint before it runs | none is needed for what is built: the enclave holds only the KEK and is handed the vault's own ciphertexts with each request, so nothing stored changes. A unit test has a key made inside read by today's vault, and keys the vault made signed with inside |

**State on 2026-11-20 (built, not lab-tested; merged from `999c54e` to `3658292`):** the starter and typed unlock, step-up checked inside, releases bound to a step, host or platform and written to the audit log from inside, the chain head kept, limits per kind of task with notifications, the label where the enclave is off, the CI build with comparison, signature and arm64, and of the layers below the second lock (file share; no TPM), the Noise channel, scheduled rotation and the 30-second route codes. Migration 046 changes no stored ciphertext; a secret given a policy and `vault second-lock on` write what 0.5.4 cannot open, and each has a command that undoes it. Lab tier 19 is written and has not run. **Open:** TPM sealing, the jailer and host-side memory locking (need root), arm64 under KVM, a real FIDO2 token, step-up for background threads, a page for secret policies, a schedule for SSH key rotation, the Dockerfile stage checking the recorded hashes, CI signing (waits for the owner's release key as the secret `STORAGEFORGE_RELEASE_KEY`), the image's own findings, and the off-machine backup copy, which fails when the vault secret is kept apart from the server.

### Layers (the owner's direction of 2026-11-18)

The enclave is the second layer on the keys. These are the rest of that direction, each a layer that still holds when the one before it fails.

| Item | What | Status |
| :--- | :--- | :--- |
| **A second lock on the KEK** | The KEK comes from the vault secret alone today. A second share held only by the enclave's host (sealed to the TPM where there is one, a root-only file where there is not) is mixed in, so the secret alone, or a stolen database and its backup with the secret beside them, opens nothing on another machine. Optional, with a recovery share printed once | open |
| **The app speaks to the enclave over a channel of its own** | vsock is local to the host, but a taken-over neighbour on the host should not read it: each connection is keyed (a Noise handshake against the enclave's static key, pinned at first start), so what crosses is encrypted and the app knows it is talking to its enclave | open |
| **Keys that rotate by themselves** | What can rotate cheaply does, on a schedule: the session-signing secret, the enclave's session tokens, job keys per run (as sends already do), the agent tunnel keys (0.5.7), and the KEK by rewrapping DEKs, which never touches a key's ciphertext. SSH keys rotate through the existing `rotate` plan, on a schedule the operator sets. A rotation that fails says so in the notification center | open |
| **Sensitive routes that move** | A sensitive request (vault, keys, deploys, the console, step-up) carries a code that changes every 30 seconds, derived from a per-session secret and the route, and is checked on the server, for the highest operations inside the enclave. It can ride in the path, as a 2FA code does, so a recorded or guessed URL is dead in half a minute. What it is worth: it binds a request to a live session and a moment, on top of the session cookie, CSRF check and fresh-password rule that already do. What it is not: a secret path is not a defence against someone who already runs code in the app, and the docs say so | open |
| **The image's own findings** | A finding with no fix published is rebuilt the day one is, and until then listed with what reaches it. 0.5.4's ten (OpenSSL 4.0.3-r8, Python 3.14) are in that state | open |

**Lab:** the enclave boots on the controller in the lab and every SSH task, deploy, `vault send-secret` and audit verify works through it. From inside the VM there is no network interface to list and nothing to reach. A private key is never found in the web app's memory, read with a debugger during a task. A taken-over web app (simulated by calling the vsock socket directly) cannot export a key, exceeds its release rate and is refused, and cannot release a sensitive secret without a step-up the enclave checks. The enclave killed: key operations fail closed and a notification opens. A host without KVM: today's vault, labelled. The image rebuilt from source gives the same hash.

## Will not be built

A shadow-copy trap on the Samba server (the deletion runs on the Windows client and never crosses SMB; the client-side tripwire is in section 11), cryptographic shred, compliance certificates, a *SECURE* banner and a WebSocket event stream, because they can't work or would claim too much: see [ransomware defense](docs/ransomware-defense.md). It isn't a replacement for NetBox, LibreNMS or Zabbix. The UI adds no framework, build step, CDN or third-party script, no telemetry about how it is used, no mobile-first redesign and no dashboard builder.

This list used to say StorageForge stays agentless and builds no live log viewer, and that the VSS trap cannot work. The first was changed by the decision to build an optional agent, and the second holds only for the server: see *Decisions taken*.
