# Roadmap: 0.7.0

0.7.0 has one theme: **features that do the same job share one backend.** StorageForge grew to 0.6.0 one feature at a time, and many features brought their own copy of something another already had: a parser, a quoting rule, a script fragment, a table of names. A copy that drifts is a bug in one feature and not its twin, and the survey behind this page found ten of those. This page lists what gets combined, in what order, and what stays apart on purpose.

It was written on 2026-11-26 from the [backend consolidation survey](docs/audit-2026-11-26-backend.md) of `a9bdc3a` (0.6.1), which holds the evidence for every item: the lines of each copy, what a second reader corrected, and the first commit it named. [roadmap.md](roadmap.md) is still the ledger of the features 0.6.0 built and of what in them is *not lab-tested*. Nothing here adds a feature.

## How to read this

An item is `BE` and a number. Each was found either as a **bug in one copy** or as a **duplicate**. **Fix** (a bug in one copy) means the item changes what StorageForge does, because one copy was wrong: its changelog line says what changed for the user. **Duplicate** means the item was found as a plain duplicate with no bug in it. It may still leave every caller with the best copy's behaviour (see rule 1). The **Status** cell is the ledger: whoever finishes an item writes the commit that finished it. There are no time estimates on this page.

## Rules for the release

1. **Combining may improve behaviour, and stays backwards compatible** (the owner, 2026-11-26). Where copies differ, the shared code takes the better behaviour for every caller: the stricter check, the clearer message, the retry or the lock wait one copy had and the others lacked. It need not reproduce each copy byte for byte. What must keep working is what others depend on: a saved plan, schedule or design still loads and runs, an API route keeps its path, its fields and its status codes, a CLI command keeps its name and flags, a stored format is read as before, and a script already deployed on a host keeps working with the controller. A difference that is there on purpose (a security check, an error type a caller catches) stays. Every behaviour that changes gets a changelog line saying what changed.
2. **What lands on a host stays whole** ([Concepts](docs/concepts.md#the-rules), rule 16: what StorageForge makes outlives it). Code is shared in the controller, where scripts are generated. A generated script, unit or job still carries every helper it uses, and none gains a call to the controller, a file another script installed, or a library on the host that it needs in order to work. Two scripts may be built from one kit; they don't come to depend on each other.
3. **A fix is its own commit,** apart from the consolidation that exposed it, with a test that failed before it.
4. **Old names stay where tests or other modules use them,** as a one-line alias to the shared function. An alias is removed only when nothing reads it.
5. **A boundary the design keeps apart is not combined:** the agent and SSH (roadmap 11.2), the enclave, the signed deploy run, the security actions and the change engine. *Will not be combined* lists what was looked at and left.
6. **Each item passes its own tests and the light block before its commit,** and each version passes light, medium and heavy on SQLite before its tag. PostgreSQL runs where `STORAGEFORGE_TEST_PG` is set, and a version that was not run there says so in its changelog.
7. **No item here is lab-tested until 0.7.0's lab run.** Versions before it ship as *built and unit-tested*. The items that change a generated script (0.6.2's BE-03, BE-04 and BE-09, and 0.6.4 and 0.6.8) are the ones the lab has to prove.
8. The version, the changelog heading and the tag come last. Signing the tag and pushing are the owner's.

## Versions and checkpoints

The order goes from what is wrong today, to the small shared pieces everything else stands on, to the larger merges, with the riskiest last. Every version ends releasable. Checkpoints are as in [roadmap.md](roadmap.md#versions-and-checkpoints): a minor checkpoint is a commit, a major checkpoint stops and tells the owner.

| Version | Theme | Minor checkpoints, a commit each | Major checkpoints |
| :--- | :--- | :--- | :--- |
| **0.6.2** | What the survey found broken | BE-01 to BE-10, in the table below | The release · tell the owner of BE-01, BE-03 and BE-10, which are security fixes |
| **0.6.3** | Shared primitives | BE-11 to BE-34, in the table below | The release |
| **0.6.4** | One script kit | BE-35 to BE-47, in the table below | The Ansible exports compared before and after, each difference named · the release |
| **0.6.5** | Platform APIs, network devices and the Toolbox | BE-48 to BE-58, in the table below | The API connection kind is a security boundary: BE-48 and BE-49 before they merge · the release |
| **0.6.6** | Hosts, keys and credentials | BE-59 to BE-66 and BE-84, in the table below | BE-59, BE-61 and BE-62 each, before they merge: every private key and the KEK rotation pass through them · the release |
| **0.6.7** | Plans, jobs, alerts and routes | BE-67 to BE-75, in the table below | BE-73 changes who is notified and when · the release |
| **0.6.8** | Shares, archives and quarantine | BE-76 to BE-80, in the table below | The lab run of the share and archive tiers, since generated scripts change · the release |
| **0.6.9** | The Rust programs and the secure channels | BE-81 to BE-83, in the table below | Each of BE-82 and BE-83 is a security boundary and changes a signed image: the owner decides whether they are done at all · the release |
| **0.7.0** | The release | The audit of everything since 0.6.1, to the audit rules, and its bugfix round, a commit per finding · the full unit suites on SQLite and PostgreSQL · the full lab, since generated scripts changed in 0.6.4 and 0.6.8 | The audit's findings · the lab results · the release |

## 0.6.2: What the survey found broken

| Item | What is combined | Found as | Status |
| :--- | :--- | :--- | :--- |
| **BE-01** | A certificate that changes, or a connection that loses its pin, in the middle of a platform read stops the read for every platform. Today six readers record it as a skipped line and store the rest as a good reading | Bug in one copy | `48c877f, 3ae46a5` |
| **BE-02** | A Xen Orchestra host with no address is no longer matched to whichever scanned host has no address either | Bug in one copy | `f2e3324` |
| **BE-03** | An NVMe over TCP share formats a disk only when `blkid` says it is blank (exit 2), as iSCSI and NBD do. Today any probe that prints nothing, a read error included, is taken as blank | Bug in one copy | `6e78500` |
| **BE-04** | The tunnel, overlay, restore-test and Toolbox steps reload systemd through `reload_systemd`, so a dead hard NFS or CIFS mount can't make them block logins | Bug in one copy | `1874de7, 6661c77, 723db68` |
| **BE-05** | A network scan left `running` by a restart is closed as interrupted at start, as deploys, change runs and file scans are | Bug in one copy | `53e3154` |
| **BE-06** | One host's malformed agent manifest no longer stops the agent's disk, file and scan alerts for every host | Bug in one copy | `219a0c9` |
| **BE-07** | Retiring a host removes everything it owns: its security readings, ban history, graph snapshots, waivers, retention policies and per-host settings are left behind today. A test lists every table with a host column and fails when retire names neither it nor an exception | Bug in one copy | `3a53dee` |
| **BE-08** | A workload managed through a platform API is named by the platform's title (Portainer), as label evidence names it, not by the connection kind (portainer) | Bug in one copy | `55a5253` |
| **BE-09** | A plan run as root with `SF_SECRET_DIR` set delivers a secret to the folder its steps then read. Today delivery uses the fixed folder and the tunnel and overlay steps read the variable's | Bug in one copy | `8a1ff66` |
| **BE-10** | A stored secret can't silently replace a credential of another kind that holds the same name: `secret-add`, `headscale-key` and the device-credentials route check first, and a re-sealed secret keeps its policy | Bug in one copy | `75d743c` |

## 0.6.3: Shared primitives

| Item | What is combined | Found as | Status |
| :--- | :--- | :--- | :--- |
| **BE-11** | One splitter for the `@@section` output of host and device scripts (netfacts, OpenWrt, pfSense, the infrastructure reading) | Duplicate | `f58c306` |
| **BE-12** | One module for SSH wire strings and key fingerprints, in place of copies in eight modules. Signature checking keeps its own refusals | Duplicate | `0ff1819` |
| **BE-13** | One reader of a host's pinned keys in `known_hosts`, in place of four `ssh-keygen -F` parsers | Duplicate | `d239985` |
| **BE-14** | One pair of functions for *is this path under that folder* and *which mount holds this path* | Duplicate | `9ca05b4` |
| **BE-15** | One fstab octal decoder, and the design versions' size text from `capacity.fmt_bin` | Duplicate | `f8f70d7` |
| **BE-16** | One module for reading platform JSON answers: the envelope loaders, list filters, bounded scalar readers and date normaliser copied in eight API modules | Duplicate | `2881207` |
| **BE-17** | The three Proxmox readers share one version parser | Duplicate | `0a6eb05` |
| **BE-18** | One parser for the *ports to publish* text, with one record shape, behind the what-if, the Terraform export and the firewall step | Duplicate | `31a11d7, a5537bf` |
| **BE-19** | One function hides a network-language secret in compiled output | Duplicate | `2d60e83` |
| **BE-20** | The folder fingerprint's hash terms are written once, for the per-mount index and the per-subtree compare | Duplicate | `e5608df` |
| **BE-21** | One query lists the first-level folders under a path with their sizes, for Moves and the file map | Duplicate | `9d6e01e` |
| **BE-22** | One `ufw` opener for the NFS and SMB script and the other share kinds | Duplicate | `ab15e7e` |
| **BE-23** | SQLite-or-PostgreSQL spellings (`ts`, `jsonp`) live on the connection, and the agent's writes into scan tables stop calling `Database.sync_mounts` with a stand-in for `self` | Duplicate | `2592286` |
| **BE-24** | One function for a host's short name, and one host-name pattern | Duplicate | `8bf734f` |
| **BE-25** | One reader of a host's JSON-lines run log, for confirmations, jobs and schedules | Duplicate | `474e70f` |
| **BE-26** | A test reads the protocol constants written once in Python and once in Rust and fails when they differ | Duplicate | `c55651b` |
| **BE-27** | Kernel lines from netconsole and pstore are built by one `hostlogs` function, and the side-source status row is written in one place | Duplicate | `edce31d` |
| **BE-28** | The agent's record queue has one *forget these records* and one batch size | Duplicate | `f6b5634` |
| **BE-29** | The Proxmox steps share their VMID lookup and their new-VMID check | Duplicate | `ac4f3d7` |
| **BE-30** | One function returns all containers of a host (scan stacks and rootless Podman), for Workloads and the Toolbox adapters | Duplicate | `971cd24` |
| **BE-31** | One place answers *which plugins does a host's manifest name*, and the label `reported by agent` is defined once | Duplicate | `bea7b58` |
| **BE-32** | One function turns a typed host name into the scanned host, behind the three known-host checks, each keeping its own error | Duplicate | `da40044, a8a377b` |
| **BE-33** | One lookup for *the interface that carries this address*, and one list of the controller's addresses | Duplicate | `d0f1c36` |
| **BE-34** | The device adapters take their gateway list and their mask-to-prefix from `netfacts` | Duplicate | `bcc78c9` |

## 0.6.4: One script kit

| Item | What is combined | Found as | Status |
| :--- | :--- | :--- | :--- |
| **BE-35** | One builder for the Ansible task that runs a step's Bash function (`shell_task`, `bash_fn`, `words_of`), in place of about 27 copies. | Duplicate | `70d7354, 119b7ce` |
| **BE-36** | One builder for the head of those tasks, used first where the heads are already identical | Duplicate | `6f4ddda` |
| **BE-37** | Every destructive step's Ansible export carries the destructive gate. Some exports have none today, because each module writes its own | Bug in one copy | `fd4edba` |
| **BE-38** | One definition of the secrets folder and the secret-name rule, and one Python check for a step's `secret` field | Duplicate | `4e7ea02` |
| **BE-39** | One checked download for VM images: `os-install` and `vm-iso` call `sf_vm_fetch` instead of carrying its body | Duplicate | `05a5a72` |
| **BE-40** | One reading of a scan's package list, and one table of package names per package manager for the generated scripts and the reinstall plan | Duplicate | `67c9a7f` |
| **BE-41** | The share drivers take their *make the share folder* step from the driver helper set | Duplicate | `7d4bdfa` |
| **BE-42** | The rclone-served share kinds share their secret-key list and their mount report | Duplicate | `90f31f3` |
| **BE-43** | One compression codec table for Moves, the job program and the archive step | Duplicate | `9aa3872, a15ac1b` |
| **BE-44** | One Bash kit for what Moves, `storageforge-job` and the archive step all carry: the idle wrapper, the rsync compression probe and the compress-and-verify command | Duplicate | `c0e9edd` |
| **BE-45** | One function stages tasks as a named change plan, with the clash rule chosen by the caller | Duplicate | `101b5f9` |
| **BE-46** | One function forgets a deployed unit's mark, and one connection helper for the after-deploy hooks | Duplicate | `83a7e42` |
| **BE-47** | The Ansible export of `md-array` runs the step's own Bash function instead of a second implementation of it | Bug in one copy | `bfe893e` |

## 0.6.5: Platform APIs, network devices and the Toolbox

| Item | What is combined | Found as | Status |
| :--- | :--- | :--- | :--- |
| **BE-48** | One platform registry and module contract, so Proxmox VE, PBS and PDM stop being a special case beside the six registered platforms | Duplicate | |
| **BE-49** | One guarded reading loop for every platform reader (the collector behind BE-01), with one way to count a capped list | Duplicate | |
| **BE-50** | The read-back's token notes (disabled, no expiry, expired) come from one helper | Duplicate | |
| **BE-51** | One resolver from a platform's node, environment or site to the scanned host it is, without a query per object | Duplicate | |
| **BE-52** | One table of container panels (name, image pattern, label prefixes, unit names, API kind) in place of four partial lists | Duplicate | |
| **BE-53** | The OpenWrt and pfSense appliers share one rollback-timer base | Duplicate | |
| **BE-54** | The SSH password environment and options are written once, and `netdevice.session` builds its transport from one table | Duplicate | |
| **BE-55** | A what-if over a firewall lays the new rules onto the machine's real chains the same way for a device change and for the planner | Bug in one copy | |
| **BE-56** | Exposure classifies VPN interfaces with the overlay naming table, by name only: a WAN address behind carrier-grade NAT stays WAN | Bug in one copy | |
| **BE-57** | One adapter kit for the Toolbox's container, unit and program adapters, in place of three sets | Duplicate | |
| **BE-58** | One permission gate for staging a tool, a bundle and a role profile, and a refused staging is audited on all three | Bug in one copy | |

## 0.6.6: Hosts, keys and credentials

| Item | What is combined | Found as | Status |
| :--- | :--- | :--- | :--- |
| **BE-59** | One vault-key signer behind deploys, the agent, SSH certificates and overlay keys | Duplicate | |
| **BE-60** | One builder of the operator-login SSH command for `send-secret`, `nebula-issue` and `headscale-key` | Duplicate | |
| **BE-61** | One *log in with a named vault key* helper for rotation, key install and sudo access | Duplicate | |
| **BE-62** | The KEK rotation walks its sealed tables from one list, for the local vault and the enclave | Duplicate | |
| **BE-63** | Remembering a host key a person confirmed is one function for the Keys page and monitoring-only adoption | Duplicate | |
| **BE-64** | The name rules copied between modules (secret name, Unix login, machine id, hex digest) are defined once | Duplicate | |
| **BE-65** | `security.py` and `secplus.py` share a host-action module instead of one reaching into the other's private functions | Duplicate | |
| **BE-66** | One store for host readings (security, infrastructure, device, package), in place of raw SQL in ten modules | Duplicate | |
| **BE-84** | Removing a device credential by name can no longer remove a step secret or an API connection's token: the remove route checks the kind, as storing does since BE-10 | Bug in one copy | |

## 0.6.7: Plans, jobs, alerts and routes

| Item | What is combined | Found as | Status |
| :--- | :--- | :--- | :--- |
| **BE-67** | One named-plan store behind move plans, change plans and storage tasks, each keeping its own errors | Duplicate | |
| **BE-68** | One table of deployable kinds replaces the if-chains over deploy kind in the server and over task type in the scheduler | Duplicate | |
| **BE-69** | The route modules take *audit and answer* and the script download from the shared route context | Duplicate | |
| **BE-70** | Deployed jobs and imported snapshot jobs share their listing parser and their after-action update | Duplicate | |
| **BE-71** | The controller's restart clean-up and its periodic loops are started from one place | Duplicate | |
| **BE-72** | Alert sources are separate functions, and one that raises no longer stops every alert from opening, resolving or being pushed | Bug in one copy | |
| **BE-73** | A failed schedule is pushed once, through the alert state machine with its mute and its history, not a second time at level `failed` | Bug in one copy | |
| **BE-74** | Queries that list their columns twice use one connection method that returns dictionaries | Duplicate | |
| **BE-75** | The forty places that print a moment as `YYYY-MM-DD HH:MM` use one function that says which clock it is | Bug in one copy | |

## 0.6.8: Shares, archives and quarantine

| Item | What is combined | Found as | Status |
| :--- | :--- | :--- | :--- |
| **BE-76** | The Ansible exports of the partition, wipe, secure-delete and archive steps run the steps' own Bash functions | Bug in one copy | |
| **BE-77** | The three rclone-served share kinds write their serve unit and login file through `rclone.LIB`, each unit's text unchanged | Duplicate | |
| **BE-78** | The three block-disk share kinds share the sparse image file, the blank-disk decision and the one-client rule | Duplicate | |
| **BE-79** | One file quarantine for ClamAV detections and threat kills. The threat copy gains the resolved-path check it lacks today | Bug in one copy | |
| **BE-80** | One package-manager layer in the generated scripts: detect, wait for the lock, retry the update, install | Duplicate | |

## 0.6.9: The Rust programs and the secure channels

| Item | What is combined | Found as | Status |
| :--- | :--- | :--- | :--- |
| **BE-81** | The agent's plugin programs take their bounded file read, disk list, clock and hex from the agent library | Duplicate | |
| **BE-82** | The two Python Noise implementations (the agent tunnel and the enclave channel) share one symmetric state, cipher and framing | Duplicate | |
| **BE-83** | The enclave takes its Noise primitives from the `wire` crate instead of its own copy | Duplicate | |

## 0.7.0: The release

| Item | Status |
| :--- | :--- |
| The audit of everything since 0.6.1, to the [audit rules](notebook/Audit%20rules/Audit%20rules.md), and its bugfix round | |
| Every alias left by rule 4 that nothing reads any more is removed | |
| The full unit suites on SQLite and PostgreSQL | |
| The full lab, every tier | |
| The release, with every *not lab-tested* label listed in the notes | |

## Decisions still open

| Decision | Needed for |
| :--- | :--- |
| Whether 0.6.9 is done at all. The two Noise implementations and the enclave's own copy of the primitives are real duplication, but they sit on the channels that carry the vault's secrets, and the enclave's image is signed and reproducible: a changed dependency changes its digest. The survey's records for them were not checked by a second reader | BE-82, BE-83 |
| Whether the CLI and the web should audit and check the same things. They differ today (three actor formats, the web audits saves and the CLI doesn't, the web's clone save checks accepted risks and the CLI's doesn't). The survey refused to merge them without a decision on which is right | Not on this roadmap until decided |
| What retiring a host does with the 31 tables that still hold its name. BE-07 removed what the roadmap named and lists the rest in `retire.KEPT`, each with a reason that starts *not decided*: the agent's tables, alerts, host logs and their counts, saved host configs, task runs, notification history, playbook runs, traffic samples, scan signatures, host checks, secret deliveries, SSH CA hosts, workload captures and four Toolbox tables. Retire can't be undone, so each needs a yes (removed with the host) or a no (kept as history) | Retire removing them |
| Unified designs, [roadmap.md](roadmap.md) step 3i. The survey found the two design stores again and left them: they wait on the answers in section 10.1 and a stored-format migration | Not on this roadmap |

## Will not be combined

Looked at by the survey and left apart, each for the reason given. The [survey](docs/audit-2026-11-26-backend.md#looked-at-and-left-apart) has the full reasoning.

| Left apart | Why |
| :--- | :--- |
| Proxmox guests, storage and datastores reach the map, the Workloads list and the comparison through the same reader hooks every other platform uses | Proxmox guests join by VMID across a cluster and across PDM, the other platforms by host, name and runtime. One hook shape can't carry both |
| One 'API beside SSH' comparison builder (outer join by key, seen_by, differs, why) in place of five per-platform loops | The five *API beside SSH* comparisons share words, not structure: a shared builder would need a parameter per line |
| HTTP and WebSocket clients share one admission gate (closed, read-only, budget, rate) and TrueNAS results stop being serialised to text only to be parsed again | The HTTP and WebSocket admission checks sit on the read-only boundary and count differently on purpose (per attempt against once) |
| What a device platform is lives in five places (PLATFORMS, APPLIERS, CLI PROFILES, emitter targets and if-platform branches); make it one registry entry per driver | The five platform tables are keyed by different things (prompt profile, emitter target, applier) and are not copies of one |
| A device reading and a host scan each write host_network and traffic samples with their own SQL | Two lines of SQL, inside two different transactions |
| Untrusted XML from a device or a scan is guarded by three separate loaders with different rules | Three XML loaders that differ in every parameter a shared one would take |
| The DSL's Linux targets (nftables, iptables, firewalld, ufw, networkd, NetworkManager) are preview-only emitters in Python, while what is actually deployed to a Linux host is written by separate bash writers in the plan steps | Not a duplicate: the network language's Linux targets are previews, and the plan steps are what is deployed. They are two products |
| NFS and SMB are hard-coded in shares.py beside a driver registry that serves the other nine kinds; make them the first two drivers | NFS and SMB are aggregate (one exports file, one smb.conf for all shares) where the driver kinds are one unit per share. The split is the design |
| rclone.LIB carries its own package installer and its own vault-secret path lookup, parallel to scriptkit.PACKAGES and netshares' secret helper | `rclone.LIB` runs in three scripts, one of which carries no package table: sharing would add code |
| Security hardening actions go through the plan steps that already exist, instead of a second set of one-off scripts | Security actions run through the audited, signed security path and plan steps through the change engine. The boundary is kept on purpose |
| Built-in step types join the registry the other 70 use, and the side registries become fields of one step record | Moving the 36 built-in step types into the registry removes no bug that exists and touches every plan |
| One frame for the downloadable scripts: option loop shell, --host hand-off, root check, lock and log | The downloadable scripts' frames differ in almost every line |
| One reader for a host's stored inventory and its text sections, instead of each module fetching inventory_json and re-parsing a section | The inventory section parsers read different texts |
| One loader for the release's agent artifacts (agentctl, Windows agentctl, plugin descriptor, plugin program, image signature) | The agent artifact loaders load different files with different checks, and already share the folder lookup |
| Readers of the open alerts share one row shape (level, host, quiet) instead of three SELECTs with different columns | Three small reads of open alerts that differ on purpose |
| Route modules share one 'refused' mapping and one audited-write wrapper | A two-line `except` swapped for a one-line call removes nothing. The useful part is BE-69 |
| One LIKE-escaping and text-filter helper for history searches | Three lines of LIKE escaping |
| Terraform and Puppet are written twice, once from a change plan (wlexport) and once from a design (mapdesign); the design already becomes plan tasks, so one exporter can serve both | The design's Puppet and Terraform exports are safer (array-form commands) and cover more than the plan's: merging toward either loses something |
| toolbox.preview and toolbox.install_words each resolve a catalog entry for a host (entry, trust, override, method, resolved ports and bind, image verification); one resolver should feed both the preview and the script-time words | Preview and install resolve a catalog entry under different rules on purpose (unsaved rows, chosen method, trust) |
| deploy.run and deploy.raw each build the signed SSH run from scratch (refusal, readiness, nonce, vault binding, signed request, ephemeral agent, transport, deploy_runs row, audit); one session helper should own that | `deploy.run` and `deploy.raw` are the signed-run boundary and differ in nearly every argument |
| Which folders are system folders that must never be given to a container (:Z) or used as a data root is listed in five places with different contents | Five lists of system folders answer five different questions |
| One reader toolkit and one dispatch table for overlays, tunnels and access proxies | The overlay, tunnel and proxy readers differ where it counts (what counts as a blanked value, the envelope keys) |
| One issued-certificate ledger and CA front for the SSH CA and the Nebula CAs | The SSH CA and the Nebula CAs have parallel life cycles and no shared code to remove |
| One host report channel for jobs, schedules and the security sentinel: token, bearer route, host-side post and scan fallback | The host report routes are the only session-less routes, and each token check differs |
| One calendar module for cron and systemd OnCalendar parsing, period and conversion | cron and systemd `OnCalendar` are two grammars. Their one shared piece is already shared |
| One audited-operation layer so the CLI and the web write the same audit rows under one actor format | The CLI and the web differ in what they audit and check, by design in places and by accident in others: that is a decision for the owner, not a merge |
| One vault-backed SSH session context manager replaces the binding, agent and Transport setup written at each call site | The vault-backed SSH session is two to four lines per site with a different argument each time, on the path every private key takes |
| One design store and one design pipeline for the storage blueprint, the map design and saved versions (finishes roadmap 3i / section 10.1) | This is roadmap step 3i (unified designs), which waits on the owner's confirmed answers and a stored-format migration. It is not a consolidation |
| One writer for graph_nodes and graph_edges instead of graph.save (storage layer) and infragraph.rebuild (every other layer) | The storage layer and the other layers write the graph tables with different rules in almost every statement |
| One Obsidian canvas writer and one export registry for the storage graph and the map | The storage canvas writer indexes five storage kinds and can't take the map's graph |
| One table of filesystem facts: which filesystem types are network or pseudo, which mount points belong to the OS, and which mount options the kernel adds | Lists of filesystem facts that share words and answer different questions |
| One byte-size formatter and one timestamp formatter for reports, exports and comparisons | Only one of the four size formatters is a duplicate, and BE-15 takes it |
