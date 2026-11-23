# The agent

StorageForge reads and changes hosts over SSH, with nothing installed on them. That stays the base, on every host, and keeps every feature. The agent is an extra, switched on one host at a time, for what a scan cannot do: readings as they happen instead of once per scan. Routers, firewalls, switches and appliances stay agentless.

**Built, not lab-tested.** What this page describes is the agent's base (its two programs, its image, how a host is set up for it and how it is enrolled, the plugin format and the signatures), its tunnel to the controller and the receiver at the other end, the trust model they keep, wipe and stop, its first four plugins (heartbeat, logs, health and network), and from 0.5.8 the disks, files, scan and sentinel plugins, monitoring-only hosts and their console (the roadmap's sections 11.1 to 11.5). Docker is the only runtime it has run under, in the unit tests, with the real image. Podman, LXC, Incus and Proxmox VE are written and have run only against stand-ins. Lab tier 24 is written and has not run.

## How it is put together

```text
controller ──signed deploy, once──► host: accounts, one sudoers line, storageforge-agentctl, the controller's key pinned
controller ──SSH, signed requests─► storageforge-agentctl (root) ──► Docker, Podman or LXC: the agent's container
                                                                      storageforge-agent, as sfagent, read-only
agent ──its own tunnel, Noise IK, both keys pinned──► receiver (a process of its own): signed batches out; manifest and plugins in
                                                       the host's firewall lets the container reach that one address and port only
```

| Part | What it is |
| :--- | :--- |
| `storageforge-agent` | The one program in the container. Rust, static: no interpreter, no OpenSSL, no libc. It runs as `sfagent`, makes its own key, reads its manifest, and starts the signed plugins the manifest names. It refuses to run as root |
| `storageforge-agentctl` | A second static Rust program, on the host, behind the one sudoers line. It takes a signed request on stdin, does one agent operation, prints one line of JSON. It drives the runtime itself, so nobody else needs access to it |
| The image | The `agent` stage of the `Dockerfile`: Wolfi's base layout, the program, and nothing else. No shell, no package manager, 1.5 MB. The same image on every host and every runtime |
| A plugin | A static program of its own, with a signed descriptor that says what it needs of the host. It reaches the agent through the tunnel; the agent starts it as a child and speaks to it over pipes. Eight are official: [heartbeat, logs, health, network, disks, files, scan and sentinel](#the-official-plugins) |
| The manifest | Which plugins a host runs, signed by the controller with the time and a counter |
| The tunnel | One TCP connection from the agent to the receiver, encrypted and authenticated both ways with Noise IK: the agent's key is its own, the receiver's is pinned on the host |
| The receiver | `python -m storageforge_index.agentreceiver`, a process of its own beside the web app, with a database role of its own: the one place what agents say comes in |

Both programs are in one Cargo workspace with the [key enclave](security.md#key-enclave) (`storageforge-indexer/Cargo.toml`), share its framing (`wire/`), and keep its habits: every input has a size limit checked before it is read, every structure refuses fields it does not know, and what no honest peer sends ends the conversation.

## Switching it on for a host

The agent is off for every host. Nothing on this page happens to a host until someone with `keys.manage` switches it on for that host and types their password.

1. **Settings on the controller.** `STORAGEFORGE_AGENT_IMAGE` names the agent's image by digest (`registry/storageforge-agent@sha256:…`; a tag is refused, since a tag can be moved to other bytes). `STORAGEFORGE_AGENT_IMAGE_SIG` names the file with the signature of that digest (see [The image](#the-image)). `STORAGEFORGE_AGENT_DIR` is where `storageforge-agentctl` is, which the server's own image sets. For the agent to report, the [receiver](#the-receiver) runs and `STORAGEFORGE_AGENT_ENDPOINT` says where agents dial it; without them the agent runs and says nothing.
2. **Deploy access.** The host needs [deploy access](deployments.md), since the setup runs through it. A host without it is [monitoring only](#monitoring-only-hosts), set up by hand with the same script.
3. **Switch it on.** `PUT /api/agents/<host>` with `{"enabled": true}`. The answer says what the last scan knows of a runtime on that host.
4. **Install.** `POST /api/agents/<host>/install`. It returns a group id, polled as a deploy is. The steps: the setup script as a signed deploy, with `storageforge-agentctl` on its stdin; `preflight`, which reads which runtimes the host has; `enroll`, which starts the container and reads back the public half of the key the agent made; `apply`, which gives it its first manifest, with no plugin in it, and with a receiver running, the receiver's address and key, which the host pins.
5. **A host with no container runtime** is not touched further at step 4. The install stops in the state `needs-podman` with a notice that Podman will be installed with the host's own package manager. Only an install started again with `{"install_podman": true}` installs it, and then the agent runs under Podman without root.

6. **Plugins.** `POST /api/agents/<host>/plugins` with the names of plugins of the release. A plugin that declares any privilege on the host takes an admin: the `agent.privilege` permission, as well as `keys.manage` and a fresh password.

Keys → Agents lists the hosts that run the agent, in which mode, and lets someone with `keys.manage` choose each one's plugins; the files plugin is shown there as root on the host in effect, and ticking it asks again. Switching the agent on, installing and adopting have no page yet: the routes are in the [API reference](api-reference.md#the-agent).

`POST /api/agents/<host>/stop`, `start`, `restart` and `status`, and `DELETE /api/agents/<host>`, do what they say. A stopped agent stays stopped: its restart policy is taken off first, and under Podman its container is removed, because Podman starts containers with a restart policy again at boot. Removing forgets the pinned key on the controller first, then takes the container, the key, both accounts, the sudoers line and the program off the host.

## Accounts, and the one sudoers line

The setup makes two system accounts, and they are not the deploy account.

| Account | What it is for | What it can do |
| :--- | :--- | :--- |
| `sfagent` | The agent runs as it, in the container and (under Podman without root) outside | Nothing but be the agent. No login shell, no password, no sudo. The setup and every request are refused while it is in `docker`, `lxd`, `incus-admin`, `sudo`, `wheel`, `admin` or `root` |
| `storageforge-agentctl` | The controller logs in as it to manage the agent | Start one program. Its key in `authorized_keys` carries `restrict,command="sudo -n /usr/local/sbin/storageforge-agentctl"`, and sudoers has one line for it |

The sudoers line, the whole file `/etc/sudoers.d/storageforge-agentctl`:

```text
storageforge-agentctl ALL=(root) NOPASSWD: /usr/local/sbin/storageforge-agentctl ""
```

The `""` means no arguments. So the account can run that program as root with nothing on its command line, and the program acts only on a request the controller signed.

**The managing user is never in the `docker`, `lxd` or `incus-admin` group.** Whoever is in one of them can start a container that mounts `/`, which is root by another name, and then the one sudoers line limits nothing. The setup script refuses to go on while `storageforge-agentctl` or `sfagent` is in one of them, before it makes anything, and says which group and how to leave it. `storageforge-agentctl` checks the user behind `sudo` again at every request and refuses with the same words, so a user added to the group later is caught too.

## What a container is given

On every runtime, whatever the manifest says:

- the process is `sfagent`, never root, and cannot gain privileges (`no-new-privileges`)
- every capability is dropped but the ones the plugins declare
- the root filesystem is read-only (Docker, Podman, plain LXC), and the one folder it can write is its own state
- every host path a plugin declares is mounted read-only at `/host` + its path, and only that filesystem: what is mounted below it stays out
- inside those mounts, these are masked: SSH's host keys, every `.ssh` folder of an account or of a folder directly under `/home` or under the mount, `/etc/shadow`, `/etc/gshadow`, `/etc/sudoers` and `/etc/sudoers.d`, `/usr/local/lib/storageforge` (the scan signing key), `/var/lib/storageforge` and `/run/storageforge` (the verifiers' stores and secrets sent from the vault), and the agent's own folders
- no runtime's socket can be mounted, and nothing under `/dev` or `/run` but the journal's folder
- **no network at all**, unless a plugin declares the host's, or the agent has a [tunnel](#the-tunnel). Then it reaches the receiver's one address and port and nothing else

| Runtime | When | How |
| :--- | :--- | :--- |
| **Podman, without root** | The host has Podman and no plugin needs a capability or a device | `sfagent` runs `podman` itself (`--userns keep-id`), so no root runtime is involved. Not lab-tested |
| **Docker** | The host has Docker and not Podman, or a plugin needs a capability or a device | `docker run --read-only --cap-drop ALL --user <sfagent>`. Run in the unit tests with the real image |
| **Podman, as root** | A plugin needs a capability or a device and there is no Docker | As Docker. Not lab-tested |
| **LXC** | The host has LXC and neither Docker nor Podman, which is every stock Proxmox VE host | Unprivileged, from the same image: through `pct` on Proxmox VE, `incus`, or plain `lxc-create -t oci`. Podman is never offered there. Not lab-tested |
| **None** | | Podman is installed, after the user was told |

What a runtime cannot give is refused with the reason, and the agent that runs is left as it is. Under LXC that is, today: a capability or a device (an unprivileged container cannot have the host's), reading as a host group, and under Incus and Proxmox VE the host's process table or network, and any mount that would show a path that has to be masked, since they cannot mask. Under Incus and Proxmox VE the root filesystem is not read-only yet.

Privileges follow plugins. The container is made again with the union of what the manifest's plugins declare, and a plugin taken out takes its privileges with it, including the host group `sfagent` was put in for it.

**A capability is kept by giving root up.** Docker and Podman give a process that is not root no capability it can use: what `--cap-add` names lands in its bounding set and nowhere else. So a container whose plugins declare a capability is started as root (`--user 0:<sfagent's group>`) with every capability dropped but the declared ones and `SETUID`, `SETGID` and `SETPCAP`, and told whom to become (`run --as UID:GID`). Before it reads anything, the agent becomes `sfagent` in every uid and gid, keeps the declared capabilities in its permitted, inheritable and ambient sets and none in its effective set, drops the other three from its bounding set, and locks the securebits so that nothing it starts can become root again (`agent/src/caps.rs`). A bounding set with anything else in it, or a failure on the way, and it does not start. Each plugin is started with only its own declared capabilities in its ambient set. The check from outside reads the process from the host's `/proc`: a uid of root, or a capability beyond the declared ones in any set, is a finding.

## Plugins

A plugin is three files:

```text
NAME.plugin.json   the descriptor
NAME.plugin.sig    an SSH signature of the descriptor's bytes, namespace "storageforge-plugin"
NAME.plugin        the program: one static executable
```

```json
{"format":1,"name":"logs","version":"0.5.7","arch":"x86_64","sha256":"<the program's>","size":712304,"protocol":1,
 "needs":{"mounts":["/etc/machine-id","/var/log/journal"],"groups":["systemd-journal"]}}
```

The signature covers the descriptor and the descriptor names the program by its hash, so one signature covers both:

```sh
ssh-keygen -Y sign -n storageforge-plugin -f KEY logs.plugin.json && mv logs.plugin.json.sig logs.plugin.sig
```

**Who may sign.** An official plugin is signed by a release key. The release keys are compiled into both programs from `agent/release_signers`, so which code may run is decided by the build, not by the host and not by the controller. `storageforge-agent anchors` prints the keys a program was built with. An operator's own plugin is signed by a key the operator put in `/etc/storageforge-agent/operator_signers` on that host, by hand, in the same format. The controller never holds that key and has no operation that writes that file.

**What a plugin may need** is a closed list, and nothing outside it can be asked for by any descriptor or manifest, whoever signed it:

| Need | Values |
| :--- | :--- |
| `mounts` | Host paths, mounted read-only. Never under `/dev` or `/run` (but `/run/log/journal`), never a `.ssh` folder, `/etc/ssh` or one of the masked folders; `/proc` and `/sys` whole or not at all |
| `capabilities` | `DAC_READ_SEARCH`, `NET_ADMIN`, `NET_RAW`, `SYS_ADMIN`, `SYS_PTRACE`, `SYS_RAWIO`. Any of them takes a runtime that runs as root |
| `devices` | `disks`: the host's whole disks, read-only |
| `namespaces` | `net`, `pid`: the host's network, the host's process table |
| `groups` | `adm`, `systemd-journal`: host groups whose files it reads |

There is no word for a writable mount, a privileged container or a socket.

**How it runs.** The agent reads the program once into a sealed memory file, hashes it there and runs it from there, so what was checked is what runs, whatever happens to the file afterwards. The child gets an empty environment, three pipes and no other open file, cannot gain privileges, and dies with the agent. Every message is a length and then JSON, at most 256 KiB: the agent says `hello`, the plugin says `ready`, then `data` readings and `log` lines. Anything else, a frame too large, or more than 6000 messages in a minute ends the plugin, and it is not started again until the agent is.

**Resuming.** A plugin that reads at its own pace (the logs plugin) puts its place in its readings as `cursor`. The agent keeps the newest one and hands it back in `hello` when it starts the plugin again; after the agent itself starts again (a reboot), the receiver hands back the cursor of the last reading it stored, in `resume`, when the session opens. A plugin whose readings wait in the agent's outbox beyond its share (4 MiB) is not read from until the tunnel has sent some, so it waits, with the journal on disk, instead of losing lines.

### The official plugins

Built from the same Cargo workspace (`src/bin/plugin-*.rs`). `agent/plugins.sh lay` writes each program and its descriptor the way the controller serves them, and `agent/plugins.sh sign OUT KEY` signs the descriptors: the release is signed with the release key by its holder, and until then the server's image carries them unsigned and offers none. What each declares is in that script and nowhere else.

| Plugin | Declares | Reports |
| :--- | :--- | :--- |
| `heartbeat` | nothing | `beat` every 10 seconds. While the tunnel is down beats wait in the outbox with their own times, so afterwards the controller sees the agent was alive and cut off. While it is up, its silence is a notification within seconds |
| `logs` | `/etc/machine-id`, `/run/log/journal`, `/var/log/journal` read-only; the `systemd-journal` group | `lines`: the journal as it is written, read from the journal files themselves (regular or compact, zstd or LZ4), up to 200 lines a reading, with the fields a scan collects (never `_CMDLINE`) and journalctl's own cursor, so a line pushed and the same line scanned are one. Debug lines are left out and said, so they are not taken for lines deleted on the host. See [host logs](web-ui.md) |
| `health` | `/proc` and `/sys` read-only; the host's process table | `health` every minute: CPU, load, memory, pressure, disk latency and how busy each disk is, md arrays with their rebuilds, ZFS pool states, btrfs allocation, uptime. `ssh` within ten seconds of a change: whether sshd runs and the ports the host listens on, so the agent says when SSH is down |
| `network` | the host's network | `shares` within five seconds of a change and every minute: who is connected to SMB (139, 445) and NFS (2049), who came and who went. `traffic` every minute: each interface's counters and rates |
| `disks` | the whole disks read-only, `SYS_RAWIO`, `/sys`, the journal folders and `/etc/machine-id` read-only, the `systemd-journal` group | `smart` at start and hourly: each disk's health, asked of the disk itself with the ioctls smartctl uses (ATA pass-through, the NVMe health log) and written in the shape `smartctl -j -a` prints, so the controller reads it with the SSH collector's own parser (PF-04) and compares the two. `errors` as they happen: the kernel's count of a disk's failed commands, md's errors per member, and the kernel's lines that say a disk failed |
| `files` | **root on the host in effect:** `SYS_ADMIN`, `SYS_PTRACE`, `DAC_READ_SEARCH`, the host's process table, `/proc` read-only | `changes` every five seconds: each file created, written, moved or deleted on the host's local filesystems, with the process and account that did it, and its size and time where it is still there. `reads` every minute: files read per account and the folders they were in. `watching`: which filesystems it watches and which it could not. See [The files plugin](#the-files-plugin-root-in-effect) |
| `scan` | the host's root, `/proc` and `/sys` read-only, the process table; no capability | `inventory` at start and every fifteen minutes: the read-only scan it carries, in parts. See [Scans carried in the plugin](#scans-carried-in-the-plugin) |
| `sentinel` | the journal folders and `/etc/machine-id` read-only, the `systemd-journal` group | `events` within two seconds: the [sentinel](security.md)'s events, which it writes to the journal as root as well as to its own file. Only lines root wrote under the name `storageforge-sentinel`, in the sentinel's form, are taken. The controller reads them through the same checks and limits as the sentinel's own reports, marked as come through the agent, and one event is one event whichever way it came |

A path a plugin declares that the host does not have (`/run/log/journal`, say, or `/var/log/journal` on a host that keeps its journal only in memory) is not mounted, and `apply` says so: a plugin gets less than it declared, never more.

### The files plugin: root in effect

It is said here first because it is the plugin that changes what the agent is. Fanotify on whole filesystems takes `SYS_ADMIN`, and a process with `SYS_ADMIN` can unmount the masks over SSH's keys and do most of what root does; it also holds `SYS_PTRACE`, to reach each filesystem through the host's first process and see which program a process runs, and `DAC_READ_SEARCH`, to find a changed file by its handle and read its size whoever owns it. So with the files plugin running, **an agent that was taken over has what root has on that host**. Without it, it has what `sfagent` has.

That is why it is off unless an admin switches it on for one host: it takes `agent.privilege` and a fresh password, Keys → Agents shows it as root on the host in effect and asks again before it is ticked, the route's answer says so once more, and the audit log records it. It opens no file's contents and writes nothing; what it reports is the host's claim like any other reading.

What it is for:

- **An index that updates itself.** Each change is applied to the host's file index as it comes, on the mounts a scan indexed (or, on a monitoring-only host, the mounts its scan plugin reported), so a search finds a file a minute after it was written.
- **The file index from both** (decision of 2026-11-16). After each SSH scan, the changes it found are set against what the agent reported since the scan before: a change the agent never reported (the plugin was held back, or lost it), and one the agent reported that the scan contradicts (the agent lied, or read too early), are a disagreement in the notification center.
- **Hand edits.** A change to a file StorageForge manages (the files its drift check lists, and fstab, crypttab, mdadm, exports and Samba files) made while no deploy of the host ran is configuration drift, which cannot be ignored. It leaves when a scan or a deploy of the host finished after the edit.
- **Reads out of hours** (roadmap section 9, *Watchers*). Files read per account and hour; an account that reads more than the limit (500 an hour) outside working hours (07:00 to 19:00, Monday to Friday, the controller's clock; setting `agent.files`) is a notification.

How it watches: one fanotify group with a mark on each local filesystem in the host's mount table (ext4, XFS, btrfs, ZFS and others; not network filesystems or tmpfs). A btrfs subvolume has an fsid of its own, which a whole-filesystem mark refuses, so there it marks each folder, and each new folder as it is made, up to 200 000 folders in all; past that it says the filesystem is watched in part. A queue overflow or changes left out (more than 500 in five seconds) are said, as is a filesystem it could not watch.

### Scans carried in the plugin

The decision of 2026-11-16: scans on an agent host are scripts carried in the scan plugin, not requests. The script (`agent/scan/inventory.scan`) is compiled into the plugin's program, so the release key that signs the program decides what it runs; no message from the controller names a script, a path or a command. Each word of it reads: a section header, the first of some files, every file a glob names, and readers for the hostname, OS, addresses, block devices, btrfs, accounts, groups and enabled units. None runs a program (the image has no shell to run one with), writes, or follows a host's words somewhere it was not told; a file that is not a plain file is not read, and nothing waits on a pipe.

It writes the sections of the SSH scan's inventory it can read from files, in their form (`hostname`, `machineid`, `ip`, `os`, `lsblk`, `mountinfo`, `btrfs`, `ids`, `nfs`, `smb`, `configs`, `accounts`, `services`, `packages`), and the controller reads them with the SSH scan's own parser. On a monitoring-only host they become the host's inventory and its mounts, labelled as reported by agent; on a host with SSH they are compared with the last SSH scan, and a difference in the OS or the filesystems mounted is a notification. It does not read what needs a program or root: ZFS pools, LVM, `df`'s usage, packages, SMART (the disks plugin's), or anything under the masks, such as `authorized_keys` and StorageForge's own records.

## Monitoring-only hosts

A host the controller has no SSH scan key and no deploy access for (roadmap section 11.5): `storageforge-agentctl` is its only way in, and the agent is the only way the controller hears of it.

In **Administration → Enclave, Agent & SSH CA**, choose **Register a monitoring-only Linux host**. After registration, open **Set up monitoring** to download the script and the matching helper. Run the displayed instructions on the host. Compare its SSH public key before pasting the adoption line and submitting it. **Agent records** shows the latest readings, labelled as reports from the agent.

The equivalent API flow is:

1. `POST /api/agents/monitoring` with `{"host", "address", "port", "arch"}` registers it, with its agent switched on in mode `monitoring`. A name or address StorageForge has already is refused: switch the agent on for that host instead.
2. `GET /api/agents/<host>/setup` gives the setup script, the same one a deploy sends, and `GET /api/agents/program/<arch>` the program it installs. On the host, as root: `bash storageforge-agent-setup.sh ./storageforge-agentctl`. It checks the program by size and sha256, and ends with a line `storageforge-agent-adopt <machine-id> ssh-ed25519 <host key>`.
3. Compare the host key in that line with the host's own (`ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`), then `POST /api/agents/<host>/adopt` with `{"line": ...}`. That takes `agent.privilege`: the host key is pinned as a key a person compared, a key already pinned for that address that is another one is refused, and the agent is enrolled through `storageforge-agentctl` as on any host.

| A monitoring-only host gets | It does not get, and why |
| :--- | :--- |
| Every plugin: health, logs, disks, network, files, sentinel, and the scan plugin's inventory and mounts, which give it a file index through the agent | Change plans, deploys, Moves, sends, clone, holds and quarantine. They act over SSH as root, which the controller does not have there. Each is refused with that reason before anything reaches the host |
| Wipe and stop, from outside and inside | A scan over SSH, so nothing checks the agent's word but its silence and the check from outside |
| A console that turns SSH on for the session ([below](#the-console-on-a-monitoring-only-host)) | |

Adding SSH access later is an upgrade, not a reinstall.

### The console on a monitoring-only host

The decision of 2026-11-16: SSH turned on for that session through `storageforge-agentctl`, and off again after. Never a shell in the agent: the agent has no part in it.

When someone with `console.open` opens a console on a monitoring-only host and names an account, the controller makes an ed25519 key for that session, held in memory only, and sends `console-open` to `storageforge-agentctl` with its public half. That puts one line in the account's own `authorized_keys`: `restrict,pty,expiry-time="…Z" ssh-ed25519 … storageforge-console:<grant>`. sshd stops taking the key five minutes later (only the login has to fall inside them), and it forwards nothing. The file is written by a child that has become that account, so a link or a file the account controls reaches nothing the account could not reach itself. When the session closes, `console-close` takes the line out; every request to `storageforge-agentctl` also takes out every grant whose time is past, so a console the controller never closed is closed by the next request, and sshd refused its key long before. Each grant is a row of `agent_console_grants` and the session is in the audit log as any console's.

**Only the accounts this host's own admin listed** in `/etc/storageforge-agent/console_users`, by hand, one name a line, may be logged in as. Without that file there is no console on that host. No request writes it, so a controller that was taken over can open a console only where a person on the host allowed one, as whom they named. The agent's two accounts are never one of them, whatever the file says. sshd before OpenSSH 8.2 does not read `expiry-time` and skips the line: no console there.

## The manifest

```json
{"format":1,"agent":"SHA256:<the agent's key>","machine":"<machine-id>","counter":7,"issued":1794960000,
 "image":"registry/storageforge-agent@sha256:…",
 "plugins":[{"name":"logs","descriptor":"<sha256 of the descriptor>","signer":"release","needs":{…}}]}
```

It is signed by the controller's agent signing key, in the namespace `storageforge-agent-manifest`, and is of use on one host only: it names that agent's key and that machine. `storageforge-agentctl` checks it before it makes a container, and the agent checks it again before it runs anything.

- **The counter only goes up.** A manifest with a lower counter than the last one accepted is an old one played back and is refused. The same counter is accepted again only with the same bytes, which is a restart. `storageforge-agentctl` and the agent each keep their own record. The controller's counter for a host is kept when an agent is removed, and is in the essentials backup.
- **A new manifest is fresh:** signed in the last 15 minutes by the host's clock.
- **It cannot give a plugin more than its signer declared.** The needs in the manifest have to equal the needs in the plugin's signed descriptor, and `storageforge-agentctl` reads the signed descriptors itself. So the controller chooses among signed plugins and cannot widen one.

## The tunnel

The agent dials the receiver; nothing dials the agent. One TCP connection, to one address:

| Where the host is | What the agent dials |
| :--- | :--- |
| A member of the [StorageForge network](security.md#the-storageforge-network), peered with the controller | The controller's address on that network, at `STORAGEFORGE_AGENT_PORT` (7843) |
| Anywhere else | `STORAGEFORGE_AGENT_ENDPOINT` (`host:port`): the controller's LAN address, or the public address remote nodes reach the controller's machine at. A name is looked up on the controller, so the host is given an address |

It is not inside an SSH session and not inside the tunnel container's SSH tunnel: the agent carries no SSH client at all. It is beside them, on a port of its own that reaches the receiver and nothing else.

**Both ends prove their keys.** The session is `Noise_IK_25519_AESGCM_SHA256`, with the primitives the key enclave's channel uses. The agent's static key is its own ed25519 key used as X25519 (the same scalar, as `age` uses SSH keys), so nothing new is pinned for it. The receiver's key is pinned on the host in `/etc/storageforge-agent/tunnel`, root's and read-only to the agent, written by `storageforge-agentctl` from a signed `apply`. A receiver that does not hold that key cannot make the second message of the handshake, and the agent says nothing to it. A receiver key that changes (the receiver set up again) is refused by the controller and by the host until an admin accepts it for that host (`accept_new_key`).

**What crosses it:**

```text
agent    -> receiver   hello: version, its claims about itself, the manifest it runs, the plugins it has loaded
receiver -> agent      the manifest the controller signed for its host, then each plugin of it the agent lacks, in chunks, then
                       where it has each plugin's readings up to (resume)
agent    -> receiver   batches: {"counter","run","sent","dropped","records":[{"seq","at","plugin","kind","body"}]}, each signed
                       with the agent's key (namespace storageforge-agent-batch); at least one a minute, empty if need be
receiver -> agent      ack or refused, per batch (a batch over the agent's quota for the minute is refused with retry, and the
                       agent sends it again ten seconds later); bye when the session is over
```

The agent writes a plugin to its plugin folder only when it is named by the manifest in force (the one `storageforge-agentctl` made the container for), its descriptor is signed by the kind of key the manifest names, and its program has the hash and size the descriptor says; then it starts itself again in place, under every runtime, to load it. A delivered manifest newer than the one in force is said in its log and not used: the privileges it takes come only through `storageforge-agentctl`, over SSH. The batch counter is written to the agent's state folder before a batch is sent, and a batch that got no answer is sent again with the same counter and bytes.

**The host's firewall.** A container with a tunnel is on a bridge of its own (`sfagent0`, under Docker and Podman as root) or behind Podman's user-mode network (`pasta`, without root). Before it is made, `storageforge-agentctl` loads an nftables table, `inet storageforge_agent`: anything that comes off the bridge, and anything `sfagent`'s own processes send, may reach the receiver's address and port, and everything else is dropped, the host's own `sshd` and every other host included. The rule is loaded again at boot by `storageforge-agent-egress.service`, ordered before the runtimes. A host without `nft` or without systemd gets no tunnel, with the reason.

## The receiver

```sh
python -m storageforge_index.agentreceiver                 # STORAGEFORGE_AGENT_RECEIVER_DIR (its key), STORAGEFORGE_AGENT_RECEIVER_DB
python -m storageforge_index.agentreceiver grant ROLE      # on PostgreSQL: the grants its own role needs
docker compose -f docker-compose.yml -f docker-compose.agent.yml up -d     # as a container beside the web app
```

It makes its X25519 key the first time it starts (mode 0600 in its folder) and writes the public half beside it, which the web app gives to hosts. It refuses to start with the vault secret in its environment, and imports nothing that reaches the vault or SSH.

| What it does | How |
| :--- | :--- |
| Knows the agent by its key | The host is the one whose pinned key opened the session. A hostname, address or machine id in a message is kept as the agent's claim and never decides where a row goes |
| Writes about the sender only | Into `agent_peers`, `agent_records` and `agent_events`. On PostgreSQL its role can write those three and read five columns of `agents` and the deliveries; on SQLite, which has no roles, an authorizer on its connection refuses every other table |
| Checks every batch | The signature first, against the pinned key; then the batch strictly: its fields, numbers, at most 512 KiB and 512 records, each record's body at most 64 KiB and 16 levels deep, plugin and kind names of a fixed form |
| Counts batches | Per key, the counter only goes up. The same counter with the same bytes is a resend: answered, not stored twice. The same counter with other bytes is a replay: refused and counted. A jump is a gap, and records the agent says it dropped are counted as lost |
| Limits each agent | 120 batches and 8 MiB a minute, one session at a time, 200 000 rows, past which its own oldest rows go by when they arrived. Five bad batches end the session and hold the key out for ten minutes |
| Limits everyone | 30 handshakes a minute per address before any key is known, 256 connections, a 1 MiB frame, 10 seconds for a handshake. A key that is no enrolled agent's is counted, once a few seconds, not per attempt |
| Keeps sessions short | Fifteen minutes, then the agent opens another with fresh keys. A key taken off the pinned list (the agent removed or enrolled again) ends its session within seconds |
| Labels what it stores | Every row of `agent_records` has `source = 'agent'`; the web app shows it as *reported by agent*, never mixed with what a scan measured |

**In the notification center:** an agent with a tunnel that has not been heard from for five minutes, or for thirty seconds when it runs the heartbeat plugin (stopped, wiped, cut off, or hiding what it sees; scans go on), batches missing or played again, batches refused, an agent that says it runs another manifest than its host was given, an agent whose health plugin says nothing listens on the host's SSH port, lines missing from the journal its logs plugin pushed, an agent that could not be checked from outside for an hour, a request of an agent's held for a person, and, as security findings that cannot be ignored, an agent that says it is on another machine than SSH reads and an agent that was wiped.

The receiver's role writes only its three tables. Moving what agents said into the rest of StorageForge (pushed lines into host logs, an agent's last word into a wipe) happens on the web app's side, on a background thread of its own every five seconds (`agentingest.py`), never on a web request's.

## Wipe and stop

Anything in an agent's container that its manifest does not account for ends its access (the owner's decision of 2026-11-16; roadmap section 11.3).

**From outside, over SSH: the check that counts**, since a container that was taken over can lie about itself. On a timer (every fifteen minutes for each running agent, and again after each scan of its host) and on `POST /api/agents/<host>/check`, the controller asks `storageforge-agentctl check`. It reads nothing the agent says, and compares:

| What | Against |
| :--- | :--- |
| The image the container runs | The one the signed manifest names, by digest, and the id the runtime has under that digest |
| Files changed in the container (`docker diff`, `podman diff`; under plain LXC a hash of its root filesystem) | Nothing but the places the runtime makes for its mounts |
| Its mounts, capabilities, devices, network, process table, user, privileged or not | What it was made with (kept on the host when it was made): the union of what the manifest's plugins declare, as [What a container is given](#what-a-container-is-given) says, the masks included |
| The plugin folder, read from the host's side | Each file of a plugin the manifest names, as signed, and nothing else. A plugin still on its way is a note, not a finding |
| The state folder | The agent's own files and nothing else; its key there, and the one enrolled |

**From inside.** At start and every thirty seconds the agent checks its manifest and every plugin file, and its own program against what it was when it started. A file in the plugin folder nothing accounts for, a plugin file that is there and is not what was signed, a manifest the controller did not sign, another agent's, or an older one played back, is tampering. A plugin that has not arrived yet is not, and a manifest merely signed long ago with a later counter is refused without wiping, since clocks differ.

**What happens.** On any finding from outside, the controller revokes the agent's key on its own side first (the receiver drops it from its pinned keys within seconds and ends its session), which nothing on the host can undo; then asks `storageforge-agentctl wipe`, which stops the container and leaves it stopped whatever its restart policy, deletes the agent's key and plugin files, writes why beside them, and forgets the key pinned on the host so that `start` and `apply` refuse; and a notification that cannot be ignored opens, until an agent is enrolled there again or removed. On tampering found inside, the agent deletes its key, writes why, gives its last word through the tunnel (one record, under the name `agent`, which no plugin may have) and exits; started again by its runtime it finds what it wrote and exits at once, making no new key. Its last word makes the controller do the same as for a finding from outside. Only an admin (`agent.privilege`, and a fresh password) enrolls an agent again after a wipe, and the audit log records it.

A check that cannot run (the host unreachable) wipes nothing: not being able to look is not a finding. After an hour it is a notification.

### What an agent's report may cause

An agent's word causes an action through one road only (`agentaction.py`), and that road holds the roadmap's two rules (11.2):

- **Its actions affect only itself.** A report acts by itself only on the agent that sent it: the host the receiver stored it under, from the key, whatever the message names. Only protective actions are allowed by themselves, and today there is one: an agent that says it wiped itself is revoked and stopped. What a lying agent gains from that it could have had by stopping. What a report names (another host, an address) is kept beside it as its claim and never chosen as a target.
- **Anything wider needs a second witness.** An action that would touch another host or client (a share frozen, a client dropped from every share) is taken only when an independent source agrees about the same target, recently: a scan over SSH, a decoy hit, or the share host's own sentinel. Never the reporter's own sentinel, and never another agent. Without one it is held, and a person is told. No such action is built yet; the shadow-copy tripwire (Windows, 0.5.14) and the share freeze will go through it.

Every action caused, held or refused is a row of `agent_actions`, shown with the host's records.

## Requests to storageforge-agentctl

```text
STORAGEFORGE-AGENTCTL 1
<length of the request>
<length of the signature>
{"op":"apply","machine":"<machine-id>","issued":1794960000,"nonce":"<32 hex>", …}<SSH signature, namespace "storageforge-agentctl">
```

A request is acted on only when the controller pinned on that host signed it, for that machine, in the last ten minutes, with a nonce not used there before. The signature is checked before the request is parsed. The operations are `preflight`, `enroll`, `apply`, `start`, `stop`, `restart`, `status`, `remove`, `check`, `wipe`, `console-open` and `console-close`. None runs a command, reads a file or makes a mount that the caller chose (the console's two write one line, as an account the host's admin listed, in that account's `authorized_keys`), and a request with a field its operation does not take is refused. It exits 0 when done, 97 when refused with nothing changed, 1 when it failed part way.

## The image

```sh
docker build --target agent -t storageforge-agent storageforge-indexer     # the image
sh storageforge-indexer/agent/build.sh                                     # the two programs alone, for x86_64 and arm64, with SHA256SUMS
```

The programs are built in the container the key enclave is built in, pinned by digest, from `Cargo.lock`, with the time and paths fixed. CI builds twice and compares.

**The image is run only when its digest is signed.** The controller names the image, so without this a controller that was taken over could name its own. `storageforge-agentctl` checks, before anything is fetched, an SSH signature of the digest made by a release key or by a key in the host's `operator_signers`:

```sh
echo sha256:… > digest && ssh-keygen -Y sign -n storageforge-agent-image -f KEY digest     # digest.sig is what STORAGEFORGE_AGENT_IMAGE_SIG names
```

**There is no release key in the repository yet.** `agent/release_signers` is empty until the owner adds the public half of the release key. Programs built from it as it is trust no release key: they run no official plugin, and no image but one signed by an operator's own key. `STORAGEFORGE_RELEASE_SIGNERS=FILE` at build time (`AGENT_RELEASE_SIGNERS` as a Docker build argument) compiles in another file, which is how the unit tests and the lab build with a key of their own.

## What the agent can and cannot do, at this stage

**It can:**

- run on a host as `sfagent`, in a container with what its plugins' signed descriptors declare and nothing more
- make its own key and keep the private half in its state folder
- read the files of the host it was given read-only mounts of, as `sfagent`
- start signed plugins named in its manifest, take readings from them, and send them through its tunnel as signed batches: with the official ones, its host's journal lines as they are written, its health, who is on its shares, and a heartbeat
- delete its own key and stop for good, which it does when it finds its container tampered with
- reach the receiver's one address and port, and take from it the signed manifest and signed plugins of its own host

**It cannot:**

- reach anything but the receiver: not the host's `sshd`, not another host, not the internet (the host's firewall drops it), and with no tunnel, nothing at all
- be reached: it opens no listening socket
- run a shell, a command, or any program that is not a signed plugin in its manifest. Its image holds no other program
- write anything on the host but its own state folder
- read SSH's keys, a `.ssh` folder, the scan signing key, secrets sent from the vault, the verifiers' stores or the sudoers files, through any mount it can be given, as far as the masks reach (see below)
- reach Docker's, Podman's, LXC's, Incus's or Proxmox's socket
- change what it is given: the manifest, the pinned keys and the tunnel file are root's and read-only to it
- become root, or use `sudo`

**The controller, through the agent's side, can:** choose which signed plugins a host runs, and which signed image; start, stop and remove the agent. **It cannot:** run code of its own on the host through the agent (no request and no tunnel message carries a command, and it holds no key that signs a plugin or an image), give a plugin more than its signed descriptor declares, or have a manifest accepted for another host or an older one accepted again.

**SSH and the agent share nothing.** The agent's key is made by the agent and signs nothing but its own batches. The controller's two agent keys (`storageforge-agentctl` to log in, `storageforge-agent-signing` to sign) are not the scan, deploy or job keys, and `storageforge-agentctl` refuses a signature made for a deploy. The receiver holds no vault secret and opens no SSH connection. Removing the agent touches no SSH access, and with the agent stopped or gone, scans, deploys and the console work as before.

## What a taken-over agent can and cannot do

Say whoever holds a host also holds its agent: its key, its state folder, its process. What they gain, towards the controller and the rest of the fleet:

| They can | What limits it |
| :--- | :--- |
| Say anything about that host: invent problems, hide them, claim another machine id or hostname | It is stored as that host's agent's claim, labelled so, and never moves to another host. A claimed machine id that is not the one SSH reads is a security finding. Hiding is not preventable: SSH scans, decoys on shares and the agent's silence stay independent of it |
| Send as much as its quota allows | 120 batches and 8 MiB a minute, 200 000 rows of its own, its own oldest rows pushed out: other agents and the web app, which is another process, are untouched |
| Stop sending | Silence for five minutes is a notification |
| Replay or delete batches on the way | A replay is refused; a gap is counted and shown |
| Send malformed or oversized input | Refused before it is stored, counted; five end the session and hold the key out for ten minutes. Frames over 1 MiB end the connection unread |
| Keep its key after the agent is removed | Removing it on the controller takes the key off the pinned list: no new session, and an open one ends within seconds |
| Read what the controller sends it | The signed manifest and plugins of its own host, and where the receiver has its readings up to: none of it secret |
| Push its host's journal lines, true or invented, and move its own resume point | Stored as that host's lines, through the scrubbing, the host's rate and its quota; a jump in the journal's numbers is a gap shown, and its resume point moves nothing but its own plugin's place |
| Say SSH is down when it is not, or up when it is not | A notification for a person, labelled as reported by agent. SSH itself is not touched, and scans say what they find |
| Have itself wiped | By claiming it found tampering: it loses its own access, which it could give up by stopping |
| Run the plugins it was given, and read what their mounts show | That host's files, as `sfagent`, which whoever holds the host already has |
| With the files plugin running: what root has on that host (`SYS_ADMIN`, `SYS_PTRACE`, `DAC_READ_SEARCH`), the masks over SSH's keys included | Only an admin switches it on, told it is root in effect. It gains nothing beyond that host: its key, the receiver and the controller treat it as any agent |
| With the disks plugin running: send its disks any command, not only reads (`SYS_RAWIO`) | That host's disks only, which whoever holds the host could already reach |
| Report file changes that did not happen, or hide ones that did, and so steer that host's file index | Each SSH scan sets the changes it found against the agent's: both kinds are a disagreement in the notification center |
| Report a hand edit, or reads out of hours, that did not happen | A notification for a person about its own host; nothing acts on it |
| Invent sentinel events for its host | Stored as that host's claim, through the sentinel's limits, marked as come through the agent, and never a witness for an action on another host |
| Send a scan inventory of its choosing | On a monitoring-only host it becomes that host's inventory, labelled as reported by agent, with its machine id kept from adoption and a claim of another compared; on a host with SSH it is compared with the SSH scan |

| They cannot | Why |
| :--- | :--- |
| Speak for another host, or write anything but its own rows | The host is worked out from its key; the receiver's role or authorizer reaches three tables |
| Cause an action on another host or client | A report acts by itself only on its sender, and only to revoke and stop it. Anything wider waits for a scan over SSH, a decoy or the share host's sentinel to agree, or for a person (no such action is built yet) |
| Keep running after its container was changed | The check from outside, over SSH, reads the runtime's own account and the host's files, not the agent's; any finding revokes its key first |
| Reach SSH, the vault or the web app | Its container reaches the receiver's port and nothing else; the receiver has no vault secret and no SSH; the web app does not listen on the tunnel |
| Get code run with more privileges | Plugins and the image are signed by the release key or the operator's own, privileges come only from a manifest `storageforge-agentctl` accepted over SSH, and one that adds any takes an admin |
| Pass for the receiver to another agent, or for another agent to the receiver | Each end pins the other's key |
| Open a console or turn SSH on | The agent has no part in it: `console-open` is a request the controller signs to `storageforge-agentctl` over SSH, for accounts the host's admin listed |
| Keep a capability past what its plugins declare, or become root | It gave root up before reading anything, its bounding set holds only the declared capabilities, the securebits are locked, and the check from outside reads its process from the host |

What they could still do, and nothing stops: tell lies about their own host that agree with each other; send up to their quota of plausible data; and, if they also hold the receiver's key (which lives on the controller), read what other agents send and offer them files, which those agents refuse unless a release key signed them.

**What a controller that was taken over can now do, through the agent's side, that it could not before 0.5.8:** open a console on a monitoring-only host, as an account that host's admin listed, and only there; choose the files plugin for a host (it holds no key that signs one, and the route takes an admin, but a controller taken over at that level signs what it wants), which makes the agent on that host root in effect. It still cannot run code of its own through the agent, choose what the scan plugin runs, or log in to a monitoring-only host where its admin listed nobody.

## What it does not do or check, yet

Stated here so that nobody takes more from the above than is there.

- **Nothing is lab-tested**, and Podman, LXC, Incus and `pct` have only run against stand-ins. The commands for LXC, Incus and Proxmox VE are written from those tools' documentation.
- **The check from outside compares the container itself under Docker and Podman, and under plain LXC its root filesystem**, against a hash taken when it was made. Under Incus and Proxmox VE only the agent's folders are compared yet. Under Podman a smaller set of fields is compared than under Docker (capabilities dropped, `no-new-privileges` and the network name are not), since how Podman reports them has not been seen on a real host.
- **The check from inside protects an honest agent from its host's files being changed under it.** An agent whose own process was taken over can skip it; that is what the check from outside is for.
- **`.ssh` folders are found when the container is made:** those of the accounts in `/etc/passwd`, of every folder directly under `/home`, and of every folder directly under a mount. One made later is masked from the next start. One deeper down (`/srv/users/ana/.ssh`) is not masked. As `sfagent`, with no capability, such a folder is unreadable anyway when its mode is the usual 0700; the masks are what protects it from a plugin that declares `DAC_READ_SEARCH` or `SYS_ADMIN`.
- **A plugin with `SYS_ADMIN` can undo a mask** by unmounting it, and is root on the host in effect. The files plugin is one, and Keys → Agents and the route say so where it is switched on.
- **Groups from a directory service are not seen.** The check that the managing user is in none of `docker`, `lxd`, `incus-admin` reads `/etc/group` and the account's own group (the setup script asks `id`, which does see them).
- **NVMe health takes `SYS_ADMIN`,** which the kernel asks of any process that reads the health log, and the disks plugin does not declare it. Where the kernel refuses, the reading says so and the SSH collector's report stays the source for that disk. An ATA disk behind a USB bridge or a virtual disk (virtio) answers no SMART data, and says so. No SMART read has run against a real disk here: the decoding is tested against the bytes the standards lay out, and the ioctls against stand-in files.
- **The files plugin runs only under Docker or Podman as root**, since an unprivileged LXC container cannot hold its capabilities, and has run only in a container against this machine's kernel. On a btrfs subvolume it marks folders one by one. It does not watch network filesystems. A process that ended before its event was read is reported without its name. Ransomware signs on every path, which the roadmap lists for it, are not built.
- **The scan plugin reads files only:** no ZFS, LVM, usage figures, packages or `authorized_keys`, and nothing under the masks.
- **The sentinel plugin reads from its start on.** An event written while the agent was down arrives by the sentinel's own report or the next scan.
- **Monitoring-only hosts are set up and adopted through the API;** there is no page for it yet. A single scan asked of one fails for want of a scan key.
- **The tunnel is not built for LXC, Incus or Proxmox VE** (an unprivileged container there has no network of its own for it yet), nor for hosts without systemd (the firewall rule could not be loaded again at boot before the container starts) or without `nft`. The agent runs there and reports nothing, with the reason.
- **The egress rule is matched on the agent's bridge and on `sfagent`'s uid,** not on the container's cgroup as the roadmap says. A process that is not `sfagent` and is put on the bridge by hand is held by it; one of `sfagent`'s outside the container is held too, which is as meant.
- **On SQLite the receiver has no database role.** It runs as its own process with an authorizer on its connection; if the process itself were taken over it could open the file without one. The role boundary is PostgreSQL's. In the Docker setup the receiver runs as the web app's user and shares its data volume, so its key file is readable by the web app.
- **The only action an agent's report causes is its own wipe.** The tripwire and the share freeze are not built; the gate they will go through is.
- **The logs plugin reads systemd's journal only.** OpenRC hosts' log files are not read yet, and a field compressed with xz (which systemd has not written by default for years) is not read and is counted. The scan stops asking for a host's lines while its agent pushes and asks again ten minutes after pushing stops.
- **Health does not read the capacity of filesystems other than btrfs, nor a ZFS scrub's progress**, which /proc and /sys do not show. Scans over SSH read those.
- **A heartbeat that stops wakes the notification center within seconds**, and the alert itself is pushed at once; the other agent notifications come at its tick, every five minutes.
- **There is no page for what agents report** in the web UI beyond Keys → Agents: the route is in the API reference.
- **The agent's state folder has no size limit.**
- **Under Podman without root there is no memory or process limit** on the container, since not every host lets a user set one.
- **`cargo audit` and `cargo deny` do not run in CI.** The workspace's `Cargo.lock` is scanned by Trivy in the enclave job.
- **Windows** is not built.

## Building and testing

```sh
cd storageforge-indexer
cargo test -p storageforge-wire --features noise -p storageforge-agent      # formats, signatures, the counter, a real plugin process, the tunnel,
                                                                           # wipe and stop, the official plugins, the journal against systemd's own files
python tests/run.py all -k test_agent                      # the setup script, the real programs against a stand-in host, the real Docker,
                                                           # the tunnel and the receiver (test_agent_tunnel, test_agent_receiver, test_agent_trust)
```

Lab tier 24 (`tests/lab/tiers_agent.py`) is written and has not run, its tunnel, receiver, plugin and wipe-and-stop checks included. The lab's build does not publish an agent image or start the receiver yet, so until it does every check of that tier shows as skip, with that reason.

`tests/test_agent_tunnel.py` checks the Python side of the handshake against the Rust side byte for byte, runs the real agent against a receiver over TCP through a plugin delivery and back, and loads the egress rule with the real `nft` in a network namespace of its own. `tests/test_agent_receiver.py` plays agents over real sessions against the real receiver, everything a taken-over agent might send, on SQLite and PostgreSQL, where the receiver's role is made and shown to reach nothing else; its `Delivery` class runs the whole road, from `sfagent` through the real `storageforge-agentctl` and agent to the receiver.

`tests/test_agent_guard.py` runs the check from outside and the wipe through the real `storageforge-agentctl`, the agent's last word through the real tunnel, and the gate on what a report may cause; `tests/test_agent_plugins.py` takes pushed lines into host logs and runs the real logs and heartbeat plugins, signed by a key made for the run, through the real tunnel against journal files written by systemd's own `systemd-journal-remote`. `agent/tests/journal.rs` reads every layout systemd writes and compares each entry with what `journalctl` says of it.

`tests/test_agent_disks.py`, `test_agent_files.py`, `test_agent_scan.py`, `test_agent_sentinel.py`, `test_agent_monitoring.py` and `test_agent_console.py` cover 0.5.8: the disks plugin's readings read with the collector's parser, the files plugin's changes in the index, hand edits, reads out of hours and the comparison with a scan, with the real plugin under the real kernel's fanotify in a container; the real scan plugin's script read by the SSH scan's parser; the real sentinel plugin against journal files systemd wrote; a host set up by hand and adopted through the real `storageforge-agentctl`; and the console's key line written and taken out by it. `RealDocker` checks that a plugin's capability is kept by giving root up, as the kernel shows the process.

`tests/test_agent.py` builds both programs with a release key it made, runs the setup script in bash against a folder that stands for a host's `/`, sends the controller's signed requests to the real `storageforge-agentctl`, and starts the real agent where a runtime would. `RealDocker` runs the same road against the real Docker with the image from the `agent` stage, where Docker and a `registry` image are at hand.
