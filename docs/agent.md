# The agent

StorageForge reads and changes hosts over SSH, with nothing installed on them. That stays the base, on every host, and keeps every feature. The agent is an extra, switched on one host at a time, for what a scan cannot do: readings as they happen instead of once per scan. Routers, firewalls, switches and appliances stay agentless.

**Built, not lab-tested.** What this page describes is the agent's base (its two programs, its image, how a host is set up for it and how it is enrolled, the plugin format and the signatures), its tunnel to the controller and the receiver at the other end, and the trust model they keep (the roadmap's sections 11.1 and 11.2). **There are no plugins of its own yet** (section 11.4), so an enrolled agent with a tunnel sends a signed, empty batch every minute, which is how its silence is noticed, and nothing else. Docker is the only runtime it has run under, in the unit tests, with the real image. Podman, LXC, Incus and Proxmox VE are written and have run only against stand-ins.

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
| A plugin | A static program of its own, with a signed descriptor that says what it needs of the host. It reaches the agent through the tunnel; the agent starts it as a child and speaks to it over pipes. None exists yet |
| The manifest | Which plugins a host runs, signed by the controller with the time and a counter |
| The tunnel | One TCP connection from the agent to the receiver, encrypted and authenticated both ways with Noise IK: the agent's key is its own, the receiver's is pinned on the host |
| The receiver | `python -m storageforge_index.agentreceiver`, a process of its own beside the web app, with a database role of its own: the one place what agents say comes in |

Both programs are in one Cargo workspace with the [key enclave](security.md#key-enclave) (`storageforge-indexer/Cargo.toml`), share its framing (`wire/`), and keep its habits: every input has a size limit checked before it is read, every structure refuses fields it does not know, and what no honest peer sends ends the conversation.

## Switching it on for a host

The agent is off for every host. Nothing on this page happens to a host until someone with `keys.manage` switches it on for that host and types their password.

1. **Settings on the controller.** `STORAGEFORGE_AGENT_IMAGE` names the agent's image by digest (`registry/storageforge-agent@sha256:…`; a tag is refused, since a tag can be moved to other bytes). `STORAGEFORGE_AGENT_IMAGE_SIG` names the file with the signature of that digest (see [The image](#the-image)). `STORAGEFORGE_AGENT_DIR` is where `storageforge-agentctl` is, which the server's own image sets. For the agent to report, the [receiver](#the-receiver) runs and `STORAGEFORGE_AGENT_ENDPOINT` says where agents dial it; without them the agent runs and says nothing.
2. **Deploy access.** The host needs [deploy access](deployments.md), since the setup runs through it. A host without it (monitoring only) is set up by hand with the same script; that road has no page in the UI yet.
3. **Switch it on.** `PUT /api/agents/<host>` with `{"enabled": true}`. The answer says what the last scan knows of a runtime on that host.
4. **Install.** `POST /api/agents/<host>/install`. It returns a group id, polled as a deploy is. The steps: the setup script as a signed deploy, with `storageforge-agentctl` on its stdin; `preflight`, which reads which runtimes the host has; `enroll`, which starts the container and reads back the public half of the key the agent made; `apply`, which gives it its first manifest, with no plugin in it, and with a receiver running, the receiver's address and key, which the host pins.
5. **A host with no container runtime** is not touched further at step 4. The install stops in the state `needs-podman` with a notice that Podman will be installed with the host's own package manager. Only an install started again with `{"install_podman": true}` installs it, and then the agent runs under Podman without root.

6. **Plugins.** `POST /api/agents/<host>/plugins` with the names of plugins of the release. A plugin that declares any privilege on the host takes an admin: the `agent.privilege` permission, as well as `keys.manage` and a fresh password.

There is no page for this in the web UI yet: the routes are in the [API reference](api-reference.md#the-agent).

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
receiver -> agent      the manifest the controller signed for its host, then each plugin of it the agent lacks, in chunks
agent    -> receiver   batches: {"counter","run","sent","dropped","records":[{"seq","at","plugin","kind","body"}]}, each signed
                       with the agent's key (namespace storageforge-agent-batch); at least one a minute, empty if need be
receiver -> agent      ack or refused, per batch; bye when the session is over
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

**In the notification center:** an agent with a tunnel that has not been heard from for five minutes (stopped, wiped, cut off, or hiding what it sees; scans go on), batches missing or played again, batches refused, an agent that says it runs another manifest than its host was given, and, as a security finding that cannot be ignored, an agent that says it is on another machine than SSH reads.

## Requests to storageforge-agentctl

```text
STORAGEFORGE-AGENTCTL 1
<length of the request>
<length of the signature>
{"op":"apply","machine":"<machine-id>","issued":1794960000,"nonce":"<32 hex>", …}<SSH signature, namespace "storageforge-agentctl">
```

A request is acted on only when the controller pinned on that host signed it, for that machine, in the last ten minutes, with a nonce not used there before. The signature is checked before the request is parsed. The operations are `preflight`, `enroll`, `apply`, `start`, `stop`, `restart`, `status` and `remove`. None runs a command, reads a file or makes a mount that the caller chose, and a request with a field its operation does not take is refused. It exits 0 when done, 97 when refused with nothing changed, 1 when it failed part way.

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
- start signed plugins named in its manifest, take readings from them, and send them through its tunnel as signed batches
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
| Read what the controller sends it | The signed manifest and plugins of its own host: none of it secret |
| Run the plugins it was given, and read what their mounts show | That host's files, as `sfagent`, which whoever holds the host already has |

| They cannot | Why |
| :--- | :--- |
| Speak for another host, or write anything but its own rows | The host is worked out from its key; the receiver's role or authorizer reaches three tables |
| Cause an action anywhere | No agent report can trigger any action yet: everything it says goes to a person, through the notification center |
| Reach SSH, the vault or the web app | Its container reaches the receiver's port and nothing else; the receiver has no vault secret and no SSH; the web app does not listen on the tunnel |
| Get code run with more privileges | Plugins and the image are signed by the release key or the operator's own, privileges come only from a manifest `storageforge-agentctl` accepted over SSH, and one that adds any takes an admin |
| Pass for the receiver to another agent, or for another agent to the receiver | Each end pins the other's key |

What they could still do, and nothing stops: tell lies about their own host that agree with each other; send up to their quota of plausible data; and, if they also hold the receiver's key (which lives on the controller), read what other agents send and offer them files, which those agents refuse unless a release key signed them.

## What it does not do or check, yet

Stated here so that nobody takes more from the above than is there.

- **Nothing is lab-tested**, and Podman, LXC, Incus and `pct` have only run against stand-ins. The commands for LXC, Incus and Proxmox VE are written from those tools' documentation.
- **No check from outside yet, and no wipe.** The agent refuses what does not match its manifest and says so in its log. Comparing the running container with the manifest over SSH, and wiping an agent that fails that, is the roadmap's section 11.3.
- **`.ssh` folders are found when the container is made:** those of the accounts in `/etc/passwd`, of every folder directly under `/home`, and of every folder directly under a mount. One made later is masked from the next start. One deeper down (`/srv/users/ana/.ssh`) is not masked. As `sfagent`, with no capability, such a folder is unreadable anyway when its mode is the usual 0700; the masks are what protects it from a plugin that declares `DAC_READ_SEARCH` or `SYS_ADMIN`.
- **A plugin with `SYS_ADMIN` can undo a mask** by unmounting it, and is root on the host in effect. The roadmap says so of the files plugin, and the UI will have to.
- **Groups from a directory service are not seen.** The check that the managing user is in none of `docker`, `lxd`, `incus-admin` reads `/etc/group` and the account's own group (the setup script asks `id`, which does see them).
- **A capability given by Docker to a process that is not root is not effective** without more work (ambient capabilities). No plugin needs one yet; the disks and files plugins will.
- **The tunnel is not built for LXC, Incus or Proxmox VE** (an unprivileged container there has no network of its own for it yet), nor for hosts without systemd (the firewall rule could not be loaded again at boot before the container starts) or without `nft`. The agent runs there and reports nothing, with the reason.
- **The egress rule is matched on the agent's bridge and on `sfagent`'s uid,** not on the container's cgroup as the roadmap says. A process that is not `sfagent` and is put on the bridge by hand is held by it; one of `sfagent`'s outside the container is held too, which is as meant.
- **On SQLite the receiver has no database role.** It runs as its own process with an authorizer on its connection; if the process itself were taken over it could open the file without one. The role boundary is PostgreSQL's. In the Docker setup the receiver runs as the web app's user and shares its data volume, so its key file is readable by the web app.
- **No agent report causes any action,** so the roadmap's protective reaction (the tripwire dropping the reporter's own address) and the second witness have nothing to act on yet.
- **"`sshd` is down" is not reported** by the agent: that takes a plugin (section 11.4). Its silence is reported.
- **There is no page for what agents report** in the web UI: the route is in the API reference.
- **The agent's state folder has no size limit.**
- **Under Podman without root there is no memory or process limit** on the container, since not every host lets a user set one.
- **`cargo audit` and `cargo deny` do not run in CI.** The workspace's `Cargo.lock` is scanned by Trivy in the enclave job.
- **Windows** is not built.

## Building and testing

```sh
cd storageforge-indexer
cargo test -p storageforge-wire --features noise -p storageforge-agent      # formats, signatures, the counter, a real plugin process, the tunnel
python tests/run.py all -k test_agent                      # the setup script, the real programs against a stand-in host, the real Docker,
                                                           # the tunnel and the receiver (test_agent_tunnel, test_agent_receiver, test_agent_trust)
```

Lab tier 24 (`tests/lab/tiers_agent.py`) is written and has not run, its tunnel and receiver checks included. The lab's build does not publish an agent image or start the receiver yet, so until it does every check of that tier shows as skip, with that reason.

`tests/test_agent_tunnel.py` checks the Python side of the handshake against the Rust side byte for byte, runs the real agent against a receiver over TCP through a plugin delivery and back, and loads the egress rule with the real `nft` in a network namespace of its own. `tests/test_agent_receiver.py` plays agents over real sessions against the real receiver, everything a taken-over agent might send, on SQLite and PostgreSQL, where the receiver's role is made and shown to reach nothing else; its `Delivery` class runs the whole road, from `sfagent` through the real `storageforge-agentctl` and agent to the receiver.

`tests/test_agent.py` builds both programs with a release key it made, runs the setup script in bash against a folder that stands for a host's `/`, sends the controller's signed requests to the real `storageforge-agentctl`, and starts the real agent where a runtime would. `RealDocker` runs the same road against the real Docker with the image from the `agent` stage, where Docker and a `registry` image are at hand.
