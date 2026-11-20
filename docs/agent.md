# The agent

StorageForge reads and changes hosts over SSH, with nothing installed on them. That stays the base, on every host, and keeps every feature. The agent is an extra, switched on one host at a time, for what a scan cannot do: readings as they happen instead of once per scan. Routers, firewalls, switches and appliances stay agentless.

**Built, not lab-tested.** What this page describes is the agent's base: its two programs, its image, how a host is set up for it and how it is enrolled, the plugin format and the signatures. **It has no tunnel to the controller yet and no plugins of its own, so an enrolled agent reports nothing.** Those come next (the roadmap's sections 11.2 to 11.4). Docker is the only runtime it has run under, in the unit tests, with the real image. Podman, LXC, Incus and Proxmox VE are written and have run only against stand-ins.

## How it is put together

```text
controller ──signed deploy, once──► host: accounts, one sudoers line, storageforge-agentctl, the controller's key pinned
controller ──SSH, signed requests─► storageforge-agentctl (root) ──► Docker, Podman or LXC: the agent's container
                                                                      storageforge-agent, as sfagent, read-only, no network
```

| Part | What it is |
| :--- | :--- |
| `storageforge-agent` | The one program in the container. Rust, static: no interpreter, no OpenSSL, no libc. It runs as `sfagent`, makes its own key, reads its manifest, and starts the signed plugins the manifest names. It refuses to run as root |
| `storageforge-agentctl` | A second static Rust program, on the host, behind the one sudoers line. It takes a signed request on stdin, does one agent operation, prints one line of JSON. It drives the runtime itself, so nobody else needs access to it |
| The image | The `agent` stage of the `Dockerfile`: Wolfi's base layout, the program, and nothing else. No shell, no package manager, 1.5 MB. The same image on every host and every runtime |
| A plugin | A static program of its own, with a signed descriptor that says what it needs of the host. The agent starts it as a child and speaks to it over pipes. None exists yet |
| The manifest | Which plugins a host runs, signed by the controller with the time and a counter |

Both programs are in one Cargo workspace with the [key enclave](security.md#key-enclave) (`storageforge-indexer/Cargo.toml`), share its framing (`wire/`), and keep its habits: every input has a size limit checked before it is read, every structure refuses fields it does not know, and what no honest peer sends ends the conversation.

## Switching it on for a host

The agent is off for every host. Nothing on this page happens to a host until someone with `keys.manage` switches it on for that host and types their password.

1. **Settings on the controller.** `STORAGEFORGE_AGENT_IMAGE` names the agent's image by digest (`registry/storageforge-agent@sha256:…`; a tag is refused, since a tag can be moved to other bytes). `STORAGEFORGE_AGENT_IMAGE_SIG` names the file with the signature of that digest (see [The image](#the-image)). `STORAGEFORGE_AGENT_DIR` is where `storageforge-agentctl` is, which the server's own image sets.
2. **Deploy access.** The host needs [deploy access](deployments.md), since the setup runs through it. A host without it (monitoring only) is set up by hand with the same script; that road has no page in the UI yet.
3. **Switch it on.** `PUT /api/agents/<host>` with `{"enabled": true}`. The answer says what the last scan knows of a runtime on that host.
4. **Install.** `POST /api/agents/<host>/install`. It returns a group id, polled as a deploy is. The steps: the setup script as a signed deploy, with `storageforge-agentctl` on its stdin; `preflight`, which reads which runtimes the host has; `enroll`, which starts the container and reads back the public half of the key the agent made; `apply`, which gives it its first manifest, with no plugin in it.
5. **A host with no container runtime** is not touched further at step 4. The install stops in the state `needs-podman` with a notice that Podman will be installed with the host's own package manager. Only an install started again with `{"install_podman": true}` installs it, and then the agent runs under Podman without root.

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
- **no network at all**, unless a plugin declares the host's. With no tunnel yet nothing needs one

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
- start signed plugins named in its manifest, and take readings from them into a queue in memory

**It cannot:**

- send anything anywhere, or be reached: it has no network, opens no socket, and there is no tunnel yet. What plugins report is counted and dropped
- run a shell, a command, or any program that is not a signed plugin in its manifest. Its image holds no other program
- write anything on the host but its own state folder
- read SSH's keys, a `.ssh` folder, the scan signing key, secrets sent from the vault, the verifiers' stores or the sudoers files, through any mount it can be given, as far as the masks reach (see below)
- reach Docker's, Podman's, LXC's, Incus's or Proxmox's socket
- change what it is given: the manifest and the pinned keys are root's and read-only to it
- become root, or use `sudo`

**The controller, through the agent's side, can:** choose which signed plugins a host runs, and which signed image; start, stop and remove the agent. **It cannot:** run code of its own on the host through the agent (no request carries a command, and it holds no key that signs a plugin or an image), give a plugin more than its signed descriptor declares, or have a manifest accepted for another host or an older one accepted again.

**SSH and the agent share nothing.** The agent's key is made by the agent and signs nothing but its own reports. The controller's two agent keys (`storageforge-agentctl` to log in, `storageforge-agent-signing` to sign) are not the scan, deploy or job keys, and `storageforge-agentctl` refuses a signature made for a deploy. Removing the agent touches no SSH access, and with the agent stopped or gone, scans, deploys and the console work as before.

## What it does not do or check, yet

Stated here so that nobody takes more from the above than is there.

- **Nothing is lab-tested**, and Podman, LXC, Incus and `pct` have only run against stand-ins. The commands for LXC, Incus and Proxmox VE are written from those tools' documentation.
- **No check from outside yet, and no wipe.** The agent refuses what does not match its manifest and says so in its log. Comparing the running container with the manifest over SSH, and wiping an agent that fails that, is the roadmap's section 11.3.
- **`.ssh` folders are found when the container is made:** those of the accounts in `/etc/passwd`, of every folder directly under `/home`, and of every folder directly under a mount. One made later is masked from the next start. One deeper down (`/srv/users/ana/.ssh`) is not masked. As `sfagent`, with no capability, such a folder is unreadable anyway when its mode is the usual 0700; the masks are what protects it from a plugin that declares `DAC_READ_SEARCH` or `SYS_ADMIN`.
- **A plugin with `SYS_ADMIN` can undo a mask** by unmounting it, and is root on the host in effect. The roadmap says so of the files plugin, and the UI will have to.
- **Groups from a directory service are not seen.** The check that the managing user is in none of `docker`, `lxd`, `incus-admin` reads `/etc/group` and the account's own group (the setup script asks `id`, which does see them).
- **A capability given by Docker to a process that is not root is not effective** without more work (ambient capabilities). No plugin needs one yet; the disks and files plugins will.
- **The agent's state folder has no size limit.**
- **Under Podman without root there is no memory or process limit** on the container, since not every host lets a user set one.
- **`cargo audit` and `cargo deny` do not run in CI.** The workspace's `Cargo.lock` is scanned by Trivy in the enclave job.
- **Windows** is not built.

## Building and testing

```sh
cd storageforge-indexer
cargo test -p storageforge-wire -p storageforge-agent      # the Rust tests: formats, signatures, the counter, a real plugin process
python tests/run.py all -k test_agent                      # the setup script, the real programs against a stand-in host, the real Docker
```

`tests/test_agent.py` builds both programs with a release key it made, runs the setup script in bash against a folder that stands for a host's `/`, sends the controller's signed requests to the real `storageforge-agentctl`, and starts the real agent where a runtime would. `RealDocker` runs the same road against the real Docker with the image from the `agent` stage, where Docker and a `registry` image are at hand.
