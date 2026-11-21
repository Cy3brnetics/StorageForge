# Workloads: stacks, LXC and Incus

StorageForge runs workloads the way it changes anything else: each is a step of a change plan, checked against the index, reported first and run when the plan is deployed, through a signed run, into the audit log. This page covers what came in 0.5.11. All of it is built, not lab-tested: lab tier 28 is written and has not run.

What is here:

- [Compose stacks, LXC containers and Incus instances](#compose-stacks-lxc-containers-and-incus-instances), each with its labels and the firewall rule for what it publishes.
- [Image updates with rollback](#image-updates-with-rollback) on a failed healthcheck.

Running one container (`container`), VMs from cloud images (`vm-create`) and the VM steps are in [VMs on libvirt](vms.md) and [Cloning and migrating hosts](host-migration.md). Installing a runtime first is the `runtime-install` step in [Change plans](change-plans.md).

## Compose stacks, LXC containers and Incus instances

Three steps under **Workloads** in the plan editor. Each one leaves alone what StorageForge did not make: a stack of the same name run from another folder, an LXC container or an Incus instance of the same name, is a conflict and nothing more.

| Step | What it makes | Labels | Firewall rule |
| :--- | :--- | :--- | :--- |
| `stack` | A compose project from the file you give, kept in `/srv/stacks/NAME` (or the folder you name) and brought up with `docker compose`, `docker-compose`, `podman compose` or `podman-compose` | In `storageforge.yaml` beside the compose file, which compose merges in, so your file stays as you gave it. Every service gets `storageforge.managed=true` and `storageforge.stack=NAME` too | A deny and an allow per source in `DOCKER-USER`, for each port the stack publishes on an address other than loopback |
| `lxc` | A container from the LXC download template (images.linuxcontainers.org), always unprivileged | In `storageforge.labels` in the container folder: LXC has no labels of its own | On the host network, a fence on input for the ports you list. Behind `lxcbr0` nothing outside reaches it; bridged onto a LAN bridge, the host firewall does not see it, and the report says so |
| `incus` | An Incus container or VM, with its profiles, storage pool and network checked first | `user.*` keys on the instance (`user.storageforge.managed=true` marks the ones StorageForge made) | A fence on input for the ports its proxy devices listen on |

**Who may reach it.** The field *Only these may reach what it publishes* takes addresses and ranges. Left empty, the check warns about each port published to every network the host is on. Docker and Podman forward published ports past the host INPUT chain, so a ufw or firewalld rule does not stop them: the rule goes in `DOCKER-USER`, through the same `storageforge-fwrules` tool and with the same rule ids as a `fw-rule` step with hook *forward*. A host with no `DOCKER-USER` chain (Podman with netavark, for one) gets a conflict telling you to publish on one address instead, never a rule that does nothing.

**What the report shows.** For a stack: compose validating the file, the volumes it uses, the lines that change against the compose file deployed before, and whether the stack is already up from this file. For LXC: the distribution, release and network, and whether root needs subordinate ids (root gets `root:1000000:65536` in `/etc/subuid` and `/etc/subgid` when it has none). For Incus: what each profile brings, the image fingerprint when the image server answers, and the exact `incus init` line.

**What the check refuses.** A secret written into a compose file (an `environment` key such as `POSTGRES_PASSWORD` with a value): keep it in a [vault secret](secrets.md), write it to a file with a `secret-file` step, and point `env_file` at that file. A service built from source (this step runs images only). Labels starting `storageforge.`, and on Incus the `user.*` keys cloud-init reads (`user-data`, `vendor-data`, `meta-data`, `network-config`). Ports published to an Incus VM, which Incus forwards only in NAT mode with fixed addresses.

Removing: `workload-remove` takes away an Incus instance or a container, keeping volumes and disks. A stack is taken down with `docker compose down` in its folder by hand for now, and an LXC container with `lxc-destroy`: neither has a step yet.

## Image updates with rollback

The `image-update` step pulls what a stack's compose file or a systemd unit names, recreates what changed, and waits for it to be healthy. If it is not healthy in time, the images it ran before are put back under their names and it is recreated again.

- **A stack** (a compose project): found by its containers' compose labels, updated in the folder and with the files it was started from. *Only this service* limits it to one service.
- **A unit**: a Podman container run by a Quadlet or a unit file, found by the `PODMAN_SYSTEMD_UNIT` label Podman gives it; with Docker, name the container the unit runs. After the pull the unit is restarted, which recreates the container from its definition.
- **A container started by hand** has nothing to recreate it from with a new image and the same settings: adopt it as compose first (see the read side), deploy that as a stack, then update the stack.

**Healthy** means each container passes its healthcheck, or, where it has none, runs for 10 seconds without restarting, within the seconds given (120 by default, 10 to 3600). A container that exits, restarts or turns unhealthy fails it at once.

**Before anything changes,** each image in use is tagged `localhost/storageforge-rollback:<name>-<date>`: that tag is what is put back, and after a good update it stays, so you can go back by hand later (`docker tag` it to the name and recreate). When the pull brings nothing new the tags are taken away again and nothing is recreated. An image pinned by digest is never updated.

The report says which images it would pull and what healthy means, and pulls nothing.
