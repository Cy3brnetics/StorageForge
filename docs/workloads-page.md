# The Workloads page

`/workloads` draws every container and VM of the fleet as one tree, and is where you make a new one or act on one that exists. It reads the same scans as the Infrastructure tab and the Map. It does not refresh by itself: each host says how old its reading is, and a host nobody has scanned says "not read yet" instead of looking empty.

**Built, not lab-tested.** The page and the Proxmox VE steps are built and tested against fixtures and stand-in tools. No real Proxmox VE node has run them yet. See [what is not lab-tested](#what-is-not-lab-tested).

## Reading the tree

The tree runs left to right: the fleet, then each host, then the runtimes found on it, then the workloads.

- **Runtimes:** Docker, Podman, libvirt (KVM), Incus, plain LXC and Proxmox VE. A runtime shows when the host can run it, even with nothing in it, so you can create the first one there.
- **Stacks:** the containers of one Compose project hang under one node, with how many of them run.
- **Dots:** green is running, grey is stopped or exited, red is failed, no dot is something else. The state is written on the card too.
- **Proxmox nodes:** a node has one `proxmox` branch holding its VMs and containers, named by VMID (`101 web`). Proxmox ships `lxc-ls`, so its containers are also read as plain LXC; the page hides that second copy.
- **Seen through connections:** guests that only a platform connection (a Proxmox API token, Xen Orchestra, TrueNAS, a panel) reports, and whose host is not scanned, hang under their own branch. They are read-only here: the steps need SSH to the host.
- **Managed by something else:** a container that Portainer, Komodo, Dockhand or Proxmox manages says so in its panel, with the warning that a change made here can be undone by that tool.

Click a card, or move to it and press Enter, to open its panel: what the scan read (state, image or disks, memory, mounts, networks, ports, findings) and the actions that apply.

| Keys | What they do |
| :-- | :-- |
| Up, Down | Move through the visible cards |
| Right | Unfold a folded card, or move to its first child |
| Left | Fold an open card, or move to its parent |
| Enter | Open the panel |
| `+` | New workload on a host or runtime card |

The **Filter** box keeps the cards whose name, host, runtime or state match, and their parents; the rest fade. **Fold all**, **Unfold all** and the zoom buttons change the view. A fleet of more than twelve hosts starts with the hosts folded. The folds, the filter and the selected card are in the address, so Back and a copied link work.

## Every action is a plan

Nothing on this page changes a host. An action or the create wizard builds one plan step, checks it against the last scan of the host (the same check as **Changes**), and shows the result: red items must be fixed, amber ones are warnings. **Save as a plan** stores a plan with that one step and links to it in **Changes**, where you read the report and apply it as for any plan, through the signed runner and the audit log.

From a panel:

| Runtime | Actions |
| :-- | :-- |
| Docker, Podman | Start, Stop, Restart, Update images (for a stack), Remove |
| libvirt | Start, Stop, Force off, Snapshot, Edit, Snapshots, Remove |
| Incus | Start, Stop, Restart, Force off, Remove |
| LXC | Start, Stop, Restart, Force off, Snapshot, Remove (destroys the container and its root filesystem) |
| Proxmox VE | Start, Shut down, Stop, Reboot, Snapshot, Remove |

An action whose step needs more than the panel knows (a snapshot name, the fields of **Edit**) asks for them in the review. Remove steps that destroy data show a warning and ask you to type the name again. **Save as a plan** stays off until it matches.

The plan's name starts as the step's title and the time. Saving the same action twice in a minute does not fail on the clash: the second one gets `(2)`.

**+ New**, at the top of a host or runtime panel, opens a wizard built from the plan steps' own field lists, so the same form appears in **Changes**. It asks what to create, where, then the step's remaining fields in groups (resources, network, access), and ends in the same review.

## Proxmox VE

Four steps (group *Proxmox VE* in **Changes**) run `qm` and `pct` on the node over SSH, so what they make is a guest of Proxmox itself and shows in the Proxmox web UI, across the cluster.

| Step | What it does |
| :-- | :-- |
| Create a Proxmox VM (`pve-vm`) | `qm create` from an ISO already on a storage of the node, or from a cloud image downloaded on the node, checked against its checksum, imported, and given a cloud-init login |
| Create a Proxmox container (`pve-ct`) | `pct create` from a template on a storage, downloaded with `pveam` when named but absent. Unprivileged by default. The root password, if you set one, comes from a vault secret on stdin and never on a command line |
| Start, stop or snapshot a Proxmox guest (`pve-action`) | `qm` or `pct` start, shutdown, stop, reboot or snapshot, for a VMID and kind |
| Remove a Proxmox guest (`pve-remove`) | `qm destroy` or `pct destroy` with `--purge`, only for a stopped guest, and only when the name you typed is the one the guest has |

What to know:

- **Root SSH.** The steps need an SSH login that is root on the node, because `qm` and `pct` write `/etc/pve`. A host scanned as an ordinary user can see its guests but not change them.
- **Choices from the node.** The scan reads the node's storages, ISOs and container templates. The wizard offers them as lists, and **Another template…** lets you type a name for `pveam` to download. With no reading, or an old one, the field is plain text and the script checks when it runs.
- **VMIDs.** Leave a VMID empty and the script asks the node for the next free one. A VMID that exists is never reused.
- **The generic steps refuse a Proxmox node.** The VM, ISO, LXC and Incus steps refuse a host that is a Proxmox VE node, in their check and again in the script (when `/etc/pve` exists), so nothing is made that Proxmox does not know about. The wizard offers only the Proxmox steps there, and none of them elsewhere. Plain LXC actions and removal refuse a Proxmox node's containers too, and point at the Proxmox steps.
- **No "managed by" warning.** `pve-action` and `pve-remove` are Proxmox's own tools, so Proxmox stays in charge and the page does not warn.
- **Ansible export.** An Ansible export of `pve-ct` with a vault password secret expects the secret's file to be on the host already: the playbook does not carry the secret. Deploy through StorageForge to have it delivered.

## Who sees it

The page needs the `workloads.view` permission, and the buttons need `plans.edit`. An account with the first and not the second can look but not change.

## What is not lab-tested

The page runs in a headless Chromium against fixture data in the test suite, and the generated scripts run against stand-in `qm`, `pct`, `pvesh` and `pveam`. Not yet run:

- Any `pve-*` step on a real Proxmox VE node (`qm create`, `pct create`, `pveam` downloads, `pvesm` readings, destroy).
- The Ansible export of the Proxmox steps.
- The page against a fleet of real size.

The KVM lab can run a Proxmox VE VM; that tier is listed in the [roadmap](../roadmap.md).
