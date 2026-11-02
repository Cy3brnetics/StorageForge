# Proxmox, TrueNAS and XCP-ng

StorageForge connects to these the way it connects to any host: over SSH, with no agent and no API key. A scan works out which one it's on and says so, and that decides what it may do there.

| Platform | Tested version | Scans | Deploys |
| :--- | :--- | :--- | :--- |
| Proxmox VE | 9.2 | Yes | Yes: shares, jobs, tasks and change plans |
| TrueNAS Community Edition | 25.10 | Yes | Refused |
| XCP-ng | 8.3 | Yes | Refused |
| XenServer | Not tested | Should work like XCP-ng | Refused |

ESXi isn't supported or tested: its installer needs a Broadcom account, so the lab can't build one.

Deploys are refused on TrueNAS and XCP-ng because an upgrade replaces the system they would change, and on TrueNAS `/usr` is read-only and the package tools are turned off. The setup scripts stop before they change anything.

## Connect

Create an ordinary user on the host, give it your SSH key, and scan it. Don't scan as root.

### Proxmox VE

A new install needs two changes before deploys work:

1. It has no `sudo`, and deploys run through it. The host check says so.
2. Its paid repository is on, so without a subscription `apt-get update` fails with a 401 and nothing can be installed. The host check warns about this. Under **Node > Updates > Repositories**, turn off the enterprise repositories and turn on no-subscription.

Then run:

```bash
apt-get update && apt-get install sudo
```

Scans skip `/etc/pve`, which is the cluster's configuration rather than storage.

### TrueNAS

SSH is off by default. Turn it on under **System > Services**, and create the user under **Credentials > Users** with a home folder and your SSH key.

[Read-only scan access](target-hosts.md) can't be added, because it installs a program under the read-only `/usr`. A scan sees only what its user may read, so give that user read permission on the datasets you want indexed. Set up shares and jobs in TrueNAS itself.

### XCP-ng

Add the user from the control domain's shell. Guest disks live in storage repositories under `/run/sr-mount`, which only root can enter. Until read-only scan access is set up there, the scan shows as partial, with the repository listed as failed. Scan access works here even though deploys don't.

## Limits

- **Files and disks only:** scans read filesystems, pools and volumes. StorageForge doesn't list VMs or containers, or use the Proxmox, TrueNAS or Xen APIs.
- **TrueNAS's own datasets:** a scan indexes the system's datasets, such as `/usr` and `/var`, as well as your pools.
- **Tested on single hosts:** the lab has no Proxmox cluster, Ceph or TrueNAS with apps installed.

See [KVM lab](kvm-lab.md#appliances) for how these are tested.
