# Platform connections

*Since 0.5.10: built, not lab-tested. Lab tier 27 is written and has not run.*

StorageForge can read a platform through the platform's own HTTPS API as well as over SSH, for what SSH reads badly or not at all: Proxmox guests and their backups, what a Backup Server holds and whether it was verified, the clusters a Datacenter Manager sees. SSH stays the default and keeps everything it does. A connection is something you add, one per platform instance, under **Keys → Platform connections**.

Three platforms can be connected so far, each not lab-tested:

| Platform | What is read | Default port |
| :--- | :--- | :--- |
| Proxmox VE | nodes, guests (VMs and containers) with their state and memory, storage, the backup jobs, and the backups kept on each storage with their last verification | 8006 |
| Proxmox Backup Server | datastores with their usage and estimated full date, backup groups, snapshots with their last verification, verify and prune jobs. Only each datastore's root namespace | 8007 |
| Proxmox Datacenter Manager | the remotes the token may see, and their nodes, guests, storage, datastores and the snapshots on those datastores | 8443 |

TrueNAS, Xen Orchestra, Dockhand, Portainer, Komodo and Pangolin are planned and not built yet.

## Adding one

The screen goes in this order, and does not ask for the next thing before the last is done.

1. **What the token needs.** Pick the platform and what it should see (Proxmox VE: `/`, or `/vms /storage /nodes`; Backup Server: the datastores; Datacenter Manager: the remotes). The guide shows the least the token needs for reading, why each part is needed, and the commands that make it, ready to copy. It is written from each platform's documentation as published on 2026-11-20.
2. **The token.** Give the connection a name, the address (`https://` only: plain HTTP is refused), the token ID (`user@realm!tokenname`) and the secret the platform showed once. The secret goes straight into the vault. Nothing is sent to the platform yet.
3. **The certificate.** StorageForge fetches the certificate the platform presents, with nothing sent but the TLS handshake, and shows its SHA-256 fingerprint. Compare it with the platform's own (`openssl x509 -noout -fingerprint -sha256 -in FILE`, with the file shown on the screen) and accept it. Only then is the token sent, and only to a server presenting that certificate. Cancelling sends nothing.

StorageForge then reads the platform once, starting with the read-back below, and again every hour.

## The least each token needs

The recommendation is always the narrowest that works: never `root@pam`, an admin key or a full-access role. A token of `root@pam` is refused outright, with the reason.

| Platform | For reading | Not offered |
| :--- | :--- | :--- |
| Proxmox VE | A user `storageforge@pve` with no password, an API token with privilege separation on (`-privsep 1`) and an expiry, and `PVEAuditor` (its privileges are the `.Audit` ones) on `/` for the user and for the token. A separated token never has a permission its user lacks, so both need it. Giving it on `/vms`, `/storage` and `/nodes` instead hides the rest of the cluster, and then the backup jobs are not read: listing them checks `Sys.Audit` on `/` | Administrator, PVEAdmin, PVEVMAdmin, PVESysAdmin; privilege separation off |
| Proxmox Backup Server | A user `storageforge@pbs` and a token with an expiry, both given `DatastoreAudit` on `/datastore/NAME` for each datastore. It lists content and cannot read the data | Admin, DatastoreAdmin; an ACL on `/` or `/datastore` when only some datastores should be seen |
| Proxmox Datacenter Manager | A user `storageforge@pdm` and a token, both given the built-in `Auditor` role on `/resource/REMOTE` for each remote. PDM has three roles and no custom ones, so this is the narrowest. Its documentation gives no command that makes a token: make it in the web interface | Administrator on any path; Auditor on `/` when only some remotes should be seen |

**A Datacenter Manager token reaches as far as PDM does.** PDM holds its own token to every remote it manages. Connecting each Proxmox VE and Backup Server directly, each with its own narrower token, is the tighter choice. PDM's list of remotes also carries each remote's own token secret: StorageForge drops it and never stores it. Where a guest is seen both through PDM and directly, the direct reading is the one used.

**Actions.** A connection is read-only: a request that is not a GET is refused by StorageForge itself unless you turned on the action it is for. Turning one on says what it needs, on which object, at that moment and not before:

| Platform | Action | What to add |
| :--- | :--- | :--- |
| Proxmox VE | `snapshot` | a role with `VM.Snapshot` on `/vms/VMID` or `/pool/POOL`, for the user and the token |
| Proxmox VE | `rollback` | `VM.Snapshot.Rollback`, the same way |
| Proxmox VE | `backup` | `VM.Backup` on the guest and `Datastore.AllocateSpace` on `/storage/TARGET` |
| Proxmox VE | `power` | `VM.PowerMgmt` on the guest |
| Proxmox Backup Server | `restore-test` | `DatastoreReader` on the datastore |
| Proxmox Backup Server | `backup` | `DatastoreBackup` on the datastore, only if StorageForge itself sends backups |
| Proxmox Datacenter Manager | none | PDM has no built-in role narrower than Administrator that may manage or migrate guests |

No action is carried out by StorageForge yet: turning one on only tells the read-back that its privileges are wanted.

## The read-back

On every read, StorageForge first asks the platform what the token can really do (`GET /access/permissions`, which answers for the token making the request) and, where the platform says, the token's expiry and privilege separation. It compares that with the guide:

- **Less than needed:** the feature that needs the missing privilege is skipped, the connection says which and what to add, where, and a notification says the same.
- **More than needed:** any privilege that changes something (anything but `.Audit`) that no action you turned on needs. This is a **security finding in the notification center that cannot be muted or snoozed**, critical when the token can change the platform's users, permissions or system. It leaves when a read-back finds the token narrowed or replaced.
- Extra read-only privileges (`Pool.Audit`, all of `/` instead of three paths) are listed and are not a finding: they change nothing.
- Privilege separation off, no expiry date, an expired or disabled token are said beside it.

## The certificate

The platform's certificate is pinned by its SHA-256 fingerprint, the way SSH host keys are pinned here, except that a person accepts it first. Every request checks the certificate before the token is written to the connection. A changed certificate (a renewal, or someone in the middle) gets nothing: the read fails, the connection says *certificate changed*, and a critical security finding is raised that cannot be muted. Accept the new certificate on the screen once you have compared it; the finding leaves.

The check is the fingerprint alone, not a certificate authority or the host name: it is stricter (one certificate, not any a CA signed) and works with the self-signed certificates these platforms make at install. An ACME certificate renews every few months, and each renewal has to be accepted again.

## Limits and timeouts

Each request has a 15 second timeout, at most 10 requests a second go to one platform, one read sends at most 3000 requests and reads at most 5000 backups or snapshots, and an answer larger than 32 MiB is not read. A read is retried only where a retry can help (a dropped connection, 429, 502, 503, 504), never for a refused token or a changed certificate.

## Where it shows

- **Map:** guests the SSH scan does not already draw are drawn with source `api`, inside their host's frame when the Proxmox node is a scanned host, otherwise hanging from the platform. A guest the scan draws gets the API's reading as a property, not a second node. Proxmox storage and Backup Server datastores are drawn in the storage layer, a datastore linked to the mount it is on.
- **Workloads:** a Proxmox guest the scan lists gets the API's state beside its own, and what the two disagree on. A guest only the API sees is added, marked as read from the API.
- **Compared, not merged:** where the SSH scan reads the same thing (Proxmox guests through `qm` and `pct`, the mount a datastore sits on), both are shown, with each field they disagree on. Neither overwrites the other. A guest only the scan sees is marked as not seen by the API, which may mean the token cannot see it.
- **Notifications:** a backup or snapshot whose last verification failed, a storage over 90 percent full, a datastore full within 30 days, a backup group with no backup in a week, a verify job that did not end well, and (for information) guests in no enabled backup job.

## What a taken-over web app can do with a stored token

The web app is the part of StorageForge that faces the browser, and it is the part that reads platforms. What it can and cannot do with a token kept here:

- **It can have a token released and use it, for that platform only.** The token's vault row carries a policy naming the one platform instance (`pve:NAME`), sealed with it. With the key enclave the policy is checked inside the enclave, each release is written into the audit log by the enclave, and one secret leaves at most 60 times a minute. A web app taken over could make the platform calls the token allows, within those limits, and each release would be written up.
- **What the token allows is what the platform allows it.** That is why the guide recommends only `.Audit` privileges and the read-back raises an un-mutable finding for anything more: a taken-over web app holding an auditor token can read the platform and change nothing on it. StorageForge's own read-only rule (no request but GET unless an action is on) is a second fence, but it lives in the same process, so the platform's permissions are the one that counts.
- **It cannot send the token anywhere else through StorageForge.** The token goes only into the Authorization header of a request to the accepted certificate; changing the accepted certificate takes a fresh password and is in the audit log.
- **It cannot read a token back through any route.** No answer, audit row, log line or error message holds one; the tests search each of them for it.
- **Without the key enclave**, the web app holds the vault key while it runs and could open any token, as it could any SSH key or secret. The enclave is the layer that takes that away, and narrow tokens are what limits the damage either way.

Removing a connection deletes its token from the vault, not from the platform: delete it there too.

## Routes

| Route | What it does | Needs |
| :--- | :--- | :--- |
| `GET /api/keys/platforms` | the connections, never a token | `keys.view` |
| `GET /api/keys/platforms/guide/KIND[?scope=&user=&token=]` | the guide for a platform | `keys.view` |
| `GET /api/keys/platforms/guide/KIND/ACTION` | what one action needs | `keys.view` |
| `POST /api/keys/platforms` | add a connection: the token into the vault, the certificate shown | `keys.manage`, a fresh password |
| `GET /api/keys/platforms/ID/certificate` | the certificate the platform presents now | `keys.view` |
| `POST /api/keys/platforms/ID/certificate` | accept a certificate by its fingerprint | `keys.manage`, a fresh password |
| `PUT /api/keys/platforms/ID/actions` | turn actions on or off | `keys.manage`, a fresh password |
| `POST /api/keys/platforms/ID/read` | read back the token and read the platform | `keys.manage` |
| `GET /api/keys/platforms/ID` | one connection, what it read and how that compares with the scan | `keys.view` |
| `DELETE /api/keys/platforms/ID` | remove it and its token | `keys.manage`, a fresh password |

Each write is in the audit log (`platform.add`, `platform.certificate`, `platform.actions`, `platform.read`, `platform.remove`), with the token ID and never the token.
