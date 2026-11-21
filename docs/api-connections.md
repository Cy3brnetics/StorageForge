# Platform connections

*Since 0.5.10: built, not lab-tested. Lab tier 27 is written and has not run.*

StorageForge can read a platform through the platform's own HTTPS API as well as over SSH, for what SSH reads badly or not at all: Proxmox guests and their backups, what a Backup Server holds and whether it was verified, the clusters a Datacenter Manager sees, what TrueNAS's middleware knows, the VMs of an XCP-ng pool, what a Docker panel manages, and what Pangolin publishes. SSH stays the default and keeps everything it does. A connection is something you add, one per platform instance, under **Keys → Platform connections**.

Nine platforms can be connected, each built and not lab-tested:

| Platform | What is read | Default port |
| :--- | :--- | :--- |
| Proxmox VE | nodes, guests (VMs and containers) with their state and memory, storage, the backup jobs, and the backups kept on each storage with their last verification | 8006 |
| Proxmox Backup Server | datastores with their usage and estimated full date, backup groups, snapshots with their last verification, verify and prune jobs. Only each datastore's root namespace | 8007 |
| Proxmox Datacenter Manager | the remotes the token may see, and their nodes, guests, storage, datastores and the snapshots on those datastores | 8443 |
| TrueNAS | pools and their health, datasets, periodic snapshot tasks and replication with how their last run went, SMB and NFS shares, apps, and TrueNAS's own alerts. Through the middleware's JSON-RPC API over a WebSocket (25.04 and later). Not individual snapshots | 443 |
| Xen Orchestra | pools, hosts, VMs with their state, memory and CPUs, storage repositories and their usage, backup jobs and the last run of each | 443 |
| Dockhand | environments, and the containers and Compose stacks in each. Not images and volumes yet | 3000 (behind HTTPS) |
| Portainer | environments, stacks, and the containers of each Docker environment. Kubernetes environments are not read | 9443 |
| Komodo | servers, stacks, deployments, and the containers on each server | 9120 |
| Pangolin | sites, the resources it publishes with their domain, the login in front of each and where each goes, and the domains | 443 (the Integration API, usually at `api.YOUR-DOMAIN`) |

Dockhand and Komodo serve plain HTTP unless told otherwise: put them behind HTTPS, since StorageForge refuses plain HTTP.

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
| TrueNAS | A local user `storageforge` with no password and no shell, in a group of its own; that group in a privilege granting only `READONLY_ADMIN` with no web shell; a user-linked API key with an expiry. TrueNAS 25.10 deprecates privileges built from single roles, so the predefined `READONLY_ADMIN` is the narrowest it keeps. The token ID is the user name, since TrueNAS logs a key in with it | `FULL_ADMIN`, `SHARING_ADMIN`, the web shell; root, `truenas_admin`, `admin` (refused) |
| Xen Orchestra | A user that is not an administrator, given one RBAC role with only `read` on `pool`, `host`, `vm`, `sr`, `backup-job` and `backup-log`, each narrowed with a `$pool` selector where only some pools should be seen, and a token made by that user (tokens always expire). Narrower than the built-in Read only template, which also reads users and groups | permission admin, the Administrator and scoped administrator templates, `sr import:vdi:url`; `admin@admin.net` (refused) |
| Dockhand | An enterprise key (roles are enforced only with one), a user given only a role with view on environments, containers, stacks, images and volumes, tied to chosen environments, and a token of that user with an expiry. Narrower than the built-in Viewer role, which also gives inspect (container environments, where secrets often are) and logs | the Admin role; a Hawser agent token; Dockhand without an enterprise key, where every user has full access |
| Portainer | A user that is not an administrator, with the Read-only user role on chosen environments (Business Edition) or only those environments (Community Edition, which has no read-only role), and an access token made by that user | an administrator or Environment administrator; `admin` (refused) |
| Komodo | A service user that is not an admin, in a user group with Read on servers, stacks and deployments and no specific permissions, and an API key with an expiry. The token ID is the key, the token is the secret | admin, Write, Terminal and Inspect on a server |
| Pangolin | An organization API key (not a root key) with only `listSites`, `listResources`, `listTargets`, `listOrgDomains` and `listApiKeyActions`. The token ID is `KEYID@ORG`: the part of the key before the dot, then the organization | a root key, any create, update or delete permission, `getVirtualApiKey` |

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
| TrueNAS | `snapshot` | `REPLICATION_ADMIN` on the StorageForge privilege; it also lets the key change replication tasks and keychain credentials, and is the narrowest TrueNAS 25.10 keeps |
| Xen Orchestra | `snapshot`, `power` | `vm snapshot`, or `vm start` and `shutdown:clean`, in the role, narrowed by a selector |
| Dockhand | `redeploy` | a role with stack edit and start, tied to the one environment |
| Portainer | `redeploy` | Operator on the one environment |
| Komodo | `redeploy` | Execute on the stacks it may redeploy |
| Pangolin | none | StorageForge only reads what Pangolin publishes |

No action is carried out by StorageForge yet: turning one on only tells the read-back that its privileges are wanted.

## The read-back

On every read, StorageForge first asks the platform what the token can really do and, where the platform says, the token's expiry. Each platform says it its own way:

| Platform | What the read-back asks |
| :--- | :--- |
| Proxmox VE, Backup Server, Datacenter Manager | `GET /access/permissions` (answered for the token making the request) and the token's own entry, for its expiry and privilege separation |
| TrueNAS | `auth.me` for the roles of the session, `api_key.my_keys` for the expiry of the key in use (known by the number before its dash) |
| Xen Orchestra | `/users/me` (an administrator has every endpoint) and `/users/me/acl-privileges`; the expiry of the token in use from the user's token list, read in memory and dropped |
| Dockhand | whether an enterprise key enforces roles, whether the token may manage the license or list users, the expiry of the token in use (known by its prefix). Dockhand gives a token no way to read its own permissions, and the read-back says so |
| Portainer | the user's role (1 is an administrator), the edition, and the role it holds on each environment (`/users/ID/effective-access`) |
| Komodo | the key's expiry from `ListApiKeys`, whether the admin-only `ListUsers` answers, and the level and specific permissions on each server, stack and deployment (`GetPermission`, user groups included) |
| Pangolin | the key's own actions (`listApiKeyActions`, which is why the guide includes it) |

It compares that with the guide:

- **Less than needed:** the feature that needs the missing privilege is skipped, the connection says which and what to add, where, and a notification says the same.
- **More than needed:** any privilege that changes something (anything but `.Audit`) that no action you turned on needs. This is a **security finding in the notification center that cannot be muted or snoozed**, critical when the token can change the platform's users, permissions or system. It leaves when a read-back finds the token narrowed or replaced.
- Extra read-only privileges (`Pool.Audit`, all of `/` instead of three paths) are listed and are not a finding: they change nothing.
- Privilege separation off, no expiry date, an expired or disabled token are said beside it, and so is anything the platform would not say.

## Expiry and replacing a token

The guide sets an expiry wherever the platform allows one (a year from now in its commands). Where the platform says when a token lapses (the three Proxmox products, TrueNAS, Xen Orchestra, Dockhand, Komodo), the read-back reads it; elsewhere the date you give with the token is used, and the connection says which. Portainer and Pangolin keys cannot expire: give the date you mean to replace the key by.

- **A warning before it lapses:** a notification 30 days before, critical in the last 7 days and once it has expired. It can be snoozed: it is not a security finding.
- **Replace the token** on the connection. The new token is sealed beside the old one and read back against the platform first. It is taken only when the platform takes it, it reads at least what the old one read, and it can do no more than StorageForge needs. Otherwise it is dropped, the old one stays in place and keeps working, and the answer says why. This is the secret store's rotation (staged where it is used, switched only once that took) with the platform as the one place.
- **The old token still works on the platform** until you delete it there. The connection and an information notification say so until you press *The old token is deleted*.

## The certificate

The platform's certificate is pinned by its SHA-256 fingerprint, the way SSH host keys are pinned here, except that a person accepts it first. Every request checks the certificate before the token is written to the connection. A changed certificate (a renewal, or someone in the middle) gets nothing: the read fails, the connection says *certificate changed*, and a critical security finding is raised that cannot be muted. Accept the new certificate on the screen once you have compared it; the finding leaves.

The check is the fingerprint alone, not a certificate authority or the host name: it is stricter (one certificate, not any a CA signed) and works with the self-signed certificates these platforms make at install. An ACME certificate renews every few months, and each renewal has to be accepted again.

## Limits and timeouts

Each request has a 15 second timeout, at most 10 requests a second go to one platform, one read sends at most 3000 requests and reads at most 5000 backups or snapshots, and an answer larger than 32 MiB is not read. A read is retried only where a retry can help (a dropped connection, 429, 502, 503, 504), never for a refused token or a changed certificate.

## Where it shows

- **Map:** guests the SSH scan does not already draw are drawn with source `api`, inside their host's frame when the Proxmox node is a scanned host, otherwise hanging from the platform. A guest the scan draws gets the API's reading as a property, not a second node. Proxmox storage and Backup Server datastores are drawn in the storage layer, a datastore linked to the mount it is on.
- **Workloads:** a Proxmox guest the scan lists gets the API's state beside its own, and what the two disagree on. A guest only the API sees is added, marked as read from the API.
- **Compared, not merged:** where the SSH scan reads the same thing (Proxmox guests through `qm` and `pct`, the mount a datastore sits on), both are shown, with each field they disagree on. Neither overwrites the other. A guest only the scan sees is marked as not seen by the API, which may mean the token cannot see it.
- **Notifications:** a backup or snapshot whose last verification failed, a storage over 90 percent full, a datastore full within 30 days, a backup group with no backup in a week, a verify job that did not end well, and (for information) guests in no enabled backup job. TrueNAS: a pool that is not healthy, a replication or snapshot task whose last run failed, TrueNAS's own critical alerts. Xen Orchestra: a backup job whose last run failed, a storage repository over 90 percent full. The panels: containers they manage that are not running. Pangolin: a resource published with no login in front, an offline site. And for every connection, a token about to expire.
- **The other platforms beside the scan:** TrueNAS pools against `zpool status` from the last SSH scan of the same host, and apps against the Compose projects the scan lists (an app is the project `ix-NAME`); Xen Orchestra's storage repositories against the mounts the scan read under `/run/sr-mount/SR-UUID` on the XCP-ng hosts, which is what a scan sees of an SR; each panel's containers against the containers the scan's Docker reading lists on the same host, by name and state. A pool or SR the scan draws gets the API's reading as a property, not a second node.
- **Exposure:** where the SSH scan found Pangolin's Newt running and could not say what it carries, a Pangolin connection that reads a site of that host name fills it in: each published resource shows in the exposure view as public, with the login in front of it and where it goes, whatever the host's firewall says. Nothing stored changes: the reading is filled when it is asked for.
- **What a panel manages (section 6):** `apiviews.managed_by(conn, host)` says which containers on a host Dockhand, Portainer or Komodo manage, from their own APIs. It is the hook for the externally managed detection, which is built apart; nothing calls it yet.

## What a taken-over web app can do with a stored token

The web app is the part of StorageForge that faces the browser, and it is the part that reads platforms. What it can and cannot do with a token kept here:

- **It can have a token released and use it, for that platform only.** The token's vault row carries a policy naming the one platform instance (`pve:NAME`), sealed with it. With the key enclave the policy is checked inside the enclave, each release is written into the audit log by the enclave, and one secret leaves at most 60 times a minute. A web app taken over could make the platform calls the token allows, within those limits, and each release would be written up.
- **What the token allows is what the platform allows it.** That is why the guide recommends only `.Audit` privileges and the read-back raises an un-mutable finding for anything more: a taken-over web app holding an auditor token can read the platform and change nothing on it. StorageForge's own read-only rule (no request but GET unless an action is on) is a second fence, but it lives in the same process, so the platform's permissions are the one that counts.
- **It cannot send the token anywhere else through StorageForge.** The token goes only into the header the platform reads it from (for TrueNAS, the login call inside the TLS connection) of a request to the accepted certificate, and a redirect is followed only to another API path on the same server; changing the accepted certificate takes a fresh password and is in the audit log.
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
| `POST /api/keys/platforms/ID/token` | replace the token: read back first, taken only if it passes | `keys.manage`, a fresh password |
| `POST /api/keys/platforms/ID/token/previous` | say the replaced token is deleted on the platform | `keys.manage` |
| `DELETE /api/keys/platforms/ID` | remove it and its token | `keys.manage`, a fresh password |

Each write is in the audit log (`platform.add`, `platform.certificate`, `platform.actions`, `platform.read`, `platform.token`, `platform.token_previous`, `platform.remove`), with the token ID and never the token. `POST /api/keys/platforms` also takes `expires_at` (a date or epoch seconds) for a platform that cannot say when its token lapses.
