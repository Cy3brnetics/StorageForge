# Install and set up

This guide takes a fresh machine to a working StorageForge, then brings hosts in step by step. It covers:

- installing it and signing in for the first time;
- scanning a first host, then giving it read-only access and deploy access;
- the optional parts: libvirt hosts, the web console, Tailscale keys, alerts, backups and remote nodes;
- running it without Docker, upgrading it, and removing it.

Each step says how to check that it worked. [Getting started](getting-started.md) is the short version of the same path.

StorageForge is meant for a LAN, behind its own TLS proxy. Do not publish it on the internet. The one part that may face it is the optional [tunnel for remote nodes](remote-nodes.md).

## 1. What you need

### The StorageForge machine

Any Linux machine that stays on: a small server, a VM or a NAS that runs containers.

| Needed | Notes |
| :--- | :--- |
| Docker Engine with Compose v2 | `docker compose version` prints v2.x |
| CPU, memory and disk | The index grows with the number of files scanned, and backups of it sit beside it. Large indexes (millions of files) want more memory and a fast disk; see [PostgreSQL](#postgresql) |
| Git | To fetch the code and to upgrade |
| A fixed address or DNS name | Hosts report back to it, and its certificate names it |

It needs to reach each host on its SSH port. The web UI is served on port 8443.

### The hosts to scan

Each host needs:

- **Linux, with an SSH server and a login with a key.** Nothing is installed to scan: it uses `find`, `findmnt`, `lsblk` and `df`, and `zpool`, `btrfs`, `lvs`, `git`, `docker` or `podman` when present.
- **To be changed by plans and deploys:** `bash`, `sudo`, `flock`, systemd, and OpenSSH 8.1 or later. Alpine can be scanned but not deployed to, because it has no bash or systemd.

[Target hosts](target-hosts.md) lists what each kind of step needs.

## 2. Install

### Get the code

```bash
git clone ssh://git@10.42.0.3:2222/Gabe/StorageForge.git     # or https://github.com/Cy3brnetics/StorageForge.git
cd StorageForge/storageforge-indexer
git checkout v0.5.2                                           # a release; main is the latest
```

### Choose settings before the first start

Put settings in a file `.env` beside `docker-compose.yml`. All are optional. Those worth deciding now:

```bash
# .env
STORAGEFORGE_TLS_NAMES=storageforge.lan,10.0.20.10     # extra names and addresses for the self-signed certificate
STORAGEFORGE_HTTPS_PORT=8443                           # the port the web UI is published on
# STORAGEFORGE_HTTPS_BIND=127.0.0.1                    # only this machine, for a reverse proxy in front
STORAGEFORGE_SCAN_INTERVAL=6h                          # rescan bound hosts this often (90m, 6h, 1d)
```

- **The certificate is made on the first start.** It names the machine's hostname and main address, plus `STORAGEFORGE_TLS_NAMES`, so set that first. To use your own certificate instead, see [Certificates](operations.md#certificates).
- **Every other setting** is in [Operations → Configuration](operations.md#configuration).

### Start it

```bash
docker compose up -d --build
docker compose ps
```

The first start runs the one-shot `init-secrets` service, then exits. It makes three things, each in a Docker volume:

- the vault secret, which unlocks the encrypted key vault;
- the session secret;
- the self-signed certificate.

Nothing is needed on the host for this, so a stack manager such as Portainer or Dockge can deploy the folder as it is.

**It worked if** `docker compose ps` shows `storageforge` and `proxy` running and healthy, and `init-secrets` exited 0. To ask the app itself:

```bash
docker compose exec storageforge storageforge-index healthcheck
```

### Back up the vault secret now

Without the vault secret, the vault and every SSH key in it are lost. Backups never contain it, and `docker compose down -v` deletes it. Copy it somewhere that is not this machine, such as a password manager:

```bash
docker compose exec storageforge cat /run/sf-secrets/vault_secret
```

### Make the first admin

Either:

```bash
docker compose exec storageforge storageforge-index user add admin     # prompts for a password, 12 characters or more
```

or name the site and take a one-time link instead, so no password is typed on the server:

```bash
docker compose exec storageforge storageforge-index site init --name home
# First admin, once and within 3 days: https://<this machine>/enroll#...
```

`site init` also sets the vault to take only keys generated in it. See [Starting a new site](operations.md#starting-a-new-site).

### Sign in

Open `https://<this machine>:8443`. The browser warns about the certificate the first time. Before you accept it, compare its fingerprint with the one the stack printed:

```bash
docker compose logs init-secrets | grep -i fingerprint
```

Sign in as `admin`. Add other people from the **Audit** panel (accounts, invite links and roles), each with the role they need. See [Administration](features/administration.md#accounts-and-sign-in).

## 3. Your first host

These steps are for one host, `nas-02` at `10.0.20.5`. They work the same for a fleet: bind a key to a network instead of one address.

### Make a scan account on the host

On the host, as root. The account needs no password and no sudo:

```bash
useradd --system --create-home --shell /bin/bash scan
install -d -m 0700 -o scan -g scan ~scan/.ssh
```

### Make a key in the vault and put it on the host

```bash
docker compose exec storageforge storageforge-index vault generate --name fleet
```

This prints the public key. Then either:

- **Append it to the host's `~scan/.ssh/authorized_keys`** (mode 0600, owned by `scan`).
- **Use Keys → Install on a host** in the web UI. It asks for that account's password once, confirms the host key with you first, installs the key, and checks that the key logs in.

### Bind it and scan

A binding says which hosts a key may reach, as which login. It can name one host, a glob or a CIDR:

```bash
docker compose exec storageforge storageforge-index vault bind --key fleet --host 10.0.20.0/24 --user scan
docker compose exec storageforge storageforge-index scan --host 10.0.20.5
```

The first scan pins the host's SSH key. A key that changes later is refused until a person confirms it.

**It worked if:**

- The scan ends with `ok` and a file count.
- The host appears in **Topology**, with its disks, filesystems and mounts.
- Searching for a file name you know on it finds it.

Bound hosts are rescanned every `STORAGEFORGE_SCAN_INTERVAL`. You can also scan from **Scans** in the web UI.

### Give it read-only scan access

A plain account sees only what it may read, so folders of other users show as unreadable. Read-only scan access lets the scan read everything without being root, and makes the key the host signs its scans with. It gives the scan account copies of `find` and `sha256sum` that can read any file and nothing more. Either:

- **Access → Set up read-only access** in the web UI. It asks you to confirm the host key, then takes a sudo password for that one session: the scan account's, or an admin's.
- **By hand,** from a machine where you can sudo on the host:

```bash
docker compose exec -T storageforge storageforge-index access script --host 10.0.20.5 | ssh admin@10.0.20.5 sudo sh
```

The script needs `setcap` (`libcap2-bin` on Debian and Ubuntu, `libcap` on Fedora and RHEL).

**It worked if** the next scan finds no unreadable folders, and `storageforge-index access signing` shows the host's last scan as signed. See [Scanning](scanning-and-search.md#unreadable-folders-and-read-only-access).

### Give it deploy access

Until now StorageForge only reads. To let it run plans, jobs, shares and tasks on the host, set up deploy access once. This makes:

- a `storageforge-deploy` account with no password;
- a runner, `storageforge-run`, which runs only scripts StorageForge signed in the last ten minutes, once each;
- a sudoers rule for that runner and nothing else.

Either:

- **Deploy → Set up…** in the web UI, with a sudo password for that one session. StorageForge then binds its deploy key and proves that a signed run works.
- **By hand:**

```bash
docker compose exec storageforge storageforge-index deploy setup-script > setup.sh
scp setup.sh admin@10.0.20.5: && ssh -t admin@10.0.20.5 sudo bash setup.sh
```

Then press **I ran it: test** in the Deploy panel.

**It worked if** the host shows `ready` under **Deploy**. Every deploy reports first, and changes only when you apply it. See [Deployments](deployments.md#setting-up-deploy-access).

### Scanning the Docker host itself

Connections from the container to the machine it runs on come in on the `sf0` bridge, not from the LAN. A firewall that allows SSH only from the LAN drops them, and those scans time out. With ufw:

```bash
sudo ufw allow in on sf0 to any port 22 proto tcp
```

## 4. Optional parts

### libvirt hosts and VMs

A host running libvirt with deploy access is measured every 6 hours, or with **Infrastructure → Measure now**. Its VMs, snapshots, networks and pools then show under **Infrastructure → Workloads**. From there you can:

- take a snapshot of a VM, change it, copy it to another libvirt host, or create one from a cloud image;
- change the host's networks and pools.

Each of these is a plan step. See [VMs on libvirt](vms.md).

For snapshots that freeze a VM's filesystems first, install `qemu-guest-agent` in the guest. VMs made by **Create a VM here…** do this when **Install the guest agent** is ticked.

### The web console

A terminal in the browser on a host or VM: over SSH by LAN or Tailscale, or a VM's serial console.

1. **Bind a key for it,** apart from the scan key, as the account the terminal opens:

```bash
docker compose exec storageforge storageforge-index vault bind --key ops --host 10.0.20.5 --user admin --actions console
```

2. **Give `console.open` only to those who need it.** Admins have it. Each session asks for the password again.
3. **To keep recordings,** turn recording on in the console page's admin panel. It is off until then, and opening and closing each session is in the audit log either way.

See [Console](console.md).

### Tailscale

To join hosts to a tailnet with a plan step, keep the auth key in the vault rather than in a plan:

```bash
docker compose exec -T storageforge storageforge-index vault secret-add tailscale-key < key.txt     # one line: the auth key
```

Then add a **Join a tailnet** step to a plan. See [Secrets for plan steps](security.md#secrets-for-plan-steps).

### Alerts

Under **Deploy → Reporting and alerts**, set:

- **Report URL:** the address hosts use to report job runs back, such as `https://storageforge.lan:8443`.
- **Alert channel:** ntfy, Gotify or a webhook.

Then press **Test**. See [Reporting, alerts and drift](deployments.md#reporting-alerts-and-drift).

### Backups of StorageForge itself

A backup of the essentials runs nightly at 03:00 into the `backups` volume, and the newest 14 are kept. Copy them off the machine, together with the vault secret you saved. Restoring is in [Operations → Backups](operations.md#backups), and a full rebuild elsewhere in [Disaster recovery](disaster-recovery.md).

### Remote nodes

For hosts StorageForge cannot reach directly, such as one behind NAT, a node there connects out through a tunnel. See [Remote nodes](remote-nodes.md).

### PostgreSQL

SQLite is the default and suits most sites. For very large indexes, build with `--build-arg EXTRAS=postgres` and set `STORAGEFORGE_DB=postgresql://user@host/storageforge`. See [Operations → PostgreSQL](operations.md#postgresql).

## 5. Without Docker

For development, or a machine without Docker. You need Python 3.10 or later and the OpenSSH client.

```bash
cd StorageForge/storageforge-indexer
python3 -m venv .venv && . .venv/bin/activate
pip install .                                                   # or: pip install '.[postgres]'
export STORAGEFORGE_VAULT_SECRET="$(openssl rand -base64 48)"   # keep it: it unlocks the vault
export STORAGEFORGE_SESSION_SECRET="$(openssl rand -base64 48)"
storageforge-index vault init
storageforge-index user add admin
storageforge-index serve --listen 127.0.0.1 --port 8080
```

- **The database** is `~/.local/share/storageforge/index.db`.
- **The session secret:** without `STORAGEFORGE_SESSION_SECRET`, everyone is signed out at each restart.
- **Plain HTTP** is fine on loopback only. For anything else, put a TLS proxy in front and set `STORAGEFORGE_COOKIE_SECURE=1` and `STORAGEFORGE_PROXY_HOPS=1`.

## 6. Upgrade

```bash
cd StorageForge/storageforge-indexer
git fetch --tags && git checkout v0.5.2          # the release you want
docker compose up -d --build
```

- **Before an upgrade,** read its *Upgrade notes* in the [changelog](../CHANGELOG.md). Some ask you to run a host's access script again.
- **Migrations** run on start, and the web UI is unavailable while they run.
- **Images** are tagged by version, so `--build` makes the new ones.

## 7. Remove

- **From each host,** remove deploy access first: **Deploy → Remove**, or run the `--remove` script. Then remove read-only access (`access script --remove`) and the scan account.
- **From the StorageForge machine:**

```bash
docker compose down        # keeps the volumes: the index, the vault and its secret
docker compose down -v     # also deletes them, with no way back
```

## When something does not work

[Troubleshooting](troubleshooting.md) covers:

- starting up: a locked vault, the certificate warning, keys not imported;
- scanning: a host key mismatch, unreadable folders, the delete guard;
- plans and deploys: the password asked again, a plan already running.

`docker compose logs storageforge` shows the server's own log. The host's side of every deploy is in `/var/log/storageforge/` on that host.
