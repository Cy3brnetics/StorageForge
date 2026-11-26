# Network filesystems and remote storage

StorageForge mounts remote storage on your hosts and serves a host's folders to other hosts. Two places do it:

- **Change plans, Mounts → Mount an rclone remote:** any of rclone's backends (Google Drive, OneDrive, Dropbox, S3 and every S3-compatible service, Backblaze B2, Azure, Google Cloud Storage, WebDAV and Nextcloud, SFTP, FTP, SMB, Proton Drive, pCloud, Mega and more) mounted on one host, with **rclone crypt** on top if you want it.
- **The share wizard:** a folder on one host served to others, and mounted on each client, in one deploy. NFS and SMB, and the protocols below.

Passwords, keys and tokens are never in a plan, a design, a script or a log. Each lives in the vault as a secret (**Keys → Secrets for plan steps**, or `storageforge-index vault secret-add NAME`), reaches the host only when you apply from StorageForge, on the signed runner's stdin, and is written into a file only root can read.

## Mount an rclone remote

| Field | What to put |
| :-- | :-- |
| Remote name | A short name, such as `gdrive`. It names the config file, `/etc/storageforge/rclone/gdrive.conf`. |
| Backend | The rclone backend: `drive`, `s3`, `webdav` … Any name `rclone help backends` lists works. |
| Folder or bucket | Where in the remote to mount, such as `Backups/nas` or `my-bucket/data`. Empty is the remote's top. |
| Settings that are not secret | `key=value`, comma separated, as `rclone config` names them: `scope=drive.file`, `provider=Minio,endpoint=https://minio.lan:9000`. A password, key or token here is refused. |
| Vault secret with its rclone config lines | The sensitive part of the remote, one `key = value` per line, the way `rclone config show` prints it. |
| Encrypt with rclone crypt | Files are encrypted before they leave the host. |
| Vault secret with the crypt passwords | `password = …`, and optionally `password2 = …` (the salt). Plain text: the host obscures them itself. |
| Mount point, owner, VFS cache | Where it appears, who the files look owned by, and rclone's cache mode (`writes` suits most programs). |

The host gets rclone and FUSE from its package manager, the config file (0600, root), and a unit, `storageforge-rclone-<mount point>.service`. The unit waits for the network, restarts rclone when it fails, and never holds up boot when the remote can't be reached. The config is rewritten, and the mount restarted, only when the remote's settings or secrets change.

### Keep the crypt secret safe

rclone crypt is real encryption: **without the crypt secret, nobody can read the files again, StorageForge included.** The vault and its backups keep it. Keep a copy offline too, somewhere that doesn't depend on the host or on StorageForge.

### Google Drive: your own client ID

rclone's shared Google client ID is being retired during 2026: Google is starting to charge for requests on it. So a Drive remote takes a client of your own. It is free, takes about ten minutes, and you only do it once:

1. In the [Google Cloud console](https://console.cloud.google.com/), create a project, then **APIs & Services → Library → Google Drive API → Enable**.
2. **OAuth consent screen:** choose *External*, fill in the app name and your email, and add yourself as a test user. Then **Publish app** to *In production*. Leave it in *Testing* and the login expires after 7 days. Google shows an "unverified app" warning when you sign in; that is expected for an app only you use.
3. **Credentials → Create credentials → OAuth client ID**, type *Desktop app*. Copy the client ID and secret.
4. On any machine with a browser and rclone, run:

   ```bash
   rclone authorize "drive" "YOUR_CLIENT_ID" "YOUR_CLIENT_SECRET"
   ```

   Sign in, and rclone prints a token: a line of JSON.
5. Put all three in one vault secret:

   ```text
   client_id = YOUR_CLIENT_ID
   client_secret = YOUR_CLIENT_SECRET
   token = {"access_token":"…","token_type":"Bearer","refresh_token":"…","expiry":"…"}
   ```

   ```bash
   docker compose exec -T storageforge storageforge-index vault secret-add gdrive-rclone < gdrive.txt && shred -u gdrive.txt
   ```

6. Add a **Mount an rclone remote** step: backend `drive`, secret `gdrive-rclone`, and `scope=drive.file` in the settings if rclone should only see what it made. Tick encryption and name a second secret for the crypt passwords if you want the files encrypted.

The token refreshes itself on the host. An account in Google's Advanced Protection Program can't use a self-made client; use a service account or another backend there.

## The share wizard's protocols

| Protocol | Server side | Clients | Who may connect |
| :-- | :-- | :-- | :-- |
| NFS | nfs-server | kernel mount | addresses and subnets |
| SMB | Samba | cifs mount | Samba accounts |
| SFTP | OpenSSH's internal-sftp, chrooted to the share; nothing to install | sshfs, with a key from the vault and the server's host key pinned from StorageForge's scan | accounts on the server |
| S3 | `rclone serve s3`: the folder is a bucket; access keys from the vault | rclone mount, optionally rclone crypt so data is encrypted before it leaves the client | addresses and subnets |
| WebDAV | `rclone serve webdav`, users from an htpasswd vault secret, optional TLS | rclone mount, optional crypt | addresses and subnets |
| rclone serve | serves an rclone *remote* (an encrypted Google Drive, say) over WebDAV, SFTP, S3 or HTTP, so only the server holds the cloud credentials; the folder is its cache | rclone mount | addresses and subnets |
| iSCSI | Linux LIO (targetcli), a file image in the folder, CHAP from the vault, ACLs for each client's initiator | open-iscsi, formatted only when the disk is blank, mounted by UUID | one client (a non-cluster filesystem) |
| NVMe over TCP | the kernel's nvmet, a file image or a block device, host NQN allow-list | nvme-cli, formatted only when blank, mounted by UUID | one client |
| virtiofs | the KVM host adds the folder to the VM's definition (takes effect at the VM's next power cycle) | `mount -t virtiofs` inside the VM | the VMs named per mount |
| NBD | nbd-server, a file image, address allow-list, optional TLS | nbd-client, formatted only when blank | one client |
| GlusterFS | a volume with a brick on the server and on each peer (peers run their part first), optional replica | the GlusterFS client, with the peers as backup volfile servers | addresses and subnets |

None of the new protocols has run against real servers yet: they are checked by their own tests and by running each generated script as a report. Treat a first deploy of each as a test, and read its report before applying. The S3, WebDAV and rclone-serve servers listen in plain HTTP unless you give them a certificate and key; on anything but a trusted network, set TLS.

### SFTP

Each share gets a chroot at `/srv/storageforge-sftp/NAME` that sshd accepts (root-owned, not writable by anyone else), with the folder bound into it. A drop-in, `/etc/ssh/sshd_config.d/50-storageforge-sftp.conf`, locks the share's accounts into that chroot with internal-sftp only: no shell, no forwarding, no tunnels. `sshd -t` checks it before sshd reloads, and a config it rejects is taken back. Your `sshd_config` must include `/etc/ssh/sshd_config.d/*.conf`, as current distributions' do.

StorageForge doesn't make the accounts: each one the share names needs to exist on the server (`useradd -M -s /usr/sbin/nologin backup`). For each client, give the account it logs in as, the vault secret with its private key, and its public key. The public key goes into that account's `authorized_keys` with `restrict`. The client mounts with sshfs as a unit, `storageforge-share-SERVER.<mount point>.service`, and refuses a server whose host key isn't the one StorageForge pinned.
