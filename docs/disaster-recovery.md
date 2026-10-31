# Disaster recovery

What you need to get StorageForge back after losing the machine it runs on, and how to rebuild a host after reinstalling its operating system.

## Keep these somewhere else

| What | Why | How |
| :--- | :--- | :--- |
| **The vault secret** | Every SSH key in a backup is encrypted with it. Backups never contain it, and without it those keys are gone for good | `docker compose exec storageforge cat /run/sf-secrets/vault_secret` |
| **An essentials backup** | Keys, accounts, plans, designs, settings and deploy state | Copy from the `sf-backups` volume, for example with a Moves **mirror** step |

Backups are not encrypted as a whole. SSH keys inside are, but password hashes, plans, host names and the audit log are readable, so store copies somewhere you trust. By default they stay on the same machine as the database, which does not protect you from losing that machine.

With PostgreSQL, StorageForge makes no backups: use `pg_dump`, and still keep the vault secret.

## Rebuild

On the new machine, with the repository checked out:

1. Put the old secret where the first deploy will find it, readable by the group in `STORAGEFORGE_SECRETS_GID`:

   ```bash
   mkdir -p secrets
   install -m 0640 /path/to/saved/vault_secret secrets/vault_secret
   ```

2. Create the volumes and the secret, then stop the app so nothing is using the database:

   ```bash
   docker compose up -d --build
   docker compose stop storageforge
   ```

3. Copy the backup into the volume and restore it:

   ```bash
   docker compose cp ./storageforge-essentials-20261027-030000.db storageforge:/app/backups/
   docker compose run --rm storageforge restore /app/backups/storageforge-essentials-20261027-030000.db --yes
   docker compose start storageforge
   ```

4. Sign in with your old account and press **Scan all hosts**. An essentials backup leaves out the file index, which these scans rebuild.

If the new machine has a different address, also do this:

- Update the **report URL** under **Deploy → Reporting and alerts**.
- Deploy the jobs again if the certificate changed, because each job trusts the certificate it was deployed with.

## If the vault secret is lost

The keys in the vault cannot be recovered. Everything else in a backup still is, but the vault cannot be unlocked with a new secret, so start with a new database: generate new keys and install them on each host. Plans and designs can be exported from the old database with `sqlite3` if you need them.

Try a restore before you need one: run steps 1 to 3 on a spare machine or VM, and check that a scan works.

## Rebuild a host after reinstalling it

Each scan saves what it takes to rebuild the host when any of it changed, keeping 30 versions per host. Versions are in every essentials backup. See them under **Rebuild** in the web UI, or with `storageforge-index config list`.

| Saved | Left out, on purpose |
| :--- | :--- |
| `/etc/fstab`, `/etc/crypttab`, `mdadm.conf`, `/etc/exports` and `exports.d`, `/etc/samba/*.conf` | Passwords in fstab options and Samba files, which are removed before saving |
| Mounts, including ones not in fstab, btrfs subvolumes and ZFS datasets | Account and Samba passwords, LUKS passphrases and key files, SSH keys, `credentials=` files |
| Users and groups with UID or GID 1000 and up, and their group memberships | Firewall rules |
| Symlinks that cross a mount, and the saved design | Everything else in `/etc`, and installed packages |

If the scan user can't read a share file, the script uses the live export table or `testparm` output instead. If it can't read `/etc/crypttab`, the script opens the LUKS volumes it knows about, but you add them to crypttab yourself.

**Keep a copy elsewhere.** A backup on the machine you are rebuilding is no help:

```bash
storageforge-index config export -o hostconfigs.tar.gz
```

Each host's folder holds `reinstall.sh`, its record, its design and its config files. The script holds everything it needs, so it works with StorageForge gone. Treat the bundle as private: it names your hosts, accounts and network.

### Run the script

```bash
bash reinstall.sh
```

This only reports. Then:

```bash
sudo bash reinstall.sh --apply
```

It installs the tools it needs, restores `mdadm.conf`, opens LUKS volumes, activates md and LVM, imports ZFS pools, adds accounts with their old IDs, adds fstab lines, mounts everything, and restores shares and symlinks. It's safe to run again.

**It never partitions or formats.** It finds filesystems by UUID, and reports one that isn't there. To rebuild onto new drives, restore their data first, or use the planner's build script.

| Option | What it does |
| :--- | :--- |
| `--force-zfs-import` | Imports pools the old install last used. A real reinstall needs it. First make sure no other machine has those drives |
| `--replace-configs` | Replaces config files that differ from the saved ones, keeping a backup. A Samba config written by a package this same run is replaced without it |
| `--any-host` | Runs on a machine with a different name |
| `--only mounts,links` | Runs only these stages: `tools`, `storage`, `accounts`, `mounts`, `shares`, `links` |
| `--host H` | Copies the script to H and runs it there with sudo |

- **Conflicts:** a line in the new fstab for the same mount point is left alone and reported, so sort those out by hand. Anything on the old system disk, such as `/home` on a root btrfs, is left to the new install.
- **Afterwards:** set passwords for restored accounts, run `smbpasswd -a` for Samba users, open firewall ports, then scan the host. If its SSH host keys changed, run `storageforge-index hosts rekey` before that scan.
- **Alpine:** the script needs bash, so run `apk add bash util-linux shadow` first. It doesn't start services there, because Alpine has no systemd.
