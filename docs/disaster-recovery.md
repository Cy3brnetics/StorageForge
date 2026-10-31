# Disaster recovery

What you need to get StorageForge back after losing the machine it runs on.

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
