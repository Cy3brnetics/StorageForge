# Troubleshooting

## Starting up

| What you see | Cause | What to do |
| :--- | :--- | :--- |
| `init-secrets: error: sf-data has a database but no vault secret was found` | The secret volume was deleted but the data was not | Put the original in `./secrets/vault_secret` and deploy again. See [Disaster recovery](disaster-recovery.md) |
| `vault locked` in the logs | `STORAGEFORGE_VAULT_SECRET` is not set or is wrong | Check the secret. Scans that use the vault wait until it unlocks |
| The browser warns about the certificate | It is self-signed, or has ended | Compare the fingerprint in `docker compose logs init-secrets`, or see [Certificates](operations.md#certificates) |
| Keys in `./keys` are not imported | The app cannot read them | Make them `0640` with the group from `STORAGEFORGE_SECRETS_GID`, and check the warning in the logs |

## Scanning

| What you see | Cause | What to do |
| :--- | :--- | :--- |
| Host key mismatch, or a scan refused for a known name | The host was reinstalled, or another machine claims its name | If you expected this: `storageforge-index hosts rekey <host>` |
| Folders listed as unreadable | The scan user lacks permission | Set up [read-only scan access](scanning-and-search.md) |
| A scan refuses to apply because too much is gone | The delete guard: a disk may be unmounted | Check the disk. If it is really gone, rerun with `--max-delete-ratio 1` |
| `scan --host 127.0.0.1` walks this machine | Loopback on port 22 means a local scan | Give `--port`, `--user` or `--key` to use SSH |
| A `scan-failed` alert | The latest scan job failed | The message holds the reason. A later good scan resolves the alert |

## Plans and deploys

| What you see | Cause | What to do |
| :--- | :--- | :--- |
| A dialog asks for your password | Running commands on hosts needs it typed again every so often | Enter your StorageForge password |
| `another run of this plan is in progress` | The lock is held | Wait, or check for a stuck script on that host |
| `destructive, skipped` | The script needs `--destructive` too | Check the task, then rerun with `--apply --destructive` |
| A job's reports are refused | Its token is gone, or the certificate changed | Deploy the job again. Logs are in `/var/log/storageforge/run.log` on the host |

## Sending snapshots

| What you see | Cause | What to do |
| :--- | :--- | :--- |
| `cannot run btrfs on …` or `cannot run zfs on …` | SSH key, host key or sudo on the receiver | See [Target hosts](target-hosts.md#sending-snapshots-between-hosts) |
| `is not read-only` | btrfs only sends read-only snapshots | Snapshot with **Read-only** ticked |
| `is there but is not a finished copy` | An earlier send was interrupted | Delete it there with `btrfs subvolume delete`, then rerun. Storage task blocks do this themselves |
| `is not on the other side` | The earlier snapshot was pruned there, or never sent | Send a full copy to a new name, then start again from it |
| `shares no snapshot` or `already exists there` (ZFS) | Pruning removed the last shared snapshot on one side | StorageForge never overwrites: receive into a new dataset, or destroy the old one yourself |
| Every send is a full copy | The newest snapshot on the receiver was pruned from the sender | Keep more snapshots on the sender, so the last one sent survives until the next send |
| An LVM snapshot went invalid | Its space filled up | It cannot be recovered. Make the next one larger, or use a thin volume |
