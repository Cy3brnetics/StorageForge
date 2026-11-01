# CLI reference

```text
storageforge-index [--db PATH_OR_URL] <command> …
```

`--db` defaults to `$STORAGEFORGE_DB`, else `~/.local/share/storageforge/index.db`. Migrations are applied automatically. In Docker, prefix commands with `docker compose exec storageforge` (add `-T` when piping stdin).

Sizes accept `100MB` (decimal), `100MiB` or `100M` (binary). Ages accept `90m`, `36h`, `7d`, `2w`, `1y`. Every command takes `--help`.

## Index and search

### `scan`

Index one or more hosts. Key authentication only; it never prompts.

```bash
storageforge-index scan --host nas-02                                   # key from the vault binding
storageforge-index scan --host 10.0.20.5 --user root --key ~/.ssh/id_ed25519
storageforge-index scan --local                                         # this machine, no SSH
storageforge-index scan --host nas-02 --dry-run                         # mount plan and find commands only
```

| Option | Default | |
| :--- | :--- | :--- |
| `--host H` | required | repeat for several hosts |
| `--user`, `--key`, `--port` | vault binding, 22 | without `--key` the vault binding is used |
| `--ssh-option OPT` | | extra `ssh -o`, e.g. `ProxyJump=bastion` |
| `--local` | | scan this machine without SSH |
| `--path P` | every eligible mount | index only this subtree (repeatable) |
| `--exclude-path P`, `--exclude-name GLOB` | | repeatable |
| `--no-default-excludes` | | walk `.git`, `node_modules`, `/proc` and the rest too |
| `--include-network`, `--include-tmpfs`, `--include-fstype FS` | | walk normally skipped mounts |
| `--parallel N` | 4 | concurrent `find` streams |
| `--batch-size N` | 20000 | rows per batch |
| `--checksum`, `--checksum-min-size SIZE` | off, 1 MiB | sha256 of size-collision candidates |
| `--max-delete-ratio R` | 0.5 | refuse a diff deleting more than this share of a mount |
| `--no-nice` | | don't use `nice`/`ionice` |
| `--json` | | print a JSON summary per host |

> `--host localhost`, `127.0.0.1` or `::1` without `--user`/`--key` scans this machine locally and ignores `--port`.

### `search`

```bash
storageforge-index search [PATTERN] [options]
```

| Option | |
| :--- | :--- |
| `PATTERN`, `--name` | shell-style name pattern |
| `--host H` | repeatable |
| `--size-gt`/`--min-size`, `--size-lt`/`--max-size` | size bounds |
| `--type f\|d\|l` | file, directory or symlink |
| `--ext E` | extensions, comma separated, repeatable |
| `--under DIR`, `--path-contains TEXT` | folder filters |
| `--newer-than AGE`, `--older-than AGE` | modification time |
| `--sort path\|name\|size\|mtime\|host`, `--desc`, `--limit N` (100) | |
| `--format table\|json\|paths` | |

### Other index commands

| Command | Does |
| :--- | :--- |
| `changes --host H [--scan ID] [--limit N] [--format table\|json]` | files added, modified or deleted in a scan (default the latest) |
| `dupes [--host H] [--min-size SIZE] [--limit N]` | identical files found by `--checksum` scans |
| `folders [--host H] [--min-files N] [--min-size SIZE] [--include-system]` | duplicate folders by names, sizes and layout |
| `hosts` | indexed hosts |
| `hosts rekey NAME [--port P]` | forget a host's pinned SSH host keys after a reinstall; scan it right after |
| `access status [--host H]` | folders the latest scans could not read |
| `access script [--host H \| --user U] [--remove]` | the read-only scan access setup script; pipe it to `ssh admin@host sudo sh` |
| `git [--host H]` | repositories, copies and archive state |
| `docker [--host H] [--path P]` | stacks, containers and folders; with `--path`, which containers use that folder |

## Plans

| Command | Does |
| :--- | :--- |
| `plan list` | change plans |
| `plan types` | change task types and their fields |
| `plan check ID` | check a change plan against the index |
| `plan script ID [-o FILE]`, `plan ansible ID [-o FILE]` | the Bash script or Ansible playbook |
| `plan import FILE [--id ID]` | save a plan from JSON (`{"name", "tasks": [...]}`) |
| `moves list`, `moves check ID` | move plans |
| `moves script ID [-o FILE]` | the Bash script (made executable) |
| `moves import FILE [--id ID]` | save a plan from JSON (`{"name", "steps": [...]}`) |
| `shares check HOST`, `shares script HOST [-o FILE]` | check or write a host's share deploy script |
| `deploy status` | deploy access, jobs with their last runs, drift |
| `deploy setup-script [--remove]` | the deploy setup script, to run as root |
| `deploy alerts` | evaluate alerts now and notify; exits 1 while any are open |

Storage tasks:

| Command | What it does |
|---|---|
| `hosts remove NAME [--keep-design]` | retire a host; refused while anything is deployed there |
| `user add NAME [--role R]`, `user role NAME ROLE` | an account and what it may do: viewer, operator or admin |
| `tasks list`, `tasks check ID` | storage tasks; `check` exits 1 on a critical finding |
| `tasks script ID [-o FILE]` | the Bash script (made executable) |
| `tasks import FILE [--id ID]` | save a task from JSON (`{"name", "host", "blocks": [...]}`) |

## Designs, graph and reports

| Command | Does |
| :--- | :--- |
| `blueprint FILE` | store a blueprint for its host; it is overlaid on scans |
| `graph build [--host H]` | rebuild the graph |
| `graph import --blueprint F [--df F] [--zpool-status F] [--lsblk F] [--fstab F] [--hostname H]` | build a host's graph from saved payloads, without scanning |
| `graph stats` | node counts by kind and health |
| `canvas [--host H] [-o FILE]` | Obsidian JSON Canvas |
| `export-markdown [--host H] [--blueprint F] [-o FILE]` | architecture report from the index, optionally overlaid with blueprints |
| `report [--blueprint F] [--lsblk F] [--fstab F] [--df F] [--zpool-status F] [--hostname H] [-o FILE]` | the same report from saved payloads, with no index and no SSH |

Both report commands also take `--title`, `--as-of YYYY-MM-DD`, `--kwh-price`, `--currency` and `--idle-share` (default 0.75).

## Vault and audit

| Command | Does |
| :--- | :--- |
| `vault init` | create the vault, or check the secret unlocks it |
| `vault status` | check the secret |
| `vault generate --name N [--type ed25519\|rsa] [--comment C]` | create a key and print its public half |
| `vault add --name N --key-file F\|- [--passphrase-env VAR]` | import a private key |
| `vault import-dir DIR` | import every key file in a folder (name = file stem) |
| `vault list`, `vault pubkey --name N`, `vault remove --name N` | |
| `vault bind --key K --host H --user U [--port P] [--actions scan,checksum] [--priority N]` | allow a key to reach a host, glob or CIDR |
| `vault unbind --id ID`, `vault bindings` | |
| `vault resolve --host H [--action A]` | which key and user a host would use |
| `vault policy [generate-only\|open]` | show or set whether imported keys are refused |
| `vault rotate-secret` | rewrap everything under `$STORAGEFORGE_VAULT_NEW_SECRET` |
| `audit tail [--limit N] [--format table\|json]` | newest entries |
| `audit verify` | check the HMAC chain |

## Accounts

| Command | Does |
| :--- | :--- |
| `user add NAME [--password-env VAR]` | create an account; prompts twice, or reads one line from stdin |
| `user passwd NAME [--password-env VAR]` | change a password and end its sessions |
| `user disable NAME`, `user enable NAME` | block or allow sign-in (disable ends sessions) |
| `user signout NAME` | end every web session of an account |
| `user remove NAME`, `user list` | |

## Task scheduler

| Command | Does |
| :--- | :--- |
| `schedule list [--host H] [--type T] [--paused] [--json]` | list scheduled tasks |
| `schedule add --name N --host H --cron EXPR --type T --ref REF [--config JSON] [--paused]` | create a schedule for any task, change, move, shares, scan or command |
| `schedule get ID` | print JSON configuration and details of a schedule |
| `schedule pause ID`, `schedule resume ID` | pause or resume scheduled runs |
| `schedule remove ID` | remove a schedule |
| `schedule token ID` | generate or rotate bearer authentication token |
| `schedule run ID [--json]` | execute a schedule immediately and verify the result |
| `schedule verify ID [--run-id R] [--json]` | re-verify a schedule or specific run against the index |
| `schedule runs [--id ID] [--host H] [--limit N] [--json]` | view execution history and server verification reports |
| `schedule cron ID` | print `/etc/cron.d/` entry for native cron execution |
| `schedule install-script ID [--report-url URL]` | generate full client installation script |

## Server and maintenance

| Command | Does |
| :--- | :--- |
| `serve [--listen ADDR] [--port P] [--scan-interval AGE] [--parallel N]` | the web UI and API (waitress, 8 threads) |
| `migrate` | apply database migrations |
| `healthcheck [--url URL]` | probe `/healthz`; used by the image's `HEALTHCHECK` |
| `config list [HOST]` | saved host configurations: the newest of each host, or every version of one |
| `config diff OLD NEW` | what changed between two versions |
| `config script [HOST] [--id N] [-o FILE]` | write a host's reinstall script ([details](disaster-recovery.md#rebuild-a-host-after-reinstalling-it)) |
| `config export [HOST] [--id N] -o FILE` | a `.tar.gz` of scripts, records and config files |
| `backup [create] [--full] [--keep N] [--dir D]` | write a backup (essentials by default) |
| `backup list [--dir D]` | backups on disk |
| `restore FILE --yes` | replace the database with a backup from this site; stop the server first |
| `hosts keys [HOST]` | keys in `authorized_keys` from the last scan, against the vault; exit 1 if any is unknown |
| `hosts allow-key FP [--note N]`, `hosts disallow-key FP` | accept a key that isn't in the vault, or undo that |
| `site [show]`, `site rename NAME` | which client this database belongs to |
| `site init --name NAME` | name a new site, refuse imported keys, print the first admin's link |
| `site status` | name, hosts, last scan, open alerts and last backup, tab-separated |
| `site fingerprints` | its key and host key fingerprints, to compare sites |
| `site archive [--archive D]` | write the archive `reset` makes, changing nothing; stop the server first |
| `reset --site-name NAME [--archive D] [--abandon-deployed] --yes` | archive this site and start a new one ([details](operations.md#starting-a-new-site)) |
| `prune [--days N] [--max-rows N] [--vacuum]` | drop old change history and job rows; `--vacuum` shrinks the file |

## Exit codes

`0` success, `1` a scan or check failed (or alerts are open, for `deploy alerts`), `2` a vault error, `130` interrupted.
