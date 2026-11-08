# Security

StorageForge holds SSH keys that reach every host, and it can run root scripts on hosts set up for deploys. This page describes how those are protected. Findings and fixes from the reviews are in [security-audit-2026-10-28.md](../security-audit-2026-10-28.md).

StorageForge is meant for a LAN behind its TLS proxy. Do not publish it on the internet. The one port that may face it is the optional [tunnel for remote nodes](remote-nodes.md).

## Key vault

```text
STORAGEFORGE_VAULT_SECRET ──Argon2id(salt, t=3, m=64 MiB, p=4)──► KEK (32 bytes, never stored)
KEK ──AES-256-GCM──► wraps one random DEK per key, the audit MAC key and a verifier
DEK ──AES-256-GCM──► encrypts the OpenSSH private key
```

- **Associated data** binds every ciphertext to its row and purpose, so a ciphertext copied into another row fails to decrypt. A GCM-encrypted verifier detects a wrong secret.
- **Weak keys:** RSA below 3072 bits is refused. Passphrase-protected keys are accepted with `--passphrase-env` and stored decrypted inside the vault.
- **Rotation:** `STORAGEFORGE_VAULT_NEW_SECRET=… storageforge-index vault rotate-secret` rewraps every DEK and the audit key under a new KEK in one transaction. Key ciphertexts never change.
- **At run time** a key is decrypted with `update_into` into an `mlock`ed buffer, written to `ssh-add -` from it, and zeroed. Each task gets its own `ssh-agent -D -a` in a fresh 0700 directory on the tmpfs runtime dir, with a key lifetime limit; the agent is killed and the directory removed when the task ends. `ssh` runs with `-F /dev/null`, `IdentityAgent=<socket>`, `BatchMode`, password auth off and a persistent `known_hosts`.
- **Child processes** (`ssh` and others) never see `STORAGEFORGE_*` variables.

Python cannot promise no other copy of a secret exists in memory: the environment variable and import paths are ordinary objects. The design minimises how long plaintext lives and never writes it to disk; it does not claim zero copies.

Backups never contain the vault secret, on purpose: a backup together with its secret would be the keys. Keep the vault secret safe somewhere else (`docker compose exec storageforge cat /run/sf-secrets/vault_secret`).

### Secrets for plan steps

Some steps need a secret on the host they run on: the `tailscale` step needs an auth key. Such a secret is stored in the vault like a device credential (`vault secret-add NAME`, one line on stdin, so it is in no shell history), and never goes into a plan, a script, the Ansible playbook or a log.

`vault send-secret NAME --host HOST` decrypts it and writes it to `/run/storageforge/secrets/NAME` on the host over SSH, on ssh's stdin. `/run` is in memory, the folder is mode 700 and the file mode 600, and both are gone at reboot. The login needs `sudo` without a password, as deploys do. The step reads the file there. The `tailscale` step hands it to Tailscale as `--auth-key=file:…`, so the key is on no command line, and removes it once the node has joined. Both commands write to the audit log, and neither prints the secret.

## Bindings

`key_bindings` maps a key to an exact host or IP, a glob (`*.tailnet.ts.net`) or a CIDR, with a user, port and allowed actions (`scan`, `checksum`, `deploy`). The most specific match wins: exact host, then glob, then longest prefix, then the lowest priority number. `vault resolve --host H` shows which key and user a host would get.

## Host identity

A host's name is what it reports, so it proves nothing.

- Each indexed host is pinned to the SSH host keys verified at its address. A scan of another machine that claims an indexed name (or the same short name) is refused and audited, and the real host's data, address and deploys are untouched. After reinstalling or moving a host: `storageforge-index hosts rekey <name>`, then scan it.
- Scans trust a new host key on first use. The worst a wrong first answer gets is a scan of the wrong machine, which pinning then contains.
- Before a **password** is sent (key install, read-only scan access, deploy access), the host key must be confirmed by a person: the UI shows the fingerprint to compare with `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` on the host, and the password then goes over a connection that accepts only that key. *(This confirmation step was being added while these pages were written; see the [audit](audit-2026-10-29.md).)*
- Signed deploy requests carry the host's `/etc/machine-id` from its last scan, so a request runs on no other machine, even one with the same short name.

### Signed scan payloads

Everything a scan reads from a host (the inventory, each folder walk, the checksum pass, the journal, the network and container surveys, the git survey) is signed on the host and checked here before any of it is used.

- For every command the scan sends a new random nonce. The host hashes exactly the bytes it sends back (SHA-256) and signs `storageforge-scan-v1`, the nonce and that hash with `ssh-keygen -Y sign` in the namespace `storageforge-scan`. StorageForge hashes what arrived, compares, and verifies the signature with a key pinned for that host.
- The key is the scan signing key that read-only scan access makes (`/usr/local/lib/storageforge/scan-sign`, readable only by the `storageforge-scan` group), or the host's own SSH host key when the scan logs in as root. When StorageForge runs the scan access setup itself, the setup's connection accepts only the host key a person confirmed, so the signing key it prints is pinned from there. A key first seen on a scan is pinned on first use, as host keys are. The namespace means these signatures count for nothing to SSH, git or anything else that verifies SSH signatures.
- A payload whose signature does not verify, that was signed by another key than the pinned one, or whose bytes differ from what the host signed, is refused. A refused folder walk leaves that mount's index as it was; a refused inventory stops the scan before anything in it (job runs, ClamAV results, security events) is taken in.
- A host that has signed before (a key is pinned for it, which now includes the SSH host key of a host scanned as root) and answers unsigned, or with a different key, is refused as a downgrade even when signed scans are not required. A person decides: forgetting its scan signing key (`storageforge-index access signing --forget <host>`, or `DELETE /api/scans/signing/<address>`) makes its scans count as unsigned until it signs again, and the next key it signs with is pinned. `PUT /api/scans/signing` takes `true` or `false` (text that plainly says on or off is read as such); anything else is a 400.
- A host that has never signed and cannot (no key the scan account can read, or OpenSSH older than 8.0) says why. Its payloads are used and shown as unsigned, unless signed scans are required: `storageforge-index access signing --require on`, or `PUT /api/scans/signing`, which takes `keys.manage` (admins, not operators: it is about which keys a host is trusted with). Then they are refused too.
- After rebuilding a host, forget its scan signing key (`storageforge-index access signing --forget <address>`) and run the scan access setup again.

What it does not stop: an attacker who controls the host's scan account, or root, can sign whatever they like, because that account is what reads the host. It proves a payload came unchanged from the machine the key belongs to, for this request and no other, and it cannot be replayed. Reports that hosts send on their own (deployed jobs, schedules and the sentinel, with a bearer token) are not scan payloads and are not signed this way.

## Accounts and sessions

- Local accounts only. Werkzeug hashes passwords (scrypt) and Flask-Login manages sessions. Passwords need at least 12 characters. A sign-in with an unknown name costs the same time as a wrong password.
- Requests that change something must come from this origin (`Sec-Fetch-Site`, or `Origin` where a browser sends no such header). `SameSite` alone would let a page on another port of this host post here.
- The session cookie is signed with `STORAGEFORGE_SESSION_SECRET`, `HttpOnly` and `SameSite=Strict`. With `STORAGEFORGE_COOKIE_SECURE=1` (compose sets it) it is also `Secure` and named `__Host-sf_session`.
- Sessions are also kept server-side; only a hash of their id is stored. Signing out ends that session even for a copied cookie. `user signout <name>` ends all of them (`user clear-keys <name>` removes a lost security key, from the server's shell only, and is audited), as do `user passwd` and `user disable`.
- A session ends 30 minutes after sign-in. Each user can raise their own to up to 8 hours from the header's **Session** menu. An open page clears itself and goes to `/login` when its session ends.
- **Re-authentication:** anything that runs commands on hosts, and changing the session length, needs the password typed within the last 5 minutes (`POST /api/reauth`).
- **Roles:** an account can do only what its role allows. The built-in roles are `search`, `viewer`, `operator` and `admin`, and custom roles draw on the permission catalogue in `permissions.py`. `operator` can deploy to every enrolled host, including destructive deploys. Only `admin` can write raw commands (`hosts.command`). See [Roles](features/administration.md#roles).

### Sign-in limits

Failed sign-ins are throttled by Flask-Limiter (successful ones don't count):

| Key | Limit |
| :--- | :--- |
| client IP | 10 per minute, 50 per hour |
| username from one network (/24 or /64) | 5 per minute, 20 per hour |
| username from anywhere | 100 per day |

The per-network limit means a stranger elsewhere cannot lock the owner out; the per-day limit is the backstop. Hitting a limit is audited and `/api/login` answers `429` with `Retry-After`. Counters live in memory and reset when the server restarts. Key install, access grant and deploy access are limited to 10 attempts per minute per user, and re-authentication shares the per-user sign-in limit.

## HTTP

- Pages and their scripts are served only with a valid session; `/login`, `login.js`, `style.css` and `favicon.svg` are the exceptions. Without a session the app redirects to `/login?next=…`, and `next` must be a path on this site.
- State-changing routes accept only `application/json`, so a cross-site form cannot reach them; no CORS is granted.
- Strict CSP (`'self'` only; the one relaxation is `style-src-attr 'unsafe-inline'` for sized bars), `nosniff`, `frame-ancestors 'none'`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store`.
- Request bodies are capped at 4 KiB. A route that takes more says how much in `server.BODY_LIMITS` (2 MiB for a design, 512 KiB for rule sets, map views and reports), and a test walks that table in both directions. List sizes and limits are clamped.
- `/healthz` returns only `{"status"}` unless asked from inside the container or by a signed-in user.
- Behind a reverse proxy, set `STORAGEFORGE_PROXY_HOPS=1` so limits and the audit log see the real client IP, and `STORAGEFORGE_PROXY_HOST` to the proxy so nothing else can claim a client address (compose sets both).
- The UI builds the DOM with `textContent`. Designs and plans reject control characters and `< > " \`` in text (see [Concepts](concepts.md#the-rules)).
- `POST /api/jobs/report` is the one API route without a session. It needs a job's bearer token, and each token may only report for its own job.

## Audit log

Every connection, scan result, denial, sign-in, plan save, script download, deploy and vault change is appended to `audit_log`. Each entry carries an HMAC-SHA256 over the previous entry's hash, keyed with a random MAC key wrapped by the KEK. Triggers reject `UPDATE` and `DELETE` (and `TRUNCATE` on PostgreSQL). `storageforge-index audit verify` (or **Audit → Verify chain**) finds an edited, deleted or reordered row even if the triggers were bypassed. When the vault is locked, entries fall back to plain SHA-256 chaining.

## Container

| Control | Setting |
| :--- | :--- |
| User | non-root uid 10001; the entrypoint refuses root |
| Filesystem | read-only root; tmpfs for `/run/storageforge` (agent sockets, 0700) and `/tmp`, both `noexec,nosuid,nodev` |
| Privileges | `cap_drop: ALL`, `no-new-privileges` |
| Limits | app: 2 CPUs, 2 GiB memory, 256 PIDs; proxy: 0.5 CPU, 64 MiB, 32 PIDs; memlock raised for `mlock` |
| Secrets | compose secret files, 0640 with your group; checked for length (≥ 32 characters) at start |
| Network | the app port is not published; only the nginx proxy is, on 8443 over TLS 1.2/1.3 with HSTS, replacing (not appending) `X-Forwarded-For` |
| Image | base image pinned by digest, Python packages pinned by hash and installed with `--require-hashes`; pip, `scp`, `sftp` and `ssh-keyscan` removed |
| Egress | optional `docker/egress-firewall.sh` lets the containers open only SSH and alert ports (`STORAGEFORGE_EGRESS_PORTS`, default `22 443`) out of the `sf0` bridge, to other machines and to the Docker host itself |

## Remote nodes

The tunnel in `docker-compose.remote.yml` is the one port meant to be open beyond the LAN. See [Remote nodes](remote-nodes.md) for what a stolen key can and can't do.

## What is signed

Everything sent to a host to run as root is signed, with these named exceptions. A signature covers the host, machine id, issue time, nonce, args and script, and not what a run reads on stdin, which is only ever data.

| What | Signed | Why |
| :--- | :--- | :--- |
| Deploys, security actions, measurements, updates, playbooks | **Yes, on each run** | Through `storageforge-run` |
| Timers on a host: jobs, tasks, schedules, the sentinel, ClamAV | **At install** | A signed deploy puts them there, root-owned. They are not checked again on each run |
| `storageforge-job --serve` on a job source, and on the receiving host of a send | **At install** | A job key's forced command with a fixed list of actions, from a config a signed deploy wrote |
| Each side of a ZFS or btrfs send to another host | **Yes, on each deploy** | A signed run on the receiver says what it may receive and writes the key's forced command. A signed run on the sender writes the key. See [Sends between hosts](#sends-between-hosts) |
| Scans: inventory, file walk, checksums, network, containers, Git | No | Read-only, as the scan user |
| First-time scan and deploy access | No | No signer is on the host yet. It takes a fresh password and a host key a person confirmed |
| **`rsync` to or from another host in a task block** | **No** | The signed script on the first host logs in with that host's own root key. Nothing is signed there and no run is recorded, so the check says so and the `deploy.start` audit row names the host (`second_hops`). Use a Moves step instead: a [deployed job](deployments.md#deployed-jobs) has a forced-command key of its own |
| Scripts you download and run yourself | No | Yours to read |

The Falco install fetches its vendor's key at run time, which a signature cannot vouch for, so the script compares it with a fingerprint it carries.

### Sends between hosts

A send to another host needs no root key between the hosts. Each side is a signed run on an enrolled host, and the stream goes over one key that can do nothing else. [Deployments](deployments.md#sends-between-hosts) has the steps.

**What the receiver holds.** A signed run writes `/etc/storageforge/receive/<id>.conf`, which says the tool, the folder or dataset, and how many copies retention keeps. It also adds a line for this send's key in `storageforge-deploy`'s `authorized_keys`: `restrict,command="sudo -n storageforge-job --serve <id> \"$SSH_ORIGINAL_COMMAND\""`. No change to sudoers is needed, because `storageforge-job --serve *` is already there.

**What a key can ask.** A fixed list of verbs. The whole line must match a strict pattern before it is split, and anything else exits 97 and is recorded.

| Verb | Does |
| :--- | :--- |
| `recv-probe` | Is the tool here, and does it run? |
| `recv-root`, `recv-list`, `recv-state <name>` | Is the folder or dataset there, what is in it, and is this copy finished? |
| `recv-mkdir` | Makes the folder from the conf |
| `recv-receive <nonce> <name>` | The stream on stdin into the folder or dataset from the conf. `btrfs receive -C`, chrooted into that folder, or `zfs receive -u -x mountpoint -x sharenfs -x sharesmb -o setuid=off -o devices=off -o canmount=noauto`, never `-F` |
| `recv-discard <name>` | Removes one unfinished btrfs copy. A finished one is refused |
| `recv-prune [dry]` | Keeps the newest copies the conf says, of the prefix the conf says |

The sender names a verb, a nonce and a snapshot. It never names a path, an option or a command, so nothing it says can change where data lands or how much retention keeps. The conf is read line by line and never run.

**What a failure looks like.** The sender checks both ends of the pipe, the exit code that comes back through ssh, the receiver's acknowledgement, and then the copy's id against its own: btrfs Received UUID, ZFS guid. A failed receive removes what it made, says why on stderr, which reaches the sender's output, and leaves a line in the record. Nothing is pruned after a failure.

**The record.** `/var/lib/storageforge/receive/<id>/runs.jsonl` on the receiver, with the verb, nonce, name, exit code and the tool's last words. A line also goes to `/var/lib/storageforge/tasks/runs.jsonl`, so the next scan of that host files it under `receive-<id>`. The signed runs are in that host's runner log, in `deploy_runs` under its name and in the audit log, and the `deploy.start` row names it under `receivers`.

**How long a key lasts.** A change plan's key ends with the plan: a signed `--remove` follows the run, and the conf carries an expiry 12 hours out in case that run never happens. So does **Run now** of a task that is not installed. An installed task or a schedule fires with nobody there, so its key stays until it is uninstalled, like a job's key. Keys are new on every apply. A timer's run has no fresh signature: it was signed at install, as a job is.

**A scan binding reaches none of this.** Being bound for scans is not being enrolled, so the check says `crit` and a deploy is refused with 409. On the host, sudo lets only `storageforge-deploy` start the verbs, and the key is root's, mode 0600.

**What a stolen job key can still do.** Someone who takes a sender can use its key. These can't be taken away while the sender is trusted to send:

- **Send junk under newer names.** Retention then removes older good copies, because the newest count win. With **Keep there** at 0 the key can remove no finished copy. A ZFS hold on the receiver also stops `zfs destroy`. A btrfs copy has no such stop, so a backup you must keep should have its retention set to 0 and its pruning done by a task on the receiver.
- **Fill the receiver's disk.** There is no quota on a send. Give the dataset a quota, or the folder a btrfs quota group, if that matters.
- **Put files with the sender's owner and mode into a btrfs copy.** `btrfs receive` keeps the owner, group, mode and setuid bits a stream carries, so a stolen key can leave a root-owned setuid file in the received folder. Nothing on the receiver strips it. Mount the folder `nosuid,nodev` (or keep it unreachable to local accounts, mode 0700 on the folder above the copies) if other accounts can log in on the receiver, and do not run files from a copy. A ZFS receive sets `setuid=off`, `devices=off` and `canmount=noauto` itself and takes no `mountpoint`, `sharenfs` or `sharesmb` from the stream, so a received dataset does not export itself, mount at boot, or honour setuid. Mount it by hand to look. These ZFS settings have not been run against a real pool yet (lab tier 16: send a stream with a setuid file and `sharenfs` set).
- **Feed a hostile stream to the tool.** A stream is the sender's data, and `btrfs receive` and `zfs receive` read it as root. The chroot and `-x mountpoint` confine what a stream can name, but a bug in the kernel or the tool is out of reach.
- **Pick a new nonce.** The nonce stops a repeat by accident or from a log. It does not stop someone holding the key.

It can't read the receiver: no verb sends anything back but names, ids and what happened. It can't remove anything outside the conf's folder or dataset, or run anything at all. A stream that makes more than it was asked for fails, and says which names it made. Those stay for you to look at.

**What this does not cover.** Scripts you download and Ansible playbooks hold no key, so a send to another host stops and says so. `rsync` blocks are the row above.

## On the hosts

| Feature | What it adds | Removal |
| :--- | :--- | :--- |
| Scanning | nothing; a user with your public key | remove the key |
| Read-only scan access | `find` and `sha256sum` copies with `CAP_DAC_READ_SEARCH`, executable only by `storageforge-scan`; the scan user in `systemd-journal`, so it can read every journal line for scans to collect | `access script --remove` |
| Deploy access | `storageforge-deploy` user, a sudoers file allowing two commands, `storageforge-run`, `allowed_signers` | the setup script's `--remove` |
| Deployed jobs | `storageforge-job`, per-job configs, keys and timers; forced-command keys on sources | deploy the plan empty (**Remove from hosts**) |
| Sends between hosts | On the receiver: `storageforge-job`, `/etc/storageforge/receive/<id>.conf` and a forced-command key. On the sender: `/etc/storageforge/sends/<id>.key` and `.hostkey` | goes when a plan ends; **Uninstall** for a task or schedule. Records stay in `/var/lib/storageforge/receive/` |

## If a key may have leaked

`storageforge-index rotate` changes every key StorageForge holds. Run it without `--apply` first: it lists each SSH key in the vault with the hosts and accounts that use it now, and what it cannot change.

```bash
docker compose exec storageforge storageforge-index rotate            # what it would do; changes nothing
docker compose exec storageforge storageforge-index rotate --apply    # do it
```

With `--apply`, for each SSH key that a scan, checksum or deploy uses on a host:

1. A new key is made in the vault.
2. Its public half is added to that account's `authorized_keys` over the old key, and a login with the new key is tried on every host.
3. Only when every host takes it: the bindings move to the new key, the old key's line is taken out of each `authorized_keys` over the new key (with any options in front of it, and nothing else touched), and the old key is deleted. The new key takes the old one's name.

If one host does not take the new key, nothing moves for that key: the new line is taken back off the hosts that had it, and the old key stays bound and working. The run says which host and why, and exits 1. A key no scanned host uses is left alone; delete it with `vault remove` if it is not needed. `--key K` limits the run to named keys.

It also ends every web session (everyone signs in again) and revokes every invite not yet used. With `STORAGEFORGE_VAULT_NEW_SECRET` set (32 characters or more) it wraps every key under that new vault secret; put it in `secrets/vault_secret` and restart straight after. Each step is in the audit log.

What it cannot change from here, and lists with what to do:

| What | How |
| :--- | :--- |
| Session secret | delete `secrets/session_secret`, run `docker/init-secrets.sh`, restart |
| TLS certificate | delete `secrets/tls_cert` and `secrets/tls_key`, run `docker/init-secrets.sh`, restart, and trust the new one |
| Vault secret | the run above with `STORAGEFORGE_VAULT_NEW_SECRET`, or `vault rotate-secret` |
| Report tokens of deployed jobs, schedules and remote nodes | deploy them again: each deploy issues a new token and the old one stops working |
| A host's scan signing key | delete `/usr/local/lib/storageforge/scan-sign*` on the host, run the scan access script again, then `access signing --forget <address>` |
| Router and switch passwords | change each on the device, then store the new one |
| Alert addresses (ntfy topics, Gotify tokens, webhook URLs) | make new ones where they are hosted and set them under Settings, Alerts |

Nothing secret is in the git repository: the folders that hold secrets (`secrets/`, `keys/`, `data/`) and `.env` are ignored, and a scan of every commit for private keys, tokens and passwords found only placeholders and test values (2026-11-07).

