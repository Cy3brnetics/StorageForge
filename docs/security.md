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

## Bindings

`key_bindings` maps a key to an exact host or IP, a glob (`*.tailnet.ts.net`) or a CIDR, with a user, port and allowed actions (`scan`, `checksum`, `deploy`). The most specific match wins: exact host, then glob, then longest prefix, then the lowest priority number. `vault resolve --host H` shows which key and user a host would get.

## Host identity

A host's name is what it reports, so it proves nothing.

- Each indexed host is pinned to the SSH host keys verified at its address. A scan of another machine that claims an indexed name (or the same short name) is refused and audited, and the real host's data, address and deploys are untouched. After reinstalling or moving a host: `storageforge-index hosts rekey <name>`, then scan it.
- Scans trust a new host key on first use. The worst a wrong first answer gets is a scan of the wrong machine, which pinning then contains.
- Before a **password** is sent (key install, read-only scan access, deploy access), the host key must be confirmed by a person: the UI shows the fingerprint to compare with `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` on the host, and the password then goes over a connection that accepts only that key. *(This confirmation step was being added while these pages were written; see the [audit](audit-2026-10-29.md).)*
- Signed deploy requests carry the host's `/etc/machine-id` from its last scan, so a request runs on no other machine, even one with the same short name.

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
| `storageforge-job --serve` on a job source | **At install** | A job key's forced command with a fixed list of actions, from a config a signed deploy wrote |
| Scans: inventory, file walk, checksums, network, containers, Git | No | Read-only, as the scan user |
| First-time scan and deploy access | No | No signer is on the host yet. It takes a fresh password and a host key a person confirmed |
| **The receiving side of a ZFS or btrfs send, and `rsync` to another host** | **No** | The signed script on the first host logs in with that host's own root key. Nothing is signed there and no run is recorded, so the check warns and the `deploy.start` audit row names the host (`second_hops`) |
| Scripts you download and run yourself | No | Yours to read |

The Falco install fetches its vendor's key at run time, which a signature cannot vouch for, so the script compares it with a fingerprint it carries.

## On the hosts

| Feature | What it adds | Removal |
| :--- | :--- | :--- |
| Scanning | nothing; a user with your public key | remove the key |
| Read-only scan access | `find` and `sha256sum` copies with `CAP_DAC_READ_SEARCH`, executable only by `storageforge-scan`; the scan user in `systemd-journal`, so it can read every journal line for scans to collect | `access script --remove` |
| Deploy access | `storageforge-deploy` user, a sudoers file allowing two commands, `storageforge-run`, `allowed_signers` | the setup script's `--remove` |
| Deployed jobs | `storageforge-job`, per-job configs, keys and timers; forced-command keys on sources | deploy the plan empty (**Remove from hosts**) |
