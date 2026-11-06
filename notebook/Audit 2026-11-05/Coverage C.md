---
tags: [audit, coverage]
date: 2026-11-05
---
# Coverage C: the UI kernel and router, generated scripts under shellcheck, dependencies and containers

Part of [[Audit 2026-11-05]]. Read at `fb6b024` (head of `dev-expanded-networking` when this reader started), tree clean. One finding: [[SF-80 A staged change plan and the planner drafts stay in the browser for the next account|SF-80]] (Low). Everything else below was checked and held.

## Read fully
- `static/kernel.js`, `router.js`, `chrome.js`, `session.js`, `login.js`, `enroll.js` (dialogs, shortcut registry, `sfStash`/`sfRecall`, `api()`, `confirmPassword`, `confirmHostKey`, hash parsing)
- `server.py` lines 165-200 (CSP and headers) and 500-740 (cookie settings, same-origin check, role check, headers, page routes, static allowlists)
- `pyproject.toml`, `Dockerfile`, `docker-compose.yml`, `docker-compose.remote.yml`, `docker/nginx.conf`, `docker/tunnel/sshd_config`, `docker/tunnel/entrypoint.sh`, `.forgejo/workflows/ci.yml`, `examples/demo/compose.demo.yml`, `examples/demo/Dockerfile.target`

## Read in part
- `docker/entrypoint.sh` (first 80 lines), `docker/egress-firewall.sh` (header and argument checks), `docker/requirements.lock` (names and versions only)
- `static/planner.js`: the escaping helpers, `scrub`/`tidy`, the draft code and the template literals that go into `innerHTML` (searched for single-quoted attributes and unescaped names; none found). Not read line by line.
- `static/changes.js` (draft code), `mapview.js` (`mapTakeLink`), `manage.js` (hash reading), `securityview.js` (`secOpen`), `netscanview.js` (link `href` from the server). A grep of every `static/*.js` for `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `eval`, `new Function`, `.href =`, `.src =`, `location =` and `window.open`.

## Not read
The other view scripts (`app.js`, `topology.js`, `filemap.js`, `gitview.js`, `deployview.js`, `tasks.js`, `scheduler.js`, `sharewiz.js`, `securityview.js`, `securitymore.js` and the rest) beyond the grep above; the rest of `server.py`; `docker/init-volumes.sh`, `docker/init-secrets.sh`, `docker/sf-site`; `examples/lab/`; the second half of `entrypoint.sh`.

## Probed
- **Browser** (`/tmp/sfaudit/c/probe_ui.py`, `probe2.py`; headless Chromium, throwaway SQLite database, two admin accounts, `127.0.0.1` only):
  - response headers on `/`: CSP as in the source, `nosniff`, `no-referrer`, `X-Frame-Options: DENY`, COOP `same-origin`, `no-store`
  - hash fuzz on the main page with markup, event-handler payloads, `__proto__` and `constructor` keys, bad percent escapes and both URL forms: no element made, no handler run, `Object.prototype` untouched, no page error
  - an inline `onerror` handler written through `innerHTML` did not run (CSP blocks it)
  - `?next=` on the login page, nine forms (`//host`, `/\host`, `/<tab>/host`, `https://`, `javascript:`, `/%2f/host`, and others): every off-site form ended on the site's own page; the already-signed-in server redirect gave `/` for `//` and `/\` forms and a percent-encoded same-site path for the rest
  - CSRF: a POST with `Origin` of another host, another port or `null`, or `Sec-Fetch-Site` of `cross-site` or `same-site`, got 403; `same-origin` and no header at all passed (documented in the code)
  - static files: with no session, only `login.js`, `enroll.js`, the three shared stylesheets and the icon are served; every other script and sheet gave 401; `..%2f`, `%2e%2e/` and `static/` paths gave 404; every file in `static/` is covered by one of the two allowlists
  - drafts across accounts: SF-80
- **shellcheck** 0.11.0 from `pip install shellcheck-py` into `/tmp/sfvenv` (the network worked). Rendered 166 scripts with synthetic arguments: 94 from the same builders `test_no_generator_lets_a_value_run_as_code` uses (every change type, task type, moves, jobs, shares, schedule, ClamAV, all four send scripts per tool) and 72 from direct calls and the raw templates of `secscripts`, `secplus`, `deploy`, `access`, `health`, `reinstall`, `remote`, `gitrepos`, `updates` and others (`/tmp/sfaudit/c/render_a.py`, `render_b.py`). `shellcheck --severity=warning` (`-s bash` when there is no shebang): **2048 findings in 139 of 166 scripts, none a real bug.** By code: SC1007 1545 (`VAR= cmd` written on purpose), SC2178 and SC2128 171 each (a local named like an array elsewhere in the same large script; shellcheck does not scope it), SC2155 60, SC2034 56 (variables of a shared kit not used by every script), SC2283/SC1083 (the raw Python text of `syncindex.SYNC_PY` and `ENTROPY_PY`, which are not shell), and parse errors on raw templates whose `@PLACEHOLDER@` or `%` fields are filled in before they are sent (not scripts as shipped). The few unique warnings were read: `ls | grep` on a folder of the program's own backup names (SC2010), `mkdir -p -m` where the leaf is the one that matters and a `chmod` follows (SC2174), a constant test `[[ / == / ]]` in the job script for a destination at `/` (SC2050), a loop over one unit name (SC2043), `{a,b}` in a bash array value for an exports line (SC2054), and `F=find; ...` (SC2209, a name). No quoting error (SC2086, SC2046 on a user value) came up; the one SC2046 is a fixed `apt-cache depends` list in `secplus.BUNDLE_BODY`. Not looked at: the exact lines of SC2155 (masked return values), which are cosmetic in scripts run with `set -u` and their own failure checks.

## Ruled out (short)
- XSS in the kernel: every dialog, toast and list is built with `createElement`, `textContent` and `append`; `sfNode` sets properties only for names that exist on the element and never `innerHTML`. A hostile host name or fingerprint in the host-key dialog stays text. The reauth dialog is built from fixed strings.
- Router: `CSS.escape` on the one selector built from the hash; unknown views and panels are looked up in lists; `URLSearchParams` has no prototype pollution; `host=` is only used if it is an option of the host picker. A `mode=constructor` in a map link picks a non-preset and is not harmful (a robustness nit, not security).
- `api()`: no token in the URL, `credentials: same-origin`, a 401 empties the page; the password retry runs once; the host-key retry only comes from a server 409 and confirms the fingerprint the server computed.
- `enroll.js`: the token is in the fragment and removed from the URL before the first request; messages are set with `textContent`.
- Server: cookie is `HttpOnly`, `SameSite=Strict`, `__Host-` and `Secure` behind the proxy; `MAX_CONTENT_LENGTH` set; JSON-only bodies; `Cache-Control: no-store` on pages.
- Containers: base image and nginx image pinned by digest; Python packages installed with `--require-hashes` from a lock of 516 hashes (versions in the lock are current for a 2026 build: flask 3.1.3, werkzeug 3.1.9, cryptography 50.0.2, waitress 3.0.2); OpenSSH built from a checksummed tarball; the runtime runs as uid 10001, `read_only`, `cap_drop: [ALL]`, `no-new-privileges`, tmpfs `noexec`; no secret in the image or in `environment` (files from a volume); the admin job has `network_mode: none`; the tunnel runs as uid 10002 with `ForceCommand /bin/false`, no TTY and `PermitOpen none`. The one root container, `init-secrets`, is on the host network with three capabilities and a read-only root; it listens on nothing and the choice is explained in the compose file.
- Not findings, noted: the CI file uses tag-pinned actions (`@v4`), `postgres:16-alpine`, `aquasec/trivy:latest` and the demo target `alpine:3.20` unpinned (CI and demo only, nothing shipped); CI runs `shellcheck --severity=error` over `docker/*.sh` only, and the two tests that lint generated scripts also stop at `error`, so a `warning`-level bug in a generated script would not be caught; `pyproject.toml` has lower bounds only (the image uses the lock).

## Not run
The KVM lab; a vulnerability scan of the image or the lock (no database was downloaded, as asked); the whole test suite; a real two-user browser check of the planner draft path.
