---
id: GM-24
status: open
severity: medium
effort: S
area: "[[Docker, Nginx and Infrastructure]]"
tags: [finding, docker, tls, nginx, ci, gemini-audit]
found: 2026-10-29
---
# GM-24 TLS 825-day cert rejected by modern browsers, nginx IPv6 and cipher gaps, and skipped tests in Dockerfile

## Location
- `docker/init-secrets.sh:21-36, 41`
- `docker/nginx.conf:19, 23, 33, 39-40`
- `docker-compose.yml:69`
- `Dockerfile:28-33, 40-41, 57-58, 64`
- `.dockerignore:1-10`

## Mechanics & Root Cause
1. **825-Day Self-Signed TLS Certificate Rejected by Chrome/Safari/iOS (`docker/init-secrets.sh:30`)**:
   - `openssl req -x509 ... -days 825` generates a leaf server certificate (`basicConstraints=critical,CA:FALSE`) with an 825-day validity period.
   - All major browsers (Chrome, Edge, Safari, Firefox, iOS/macOS) enforce a **398-day maximum lifetime** on TLS server certificates and reject 825-day certificates with `ERR_CERT_VALIDITY_TOO_LONG`—even when manually imported as instructed by line 35 (`"or import secrets/tls_cert as trusted"`).
   - Furthermore, because `basicConstraints=critical,CA:FALSE` is set, OS root CA importers (`update-ca-certificates`, macOS Keychain root store, Android) refuse to trust it as a CA anchor.
2. **Nginx Missing IPv6 Listener, TLS 1.2 Cipher Restriction, and Dynamic DNS Resolution (`docker/nginx.conf:19, 23, 33`)**:
   - `listen 8443 ssl;` binds only IPv4 (`0.0.0.0:8443`), omitting `listen [::]:8443 ssl;` despite `init-secrets.sh` adding `IP:::1` and global IPv6 addresses to the certificate SANs.
   - `ssl_protocols TLSv1.2 TLSv1.3;` does not specify `ssl_ciphers` for TLS 1.2.
   - `proxy_pass http://storageforge:8080;` resolves `storageforge` only once at nginx startup; recreating the `storageforge` container causes `502 Bad Gateway` until `proxy` is also restarted.
   - `docker-compose.yml:69` uses an unpinned tag `nginxinc/nginx-unprivileged:1.27-alpine` and defines no `healthcheck` for `proxy`.
3. **Silent Test Skips in `Dockerfile` `test` Stage (`Dockerfile:28-33`)**:
   - The `test` stage in `Dockerfile:28-33` omits `git` from `apt-get install`, causing `test_git_repositories_and_copies` to be skipped silently.
   - Because the `test` stage runs as `root` (`uid 0`), three critical security/functional tests that have `@unittest.skipIf(os.geteuid() == 0, ...)` are **never run** during `docker build --target test .`:
     - `test_unreadable_folders_and_duplicate_folders` (`tests/test_indexer.py:331`)
     - `test_task_script_runs_end_to_end` (`tests/test_tasks.py:184`)
     - `test_runner_verifies_signature_and_blocks_replay_and_wrong_host` (`tests/test_platform.py:1097`)
4. **Stale `SQLITE_TMPDIR` (`/app/data/tmp`) and Incomplete `.dockerignore`**:
   - `entrypoint.sh` never cleans `/app/data/tmp` on startup, leaving orphaned SQLite temp files after crashes.
   - `.dockerignore` does not exclude `.ruff_cache/`, `*.egg-info/`, `.env.*`, `data/`, or `*.sqlite*`.

## Impact
Modern browsers reject the generated 825-day TLS certificate even if imported; `docker build --target test .` silently skips 4 key tests (including the cryptographic signature verification test for `storageforge-run`!); and recreating `storageforge` can leave `proxy` serving `502 Bad Gateway`.

## Remediation
1. Change `-days 825` to `-days 397` in `docker/init-secrets.sh:30`.
2. Add `listen [::]:8443 ssl;`, TLS 1.2 AEAD `ssl_ciphers`, and `resolver 127.0.0.11 valid=10s;` in `docker/nginx.conf`.
3. In `Dockerfile:28-33`, install `git` and run `python -m unittest` as a non-root user so none of the `skipIf(os.geteuid() == 0)` tests are skipped.
4. Clean `/app/data/tmp` on startup in `docker/entrypoint.sh` and expand `.dockerignore`.

## Done when
- [ ] `init-secrets.sh` generates `<= 397`-day certificates.
- [ ] `docker build --target test .` runs all tests as non-root with `git` installed (0 skipped tests).
