# StorageForge Security Parameters & Hardening Guide

This document defines the security parameters, threat model, controls, and hardening recommendations for StorageForge. It is intended as a living reference for operators and auditors.

## 1. Scope
StorageForge consists of:
- `storageforge-indexer` (Python package): CLI, scanner (agentless SSH), encrypted vault, audit log, graph/reporting, web UI/API (Flask + Waitress), planner.
- Containerized deployment (`docker/`, `docker-compose.yml`) with hardened runtime.
- External targets scanned over SSH (agentless, POSIX tools).

## 2. Trust Model & Threats

### Assets
- SSH private keys (vault)
- Vault secret / session secret
- Host inventory, file metadata/index
- User credentials/sessions
- Audit trail integrity
- Network topology/design blueprints

### Threat Actors
- Network attacker (MITM on SSH/API if not properly secured)
- Compromised web user account
- Compromised target host / lateral movement
- Malicious insider with DB/FS access
- Container escape / host compromise
- Supply chain (dependencies)

### Key Threats & Mitigations (by design)
| Threat | Mitigation | Notes |
|---|---|---|
| Key exfiltration at rest | Envelope encryption (Argon2id KEK → AES-256-GCM wrapped DEKs), AAD binds ciphertext to row/UUID/purpose. Keys never written plaintext. | Python memory copies not guaranteed zero; minimize lifetime. |
| Key misuse / lateral movement | Host bindings with specificity (host/glob/CIDR), action restrictions (scan/checksum), ephemeral ssh-agent per task on tmpfs, agent killed/dir removed after task. | Trust-on-first-use for host keys; stored in vault's `known_hosts`. |
| Brute force / auth abuse | scrypt password hashing, per-IP and per-username rate limits on login (Flask-Limiter), account lockout semantics via counters (reset on restart), session versioning on password/change/disable. | Behind proxy set `STORAGEFORGE_PROXY_HOPS`. |
| Audit tampering | HMAC-SHA256 chained entries (prev_hash), DB triggers reject UPDATE/DELETE/TRUNCATE on audit_log, `audit verify` detects tampering/reordering/deletion. | Needs vault unlocked for HMAC verification; falls back to plain SHA-256 if vault locked. |
| CSRF / API abuse | JSON-only for state changes (`application/json` required), strict CSP, SameSite=Strict cookies, HttpOnly cookies, no CORS grants. | Form POSTs rejected unless JSON. |
| Path traversal / injection | shlex.quote for remote commands, glob escaping in find paths, parameterized SQL, input validation (host/user/key names). | Agentless commands built carefully. |
| Mass deletion / data loss | Mass-delete guard (>50% of mount entries vanish with >1000 entries → diff refused), subtree scans scoped, partial/fail aborts don't delete. | Configurable via `--max-delete-ratio`. |
| Info disclosure | UI uses textContent only, no secrets in logs (passwords never logged), public key only exposed via API, CSP restricts sources. | Passwords passed via askpass env, not argv. |
| Container escape | Non-root (uid 10001), read-only rootfs, cap_drop ALL, no-new-privileges, tmpfs for runtime/tmp, resource limits, loopback port only. | memlock raised for mlock; secrets from files. |

## 3. Security Configuration Parameters

### Environment Variables (Critical)
| Variable | Required | Purpose | Recommendations |
|---|---|---|---|
| `STORAGEFORGE_VAULT_SECRET` or `STORAGEFORGE_VAULT_SECRET_FILE` | Yes (for vault features) | Master secret for vault KEK derivation (≥32 chars). | Use strong random (e.g., `openssl rand -base64 48`), store in secret manager/file with tight perms, never in env of logs/child dumps. Rotate via `vault rotate-secret`. |
| `STORAGEFORGE_SESSION_SECRET` or `STORAGEFORGE_SESSION_SECRET_FILE` | Yes (for web UI) | Signs Flask session cookies (≥32 chars). | Rotate on compromise; invalidates sessions. |
| `STORAGEFORGE_DB` | No | DB URL (sqlite path or postgresql://). Default `~/.local/share/storageforge/index.db`. | For Postgres use TLS, least-privilege user. |
| `STORAGEFORGE_COOKIE_SECURE` | No | Set to `1/true/yes` if behind HTTPS. | Must be true in production behind TLS. |
| `STORAGEFORGE_PROXY_HOPS` | No | Number of trusted proxies for X-Forwarded-For. | Set correctly so rate limits/audit see real IPs. |
| `STORAGEFORGE_LISTEN`/`STORAGEFORGE_PORT` | No | Bind address/port. | Bind to 127.0.0.1 behind reverse proxy. |
| `STORAGEFORGE_RUNTIME_DIR` | No | tmpfs dir for ephemeral agents. Default `/run/storageforge` or XDG_RUNTIME_DIR/tmp. | Must be memory-backed (tmpfs/ramfs). Warn if not. |
| `STORAGEFORGE_DATA_DIR` | No | Data dir for index/known_hosts. | Protect permissions (0700/0600). |
| `STORAGEFORGE_VAULT_NEW_SECRET` | Only for rotation | New secret during `vault rotate-secret`. | Provided via env at rotation time only. |
| `STORAGEFORGE_SCAN_INTERVAL` | No | Auto-rescan interval for bound hosts. | Consider operational impact. |
| `STORAGEFORGE_INCLUDE_FSTYPES` | No | Extra fstype to include in scans. | Use with caution. |

### CLI Security Parameters
| Flag | Default | Notes |
|---|---|---|
| `--max-delete-ratio` | 0.5 | Abort diff if deletions > ratio and >1000 entries. Increase carefully. |
| `--no-nice` | false | Runs find without nice/ionice (higher load). |
| `--dry-run` | false | Safe inspection. |
| Vault key constraints | RSA≥3072 required | RSA<3072 refused. |
| Password policy (users) | ≥12 chars | Enforced. |

### Web/API Security Parameters
| Setting | Value | Notes |
|---|---|---|
| Session lifetime | 12 hours | Flask permanent session. |
| Session protection | strong (Flask-Login) | |
| Cookie flags | HttpOnly, SameSite=Strict, Secure if configured | |
| Login rate limits | 10/min, 50/hour per IP; 5/min, 20/hour per username | Failed attempts only; counters reset on restart. |
| Key install rate limit | 10/min per user | |
| Max body sizes | 4KB default, 2MB for `/api/planner/design` PUT | |
| CSP | `default-src 'self'; img-src 'self' data:; style-src 'self'; style-src-attr 'unsafe-inline'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'` | style-src-attr unsafe-inline only for planner inline styles. |
| Security headers | nosniff, no-referrer, DENY frame, same-origin opener, no-store | |

## 4. Operational Security Checklist

### Deployment
- [ ] Run behind TLS reverse proxy (nginx/caddy) with proper headers
- [ ] Bind to 127.0.0.1 only; never expose directly to internet
- [ ] Set `STORAGEFORGE_COOKIE_SECURE=1`
- [ ] Set `STORAGEFORGE_PROXY_HOPS` correctly
- [ ] Use strong random secrets (≥32 chars), rotate periodically
- [ ] Use container hardening as provided (non-root, read-only fs, caps dropped)
- [ ] Ensure runtime dir is tmpfs
- [ ] Put secrets in files with 0600 perms, not in shell history
- [ ] For Postgres, use TLS and least-privilege DB user

### Vault & Keys
- [ ] Initialize vault with strong secret
- [ ] Use ed25519 where possible
- [ ] Set host bindings with minimal scope (specific hosts > globs > broad CIDRs)
- [ ] Restrict actions per binding (scan vs checksum)
- [ ] Rotate vault secret periodically with `vault rotate-secret` (plan for rewrap)
- [ ] Audit vault operations regularly (`audit tail/verify`)
- [ ] Remove unused keys/bindings
- [ ] Don't store passphrases in env if avoidable; use `--passphrase-env` carefully

### Access Control
- [ ] Create users with strong passwords (≥12 chars)
- [ ] Disable/remove unused accounts
- [ ] Monitor failed login attempts
- [ ] Use session versioning features (password change/disables invalidate sessions)
- [ ] Limit who can access the web UI

### Scanning
- [ ] Review mount plans with `--dry-run` first
- [ ] Be cautious with `--include-network` (scans remote mounts on source)
- [ ] Use `--path` for subtree scans when appropriate
- [ ] Understand mass-delete guard behavior
- [ ] Run with least privilege SSH user on targets
- [ ] Trust host keys via TOFU; monitor for changes

### Monitoring & Response
- [ ] Monitor audit log (`audit tail`, API `/api/audit`)
- [ ] Run `audit verify` regularly to detect tampering
- [ ] Monitor health endpoint
- [ ] Alert on failed scans/auth failures
- [ ] Have incident response plan for secret compromise (rotate vault secret, rotate session secret, invalidate sessions)

## 5. Known Limitations & Assumptions
- Python memory is not zero-copy guaranteed; design minimizes lifetime
- Rate limit counters reset on server restart (in-memory)
- PostgreSQL DDL exists but not tested against live server
- No role-based access control yet (any signed-in user can do key install/generate)
- HMAC audit verification requires vault unlocked
- Behind proxy, IP-based limits depend on correct `STORAGEFORGE_PROXY_HOPS`

## 6. Hardening Recommendations (Priority)
### High Priority
1. Enforce HTTPS in production (set `COOKIE_SECURE`, put behind TLS proxy)
2. Use secret management (Vault/KMS) instead of plain env/files where possible
3. Implement RBAC for admin operations (user management, vault operations)
4. Add session IP binding or additional checks if needed
5. Monitor and alert on audit log verification failures
6. Regular secret rotation policy

### Medium Priority
1. Consider database encryption at rest
2. Add 2FA for web UI
3. Implement failed login account lockout with persistence (not just in-memory counters)
4. Add CSP report-uri or stricter policies
5. Enhance logging (structured logs, SIEM integration)
6. Test PostgreSQL path thoroughly

### Low Priority
1. Add rate limiting to more API endpoints
2. Implement key usage quotas
3. Add security.txt
4. Enhanced container scanning in CI

## 7. References
- README security model (lines 35-49)
- Tests: `tests/test_platform.py` covers key security scenarios
- OWASP Top 10 considerations addressed where applicable
