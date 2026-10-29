# StorageForge Security Audit Results

**Audit Date:** 2026-10-26  
**Auditor:** AI Security Review  
**Scope:** Full codebase review of storageforge-indexer  
**Methodology:** Static code analysis, architecture review, test coverage analysis

## Executive Summary

StorageForge demonstrates a **strong security-first design** with defense-in-depth principles. The implementation shows careful attention to secret handling, cryptography, audit integrity, and secure defaults. Most security controls are well-implemented. However, there are several areas that need attention, particularly around RBAC, persistent rate limiting, and some operational concerns.

**Overall Risk Rating: MEDIUM-LOW** (with recommendations to address identified issues)

## Findings

### CRITICAL SEVERITY
*None identified.*

### HIGH SEVERITY

#### H-01: No Role-Based Access Control (RBAC)
- **Location:** `server.py`, `cli.py`, `users.py`
- **Description:** Any authenticated user can perform privileged operations including generating vault keys, installing keys on hosts via ssh-copy-id, binding keys, managing other users (via CLI), and accessing all hosts/data.
- **Impact:** Compromise of a single web user account gives full control over vault operations and host access.
- **Evidence:** `@login_required` on all `/api/keys*` routes; `users` module has no roles/permissions; CLI has no authz checks.
- **Recommendation:** Implement RBAC with roles (e.g., viewer, operator, admin). Restrict key generation/install/binding to admins/operators. Consider separating CLI auth from web auth or adding permission checks.

#### H-02: In-Memory Rate Limit Counters Reset on Restart
- **Location:** `server.py:181` (Flask-Limiter with `storage_uri='memory://'`)
- **Description:** Failed login attempt counters are stored only in memory. Server restart clears all counters, allowing attackers to reset brute force attempts.
- **Impact:** Brute force protection is ineffective across restarts; attackers can retry after crashes/restarts.
- **Evidence:** `limiter = Limiter(get_remote_address, app=web, storage_uri='memory://', headers_enabled=True)`
- **Recommendation:** Use persistent storage backend (Redis) for rate limiting, or implement persistent lockout tracking in database.

#### H-03: Vault Secret in Memory as String/Bytes
- **Location:** `vault.py:151-162`, passed around as `bytes`
- **Description:** While secrets are minimized in lifetime, Python strings/bytes are immutable and may have copies in memory. The code acknowledges this limitation but could do better.
- **Impact:** Memory dumps could potentially expose secrets.
- **Evidence:** Comments acknowledge "Python cannot guarantee no other copy exists (the import path and the env var itself are ordinary objects)"
- **Recommendation:** Accept the limitation as documented, but ensure secrets are zeroed where possible, avoid logging, and use secure memory practices. Consider using `ctypes` or `bytearray` more aggressively.

### MEDIUM SEVERITY

#### M-01: HMAC Audit Verification Requires Vault Unlocked
- **Location:** `server.py:350-356`, `cli.py:359-369`, `vault.py:451-454`
- **Description:** When vault is locked, audit entries use plain SHA-256 chaining (`alg='sha256'`) instead of HMAC. API endpoint `/api/audit/verify` requires vault to be unlocked to verify HMAC entries - if vault is locked, verification will fail or behave unexpectedly.
- **Impact:** Audit integrity verification depends on vault availability; an attacker who can lock/disrupt vault access might complicate forensics.
- **Evidence:** `if alg == 'hmac-sha256': if self.key is None: raise VaultLocked('unlock the vault to verify HMAC audit entries')`
- **Recommendation:** Store audit MAC key separately or allow verification with stored key. Consider making audit verification work even if vault is locked by caching the audit key securely.

#### M-02: No Persistent Account Lockout
- **Location:** `users.py`, `server.py` (rate limiting only)
- **Description:** Failed login rate limiting is per-IP and per-username but counters reset on restart and aren't persisted. There's no permanent account lockout mechanism.
- **Impact:** Attackers can brute force accounts across restarts or from different IPs.
- **Evidence:** Rate limits use in-memory storage; no lockout timestamp in DB.
- **Recommendation:** Implement persistent failed login tracking in database with lockout periods, and don't reset on restart.

#### M-03: Password Passed via Environment Variable in Some Cases
- **Location:** `cli.py:445-447`, `server.py:399`, `keyinstall.py:82`
- **Description:** While askpass is used for ssh-copy-id (good), CLI allows reading passwords from env vars (`--password-env`). Also web API receives passwords in JSON body.
- **Impact:** Environment variables can be visible in process lists, logs, or to child processes.
- **Evidence:** `BOT_PW` env var used in README example; `--password-env` flag exists.
- **Recommendation:** Prefer interactive prompts or secure secret injection. Document risks clearly. Ensure env vars are not logged.

#### M-04: Session Secret Auto-Generated if Missing
- **Location:** `server.py:73-84`
- **Description:** If `STORAGEFORGE_SESSION_SECRET` not set, a random secret is generated and logged as warning. Sessions end on restart anyway, but this could be unexpected.
- **Impact:** In production, missing secret causes sessions to be invalidated on every restart and secret is not persisted.
- **Evidence:** Generates `secrets.token_urlsafe(48)` if missing.
- **Recommendation:** Fail hard in production if session secret not set, or require it. Only auto-generate in dev mode.

#### M-05: PostgreSQL Support Untested
- **Location:** `README.md:195`, `db.py`
- **Description:** PostgreSQL code paths exist but "not yet been run against a live server". Dialect differences are handled but could have bugs.
- **Impact:** Production use with Postgres may have issues.
- **Evidence:** README states "The PostgreSQL DDL is written but has not yet been run against a live server."
- **Recommendation:** Test PostgreSQL thoroughly, add integration tests, or mark as experimental.

#### M-06: RSA Keys Allowed Down to 3072 (Borderline)
- **Location:** `vault.py:298-299`
- **Description:** RSA keys below 3072 bits are refused, RSA 3072+ allowed. NIST recommends 3072 for near-term, 4096 for longer security. 3072 is acceptable but could be stricter.
- **Impact:** Slightly weaker than ed25519 preference.
- **Evidence:** `if isinstance(key, rsa.RSAPrivateKey) and key.key_size < 3072: raise VaultError(f'RSA-{key.key_size} is too weak; use ed25519 or RSA ≥ 3072 bits')`
- **Recommendation:** Prefer ed25519, consider requiring 4096 for RSA or deprecating RSA.

### LOW SEVERITY

#### L-01: Error Messages May Leak Information
- **Location:** Various (e.g., `vault.py:160`, `server.py:221`)
- **Description:** Some error messages are detailed (e.g., "Not a readable private key...", ssh errors). Generally acceptable but could be tightened.
- **Impact:** Minor information disclosure.
- **Recommendation:** Review error messages to ensure no sensitive paths/secrets leaked. Generic messages for auth failures are good (login returns same error).

#### L-02: No CSRF Protection for Non-JSON (But JSON-Only Helps)
- **Location:** `server.py:228-233`
- **Description:** CSRF protection relies on requiring `application/json` content-type. This is good defense-in-depth, but not a full CSRF token mechanism.
- **Impact:** If CORS is misconfigured or browser behavior changes, could be an issue. But no CORS granted.
- **Evidence:** "a cross-site form cannot send application/json without a CORS preflight, which we never grant"
- **Recommendation:** Consider adding explicit CSRF tokens for extra defense, though current approach is reasonable.

#### L-03: In-Memory Job Queue Lost on Restart
- **Location:** `server.py:100-111`
- **Description:** Jobs in queue are lost on restart; jobs marked as failed. Acceptable for design but could be noted.
- **Impact:** In-progress scans lost on restart.
- **Recommendation:** Document behavior; consider persistent queue if needed.

#### L-04: Default Bind Address
- **Location:** `cli.py:659`, `server.py:496`
- **Description:** Defaults to `127.0.0.1` which is good. But ensure operators don't override to `0.0.0.0`.
- **Impact:** If bound to all interfaces without proxy/firewall, exposed.
- **Recommendation:** Document securely; consider warning if binding to non-localhost.

#### L-05: Known Hosts TOFU
- **Location:** `remote.py:84`, `keyinstall.py:75`
- **Description:** Trust-on-first-use for host keys is convenient but vulnerable to MITM on first connection.
- **Impact:** First connection could be MITM'd.
- **Recommendation:** Document risk; provide way to pre-populate known_hosts or verify fingerprints.

### INFORMATIONAL

#### I-01: Excellent Secret Handling Practices
- Envelope encryption with per-key DEKs
- AAD binding prevents ciphertext swapping
- Ephemeral ssh-agent on tmpfs with mlock/zeroing
- Passwords via askpass, never in argv
- Keys never written plaintext to disk

#### I-02: Strong Audit Trail
- HMAC-chained with prev_hash
- DB triggers prevent tampering
- Verification mechanism exists
- All sensitive operations audited

#### I-03: Good Container Hardening
- Non-root user, read-only fs, dropped caps, no-new-privileges
- Resource limits, tmpfs mounts
- Healthcheck, tini init

#### I-04: Robust Input Validation
- Host/user/port validation in keyinstall
- Key name regex validation
- JSON-only API
- SQL parameterization throughout

#### I-05: Thoughtful Error Handling in Scanning
- Mass-delete guard
- Bind mount handling to avoid double-counting
- Symlink loop protection
- Partial failure handling

## Test Coverage Assessment

**Strong coverage in `tests/test_platform.py`:**
- ✅ Vault roundtrip, wrong secret, tampered/swapped ciphertexts
- ✅ Rotation
- ✅ Binding specificity and actions
- ✅ Audit chain tampering detection
- ✅ Ephemeral agent behavior
- ✅ HTTP API auth, sessions, CSP, rate limiting
- ✅ Password change/disable session invalidation
- ✅ Key generation and install flow
- ✅ Askpass behavior
- ✅ Planner permissions and design saving

**Gaps:**
- PostgreSQL path not tested against live DB
- Some edge cases in rate limiting across restarts
- RBAC not tested (doesn't exist)
- Container escape scenarios not tested
- Network mount handling
- Large-scale performance edge cases

## Cryptographic Review

| Component | Algorithm | Assessment |
|---|---|---|
| KEK derivation | Argon2id (t=3, m=64MiB, p=4) | ✅ Strong, appropriate parameters |
| Key wrapping | AES-256-GCM | ✅ Strong, authenticated encryption |
| Data encryption | AES-256-GCM | ✅ Strong |
| Password hashing | Werkzeug scrypt | ✅ Strong (modern) |
| Audit MAC | HMAC-SHA256 | ✅ Strong |
| Key types | ed25519 preferred, RSA≥3072, ECDSA supported | ✅ Good (ed25519 best) |
| Nonces | os.urandom(12) for GCM | ✅ Correct size |

**Notes:**
- AAD properly used to bind ciphertexts to context
- Nonce reuse prevention relies on os.urandom (sufficient for GCM)
- Key rotation rewraps without re-encrypting data keys (efficient, secure)

## Network Security Review

| Aspect | Status | Notes |
|---|---|---|
| SSH hardening | ✅ | BatchMode, no password auth when using agent, ControlMaster, accept-new TOFU |
| API binding | ✅ | Defaults to 127.0.0.1 |
| Cookie security | ✅ | HttpOnly, SameSite=Strict, Secure configurable |
| CSP | ✅ | Strict, minimal exceptions |
| Headers | ✅ | nosniff, no-referrer, frame-ancestors none, etc. |
| Rate limiting | ⚠️ | Good but in-memory only |
| TLS | ⚠️ | Relies on reverse proxy (documented) |

## Recommendations Summary

### Immediate (High Priority)
1. **Implement RBAC** - Add role system for web users and CLI operations
2. **Persistent rate limiting** - Use Redis or DB-backed storage for login/install limits
3. **Persistent account lockout** - Track failed attempts in DB
4. **Harden session secret handling** - Require in production, fail if missing
5. **Add security warnings** - Warn if binding to non-localhost or missing secure cookie in production

### Short Term (Medium Priority)
1. **Test PostgreSQL path** - Add integration tests
2. **Improve audit verification** - Allow verification without full vault unlock
3. **Review error messages** - Ensure no info leakage
4. **Add 2FA** - For web UI authentication
5. **Security documentation** - Add deployment security guide

### Long Term (Low Priority)
1. **Database encryption at rest** - Consider SQLCipher or TDE
2. **SIEM integration** - Structured audit logs
3. **Key usage tracking** - Monitor key usage patterns
4. **Automated security scanning** - Add to CI/CD

## Conclusion

StorageForge is well-architected from a security perspective with many security best practices implemented correctly. The vault design is particularly strong, audit trail is tamper-evident, and operational security is well-considered. The main gaps are around access control (RBAC), persistent brute-force protection, and some operational hardening items.

With the recommended fixes, this would be suitable for production deployment in a security-conscious environment. The codebase shows maturity and attention to detail that's uncommon in self-hosted tools.

**Recommendation: APPROVE with conditions** - Address High severity findings before production deployment.
