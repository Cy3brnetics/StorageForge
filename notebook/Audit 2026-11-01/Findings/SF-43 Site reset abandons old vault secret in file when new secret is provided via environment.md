---
id: SF-43
status: done
severity: medium
effort: S
area: Multi-tenant / Reset
verified: read
tags: [finding, audit-2026-11-01]
found: 2026-11-01
---
# SF-43 Site reset abandons old vault secret in file when new secret is provided via environment

**Medium** · effort S · Multi-tenant / Reset · Read · part of [[Audit 2026-11-01]]

## What exists
`storageforge_index/reset.py` manages site resets (`storageforge-index site reset --yes`). When re-keying the vault secret, `_new_secret()` checks `STORAGEFORGE_VAULT_NEW_SECRET`. If set, it returns `(given, False)`. However, `reset.run()` checks `if installs: _install_secret(secret_path, secret)`. Because `installs` is `False`, `_install_secret` is completely skipped, leaving the previous tenant's secret file on disk untouched.

## Evidence
- `storageforge_index/reset.py:101-105`:
  ```python
  def _new_secret() -> tuple[str, bool]:
      given = (os.environ.get('STORAGEFORGE_VAULT_NEW_SECRET') or '').strip()
      if given:
          return given, False
      return secrets.token_hex(32), True
  ```
- `storageforge_index/reset.py:192-198`:
  ```python
  secret, installs = _new_secret()
  ...
  if installs:
      _install_secret(secret_path, secret)
  ```
- When `STORAGEFORGE_VAULT_NEW_SECRET` is supplied (as expected in automated multi-tenant teardown/re-provisioning workflows), `installs` evaluates to `False`. The file at `secret_path` (`/run/sf-secrets/vault_secret` or `STORAGEFORGE_VAULT_SECRET_FILE`) is never updated with the new secret, nor is the `reset_at` marker created.

## Why it matters
When provisioning a new tenant site with an explicitly provided vault secret, the system wipes the database and seeds it assuming the new secret, but leaves the physical secret file containing the previous tenant's key. When the server or background runner reads the secret from the file, cryptographic mismatch occurs, preventing key decryption or leading to key reuse across supposedly isolated tenant resets.

## Suggested approach
Always install the secret when `secret_path` is writable, regardless of whether it was generated on the fly or provided via `STORAGEFORGE_VAULT_NEW_SECRET`:
```python
if secret_path:
    _install_secret(secret_path, secret)
```

## Done when
- [ ] Running `reset.run()` with `STORAGEFORGE_VAULT_NEW_SECRET` writes the specified secret to the vault secret file.
- [ ] A unit test verifies that `STORAGEFORGE_VAULT_SECRET_FILE` contains the new secret after reset.

## Outcome
**Severity after checking: Low (was Medium).** Mostly not as described. Gemini's quotes are not the code in `reset.py`, and there is no key reuse: the old secret cannot open the new vault, so the server fails closed. `installs=False` with a secret from the environment is intended and tested. The real gap is narrower: with a writable secret file and `NEW_SECRET`, reset left the old file, and the message only mentioned the environment variable. Fixed 2026-11-01 in `b222e78`: that file is now written, and the message covers both. Test: `test_a_given_secret_goes_in_a_file_this_command_can_write`.
