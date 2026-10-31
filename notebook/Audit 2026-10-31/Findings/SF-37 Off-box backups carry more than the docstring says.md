---
id: SF-37
status: done
severity: low
effort: S
area: Backups
verified: read
tags: [finding, audit-2026-10-31]
found: 2026-10-31
---
# SF-37 Off-box backups carry more than the docstring says

**Low** · effort S · Backups · Read in the code, not run · part of [[Audit 2026-10-31]]

## What exists
`send_file` says the other host "learns nothing without the vault secret". The essentials backup also holds scrypt password hashes (`users`), alert tokens in plain JSON (`settings`), host configs, the audit log, and schedule definitions with env values. `backups.manage` chooses the destination and is not marked high risk. `settings.manage` also isn't, and it redirects every job's report URL.

## Evidence
- `backup.py:27-29`, `:102-103`, `alerts.py:39-47`, `permissions.py:44-46`

## Why it matters
A destination host's root can attack password hashes offline and read alert tokens and env values. The risk flag is what an admin relies on when building a custom role, so wrong flags mislead.

## Suggested approach
Encrypt the file with a key from the vault before it leaves. Correct the docstring and the docs. Mark `backups.manage` and `settings.manage` high risk.

## Done when
- [x] A backup on the destination is unreadable without the vault secret

## Fixed
2026-10-31. Copies are AES-256-GCM in chunks, under a key from Argon2id over the vault secret and a random salt, so restoring needs nothing from inside the backup. Changing or cutting the file fails. No secret means no copy. `restore` takes them directly. If the vault secret is rotated, older copies still need the old secret. Local backups on the same volume stay unencrypted. Tests: `test_an_off_box_copy_is_encrypted`, `test_no_secret_means_no_copy`, `test_restore_takes_an_encrypted_copy`, `test_risky_permissions_say_so`.
