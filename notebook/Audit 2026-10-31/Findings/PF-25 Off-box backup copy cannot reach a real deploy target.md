---
id: PF-25
status: done
severity: high
effort: S
area: Backups
verified: read
tags: [finding, audit-2026-10-31]
found: 2026-10-31
---
# PF-25 Off-box backup copy cannot reach a real deploy target

**High** · effort S · Backups · Read in the code, not run · part of [[Audit 2026-10-31]]

## What exists
`copy_off` connects with the key bound for deploys and sends a shell command with the file on stdin. That key's `authorized_keys` line forces `sudo -n storageforge-run`, which accepts only a signed request, so the command is ignored and the backup bytes are read as a request that fails its signature check.

## Evidence
- `backup.py:101-134`, `deploy.py:5`, `deploy.py:212`
- The only test uses `Transport('localhost', local=True)` (`tests/test_platform.py:342-360`). The roadmap says "off-box copy not yet tried on a real host".
- Read from the code and not run. A failure should raise the backup alert, which limits the damage if that alert works.

## Why it matters
This is the disaster recovery path. Anyone relying on it may have only local backups.

## Suggested approach
Run the receive step as a signed script with the file as `data` on stdin (`deploy.run` supports that), or use a dedicated upload key with its own forced command. Add it to the KVM lab tier and try a restore from the copy.

## Done when
- [x] Lab test: nightly backup arrives on a real deploy host and restores

## Fixed
2026-10-31, in `85f805a`. The copy is a signed run with the file on stdin. Tested with the script run locally and a mocked `deploy.run`; **the lab test in Done when has not been run, so that box is open.** Test: `test_a_backup_copy_is_a_signed_run`.

## Finished
2026-10-31. Lab case `backup-copy-restores` passes in `reports/lab-2026-10-31-1618.md` (344 passed, 0 failed, 4 known): a real copy reached a deploy host through the signed runner, encrypted, and decrypted to a database holding the accounts. It checks the decrypted copy, not a full `restore` over a running system.
