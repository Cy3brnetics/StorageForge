---
id: PF-25
status: open
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
- [ ] Lab test: nightly backup arrives on a real deploy host and restores
