---
id: EQ-05
status: open
severity: low
effort: S
area: Operations
verified: read
tags: [finding, audit-2026-10-31]
found: 2026-10-31
---
# EQ-05 Uncommitted lab fixes need a lab run

**Low** · effort S · Operations · Read in the code, not run · part of [[Audit 2026-10-31]]

## What exists
The working tree holds fixes for bugs found in the KVM lab, and removes their `KNOWN` entries from `tests/lab/tiers.py`. This audit read them: `lvextend -y`, safer runner update, `userdel` wait, rootless Podman detection, rsync `-S` and xattr filters, the `canonical` IP rule. The unit suite passes with them.

Three notes:
- The KVM tier wasn't run, so removing `KNOWN` entries is unconfirmed.
- `serve` in `jobscript.py` appends `.git` after the `under` check. A `.git` symlink in the source can point outside the job's root. Re-check after the change, using `realpath`.
- `security.selinux` is no longer copied. That is right for a mirror on another host, but a restore to the original needs `restorecon`. The restore flow should say so.

## Evidence
- `git diff` at audit time, `jobscript.py:109`, `deploy.py:173-176`

## Why it matters
A small risk, and worth closing before these get committed.

## Suggested approach
Run the lab tiers, fix the symlink case, add the restore note, then commit.

## Done when
- [ ] Lab results recorded with no new failures
