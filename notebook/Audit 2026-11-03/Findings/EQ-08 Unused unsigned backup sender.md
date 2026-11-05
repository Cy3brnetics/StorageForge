---
id: EQ-08
status: done
severity: low
effort: S
area: Backups
verified: proven
tags: [finding, audit-2026-11-03]
found: 2026-11-03
---
# EQ-08 Unused unsigned backup sender

**Low** · S · Backups · Proven · part of [[Audit 2026-11-03]]

## What exists
`backup.send_file` streams a backup to a host over a raw transport, unsigned and unencrypted. Production code no longer calls it: `copy_off` replaced it with a signed, encrypted run.

## Evidence
`backup.py:120` defines it. A search of the package and tests finds only `tests/test_platform.py:381` and `:387` calling it. `backup.py:179` is the signed route used now, and its docstring says no vault secret means no copy, "never a copy in the clear".

## Why it matters
No exposure today. But it's a ready-made way to send a backup in the clear and to run a script unsigned, and the next person writing backup code could easily pick it up. Its tests also make the path look supported.

## Suggested approach
Delete `send_file` and its tests. `receive_script` stays, since `copy_off` uses it. Untested.

## Done when
- [x] `send_file` is gone, and `copy_off` is the only way a backup leaves the server

**Fixed** in `a267227` (committed 2026-11-04), checked on 2026-11-04 by searching: `send_file` is nowhere in `storageforge_index` or `tests`, and `backup.copy_off` is the one way a backup leaves the server. `send_file` and its test are deleted.
