---
id: EQ-09
status: done
severity: low
effort: S
area: Docs
verified: read
tags: [finding, audit-2026-11-03]
found: 2026-11-03
---
# EQ-09 The signing promise reads wider than the code

**Low** · S · Docs · Read · part of [[Audit 2026-11-03]]

## What exists
[[Project invariants]] says sync and snapshot jobs "run only signed scripts through `storageforge-run`". What is signed is the install. After that, timers run the installed program with no signature check on each run, and a job key's forced command runs `storageforge-job --serve` directly under its own sudoers rule.

## Evidence
`deploy.py:221` allows `storageforge-job --serve *` beside the runner. `jobscript.py:144` and `:145` run the job's `pre` and `post` commands from its deployed config on request over that key. Sentinel, ClamAV, identity, task and schedule timers work the same way.

**This is a sound design, not a security bug.** Those files are root-owned and were delivered signed, and `--serve` allows a fixed list of actions. Anyone who could change them is already root. Only the wording is off.

## Why it matters
Someone relying on the sentence would believe every run is checked at run time, and an audit can't tell whether a new unsigned path is allowed. This audit had to work out the boundary for itself.

## Suggested approach
Reword the invariant: what is sent to a host is signed, what runs later from a timer was installed by a signed deploy and isn't checked again, and the scan channel and the first-time setup are the named exceptions. Move the table from [[Audit 2026-11-03]] into `docs/security.md`. Untested wording.

## Done when
- [x] The invariant and `docs/security.md` list what is signed, what isn't, and why

**Fixed** in `a267227` (committed 2026-11-04), checked on 2026-11-04 by reading: `docs/security.md` ("What is signed") and the invariants row say what is signed, what is not, and why. The invariants are reworded, and `docs/security.md` has a table of what is signed.
