---
id: SF-65
status: open
severity: low
effort: S
area: Hardening steps
verified: read
tags: [finding, audit-2026-11-05]
found: 2026-11-05
---
# SF-65 Two hardening steps write their error output to fixed names in the world-writable temp folder

**Low** · S · Hardening steps · Read · part of [[Audit 2026-11-05]]

## What exists
The `sshd-option` and `apparmor-local` steps run as root on the host. Each checks its change with a tool and keeps the tool's complaint in a file with a fixed name under `/tmp`, then prints the file into the report: `sshd -t 2>/tmp/sf-sshd.err` and `apparmor_parser ... >/tmp/sf-aa.err 2>&1`. Any local account on the host can create that name first, as a file it owns or as a link to another file.

## Evidence
`steps_infra.py:494` (`if ! sshd -t 2>/tmp/sf-sshd.err; then ... $(cat /tmp/sf-sshd.err)`) and `:538` (`apparmor_parser -Q -K ... >/tmp/sf-aa.err 2>&1` and `tail -n 3 /tmp/sf-aa.err`). Read, not run: it needs a second local account on an enrolled host, and the lab hosts have none. Most current distributions set `fs.protected_symlinks=1`, which stops root following a link in a sticky folder that another user made, so the usual case is the pre-made regular file, which root overwrites and the other account reads or swaps.

## Why it matters
The same class as [[SF-55 A device rollback script runs from a guessable temporary folder|SF-55]], and the checklist asks for it: a root script uses a predictable name in `/tmp`. The file holds only a tool's error text, so what an attacker gains is the ability to change what the report prints (a rejected `sshd` change reported with another account's words) and, on a host without protected links, to make root write over a file of their choosing. A host with other local accounts is needed, so Low.

## Suggested approach
Use `mktemp` for both files and remove them when the step ends (`err=$(mktemp) ... rm -f "$err"`), as `fw_tool` already does for its own copy.

## Done when
- [ ] Neither step names a fixed file under `/tmp`
- [ ] A test runs each step under a stand-in shell with a pre-made file of the old name and sees it not used
- [ ] The commit is written here
