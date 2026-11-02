---
id: PF-29
status: done
severity: high
effort: S
area: Snapshot engine / Shell probes
verified: proven
tags: [finding, audit-2026-11-01]
found: 2026-11-01
---
# PF-29 Snapfind fails silently if capability find is unexecutable

**High** · effort S · Snapshot engine / Shell probes · Proven: ran it · part of [[Audit 2026-11-01]]

## What exists
`snapfind.py` generates a shell probe run on scanned hosts to discover snapshot roots and intervals for rsnapshot and snapper. It prefers `/usr/local/lib/storageforge/find` over the system `find`. If this binary exists but execution fails (due to restrictive file permissions, missing Linux capabilities, or SELinux policies), the shell script swallows the execution error with `2>/dev/null` and silently produces empty output, discovering zero snapshots.

## Evidence
- `storageforge_index/snapfind.py:13-40`:
  ```bash
  [ -x /usr/local/lib/storageforge/find ] && F=/usr/local/lib/storageforge/find || F=find
  ...
  $F "$p" -maxdepth 1 -mindepth 1 2>/dev/null | tag S "$c"
  ```
- Proof: Running the unit test suite against the local host environment produced:
  `tests/test_snapjobs.py:test_the_search_runs_and_finds_a_config_by_its_cron_line`:
  `AssertionError: Lists differ: [] != ['daily.0']`
  Investigating `/usr/local/lib/storageforge/find` revealed permissions `-rwxr-x--- 1 nobody nobody`. Because the test ran under an unprivileged user not in group `nobody`, test `[ -x ... ]` succeeded for bash test flags on some environments or the file existed, but execution returned EPERM (exit code 126).
  Because stderr is redirected to `/dev/null`, the probe reported no errors, printed no output, and returned zero snapshots instead of falling back to standard `find`.

## Why it matters
The snapshot discovery engine is a core feature for automated data protection tracking. If an admin installs the capability binary with non-standard ownership/permissions, or if security hardening denies access to the scan user, StorageForge silently fails to discover all existing snapshots, presenting hosts as unprotected without any diagnostic alert or error message.

## Suggested approach
In `snapfind.py`, verify that `/usr/local/lib/storageforge/find` can actually be executed before selecting it:
```bash
F=find
if [ -x /usr/local/lib/storageforge/find ] && /usr/local/lib/storageforge/find --version >/dev/null 2>&1; then
    F=/usr/local/lib/storageforge/find
fi
```
Additionally, if `$F` fails with code 126 or 127 during path exploration, fall back to standard `find`.

## Done when
- [ ] `snapfind.py` falls back to system `find` if `/usr/local/lib/storageforge/find` fails to execute.
- [ ] `test_snapjobs.py` passes cleanly regardless of `/usr/local/lib/storageforge/find` file permissions.

## Outcome
**Severity after checking: Medium (was High).** Confirmed by reading, and by a stand-in that exits 126. Fixed 2026-11-01 in `b222e78`: the helper must run before it is used, as `remote._tool` already does. Gemini's failing test did **not** reproduce here: `tests.test_snapjobs` passed before the fix, because the helper runs for this user, and the `nobody:nobody` it reports looks like its sandbox. Lowered because the kernel or an admin has to refuse the helper first. Test: `test_a_capability_find_that_cannot_run_is_passed_over`.
