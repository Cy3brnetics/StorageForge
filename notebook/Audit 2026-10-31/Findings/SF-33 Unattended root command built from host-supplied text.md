---
id: SF-33
status: done
severity: medium
effort: S
area: Deploy
verified: read
tags: [finding, audit-2026-10-31]
found: 2026-10-31
---
# SF-33 Unattended root command built from host-supplied text

**Medium** · effort S · Deploy · Read in the code, not run · part of [[Audit 2026-10-31]]

## What exists
When a scan sees a failed task, `fetch_problem_logs` signs and runs a log fetch as root with no person involved. The task name is pasted in unquoted, and it comes from a file the host supplied. If `journalctl` is missing it falls back to `cat /var/log/messages`, stored whole.

## Evidence
- `confirm.py:37`, `confirm.py:186`, `confirm.py:191-194`
- `tasks.py:908`, `:966`: the state files are root-written, so a local user cannot normally reach this. A compromised host can, but it is already root there.
- `int(r['started'])` at `confirm.py:38` has no guard, so one bad line raises during the scan's ingestion.

## Why it matters
The practical injection risk is low. It still breaks concepts rule 3 in the one path that signs without a person, and `test_no_generator_lets_a_value_run_as_code` does not cover it. The more immediate problem is a whole system log copied into the database and readable with `logs.view`, a viewer permission.

## Suggested approach
Quote the name, or better, validate it against known task slugs. Cap output (`tail -n 200`) and remove the `cat` fallback. Skip lines that fail to parse.

## Done when
- [x] Hostile task names reach bash as data, with a test
- [x] Fetched output is capped

## Fixed
2026-10-31, in `85f805a`. Odd task names are skipped and the rest quoted. The `cat /var/log/messages` fallback is gone, stored output is capped at 256 KiB, and a bad line can't stop the scan. Test: `test_the_log_fetch_keeps_host_text_as_data`.
