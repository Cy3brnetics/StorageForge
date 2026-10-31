---
id: PF-16
status: open
severity: medium
effort: M
area: "[[Operations and engineering]]"
tags: [finding, roadmap]
found: 2026-10-29
---
# PF-16 One scan worker and one global schedule

Roadmap item #6 from the 10-27 audit. **Worker pool done; per-host schedules not started.**

## What exists
- `App.__init__` starts `STORAGEFORGE_SCAN_WORKERS` (default 4) `scan-worker` threads on one queue. `--parallel` is the parallelism *inside* one scan.
- One interval for every host, `--scan-interval` / `STORAGEFORGE_SCAN_INTERVAL` (`cli.py:1010`). `due_hosts()` is careful (no burst after restart, failures retried once per interval).

## What is missing
- No per-host interval, quiet hours, or "skip when unreachable without counting as failed".

## Suggested approach
1. `hosts.scan_interval` and `hosts.quiet_hours` (nullable; null means the global value), editable from the host's menu. `due_hosts()` reads them.

## Done when
- [x] A Pi's scan starts while a large host is still scanning
- [ ] One host can scan hourly while another scans nightly
