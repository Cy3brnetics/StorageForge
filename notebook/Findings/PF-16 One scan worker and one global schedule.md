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

Roadmap item #6 from the 10-27 audit. **Not started.**

## What exists
- `App.__init__` starts one `scan-worker` thread reading one queue (`server.py:166-167`). `--parallel` is the parallelism *inside* one scan.
- One interval for every host, `--scan-interval` / `STORAGEFORGE_SCAN_INTERVAL` (`cli.py:1010`). `due_hosts()` is careful (no burst after restart, failures retried once per interval).

## What is missing
- A slow host (the 6M-file cachyos box takes about 5 minutes) holds up every Pi behind it, and a hung SSH connection holds up everything until it times out.
- No per-host interval, quiet hours, or "skip when unreachable without counting as failed".

## Suggested approach
1. A small pool: `STORAGEFORGE_SCAN_WORKERS` (default 2) threads on the same queue. The busy check in `enqueue()` already prevents two scans of one host. Check SQLite write contention with two scans first; WAL plus short transactions should be fine, but measure.
2. `hosts.scan_interval` and `hosts.quiet_hours` (nullable; null means the global value), editable from the host's menu. `due_hosts()` reads them.

## Done when
- [ ] A Pi's scan starts while a large host is still scanning
- [ ] One host can scan hourly while another scans nightly
