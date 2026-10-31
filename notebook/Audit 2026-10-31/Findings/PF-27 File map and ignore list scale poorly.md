---
id: PF-27
status: done
severity: low
effort: S
area: File map
verified: read
tags: [finding, audit-2026-10-31]
found: 2026-10-31
---
# PF-27 File map and ignore list scale poorly

**Low** · effort S · File map · Read in the code, not run · part of [[Audit 2026-10-31]]

## What exists
- `/api/filemap` reads every checksummed row into Python on each request, with no cache unless `folders=1` is asked for and no limit.
- `PUT /api/files/ignore` rebuilds the graph of every host inside the request.
- The route accepts up to 2000 paths, but the 4 KiB body limit stops it long before that.
- Retiring a host leaves its schedules behind, which keep raising stale alerts (`retire.py`).

## Evidence
- `filemap.py:29-41`, `server.py:2186-2211`, `server.py:162`
- Read from the code; no large index was measured.

## Why it matters
Slow pages, and tied-up threads at index sizes this tool is meant for. Otherwise the feature is well made: DOM-only rendering, read-only, hard-link limitation documented.

## Suggested approach
Use the existing `folder_result` cache and a SQL `GROUP BY` with a limit. Rebuild graphs in the background. Raise the body limit for that route. Make `retire.blockers` include schedules.

## Done when
- [x] Map loads under 2 seconds on a large test index

## Fixed
2026-10-31. The query reads only checksums that repeat, and the result is kept until the index or ignore list changes. Measured on 1,000,000 synthetic checksummed files on SQLite: `filemap.build` 0.42 s, on this machine. Ignore routes take 256 KiB. Graph rebuilds run in a background thread, so the next graph view may briefly be the old one. Retiring a host with schedules is refused. Tests: `test_file_map_is_kept_until_something_changes`, `test_a_long_ignore_list_fits`, `test_only_duplicates_are_read_for_the_map`, `test_retiring_a_host_with_a_schedule_is_refused`.
