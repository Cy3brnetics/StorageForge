---
id: PF-27
status: open
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
- [ ] Map loads under 2 seconds on a large test index
