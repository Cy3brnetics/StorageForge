---
id: PF-10
status: open
severity: low
effort: S
area: "[[Operations and engineering]]"
tags: [finding, bug]
found: 2026-10-29
---
# PF-10 Cleanup cache holds one result

U4 from the 10-27 audit, half done.

## What exists
`server.py:1163-1187`: `folder_cache` keyed on the arguments plus `max(scan_id)`, so a new scan invalidates it.

## What is wrong
- Both `/api/folders/cold` and `/api/folders/duplicates` call `folder_cache.clear()` before storing. The Cleanup tab loads both, so each evicts the other: opening the tab twice recomputes both (8-13 s each on 6M files, measured 10-27).
- Nothing is computed after a scan, so the first visit is still slow.
- No lock: two requests at once (two tabs, or waitress threads) both compute.

## Suggested approach
1. Keep one entry per kind: `folder_cache[kind] = (key, result)`, and a `threading.Lock` per kind.
2. After each scan job finishes (`App._work`), warm the default queries for that host in the worker thread.
3. Return `computed_at` so the tab can say "worked out after the scan at 03:12".

## Done when
- [ ] Switching between Copies and Cold data is instant after the first load
