---
id: PF-08
status: in-progress
severity: medium
effort: M
area: "[[Hosts, keys and accounts]]"
tags: [finding, partial]
found: 2026-10-29
---
# PF-08 No way to retire a host

## What exists
- CLI: `vault remove`, `vault unbind`, `vault rotate-secret`, `hosts rekey` (forget pinned host keys).
- UI Keys tab (`app.js:667-693`): generate a key, install it, list keys and bindings, "Scan now".

## What is missing
- **No host removal anywhere.** There is no `DELETE FROM hosts` in the code. A decommissioned or renamed machine keeps its index (search results), its graph nodes, its design and its alerts forever. The `ON DELETE CASCADE` on `mounts`/`file_records` is there, unused.
- **Keys tab is list-only.** Unbinding, removing a key or rotating it needs the CLI, so the UI can add access but never take it away.
- The scheduler keeps scanning a dead host for as long as its binding exists, failing once per interval.

## Suggested approach
1. `hosts remove NAME [--keep-design]` and `DELETE /api/hosts/<name>` (password-confirmed): refuse while jobs or shares are deployed there (same rule as plans, `server.py:788`), otherwise delete the host row (cascades), its graph nodes, scan jobs, and optionally its blueprint; audit it.
2. Keys tab: "Unbind" per binding and "Remove" per key with no bindings, both password-confirmed.
3. Show "last scanned N days ago" in grey on hosts not scanned for 3 intervals, with "Retire…" in the host menu.

## Done when
- [ ] A host can be retired from the UI and disappears from search, graph and the scheduler
- [ ] Bindings can be removed from the UI

## Progress 2026-10-30
`retire.py`, `hosts remove`, `DELETE /api/hosts/<name>`, and Remove and Unbind in the Keys tab. Not done: grey "not scanned for N days" on stale hosts.
