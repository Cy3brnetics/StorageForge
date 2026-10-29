---
id: PF-11
status: open
severity: medium
effort: M
area: "[[Reports and exports]]"
tags: [finding, partial]
found: 2026-10-29
---
# PF-11 File history and content dupes are CLI-only

## What exists
- `file_changes`: every add, modify and delete per scan, kept 90 days and up to 2M rows (`db.py:25-26`, `STORAGEFORGE_CHANGE_DAYS`).
- CLI `changes` (files changed in a scan) and `dupes` (identical files from `--checksum` scans), `cli.py:799,806`.

## What is missing
Neither has an API route or UI. The web app shows *folder*-level copies (by name and structure) but not *file*-level identical content, and has no "what changed on this host since yesterday", although the data is already paid for.

## Suggested approach
1. `GET /api/file-changes?host=&scan=&kind=&under=&limit=`. Not under `/api/changes`, which is change plans (the naming clash noted as P3 in the consistency audit).
2. A "Changed" mode in the Search tab: pick a host and a scan (default: latest), list adds/modifies/deletes with size deltas; group by top folder so a 50k-file `npm install` collapses to one row.
3. `GET /api/dupes` and a third section in Cleanup, only shown when any checksum scan exists.
4. Bonus: a "large deletes" check (over N GB or N files gone in one scan) as an alert under [[PF-01 Alerts only cover deploys|PF-01]]; it's the cheapest ransomware/accident signal there is.

## Done when
- [ ] The UI answers "what changed on host X in the last scan"
- [ ] Checksum duplicates are visible in Cleanup
