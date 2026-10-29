---
id: PF-07
status: open
severity: medium
effort: M
area: "[[Operations and engineering]]"
tags: [finding, partial]
found: 2026-10-29
---
# PF-07 Backups have no UI and stay on the same volume

## What exists
`backup.py` (essentials and full), nightly run at `STORAGEFORGE_BACKUP_HOUR` (`server.py:262`), CLI `backup create|list|restore|prune`, and `GET/POST /api/backups` (`server.py:1146-1161`).

## What is missing
1. **No UI.** No `static/*.js` calls `/api/backups`. The only sign a nightly backup failed is an audit entry.
2. **Same volume.** Backups go to `<data>/backups`, next to `index.db`. Losing the volume (the scenario O1 in the 10-27 audit was about) loses the backups too.
3. **PostgreSQL gets none.** `_sqlite_path` raises for Postgres, the nightly thread only prunes, and `GET /api/backups` returns an empty list.

## Suggested approach
1. A "Backups" card in the Audit tab (or a new Admin group): list with kind, size, age; "Back up now"; last nightly result.
2. Off-box copy: an optional setting `backup_target` that is a host already bound in the vault; after each nightly, `rsync` the new essentials file there with the existing runner. Essentials are a few MB.
3. Postgres: run `pg_dump -Fc` for full and a `COPY` of the `ESSENTIAL` tables for essentials, or say clearly in the UI that backups are external.
4. Nightly failure becomes an alert ([[PF-01 Alerts only cover deploys|PF-01]]).

## Done when
- [ ] The UI shows the newest backup and its age, and can make one
- [ ] At least one copy can live off the data volume
