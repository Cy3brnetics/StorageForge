---
id: SF-51
status: done
severity: low
effort: S
area: Infrastructure map
verified: proven
tags: [finding, audit-2026-11-03]
found: 2026-11-03
---
# SF-51 Comparing a design writes to the database on a GET

**Low** · S · Infrastructure map · Proven · part of [[Audit 2026-11-03]]

## What exists
`GET /api/map/designs/<id>/compare` records when the design was last compared. A viewer, who has no write access to designs, can change the row.

## Evidence
`routes_infra.py:234` calls `mapdesign.mark_compared`. Proof as a built-in viewer: `200`, and the row differs before and after.

## Why it matters
Only a timestamp changes. It breaks the checklist's rule that a GET changes nothing, including database rows, and the timestamp can suggest that someone responsible reviewed the design when any viewer's page load did it.

## Suggested approach
Keep the GET read-only and return `compared_at` without saving it, or move the saving to a POST under `plans.edit`. Untested.

## Done when
- [x] A GET leaves the row unchanged

**Fixed** in `a267227` (committed 2026-11-04), checked on 2026-11-04 by `MapViews.test_comparing_a_design_changes_nothing` in `tests/test_audit_2026_11_03.py` (passing). The GET no longer writes. It still returns `compared_at`. The `map_designs.compared_at` column stays, unused, since nothing read it and dropping it is not worth a migration.
