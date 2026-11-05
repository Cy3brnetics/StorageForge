---
id: SF-50
status: done
severity: low
effort: S
area: Infrastructure map
verified: proven
tags: [finding, audit-2026-11-03]
found: 2026-11-03
---
# SF-50 Any map editor can overwrite or delete another person's view

**Low** · S · Infrastructure map · Proven · part of [[Audit 2026-11-03]]

## What exists
Saved map views have an owner column and a `shared` flag, but neither is checked. Everyone with `map.view` sees all views, and anyone with `map.edit` can overwrite or delete any of them. Saving under an existing name also takes over its ownership.

## Evidence
`routes_infra.py:281` saves with `ON CONFLICT (name) DO UPDATE ... owner = excluded.owner`. `routes_infra.py:298` deletes by id alone. `routes_infra.py:276` lists all rows. Dashboards do this properly: `secplus.py:1389` deletes with `AND owner = :o`.

Proof with two operators:

```text
op3 saves 'mine' with shared=False
op4 lists views:     [('mine', 'web:op3', False)]
op4 overwrites:      200    row is now owner='web:op4', positions changed
op4 deletes:         200
```

## Why it matters
Layouts and filters only, so nothing on a host changes. But the `shared` flag suggests a privacy that doesn't exist. The same applies to design ownership in `mapdesign.save_design`, read but not proven.

## Suggested approach
Do as dashboards do: key views on owner and name, list only the account's own and the shared ones, and restrict changes to the owner. Untested.

## Done when
- [x] Another account cannot see an unshared view, overwrite it, or delete it
- [x] A shared view is visible to all with `map.view`, and only its owner can change it

**Fixed** in `a267227` (committed 2026-11-04), checked on 2026-11-04 by `MapViews` in `tests/test_audit_2026_11_03.py` (`test_a_view_is_its_owners` and `test_a_shared_view_is_seen_by_all_and_changed_by_one`, passing). Views are visible to their owner or to all if shared, and only the owner changes them. Names stay unique across the site, so another person's name answers 409. Views saved before this have no `shared` flag and become private to their owner: nothing is lost. Designs were left as team objects under `plans.edit`, on purpose.
