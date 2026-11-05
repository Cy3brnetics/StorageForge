---
id: SF-46
status: done
severity: medium
effort: S
area: Retention holds and permissions
verified: proven
tags: [finding, audit-2026-11-03]
found: 2026-11-03
---
# SF-46 Operators can apply legal holds through retention policies

**Medium** · S · Retention holds and permissions · Proven · part of [[Audit 2026-11-03]]

## What exists
The catalog puts applying and releasing holds under `security.emergency`, and `POST /api/security/worm/hold` enforces it. Saving a retention policy and applying policies take only `security.manage`, which operators hold, and they end in the same `security.apply_hold`, including legal holds.

## Evidence
`permissions.py` gives `worm/policies` and `worm/policies/apply` to `security.manage` in the rule above the general `worm/.*` one. `secplus.apply_policies` calls `security.apply_hold` at `secplus.py:329`. With `auto: true`, `secplus.tick` does the same once a day with nobody involved (`secplus.py:1478`).

Proof as a built-in operator, against the test suite's stand-in `zfs`:

```text
direct legal hold:    403 {'error': 'your account (operator) may not do this'}
save legal policy:    200 {'id': 1, 'ok': True}
apply policies:       200 {"done": [{"snapshot": "tank/shares@s1", "legal": true, ...}], "ok": true}
hold row:             ('tank/shares@s1', legal_hold=1, 'locked', applied_by='web:op1')
```

## Why it matters
A hold fails safe, since it keeps data rather than losing it, which is why this is Medium. But an operator can hold snapshots they aren't allowed to hold directly, and an `auto` policy keeps adding them daily, across all hosts with `host: '*'`. Held ZFS snapshots can't be pruned, so a pool can fill, and getting out of a legal hold takes the release process meant for it.

## Suggested approach
Move saving, deleting and applying policies to `security.emergency`. Previewing can stay with `security.manage`, so that needs either a separate route or a check on the mode inside the view. Untested.

## Done when
- [x] An operator gets 403 for saving a policy and for applying one in `apply` mode
- [x] A person with `security.emergency` can still do both
- [x] A test states that every route ending in `apply_hold` takes the same permission. It walks the package's call graph from what signs a script that holds snapshots back to the URL map, so a new route is found without anyone naming it (`ca2eacb`)

**Fixed** in `a267227`, with the walk test in `ca2eacb` (merged in `4d8b083`); checked on 2026-11-05 by running it, 48 tests of that file passing. The walk found seven routes, six taking `security.emergency` by rule and applying policies taking it in the view when the mode is apply, so none asks for less than a hold needs, and nothing needed fixing. Saving and deleting policies take `security.emergency`, and so does `apply` mode. Preview and report stay with `security.manage`.
