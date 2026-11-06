---
id: SF-63
status: open
severity: low
effort: S
area: Network devices
verified: proven
tags: [finding, audit-2026-11-05]
found: 2026-11-05
---
# SF-63 One change route returns firewall rules a role without security view is refused elsewhere

**Low** · S · Network devices · Proven · part of [[Audit 2026-11-05]]

## What exists
The device routes treat a firewall rule as sensitive ("a rule is how to get in"): `GET /api/devices/<name>` and `GET /api/fleet` cut a change down to its id, device, status, actor and times, and drop the firewall, the facts' config and the DSL, unless the caller holds `security.view`. `GET /api/devices/changes/<id>` is covered only by the broader rule `GET /api/devices(/.*)?` → `devices.view`, and returns the whole change to anyone with that permission: the statements, the report with the compiled `native` text, `cuts_off` and `output`.

## Evidence
`routes_network.py:134-137` (`api_device_change` returns `netdevice.change(...)` with no filter) against `routes_network.py:75-79` and `:165-166`, which filter. The rule is `permissions.py` `(READ, r'/api/devices(/.*)?', 'devices.view')`.

Ran `/tmp/sfaudit/a/probe_role.py`: a throwaway database, a custom role holding only `devices.view`, one reported change with a rule. For that account `GET /api/devices/gw` listed the change with keys `actor, applied_at, created_at, device, finished_at, id, status` and `dsl: None`; `GET /api/devices/changes/1` answered 200 with `statements`, `report` (`cuts_off, native, notes, platform, statements, unsupported`) and `output`, and the rule's text was in the body. `GET /api/firewall` and `GET /api/dsl/of` answered 403 for the same account. Ids run from 1, so every device's changes can be listed by counting.

## Why it matters
A custom role made to see devices but not firewall rules sees the rules, including the compiled device commands, through this route. The built-in roles are not affected, since `viewer` holds `security.view`, which is why it is Low: it needs a custom role of the kind the filters were written for.

## Suggested approach
Apply the same filter in `api_device_change`: without `security.view`, return only the id, device, status, actor and times. Better, put the filter in one helper used by the three routes.

## Done when
- [ ] `GET /api/devices/changes/<id>` for a role without `security.view` returns no statements, report or output
- [ ] A test in `test_routers.py` with a `devices.view`-only role covers the change route next to the device route
- [ ] The commit is written here
