---
id: PF-09
status: done
severity: medium
effort: M
area: "[[Hosts, keys and accounts]]"
tags: [finding, partial, security]
found: 2026-10-29
---
# PF-09 Accounts are CLI-only and have no roles

## What exists
`users.py` has create, set_password, set_disabled, remove, session lengths and server-side sessions. `PUT /api/me` sets only `session_minutes`.

## What is missing
- A signed-in user can't change their own password in the UI; it needs shell access to the container (`user passwd`).
- No roles: H-01 (10-26) and SF-02 (10-28) are still open, so every account can deploy root scripts to every host. Fine for one user, a blocker for a second.

## Suggested approach
1. `PUT /api/me {"password", "new_password"}`: needs the current password, ends other sessions (`end_all_sessions` exists).
2. Roles as one column, `users.role IN ('viewer','operator','admin')`, default `admin` for existing users so nothing changes on upgrade. One decorator `@needs('operator')` on every route that writes or runs; `admin` for keys, access grants, users and settings. `test_every_route_needs_a_session_unless_listed` already enumerates routes; extend it to assert each route's role.
3. Users card for admins: list, add, disable, set role.

## Done when
- [ ] Password change works from the UI
- [ ] A viewer can browse and search but every write route answers 403

## Progress 2026-10-30
Password change, Accounts card, and `required_role` in `server.py`: default-deny, with a test that walks every route as a viewer. Buttons a viewer may not use are still shown and answer 403.
