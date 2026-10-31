---
id: SF-36
status: open
severity: low
effort: S
area: Accounts
verified: proven
tags: [finding, audit-2026-10-31]
found: 2026-10-31
---
# SF-36 Reset links check the role name, not what it allows

**Low** · effort S · Accounts · Proven: ran it · part of [[Audit 2026-10-31]]

## What exists
A reset link is cancelled if the account's role **name** changed, so a link for a viewer can't take over a later admin. Editing the role's permissions leaves the link alive. It also survives the account being removed and recreated under the same name and role, and a newer link doesn't cancel an older one. Open invites have the same gap for role growth.

## Evidence
- `users.py:204-227`
- Proof: a reset link made while role `small` allowed only search stayed valid after `small` was given every permission.

## Why it matters
Needs someone to hold an old link while an admin widens a role, so it is unlikely. It is cheap to close.

## Suggested approach
Store the role's permission list, or the user id plus `session_version`, in the link. Refuse if either changed. Creating a link revokes older ones for that account.

## Done when
- [ ] Widening a role cancels links that name it
