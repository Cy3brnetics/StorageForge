---
id: SF-36
status: done
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
- [x] Widening a role cancels links that name it

## Fixed
2026-10-31. Migration 025 stores what a link grants and, for a reset, the account id and session version. A link dies if its role comes to allow more, or its account changes in any way; a new link and removing the account both revoke. Links from before this are dead. Tests: `test_links_die_when_what_they_grant_changes`, `test_a_reset_link_is_for_one_account_as_it_was`, `test_a_link_from_before_the_checks_is_dead`.
