---
id: SF-80
status: done
severity: low
effort: S
area: Web UI
verified: proven
tags: [finding, audit-2026-11-05]
found: 2026-11-05
---
# SF-80 A staged change plan and the planner drafts stay in the browser for the next account

**Low** · S · Web UI · Proven (the Changes draft; the planner draft by reading) · part of [[Audit 2026-11-05]]

## What exists
`kernel.js` keeps drafts with `sfStash` and `sfRecall`, which store the signed-in user's name with the value and hand it back only to the same user. Its comment says why: "A draft kept in this browser belongs to the person who wrote it, so another account on the same browser never sees it." Two other places keep drafts in `localStorage` without that: the Changes tab (`sf.changes.draft`, the whole staged plan with its host names, paths and notes) and the planner (`storageforge.v1` and `storageforge.v1:<host>`, a whole design of a host's disks, serial numbers and mounts). Neither is stamped with a user, and signing out removes neither.

## Evidence
`static/changes.js:8-22`: `CH_DRAFT = 'sf.changes.draft'` is read at load with `JSON.parse(localStorage.getItem(CH_DRAFT))` and written by `chKeep()` as `JSON.stringify({ ...CH.plan, dirty: CH.dirty })`. `static/planner.js:115-118`: `draftKey = h => 'storageforge.v1' + (h ? ':' + h : '')`, `load()` and `save()` use it directly. Compare `static/kernel.js:149-160` (`sfStash`/`sfRecall`, user-stamped), which only `mapview.js` and `manage.js` use.

What I ran (headless Chromium against the app on `127.0.0.1` with a throwaway SQLite database and two admin accounts, `/tmp/sfaudit/c/probe_ui.py`): signed in as the first account, staged a plan with the name `admin-private-plan` and a folder task under `/srv/secret-project`, wrote a planner draft, then signed out through `sfSignOut()`. `Object.keys(localStorage)` still held `sf.changes.draft` and `storageforge.v1:nas`. Signed in as the second account in the same browser profile: `CH.plan` held the first account's plan with its task, `CH.dirty` was true, and the Changes tab's page text contained both strings. The planner draft is read the same way (`planner.js:1070`, `load(host)`), which I did not run as the second account.

## Why it matters
On a browser shared by two people (a shared admin workstation, a jump host), the second account sees what the first was about to do: host names, paths and the planner's disk layout, and carries the unsaved plan into its own session, where one click on Save keeps it under the wrong name. The server still checks permissions on every call, so the second account gains no power it lacks; this is information and tidiness, and it breaks the promise the kernel's own comment makes. Low, because it needs a shared browser profile.

## Suggested approach
Move both to `sfStash`/`sfRecall` with the signed-in name (the planner already learns it from `/api/me`). Signing out can then leave the drafts in place (the same person finds them again), because the stash hides them from other accounts. Old unstamped keys have no owner: remove them rather than hand them to whoever signs in next. Add a case to `tests/test_ui_kernel.py` that fails when a script writes a `localStorage` key not routed through the stash.

## Done when
- [x] The Changes draft and the planner drafts are stamped with the user and not shown to another account
- [x] Unstamped drafts from earlier versions are dropped, not handed to whoever signs in next
- [x] A browser test signs in as two accounts and sees the second get an empty plan
- [x] The commit is written here

## Fixed
2026-11-06, in `3c1f9b6`. The change plan and planner drafts go through `sfStash`/`sfRecall`, stamped with the account, and old unstamped keys are removed on load. Signing out still leaves the drafts, now under their own account. The suggested rule in `test_ui_kernel.py` against any `localStorage` key outside the stash was not added. Unit-tested, with the test seen to fail on the old code. Not lab-tested.
