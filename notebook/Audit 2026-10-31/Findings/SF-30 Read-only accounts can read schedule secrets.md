---
id: SF-30
status: done
severity: medium
effort: S
area: Permissions
verified: proven
tags: [finding, audit-2026-10-31]
found: 2026-10-31
---
# SF-30 Read-only accounts can read schedule secrets

**Medium** · effort S · Permissions · Proven: ran it · part of [[Audit 2026-10-31]]

## What exists
Two routes hand back data the permission model says those accounts should not see. `plans.view` returns schedule commands, env values and run output. `/api/deploy` returns the alert settings that `/api/deploy/settings` refuses to the same account.

## Evidence
- `permissions.py:95`, `server.py:1590`, `alerts.py:34` (webhook URL is not in `SECRET_FIELDS`)
- Proof as `viewer`: read `{'API_KEY': 'hunter2'}` and the command text; `/api/deploy/settings` answered 403 while `/api/deploy` returned the full webhook URL.
- Proof with a role holding only `plans.view`: `/api/log/output` answered 403 while the same run's output came back from `/api/scheduler/schedules/<id>/runs`.

## Why it matters
A viewer can collect API keys people put in schedule env, tokens in commands, whatever a job printed, and webhook URLs. For Slack or Discord style webhooks, the URL is the credential.

## Suggested approach
Mask env values and return them only to `plans.edit`. Require `logs.view` for run output. Send `/api/deploy` only what `deploy.view` should see. Add `('webhook', 'url')` to the masked fields, showing the origin only. Better long term: store env values in the vault, or drop env entirely.

## Done when
- [x] A viewer test sees no env value, no run output and no webhook path

## Fixed
2026-10-31, in the working tree, not committed yet: add the commit here. Without `plans.edit`, env values and command text are masked. Run output needs `logs.view`. Without `settings.manage`, `/api/deploy` shows alert addresses as origin only and masks the ntfy topic. Env values are still stored in plain text in the database. Test: `test_read_only_accounts_do_not_see_secrets`.
