---
id: SF-45
status: in-progress
severity: high
effort: S
area: Sentinel and permissions
verified: proven
tags: [finding, audit-2026-11-03]
found: 2026-11-03
---
# SF-45 deploy.apply removes the sentinel that security.emergency guards

**High** · S · Sentinel and permissions · Proven at the route · part of [[Audit 2026-11-03]]

## What exists
The catalog says arming the sentinel takes `security.emergency`, and `POST /api/security/sentinel` enforces that. But `POST /api/deploy/start` with `kind: security` asks only for `deploy.apply`, and it takes `remove` and `rearm`. The built-in operator role holds `deploy.apply` and not `security.emergency`.

## Evidence
`need_for_deploy` (`server.py:1585`) has no check for this kind. `security.deploy_items` passes `--uninstall`. On the host that stops the sentinel, deletes the brake and fence programs and unchanged decoys, and the controller forgets the report token (`secscripts.py:629`, `security.py:950`).

Proof as a built-in operator. `deploy.start_group` was replaced to capture the items, so the route decision is proven and the script did not run here:

```text
change sentinel config:            403 {'error': 'your account (operator) may not do this'}
deploy/start kind=security remove: 200 items=[('nas', ['--uninstall'], 'apply')] who=web:op2
deploy/start kind=security rearm:  200 items=[('nas', ['--apply'], 'apply')]
```

**The UI offers this on purpose:** `static/securityview.js:266` shows the deploy and Remove buttons to `deploy.apply`. So this may be a decision nobody wrote down rather than a slip, and the catalog text doesn't tell anyone about it.

## Why it matters
Ransomware that gets an operator's session and password can take the detection off each host before it starts encrypting, while the account is barred from changing the same sentinel's settings. It takes a fresh password and leaves an audit row.

## Suggested approach
**Decision needed.** Recommended: removing or re-arming takes `security.emergency`, and a plain install or update of the saved config stays with `deploy.apply`. Add to `need_for_deploy`:

```python
if kind == 'security' and mode == 'apply' and (options.get('remove') or options.get('rearm')):
    need('security.emergency')
```

Hide the Remove button to match. Untested. If operators are meant to keep this, say so in the catalog's text for `deploy.apply`, and close this as `wontfix` with who decided.

## Done when
- [x] An operator gets 403 for `remove` and `rearm` on `kind: security`, or the catalog says they may
- [x] An admin can still remove and re-arm
- [x] A test walks every deploy option for this kind against the role

**Fix:** in the working tree on 2026-11-03, not committed, so this is `in-progress` until a commit can be recorded here. Decided 2026-11-03: the sentinel gets its own permission, `security.sentinel`, held by admins and not operators. Setting it up takes it. Deploying, re-arming and removing take it and `deploy.apply`, retries included. A dry run stays with `deploy.report`. Migration 037 gives it to custom roles holding `security.emergency`. The real uninstall script was not run in this check, only the route's decision.
