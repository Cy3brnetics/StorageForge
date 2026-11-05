---
id: SF-44
status: done
severity: high
effort: S
area: Security key step-up
verified: proven
tags: [finding, audit-2026-11-03]
found: 2026-11-03
---
# SF-44 Security key can be removed or replaced without touching it

**High** · S · Security key step-up · Proven · part of [[Audit 2026-11-03]]

## What exists
Once an account has a security key, `step_up` asks for a touch before releasing a hold, approving a release, using or minting the offline key, or airgapping a host. The routes that delete or add a key ask only for a fresh password.

## Evidence
`routes_secplus.py:39` is the gate. `api_webauthn_delete` (`routes_secplus.py:109`) and both register routes (`routes_secplus.py:54`, `:64`) have `@password_confirmed` and no `@step_up`. `webauthn.required` (`webauthn.py:162`) is true only while the account has a key, unless the site setting is on, and nothing can set it ([[PF-33 Nothing can turn on a site-wide key requirement]]).

Proof, an admin with a key enrolled, on a throwaway database:

```text
release with enrolled key, no touch:  403 {'error': 'touch your security key first', 'webauthn': True}
delete key with no touch:             200 {'ok': True}
release after delete:                 404 {'error': 'no such hold'}     <- past the gate; no hold with that id existed
```

Adding a key works too. With the real key still enrolled, a software key built by the proof script was accepted (200), which also marks the session as having touched, and the next release got past the gate the same way.

## Why it matters
The touch is there for the case where the session and password are both stolen. That same attacker can remove the key, or add their own, in one request, so the second factor protects nothing against the case it was built for. The audit log records the change, but the action is not stopped.

## Suggested approach
Add `@step_up` to delete and to both register routes when the account already has a key. A first key still needs no touch. Keep the existing way out for a lost token: the offline key, as the module's docstring says. Untested.

## Done when
- [x] With a key enrolled and no touch, deleting a key and registering another each answer 403 with `webauthn: true`
- [x] Enrolling the first key still works with only a fresh password
- [x] A person who lost their only key has a documented way back, and it is audited

**Fixed** in `a267227` (committed 2026-11-04), checked on 2026-11-04 by `SecurityKeys` in `tests/test_audit_2026_11_03.py` (5 tests, passing). `@step_up` on key removal and both register routes. A first key needs no touch. `user clear-keys <name>` on the server is the way back from a lost key, and is audited.
