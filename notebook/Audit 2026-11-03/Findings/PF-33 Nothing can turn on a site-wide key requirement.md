---
id: PF-33
status: done
severity: low
effort: S
area: Security key step-up
verified: read
tags: [finding, audit-2026-11-03]
found: 2026-11-03
---
# PF-33 Nothing can turn on a site-wide key requirement

**Low** · S · Security key step-up · Read · part of [[Audit 2026-11-03]]

## What exists
The docstring in `webauthn.py` says that having a key enrolled, "or the site asking for one", makes the step-up required. `required` reads the setting `security.webauthn_required`, but nothing writes it.

## Evidence
`webauthn.py:23` and `:163` are the only places in the Python and browser code where the name appears. A search of `storageforge_index/*.py` and `static/*.js` found no other use, and no route or CLI command sets it.

## Why it matters
An admin who wants every account to need a key has no way to ask for it. Because of [[SF-44 Security key can be removed or replaced without touching it]], this setting is also what would have stopped a key's removal from lifting the requirement.

## Suggested approach
Add it to the settings route under `settings.manage`, and audit the change. Enrolling a first key must stay possible while it's on, and accounts with no key need a clear message. Or remove the setting and correct the docstring. Untested.

## Done when
- [x] The setting can be changed from the UI and CLI, and takes effect, or it's gone and the docstring says so

**Fixed** in `a267227` (committed 2026-11-04), checked on 2026-11-04 by searching the code and the docs: no setting and no claim of one remains. The setting and its docstring claim are removed.
