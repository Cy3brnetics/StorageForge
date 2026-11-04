---
id: SF-47
status: in-progress
severity: medium
effort: S
area: Evidence export
verified: proven
tags: [finding, audit-2026-11-03]
found: 2026-11-03
---
# SF-47 A viewer's GET unlocks the vault to sign evidence

**Medium** · S · Evidence export · Proven in part · part of [[Audit 2026-11-03]]

## What exists
`GET /api/security/evidence` needs `audit.view`, which every viewer holds. Each request unlocks the vault, loads the deploy signing key, signs a document and writes an audit row. It has no rate limit. The catalog keeps `audit.verify` separate because it "unlocks the vault", and viewers don't hold that.

## Evidence
`routes_secplus.py:239` is the route, and `secplus.py:443` to `:461` unlock the vault and call `deploy._signer`. There is no `@limiter` on it.

Proof as a built-in viewer:

```text
viewer GET x5:             [200, 200, 200, 200, 200]    vault unlocks: 5    0.34 s
audit rows from those GETs: 6 (one more request followed)
control, /api/audit/verify: 403
```

**Proven:** the access, the unlocks, the rows and the missing limit. **Not measured:** how many requests would hurt a real server. Each unlock is Argon2id at 64 MiB by default (`vault.py:44`), and no load test was run.

**Not a finding, proven:** a signed evidence file can't be replayed as a deploy. It uses the namespace `storageforge-evidence`, and the real runner refused a request signed in that namespace.

## Why it matters
The lowest role with access can make the server do its most expensive operation in a loop and grow the append-only audit log. It also breaks the checklist's rules for a GET and for a costly route, and takes the root-script signing key out of the vault for a read-only account.

## Suggested approach
Make it a POST, require `audit.verify` as well, and rate limit it as the other costly routes are. Longer term, give evidence its own signing key, so that this path never loads the key that signs root scripts. Untested.

## Done when
- [x] A viewer gets 403, and a holder of the new permission can still export
- [x] Past the limit the route answers 429 without unlocking the vault
- [x] A GET leaves the audit log unchanged

**Fix:** in the working tree on 2026-11-03, not committed, so this is `in-progress` until a commit can be recorded here. Now a POST that takes `audit.view` and `audit.verify`, limited to 10 a minute per account, and past the limit it does not unlock the vault. A separate evidence signing key was not done: this path still loads the key that signs root scripts, for those allowed to use it.
