---
id: PF-31
status: done
severity: medium
effort: S
area: Request limits
verified: proven
tags: [finding, audit-2026-11-03]
found: 2026-11-03
---
# PF-31 The 4 KiB body limit refuses what new routes accept

**Medium** · S · Request limits · Proven · part of [[Audit 2026-11-03]]

## What exists
Every request body is limited to 4 KiB unless `body_limit` raises it, and it does so for only four paths. Several new routes validate far larger input, but that input never reaches the validator.

## Evidence
`server.py:504` sets `MAX_CONTENT_LENGTH=MAX_BODY` (4096), and `server.py:599` raises it only for planner, ignore-list and report paths. Against that:

| Route | The code accepts | Proof with a body over 4 KiB |
| :-- | :-- | :-- |
| `POST /api/map/views` | 200,000 characters (`routes_infra.py:288`) | 413 |
| `POST /api/map/designs` | Its own `LIMIT` (`mapdesign.py:287`) | 413 |
| `POST /api/security/behavior/yara/rules` | 200,000 characters (`secplus.py:848`) | 413 |
| `POST /api/security/behavior/falco` | 200,000 characters (`secplus.py:745`) | 413 |
| `POST /api/security/report` | 100 lines of 32 KiB (`routes_security.py:63`) | 413 with a valid token |

For the report route, one event with a 3,800-byte path, and a batch of 100 small events, were both refused. A smaller event (1,000 bytes of detail) was accepted. The route refuses a bad token first, so the limit only shows with a valid one.

## Why it matters
The map saves pin positions in a view (`mapview.js:361`), so saving a view with many pinned nodes fails. Real YARA and Falco rule sets are often over 4 KiB. It's the same kind of bug as [[PF-28 Job reports over 4 KiB are refused with 413 Payload Too Large|PF-28]]. The sentinel's reports fall back to the next scan or measurement, so a very long path is delayed rather than lost (read, not run).

## Suggested approach
Add these paths to `body_limit`, each with a limit matching what its validator accepts. Better still, keep the path and its limit in one table, and test the table by posting just under and just over each limit. Untested.

## Done when
- [x] Each route accepts a body at its stated limit and refuses one over it
- [x] A map view with several hundred pins saves
- [x] A test walks the table in both directions

**Fixed** in `a267227` (committed 2026-11-04), checked on 2026-11-04 by `BodyLimits` in `tests/test_audit_2026_11_03.py` (4 tests, passing). `server.BODY_LIMITS` holds each route's limit, and a test walks it in both directions. The report routes check the token first, so a stranger cannot make them read a large body.
