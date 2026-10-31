---
id: SF-31
status: done
severity: medium
effort: S
area: Scheduler
verified: proven
tags: [finding, audit-2026-10-31]
found: 2026-10-31
---
# SF-31 Schedule report tokens are rotated by a GET and can go out in clear text

**Medium** · effort S · Scheduler · Proven: ran it · part of [[Audit 2026-10-31]]

## What exists
Three separate token problems:
1. Downloading the install script rotates the token, so a look at it breaks the installed host's reporting. Nothing audits the rotation or the download.
2. With no report URL set, the URL becomes `http://` plus the request's Host header, so tokens and output cross the network unencrypted and to whatever name the request carried.
3. Reports have no replay check. `nonce` is recorded but only compared in scan ingestion.

## Evidence
- `server.py:2003-2015`, `:1645`, `:1957`, `:2009`, `scheduler.py:829`
- Proof: old token 200, `GET install-script` 200, old token 401, and no `scheduler.token*` audit rows. With no setting, the script held `http://localhost`, taken from the request.
- A forged Host header was not demonstrated end to end, because the test client drops the session cookie across hosts. It comes from reading `request.host`; `TRUSTED_HOSTS` is not set.
- `jobs` have no such fallback: `report_url` stays empty, so this is a step back.

## Why it matters
A person with `plans.scripts` can silently stop a host's reports, which then look like a stale schedule. A person on the network path can capture a token and forge `verified` runs. Rotating on apply also kills the old token before the deploy succeeds.

## Suggested approach
Rotate only on an explicit POST or after a successful install. Refuse to deploy a schedule without a configured `report_url`, as jobs do. Reject repeated nonces and unreasonable `started_at`. Audit each token issue.

## Done when
- [x] GET changes nothing
- [x] No script is generated with a URL taken from a request header

## Fixed
2026-10-31, in `6a5a990`. A GET rotates nothing: a downloaded script carries no token and reports through scans. No report URL comes from a request; with none set, runs arrive by scan, as jobs do. An install switches the token only once it succeeded; **Run now** still switches first, because it reports during the deploy. Repeated nonces and future start times are refused. Test: `test_tokens_change_only_when_a_host_gets_the_new_one`.
