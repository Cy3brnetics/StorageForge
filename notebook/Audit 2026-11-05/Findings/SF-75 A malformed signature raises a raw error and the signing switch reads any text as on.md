---
id: SF-75
status: open
severity: low
effort: S
area: Signed scan payloads
verified: proven
tags: [finding, audit-2026-11-05]
found: 2026-11-05
---
# SF-75 A malformed signature raises a raw error and the signing switch reads any text as on

**Low** · S · Signed scan payloads · Proven · part of [[Audit 2026-11-05]]

## What exists
`Signing.check` is meant to raise `BadSignature` (a `RemoteError`) for anything that must not be used, and callers rely on that type. `PUT /api/scans/signing` turns the site-wide requirement on and off.

## Evidence
`scansign.py:183-188` catches `(ValueError, UnicodeDecodeError)` around `signer_key`. `signer_key` calls `struct.unpack` through `_ssh_string` (`:93-96`), which raises `struct.error` on a short buffer, and `struct.error` is not a `ValueError`. Probe `/tmp/sfaudit/b/p1.py`, case 5: three truncated SSH signatures (`SSHSIG` alone, with a version and nothing more, with a length that overruns) each ended in `error: unpack requires a buffer of 4 bytes`, not `BadSignature`. The payload is still not used, so this fails closed, but the error is a bare exception: `stream_job` catches everything and aborts that mount, while `Transport.run` (the inventory, Docker and git surveys) and `checksum_pass` let it out of `scan_host` with an unhelpful text, and the audit row for the scan carries `unpack requires a buffer of 4 bytes`. A host can produce this at will.

`server.py:2251`: `need = bool(json_body().get('require'))`. A body of `{"require": "false"}` or `"0"` is a non-empty string, so it switches the requirement on, and the response says `require: true`. Read, not run through the server. It fails toward safer, but it breaks every scan of an unsigned host after a client sent a string.

## Why it matters
Tidiness and error quality: one hostile host can make its scans fail with an internal-looking message instead of the explained refusal, and the switch does what the sender did not mean. Both small.

## Suggested approach
Catch `struct.error` (and `IndexError`) in `signer_key` and re-raise `ValueError`. In the route, accept only a JSON boolean (`isinstance(v, bool)`) and return 400 otherwise, as the neighbours do. Add a test for each.

## Done when
- [ ] A truncated or overrunning signature gives `BadSignature` with the usual text from every caller
- [ ] `PUT /api/scans/signing` refuses a non-boolean `require`
