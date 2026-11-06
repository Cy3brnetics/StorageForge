---
id: SF-74
status: open
severity: low
effort: S
area: Signed scan payloads
verified: proven
tags: [finding, audit-2026-11-05]
found: 2026-11-05
---
# SF-74 Signed scans accept an unsigned or newly signed answer from a host that signed before

**Low** · S · Signed scan payloads · Proven · part of [[Audit 2026-11-05]]

## What exists
Scan payloads are signed on the host and checked by `scansign.Signing.check` against a key pinned for that host. A host that cannot sign says so with an `SFSIG0` line and its answer is used as unsigned, unless the site setting `scans.require_signed` is on (off by default). A host with no pinned scan key accepts the first valid signer on trust on first use.

## Evidence
`scansign.py:174-181`: for a mark of `SFSIG0`, or no mark at all, `check` returns `'unsigned'` whenever `require` is false, even when `self.pinned` is set for this very host or the host signed on every earlier scan. Probe `/tmp/sfaudit/b/p1.py`, cases 2 and 2b: a host with a pinned key that answers with `SFSIG0 ...` or with no mark is `unsigned`, used, and shown only as a state in `scan_signatures`. No alert is raised.

`scansign.py:195`: `elif not self.pinned and key not in host_keys and _valid_alone(...)`. For a host that signs with its SSH host key (a root scan; the key is in known_hosts, so `pinned` stays empty forever), any other key is pinned and accepted. Probe `/tmp/sfaudit/b/p6.py`: scan 1 signed with the host key was `signed`; scan 2, signed with a different key over different bytes, was also `signed` and pinned that key.

The controller does remember what the last scan used (`scan_signatures.keys`, `.state`) but does not consult it.

## Why it matters
The signature is meant to show that the payload came from that host's signer, unchanged. Today a party that can make signing fail on the host (fill `/tmp`, remove `ssh-keygen`, make the key unreadable) or that signs with a key of its own gets the same acceptance as a host that never signed. The stated limit is that a taken-over scan account can sign anything, so this adds little against that case; it matters against a weaker party, and it makes `signed` on a root-scanned host mean less than the docs suggest. Low, because the docs name both behaviours and the one stronger setting exists.

## Suggested approach
Once a host has signed (a pinned key, or `scan_signatures.state = 'signed'`), treat `SFSIG0` or a missing mark as a failure for that host and say why, with a one-click "this host no longer signs" accept that keeps the old key pinned. For root-scanned hosts pin the host key too (pin when `key in host_keys`) so a different key is a mismatch. Tests: pinned host with `SFSIG0`; root-scanned host with a foreign key.

## Done when
- [ ] A host that signed before and now returns unsigned is refused or flagged, not silently used
- [ ] A host that signs with its SSH host key refuses a different signer
- [ ] Tests for both, and `docs/security.md` says what the default does
