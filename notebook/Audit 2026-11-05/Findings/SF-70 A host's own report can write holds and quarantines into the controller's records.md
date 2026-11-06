---
id: SF-70
status: open
severity: medium
effort: S
area: Ransomware defense
verified: proven
tags: [finding, audit-2026-11-05]
found: 2026-11-05
---
# SF-70 A host's own report can write holds and quarantines into the controller's records

**Medium** · S · Ransomware defense · Proven · part of [[Audit 2026-11-05]]

## What exists
The module header of `security.py` makes two promises: "A row means it happened. A hold, a quarantine or a decoy is recorded after a signed run on the host has confirmed it", and "nothing a host reports releases a hold, disarms anything or clears an alert". A sentinel reports with a per-host bearer token to `POST /api/security/report`, and the lines it sends become events. One kind of event, `brake_ran`, is also parsed for output lines.

## Evidence
`security.py:55` lists `brake_ran` in `HOST_EVENTS`, so `parse_event_line` accepts it from a report. `ingest_events` then calls `_record_brake_output(conn, host, ev['detail'], 'sentinel', ...)` (`:193-194`). That function (`:198-207`) takes any line `QUARANTINED <\S+>` or `HELD (zfs|btrfs) <b64> <b64>` out of the host-written text and inserts rows:
- into `security_quarantine`, with no check that the text is an address (`clean_target` is never called);
- into `security_retention_holds` through `_record_hold(..., legal=True, ...)`, so the row is a legal hold that never expires, and for an existing hold it sets `missing_at = NULL` and `verified_at = now`.

I ran it (`/tmp/sfaudit/b/p3.py`, a throwaway SQLite database, synthetic names). One `brake_ran` line in a report with a token's host:
- turned a hold that a measurement had marked `missing_at` back to verified (the `hold_missing` alarm state cleared by the host itself);
- created a quarantine row whose address was a 300-character string;
- created two legal holds for snapshots that no signed run ever made, one named `<img src=x onerror=alert(1)>`;
- with only that report and no signed run, `security._check(..., 'worm', ...)` returned `('pass', 'tank/never@made')`, so the compliance control "A verified hold of the required length" passes.

## Why it matters
The module exists because a compromised host lies. This path lets the lying host report protection it does not have (a hold that is not there, a verified WORM control), and it hides its own `hold_missing` state, which is the sign that someone with root has been at the snapshots. The posture, the compliance score, the blast-radius RPO and the evidence document, which is signed, all read these rows. The token is a host credential, so the attacker is root on that host, which is the threat the page is written for. The text of fake snapshot names is shown in the UI (DOM APIs, so not markup), and fake legal-hold rows cannot be removed by the host but also give an admin "release" requests against names that do not exist.

## Suggested approach
Do not parse `brake_ran` detail for rows when the event came in by `report` or `scan`. Rows from brake output should come only from a signed run (`security.brake`, playbooks), which already calls `_record_brake_output` with the run's own output. If the sentinel's own brake output must be learned, make it a request to measure (the next signed measurement reads the table and holds). Validate whatever is parsed: `clean_target` for addresses, `ZFS_SNAP_RE` or `clean_path` for snapshots, `TAG_RE` for tags. Never clear `missing_at` outside a signed measurement.

## Done when
- [ ] A report carrying `QUARANTINED` or `HELD` lines in a `brake_ran` event writes no row
- [ ] A test posts that report with a valid token and checks the three tables are unchanged, including a hold marked missing
- [ ] Rows from `security.brake` (signed run) still arrive, with their values checked
