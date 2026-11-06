---
id: SF-73
status: done
severity: medium
effort: S
area: Ransomware defense
verified: proven
tags: [finding, audit-2026-11-05]
found: 2026-11-05
---
# SF-73 A host with a report token can fill the controller's database

**Medium** · S · Ransomware defense · Proven · part of [[Audit 2026-11-05]]

## What exists
`POST /api/security/report` takes event lines from a sentinel, with a bearer token and no session. Each new event is a row in `security_events`.

## Evidence
`server.py:201` gives this route a 512 KiB body (`MAX_REPORT`), `routes_security.py:55-65` allows up to 100 lines per request and 120 requests a minute per address (in-memory limiter). `record_event` stores `detail` up to 8,000 characters and dedupes on a uuid the host chooses, so every line can be new. `security.tick` prunes only `severity = 'info'` rows older than 90 days (`security.py:811`); `canary_tripped`, `brake_ran`, `clock_jump`, `watcher_stopped` and the other warn and crit kinds are never removed.

Probe (`/tmp/sfaudit/b/p5.py`, throwaway SQLite): 5 requests of 100 `canary_tripped` lines with 8,000-character details wrote 500 rows and 4.4 MB (about 9 KB a row). At the 512 KiB body limit a request holds about 60 such lines, so 120 requests a minute is about 7,000 rows and 60 MB a minute, about 3.5 GB an hour. After a simulated year, the tick's prune left all 500 rows. I did not send the flood through the limiter.

## Why it matters
Any host with a token (any host with the sentinel and a report URL) can run the controller out of disk, which stops the database and the audit log, the thing that every other defense on this page depends on. The host is the party this module assumes can lie. It also fills the alert queue with crit events, which hides a real one. The `(address)` limiter is per source address, so more hosts or addresses multiply it.

## Suggested approach
Cap events per host per hour in `ingest_events` (a few hundred) and drop beyond it with one summary event; cap the `detail` stored for host-sent events well below 8,000 (1 KiB is enough for every kind the sentinel emits); prune warn and crit events that are acknowledged and older than a year, or all events beyond a row count per host. Rate limit by token as well as by address.

## Done when
- [x] A host's report beyond the cap writes no more rows, and the cap is visible in the response
- [x] A test posts 10,000 distinct lines with a valid token and checks the table size is bounded
- [x] Old acknowledged events are pruned

## Fixed
2026-11-06, in `1e528bb`. At most 300 events an hour per host and 100 of any one kind, detail cut at 2048 characters, an `events_dropped` warning once an hour, acknowledged events older than a year pruned and the newest 5000 per host kept. No per-token rate limiter was added. Unit-tested, with the test seen to fail on the old code. Not lab-tested.
