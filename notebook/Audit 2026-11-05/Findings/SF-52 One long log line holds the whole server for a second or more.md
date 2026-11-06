---
id: SF-52
status: open
severity: medium
effort: S
area: Host logs
verified: proven
tags: [finding, audit-2026-11-05]
found: 2026-11-05
---
# SF-52 One long log line holds the whole server for a second or more

**Medium** · S · Host logs · Proven · part of [[Audit 2026-11-05]]

## What exists
Every journal line a scan collects goes through `hostlogs.scrub()` on the controller before it is stored, to take secrets out of it. The first of its patterns starts with `[\w.-]*` in front of a secret word, so on a run of word characters with no secret word in it the engine tries every start position and scans to the end of the run from each: the work grows with the square of the line's length. A line is cut to `MESSAGE_CHARS`, 4000, before this, and a pickup takes up to `LINES_IMPORTANT + LINES_ROUTINE`, 7000 lines.

## Evidence
`hostlogs.py:75-80`, the pattern, and `hostlogs.py:141`, where each message is cut and scrubbed. Timed on this machine with `hostlogs.scrub('a' * n)`:

| n | time |
| --: | --: |
| 500 | 19 ms |
| 1,000 | 48 ms |
| 2,000 | 201 ms |
| 4,000 | 780 ms |

Doubling the line multiplies the time by about four. A line of base64, a hex dump or a long JSON value is such a run, and none needs to be hostile. Python's `re` does not release the GIL while it matches, so the whole server, web requests included, waits for it. At 4,000 characters a pickup of 100 such lines is about 78 seconds, and one of 7,000 about an hour and a half. The probe: `scrub` on the cases `a*4000`, `eyJ` + `a*4000`, `://` + `a*4000` + `:` and `bearer ` + `a*4000` each took 0.74 to 0.81 s. Not run: a real scan of a real host producing these lines, which is the KVM lab.

## Why it matters
A managed host that has been taken over, or one with a noisy daemon, can stall the controller for every user, and a scan of it never finishes. The host logs are the first thing a scan collects from a host that might be hostile. It needs an enrolled host, so it is Medium, not High.

## Suggested approach
Bound the repetitions (`[\w.-]{0,64}` on both sides of the secret word) and skip the secret patterns altogether when a cheap linear check finds none of their words in the line. Then time the worst lines, including ones that are full of secret words, and assert a ceiling in a test. Not yet tried: this approach was only reasoned, so the test decides.

## Done when
- [ ] `scrub` of a 4,000-character run of word characters, and of 4,000 characters made of secret words, each takes under 100 ms
- [ ] A secret with a long prefix (`MYSQL_ROOT_PASSWORD=x`) is still redacted, and every existing scrub test still passes
- [ ] The commit is written here

