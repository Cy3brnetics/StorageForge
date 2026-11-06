---
id: SF-54
status: done
severity: low
effort: S
area: Source hygiene
verified: proven
tags: [finding, audit-2026-11-05]
found: 2026-11-05
---
# SF-54 Source files hold bidirectional control characters

**Low** · S · Source hygiene · Proven · part of [[Audit 2026-11-05]]

## What exists
`hostlogs.py:75`, the pattern that takes control characters out of a log line, holds U+2028, U+2029, U+202A, U+202E, U+2066 and U+2069 as literal characters, and `tests/test_hostlogs.py` holds U+202E in a test string. They are meant: the code strips them. But the same characters in a source file are how a "Trojan Source" change hides: they reorder what an editor or a review tool shows.

## Evidence
`bandit` rule B613 flagged `hostlogs.py:77`. A scan of every `.py`, `.js`, `.css`, `.html`, `.sql` and `.sh` file under `storageforge_index/` and `tests/` for U+202A to U+202E and U+2066 to U+2069 found these two files and no others. `str.splitlines()` also splits the pattern's line at the literal U+2028 and U+2029, which is how a tool that reads lines gets it wrong.

## Why it matters
Nothing is wrong with what these two lines do. The risk is the next change: a reviewer cannot tell a deliberate character in these files from one that was added to hide something, and a check that forbids them everywhere is simpler than a list of the places they are allowed.

## Suggested approach
Write them as escapes (`\u202a-\u202e`), and add a test that fails when any bidirectional control appears literally in a source file.

## Done when
- [x] No source file holds one, and the pattern's behaviour is unchanged
- [x] A test scans the sources
- [x] The commit is written here

## Fixed
2026-11-05, in `b7c34bd`. The class in `hostlogs.py` and the string in `tests/test_hostlogs.py` write the characters as escapes, and the pattern matches the same set. `tests/test_source_hygiene.py` walks every `.py`, `.js`, `.mjs`, `.css`, `.html`, `.sql`, `.sh`, `.yml`, `.toml` and `.json` file in the repository (not `archive/`, `.git`, `.obsidian`) and fails if one holds U+202A to U+202E or U+2066 to U+2069. It found nothing else. It reads lines with `split('\n')`, because `splitlines()` splits on two of those characters.
