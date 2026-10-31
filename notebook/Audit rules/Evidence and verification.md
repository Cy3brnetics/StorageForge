---
tags: [audit-rules]
---
# Evidence and verification

A finding is only as good as what backs it. The review of the Gemini audit found quoted code that wasn't in the repo, inflated severities and a suggested fix that doesn't work. So:

## Labels
Every finding carries one, in `verified` in its frontmatter:
- **proven:** you reproduced the behaviour and recorded the result.
- **read:** you traced it through the code but didn't run it. Say why, and what remains unknown.

Don't write *confirmed* for something only read. If only part of a finding is proven, say which part.

## Rules
- Every high or critical needs a proof when one is possible. If none is, say what would prove it.
- Quote the file and line from the code as it is today. Never reuse a quote from another audit or tool without opening the file.
- Include a control when it helps: the older route that refuses, next to the new route that allows.
- Test the fix you suggest, where you can, or mark it untested. Options have to exist: check `--help`.
- Say what wasn't run, on the audit's first page.
- Severity comes from [[Severity and status]], not from how a tool scored it.
- Tools and other auditors produce leads, not findings. Scanner results need a reachability decision before they count.

## How to prove safely
- A throwaway SQLite database in a temp folder, with Flask's `test_client`.
- Build accounts with `users.create`, and age the password with `session_transaction` (`s['auth_at'] = 0`).
- For behaviour on a host, use the KVM lab (`docs/kvm-lab.md`) or a local throwaway folder. Never a real host.
- Harmless payloads only: write a marker file in your own temp folder.
- Keep proof scripts out of the repo. Record what they showed in the finding, and add the good ones as regression tests when the fix lands.
- Don't leave the repo dirty: `git status` before and after.
