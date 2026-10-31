---
id: PF-06
status: in-progress
severity: medium
effort: S
area: "[[Plans and the planner]]"
tags: [finding, partial, roadmap]
found: 2026-10-29
---
# PF-06 Move progress from scans

Roadmap item #1 from the 10-27 audit. **Half done.**

## What exists
- Deployed move jobs report each run, so the Deploy tab knows their state.
- The downloadable move script writes `/var/lib/storageforge/moves/<plan>/<step>.done` and `<step>.cutover` on the host (`moves.py:502,553,595,630`).

## What is missing
Scans read `/var/lib/storageforge/jobs/*/runs.jsonl` and `managed/*` (`remote.py:267-269`) but not `moves/`. A plan run by hand with the downloaded script, which is the path the Moves tab offers first ("Download script"), never shows progress in the UI.

## Suggested approach
1. Add one line to the scan script: `echo '@@moves'; for f in /var/lib/storageforge/moves/*/*; do [ -r "$f" ] && printf '%s\t%s\n' "$f" "$(head -c 200 "$f")"; done`.
2. Store per host in the inventory JSON; in `GET /api/moves/<id>` attach `progress[step] = {copied, cutover}` matched by plan slug.
3. Show "copied 2026-10-27 · cut over 2026-10-28" on each step in `moves.js`.

## Done when
- [ ] Running a move script by hand, then rescanning, shows the step as copied

## Progress 2026-10-30
Scans read `moves/`, and steps show "copied" and "cut over". Not yet checked with a move script run on a real host.
