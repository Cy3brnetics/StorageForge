---
id: PF-15
status: open
severity: low
effort: S
area: "[[Plans and the planner]]"
tags: [finding, carried-over, qol]
found: 2026-10-29
---
# PF-15 Moves and Git QoL

U7 and U8 from the 10-27 audit, still open.

- **Moves** (`moves.js`): buttons are add/reorder/remove step, Check, Download, Deploy, Delete. No **Duplicate**, no rename in place, no **Export JSON** to pair with the CLI's `moves import`.
- **Git** (`gitview.js`): one "Archive to…" per repository. No bulk "archive every single-copy repo to…", and the noise list (`gitrepos.py:20 NOISE`) is fixed in code, so cache and build repos can't be hidden or un-hidden per host.

## Suggested approach
- `POST /api/moves/<id>/copy` and a JSON download link (the plan body is already JSON).
- A `git_ignore` setting (list of path fragments, global and per host) merged with `NOISE`; a checkbox column plus "Archive selected to…" that builds one move plan with one git step per repo.
