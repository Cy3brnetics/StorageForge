---
tags: [area, gemini-audit]
---
# Plans, Planner and UI

Frontend JavaScript (`static/app.js`, `static/planner.js`, `static/plans.js`, `static/shares.js`, `static/tasks.js`, `static/deploy.js`, `static/checks.js`, `static/picker.js`), blueprint serialization (`blueprint.py`), and design-to-change-plan staging (`fromdesign.py`).

## Findings
- [[GM-07 Planner scrub is a no-op and innerHTML sinks lack escaping]] (High)
- [[GM-09 Change plan perms task clobbers descendant groups and follows symlinks as root]] (High)
- [[GM-21 Move plan verify_step ignores rsync exit code and shares fstab preservation triggers false drift]] (Medium)

Back to [[Home]]
