---
tags: [moc]
---
# StorageForge notebook

Working notes for the StorageForge indexer. Start with the latest audit, then the roadmap.

- [[Audit 2026-10-29 - features]]: partially built features and things worth building better
- [[Roadmap]]: the findings in the order to tackle them (also as a canvas: [[Roadmap.canvas]])
- [[Carried over]]: what happened to the items from the 10-27 and 10-29 audits

## Areas
- [[Alerts and monitoring]]
- [[Data protection]]
- [[Hosts, keys and accounts]]
- [[Plans and the planner]]
- [[Reports and exports]]
- [[Operations and engineering]]

## Other records (outside this vault)
These live in the repo and are not linked notes, so open them from the file browser:
- `audit-2026-10-27.md`: QoL, gaps and next features
- `security-audit-2026-10-28.md`: security audit, SF-01 to SF-22
- `docs/audit-2026-10-29.md`: consistency audit (code vs docs vs README)
- `docs/`: user documentation

## Conventions
- One note per finding in `Findings/`, named `PF-nn` (partial feature or feature gap) or `EQ-nn` (engineering quality).
- Frontmatter: `status` (open, in-progress, done, wontfix), `severity` (high, medium, low), `effort` (S under a day, M a few days, L a week or more), `area`.
- New findings: use the `Finding` template (Templates core plugin).
- When something is fixed, set `status: done` and add the commit hash under **Done when**.
