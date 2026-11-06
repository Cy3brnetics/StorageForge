---
tags: [moc]
---
# StorageForge notebook

Working notes for the StorageForge indexer. Start with the latest audit, then the roadmap.

- [[Audit 2026-11-05]]: the newest audit, partial: network devices, host logs and the network language since `d78881b`
- [[Audit 2026-11-03]]: the audit before it, unsigned scripts and auth on new routes since `31fc091`
- [[Audit 2026-11-01]]: remote nodes, snapshot engine, and site isolation since `7855063`
- [[Audit 2026-10-31]]: security and new features since `68a6d73`
- [[Audit rules]]: how every audit is run, and where the next one starts
- [[Review of Gemini audit 2026-10-29]]: each GM finding checked against the code, with revised severities and what to fix first
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
- `security-audit-2026-10-28.md`: security audit, SF-01 to SF-22
- `docs/audit-2026-10-29.md`: consistency audit (code vs docs vs README)
- `docs/`: user documentation

## Conventions
- One note per finding in `Findings/`, named `PF-nn` (partial feature or feature gap) or `EQ-nn` (engineering quality).
- Frontmatter: `status` (open, in-progress, done, wontfix), `severity` (high, medium, low), `effort` (S under a day, M a few days, L a week or more), `area`.
- New findings: use the `Finding` template (Templates core plugin).
- When something is fixed, set `status: done` and add the commit hash under **Done when**.
