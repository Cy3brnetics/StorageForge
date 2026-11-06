---
tags: [audit-rules]
---
# Severity and status

Rate what could happen in the way StorageForge is actually deployed: on a LAN, by a small team, with root on the hosts it manages. Use the highest row that fits, then lower it one step if an unusual precondition is required, and say so.

| Severity | Means | Examples |
| :-- | :-- | :-- |
| **Critical** | Vault, all hosts or the server taken over by someone who shouldn't have that power, or data destroyed with no recovery | Operator runs shell on the server |
| **High** | Root or code execution on a host beyond the account's rights; a protection bypassed; a main feature silently failing; loss of the only backup | Destructive permission bypass; reports refused; orphaned root cron job |
| **Medium** | Secrets exposed to a lesser account; a promise broken with limited impact; a feature wrong in common cases | Viewer reads webhook URL; a setting that does nothing |
| **Low** | Needs an unlikely setup, or is hardening and tidiness | Reset link survives a role change |

Add **Effort**: S under a day, M a few days, L a week or more.

## Status
`open`, `in-progress`, `done`, `wontfix`. For `done`, add the commit under **Done when**. For `wontfix`, add the reason and who decided. A later audit re-checks a sample of `done` findings against the code.

## Numbering
Numbers carry on across audits and are never reused:
- `SF-nn` security (`SF-55` was the last used on 2026-11-05; next starts at `SF-56`)
- `PF-nn` a partial feature, or a feature that should be built differently (`PF-33` on 2026-11-03; next starts at `PF-34`)
- `EQ-nn` engineering quality (`EQ-09` on 2026-11-03; next starts at `EQ-10`)
- `GM-nn` is kept for the Gemini review and isn't extended
