---
tags: [audit-rules, checklist]
---
# Project invariants

Promises from `docs/concepts.md`, `CONTRIBUTING.md` and `security-parm.md`. Every audit checks that new code still keeps them. A break is a finding even when no attacker is obvious, because people rely on these. If a promise has changed on purpose, the docs must change with it.

| Promise | Quick test |
| :-- | :-- |
| With no flags, a generated script only reports | Run it with no flags: nothing changes |
| Reruns are safe; every step looks before it acts | Run it twice |
| Destructive needs three locks: device typed twice, `--destructive`, device not in use | Try to reach `--destructive` by any route without `deploy.destructive` |
| Values reach Bash as data | The generator is in `test_no_generator_lets_a_value_run_as_code` |
| Nothing is deleted outright: trash, `.migrated-<date>`, backups of fstab | Read the delete paths |
| Every table is in `backup.ESSENTIAL` or `backup.REBUILDABLE`, both databases | `tests/test_consistency.py` |
| Secrets never touch disk in plaintext | Search the new code for tokens and keys being written |
| Commands on hosts need a password typed in the last 5 minutes | Age `auth_at` in the session, then call the route |
| Everything is audited; the log is append-only and chained | Count audit rows before and after; `audit verify` |
| Scan access is read-only | No change is made using a `scan` binding |
| Deploys run only signed scripts through `storageforge-run` | No raw command over the deploy key |
| New `/api` routes are denied until listed | `test_every_route_is_listed` |
| Nobody hands out more than they hold | Try it from a limited custom role |
| Browser code uses DOM APIs for data | Search for `innerHTML` in changed JS |
| New scripts bring tests | Check the test exists, and that it can fail |
| Remote nodes dial in safely: reverse SSH tunnel allows no server shell or unverified forwarding | Check tunnel authorized_keys options: forced command, no-pty, no-agent-forwarding, loopback-only port forward |
| Sites never leak across boundaries: keys, vaults, and configs are strictly site-isolated | Attempt to access another site's keys or data through site-scoped endpoints |
| Generate-only key vaults never expose private keys once written | Request private key download/export from generate-only vault |
| Reset links and invite tokens are single-use, time-bounded, and invalidate sessions on password reset | Use token twice; verify previous session cookies become invalid on reset |
| Sync and snapshot jobs acquire volume locks and run only signed scripts through `storageforge-run` | Attempt concurrent syncs on the same volume; inspect generated job scripts |
