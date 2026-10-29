---
id: PF-12
status: open
severity: low
effort: S
area: "[[Plans and the planner]]"
tags: [finding, carried-over]
found: 2026-10-29
---
# PF-12 Storage tasks lag the other plan types

Carried from the consistency audit (P1, P2). Both still open.

- **No CLI.** `plan`, `moves` and `shares` all have `list/check/script` (and `import` where it applies); there is no `tasks` subcommand in `cli.py`.
- **No container warning.** `moves.py:317` and `changes.py:237` call `docker.users_of()` to warn when a step touches a folder a running container uses; `tasks.py` doesn't, so a task mirroring a live database folder gets no warning.

## Suggested approach
Copy the `plan` subcommand's shape (`cli.py:851`) for `tasks list|check|script|import`, and call `users_of` in `tasks.check()` for copy and snapshot blocks.

## Done when
- [ ] `storageforge-index tasks script <id>` works
- [ ] A copy block whose source is a running container's bind mount gets a warning
