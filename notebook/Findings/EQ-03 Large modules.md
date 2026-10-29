---
id: EQ-03
status: open
severity: low
effort: L
area: "[[Operations and engineering]]"
tags: [finding, refactor]
found: 2026-10-29
---
# EQ-03 Large modules

Not urgent; worth doing before the next big feature lands in these files.

- `server.py`, 1312 lines: every route is defined inside one `create_app()` closure, sharing `conn()`, `actor()` and decorators by closure. Splitting by area into Flask blueprints (`auth`, `index`, `plans`, `deploy`, `admin`) makes each reviewable and lets the role decorator in [[PF-09 Accounts are CLI-only and have no roles|PF-09]] be applied per blueprint.
- `changes.py` (1031), `payloads.py` (900), `tasks.py` (842), `moves.py` (771): generated Bash lives in Python string constants. Moving each script body to `storageforge_index/scripts/*.sh` (loaded with `importlib.resources`) lets `shellcheck` run over them in CI. The risky code in this app is the Bash, and it currently gets no linter.
- No lint configuration in `pyproject.toml`; the 10-27 audit ran ruff by hand. Add a `[tool.ruff]` section with the rule set used then.
- `pyproject.toml` lists `pyyaml` both as a core dependency and as the `yaml` extra; drop the extra.

## Done when
- [ ] `shellcheck` runs over every generated script template in CI
