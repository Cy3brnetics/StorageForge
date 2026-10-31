# Contributing

## Set up and test

```bash
cd storageforge-indexer
python3 -m venv .venv && .venv/bin/pip install -e ".[postgres]"
.venv/bin/python -m unittest discover -s tests
```

Without the install, every test that needs Flask errors with `ModuleNotFoundError`, so a bare `python3 -m unittest` says little. To run the suite on PostgreSQL as well, see [Operations](docs/operations.md#tests). CI runs both databases, plus ruff and shellcheck, from `.gitea/workflows/ci.yml`.

## Rules every change follows

[Concepts](docs/concepts.md) has the full list. The ones that catch people out:

- **Scripts look before they act.** With no flags a generated script only reports. Reruns are safe, and anything that destroys data also needs `--destructive`.
- **Values reach Bash as data.** Quote with `shlex.quote` in Python. `test_no_generator_lets_a_value_run_as_code` runs every task type with hostile values, so a new field kind must be added there.
- **Every table is in a backup list.** A migration adds its table to `backup.ESSENTIAL` or `backup.REBUILDABLE`, for both SQLite and PostgreSQL.
- **New scripts bring tests.** Commands that need root or a real pool are tested against stand-ins: see `tests/test_storage_ops.py`.

## Adding a filesystem operation

Change plan tasks (one-off, in order) live in `changes.py`: add the type to `TYPES`, its title, its checks in `_check_task`, its `ARGS`, a `t_<name>` Bash function, and an Ansible step. Storage task blocks (repeatable, on a timer) live in `tasks.py`. The web forms are built from `TYPES`, so most operations need no JavaScript.
