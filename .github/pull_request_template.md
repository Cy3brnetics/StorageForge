## What this changes

<!-- What it does and why. Link the issue it closes, if there is one: Closes #123 -->

## How it was tested

<!-- The tests you added or ran, and whether it touched real hosts or only stand-ins (and which distros or devices). -->

## Checklist

- [ ] Tests pass: `cd storageforge-indexer && python -m unittest discover -s tests` (and on PostgreSQL if it touches the database)
- [ ] `ruff check storageforge_index tests` is clean
- [ ] A generated script only reports with no flags, and anything that destroys data needs `--destructive`
- [ ] Values reach Bash as data (`shlex.quote`), never as code
- [ ] A new table is in `backup.ESSENTIAL` or `backup.REBUILDABLE`, for SQLite and PostgreSQL
- [ ] UI text reaches the page through DOM APIs only, never as markup
- [ ] The docs and the changelog's *Unreleased* say what changed
- [ ] No passwords, keys, tokens or real host names in the code, tests or this description

See [CONTRIBUTING.md](../CONTRIBUTING.md) for the rules every change follows.
