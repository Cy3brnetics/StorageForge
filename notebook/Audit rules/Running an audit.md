---
tags: [audit-rules]
---
# Running an audit

## 1. Fix the scope
Read the newest row in [[Audit history]]. That commit is the baseline.

```bash
git log --oneline <baseline>..HEAD
git diff --stat <baseline> HEAD
git status --short
```

Write these in the audit's first note: baseline, head, and whether the uncommitted tree is included. Include it by default.

A scanner report isn't a code audit, and doesn't move the baseline.

## 2. Map what changed
- New or changed routes: `server.py`, and the URL map at run time
- New or changed scripts that run on hosts: anything writing Bash, Ansible, cron or systemd
- New tables and migrations, on both databases
- New permissions, or changed rules in `permissions.py`
- New browser code that shows data from hosts
- New anything that listens, stores a token or takes a path

Spend time by risk, in this order: runs on a host or the server > handles credentials > decides permissions > takes data from hosts > everything else.

## 3. Run the baseline tools
Use a virtual environment outside the repo, so an audit leaves the tree clean.

```bash
python3 -m venv "$SCRATCH/venv" && "$SCRATCH/venv/bin/pip" install -e storageforge-indexer ruff bandit
cd storageforge-indexer && "$SCRATCH/venv/bin/python" -m unittest discover -s tests
"$SCRATCH/venv/bin/bandit" -q -r storageforge_index -ll
```

Record the test count and result. Run PostgreSQL and the KVM lab when the change touches SQL or host behaviour, and if you can't, say so in the audit.

## 4. Read and check
Go through the [[Security checklist]] for each route and generator, then the [[Feature and design checklist]] for each feature. Read new code in full. Say plainly in the audit what was read in full, read in part and not read.

Compare the new path with an older one doing the same job. Most bugs in the 2026-10-31 audit were protections an older path had and the new path left out.

## 5. Prove it
For each high or critical candidate, write a small script. See [[Evidence and verification]].

## 6. Write it up
Follow [[Note format]]. Say what was done well too, so fixes don't remove it.

## 7. Close
- Add a row to [[Audit history]]
- Link the audit from `Home`
- Add a rule here for any class of bug that a rule would have caught
- Check that `git status` shows only new notes
