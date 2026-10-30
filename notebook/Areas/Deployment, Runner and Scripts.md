---
tags: [area, gemini-audit]
---
# Deployment, Runner and Scripts

Signed remote deployment (`deploy.py`), on-host runner (`storageforge-run`, `storageforge-apply`), backup/snapshot/restore jobs (`jobs.py`, `jobscript.py`), and Bash script generators (`scriptkit.py`, `moves.py`, `changes.py`, `shares.py`, `tasks.py`).

## Findings
- [[GM-01 Restore unpack as root allows device nodes and TOCTOU]] (**Critical**)
- [[GM-02 Remote command injection in scriptkit host relay]] (High)
- [[GM-03 Deployed tasks fail under systemd with 203 EXEC due to missing shebang]] (High)
- [[GM-08 Leading-hyphen hostnames allow rsync and ssh option injection in tasks and remote]] (High)
- [[GM-09 Change plan perms task clobbers descendant groups and follows symlinks as root]] (High)
- [[GM-10 Four broken code paths in jobscript backup and snapshot execution]] (High)
- [[GM-21 Move plan verify_step ignores rsync exit code and shares fstab preservation triggers false drift]] (Medium)
- [[GM-22 Cross-host restore drops pack error output, lacks runner lock, and leaves empty directories]] (Medium)

Back to [[Home]]
