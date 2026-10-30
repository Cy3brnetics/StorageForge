---
id: GM-08
status: open
severity: high
effort: S
area: "[[Deployment, Runner and Scripts]]"
tags: [finding, security, logic, tasks, moves, remote, gemini-audit]
found: 2026-10-29
---
# GM-08 Leading-hyphen hostnames allow rsync and ssh option injection in tasks and remote

## Location
- `storageforge_index/tasks.py:29, 158, 222, 458-467, 533-538, 723`
- `storageforge_index/moves.py:34, 506, 519`
- `storageforge_index/remote.py:65, 136-157, 191, 200`

## Mechanics & Root Cause
1. **`tasks.py` `HOST_RE` Permits Leading Hyphens**:
   Unlike `scriptkit.host_name()` and `keyinstall.validate()`, which explicitly check `not h.startswith('-')`, `tasks.py:29` defines:
   ```python
   HOST_RE = re.compile(r'([A-Za-z0-9._-]{1,32}@)?[A-Za-z0-9.:_\[\]-]{1,253}')
   ```
   A `src_host` or `dst_host` beginning with `-` (e.g. `-e...` or `-f...`) passes `HOST_RE.fullmatch(v)` (`tasks.py:158, 222`). In `tasks.py:467, 533-538`, `rsync_side()` formats `q(f'{login}:{p}')` and passes it to `rs ... {src} {dst}` without `--` before the positional arguments, so `rsync` interprets a leading-hyphen `src` or `dst` as a command-line option (such as `-e` to execute an arbitrary shell command).
2. **Broken IPv6 `/dev/tcp` Check in `tasks.py:723`**:
   `HOST_RE` allows bracketed IPv6 literals (`[fe80::1]`), which are passed into `reach() { timeout 5 bash -c "</dev/tcp/$1/$2" 2>/dev/null; }`. Bash's `/dev/tcp/<host>/<port>` syntax does not strip `[` `]`, so IPv6 reachability checks always fail.
3. **`remote.py` Missing `--` and Leading-Hyphen Validation**:
   `Transport` (`remote.py:157, 191`) passes `self.target` to `ssh` without `--` and without validating that `self.host` / `self.user` do not begin with `-`. Similarly, `ssh-keygen -F` (`remote.py:65`) and `ssh-keygen -R` (`cli.py:433`) do not pass `--` before the hostname.

## Impact
Option injection into `rsync` / `ssh` via leading-hyphen host or login specifications in task scripts and CLI invocations; failed pre-flight TCP checks for IPv6 hosts in `tasks.py`.

## Remediation
1. In `tasks.py`, reject any `host` parameter where the string or the hostname part after `@` starts with `-` (and strip `[]` in `reach()`).
2. Pass `--` before positional `src`/`dst` arguments in `tasks.py` and `moves.py`, and before `self.target` in `remote.py`.
3. Validate `host` and `user` in `Transport.__post_init__`.

## Done when
- [ ] `tasks.py` and `remote.py` reject leading-hyphen host/user values and pass `--` before positional arguments.
