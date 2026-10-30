---
id: GM-03
status: open
severity: high
effort: S
area: "[[Deployment, Runner and Scripts]]"
tags: [finding, logic, deploy, tasks, systemd, gemini-audit]
found: 2026-10-29
---
# GM-03 Deployed tasks fail under systemd with 203 EXEC due to missing shebang

## Location
- `storageforge_index/deploy.py:159-162, 360` (`RUNNER_UPDATE`, `run()`)
- `storageforge_index/tasks.py:779, 788` (`install_units()`)

## Mechanics & Root Cause
When `deploy.run()` deploys a script to a remote host (`deploy.py:360`), it prepends `RUNNER_UPDATE` to the script payload:
```python
# deploy.py:159-162
RUNNER_UPDATE = ('if ((EUID == 0)); then _sf_new=$(mktemp) && cat >"$_sf_new" <<\'STORAGEFORGE_RUNNER_UPDATE\'\n'
                 + RUNNER_SCRIPT + 'STORAGEFORGE_RUNNER_UPDATE\n'
                 f'cmp -s "$_sf_new" {RUNNER} || install -o root -g root -m 0755 "$_sf_new" {RUNNER}\n'
                 'rm -f "$_sf_new"; unset _sf_new; fi >/dev/null 2>&1\n')

# deploy.py:360
req = request(_signer(v), name, RUNNER_UPDATE + script, args, machine=_machine(conn, name))
```
1. `RUNNER_UPDATE` begins with `if ((EUID == 0)); then` rather than `#!/usr/bin/env bash`. The original `#!/usr/bin/env bash` shebang of `script` is pushed down to line 69 of `$work/script`.
2. During the initial deploy, `storageforge-run` runs `bash "$work/script" "${args[@]}"` (`deploy.py:124`), which succeeds because `bash` is invoked explicitly.
3. However, `tasks.py:779` installs the task script by copying `$0` (`$work/script`) verbatim:
   ```bash
   install -D -m 0750 "$0" "$LIB/$TASK.sh"
   ```
   and writes `/etc/systemd/system/$UNIT.service` (`tasks.py:788`) with:
   ```ini
   ExecStart=$LIB/$TASK.sh --run
   ```
4. Because `/usr/local/lib/storageforge/tasks/$TASK.sh` starts with `if ((EUID == 0)); then` instead of `#!`, when `systemd` starts the service or timer, the kernel's `execve()` returns `ENOEXEC` (`Exec format error`), and `systemd` fails the service with `status=203/EXEC`.
5. Furthermore, even if a shebang were present, copying `$0` means every scheduled task execution re-runs `RUNNER_UPDATE` on every timer tick.

## Impact
**Every scheduled Storage Task (`tasks.py`) deployed through the UI or `deploy` API fails to execute when triggered by its systemd timer or `systemctl start`.**

## Remediation
1. Start `RUNNER_UPDATE` with `#!/usr/bin/env bash\n` so `$work/script` always has a valid shebang on line 1.
2. In `tasks.py:779`, strip the `RUNNER_UPDATE` block when installing `$0` to `$LIB/$TASK.sh` (or invoke `ExecStart=/usr/bin/env bash $LIB/$TASK.sh --run`).

## Done when
- [ ] `RUNNER_UPDATE` begins with `#!/usr/bin/env bash`.
- [ ] Installed task scripts in `/usr/local/lib/storageforge/tasks/` start with `#!/usr/bin/env bash` and execute cleanly under `systemd`.
