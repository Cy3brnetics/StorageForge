---
id: GM-22
status: open
severity: medium
effort: S
area: "[[Deployment, Runner and Scripts]]"
tags: [finding, logic, restore, jobs, deploy, gemini-audit]
found: 2026-10-29
---
# GM-22 Restore drops pack error output, lacks runner lock in deploy.raw, and leaves empty directories

## Location
- `storageforge_index/jobs.py:475-496` (`restore()`)
- `storageforge_index/deploy.py:421-466` (`raw()`)
- `storageforge_index/jobscript.py:338-351` (`unpack()`)

## Mechanics & Root Cause
In `jobs.py:488-496`, `restore()` handles both same-host (`j['runner'] == j['source']`) and cross-host (`j['runner'] != j['source']`) snapshot restores:
```python
if j['runner'] == j['source']:
    res = deploy.run(db, j['runner'], f'set -o pipefail\n{deploy.JOBBIN} pack {jid} {q(snapshot)} {q(rel)} 2>/dev/null | '
                                      f'{deploy.JOBBIN} unpack {jid} {q(target)}', kind='restore', ref=jid, mode='apply',
                     actor=actor, group_id=gid)
else:
    with deploy.raw(db, j['runner'], pack, kind='restore-pack', ref=jid, actor=actor, group_id=gid) as p:
        res = deploy.run(db, j['source'], unpack, kind='restore', ref=jid, mode='apply', actor=actor, group_id=gid,
                         data=iter(lambda: p.stdout.read(1 << 16), b''), timeout=6 * 3600)
return {**res, 'target': target, 'parent': parent}
```
1. **`pack` Error Output Discarded in Both Modes (`jobs.py:489, 493-496`)**:
   - In same-host mode (`line 489`), `pack ... 2>/dev/null` explicitly redirects `pack`'s `stderr` to `/dev/null` (because `pack` prints the byte count on `stderr` at `jobscript.py:335`), which also silences any `die "..."` error message from `pack`!
   - In cross-host mode (`lines 493-496`), `deploy.raw()` (`deploy.py:448, 464`) captures `p.stderr` into a separate `restore-pack` `deploy_runs` row, and `jobs.restore()` returns only `res` (the `unpack` run from `j['source']`). When `pack` fails on the runner host, `p.stdout` closes with 0 bytes, and `tar -C "$t" -xpf -` on the source host exits `0` on empty tar input (or fails with a generic EOF error), without surfacing `pack`'s failure or `stderr` in `res`.
2. **Empty `.restored-<ts>` Directory Left on Source Host (`jobscript.py:342-350`)**:
   - In `jobscript.py:342`, `unpack()` runs `mkdir -p -- "$t" || return` before `tar -C "$t" -xpf -`. When `pack` fails before writing any archive entries, the empty directory `$t` is left behind on the source host (and if GNU `tar` exits `0` on an empty stream in cross-host mode, `unpack()` even prints `"restored into $t"`!).
3. **No Per-Host Lock in `deploy.raw()` (`deploy.py:421-466`)**:
   - Unlike `deploy.run()` (`deploy.py:354`, `with _lock(name), Vault(db, conn).unlock() as v:`), `deploy.raw()` (`deploy.py:438`) does not acquire `_lock(name)`, allowing concurrent deploy/job operations on the runner host.

## Impact
Restore failures discard the root-cause error message from `pack`, leave empty `.restored-<timestamp>` directories on the source host (or report false success on empty streams in cross-host mode), and run without per-host locking on the runner.

## Remediation
1. Check `deploy.raw()`'s exit status (`p.returncode != 0`) in `jobs.restore()` and mark `res['status'] = 'failed'` with `pack`'s stderr when `pack` fails; in same-host mode, capture `pack`'s stderr to a temp file and print it if `pack` exits non-zero.
2. In `jobscript.py:unpack`, check that `$t` is non-empty after `tar` (`[[ -n $(ls -A "$t" 2>/dev/null) ]]`) and remove `$t` (`rmdir -- "$t" 2>/dev/null || true`) if extraction failed or wrote nothing.
3. Acquire `_lock(name)` in `deploy.raw()`.

## Done when
- [ ] Failed restores surface `pack`'s error output, clean up empty `$t` directories, and acquire `_lock(name)` in `deploy.raw()`.
