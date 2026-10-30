---
id: GM-14
status: open
severity: high
effort: S
area: "[[Scanner, Database and Analytics]]"
tags: [finding, logic, scanner, btrfs, mounts, gemini-audit]
found: 2026-10-29
---
# GM-14 Scanner skips child Btrfs subvolumes by marking them alias while also pruning them

## Location
- `storageforge_index/scanner.py:101-119` (`plan_mounts()`)
- `storageforge_index/scanner.py:122-146` (`build_jobs()`)

## Mechanics & Root Cause
In `scanner.py:112-118`, `plan_mounts()` checks whether a mount `m` shares its device `majmin` with an earlier `'scan'` mount `prior` whose `fsroot` is an ancestor of `m.fsroot`:
```python
prior = next((p for p in kept.get(m.majmin, []) if is_under(m.fsroot or '/', p.info.fsroot or '/')), None) if m.majmin else None
if prior:
    plans.append(MountPlan(m, 'alias', f'bind of {prior.info.target}', alias_of=prior))
else:
    plan = MountPlan(m, 'scan')
    plans.append(plan)
    kept.setdefault(m.majmin, []).append(plan)
```
Then, in `build_jobs()` (`scanner.py:123, 141-146`):
```python
targets = [p.info.target for p in plans]
scan = [p for p in plans if p.action == 'scan']
...
jobs = []
for i, (plan, root) in enumerate(pairs.values()):
    prune = sorted({t for t in targets if t != root and is_under(t, root)}
                   | {x for x in opts.exclude_paths if x != root and is_under(x, root)})
    jobs.append(ScanJob(i, plan, root, prune))
```
Consider a standard Btrfs layout (such as openSUSE, Fedora, Ubuntu, or Arch with nested subvolumes) where:
- `/` is mounted from `/dev/sda2` (`majmin="0:25"`, `fsroot="/@"`, `target="/"`) -> `action='scan'`, `kept["0:25"] = [/]`
- `/home` or `/var/log` is a child Btrfs subvolume on the same filesystem (`majmin="0:25"`, `fsroot="/@/home"` or `"/@/var/log"`, `target="/home"` or `"/var/log"`).
1. Because `is_under('/@/home', '/@')` is `True`, `plan_mounts()` classifies `/home` as `action='alias'` (`bind of /`), so **no `ScanJob` is created for `/home`**.
2. Next, in `build_jobs()`, `targets` includes **all** mounts in `plans` (including `'alias'` mounts!). When building the `ScanJob` for `root="/"`, `prune` includes every `t in targets` under `/`, which **adds `/home` to the `-prune` list of `/`'s `find` command**!
3. Even if `find` on `/` did not `-xdev` across subvolume boundaries, `-path /home -prune` explicitly instructs `find` on `/` to skip `/home`—while `plan_mounts()` skipped creating a job for `/home` because it assumed `/` would index it!

Additionally, in `scanner.py:261-273` (`checksum_pass()`), `StderrTail(proc.stderr)` is instantiated without saving the reference or calling `.join()`, and `proc.stderr.close()` is never called, leaking the pipe file descriptor.

## Impact
Child Btrfs subvolumes (or bind mounts mounted inside their parent mount at the exact path where those files reside) are both pruned from the parent mount's `find` walk and skipped as `'alias'` jobs, causing their files to be **completely omitted from the index**.

## Remediation
1. Only classify a mount `m` as `'alias'` if its `fsroot` is reachable at a *different*, non-pruned path under `prior.info.target` (and note that on Btrfs, separate subvolumes have distinct device numbers in `stat(2)` so `find -xdev` on the parent will not descend into a child subvolume anyway—nested Btrfs subvolumes must be scanned as their own mount or not pruned).
2. In `checksum_pass()`, assign `err = StderrTail(proc.stderr)`, call `err.join(5)`, and close `proc.stderr`.

## Done when
- [ ] Nested Btrfs subvolumes mounted under `/` (e.g. `/home`, `/srv`, `/var/log`) are indexed rather than simultaneously aliased and pruned.
- [ ] `checksum_pass` closes `proc.stderr`.
