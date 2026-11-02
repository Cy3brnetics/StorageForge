# Code audit, 2026-11-01 (bugs)

A read of the indexer's code looking for bugs, done after the [feature audit of the same day](audit-2026-11-01-features.md). Unlike the [2026-10-29 consistency audit](audit-2026-10-29.md) it compares the code with itself, not with the docs: logic that cannot do what it means to, permission rules that disagree with each other, and failure paths that leave things broken.

**Scope.** Branch `claude/project-audit-0f70ed` at `d00b287`. Read in full: `db.py`, `vault.py`, `scheduler.py`, `jobs.py`, `server.py`, `users.py`, `permissions.py`, `routes_accounts.py`, `routes_scheduler.py`, `changes.py`, `moves.py` (first third), `alerts.py`, `capacity.py`, `search.py`, `logbook.py`, `backup.py`, `deploy.py`, `engine.py`, `remote.py`, `runner.py`, `scanner.py`, and the task-shaped parts of `tasks.py` and `cli.py`. Skimmed or not read: `shares.py`, `payloads.py`, `gitrepos.py`, `docker.py`, `graph.py`/`canvas.py`, `filemap.py`/`folders.py`/`fsmap.py`, `hostconfig.py`/`reinstall.py`, `snapjobs.py`/`snapfind.py`, `remotes.py`, `reset.py`/`retire.py`, `health.py`, `analysis.py`, `preflight.py`, `protection.py`, `blueprint.py`/`fromdesign.py`, the generated-Bash bodies of `jobscript.py`/`schedscript.py`, and all of the web UI's JavaScript. Findings there would not have been seen.

**Tests.** `pytest tests --ignore=tests/lab`: 561 passed, 8 skipped, 43 subtests passed. (`tests/lab` needs the KVM rig and was not run.) `ruff` with the bug-finding rule sets (F, B, PLE, PLW) reports nothing real: every B023 closure-capture warning is a closure used inside its own iteration.

## Summary

| # | Area | Finding | Severity |
| :--- | :--- | :--- | :--- |
| B1 | Search | `*.tar.gz` (any two-dot pattern) silently matches nothing | **Medium**, fixed |
| B2 | Scheduler | A failed **Run now** leaves the schedule unable to report | Medium–low, fixed |
| B3 | Permissions | The schedule mask (`••••••`) is bypassed by the script download routes | Low, fixed |
| B4 | Change scripts | The `/tmp` lock-file fallback follows symlinks as root | Low, fixed |
| B5 | Scheduler API | `verify` accepts a `run_id` belonging to another schedule | Low, fixed |
| B6 | Scans | Checksums of files with non-UTF-8 names are silently dropped | Low, fixed |
| B7 | Jobs | A calendar expression `period()` cannot parse breaks `/api/deploy` | Low, fixed |
| N1–N4 | Various | Unbounded in-memory sets, cache wipe, pagination under-fill | Cosmetic, fixed |

## B1. A search for `*.tar.gz` finds nothing

`search.classify()` treats any `*.<something>` pattern as an extension lookup:

```python
EXT_RE = re.compile(r'^\*\.([^*?\[\]/]+)$')      # search.py
```

so `*.tar.gz` becomes `WHERE f.extension = 'tar.gz'`. But `stream.extension()` stores only the text after the **last** dot (`gz` for `backup.tar.gz`). The query is valid, runs fast, and returns zero rows — in the web UI, the API and the CLI alike. `*.gz` works, `*tar.gz` works (glob path), `*.tar.gz` does not, with no hint why. Verified by running `classify('*.tar.gz')` → `('ext', 'tar.gz')` against `extension('backup.tar.gz', False)` → `'gz'`.

**Fixed.** The fast path now applies only to what `stream.extension()` could have stored. That also covers two cases this audit missed: suffixes with a space and suffixes over 16 characters, which `extension()` stores as empty. Everything else goes to the glob branch. Left as it is: `*.env` does not match a file named exactly `.env`, which has no extension. A shell glob doesn't match it either.

## B2. A failed "Run now" breaks a schedule's direct reporting

`scheduler.deploy_items(run_now=True)` rotates the report token **before** anything reaches the host:

```python
elif run_now:
    token = token_for_schedule(conn, sid, actor)   # updates auth_token_hash now
```

That is deliberate for the success path — the run reports *during* the deploy, with the new token the script just wrote. But when the deploy fails (host down, SSH refused, script error), the database now only accepts the new token while the host still holds the old one. Every later timer-fired report answers 401 until someone deploys the schedule again; runs are then only picked up by scans, and nothing says why. The ordinary apply path avoids exactly this with its `promote`-on-success pattern.

**Fixed**, though not as this audit first suggested. Restoring the old hash in an `on_fail` hook would be wrong: the install writes the token before the task runs, so a task that exits non-zero fails the deploy while the host already holds the new token. The server can't tell the two cases apart. A new `pending_token_hash` (migration 029) is accepted beside the current hash, and becomes the current one when the host reports with it or the deploy ends well. Rotating the token clears it. The ordinary apply path had the same gap when it failed after writing the token, and now shares this. One gap remains: if a failed deploy did reach the host and a later one never does, the host holds a token that is no longer accepted until the next deploy.

## B3. The schedule mask is bypassed by the script downloads

`routes_scheduler.schedule_view()` masks a command schedule's `task_ref` and env values for accounts without `plans.edit`, because "commands and env values can hold secrets". But three GET routes return the same material unmasked, and the permission rule

```python
(READ, r'/api/.*/(script|ansible|install-script|cron|bundle)', 'plans.scripts'),
```

gates them on `plans.scripts` only. `/api/scheduler/schedules/<id>/script` returns the raw command inline; `/install-script` additionally embeds the env values and `info 'runs: <command>'`. So a custom role holding `plans.view` + `plans.scripts` but not `plans.edit` reads everything the mask hides. No built-in role is affected (viewer lacks `plans.scripts`; operator has `plans.edit`), so this needs a custom role to matter.

**Fixed.** Both routes now also require `plans.edit` for command schedules, and the UI hides the links. Other schedule types keep `plans.scripts` alone, since nothing in them is masked. Not changed: a dry run prints the command on purpose (`runs: …`), so a `deploy.report` holder can still start one and read it, and `deploy.view` can read that run's output. The code treats this as the approver reading what they approve. A role that must not see commands should not hold those permissions.

## B4. The change-plan lock falls back to a predictable /tmp path

`changes.py` (CHANGE_BODY_3), run as root on hosts:

```bash
exec 9>"/run/lock/sf-changes-$PLAN.lock" 2>/dev/null || exec 9>"/tmp/sf-changes-$PLAN.lock"
```

On a host without `/run/lock`, root opens (and truncates) a predictable name in the world-writable `/tmp`; `>` follows symlinks, so a local user who pre-creates `/tmp/sf-changes-<plan>.lock → /etc/something` gets that file truncated by root. The plan slug is guessable from the plan name. Low severity — it needs a hostile local user and a host without `/run/lock` — but the fix is one line.

**Fixed.** The fallback is now a root-owned folder, `/var/lib/storageforge/locks`. `moves.py` had the same line, which this audit missed. A non-root `--dry-run` of a move on a host without `/run/lock` now stops at the lock instead of using `/tmp`.

## B5. Re-verify takes a run of another schedule

`POST /api/scheduler/schedules/<sid>/verify` with `{"run_id": N}` calls `reverify_run(conn, N)` without checking that run N belongs to schedule `<sid>` (routes_scheduler.py). Any `deploy.report` holder can re-verify any run, and the audit entry names the wrong schedule. Consequences are mild (statuses are recomputed, not forged), but the route's shape promises a binding it does not enforce.

**Fixed.** A run of another schedule now answers 404.

## B6. Checksum results are dropped for non-UTF-8 file names

*Corrected: the cause first written here was wrong.* The symptom is right, but the answer's lookup was never the problem. `stream.decode()` stores a non-UTF-8 byte as the text `\xNN`, and `scanner.checksum_pass()` sent that text to the host as the file name. So `sha256sum` was asked for a file that does not exist, and the checksum was never computed. Confirmed by running `sha256sum` on such a name.

**Fixed.** The bytes are recovered from the stored text. A real name can also contain the text `\xNN`, so both forms are sent: the host hashes whichever exists, and both decode to the same stored path.

## B7. `jobs.period()` can raise on a schedule the validators accept

`moves.CALENDAR_RE` accepts strings like `*-*-* *:5/x:00`; `jobs.period()` then runs `int(mm.split('/')[1])` on `x` and raises `ValueError`. `jobs.overview()` calls `period()` unguarded, and `/api/deploy` turns a `ValueError` into a 400 — so one deployed mirror job with such a schedule would blank the whole Deploy tab. Not confirmed end-to-end (the host-side `systemd-analyze calendar` check flags the bad time at install, but the job row is written regardless). Confirmed by running `period()` on that string.

**Fixed.** `period()` falls back to daily, as `scheduler.period()` already does.

## Nits

All closed.

- **N1** Partly overstated. `breaches` already prunes itself, and `_host_locks` grows only with the number of hosts, so neither changed. `signed_in_from` grows only on successful sign-ins, and it now clears at 10,000 entries, which at worst drops an exemption from the daily limit.
- **N2** `server.remember()` now evicts only the oldest entry.
- **N3** `logbook._hostlog()` filters by outcome in the SQL, before the `LIMIT`.
- **N4** New and edited schedules must have a real window time. Saved rows are not re-checked, so old ones can still be read, hashed and uninstalled.

## Checked and fine

Things specifically looked at because they smelled risky, and found correct:

- `alerts.save_settings()` keeps a stored token only while the channel URL's scheme/host/port are unchanged — the comparison reads the *new* URL against an origin captured before the loop, which works because `url` is processed before `token` in each channel's field tuple.
- `db.apply_diff()`'s scoped-subtree delete, the mass-delete guard, and the FTS maintenance; `db.prune()`'s newest-scan-per-host protection.
- The vault envelope (AAD per row and purpose, rotation, verifier), the audit chain (per-dialect serialization, the advisory lock on PostgreSQL), and `AuditLog.unkeyed()`.
- The SSHSIG request flow end to end: header injection is closed by `ARG_RE`/slug/hex checks, nonces are claimed atomically with `noclobber`, clock skew is bounded both ways, and the runner self-update refuses partial writes.
- `permissions._RULES` route-by-route against `server.py`, `routes_git.py` registrations and `routes_scheduler.py`: first-match order is right everywhere else; job/schedule report routes are correctly reachable without a session (token-gated), and a session without the permission cannot use them cross-site (`Sec-Fetch-Site`/Origin check plus SameSite=Strict).
- Account management: role handout bounds (`may_hand_out`, the role-subset check on `save_role`), last-admin protection, invite/reset single-use claims (atomic UPDATE with rollback), reset-link death on role/password/account change.
- `users.enroll()` race behaviour, `_DUMMY_HASH` timing equalization, per-user/per-network login limits and the `known_network` exemption.
- The alert sender's SSRF guards (resolve-once-and-connect, redirect refusal, loopback/link-local/mapped-IPv4 refusal).
- `backup.create/restore/encrypted/decrypt_file` (chunk counter + last-chunk flag in the AAD; truncation and reordering both fail), and `receive_script`'s remote pruning scope.
- `scheduler.on_calendar()` against `parse_cron()` (both read day-of-month AND day-of-week, documented), `hdparm -S` spin-down encoding in both the Bash and Ansible emitters, and `_remove_block`'s sed escaping.
- `changes.py`'s generated Bash: quoting discipline (`q()` on every interpolated value), fstab backup/verify/rollback, the `owner_mode` symlink refusal, `to-subvolume`'s copy-count check, and the Ansible `!unsafe` tagging that keeps Jinja out of module arguments.
- `engine._work()` phase ordering, cancel/force-cancel paths, and `deploy.run()`'s never-left-running guarantees.

## How this was checked

Static read plus small Python repros for anything claimed as confirmed (B1's was run; B2, B3 are confirmed by reading the single code path involved; B4–B7 are plausible-to-likely but were not exercised against a live host). No code was changed by the audit itself. All findings above were fixed afterwards. B4 to B7 were rechecked first, which is where the B6 correction comes from.
