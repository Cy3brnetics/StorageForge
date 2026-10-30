---
date: 2026-10-29
tags: [audit, review, gemini-audit]
reviews: "[[Audit 2026-10-29 - gemini]]"
---
# Review of Gemini audit 2026-10-29

Each of [[Audit 2026-10-29 - gemini|Gemini's]] 25 findings was checked against the current source, not just its own quotes.
**Short version:** the line references are mostly right, and about half of the findings are real bugs. Severity is
inflated across the board (1 Critical / 15 High), several sub-claims are wrong, and two of its "code quotes" are not the code that is in the repo
(GM-04 `install_public_key` args, GM-07 `tidy()`), so don't paste its snippets as evidence without checking them.

## Fix these first

Each of these is confirmed and breaks something real. **Fixed 2026-10-29** (uncommitted), each with a regression test that fails on the old code. The tests are in `tests/test_indexer.py` (`GeneratedBash`, `Planning`) and `tests/test_tasks.py`.

1. [[GM-03 Deployed tasks fail under systemd with 203 EXEC due to missing shebang|GM-03]]: every storage task deployed from the UI installs `$0`, which starts with `RUNNER_UPDATE` (`if ((EUID == 0))…`) and not `#!`. Its `ExecStart=$LIB/$TASK.sh --run` → `203/EXEC`. The tests run the script through `bash`, so they never see it.
2. [[GM-21 Move plan verify_step ignores rsync exit code and shares fstab preservation triggers false drift|GM-21]] part 1: `moves.py` `verify_step` does `out=$("${RS[@]}" | grep … || true)`, and rsync errors go to stderr. A failed rsync (unreachable host, missing source) therefore gives 0 lines and reports **"destination matches the source"**, and `cutover` uses that as its gate. Gemini rated it Medium, but it's **High**. (The `jobscript.py` `verify_job` instance is mostly safe: it uses `2>&1`, so error lines count as differences.)
3. [[GM-10 Four broken code paths in jobscript backup and snapshot execution|GM-10]]: parts 1–3 are confirmed. `snap_path` gives `//.storageforge-snap/<SID>var/lib/…` when the subvolume is `/`. `under x /` tests `//*` and matches nothing. A remote git job with `snapshot` is refused by `serve` because the snapshot path lies outside `ROOT`. Part 4 (rsnapshot rejects `user@host::src/`) is plausible but untested, since rsnapshot isn't installed here. To check it, run `rsnapshot configtest` on a generated config, or switch to `rsync://storageforge-deploy@host/src/`, which `RSYNC_CONNECT_PROG` also covers.
4. [[GM-14 Scanner skips child Btrfs subvolumes by marking them alias while also pruning them|GM-14]]: confirmed for **nested** subvolume layouts (openSUSE `/@/home`). `plan_mounts` marks the mount `alias` because its fsroot is under `/@`, and `build_jobs` adds every target (aliases included) to `/`'s prune list, so `/home` is never indexed and nothing reports it. Flat layouts (`@`, `@home` siblings: Ubuntu, Arch, Fedora) are not affected.
5. [[GM-09 Change plan perms task clobbers descendant groups and follows symlinks as root|GM-09]] part 1: with owner set, group blank and recursive on, `chown -R` writes the top folder's group onto the whole tree. Part 2 is **not a bug**: the field's label reads "Owner and group for everything inside too", so leaving the mode on the top folder only is intended. Part 3 (symlinks): `chown -R` defaults to `-P`, so only a symlinked top path is followed. Fixed by refusing that. Still open: the Ansible export passes `recurse` together with `mode`, so it *does* chmod the whole tree, which doesn't match the shell script.
6. [[GM-01 Restore unpack as root allows device nodes and TOCTOU|GM-01]]: the attack is real (`find -type f` misses device nodes, and setuid files stay live until tar finishes), but it needs a compromised backup host, so it's **High, not Critical**. **Gemini's fix doesn't work:** GNU tar has no `--no-devices` / `--no-specials` (checked with `tar --help`). The fix that does work is `mkdir -m 0700 "$t"` (nobody else can reach anything while the extraction runs), then `find "$t" -xdev \( -type b -o -type c -o -type p -o -type s \) -delete` and strip setuid/setgid from files before opening the mode up. Setgid *directories* are kept: they only set group inheritance and aren't an escalation.

## Second batch (fixed 2026-10-29, uncommitted)

Each fix has a regression test that fails on the old code (in `tests/test_platform.py` and `tests/test_consistency.py`).

- **GM-04:** `/api/keys/install` now asks for host-key confirmation *before* any connection, and the key-login probe uses `StrictHostKeyChecking=yes`, so it can't pin a key. `rekey_host` now also deletes that host's `host_key_confirmations`.
- **GM-06:** A stored token is kept only when the scheme, host and port are all unchanged. 6to4 and Teredo addresses are unwrapped and checked too. Alert requests now connect to the exact address that was checked, so DNS rebinding can't redirect them. HTTPS still verifies the certificate against the name (checked against example.com). Alerts now ignore proxy environment variables. `PUT /api/deploy/settings` needs a recent password (this closes A1). **Correction:** the SMTP part of GM-06 doesn't exist: there is no SMTP channel in `alerts.py`, so Gemini's quote of it was invented.
- **GM-16:** `restore` now skips `migrate`, `vault init` and the key import. The entrypoint finds the subcommand after `--db <path>`, so the session-secret check applies there, and it passes `--db` on to `migrate`, `vault init` and the key import. With no arguments it defaults to `serve`.
- **GM-18:** The firewall now uses a chain per bridge (`SF-EGRESS-<bridge>`, alternating with `-b` on reruns). The new chain is hooked in before the old one is unhooked, so no bridge is ever left open. Bridge names and port ranges are checked before any rule changes. Traffic to the Docker host itself is now filtered through `INPUT`, with ICMPv6 allowed so IPv6 neighbor discovery keeps working. It moves off the old shared `SF-EGRESS` chain cleanly. **Untested against real iptables:** the tests use a fake `iptables` that tracks chain state.
- **GM-15:** `init-secrets.sh` makes `keys/` `0750`. The entrypoint now logs a warning when it can't list the import dir, instead of skipping it silently. `docs/getting-started.md` now tells people to make key files `0640`. Note: ssh-keygen creates keys as `0600`, which the container can't read through the group. The import already logs `skipped <file>: Permission denied` for those.

## Verdict per finding

| ID | Gemini | Verdict | Revised | Notes |
| :-- | :-- | :-- | :-- | :-- |
| GM-01 | Critical | Partly | High | See above; remediation flags don't exist in GNU tar |
| GM-02 | High | Mechanism right, threat wrong | Low | `REST` comes from the operator's own command line on their own machine, and they already run sudo there. It's a robustness bug (args with spaces break), not an injection |
| GM-03 | High | **Confirmed** | High | Top priority |
| GM-04 | High | Partly | Medium | `key_login_works` does use `accept-new`, so the probe TOFU-pins before the prompt, and the prompt then says "pinned by a scan" with an empty type. But the password still only goes out after a person confirms the fingerprint, so there's no real bypass. Cheap fixes: confirm first, `strict=True`. `rekey_host` leaving `host_key_confirmations`: valid, low |
| GM-05 | High | Confirmed | Low–Med | No host validation, and the binding survives a failed probe. Exploiting it needs a password-confirmed admin, and the deploy key only works where setup ran |
| GM-06 | High | Confirmed | Medium | `_host()` ignores scheme and port, so `https→http` keeps the token (the SMTP check ignores port/TLS the same way). Rebinding and 6to4 are valid hardening. The missing re-auth is already tracked as A1 in `docs/audit-2026-10-29.md` |
| GM-07 | High | Mostly wrong | Low | `tidy()` *does* sanitize `encryption/recordsize/compression/sync`. `tier`/`kind` are unescaped, but they sit inside double-quoted attributes after `scrub` strips `<>"'\``, so the worst case is class injection from your own draft, not XSS. The planner `apiJSON` lacking reauth is moot today (no planner route uses `@password_confirmed`) |
| GM-08 | High | Partly | Low | `tasks.HOST_RE` does allow a leading `-`, but with no spaces or `/` allowed in the host, an `-e` payload is contrived. Add the `startswith('-')` check and `--` anyway |
| GM-09 | High | Part 1 confirmed, part 2 wrong | Medium | See above |
| GM-10 | High | 3 confirmed, 1 plausible | High | See above |
| GM-11 | High | Mostly design disagreement | Low | `dryrun/log/snapshots/browse` are exempt on purpose (they only read; there's a comment saying so). **`/api/hostkey/confirm` already has `@password_confirmed`**, so that claim is false. Settings: same as A1 |
| GM-12 | High | Confirmed | Medium | `threads=8`, and restore holds a worker for up to 6 h. Move it onto the `start_group` async pattern |
| GM-13 | High | Confirmed (5/5) | Medium | Postgres: `is_symlink = 0` against BOOLEAN, datetime vs int in `cold_folders`, `json.loads(dict)` in alerts/shares, raw TIMESTAMPTZ in `/api/hosts`. The `SystemExit` fails the request but doesn't kill Waitress. Same theme as [[EQ-01 No CI and untested paths|EQ-01]] |
| GM-14 | High | **Confirmed** | High | Nested layouts only |
| GM-15 | High | Part 1 confirmed | Medium | `keys/` is `0700 archie` (checked here), so uid 10001 can't list it and `ls … 2>/dev/null` makes the skip silent. Demo empty password: sshd refuses empty passwords by default, and it's a demo. `secrets/api_token` 0644 sits inside a 0700 dir, so it's not exposed, but it's stale: delete it |
| GM-16 | High | Partly | Medium | `restore` runs `migrate` + `vault init` first: confirmed and real. **False:** "CLI runs delete the server's agent sockets" (each `compose run` gets its own tmpfs) and "empty `$@` fails" (`CMD ["serve"]`). The `storageforge-index` prefix skipping the checks is minor: the image is already `USER 10001` |
| GM-17 | Medium | Valid | Low | Only containers on `sf`/`demo`, or host users reaching the bridge IP, can spoof XFF, and that only affects rate limits and audit IPs. `PROXY_HOPS>1` is broken by nginx overwriting XFF: valid |
| GM-18 | Medium | **Confirmed** | Medium | Running for a second bridge flushes `SF-EGRESS`, `-N` then fails under `set -e`, and `sf0` is left with an empty chain (fails open). Port 70000 tears it down too. `INPUT` (the host's own services) isn't covered |
| GM-19 | Medium | Valid trade-off | Low | 100/day per account is a deliberate backstop. The lockout risk is real but known |
| GM-20 | Medium | Part 1 confirmed | Medium | `sudo_run` resolves a `scan` binding before it looks at `admin_user`. Port-22 binding on unscanned hosts: plausible |
| GM-21 | Medium | **Confirmed** | **High** (part 1) | See above. The fstab false drift (`WANT_LINES` gets the generated line when the existing one is kept) is confirmed: Medium |
| GM-22 | Medium | Partly | Low | `pack 2>/dev/null` hides its errors, and `raw()` has no lock: valid. **False:** "tar exits 0 on an empty stream and prints restored into": GNU tar exits 2 (tested). An empty target dir is left behind: valid |
| GM-23 | Medium | Partly checked | Low | `parse_sections` never flushes the last section, and the `run_dupes` member query ignores `host`: both confirmed. Not checked: capacity negatives, mountinfo `b[2]` |
| GM-24 | Medium | Mostly wrong | Low | **False:** the 398-day limit applies only to publicly trusted CAs. Self-signed/user-trusted certs are exempt, and 825 days is exactly Apple's cap for those, so the current value is right. The test stage runs as root *on purpose* (the chroot test needs it; the root-skipped tests run in normal runs). Valid: no `git` in the test stage, no IPv6 `listen`, `proxy_pass` resolves once |
| GM-25 | Low | Plausible | Low | `folder_cache` keys on `max(scan_id)`, which a running scan already bumped, so results can be stale. Its clear/assign race is rare. Nested `tx()` on SQLite is latent unless something nests it |

## Other problems in the Gemini notebook
- Its inventory counts are wrong: it says 85 routes, 26 modules and 8 JS files, but there are 76 route decorators, 38 `.py` modules and 14 JS files.
- Its notebook was copied into `notebook/` (the GM files, Areas, and companion notes) as well as living in `notebook-gemini/`. Keep one copy.
- Its severity labels shouldn't drive [[Roadmap]] ordering. Use the revised column above.

Back to [[Home]]
