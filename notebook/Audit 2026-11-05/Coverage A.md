---
tags: [audit, coverage]
date: 2026-11-05
---
# Coverage A: network, infrastructure steps and the language emitters

Part of [[Audit 2026-11-05]]. Baseline: `dev-expanded-networking` at `fb6b024`, tree clean. One reader, no application code or test changed. Probes live in `/tmp/sfaudit/a/` (throwaway SQLite databases, synthetic values, no host contacted, no vault or key file opened).

## Read in full
| File | Lines | Found | Ruled out |
| :-- | --: | :-- | :-- |
| `steps_infra.py` | 1161 | [[SF-65 Two hardening steps write their error output to fixed names in the world-writable temp folder\|SF-65]] | Every step's field kind: `cidr`, `cidrs`, `iface`, `word`, `name`, `ports`, `number` cannot hold a shell metacharacter, a space or a newline, and `fullmatch` is used (`changes.py:312`). The journal lines run by `bash -c` in `revert` hold only validated values. No nested quantifier in the new `CHECKS` patterns. `FWRULES` heredocs are fed validated words. The apparmor warning regex is quadratic but at the 4 KiB body limit costs about 0.05 s a request (0.74 s at the 8,000-character field cap, which the body limit stops), so not a finding |
| `whatif.py` | 281 | nothing | Pure analysis of copies; 50 flows capped; the plan goes through `changes.normalize` |
| `reach.py` | 302 | nothing | Sends nothing; hop count capped at 8; loop detection present |
| `mapdesign.py` | 298 | nothing | The design is validated by running its tasks through `changes.normalize`; Terraform values go through `json.dumps` with `${` and `%{` escaped, Puppet through `_pp`, comments lose newlines. Stored values keep edge whitespace that `normalize` strips, but only inside quotes |
| `traffic.py` | 89 | nothing | Sends nothing; counters are read from readings; rows kept 14 days; windowed queries |
| `routes_network.py` | 296 | [[SF-60 The compile route runs once per target in a list a caller can make 30,000 long\|SF-60]], [[SF-63 One change route returns firewall rules a role without security view is refused elsewhere\|SF-63]] | Every route has `@login_required`; every state change has `@password_confirmed` except `read`, `report`, `netscan/run`, `dsl/stage`, which run no command on a host or change a device (read only reads; report only stores); permissions match `permissions._RULES` order (checked by hand for `devices/changes/<id>/apply`, `/report`, `/read`, `dsl/*`) |
| `rostranspiler.py` | 1073 | [[SF-64 The address checks of the network language accept IPv6 zone text and non-ASCII digits\|SF-64]] | Comments, names and quoted values: `fullmatch`, control characters refused, hidden characters refused. `shlex.quote` on the OpenWrt, firewalld and NetworkManager lines. pfSense XML goes through `escape`. 200,000-character and 2,000-statement caps hold; parse of adversarial text (quote and `=` runs, one 190,000-character word, 8,000 continuations) took under 15 ms; 2,000 statements emit in 5 ms per target. Compiling 2,000 WireGuard statements for all ten targets with the secret-hiding loop took 1.0 s |
| `netdevice.py` | 643 | [[SF-61 A RouterOS change goes ahead when planting its rollback failed\|SF-61]] | `apply` and `confirm` need `devices.apply` and a fresh password; the rollback range is 60 to 3600; a secret-carrying report is kept in memory only; `StrictHostKeyChecking` and password handling as audited before. The check-then-set on `status` in `apply()` is a window of microseconds, and a second plant fails on `mkdir` (SF-55), so not raised |

## Also read
- `permissions.py` in full, for the rules above.
- `openwrt.py` (collect, parse, the script) and `cisco.py:21-23`, for what a device's `config` holds: [[SF-62 An OpenWrt reading keeps WireGuard keys in the clear and a viewer can read them\|SF-62]].
- `routes_infra.py:100-270`, `server.py` body limits and error handler, `vault.py` `unlock` and `list_credentials`, `nettransport.py` `DirectTransport` and `check_command`, `remote.py` `run`, for context.

## Not read, or only in part
- The tests beside these files (`test_routers.py` was read where it was used to build probes, `test_infra.py` not opened).
- `changes.py` was read only for `normalize`, `CHECKS` and `check`: how a step's parameters are quoted into the generated Bash is not reviewed here.
- `netfacts.py`, `firewall.py`, `exposure.py`, `routeros.py`, `pfsense.py` readers, `nettransport.py` beyond the command check.
- The device scripts under `tests/lab` and the generated scripts under `shellcheck`.

## Probed
| Probe | Result |
| :-- | :-- |
| Zone text and non-ASCII digits through `parse` and every emitter (`p1.py`) | accepted and emitted unquoted in six emitters: SF-64 |
| 2,000-statement compile with 1, 200 and 2,000 targets, as a viewer, on the real route (`probe_api.py`) | 0.04, 1.04, 9.35 s: SF-60 |
| OpenWrt reading with synthetic WireGuard keys, `GET /api/devices/<name>` as a viewer | both keys in the response and in one stored row: SF-62 |
| `netdevice.apply` against a stand-in session that fails the RouterOS backup and scheduler | change lines still sent: SF-61 |
| Custom role with only `devices.view` against `/api/devices/<name>` and `/api/devices/changes/<id>` | the second returns rules the first and `/api/firewall` refuse: SF-63 |
| `GET /api/devices/credentials` as a viewer | it unlocks the vault (Argon2) to list names that sit in a plain table; 0.08 s each, 8 in parallel took 0.8 s. Not raised alone: a cost like any heavy GET, but the unlock is not needed and the list would fail whenever the vault secret is not set. Worth fixing with SF-60 |
| `changes.check` of an `apparmor-local` step with 8,000 characters | 0.74 s per task, linear in tasks; held to a few tens of ms by the 4 KiB body limit (not a finding) |

## Not run
Anything on a real router, firewall or Linux host, the lab, the whole suite, `shellcheck`, a dependency or container review. SF-61's effect on a real RouterOS (its text and exit status when a backup or scheduler command fails) is unconfirmed.

## Ruled out, in short
No `shell=True`, `eval` or unquoted user value in the OpenWrt, firewalld, NetworkManager or pfSense output; no secret in `/api/dsl/compile` output (`private-key` is hidden in text and files, and `Stmt.text` redacts); no SSRF or send in `traffic.py`, `reach.py`, `whatif.py` or `mapdesign.py`; no path traversal in a step: `iface`, `name` and `label` kinds hold no `/`, and a `/` in the bridge `ports` list (`word`) cannot reach outside `/etc/systemd/network` because the first path part carries the `10-sf-<name>-` prefix.
