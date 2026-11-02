# Ransomware defense audit, 2026-11-02

A review of the first implementation of the [ransomware defense roadmap](../ransomware-defense-roadmap.md) (branch `dev`, commits `c21e652`, `1f2df07`, `d29bf2f`), and what replaced it.

**Scope.** Read in full: `security.py`, `routes_security.py`, `securityview.js`, both `031` migrations, `test_security.py`, and the diff to existing files. Every finding marked *confirmed* was reproduced against the running API, in a browser, or by running the generated script.

**Verdict.** The code was a mock-up that presented itself as working. It never called `deploy.run`, so **nothing it did reached a host**, and most of what it displayed was hardcoded. Its 694 passing tests asserted those same hardcoded values. It was replaced rather than repaired, because the missing part (measuring hosts and acting on them) was the feature. See [Ransomware defense](ransomware-defense.md) for what exists now.

## Summary

| # | Area | Finding | Severity |
| :--- | :--- | :--- | :--- |
| R1 | Emergency brake | Reports every step as done without running anything, even on a host that does not exist | **Critical** |
| R2 | Posture | Says `SECURE: all monitored hosts hardened` with zero hosts, zero decoys and zero holds | **Critical** |
| R3 | Holds | A 365-day hold, a 24-hour cool-off: one admin can approve their own release at once | **Critical** |
| R4 | Holds | Holds, releases and quarantines exist only in the database: no snapshot, hold or firewall rule is ever made | **Critical** |
| R5 | Malware | "Shred" and "Restore" report success without touching the file. The shred script targets a directory, and hides that it fails | **Critical** |
| R6 | Offline key | One admin can mint a new key and use it immediately, defeating dual custody | **High** |
| R7 | Holds | Posting a hold again removes a legal hold and shortens its expiry to a day | **High** |
| R8 | Holds | A legal hold can be released like any other | **High** |
| R9 | Clock guard | Drift, peers and NTS status are hardcoded; nothing ever measures a clock. A reading from any host clears a freeze on every host | **High** |
| R10 | Compliance | "Staging" HIPAA on a host that does not exist records a score of 100 with no drift | **High** |
| R11 | Scripts | A decoy file name breaks out of a heredoc: hostile input runs as root if the script is used | **High** |
| R12 | Firewall | The quarantine script creates a set that no rule refers to, so it drops nothing | **High** |
| R13 | Firewall | The airgap disarm script flushes rules but keeps the `policy drop` chain: it would lock the host off the network | **High** |
| R14 | Firewall | `0.0.0.0/0` can be quarantined. IPv6 goes into an IPv4 set. Airgap leaves SSH open to everyone | **High** |
| R15 | UI | Every control is an inline `onclick`, which the app's CSP refuses. No sub-tab or button in the panel ever worked | **High** |
| R16 | MAC | `/api/security/mac/status` is a 500 for every host: its query names a column that does not exist. Its data was hardcoded anyway | **High** |
| R17 | Malware | `/api/security/malware/quarantine` is a 500 for every request (`closed=True` is not an argument) | Medium |
| R18 | Detection | Velocity is a count of every change ever, labelled files an hour. The entropy function is never called, and its 65% / 35% / 0% split is a literal | **High** |
| R19 | Decoys | No file is ever written. `baseline_sha256` hashes a string made from the name. "Latency: 1.2 ms" is a literal | **High** |
| R20 | Integrity | Lynis reports 86 and AIDE "verified" when neither has run. `aide_init` inserts `SHA256 OK` rows | **High** |
| R21 | Identity | "Anomalies" are quarantine rows relabelled, with the operator shown as the suspect | Medium |
| R22 | Integration | No alert is ever raised; nothing reads events; the timelock queue has no worker; playbooks never run; retiring a host leaves its rows | **High** |
| R23 | Scripts | `net.ipv4.conf.all.accept_Redirects` is not a setting: sysctl names are case-sensitive, and `\|\| true` hid the failure | Low |
| R24 | Scripts | Failures hidden throughout: `2>/dev/null \|\| true` on every step of the brake and quarantine | Medium |
| R25 | Tests | They assert the invented values (`assertIn('filesystem_remounted_ro', steps_executed)`), so a broken feature passes | **High** |
| R26 | Rules | Breaks the [rules every feature follows](concepts.md#the-rules): report first, values as data, nothing is deleted, commands through the runner | **High** |

## How each was confirmed

R1 to R14, R17, R19 and R23 by a script against the API. Abridged output:

```text
zero hosts, zero canaries, posture -> {'state': 'secure', 'banner': 'SECURE: All monitored hosts hardened, canaries armed, WORM retention active',
                                       'monitored_hosts': 0, 'armed_canaries': 0, 'lynis_hardening_index': 86, 'aide_baseline_verified': True}
clock guard, no data -> {'label': 'NTS Monotonic (Drift 2ms, 3 peers)', 'nts_authenticated': True, 'drift_ms': 2}
EMERGENCY BRAKE on nonexistent host -> ok=True steps=['volatile_ram_triage_dump', 'ip_quarantined', 'filesystem_remounted_ro', 'immutable_snapshot_locked']
solo admin, 24h cool-off, immediate self-approve -> executed | hold now: ['released']
re-POST over a legal hold -> legal_hold=False expires in 1.0d
one admin mints a NEW break-glass key then uses it (dual-admin fleet, no 2nd admin) -> executed
30-day jump on nas, then 1s reading from ANOTHER host -> freeze= False
hostile canary file name, heredoc breakout in script -> True
quarantine 0.0.0.0/0 -> HTTP 200
"stage" HIPAA on nonexistent host, nothing run -> score 100 drift 0
```

R15 by the header itself: `script-src 'self'` blocks inline handlers, and `main`'s `index.html` has none. This is why only the first panel was ever seen: `loadSecurity()` draws it directly.

## What was kept

The roadmap's route names where they still describe something real, the permission split (`security.view`, `.manage`, `.emergency`), the sidebar entry, and the package names added to `scriptkit.NEEDS`.

## Bugs found while rebuilding

Worth recording, because reading the code would not have found them. Each has a test.

| Bug | How it was found |
| :--- | :--- |
| **The sentinel lost alarms.** Its loop reads events from stdin, and `ausearch` reads stdin when it is not a terminal. So working out who changed a decoy ate the next trip, and held up the alarm by up to 5 seconds | Real auditd as root in a container. Stand-ins never showed it |
| A real second admin could never approve: `web:admin2` was compared with `admin2` | Running a release end to end |
| With this machine's clock moved, an automatic measurement blamed the host's clock and froze it too | A test of the controller's clock guard |
| `is_directory = 0` fails on PostgreSQL, where it is a boolean | Running the flows on PostgreSQL 16 |
| Wide tables were unreadable and the panel navigation collapsed to nothing in the narrow side panel | Looking at a screenshot |
