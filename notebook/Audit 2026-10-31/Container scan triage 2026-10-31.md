---
date: 2026-10-31
tags: [audit, triage]
---
# Container scan triage, 2026-10-31

For [[SF-38 Container scan report is committed but not triaged]]. The raw report left the repo; it is in git history at `c710904` as `vuln-report-storageforge-0.2.0-combined-2026-10-31.md`.

**The report is out of date.** It lists Debian 12 packages (`deb12`), written at 00:13. The local `storageforge:0.2.0` image, built 12:26 the same day, is Debian 13, and the Dockerfile now builds OpenSSH itself. No fresh scan has been run: this machine has no scanner.

## What the image holds
Read from the image with `dpkg-query` and `ssh -V`, with no network.

| Package | In the report | In the image |
| :-- | :-- | :-- |
| OpenSSH client | 9.2p1 | 10.6p1, built in the Dockerfile |
| glibc | 2.36 | 2.41 |
| SQLite library | 3.40.1 | 3.46.1 |
| zlib | 1.2.13 | 1.3.1 |
| `sqlite3` tool, `util-linux`, `mount`, `gzip`, `perl-base` | present | **not installed** |

## The criticals
| CVE | Package | Decision | Why |
| :-- | :-- | :-- | :-- |
| CVE-2026-60002 | OpenSSH client | **Fixed** | The report says "before 10.4", and the image has 10.6p1 |
| CVE-2025-7458 | SQLite | **Fixed** | The report says 3.39.2 to 3.41.1, and the image has 3.46.1. It also needs arbitrary SQL, which StorageForge does not take |
| CVE-2023-45853 | zlib | **Expected fixed: check on rescan** | The image moved to 1.3.1. The report's text wasn't checked against that version |
| CVE-2026-5450 | glibc | **Accept for now** | 2.41 is still in the report's range (2.7 to 2.43). It needs a `scanf` `%mc` with a width over 1024. Python's own code path wasn't analysed, so this is a judgement. Take the fix when Debian ships it |

## The highs
None had a fix available in the report. Most belong to packages no longer installed (`util-linux` and its libraries, `gzip`, `perl-base`, `sqlite3`) or the old OpenSSH. Not reviewed one by one: the fresh scan decides what is left.

## Fresh scan, 2026-10-31
Trivy over `storageforge:0.2.0`, from a saved image with no Docker socket: Debian 13.7, **no criticals, one high**.

| CVE | Package | Decision |
| :-- | :-- | :-- |
| CVE-2026-54369 | libacl1 2.3.2 | Accept for now: no fix available. The scanner calls it symlink traversal in libacl functions; whether anything in the image reaches them was not analysed. Take the fix when Debian ships it |

This settles the table above: zlib and the rest no longer show, and neither does the glibc CVE, at these severities. Trivy's view only; Grype was not rerun.

CI scans each build and fails on a critical not in `.trivyignore`, once a runner exists.

## Rescan, 2026-11-01
`e02be16`, rebuilt. Trivy 0.76.1: **no criticals, three highs**. Grype: **no criticals**, 13 highs, not reviewed one by one, as no gate reads them.

| CVE | Package | Decision |
| :-- | :-- | :-- |
| CVE-2026-54369 | libacl1 | Unchanged: accept for now, no fix available |
| CVE-2026-119586 | libsqlite3-0 | **Not reachable as described**: the scanner names the `.recover` command, part of the `sqlite3` tool, which the image does not hold |
| CVE-2026-119373 | libsqlite3-0 | **Accept for now, and watch it**: FTS5 denial of service with no fix available. StorageForge does use FTS5 (`file_fts`, search on SQLite), so this cannot be ruled out. Whether a search or an indexed name can trigger it was not analysed. PostgreSQL installs do not use FTS5. Take the fix when Debian ships it |

## Rescan, 2026-11-15: the runtime moves to Wolfi
The 0.5.2 report (Grype 134, Trivy 132: 19 and 7 highs, no criticals) was entirely Debian 13 packages, almost all with no fix available: glibc, SQLite, the GCC runtime, OpenSSL, systemd, dbus, nmap and libpcap. Accepting them one at a time would not have ended, so every stage now builds on `cgr.dev/chainguard/wolfi-base`, pinned by digest. Wolfi ships upstream fixes quickly and publishes a security feed both scanners read.

| What | Before | After |
| :-- | :-- | :-- |
| Base | `python:3.13-slim-trixie` | `wolfi-base`, no `apk` in the runtime (the database stays for scanners) |
| Python | 3.13.18 (Debian image) | Wolfi `python-3.14`: on 3.13, Grype still listed CVE-2025-15367 and CVE-2026-116566 as unfixed |
| nmap | Debian 7.95 | 7.991 built from source, no NSE scripts, ncat, nping, OpenSSL or zenmap. Wolfi's free repository stops at 7.94, which has CVE-2026-58058 |
| OpenSSH | 10.6p1 from source | Unchanged, now linked against Wolfi's OpenSSL 4 |

Result, Trivy 0.75.0 and Grype 0.119.0 over the runtime image: **Trivy 0. Grype 0 with `.grype.yaml`**, 1 Low without it.

| CVE | Package | Decision |
| :-- | :-- | :-- |
| CVE-2026-103995 | python-3.14 | **Accept, in `.grype.yaml`**. `http.client` takes chunk sizes like `-1` or `0x10`. No released Python fixes it (3.16.0 will) and Wolfi has no backport; read in the image's `http/client.py`. StorageForge's only HTTP client use is POSTing alerts to webhooks an admin configured. Remove the entry when Wolfi marks it fixed. Trivy does not report it |
| CVE-2026-58058 | nmap | **Fixed** by the source build (7.991). It was not reachable anyway: the bug is in raw IPv6 scans, and netscan.py only runs connect scans (`-sT`) |
| CVE-2026-54369, CVE-2026-119373 | libacl1, libsqlite3-0 | **Gone**. Wolfi's versions are not affected. Python's `sqlite3` now uses SQLite 3.54.1 |

Scanners cannot see the source-built nmap and OpenSSH. Their release notes are the check when bumping: README "Updating dependencies".

Found on the way: Wolfi has no `/usr/share/zoneinfo` unless `tzdata` is installed. Without it the scheduler cannot load any zone, not even UTC. The runtime installs it, and a run of `scheduler.next_run` in a zone was checked in the image.
