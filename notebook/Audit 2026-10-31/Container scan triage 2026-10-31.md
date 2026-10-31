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

## Next
```bash
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy image --severity CRITICAL,HIGH storageforge:0.2.0
```
Update this note from the result. Then add it to CI, failing on a critical not listed here.
