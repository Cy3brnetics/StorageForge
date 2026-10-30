---
tags: [moc, gemini-audit]
---
# StorageForge Audit Notebook (gemini)

Full-stack codebase, API route, code-path, database, and Docker infrastructure audit of `storageforge-indexer` (2026-10-29).

## Start Here
- [[Audit 2026-10-29 - gemini]]: Executive summary and master table of all **25 newly discovered findings (`GM-01` to `GM-25`)**
- [[API Routes and Code Paths - gemini]]: Complete matrix of all **85 HTTP routes** in `server.py` and their downstream code paths
- [[Docker and Infrastructure Audit - gemini]]: Deep dive into `Dockerfile`, `docker-compose.yml`, `entrypoint.sh`, `init-secrets.sh`, `nginx.conf`, `egress-firewall.sh`, and `examples/demo/`

## Audit Areas
- [[API, Auth and Security]]
- [[Deployment, Runner and Scripts]]
- [[Docker, Nginx and Infrastructure]]
- [[Scanner, Database and Analytics]]
- [[Plans, Planner and UI]]

## All Findings by Severity

### Critical
- [[GM-01 Restore unpack as root allows device nodes and TOCTOU]]

### High
- [[GM-02 Remote command injection in scriptkit host relay]]
- [[GM-03 Deployed tasks fail under systemd with 203 EXEC due to missing shebang]]
- [[GM-04 Key install probes host with accept-new before host key confirmation]]
- [[GM-05 Deploy adopt lacks hostname validation and binds arbitrary vault patterns]]
- [[GM-06 Alert settings leak secret tokens on URL change and allow SSRF via IPv4-mapped IPv6 and DNS rebinding]]
- [[GM-07 Planner scrub is a no-op and innerHTML sinks lack escaping]]
- [[GM-08 Leading-hyphen hostnames allow rsync and ssh option injection in tasks and remote]]
- [[GM-09 Change plan perms task clobbers descendant groups and follows symlinks as root]]
- [[GM-10 Four broken code paths in jobscript backup and snapshot execution]]
- [[GM-11 Missing password confirmation on remote execution and security-critical routes]]
- [[GM-12 Waitress 8-thread pool exhaustion via synchronous 6-hour restore and deploy endpoints]]
- [[GM-13 PostgreSQL runtime crashes across folders, backups, alerts, shares, and timestamps]]
- [[GM-14 Scanner skips child Btrfs subvolumes by marking them alias while also pruning them]]
- [[GM-15 Docker keys import fails silently on 0700 permissions and demo target has empty scan password]]
- [[GM-16 Entrypoint bypasses on global flags and destructive pre-restore initialization]]

### Medium
- [[GM-17 Proxy header spoofing on shared Docker networks and broken multi-hop X-Forwarded-For]]
- [[GM-18 Egress firewall fails open on bridge switch or invalid port and misses host INPUT chain]]
- [[GM-19 Global account lockout DoS and unauthenticated audit_log flooding on login]]
- [[GM-20 Deploy enroll and sudo_run fail without existing scan key binding or on non-default SSH ports]]
- [[GM-21 Move plan verify_step ignores rsync exit code and shares fstab preservation triggers false drift]]
- [[GM-22 Cross-host restore drops pack error output, lacks runner lock, and leaves empty directories]]
- [[GM-23 Inventory section parser collisions, missing mountinfo superblock options, and capacity edge cases]]
- [[GM-24 TLS 825-day cert rejected by modern browsers, nginx IPv6 and cipher gaps, and skipped tests in Dockerfile]]

### Low
- [[GM-25 Thread-safety races in folder_cache, backup.create, Vault._UNLOCKED, and SQLite nested tx]]
