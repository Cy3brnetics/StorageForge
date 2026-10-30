---
tags: [area, gemini-audit]
---
# API, Auth and Security

Web server routes (`server.py`), authentication (`users.py`), session cookies, password re-confirmation (`@password_confirmed`), SSH key vault (`vault.py`), host key confirmation (`hostkeys.py`, `keyinstall.py`), remote sudo access (`access.py`), and alert webhooks (`alerts.py`).

## Findings
- [[GM-04 Key install probes host with accept-new before host key confirmation]] (High)
- [[GM-05 Deploy adopt lacks hostname validation and binds arbitrary vault patterns]] (High)
- [[GM-06 Alert settings leak secret tokens on URL change and allow SSRF via IPv4-mapped IPv6 and DNS rebinding]] (High)
- [[GM-11 Missing password confirmation on remote execution and security-critical routes]] (High)
- [[GM-12 Waitress 8-thread pool exhaustion via synchronous 6-hour restore and deploy endpoints]] (High)
- [[GM-19 Global account lockout DoS and unauthenticated audit_log flooding on login]] (Medium)
- [[GM-20 Deploy enroll and sudo_run fail without existing scan key binding or on non-default SSH ports]] (Medium)

## Reference Notes
- [[API Routes and Code Paths - gemini]]

Back to [[Home]]
