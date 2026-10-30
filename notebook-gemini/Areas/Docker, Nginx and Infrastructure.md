---
tags: [area, gemini-audit]
---
# Docker, Nginx and Infrastructure

Container images (`Dockerfile`, `examples/demo/Dockerfile.target`), Compose stacks (`docker-compose.yml`, `examples/demo/compose.demo.yml`), container entrypoint (`docker/entrypoint.sh`), secret initialization (`docker/init-secrets.sh`), TLS reverse proxy (`docker/nginx.conf`), and host egress firewall (`docker/egress-firewall.sh`).

## Findings
- [[GM-15 Docker keys import fails silently on 0700 permissions and demo target has empty scan password]] (High)
- [[GM-16 Entrypoint bypasses on global flags and destructive pre-restore initialization]] (High)
- [[GM-17 Proxy header spoofing on shared Docker networks and broken multi-hop X-Forwarded-For]] (Medium)
- [[GM-18 Egress firewall fails open on bridge switch or invalid port and misses host INPUT chain]] (Medium)
- [[GM-24 TLS 825-day cert rejected by modern browsers, nginx IPv6 and cipher gaps, and skipped tests in Dockerfile]] (Medium)

## Reference Notes
- [[Docker and Infrastructure Audit - gemini]]

Back to [[Home]]
