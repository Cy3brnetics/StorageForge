---
id: GM-17
status: open
severity: medium
effort: S
area: "[[Docker, Nginx and Infrastructure]]"
tags: [finding, security, docker, nginx, rate-limiting, gemini-audit]
found: 2026-10-29
---
# GM-17 Proxy header spoofing on shared Docker networks and broken multi-hop X-Forwarded-For

## Location
- `Dockerfile:60-61` (`STORAGEFORGE_LISTEN=0.0.0.0`, `STORAGEFORGE_PORT=8080`)
- `docker-compose.yml:25, 48, 86`
- `docker/nginx.conf:27, 35-38`
- `examples/demo/compose.demo.yml:10, 21`
- `storageforge_index/server.py:321-322, 485, 494-520`

## Mechanics & Root Cause
1. **Unauthenticated `X-Forwarded-For` Trust Across Shared Docker Networks (`sf` and `demo`)**:
   - `storageforge` binds `0.0.0.0:8080` (`Dockerfile:60`) with `STORAGEFORGE_PROXY_HOPS=1` (`docker-compose.yml:25`).
   - `Werkzeug.middleware.proxy_fix.ProxyFix(web.wsgi_app, x_for=proxy_hops, x_proto=proxy_hops)` (`server.py:321-322`) trusts `X-Forwarded-For` from **any** TCP peer connecting to port `8080`, without checking that `REMOTE_ADDR` is the `proxy` container.
   - Because `storageforge` shares the `sf` network (`sf0` bridge) and in the demo stack shares the `demo` network (`sfdemo0`) directly with the scanned `target` SSH container (`compose.demo.yml:10, 21`), any container on those networks (or any local user on the Docker host connecting via `sf0`) can connect directly to `http://storageforge:8080` and send arbitrary `X-Forwarded-For` headers.
2. **`STORAGEFORGE_PROXY_HOPS > 1` Broken by `nginx.conf:37`**:
   - `docker-compose.yml:25` exposes `${STORAGEFORGE_PROXY_HOPS:-1}` so operators can run an upstream reverse proxy in front of the stack.
   - However, `docker/nginx.conf:37` sets `proxy_set_header X-Forwarded-For $remote_addr;` (overwriting any upstream `X-Forwarded-For` header so it only ever contains 1 IP). If `STORAGEFORGE_PROXY_HOPS=2` is set, `ProxyFix(x_for=2)` sees only 1 IP in `X-Forwarded-For` and falls back to the nginx container's IP for every client!
3. **Unvalidated `$http_host` Redirect on Error 497 (`nginx.conf:27`)**:
   - `error_page 497 =301 https://$http_host$request_uri;` reflects the client-supplied `Host` header verbatim without validation.

## Impact
Any container on the scan network (`sf` or `demo`) or local process on the Docker host can bypass IP-based login rate limits (`LOGIN_LIMIT_PER_IP`, `LOGIN_LIMIT_PER_USER`) and spoof client IPs in `audit_log` and `job_runs`. Setting `STORAGEFORGE_PROXY_HOPS > 1` breaks client IP attribution behind an external reverse proxy.

## Remediation
1. Place `proxy` and `storageforge` on a dedicated `internal: true` Compose network (or communicate via a Unix domain socket on a shared tmpfs volume) so port `8080` is never reachable from scanned target networks (`sf` / `demo`).
2. Use `$host:$server_port` instead of `$http_host` in `nginx.conf:27`, and document/configure `X-Forwarded-For` handling when `STORAGEFORGE_PROXY_HOPS > 1`.

## Done when
- [ ] `storageforge:8080` is only reachable by `proxy` (via Unix socket or isolated network), not from target scan networks.
