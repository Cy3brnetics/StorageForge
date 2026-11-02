---
id: SF-42
status: done
severity: medium
effort: S
area: CSRF / Auth
verified: proven
tags: [finding, audit-2026-11-01]
found: 2026-11-01
---
# SF-42 Same-origin fallback omits port comparison on cross-origin requests

**Medium** · effort S · CSRF / Auth · Proven · part of [[Audit 2026-11-01]]

## What exists
`same_origin_only` in `server.py` guards against Cross-Site Request Forgery (CSRF). When the `Sec-Fetch-Site` header is missing, it falls back to parsing `Origin` or `Referer` and comparing the hostname with `request.host`. However, it compares only `urlsplit(origin).hostname == urlsplit(f'//{request.host}').hostname`, completely ignoring the port number.

## Evidence
- `storageforge_index/server.py:531-542`:
  ```python
  if origin:
      p = urlsplit(origin)
      if p.hostname and p.hostname == urlsplit(f'//{request.host}').hostname:
          return None
  if referer:
      p = urlsplit(referer)
      if p.hostname and p.hostname == urlsplit(f'//{request.host}').hostname:
          return None
  ```
- Proof: Consider StorageForge running on `http://localhost:8000`. If an attacker or untrusted local script runs a web application on `http://localhost:3000`, a cross-origin state-changing request (POST/DELETE) with header `Origin: http://localhost:3000` (and `Sec-Fetch-Site` stripped or absent) passes the check:
  `urlsplit("http://localhost:3000").hostname` is `"localhost"`.
  `urlsplit("//localhost:8000").hostname` is `"localhost"`.
  The condition evaluates to `True`, and the request is permitted without CSRF block.

## Why it matters
RFC 6454 defines an origin as the tuple `(scheme, host, port)`. By ignoring the port and scheme, any other web service running on the same host or loopback address (such as a developer dev-server, local notebook, or container port mapping on port 3000, 8080, etc.) can issue authenticated cross-origin requests against StorageForge whenever `Sec-Fetch-Site` is absent (such as older browser clients, non-browser clients, or reverse proxies stripping fetch metadata).

## Suggested approach
Validate the full `netloc` (or scheme, hostname, and port):
```python
p = urlsplit(origin)
if p.netloc and p.netloc == request.host:
    return None
```
Ensure the port on `Origin` matches the port on `request.host`.

## Done when
- [ ] `same_origin_only` rejects requests where `Origin` has a differing port from `request.host`.
- [ ] A unit test verifies that cross-port requests without `Sec-Fetch-Site` return 403 Forbidden.

## Outcome
**Severity after checking: Low (was Medium).** Confirmed, with the wrong code quoted: there is no Referer fallback. Fixed 2026-11-01 in `b222e78`. **Gemini's `netloc` fix was rejected:** it breaks a proxy that drops the port from Host, which `test_state_changes_come_from_this_origin` requires. Ports are now compared when Host has one, with default ports filled in. Still allowed: a Host with no port, where the port can't be known. Reach is plain HTTP, since modern browsers send `Sec-Fetch-Site` on HTTPS and localhost. Test: `test_plain_http_tells_ports_apart`.
