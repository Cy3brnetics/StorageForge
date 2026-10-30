---
id: GM-06
status: open
severity: high
effort: S
area: "[[API, Auth and Security]]"
tags: [finding, security, alerts, ssrf, gemini-audit]
found: 2026-10-29
---
# GM-06 Alert settings leak secret tokens on URL downgrade/port change and allow SSRF via IPv6 transition addresses and DNS rebinding

## Location
- `storageforge_index/alerts.py:59-81` (`save_settings()`, `_host()`)
- `storageforge_index/alerts.py:84-114` (`_check_target()`, `_post()`)
- `storageforge_index/server.py:1118-1132` (`PUT /api/deploy/settings`, `POST /api/deploy/settings/test`)

## Mechanics & Root Cause
### 1. Scheme Downgrade & Port Change Preserve Stored Secret Tokens (`alerts.py:60-81`)
When saving alert settings where a secret field (`token`, `password`) is submitted as the UI mask `'••••••'`, `save_settings()` checks whether the target host changed:
```python
for ch, fields in (('ntfy', ('url', 'topic', 'token')), ('gotify', ('url', 'token')), ('webhook', ('url',))):
    old_host = _host(cur[ch].get('url'))
    for f in fields:
        given = (new.get(ch) or {}).get(f)
        v = str(cur[ch].get(f, '') if given is None else given or '').strip()
        if (ch, f) in SECRET_FIELDS and (given is None or v == '••••••'):    # the stored token, kept
            # ...unless the server changed: then it is not sent there until typed in again
            v = cur[ch].get(f, '') if _host(cur[ch].get('url')) == old_host else ''
        if f == 'url' and v:
            _check_target(v)
        cur[ch][f] = v.rstrip('/') if f == 'url' else v
    cur[ch]['enabled'] = bool((new.get(ch) or {}).get('enabled', cur[ch].get('enabled'))) and bool(cur[ch]['url'])
old_smtp = (cur['smtp'].get('host') or '').lower()
for f in ('host', 'port', 'user', 'password', 'from', 'to'):
    given = (new.get('smtp') or {}).get(f)
    v = cur['smtp'].get(f, '') if given is None else given
    if f == 'password' and (given is None or v == '••••••'):
        v = cur['smtp'].get('password', '') if (cur['smtp'].get('host') or '').lower() == old_smtp else ''
```
And `_host()` (`lines 80-81`) is defined as:
```python
def _host(url: str | None) -> str:
    return (urllib.parse.urlparse(url or '').hostname or '').lower()
```
1. **HTTP Scheme Downgrade & Port Redirect**: Because `_host()` only compares `.hostname.lower()` (ignoring `.scheme` and `.port`), changing `https://ntfy.lan/alerts` to `http://ntfy.lan:8080/alerts` (or another service on a different port of the same host) keeps `_host(...) == old_host` `True`. Clicking Test (`POST /api/deploy/settings/test`) then transmits the stored `Bearer` token or `X-Gotify-Key` in cleartext HTTP or to the unprivileged port!
2. **SMTP TLS Stripping & Port Change**: Similarly, for `smtp` (`lines 74-79`), `old_smtp` only compares `host` and ignores changes to `port` or `tls` (`cur['smtp']['tls'] = False`), allowing the stored SMTP password to be sent without TLS or to an arbitrary port on the same hostname.
3. **Missing `@password_confirmed`**: Neither `PUT /api/deploy/settings` nor `POST /api/deploy/settings/test` requires `@password_confirmed` (`server.py:1118-1132`).

### 2. IPv6 Transition Addresses & TOCTOU DNS Rebinding in `_check_target()` (`alerts.py:84-114`)
```python
def _check_target(url: str) -> None:
    """Alert URLs reach external notification servers, never loopback or link-local metadata endpoints."""
    u = urllib.parse.urlparse(url)
    if u.scheme not in ('http', 'https') or not u.hostname:
        raise ValueError(f'alert URL must be http:// or https://, got {url!r}')
    try:
        infos = socket.getaddrinfo(u.hostname, u.port or (443 if u.scheme == 'https' else 80), type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError(f'cannot resolve {u.hostname}: {exc}') from None
    for *_, sockaddr in infos:
        ip = ipaddress.ip_address(sockaddr[0].split('%')[0])
        ip = getattr(ip, 'ipv4_mapped', None) or ip
        if ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_multicast:
            raise ValueError(f'alert URL may not point to {ip} ({u.hostname})')
```
1. **TOCTOU DNS Rebinding**: `_check_target(url)` resolves `u.hostname` via `socket.getaddrinfo()`, discards the resolved IP, and then `_opener.open(req, timeout=10)` (`line 112`) resolves `u.hostname` a **second time** when opening the socket. An attacker-controlled `TTL=0` DNS record can return a public IP during `_check_target()` and `127.0.0.1` or `169.254.169.254` during `_opener.open()`.
2. **IPv6 Transition Prefixes (`sixtofour`, `teredo`, NAT64)**: While line 94 unwraps `ip.ipv4_mapped`, it does not unwrap `ip.sixtofour` (`2002:7f00:0001::` -> `127.0.0.1`, `2002:a9fe:a9fe::` -> `169.254.169.254`) or `ip.teredo`.

## Impact
1. Stored notification tokens and SMTP passwords can be exfiltrated via `https -> http` scheme downgrade or port changes without re-authenticating.
2. SSRF protection (`SF-06`) can be bypassed via DNS rebinding between `_check_target()` and `_opener.open()`.

## Remediation
1. Replace `_host(url)` with an origin tuple `(u.scheme.lower(), (u.hostname or '').lower(), u.port or (443 if u.scheme == 'https' else 80))`, and for SMTP compare `(host.lower(), int(port), bool(tls))`.
2. In `_check_target()`, also unwrap `getattr(ip, 'sixtofour', None)` and `getattr(ip, 'teredo', None)` (and check `ip.is_reserved`), and pin the resolved IP address in the HTTP transport so `_opener.open()` cannot re-resolve a different IP.
3. Add `@password_confirmed` to `PUT /api/deploy/settings` and `POST /api/deploy/settings/test`.

## Done when
- [ ] Changing an alert channel's host, scheme, port, or TLS setting clears masked secrets.
- [ ] HTTP alert delivery connects to the IP verified by `_check_target` (preventing DNS rebinding).
- [ ] Alert settings endpoints require `@password_confirmed`.
