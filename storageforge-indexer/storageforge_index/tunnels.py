"""Tunnels that publish a service (roadmap section 2, part 4: exposure): what Cloudflare Tunnel, frp and ngrok are configured to make
public, read from their own configuration files.

A tunnel makes a service public with no port open on the host or on the router, so nothing in a firewall reading shows it. Each
reader takes the text of a configuration file a host sent and returns one shape:

    {'tool': 'cloudflared', 'server': …, 'published': [{'public': 'https://app.example.com', 'local': 'localhost:8080', 'protocol': 'http'}]}

These files hold the tunnel's credentials. The collector on the host blanks the value of those lines before anything is sent
(`SECRET_LINE` picks the lines, `TUNNEL_AWK` blanks them), and the readers never copy a key they were not written to copy, so a token
that gets past the first is dropped by the second. The line itself stays, so a hostname next to a credential word is still read. A reader never raises: what it cannot read is `{'tool': …, 'error': …}`.
"""
from __future__ import annotations

import configparser
import re
import tomllib

import yaml

MAX_INPUT, MAX_PUBLISHED, MAX_TEXT = 256 * 1024, 500, 255

# A line of a configuration file that holds a credential, in any of the three tools' spellings. The host-side collector blanks the
# value of these lines with awk, so this is written as an extended regular expression awk also takes.
SECRET_LINE = r'(token|secret|password|passwd|credential|authtoken|api_?key|priv(ate)?_?key|oidc|cert_?pem)'
_SECRET = re.compile(SECRET_LINE, re.IGNORECASE)

# The same rule for the host, in awk: a credential line keeps what is before its first `:` or `=` and its value becomes "***". The mask
# is quoted because a bare `*` is a YAML alias and a bare word is not a TOML value, so the file still parses. A line with no `:` or `=`
# has no name to keep and goes.
TUNNEL_AWK = 'tolower($0) ~ re { if (match($0, /[:=]/)) print substr($0, 1, RSTART) " \\"***\\""; next } { print }'


def scrub(text: str) -> str:
    """The file with the value of each credential line blanked, for when the text itself is kept or shown."""
    out = []
    for line in text.splitlines():
        if not _SECRET.search(line):
            out.append(line)
        elif (m := re.search(r'[:=]', line)):
            out.append(line[:m.end()] + ' "***"')
    return '\n'.join(out)


def _text(v) -> str | None:
    return str(v)[:MAX_TEXT] if isinstance(v, (str, int)) and not isinstance(v, bool) and str(v) not in ('', '***') else None      # *** is a blanked credential


def _input(tool: str, text):
    if not isinstance(text, str) or not text.strip():
        return {'tool': tool, 'error': 'nothing read'}
    if len(text) > MAX_INPUT:
        return {'tool': tool, 'error': 'larger than a configuration file should be'}
    return None


def _yaml(tool: str, text: str):
    try:
        doc = yaml.safe_load(text)
    except (yaml.YAMLError, RecursionError, ValueError):
        doc = None
    return (doc, None) if isinstance(doc, dict) else (None, {'tool': tool, 'error': 'not this tool\'s configuration'})


def _local(service) -> tuple[str | None, str | None]:
    """('localhost:8080', 'http') from 'http://localhost:8080', and the like."""
    s = _text(service)
    if not s:
        return None, None
    m = re.fullmatch(r'([a-z][a-z0-9+.-]*)://([^/]+).*', s)
    return (m.group(2), m.group(1)) if m else (s, None)


def cloudflared(text: str) -> dict:
    """`/etc/cloudflared/config.yml`: each ingress rule with a hostname is public at that name. A tunnel run with only a token keeps
    its routes at Cloudflare, and then there is nothing here to read: `remote` says so."""
    if (bad := _input('cloudflared', text)):
        return bad
    doc, error = _yaml('cloudflared', scrub(text))
    if error:
        return error
    published = []
    for rule in (doc.get('ingress') if isinstance(doc.get('ingress'), list) else [])[:MAX_PUBLISHED]:
        if not isinstance(rule, dict) or not _text(rule.get('hostname')):
            continue                                   # the last rule has no hostname: it is what unmatched requests get
        local, protocol = _local(rule.get('service'))
        published.append({'public': f'https://{_text(rule["hostname"])}' + (_text(rule.get('path')) or ''), 'local': local, 'protocol': protocol})
    return {'tool': 'cloudflared', 'server': 'Cloudflare', 'tunnel': _text(doc.get('tunnel')), 'published': published, 'remote': not published}


def _frp_proxy(name, p: dict, server: str | None) -> list[dict]:
    kind = _text(p.get('type')) or 'tcp'
    host, port = _text(p.get('localIP') or p.get('local_ip')) or '127.0.0.1', _text(p.get('localPort') or p.get('local_port'))
    local = f'{host}:{port}' if port else None
    out = []
    if kind in ('http', 'https', 'tcpmux'):
        domains = p.get('customDomains') or p.get('custom_domains') or []
        domains = [d.strip() for d in domains.split(',')] if isinstance(domains, str) else domains if isinstance(domains, list) else []
        sub = _text(p.get('subdomain'))
        for d in [d for d in domains if isinstance(d, str) and d][:16] + ([f'{sub}.(the server\'s domain)'] if sub else []):
            out.append({'public': f'{"https" if kind == "https" else "http"}://{d[:MAX_TEXT]}', 'local': local, 'protocol': kind, 'name': _text(name)})
    elif kind in ('tcp', 'udp'):
        remote = _text(p.get('remotePort') or p.get('remote_port'))
        if remote:
            out.append({'public': f'{server or "(the frp server)"}:{remote}/{kind}', 'local': local, 'protocol': kind, 'name': _text(name)})
    # stcp, xtcp and sudp are reached only by a visitor that holds the same key: not public
    return out


def frp(text: str) -> dict:
    """`frpc.toml`, or the older `frpc.ini`: each proxy with a remote port or a domain is public at the frp server."""
    if (bad := _input('frp', text)):
        return bad
    text = scrub(text)
    proxies, server = [], None
    try:
        doc = tomllib.loads(text)
        server = _text(doc.get('serverAddr'))
        listed = doc.get('proxies') if isinstance(doc.get('proxies'), list) else []
        proxies = [(p.get('name'), p) for p in listed if isinstance(p, dict)]
        if not server and not proxies:
            raise ValueError('not the TOML form')
    except (tomllib.TOMLDecodeError, ValueError, RecursionError):
        ini = configparser.ConfigParser(interpolation=None, strict=False)
        try:
            ini.read_string(text)
        except configparser.Error:
            return {'tool': 'frp', 'error': 'not this tool\'s configuration'}
        if not ini.sections():
            return {'tool': 'frp', 'error': 'not this tool\'s configuration'}
        server = _text(ini.get('common', 'server_addr', fallback=None))
        proxies = [(name, dict(ini[name])) for name in ini.sections() if name != 'common']
    published = []
    for name, p in proxies[:MAX_PUBLISHED]:
        published += _frp_proxy(name, p, server)
    return {'tool': 'frp', 'server': server, 'published': published[:MAX_PUBLISHED], 'remote': False}


def ngrok(text: str) -> dict:
    """`ngrok.yml` (versions 2 and 3): tunnels and endpoints with a name of their own are public there; one without gets a random
    name from ngrok each time it starts, which is public all the same."""
    if (bad := _input('ngrok', text)):
        return bad
    doc, error = _yaml('ngrok', scrub(text))
    if error:
        return error
    published = []
    tunnels = doc.get('tunnels') if isinstance(doc.get('tunnels'), dict) else {}
    for name, t in list(tunnels.items())[:MAX_PUBLISHED]:
        if not isinstance(t, dict):
            continue
        protocol = _text(t.get('proto')) or 'http'
        public = _text(t.get('domain') or t.get('hostname') or t.get('remote_addr'))
        addr = _text(t.get('addr'))
        published.append({'public': (f'https://{public}' if protocol in ('http', 'https', 'tls') else public) if public else '(a random ngrok address)',
                          'local': f'localhost:{addr}' if addr and addr.isdigit() else addr, 'protocol': protocol, 'name': _text(name)})
    for e in (doc.get('endpoints') if isinstance(doc.get('endpoints'), list) else [])[:MAX_PUBLISHED]:
        if not isinstance(e, dict):
            continue
        upstream = e.get('upstream') if isinstance(e.get('upstream'), dict) else {}
        local, protocol = _local(upstream.get('url'))
        published.append({'public': _text(e.get('url')) or '(a random ngrok address)', 'local': local, 'protocol': protocol, 'name': _text(e.get('name'))})
    return {'tool': 'ngrok', 'server': 'ngrok', 'published': published[:MAX_PUBLISHED], 'remote': False}


READERS = {'cloudflared': cloudflared, 'frp': frp, 'ngrok': ngrok}
LABELS = {'cloudflared': 'Cloudflare Tunnel', 'frp': 'frp', 'ngrok': 'ngrok', 'newt': 'Pangolin'}


def sentence(reading: dict) -> str:
    """What the security view says about one host's tunnel."""
    name = LABELS.get(reading.get('tool'), 'a tunnel')
    if reading.get('error'):
        return f'{name} is here, and its configuration could not be read: what it publishes is not known'
    published = reading.get('published') or []
    if not published:
        return (f'{name} runs with its routes kept at {reading.get("server") or "its server"}: what it publishes cannot be read from this host'
                if reading.get('remote') else f'{name} is configured and publishes nothing')
    return f'Public through {name}: ' + ', '.join(f'{p["public"]} → {p["local"] or "?"}' for p in published[:8]) + (f' and {len(published) - 8} more' if len(published) > 8 else '')
