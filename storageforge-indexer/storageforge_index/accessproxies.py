"""Access proxies (roadmap section 2): what OpenZiti, Teleport, Boundary and Pomerium on a host say they give access to.

These are not networks a host has an address on. Each stands in front of other machines and decides who reaches them, so what a
scan wants from one is its targets: the services a Ziti identity may dial or hosts, the nodes a Teleport cluster knows, the targets
of a Boundary controller, the routes of a Pomerium proxy and who each lets in. Each reader returns one shape:

    {'tool': 'teleport', 'roles': ['auth', 'proxy'], 'cluster': 'lab', 'server': …,
     'targets': [{'name': 'db1', 'address': '10.42.0.9', 'port': '3022', 'kind': 'ssh', 'access': …}]}

A reader is given text a host sent, and that text has already lost its credentials on the host (`confread.SCRUB_AWK` for a file,
a short list of wanted fields for a command). It never raises: what it cannot read is `{'tool': …, 'error': …}`. No user, no
email address and no group is kept: a policy is told by the kinds of thing it asks for, and how many, not by who.
"""
from __future__ import annotations

import ipaddress
import json
import re

import yaml

from . import confread

MAX_INPUT, MAX_TARGETS, MAX_TEXT, MAX_LIST = 4 * 1024 * 1024, 2000, 255, 16
LABELS = {'openziti': 'OpenZiti', 'teleport': 'Teleport', 'boundary': 'Boundary', 'pomerium': 'Pomerium'}


def _text(v, limit: int = MAX_TEXT) -> str | None:
    return str(v)[:limit] if isinstance(v, (str, int)) and not isinstance(v, bool) and str(v) not in ('', '***') else None      # *** is a blanked credential


def _target(name, address=None, port=None, kind=None, access=None, **more) -> dict:
    return {'name': _text(name), 'address': _text(address), 'port': _text(port, 32), 'kind': _text(kind, 32), 'access': _text(access)} | more


def _json(tool: str, text, want: type):
    """The tool's JSON, or the error to return. A tool prints warnings before its JSON: it starts at the first bracket."""
    if not isinstance(text, str) or not text.strip():
        return None, {'tool': tool, 'error': 'nothing read'}
    if len(text) > MAX_INPUT:
        return None, {'tool': tool, 'error': 'more than it should ever print'}
    at = text.find('{' if want is dict else '[')
    try:
        doc = json.loads(text[at:]) if at >= 0 else None
    except (ValueError, RecursionError):
        doc = None
    return (doc, None) if isinstance(doc, want) else (None, {'tool': tool, 'error': 'not the JSON this tool prints'})


def _yaml(text) -> dict | None:
    """A configuration file, cut again by the rule the host cut it with. None when it is not a mapping."""
    if not isinstance(text, str) or not text.strip() or len(text) > MAX_INPUT:
        return None
    try:
        doc = yaml.safe_load(confread.scrub(text))
    except (yaml.YAMLError, RecursionError, ValueError):
        return None
    return doc if isinstance(doc, dict) else None


def _part(doc: dict, name: str) -> dict:
    return doc.get(name) if isinstance(doc.get(name), dict) else {}


def _host_port(value) -> tuple[str | None, str | None]:
    """('10.42.0.9', '3022') from '10.42.0.9:3022', '[fd00::9]:3022' or 'https://db.lab:443/x'. A password in a URL never arrives
    (the host drops that line), and if one did it is cut off here."""
    s = _text(value)
    if not s:
        return None, None
    s = re.sub(r'^[a-z][a-z0-9+.-]*://', '', s).split('/')[0].rsplit('@', 1)[-1]
    m = re.fullmatch(r'\[([0-9a-fA-F:.]+)\](?::(\d+))?|([^:]*)(?::(\d+))?', s)
    if not m:
        return s, None
    return (m[1] or m[3] or None), (m[2] or m[4] or None)


# ── OpenZiti, where a tunneler runs ──
def openziti(text: str) -> dict:
    """`ziti-edge-tunnel tunnel_status`: the identities the tunneler has loaded, and the services each may dial (reach from this
    host, at an address the tunneler intercepts) or bind (this host is where the service comes out)."""
    doc, error = _json('openziti', text, dict)
    if error:
        return error
    data = doc.get('Data') if isinstance(doc.get('Data'), dict) else doc
    if not isinstance(data.get('Identities'), list) and 'TunIpv4' not in data:
        return {'tool': 'openziti', 'error': 'not the JSON this tool prints'}
    identities, targets = [], []
    for i in (data.get('Identities') or [])[:MAX_LIST * 4]:
        if not isinstance(i, dict):
            continue
        services = [s for s in i.get('Services') or [] if isinstance(s, dict)] if isinstance(i.get('Services'), list) else []
        identities.append({'name': _text(i.get('Name')), 'active': i.get('Active') is True, 'loaded': i.get('Loaded') is True, 'controller': _text(_part(i, 'Config').get('ztAPI')),
                           'needs_login': i.get('NeedsExtAuth') is True or i.get('MfaNeeded') is True, 'services': len(services)})
        for s in services:
            if len(targets) >= MAX_TARGETS:
                break
            addresses = []
            for a in s.get('Addresses') if isinstance(s.get('Addresses'), list) else []:
                if isinstance(a, dict) and (where := _text(a.get('HostName') if a.get('IsHost') else a.get('IP'))):
                    addresses.append(where)
            ports = [f'{p["Low"]}' if p.get('Low') == p.get('High') else f'{p.get("Low")}-{p.get("High")}' for p in s.get('Ports') or []
                     if isinstance(p, dict) and isinstance(p.get('Low'), int)] if isinstance(s.get('Ports'), list) else []
            may = _part(s, 'Permissions')
            kind = ' and '.join(k for k, on in (('dial', may.get('Dial') is True), ('bind', may.get('Bind') is True)) if on) or None
            targets.append(_target(s.get('Name'), addresses[0] if addresses else None, ports[0] if ports else None, kind, None, addresses=addresses[:MAX_LIST], ports=ports[:MAX_LIST],
                                   protocols=[x[:8] for x in s.get('Protocols') or [] if isinstance(x, str)][:4] if isinstance(s.get('Protocols'), list) else [],
                                   identity=_text(i.get('Name')), hosted_here=may.get('Bind') is True))
    return {'tool': 'openziti', 'roles': ['tunneler'], 'cluster': None, 'server': next((i['controller'] for i in identities if i['controller']), None),
            'interface': _text(data.get('TunName'), 15), 'identities': identities, 'targets': targets}


# ── Teleport ──
_PAIR = re.compile(r'"(\w+)":\s*(?:"([^"]*)"|(true|false))')


def _pairs(text) -> list[tuple[str, str | bool]]:
    """`"name": "value"` pairs in the order printed. The host sends only the fields asked for (grep -o), so that a label, a
    command or a user name never leaves it; the whole JSON reads the same way."""
    if not isinstance(text, str) or len(text) > MAX_INPUT:
        return []
    return [(m[1], m[2] if m[3] is None else m[3] == 'true') for m in _PAIR.finditer(text)]


def _on(section) -> bool:
    return isinstance(section, dict) and str(section.get('enabled')).strip().lower() in ('true', 'yes', 'on', '1')


def teleport(status: str = '', nodes: str = '', config: str = '', login: str = '') -> dict:
    """`tctl status --format=json` (or its text, from a Teleport that has no such flag) and the nodes of `tctl get nodes
    --format=json` on an auth server, `/etc/teleport.yaml` without its token on any Teleport host, and `tsh status --format=json`
    where root is logged in. Each node the cluster knows is a target: its name and where its SSH service answers, or that it is
    reached through the proxy alone. In a node, `kind` is printed first and `spec` after `metadata`, so the last `hostname` and
    `addr` before the next node are the node's own and not a label that happens to be called the same."""
    if not any(isinstance(t, str) and t.strip() for t in (status, nodes, config, login)):
        return {'tool': 'teleport', 'error': 'nothing read'}
    cluster = {}
    for key, value in _pairs(status):            # the cluster comes first in what tctl prints, before its authorities
        if key in ('name', 'version') and isinstance(value, str) and key not in cluster:
            cluster[key] = value
    for key, pattern in (('name', r'^Cluster:?\s+(\S+)'), ('version', r'^Version:?\s+(\S+)')):
        if key not in cluster and isinstance(status, str) and (m := re.search(pattern, status[:MAX_INPUT], re.M)):
            cluster[key] = m[1]
    targets, cur = [], None
    for key, value in _pairs(nodes):
        if key == 'kind' and value == 'node':
            if len(targets) >= MAX_TARGETS:
                break
            cur = _target(None, None, None, 'ssh', None)
            targets.append(cur)
        elif cur is None:
            continue
        elif key == 'hostname' and isinstance(value, str):
            cur['name'] = _text(value)
        elif key == 'addr' and isinstance(value, str):
            cur['address'], cur['port'] = _host_port(value)
        elif key == 'use_tunnel' and value is True:
            cur['access'] = 'reached through the proxy'
    targets = [t for t in targets if t['name'] or t['address']]
    doc = _yaml(config) or {}
    roles = [name for name, section in (('auth', 'auth_service'), ('proxy', 'proxy_service'), ('node', 'ssh_service'), ('app', 'app_service'), ('database', 'db_service'),
                                        ('kubernetes', 'kubernetes_service')) if _on(doc.get(section))]
    main = _part(doc, 'teleport')
    joins = main.get('proxy_server') or main.get('auth_server') or main.get('auth_servers')
    public = _part(doc, 'proxy_service').get('public_addr')
    signed_in = {}
    for key, value in _pairs(login):
        if key in ('profile_url', 'cluster', 'valid_until') and isinstance(value, str) and key not in signed_in:
            signed_in[key] = value[:MAX_TEXT]
    if not (cluster or targets or roles or main or signed_in):
        return {'tool': 'teleport', 'error': 'not what Teleport prints'}
    return {'tool': 'teleport', 'roles': roles, 'cluster': _text(cluster.get('name')) or signed_in.get('cluster'), 'version': _text(cluster.get('version'), 32),
            'server': _text(joins[0] if isinstance(joins, list) and joins else joins), 'public': _text(public[0] if isinstance(public, list) and public else public),
            'name': _text(main.get('nodename')), 'targets': targets,
            'login': {'cluster': signed_in.get('cluster'), 'proxy': signed_in.get('profile_url'), 'valid_until': signed_in.get('valid_until')} if signed_in else None}


# ── HashiCorp Boundary ──
def boundary(targets: str = '', config: str = '') -> dict:
    """`boundary targets list -recursive -format json`, which answers only where a token is at hand, and the controller's or
    worker's configuration without its keys and database address: what this host is to Boundary, and where it listens."""
    have = [isinstance(t, str) and bool(t.strip()) for t in (targets, config)]
    if not any(have):
        return {'tool': 'boundary', 'error': 'nothing read'}
    listed, error = _json('boundary', targets, dict) if have[0] else (None, None)
    out = []
    for t in (listed.get('items') if isinstance(listed, dict) and isinstance(listed.get('items'), list) else [])[:MAX_TARGETS]:
        if not isinstance(t, dict):
            continue
        port = _part(t, 'attributes').get('default_port')
        sources = t.get('host_source_ids') if isinstance(t.get('host_source_ids'), list) else []
        out.append(_target(t.get('name') or t.get('id'), t.get('address'), port, t.get('type'), None if t.get('address') else f'{len(sources)} host source(s)' if sources else None,
                           scope=_text(_part(t, 'scope').get('name'))))
    text = confread.scrub(config) if have[1] and len(config) <= MAX_INPUT else ''
    roles = [role for role in ('controller', 'worker') if re.search(rf'^\s*{role}\s*\{{', text, re.M)]

    def value(key):
        m = re.search(rf'^\s*{key}\s*=\s*"([^"]*)"', text, re.M)
        return m[1][:MAX_TEXT] if m and m[1] else None
    upstream = re.search(r'^\s*initial_upstreams\s*=\s*\[\s*"([^"]*)"', text, re.M)
    if have[0] and error and not roles:
        return error
    if not out and not roles and listed is None:
        return {'tool': 'boundary', 'error': 'not a Boundary configuration'}
    return {'tool': 'boundary', 'roles': roles, 'cluster': None, 'server': upstream[1][:MAX_TEXT] if upstream and upstream[1] else None, 'public': value('public_addr') or value('public_cluster_addr'),
            'name': value('name'), 'targets': out, 'targets_read': listed is not None}


# ── Pomerium ──
_PPL_WORDS = {'allow', 'deny', 'and', 'or', 'not', 'nor'}


def _criteria(policy, depth: int = 0) -> set:
    """The kinds of thing a policy asks for (`domain`, `email`, `groups`, `claim`): never the values, which are people."""
    found = set()
    if depth > 8:
        return found
    for item in policy if isinstance(policy, list) else [policy]:
        if not isinstance(item, dict):
            continue
        for key, inner in list(item.items())[:64]:
            if not isinstance(key, str):
                continue
            if key in _PPL_WORDS:
                found |= _criteria(inner, depth + 1)
            elif depth and not (key in ('accept', 'authenticated_user') and inner is not True):
                found.add(key.split('/')[0][:32])
    return found


def _who(route: dict) -> tuple[str, bool]:
    """(who gets in, in words; whether that is everyone)."""
    asks = _criteria(route.get('policy')) if route.get('policy') is not None else set()
    denies = any(isinstance(p, dict) and 'deny' in p for p in (route.get('policy') if isinstance(route.get('policy'), list) else [route.get('policy')]))
    if route.get('allow_public_unauthenticated_access') is True or ('accept' in asks and not denies):
        return 'public: anyone, without signing in', True
    if 'accept' in asks and denies:
        # not called public, since the deny rules may keep most people out; but "by policy" alone would hide that everyone is let in first
        return 'everyone is allowed, except what the deny rules exclude', False
    if route.get('allow_any_authenticated_user') is True or asks == {'authenticated_user'}:
        return 'anyone who can sign in', False
    counts = [f'{len(route[k])} {word}' for k, word in (('allowed_users', 'user(s)'), ('allowed_domains', 'domain(s)'), ('allowed_idp_claims', 'claim(s)')) if isinstance(route.get(k), (list, dict)) and route[k]]
    if asks or counts:
        return 'by policy: ' + ', '.join(sorted(asks - {'accept'}) + counts), False
    return 'no policy: nobody is let in', False


def pomerium(text: str) -> dict:
    """`/etc/pomerium/config.yaml`, which arrives without its secrets, keys and request headers: each route, where it sends what
    it accepts, and who it lets in. A route that lets in anyone without a sign-in is public, and is marked so."""
    if not isinstance(text, str) or not text.strip():
        return {'tool': 'pomerium', 'error': 'nothing read'}
    if len(text) > MAX_INPUT:
        return {'tool': 'pomerium', 'error': 'larger than a configuration file should be'}
    doc = _yaml(text)
    listed = None if doc is None else doc.get('routes') if isinstance(doc.get('routes'), list) else doc.get('policy') if isinstance(doc.get('policy'), list) else None
    if doc is None or (listed is None and not any(k in doc for k in ('authenticate_service_url', 'pomerium_debug', 'idp_provider', 'address', 'routes'))):
        return {'tool': 'pomerium', 'error': 'not a Pomerium configuration'}
    targets = []
    for r in (listed or [])[:MAX_TARGETS]:
        if not isinstance(r, dict) or not _text(r.get('from')):
            continue
        to = r.get('to')[0] if isinstance(r.get('to'), list) and r.get('to') else r.get('to')
        to = None if to == '***' else to                   # blanked on the host: it held a password
        host, port = _host_port(to)
        who, public = _who(r)
        kind = 'redirect' if isinstance(r.get('redirect'), dict) else 'fixed answer' if isinstance(r.get('response'), dict) else (re.match(r'[a-z][a-z0-9+.-]*(?=://)', str(r['from'])) or [None])[0]
        path = _text(r.get('prefix') or r.get('path'))
        targets.append(_target(re.sub(r'//[^/@]*@', '//', str(r['from'])) + (path or ''), host, port, kind, who, public=public,
                               upstream=re.sub(r'//[^/@]*@', '//', _text(to) or '') or None, unverified=r.get('tls_skip_verify') is True))
    return {'tool': 'pomerium', 'roles': ['proxy'], 'cluster': None, 'server': _text(doc.get('authenticate_service_url')), 'public': None, 'targets': targets}


READERS = {'openziti': openziti, 'teleport': teleport, 'boundary': boundary, 'pomerium': pomerium}


def is_address(value) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except (ValueError, TypeError):
        return False


def sentence(reading: dict) -> str:
    """What the map says about one access proxy on a host."""
    name = LABELS.get(reading.get('tool'), 'An access proxy')
    if reading.get('error'):
        return f'{name} is here, and what it gives access to could not be read'
    targets, roles = reading.get('targets') or [], ' and '.join(reading.get('roles') or [])
    what = {'openziti': 'service(s)', 'teleport': 'node(s)', 'boundary': 'target(s)', 'pomerium': 'route(s)'}.get(reading.get('tool'), 'target(s)')
    open_to_all = [t['name'] for t in targets if t.get('public')]
    text = f'{name}{f" ({roles})" if roles else ""}' + (f' of {reading["cluster"]}' if reading.get('cluster') else '') + f': {len(targets)} {what}'
    if reading.get('tool') == 'boundary' and not reading.get('targets_read'):
        text = f'{name}{f" ({roles})" if roles else ""}: its targets are kept at the controller and need a token to list'
    if open_to_all:
        text += '. Public without a sign-in: ' + ', '.join(str(n) for n in open_to_all[:8]) + (f' and {len(open_to_all) - 8} more' if len(open_to_all) > 8 else '')
    return text


def inventory_targets(conn) -> list[dict]:
    """Generate Teleport and Boundary target descriptors from StorageForge's scanned host inventory."""
    rows = conn.all('SELECT hostname, ssh_host, ssh_port, os_info FROM hosts ORDER BY hostname')
    out = []
    for hostname, ssh_host, ssh_port, os_info in rows:
        addr = ssh_host or hostname
        port = int(ssh_port or 22)
        out.append({
            'host': hostname,
            'address': addr,
            'port': port,
            'os': os_info or '',
            'teleport_node': {'kind': 'node', 'hostname': hostname, 'addr': f'{addr}:{port}', 'labels': {'managed_by': 'storageforge'}},
            'boundary_target': {'name': hostname, 'type': 'ssh', 'address': addr, 'default_port': port},
        })
    return out


def teleport_recording_check(conn, host: str, reading: dict | None = None, recording_path: str = '/var/lib/teleport/log') -> dict:
    """Check whether a Teleport host's session recording directory sits on a ZFS or btrfs mount covered by a retention hold."""
    rows = conn.all("""SELECT m.mount_point, m.fs_type FROM mounts m JOIN hosts h ON h.host_id = m.host_id
                       WHERE h.hostname = :h""", {'h': host})
    best_mp, best_fs = None, None
    for mp, fstype in rows:
        if recording_path == mp or recording_path.startswith(str(mp).rstrip('/') + '/'):
            if best_mp is None or len(str(mp)) > len(best_mp):
                best_mp, best_fs = str(mp), str(fstype or '')
    holds = conn.all("SELECT dataset FROM security_retention_holds WHERE host = :h AND status IN ('held', 'active')", {'h': host})
    has_hold = bool(holds) and best_fs in ('zfs', 'btrfs')
    return {
        'host': host,
        'recording_path': recording_path,
        'mount_point': best_mp,
        'fstype': best_fs,
        'hold': has_hold,
        'protected': bool(best_fs in ('zfs', 'btrfs') and has_hold),
    }
