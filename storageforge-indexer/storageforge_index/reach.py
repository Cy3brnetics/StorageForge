"""Can A reach B? Worked out from the routes and firewall rules hosts reported. Nothing is sent to find out.

The answer walks the path a packet would take: out of A (its route to B, its output rules), across whatever is between them
(a directly attached network, or a router that may or may not be scanned), and into B (its forward rules for a published port,
its input rules for a listener, or nothing listening at all). The first rule that decides it is named. Every hop that was not
read is a blind spot and is listed, and a blind spot can turn "allowed" into "allowed as far as we can see", never the other way.

    verdict: allowed, blocked, or unknown when a part that decides it could not be read or understood
"""
from __future__ import annotations

import ipaddress

from . import exposure, inframeasure, netfacts, workloads
from .db import Conn

CAVEAT = 'Per configuration, from the last readings. Nothing was sent to test it.'
MAX_HOPS = 8


def _ip(text):
    try:
        return ipaddress.ip_address(str(text))
    except ValueError:
        return None


class Fleet:
    """Everything hosts reported, indexed by address. Pure once loaded, so tests can build it directly."""

    def __init__(self, hosts: dict):
        self.hosts = hosts          # name → {'net': ..., 'infra': ..., 'containers': [...]}
        self.by_addr: dict = {}
        for name, h in hosts.items():
            for i in (h.get('net') or {}).get('interfaces') or []:
                for a in i.get('addresses') or []:
                    ip = _ip(a.get('ip'))
                    if ip and not ip.is_loopback and not ip.is_link_local:
                        self.by_addr[str(ip)] = (name, i['name'])
        self.by_guest: dict = {}
        for name, h in hosts.items():
            for c in h.get('containers') or []:
                self.by_guest[c.get('name')] = (name, c)

    def address_of(self, host: str, toward: str | None = None) -> str | None:
        """An address of this host, preferring the one on a network shared with `toward`."""
        ifaces = (self.hosts.get(host, {}).get('net') or {}).get('interfaces') or []
        addrs = [(a['ip'], a.get('prefix')) for i in ifaces if i['kind'] not in ('loopback', 'veth') and not i.get('master') for a in i.get('addresses') or [] if _ip(a.get('ip')) and not _ip(a['ip']).is_loopback and not _ip(a['ip']).is_link_local]
        peer = _ip(toward) if toward else None
        if peer:
            for ip, prefix in addrs:
                try:
                    if peer in ipaddress.ip_interface(f'{ip}/{prefix}').network:
                        return ip
                except (ValueError, TypeError):
                    pass
        return addrs[0][0] if addrs else None


def load(conn: Conn) -> Fleet:
    return Fleet({name: {'net': netfacts.reading(conn, name), 'infra': inframeasure.reading(conn, name), 'containers': workloads.containers_of(conn, name)}
                  for (name,) in conn.all('SELECT hostname FROM hosts')})


def route_to(net: dict, dest: str) -> dict | None:
    """The longest matching route, as the kernel would pick it."""
    ip = _ip(dest)
    if not ip:
        return None
    best, best_len = None, -1
    for r in (net or {}).get('routes') or []:
        if r.get('family') != ip.version or r.get('table', 'main') != 'main':
            continue
        if r.get('dst') == 'default':
            length = 0
        else:
            try:
                n = ipaddress.ip_network(r['dst'], strict=False)
            except (ValueError, TypeError, KeyError):
                continue
            if ip not in n:
                continue
            length = n.prefixlen
        if length > best_len or (length == best_len and (r.get('metric') or 0) < ((best or {}).get('metric') or 0)):
            best, best_len = r, length
    return best


def _fw_readable(h: dict) -> dict | None:
    fw = (h.get('infra') or {}).get('firewall')
    return fw if fw and fw.get('readable') else None


def _dnat(fleet: Fleet, host: str | None, dst_ip, port: int, proto: str, src_ip) -> tuple | None:
    """A port forward on this host that this packet matches: (rule, address, port, interface it leaves by). Only a device's: a Linux host's DNAT is its containers, which are handled by name."""
    if not host:
        return None
    h = fleet.hosts[host]
    fw = _fw_readable(h)
    if not fw or not (h.get('infra') or {}).get('device'):
        return None
    iif = fleet.by_addr.get(dst_ip, (None, None))[1]
    for rule in fw.get('nat') or []:
        if rule.get('action') != 'dnat' or not rule.get('to_addr') or (rule.get('proto') and proto not in str(rule['proto']).split(',')):
            continue
        if not rule.get('dports') or not exposure.port_matches(rule['dports'], port):
            continue
        if not exposure._ifname_match(rule.get('iif'), iif) or (rule.get('daddr') and rule['daddr'] != dst_ip):
            continue
        out = route_to(h.get('net'), rule['to_addr'])
        return rule, rule['to_addr'], rule.get('to_port') or port, (out or {}).get('dev')
    return None


def _hop(name: str, what: str, verdict: str, rule=None, why=None) -> dict:
    return {'at': name, 'what': what, 'verdict': verdict, 'rule': rule, 'why': why or []}


def _decided(res: dict) -> str:
    """accept, drop, or unknown when a rule on the path could not be understood and might have let it through."""
    if res['verdict'] == 'unknown' or (res['verdict'] != 'accept' and res.get('may_allow')):
        return 'unknown'
    return 'accept' if res['verdict'] == 'accept' else 'drop'


def query(fleet: Fleet, src: str, dst: str, port: int, proto: str = 'tcp') -> dict:
    """src, dst: a scanned host's name, an address, or a container's name for dst."""
    blind: list[str] = []
    hops: list[dict] = []
    src_host = src if src in fleet.hosts else fleet.by_addr.get(src, (None,))[0]
    src_ip = _ip(src) and src
    container, dst_host, dst_ip = None, None, None
    if dst in fleet.hosts:
        dst_host = dst
    elif dst in fleet.by_addr:
        dst_host, dst_ip = fleet.by_addr[dst][0], dst
    elif dst in fleet.by_guest:
        dst_host, container = fleet.by_guest[dst]
    elif _ip(dst):
        dst_ip = dst
    else:
        return {'verdict': 'unknown', 'from': src, 'to': dst, 'port': port, 'proto': proto, 'hops': [], 'blind_spots': [f'{dst} is not a scanned host, container or address'], 'caveat': CAVEAT}
    if dst_host and not dst_ip:
        dst_ip = fleet.address_of(dst_host, fleet.address_of(src_host) if src_host else src_ip)
    if src_host and not src_ip:
        src_ip = fleet.address_of(src_host, dst_ip)

    out = {'from': src, 'to': dst, 'port': port, 'proto': proto, 'from_host': src_host, 'to_host': dst_host, 'from_ip': src_ip, 'to_ip': dst_ip, 'hops': hops, 'blind_spots': blind, 'caveat': CAVEAT}
    if not src_host and not src_ip:
        return {**out, 'verdict': 'unknown', 'blind_spots': [f'{src} is not a scanned host or an address']}

    # out of A
    if src_host:
        h = fleet.hosts[src_host]
        fw = _fw_readable(h)
        route = route_to(h.get('net'), dst_ip) if dst_ip else None
        if not h.get('net'):
            blind.append(f'the routes of {src_host} have not been read')
        elif not route:
            hops.append(_hop(src_host, 'no route to it', 'drop', 'no matching route'))
            return {**out, 'verdict': 'blocked', 'decided_by': f'{src_host} has no route to {dst_ip}'}
        else:
            how = f'via {route["via"]}' if route.get('via') else 'directly attached'
            hops.append(_hop(src_host, f'{route.get("dev")} {how}', 'accept', f'route {route.get("dst")}'))
        if fw and fw.get('backends'):
            res = exposure.kernel_path(fw, 'output', {'proto': proto, 'port': port, 'oif': (route or {}).get('dev'), 'daddr': dst_ip, 'saddr': src_ip, 'family': 'ip6' if ':' in str(dst_ip) else 'ip'})
            state = _decided(res)
            hops.append(_hop(src_host, 'output rules', state, res['rule'], res['unknown']))
            if state == 'drop':
                return {**out, 'verdict': 'blocked', 'decided_by': f'{src_host}: {res["rule"]}'}
            if state == 'unknown':
                blind.append(f'an output rule on {src_host} could not be understood')
        elif not fw:
            blind.append(f'the firewall of {src_host} has not been read: outgoing rules are not counted')

    # across the middle: router by router, each one's own routes saying where next
    here = fleet.hosts[src_host].get('net') if src_host else None
    route = route_to(here, dst_ip) if here and dst_ip else None
    seen = {src_host}
    for _ in range(MAX_HOPS):
        gateway = (route or {}).get('via')
        if not gateway:
            break
        router = fleet.by_addr.get(gateway, (None,))[0]
        if not router:
            blind.append(f'{gateway} routes this and is not scanned: whatever it filters is out of sight')
            break
        if router in seen:
            hops.append(_hop(router, f'a routing loop back to {router}', 'drop', 'routing loop'))
            return {**out, 'verdict': 'blocked', 'decided_by': f'{router}: a routing loop'}
        seen.add(router)
        g = fleet.hosts[router]
        next_route = route_to(g.get('net'), dst_ip) if g.get('net') else None
        iif = fleet.by_addr.get(gateway, (None, None))[1]
        if router == dst_host:
            break                  # it's for the router itself: its own input rules decide, below
        if not g.get('net'):
            blind.append(f'the routes of {router} have not been read')
            break
        if not next_route:
            hops.append(_hop(router, f'no route to {dst_ip}', 'drop', 'no matching route'))
            return {**out, 'verdict': 'blocked', 'decided_by': f'{router} has no route to {dst_ip}'}
        fw = _fw_readable(g)
        if not fw:
            blind.append(f'the firewall of {router}, which routes this, has not been read')
        elif fw.get('backends'):
            res = exposure.kernel_path(fw, 'forward', {'proto': proto, 'port': port, 'iif': iif, 'oif': next_route.get('dev'), 'daddr': dst_ip, 'saddr': src_ip, 'family': 'ip6' if ':' in str(dst_ip) else 'ip'})
            state = _decided(res)
            hops.append(_hop(router, f'forward rules, {iif} to {next_route.get("dev")}', state, res['rule'], res['unknown']))
            if state == 'drop':
                return {**out, 'verdict': 'blocked', 'decided_by': f'{router}: {res["rule"]}'}
            if state == 'unknown':
                blind.append(f'a forward rule on {router} could not be understood')
        route = next_route
    else:
        blind.append(f'the path is more than {MAX_HOPS} routers long: only those were followed')

    # into a router that forwards this port on
    target = _dnat(fleet, dst_host, dst_ip, port, proto, src_ip)
    if target:
        g = fleet.hosts[dst_host]
        fw = _fw_readable(g)
        rule, to_ip, to_port, oif = target
        iif = fleet.by_addr.get(dst_ip, (None, None))[1]
        res = exposure.kernel_path(fw, 'forward', {'proto': proto, 'port': to_port, 'iif': iif, 'oif': oif, 'daddr': to_ip, 'saddr': src_ip, 'family': 'ip', 'dnat': True})
        state = _decided(res)
        hops.append(_hop(dst_host, f'forwards {port} to {to_ip}:{to_port} ({rule.get("comment") or "port forward"})', state, res['rule'], res['unknown']))
        if state == 'drop':
            return {**out, 'verdict': 'blocked', 'decided_by': f'{dst_host}: {res["rule"]}'}
        if state == 'unknown':
            blind.append(f'a forward rule on {dst_host} could not be understood')
        port, dst_ip = to_port, to_ip
        dst_host = fleet.by_addr.get(to_ip, (None,))[0]
        out = {**out, 'to_host': dst_host, 'forwarded_to': f'{to_ip}:{to_port}', 'to_ip': to_ip}

    # into B
    if not dst_host:
        blind.append(f'{dst_ip} is not a scanned host: whether anything listens there, and what its firewall does, is out of sight')
        return {**out, 'verdict': 'unknown', 'decided_by': None}
    h = fleet.hosts[dst_host]
    net = h.get('net')
    if not net:
        blind.append(f'{dst_host} has not been read')
        return {**out, 'verdict': 'unknown', 'decided_by': None}
    fw = (h.get('infra') or {}).get('firewall')
    iface = next((i for i in net.get('interfaces') or [] if any(a.get('ip') == dst_ip for a in i.get('addresses') or [])), None)
    iif = (iface or {}).get('name')
    fam = 'ip6' if ':' in str(dst_ip) else 'ip'

    # a published port, or a container asked for by name
    pub = None
    for c in h.get('containers') or []:
        if c.get('state') != 'running' or (container and c is not container):
            continue
        for p in c.get('ports') or []:
            if p['proto'] == proto and (p['host_port'] == port or (container and p['port'] == port)):
                pub = (c, p)
                break
        if pub:
            break
    if container and not pub:
        hops.append(_hop(dst_host, f'{container.get("name")} does not publish {port}/{proto}', 'drop', 'nothing published'))
        return {**out, 'verdict': 'blocked', 'decided_by': f'{container.get("name")} publishes no {proto}/{port} on {dst_host}'}
    if pub:
        c, p = pub
        bind = p.get('host_ip')
        if _ip(bind) and _ip(bind).is_loopback:
            return {**out, 'verdict': 'blocked', 'decided_by': f'{c["name"]} publishes on {bind} only'}
        n = next((x for x in c.get('networks') or [] if x.get('ip')), None)
        if not _fw_readable(h):
            blind.append(f'the firewall of {dst_host} has not been read')
            hops.append(_hop(dst_host, f'published by {c["name"]}', 'unknown'))
            return {**out, 'verdict': 'unknown', 'decided_by': None, 'target': c['name']}
        oif = exposure._bridge_for(n.get('gateway'), net) if n else None
        res = exposure.kernel_path(fw, 'forward', {'proto': proto, 'port': p['port'], 'orig_port': p['host_port'], 'iif': iif, 'oif': oif, 'daddr': (n or {}).get('ip'), 'saddr': src_ip, 'family': fam}) if n else exposure._input_path(fw, {'proto': proto, 'port': port, 'iif': iif, 'daddr': dst_ip, 'saddr': src_ip, 'family': fam})
        state = _decided(res)
        hops.append(_hop(dst_host, f'published by {c["name"]} ({p["host_port"]} to {p["port"]})', state, res['rule'], res['unknown']))
        verdict = {'accept': 'allowed', 'drop': 'blocked', 'unknown': 'unknown'}[state]
        return {**out, 'verdict': verdict, 'decided_by': f'{dst_host}: {res["rule"]}', 'target': c['name'], 'bypasses_frontend': bool({'ufw', 'firewalld'} & set(fw['backends']))}

    # a listener on the host itself
    listeners = (h.get('infra') or {}).get('listeners') or net.get('listeners') or []
    match = [x for x in listeners if x['proto'] == proto and x['port'] == port and (x['scope'] == 'any' or x['addr'] == dst_ip)]
    if not match:
        if 'listeners' in (net.get('unreadable') or []):
            blind.append(f'the listeners of {dst_host} could not be read')
        else:
            hops.append(_hop(dst_host, f'nothing listens on {port}/{proto}', 'drop', 'no listener'))
            return {**out, 'verdict': 'blocked', 'decided_by': f'nothing listens on {proto}/{port} on {dst_host}'}
    if not _fw_readable(h):
        blind.append(f'the firewall of {dst_host} has not been read')
        hops.append(_hop(dst_host, 'input rules', 'unknown'))
        return {**out, 'verdict': 'unknown', 'decided_by': None, 'process': (match[0].get('process') if match else None)}
    if not fw.get('backends'):
        hops.append(_hop(dst_host, 'no firewall', 'accept', 'no firewall on this host'))
        return {**out, 'verdict': 'allowed', 'decided_by': f'{dst_host}: no firewall', 'process': (match[0].get('process') if match else None)}
    res = exposure._input_path(fw, {'proto': proto, 'port': port, 'iif': iif, 'daddr': dst_ip, 'saddr': src_ip, 'family': fam})
    state = _decided(res)
    if state == 'drop' and res.get('sources'):
        state = 'unknown'                 # only named sources get in, and the source here could not be matched to one of them
    hops.append(_hop(dst_host, 'input rules', state, res['rule'], res['unknown']))
    return {**out, 'verdict': {'accept': 'allowed', 'drop': 'blocked', 'unknown': 'unknown'}[state], 'decided_by': f'{dst_host}: {res["rule"]}', 'process': (match[0].get('process') if match else None)}
