"""A host's network as its scan user can read it: interfaces, bridges, VLANs, routes, neighbours, listeners and DNS, and what its
network files say (netconfig.py: netplan, NetworkManager, systemd-networkd, ifupdown).

Only reads, and only the host's own state: nothing here sends a packet to find out what exists. It runs after the walk in
the scan's SSH session, as the scan user, so what needs root is not here: a listener's owning process and the firewall rules
come from a measurement (inframeasure.py). A command that fails or is missing makes that part unreadable, which is
recorded and is never the same as empty. Busybox's ip has no -j, so Alpine says so. A failure here never fails the scan.
"""
from __future__ import annotations

import ipaddress
import json
import re
import time

from . import netconfig
from .db import Conn

# Debian keeps ip and ss off an ordinary user's PATH. POSIX sh: Alpine has no bash.
SCRIPT = r"""
PATH=$PATH:/usr/sbin:/sbin; export PATH LC_ALL=C
t() { if command -v timeout >/dev/null 2>&1; then timeout 20 "$@" 2>/dev/null; else "$@" 2>/dev/null; fi; }
echo '@@link'; t ip -j -s -d link show
echo; echo '@@addr'; t ip -j addr show
echo; echo '@@route'; t ip -j route show
echo; echo '@@route6'; t ip -j -6 route show
echo; echo '@@neigh'; t ip -j neigh show
echo; echo '@@bridge'; t bridge -j vlan show
echo; echo '@@listen'; t ss -H -tuln || echo '@@listen_failed'
echo; echo '@@lldp'; t lldpctl -f json
echo; echo '@@resolv'; [ -r /etc/resolv.conf ] && grep -E '^(nameserver|search)[[:space:]]' /etc/resolv.conf
@NETCONFIG@
echo; echo '@@end'
""".replace('@NETCONFIG@', netconfig.SCRIPT.strip())
SECTIONS = ('link', 'addr', 'route', 'route6', 'neigh', 'bridge', 'listen', 'listen_failed', 'lldp', 'resolv', *netconfig.SECTIONS, 'end')
MAX_NEIGHBOURS = 500


def split_sections(text: str, names, lines: bool = False) -> dict:
    """Split a host or device script's output into its `@@name` sections.

    A header is a line that is exactly `@@` and one of `names`; other lines go to the section open
    above them, and lines before the first header are dropped. A section that appears twice keeps
    only its last copy. Each section is its lines joined and stripped, or with `lines` the list of
    lines as printed. Whether the reading was cut short (no `end`) is for the caller to decide.
    """
    out, cur = {}, None
    for line in text.splitlines():
        if line.startswith('@@') and line[2:] in names:
            cur = line[2:]
            out[cur] = []
        elif cur:
            out[cur].append(line)
    if lines:
        return out
    return {k: '\n'.join(v).strip() for k, v in out.items()}


def _sections(text: str) -> dict:
    return split_sections(text, SECTIONS)


def _json(text: str):
    """A list of objects, or None when the command gave nothing we can read. '[]' stays an honest empty. A list holding anything but objects
    is unreadable too: it used to throw, and one odd section lost the whole reading (found by test_props_parsers)."""
    if not text:
        return None
    try:
        v = json.loads(text)
    except ValueError:
        return None
    return v if isinstance(v, list) and all(isinstance(x, dict) for x in v) else None


def _split_addr(local: str) -> tuple[str, int] | None:
    """ss's local column: 0.0.0.0:22, [::]:22, *:22, 127.0.0.53%lo:53, [fe80::1]%eth0:546."""
    m = re.fullmatch(r'\[?([^\]]*?)\]?(?:%[^:]+)?:(\d+)', local)
    return (m.group(1), int(m.group(2))) if m else None


def bind_scope(addr: str) -> str:
    """What a bind address says by itself, before any firewall: loopback, any (every address), link or address."""
    if addr in ('*', '0.0.0.0', '::'):
        return 'any'
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return 'address'
    return 'loopback' if ip.is_loopback else 'link' if ip.is_link_local else 'address'


def parse_listeners(text: str) -> list[dict]:
    out, seen = [], set()
    for line in (text or '').splitlines():
        f = line.split()
        if len(f) < 5 or f[0] not in ('tcp', 'udp'):
            continue
        parsed = _split_addr(f[4])
        if not parsed:
            continue
        key = (f[0], parsed[0], parsed[1])
        if key not in seen:
            seen.add(key)
            out.append({'proto': f[0], 'addr': parsed[0], 'port': parsed[1], 'scope': bind_scope(parsed[0])})
    return sorted(out, key=lambda x: (x['port'], x['proto'], x['addr']))


def _kind(link: dict) -> str:
    info = link.get('linkinfo') or {}
    kind = info.get('info_kind')
    if link.get('link_type') == 'loopback':
        return 'loopback'
    return kind if kind else 'ethernet' if link.get('link_type') == 'ether' else (link.get('link_type') or 'unknown')


def _lldp(text: str | None) -> list[dict]:
    if not text:
        return []
    try:
        doc = json.loads(text)
    except ValueError:
        return []
    if not isinstance(doc, dict):
        return []
    lldp = doc.get('lldp') if isinstance(doc.get('lldp'), dict) else {}
    ifaces = lldp.get('interface')
    items = ifaces if isinstance(ifaces, list) else [ifaces] if isinstance(ifaces, dict) else []
    out = []
    for entry in items:
        if not isinstance(entry, dict):
            continue
        for local_if, body in entry.items():
            if not isinstance(body, dict):
                continue
            ch = body.get('chassis') if isinstance(body.get('chassis'), dict) else {}
            port = body.get('port') if isinstance(body.get('port'), dict) else {}
            for name, info in ch.items():
                if not isinstance(info, dict):
                    continue
                ip = info.get('mgmt-ip')
                if isinstance(ip, list):
                    ip = ip[0] if ip else None
                out.append({'name': name, 'ip': ip if isinstance(ip, str) else None, 'platform': str(info.get('descr') or '')[:120] or None,
                            'via': local_if, 'remote_port': port.get('id', {}).get('value') if isinstance(port.get('id'), dict) else None, 'protocol': 'lldp'})
    return out[:200]


def _counters(links: list[dict] | None) -> list[dict]:
    out = []
    for link in links or []:
        name = link.get('ifname')
        if not name or link.get('link_type') == 'loopback':
            continue
        st = link.get('stats64') or link.get('stats') or {}
        rx, tx = st.get('rx') or {}, st.get('tx') or {}
        if isinstance(rx.get('bytes'), int) and isinstance(tx.get('bytes'), int):
            out.append({
                'iface': name,
                'rx_bytes': int(rx['bytes']),
                'tx_bytes': int(tx['bytes']),
                'rx_drop': int(rx.get('dropped') or 0),
                'tx_drop': int(tx.get('dropped') or 0),
                'rx_error': int(rx.get('errors') or 0),
                'tx_error': int(tx.get('errors') or 0),
            })
    return out


def parse(text: str) -> dict:
    """What the script printed, as one record. `unreadable` lists what could not be read: never treat those as empty."""
    s = _sections(text)
    links, addrs, routes, routes6, neigh, vlans = (_json(s.get(k, '')) for k in ('link', 'addr', 'route', 'route6', 'neigh', 'bridge'))
    unreadable = [name for name, v in (('interfaces', links), ('addresses', addrs), ('routes', routes), ('neighbours', neigh)) if v is None]
    if 'listen' not in s or 'listen_failed' in s:      # no ss, or it failed: that is not the same as nothing listening
        unreadable.append('listeners')
    by_addr = {a.get('ifname'): a for a in addrs or []}
    bridge_vlans = {b.get('ifname'): sorted({v.get('vlan') for v in b.get('vlans') or [] if v.get('vlan')}) for b in vlans or []}
    interfaces = []
    for link in links or []:
        name = link.get('ifname')
        info = link.get('linkinfo') or {}
        data = info.get('info_data') or {}
        interfaces.append({
            'name': name, 'kind': _kind(link), 'state': (link.get('operstate') or 'UNKNOWN').lower(), 'mtu': link.get('mtu'), 'mac': link.get('address') or None,
            'master': link.get('master'), 'parent': link.get('link'), 'vlan_id': data.get('id') if info.get('info_kind') == 'vlan' else None,
            'bridge_vlans': bridge_vlans.get(name) or [],
            'addresses': [{'ip': a.get('local'), 'prefix': a.get('prefixlen'), 'scope': a.get('scope')} for a in (by_addr.get(name) or {}).get('addr_info') or [] if a.get('local')]})
    def route(r, family):
        return {'dst': r.get('dst'), 'via': r.get('gateway') or (r.get('via') or {}).get('host'), 'dev': r.get('dev'), 'metric': r.get('metric'), 'family': family}
    all_routes = [route(r, 4) for r in routes or []] + [route(r, 6) for r in routes6 or []]
    resolv = (s.get('resolv') or '').splitlines()
    return {
        'interfaces': interfaces, 'routes': all_routes, 'gateways': sorted({r['via'] for r in all_routes if r['dst'] == 'default' and r['via']}),
        'neighbours': [{'ip': n.get('dst'), 'mac': n.get('lladdr'), 'dev': n.get('dev')} for n in neigh or []
                       if n.get('dst') and n.get('lladdr') and 'FAILED' not in (n.get('state') or [])][:MAX_NEIGHBOURS],
        'listeners': parse_listeners(s.get('listen', '')),
        'dns': {'nameservers': [x.split()[1] for x in resolv if x.startswith('nameserver') and len(x.split()) > 1],
                'search': [w for x in resolv if x.startswith('search') for w in x.split()[1:]]},
        'counters': _counters(links),
        'discovered': _lldp(s.get('lldp')),
        'config': netconfig.read(s), 'unreadable': unreadable, 'complete': 'end' in s}


def survey(conn: Conn, t, host_id: int, scan_id: int) -> dict:
    """Keeps the last good reading when this one was cut short: a failed read deletes nothing."""
    data = parse(t.run(SCRIPT, timeout=120))
    if not data['complete']:
        return {'error': 'the network read was cut short'}
    now = int(time.time())
    with conn.tx():
        conn.execute('DELETE FROM host_network WHERE host_id = :h', {'h': host_id})
        conn.execute('INSERT INTO host_network (host_id, data_json, scan_id, updated_at) VALUES (:h, :d, :s, :t)',
                     {'h': host_id, 'd': json.dumps(data), 's': scan_id, 't': now})
    host = conn.scalar('SELECT hostname FROM hosts WHERE host_id = :h', {'h': host_id})
    if host and data.get('counters'):
        from . import traffic
        traffic.record(conn, host, data['counters'], now)
    return {'interfaces': len(data['interfaces']), 'listeners': len(data['listeners']), 'unreadable': data['unreadable']}


def reading(conn: Conn, host: str) -> dict | None:
    rows = conn.all("""SELECT n.data_json, n.updated_at FROM host_network n JOIN hosts h ON h.host_id = n.host_id
                       WHERE lower(h.hostname) = lower(:h)""", {'h': host})
    if not rows:
        return None
    raw = rows[0][0]
    return {**(raw if isinstance(raw, dict) else json.loads(raw)), 'read_at': rows[0][1]}
