"""OpenWrt: a Linux with a POSIX shell, so most of this is netfacts and firewall.py reading what they read on any host. On top: DHCP leases, the UCI zones that say
which network is the WAN, and the fw4 ruleset as nft JSON. Only reads. Older releases have fw3, read through iptables-save.

Busybox's ip has no -j, so addresses, routes and neighbours come from ubus and /proc when it's missing. ubus is the only source of an interface's logical name.
"""
from __future__ import annotations

import json
import re

from . import firewall as fwmodel
from . import netfacts

SCRIPT = netfacts.SCRIPT.replace("echo; echo '@@end'", r"""
echo; echo '@@ubus'; ubus call network.interface dump 2>/dev/null
echo; echo '@@board'; ubus call system board 2>/dev/null
echo; echo '@@uci_network'; uci show network 2>/dev/null
echo; echo '@@uci_firewall'; uci show firewall 2>/dev/null
echo; echo '@@leases'; cat /tmp/dhcp.leases 2>/dev/null
echo; echo '@@nft'; nft -j list ruleset 2>/dev/null
echo; echo '@@iptables'; iptables-save 2>/dev/null
echo; echo '@@dev'; cat /proc/net/dev 2>/dev/null
echo; echo '@@arp'; cat /proc/net/arp 2>/dev/null
echo; echo '@@netstat'; netstat -ltun 2>/dev/null
echo; echo '@@wifi'; iwinfo 2>/dev/null | head -n 100
echo; echo '@@end'""")
EXTRA = ('ubus', 'board', 'uci_network', 'uci_firewall', 'leases', 'nft', 'iptables', 'dev', 'arp', 'netstat', 'wifi')
# Interfaces OpenWrt names by role: what the firewall's zones call them
ALL_SECTIONS = (*netfacts.SECTIONS, *EXTRA)


def sections(text: str) -> dict:
    out, cur = {}, None
    for line in text.splitlines():
        if line.startswith('@@') and line[2:] in ALL_SECTIONS:
            cur = line[2:]
            out[cur] = []
        elif cur:
            out[cur].append(line)
    return {k: '\n'.join(v).strip() for k, v in out.items()}


def parse_leases(text: str) -> list[dict]:
    """/tmp/dhcp.leases: expiry, MAC, address, name, client id."""
    out = []
    for line in (text or '').splitlines():
        f = line.split()
        if len(f) >= 4:
            out.append({'ip': f[2], 'mac': f[1].lower(), 'name': None if f[3] == '*' else f[3], 'expires': int(f[0]) if f[0].isdigit() else None, 'static': f[0] == '0'})
    return out[:2000]


def parse_uci(text: str) -> dict:
    """`uci show`: package.section.option='value'. {section: {'.type': ..., option: value}}. A list is space-separated quoted values."""
    out: dict = {}
    for line in (text or '').splitlines():
        m = re.match(r"^[\w-]+\.(@?[\w\[\]-]+)(?:\.([\w-]+))?='?(.*?)'?$", line)
        if not m:
            continue
        section, option, value = m[1], m[2], m[3]
        row = out.setdefault(section, {})
        if option is None:
            row['.type'] = value
        else:
            row[option] = [v for v in value.split("' '")] if "' '" in value else value
    return out


def zones(uci: dict) -> list[dict]:
    """fw4's zones: which UCI networks are in each, and what it does with what comes in."""
    out = []
    for row in uci.values():
        if row.get('.type') != 'zone':
            continue
        nets = row.get('network') or []
        out.append({'name': row.get('name'), 'networks': nets if isinstance(nets, list) else nets.split(), 'input': (row.get('input') or '').lower(), 'forward': (row.get('forward') or '').lower(), 'masq': row.get('masq') == '1'})
    return out


def _ubus_interfaces(text: str) -> dict:
    """Logical name, device, address and routes from `ubus call network.interface dump`."""
    try:
        data = json.loads(text or '{}')
    except ValueError:
        return {}
    return {i.get('interface'): i for i in data.get('interface') or [] if isinstance(i, dict)}


def _from_ubus(net: dict, ubus: dict) -> None:
    """Fills in what busybox's ip could not give."""
    if not net['interfaces']:
        for name, i in ubus.items():
            dev = i.get('l3_device') or i.get('device')
            if dev:
                net['interfaces'].append({'name': dev, 'kind': 'ethernet', 'state': 'up' if i.get('up') else 'down', 'mtu': None, 'mac': None, 'master': None, 'parent': None, 'vlan_id': None, 'bridge_vlans': [],
                                          'addresses': [{'ip': a.get('address'), 'prefix': a.get('mask'), 'scope': 'global'} for a in i.get('ipv4-address') or []]})
        net['unreadable'] = [u for u in net['unreadable'] if u not in ('interfaces', 'addresses')]
    if not net['routes']:
        for i in ubus.values():
            dev = i.get('l3_device') or i.get('device')
            for r in i.get('route') or []:
                dst = 'default' if r.get('target') == '0.0.0.0' and not r.get('mask') else f'{r.get("target")}/{r.get("mask")}'
                net['routes'].append({'dst': dst, 'via': None if r.get('nexthop') in (None, '0.0.0.0') else r['nexthop'], 'dev': dev, 'metric': r.get('metric'), 'family': 4})
            for a in i.get('ipv4-address') or []:
                import ipaddress
                net['routes'].append({'dst': str(ipaddress.ip_interface(f'{a.get("address")}/{a.get("mask")}').network), 'via': None, 'dev': dev, 'metric': 0, 'family': 4})
        net['unreadable'] = [u for u in net['unreadable'] if u != 'routes']
        net['gateways'] = sorted({r['via'] for r in net['routes'] if r['dst'] == 'default' and r['via']})


def parse_arp(text: str) -> list[dict]:
    """/proc/net/arp: address, type, flags, MAC, mask, device. A 00:00.. entry never resolved."""
    out = []
    for line in (text or '').splitlines()[1:]:
        f = line.split()
        if len(f) >= 6 and f[3] != '00:00:00:00:00:00':
            out.append({'ip': f[0], 'mac': f[3].lower(), 'dev': f[5]})
    return out[:500]


def parse_netstat(text: str) -> list[dict]:
    """busybox netstat -ltun: proto, recv, send, local, foreign, state."""
    out, seen = [], set()
    for line in (text or '').splitlines():
        f = line.split()
        if len(f) < 4 or not f[0].startswith(('tcp', 'udp')):
            continue
        got = netfacts._split_addr(f[3]) if not f[3].startswith(':::') else ('::', int(f[3].rsplit(':', 1)[1]))
        if not got:
            continue
        key = (f[0][:3], got[0], got[1])
        if key not in seen:
            seen.add(key)
            out.append({'proto': f[0][:3], 'addr': got[0], 'port': got[1], 'scope': netfacts.bind_scope(got[0])})
    return sorted(out, key=lambda x: (x['port'], x['proto']))


def _zone_devices(fw: dict, ubus: dict, zone_rows: list[dict]) -> None:
    """fw4 sends what arrives on a zone's devices to dstnat_<zone>, so a forward in that chain only applies there: the rule in it can't say so itself."""
    for rule in fw.get('nat') or []:
        m = re.match(r'^dstnat_(.+)$', str(rule.get('chain') or ''))
        if not m or rule.get('iif'):
            continue
        devices = [(ubus.get(n) or {}).get('l3_device') or (ubus.get(n) or {}).get('device') for z in zone_rows if z['name'] == m[1] for n in z['networks']]
        rule['iif'] = ','.join(d for d in devices if d) or None
        if rule.get('comment', '').startswith('!fw4: '):
            rule['comment'] = rule['comment'][6:]


def wan_devices(ubus: dict, zone_rows: list[dict]) -> list[str]:
    """The devices in a zone that masquerades, which is how fw4 says "this is the outside"."""
    return sorted({(ubus.get(n) or {}).get('l3_device') or (ubus.get(n) or {}).get('device') for z in zone_rows if z['masq'] for n in z['networks']} - {None})


def parse(text: str) -> dict:
    s = sections(text)
    if 'end' not in s:
        raise ValueError('the reading was cut short')
    net = netfacts.parse(text)
    ubus = _ubus_interfaces(s.get('ubus'))
    _from_ubus(net, ubus)
    tools = (['nft'] if s.get('nft') else []) + (['iptables-save'] if s.get('iptables') else [])
    fw = fwmodel.model({'tools': tools, 'nft': s.get('nft'), 'iptables': s.get('iptables')})
    zone_rows = zones(parse_uci(s.get('uci_firewall')))
    fw['zones_uci'] = zone_rows
    _zone_devices(fw, ubus, zone_rows)
    for i in net['interfaces']:
        if i['name'] == 'lo':
            i['kind'] = 'loopback'
    if 'neighbours' in net['unreadable'] and s.get('arp'):
        net['neighbours'] = parse_arp(s['arp'])
        net['unreadable'] = [u for u in net['unreadable'] if u != 'neighbours']
    if 'listeners' in net['unreadable'] and s.get('netstat'):
        net['listeners'] = parse_netstat(s['netstat'])
        net['unreadable'] = [u for u in net['unreadable'] if u != 'listeners']
    if not tools:
        fw.update(readable=False)
        fw['notes'].append('neither nft nor iptables-save gave anything')
    try:
        board = json.loads(s.get('board') or '{}')
    except ValueError:
        board = {}
    version = (board.get('release') or {}).get('version')
    from .routeros import counters
    rows = []
    for line in (s.get('dev') or '').splitlines()[2:]:
        name, _, rest = line.partition(':')
        f = rest.split()
        if len(f) >= 12:
            rows.append({'name': name.strip(), 'rx-byte': f[0], 'rx-error': f[2], 'rx-drop': f[3], 'tx-byte': f[8], 'tx-error': f[10], 'tx-drop': f[11]})
    return {'net': net, 'firewall': fw, 'os': f'OpenWrt {version or "unknown"}', 'identity': board.get('hostname'),
            'facts': {'platform': 'openwrt', 'version': version, 'identity': board.get('hostname'), 'board': board.get('model'), 'leases': parse_leases(s.get('leases')), 'discovered': [],
                      'wan': wan_devices(ubus, zone_rows), 'zones': zone_rows, 'counters': counters(rows), 'wifi': (s.get('wifi') or '')[:4000]}, 'config': s.get('uci_network')}


def collect(run) -> dict:
    return parse(run(SCRIPT))
