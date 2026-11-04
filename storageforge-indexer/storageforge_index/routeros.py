"""MikroTik RouterOS: what its SSH says, as the records every other host's readings use. Pure parsing, with collect() the only part that talks.

Only reads. `print as-value` over SSH prints nothing, so a table comes through `:put [:serialize to=json [...]]`, which RouterOS has from 7.13. Before
that, and on v6, it comes from `print terse`, a weaker format whose paths are spaced. A table that could not be read is listed in `unreadable` and is never
the same as empty, and a firewall table that could not be read makes the whole firewall unknown. A match this model has no field for marks its rule `unmodelled`.

RouterOS accepts what no rule decides, so each chain's policy is accept. A rule naming an address list is resolved from the lists read in the same pass.
"""
from __future__ import annotations

import ipaddress
import json
import re

from .firewall import _ports, _rule

TABLES = {'address': '/ip/address', 'interface': '/interface', 'route': '/ip/route', 'filter': '/ip/firewall/filter', 'nat': '/ip/firewall/nat', 'neighbor': '/ip/neighbor',
          'bridge_port': '/interface/bridge/port', 'bridge_vlan': '/interface/bridge/vlan', 'vlan': '/interface/vlan', 'bonding': '/interface/bonding', 'lease': '/ip/dhcp-server/lease',
          'arp': '/ip/arp', 'address_list': '/ip/firewall/address-list', 'service': '/ip/service', 'iface_list': '/interface/list/member', 'address6': '/ipv6/address', 'route6': '/ipv6/route'}
MUST_READ = ('address', 'interface', 'route', 'filter', 'nat')
KINDS = {'ether': 'ethernet', 'bridge': 'bridge', 'vlan': 'vlan', 'bond': 'bond', 'wg': 'wireguard', 'loopback': 'loopback', 'pppoe-out': 'tunnel', 'gre-tunnel': 'tunnel', 'ipip-tunnel': 'tunnel', 'eoip': 'tunnel', 'l2tp-out': 'tunnel', 'wlan': 'wireless', 'wifi': 'wireless'}
# Matches that only narrow a rule by how a packet is logged or counted, or that the model reads elsewhere
KNOWN = {'.id', 'chain', 'action', 'comment', 'disabled', 'dynamic', 'invalid', 'protocol', 'dst-port', 'src-address', 'dst-address', 'src-address-list', 'dst-address-list', 'in-interface', 'out-interface',
         'in-interface-list', 'out-interface-list', 'connection-state', 'jump-target', 'to-addresses', 'to-ports', 'log', 'log-prefix', 'bytes', 'packets', 'reject-with', 'hw-offload', 'routing-mark', 'address-list', 'address-list-timeout'}
NO_VERDICT = ('passthrough', 'log', 'add-src-to-address-list', 'add-dst-to-address-list', 'mark-connection', 'mark-packet', 'mark-routing')
MAX_ROWS = 20000
TERSE_KEY = re.compile(r'(?:^|\s)(?=[a-zA-Z.][\w.-]*=)')


def command(path: str) -> str:
    return f':put [:serialize to=json [{path}/print as-value]]'


def legacy_command(path: str) -> str:
    return ' '.join(path.split('/')).strip().join(('/', ' print terse without-paging'))


def parse_terse(text: str) -> list[dict] | None:
    """`0 X D name=value name=value`: a row number, flag letters, then pairs. Values aren't quoted, so a value runs up to the next name=."""
    if re.search(r'(?:bad command|syntax error|expected|no such item|not enough permissions)', text or ''):
        return None
    rows = []
    for line in (text or '').splitlines():
        m = re.match(r'\s*\d+\s+([A-Za-z ]*?)\s*(?=[a-zA-Z.][\w.-]*=)(.*)$', line)
        if not m:
            continue
        row = {k: v.strip() for k, _, v in (p.partition('=') for p in TERSE_KEY.split(m[2]) if p)}
        flags = m[1].replace(' ', '')
        row.update({'disabled': 'X' in flags, 'dynamic': 'D' in flags, 'running': 'R' in flags, 'invalid': 'I' in flags, 'active': 'A' in flags})
        rows.append(row)
    return rows[:MAX_ROWS]


def parse_table(text: str) -> list[dict] | None:
    """A table as RouterOS serialized it, None when what came back isn't one: an error, a refusal, a cut-off."""
    try:
        got = json.loads(text)
    except (ValueError, TypeError):
        return None
    if isinstance(got, dict):
        got = [got]
    return [r for r in got if isinstance(r, dict)][:MAX_ROWS] if isinstance(got, list) else None


def _text(v) -> str | None:
    """Serialized numbers come as 80.000000, and lists come as lists."""
    if v is None or v == '':
        return None
    if isinstance(v, bool):
        return 'yes' if v else 'no'
    if isinstance(v, float) and v == int(v):
        return str(int(v))
    if isinstance(v, (list, tuple)):
        return ','.join(str(_text(x)) for x in v)
    return str(v)


def _yes(v) -> bool:
    return v is True or v == 'true' or v == 'yes'


def _ip(text):
    try:
        return ipaddress.ip_address(str(text).split('%')[0])
    except ValueError:
        return None


def _vlans(text) -> list[int]:
    out = []
    for part in str(_text(text) or '').split(','):
        low, _, high = part.partition('-')
        if low.isdigit():
            out += list(range(int(low), int(high) + 1)) if high.isdigit() and int(high) - int(low) < 4096 else [int(low)]
    return out


def network(t: dict) -> dict:
    """The same record netfacts.parse gives for a Linux host."""
    addrs: dict = {}
    for a in (t.get('address') or []) + (t.get('address6') or []):
        if _yes(a.get('disabled')) or _yes(a.get('invalid')) or not a.get('address'):
            continue
        ip, _, prefix = str(a['address']).partition('/')
        got = _ip(ip)
        scope = 'link' if got and got.is_link_local else 'global'
        addrs.setdefault(a.get('actual-interface') or a.get('interface'), []).append({'ip': ip, 'prefix': int(prefix) if prefix.isdigit() else None, 'scope': scope})
    master = {p.get('interface'): p.get('bridge') for p in t.get('bridge_port') or [] if not _yes(p.get('disabled'))}
    for b in t.get('bonding') or []:
        for s in str(_text(b.get('slaves')) or '').split(','):
            if s:
                master[s] = b.get('name')
    vlan_of = {v.get('name'): v for v in t.get('vlan') or []}
    bridge_vlans: dict = {}
    for v in t.get('bridge_vlan') or []:
        if not _yes(v.get('disabled')):
            bridge_vlans.setdefault(v.get('bridge'), set()).update(_vlans(v.get('vlan-ids')))
    interfaces = []
    for i in t.get('interface') or []:
        name = i.get('name')
        vlan = vlan_of.get(name) or {}
        mtu = i.get('actual-mtu') or i.get('mtu')
        interfaces.append({'name': name, 'kind': KINDS.get(i.get('type'), i.get('type') or 'unknown'), 'state': 'up' if _yes(i.get('running')) and not _yes(i.get('disabled')) else 'down',
                           'mtu': int(mtu) if str(_text(mtu) or '').isdigit() else None, 'mac': (str(i['mac-address']).lower() if i.get('mac-address') else None) if i.get('mac-address') != '00:00:00:00:00:00' else None,
                           'master': master.get(name), 'parent': vlan.get('interface'), 'vlan_id': int(_text(vlan['vlan-id'])) if vlan.get('vlan-id') is not None else None,
                           'bridge_vlans': sorted(bridge_vlans.get(name) or []), 'addresses': addrs.get(name) or []})
    subnets = [(ipaddress.ip_interface(f'{a["ip"]}/{a["prefix"]}').network, n) for n, rows in addrs.items() for a in rows if a.get('prefix') is not None and a.get('scope') == 'global' and n]
    routes = []
    for family, rows in ((4, t.get('route')), (6, t.get('route6'))):
        for r in rows or []:
            if _yes(r.get('disabled')) or r.get('active') is False or _yes(r.get('inactive')):
                continue
            dst, gw = r.get('dst-address'), str(_text(r.get('gateway')) or r.get('immediate-gw') or '')
            via = gw.split('%')[0] if _ip(gw) else None
            dev = gw.split('%')[1] if '%' in gw else None if via else (gw or None)
            if via and not dev:
                dev = next((n for net, n in subnets if _ip(via) in net and net.version == _ip(via).version), None)
            routes.append({'dst': 'default' if dst in ('0.0.0.0/0', '::/0') else dst, 'via': via, 'dev': dev, 'metric': r.get('distance'), 'family': family, 'table': r.get('routing-table') or 'main'})
    listeners, seen = [], set()
    for s in t.get('service') or []:
        if _yes(s.get('disabled')) or _yes(s.get('invalid')) or not str(_text(s.get('port')) or '').isdigit() or _text(s.get('port')) in seen:
            continue
        seen.add(_text(s['port']))
        limit = _text(s.get('available-from') or s.get('address'))
        listeners.append({'proto': 'tcp', 'addr': '0.0.0.0', 'port': int(_text(s['port'])), 'scope': 'any', 'process': [s.get('name')], **({'only_from': limit} if limit else {})})
    unreadable = [{'address': 'addresses', 'interface': 'interfaces', 'route': 'routes', 'arp': 'neighbours', 'service': 'listeners'}[k] for k in ('address', 'interface', 'route', 'arp', 'service') if t.get(k) is None]
    dns = t.get('dns') or {}
    servers = dns.get('servers')
    return {'interfaces': interfaces, 'routes': routes, 'gateways': sorted({r['via'] for r in routes if r['dst'] == 'default' and r['via']}),
            'neighbours': [{'ip': n.get('address'), 'mac': str(n['mac-address']).lower(), 'dev': n.get('interface')} for n in t.get('arp') or [] if n.get('address') and n.get('mac-address')][:500],
            'listeners': sorted(listeners, key=lambda x: x['port']), 'dns': {'nameservers': [x for x in (servers if isinstance(servers, list) else str(servers or '').split(',')) if x], 'search': []},
            'unreadable': unreadable, 'complete': True}


def _lists(t: dict) -> dict:
    out: dict = {}
    for row in t.get('address_list') or []:
        if not _yes(row.get('disabled')) and row.get('list') and row.get('address'):
            out.setdefault(row['list'], []).append(str(row['address']))
    return out


def _members(t: dict) -> dict:
    out: dict = {}
    for row in t.get('iface_list') or []:
        if not _yes(row.get('disabled')) and row.get('list') and row.get('interface'):
            out.setdefault(row['list'], []).append(row['interface'])
    return out


def _addr(rule: dict, key: str, raw, negated_key: str | None = None) -> None:
    text = _text(raw)
    if not text:
        return
    if text.startswith('!'):
        if negated_key:
            rule[negated_key] = text[1:]
        else:
            rule['unmodelled'].append(f'{key} {text}')
        return
    rule[key] = text


def _named(rule: dict, key: str, name, table: dict, negated_key: str | None, what: str) -> None:
    """A named list, by its contents. Empty or unknown stays unmodelled: the rule's reach can't be said."""
    text = _text(name)
    if not text:
        return
    negated = text.startswith('!')
    got = table.get(text[1:] if negated else text)
    if not got or (negated and not negated_key):
        rule['unmodelled'].append(f'{what} {text}')
    else:
        rule[negated_key if negated else key] = ','.join(got)


def _row_to_rule(row: dict, table: str, order: int, lists: dict, members: dict) -> dict:
    chain = row.get('chain')
    rule = _rule('routeros', table, chain, order, hook=chain if chain in ('input', 'forward', 'output', 'prerouting', 'postrouting') else None, comment=row.get('comment'), proto=_text(row.get('protocol')), id=row.get('.id'))
    action = row.get('action') or 'accept'
    if action == 'jump':
        rule['action'] = f'jump:{row.get("jump-target")}'
    elif action in ('accept', 'drop', 'reject', 'return'):
        rule['action'] = action
    elif action == 'tarpit':
        rule['action'] = 'drop'
    elif action == 'fasttrack-connection':      # accepts, and only ever for established traffic
        rule['action'] = 'accept'
    elif action in NO_VERDICT:
        rule['action'] = None
    elif action in ('dst-nat', 'redirect', 'netmap'):
        rule['action'] = 'dnat'
    elif action in ('src-nat', 'masquerade', 'same'):
        rule['action'] = 'snat'
    else:
        rule['action'] = None
        rule['unmodelled'].append(f'action {action}')
    ports = _text(row.get('dst-port'))
    if ports:
        got = _ports(ports[1:] if ports.startswith('!') else ports)
        if got is None or ports.startswith('!'):
            rule['unmodelled'].append(f'dst-port {ports}')
        else:
            rule['dports'] = got
    _addr(rule, 'saddr', row.get('src-address'), 'not_saddr')
    _addr(rule, 'daddr', row.get('dst-address'))
    _addr(rule, 'iif', row.get('in-interface'), 'not_iif')
    _addr(rule, 'oif', row.get('out-interface'), 'not_oif')
    _named(rule, 'saddr', row.get('src-address-list'), lists, 'not_saddr', 'src-address-list')
    _named(rule, 'daddr', row.get('dst-address-list'), lists, None, 'dst-address-list')
    _named(rule, 'iif', row.get('in-interface-list'), members, 'not_iif', 'in-interface-list')
    _named(rule, 'oif', row.get('out-interface-list'), members, 'not_oif', 'out-interface-list')
    state = _text(row.get('connection-state'))
    if state:
        rule['ct'] = state
    rule['unmodelled'] += [f'{k}={_text(v)}' for k, v in row.items() if k not in KNOWN and v not in (None, '', False) and not k.startswith('.')]
    return rule


def firewall(t: dict) -> dict:
    """The model firewall.py gives for a Linux host. A base chain RouterOS has and no rule uses still takes the rest of the path through its policy."""
    out = {'readable': True, 'backends': ['routeros'], 'policies': {h: 'accept' for h in ('input', 'forward', 'output')},
           'chains': [{'backend': 'routeros', 'table': 'filter', 'name': h, 'hook': h, 'prio': 0, 'policy': 'accept', 'family': 'ip'} for h in ('input', 'forward', 'output')],
           'rules': [], 'nat': [], 'zones': [], 'notes': []}
    if t.get('filter') is None or t.get('nat') is None:
        return {**out, 'readable': False, 'backends': [], 'chains': [], 'notes': ['could not read the firewall tables']}
    lists, members = _lists(t), _members(t)
    for i, row in enumerate(t['filter'], 1):
        if not _yes(row.get('disabled')):
            out['rules'].append(_row_to_rule(row, 'filter', i * 10, lists, members))
    for i, row in enumerate(t['nat'], 1):
        if _yes(row.get('disabled')):
            continue
        rule = _row_to_rule(row, 'nat', i * 10, lists, members)
        to_port = _text(row.get('to-ports'))
        rule.update(to_addr=_text(row.get('to-addresses')), to_port=int(to_port) if str(to_port).isdigit() else None)
        out['nat'].append(rule)
    return out


def facts(t: dict, extra: dict) -> dict:
    """What only a network device has: who it found by discovery, whom it leased to, and its own counters."""
    return {'platform': 'routeros', 'version': extra.get('version'), 'identity': extra.get('identity'), 'board': extra.get('board'), 'uptime': extra.get('uptime'),
            'discovered': [{'ip': n.get('address'), 'mac': str(n.get('mac-address') or '').lower() or None, 'name': n.get('identity'), 'platform': n.get('platform'), 'via': n.get('interface'), 'protocol': _text(n.get('discovered-by'))} for n in t.get('neighbor') or []],
            'leases': [{'ip': x.get('address'), 'mac': str(x.get('mac-address') or '').lower() or None, 'name': x.get('host-name'), 'state': x.get('status'), 'static': not _yes(x.get('dynamic'))} for x in t.get('lease') or []],
            'counters': extra.get('counters') or [], 'connections': extra.get('connections')}


def counters(rows: list[dict] | None) -> list[dict]:
    return [{'iface': r.get('name'), 'rx_bytes': int(r.get('rx-byte') or 0), 'tx_bytes': int(r.get('tx-byte') or 0), 'rx_drop': int(r.get('rx-drop') or 0), 'tx_drop': int(r.get('tx-drop') or 0),
             'rx_error': int(r.get('rx-error') or 0), 'tx_error': int(r.get('tx-error') or 0)} for r in rows or [] if r.get('name')]


def collect(run) -> dict:
    """run(command) → text. {'net', 'firewall', 'facts'}. A device that doesn't know :serialize is asked again in the older format, table by table."""
    tables: dict = {}
    legacy = parse_table(run(command('/ip/address'))) is None
    for key, path in TABLES.items():
        if legacy:
            tables[key] = parse_terse(run(legacy_command(path)))
        else:
            tables[key] = parse_table(run(command(path)))
    info: dict = {}
    if legacy:
        res = run('/system resource print')
        m = re.search(r'version:\s*(\S+)', res)
        info['version'] = m[1] if m else None
        m = re.search(r'name:\s*(\S+)', run('/system identity print'))
        info['identity'] = m[1] if m else None
    else:
        res = parse_table(run(':put [:serialize to=json [/system/resource/get]]')) or [{}]
        info.update(version=res[0].get('version'), board=res[0].get('board-name'), uptime=_text(res[0].get('uptime')))
        info['identity'] = (run(':put [/system/identity/get name]') or '').strip() or None
        tables['dns'] = (parse_table(run(':put [:serialize to=json [/ip/dns/get]]')) or [{}])[0]
        info['counters'] = counters(parse_table(run(':put [:serialize to=json [/interface/print stats as-value]]')))
        count = (run('/ip/firewall/connection/print count-only') or '').strip()
        info['connections'] = int(count) if count.isdigit() else None
    missing = [k for k in MUST_READ if tables.get(k) is None]
    if missing:
        raise ValueError('could not read ' + ', '.join(TABLES[k] for k in missing) + ' from this device')
    return {'net': network(tables), 'firewall': firewall(tables), 'facts': facts(tables, info), 'os': f'RouterOS {info.get("version") or "unknown"}', 'identity': info.get('identity'), 'config': None}
