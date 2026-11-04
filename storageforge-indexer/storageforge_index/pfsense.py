"""pfSense and OPNsense: /conf/config.xml is the source of truth, read once, with `pfctl` for what the kernel has loaded. Only reads.

config.xml holds password hashes, private keys and API secrets, so this names what it takes and copies nothing else out: the file itself is never stored.
Parsed with the standard library's expat under a limit, and any document declaring an entity is refused: a device isn't trusted not to send a billion laughs.
"""
from __future__ import annotations

import ipaddress
import re
from xml.etree import ElementTree

from .firewall import _ports, _rule

MAX_XML = 16 << 20
SCRIPT = """
export LC_ALL=C PATH=$PATH:/sbin:/usr/sbin:/usr/local/sbin
echo '@@config'; cat /cf/conf/config.xml 2>/dev/null || cat /conf/config.xml 2>/dev/null
echo; echo '@@version'; cat /etc/version 2>/dev/null; opnsense-version 2>/dev/null
echo; echo '@@hostname'; hostname
echo; echo '@@ifconfig'; ifconfig -a 2>/dev/null
echo; echo '@@netstat'; netstat -rn 2>/dev/null
echo; echo '@@arp'; arp -an 2>/dev/null
echo; echo '@@sockstat'; sockstat -4 -6 -l 2>/dev/null
echo; echo '@@pfrules'; pfctl -sr 2>/dev/null
echo; echo '@@pfnat'; pfctl -sn 2>/dev/null
echo; echo '@@pfstates'; pfctl -si 2>/dev/null
echo; echo '@@end'
"""
SECTIONS = ('config', 'version', 'hostname', 'ifconfig', 'netstat', 'arp', 'sockstat', 'pfrules', 'pfnat', 'pfstates', 'end')


def sections(text: str) -> dict:
    out, cur = {}, None
    for line in text.splitlines():
        if line.startswith('@@') and line[2:] in SECTIONS:
            cur = line[2:]
            out[cur] = []
        elif cur:
            out[cur].append(line)
    return {k: '\n'.join(v).strip() for k, v in out.items()}


def load_xml(text: str):
    if not text or len(text) > MAX_XML:
        raise ValueError('config.xml is missing or too large')
    if re.search(r'<!(?:DOCTYPE|ENTITY)', text):
        raise ValueError('config.xml declares an entity: refused')
    return ElementTree.fromstring(text)


def _t(node, path, default=None):
    got = node.find(path) if node is not None else None
    return (got.text or '').strip() if got is not None and got.text else default


def _has(node, path) -> bool:
    return node is not None and node.find(path) is not None


def _prefix(mask) -> int | None:
    return int(mask) if str(mask or '').isdigit() else None


def interfaces(root) -> dict:
    """{logical name: {'if', 'descr', 'ip', 'prefix', 'gateway', 'enabled', 'mtu', 'mac'}}."""
    out = {}
    for node in list(root.find('interfaces') if root.find('interfaces') is not None else []):
        out[node.tag] = {'if': _t(node, 'if'), 'descr': _t(node, 'descr') or node.tag, 'ip': _t(node, 'ipaddr'), 'prefix': _prefix(_t(node, 'subnet')), 'gateway': _t(node, 'gateway'),
                         'enabled': _has(node, 'enable'), 'mtu': _t(node, 'mtu'), 'mac': _t(node, 'spoofmac')}
    return out


def aliases(root) -> dict:
    """{name: 'value,value'}, expanding an alias in an alias. Unknown or URL aliases are left out, so a rule naming one stays unmodelled."""
    raw = {}
    for a in root.findall('aliases/alias') + root.findall('OPNsense/Firewall/Alias/aliases/alias'):
        kind, name, content = _t(a, 'type'), _t(a, 'name'), _t(a, 'address') or _t(a, 'content')
        if name and kind in ('host', 'network', 'port') and content:
            raw[name] = re.split(r'[\s,]+', content.strip())
    def expand(name, depth=0):
        out = []
        for v in raw.get(name, []):
            out += expand(v, depth + 1) if v in raw and depth < 8 else [v]
        return out
    return {k: ','.join(expand(k)) for k in raw}


def _endpoint(node, ifaces, table) -> tuple:
    """(address, negated) of a <source> or <destination>. ('unknown', ..) when it names an alias that isn't known."""
    if node is None or _has(node, 'any'):
        return None, False
    negated = _has(node, 'not')
    addr = _t(node, 'address')
    net = _t(node, 'network')
    if addr:
        if addr in table:
            return table[addr], negated
        try:
            ipaddress.ip_network(addr, strict=False)
            return addr, negated
        except ValueError:
            return f'@{addr}', negated
    if net:
        base = net[:-2] if net.endswith('ip') else net
        i = ifaces.get(base)
        if i and i.get('ip') and i.get('prefix') is not None:
            return (i['ip'] if net.endswith('ip') else str(ipaddress.ip_interface(f'{i["ip"]}/{i["prefix"]}').network)), negated
        return f'@{net}', negated
    return None, negated


def firewall(root, ifaces: dict) -> dict:
    """pf reads top to bottom with the last match winning unless `quick`, and the GUI writes every rule quick. Interface tabs hold rules for what comes in on that
    interface. What no rule passes is blocked by pfSense's default deny."""
    table = aliases(root)
    out = {'readable': True, 'backends': ['pf'], 'policies': {'input': 'drop', 'forward': 'drop', 'output': 'accept'},
           'chains': [{'backend': 'pf', 'table': 'filter', 'name': h, 'hook': h, 'prio': 0, 'policy': p, 'family': 'ip'} for h, p in (('input', 'drop'), ('forward', 'drop'), ('output', 'accept'))],
           'rules': [], 'nat': [], 'zones': [], 'notes': []}
    own = {i['ip'] for i in ifaces.values() if i.get('ip') and i['ip'] != 'dhcp'}
    for i, r in enumerate(root.findall('filter/rule'), 1):
        if _has(r, 'disabled'):
            continue
        kind = (_t(r, 'type') or 'pass')
        action = {'pass': 'accept', 'block': 'drop', 'reject': 'reject'}.get(kind, None)
        names = (_t(r, 'interface') or '').split(',')
        devices = [ifaces[n]['if'] for n in names if n in ifaces and ifaces[n].get('if')]
        src, src_not = _endpoint(r.find('source'), ifaces, table)
        dst, dst_not = _endpoint(r.find('destination'), ifaces, table)
        proto = (_t(r, 'protocol') or '').lower() or None
        rule_common = dict(action=action, proto='tcp,udp' if proto == 'tcp/udp' else proto, comment=_t(r, 'descr'), iif=','.join(devices) or None)
        unmodelled = []
        if devices == [] and names != ['']:
            unmodelled.append(f'interface {",".join(names)}')
        port = _t(r.find('destination'), 'port') if r.find('destination') is not None else None
        dports = []
        if port:
            value = table.get(port, port)
            dports = _ports(value.replace(' ', ','))
            if dports is None:
                unmodelled.append(f'port {port}')
                dports = []
        if str(src or '').startswith('@'):
            unmodelled.append(f'source {src}')
            src = None
        if str(dst or '').startswith('@'):
            unmodelled.append(f'destination {dst}')
            dst = None
        if dst_not:
            unmodelled.append(f'destination not {dst}')
            dst = None
        extra = {'not_saddr': src, 'saddr': None} if src_not else {'saddr': src}
        # one rule written for "this firewall" is input, for anything else is forward; an unnamed destination goes on both
        for chain in (['input'] if dst and dst in own else ['forward'] if dst else ['input', 'forward']):
            out['rules'].append(_rule('pf', 'filter', chain, i * 10, hook=chain, dports=dports, daddr=dst, unmodelled=list(unmodelled), **rule_common, **extra))
    for i, r in enumerate(root.findall('nat/rule'), 1):
        if _has(r, 'disabled'):
            continue
        dest = r.find('destination')
        port = _t(dest, 'port') if dest is not None else None
        value = table.get(port or '', port)
        target, local = _t(r, 'target'), _t(r, 'local-port')
        name = _t(r, 'interface')
        rule = _rule('pf', 'nat', 'dstnat', i * 10, action='dnat', proto=_t(r, 'protocol'), dports=_ports(value) or [] if value else [], iif=(ifaces.get(name) or {}).get('if'), comment=_t(r, 'descr'),
                     to_addr=table.get(target or '', target), to_port=int(local) if str(local or '').isdigit() else None)
        out['nat'].append(rule)
    for i, r in enumerate(root.findall('nat/onetoone'), 1):
        if not _has(r, 'disabled'):
            out['nat'].append(_rule('pf', 'nat', 'dstnat', 1000 + i, action='dnat', iif=(ifaces.get(_t(r, 'interface') or '') or {}).get('if'), comment=_t(r, 'descr'), daddr=_t(r, 'external'), to_addr=_t(r.find('source'), 'address')))
    return out


def network(root, ifaces: dict, s: dict) -> dict:
    live = _ifconfig(s.get('ifconfig') or '')
    rows, vlans = [], {_t(v, 'vlanif'): v for v in root.findall('vlans/vlan')}
    for logical, i in ifaces.items():
        dev = i.get('if')
        if not dev:
            continue
        seen = live.get(dev) or {}
        ip = i.get('ip')
        addrs = seen.get('addresses') or ([{'ip': ip, 'prefix': i.get('prefix'), 'scope': 'global'}] if ip and ip not in ('dhcp', 'dhcp6') else [])
        vlan = vlans.get(dev)
        rows.append({'name': dev, 'logical': logical, 'descr': i.get('descr'), 'kind': 'vlan' if vlan is not None else 'ethernet', 'state': seen.get('state') or ('up' if i.get('enabled') else 'down'), 'mtu': seen.get('mtu') or (int(i['mtu']) if str(i.get('mtu') or '').isdigit() else None),
                     'mac': seen.get('mac') or i.get('mac'), 'master': None, 'parent': _t(vlan, 'if') if vlan is not None else None, 'vlan_id': int(_t(vlan, 'tag')) if vlan is not None and str(_t(vlan, 'tag') or '').isdigit() else None, 'bridge_vlans': [], 'addresses': addrs})
    routes = parse_netstat(s.get('netstat') or '')
    if not routes:
        for r in root.findall('staticroutes/route'):
            routes.append({'dst': _t(r, 'network'), 'via': _gateway(root, _t(r, 'gateway')), 'dev': None, 'metric': None, 'family': 4})
        for g in root.findall('gateways/gateway_item'):
            if _has(g, 'defaultgw'):
                routes.append({'dst': 'default', 'via': _t(g, 'gateway'), 'dev': (ifaces.get(_t(g, 'interface') or '') or {}).get('if'), 'metric': None, 'family': 4})
    listeners = parse_sockstat(s.get('sockstat') or '')
    return {'interfaces': rows, 'routes': routes, 'gateways': sorted({r['via'] for r in routes if r['dst'] == 'default' and r['via']}), 'neighbours': parse_arp(s.get('arp') or ''), 'listeners': listeners,
            'dns': {'nameservers': [x.text.strip() for x in root.findall('system/dnsserver') if x.text], 'search': [_t(root, 'system/domain')] if _t(root, 'system/domain') else []},
            'unreadable': [] if s.get('sockstat') else ['listeners'], 'complete': True}


def _gateway(root, name):
    for g in root.findall('gateways/gateway_item'):
        if _t(g, 'name') == name:
            return _t(g, 'gateway')
    return None


def _ifconfig(text: str) -> dict:
    out, cur = {}, None
    for line in text.splitlines():
        m = re.match(r'^(\S+): flags=\S*<([^>]*)>.*?mtu (\d+)', line)
        if m:
            cur = out.setdefault(m[1], {'state': 'up' if 'UP' in m[2].split(',') else 'down', 'mtu': int(m[3]), 'addresses': [], 'mac': None})
            continue
        if not cur:
            continue
        m = re.match(r'\s+inet (\S+) netmask (0x[0-9a-f]+)', line)
        if m:
            cur['addresses'].append({'ip': m[1], 'prefix': bin(int(m[2], 16)).count('1'), 'scope': 'global'})
        m = re.match(r'\s+ether (\S+)', line)
        if m:
            cur['mac'] = m[1].lower()
    return out


def parse_netstat(text: str) -> list[dict]:
    out, family = [], None
    for line in text.splitlines():
        if line.startswith('Internet:'):
            family = 4
        elif line.startswith('Internet6:'):
            family = 6
        f = line.split()
        if family and len(f) >= 4 and f[0] not in ('Destination', 'Internet:', 'Internet6:'):
            gw = f[1]
            via = gw if re.fullmatch(r'[0-9.]+|[0-9a-f:]+', gw) else None
            out.append({'dst': 'default' if f[0] == 'default' else f[0], 'via': via, 'dev': f[3] if len(f) > 3 else None, 'metric': None, 'family': family})
    return out


def parse_arp(text: str) -> list[dict]:
    out = []
    for line in text.splitlines():
        m = re.match(r'\S+ \(([0-9.]+)\) at ([0-9a-f:]+) on (\S+)', line)
        if m:
            out.append({'ip': m[1], 'mac': m[2], 'dev': m[3]})
    return out[:500]


def parse_sockstat(text: str) -> list[dict]:
    """sockstat -l: USER COMMAND PID FD PROTO LOCAL FOREIGN. Its local column ends in :port, and *: means every address."""
    out, seen = [], set()
    for line in text.splitlines():
        f = line.split()
        if len(f) < 6 or f[0] == 'USER' or not f[4].startswith(('tcp', 'udp')):
            continue
        addr, _, port = f[5].rpartition(':')
        if not port.isdigit():
            continue
        key = (f[4][:3], addr, port)
        if key in seen:
            continue
        seen.add(key)
        scope = 'any' if addr in ('*', '0.0.0.0', '::') else 'loopback' if addr.startswith(('127.', '::1')) else 'address'
        out.append({'proto': f[4][:3], 'addr': addr, 'port': int(port), 'scope': scope, 'process': [f[1]]})
    return sorted(out, key=lambda x: x['port'])


def parse(text: str) -> dict:
    s = sections(text)
    if 'end' not in s:
        raise ValueError('the reading was cut short')
    root = load_xml(s.get('config') or '')
    ifaces = interfaces(root)
    fw = firewall(root, ifaces)
    net = network(root, ifaces, s)
    version = (s.get('version') or '').splitlines()[0] if s.get('version') else None
    wan = [i['if'] for k, i in ifaces.items() if k == 'wan' and i.get('if')]
    return {'net': net, 'firewall': fw, 'os': f'{"OPNsense" if root.tag == "opnsense" else "pfSense"} {version or "unknown"}', 'identity': s.get('hostname') or _t(root, 'system/hostname'),
            'facts': {'platform': 'opnsense' if root.tag == 'opnsense' else 'pfsense', 'version': version, 'identity': s.get('hostname'), 'wan': wan, 'discovered': [], 'counters': [],
                      'leases': [{'ip': _t(m, 'ipaddr'), 'mac': (_t(m, 'mac') or '').lower() or None, 'name': _t(m, 'hostname'), 'static': True} for m in root.findall('dhcpd/*/staticmap')],
                      'vpn': {'wireguard': bool(root.findall('wireguard') or root.findall('OPNsense/wireguard')), 'openvpn': bool(root.findall('openvpn/openvpn-server') or root.findall('openvpn/openvpn-client'))}}, 'config': None}


def collect(run) -> dict:
    return parse(run(SCRIPT))
