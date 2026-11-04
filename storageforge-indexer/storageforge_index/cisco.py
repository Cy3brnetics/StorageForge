"""Cisco IOS and IOS-XE, from `show` commands over a terminal. Only reads. Text is all these devices give over SSH, so each parser takes what it can name and anything it can't
stays out of the model: an ACL line it doesn't follow is kept and marked unmodelled, because a rule nobody understood may still decide what passes.

Written against published formats and a simulated shell: no Cisco image is freely available for the KVM lab, so none of this has met a real device.
An ACL applies to traffic crossing the interface it is bound to, so rules are per ACL and a base chain is made per direction. What no ACL covers is permitted, as IOS does.
"""
from __future__ import annotations

import ipaddress
import re

from .firewall import _rule

COMMANDS = {'version': 'show version', 'brief': 'show ip interface brief', 'running': 'show running-config', 'route': 'show ip route', 'arp': 'show ip arp', 'acl': 'show ip access-lists', 'vlan': 'show vlan brief',
            'cdp': 'show cdp neighbors detail', 'lldp': 'show lldp neighbors detail', 'mac': 'show mac address-table', 'nat': 'show ip nat translations', 'counters': 'show interfaces'}
SERVICES = {'www': 80, 'http': 80, 'https': 443, 'ssh': 22, 'telnet': 23, 'smtp': 25, 'domain': 53, 'ftp': 21, 'ntp': 123, 'pop3': 110, 'imap': 143, 'snmp': 161, 'syslog': 514, 'bgp': 179, 'tftp': 69, 'isakmp': 500}
ERROR = re.compile(r'^\s*(?:% ?Invalid|% ?Incomplete|% ?Ambiguous|% ?Unknown|% ?Authorization)', re.M)
SECRET = re.compile(r'^(\s*(?:username|enable (?:secret|password)|snmp-server community|.*\bpassword\b|.*\bsecret\b|.*\bkey\b)).*$', re.M | re.I)


def strip_secrets(config: str) -> str:
    """A running config holds password hashes and community strings. What it says about them is replaced before it goes anywhere."""
    return SECRET.sub(lambda m: f'{m[1].split()[0]} <removed>', config or '')


def wildcard_to_cidr(addr: str, wild: str) -> str | None:
    """10.0.0.0 0.0.0.255 → 10.0.0.0/24. A wildcard with holes in it has no CIDR."""
    try:
        bits = int(ipaddress.ip_address(wild))
    except ValueError:
        return None
    if bits & (bits + 1):
        return None
    inverse = bits ^ 0xFFFFFFFF
    prefix = bin(inverse).count('1')
    try:
        return str(ipaddress.ip_network(f'{addr}/{prefix}', strict=False))
    except ValueError:
        return None


def _endpoint(words: list[str]) -> tuple[str | None, bool]:
    """Takes an address spec off the front of words. (cidr or None for any, understood)."""
    w = words.pop(0)
    if w == 'any':
        return None, True
    if w == 'host':
        return f'{words.pop(0)}/32', True
    if w == 'object-group' or w == 'addrgroup':
        name = words.pop(0)
        return f'@{name}', False
    if words and re.fullmatch(r'[0-9.]+', words[0]):
        wild = words.pop(0)
        got = wildcard_to_cidr(w, wild)
        return (got, True) if got else (f'{w} {wild}', False)
    return f'{w}/32', True


def _port_op(words: list[str]) -> tuple[list, bool]:
    """eq, range, gt, lt, neq off the front. ([], True) when there's none."""
    if not words or words[0] not in ('eq', 'range', 'gt', 'lt', 'neq'):
        return [], True
    op = words.pop(0)

    def num(t):
        return int(t) if t.isdigit() else SERVICES.get(t)
    if op == 'eq':
        vals = []
        while words and (num(words[0]) is not None):
            vals.append(num(words.pop(0)))
        return vals, bool(vals)
    if op == 'range':
        low, high = num(words.pop(0)), num(words.pop(0))
        return [[low, high]], low is not None and high is not None
    value = num(words.pop(0))
    if value is None or op == 'neq':
        return [], False
    return ([[value + 1, 65535]] if op == 'gt' else [[1, value - 1]]), True


def parse_ace(line: str, acl: str, order: int) -> dict | None:
    m = re.match(r'^\s*(?:(\d+)\s+)?(permit|deny)\s+(.*?)(?:\s*\(\d+ match(?:es)?\))?\s*$', line)
    if not m:
        return None
    words = m[3].split()
    rule = _rule('cisco_acl', 'acl', acl, int(m[1]) if m[1] else order, action='accept' if m[2] == 'permit' else 'drop', unmodelled=[])
    extended = bool(words) and (words[0] in ('ip', 'tcp', 'udp', 'icmp', 'gre', 'esp', 'ahp', 'ospf', 'eigrp', 'pim') or words[0].isdigit() or words[0] == 'object-group') and len(words) > 2
    try:
        if not extended:
            src, ok = _endpoint(words)
            if not ok:
                rule['unmodelled'].append(f'source {src}')
            rule['saddr'] = src if ok else None
        else:
            proto = words.pop(0)
            rule['proto'] = None if proto == 'ip' else proto
            src, ok = _endpoint(words)
            if not ok:
                rule['unmodelled'].append(f'source {src}')
            rule['saddr'] = src if ok else None
            _, ok = _port_op(words)
            if not ok:
                rule['unmodelled'].append('source port')
            elif _:
                rule['unmodelled'].append('source port')
            dst, ok = _endpoint(words)
            if not ok:
                rule['unmodelled'].append(f'destination {dst}')
            rule['daddr'] = dst if ok else None
            ports, ok = _port_op(words)
            rule['dports'] = ports
            if not ok:
                rule['unmodelled'].append('destination port')
        rest = [w for w in words if w not in ('log', 'log-input')]
        if rest == ['established']:
            rule['ct'] = 'established,related'
        elif rest:
            rule['unmodelled'].append(' '.join(rest))
    except (IndexError, ValueError):
        rule['unmodelled'].append(line.strip())
    return rule


def parse_acls(text: str) -> dict:
    """{name: [rule, ...]}, from `show ip access-lists`."""
    out: dict = {}
    current = None
    for line in (text or '').splitlines():
        m = re.match(r'^(?:Standard|Extended|Reflexive)\s+IP access list\s+(\S+)', line)
        if m:
            current = out.setdefault(m[1], [])
            continue
        if current is not None and line[:1].isspace():
            got = parse_ace(line, next(k for k, v in out.items() if v is current), (len(current) + 1) * 10)
            if got:
                current.append(got)
    return out


def parse_running(text: str) -> dict:
    """Per interface: description, address, VLAN mode, ACL bindings, NAT side. And: hostname, static NAT, default gateway."""
    out = {'interfaces': {}, 'hostname': None, 'nat': [], 'name_servers': []}
    cur = None
    for line in (text or '').splitlines():
        if not line.startswith(' '):
            cur = None
        m = re.match(r'^hostname (\S+)', line)
        if m:
            out['hostname'] = m[1]
        m = re.match(r'^interface (\S+)', line)
        if m:
            cur = out['interfaces'].setdefault(m[1], {'acl_in': None, 'acl_out': None, 'nat': None, 'mode': None, 'access_vlan': None, 'trunk_vlans': [], 'channel': None, 'shutdown': False, 'descr': None, 'addresses': []})
            continue
        m = re.match(r'^ip name-server (.*)', line)
        if m:
            out['name_servers'] += m[1].split()
        m = re.match(r'^ip nat inside source static (tcp|udp)\s+(\S+)\s+(\d+)\s+(?:interface\s+(\S+)|(\S+))\s+(\d+)', line)
        if m:
            out['nat'].append(_rule('cisco_acl', 'nat', 'dstnat', len(out['nat']) + 1, action='dnat', proto=m[1], dports=[int(m[6])], to_addr=m[2], to_port=int(m[3]), iif=m[4], daddr=m[5]))
        elif (m := re.match(r'^ip nat inside source static\s+(\S+)\s+(\S+)', line)):
            out['nat'].append(_rule('cisco_acl', 'nat', 'dstnat', len(out['nat']) + 1, action='dnat', to_addr=m[1], daddr=m[2]))
        if cur is None:
            continue
        s = line.strip()
        if (m := re.match(r'^ip access-group (\S+) (in|out)', s)):
            cur[f'acl_{m[2]}'] = m[1]
        elif s == 'ip nat inside':
            cur['nat'] = 'inside'
        elif s == 'ip nat outside':
            cur['nat'] = 'outside'
        elif (m := re.match(r'^switchport mode (\S+)', s)):
            cur['mode'] = m[1]
        elif (m := re.match(r'^switchport access vlan (\d+)', s)):
            cur['access_vlan'] = int(m[1])
        elif (m := re.match(r'^switchport trunk allowed vlan (?:add )?([\d,-]+)', s)):
            from .routeros import _vlans
            cur['trunk_vlans'] += _vlans(m[1])
        elif (m := re.match(r'^channel-group (\d+)', s)):
            cur['channel'] = f'Port-channel{m[1]}'
        elif s == 'shutdown':
            cur['shutdown'] = True
        elif (m := re.match(r'^description (.*)', s)):
            cur['descr'] = m[1]
        elif (m := re.match(r'^ip address (\S+) (\S+)', s)):
            try:
                cur['addresses'].append({'ip': m[1], 'prefix': ipaddress.ip_network(f'0.0.0.0/{m[2]}').prefixlen, 'scope': 'global'})
            except ValueError:
                pass
    return out


def parse_brief(text: str) -> dict:
    out = {}
    for line in (text or '').splitlines():
        f = line.split()
        if len(f) >= 6 and f[0] != 'Interface':
            state = ' '.join(f[4:-1])
            out[f[0]] = {'ip': None if f[1] == 'unassigned' else f[1], 'state': 'up' if f[-1] == 'up' and 'down' not in state else 'down'}
    return out


def parse_routes(text: str) -> list[dict]:
    """`show ip route`: C and L are on an interface, S and the dynamic codes have `via`. `*` marks a candidate default."""
    out = []
    for line in (text or '').splitlines():
        m = re.match(r'^([A-Z][A-Za-z0-9 *%+]{0,6}?)\s+([0-9.]+(?:/\d+)?)\s+(?:\[(\d+)/(\d+)\]\s+)?(?:via ([0-9.]+)|is directly connected)(?:,\s*(?:\S+,\s*)?(\S+))?', line)
        if not m or m[1].strip().startswith('L'):
            continue
        dst = m[2]
        out.append({'dst': 'default' if dst.startswith('0.0.0.0') else dst, 'via': m[5], 'dev': m[6], 'metric': int(m[4]) if m[4] else None, 'family': 4})
    return out


def parse_arp(text: str) -> list[dict]:
    out = []
    for line in (text or '').splitlines():
        f = line.split()
        if len(f) >= 6 and f[0] == 'Internet' and f[3] != 'Incomplete':
            dotted = f[3].replace('.', '')
            out.append({'ip': f[1], 'mac': ':'.join(dotted[i:i + 2] for i in range(0, 12, 2)), 'dev': f[5]})
    return out[:500]


def parse_cdp(text: str) -> list[dict]:
    out = []
    for block in re.split(r'^-{5,}\s*$', text or '', flags=re.M):
        name = re.search(r'Device ID:\s*(\S+)', block)
        if not name:
            continue
        ip = re.search(r'IP(?:v4)? [Aa]ddress:\s*([0-9.]+)', block)
        platform = re.search(r'Platform:\s*([^,\n]+)', block)
        port = re.search(r'Interface:\s*([^,\s]+),\s*Port ID \(outgoing port\):\s*(\S+)', block)
        out.append({'name': name[1], 'ip': ip[1] if ip else None, 'platform': platform[1].strip() if platform else None, 'via': port[1] if port else None, 'remote_port': port[2] if port else None, 'protocol': 'cdp'})
    return out


def parse_lldp(text: str) -> list[dict]:
    out = []
    for block in re.split(r'^-{5,}\s*$', text or '', flags=re.M):
        name = re.search(r'System Name:\s*(\S+)', block)
        if not name:
            continue
        ip = re.search(r'IP:\s*([0-9.]+)', block)
        port = re.search(r'Port id:\s*(\S+)', block)
        via = re.search(r'Local Intf:\s*(\S+)', block)
        out.append({'name': name[1], 'ip': ip[1] if ip else None, 'platform': None, 'via': via[1] if via else None, 'remote_port': port[1] if port else None, 'protocol': 'lldp'})
    return out


def parse_vlans(text: str) -> list[dict]:
    out = []
    for line in (text or '').splitlines():
        m = re.match(r'^(\d+)\s+(\S+)\s+(active|act/\S+|suspended)\s*(.*)$', line)
        if m:
            out.append({'id': int(m[1]), 'name': m[2], 'ports': [p.strip() for p in m[4].split(',') if p.strip()]})
    return out


def parse_counters(text: str) -> list[dict]:
    out, cur = [], None
    for line in (text or '').splitlines():
        m = re.match(r'^(\S+) is (?:administratively )?\S+, line protocol', line)
        if m:
            cur = {'iface': m[1], 'rx_bytes': 0, 'tx_bytes': 0, 'rx_drop': 0, 'tx_drop': 0, 'rx_error': 0, 'tx_error': 0}
            out.append(cur)
        elif cur:
            if (m := re.search(r'(\d+) packets input, (\d+) bytes', line)):
                cur['rx_bytes'] = int(m[2])
            elif (m := re.search(r'(\d+) packets output, (\d+) bytes', line)):
                cur['tx_bytes'] = int(m[2])
            elif (m := re.search(r'(\d+) input errors', line)):
                cur['rx_error'] = int(m[1])
            elif (m := re.search(r'(\d+) output errors', line)):
                cur['tx_error'] = int(m[1])
    return out


def _kind(name: str) -> str:
    low = name.lower()
    return 'bond' if low.startswith('port-channel') else 'vlan' if low.startswith('vlan') else 'loopback' if low.startswith('loopback') else 'tunnel' if low.startswith('tunnel') else 'ethernet'


def model(t: dict) -> dict:
    """t: each command's text. Raises when what must be read wasn't."""
    for key in ('brief', 'running', 'route', 'acl'):
        if t.get(key) is None or ERROR.search(t.get(key) or ''):
            raise ValueError(f'could not read `{COMMANDS[key]}`: enable mode may be needed')
    run = parse_running(t['running'])
    brief = parse_brief(t['brief'])
    interfaces = []
    names = sorted(set(brief) | set(run['interfaces']))
    for name in names:
        cfg = run['interfaces'].get(name) or {}
        addrs = cfg.get('addresses') or ([{'ip': brief[name]['ip'], 'prefix': None, 'scope': 'global'}] if brief.get(name, {}).get('ip') else [])
        vlan = re.match(r'^Vlan(\d+)$', name, re.I)
        interfaces.append({'name': name, 'kind': _kind(name), 'state': (brief.get(name) or {}).get('state') or ('down' if cfg.get('shutdown') else 'unknown'), 'mtu': None, 'mac': None, 'master': cfg.get('channel'), 'parent': None,
                           'vlan_id': int(vlan[1]) if vlan else cfg.get('access_vlan'), 'bridge_vlans': cfg.get('trunk_vlans') or [], 'switchport': cfg.get('mode'), 'descr': cfg.get('descr'), 'nat_side': cfg.get('nat'), 'addresses': addrs})
    routes = parse_routes(t['route'])
    net = {'interfaces': interfaces, 'routes': routes, 'gateways': sorted({r['via'] for r in routes if r['dst'] == 'default' and r['via']}), 'neighbours': parse_arp(t.get('arp')), 'listeners': [],
           'dns': {'nameservers': run['name_servers'], 'search': []}, 'unreadable': ['listeners'], 'complete': True}
    acls = parse_acls(t['acl'])
    fw = {'readable': True, 'backends': ['cisco_acl'], 'policies': {'input': 'accept', 'forward': 'accept', 'output': 'accept'}, 'chains': [], 'rules': [], 'nat': run['nat'], 'zones': [], 'notes': [], 'interface_acls': {}}
    # An ACL on an interface sees what crosses that interface: one forward chain, and within it one jump per binding, guarded by the interface
    fw['chains'].append({'backend': 'cisco_acl', 'table': 'acl', 'name': 'forward', 'hook': 'forward', 'prio': 0, 'policy': 'accept', 'family': 'ip'})
    fw['chains'].append({'backend': 'cisco_acl', 'table': 'acl', 'name': 'input', 'hook': 'input', 'prio': 0, 'policy': 'accept', 'family': 'ip'})
    order = 0
    for name, cfg in run['interfaces'].items():
        for side, key in (('in', 'acl_in'), ('out', 'acl_out')):
            acl = cfg.get(key)
            if not acl:
                continue
            fw['interface_acls'].setdefault(name, {})[side] = acl
            if acl not in acls:
                fw['notes'].append(f'{name} names ACL {acl}, which was not read')
                continue
            # an ACL ends in an implicit deny: that is part of what it says
            for rule in acls[acl]:
                order += 1
                fw['rules'].append({**rule, 'chain': 'forward', 'order': order, 'hook': 'forward', 'iif': name if side == 'in' else None, 'oif': name if side == 'out' else None, 'acl': acl})
            order += 1
            fw['rules'].append(_rule('cisco_acl', 'acl', 'forward', order, action='drop', hook='forward', iif=name if side == 'in' else None, oif=name if side == 'out' else None, acl=acl, comment=f'{acl}: implicit deny'))
    version = re.search(r'Version ([^\s,]+)', t.get('version') or '')
    return {'net': net, 'firewall': fw, 'os': f'Cisco IOS {version[1] if version else "unknown"}', 'identity': run['hostname'],
            'facts': {'platform': 'cisco', 'version': version[1] if version else None, 'identity': run['hostname'], 'discovered': parse_cdp(t.get('cdp')) + parse_lldp(t.get('lldp')), 'leases': [], 'vlans': parse_vlans(t.get('vlan')), 'counters': parse_counters(t.get('counters')),
                      'wan': [n for n, c in run['interfaces'].items() if c.get('nat') == 'outside']}, 'config': strip_secrets(t['running'])}


def collect(run) -> dict:
    texts = {}
    for key, cmd in COMMANDS.items():
        try:
            texts[key] = run(cmd)
        except Exception:
            if key in ('brief', 'running', 'route', 'acl'):
                raise
            texts[key] = None
    return model(texts)
