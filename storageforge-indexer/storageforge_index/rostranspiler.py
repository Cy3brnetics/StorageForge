"""One way to write a network: RouterOS's syntax, whatever the target runs. parse() reads it into statements and refuses anything it can't vouch for, each emitter writes one target's native
form, and from_model() goes back the other way, so a rule read from any firewall shows up in the same syntax.

Every value is checked against a pattern for its kind before anything sees it, because these become shell lines, XML and device commands. A statement a target can't express is listed in `unsupported`,
never quietly dropped: what the operator wrote and what got emitted must not differ without saying so.

    emit(stmts, target) → {'target', 'text', 'files', 'unsupported': [...], 'notes': [...]}
"""
from __future__ import annotations

import ipaddress
import re
import shlex
from dataclasses import dataclass, field
from xml.sax.saxutils import escape

MAX_STATEMENTS = 2000
NAME = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._:/-]{0,63}$')
COMMENT = re.compile(r'^[^\x00-\x1f\x7f"\'`$\\<>;&|\[\]{}]{0,120}$')     # [ ] is a command to RouterOS, and { } to its scripts
MAC = re.compile(r'^[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}$')
WGKEY = re.compile(r'^[A-Za-z0-9+/]{42,43}=$')
PROTOS = {'tcp', 'udp', 'icmp', 'icmpv6', 'gre', 'esp', 'ah', 'ospf', 'any'}
ACTIONS = {'accept', 'drop', 'reject', 'jump', 'return', 'log', 'passthrough', 'fasttrack-connection'}
NAT_ACTIONS = {'dst-nat', 'src-nat', 'masquerade', 'redirect'}
STATES = {'new', 'established', 'related', 'invalid', 'untracked'}
TARGETS = ('routeros', 'nftables', 'iptables', 'firewalld', 'ufw', 'openwrt', 'pfsense', 'cisco', 'networkd', 'networkmanager')


class DslError(ValueError):
    pass


def _ip_ok(v):
    ipaddress.ip_address(v)


def _cidr(v):
    if v.startswith('!'):
        v = v[1:]
    if '-' in v:
        a, b = v.split('-', 1)
        ipaddress.ip_address(a), ipaddress.ip_address(b)
    else:
        ipaddress.ip_network(v, strict=False)


def _iface_addr(v):
    ipaddress.ip_interface(v)
    if '/' not in v:
        raise ValueError('needs a prefix')


def _ports(v):
    for part in v.lstrip('!').split(','):
        low, _, high = part.partition('-')
        if not low.isdigit() or not 0 < int(low) < 65536 or (high and (not high.isdigit() or not int(low) <= int(high) < 65536)):
            raise ValueError('not a port')


def _int(v):
    if not v.isdigit() or len(v) > 9:
        raise ValueError('not a number')


def _yesno(v):
    if v not in ('yes', 'no', 'true', 'false'):
        raise ValueError('yes or no')


def _name(v):
    if not NAME.fullmatch(v.lstrip('!')):
        raise ValueError('not a plain name')


def _names(v):
    for x in v.split(','):
        _name(x)


HIDDEN = re.compile(r'[\u200b-\u200f\u2028\u2029\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]')      # they reorder or hide what a person reads in the output (SF-53)


def _comment(v):
    if HIDDEN.search(v):
        raise ValueError('holds a text-direction or zero-width character')
    if not COMMENT.fullmatch(v):
        raise ValueError('holds a character that would not survive a target')


def _mac(v):
    if not MAC.fullmatch(v):
        raise ValueError('not a MAC address')


def _oneof(*options):
    def check(v):
        if v not in options:
            raise ValueError('one of ' + ', '.join(options))
    return check


def _proto(v):
    if v not in PROTOS and not (v.isdigit() and int(v) < 256):
        raise ValueError('not a protocol')


def _state(v):
    if not set(v.split(',')) <= STATES:
        raise ValueError('not a connection state')


def _vlans(v):
    for part in v.split(','):
        low, _, high = part.partition('-')
        if not low.isdigit() or not 0 < int(low) < 4095 or (high and (not high.isdigit() or not 0 < int(high) < 4095)):
            raise ValueError('not a VLAN')


def _ips(v):
    for x in v.split(','):
        ipaddress.ip_address(x)


def _cidrs(v):
    for x in v.split(','):
        ipaddress.ip_network(x, strict=False)


def _range(v):
    for part in v.split(','):
        a, _, b = part.partition('-')
        ipaddress.ip_address(a)
        if b:
            ipaddress.ip_address(b)


def _endpoint(v):
    host, _, port = v.rpartition(':')
    if not host or not port.isdigit() or not 0 < int(port) < 65536 or not re.fullmatch(r'[A-Za-z0-9.:-]+', host):
        raise ValueError('host:port')


def _wgkey(v):
    if not WGKEY.fullmatch(v):
        raise ValueError('not a WireGuard key')


FILTER_ATTRS = {'chain': _name, 'action': _oneof(*sorted(ACTIONS)), 'protocol': _proto, 'src-address': _cidr, 'dst-address': _cidr, 'src-port': _ports, 'dst-port': _ports, 'in-interface': _name, 'out-interface': _name,
                'src-address-list': _name, 'dst-address-list': _name, 'connection-state': _state, 'comment': _comment, 'jump-target': _name, 'log-prefix': _comment}
NAT_ATTRS = {'chain': _oneof('dstnat', 'srcnat'), 'action': _oneof(*sorted(NAT_ACTIONS)), 'protocol': _proto, 'src-address': _cidr, 'dst-address': _cidr, 'dst-port': _ports, 'in-interface': _name, 'out-interface': _name, 'to-addresses': _ip_ok, 'to-ports': _ports, 'comment': _comment,
             'src-address-list': _name, 'dst-address-list': _name}
SCHEMA = {
    ('ip', 'firewall', 'filter'): ('add', FILTER_ATTRS, ('chain', 'action')),
    ('ip', 'firewall', 'nat'): ('add', NAT_ATTRS, ('chain', 'action')),
    ('ip', 'firewall', 'address-list'): ('add', {'list': _name, 'address': _cidr, 'comment': _comment}, ('list', 'address')),
    ('interface', 'bridge'): ('add', {'name': _name, 'vlan-filtering': _yesno, 'comment': _comment, 'mtu': _int}, ('name',)),
    ('interface', 'bridge', 'port'): ('add', {'bridge': _name, 'interface': _name, 'pvid': _int}, ('bridge', 'interface')),
    ('interface', 'bridge', 'vlan'): ('add', {'bridge': _name, 'vlan-ids': _vlans, 'tagged': _names, 'untagged': _names}, ('bridge', 'vlan-ids')),
    ('interface', 'vlan'): ('add', {'name': _name, 'vlan-id': _int, 'interface': _name, 'mtu': _int, 'comment': _comment}, ('name', 'vlan-id', 'interface')),
    ('interface', 'bonding'): ('add', {'name': _name, 'slaves': _names, 'mode': _oneof('802.3ad', 'active-backup', 'balance-rr', 'balance-xor', 'balance-tlb', 'balance-alb', 'broadcast'), 'mtu': _int}, ('name', 'slaves')),
    ('ip', 'address'): ('add', {'address': _iface_addr, 'interface': _name, 'comment': _comment}, ('address', 'interface')),
    ('ipv6', 'address'): ('add', {'address': _iface_addr, 'interface': _name, 'comment': _comment}, ('address', 'interface')),
    ('ip', 'pool'): ('add', {'name': _name, 'ranges': _range}, ('name', 'ranges')),
    ('ip', 'route'): ('add', {'dst-address': _cidr, 'gateway': _ip_ok, 'distance': _int, 'routing-table': _name, 'comment': _comment}, ('dst-address', 'gateway')),
    ('ipv6', 'route'): ('add', {'dst-address': _cidr, 'gateway': _ip_ok, 'distance': _int, 'comment': _comment}, ('dst-address', 'gateway')),
    ('routing', 'table'): ('add', {'name': _name, 'fib': _yesno}, ('name',)),
    ('routing', 'rule'): ('add', {'src-address': _cidr, 'dst-address': _cidr, 'table': _name, 'action': _oneof('lookup', 'drop')}, ('table',)),
    ('ip', 'dns'): ('set', {'servers': _ips, 'allow-remote-requests': _yesno, 'domain': _name}, ()),
    ('ip', 'dhcp-server'): ('add', {'name': _name, 'interface': _name, 'address-pool': _name, 'lease-time': _name, 'disabled': _yesno}, ('name', 'interface')),
    ('ip', 'dhcp-server', 'network'): ('add', {'address': _cidr, 'gateway': _ip_ok, 'dns-server': _ips}, ('address',)),
    ('ip', 'dhcp-server', 'lease'): ('add', {'address': _ip_ok, 'mac-address': _mac, 'server': _name, 'comment': _comment}, ('address', 'mac-address')),
    ('ip', 'dhcp-client'): ('add', {'interface': _name, 'add-default-route': _yesno, 'use-peer-dns': _yesno, 'disabled': _yesno}, ('interface',)),
    ('interface', 'wireguard'): ('add', {'name': _name, 'listen-port': _ports, 'private-key': _wgkey, 'mtu': _int}, ('name',)),
    ('interface', 'wireguard', 'peers'): ('add', {'interface': _name, 'public-key': _wgkey, 'allowed-address': _cidrs, 'endpoint-address': _endpoint, 'endpoint-port': _ports, 'persistent-keepalive': _name, 'comment': _comment}, ('interface', 'public-key')),
}
SECRET_ATTRS = {'private-key'}


@dataclass
class Stmt:
    path: tuple
    verb: str
    attrs: dict = field(default_factory=dict)
    line: int = 0

    def __getitem__(self, k):
        return self.attrs[k]

    def get(self, k, default=None):
        return self.attrs.get(k, default)

    def text(self, redact: bool = True) -> str:
        parts = []
        for k, v in self.attrs.items():
            if redact and k in SECRET_ATTRS:
                v = '<hidden>'
            parts.append(f'{k}="{v}"' if k == 'comment' or k == 'log-prefix' or ' ' in v or v == '' else f'{k}={v}')
        return '/' + ' '.join(self.path) + f' {self.verb} ' + ' '.join(parts)


TOKEN = re.compile(r'''([A-Za-z.][\w.-]*)=(?:"([^"]*)"|([^\s"]*))|(\S+)''')


def parse(text: str) -> list[Stmt]:
    """A `/ip firewall filter` line sets the path for what follows, as an export does. Both /ip/firewall/filter and /ip firewall filter name it."""
    if len(text or '') > 200_000:
        raise DslError('that is too long to read')
    out, path = [], None
    joined, start = [], 0
    for n, raw in enumerate((text or '').splitlines(), 1):
        if any(ord(c) < 32 and c != '\t' or ord(c) == 127 for c in raw):
            raise DslError(f'line {n}: a control character')
        line = raw.strip()
        if not joined:
            start = n
        if line.endswith('\\'):
            joined.append(line[:-1].strip())
            continue
        joined.append(line)
        whole, joined = ' '.join(x for x in joined if x), []
        if not whole or whole.startswith('#'):
            continue
        out_path, verb, rest = None, None, whole
        if whole.startswith('/'):
            words = whole[1:].split()
            segs = []
            consumed = 0
            for w in words:
                if '=' in w or w in ('add', 'set'):
                    break
                segs += [s for s in w.split('/') if s]
                consumed += 1
            # /ip/firewall/filter/add: the verb may be the last part of the path
            if segs and segs[-1] in ('add', 'set'):
                verb = segs.pop()
            out_path = tuple(segs)
            rest = ' '.join(words[consumed:])
            if tuple(out_path) not in SCHEMA:
                raise DslError(f'line {start}: no path /{" ".join(out_path)} in this language')
            path = out_path
            if not rest and not verb:
                continue
        if path is None:
            raise DslError(f'line {start}: no path has been set')
        tokens = list(TOKEN.finditer(rest))
        if tokens and tokens[0][4] in ('add', 'set'):
            verb = tokens.pop(0)[4]
        if not verb:
            raise DslError(f'line {start}: add or set?')
        want_verb, schema, required = SCHEMA[path]
        if verb != want_verb:
            raise DslError(f'line {start}: /{" ".join(path)} takes {want_verb}, not {verb}')
        attrs: dict = {}
        for t in tokens:
            if t[4]:
                raise DslError(f'line {start}: {t[4]!r} is not name=value')
            name, value = t[1], t[2] if t[2] is not None else (t[3] or '')
            check = schema.get(name)
            if check is None:
                raise DslError(f'line {start}: /{" ".join(path)} has no {name}')
            try:
                check(value)
            except ValueError as exc:
                raise DslError(f'line {start}: {name}: {exc}') from None
            attrs[name] = value
        for name in required:
            if name not in attrs:
                raise DslError(f'line {start}: /{" ".join(path)} needs {name}')
        if path == ('ip', 'firewall', 'filter') and attrs.get('action') == 'jump' and 'jump-target' not in attrs:
            raise DslError(f'line {start}: a jump needs jump-target')
        if path == ('ip', 'firewall', 'nat') and attrs.get('action') == 'dst-nat' and 'to-addresses' not in attrs:
            raise DslError(f'line {start}: a dst-nat needs to-addresses')
        out.append(Stmt(path, verb, attrs, start))
        if len(out) > MAX_STATEMENTS:
            raise DslError(f'more than {MAX_STATEMENTS} statements')
    return out


# ── helpers ─────────────────────────────────────────────────────────
def _neg(v):
    return (v[1:], True) if v and v.startswith('!') else (v, False)


def _fam(addr) -> int:
    return 6 if addr and ':' in addr else 4


def _q(v) -> str:
    return shlex.quote(v)


def _lists(stmts) -> dict:
    out: dict = {}
    for s in stmts:
        if s.path == ('ip', 'firewall', 'address-list'):
            out.setdefault(s['list'], []).append(s['address'])
    return out


FILTER = ('ip', 'firewall', 'filter')
NAT = ('ip', 'firewall', 'nat')
ALIST = ('ip', 'firewall', 'address-list')


class Out:
    def __init__(self, target):
        self.target, self.lines, self.files, self.unsupported, self.notes = target, [], {}, [], []

    def no(self, s: Stmt, why: str):
        self.unsupported.append({'line': s.line, 'statement': s.text(), 'why': why})

    def done(self) -> dict:
        return {'target': self.target, 'text': '\n'.join(self.lines) + ('\n' if self.lines else ''), 'files': self.files, 'unsupported': self.unsupported, 'notes': self.notes}


# ── RouterOS ────────────────────────────────────────────────────────
def to_routeros(stmts, **_) -> dict:
    o = Out('routeros')
    for s in stmts:
        o.lines.append(s.text(redact=False))
    return o.done()


# ── nftables ────────────────────────────────────────────────────────
def _nft_addr(prefix: str, value: str, lists: dict) -> str:
    v, neg = _neg(value)
    v = v.replace(' ', '')
    return f'{"ip6" if _fam(v) == 6 else "ip"} {prefix} {"!= " if neg else ""}{v}'


def _nft_ports(field_: str, v: str) -> str:
    v, neg = _neg(v)
    return f'{field_} {"!= " if neg else ""}' + ('{ ' + ', '.join(v.split(',')) + ' }' if ',' in v else v)


def _nft_match(s: Stmt, lists: dict, o: Out) -> list:
    m = []
    if s.get('in-interface'):
        v, neg = _neg(s['in-interface'])
        m.append(f'iifname {"!= " if neg else ""}"{v}"')
    if s.get('out-interface'):
        v, neg = _neg(s['out-interface'])
        m.append(f'oifname {"!= " if neg else ""}"{v}"')
    if s.get('src-address'):
        m.append(_nft_addr('saddr', s['src-address'], lists))
    if s.get('dst-address'):
        m.append(_nft_addr('daddr', s['dst-address'], lists))
    if s.get('src-address-list'):
        m.append(f'ip saddr @{_setname(s["src-address-list"])}')
    if s.get('dst-address-list'):
        m.append(f'ip daddr @{_setname(s["dst-address-list"])}')
    proto = s.get('protocol')
    if proto and proto != 'any':
        if s.get('dst-port') or s.get('src-port'):
            pass
        else:
            m.append(f'meta l4proto {proto}')
    if s.get('src-port') or s.get('dst-port'):
        if proto not in ('tcp', 'udp'):
            o.no(s, 'a port needs protocol=tcp or udp')
            return None
        if s.get('src-port'):
            m.append(_nft_ports(f'{proto} sport', s['src-port']))
        if s.get('dst-port'):
            m.append(_nft_ports(f'{proto} dport', s['dst-port']))
    if s.get('connection-state'):
        m.append('ct state { ' + ', '.join(s['connection-state'].split(',')) + ' }')
    return m


def _setname(name: str) -> str:
    return re.sub(r'[^A-Za-z0-9_]', '_', name)


def _chainname(name: str) -> str:
    return re.sub(r'[^A-Za-z0-9_]', '_', name)


def to_nftables(stmts, table: str = 'storageforge_dsl', **_) -> dict:
    o = Out('nftables')
    lists = _lists(stmts)
    filt, nat = [], []
    chains = {'input': [], 'forward': [], 'output': []}
    extra: dict = {}
    for s in stmts:
        if s.path == FILTER:
            m = _nft_match(s, lists, o)
            if m is None:
                continue
            act = s['action']
            if act == 'fasttrack-connection':
                o.notes.append('fasttrack-connection is written as accept: nftables flowtables are not set up here')
                act = 'accept'
            verdict = {'jump': f'jump {_chainname(s.get("jump-target", ""))}', 'log': f'log prefix "{s.get("log-prefix", "sf ")} "', 'passthrough': ''}.get(act, act)
            line = ' '.join([*m, 'counter', verdict]).strip()
            if s.get('comment'):
                line += f' comment "{s["comment"]}"'
            chain = s['chain']
            (chains if chain in chains else extra).setdefault(chain, []).append(line)
            if s.get('jump-target'):
                extra.setdefault(s['jump-target'], [])
        elif s.path == NAT:
            m = _nft_match(s, lists, o)
            if m is None:
                continue
            act = s['action']
            if act == 'masquerade':
                verdict = 'masquerade'
            elif act == 'redirect':
                verdict = f'redirect to :{s.get("to-ports", "")}'.rstrip(':')
            elif act == 'dst-nat':
                to = s['to-addresses'] + (f':{s["to-ports"]}' if s.get('to-ports') else '')
                verdict = f'dnat ip to {to}' if s.get('protocol') not in ('tcp', 'udp') or True else ''
            else:
                to = s.get('to-addresses', '')
                verdict = f'snat ip to {to}'
            nat.append((s['chain'], ' '.join([*m, verdict]) + (f' comment "{s["comment"]}"' if s.get('comment') else '')))
        elif s.path == ALIST:
            pass
        else:
            o.no(s, 'not a firewall statement: use the networkd or NetworkManager target for this on a Linux host')
    o.lines.append(f'table inet {table}')
    o.lines.append(f'delete table inet {table}')
    o.lines.append(f'table inet {table} {{')
    for name, items in lists.items():
        fam = 'ipv6_addr' if any(':' in x for x in items) else 'ipv4_addr'
        o.lines += [f'  set {_setname(name)} {{', f'    type {fam}', '    flags interval', '    elements = { ' + ', '.join(items) + ' }', '  }']
    for hook, rules in chains.items():
        o.lines += [f'  chain {hook} {{', f'    type filter hook {hook} priority -10; policy accept;']
        o.lines += [f'    {r}' for r in rules]
        o.lines.append('  }')
    for name, rules in extra.items():
        o.lines.append(f'  chain {_chainname(name)} {{')
        o.lines += [f'    {r}' for r in rules]
        o.lines.append('  }')
    o.lines.append('}')
    if nat:
        o.lines += [f'table ip {table}_nat', f'delete table ip {table}_nat', f'table ip {table}_nat {{']
        for chain, hook, prio in (('dstnat', 'prerouting', -100), ('srcnat', 'postrouting', 100)):
            o.lines += [f'  chain {chain} {{', f'    type nat hook {hook} priority {prio}; policy accept;']
            o.lines += [f'    {r.replace("dnat ip to", "dnat to").replace("snat ip to", "snat to")}' for c, r in nat if c == chain]
            o.lines.append('  }')
        o.lines.append('}')
    return o.done()


# ── iptables ────────────────────────────────────────────────────────
def _ipt_match(s: Stmt, o: Out) -> list | None:
    a = []
    for key, flag in (('in-interface', '-i'), ('out-interface', '-o')):
        if s.get(key):
            v, neg = _neg(s[key])
            a += (['!'] if neg else []) + [flag, v]
    if s.get('protocol') and s['protocol'] != 'any':
        a += ['-p', s['protocol']]
    for key, flag in (('src-address', '-s'), ('dst-address', '-d')):
        if s.get(key):
            v, neg = _neg(s[key])
            if '-' in v:
                a += ['-m', 'iprange'] + (['!'] if neg else []) + ['--src-range' if flag == '-s' else '--dst-range', v]
            else:
                a += (['!'] if neg else []) + [flag, v]
    if s.get('src-address-list') or s.get('dst-address-list'):
        o.no(s, 'iptables has no address lists here: an ipset would have to be made first')
        return None
    ports = s.get('dst-port')
    if ports or s.get('src-port'):
        if s.get('protocol') not in ('tcp', 'udp'):
            o.no(s, 'a port needs protocol=tcp or udp')
            return None
    if ports:
        v, neg = _neg(ports)
        v = v.replace('-', ':')
        a += (['-m', 'multiport'] + (['!'] if neg else []) + ['--dports', v]) if ',' in v else ((['!'] if neg else []) + ['--dport', v])
    if s.get('src-port'):
        a += ['--sport', s['src-port'].replace('-', ':')]
    if s.get('connection-state'):
        a += ['-m', 'conntrack', '--ctstate', s['connection-state'].upper()]
    if s.get('comment'):
        a += ['-m', 'comment', '--comment', f'"{s["comment"]}"']       # iptables-restore splits on its own rules: double quotes, and the check on a comment keeps them out of it
    return a


def to_iptables(stmts, **_) -> dict:
    o = Out('iptables')
    filt, nat, custom = [], [], {}
    for s in stmts:
        if s.path == FILTER:
            m = _ipt_match(s, o)
            if m is None:
                continue
            chain = {'input': 'INPUT', 'forward': 'FORWARD', 'output': 'OUTPUT'}.get(s['chain'], s['chain'])
            if chain == s['chain']:
                custom[chain] = 1
            act = s['action']
            target = {'accept': 'ACCEPT', 'drop': 'DROP', 'reject': 'REJECT', 'return': 'RETURN', 'log': 'LOG', 'fasttrack-connection': 'ACCEPT'}.get(act)
            if act == 'jump':
                target = s['jump-target']
                custom[target] = 1
            filt.append(' '.join(['-A', chain, *m, *(['-j', target] if target else [])]))
        elif s.path == NAT:
            m = _ipt_match(s, o)
            if m is None:
                continue
            chain = 'PREROUTING' if s['chain'] == 'dstnat' else 'POSTROUTING'
            if s['action'] == 'masquerade':
                tail = ['-j', 'MASQUERADE']
            elif s['action'] == 'dst-nat':
                tail = ['-j', 'DNAT', '--to-destination', s['to-addresses'] + (f':{s["to-ports"]}' if s.get('to-ports') else '')]
            elif s['action'] == 'redirect':
                tail = ['-j', 'REDIRECT'] + (['--to-ports', s['to-ports']] if s.get('to-ports') else [])
            else:
                tail = ['-j', 'SNAT', '--to-source', s.get('to-addresses', '')]
            nat.append(' '.join(['-A', chain, *m, *tail]))
        elif s.path == ALIST:
            o.no(s, 'iptables has no address lists here: an ipset would have to be made first')
        else:
            o.no(s, 'not a firewall statement')
    # --noflush: this adds to what's there, for iptables-restore
    o.lines += ['*filter', *[f':{c} - [0:0]' for c in custom], *filt, 'COMMIT']
    if nat:
        o.lines += ['*nat', *nat, 'COMMIT']
    return o.done()


# ── firewalld ───────────────────────────────────────────────────────
def to_firewalld(stmts, zone: str = 'public', **_) -> dict:
    o = Out('firewalld')
    zone = zone if NAME.fullmatch(zone or '') else 'public'
    base = f'firewall-cmd --permanent --zone={zone}'
    for s in stmts:
        if s.path == FILTER:
            if s['chain'] != 'input' or s['action'] not in ('accept', 'drop', 'reject') or s.get('connection-state') or s.get('out-interface'):
                o.no(s, 'firewalld rich rules are for what comes in: other chains and states need a policy written by hand')
                continue
            fam = 'ipv6' if _fam(s.get('src-address') or s.get('dst-address')) == 6 else 'ipv4'
            parts = [f'rule family="{fam}"']
            if s.get('src-address'):
                v, neg = _neg(s['src-address'])
                parts.append(f'source {"NOT " if neg else ""}address="{v}"')
            if s.get('src-address-list'):
                parts.append(f'source ipset="{s["src-address-list"]}"')
            if s.get('dst-address'):
                v, neg = _neg(s['dst-address'])
                parts.append(f'destination {"NOT " if neg else ""}address="{v}"')
            if s.get('dst-port'):
                if s.get('protocol') not in ('tcp', 'udp'):
                    o.no(s, 'a port needs protocol=tcp or udp')
                    continue
                parts.append(f'port port="{s["dst-port"]}" protocol="{s["protocol"]}"')
            elif s.get('protocol') not in (None, 'any'):
                parts.append(f'protocol value="{s["protocol"]}"')
            parts.append(s['action'])
            o.lines.append(f'{base} --add-rich-rule={_q(" ".join(parts))}')
        elif s.path == NAT:
            if s['action'] == 'masquerade':
                o.lines.append(f'{base} --add-masquerade')
            elif s['action'] == 'dst-nat' and s.get('dst-port') and s.get('protocol') in ('tcp', 'udp'):
                o.lines.append(f'{base} --add-forward-port={_q("port=" + s["dst-port"] + ":proto=" + s["protocol"] + ":toaddr=" + s["to-addresses"] + (":toport=" + s["to-ports"] if s.get("to-ports") else ""))}')
            else:
                o.no(s, 'firewalld forward ports take a port and protocol')
        elif s.path == ALIST:
            name, addr = s['list'], s['address']
            line = f'firewall-cmd --permanent --new-ipset={_q(name)} --type=hash:net 2>/dev/null || true'
            if line not in o.lines:
                o.lines.append(line)
            o.lines.append(f'firewall-cmd --permanent --ipset={_q(name)} --add-entry={_q(addr)}')
        else:
            o.no(s, 'not a firewall statement')
    o.lines.append('firewall-cmd --reload')
    return o.done()


# ── ufw ─────────────────────────────────────────────────────────────
def to_ufw(stmts, **_) -> dict:
    o = Out('ufw')
    verbs = {'accept': 'allow', 'drop': 'deny', 'reject': 'reject'}
    for s in stmts:
        if s.path != FILTER:
            o.no(s, 'ufw has no syntax for this: NAT goes in before.rules by hand')
            continue
        if s['action'] not in verbs or s.get('connection-state') or s.get('src-address-list') or s.get('dst-address-list') or s.get('src-port') or str(s.get('src-address', '')).startswith('!'):
            o.no(s, 'ufw rules are a verdict, addresses and a port')
            continue
        if s['chain'] not in ('input', 'output', 'forward'):
            o.no(s, 'ufw has no custom chains')
            continue
        words = ['ufw']
        if s['chain'] == 'forward':
            words.append('route')
        words.append(verbs[s['action']])
        if s['chain'] == 'output' and not s.get('out-interface'):
            words.append('out')
        if s.get('in-interface'):
            words += ['in', 'on', s['in-interface']]
        if s.get('out-interface'):
            words += ['out', 'on', s['out-interface']]
        if s.get('protocol') in ('tcp', 'udp'):
            words += ['proto', s['protocol']]
        elif s.get('protocol') not in (None, 'any'):
            o.no(s, 'ufw takes tcp or udp here')
            continue
        words += ['from', s.get('src-address', 'any'), 'to', s.get('dst-address', 'any')]
        if s.get('dst-port'):
            if s.get('protocol') not in ('tcp', 'udp'):
                o.no(s, 'a port needs protocol=tcp or udp')
                continue
            words += ['port', s['dst-port'].replace('-', ':')]
        if s.get('comment'):
            words += ['comment', _q(s['comment'])]
        o.lines.append(' '.join(words))
    return o.done()


# ── OpenWrt ─────────────────────────────────────────────────────────
def to_openwrt(stmts, zones: dict | None = None, **_) -> dict:
    """zones: {interface: fw4 zone}. A firewall rule speaks in zones; an interface with no zone given is taken as the zone's name."""
    o = Out('openwrt')
    zones = zones or {}

    def zone(i):
        return zones.get(i, i)
    add = o.lines.append

    def section(pkg, kind, values):
        add(f'r=$(uci add {pkg} {kind})')
        for k, v in values.items():
            if isinstance(v, list):
                for x in v:
                    add(f'uci add_list {pkg}.$r.{k}={_q(x)}')
            elif v not in (None, ''):
                add(f'uci set {pkg}.$r.{k}={_q(str(v))}')
    touched = set()
    for s in stmts:
        p = s.path
        if p == FILTER:
            touched.add('firewall')
            if s['action'] not in ('accept', 'drop', 'reject') or s['chain'] not in ('input', 'forward', 'output') or s.get('connection-state') or s.get('src-address-list') or s.get('dst-address-list'):
                o.no(s, 'an fw4 rule is a verdict between zones')
                continue
            vals = {'name': s.get('comment') or f'sf-{s.line}', 'target': s['action'].upper(), 'proto': s.get('protocol'), 'src_ip': s.get('src-address'), 'dest_ip': s.get('dst-address'), 'dest_port': (s.get('dst-port') or '').replace(',', ' ').replace('-', ':') or None, 'src_port': s.get('src-port')}
            if s['chain'] == 'input':
                vals['src'] = zone(s.get('in-interface')) if s.get('in-interface') else '*'
            elif s['chain'] == 'forward':
                vals['src'] = zone(s.get('in-interface')) if s.get('in-interface') else '*'
                vals['dest'] = zone(s.get('out-interface')) if s.get('out-interface') else '*'
            else:
                vals['dest'] = zone(s.get('out-interface')) if s.get('out-interface') else '*'
            section('firewall', 'rule', vals)
        elif p == NAT:
            touched.add('firewall')
            if s['action'] == 'dst-nat' and s.get('dst-port'):
                section('firewall', 'redirect', {'name': s.get('comment') or f'sf-{s.line}', 'target': 'DNAT', 'src': zone(s.get('in-interface')) if s.get('in-interface') else '*', 'proto': s.get('protocol'), 'src_dport': s['dst-port'], 'dest_ip': s['to-addresses'], 'dest_port': s.get('to-ports') or s['dst-port']})
            elif s['action'] == 'masquerade' and s.get('out-interface'):
                add(f"for z in $(uci show firewall | sed -n \"s/^firewall\\.\\(.*\\)\\.name='{zone(s['out-interface'])}'$/\\1/p\"); do uci set firewall.$z.masq=1; done")
            else:
                o.no(s, 'fw4 has redirects with a port, and masquerade on a zone')
        elif p == ALIST:
            touched.add('firewall')
            add(f'n=$(uci show firewall | grep -c "\\.name=\'{s["list"]}\'" || true); [ "$n" != 0 ] || {{ r=$(uci add firewall ipset); uci set firewall.$r.name={_q(s["list"])}; uci set firewall.$r.match=src_net; }}')
            add(f"for z in $(uci show firewall | sed -n \"s/^firewall\\.\\(.*\\)\\.name='{s['list']}'$/\\1/p\"); do uci add_list firewall.$z.entry={_q(s['address'])}; done")
        elif p == ('interface', 'bridge'):
            touched.add('network')
            section('network', 'device', {'type': 'bridge', 'name': s['name'], 'mtu': s.get('mtu'), 'vlan_filtering': '1' if s.get('vlan-filtering') in ('yes', 'true') else None})
        elif p == ('interface', 'bridge', 'port'):
            touched.add('network')
            add(f"for d in $(uci show network | sed -n \"s/^network\\.\\(.*\\)\\.name='{s['bridge']}'$/\\1/p\"); do uci add_list network.$d.ports={_q(s['interface'])}; done")
        elif p == ('interface', 'vlan'):
            touched.add('network')
            section('network', 'device', {'type': '8021q', 'name': s['name'], 'ifname': s['interface'], 'vid': s['vlan-id']})
        elif p == ('ip', 'address'):
            touched.add('network')
            i = ipaddress.ip_interface(s['address'])
            logical = re.sub(r'[^A-Za-z0-9_]', '_', s['interface'])
            add(f'uci set network.{logical}=interface; uci set network.{logical}.device={_q(s["interface"])}; uci set network.{logical}.proto=static; uci set network.{logical}.ipaddr={_q(str(i.ip))}; uci set network.{logical}.netmask={_q(str(i.netmask))}')
        elif p == ('ip', 'route'):
            touched.add('network')
            net = ipaddress.ip_network(s['dst-address'], strict=False)
            section('network', 'route', {'interface': 'mgmt', 'target': str(net), 'gateway': s['gateway'], 'metric': s.get('distance')})
            o.notes.append('a static route names a UCI interface: check it is the right one')
        elif p == ('ip', 'dns'):
            touched.add('dhcp')
            for server in (s.get('servers') or '').split(','):
                if server:
                    add(f'uci add_list dhcp.@dnsmasq[0].server={_q(server)}')
        elif p == ('ip', 'dhcp-server', 'lease'):
            touched.add('dhcp')
            section('dhcp', 'host', {'name': s.get('comment') or f'sf-{s.line}', 'mac': s['mac-address'], 'ip': s['address']})
        elif p == ('interface', 'wireguard'):
            touched.add('network')
            logical = re.sub(r'[^A-Za-z0-9_]', '_', s['name'])
            add(f'uci set network.{logical}=interface; uci set network.{logical}.proto=wireguard' + (f'; uci set network.{logical}.private_key={_q(s["private-key"])}' if s.get('private-key') else '') + (f'; uci set network.{logical}.listen_port={_q(s["listen-port"])}' if s.get('listen-port') else ''))
        elif p == ('interface', 'wireguard', 'peers'):
            touched.add('network')
            logical = re.sub(r'[^A-Za-z0-9_]', '_', s['interface'])
            section('network', f'wireguard_{logical}', {'public_key': s['public-key'], 'allowed_ips': (s.get('allowed-address') or '').split(',')})
        else:
            o.no(s, 'no UCI form for this here')
    for pkg in sorted(touched):
        add(f'uci commit {pkg}')
    return o.done()


# ── pfSense / OPNsense ──────────────────────────────────────────────
def _x(tag, v) -> str:
    return f'<{tag}>{escape(str(v))}</{tag}>'


def _pf_end(tag, addr, port, lst, ifaces) -> str:
    inner = ''
    if addr:
        v, neg = _neg(addr)
        inner += ('<not/>' if neg else '') + _x('address', v)
    elif lst:
        inner += _x('address', lst)
    else:
        inner += '<any/>'
    if port:
        inner += _x('port', port.replace(',', ' '))
    return f'<{tag}>{inner}</{tag}>'


def to_pfsense(stmts, interfaces: dict | None = None, **_) -> dict:
    """XML fragments for the sections of config.xml. interfaces: {name in the DSL: pf's logical name, wan or opt1}. Names with none given go in as they are."""
    o = Out('pfsense')
    ifmap = interfaces or {}
    sec: dict = {'filter': [], 'nat': [], 'aliases': [], 'vlans': [], 'staticroutes': [], 'dnsserver': []}

    def nm(i):
        return ifmap.get(i, i)
    for s in stmts:
        p = s.path
        if p == FILTER:
            if s['action'] not in ('accept', 'drop', 'reject') or not s.get('in-interface') and s['chain'] == 'forward' or s.get('connection-state') or s['chain'] not in ('input', 'forward'):
                o.no(s, 'a pf rule in config.xml is a verdict on the interface traffic comes in on')
                continue
            if not s.get('in-interface'):
                o.no(s, 'pf holds rules on the interface traffic comes in on: name in-interface')
                continue
            kind = {'accept': 'pass', 'drop': 'block', 'reject': 'reject'}[s['action']]
            proto = s.get('protocol')
            sec['filter'].append('<rule>' + _x('type', kind) + _x('interface', nm(s['in-interface'])) + _x('ipprotocol', 'inet') + (_x('protocol', proto) if proto and proto != 'any' else '') +
                                 _pf_end('source', s.get('src-address'), s.get('src-port'), s.get('src-address-list'), ifmap) + _pf_end('destination', s.get('dst-address'), s.get('dst-port'), s.get('dst-address-list'), ifmap) +
                                 (_x('descr', s['comment']) if s.get('comment') else '') + '</rule>')
        elif p == NAT:
            if s['action'] == 'dst-nat' and s.get('dst-port'):
                sec['nat'].append('<rule>' + _x('protocol', s.get('protocol') or 'tcp') + _x('interface', nm(s.get('in-interface') or 'wan')) + '<source><any/></source>' +
                                  '<destination>' + (_x('address', s['dst-address']) if s.get('dst-address') else '<network>wanip</network>') + _x('port', s['dst-port']) + '</destination>' +
                                  _x('target', s['to-addresses']) + _x('local-port', s.get('to-ports') or s['dst-port']) + (_x('descr', s['comment']) if s.get('comment') else '') + '</rule>')
            else:
                o.no(s, 'outbound NAT is a mode in pfSense: only inbound port forwards are written here')
        elif p == ALIST:
            sec['aliases'].append('<alias>' + _x('name', _setname(s['list'])) + _x('type', 'network' if '/' in s['address'] else 'host') + _x('address', s['address']) + (_x('descr', s['comment']) if s.get('comment') else '') + '</alias>')
        elif p == ('interface', 'vlan'):
            sec['vlans'].append('<vlan>' + _x('if', s['interface']) + _x('tag', s['vlan-id']) + _x('vlanif', f'{s["interface"]}.{s["vlan-id"]}') + _x('descr', s.get('comment') or s['name']) + '</vlan>')
        elif p == ('ip', 'route'):
            sec['staticroutes'].append('<route>' + _x('network', s['dst-address']) + _x('gateway', s['gateway']) + (_x('descr', s['comment']) if s.get('comment') else '') + '</route>')
        elif p == ('ip', 'dns'):
            sec['dnsserver'] += [_x('dnsserver', x) for x in (s.get('servers') or '').split(',') if x]
        else:
            o.no(s, 'not written to config.xml here')
    for name, rows in sec.items():
        if rows:
            o.files[name] = '\n'.join(rows)
            o.lines.append(f'<!-- into <{name}> -->')
            o.lines += rows
    return o.done()


# ── Cisco ───────────────────────────────────────────────────────────
def _wild(addr: str) -> str:
    v, neg = _neg(addr)
    if '-' in v:
        return None
    n = ipaddress.ip_network(v, strict=False)
    if n.prefixlen == 32:
        return f'host {n.network_address}'
    if n.prefixlen == 0:
        return 'any'
    return f'{n.network_address} {n.hostmask}'


def _ace_port(v):
    if ',' in v:
        return 'eq ' + ' '.join(v.split(','))
    if '-' in v:
        return 'range ' + ' '.join(v.split('-'))
    return f'eq {v}'


def to_cisco(stmts, **_) -> dict:
    o = Out('cisco')
    acls: dict = {}
    other = []
    for s in stmts:
        p = s.path
        if p == FILTER:
            if s['action'] not in ('accept', 'drop', 'reject') or s.get('connection-state') not in (None, 'established', 'established,related') or s.get('src-address-list') or s.get('dst-address-list'):
                o.no(s, 'an ACL entry is a verdict on addresses and ports')
                continue
            iface = s.get('in-interface') or s.get('out-interface')
            if not iface or s['chain'] not in ('input', 'forward', 'output'):
                o.no(s, 'an ACL is bound to an interface: name in-interface or out-interface')
                continue
            side = 'in' if s.get('in-interface') else 'out'
            src = _wild(s.get('src-address', '0.0.0.0/0'))
            dst = _wild(s.get('dst-address', '0.0.0.0/0'))
            if src is None or dst is None or str(s.get('src-address', '')).startswith('!') or str(s.get('dst-address', '')).startswith('!'):
                o.no(s, 'an ACL entry has no negated address or address range')
                continue
            proto = s.get('protocol')
            proto = 'ip' if proto in (None, 'any') else proto
            ace = ['permit' if s['action'] == 'accept' else 'deny', proto, src]
            if s.get('src-port'):
                ace.append(_ace_port(s['src-port']))
            ace.append(dst)
            if s.get('dst-port'):
                if proto not in ('tcp', 'udp'):
                    o.no(s, 'a port needs protocol=tcp or udp')
                    continue
                ace.append(_ace_port(s['dst-port']))
            if s.get('connection-state'):
                ace.append('established')
            acls.setdefault((iface, side), []).append((s.get('comment'), ' '.join(ace)))
        elif p == NAT:
            if s['action'] == 'dst-nat' and s.get('dst-port') and s.get('protocol') in ('tcp', 'udp') and s.get('in-interface'):
                other.append(f'ip nat inside source static {s["protocol"]} {s["to-addresses"]} {s.get("to-ports") or s["dst-port"]} interface {s["in-interface"]} {s["dst-port"]}')
            elif s['action'] == 'masquerade' and s.get('out-interface'):
                other += ['access-list 199 permit ip any any', f'ip nat inside source list 199 interface {s["out-interface"]} overload']
            else:
                o.no(s, 'IOS NAT here is a static port or overload on an interface')
        elif p == ('ip', 'address'):
            i = ipaddress.ip_interface(s['address'])
            other += [f'interface {s["interface"]}', f' ip address {i.ip} {i.netmask}', ' no shutdown', 'exit']
        elif p == ('ip', 'route'):
            n = ipaddress.ip_network(s['dst-address'], strict=False)
            other.append(f'ip route {n.network_address} {n.netmask} {s["gateway"]}' + (f' {s["distance"]}' if s.get('distance') else ''))
        elif p == ('ip', 'dns'):
            for server in (s.get('servers') or '').split(','):
                if server:
                    other.append(f'ip name-server {server}')
        elif p == ('interface', 'vlan'):
            other += [f'vlan {s["vlan-id"]}', f' name {s["name"]}', 'exit']
        elif p == ('interface', 'bonding'):
            for i, slave in enumerate(s['slaves'].split(',')):
                other += [f'interface {slave}', f' channel-group {re.sub(r"[^0-9]", "", s["name"]) or 1} mode active', 'exit']
        elif p == ('ip', 'dhcp-server', 'network'):
            n = ipaddress.ip_network(s['address'], strict=False)
            other += [f'ip dhcp pool SF_{str(n.network_address).replace(".", "_")}', f' network {n.network_address} {n.netmask}'] + ([f' default-router {s["gateway"]}'] if s.get('gateway') else []) + ['exit']
        else:
            o.no(s, 'no IOS form for this here')
    o.lines += other
    for (iface, side), aces in acls.items():
        name = 'SF_' + re.sub(r'[^A-Za-z0-9]', '_', iface).upper() + '_' + side.upper()
        o.lines.append(f'ip access-list extended {name}')
        for comment, ace in aces:
            if comment:
                o.lines.append(f' remark {comment}')
            o.lines.append(f' {ace}')
        o.lines += ['exit', f'interface {iface}', f' ip access-group {name} {side}', 'exit']
    return o.done()


# ── Linux: systemd-networkd and NetworkManager ──────────────────────
def to_networkd(stmts, **_) -> dict:
    """Files for /etc/systemd/network. The firewall part goes through a firewall target, so this only says what it left out."""
    o = Out('networkd')
    nets: dict = {}

    def net(iface):
        return nets.setdefault(iface, {'addr': [], 'route': [], 'dns': [], 'vlan': [], 'bridge': None, 'bond': None, 'dhcp': None})
    n = 50
    for s in stmts:
        p = s.path
        if p == ('interface', 'bridge'):
            o.files[f'{n}-{s["name"]}.netdev'] = f'[NetDev]\nName={s["name"]}\nKind=bridge\n' + (f'MTUBytes={s["mtu"]}\n' if s.get('mtu') else '') + ('\n[Bridge]\nVLANFiltering=yes\n' if s.get('vlan-filtering') in ('yes', 'true') else '')
            net(s['name'])
        elif p == ('interface', 'bridge', 'port'):
            net(s['interface'])['bridge'] = s['bridge']
        elif p == ('interface', 'vlan'):
            o.files[f'{n}-{s["name"]}.netdev'] = f'[NetDev]\nName={s["name"]}\nKind=vlan\n\n[VLAN]\nId={s["vlan-id"]}\n'
            net(s['interface'])['vlan'].append(s['name'])
            net(s['name'])
        elif p == ('interface', 'bonding'):
            mode = s.get('mode') or 'active-backup'
            o.files[f'{n}-{s["name"]}.netdev'] = f'[NetDev]\nName={s["name"]}\nKind=bond\n\n[Bond]\nMode={mode}\n'
            for slave in s['slaves'].split(','):
                net(slave)['bond'] = s['name']
            net(s['name'])
        elif p in (('ip', 'address'), ('ipv6', 'address')):
            net(s['interface'])['addr'].append(s['address'])
        elif p == ('ip', 'route') or p == ('ipv6', 'route'):
            found = None
            gateway = ipaddress.ip_address(s['gateway'])
            for iface, row in nets.items():
                if any(gateway in ipaddress.ip_interface(a).network for a in row['addr']):
                    found = iface
            if found is None:
                o.no(s, 'no address written so far puts the gateway on an interface')
                continue
            nets[found]['route'].append((s['dst-address'], s['gateway'], s.get('distance')))
        elif p == ('ip', 'dns'):
            o.notes.append('DNS goes on each .network file written here')
            for row in nets.values():
                row['dns'] = (s.get('servers') or '').split(',')
        elif p == ('ip', 'dhcp-client'):
            net(s['interface'])['dhcp'] = True
        elif p == ('interface', 'wireguard'):
            o.files[f'{n}-{s["name"]}.netdev'] = f'[NetDev]\nName={s["name"]}\nKind=wireguard\n\n[WireGuard]\n' + (f'ListenPort={s["listen-port"]}\n' if s.get('listen-port') else '') + (f'PrivateKey={s["private-key"]}\n' if s.get('private-key') else '')
            net(s['name'])
        elif p == ('interface', 'wireguard', 'peers'):
            key = next((k for k in o.files if k.endswith(f'-{s["interface"]}.netdev')), None)
            if key is None:
                o.no(s, 'its interface was not written before it')
                continue
            o.files[key] += f'\n[WireGuardPeer]\nPublicKey={s["public-key"]}\nAllowedIPs={s.get("allowed-address", "")}\n' + (f'Endpoint={s["endpoint-address"]}\n' if s.get('endpoint-address') else '')
        elif p in (FILTER, NAT, ALIST):
            o.no(s, 'a firewall statement: compile it for nftables, iptables, firewalld or ufw')
        else:
            o.no(s, 'networkd has no form for this: a DHCP server is dnsmasq or kea')
    for iface, row in nets.items():
        text = f'[Match]\nName={iface}\n\n[Network]\n'
        text += ''.join(f'Address={a}\n' for a in row['addr'])
        text += ''.join(f'VLAN={v}\n' for v in row['vlan'])
        text += f'Bridge={row["bridge"]}\n' if row['bridge'] else ''
        text += f'Bond={row["bond"]}\n' if row['bond'] else ''
        text += 'DHCP=yes\n' if row['dhcp'] else ''
        text += ''.join(f'DNS={d}\n' for d in row['dns'] if d)
        for dst, gw, dist in row['route']:
            text += f'\n[Route]\nDestination={dst}\nGateway={gw}\n' + (f'Metric={dist}\n' if dist else '')
        o.files[f'{n}-{iface}.network'] = text
    o.lines += [f'# /etc/systemd/network/{name}\n{body}' for name, body in o.files.items()]
    return o.done()


def to_networkmanager(stmts, **_) -> dict:
    o = Out('networkmanager')
    for s in stmts:
        p = s.path
        if p == ('interface', 'bridge'):
            o.lines.append(f'nmcli connection add type bridge ifname {_q(s["name"])} con-name {_q(s["name"])}')
        elif p == ('interface', 'bridge', 'port'):
            o.lines.append(f'nmcli connection add type bridge-slave ifname {_q(s["interface"])} master {_q(s["bridge"])} con-name {_q(s["interface"] + "-port")}')
        elif p == ('interface', 'vlan'):
            o.lines.append(f'nmcli connection add type vlan ifname {_q(s["name"])} dev {_q(s["interface"])} id {_q(s["vlan-id"])} con-name {_q(s["name"])}')
        elif p == ('interface', 'bonding'):
            o.lines.append(f'nmcli connection add type bond ifname {_q(s["name"])} con-name {_q(s["name"])}' + (f' bond.options mode={_q(s["mode"])}' if s.get('mode') else ''))
            for slave in s['slaves'].split(','):
                o.lines.append(f'nmcli connection add type bond-slave ifname {_q(slave)} master {_q(s["name"])} con-name {_q(slave + "-bond")}')
        elif p in (('ip', 'address'), ('ipv6', 'address')):
            fam = 'ipv6' if p[0] == 'ipv6' else 'ipv4'
            o.lines.append(f'nmcli connection modify {_q(s["interface"])} {fam}.method manual +{fam}.addresses {_q(s["address"])}')
        elif p in (('ip', 'route'), ('ipv6', 'route')):
            o.no(s, 'a route belongs to a connection: name it with its address on the connection by hand')
        else:
            o.no(s, 'nmcli form not written here')
    return o.done()


EMITTERS = {'routeros': to_routeros, 'nftables': to_nftables, 'iptables': to_iptables, 'firewalld': to_firewalld, 'ufw': to_ufw, 'openwrt': to_openwrt, 'pfsense': to_pfsense, 'cisco': to_cisco, 'networkd': to_networkd, 'networkmanager': to_networkmanager}


def emit(stmts: list[Stmt], target: str, **options) -> dict:
    if target not in EMITTERS:
        raise DslError(f'no target {target!r}: one of ' + ', '.join(TARGETS))
    return EMITTERS[target](stmts, **options)


def compile_text(text: str, target: str, **options) -> dict:
    return emit(parse(text), target, **options)


# ── back to the model, and back to the language ─────────────────────
def to_model_rules(stmts: list[Stmt], start: int = 0) -> dict:
    """What these statements would add to a firewall model: for a what-if, before anything is sent."""
    from .firewall import _ports as fw_ports
    from .firewall import _rule
    rules, nat = [], []
    order = start
    for s in stmts:
        if s.path not in (FILTER, NAT):
            continue
        order += 10
        kw = dict(proto=None if s.get('protocol') in (None, 'any') else s['protocol'], comment=s.get('comment'), dports=fw_ports(s['dst-port']) or [] if s.get('dst-port') else [], saddr=s.get('src-address'), daddr=s.get('dst-address'), iif=s.get('in-interface'), oif=s.get('out-interface'), ct=s.get('connection-state'))
        if s.path == FILTER:
            act = s['action']
            action = {'jump': f'jump:{s.get("jump-target")}', 'fasttrack-connection': 'accept', 'log': None, 'passthrough': None}.get(act, act)
            rules.append(_rule('routeros', 'filter', s['chain'], order, action=action, hook=s['chain'], **kw))
        else:
            action = 'dnat' if s['action'] in ('dst-nat', 'redirect') else 'snat'
            nat.append(_rule('routeros', 'nat', s['chain'], order, action=action, to_addr=s.get('to-addresses'), to_port=int(s['to-ports']) if str(s.get('to-ports') or '').isdigit() else None, **kw))
    return {'rules': rules, 'nat': nat}


def _value(v) -> str:
    v = str(v)
    return f'"{v}"' if re.search(r'\s', v) else v


def _port_text(ports) -> str:
    return ','.join(str(p) if isinstance(p, int) else f'{p[0]}-{p[1]}' for p in ports or [])


def _rule_to_dsl(r: dict, chain: str | None = None) -> str:
    """One model rule. Anything the model couldn't follow goes in a comment after it, so nobody reads this as complete when it isn't."""
    action = r.get('action') or 'passthrough'
    words = [f'chain={chain or r.get("hook") or r.get("chain")}']
    if str(action).startswith('jump:'):
        words += ['action=jump', f'jump-target={action[5:]}']
    else:
        words.append(f'action={action}')
    for key, name in (('proto', 'protocol'), ('saddr', 'src-address'), ('daddr', 'dst-address'), ('iif', 'in-interface'), ('oif', 'out-interface'), ('ct', 'connection-state')):
        if r.get(key):
            words.append(f'{name}={_value(r[key]).replace(" ", "")}')
    if r.get('not_saddr'):
        words.append(f'src-address=!{r["not_saddr"]}')
    if r.get('not_iif'):
        words.append(f'in-interface=!{r["not_iif"]}')
    if r.get('not_oif'):
        words.append(f'out-interface=!{r["not_oif"]}')
    if r.get('dports'):
        words.append(f'dst-port={_port_text(r["dports"])}')
    if r.get('comment'):
        words.append(f'comment={_value(r["comment"])}')
    line = '/ip firewall filter add ' + ' '.join(words)
    if r.get('unmodelled'):
        line += '  # also: ' + '; '.join(map(str, r['unmodelled']))[:200]
    return line


def from_model(net: dict | None, fw: dict | None) -> str:
    """Whatever a host or device runs, in one syntax. Read-only rendering of a reading: it isn't a script to run back."""
    out = []
    if net:
        for i in net.get('interfaces') or []:
            if i.get('kind') == 'bridge':
                out.append(f'/interface bridge add name={i["name"]}')
            elif i.get('kind') == 'vlan' and i.get('vlan_id'):
                out.append(f'/interface vlan add name={i["name"]} vlan-id={i["vlan_id"]} interface={i.get("parent") or "?"}')
            elif i.get('kind') == 'bond':
                out.append(f'/interface bonding add name={i["name"]}')
            if i.get('master'):
                out.append(f'/interface bridge port add bridge={i["master"]} interface={i["name"]}')
        for i in net.get('interfaces') or []:
            for a in i.get('addresses') or []:
                if a.get('scope') != 'link' and i.get('kind') != 'loopback' and a.get('prefix') is not None:
                    out.append(f'/ip{"v6" if ":" in str(a["ip"]) else ""} address add address={a["ip"]}/{a["prefix"]} interface={i["name"]}')
        for r in net.get('routes') or []:
            if r.get('via'):
                out.append(f'/ip{"v6" if r.get("family") == 6 else ""} route add dst-address={"0.0.0.0/0" if r["dst"] == "default" and r.get("family") != 6 else "::/0" if r["dst"] == "default" else r["dst"]} gateway={r["via"]}' + (f' distance={r["metric"]}' if r.get('metric') else ''))
        dns = (net.get('dns') or {}).get('nameservers')
        if dns:
            out.append(f'/ip dns set servers={",".join(dns)}')
    if fw:
        if not fw.get('readable', True):
            out.append('# the firewall could not be read')
        for r in sorted(fw.get('rules') or [], key=lambda x: x.get('order') or 0):
            out.append(_rule_to_dsl(r))
        for n in fw.get('nat') or []:
            words = [f'chain={"dstnat" if n.get("action") == "dnat" else "srcnat"}', f'action={"dst-nat" if n.get("action") == "dnat" else "masquerade"}']
            for key, name in (('proto', 'protocol'), ('iif', 'in-interface'), ('oif', 'out-interface'), ('saddr', 'src-address'), ('daddr', 'dst-address')):
                if n.get(key):
                    words.append(f'{name}={n[key]}')
            if n.get('dports'):
                words.append(f'dst-port={_port_text(n["dports"])}')
            if n.get('to_addr'):
                words.append(f'to-addresses={n["to_addr"]}')
            if n.get('to_port'):
                words.append(f'to-ports={n["to_port"]}')
            if n.get('comment'):
                words.append(f'comment={_value(n["comment"])}')
            out.append('/ip firewall nat add ' + ' '.join(words))
    return '\n'.join(out) + ('\n' if out else '')
