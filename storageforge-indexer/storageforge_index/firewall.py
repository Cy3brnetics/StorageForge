"""nftables, iptables, ufw and firewalld, read into one model, so nothing above this needs to know which a host runs.

Pure parsing: the text comes from a measurement (inframeasure.py). A rule this cannot fully understand is kept and marked
`unmodelled`, because whoever asks what a firewall allows must be told what could not be worked out. A backend that could not
be read makes the whole model `readable: False`, which means unknown, and never means open or closed.

    {'readable', 'backends', 'policies': {'input': 'drop', ...}, 'chains': [...], 'rules': [...], 'nat': [...], 'zones': [...], 'notes': [...]}
    a base chain: {'backend', 'table', 'name', 'hook', 'prio', 'policy'}
    a rule: {'backend', 'table', 'chain', 'order', 'action', 'proto', 'dports', 'saddr', 'daddr', 'iif', 'oif', 'ct', 'comment', 'unmodelled'}
"""
from __future__ import annotations

import json
import re
import shlex

MAX_RULES = 5000
HOOKS = ('input', 'forward', 'output', 'prerouting', 'postrouting')
ACTIONS = {'accept': 'accept', 'drop': 'drop', 'reject': 'reject', 'return': 'return'}
# Tables iptables-nft owns. nft shows their rules as opaque xt expressions, so iptables-save is the one to read them from.
COMPAT_TABLES = ('filter', 'nat', 'mangle', 'raw', 'security')
MAX_PORT = 65535


def _rule(backend: str, table: str, chain: str, order: int, **f) -> dict:
    return {'backend': backend, 'table': table, 'chain': chain, 'order': order, 'action': None, 'proto': None, 'dports': [], 'saddr': None, 'daddr': None,
            'iif': None, 'oif': None, 'not_iif': None, 'not_oif': None, 'ct': None, 'comment': None, 'unmodelled': [], **f}


def _ports(text) -> list:
    """'22', '8000:8100', '80,443' as ints and [low, high] pairs. None when any part is not a port (a service name)."""
    out = []
    for part in str(text).split(','):
        low, _, high = part.replace('-', ':').partition(':')
        if not low.isdigit() or (high and not high.isdigit()):
            return None
        out.append([int(low), int(high)] if high else int(low))
    return out


def port_matches(dports: list, port: int) -> bool:
    return any(p == port if isinstance(p, int) else p[0] <= port <= p[1] for p in dports)


# ── nftables ─────────────────────────────────────────────────────────
def _nft_value(v):
    """The right side of a match, as text: an address, prefix, range, named set or plain value."""
    if isinstance(v, dict):
        if 'prefix' in v:
            return f"{v['prefix'].get('addr')}/{v['prefix'].get('len')}"
        if 'range' in v:
            return f'{v["range"][0]}-{v["range"][1]}'
        if 'set' in v:
            return ','.join(str(_nft_value(x)) for x in v['set'])
        return None
    return v


def _nft_ports(v):
    if isinstance(v, int):
        return [v]
    if isinstance(v, str) and v.startswith('@'):
        return None
    if isinstance(v, dict) and 'range' in v:
        return [[int(v['range'][0]), int(v['range'][1])]]
    if isinstance(v, dict) and 'set' in v:
        out = []
        for x in v['set']:
            got = _nft_ports(x)
            if got is None:
                return None
            out += got
        return out
    if isinstance(v, list) and len(v) == 2:          # a set element that is a range
        return [[int(v[0]), int(v[1])]]
    return None


def _nft_expr(rule: dict, expr: dict):
    if 'counter' in expr or 'log' in expr or 'limit' in expr:
        return
    for act in ACTIONS:
        if act in expr:
            rule['action'] = ACTIONS[act]
            return
    if 'jump' in expr or 'goto' in expr:
        rule['action'] = 'jump:' + str((expr.get('jump') or expr.get('goto')).get('target'))
        return
    if 'dnat' in expr or 'redirect' in expr:
        rule['action'] = 'dnat'
        d = expr.get('dnat') or expr.get('redirect') or {}
        rule['to_addr'], rule['to_port'] = d.get('addr'), d.get('port')
        return
    if 'snat' in expr or 'masquerade' in expr:
        rule['action'] = 'snat'
        return
    if 'match' not in expr:
        rule['unmodelled'].append(next(iter(expr), 'unknown'))
        return
    m = expr['match']
    left, right, op = m.get('left') or {}, m.get('right'), m.get('op', '==')
    negated = op == '!='
    if isinstance(left, dict) and isinstance(left.get('meta'), dict) and left['meta'].get('key') in ('iifname', 'oifname') and negated:
        rule['not_' + left['meta']['key'][:3]] = _nft_value(right)
        return
    payload = left.get('payload') if isinstance(left, dict) else None
    meta = left.get('meta') if isinstance(left, dict) else None
    ct = left.get('ct') if isinstance(left, dict) else None
    if payload and payload.get('protocol') in ('ip', 'ip6') and payload.get('field') in ('saddr', 'daddr'):
        rule['family'] = payload['protocol']       # in an inet table, `ip6 saddr` only ever matches IPv6, and nft leaves out the nfproto that says so
    if payload and payload.get('field') == 'saddr' and negated:    # a fence: everyone but these
        rule['not_saddr'] = _nft_value(right)
        return
    if payload and payload.get('field') in ('dport', 'sport'):
        if payload.get('protocol') != 'th':       # th: whichever transport an earlier match allowed
            rule['proto'] = rule['proto'] or payload.get('protocol')
        if payload['field'] == 'dport' and not negated:
            ports = _nft_ports(right)
            if ports is not None:
                rule['dports'] = ports
                return
        rule['unmodelled'].append(f'{payload["field"]} {op} {_nft_value(right)}')
    elif payload and payload.get('field') in ('saddr', 'daddr') and not negated:
        rule[payload['field']] = _nft_value(right)
    elif meta and meta.get('key') in ('iifname', 'iif') and not negated:
        rule['iif'] = _nft_value(right)
    elif meta and meta.get('key') in ('oifname', 'oif') and not negated:
        rule['oif'] = _nft_value(right)
    elif meta and meta.get('key') == 'l4proto' and not negated:
        rule['proto'] = _nft_value(right)
    elif payload and payload.get('field') in ('protocol', 'nexthdr') and not negated:
        rule['proto'] = _nft_value(right)
    elif meta and meta.get('key') == 'nfproto':
        if not negated and right in ('ipv4', 'ipv6'):
            rule['family'] = 'ip' if right == 'ipv4' else 'ip6'
        return
    elif ct and ct.get('key') == 'status' and right == 'dnat' and not negated:      # fw4's zones: only what a port forward already chose
        rule['ct_dnat'] = True
    elif ct and ct.get('key') == 'state':
        rule['ct'] = _nft_value(right) if not isinstance(right, list) else ','.join(map(str, right))
    else:
        rule['unmodelled'].append(json.dumps(m)[:160])


def parse_nft(text: str, skip_compat: bool = False) -> dict | None:
    """skip_compat: iptables-save was read too, so ip and ip6 tables it owns come from there. A native table that happens to be
    called filter is only left out then."""
    docs = []
    try:
        docs = [json.loads(text)]
    except ValueError:
        try:                       # table by table, one a line. One cut short makes the whole reading unreadable, not smaller
            docs = [json.loads(line) for line in text.splitlines() if line.strip()]
        except ValueError:
            return None
    if not docs or not all(isinstance(d, dict) and isinstance(d.get('nftables'), list) for d in docs):
        return None
    items = [i for d in docs for i in d['nftables'] if isinstance(i, dict)]
    policies, rules, nat, notes, order, chains = {}, [], [], [], 0, []
    kinds = {}
    for it in items:
        ch = it.get('chain')
        if ch:
            kinds[(ch.get('family'), ch.get('table'), ch.get('name'))] = ch
            compat = skip_compat and ch.get('table') in COMPAT_TABLES and ch.get('family') in ('ip', 'ip6')
            if ch.get('hook') in HOOKS and ch.get('type') == 'filter' and not compat:
                chains.append({'backend': 'nftables', 'table': f"{ch.get('family')} {ch.get('table')}", 'name': ch.get('name'), 'hook': ch['hook'],
                               'prio': ch.get('prio') or 0, 'policy': ch.get('policy') or 'accept', 'family': ch.get('family')})
            if ch.get('hook') in HOOKS and ch.get('type') == 'filter' and ch.get('policy') and not compat:
                # any base chain that drops by default makes the hook drop, whatever the others say
                old = policies.get(ch['hook'])
                policies[ch['hook']] = 'drop' if 'drop' in (old, ch['policy']) else ch['policy']
    for it in items:
        r = it.get('rule')
        if not r or skip_compat and r.get('table') in COMPAT_TABLES and r.get('family') in ('ip', 'ip6'):
            continue
        order += 1
        rule = _rule('nftables', f"{r.get('family')} {r.get('table')}", r.get('chain'), order, comment=r.get('comment'), family=r.get('family'))
        rule['hook'] = (kinds.get((r.get('family'), r.get('table'), r.get('chain'))) or {}).get('hook')
        for e in r.get('expr') or []:
            _nft_expr(rule, e)
        (nat if rule['action'] == 'dnat' else rules).append(rule)
    return {'policies': policies, 'chains': chains, 'rules': rules, 'nat': nat, 'notes': notes}


# ── iptables-save ────────────────────────────────────────────────────
def parse_iptables(text: str, family: int = 4) -> dict | None:
    if not text or not text.strip():
        return None
    table, policies, rules, nat, order, chains = None, {}, [], [], 0, []
    for line in text.splitlines():
        line = line.strip()
        if line.startswith('*'):
            table = line[1:]
        elif line.startswith(':') and table == 'filter':
            f = line[1:].split()
            if len(f) >= 2 and f[0].lower() in HOOKS and f[1] != '-':
                policies[f[0].lower()] = f[1].lower()
                chains.append({'backend': 'iptables', 'table': 'filter' if family == 4 else 'filter6', 'name': f[0], 'hook': f[0].lower(), 'prio': 0, 'policy': f[1].lower(), 'family': 'ip' if family == 4 else 'ip6'})
        elif line.startswith('-A '):
            order += 1
            try:
                w = shlex.split(line)
            except ValueError:
                w = line.split()
            if len(w) < 2:
                continue
            rule = _rule('iptables', f'{table}{"" if family == 4 else "6"}', w[1], order, hook=w[1].lower() if w[1].lower() in HOOKS else None, family='ip' if family == 4 else 'ip6')
            i = 2
            while i < len(w):
                tok, val = w[i], w[i + 1] if i + 1 < len(w) else ''
                if tok == '!':
                    if val in ('-i', '-o') and i + 2 < len(w):
                        rule['not_iif' if val == '-i' else 'not_oif'] = w[i + 2]
                    else:
                        rule['unmodelled'].append(' '.join(w[i:i + 3]))
                    i += 3
                    continue
                i += 2
                if tok == '-p':
                    rule['proto'] = val
                elif tok == '-s':
                    rule['saddr'] = val
                elif tok == '-d':
                    rule['daddr'] = val
                elif tok == '-i':
                    rule['iif'] = val
                elif tok == '-o':
                    rule['oif'] = val
                elif tok in ('--dport', '--dports', '--destination-port'):
                    ports = _ports(val)
                    if ports is None:
                        rule['unmodelled'].append(f'{tok} {val}')
                    else:
                        rule['dports'] = ports
                elif tok in ('--ctstate', '--state'):
                    rule['ct'] = val.lower()
                elif tok == '--ctorigdstport':     # a published port, by the number it was published on
                    ports = _ports(val)
                    if ports is None:
                        rule['unmodelled'].append(f'{tok} {val}')
                    else:
                        rule['orig_dports'] = ports
                elif tok == '--ctdir':
                    pass
                elif tok == '--comment':
                    rule['comment'] = val
                elif tok == '-m':
                    pass
                elif tok == '-j':
                    rule['action'] = ACTIONS.get(val.lower(), 'dnat' if val == 'DNAT' else 'snat' if val in ('SNAT', 'MASQUERADE') else f'jump:{val}')
                elif tok == '-g':
                    rule['action'] = f'jump:{val}'
                elif tok == '--to-destination':
                    addr, _, port = val.rpartition(':')
                    rule['to_addr'], rule['to_port'] = addr, int(port) if port.isdigit() else None
                elif tok in ('--reject-with', '--to-source', '--random', '--sport'):
                    pass
                else:
                    rule['unmodelled'].append(f'{tok} {val}'.strip())
            (nat if rule['action'] == 'dnat' else rules).append(rule)
    return {'policies': policies, 'chains': chains, 'rules': rules, 'nat': nat, 'notes': []}


# ── ufw ──────────────────────────────────────────────────────────────
UFW_LINE = re.compile(r'^(?P<to>.+?)\s{2,}(?P<action>ALLOW|DENY|REJECT|LIMIT)(?:\s+(?P<dir>IN|OUT|FWD))?\s{2,}(?P<frm>.+?)\s*$')


def parse_ufw(text: str) -> dict | None:
    if not text or 'Status:' not in text:
        return None
    if 'Status: active' not in text:
        return {'active': False, 'policies': {}, 'rules': [], 'nat': [], 'notes': []}
    policies = {}
    m = re.search(r'^Default:\s*(.*)$', text, re.M)
    if m:
        for action, where in re.findall(r'(\w+) \((\w+)\)', m.group(1)):
            policies[{'incoming': 'input', 'outgoing': 'output', 'routed': 'forward'}.get(where, where)] = {'allow': 'accept', 'deny': 'drop', 'reject': 'reject', 'disabled': 'disabled'}.get(action, action)
    rules, order = [], 0
    for line in text.splitlines():
        line, _, note = line.partition(' # ')
        u = UFW_LINE.match(line.rstrip())
        if not u:
            continue
        order += 1
        to, frm, direction = u['to'].strip(), u['frm'].strip(), (u['dir'] or 'IN')
        chain = {'IN': 'input', 'OUT': 'output', 'FWD': 'forward'}[direction]
        rule = _rule('ufw', 'ufw', chain, order, hook=chain, comment=note.strip() or None, action={'ALLOW': 'accept', 'DENY': 'drop', 'REJECT': 'reject', 'LIMIT': 'accept'}[u['action']])
        spec = to.replace(' (v6)', '').strip()
        port, _, proto = spec.partition('/')
        ports = _ports(port.split(' on ')[0].strip())
        if ports is None:
            if spec.startswith('Anywhere'):
                pass
            else:
                rule['unmodelled'].append(f'to {to}')
        else:
            rule['dports'], rule['proto'] = ports, proto.split()[0] if proto else None
        if ' on ' in to:
            rule['iif'] = to.split(' on ', 1)[1].split()[0]
        source = frm.replace(' (v6)', '').strip()
        rule['saddr'] = None if source.startswith('Anywhere') else source
        rules.append(rule)
    return {'active': True, 'policies': policies, 'rules': rules, 'nat': [], 'notes': []}


# ── firewalld ────────────────────────────────────────────────────────
# Ports of the services this project cares about. Any other service name stays unmodelled rather than guessed.
SERVICES = {'ssh': ('tcp', 22), 'http': ('tcp', 80), 'https': ('tcp', 443), 'samba': ('tcp', 445), 'nfs': ('tcp', 2049), 'mountd': ('tcp', 20048), 'cockpit': ('tcp', 9090)}


RICH = re.compile(r'^rule(?: family="(?P<family>ipv[46])")?(?: source address="(?P<src>[0-9a-fA-F:./]+)")? port port="(?P<port>[0-9-]+)" protocol="(?P<proto>tcp|udp)" (?P<action>accept|drop|reject)$')


def _rich(text: str) -> dict | None:
    """The plain kind of rich rule: a source, a port, a verdict. Anything else stays unmodelled."""
    m = RICH.match(text.strip())
    if not m:
        return None
    return {'proto': m['proto'], 'dports': _ports(m['port']) or [], 'saddr': m['src'], 'action': m['action'], **({'family': 'ip' if m['family'] == 'ipv4' else 'ip6'} if m['family'] else {})}


def parse_firewalld(text: str) -> dict | None:
    if not text or not text.strip():
        return None
    zones, cur = [], None
    for raw in text.splitlines():
        if raw and not raw[0].isspace():
            cur = {'name': raw.split()[0], 'active': 'active' in raw, 'target': None, 'interfaces': [], 'sources': [], 'services': [], 'ports': [], 'rich': []}
            zones.append(cur)
        elif cur and ':' in raw:
            key, _, val = raw.strip().partition(':')
            words = val.split()
            if key == 'target':
                cur['target'] = val.strip()
            elif key in ('interfaces', 'sources', 'services', 'ports'):
                cur[key] = words
            elif key == 'rich rules':
                pass
        elif cur and raw.strip().startswith('rule '):
            cur['rich'].append(raw.strip())
    rules, order = [], 0
    for z in zones:
        if not (z['active'] or z['interfaces'] or z['sources']):
            continue
        for src in z['sources'] or [None]:
            def add(**f):
                nonlocal order
                order += 1
                rules.append(_rule('firewalld', f'zone {z["name"]}', z['name'], order, hook='input', zone=z['name'], zone_interfaces=z['interfaces'], saddr=src, action='accept', **f))
            for svc in z['services']:
                if svc in SERVICES:
                    add(proto=SERVICES[svc][0], dports=[SERVICES[svc][1]], comment=f'service {svc}')
                else:
                    add(comment=f'service {svc}', unmodelled=[f'service {svc}: its ports are not known here'])
            for p in z['ports']:
                port, _, proto = p.partition('/')
                ports = _ports(port)
                add(proto=proto or None, dports=ports or [], unmodelled=[] if ports else [p])
            for rich in z['rich']:
                got = _rich(rich)
                if got and src is None:
                    order += 1
                    rules.append(_rule('firewalld', f'zone {z["name"]}', z['name'], order, hook='input', zone=z['name'], zone_interfaces=z['interfaces'], comment=rich, rich=True, **got))
                else:
                    add(comment=rich, unmodelled=[rich])
    return {'policies': {}, 'rules': rules, 'nat': [], 'zones': zones, 'notes': []}


# ── one model ────────────────────────────────────────────────────────
def model(sections: dict) -> dict:
    """sections: {'tools': names present, 'nft': text, 'iptables': text, 'ip6tables': text, 'ufw': text, 'firewalld': text, 'firewalld_state': text}.
    A tool that is present but gave nothing readable makes the model unreadable rather than quietly smaller."""
    tools = set(sections.get('tools') or [])
    out = {'readable': True, 'backends': [], 'policies': {}, 'chains': [], 'rules': [], 'nat': [], 'zones': [], 'notes': []}
    failed = []

    def take(name, got):
        if got is None:
            failed.append(name)
            return
        out['backends'].append(name)
        for hook, pol in (got.get('policies') or {}).items():
            old = out['policies'].get(hook)
            out['policies'][hook] = 'drop' if 'drop' in (old, pol) else pol
        out['rules'] += got['rules']
        out['chains'] += got.get('chains') or []
        out['nat'] += got['nat']
        out['zones'] += got.get('zones') or []
        out['notes'] += got.get('notes') or []

    if 'firewall-cmd' in tools and (sections.get('firewalld_state') or '').strip() == 'running':
        take('firewalld', parse_firewalld(sections.get('firewalld') or ''))
    if 'ufw' in tools:
        u = parse_ufw(sections.get('ufw') or '')
        if u is None:
            failed.append('ufw')
        elif u['active']:
            take('ufw', u)
    if 'nft' in tools:
        take('nftables', parse_nft(sections.get('nft') or '', skip_compat=bool((sections.get('iptables') or '').strip())))
    if 'iptables' in tools or 'iptables-save' in tools:
        for name, fam in (('iptables', 4), ('ip6tables', 6)):
            text = sections.get(name) or ''
            if text.strip():
                got = parse_iptables(text, fam)
                if got and (got['rules'] or got['nat'] or any(p != 'accept' for p in got['policies'].values())):
                    take('iptables' if fam == 4 else 'ip6tables', got)
    if not tools & {'nft', 'iptables', 'iptables-save', 'ufw', 'firewall-cmd'}:
        out['notes'].append('none of nft, iptables, ufw or firewall-cmd is on this host')
    if failed:
        out['readable'] = False
        out['notes'].append('could not read: ' + ', '.join(failed))
    if len(out['rules']) > MAX_RULES:
        out['notes'].append(f'{len(out["rules"])} rules, kept the first {MAX_RULES}')
        out['rules'] = out['rules'][:MAX_RULES]
    out['backends'] = sorted(set(out['backends']))
    return out
