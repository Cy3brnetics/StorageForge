"""Who can reach each listener and published port, worked out from a host's bind addresses, firewall rules and runtime NAT.

Nothing is probed. Every answer is what the configuration says, and it says so. A wrong "not reachable" is worse than no
answer, so when rules cannot be read or a rule on the path could not be understood, the level is `unknown` and the reason is
given. Rules on anything between hosts are out of sight: a router's port forward can put a `lan` service on the internet.

    level: loopback  only this machine
           blocked   the firewall drops it from every network this host is on
           vpn       only over a VPN interface
           lan       from private networks
           any       from any address, on an interface with a public address
           unknown   could not be worked out; see `why`

Input traffic goes through the front end that owns it (firewalld zones, ufw's rules), or the kernel's chains otherwise. A
published container port is DNATed before input, so it goes through the forward chains, which is why ufw does not stop it.
"""
from __future__ import annotations

import ipaddress

from .firewall import port_matches

ORDER = {'loopback': 0, 'blocked': 1, 'vpn': 2, 'lan': 3, 'any': 4, 'unknown': 5}
VPN_NAMES = ('wg', 'tun', 'tap', 'tailscale', 'nebula', 'zt', 'netbird')
LOCAL_KINDS = ('veth', 'dummy', 'loopback')
CAVEAT = 'Per configuration, from the last reading. Anything between hosts, such as a router, is not seen.'


def _net(text):
    try:
        return ipaddress.ip_network(str(text), strict=False)
    except ValueError:
        return None


def _ifname_match(pattern, name) -> bool:
    if pattern is None or name is None:
        return True
    pattern = str(pattern)
    if ',' in pattern:
        return any(_ifname_match(p, name) for p in pattern.split(','))
    if pattern.endswith(('+', '*')):
        return name.startswith(pattern[:-1])
    return pattern == name


def _everyone(saddr) -> bool:
    return saddr in (None, '0.0.0.0/0', '::/0', 'Anywhere')


def _addr_matches(rule_addr, addr) -> bool | None:
    """None when it cannot be said: a named set, or no address to compare."""
    if rule_addr is None:
        return True
    if addr is None or str(rule_addr).startswith('@'):
        return None
    for part in str(rule_addr).split(','):
        net = _net(part)
        if net is None:
            return None
        try:
            if ipaddress.ip_address(addr) in net:
                return True
        except ValueError:
            return None
    return False


def _match(rule: dict, flow: dict) -> str:
    """yes, no, source (matches for only some source addresses) or unknown (a part of it could not be understood)."""
    if rule.get('family') in ('ip', 'ip6') and flow.get('family') and rule['family'] != flow['family']:
        return 'no'
    if rule.get('proto') and flow['proto'] not in str(rule['proto']).lower().split(','):
        return 'no'
    if rule.get('dports') and not port_matches(rule['dports'], flow['port']):
        return 'no'
    if rule.get('orig_dports'):
        if flow.get('orig_port') is None:
            return 'no'
        if not port_matches(rule['orig_dports'], flow['orig_port']):
            return 'no'
    if rule.get('ct') and 'new' not in str(rule['ct']).lower():
        return 'no'
    if not _ifname_match(rule.get('iif'), flow.get('iif')) or not _ifname_match(rule.get('oif'), flow.get('oif')):
        return 'no'
    if rule.get('not_iif') and flow.get('iif') and _ifname_match(rule['not_iif'], flow['iif']):
        return 'no'
    if rule.get('not_oif') and flow.get('oif') and _ifname_match(rule['not_oif'], flow['oif']):
        return 'no'
    dst = _addr_matches(rule.get('daddr'), flow.get('daddr'))
    if dst is False:
        return 'no'
    if rule.get('unmodelled') or dst is None:
        return 'unknown'
    source = flow.get('saddr')
    if rule.get('not_saddr'):
        if source is None:
            return 'except'
        return 'no' if _addr_matches(rule['not_saddr'], source) else 'yes'
    if _everyone(rule.get('saddr')):
        return 'yes'
    if source is None:
        return 'source'
    got = _addr_matches(rule['saddr'], source)      # a question about one address has an answer, unless the rule names a set
    return 'yes' if got else 'no' if got is False else 'unknown'


def _label(rule: dict) -> str:
    parts = [rule.get('backend') or '', str(rule.get('chain') or ''), str(rule.get('action') or '')]
    if rule.get('dports'):
        parts.append('port ' + ','.join(str(p if isinstance(p, int) else f'{p[0]}-{p[1]}') for p in rule['dports']))
    if rule.get('saddr'):
        parts.append(f'from {rule["saddr"]}')
    return ' '.join(p for p in parts if p)


def walk(chain_rules: list[dict], by_chain: dict, flow: dict, state: dict, depth: int = 0) -> str | None:
    """Goes down one chain in order. accept, drop, return, or None when it falls off the end. Source-limited rules are noted and passed."""
    if depth > 16:
        state['unknown'].append('chains nest too deeply to follow')
        state['may_allow'] = True
        return None
    for rule in chain_rules:
        got = _match(rule, flow)
        if got == 'no':
            continue
        action = rule.get('action')
        if got == 'unknown':
            if action and action != 'return':
                state['unknown'].append(_label(rule) + ': not understood: ' + '; '.join(rule.get('unmodelled') or ['a named set']))
                # a drop we misread can only make this look more open than it is, which is the safe way to be wrong
                state['may_allow'] = state.get('may_allow') or action == 'accept' or action.startswith('jump:')
            continue
        if got == 'except':                     # a fence: everyone but these. Only these can be reached, if anything lets them in
            if action in ('drop', 'reject'):
                state.setdefault('fenced', []).append({'only': rule['not_saddr'], 'rule': _label(rule)})
            else:
                state['unknown'].append(_label(rule) + ': a rule for everyone but some sources')
            continue
        if got == 'source':
            if action == 'accept':
                state['sources'].append({'source': rule['saddr'], 'rule': _label(rule)})
            elif action and action.startswith('jump:'):
                state['unknown'].append(_label(rule) + ': a chain only for some sources')
                state['may_allow'] = True
            continue
        if action is None:
            continue
        if action.startswith('jump:'):
            target = action[5:]
            if target in ('DROP', 'REJECT', 'ACCEPT'):
                action = target.lower()
            else:
                got = walk(by_chain.get((rule.get('table'), target), []), by_chain, flow, state, depth + 1)
                if got in ('accept', 'drop', 'reject'):
                    return got
                continue
        if action in ('accept', 'drop', 'reject', 'return'):
            state['rule'] = _label(rule)
            return action
    return None


OWN_TABLES = 'inet storageforge_'


def _path(state: dict, verdict: str, rule) -> dict:
    return {'verdict': verdict, 'rule': rule, 'sources': state['sources'], 'unknown': state['unknown'], 'may_allow': state.get('may_allow'), 'fenced': state.get('fenced') or []}


def kernel_path(fw: dict, hook: str, flow: dict, own_only: bool = False) -> dict:
    """Every base chain on the hook, lowest priority first. A packet must get through all of them. own_only: just the tables
    StorageForge writes, which sit ahead of whichever front end the host runs."""
    by_chain: dict = {}
    for r in sorted(fw['rules'], key=lambda r: r.get('order') or 0):
        by_chain.setdefault((r.get('table'), r.get('chain')), []).append(r)
    state = {'unknown': [], 'sources': [], 'rule': None}
    chains = [c for c in fw.get('chains') or [] if c['hook'] == hook and c.get('family') in (None, 'inet', flow.get('family')) and (not own_only or str(c.get('table')).startswith(OWN_TABLES))]
    verdict = 'accept'
    for c in sorted(chains, key=lambda c: c.get('prio') or 0):
        state['rule'] = None
        got = walk(by_chain.get((c['table'], c['name']), []), by_chain, flow, state)
        if got in (None, 'return'):
            got = c.get('policy') or 'accept'
            state['rule'] = f'{c["backend"]} {c["name"]} policy {got}'
        if got != 'accept':
            verdict = 'drop'
            break
    return _path(state, verdict, state['rule'])


def ufw_path(fw: dict, flow: dict) -> dict:
    state = {'unknown': [], 'sources': [], 'rule': None}
    rules = [r for r in fw['rules'] if r['backend'] == 'ufw' and r['chain'] == 'input']
    got = walk(rules, {}, flow, state)
    if got in ('accept', 'drop', 'reject'):
        return {'verdict': 'accept' if got == 'accept' else 'drop', 'rule': state['rule'], 'sources': state['sources'], 'unknown': state['unknown'], 'may_allow': state.get('may_allow')}
    pol = fw['policies'].get('input', 'drop')
    return {'verdict': 'accept' if pol == 'accept' else 'drop', 'rule': f'ufw default {pol}', 'sources': state['sources'], 'unknown': state['unknown'], 'may_allow': state.get('may_allow')}


def firewalld_path(fw: dict, flow: dict) -> dict:
    zones = [z for z in fw.get('zones') or [] if flow.get('iif') in z['interfaces']] or [z for z in fw.get('zones') or [] if z.get('active') and not z['sources'] and not z['interfaces']]
    if not zones:
        return {'verdict': 'unknown', 'rule': None, 'sources': [], 'unknown': [f'no firewalld zone found for {flow.get("iif")}'], 'may_allow': True}
    z = zones[0]
    if z.get('target') == 'ACCEPT':
        return {'verdict': 'accept', 'rule': f'zone {z["name"]} target ACCEPT', 'sources': [], 'unknown': []}
    state = {'unknown': [], 'sources': [], 'rule': None}
    rules = sorted((r for r in fw['rules'] if r['backend'] == 'firewalld' and r.get('zone') == z['name']), key=lambda r: (not r.get('rich'), r.get('action') == 'accept', r.get('order') or 0))
    got = walk([{**r, 'iif': None} for r in rules], {}, flow, state)
    if got == 'accept':
        return {'verdict': 'accept', 'rule': state['rule'], 'sources': [], 'unknown': state['unknown']}
    return {'verdict': 'drop', 'rule': f'zone {z["name"]} default', 'sources': state['sources'], 'unknown': state['unknown'], 'may_allow': state.get('may_allow')}


def _input_path(fw: dict, flow: dict) -> dict:
    """A front end says what it lets in, and StorageForge's own tables, ahead of it, can take away from that."""
    front = firewalld_path if 'firewalld' in fw['backends'] else ufw_path if 'ufw' in fw['backends'] else None
    if front is None:
        return kernel_path(fw, 'input', flow)
    own = kernel_path(fw, 'input', flow, own_only=True)
    if own['verdict'] != 'accept':
        return own
    return {**front(fw, flow), 'fenced': own['fenced']}


def _iface_class(iface: dict) -> str | None:
    """What reaching this interface means. None for what is not a way in from outside this machine."""
    name = iface['name'] or ''
    if iface['kind'] in LOCAL_KINDS or iface.get('master') or iface.get('state') == 'down' or not iface.get('addresses'):
        return None
    if iface['kind'] == 'bridge' and (name.startswith(('docker', 'br-', 'podman', 'cni', 'virbr', 'lxdbr', 'incusbr'))):
        return None
    if iface['kind'] == 'wireguard' or name.startswith(VPN_NAMES):
        return 'vpn'
    for a in iface['addresses']:
        try:
            ip = ipaddress.ip_address(a['ip'])
        except (ValueError, TypeError):
            continue
        if ip.is_global:
            return 'any'
    return 'lan'


def _family(addr) -> str | None:
    try:
        return 'ip6' if ipaddress.ip_address(addr).version == 6 else 'ip'
    except ValueError:
        return None


def _level_for(paths: list[tuple[dict, str, str]]) -> tuple[str, str | None, list, list]:
    """Each path: (result, interface class, interface). A path that came out closed, past a rule that might have let it through, is
    open to doubt. The answer is unknown only if that doubt could make it wider than what is certain."""
    best, rule, why, reached = 'blocked', None, [], []
    doubt = None
    for res, cls, name in paths:
        why += res['unknown']
        if res['verdict'] == 'unknown' or (res['verdict'] != 'accept' and res.get('may_allow')):
            doubt = cls if doubt is None else max(doubt, cls, key=lambda x: ORDER[x])
        if res['verdict'] == 'accept':
            reached.append(name)
            level = cls
            if res.get('fenced'):                   # let in, but a fence keeps everyone else out first
                nets = [_net(x) for f in res['fenced'] for x in str(f['only']).split(',')]
                level = 'lan' if nets and all(n is not None and n.is_private for n in nets) and cls != 'vpn' else cls
            if ORDER[level] >= ORDER[best]:
                best, rule = level, res['fenced'][0]['rule'] if res.get('fenced') else res['rule']
        elif res['sources']:                    # dropped by default, but let in for some sources
            limited = 'lan'
            for s in res['sources']:
                net = _net(s['source'])
                if net is None:
                    doubt = cls if doubt is None else max(doubt, cls, key=lambda x: ORDER[x])
                    why.append(f'{s["rule"]}: a source that could not be read')
                elif not net.is_private:
                    limited = cls
            limited = min((limited, cls), key=lambda x: ORDER[x]) if cls in ('vpn',) else limited
            reached.append(name)
            if ORDER[limited] >= ORDER[best]:
                best, rule = limited, res['sources'][0]['rule']
        elif best == 'blocked' and rule is None:
            rule = res['rule']
    if doubt and ORDER[doubt] > ORDER[best]:
        return 'unknown', rule, sorted(set(why)) or ['a rule on the path could not be understood'], reached
    return best, rule, sorted(set(why)), reached


def _interfaces(net: dict) -> list[tuple[dict, str]]:
    return [(i, c) for i in net.get('interfaces') or [] if (c := _iface_class(i))]


def listener_item(lsn: dict, net: dict, fw: dict | None) -> dict:
    item = {'kind': 'listener', 'proto': lsn['proto'], 'addr': lsn['addr'], 'port': lsn['port'], 'process': lsn.get('process'), 'level': 'unknown', 'rule': None, 'why': [], 'reached_on': []}
    if lsn['scope'] == 'loopback':
        return {**item, 'level': 'loopback', 'rule': f'bound to {lsn["addr"]}'}
    ifaces = _interfaces(net)
    if lsn['scope'] in ('address', 'link'):
        ifaces = [(i, c) for i, c in ifaces if any(a['ip'] == lsn['addr'] for a in i['addresses'])]
        if not ifaces:      # on a container bridge or an address that is not a way in
            return {**item, 'level': 'loopback', 'rule': f'bound to {lsn["addr"]}, which is not on an outside interface'}
    if not ifaces:
        return {**item, 'why': ['no outside interface was read on this host']}
    if not fw or not fw.get('readable', False):
        return {**item, 'why': ['the firewall rules have not been read: ' + ('; '.join(fw['notes']) if fw else 'no measurement yet')]}
    if not fw['backends']:
        best = max((c for _, c in ifaces), key=lambda c: ORDER[c])
        return {**item, 'level': best, 'rule': 'no firewall on this host', 'reached_on': [i['name'] for i, _ in ifaces]}
    paths = []
    for iface, cls in ifaces:
        fam = _family(lsn['addr']) if lsn['scope'] != 'any' else ('ip6' if ':' in lsn['addr'] else 'ip')
        if lsn['addr'] == '*':
            fam = 'ip'
        flow = {'proto': lsn['proto'], 'port': lsn['port'], 'iif': iface['name'], 'daddr': lsn['addr'] if lsn['scope'] != 'any' else None, 'family': fam}
        paths.append((_input_path(fw, flow), cls, iface['name']))
    level, rule, why, reached = _level_for(paths)
    fenced = sorted({str(f['only']) for res, _, _ in paths for f in res.get('fenced') or []})
    return {**item, 'level': level, 'rule': rule, 'why': why, 'reached_on': reached, **({'fenced_to': fenced} if fenced else {})}


def _bridge_for(gateway, net: dict) -> str | None:
    for i in net.get('interfaces') or []:
        if any(a['ip'] == gateway for a in i.get('addresses') or []):
            return i['name']
    return None


def published_item(container: dict, port: dict, net: dict, fw: dict | None, host: str) -> dict:
    item = {'kind': 'published', 'container': container['name'], 'host': host, 'proto': port['proto'], 'addr': port['host_ip'], 'port': port['host_port'], 'target_port': port['port'],
            'level': 'unknown', 'rule': None, 'why': [], 'reached_on': []}
    bind = port['host_ip']
    try:
        if ipaddress.ip_address(bind).is_loopback:
            return {**item, 'level': 'loopback', 'rule': f'published on {bind}'}
    except ValueError:
        pass
    if container.get('state') != 'running':
        return {**item, 'level': 'loopback', 'rule': 'not running, so nothing is listening now', 'stopped': True}
    ifaces = _interfaces(net)
    if bind not in ('0.0.0.0', '::'):
        ifaces = [(i, c) for i, c in ifaces if any(a['ip'] == bind for a in i['addresses'])]
    if not ifaces:
        return {**item, 'why': ['no outside interface was read on this host']}
    if not fw or not fw.get('readable', False):
        return {**item, 'why': ['the firewall rules have not been read: ' + ('; '.join(fw['notes']) if fw else 'no measurement yet')]}
    n = next((x for x in container.get('networks') or [] if x.get('ip')), None)
    if container.get('network_mode') == 'host' or not n:
        # no NAT: it is a listener on the host, so it answers to the input rules
        flow_item = listener_item({'proto': port['proto'], 'addr': bind, 'port': port['host_port'], 'scope': 'any' if bind in ('0.0.0.0', '::') else 'address'}, net, fw)
        return {**item, **{k: flow_item[k] for k in ('level', 'rule', 'why', 'reached_on')}}
    oif = _bridge_for(n.get('gateway'), net)
    fam = 'ip6' if ':' in bind else 'ip'
    paths = [(kernel_path(fw, 'forward', {'proto': port['proto'], 'port': port['port'], 'orig_port': port['host_port'], 'iif': i['name'], 'oif': oif, 'daddr': n['ip'] if fam == 'ip' else n.get('ip6'), 'family': fam}), c, i['name']) for i, c in ifaces]
    level, rule, why, reached = _level_for(paths)
    out = {**item, 'level': level, 'rule': rule, 'why': why, 'reached_on': reached}
    if 'ufw' in fw['backends'] or 'firewalld' in fw['backends']:
        out['bypasses_frontend'] = level in ('lan', 'any', 'vpn')
    return out


def host_report(net: dict | None, infra: dict | None, containers: list[dict], host: str) -> dict:
    """Everything this host listens on, widest first. Without a network reading there is nothing to say."""
    if not net:
        return {'host': host, 'read': False, 'items': [], 'caveat': CAVEAT, 'why': 'not scanned since this was added'}
    fw = (infra or {}).get('firewall')
    published = {(p['proto'], p['host_port']) for c in containers for p in c.get('ports') or []}
    listeners = (infra or {}).get('listeners') or net.get('listeners') or []
    items = [listener_item(lsn, net, fw) for lsn in listeners if (lsn['proto'], lsn['port']) not in published]
    items += [published_item(c, p, net, fw, host) for c in containers for p in c.get('ports') or []]
    items.sort(key=lambda i: (-ORDER[i['level']], i['port']))
    return {'host': host, 'read': True, 'firewall_read': bool(fw and fw.get('readable')), 'backends': (fw or {}).get('backends') or [], 'items': items,
            'measured_at': (infra or {}).get('measured_at'), 'network_read_at': net.get('read_at'), 'caveat': CAVEAT}


def in_scope(level: str, scope: str | None) -> bool:
    """Is a listener at this level reachable from this scope? `unknown` always counts: it might be."""
    if not scope or scope == 'all':
        return True
    if level == 'unknown':
        return True
    return {'any': level == 'any', 'lan': level in ('lan', 'any'), 'vpn': level in ('vpn', 'lan', 'any')}.get(scope, True)
