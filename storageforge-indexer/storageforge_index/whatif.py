"""What a draft plan would do, before it does it. It copies the facts, applies each staged step to the copy, and compares.

    ghost        nodes and edges to draw in outline, and the ones to strike through
    exposure     which listeners would become reachable from further, or less far
    reach        any flow asked about, before and after
    conflicts    duplicate addresses, port clashes, and anything that would cut StorageForge's own way in

Only analysis of configuration, and it says so. Steps it does not model are listed, not assumed harmless. The Report on the
host, which looks at the real thing, stays the source of truth before Apply.
"""
from __future__ import annotations

import copy
import ipaddress
import re

from . import changes, exposure, firewall, inframeasure, netfacts, reach, security, workloads
from .db import Conn
from .moves import find_host, hosts

CAVEAT = 'Per configuration, from the last readings. Nothing has changed on any host, and the Report on the host itself has the last word.'
MODELLED = {'fw-rule', 'fw-fence', 'net-bridge', 'net-vlan', 'net-mtu', 'container', 'vm', 'workload-action', 'workload-remove', 'wg-peer'}
NOT_ON_THE_MAP = {'sysctl-set', 'umask-set', 'sshd-option', 'selinux-boolean', 'selinux-relabel', 'apparmor-local', 'apparmor-mode', 'chrony-nts'}


def _facts(conn: Conn, host: str) -> dict:
    return {'net': netfacts.reading(conn, host), 'infra': inframeasure.reading(conn, host), 'containers': workloads.containers_of(conn, host)}


def _port_list(text: str):
    return firewall._ports(str(text).replace('-', ':')) or []


def _fw_of(facts: dict) -> dict | None:
    return (facts.get('infra') or {}).get('firewall')


def _apply_fw_rule(facts: dict, p: dict) -> str | None:
    """Writes the rule into the model where storageforge-fwrules would write it on this host's firewall."""
    fw = _fw_of(facts)
    if not fw or not fw.get('readable'):
        return f'the firewall has not been read, so "{p["action"]} {p["proto"]}/{p["port"]}" cannot be shown'
    action = 'accept' if p['action'] == 'allow' else 'drop'
    fields = {'proto': p['proto'], 'dports': _port_list(p['port']), 'saddr': p['source'] or None, 'iif': p['iface'] or None, 'action': action, 'comment': 'staged', 'staged': True}
    backends = fw['backends']
    if p['state'] == 'absent':
        before = len(fw['rules'])
        fw['rules'] = [r for r in fw['rules'] if not (r.get('proto') == fields['proto'] and r.get('dports') == fields['dports'] and r.get('saddr') == fields['saddr'] and r.get('action') == action)]
        return None if len(fw['rules']) < before else f'no rule like {p["action"]} {p["proto"]}/{p["port"]} was read, so removing it changes nothing here'
    if p['hook'] == 'forward':
        hasdu = any(r.get('chain') == 'DOCKER-USER' for r in fw['rules']) or any(r.get('action') == 'jump:DOCKER-USER' for r in fw['rules'])
        if hasdu:
            first = {**fields, 'dports': [], 'orig_dports': fields['dports'], 'backend': 'iptables', 'table': 'filter', 'chain': 'DOCKER-USER', 'hook': None, 'order': -1, 'action': action if action == 'drop' else 'return'}
            fw['rules'].insert(0, firewall._rule('iptables', 'filter', 'DOCKER-USER', -1, **{k: v for k, v in first.items() if k not in ('backend', 'table', 'chain', 'order')}))
            return None
        fw['rules'].insert(0, firewall._rule('iptables', 'filter', 'FORWARD', -1, **fields, hook='forward'))
        return None
    if 'firewalld' in backends:
        zones = [z for z in fw.get('zones') or [] if z.get('active')] or fw.get('zones') or []
        for z in zones:
            fw['rules'].insert(0, firewall._rule('firewalld', f'zone {z["name"]}', z['name'], -1, hook='input', zone=z['name'], zone_interfaces=z['interfaces'], rich=True, **fields))
        return None
    if 'ufw' in backends:
        fw['rules'].insert(0, firewall._rule('ufw', 'ufw', 'input', -1, hook='input', **fields))
        return None
    if action == 'drop':
        table = 'inet storageforge_rules'
        if not any(c['table'] == table and c['hook'] == 'input' for c in fw.get('chains') or []):
            fw.setdefault('chains', []).append({'backend': 'nftables', 'table': table, 'name': 'input', 'hook': 'input', 'prio': -150, 'policy': 'accept', 'family': 'inet'})
        fw['rules'].insert(0, firewall._rule('nftables', table, 'input', -1, hook='input', family='inet', **fields))
        fw['backends'] = sorted(set(backends) | {'nftables'})
        return None
    for c in [c for c in fw.get('chains') or [] if c['hook'] == 'input' and c.get('policy') == 'drop'] or []:
        fw['rules'].insert(0, firewall._rule(c['backend'], c['table'], c['name'], -1, hook='input', family=c.get('family'), **fields))
    if 'nftables' not in backends and 'iptables' not in backends:
        fw['backends'] = sorted(set(backends) | {'nftables'})
    return None


def _apply_fence(facts: dict, p: dict) -> str | None:
    fw = _fw_of(facts)
    if not fw or not fw.get('readable'):
        return f'the firewall has not been read, so the fence "{p["name"]}" cannot be shown'
    from .steps_infra import SERVICE_PORTS
    table = 'inet storageforge_shares'
    ports = _port_list(SERVICE_PORTS.get(p['service']) or p['ports'])
    if p['state'] == 'absent':
        fw['rules'] = [r for r in fw['rules'] if r.get('fence') != p['name']]
        return None
    if not any(c['table'] == table for c in fw.get('chains') or []):
        fw.setdefault('chains', []).append({'backend': 'nftables', 'table': table, 'name': 'input', 'hook': 'input', 'prio': -190, 'policy': 'accept', 'family': 'inet'})
    fw['rules'].insert(0, firewall._rule('nftables', table, 'input', -1, hook='input', family='ip', proto='tcp,udp', dports=ports, not_saddr=p['clients'], action='drop', fence=p['name'], comment='staged'))
    if p['iface']:
        fw['rules'].insert(0, firewall._rule('nftables', table, 'input', -1, hook='input', family='ip', proto='tcp,udp', dports=ports, not_iif=p['iface'], action='drop', fence=p['name'], comment='staged'))
    if 'nftables' not in fw['backends']:
        fw['backends'] = sorted(set(fw['backends']) | {'nftables'})
    return None


def _publish_parts(text: str) -> list[dict]:
    out = []
    for part in filter(None, (text or '').split(',')):
        spec, _, proto = part.partition('/')
        f = spec.rsplit(':', 2)
        if len(f) == 3:
            out.append({'host_ip': f[0].strip('[]'), 'host_port': int(f[1]), 'port': int(f[2]), 'proto': proto or 'tcp'})
        elif len(f) == 2:
            out.append({'host_ip': '0.0.0.0', 'host_port': int(f[0]), 'port': int(f[1]), 'proto': proto or 'tcp'})
    return out


def _apply_task(t: dict, facts: dict, ghost: dict, conflicts: list, host: str, fleet_addrs: dict) -> str | None:
    k, p = t['type'], t['params']
    node = lambda nid, kind, label, **props: ghost['add'].append({'id': nid, 'kind': kind, 'label': label, 'host': host, 'staged': True, 'props': props})  # noqa: E731
    edge = lambda a, b, rel: ghost['edges'].append({'src': a, 'dst': b, 'rel': rel, 'staged': True})  # noqa: E731
    net = facts.get('net')
    if k == 'fw-rule':
        ghost['changed'].append({'id': f'fw:{host}', 'what': changes.title(t)})
        return _apply_fw_rule(facts, p)
    if k == 'fw-fence':
        ghost['changed'].append({'id': f'fw:{host}', 'what': changes.title(t)})
        return _apply_fence(facts, p)
    if k in ('net-bridge', 'net-vlan'):
        name = p['name'] if k == 'net-bridge' else f'{p["parent"]}.{p["vlan_id"]}'
        kind = 'Bridge' if k == 'net-bridge' else 'VLAN'
        node(f'nic:{host}:{name}', kind, name, addresses=[p['address']] if p['address'] else [])
        edge(f'nic:{host}:{name}', f'host:{host}', 'ATTACHED_TO')
        ip = p['address'].split('/')[0] if p['address'] else None
        if ip and ip in fleet_addrs and fleet_addrs[ip] != host:
            conflicts.append({'level': 'crit', 'text': f'{ip} is already held by {fleet_addrs[ip]}'})
        if net is not None and not any(i['name'] == name for i in net.get('interfaces') or []):
            net.setdefault('interfaces', []).append({'name': name, 'kind': 'bridge' if k == 'net-bridge' else 'vlan', 'state': 'up', 'mtu': 1500, 'mac': None, 'master': None, 'parent': p.get('parent'),
                                                     'vlan_id': p.get('vlan_id'), 'bridge_vlans': [], 'addresses': [{'ip': ip, 'prefix': int(p['address'].split('/')[1]) if '/' in p['address'] else 32, 'scope': 'global'}] if ip else []})
        return None
    if k == 'net-mtu':
        ghost['changed'].append({'id': f'nic:{host}:{p["iface"]}', 'what': f'MTU {p["mtu"]}'})
        return None
    if k == 'container':
        nid = f'wl:{host}:{p["runtime"]}::{p["name"]}'
        node(nid, 'Container', p['name'], image=p['image'], runtime=p['runtime'])
        edge(nid, f'host:{host}', 'RUNS_ON')
        ports = _publish_parts(p['publish'])
        busy = {(x['proto'], x['port']) for x in (net or {}).get('listeners') or []} | {(q['proto'], q['host_port']) for c in facts['containers'] for q in c.get('ports') or []}
        for q in ports:
            if (q['proto'], q['host_port']) in busy:
                conflicts.append({'level': 'crit', 'text': f'{q["proto"]}/{q["host_port"]} is already in use on {host}'})
            lid = f'lsn:{host}:{q["proto"]}:{q["host_port"]}'
            node(lid, 'Listener', f'{q["host_port"]}/{q["proto"]}')
            edge(nid, lid, 'PUBLISHES')
        gateway = next((a['ip'] for i in (net or {}).get('interfaces') or [] if (i['name'] or '').startswith('docker') for a in i.get('addresses') or []), None)
        facts['containers'].append({'name': p['name'], 'state': 'running', 'ports': ports, 'networks': [{'ip': '172.17.255.254', 'gateway': gateway}] if gateway else [], 'staged': True})
        return None
    if k == 'vm':
        nid = f'wl:{host}:libvirt::{p["name"]}'
        node(nid, 'VM', p['name'], disk=p['disk'])
        edge(nid, f'host:{host}', 'RUNS_ON')
        return None
    if k == 'workload-action':
        ghost['changed'].append({'id': f'wl:{host}:{p["runtime"]}::{p["name"]}', 'what': p['action']})
        if p['action'] == 'stop':
            for c in facts['containers']:
                if c.get('name') == p['name']:
                    c['state'] = 'exited'
        return None
    if k == 'workload-remove':
        ghost['remove'].append({'id': f'wl:{host}:{p["runtime"]}::{p["name"]}'})
        facts['containers'] = [c for c in facts['containers'] if c.get('name') != p['name']]
        return None
    if k == 'wg-peer':
        ghost['changed'].append({'id': f'vpn:{host}:{p["iface"]}', 'what': changes.title(t)})
        return None
    if k in NOT_ON_THE_MAP:
        return None
    return f'{changes.title(t)}: this kind of step is not modelled, so it changes nothing shown here'


def _ssh_path(fleet_before: reach.Fleet, fleet_after: reach.Fleet, conn: Conn, host: str, h: dict) -> list[dict]:
    """StorageForge comes in from its own address: does each step leave that path open?"""
    out = []
    port = int(h.get('ssh_port') or 22)
    for ctrl in security._controller_ips(conn, host) or []:
        facts = fleet_after.hosts.get(host)
        if not facts:
            continue
        before = _ssh_verdict(fleet_before.hosts[host], ctrl, h, port)
        after = _ssh_verdict(facts, ctrl, h, port)
        if before['verdict'] != 'drop' and after['verdict'] == 'drop':
            out.append({'level': 'crit', 'text': f'this cuts SSH from {ctrl} to {host}, which is how StorageForge reaches it: {after["rule"]}', 'host': host, 'blocks_ssh': True})
    return out


def _ssh_iface(tasks: list[dict], facts: dict, host: str, h: dict) -> list[dict]:
    """A step that moves or reshapes the interface StorageForge comes in on. Firewall rules cannot show this, so it is looked at apart."""
    addr = h.get('ssh_host')
    iface = next((i['name'] for i in (facts.get('net') or {}).get('interfaces') or [] if any(a.get('ip') == addr for a in i.get('addresses') or [])), None)
    out = []
    for t in tasks:
        if t['host'] != host or not iface:
            continue
        p = t['params']
        names = (p.get('ports') or '').split(',') if t['type'] == 'net-bridge' else [p.get('iface')] if t['type'] == 'net-mtu' else []
        if iface in names:
            out.append({'level': 'crit', 'text': f'{changes.title(t)} touches {iface}, which is how StorageForge reaches {host}', 'host': host, 'blocks_ssh': True})
    return out


def _ssh_verdict(facts: dict, ctrl: str, h: dict, port: int) -> dict:
    fw = _fw_of(facts)
    if not fw or not fw.get('readable') or not fw.get('backends'):
        return {'verdict': 'unknown', 'rule': None}
    addr = h.get('ssh_host')
    iface = next((i for i in (facts.get('net') or {}).get('interfaces') or [] if any(a.get('ip') == addr for a in i.get('addresses') or [])), None)
    res = exposure._input_path(fw, {'proto': 'tcp', 'port': port, 'iif': (iface or {}).get('name'), 'daddr': addr, 'saddr': ctrl, 'family': 'ip6' if ':' in ctrl else 'ip'})
    return {'verdict': 'accept' if res['verdict'] == 'accept' else 'drop', 'rule': res['rule']}


def _exposure_diff(before: dict, after: dict) -> list[dict]:
    key = lambda i: (i['proto'], i['port'], i.get('addr'), i.get('container'))  # noqa: E731
    old, new = {key(i): i for i in before['items']}, {key(i): i for i in after['items']}
    out = []
    for k in set(old) | set(new):
        a, b = old.get(k), new.get(k)
        if a and b and a['level'] == b['level'] and a.get('fenced_to') == b.get('fenced_to'):
            continue
        out.append({'proto': k[0], 'port': k[1], 'addr': k[2], 'container': k[3], 'before': (a or {}).get('level'), 'after': (b or {}).get('level'), 'rule': (b or {}).get('rule'), 'why': (b or {}).get('why') or [], 'fenced_to': (b or {}).get('fenced_to'),
                    'wider': exposure.ORDER.get((b or {}).get('level'), -1) > exposure.ORDER.get((a or {}).get('level'), -1)})
    return sorted(out, key=lambda x: x['port'])


def run(conn: Conn, body: dict) -> dict:
    """body: {'tasks': [...], 'flows': [{'from', 'to', 'port', 'proto'}]}. Reads only."""
    plan = changes.normalize({'name': body.get('name') or 'what if', 'tasks': body.get('tasks') or []})
    hs = hosts(conn)
    ghost = {'add': [], 'remove': [], 'edges': [], 'changed': []}
    conflicts, blind = [], []
    before = reach.load(conn)
    after = reach.Fleet(copy.deepcopy(before.hosts))
    fleet_addrs = {ip: h for ip, (h, _) in before.by_addr.items()}
    touched: dict[str, dict] = {}
    for t in plan['tasks']:
        h = find_host(hs, t['host'])
        if not h:
            conflicts.append({'level': 'crit', 'text': f'{t["host"]} has not been scanned'})
            continue
        name = h['name']
        touched[name] = h
        facts = after.hosts.setdefault(name, {'net': None, 'infra': None, 'containers': []})
        note = _apply_task(t, facts, ghost, conflicts, name, fleet_addrs)
        if note:
            blind.append(note)
    after = reach.Fleet(after.hosts)
    report = []
    for name, h in touched.items():
        was, now = before.hosts.get(name) or {}, after.hosts[name]
        a = exposure.host_report(was.get('net'), was.get('infra'), was.get('containers') or [], name)
        b = exposure.host_report(now.get('net'), now.get('infra'), now.get('containers') or [], name)
        report.append({'host': name, 'firewall_read': b.get('firewall_read'), 'changes': _exposure_diff(a, b)})
        conflicts += _ssh_path(before, after, conn, name, h)
        conflicts += _ssh_iface(plan['tasks'], was, name, h)
        if not (now.get('infra') or {}).get('firewall'):
            blind.append(f'{name}: no firewall reading, so reachability there is unknown')
    rolled = {t['host'] for t in plan['tasks'] if t['params'].get('rollback')}
    for c in conflicts:
        if c.get('blocks_ssh') and c.get('host') in rolled:
            c['level'] = 'warn'
            c['text'] += '. A rollback timer is staged, so it undoes itself'
    flows = []
    for f in (body.get('flows') or [])[:50]:
        port = int(f.get('port') or 0)
        proto = 'udp' if f.get('proto') == 'udp' else 'tcp'
        a, b = reach.query(before, str(f.get('from')), str(f.get('to')), port, proto), reach.query(after, str(f.get('from')), str(f.get('to')), port, proto)
        flows.append({'from': f.get('from'), 'to': f.get('to'), 'port': port, 'proto': proto, 'before': a['verdict'], 'after': b['verdict'], 'decided_by': b.get('decided_by'), 'blind_spots': b['blind_spots']})
    return {'ghost': ghost, 'exposure': report, 'flows': flows, 'conflicts': conflicts, 'blocked': any(c['level'] == 'crit' for c in conflicts), 'not_modelled': blind, 'caveat': CAVEAT}


def plan_summary_for(conn: Conn, plan: dict) -> dict:
    """The same answer for a saved plan, for the Changes tab."""
    return run(conn, {'name': plan.get('name'), 'tasks': plan.get('tasks')})


_ = (re, ipaddress)
