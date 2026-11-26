"""The map as text to keep or share: JSON, Mermaid, Graphviz DOT and Obsidian canvas, each optionally redacted.

Redaction renames hosts, and blanks addresses and MACs wherever they appear, including inside ids, labels, evidence and notes,
because an id like nic:nas-01:eth0 gives away a name as surely as a label does.
"""
from __future__ import annotations

import json
import re

IPV4 = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b')
IPV6 = re.compile(r'(?<![\w:])(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F:]*(?:/\d{1,3})?(?![\w:])|(?<![\w:])::[0-9a-fA-F:]*[0-9a-fA-F](?:/\d{1,3})?(?![\w:])')
MAC = re.compile(r'\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b')


def _scrub(text: str, names: list[tuple[str, str]]) -> str:
    text = MAC.sub('<mac>', text)
    text = IPV6.sub('<ip>', text)
    text = IPV4.sub('<ip>', text)
    for name, alias in names:
        text = re.sub(re.escape(name), alias, text, flags=re.I)
    return text


def redact(graph: dict, extra_names=()) -> dict:
    """A copy with no address, MAC or host name in it, and generic names for hosts."""
    hosts = sorted({n['host'] for n in graph['nodes'] if n.get('host')} | {n['label'] for n in graph['nodes'] if n['kind'] == 'Host'} | set(extra_names), key=lambda h: (-len(h), h))
    names = [(h, f'host{i + 1}') for i, h in enumerate(hosts)]
    names += [(h.split('.')[0], a) for h, a in names if '.' in h]
    alias_ids: dict[str, str] = {}

    def nid(v):
        return alias_ids.setdefault(v, _scrub(v, names) if not IPV4.search(v) and not IPV6.search(v) else f'n{len(alias_ids) + 1}')

    def walk(v):
        if isinstance(v, str):
            return _scrub(v, names)
        if isinstance(v, list):
            return [walk(x) for x in v]
        if isinstance(v, dict):
            return {k: walk(x) for k, x in v.items()}
        return v

    return {**{k: v for k, v in graph.items() if k not in ('nodes', 'edges')},
            'nodes': [{**walk({k: v for k, v in n.items() if k != 'id'}), 'id': nid(n['id'])} for n in graph['nodes']],
            'edges': [{**walk({k: v for k, v in e.items() if k not in ('src', 'dst')}), 'src': nid(e['src']), 'dst': nid(e['dst'])} for e in graph['edges']], 'redacted': True}


def _id(node_id: str, seen: dict) -> str:
    return seen.setdefault(node_id, f'n{len(seen) + 1}')


def _safe(label: str) -> str:
    return re.sub(r'["\\<>{}|\[\]\r\n`]', ' ', str(label))[:80]


def mermaid(graph: dict) -> str:
    ids: dict = {}
    lines = ['flowchart LR']
    for n in graph['nodes']:
        lines.append(f'  {_id(n["id"], ids)}["{_safe(n["kind"])}: {_safe(n["label"])}"]')
    for e in graph['edges']:
        if e['src'] in ids and e['dst'] in ids:
            arrow = '-.->' if (e.get('props') or {}).get('confidence') == 'inferred' else '-->'
            lines.append(f'  {ids[e["src"]]} {arrow}|{_safe(e["rel"])}| {ids[e["dst"]]}')
    return '\n'.join(lines) + '\n'


def dot(graph: dict) -> str:
    ids: dict = {}
    lines = ['digraph storageforge {', '  rankdir=LR;']
    for n in graph['nodes']:
        style = ', style=dashed' if n.get('confidence') == 'inferred' else ''
        lines.append(f'  {_id(n["id"], ids)} [label="{_safe(n["kind"])}: {_safe(n["label"])}"{style}];')
    for e in graph['edges']:
        if e['src'] in ids and e['dst'] in ids:
            style = ', style=dashed' if (e.get('props') or {}).get('confidence') == 'inferred' else ''
            lines.append(f'  {ids[e["src"]]} -> {ids[e["dst"]]} [label="{_safe(e["rel"])}"{style}];')
    return '\n'.join(lines) + '\n}\n'


# ── drawn, for documents and diagrams ───────────────────────────────
ORDER = ('Host', 'Subnet', 'DHCPScope', 'Gateway', 'Neighbour', 'NIC', 'Bond', 'Bridge', 'VLAN', 'VPNInterface', 'VPNNetwork', 'Peer', 'Tunnel', 'AccessProxy', 'ProxyRoute', 'IdentityProvider', 'FirewallPolicy', 'Listener', 'Container', 'VM', 'Instance', 'StoragePool', 'Filesystem', 'MountPoint', 'Symlink')


def layout(graph: dict) -> dict:
    """One column for each host, with shared things in a row above. The same graph always draws the same. {id: (x, y)}"""
    W, H = 240, 34
    pos, cols = {}, {}
    shared = []
    for n in graph['nodes']:
        if n.get('host'):
            cols.setdefault(n['host'], []).append(n)
        elif n['kind'] == 'Host':
            cols.setdefault(n['label'], []).append(n)
        else:
            shared.append(n)
    rank = {k: i for i, k in enumerate(ORDER)}
    for i, n in enumerate(sorted(shared, key=lambda n: (n['kind'], n['label']))):
        pos[n['id']] = (20 + (i % 6) * (W + 20), 20 + (i // 6) * (H + 10))
    top = 40 + (len(shared) // 6 + 1) * (H + 10) if shared else 20
    for c, (_host, nodes) in enumerate(sorted(cols.items())):
        for r, n in enumerate(sorted(nodes, key=lambda n: (rank.get(n['kind'], 99), n['label']))):
            pos[n['id']] = (20 + c * (W + 40), top + r * (H + 8))
    return pos


def _xml(text) -> str:
    return str(text).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;')


def svg(graph: dict) -> str:
    pos = layout(graph)
    W, H = 240, 34
    width = max((x for x, _ in pos.values()), default=0) + W + 20
    height = max((y for _, y in pos.values()), default=0) + H + 60
    out = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" width="{width}" height="{height}" font-family="sans-serif" font-size="12">', f'<rect width="{width}" height="{height}" fill="#fff"/>']
    for e in graph['edges']:
        if e['src'] in pos and e['dst'] in pos:
            (ax, ay), (bx, by) = pos[e['src']], pos[e['dst']]
            dash = ' stroke-dasharray="5 4"' if (e.get('props') or {}).get('confidence') in ('inferred', 'manual') else ''
            out.append(f'<line x1="{ax + W / 2}" y1="{ay + H / 2}" x2="{bx + W / 2}" y2="{by + H / 2}" stroke="#889"{dash}/>')
    colour = {'any': '#d33', 'lan': '#d80', 'vpn': '#27a', 'blocked': '#3a3', 'loopback': '#999', 'unknown': '#a3a'}
    for n in graph['nodes']:
        if n['id'] not in pos:
            continue
        x, y = pos[n['id']]
        dash = ' stroke-dasharray="5 4"' if n.get('confidence') in ('inferred', 'manual') else ''
        stroke = colour.get((n.get('props') or {}).get('exposure'), '#445')
        out.append(f'<rect x="{x}" y="{y}" width="{W}" height="{H}" rx="4" fill="#f6f7f9" stroke="{stroke}"{dash}/><text x="{x + 8}" y="{y + 21}" fill="#123">{_xml(n["kind"])}: {_xml(str(n["label"])[:30])}</text>')
    out.append(f'<text x="20" y="{height - 16}" fill="#567">Per configuration, from what hosts reported. Dashed: inferred or placed by hand.{" Redacted." if graph.get("redacted") else ""}</text></svg>')
    return '\n'.join(out) + '\n'


def drawio(graph: dict) -> str:
    pos = layout(graph)
    ids: dict = {}
    cells = ['<mxCell id="0"/>', '<mxCell id="1" parent="0"/>']
    for n in graph['nodes']:
        if n['id'] not in pos:
            continue
        x, y = pos[n['id']]
        dash = 'dashed=1;' if n.get('confidence') in ('inferred', 'manual') else ''
        cells.append(f'<mxCell id="{_id(n["id"], ids)}" value="{_xml(n["kind"])}: {_xml(n["label"])}" style="rounded=1;whiteSpace=wrap;html=1;{dash}" vertex="1" parent="1"><mxGeometry x="{x}" y="{y}" width="240" height="34" as="geometry"/></mxCell>')
    for i, e in enumerate(graph['edges']):
        if e['src'] in ids and e['dst'] in ids:
            dash = 'dashed=1;' if (e.get('props') or {}).get('confidence') in ('inferred', 'manual') else ''
            cells.append(f'<mxCell id="e{i}" value="{_xml(e["rel"])}" style="endArrow=block;{dash}" edge="1" parent="1" source="{ids[e["src"]]}" target="{ids[e["dst"]]}"><mxGeometry relative="1" as="geometry"/></mxCell>')
    return '<mxfile><diagram name="StorageForge"><mxGraphModel><root>' + ''.join(cells) + '</root></mxGraphModel></diagram></mxfile>\n'


def canvas(graph: dict) -> str:
    """An Obsidian canvas of the layers above storage. The storage graph has its own, richer one."""
    pos = layout(graph)
    nodes = [{'id': n['id'], 'type': 'text', 'x': pos[n['id']][0], 'y': pos[n['id']][1], 'width': 240, 'height': 60, 'text': f'**{n["kind"]}** {n["label"]}'} for n in graph['nodes'] if n['id'] in pos]
    edges = [{'id': f'e{i}', 'fromNode': e['src'], 'toNode': e['dst'], 'label': e['rel']} for i, e in enumerate(graph['edges']) if e['src'] in pos and e['dst'] in pos]
    return json.dumps({'nodes': nodes, 'edges': edges}, indent=1) + '\n'


def _prefix_of(n: dict, p: dict) -> str | None:
    """The network a Subnet or DHCPScope node stands for: a cidr prop, the Subnet's label, or the scope's subnet prop."""
    import ipaddress
    for cand in (p.get('cidr'), n['label'] if n['kind'] == 'Subnet' else None, p.get('subnet')):
        if not cand or '/' not in str(cand):
            continue
        try:
            return str(ipaddress.ip_network(str(cand).strip(), strict=False))
        except ValueError:
            continue
    return None


def netbox(graph: dict) -> str:
    """NetBox-compatible DCIM/IPAM bulk JSON export: devices, interfaces, prefixes, IP addresses and services."""
    devices, interfaces, prefixes, ips, services = [], [], [], [], []
    seen_prefix = set()
    for n in graph['nodes']:
        p = n.get('props') or {}
        if n['kind'] == 'Host':
            devices.append({'name': n['label'], 'role': p.get('platform') or 'server', 'status': 'active'})
        elif n['kind'] in ('Subnet', 'DHCPScope') and _prefix_of(n, p):
            cidr = _prefix_of(n, p)
            if cidr not in seen_prefix:
                seen_prefix.add(cidr)
                prefixes.append({'prefix': cidr, 'status': 'active', 'description': n['label']})
        elif n['kind'] in ('NIC', 'Bond', 'Bridge', 'VLAN', 'VPNInterface') and n.get('host'):
            interfaces.append({'device': n['host'], 'name': n['label'], 'type': n['kind'].lower(), 'mac_address': p.get('mac'), 'mtu': p.get('mtu')})
            for addr in p.get('addresses') or []:
                ips.append({'address': addr, 'assigned_object_device': n['host'], 'assigned_object_name': n['label'], 'status': 'active'})
        elif n['kind'] == 'Listener' and n.get('host'):
            port_s, _, proto = str(n['label']).partition('/')
            if port_s.isdigit():
                services.append({'device': n['host'], 'name': (p.get('process') or [n['label']])[0], 'protocol': proto or 'tcp', 'ports': [int(port_s)]})
    return json.dumps({'schema': 'storageforge/netbox-v1', 'redacted': bool(graph.get('redacted')),
                       'devices': devices, 'interfaces': interfaces, 'prefixes': prefixes, 'ip_addresses': ips, 'services': services}, indent=1) + '\n'


def grafana(graph: dict) -> str:
    """Grafana Node Graph panel + dashboard JSON export."""
    nodes = [{'id': n['id'], 'title': n['label'], 'subTitle': n['kind'], 'mainStat': (n.get('props') or {}).get('exposure') or n.get('layer'),
              'arc__failed': 1 if (n.get('props') or {}).get('exposure') == 'any' else 0,
              'arc__ok': 0 if (n.get('props') or {}).get('exposure') == 'any' else 1} for n in graph['nodes']]
    edges = [{'id': f'e{i}', 'source': e['src'], 'target': e['dst'], 'mainStat': e['rel']} for i, e in enumerate(graph['edges'])]
    dash = {
        'schemaVersion': 39,
        'title': 'StorageForge Fleet Map',
        'tags': ['storageforge', 'infrastructure'],
        'panels': [
            {'id': 1, 'type': 'nodeGraph', 'title': 'Fleet Topology', 'gridPos': {'h': 16, 'w': 24, 'x': 0, 'y': 0},
             'targets': [{'refId': 'A', 'nodes': nodes, 'edges': edges}]},
        ],
    }
    return json.dumps(dash, indent=1) + '\n'


FORMATS = {'svg': ('image/svg+xml', 'svg', svg), 'drawio': ('application/xml', 'drawio', drawio), 'canvas': ('application/json', 'canvas', canvas), 'json': ('application/json', 'json', lambda g: json.dumps(g, indent=1, default=str)), 'mermaid': ('text/plain', 'mmd', mermaid), 'dot': ('text/vnd.graphviz', 'dot', dot), 'netbox': ('application/json', 'netbox.json', netbox), 'grafana': ('application/json', 'grafana.json', grafana)}
