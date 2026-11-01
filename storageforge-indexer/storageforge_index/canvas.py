"""Obsidian JSON Canvas (.canvas) export of the storage graph.

Spec: https://jsoncanvas.org/spec/1.0/ — text nodes, group nodes and edges with sides and colours.
Layout is deterministic: one group per host, columns by kind (Host → Pool → Filesystem →
Mount point → Symlink), children placed level with their parent, external targets on the right.
"""
from __future__ import annotations

import hashlib
import json

COLUMNS = {'Host': 0, 'StoragePool': 1, 'Filesystem': 2, 'MountPoint': 3, 'Symlink': 4}
SIZE = {'Host': (300, 120), 'StoragePool': (300, 140), 'Filesystem': (300, 100), 'MountPoint': (320, 120), 'Symlink': (340, 100)}
COL_W, GAP_Y, PAD = 400, 30, 60
COLOR = {'protected': '4', 'local-only': '3', 'broken': '1'}      # Obsidian presets: 4 green, 3 yellow, 1 red
ICON = {'protected': '🟢', 'local-only': '🟡', 'broken': '🔴', 'unknown': '⚪'}
HEALTH_TEXT = {'protected': 'Protected', 'local-only': 'Local-only', 'broken': 'Broken / offline', 'unknown': 'No protection data'}


def cid(s: str) -> str:
    return hashlib.sha1(s.encode()).hexdigest()[:16]


def _bin(n) -> str:
    if n is None:
        return '—'
    v, units = float(n), ('B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB')
    i = 0
    while v >= 1024 and i < len(units) - 1:
        v /= 1024
        i += 1
    return f'{v:.1f} {units[i]}'


def node_text(n: dict) -> str:
    p = n['props']
    lines = [f'### {ICON[n["health"]]} {n["label"]}', f'**{n["kind"]}** · {HEALTH_TEXT[n["health"]]}']
    if n['kind'] == 'Host':
        lines.append(' · '.join(x for x in (p.get('ip'), p.get('os'), 'external target' if p.get('external') else None,
                                             p.get('protocol'), p.get('via')) if x))
    elif n['kind'] == 'StoragePool':
        lines.append(f'{p.get("layout") or p.get("level")} · usable {_bin(p.get("usable_bytes"))} · tolerates {p.get("tolerance", "?")}')
        if p.get('state'):
            lines.append(f'state {p["state"]}')
    elif n['kind'] == 'Filesystem':
        lines.append(f'`{p.get("source")}`')
    elif n['kind'] == 'MountPoint':
        if p.get('bind'):
            lines.append(f'bind of `{p.get("source")}`')
        else:
            lines.append(f'{p.get("fstype") or ""} · {_bin(p.get("used_bytes"))} of {_bin(p.get("total_bytes"))}'
                         + (f' ({p["use_pct"]:.0f}%)' if p.get('use_pct') is not None else ''))
    elif n['kind'] == 'Symlink':
        lines.append(f'→ `{p.get("target")}`')
        if p.get('note') and n['health'] == 'broken':
            lines.append(p['note'])
    return '\n'.join(l for l in lines if l)


def extras(conn, host: str | None) -> dict:
    """What each host serves and runs, beside its storage: {host: {'shares': [...], 'stacks': [...]}}."""
    from . import docker, shares
    out: dict = {}
    names = [host] if host else [r[0] for r in conn.all('SELECT hostname FROM hosts ORDER BY hostname')]
    for name in names:
        here = {'shares': [], 'stacks': []}
        try:
            here['shares'] = [{k: e.get(k) for k in ('protocol', 'name', 'path', 'clients')} for e in shares.check(conn, name)['exports']]
        except LookupError:
            pass
        for view in docker.listing(conn, name):
            here['stacks'] += [s['name'] for s in view.get('stacks') or [] if s.get('name')]
        if here['shares'] or here['stacks']:
            out[name] = here
    return out


def _extra_nodes(extras_by_host: dict, nodes: dict, out_nodes: list, out_edges: list):
    """A card under the map for each share and stack, joined to its host, and to the client hosts a share names."""
    y = max((n['y'] + n['height'] for n in out_nodes), default=0) + PAD
    x = 0

    def card(key, text):
        nonlocal x
        out_nodes.append({'id': cid(key), 'type': 'text', 'text': text, 'x': x, 'y': y, 'width': 320, 'height': 120})
        x += 320 + GAP_Y

    def join(src, dst, label, color):
        out_edges.append({'id': cid(f'{src}|{dst}'), 'fromNode': cid(src), 'toNode': cid(dst), 'fromSide': 'bottom', 'toSide': 'top',
                          'toEnd': 'arrow', 'label': label, 'color': color})
    for host, what in sorted(extras_by_host.items()):
        hid = f'host:{host}'
        for s in what['shares']:
            key = f'share:{host}:{s.get("protocol")}:{s.get("name")}:{s.get("path")}'
            card(key, f'### {s.get("name") or s.get("path")}\n**{s.get("protocol")} share** on {host}\n`{s.get("path")}`')
            if hid in nodes:
                join(hid, key, 'serves', '6')
            for client in str(s.get('clients') or '').split():
                if f'host:{client}' in nodes:
                    join(key, f'host:{client}', 'client', '6')
        for stack in what['stacks']:
            key = f'stack:{host}:{stack}'
            card(key, f'### {stack}\n**Compose stack** on {host}')
            if hid in nodes:
                join(hid, key, 'runs', '5')


def to_canvas(graph: dict, extras_by_host: dict | None = None) -> dict:
    nodes = {n['id']: n for n in graph['nodes']}
    edges = graph['edges']
    out_nodes, out_edges = [], []
    children: dict[str, list[str]] = {}
    for e in edges:
        if e['rel'] in ('CONTAINS', 'MOUNTED_AT'):
            children.setdefault(e['src'], []).append(e['dst'])
        elif e['rel'] == 'SYMLINK_TO':
            children.setdefault(e['dst'], []).append(e['src'])        # place links next to their target

    hosts = sorted(n['id'] for n in nodes.values() if n['kind'] == 'Host' and n['host'])
    placed: dict[str, tuple[int, int, int, int]] = {}
    gx, top = 0, 0
    for hid in hosts:
        hname = nodes[hid]['host']
        col_y = [top + PAD + 40] * len(COLUMNS)
        members = {nid for nid, n in nodes.items() if n['host'] == hname}

        def place(nid, parent_y):
            if nid in placed or nid not in members:
                return
            n = nodes[nid]
            c = COLUMNS[n['kind']]
            w, h = SIZE[n['kind']]
            y = max(col_y[c], parent_y)
            placed[nid] = (gx + PAD + c * COL_W, y, w, h)
            col_y[c] = y + h + GAP_Y
            for kid in sorted(children.get(nid, []), key=lambda k: (COLUMNS[nodes[k]['kind']], nodes[k]['label'])):
                place(kid, y)

        place(hid, top + PAD + 40)
        for nid in sorted(members - set(placed)):
            place(nid, top + PAD + 40)
        used_cols = {COLUMNS[nodes[n]['kind']] for n in members if n in placed}
        width = PAD * 2 + (max(used_cols, default=0)) * COL_W + max(w for w, _ in SIZE.values())
        height = max(col_y) - top + PAD
        out_nodes.append({'id': cid('group:' + hid), 'type': 'group', 'label': hname, 'x': gx, 'y': top,
                          'width': width, 'height': height, 'color': COLOR.get(nodes[hid]['health'])})
        gx += width + 160

    ext = sorted(nid for nid, n in nodes.items() if nid not in placed)
    if ext:
        y = top + PAD + 40
        for nid in ext:
            w, h = SIZE[nodes[nid]['kind']]
            placed[nid] = (gx + PAD, y, w, h)
            y += h + GAP_Y
        out_nodes.append({'id': cid('group:external'), 'type': 'group', 'label': 'External targets', 'x': gx, 'y': top,
                          'width': PAD * 2 + 340, 'height': y - top + PAD})

    for nid, (x, y, w, h) in placed.items():
        n = nodes[nid]
        node = {'id': cid(nid), 'type': 'text', 'text': node_text(n), 'x': x, 'y': y, 'width': w, 'height': h}
        if n['health'] in COLOR:
            node['color'] = COLOR[n['health']]
        out_nodes.append(node)

    for e in edges:
        if e['src'] not in placed or e['dst'] not in placed:
            continue
        backwards = placed[e['src']][0] > placed[e['dst']][0]
        edge = {'id': cid(f'{e["src"]}|{e["rel"]}|{e["dst"]}'), 'fromNode': cid(e['src']), 'toNode': cid(e['dst']),
                'fromSide': 'left' if backwards else 'right', 'toSide': 'right' if backwards else 'left', 'toEnd': 'arrow'}
        if e['rel'] == 'REPLICATES_TO':
            edge['label'] = f'{e["props"].get("mode", "replicates")}: {e["props"].get("state") or e["props"].get("detail") or ""}'.strip(': ')
            if e['props'].get('health') in COLOR:
                edge['color'] = COLOR[e['props']['health']]
        elif e['rel'] == 'SYMLINK_TO':
            edge['label'] = 'symlink'
            edge['color'] = '6'
        elif e['rel'] == 'MOUNTED_AT' and e['props'].get('bind'):
            edge['label'] = 'bind'
            edge['color'] = '5'
        elif e['rel'] == 'MOUNTED_AT' and e['props'].get('subvol'):
            edge['label'] = e['props']['subvol']
        out_edges.append(edge)
    if extras_by_host:
        _extra_nodes(extras_by_host, nodes, out_nodes, out_edges)
    return {'nodes': out_nodes, 'edges': out_edges}


def dumps(graph: dict, extras_by_host: dict | None = None) -> str:
    return json.dumps(to_canvas(graph, extras_by_host), indent='\t', ensure_ascii=False)
