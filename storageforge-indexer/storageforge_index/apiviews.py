"""What the platform API connections read, fed to the views StorageForge already has: the map, the Workloads list, the notification
center (apiread.problems), and a comparison with the SSH scan.

Compared, not merged: where the SSH scan of a host already reads the same thing (Proxmox guests, through qm and pct), the two are put
side by side and every field they disagree on is said. Neither replaces the other. A guest only the API sees (on a cluster node that is
not scanned, or one the scan could not read) is listed and drawn with source "api"; one only the scan sees is marked as not seen by the
API, which may mean the token cannot see it.

Nothing here is stored: it is worked out from platform_objects and the scans when a view asks, as manual map nodes are.
"""
from __future__ import annotations

from . import apiread, inframeasure
from .db import Conn

PROXMOX = ('pve', 'pbs', 'pdm')


def _hosts(conn: Conn) -> dict:
    out = {}
    for (name,) in conn.all('SELECT hostname FROM hosts'):
        out[name.lower()] = name
        out.setdefault(name.split('.')[0].lower(), name)
    return out


def host_of_node(hosts: dict, conn_row: dict, node: str | None, nodes: int) -> str | None:
    """The scanned host a platform's node is: by name, or the connection's own host when the platform has one node."""
    if node and node.lower() in hosts:
        return hosts[node.lower()]
    if nodes == 1 and conn_row.get('host'):
        return conn_row['host']
    return None


def _mib(b):
    return round(b / 1048576) if isinstance(b, int) else None


def guests(conn: Conn) -> list[dict]:
    """Every guest any connection reads (a PVE cluster, or PVE remotes through PDM), with the scanned host it runs on when known."""
    from . import apiconn
    hosts = _hosts(conn)
    rows = {r['conn_id']: r for r in apiconn.listing(conn)}
    objs = apiread.objects(conn)
    nodes_of: dict = {}
    for o in objs:
        if o['kind'] == 'node':
            nodes_of.setdefault((o['conn_id'], o.get('remote')), set()).add(o.get('node'))
    out = []
    for o in sorted(objs, key=lambda o: o.get('remote') is None):      # through PDM first, so a direct connection's reading comes last and wins
        if o['kind'] != 'guest':
            continue
        r = rows[o['conn_id']]
        n = len(nodes_of.get((o['conn_id'], o.get('remote')), ())) if not o.get('remote') else 0
        out.append({**o, 'on_host': host_of_node(hosts, r, o.get('node'), n), 'title': r['title']})
    return out


def compare(conn: Conn) -> list[dict]:
    """For each host the SSH scan read Proxmox guests on and an API connection reads too: each guest, from both sides, and what differs."""
    api_by_host: dict = {}
    for g in guests(conn):
        if g.get('on_host'):
            api_by_host.setdefault(g['on_host'], {})[str(g.get('vmid'))] = g
    out = []
    for host, api in sorted(api_by_host.items()):
        m = inframeasure.reading(conn, host) or {}
        ssh = {str(x.get('vmid')): x for x in m.get('proxmox') or []}
        if not m:
            out.append({'host': host, 'scanned': False, 'guests': [{'vmid': k, 'name': v.get('name'), 'seen_by': ['api'], 'differs': []} for k, v in sorted(api.items())]})
            continue
        rows = []
        for vmid in sorted(set(api) | set(ssh), key=lambda x: (len(x), x)):
            a, s = api.get(vmid), ssh.get(vmid)
            if a and s:
                differs = []
                if (a.get('name') or '') != (s.get('name') or ''):
                    differs.append({'field': 'name', 'api': a.get('name'), 'ssh': s.get('name')})
                if (a.get('status') or '') != (s.get('state') or ''):
                    differs.append({'field': 'state', 'api': a.get('status'), 'ssh': s.get('state')})
                if s.get('memory_mib') and _mib(a.get('maxmem')) and abs(_mib(a['maxmem']) - s['memory_mib']) > 1:
                    differs.append({'field': 'memory_mib', 'api': _mib(a['maxmem']), 'ssh': s['memory_mib']})
                kind = 'lxc' if a.get('type') == 'lxc' else 'qemu'
                if s.get('kind') and s['kind'] != kind:
                    differs.append({'field': 'type', 'api': kind, 'ssh': s['kind']})
                rows.append({'vmid': vmid, 'name': a.get('name') or s.get('name'), 'seen_by': ['api', 'ssh'], 'differs': differs, 'connection': a['connection']})
            elif a:
                rows.append({'vmid': vmid, 'name': a.get('name'), 'seen_by': ['api'], 'differs': [], 'connection': a['connection'],
                             'why': 'the SSH scan of this host did not list it'})
            else:
                rows.append({'vmid': vmid, 'name': s.get('name'), 'seen_by': ['ssh'], 'differs': [],
                             'why': 'the API did not list it: the token may not see it, or the guest is new since the last read'})
        out.append({'host': host, 'scanned': True, 'measured_at': m.get('measured_at'), 'guests': rows})
    return out


def annotate_workloads(conn: Conn, listing: dict, host: str | None = None) -> dict:
    """The Workloads list with the API beside the scan: a Proxmox guest the scan lists gets an `api` field saying what the API reads and
    where they differ; a guest only the API reads is added with source "api"."""
    cmp = {(c['host'], g['vmid']): g for c in compare(conn) for g in c['guests']}
    api = {(g['on_host'], str(g.get('vmid'))): g for g in guests(conn) if g.get('on_host')}
    listed = set()
    for w in listing.get('workloads') or []:
        if w.get('runtime') != 'proxmox':
            continue
        key = (w['host'], str(w.get('vmid')))
        listed.add(key)
        if key in api:
            a = api[key]
            w['api'] = {'connection': a['connection'], 'status': a.get('status'), 'node': a.get('node'), 'differs': (cmp.get(key) or {}).get('differs', [])}
        elif key in cmp:
            w['api'] = {'seen': False, 'why': cmp[key].get('why')}
    added = {}
    for g in guests(conn):
        key = (g.get('on_host') or g.get('node'), str(g.get('vmid')))
        if key in added:                    # the same guest through PDM and directly: the direct reading, which comes last
            listing['workloads'].remove(added.pop(key))
        if key in listed or (host and (g.get('on_host') or '').lower() != host.lower()):
            continue
        listing.setdefault('workloads', []).append({
            'host': g.get('on_host') or g.get('node'), 'runtime': 'proxmox', 'kind': 'instance' if g.get('type') == 'lxc' else 'vm', 'name': g.get('name') or str(g.get('vmid')),
            'vmid': g.get('vmid'), 'state': g.get('status'), 'memory_mib': _mib(g.get('maxmem')), 'vcpus': g.get('maxcpu'), 'mounts': [], 'networks': [], 'ports': [],
            'detail': False, 'managed_by': 'proxmox', 'source': 'api', 'security': None, 'findings': [],
            'api': {'connection': g['connection'], 'status': g.get('status'), 'node': g.get('node'), 'remote': g.get('remote'), 'differs': []}})
        added[key] = listing['workloads'][-1]
    for pw in platform_workloads(conn, host):          # Xen Orchestra, TrueNAS and the panels: beside the scan's reading, or added
        same = next((w for w in listing.get('workloads') or [] if pw.get('host') and w.get('host') == pw['host'] and w.get('name') == pw.get('name')
                     and w.get('runtime') == pw.get('runtime') and w.get('source') != 'api'), None)
        if same:
            differs = [{'field': 'state', 'api': pw.get('state'), 'ssh': same.get('state')}] if pw.get('state') and same.get('state') and pw['state'] != same['state'] else []
            same['api'] = {**pw['api'], 'state': pw.get('state'), 'stack': pw.get('stack'), 'differs': differs}
            continue
        listing.setdefault('workloads', []).append({
            'host': pw.get('host'), 'runtime': pw.get('runtime'), 'kind': pw.get('kind') or 'container', 'name': pw.get('name'), 'state': pw.get('state'),
            'memory_mib': pw.get('memory_mib'), 'vcpus': pw.get('vcpus'), 'mounts': [], 'networks': [], 'ports': [], 'detail': False,
            'managed_by': pw['api']['platform'], 'source': 'api', 'security': None, 'findings': [], 'api': {**pw['api'], 'stack': pw.get('stack'), 'differs': []}})
    return listing


def map_extra(conn: Conn, g: dict, layers) -> dict:
    """Adds to a map graph what the connections read: guests the scan does not already draw (workloads layer), the platform's storage and
    datastores (storage layer). A guest the scan draws gets the API's reading as a property, not a second node."""
    from . import apiconn
    hosts = _hosts(conn)
    known = {n['id']: n for n in g['nodes']}
    drawn_hosts = {n['label'] for n in g['nodes'] if n['kind'] == 'Host'}

    def add(nid, kind, label, layer, host, **props):
        if nid in known:
            return nid
        n = {'id': nid, 'kind': kind, 'label': label, 'host': host if host in drawn_hosts else None, 'layer': layer, 'confidence': 'certain', 'health': 'unknown',
             'first_seen': None, 'props': {k: v for k, v in {**props, 'source': 'api'}.items() if v not in (None, '', [], {})}}
        g['nodes'].append(n)
        known[nid] = n
        return nid

    def edge(src, dst, rel, why):
        if src in known and dst in known:
            g['edges'].append({'src': src, 'dst': dst, 'rel': rel, 'props': {'confidence': 'certain', 'evidence': {'source': why}}})

    rows = {r['conn_id']: r for r in apiconn.listing(conn)}
    for cid, r in rows.items():
        if not r.get('read_ok') and not r.get('read_at'):
            continue
        pid = add(f'api:{r["name"]}', 'Platform', f'{r["title"]} {r["name"]}', 'workloads', r.get('host'), platform=r['kind'], url=r['base_url'], state=r['state'])
        if r.get('host') and f'host:{r["host"]}' in known:
            edge(pid, f'host:{r["host"]}', 'RUNS_ON', f'{r["title"]} API at {r["base_url"]}')
    if 'workloads' in layers:
        for x in {(x.get('on_host') or x.get('node'), x.get('vmid')): x for x in guests(conn)}.values():     # one node per guest: the direct reading wins
            host = x.get('on_host')
            wl = f'wl:{host}:proxmox::{x.get("name")}' if host else None
            if wl and wl in known:          # the scan draws it: the API's reading goes beside it
                known[wl]['props']['api'] = {'connection': x['connection'], 'status': x.get('status'), 'node': x.get('node')}
                continue
            nid = add(f'api:{x["connection"]}:guest:{x.get("remote") or ""}:{x.get("vmid")}', 'Instance' if x.get('type') == 'lxc' else 'VM', x.get('name') or str(x.get('vmid')),
                      'workloads', host, runtime='proxmox', vmid=x.get('vmid'), state=x.get('status'), node=x.get('node'), remote=x.get('remote'), connection=x['connection'])
            if host and f'host:{host}' in known:
                edge(nid, f'host:{host}', 'RUNS_ON', f'{x["title"]} API: on node {x.get("node")}')
            else:
                edge(nid, f'api:{x["connection"]}', 'MANAGED_BY', f'{x["title"]} API: on node {x.get("node")}, which is not a scanned host')
    for cid, r in rows.items():                 # the platforms beyond Proxmox draw their own objects (map_nodes in each reader)
        mod = apiread.reader(r['kind'])
        if r['kind'] in PROXMOX or not hasattr(mod, 'map_nodes') or (not r.get('read_ok') and not r.get('read_at')):
            continue
        for n in mod.map_nodes(conn, r, apiread.objects(conn, cid), hosts, layers):
            if n.get('attach') in known:     # the scan draws it already: the API's reading goes beside it, not a second node
                known[n['attach']]['props']['api'] = {**n.get('props', {}), 'connection': r['name']}
                continue
            nid = add(n['id'], n['kind'], n['label'], n['layer'], n.get('host'), **n.get('props', {}))
            for dst, rel, why in n.get('edges', []):
                edge(nid, dst, rel, why)
            if not n.get('edges'):
                edge(nid, f'api:{r["name"]}', 'MANAGED_BY', f'{r["title"]} API')
    if 'storage' in layers:
        for o in apiread.objects(conn):
            if o['kind'] not in ('storage', 'datastore') or o['platform'] not in PROXMOX:
                continue
            r = rows[o['conn_id']]
            host = host_of_node(hosts, r, o.get('node'), 1 if o['kind'] == 'datastore' else 0) if not o.get('remote') else None
            label = o.get('storage') or o.get('store') or o['ref']
            used = o.get('disk') if o.get('disk') is not None else o.get('used')
            total = o.get('maxdisk') or o.get('total')
            nid = add(f'api:{o["connection"]}:{o["kind"]}:{o["ref"]}', 'StoragePool', label, 'storage', host, platform=o['platform'], plugintype=o.get('plugintype'),
                      used=used, total=total, shared=o.get('shared'), node=o.get('node'), remote=o.get('remote'), connection=o['connection'])
            edge(nid, f'api:{o["connection"]}', 'MANAGED_BY', f'{r["title"]} API')
            if host and o.get('path'):          # a Backup Server datastore sits on a mount the scan drew
                points = [n['label'] for n in g['nodes'] if n['kind'] == 'MountPoint' and n.get('host') == host and (o['path'] == n['label'] or o['path'].startswith(n['label'].rstrip('/') + '/'))]
                if points:
                    edge(nid, f'mnt:{host}:{max(points, key=len)}', 'STORED_ON', f'{r["title"]} API: datastore path {o["path"]}')
    return g


def compare_connection(conn: Conn, row: dict) -> dict:
    """What this connection reads beside what the SSH scan reads of the same things."""
    out = {'guests': [], 'datastores': []}
    if row['kind'] in ('pve', 'pdm'):
        out['guests'] = [c for c in compare(conn) if any(g.get('connection') == row['name'] for g in c['guests'])]
    if row['kind'] == 'pbs':
        from . import apipbs
        out['datastores'] = apipbs.compare_mounts(conn, row, apiread.objects(conn, row['conn_id']))
    mod = apiread.reader(row['kind'])
    if row['kind'] not in PROXMOX and hasattr(mod, 'compare'):
        out.update(mod.compare(conn, row, apiread.objects(conn, row['conn_id'])))
    return out


def platform_workloads(conn: Conn, host: str | None = None) -> list[dict]:
    """What the platforms beyond Proxmox say runs where (Xen Orchestra's VMs, a panel's containers, TrueNAS apps), each reader's
    workloads(), for the Workloads list: one entry per workload, with the scanned host when one is known."""
    from . import apiconn
    out = []
    for r in apiconn.listing(conn):
        mod = apiread.reader(r['kind'])
        if r['kind'] in PROXMOX or not hasattr(mod, 'workloads'):
            continue
        for w in mod.workloads(conn, r, apiread.objects(conn, r['conn_id'])):
            if host and (w.get('host') or '').lower() != host.lower():
                continue
            out.append({**w, 'api': {**(w.get('api') or {}), 'connection': r['name'], 'platform': r['kind']}})
    return out


def managed_by_host(conn: Conn, host: str | None = None) -> dict:
    """Docker workloads a connected platform manages, indexed by scanned host and workload name."""
    out = {}
    for w in platform_workloads(conn, host):
        if w.get('runtime') in ('docker', 'compose') and w.get('host') and w.get('name'):
            api = w['api']
            out.setdefault(w['host'].lower(), {})[w['name']] = {
                'panel': api['platform'], 'connection': api['connection'],
                'stack': w.get('stack'), 'environment': api.get('environment'),
            }
    return out


def managed_by(conn: Conn, host: str) -> dict:
    """The connected platform managers of Docker workloads on one scanned host."""
    return managed_by_host(conn, host).get(host.lower(), {})
