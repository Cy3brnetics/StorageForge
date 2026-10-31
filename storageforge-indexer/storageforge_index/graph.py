"""Storage topology graph: builds, stores and loads Host → StoragePool → Filesystem → MountPoint ← Symlink.

Relationships
    CONTAINS       Host → StoragePool, Host/StoragePool → Filesystem, remote Host → exported Filesystem
    MOUNTED_AT     Filesystem → MountPoint, MountPoint → MountPoint (bind mount)
    SYMLINK_TO     Symlink → MountPoint holding its target (or → Symlink for chained links)
    REPLICATES_TO  Filesystem → Host receiving sync or backup copies

Health (3-2-1 colouring)
    protected   snapshots + validated offsite copy        local-only  single site or stale copy
    broken      broken link, offline target, failed pool   unknown     no protection data
"""
from __future__ import annotations

import datetime as dt
import json
import posixpath
import re
import time

from .analysis import containing_mount, link_health, protection_status, real_mounts, use_pct, resolve
from .remote import is_under

KINDS = ('Host', 'StoragePool', 'Filesystem', 'MountPoint', 'Symlink')
RELS = ('CONTAINS', 'MOUNTED_AT', 'SYMLINK_TO', 'REPLICATES_TO')
RANK = {'unknown': 0, 'protected': 1, 'local-only': 2, 'broken': 3}
FROM_PROTECTION = {'protected': 'protected', 'local-only': 'local-only', 'critical': 'broken', 'excluded': 'unknown'}


def worst(*healths) -> str:
    hs = [h for h in healths if h]
    return max(hs, key=RANK.get) if hs else 'unknown'


def _remote_host(endpoint: str) -> str:
    e = endpoint or ''
    if e.startswith('//'):
        return e[2:].split('/')[0]
    if ':' in e:
        return e.split(':')[0]
    return e.split('/')[0]


def _target_name(text: str) -> str | None:
    """'syncoid → nas-02/media' → 'nas-02'; 'restic → B2' → 'B2'; 'rsync → office-nas' → 'office-nas'."""
    if not text:
        return None
    pieces = re.split(r'→|->', text)
    part = pieces[-1].strip()
    if len(pieces) == 1:
        part = part.split()[0] if part.split() else ''      # 'nas-02 nightly 02:30' → 'nas-02'
    return part.split('/')[0].strip() or None


def build(node: dict, as_of: dt.date | None = None) -> tuple[dict, list]:
    as_of = as_of or dt.date.today()
    h = node['hostname']
    N: dict[str, dict] = {}
    E: list[dict] = []

    def add(nid, kind, label, health='unknown', host=h, **props):
        if nid not in N:
            N[nid] = {'id': nid, 'kind': kind, 'label': label, 'host': host, 'health': health,
                      'props': {k: v for k, v in props.items() if v not in (None, '', [], {})}}
        else:
            N[nid]['health'] = worst(N[nid]['health'], health)
        return N[nid]

    def edge(src, dst, rel, **props):
        if src in N and dst in N and src != dst:
            E.append({'src': src, 'dst': dst, 'rel': rel, 'props': {k: v for k, v in props.items() if v is not None}})

    for l in node['links']:
        if 'state' not in l:
            l['state'], l['note'] = link_health(l, node)

    host_id = f'host:{h}'
    add(host_id, 'Host', h, ip=node.get('ip'), os=node.get('os'), node_id=node.get('node_id'),
        last_scanned=node.get('last_scanned'))

    externals: dict[str, str] = {}

    peers = node.get('peers') or {}          # ip or name → hostname of another scanned host

    def external(name, status=None, **props):
        key = name.lower()
        peer = peers.get(key)
        if peer and peer != h:                # an NFS/SMB server we also scan: point at its real Host node
            return add(f'host:{peer}', 'Host', peer, host=peer)['id']
        for known, nid in externals.items():
            if known == key or known.startswith(key + '.') or key.startswith(known + '.'):
                return nid
        nid = f'host:{name}'
        add(nid, 'Host', name, health='broken' if status not in (None, 'connected') else 'unknown', host=None,
            external=True, **props)
        externals[key] = nid
        return nid

    peer_mounts, peer_shares = node.get('peer_mounts') or {}, node.get('peer_shares') or {}

    def share_source(src: str):
        """'10.42.0.10:/srv/media/tv' or '//nas/media/tv' → the server's mount point node holding that folder."""
        peer = peers.get(_remote_host(src).lower())
        if not peer or peer == h or not peer_mounts.get(peer):
            return None
        shares = peer_shares.get(peer) or []
        if src.startswith('//'):
            name, _, sub = src[2:].partition('/')[2].partition('/')
            share = next((x for x in shares if x['protocol'] == 'SMB' and x['name'].lower() == name.lower()), None)
            if not share:
                return None
            path = posixpath.join(share['path'], sub) if sub else share['path']
            label = f'SMB [{share["name"]}] {share["path"]}'
        else:
            path = src.partition(':')[2] or '/'
            share = max((x for x in shares if x['protocol'] == 'NFS' and is_under(path, x['path'])),
                        key=lambda x: len(x['path']), default=None)
            label = f'NFS {share["path"]}' if share else f'NFS {path}'
        target = max((m for m in peer_mounts[peer] if is_under(path, m)), key=len, default=None)
        if not target:
            return None
        smid = add(f'mnt:{peer}:{target}', 'MountPoint', target, host=peer)['id']   # stub: the server's build owns it
        return smid, {'share': label, 'server': peer, 'path': path}

    for r in node['remotes']:
        if r.get('endpoint'):
            external(_remote_host(r['endpoint']), r.get('status'), via=r.get('via'), protocol=r.get('proto'))

    prot = {r['path']: r for r in node['protection'] if r.get('path')}
    remote_by_mount = {r.get('mount'): r for r in node['remotes']}

    def mount_health(m):
        r = prot.get(m['target'])
        if r:
            return FROM_PROTECTION[protection_status(r, as_of)[0]]
        rm = remote_by_mount.get(m['target'])
        if rm and rm.get('status') not in (None, 'connected'):
            return 'broken'
        return 'unknown'

    pools = {p['name']: p for p in node['pools']}
    pool_dev = {a: p['name'] for p in node['pools'] for a in (p['name'], *p.get('aliases', ()))}   # LVM: mapper/vg-lv
    member_pool = {m: p['name'] for p in node['pools'] for m in p['members']}
    for p in node['pools']:
        c = p.get('cap') or {}
        failed = p.get('health') not in (None, 'ONLINE')
        add(f'pool:{h}:{p["name"]}', 'StoragePool', f'{p["vg"]}/{p["lv"]}' if p.get('lv') else p['name'], 'broken' if failed else 'unknown',
            type=p['type'], level=p.get('level'), layout=c.get('layout'), usable_bytes=c.get('usable'),
            raw_bytes=c.get('raw'), tolerance=c.get('tolerance'), members=p['members'], log=p.get('log'),
            cache=p.get('cache'), state=p.get('health'), scan=p.get('scan'), device_errors=p.get('device_errors'),
            encryption=p.get('encryption'), volume=f'{p["vg"]}/{p["lv"]}' if p.get('lv') else None,
            volumes=[ds['name'] for ds in p['datasets']] if p['type'] == 'lvm' and not p.get('lv') else None,
            level_source=p.get('level_source'))
        edge(host_id, f'pool:{h}:{p["name"]}', 'CONTAINS')

    fs_of_mount: dict[str, str] = {}
    mounts = real_mounts(node)
    for m in sorted(mounts, key=lambda m: m['target']):
        if m.get('kind') == 'bind':
            continue
        src = m.get('source') or m.get('spec') or m['target']
        kind = m.get('kind')
        key = src if kind != 'subvol' else src
        fid = f'fs:{h}:{key}'
        if kind == 'remote':
            parent = external(_remote_host(src))
        elif kind == 'zfs' and src.split('/')[0] in pools:
            parent = f'pool:{h}:{src.split("/")[0]}'
        elif src.removeprefix('/dev/') in pool_dev:
            parent = f'pool:{h}:{pool_dev[src.removeprefix("/dev/")]}'
        elif src.removeprefix('/dev/') in member_pool:
            parent = f'pool:{h}:{member_pool[src.removeprefix("/dev/")]}'
        else:
            parent = host_id
        add(fid, 'Filesystem', f'{m.get("fstype") or "?"} · {src}', host=h, fstype=m.get('fstype'), source=src,
            remote=kind == 'remote' or None)
        edge(parent, fid, 'CONTAINS')
        mid = f'mnt:{h}:{m["target"]}'
        health = mount_health(m)
        sub = next((o.split('=', 1)[1] for o in m.get('options') or [] if o.startswith('subvol=')), None)
        add(mid, 'MountPoint', m['target'], health, fstype=m.get('fstype'), options=[o for o in m.get('options') or [] if o],
            total_bytes=m.get('total'), used_bytes=m.get('used'), use_pct=round(use_pct(m), 1) if use_pct(m) is not None else None,
            spec=m.get('spec'), tier=m.get('tier'))
        N[fid]['health'] = worst(N[fid]['health'], health)
        edge(fid, mid, 'MOUNTED_AT', subvol=sub)
        if kind == 'remote':                  # an NFS/SMB mount from a host we also scan: line from its real folder
            src_mount = share_source(src)
            if src_mount:
                smid, props = src_mount
                edge(smid, mid, 'MOUNTED_AT', remote=True, **props)
        fs_of_mount[m['target']] = fid

    for m in mounts:
        if m.get('kind') != 'bind':
            continue
        link = next((l for l in node['links'] if l['kind'] == 'bind' and l['path'] == m['target']), {})
        health = {'crit': 'broken', 'warn': 'local-only'}.get(link.get('state'), 'unknown')
        mid = f'mnt:{h}:{m["target"]}'
        add(mid, 'MountPoint', m['target'], health, bind=True, source=m.get('spec') or m.get('source'),
            note=link.get('note'))
        src = containing_mount(m.get('spec') or m.get('source') or '', mounts)
        if src:
            edge(f'mnt:{h}:{src["target"]}', mid, 'MOUNTED_AT', bind=True, source=m.get('spec'))

    file_links = [l for l in node['links'] if l['kind'] in ('symlink', 'hardlink')]
    link_paths = {l['path'] for l in file_links}
    for l in file_links:                                     # all nodes first, so chained links can point at each other
        tm = containing_mount(l.get('resolved') or resolve(l['path'], l['target']), mounts)
        tmid = f'mnt:{h}:{tm["target"]}' if tm else None
        health = {'crit': 'broken', 'warn': 'local-only'}.get(l.get('state')) or (N.get(tmid, {}).get('health', 'unknown'))
        add(f'link:{h}:{l["path"]}', 'Symlink', l['path'], health, target=l['target'], link_kind=l['kind'], note=l.get('note'))
    for l in file_links:
        lid = f'link:{h}:{l["path"]}'
        target_abs = resolve(l['path'], l['target'])
        tm = containing_mount(l.get('resolved') or target_abs, mounts)
        tmid = f'mnt:{h}:{tm["target"]}' if tm else None
        if target_abs in link_paths:
            edge(lid, f'link:{h}:{target_abs}', 'SYMLINK_TO', target=l['target'])
        elif tmid:
            edge(lid, tmid, 'SYMLINK_TO', target=l['target'])

    for r in node['protection']:
        fid = fs_of_mount.get(r.get('path'))
        if not fid:
            continue
        sync, bk = r.get('sync') or {}, r.get('backup') or {}
        if sync.get('state') not in (None, 'None') and _target_name(sync.get('target')):
            state = sync['state']
            edge(fid, external(_target_name(sync['target'])), 'REPLICATES_TO', mode='sync', state=state,
                 detail=sync.get('target'), lag=sync.get('lag'),
                 health={'Active Sync': 'protected', 'Rsync Scheduled': 'protected', 'Lagging': 'local-only'}.get(state, 'broken'))
        if bk.get('target') and _target_name(bk['target']):
            age = (as_of - dt.date.fromisoformat(bk['last'][:10])).days if bk.get('last') else None
            edge(fid, external(_target_name(bk['target'])), 'REPLICATES_TO', mode='backup', detail=bk['target'],
                 offsite=bk.get('offsite'), validated=bk.get('last'), encryption=bk.get('enc'),
                 health='broken' if age is None or age > 90 else 'local-only' if age > 30 or not bk.get('offsite') else 'protected')

    for j in node.get('jobs') or []:          # deployed mirror/rsnapshot jobs count as backups, as fresh as their last good run
        at = max((m for m in fs_of_mount if j['src'] == m or j['src'].startswith(m.rstrip('/') + '/')), key=len, default=None)
        if not at:
            continue
        same = j['runner'] == h
        health = {'ok': 'local-only' if same else 'protected', 'stale': 'local-only', 'paused': 'local-only',
                  'failed': 'broken', 'never-ran': 'unknown'}.get(j['state'], 'unknown')
        edge(fs_of_mount[at], host_id if same else external(j['runner']), 'REPLICATES_TO', mode=j['method'],
             detail=f'job {j["id"]}: {j["runner"]}:{j["dst"]}', state=j['state'], validated=j.get('validated'), health=health)

    scanned_shares = [f'{e["protocol"]} {e["name"] if e["protocol"] == "SMB" else e["path"]}' for e in node.get('exports') or []
                      if e.get('fromScan')]
    if scanned_shares:
        N[host_id]['props']['shares'] = scanned_shares
        N[host_id]['props']['serves'] = ' + '.join(sorted({s.split()[0] for s in scanned_shares}))

    # roll health up: pools from their filesystems, the host from everything it holds
    for p in node['pools']:
        pid = f'pool:{h}:{p["name"]}'
        kids = [N[e['dst']]['health'] for e in E if e['src'] == pid]
        N[pid]['health'] = worst(N[pid]['health'], *kids)
    N[host_id]['health'] = worst(*(n['health'] for n in N.values() if n['host'] == h and n['id'] != host_id))
    seen, unique = set(), []
    for e in E:
        k = (e['src'], e['dst'], e['rel'])
        if k not in seen:
            seen.add(k)
            unique.append(e)
    return N, unique


def save(db, conn, hostname: str, nodes: dict, edges: list):
    now = int(time.time())
    with conn.tx():
        # Replace the edges this build made, then its stale nodes. Nodes are updated in place, never deleted and
        # re-added: other hosts' edges point at them (an NFS client's mount at this server's folder, a backup at
        # this Host) and the cascade would drop those. Edges from before built_by existed fall back to the old rule.
        conn.execute("""DELETE FROM graph_edges WHERE built_by = :h OR (built_by IS NULL AND (
                            src IN (SELECT node_id FROM graph_nodes WHERE host = :h AND kind <> 'Host')
                            OR dst IN (SELECT node_id FROM graph_nodes WHERE host = :h AND kind <> 'Host')))""", {'h': hostname})
        keep = [n['id'] for n in nodes.values() if n['host'] == hostname]
        for stale in {r[0] for r in conn.all('SELECT node_id FROM graph_nodes WHERE host = :h', {'h': hostname})} - set(keep):
            conn.execute('DELETE FROM graph_nodes WHERE node_id = :id', {'id': stale})
        for n in nodes.values():
            if n['host'] not in (None, hostname):      # another scanned host's node: its own build owns it
                continue
            conn.execute("""INSERT INTO graph_nodes (node_id, kind, label, host, health, props_json, updated_at)
                            VALUES (:id, :k, :l, :h, :he, :p, :now)
                            ON CONFLICT (node_id) DO UPDATE SET kind = excluded.kind, label = excluded.label, host = excluded.host,
                                health = excluded.health,
                                props_json = excluded.props_json, updated_at = excluded.updated_at""",
                         {'id': n['id'], 'k': n['kind'], 'l': n['label'], 'h': n['host'], 'he': n['health'],
                          'p': json.dumps(n['props'], default=str), 'now': now})
        for e in edges:
            conn.execute("""INSERT INTO graph_edges (src, dst, rel, props_json, built_by) VALUES (:s, :d, :r, :p, :h)
                            ON CONFLICT (src, dst, rel) DO UPDATE SET props_json = excluded.props_json, built_by = excluded.built_by""",
                         {'s': e['src'], 'd': e['dst'], 'r': e['rel'], 'p': json.dumps(e['props'], default=str), 'h': hostname})
        conn.execute("""DELETE FROM graph_nodes WHERE host IS NULL AND node_id NOT IN
                        (SELECT src FROM graph_edges UNION SELECT dst FROM graph_edges)""")


def load(conn, host: str | None = None) -> dict:
    nodes = [{'id': r[0], 'kind': r[1], 'label': r[2], 'host': r[3], 'health': r[4], 'props': json.loads(r[5] or '{}')}
             for r in conn.all('SELECT node_id, kind, label, host, health, props_json FROM graph_nodes ORDER BY node_id')]
    edges = [{'src': r[0], 'dst': r[1], 'rel': r[2], 'props': json.loads(r[3] or '{}')}
             for r in conn.all('SELECT src, dst, rel, props_json FROM graph_edges ORDER BY src, dst, rel')]
    if host:
        keep = {n['id'] for n in nodes if n['host'] == host}
        keep |= {e['dst'] for e in edges if e['src'] in keep} | {e['src'] for e in edges if e['dst'] in keep}
        nodes = [n for n in nodes if n['id'] in keep]
        edges = [e for e in edges if e['src'] in keep and e['dst'] in keep]
    return {'nodes': nodes, 'edges': edges}


def stored_blueprint(conn, hostname: str):
    rows = conn.all('SELECT body_json FROM blueprints WHERE hostname = :h OR :h LIKE hostname || :dot',
                    {'h': hostname, 'dot': '.%'})
    return json.loads(rows[0][0]) if rows else None


def store_blueprint(conn, bp: dict) -> str:
    host = (bp.get('metadata') or {}).get('host')
    if not host:
        raise ValueError('blueprint has no metadata.host')
    conn.execute("""INSERT INTO blueprints (hostname, body_json, imported_at) VALUES (:h, :b, :t)
                    ON CONFLICT (hostname) DO UPDATE SET body_json = excluded.body_json, imported_at = excluded.imported_at""",
                 {'h': host, 'b': json.dumps(bp), 't': int(time.time())})
    return host


def rebuild_host(db, conn, hostname: str, rebuild_clients: bool = True) -> tuple[int, int]:
    """Rebuild one scanned host's graph from the index, overlaid with its stored blueprint."""
    from .payloads import merge_blueprint, node_from_blueprint, node_from_index, shares_from_inventory
    node = node_from_index(conn, hostname, stats=False)
    node['peers'] = {k.lower(): name for name, ip in conn.all('SELECT hostname, ip_address FROM hosts')
                     for k in (name, name.split('.')[0], ip) if k}
    node['peer_mounts'] = {}                  # other hosts' mount points already in the graph: share targets
    for host, label in conn.all("SELECT host, label FROM graph_nodes WHERE kind = 'MountPoint' AND host IS NOT NULL"):
        node['peer_mounts'].setdefault(host, []).append(label)
    node['peer_shares'] = {}
    for host, inv in conn.all('SELECT hostname, inventory_json FROM hosts'):
        inv = inv if isinstance(inv, dict) else json.loads(inv or '{}')
        node['peer_shares'][host] = shares_from_inventory(inv or {})
    bp = stored_blueprint(conn, hostname)
    if bp:
        merge_blueprint(node, node_from_blueprint(bp))
    try:
        from .jobs import overview
        node['jobs'] = [{'id': j['id'], 'src': j['src'] or '', 'dst': j['dst'], 'runner': j['runner'], 'method': j['method'],
                         'state': j['state'], 'validated': dt.date.fromtimestamp(j['last_ok']['end']).isoformat()
                         if j['last_ok'] and j['last_ok'].get('end') else None}
                        for j in overview(conn) if j['source'] == node['hostname'] and j['method'] in ('mirror', 'rsnapshot')]
    except Exception:                         # an older schema (no jobs table yet) or no jobs: nothing to add
        node['jobs'] = []
    nodes, edges = build(node)
    save(db, conn, node['hostname'], nodes, edges)
    if rebuild_clients:   # hosts that mount from this one draw their line to its folders: redraw them too
        clients = {r[0] for r in conn.all("""SELECT DISTINCT n.host FROM graph_edges e JOIN graph_nodes n ON n.node_id = e.dst
                                             WHERE e.src = :h AND n.host IS NOT NULL AND n.host <> :name""",
                                          {'h': f'host:{node["hostname"]}', 'name': node['hostname']})}
        for c in sorted(clients):
            rebuild_host(db, conn, c, rebuild_clients=False)
    return len(nodes), len(edges)
