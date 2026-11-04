"""The layers of the map above storage: networks, services, firewalls and workloads, as nodes and edges in the same graph.

Derived, never drawn: rebuilt from what scans and measurements read. Each node and edge says how it is known:

    certain    read on this host: an interface in a bridge, a listener, a container's mount
    confirmed  across hosts, by address: a default route through an address another scanned host holds
    inferred   a guess worth showing: the same subnet, a neighbour-table entry. Unscanned devices are placeholders, never hosts

Same-subnet is inferred because two sites can both use 192.168.1.0/24. Container bridges make no subnet node for that reason:
every Docker host has a 172.17.0.0/16 and they have nothing to do with each other.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import time

from . import exposure, inframeasure, netfacts, workloads
from .db import Conn, loads

LAYERS = ('storage', 'network', 'services', 'firewall', 'workloads', 'access', 'manual')
# Who made this interface, from the first three bytes of its MAC. Only what a person would recognise; the rest stays unknown.
OUI = {'52:54:00': 'QEMU/KVM', '00:50:56': 'VMware', '00:0c:29': 'VMware', '08:00:27': 'VirtualBox', '02:42:ac': 'Docker', '00:16:3e': 'Xen', 'b8:27:eb': 'Raspberry Pi', 'dc:a6:32': 'Raspberry Pi', 'e4:5f:01': 'Raspberry Pi',
       '00:1a:79': 'Ubiquiti', '24:5a:4c': 'Ubiquiti', '74:83:c2': 'Ubiquiti', 'f0:9f:c2': 'Ubiquiti', '00:11:32': 'Synology', '00:08:9b': 'QNAP', '24:5e:be': 'QNAP', '3c:ec:ef': 'Supermicro', '00:25:90': 'Supermicro', 'ac:1f:6b': 'Supermicro'}
IDENTITY = (('Authelia', r'authelia'), ('Authentik', r'authentik'), ('Keycloak', r'keycloak'), ('LLDAP', r'lldap'), ('Kanidm', r'kanidm'), ('Pomerium', r'pomerium'), ('FreeIPA', r'freeipa'))
KIND = {'bridge': 'Bridge', 'bond': 'Bond', 'vlan': 'VLAN', 'wireguard': 'VPNInterface'}
SKIP_IFACES = ('veth', 'loopback', 'dummy')
MAX_NEIGHBOURS = 100
ALERT_WINDOW = 7 * 86400
KEEP_SNAPSHOTS = 200


def _bridge_name(iface: dict) -> bool:
    return iface['kind'] == 'bridge' and (iface['name'] or '').startswith(('docker', 'br-', 'podman', 'cni', 'virbr', 'lxdbr', 'incusbr'))


def build(host: str, net: dict | None, infra: dict | None, containers: list[dict], loads_workloads: list[dict], peers: dict, mount_nodes: set, wg_keys: dict | None = None, forwards: list | None = None) -> tuple[dict, list]:
    """peers: every other scanned host's addresses, address → name. wg_keys: every scanned host's WireGuard public keys. Pure, so
    it can be tested with no database."""
    wg_keys = wg_keys or {}
    host_id = f'host:{host}'
    nodes: dict[str, dict] = {}
    edges: list[dict] = []

    def add(nid, kind, label, layer, owner=host, confidence='certain', **props):
        if nid not in nodes:
            nodes[nid] = {'id': nid, 'kind': kind, 'label': label, 'host': owner, 'layer': layer, 'confidence': confidence, 'props': {k: v for k, v in props.items() if v not in (None, '', [], {})}}
        return nid

    def edge(src, dst, rel, source, confidence='certain', **props):
        edges.append({'src': src, 'dst': dst, 'rel': rel, 'props': {'evidence': {'host': host, 'source': source}, 'confidence': confidence, **props}})

    names = {}
    for iface in (net or {}).get('interfaces') or []:
        if iface['kind'] in SKIP_IFACES:
            continue
        nid = add(f'nic:{host}:{iface["name"]}', KIND.get(iface['kind'], 'NIC'), iface['name'], 'network', state=iface.get('state'), mac=iface.get('mac'), mtu=iface.get('mtu'),
                  addresses=[f'{a["ip"]}/{a["prefix"]}' for a in iface.get('addresses') or []], vlan_id=iface.get('vlan_id'), container_bridge=_bridge_name(iface) or None)
        names[iface['name']] = nid
    for iface in (net or {}).get('interfaces') or []:
        nid = names.get(iface['name'])
        if not nid:
            continue
        master, parent = names.get(iface.get('master')), names.get(iface.get('parent'))
        if master:
            edge(nid, master, 'MEMBER_OF', f'ip link: {iface["name"]} master {iface["master"]}')
        elif parent:
            edge(nid, parent, 'TAGGED', f'ip link: {iface["name"]} on {iface["parent"]}')
        else:
            edge(nid, host_id, 'ATTACHED_TO', f'ip link: {iface["name"]}')
        if _bridge_name(iface):
            continue
        for a in iface.get('addresses') or []:
            try:
                cidr = ipaddress.ip_interface(f'{a["ip"]}/{a["prefix"]}')
            except (ValueError, TypeError):
                continue
            if cidr.ip.is_loopback or cidr.ip.is_link_local or cidr.network.prefixlen == cidr.network.max_prefixlen:
                continue
            sub = add(f'subnet:{cidr.network}', 'Subnet', str(cidr.network), 'network', owner=None, confidence='inferred')
            edge(nid, sub, 'ON_SUBNET', f'ip addr: {a["ip"]}/{a["prefix"]} on {iface["name"]}', 'inferred')

    def placeholder(ip, kind, how, **props):
        vendor = OUI.get((props.get('mac') or '')[:8].lower())
        if props.get('mac') and not vendor and int(props['mac'][:2], 16) & 2:
            vendor = 'locally administered'
        return add(f'ph:{ip}', kind, ip, 'network', owner=None, confidence='inferred', placeholder=True, seen_as=how, vendor=vendor, **props)

    me = {a['ip'] for i in (net or {}).get('interfaces') or [] for a in i.get('addresses') or []}
    for gw in (net or {}).get('gateways') or []:
        if gw in peers and peers[gw] != host:
            edge(host_id, f'host:{peers[gw]}', 'ROUTES_VIA', f'ip route: default via {gw}', 'confirmed', via=gw)
        elif gw not in me:
            edge(host_id, placeholder(gw, 'Gateway', f'default gateway of {host}'), 'ROUTES_VIA', f'ip route: default via {gw}', 'inferred', via=gw)
    for dns in ((net or {}).get('dns') or {}).get('nameservers') or []:
        if dns in peers and peers[dns] != host:
            edge(host_id, f'host:{peers[dns]}', 'RESOLVES_VIA', f'resolv.conf: nameserver {dns}', 'confirmed')
    seen = 0
    outside = {i['name'] for i in (net or {}).get('interfaces') or [] if i['kind'] not in SKIP_IFACES and not _bridge_name(i) and not i.get('master')}
    for n in (net or {}).get('neighbours') or []:
        if n['dev'] not in outside or n['ip'] in peers or n['ip'] in me or seen >= MAX_NEIGHBOURS:
            continue
        try:
            if ipaddress.ip_address(n['ip']).is_link_local:
                continue
        except ValueError:
            continue
        seen += 1
        edge(host_id, placeholder(n['ip'], 'Neighbour', f'in the neighbour table of {host}', mac=n.get('mac')), 'NEIGHBOUR_OF', f'ip neigh: {n["ip"]} on {n["dev"]}', 'inferred')

    report = exposure.host_report(net, infra, containers, host, forwards)
    for item in report['items']:
        nid = add(f'lsn:{host}:{item["proto"]}:{item["port"]}', 'Listener', f'{item["port"]}/{item["proto"]}', 'services', bind=item.get('addr'), process=item.get('process'), exposure=item['level'], rule=item.get('rule'), why=item.get('why'),
                  container=item.get('container'), bypasses_frontend=item.get('bypasses_frontend'))
        edge(nid, host_id, 'LISTENS_ON', 'ss' if item['kind'] == 'listener' else f'container {item.get("container")} publishes this port')

    fw = (infra or {}).get('firewall')
    if fw:
        nid = add(f'fw:{host}', 'FirewallPolicy', ', '.join(fw.get('backends') or []) or 'no firewall', 'firewall', readable=fw.get('readable'), policies=fw.get('policies'), rules=len(fw.get('rules') or []), notes=fw.get('notes'))
        edge(nid, host_id, 'APPLIES_TO', 'signed reading of the firewall rules')

    for w in loads_workloads:
        kind = {'container': 'Container', 'vm': 'VM', 'instance': 'Instance'}.get(w['kind'], 'Container')
        nid = add(f'wl:{host}:{w["runtime"]}:{w.get("user") or ""}:{w["name"]}', kind, w['name'], 'workloads', runtime=w['runtime'], state=w.get('state'), image=w.get('image'), stack=w.get('stack'), panel=w.get('panel'), findings=w.get('findings'), managed_by=w.get('managed_by'), detail=w.get('detail'))
        edge(nid, host_id, 'RUNS_ON', f'{w["runtime"]} on {host}')
        for point in {(m.get('on') or {}).get('mount') for m in w.get('mounts') or []} - {None}:
            target = f'mnt:{host}:{point}'
            if target in mount_nodes:
                edge(nid, target, 'MOUNTS', f'{w["runtime"]}: stored on {point}')
        for p in w.get('ports') or []:
            target = f'lsn:{host}:{p["proto"]}:{p["host_port"]}'
            if target in nodes:
                edge(nid, target, 'PUBLISHES', f'{w["runtime"]}: {p["host_ip"]}:{p["host_port"]} to {p["port"]}')
        for n in w.get('networks') or []:
            bridge = n.get('source') if w['kind'] != 'container' else next((i['name'] for i in (net or {}).get('interfaces') or [] for a in i.get('addresses') or [] if a['ip'] == n.get('gateway')), None)
            if bridge in names:
                edge(nid, names[bridge], 'ATTACHED_TO', f'{w["runtime"]}: network {bridge}')
    # who is connected to its storage ports, as a measurement counted them: another scanned host is confirmed, anything else a placeholder
    for c in (infra or {}).get('storage_clients') or []:
        ip = c.get('client')
        if not ip or ip in me:
            continue
        via = f'ss: {c["connections"]} connection(s) on port {c["port"]}'
        target = f'host:{peers[ip]}' if ip in peers else placeholder(ip, 'Neighbour', f'a client of {host} on a storage port')
        edge(target, host_id, 'CLIENT_OF', via, 'confirmed' if ip in peers else 'inferred', port=c['port'], connections=c['connections'])

    # the access layer: VPNs, by public key, and what proxies front
    acc = (infra or {}).get('access') or {}
    for wg in acc.get('wireguard') or []:
        vid = add(f'vpn:{host}:{wg["name"]}', 'VPNNetwork', wg['name'], 'access', public_key=wg['public_key'], listen_port=wg.get('listen_port'), peers=len(wg['peers']))
        edge(vid, host_id, 'RUNS_ON', f'wg show {wg["name"]}')
        for peer in wg['peers']:
            allowed = peer.get('allowed_ips') or []
            other = wg_keys.get(peer['public_key'])
            if other and other[0] != host:
                edge(vid, f'vpn:{other[0]}:{other[1]}', 'PEERS_WITH', f'wg show: its peer key is the key of {other[1]} on {other[0]}', 'confirmed', allowed_ips=allowed)
            else:
                pid = add(f'wgpeer:{host}:{wg["name"]}:{peer["public_key"][:16]}', 'Peer', peer['public_key'][:10] + '…', 'access', owner=host, confidence='inferred', placeholder=not other, public_key=peer['public_key'], endpoint=peer.get('endpoint'), allowed_ips=allowed, handshake=peer.get('handshake'))
                edge(vid, pid, 'PEERS_WITH', f'wg show {wg["name"]}: a peer no scanned host holds the key of', 'inferred', allowed_ips=allowed)
    for ts in acc.get('tailscale') or []:
        tid = f'host:{peers[ts["ip"]]}' if ts['ip'] in peers else add(f'tsnode:{ts["ip"]}', 'Peer', ts['name'], 'access', owner=None, confidence='inferred', placeholder=True, ip=ts['ip'], os=ts.get('os'))
        if tid != host_id:
            edge(host_id, tid, 'PEERS_WITH', 'tailscale status', 'confirmed' if ts['ip'] in peers else 'inferred', active=ts.get('active'))
    for r in acc.get('proxy_routes') or []:
        rid = add(f'route:{host}:{r["proxy"]}:{r["site"]}:{r["upstream"]}', 'ProxyRoute', str(r['site'])[:60], 'access', proxy=r['proxy'], upstream=r['upstream'])
        edge(rid, host_id, 'RUNS_ON', f'{r["proxy"]} config')
        m = re.search(r'(?:^|//)([^/:]+):(\d+)', str(r['upstream']))
        if m:
            target = f'lsn:{host}:tcp:{m[2]}' if m[1] in ('localhost', '127.0.0.1', '[::1]') or m[1] in me else None
            if target and target in nodes:
                edge(rid, target, 'FRONTS', f'{r["proxy"]}: {r["site"]} to {r["upstream"]}')
            elif m[1] in peers:
                edge(rid, f'host:{peers[m[1]]}', 'FRONTS', f'{r["proxy"]}: {r["site"]} to {r["upstream"]}', 'confirmed')
    for w in loads_workloads:
        image = w.get('image') or ''
        who = next((name for name, rx in IDENTITY if re.search(rx, image, re.I)), None)
        if who:
            pid = add(f'idp:{host}:{w["name"]}', 'IdentityProvider', who, 'access', container=w['name'])
            edge(pid, host_id, 'RUNS_ON', f'{w["runtime"]}: the image is {image}')
    for unit in acc.get('units') or []:
        who = next((name for name, rx in IDENTITY if re.search(rx, unit, re.I)), None)
        if who:
            pid = add(f'idp:{host}:{unit}', 'IdentityProvider', who, 'access', unit=unit)
            edge(pid, host_id, 'RUNS_ON', f'systemd: {unit} is running')
    return nodes, edges


def _wg_keys(conn: Conn) -> dict:
    out = {}
    for host, raw in conn.all("SELECT host, data_json FROM security_measurements WHERE kind = 'infra'"):
        for wg in ((loads(raw) or {}).get('access') or {}).get('wireguard') or []:
            out[wg['public_key']] = (host, wg['name'])
    return out


def _peers(conn: Conn) -> dict:
    out = {}
    for host_id, name, ip in conn.all('SELECT host_id, hostname, ip_address FROM hosts'):
        if ip:
            out[ip] = name
        raw = conn.scalar('SELECT data_json FROM host_network WHERE host_id = :h', {'h': host_id})
        data = loads(raw) if isinstance(raw, str) else raw
        for i in (data or {}).get('interfaces') or []:
            if i['kind'] in SKIP_IFACES or _bridge_name(i):
                continue
            for a in i.get('addresses') or []:
                try:
                    if not ipaddress.ip_address(a['ip']).is_loopback:
                        out[a['ip']] = name
                except (ValueError, TypeError):
                    pass
    return out


def _fingerprint(nodes: dict, edges: list) -> dict:
    """What counts as a change, per node: not byte counters or timestamps. Neighbours come and go, so they are left out."""
    out = {}
    for n in nodes.values():
        if n['kind'] == 'Neighbour':
            continue
        p = {k: v for k, v in n['props'].items() if k not in ('why', 'seen_as', 'notes')}
        out[n['id']] = hashlib.sha256(json.dumps([n['label'], p], sort_keys=True, default=str).encode()).hexdigest()[:16]
    return out


def diff(old: dict, new: dict) -> dict:
    return {'added': sorted(set(new) - set(old)), 'removed': sorted(set(old) - set(new)), 'changed': sorted(k for k in set(old) & set(new) if old[k] != new[k])}


def _snapshot(conn: Conn, host: str, nodes: dict, edges: list, now: int) -> dict | None:
    keys = _fingerprint(nodes, edges)
    digest = hashlib.sha256(json.dumps(keys, sort_keys=True).encode()).hexdigest()
    rows = conn.all('SELECT graph_hash, keys_json FROM graph_snapshots WHERE host = :h ORDER BY taken_at DESC, id DESC LIMIT 1', {'h': host})
    if rows and rows[0][0] == digest:
        return None
    change = diff(loads(rows[0][1]) or {}, keys) if rows else {'added': [], 'removed': [], 'changed': [], 'first': True}
    conn.execute('INSERT INTO graph_snapshots (host, taken_at, graph_hash, keys_json, diff_json, graph_json) VALUES (:h, :t, :g, :k, :d, :j)',
                 {'h': host, 't': now, 'g': digest, 'k': json.dumps(keys), 'd': json.dumps(change), 'j': json.dumps({'nodes': list(nodes.values()), 'edges': edges}, default=str)})
    # the timeline keeps this many of each host's changes. The newest is always kept, because it is what the next diff compares with
    conn.execute("""DELETE FROM graph_snapshots WHERE host = :h AND id NOT IN
                      (SELECT id FROM graph_snapshots WHERE host = :h ORDER BY taken_at DESC, id DESC LIMIT :n)""", {'h': host, 'n': KEEP_SNAPSHOTS})
    return change


def rebuild(conn: Conn, host: str) -> tuple[int, int]:
    """Replaces this host's nodes above the storage layer. An unknown edge target is dropped rather than invented."""
    now = int(time.time())
    net, infra = netfacts.reading(conn, host), inframeasure.reading(conn, host)
    listed = workloads.listing(conn, host)['workloads']
    mount_nodes = {r[0] for r in conn.all("SELECT node_id FROM graph_nodes WHERE host = :h AND kind = 'MountPoint'", {'h': host})}
    from .netdevice import forwards
    nodes, edges = build(host, net, infra, workloads.containers_of(conn, host), listed, _peers(conn), mount_nodes, _wg_keys(conn), forwards(conn))
    built_by = f'infra:{host}'
    with conn.tx():
        conn.execute('DELETE FROM graph_edges WHERE built_by = :b', {'b': built_by})
        for stale in {r[0] for r in conn.all("SELECT node_id FROM graph_nodes WHERE host = :h AND layer <> 'storage'", {'h': host})} - set(nodes):
            conn.execute('DELETE FROM graph_nodes WHERE node_id = :id', {'id': stale})
        for n in nodes.values():
            conn.execute("""INSERT INTO graph_nodes (node_id, kind, label, host, props_json, updated_at, layer, confidence, first_seen)
                            VALUES (:id, :k, :l, :h, :p, :t, :y, :c, :t)
                            ON CONFLICT (node_id) DO UPDATE SET kind = excluded.kind, label = excluded.label, props_json = excluded.props_json,
                                updated_at = excluded.updated_at, layer = excluded.layer, confidence = excluded.confidence""",
                         {'id': n['id'], 'k': n['kind'], 'l': n['label'], 'h': n['host'], 'p': json.dumps(n['props'], default=str), 't': now, 'y': n['layer'], 'c': n['confidence']})
        known = {r[0] for r in conn.all('SELECT node_id FROM graph_nodes')}
        kept = 0
        for e in edges:
            if e['src'] in known and e['dst'] in known:
                conn.execute("""INSERT INTO graph_edges (src, dst, rel, props_json, built_by) VALUES (:s, :d, :r, :p, :b)
                                ON CONFLICT (src, dst, rel) DO UPDATE SET props_json = excluded.props_json, built_by = excluded.built_by""",
                             {'s': e['src'], 'd': e['dst'], 'r': e['rel'], 'p': json.dumps(e['props'], default=str), 'b': built_by})
                kept += 1
        conn.execute("""DELETE FROM graph_nodes WHERE host IS NULL AND layer <> 'storage' AND node_id NOT IN (SELECT src FROM graph_edges UNION SELECT dst FROM graph_edges)""")
        _snapshot(conn, host, nodes, edges, now)
    return len(nodes), kept


def timeline(conn: Conn, host: str | None = None, limit: int = 100) -> list[dict]:
    rows = conn.all(f"""SELECT id, host, taken_at, diff_json FROM graph_snapshots {'WHERE lower(host) = lower(:h)' if host else ''} ORDER BY taken_at DESC, id DESC LIMIT :n""", {'h': host, 'n': limit})
    return [{'id': r[0], 'host': r[1], 'taken_at': r[2], **(loads(r[3]) or {})} for r in rows]


def problems(conn: Conn) -> dict:
    """A listener that appeared recently and can be reached from outside this machine. It stops being news after a week."""
    out = {}
    since = int(time.time()) - ALERT_WINDOW
    first = {}
    for host, diff_json, at in conn.all('SELECT host, diff_json, taken_at FROM graph_snapshots WHERE taken_at >= :t', {'t': since}):
        for nid in (loads(diff_json) or {}).get('added') or []:
            if nid.startswith('lsn:'):
                first[nid] = (host, at)
    if not first:
        return out
    for nid, label, raw in conn.all("SELECT node_id, label, props_json FROM graph_nodes WHERE kind = 'Listener'"):
        if nid not in first:
            continue
        level = (loads(raw) or {}).get('exposure')
        if level in ('any', 'lan', 'vpn', 'unknown'):
            host = first[nid][0]
            out[f'map-listener:{host}:{label}'] = ('map-listener', host, f'New listener on {host}: {label}', f'Who can reach it, per configuration: {level}.', 'crit' if level == 'any' else 'warn')
    return out


def mount_badges(conn: Conn) -> dict:
    """(host, mount) → holds and decoys under it, with the soonest expiry, for the topology and the map."""
    from . import security
    out: dict = {}
    mounts = {}
    for host, point in conn.all("""SELECT h.hostname, m.mount_point FROM mounts m JOIN hosts h ON h.host_id = m.host_id WHERE m.scan_state <> 'gone'"""):
        mounts.setdefault(host, []).append(point)
    for host, points in mounts.items():
        from .workloads import sits_on
        pairs = [(p, '') for p in points]
        for h in security.hold_rows(conn, host):
            if h['status'] == 'released':
                continue
            path = h['snapshot'] if h['snapshot'].startswith('/') else '/' + h['snapshot'].split('@')[0]
            on = (sits_on(pairs, path) or {}).get('mount')
            if on:
                b = out.setdefault(host, {}).setdefault(on, {'holds': 0, 'decoys': 0, 'expires_at': None, 'missing': 0})
                b['holds'] += 1
                b['missing'] += 1 if h['missing_at'] else 0
                if h['expires_at'] and not h['legal_hold'] and (b['expires_at'] is None or h['expires_at'] < b['expires_at']):
                    b['expires_at'] = h['expires_at']
        for (path, status) in conn.all('SELECT path, status FROM security_canaries WHERE lower(host) = lower(:h)', {'h': host}):
            on = (sits_on(pairs, path) or {}).get('mount')
            if on:
                b = out.setdefault(host, {}).setdefault(on, {'holds': 0, 'decoys': 0, 'expires_at': None, 'missing': 0})
                b['decoys'] += 1
                if status == 'tripped':
                    b['tripped'] = b.get('tripped', 0) + 1
    return out


def security_badges(conn: Conn) -> dict:
    """host → what Security already measured, for the map. Only what was read: an unread host has no badges, not good ones."""
    from . import security
    out: dict = {}

    def bump(host, key):
        out.setdefault(host, {})
        out[host][key] = out[host].get(key, 0) + 1

    for (host,) in conn.all('SELECT host FROM security_canaries'):
        bump(host, 'decoys')
    for (host,) in conn.all("SELECT host FROM security_retention_holds WHERE status <> 'released'"):
        bump(host, 'holds')
    for (host,) in conn.all('SELECT host FROM security_quarantine'):
        bump(host, 'quarantined')
    for (name,) in conn.all('SELECT hostname FROM hosts'):
        m = security.measurement(conn, name)
        if m:
            out.setdefault(name, {}).update({'selinux': m.get('selinux'), 'apparmor': m.get('apparmor'), 'measured_at': m['measured_at'], 'stale': m['stale']})
    return out


# ── going back in time ───────────────────────────────────────────────
def at_time(conn: Conn, when: int, host: str | None = None) -> dict:
    """Each host's layers above storage as they stood at that time. Storage is not kept, so asking this shows the layers only."""
    nodes: dict = {}
    edges: list = []
    hosts = [r[0] for r in conn.all('SELECT DISTINCT host FROM graph_snapshots')]
    for name in hosts:
        if host and name.lower() != host.lower():
            continue
        raw = conn.scalar('SELECT graph_json FROM graph_snapshots WHERE host = :h AND taken_at <= :t ORDER BY taken_at DESC, id DESC LIMIT 1', {'h': name, 't': when})
        got = loads(raw) if raw else None
        if not got:
            continue
        nodes.setdefault(f'host:{name}', {'id': f'host:{name}', 'kind': 'Host', 'label': name, 'host': name, 'layer': 'storage', 'confidence': 'certain', 'props': {}, 'health': 'unknown', 'first_seen': None})
        for n in got.get('nodes') or []:
            nodes[n['id']] = {'health': 'unknown', 'first_seen': None, **n}
        edges += got.get('edges') or []
    known = set(nodes)
    return {'nodes': list(nodes.values()), 'edges': [e for e in edges if e['src'] in known and e['dst'] in known], 'at': when}


def history_of(conn: Conn, node_id: str, limit: int = 50) -> list[dict]:
    """When this node came, changed and went. Each snapshot says that about the nodes it touched."""
    host = node_id.split(':')[1] if ':' in node_id else None
    out = []
    for at, raw in conn.all('SELECT taken_at, diff_json FROM graph_snapshots WHERE host = :h ORDER BY taken_at DESC, id DESC LIMIT 200', {'h': host}):
        d = loads(raw) or {}
        for what in ('added', 'changed', 'removed'):
            if node_id in (d.get(what) or []):
                out.append({'at': at, 'what': what})
    return out[:limit]


# ── what the operator put there ──────────────────────────────────────
MANUAL_KINDS = ('Switch', 'Router', 'Modem', 'AccessPoint', 'Firewall', 'IoT', 'Server', 'Other')
LABEL_OK = re.compile(r'[^\x00-\x1f\x7f<>"`]{1,120}')


def manual_nodes(conn: Conn) -> dict:
    """Marked as placed by hand, on the wire and on the screen. They never count as facts, so they join the graph here and never in its tables."""
    nodes, edges = [], []
    for i, kind, label, attrs, links, by, at in conn.all('SELECT id, kind, label, attrs_json, links_json, created_by, updated_at FROM map_manual ORDER BY id'):
        nid = f'manual:{i}'
        nodes.append({'id': nid, 'kind': kind, 'label': label, 'host': None, 'layer': 'manual', 'confidence': 'manual', 'health': 'unknown', 'first_seen': at, 'props': {**(loads(attrs) or {}), 'manual_id': i, 'placed_by': by}})
        for link in loads(links) or []:
            edges.append({'src': nid, 'dst': link['to'], 'rel': link.get('rel') or 'LINKED_TO', 'props': {'confidence': 'manual', 'evidence': {'source': f'placed by {by}, not verified'}}})
    return {'nodes': nodes, 'edges': edges}


def save_manual(conn: Conn, body: dict, actor: str, manual_id: int | None = None) -> dict:
    kind, label = str(body.get('kind') or 'Other'), str(body.get('label') or '').strip()
    if kind not in MANUAL_KINDS:
        raise ValueError('kind is one of ' + ', '.join(MANUAL_KINDS))
    if not LABEL_OK.fullmatch(label):
        raise ValueError('a manual node needs a plain label')
    attrs = {k: str(body[k])[:300] for k in ('url', 'notes', 'asset', 'rack', 'ip') if body.get(k)}
    if attrs.get('url') and not attrs['url'].startswith(('http://', 'https://')):
        raise ValueError('a link is an http or https address')
    links = []
    for link in (body.get('links') or [])[:50]:
        to = str(link.get('to') or '')
        if not to or len(to) > 300:
            raise ValueError('a link needs something to link to')
        links.append({'to': to, 'rel': re.sub(r'[^A-Z_]', '', str(link.get('rel') or 'LINKED_TO').upper())[:30] or 'LINKED_TO'})
    now = int(time.time())
    if manual_id:
        conn.execute('UPDATE map_manual SET kind = :k, label = :l, attrs_json = :a, links_json = :j, updated_at = :t WHERE id = :i', {'k': kind, 'l': label, 'a': json.dumps(attrs), 'j': json.dumps(links), 't': now, 'i': manual_id})
        return {'ok': True, 'id': manual_id}
    return {'ok': True, 'id': conn.scalar('INSERT INTO map_manual (kind, label, attrs_json, links_json, created_by, updated_at) VALUES (:k, :l, :a, :j, :b, :t) RETURNING id',
                                          {'k': kind, 'l': label, 'a': json.dumps(attrs), 'j': json.dumps(links), 'b': actor, 't': now})}


def annotations(conn: Conn, view_id: int | None = None) -> list[dict]:
    return [{'id': r[0], 'view_id': r[1], 'target': r[2], 'text': r[3], 'style': loads(r[4]) or {}, 'by': r[5], 'updated_at': r[6]}
            for r in conn.all('SELECT id, view_id, target, text, style_json, created_by, updated_at FROM map_annotations ORDER BY id') if view_id is None or r[1] in (None, view_id)]


def save_annotation(conn: Conn, body: dict, actor: str) -> dict:
    target, text = str(body.get('target') or '').strip()[:300], str(body.get('text') or '').strip()
    if not target or not text or len(text) > 2000:
        raise ValueError('a note needs something to sit on, and some text up to 2000 characters')
    style = {k: body['style'][k] for k in ('x', 'y', 'w', 'h') if isinstance((body.get('style') or {}).get(k), (int, float))}
    view = body.get('view_id') if isinstance(body.get('view_id'), int) else None
    return {'ok': True, 'id': conn.scalar('INSERT INTO map_annotations (view_id, target, text, style_json, created_by, updated_at) VALUES (:v, :g, :x, :s, :b, :t) RETURNING id',
                                          {'v': view, 'g': target, 'x': text, 's': json.dumps(style), 'b': actor, 't': int(time.time())})}


# ── where security and the map meet ──────────────────────────────────
def coverage(conn: Conn, host: str | None = None) -> list[dict]:
    """What runs where no hold or decoy reaches. Only what was read: a host with nothing measured says that."""
    from . import security
    out = []
    for w in workloads.listing(conn, host)['workloads']:
        points = sorted({(m.get('on') or {}).get('mount') for m in w.get('mounts') or []} - {None, '/'})
        if not points:
            continue
        holds = [h for h in security.hold_rows(conn, w['host']) if h['status'] != 'released' and not h['missing_at']]
        decoys = [r[0] for r in conn.all('SELECT path FROM security_canaries WHERE lower(host) = lower(:h)', {'h': w['host']})]
        for point in points:
            held = any(_under_mount(h['snapshot'], point) for h in holds)
            watched = any(d.startswith(point.rstrip('/') + '/') for d in decoys)
            if not held or not watched:
                out.append({'host': w['host'], 'workload': w['name'], 'kind': w['kind'], 'mount': point, 'hold': held, 'decoy': watched})
    return out


def _under_mount(snapshot: str, point: str) -> bool:
    if snapshot.startswith('/'):
        return snapshot == point or snapshot.startswith(point.rstrip('/') + '/')
    return ('/' + snapshot.split('@')[0]).startswith(point.rstrip('/')) or point.startswith('/' + snapshot.split('@')[0])


def warnings(conn: Conn) -> list[dict]:
    """Machines an armed sentinel could cut off that the fleet cannot do without: gateways, DNS servers, hypervisors."""
    from . import security
    armed = [h for (h,) in conn.all('SELECT hostname FROM hosts') if security.sentinel_config(conn, h)['armed']]
    if not armed:
        return []
    vips = [ipaddress.ip_network(v, strict=False) for v in security.vip_list(conn)]
    out = []
    addr = {}
    for (name,) in conn.all('SELECT hostname FROM hosts'):
        net = netfacts.reading(conn, name) or {}
        for gw in net.get('gateways') or []:
            addr.setdefault(gw, []).append(f'the default gateway of {name}')
        for dns in (net.get('dns') or {}).get('nameservers') or []:
            addr.setdefault(dns, []).append(f'the DNS server of {name}')
    for w in workloads.listing(conn)['workloads']:
        if w['kind'] == 'vm':
            for a, (h, _) in _addresses_of(conn, w['host']).items():
                addr.setdefault(a, []).append(f'{w["host"]}, a hypervisor')
    for ip, why in sorted(addr.items()):
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if a.is_loopback or any(a.version == n.version and a in n for n in vips):
            continue
        out.append({'address': ip, 'why': sorted(set(why))[:4], 'armed_on': armed})
    return out


def _addresses_of(conn: Conn, host: str) -> dict:
    out = {}
    for i in (netfacts.reading(conn, host) or {}).get('interfaces') or []:
        if i['kind'] in SKIP_IFACES or _bridge_name(i):
            continue
        for a in i.get('addresses') or []:
            out[a['ip']] = (host, i['name'])
    return out

