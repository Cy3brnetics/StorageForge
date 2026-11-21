"""Proxmox Datacenter Manager through its API (roadmap section 13): one view of many Proxmox VE clusters and Backup Servers, read through
one token. The remotes the token may see, and through them their nodes, guests, storage, datastores and the snapshots on those datastores.

    GET /version
    GET /remotes/remote                                 the remotes: ID, type (pve or pbs), node addresses. The listing also carries each
                                                        remote's own token secret ("token"): it is dropped here and never stored
    GET /resources/list                                 every remote's resources, each typed pve-node, pve-qemu, pve-lxc, pve-storage,
                                                        pbs-node or pbs-datastore, with a remote that could not be reached said as an error
    GET /pbs/remotes/R/datastore/D/snapshots            the snapshots on each Backup Server datastore, with their verification

A PDM token reaches as far as PDM does (the guide says so): connecting each Proxmox VE and Backup Server directly is the tighter choice,
and where both are connected the direct connection's reading is preferred in the comparison with the SSH scan.

Field names are those of the API viewer (pdm docs api-viewer/apidoc.js, fetched 2026-11-20). Every parse_ function reads what it can and
never raises.
"""
from __future__ import annotations

from .apipbs import parse_snapshots
from .apipve import _b, _data, _f, _i, _items, _s

MAX_SNAPSHOTS = 5000


def parse_version(text: str) -> dict:
    data = _data(text)
    data = data if isinstance(data, dict) else {}
    return {'version': _s(data.get('version'), 60), 'release': _s(data.get('release'), 20)}


def parse_remotes(text: str) -> dict:
    """The remotes, without the token secret the listing carries for each."""
    items, bad = _items(text)
    out = []
    for x in items:
        if not _s(x.get('id')) or x.get('type') not in ('pve', 'pbs'):
            continue
        nodes = []
        for n in x.get('nodes') if isinstance(x.get('nodes'), list) else []:
            host = n if isinstance(n, str) else n.get('hostname') if isinstance(n, dict) else None
            if _s(host):
                nodes.append(_s(host, 255))
        out.append({'id': _s(x['id'], 64), 'type': x['type'], 'nodes': nodes[:32], 'authid': _s(x.get('authid'), 128), 'web_url': _s(x.get('web-url'), 300)})
    return {'remotes': out, 'unreadable': bad}


def parse_resources(text: str) -> dict:
    """{'nodes', 'guests', 'storage', 'datastores', 'errors': {remote: why}, 'unreadable'} from /resources/list."""
    items, bad = _items(text)
    out = {'nodes': [], 'guests': [], 'storage': [], 'datastores': [], 'errors': {}, 'unreadable': bad}
    for block in items:
        remote = _s(block.get('remote'), 64)
        if not remote:
            continue
        if _s(block.get('error')):
            out['errors'][remote] = _s(block['error'], 300)
        for x in block.get('resources') if isinstance(block.get('resources'), list) else []:
            if not isinstance(x, dict):
                continue
            t = x.get('type')
            if t in ('pve-node', 'pbs-node'):
                name = _s(x.get('node') if t == 'pve-node' else x.get('name'), 64)
                if name:
                    out['nodes'].append({'remote': remote, 'node': name, 'platform': t[:3], 'status': _s(x.get('status'), 20), 'cpu': _f(x.get('cpu')),
                                         'maxcpu': _f(x.get('maxcpu')), 'mem': _i(x.get('mem')), 'maxmem': _i(x.get('maxmem')), 'uptime': _i(x.get('uptime'))})
            elif t in ('pve-qemu', 'pve-lxc') and _i(x.get('vmid')) is not None:
                out['guests'].append({'remote': remote, 'vmid': _i(x['vmid']), 'type': t[4:], 'name': _s(x.get('name'), 128), 'node': _s(x.get('node'), 64),
                                      'status': _s(x.get('status'), 20), 'template': _b(x.get('template')) or False, 'maxmem': _i(x.get('maxmem')), 'mem': _i(x.get('mem')),
                                      'maxcpu': _f(x.get('maxcpu')), 'maxdisk': _i(x.get('maxdisk')), 'pool': _s(x.get('pool'), 64), 'uptime': _i(x.get('uptime'))})
            elif t == 'pve-storage' and _s(x.get('storage')):
                out['storage'].append({'remote': remote, 'storage': _s(x['storage'], 64), 'node': _s(x.get('node'), 64), 'status': _s(x.get('status'), 20),
                                       'shared': _b(x.get('shared')) or False, 'disk': _i(x.get('disk')), 'maxdisk': _i(x.get('maxdisk'))})
            elif t == 'pbs-datastore' and _s(x.get('name')):
                out['datastores'].append({'remote': remote, 'store': _s(x['name'], 64), 'used': _i(x.get('disk')), 'total': _i(x.get('maxdisk')),
                                          'usage': _f(x.get('usage')), 'maintenance': _s(x.get('maintenance'), 100), 'backend': _s(x.get('backend-type'), 20)})
    return out


def read(client, row: dict, rb: dict) -> tuple[list, list]:
    from .apiconn import ApiError
    objs, skipped = [('platform', 'version', parse_version(client.get('/version')))], []
    if not (rb.get('features') or {}).get('remotes', {}).get('ok'):
        return objs, ['remotes: the token lacks Resource.Audit on any remote']
    for r in parse_remotes(client.get('/remotes/remote'))['remotes']:
        objs.append(('remote', r['id'], r))
    res = parse_resources(client.get('/resources/list'))
    for remote, why in sorted(res['errors'].items()):
        skipped.append(f'{remote}: PDM could not read it: {why}'[:200])
    for n in res['nodes']:
        objs.append(('node', f'{n["remote"]}/{n["node"]}', n))
    for g in res['guests']:
        objs.append(('guest', f'{g["remote"]}/{g["vmid"]}', g))
    for s in res['storage']:
        objs.append(('storage', f'{s["remote"]}/{s["node"]}/{s["storage"]}', s))
    count = 0
    for d in res['datastores']:
        objs.append(('datastore', f'{d["remote"]}/{d["store"]}', d))
        try:
            snaps = parse_snapshots(client.get(f'/pbs/remotes/{client.seg(d["remote"])}/datastore/{client.seg(d["store"])}/snapshots'))['snapshots']
        except ApiError as exc:
            skipped.append(f'snapshots on {d["remote"]}/{d["store"]}: {exc}'[:200])
            continue
        for sn in snaps:
            if count >= MAX_SNAPSHOTS:
                skipped.append(f'more than {MAX_SNAPSHOTS} snapshots: the rest was not read')
                break
            count += 1
            objs.append(('snapshot', f'{d["remote"]}/{d["store"]}/{sn["type"]}/{sn["id"]}/{sn["time"]}', {**sn, 'remote': d['remote'], 'store': d['store']}))
    return objs, list(dict.fromkeys(skipped))


def problems(conn, row: dict, objects: list[dict]) -> dict:
    out, host = {}, row['host'] or row['name']
    failed = [o for o in objects if o['kind'] == 'snapshot' and o.get('verify') == 'failed']
    if failed:
        out[f'api-backup-verify:{row["name"]}'] = ('api-backup-verify', host, f'{len(failed)} snapshot(s) seen through {row["name"]} failed verification',
                                                  ', '.join(sorted({o['ref'] for o in failed})[:5]), 'warn')
    return out
