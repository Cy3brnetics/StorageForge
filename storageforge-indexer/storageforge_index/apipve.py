"""Proxmox VE through its API (roadmap section 13): what the cluster says of its nodes, guests, storage, backup jobs and the backups kept
on its storage with their verification, for the places StorageForge's model has for them.

    GET /version                                     the release
    GET /cluster/resources                           nodes, guests (qemu and lxc) and storage, cluster wide (each entry only as far as the
                                                     token may see it)
    GET /cluster/ceph/status                         cluster health when Ceph is configured and visible to the token
    GET /cluster/backup                              the backup jobs: only with Sys.Audit on /, which the read-back says
    GET /nodes/N/storage/S/content?content=backup    the backups on each storage that holds them, with each one's last verification
                                                     (Proxmox Backup Server storage only); a shared storage is read once

Field names are those of the API viewer (pve-docs/api-viewer/apidoc.js, fetched 2026-11-20). Every parse_ function reads what it can
of an answer and never raises: an entry it cannot read is dropped and counted, as a scan's parsers do.
"""
from __future__ import annotations

import time

from .apiparse import _b, _data, _f, _i, _items, _s

MAX_BACKUPS = 5000           # per read: past that the rest is left out and the read says so
VERIFY_STALE = 30 * 86400


def parse_version(text: str) -> dict:
    data = _data(text)
    data = data if isinstance(data, dict) else {}
    return {'version': _s(data.get('version'), 60), 'release': _s(data.get('release'), 20)}


def parse_resources(text: str) -> dict:
    """{'nodes', 'guests', 'storage', 'dropped', 'unreadable'} from /cluster/resources."""
    items, bad = _items(text)
    out = {'nodes': [], 'guests': [], 'storage': [], 'dropped': 0, 'unreadable': bad}
    for x in items:
        t = x.get('type')
        if t == 'node' and _s(x.get('node')):
            out['nodes'].append({'node': _s(x['node'], 64), 'status': _s(x.get('status'), 20), 'cpu': _f(x.get('cpu')), 'maxcpu': _f(x.get('maxcpu')),
                                 'mem': _i(x.get('mem')), 'maxmem': _i(x.get('maxmem')), 'uptime': _i(x.get('uptime')), 'level': _s(x.get('level'), 20)})
        elif t in ('qemu', 'lxc') and _i(x.get('vmid')) is not None:
            out['guests'].append({'vmid': _i(x['vmid']), 'type': t, 'name': _s(x.get('name'), 128), 'node': _s(x.get('node'), 64), 'status': _s(x.get('status'), 20),
                                  'template': _b(x.get('template')) or False, 'maxmem': _i(x.get('maxmem')), 'mem': _i(x.get('mem')), 'maxcpu': _f(x.get('maxcpu')),
                                  'maxdisk': _i(x.get('maxdisk')), 'uptime': _i(x.get('uptime')), 'pool': _s(x.get('pool'), 64), 'tags': _s(x.get('tags'), 200),
                                  'lock': _s(x.get('lock'), 40), 'hastate': _s(x.get('hastate'), 40)})
        elif t == 'storage' and _s(x.get('storage')) and _s(x.get('node')):
            content = _s(x.get('content'), 200) or ''
            out['storage'].append({'storage': _s(x['storage'], 64), 'node': _s(x['node'], 64), 'status': _s(x.get('status'), 20), 'plugintype': _s(x.get('plugintype'), 40),
                                   'shared': _b(x.get('shared')) or False, 'content': [c for c in content.split(',') if c], 'disk': _i(x.get('disk')), 'maxdisk': _i(x.get('maxdisk'))})
        elif t in ('node', 'qemu', 'lxc', 'storage'):
            out['dropped'] += 1
    return out


def parse_backup_jobs(text: str) -> dict:
    items, bad = _items(text)
    jobs = []
    for x in items:
        if not _s(x.get('id')):
            continue
        enabled = _b(x.get('enabled'))
        jobs.append({'id': _s(x['id'], 50), 'enabled': True if enabled is None else enabled, 'schedule': _s(x.get('schedule'), 128), 'storage': _s(x.get('storage'), 64),
                     'all': _b(x.get('all')) or False, 'vmid': [v for v in (_s(x.get('vmid'), 2000) or '').split(',') if v.strip().isdigit()],
                     'exclude': [v for v in (_s(x.get('exclude'), 2000) or '').split(',') if v.strip().isdigit()], 'pool': _s(x.get('pool'), 64),
                     'node': _s(x.get('node'), 64), 'mode': _s(x.get('mode'), 20), 'next_run': _i(x.get('next-run')), 'comment': _s(x.get('comment'), 200)})
    return {'jobs': jobs, 'unreadable': bad}


def parse_ceph_status(text: str) -> dict:
    """Parses Proxmox VE Ceph status: /cluster/ceph/status."""
    data = _data(text)
    data = data if isinstance(data, dict) else {}
    health = data.get('health') if isinstance(data.get('health'), dict) else {}
    osdmap = data.get('osdmap') if isinstance(data.get('osdmap'), dict) else {}
    if isinstance(osdmap.get('osdmap'), dict):
        osdmap = osdmap['osdmap']
    return {
        'status': _s(health.get('status') or health.get('overall_status'), 20) or 'UNKNOWN',
        'num_osds': _i(osdmap.get('num_osds')) or 0,
        'num_up_osds': _i(osdmap.get('num_up_osds')) or 0,
        'num_in_osds': _i(osdmap.get('num_in_osds')) or 0,
        'degraded': _b(health.get('degraded')) is True or (health.get('status') or health.get('overall_status')) in ('HEALTH_WARN', 'HEALTH_ERR'),
    }


def parse_backups(text: str) -> dict:
    """The backups on one storage: /nodes/N/storage/S/content?content=backup."""
    items, bad = _items(text)
    out = []
    for x in items:
        volid = _s(x.get('volid'), 300)
        if not volid:
            continue
        v = x.get('verification') if isinstance(x.get('verification'), dict) else {}
        out.append({'volid': volid, 'vmid': _i(x.get('vmid')), 'ctime': _i(x.get('ctime')), 'size': _i(x.get('size')), 'format': _s(x.get('format'), 40),
                    'protected': _b(x.get('protected')) or False, 'encrypted': bool(x.get('encrypted')), 'verify': _s(v.get('state'), 20),
                    'subtype': _s(x.get('subtype'), 20), 'notes': _s(x.get('notes'), 200)})
    return {'backups': out, 'unreadable': bad}


def read(client, row: dict, rb: dict) -> tuple[list, list]:
    """(objects, skipped). Each feature the read-back found the token lacks is skipped and said, not asked for and refused."""
    from .apicollect import Reading
    feats = rb.get('features') or {}
    r = Reading()
    v = parse_version(client.get('/version'))
    r.objs.append(('platform', 'version', v))
    res = parse_resources(client.get('/cluster/resources'))
    if res['unreadable']:
        r.skip('the resource list was not readable')
    for n in res['nodes']:
        r.objs.append(('node', n['node'], n))
    ceph = r.call('ceph', lambda: parse_ceph_status(client.get('/cluster/ceph/status')), quiet=True)
    if ceph and ceph['status'] != 'UNKNOWN':
        r.objs.append(('ceph', 'status', ceph))
    for g in res['guests']:
        r.objs.append(('guest', str(g['vmid']), g))
    for s in res['storage']:
        r.objs.append(('storage', f'{s["node"]}/{s["storage"]}', s))
    if feats.get('backup-jobs', {}).get('ok'):
        jobs = parse_backup_jobs(client.get('/cluster/backup'))
        for j in jobs['jobs']:
            r.objs.append(('backup-job', j['id'], j))
    else:
        r.skip('backup jobs: the token lacks Sys.Audit on /')
    if feats.get('storage', {}).get('ok'):
        done, cap = set(), r.cap(MAX_BACKUPS, 'backups')
        for s in res['storage']:
            if 'backup' not in s['content'] or s['status'] not in (None, 'available'):
                continue
            key = s['storage'] if s['shared'] else f'{s["node"]}/{s["storage"]}'
            if key in done:
                continue
            done.add(key)
            if cap.full():
                break
            got = r.call(f'backups on {key}', lambda: parse_backups(client.get(f'/nodes/{client.seg(s["node"])}/storage/{client.seg(s["storage"])}/content', content='backup')))
            for b in cap.take(got['backups'] if got else []):
                r.objs.append(('backup', b['volid'], {**b, 'storage': s['storage'], 'node': s['node']}))
    else:
        r.skip('storage and backups: the token lacks Datastore.Audit')
    return r.result()

def problems(conn, row: dict, objects: list[dict], now: float | None = None) -> dict:
    """Alerts from Ceph, storage capacity, backup verification and job coverage."""
    out = {}
    host = row['host'] or row['name']
    ceph = next((o for o in objects if o['kind'] == 'ceph' and o['ref'] == 'status'), None)
    if ceph and ceph.get('degraded'):
        out[f'api-pve-ceph:{row["name"]}'] = ('api-pve-ceph', host, f'Ceph cluster on {row["name"]} is degraded ({ceph.get("status")})',
                                                f'OSDs: {ceph.get("num_up_osds")}/{ceph.get("num_osds")} up', 'warn')
    failed = [o for o in objects if o['kind'] == 'backup' and o.get('verify') == 'failed']
    if failed:
        out[f'api-backup-verify:{row["name"]}'] = ('api-backup-verify', host, f'{len(failed)} backup(s) on {row["name"]} failed verification',
                                                  ', '.join(sorted({o['volid'] for o in failed})[:5]), 'warn')
    for o in objects:
        if o['kind'] == 'storage' and o.get('maxdisk') and o.get('disk') is not None and o['disk'] / o['maxdisk'] > 0.9:
            out[f'api-storage-full:{row["name"]}:{o["ref"]}'] = ('api-storage-full', host, f'Storage {o["ref"]} on {row["name"]} is {round(100 * o["disk"] / o["maxdisk"])}% full', '', 'warn')
    jobs = [o for o in objects if o['kind'] == 'backup-job' and o.get('enabled')]
    if jobs:
        covered_all = any(j.get('all') for j in jobs)
        excluded = set.intersection(*[set(j.get('exclude') or []) for j in jobs if j.get('all')]) if covered_all else set()
        named = {v for j in jobs for v in j.get('vmid') or []}
        pools = {j.get('pool') for j in jobs if j.get('pool')}
        bare = [o for o in objects if o['kind'] == 'guest' and not o.get('template') and not (
            (covered_all and o['ref'] not in excluded) or o['ref'] in named or (o.get('pool') and o['pool'] in pools))]
        if bare:
            out[f'api-guest-unbacked:{row["name"]}'] = ('api-guest-unbacked', host, f'{len(bare)} guest(s) on {row["name"]} are in no backup job',
                                                       ', '.join(f'{o["ref"]} {o.get("name") or ""}'.strip() for o in bare[:8]), 'info')
    return out
