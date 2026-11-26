"""Proxmox Backup Server through its API (roadmap section 13): datastores, backup groups and snapshots with their verification, and the
verify and prune jobs, so "is it backed up, and was the backup checked" is read from the server itself.

    GET /version
    GET /status/datastore-usage                       each datastore the token may see: total, used, available, the estimated full date
    GET /config/datastore                             where each datastore is on disk, compared with the SSH scan's mounts
    GET /admin/datastore/S/namespace                  namespaces visible to the token
    GET /admin/datastore/S/groups                     backup groups: type, ID, how many snapshots, the last backup, the owner
    GET /admin/datastore/S/snapshots                  snapshots, each with its last verification (ok or failed)
    GET /admin/verify, /admin/prune                   the jobs, with the state of their last run

Reads the root namespace and any additional namespaces visible to the token. Every parse_ function reads what it can and never raises.
"""
from __future__ import annotations

import time

from .apiparse import _b, _i, _items, _s
from .apipve import parse_version

MAX_SNAPSHOTS = 5000
STALE_BACKUP = 7 * 86400
FULL_SOON = 30 * 86400


def parse_usage(text: str) -> dict:
    items, bad = _items(text)
    out = []
    for x in items:
        if not _s(x.get('store')):
            continue
        out.append({'store': _s(x['store'], 64), 'total': _i(x.get('total')), 'used': _i(x.get('used')), 'avail': _i(x.get('avail')),
                    'full_at': _i(x.get('estimated-full-date')), 'error': _s(x.get('error'), 200), 'mount_status': _s(x.get('mount-status'), 40),
                    'backend': _s(x.get('backend-type'), 20)})
    return {'datastores': out, 'unreadable': bad}


def parse_config(text: str) -> dict:
    items, bad = _items(text)
    out = {}
    for x in items:
        if _s(x.get('name')):
            out[_s(x['name'], 64)] = {'path': _s(x.get('path'), 500), 'gc_schedule': _s(x.get('gc-schedule'), 100), 'verify_new': _b(x.get('verify-new')),
                                      'comment': _s(x.get('comment'), 200)}
    return {'config': out, 'unreadable': bad}


def parse_namespaces(text: str) -> dict:
    items, bad = _items(text)
    return {'namespaces': list(dict.fromkeys(x['ns'] for x in items if isinstance(x.get('ns'), str) and x['ns'])), 'unreadable': bad}


def parse_groups(text: str) -> dict:
    items, bad = _items(text)
    out = []
    for x in items:
        if x.get('backup-type') not in ('vm', 'ct', 'host') or not _s(x.get('backup-id')):
            continue
        out.append({'type': x['backup-type'], 'id': _s(x['backup-id'], 128), 'count': _i(x.get('backup-count')), 'last': _i(x.get('last-backup')),
                    'owner': _s(x.get('owner'), 128), 'comment': _s(x.get('comment'), 200)})
    return {'groups': out, 'unreadable': bad}


def parse_snapshots(text: str) -> dict:
    items, bad = _items(text)
    out = []
    for x in items:
        if x.get('backup-type') not in ('vm', 'ct', 'host') or not _s(x.get('backup-id')) or _i(x.get('backup-time')) is None:
            continue
        v = x.get('verification') if isinstance(x.get('verification'), dict) else {}
        out.append({'type': x['backup-type'], 'id': _s(x['backup-id'], 128), 'time': _i(x['backup-time']), 'size': _i(x.get('size')),
                    'protected': _b(x.get('protected')) or False, 'verify': v.get('state') if v.get('state') in ('ok', 'failed') else None,
                    'encrypted': bool(_s(x.get('fingerprint'))), 'owner': _s(x.get('owner'), 128)})
    return {'snapshots': out, 'unreadable': bad}


def parse_jobs(text: str) -> dict:
    """Verify or prune jobs: id, store, schedule and how their last run went."""
    items, bad = _items(text)
    out = []
    for x in items:
        if not _s(x.get('id')):
            continue
        out.append({'id': _s(x['id'], 64), 'store': _s(x.get('store'), 64), 'schedule': _s(x.get('schedule'), 100), 'last_state': _s(x.get('last-run-state'), 200),
                    'last_end': _i(x.get('last-run-endtime')), 'next_run': _i(x.get('next-run')), 'outdated_after': _i(x.get('outdated-after')),
                    'keep': {k[5:]: _i(x.get(k)) for k in ('keep-last', 'keep-hourly', 'keep-daily', 'keep-weekly', 'keep-monthly', 'keep-yearly') if _i(x.get(k)) is not None}})
    return {'jobs': out, 'unreadable': bad}


def read(client, row: dict, rb: dict) -> tuple[list, list]:
    from .apiconn import ApiError, CertificateChanged, NotPinned
    objs, skipped = [('platform', 'version', parse_version(client.get('/version')))], []
    if not (rb.get('features') or {}).get('datastores', {}).get('ok'):
        return objs, ['datastores: the token lacks Datastore.Audit']
    usage = parse_usage(client.get('/status/datastore-usage'))['datastores']
    try:
        config = parse_config(client.get('/config/datastore'))['config']
    except ApiError as exc:
        config = {}
        skipped.append(f'datastore paths: {exc}'[:200])
    count = 0
    for d in usage:
        store = d['store']
        objs.append(('datastore', store, {**d, **(config.get(store) or {})}))
        path = f'/admin/datastore/{client.seg(store)}'
        ns_list = ['']
        try:
            namespaces = parse_namespaces(client.get(f'{path}/namespace'))
            ns_list.extend(namespaces['namespaces'])
            if namespaces['unreadable']:
                skipped.append(f'{store} namespaces: the list was not readable')
        except (CertificateChanged, NotPinned):
            raise
        except ApiError as exc:
            skipped.append(f'{store} namespaces: {exc}'[:200])
        for ns in ns_list:
            ns_arg = {'ns': ns} if ns else {}
            ref = f'{store}/{ns}' if ns else store
            for endpoint, parse, kind in (('groups', parse_groups, 'backup-group'), ('snapshots', parse_snapshots, 'snapshot')):
                if kind == 'snapshot' and count >= MAX_SNAPSHOTS:
                    skipped.append(f'snapshot limit of {MAX_SNAPSHOTS} reached')
                    continue
                try:
                    parsed = parse(client.get(f'{path}/{endpoint}', **ns_arg))
                except (CertificateChanged, NotPinned):
                    raise
                except ApiError as exc:
                    skipped.append(f'{ref} {endpoint}: {exc}'[:200])
                    continue
                if parsed['unreadable']:
                    skipped.append(f'{ref} {endpoint}: the list was not readable')
                items = parsed[endpoint]
                if kind == 'snapshot':
                    if len(items) > MAX_SNAPSHOTS - count:
                        skipped.append(f'snapshot limit of {MAX_SNAPSHOTS} reached')
                    items = items[:MAX_SNAPSHOTS - count]
                    count += len(items)
                for item in items:
                    key = f'{ref}/{item["type"]}/{item["id"]}'
                    if kind == 'snapshot':
                        key = f'{key}/{item["time"]}'
                    objs.append((kind, key, {**item, 'store': store, 'ns': ns}))
    for path, kind in (('/admin/verify', 'verify-job'), ('/admin/prune', 'prune-job')):
        try:
            for j in parse_jobs(client.get(path))['jobs']:
                objs.append((kind, j['id'], j))
        except ApiError as exc:
            skipped.append(f'{kind}s: {exc}'[:200])
    return objs, list(dict.fromkeys(skipped))


def compare_mounts(conn, row: dict, objects: list[dict]) -> list[dict]:
    """Each datastore's path against the mounts the SSH scan of the Backup Server read: which mount holds it, and whether the two agree on
    its size. Nothing is merged: both numbers are shown."""
    if not row.get('host'):
        return []
    mounts = conn.all("""SELECT m.mount_point, m.total_bytes, m.used_bytes, m.filesystem_type FROM mounts m JOIN hosts h ON h.host_id = m.host_id
                         WHERE h.hostname = :h AND m.scan_state <> 'gone'""", {'h': row['host']})
    out = []
    for o in objects:
        if o['kind'] != 'datastore' or not o.get('path'):
            continue
        under = [m for m in mounts if o['path'] == m[0] or o['path'].startswith(m[0].rstrip('/') + '/')]
        m = max(under, key=lambda m: len(m[0]), default=None)
        if not m:
            out.append({'store': o['ref'], 'path': o['path'], 'mount': None, 'differs': [], 'why': 'no mount the SSH scan read holds this path'})
            continue
        differs = []
        if m[1] and o.get('total') and abs(m[1] - o['total']) > 0.05 * m[1]:
            differs.append({'field': 'total_bytes', 'api': o['total'], 'ssh': m[1]})
        out.append({'store': o['ref'], 'path': o['path'], 'mount': m[0], 'fstype': m[3], 'differs': differs})
    return out


def problems(conn, row: dict, objects: list[dict], now: float | None = None) -> dict:
    now = now or time.time()
    out, host = {}, row['host'] or row['name']
    failed = [o for o in objects if o['kind'] == 'snapshot' and o.get('verify') == 'failed']
    if failed:
        out[f'api-backup-verify:{row["name"]}'] = ('api-backup-verify', host, f'{len(failed)} snapshot(s) on {row["name"]} failed verification',
                                                  ', '.join(sorted({o['ref'] for o in failed})[:5]), 'warn')
    stale = [o for o in objects if o['kind'] == 'backup-group' and o.get('last') and now - o['last'] > STALE_BACKUP]
    if stale:
        out[f'api-backup-stale:{row["name"]}'] = ('api-backup-stale', host, f'{len(stale)} backup group(s) on {row["name"]} have no backup in a week',
                                                 ', '.join(o['ref'] for o in stale[:8]), 'warn')
    for o in objects:
        if o['kind'] == 'verify-job' and o.get('last_state') and o['last_state'].upper() != 'OK':
            out[f'api-verify-job:{row["name"]}:{o["ref"]}'] = ('api-verify-job', host, f'The verify job {o["ref"]} on {row["name"]} did not end well', o['last_state'], 'warn')
        if o['kind'] == 'datastore' and o.get('full_at') and 0 < o['full_at'] - now < FULL_SOON:
            out[f'api-datastore-full:{row["name"]}:{o["ref"]}'] = ('api-datastore-full', host, f'Datastore {o["ref"]} on {row["name"]} will be full within 30 days',
                                                                 time.strftime('estimated %Y-%m-%d', time.localtime(o['full_at'])), 'warn')
    return out
