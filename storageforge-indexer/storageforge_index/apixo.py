"""Xen Orchestra through its REST API (roadmap section 13): pools, hosts, VMs, storage repositories, backup jobs and their last runs, for
XCP-ng pools that SSH scans see only in part (an SSH scan of an XCP-ng host reads its mounts, not its VMs or what each SR is).

    GET /rest/v0/users/me                       the token's user: permission "admin" means every endpoint (the read-back)
    GET /rest/v0/users/me/acl-privileges        its RBAC privileges: resource, action, effect, selector (the read-back)
    GET /rest/v0/users/me/authentication_tokens its tokens with their expiration: only the one in use is looked at, in memory
    GET /rest/v0/pools, /hosts, /vms, /srs      with fields=, as the REST API returns objects instead of URLs when fields are asked for
    GET /rest/v0/backup-jobs, /backup-logs      the jobs, and their runs with status

The token goes in the authenticationToken cookie, as the REST API documentation shows. A Xen Orchestra token's ID is the token itself,
so the list of the user's tokens holds secrets: it is read only to find the expiry of the token in use, compared in memory, and nothing
of it but that one date is kept.

Field names are those of the REST API's OpenAPI examples (xen-orchestra @xen-orchestra/rest-api/src/open-api/oa-examples, fetched
2026-11-20) and the RBAC page (docs/docs/security/user-management/rbac.md). Each parse_ function takes the JSON text of one answer and
never raises.
"""
from __future__ import annotations

import json
import re
import time

from .apiparse import _b, _i, _list, _load, _s

FETCHED = '2026-11-20'
SOURCES = ['https://docs.xen-orchestra.com/automation/restapi (authentication with the authenticationToken cookie, tokens, fields=, collections)',
           'https://docs.xen-orchestra.com/security/user-management/rbac (RBAC: roles, privileges, resources and actions, self endpoints, templates)',
           'https://github.com/vatesfr/xen-orchestra/tree/master/@xen-orchestra/rest-api/src/open-api/oa-examples (vm, host, pool, sr, user, backup-job, backup-log, acl-privilege)']
RESOURCES = ('pool', 'host', 'vm', 'sr', 'backup-job', 'backup-log')
READ = {
    'pools': {'resource': 'pool', 'what': 'pools'},
    'hosts': {'resource': 'host', 'what': 'hosts and their state'},
    'vms': {'resource': 'vm', 'what': 'VMs, their state, memory and CPUs'},
    'srs': {'resource': 'sr', 'what': 'storage repositories and their usage'},
    'backup-jobs': {'resource': 'backup-job', 'what': 'backup jobs'},
    'backup-logs': {'resource': 'backup-log', 'what': 'the runs of the backup jobs and how they ended'},
}
ADMIN_RESOURCES = {'user', 'group', 'acl-role', 'acl-privilege', 'server', 'proxy'}
MAX_LOGS = 200
FULL_SR = 0.9

GUIDE = {
    'title': 'Xen Orchestra',
    'least': 'a dedicated Xen Orchestra user storageforge that is not an administrator, given one role holding only read on pool, host, vm, sr, backup-job and backup-log (narrowed with a $pool selector to the pools it should see), and a token made by that user',
    'role': 'StorageForge read (read on pool, host, vm, sr, backup-job, backup-log)',
    'why_role': ('RBAC is deny by default: a user that is not an administrator sees nothing it was not given. The read action on these six '
                 'resources lists them and changes nothing. The built-in Read only template reads the whole infrastructure and every XO object, '
                 'users and groups too, which is more than StorageForge needs, so a role of its own is the narrower choice.'),
    'scope': 'A selector on each privilege narrows it to some objects: "$pool: POOL-UUID" for one pool. Without one it covers every object of that kind. RBAC is part of the Essential+, Pro and Enterprise bundles on XOA, and of every installation from the sources.',
    'read': {f: {'what': v['what'], 'privs': [f'{v["resource"]}:read'], 'paths': ['all, or a $pool selector']} for f, v in READ.items()},
    'actions': {
        'snapshot': {'title': 'take snapshots of VMs', 'privs': ['vm:snapshot'], 'on': 'the VMs, by a selector (a tag or a pool)', 'role': 'a role with vm snapshot'},
        'power': {'title': 'start and stop VMs', 'privs': ['vm:start', 'vm:shutdown:clean'], 'on': 'the VMs, by a selector', 'role': 'a role with vm start and shutdown:clean'},
    },
    'admin': ['permission admin', 'user, group, acl-role, acl-privilege or server actions', 'the Administrator template'],
    'never': ['admin@admin.net or any administrator user (an administrator has every endpoint; refused here for admin@admin.net, and a finding for any other)',
              'the Administrator, Storage administrator or Network administrator template', 'sr import:vdi:url: it makes XO fetch any address it can reach'],
    'check': 'GET /rest/v0/users/me/acl-privileges with the token: only read actions should be listed',
    'expiry': {'allowed': True, 'read_back': True, 'how': 'every token expires; the longest is maxTokenValidity in the xo-server configuration (half a year by default). The read-back reads the expiration of the token in use, and a warning comes 30 days before it lapses'},
    'token_id_placeholder': 'storageforge',
    'scope_hint': ('The UUIDs of the pools it should see, separated by spaces; empty for all.', ''),
    'fetched': FETCHED,
}


def steps(user: str, token: str, scope, expire: int) -> list[dict]:
    from .apiguide import _q
    pools = [p for p in (scope if isinstance(scope, list) else str(scope or '').split()) if p]
    if any(not re.fullmatch(r'[0-9a-fA-F-]{36}', p) for p in pools):
        from .apiguide import GuideError
        raise GuideError('the pools are given by their UUIDs')
    xo = 'https://XO'
    priv = []
    for r in RESOURCES:
        for p in pools or [None]:
            body = {'resource': r, 'action': 'read', 'effect': 'allow', 'roleId': 'ROLE_ID'}
            if p:
                body['selector'] = '$pool: ' + p if r != 'pool' else 'id: ' + p
            priv.append(f'curl -sS -u ADMIN -H {_q("Content-Type: application/json")} -d {_q(json.dumps(body))} {xo}/rest/v0/acl-privileges')
    return [
        {'where': 'the Xen Orchestra web interface, as an administrator: Settings, Users', 'say': f'Make a user {user} whose permission is user, not admin, with a long random password nobody keeps. It only makes its token.',
         'run': []},
        {'where': 'any shell that reaches Xen Orchestra (curl asks the administrator password: it is not on the command line)', 'say': 'Make a role for StorageForge. The answer is its id: put it in place of ROLE_ID below, and the administrator user in place of ADMIN.',
         'run': [f'curl -sS -u ADMIN -H {_q("Content-Type: application/json")} -d {_q(json.dumps({"name": "StorageForge read"}))} {xo}/rest/v0/acl-roles']},
        {'where': 'the same shell', 'say': 'Give the role read on pools, hosts, VMs, storage repositories, backup jobs and their logs' + (', each narrowed to the pools you named' if pools else '') + ', and nothing else.',
         'run': priv},
        {'where': 'the same shell', 'say': f'Give the role to {user}. Its id is in Settings, Users, or GET /rest/v0/users?fields=name,id.',
         'run': [f'curl -sS -u ADMIN -X PUT {xo}/rest/v0/acl-roles/ROLE_ID/users/USER_ID']},
        {'where': 'the same shell, as the new user (curl asks its password)', 'say': 'Make the token as that user. Its "id" is the token: copy it for the next screen. It expires by itself, at the longest after maxTokenValidity (half a year unless the configuration says otherwise).',
         'run': [f'curl -sS -u {_q(user)} -X POST {xo}/rest/v0/users/me/authentication_tokens']},
        {'where': 'the same shell', 'say': 'Check: only read actions on those six resources. StorageForge reads the same back after you enter the token.',
         'run': [f'curl -sS -u {_q(user)} {_q(xo + "/rest/v0/users/me/acl-privileges?fields=resource,action,effect,selector")}']},
    ]


def action_steps(action: str, spec: dict, user: str) -> list[dict]:
    from .apiguide import _q
    run = [f'curl -sS -u ADMIN -H {_q("Content-Type: application/json")} -d '
           f'{_q(json.dumps({"resource": "vm", "action": p.split(":", 1)[1], "effect": "allow", "selector": "tags: storageforge", "roleId": "ROLE_ID"}))} https://XO/rest/v0/acl-privileges'
           for p in spec['privs']]
    return [{'where': 'a shell that reaches Xen Orchestra, as an administrator', 'say': f'To {spec["title"]}: add {", ".join(spec["privs"])} to the StorageForge role, narrowed by a selector (here the VMs tagged storageforge). Never the Administrator template.',
             'run': run}]


# ── parsers ───────────────────────────────────────────────────────────
def _uuid(v):
    return v if isinstance(v, str) and re.fullmatch(r'[0-9A-Za-z_-]{1,64}', v) else None


def parse_me(text: str) -> dict:
    doc = _load(text)
    doc = doc if isinstance(doc, dict) else {}
    return {'id': _uuid(doc.get('id')), 'name': _s(doc.get('name') or doc.get('email'), 128), 'permission': _s(doc.get('permission'), 20)}


def parse_privileges(text: str) -> dict:
    items, bad = _list(text)
    out = []
    for x in items:
        if not _s(x.get('resource')) or not _s(x.get('action')):
            continue
        out.append({'resource': _s(x['resource'], 40), 'action': _s(x['action'], 80), 'effect': _s(x.get('effect'), 10) or 'allow', 'selector': _s(x.get('selector'), 200)})
    return {'privileges': out, 'unreadable': bad}


def parse_token_expiry(text: str, secret: str | None = None) -> dict:
    """{'expire': ms->s of the token in use, or None}. Every other entry, and the IDs (which are tokens), are dropped here."""
    items, _ = _list(text)
    for x in items:
        if secret and x.get('id') == secret:
            exp = _i(x.get('expiration'))
            return {'expire': exp // 1000 if exp and exp > 1 << 33 else exp, 'found': True}
    return {'expire': None, 'found': False}


def parse_pools(text: str) -> dict:
    items, bad = _list(text)
    return {'pools': [{'id': _uuid(x.get('id')), 'name': _s(x.get('name_label'), 128), 'master': _uuid(x.get('master'))} for x in items if _uuid(x.get('id'))], 'unreadable': bad}


def parse_hosts(text: str) -> dict:
    items, bad = _list(text)
    out = []
    for x in items:
        if not _uuid(x.get('id')):
            continue
        mem = x.get('memory') if isinstance(x.get('memory'), dict) else {}
        out.append({'id': _uuid(x['id']), 'name': _s(x.get('name_label'), 128), 'address': _s(x.get('address'), 64), 'power_state': _s(x.get('power_state'), 20),
                    'pool': _uuid(x.get('$pool')), 'memory': _i(mem.get('size')), 'memory_used': _i(mem.get('usage'))})
    return {'hosts': out, 'unreadable': bad}


def parse_vms(text: str) -> dict:
    items, bad = _list(text)
    out = []
    for x in items:
        if not _uuid(x.get('id')):
            continue
        mem = x.get('memory') if isinstance(x.get('memory'), dict) else {}
        cpus = x.get('CPUs') if isinstance(x.get('CPUs'), dict) else {}
        out.append({'id': _uuid(x['id']), 'name': _s(x.get('name_label'), 128), 'power_state': _s(x.get('power_state'), 20), 'pool': _uuid(x.get('$pool')),
                    'container': _uuid(x.get('$container')), 'memory': _i(mem.get('size')), 'cpus': _i(cpus.get('number')),
                    'tags': [t[:60] for t in x.get('tags') or [] if isinstance(t, str)][:20] if isinstance(x.get('tags'), list) else []})
    return {'vms': out, 'unreadable': bad}


def parse_srs(text: str) -> dict:
    items, bad = _list(text)
    out = []
    for x in items:
        if not _uuid(x.get('id')):
            continue
        out.append({'id': _uuid(x['id']), 'name': _s(x.get('name_label'), 128), 'type': _s(x.get('SR_type'), 40), 'size': _i(x.get('size')),
                    'physical_usage': _i(x.get('physical_usage')), 'usage': _i(x.get('usage')), 'shared': _b(x.get('shared')), 'pool': _uuid(x.get('$pool')),
                    'container': _uuid(x.get('$container')), 'content_type': _s(x.get('content_type'), 20)})
    return {'srs': out, 'unreadable': bad}


def parse_backup_jobs(text: str) -> dict:
    items, bad = _list(text)
    return {'jobs': [{'id': _uuid(x.get('id')), 'name': _s(x.get('name'), 200), 'mode': _s(x.get('mode'), 20), 'type': _s(x.get('type'), 40)}
                     for x in items if _uuid(x.get('id'))], 'unreadable': bad}


def parse_backup_logs(text: str) -> dict:
    items, bad = _list(text)
    out = []
    for x in items:
        if not (_s(x.get('id')) or _i(x.get('id'))):
            continue
        out.append({'id': str(x['id'])[:40], 'job': _uuid(x.get('jobId')), 'job_name': _s(x.get('jobName'), 200), 'status': _s(x.get('status'), 20),
                    'start': (_i(x.get('start')) or 0) // 1000 or None, 'end': (_i(x.get('end')) or 0) // 1000 or None})
    return {'logs': out, 'unreadable': bad}


# ── the read-back ─────────────────────────────────────────────────────
def judge(me: dict, privileges: list[dict], actions: list[str] | None = None, token: dict | None = None) -> dict:
    from .apireadback import verdict
    admin = me.get('permission') == 'admin'
    allow = [p for p in privileges if p['effect'] == 'allow']
    features = {}
    for f, need in READ.items():
        on = [p.get('selector') or 'all' for p in allow if p['resource'] == need['resource'] and p['action'] in ('read', '*')]
        features[f] = {'ok': admin or bool(on), 'what': need['what'], 'on': ['everything (administrator)'] if admin else on,
                       'add': f'read on {need["resource"]} in the StorageForge role'}
    wanted = {p for a in actions or [] for p in (GUIDE['actions'].get(a) or {}).get('privs', [])}
    over, extra = [], []
    if admin:
        over.append({'path': 'Xen Orchestra', 'priv': 'permission admin: every endpoint', 'admin': True})
    for p in allow:
        name = f'{p["resource"]}:{p["action"]}'
        if p['action'] == 'read':
            if p['resource'] not in RESOURCES:
                extra.append({'path': p.get('selector') or 'all', 'priv': name})
            continue
        if name in wanted:
            continue
        over.append({'path': p.get('selector') or 'all', 'priv': name, 'admin': p['resource'] in ADMIN_RESOURCES or p['action'] == '*' or name.startswith('sr:import')})
    return verdict('xo', features, over, token, extra=extra, actions=actions)


def readback(client, row: dict) -> dict:
    from .apiconn import ApiError
    me = parse_me(client.get('/users/me'))
    privs = parse_privileges(client.get('/users/me/acl-privileges', fields='resource,action,effect,selector'))
    if privs['unreadable'] and me.get('permission') != 'admin':
        raise ApiError('Xen Orchestra answered /users/me/acl-privileges with something that is not a list of privileges')
    token = {'expire': None, 'enable': None}
    try:
        token = {**token, 'expire': parse_token_expiry(client.get('/users/me/authentication_tokens', fields='id,expiration'), client._secret)['expire']}
    except ApiError:
        pass
    out = judge(me, privs['privileges'], row.get('actions'), token)
    return {**out, 'paths': {p.get('selector') or 'all': {f'{p["resource"]}:{p["action"]}': p['effect'] == 'allow'} for p in privs['privileges']}, 'user': me.get('name')}


# ── the read ──────────────────────────────────────────────────────────
CALLS = (('pools', '/pools', 'id,name_label,master', parse_pools, 'pools', 'xo-pool'),
         ('hosts', '/hosts', 'id,name_label,address,power_state,$pool,memory', parse_hosts, 'hosts', 'xo-host'),
         ('vms', '/vms', 'id,name_label,power_state,$pool,$container,memory,CPUs,tags', parse_vms, 'vms', 'vm'),
         ('srs', '/srs', 'id,name_label,SR_type,size,physical_usage,usage,shared,$pool,$container,content_type', parse_srs, 'srs', 'sr'),
         ('backup-jobs', '/backup-jobs', 'id,name,mode,type', parse_backup_jobs, 'jobs', 'backup-job'))


def read(client, row: dict, rb: dict) -> tuple[list, list]:
    from .apicollect import Reading
    r = Reading()
    feats = rb.get('features') or {}
    for feature, path, fields, parse, key, kind in CALLS:
        if not feats.get(feature, {}).get('ok'):
            r.skip(f'{feature}: the token lacks read on {READ[feature]["resource"]}')
            continue
        got = r.call(feature, lambda: parse(client.get(path, fields=fields)))
        r.objs += [(kind, x['id'], x) for x in (got[key] if got else [])]
    if feats.get('backup-logs', {}).get('ok'):
        got = r.call('backup-logs', lambda: parse_backup_logs(client.get('/backup-logs', fields='id,jobId,jobName,status,start,end', limit=MAX_LOGS)))
        latest = {}
        for lg in (got['logs'] if got else []):
            if lg['job'] and (lg['job'] not in latest or (lg['start'] or 0) > (latest[lg['job']]['start'] or 0)):
                latest[lg['job']] = lg
        r.objs += [('backup-run', job, lg) for job, lg in latest.items()]
    return r.result()


# ── beside the scan, and the views ────────────────────────────────────
def _host_map(conn, objects: list[dict], hosts=None) -> dict:
    """XO host id -> the scanned host, by name or address. hosts: an apiviews.HostIndex already read."""
    from .apiviews import HostIndex
    index = hosts if hosts is not None else HostIndex(conn)
    return {o['ref']: index.name(o.get('name')) or index.address(o.get('address')) for o in objects if o['kind'] == 'xo-host'}


def compare(conn, row: dict, objects: list[dict]) -> dict:
    """Each storage repository against the mounts the SSH scan read on the XCP-ng hosts: a file-based SR is mounted at
    /run/sr-mount/SR-UUID, so the scan sees a mount with a UUID for a name and the API says what it is. A mount there that no SR the token
    sees owns is listed too."""
    hostmap = _host_map(conn, objects)
    scanned = sorted({h for h in hostmap.values() if h})
    mounts = {}
    for h in scanned:
        for mp, total, used, fs in conn.all("""SELECT m.mount_point, m.total_bytes, m.used_bytes, m.filesystem_type FROM mounts m JOIN hosts h ON h.host_id = m.host_id
                                               WHERE h.hostname = :h AND m.scan_state <> 'gone' AND m.mount_point LIKE '/run/sr-mount/%'""", {'h': h}):
            mounts.setdefault(mp.rsplit('/', 1)[-1], []).append({'host': h, 'mount': mp, 'total': total, 'used': used, 'fstype': fs})
    out = []
    for o in objects:
        if o['kind'] != 'sr':
            continue
        seen = mounts.pop(o['ref'], [])
        differs = [{'field': 'total_bytes', 'api': o.get('size'), 'ssh': m['total'], 'host': m['host']} for m in seen
                   if m['total'] and o.get('size') and abs(m['total'] - o['size']) > 0.05 * m['total']]
        out.append({'sr': o['ref'], 'name': o.get('name'), 'type': o.get('type'), 'mounted_on': [m['host'] for m in seen], 'differs': differs,
                    'seen_by': ['api', 'ssh'] if seen else ['api'], 'why': None if seen else 'no scanned host mounts it under /run/sr-mount (a block SR such as LVM is not mounted)'})
    for uuid, ms in mounts.items():
        out.append({'sr': uuid, 'name': None, 'mounted_on': [m['host'] for m in ms], 'differs': [], 'seen_by': ['ssh'], 'why': 'the API did not list this SR: the token may not see it'})
    return {'srs': out, 'scanned_hosts': scanned}


def workloads(conn, row: dict, objects: list[dict]) -> list[dict]:
    hostmap = _host_map(conn, objects)
    xo_hosts = {o['ref']: o for o in objects if o['kind'] == 'xo-host'}
    out = []
    for o in objects:
        if o['kind'] != 'vm':
            continue
        on = hostmap.get(o.get('container'))
        out.append({'host': on or (xo_hosts.get(o.get('container')) or {}).get('name'), 'runtime': 'xen', 'kind': 'vm', 'name': o.get('name') or o['ref'],
                    'state': (o.get('power_state') or '').lower() or None, 'memory_mib': round(o['memory'] / 1048576) if o.get('memory') else None, 'vcpus': o.get('cpus'),
                    'api': {'uuid': o['ref'], 'pool': o.get('pool')}})
    return out


def map_nodes(conn, row: dict, objects: list[dict], hosts: dict, layers) -> list[dict]:
    hostmap = _host_map(conn, objects, hosts)
    out = []
    if 'workloads' in layers:
        for o in objects:
            if o['kind'] == 'vm':
                on = hostmap.get(o.get('container'))
                out.append({'id': f'api:{row["name"]}:vm:{o["ref"]}', 'kind': 'VM', 'label': o.get('name') or o['ref'], 'layer': 'workloads', 'host': on,
                            'props': {'runtime': 'xen', 'state': (o.get('power_state') or '').lower(), 'uuid': o['ref'], 'connection': row['name']},
                            'edges': [(f'host:{on}', 'RUNS_ON', 'Xen Orchestra API')] if on else []})
    if 'storage' in layers:
        for o in objects:
            if o['kind'] == 'sr':
                on = hostmap.get(o.get('container'))
                edges = [(f'host:{on}', 'RUNS_ON', 'Xen Orchestra API: a local SR')] if on else []
                for h in sorted({x for x in hostmap.values() if x}):
                    edges.append((f'mnt:{h}:/run/sr-mount/{o["ref"]}', 'STORED_ON', 'Xen Orchestra API: the SR mounted there'))
                out.append({'id': f'api:{row["name"]}:sr:{o["ref"]}', 'kind': 'StoragePool', 'label': o.get('name') or o['ref'], 'layer': 'storage', 'host': on,
                            'props': {'platform': 'xo', 'plugintype': o.get('type'), 'total': o.get('size'), 'used': o.get('physical_usage'), 'shared': o.get('shared'), 'connection': row['name']},
                            'edges': edges})
    return out


def problems(conn, row: dict, objects: list[dict], now: float | None = None) -> dict:
    out, host = {}, row['host'] or row['name']
    failed = [o for o in objects if o['kind'] == 'backup-run' and o.get('status') in ('failure', 'interrupted')]
    if failed:
        out[f'api-xo-backup:{row["name"]}'] = ('api-xo-backup', host, f'{len(failed)} backup job(s) on {row["name"]} did not end well at their last run',
                                              ', '.join(f'{o.get("job_name") or o["ref"]} ({o["status"]})' for o in failed[:6]), 'warn')
    for o in objects:
        if o['kind'] == 'sr' and o.get('size') and o.get('physical_usage') and o['physical_usage'] > FULL_SR * o['size']:
            out[f'api-xo-sr-full:{row["name"]}:{o["ref"]}'] = ('api-xo-sr-full', host, f'Storage repository {o.get("name") or o["ref"]} on {row["name"]} is over 90 percent full',
                                                             f'{round(100 * o["physical_usage"] / o["size"])} percent used', 'warn')
    return out
