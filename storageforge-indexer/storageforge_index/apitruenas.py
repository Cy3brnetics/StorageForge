"""TrueNAS through its middleware API (roadmap section 13): pools, datasets, snapshot tasks, replication, shares, apps and alerts, read
from the middleware rather than from files the appliance keeps out of reach.

The API is JSON-RPC 2.0 over a WebSocket at /api/current (TrueNAS 25.04 and later; the REST API is deprecated and goes in a later
release). apiconn.WsClient opens it on the pinned TLS connection and logs in with auth.login_ex, mechanism API_KEY_PLAIN, the user
name and the key: the key crosses once, inside TLS, and TrueNAS itself revokes a user-linked key that is ever sent over plain HTTP.

    auth.me                       the session's user, with privilege.roles: what the key can do (the read-back)
    api_key.my_keys               the keys of that user: the one in use (by the number before its dash) gives expires_at and revoked
    system.info                   the version and host name
    pool.query                    pools: name, status, healthy, size, allocated, free
    pool.dataset.query            datasets (flat list): name, pool, type, used, available, mountpoint, encrypted
    pool.snapshot.query           individual snapshots and selected ZFS properties
    pool.snapshottask.query       periodic snapshot tasks and the state of their last run
    replication.query             replication tasks and the state of their last run (credentials in it are dropped)
    sharing.smb.query, sharing.nfs.query   shares
    app.query                     apps with their state, version and containers
    alert.list                    the alerts TrueNAS raised itself

Field names are those of the API reference for TrueNAS 25.10.5 (api.truenas.com/v25.10, fetched 2026-11-20). Each parse_ function takes
the JSON text of one result and never raises: what it cannot read is dropped, as a scan's parsers do.

Reads use the documented TrueNAS 25.10 middleware methods.
"""
from __future__ import annotations

import json
import re
import time

from .apiparse import _b, _i, _list, _load, _s, _when

FETCHED = '2026-11-20'
SOURCES = ['https://api.truenas.com/v25.10/jsonrpc.html (JSON-RPC 2.0 over WebSocket, TrueNAS API v25.10.5)',
           'https://api.truenas.com/v25.10/rbac.html (roles, privileges, READONLY_ADMIN, REPLICATION_ADMIN, custom privileges deprecated)',
           'https://api.truenas.com/v25.10/api_methods_auth.login_ex.html (API_KEY_PLAIN) and api_methods_auth.me.html',
           'https://api.truenas.com/v25.10/api_methods_api_key.create.html and api_methods_api_key.my_keys.html (expires_at, revoked)',
           'https://api.truenas.com/v25.10/api_methods_user.create.html and api_methods_privilege.create.html',
           'https://www.truenas.com/docs/scale/25.10/scaletutorials/toptoolbar/managingapikeys/ (user-linked keys, revoked over HTTP, expiry)']
MAX_DATASETS = 5000
MAX_SNAPSHOTS = 5000

# what each feature reads, and the individual role READONLY_ADMIN gives it (READONLY_ADMIN expands into every *_READ role)
READ = {
    'pools': {'roles': ['POOL_READ'], 'what': 'pools and their health'},
    'datasets': {'roles': ['DATASET_READ'], 'what': 'datasets, their space and mount points'},
    'snapshots': {'roles': ['SNAPSHOT_READ'], 'what': 'individual ZFS snapshots'},
    'snapshot-tasks': {'roles': ['SNAPSHOT_TASK_READ'], 'what': 'periodic snapshot tasks and their last run'},
    'replication': {'roles': ['REPLICATION_TASK_READ'], 'what': 'replication tasks and their last run'},
    'shares': {'roles': ['SHARING_SMB_READ', 'SHARING_NFS_READ'], 'what': 'SMB and NFS shares'},
    'apps': {'roles': ['APPS_READ'], 'what': 'apps and their containers'},
}
# roles that give control of the appliance itself, its accounts, keys, privileges or system: never needed
ADMIN = re.compile(r'FULL_ADMIN|ACCOUNT_WRITE|API_KEY_WRITE|PRIVILEGE_WRITE|AUTH_SESSIONS_WRITE|SSH_WRITE|SYSTEM_[A-Z_]+_WRITE|DIRECTORY_SERVICE_WRITE|KMIP_WRITE|SUPPORT_WRITE')
REPLICATION_ADMIN = ['REPLICATION_ADMIN', 'KEYCHAIN_CREDENTIAL_WRITE', 'REPLICATION_TASK_CONFIG_WRITE', 'REPLICATION_TASK_WRITE', 'SNAPSHOT_TASK_WRITE', 'SNAPSHOT_WRITE']

GUIDE = {
    'title': 'TrueNAS',
    'least': 'a dedicated local user storageforge with no password, in a group of its own, that group in a privilege granting only READONLY_ADMIN with no web shell, and a user-linked API key with an expiry date',
    'role': 'READONLY_ADMIN',
    'why_role': ('READONLY_ADMIN expands into every *_READ role: it can call the query and get methods and change nothing. TrueNAS 25.10 '
                 'deprecates privileges built from individual roles (they go in TrueNAS 28), so the narrowest it keeps is this predefined '
                 'role. Fields marked secret (credentials, passwords) come back redacted to any session without FULL_ADMIN.'),
    'scope': 'TrueNAS has no scope narrower than the whole appliance for a role: the key reads everything READONLY_ADMIN reads. The user is local, so it never reaches a directory service.',
    'read': {f: {'what': v['what'], 'privs': v['roles'], 'paths': ['the appliance']} for f, v in READ.items()},
    'actions': {
        'snapshot': {'title': 'take and delete snapshots, run replication', 'privs': REPLICATION_ADMIN, 'on': 'the appliance (TrueNAS has no narrower scope)', 'role': 'REPLICATION_ADMIN'},
    },
    'admin': ['FULL_ADMIN', 'ACCOUNT_WRITE', 'API_KEY_WRITE', 'PRIVILEGE_WRITE', 'SYSTEM_*_WRITE', 'SSH_WRITE', 'web shell'],
    'never': ['root, truenas_admin or admin, or a key of theirs (refused here: they hold FULL_ADMIN)', 'FULL_ADMIN or SHARING_ADMIN',
              'the web shell on the privilege', 'a key sent over plain HTTP: TrueNAS revokes it'],
    'check': "midclt call auth.me (run as the storageforge user's key) or Credentials, Groups, Privileges in the web interface",
    'expiry': {'allowed': True, 'read_back': True, 'how': 'api_key.create takes expires_at (or clear Non-expiring in the web interface); the read-back reads it from api_key.my_keys, and a warning comes 30 days before it lapses'},
    'token_id_placeholder': 'storageforge',
    'scope_hint': ('Nothing to choose: a TrueNAS role covers the whole appliance.', ''),
    'fetched': FETCHED,
}


def steps(user: str, token: str, scope, expire: int) -> list[dict]:
    """How to make the user, its group's privilege and the key. Commands are midclt calls in a root shell on TrueNAS (System, Shell),
    as the API reference names the methods and fields."""
    from .apiguide import _q
    when = time.strftime('%Y-%m-%dT00:00:00Z', time.gmtime(expire))
    group = user
    create_user = json.dumps({'username': user, 'full_name': 'StorageForge: reads through the API', 'group_create': True, 'password_disabled': True,
                              'smb': False, 'shell': '/usr/sbin/nologin'})
    shape = '{name: "StorageForge read", local_groups: [.id], roles: ["READONLY_ADMIN"], web_shell: false}'
    privilege = (f'midclt call privilege.create "$(midclt call group.query {_q(json.dumps([["group", "=", group]]))} {_q(json.dumps({"get": True}))} '
                 f'| jq -c {_q(shape)})"')
    key = json.dumps({'name': token, 'username': user, 'expires_at': when})
    return [
        {'where': 'System, Shell in the TrueNAS web interface (a root shell)', 'say': 'Make a local user for StorageForge with no password and no shell, in a new group of its own name.',
         'run': [f'midclt call user.create {_q(create_user)}']},
        {'where': 'the same shell', 'say': 'Give that group a privilege with only READONLY_ADMIN and no web shell. The same in the web interface: Credentials, Groups, Privileges, Add.',
         'run': [privilege]},
        {'where': 'the same shell, or Credentials, Users, storageforge, View API Keys, Add', 'say': f'Make a user-linked API key for it with an expiry date ({when[:10]}, a year from now). The key is shown once, in the "key" field: copy it for the next screen. Give it only over HTTPS: TrueNAS revokes a key that crosses plain HTTP.',
         'run': [f'midclt call api_key.create {_q(key)}']},
        {'where': 'the same shell', 'say': 'Check the privilege: only READONLY_ADMIN, web_shell false. StorageForge reads the same back with auth.me after you enter the key.',
         'run': [f'midclt call privilege.query {_q(json.dumps([["name", "=", "StorageForge read"]]))}']},
    ]


def action_steps(action: str, spec: dict, user: str) -> list[dict]:
    return [{'where': 'Credentials, Groups, Privileges in the TrueNAS web interface', 'say': (
        f'To {spec["title"]}: add REPLICATION_ADMIN to the StorageForge privilege. It also lets the key change replication tasks and keychain '
        'credentials (SSH keypairs used by replication): TrueNAS 25.10 no longer lets a privilege hold SNAPSHOT_WRITE alone, so this is its narrowest. Never FULL_ADMIN.'),
        'run': []}]


# ── parsers: the JSON text of one result each ─────────────────────────
def _prop(v):
    """A ZFS property as pool.dataset.query gives it: {"parsed": ..., "rawvalue": ...}, or a bare value."""
    if isinstance(v, dict):
        return _i(v.get('parsed')) if _i(v.get('parsed')) is not None else _i(v.get('rawvalue'))
    return _i(v)


def parse_me(text: str) -> dict:
    """{'user', 'roles', 'web_shell', 'unreadable'} from auth.me. privilege.roles is a list (or a {"$set": [...]} from the encoder)."""
    doc = _load(text)
    if not isinstance(doc, dict):
        return {'user': None, 'roles': [], 'web_shell': None, 'unreadable': True}
    priv = doc.get('privilege') if isinstance(doc.get('privilege'), dict) else {}
    roles = priv.get('roles')
    if isinstance(roles, dict):
        roles = roles.get('$set')
    roles = sorted({r[:64] for r in roles if isinstance(r, str) and re.fullmatch(r'[A-Z][A-Z0-9_]{0,63}', r)}) if isinstance(roles, list) else []
    return {'user': _s(doc.get('pw_name'), 64), 'roles': roles, 'web_shell': _b(priv.get('web_shell')), 'unreadable': not isinstance(doc.get('privilege'), dict)}


def parse_keys(text: str) -> dict:
    items, bad = _list(text)
    out = []
    for x in items:
        if _i(x.get('id')) is None:
            continue
        exp = x.get('expires_at')
        out.append({'id': _i(x['id']), 'name': _s(x.get('name'), 200), 'username': _s(x.get('username'), 64),
                    'expires_at': 0 if exp is None else _when(exp), 'revoked': _b(x.get('revoked')), 'revoked_reason': _s(x.get('revoked_reason'), 200)})
    return {'keys': out, 'unreadable': bad}


def parse_system(text: str) -> dict:
    doc = _load(text)
    doc = doc if isinstance(doc, dict) else {}
    return {'version': _s(doc.get('version'), 80), 'hostname': _s(doc.get('hostname'), 128), 'uptime_seconds': _i(doc.get('uptime_seconds'))}


def parse_pools(text: str) -> dict:
    items, bad = _list(text)
    out = []
    for x in items:
        if not _s(x.get('name')):
            continue
        out.append({'name': _s(x['name'], 128), 'status': _s(x.get('status'), 20), 'healthy': _b(x.get('healthy')), 'size': _i(x.get('size')),
                    'allocated': _i(x.get('allocated')), 'free': _i(x.get('free')), 'path': _s(x.get('path'), 300), 'guid': _s(x.get('guid'), 40),
                    'status_detail': _s(x.get('status_detail'), 300)})
    return {'pools': out, 'unreadable': bad}


def parse_datasets(text: str) -> dict:
    items, bad = _list(text)
    out = []
    for x in items[:MAX_DATASETS]:
        if not _s(x.get('name')):
            continue
        out.append({'name': _s(x['name'], 300), 'pool': _s(x.get('pool'), 128), 'type': _s(x.get('type'), 20), 'used': _prop(x.get('used')),
                    'available': _prop(x.get('available')), 'mountpoint': _s(x.get('mountpoint'), 500), 'encrypted': _b(x.get('encrypted'))})
    return {'datasets': out, 'unreadable': bad, 'cut': len(items) > MAX_DATASETS}


def parse_snapshots(text: str) -> dict:
    items, bad = _list(text)
    out = []
    for x in items[:MAX_SNAPSHOTS]:
        name, dataset = _s(x.get('name'), 300), _s(x.get('dataset'), 255)
        if not dataset or not name or not name.startswith(dataset + '@') or not name.rpartition('@')[2]:
            continue
        properties = x.get('properties')
        properties = properties if isinstance(properties, dict) else {}
        out.append({'name': name, 'dataset': dataset, 'pool': _s(x.get('pool'), 128),
                    'created': _prop(properties.get('creation')), 'used': _prop(properties.get('used')),
                    'referenced': _prop(properties.get('referenced'))})
    return {'snapshots': out, 'unreadable': bad, 'cut': len(items) > MAX_SNAPSHOTS}


def _state(v) -> dict:
    v = v if isinstance(v, dict) else {}
    return {'state': _s(v.get('state'), 40), 'at': _when(v.get('datetime')), 'error': _s(v.get('error'), 300)}


def parse_snapshot_tasks(text: str) -> dict:
    items, bad = _list(text)
    out = []
    for x in items:
        if _i(x.get('id')) is None or not _s(x.get('dataset')):
            continue
        out.append({'id': _i(x['id']), 'dataset': _s(x['dataset'], 300), 'recursive': _b(x.get('recursive')), 'enabled': _b(x.get('enabled')),
                    'keep': f'{_i(x.get("lifetime_value"))} {_s(x.get("lifetime_unit"), 10)}' if _i(x.get('lifetime_value')) is not None else None,
                    'last': _state(x.get('state'))})
    return {'tasks': out, 'unreadable': bad}


def parse_replications(text: str) -> dict:
    """Replication tasks. Their ssh_credentials (a keypair) are never copied: TrueNAS redacts the secret half for a read-only session,
    and this drops the whole entry anyway."""
    items, bad = _list(text)
    out = []
    for x in items:
        if _i(x.get('id')) is None:
            continue
        sources = [s[:300] for s in x.get('source_datasets') or [] if isinstance(s, str)][:50] if isinstance(x.get('source_datasets'), list) else []
        out.append({'id': _i(x['id']), 'name': _s(x.get('name'), 200), 'direction': _s(x.get('direction'), 10), 'transport': _s(x.get('transport'), 20),
                    'source_datasets': sources, 'target_dataset': _s(x.get('target_dataset'), 300), 'enabled': _b(x.get('enabled')), 'last': _state(x.get('state'))})
    return {'replications': out, 'unreadable': bad}


def parse_shares(text: str, protocol: str = 'smb') -> dict:
    items, bad = _list(text)
    out = []
    for x in items:
        if not _s(x.get('path')):
            continue
        out.append({'protocol': protocol, 'name': _s(x.get('name'), 128) if protocol == 'smb' else None, 'path': _s(x['path'], 500), 'enabled': _b(x.get('enabled')),
                    'readonly': _b(x.get('readonly') if protocol == 'smb' else x.get('ro')), 'guest': _b(x.get('guestok')) if protocol == 'smb' else None,
                    'networks': [n[:60] for n in x.get('networks') or [] if isinstance(n, str)][:50] if protocol == 'nfs' and isinstance(x.get('networks'), list) else []})
    return {'shares': out, 'unreadable': bad}


def parse_apps(text: str) -> dict:
    items, bad = _list(text)
    out = []
    for x in items:
        if not _s(x.get('name')):
            continue
        work = x.get('active_workloads') if isinstance(x.get('active_workloads'), dict) else {}
        details = [d for d in work.get('container_details') or [] if isinstance(d, dict)] if isinstance(work.get('container_details'), list) else []
        out.append({'name': _s(x['name'], 128), 'state': _s(x.get('state'), 20), 'version': _s(x.get('human_version') or x.get('version'), 60),
                    'upgrade_available': _b(x.get('upgrade_available')), 'custom': _b(x.get('custom_app')), 'containers': _i(work.get('containers')),
                    'services': [{'service': _s(d.get('service_name'), 128), 'image': _s(d.get('image'), 300), 'state': _s(d.get('state'), 20)} for d in details[:50]]})
    return {'apps': out, 'unreadable': bad}


def parse_alerts(text: str) -> dict:
    items, bad = _list(text)
    out = []
    for x in items:
        if not _s(x.get('uuid')):
            continue
        out.append({'uuid': _s(x['uuid'], 64), 'klass': _s(x.get('klass'), 80), 'level': _s(x.get('level'), 20), 'text': _s(x.get('formatted'), 500),
                    'dismissed': _b(x.get('dismissed')), 'at': _when(x.get('datetime'))})
    return {'alerts': out, 'unreadable': bad}


# ── the read-back ─────────────────────────────────────────────────────
def judge(roles: list[str], web_shell, actions: list[str] | None = None, token: dict | None = None) -> dict:
    from .apireadback import verdict
    have = set(roles)
    full_read = 'READONLY_ADMIN' in have or 'FULL_ADMIN' in have
    features = {}
    for f, need in READ.items():
        ok = full_read or all(r in have for r in need['roles'])
        features[f] = {'ok': ok, 'what': need['what'], 'on': ['the appliance'] if ok else [],
                       'add': f'READONLY_ADMIN on the privilege of the StorageForge group (it gives {", ".join(need["roles"])})'}
    allowed = {r for a in actions or [] for r in (GUIDE['actions'].get(a) or {}).get('privs', [])}
    over = [{'path': 'the appliance', 'priv': r, 'admin': bool(ADMIN.fullmatch(r))} for r in sorted(have)
            if r != 'READONLY_ADMIN' and not r.endswith('_READ') and r not in allowed]
    if web_shell:
        over.append({'path': 'the appliance', 'priv': 'web shell', 'admin': True})
    extra = []
    return verdict('truenas', features, over, token, extra=extra, actions=actions)


def key_number(secret: str | None) -> int | None:
    """The number before the dash of a TrueNAS key (ID-SECRET): which of the user's keys is in use. Not secret: api_key.my_keys lists it."""
    m = re.match(r'(\d{1,12})-', secret or '')
    return int(m.group(1)) if m else None


def readback(client, row: dict) -> dict:
    from .apiconn import ApiError
    me = parse_me(json.dumps(client.call('auth.me')))
    if me['unreadable']:
        raise ApiError('TrueNAS answered auth.me without the privilege of the session')
    token = {'expire': None, 'enable': None}
    try:
        keys = parse_keys(json.dumps(client.call('api_key.my_keys')))['keys']
        mine = next((k for k in keys if k['id'] == key_number(client._secret)), None)
        if mine:
            token = {'expire': mine['expires_at'], 'enable': None if mine['revoked'] is None else not mine['revoked'], 'name': mine['name']}
    except ApiError:
        pass                     # the roles above still stand
    out = judge(me['roles'], me['web_shell'], row.get('actions'), token)
    if me['user'] and me['user'] != row['token_id']:
        out['notes'].append(f'the key belongs to {me["user"]}, not {row["token_id"]}')
    return {**out, 'paths': {'the appliance': {r: True for r in me['roles']}}}


# ── the read ──────────────────────────────────────────────────────────
CALLS = (('pools', 'pool.query', parse_pools, 'pool', 'pools', 'name'),
         ('datasets', 'pool.dataset.query', parse_datasets, 'dataset', 'datasets', 'name'),
         ('snapshots', 'pool.snapshot.query', parse_snapshots, 'snapshot', 'snapshots', 'name'),
         ('snapshot-tasks', 'pool.snapshottask.query', parse_snapshot_tasks, 'snapshot-task', 'tasks', 'id'),
         ('replication', 'replication.query', parse_replications, 'replication', 'replications', 'id'),
         ('apps', 'app.query', parse_apps, 'app', 'apps', 'name'))


def read(client, row: dict, rb: dict) -> tuple[list, list]:
    from .apiconn import ApiError
    objs, skipped = [('platform', 'version', parse_system(json.dumps(client.call('system.info'))))], []
    feats = rb.get('features') or {}
    for feature, method, parse, kind, key, ref in CALLS:
        if not feats.get(feature, {}).get('ok'):
            skipped.append(f'{feature}: the key lacks {", ".join(READ[feature]["roles"])}')
            continue
        try:
            params = ([], {'limit': MAX_SNAPSHOTS + 1, 'extra': {'properties': ['creation', 'used', 'referenced']}}) if feature == 'snapshots' else ()
            got = parse(json.dumps(client.call(method, *params)))
        except ApiError as exc:
            skipped.append(f'{feature}: {exc}'[:200])
            continue
        if got.get('unreadable'):
            skipped.append(f'{feature}: the list was not readable')
        if got.get('cut'):
            limit = MAX_SNAPSHOTS if feature == 'snapshots' else MAX_DATASETS
            skipped.append(f'more than {limit} {feature}: the rest was not read')
        objs += [(kind, str(x[ref]), x) for x in got[key]]
    if feats.get('shares', {}).get('ok'):
        for proto, method in (('smb', 'sharing.smb.query'), ('nfs', 'sharing.nfs.query')):
            try:
                objs += [('share', f'{proto}:{s["path"]}:{s["name"] or ""}', s) for s in parse_shares(json.dumps(client.call(method)), proto)['shares']]
            except ApiError as exc:
                skipped.append(f'{proto} shares: {exc}'[:200])
    try:
        objs += [('alert', a['uuid'], a) for a in parse_alerts(json.dumps(client.call('alert.list')))['alerts']]
    except ApiError as exc:
        skipped.append(f'alerts: {exc}'[:200])
    return objs, list(dict.fromkeys(skipped))


# ── beside the scan ───────────────────────────────────────────────────
def _scanned_pools(conn, host: str) -> dict | None:
    from .payloads import parse_zpool_status
    raw = conn.scalar('SELECT inventory_json FROM hosts WHERE hostname = :h', {'h': host})
    if raw is None:
        return None
    inv = (raw if isinstance(raw, dict) else json.loads(raw or '{}')) or {}
    return {p['name']: p for p in parse_zpool_status(inv['zpool_status'])} if inv.get('zpool_status') else {}


def compare(conn, row: dict, objects: list[dict]) -> dict:
    """Each pool the middleware reads against what `zpool status` printed at the last SSH scan of the same host, and each app against
    the Compose projects the scan's Docker reading lists (TrueNAS runs an app as the project ix-NAME). Compared, not merged."""
    out = {'pools': [], 'apps': []}
    host = row.get('host')
    if not host:
        return out
    scanned = _scanned_pools(conn, host)
    if scanned is not None:
        api = {o['ref']: o for o in objects if o['kind'] == 'pool'}
        for name in sorted(set(api) | set(scanned)):
            a, s = api.get(name), scanned.get(name)
            if a and s:
                differs = [{'field': 'state', 'api': a.get('status'), 'ssh': s.get('state')}] if (a.get('status') or '') != (s.get('state') or '') else []
                out['pools'].append({'pool': name, 'seen_by': ['api', 'ssh'], 'differs': differs})
            else:
                out['pools'].append({'pool': name, 'seen_by': ['api'] if a else ['ssh'], 'differs': [],
                                     'why': 'zpool status at the last scan did not list it' if a else 'the middleware did not list it: the key may not read pools'})
    from .runtimes import docker
    projects = {s['project'] for h in docker.listing(conn, host) for s in h['stacks'] if s.get('project')}
    for o in objects:
        if o['kind'] == 'app':
            out['apps'].append({'app': o['ref'], 'state': o.get('state'), 'project': f'ix-{o["ref"]}', 'seen_by': ['api', 'ssh'] if f'ix-{o["ref"]}' in projects else ['api']})
    return out


def workloads(conn, row: dict, objects: list[dict]) -> list[dict]:
    return [{'host': row.get('host'), 'runtime': 'truenas-app', 'kind': 'app', 'name': o['ref'], 'state': (o.get('state') or '').lower() or None,
             'stack': f'ix-{o["ref"]}', 'api': {'version': o.get('version'), 'upgrade_available': o.get('upgrade_available')}} for o in objects if o['kind'] == 'app']


def map_nodes(conn, row: dict, objects: list[dict], hosts: dict, layers) -> list[dict]:
    """Pools in the storage layer (beside the scan's own pool node when it draws one), apps in the workloads layer."""
    host = row.get('host')
    out = []
    if 'storage' in layers:
        for o in objects:
            if o['kind'] == 'pool':
                props = {'platform': 'truenas', 'status': o.get('status'), 'healthy': o.get('healthy'), 'total': o.get('size'), 'used': o.get('allocated'), 'connection': row['name']}
                out.append({'attach': f'pool:{host}:{o["ref"]}' if host else None, 'id': f'api:{row["name"]}:pool:{o["ref"]}', 'kind': 'StoragePool', 'label': o['ref'],
                            'layer': 'storage', 'host': host, 'props': props, 'edges': [(f'host:{host}', 'RUNS_ON', 'TrueNAS API')] if host else []})
    if 'workloads' in layers:
        for o in objects:
            if o['kind'] == 'app':
                out.append({'id': f'api:{row["name"]}:app:{o["ref"]}', 'kind': 'Container', 'label': o['ref'], 'layer': 'workloads', 'host': host,
                            'props': {'runtime': 'truenas-app', 'state': (o.get('state') or '').lower(), 'version': o.get('version'), 'connection': row['name']},
                            'edges': [(f'host:{host}', 'RUNS_ON', 'TrueNAS API: an app')] if host else []})
    return out


def problems(conn, row: dict, objects: list[dict], now: float | None = None) -> dict:
    out, host = {}, row['host'] or row['name']
    for o in objects:
        if o['kind'] == 'pool' and o.get('healthy') is False:
            out[f'api-truenas-pool:{row["name"]}:{o["ref"]}'] = ('api-truenas-pool', host, f'Pool {o["ref"]} on {row["name"]} is {o.get("status") or "not healthy"}',
                                                                o.get('status_detail') or 'TrueNAS says the pool is not healthy.', 'crit')
        if o['kind'] in ('replication', 'snapshot-task') and (o.get('last') or {}).get('state') in ('ERROR', 'FAILED'):
            what = 'Replication' if o['kind'] == 'replication' else 'The snapshot task'
            out[f'api-truenas-task:{row["name"]}:{o["kind"]}:{o["ref"]}'] = ('api-truenas-task', host, f'{what} {o.get("name") or o.get("dataset") or o["ref"]} on {row["name"]} failed',
                                                                           (o['last'].get('error') or 'TrueNAS says the last run failed.')[:300], 'warn')
    loud = [o for o in objects if o['kind'] == 'alert' and not o.get('dismissed') and o.get('level') in ('CRITICAL', 'ALERT', 'EMERGENCY', 'ERROR')]
    if loud:
        out[f'api-truenas-alerts:{row["name"]}'] = ('api-truenas-alerts', host, f'TrueNAS {row["name"]} raised {len(loud)} alert(s)',
                                                   '; '.join((o.get('text') or o.get('klass') or '')[:120] for o in loud[:4]), 'warn')
    return out
