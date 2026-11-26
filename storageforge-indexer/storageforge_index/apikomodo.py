"""Komodo through its API (roadmap section 13): servers, stacks, deployments and the containers on each server, compared with the SSH
scan and fed to the same views and the section 6 hook as the other panels (apidockhand's panel functions, shared).

Komodo's API is RPC over HTTP: every call is a POST of a JSON body to /read/NAME, /write/NAME or /execute/NAME, with the API key
and secret in the X-Api-Key and X-Api-Secret headers. Only /read/NAME is let through without an action turned on (apiconn's read_post);
a write or an execute is refused before it leaves.

    POST /read/ListApiKeys          the calling user's keys: the one in use (by its key) gives its expiry; nothing else of them is kept
    POST /read/ListUsers            admin only: when it answers, the key is an administrator's (the read-back)
    POST /read/GetPermission        the level (None, Read, Execute, Write) and specific permissions on one resource, groups included
    POST /read/ListServers          servers with their state and address
    POST /read/ListStacks           stacks with their server, state and services
    POST /read/ListDeployments      deployments with their server, image and state
    POST /read/ListContainers       the containers on one server

Field names are those of the Rust client (github.com/moghtech/komodo, client/core/rs/src/api/read and entities), fetched 2026-11-20.
Each parse_ function takes the JSON text of one answer and never raises.
"""
from __future__ import annotations

from urllib.parse import urlsplit

from .apidockhand import compare, map_nodes, problems, workloads  # noqa: F401  the panel views are the same for every panel
from .apiparse import _b, _i, _list, _load, _s

FETCHED = '2026-11-20'
SOURCES = ['https://github.com/moghtech/komodo/blob/main/client/core/rs/src/api/mod.rs (POST /read, /write, /execute; X-Api-Key and X-Api-Secret)',
           'https://github.com/moghtech/komodo/blob/main/docsite/docs/configuration/permissioning.md (None, Read, Execute, Write; Logs, Inspect, Terminal, Attach, Processes; admins)',
           'https://github.com/moghtech/komodo/tree/main/client/core/rs/src/api/read (ListApiKeys, ListUsers admin only, GetPermission, ListServers, ListStacks, ListDeployments, ListContainers)',
           'https://github.com/moghtech/komodo/tree/main/client/core/rs/src/entities (ApiKey.expires, Permission, ServerListItemInfo, StackListItemInfo, DeploymentListItemInfo, ContainerListItem)']
READ = {
    'servers': {'what': 'the servers it may see and their state'},
    'stacks': {'what': 'the stacks and their services'},
    'deployments': {'what': 'the deployments'},
    'containers': {'what': 'the containers on each server'},
}
LEVELS = ('None', 'Read', 'Execute', 'Write')
SPECIFIC_OVER = {'Terminal': True, 'Attach': False, 'Inspect': False}      # name: gives control of the host (admin). Logs and Processes only read
MAX_SERVERS = 100

GUIDE = {
    'title': 'Komodo',
    'least': 'a dedicated user storageforge that is not an administrator, in a user group given Read on all Servers, Stacks and Deployments (or on the ones it should see), with no specific permissions, and an API key of that user with an expiry',
    'role': 'Read on Servers, Stacks and Deployments, no specific permissions',
    'why_role': ('Read lets a user see a resource and its configuration and blocks every update and action. The specific permissions are left '
                 'out: Inspect exposes every container environment on a server, where secrets often are, and Terminal is a shell on the host. '
                 'Komodo hides from a user what it may not read, so a narrower Read shows fewer resources and nothing more.'),
    'scope': 'A user group with all.Server, all.Stack and all.Deployment set to Read, or Read on single resources (a regex on the id matches several). Komodo lets a service user hold the key: one that cannot sign in at all.',
    'read': {f: {'what': v['what'], 'privs': ['Read'], 'paths': ['the resources the group is given']} for f, v in READ.items()},
    'actions': {
        'redeploy': {'title': 'redeploy a stack or a deployment', 'privs': ['Execute'], 'on': 'the stacks it may redeploy', 'role': 'Execute on those stacks'},
    },
    'admin': ['admin or super admin', 'Write on any resource', 'Terminal'],
    'never': ['an administrator key, or a key of the first (super admin) user', 'Write, or Terminal and Inspect on a server', 'KOMODO_TRANSPARENT_MODE, which gives every user Read on everything'],
    'check': 'Settings, Users and User Groups in Komodo: the user is not an admin and its group holds only Read',
    'expiry': {'allowed': True, 'read_back': True, 'how': 'an API key is made with an expiry (or none); the read-back reads it from ListApiKeys, and a warning comes 30 days before it lapses'},
    'token_id_placeholder': 'K-xxxxxxxx (the key, not the secret)',
    'scope_hint': ('Nothing to choose here: the user group decides what it sees.', ''),
    'fetched': FETCHED,
}


def steps(user: str, token: str, scope, expire: int) -> list[dict]:
    import time
    when = time.strftime('%Y-%m-%d', time.gmtime(expire))
    toml = f'[[user_group]]\nname = "storageforge-read"\nusers = ["{user}"]\nall.Server = "Read"\nall.Stack = "Read"\nall.Deployment = "Read"'
    return [
        {'where': 'Komodo as an administrator: Settings, Users', 'say': f'Make a service user {user} (it cannot sign in; only its API keys work), not an admin, with no create permissions.', 'run': []},
        {'where': 'Settings, User Groups, or a resource sync', 'say': 'Make a user group with Read on all servers, stacks and deployments and no specific permissions, holding the user. As a resource sync it is the TOML below.',
         'run': [toml]},
        {'where': f'Settings, Users, {user}, API keys, New', 'say': f'Make a key named {token} that expires on {when}. Komodo shows the key and the secret once: the key is the token ID on the next screen, the secret is the token.', 'run': []},
    ]


def action_steps(action: str, spec: dict, user: str) -> list[dict]:
    return [{'where': 'Settings, User Groups, or the resource', 'say': f'To {spec["title"]}: Execute on {spec["on"]} only, for {user}. Never Write, never Terminal, never admin.', 'run': []}]


# ── parsers ───────────────────────────────────────────────────────────
def _info(x: dict) -> dict:
    return x.get('info') if isinstance(x.get('info'), dict) else {}


def parse_api_keys(text: str, key: str | None = None) -> dict:
    """{'expire', 'user_id'} of the key in use: expires is 0 for a key that never expires (ms otherwise). The hashed secrets are dropped."""
    items, _ = _list(text)
    for x in items:
        if key and x.get('key') == key:
            exp = _i(x.get('expires'))
            return {'expire': 0 if exp == 0 else (exp // 1000 if exp and exp > 1 << 33 else exp), 'user_id': _s(x.get('user_id'), 64), 'found': True}
    return {'expire': None, 'user_id': None, 'found': False}


def parse_permission(text: str) -> dict:
    doc = _load(text)
    doc = doc if isinstance(doc, dict) else {}
    level = doc.get('level') if doc.get('level') in LEVELS else None
    spec = doc.get('specific')
    return {'level': level, 'specific': sorted({s for s in spec if isinstance(s, str) and len(s) < 40}) if isinstance(spec, list) else []}


def parse_servers(text: str) -> dict:
    items, bad = _list(text)
    out = []
    for x in items[:MAX_SERVERS]:
        if not _s(x.get('id')) or not _s(x.get('name')):
            continue
        i = _info(x)
        address = _s(i.get('address'), 255) or ''
        out.append({'id': _s(x['id'], 64), 'name': _s(x['name'], 128), 'state': _s(i.get('state'), 20), 'address': address, 'host': urlsplit(address).hostname if '://' in address else (address or None),
                    'public_ip': _s(i.get('public_ip'), 64), 'version': _s(i.get('version'), 40), 'connection': 'remote', 'template': _b(x.get('template'))})
    return {'servers': out, 'unreadable': bad}


def parse_stacks(text: str) -> dict:
    items, bad = _list(text)
    out = []
    for x in items:
        if not _s(x.get('id')) or not _s(x.get('name')):
            continue
        i = _info(x)
        services = [s for s in i.get('services') or [] if isinstance(s, dict)] if isinstance(i.get('services'), list) else []
        out.append({'id': _s(x['id'], 64), 'name': _s(x['name'], 128), 'server': _s(i.get('server_id'), 64), 'state': _s(i.get('state'), 20), 'status': _s(i.get('status'), 100),
                    'services': [{'service': _s(s.get('service'), 128), 'image': _s(s.get('image'), 300), 'update_available': _b(s.get('update_available'))} for s in services[:50]]})
    return {'stacks': out, 'unreadable': bad}


def parse_deployments(text: str) -> dict:
    items, bad = _list(text)
    out = []
    for x in items:
        if not _s(x.get('id')) or not _s(x.get('name')):
            continue
        i = _info(x)
        out.append({'id': _s(x['id'], 64), 'name': _s(x['name'], 128), 'container': _s(i.get('custom_name'), 128) or _s(x['name'], 128), 'server': _s(i.get('server_id'), 64),
                    'state': _s(i.get('state'), 20), 'image': _s(i.get('image'), 300), 'update_available': _b(i.get('update_available'))})
    return {'deployments': out, 'unreadable': bad}


def parse_containers(text: str) -> dict:
    items, bad = _list(text)
    return {'containers': [{'id': _s(x.get('id'), 64), 'name': _s(x.get('name'), 255).lstrip('/'), 'image': _s(x.get('image'), 300),
                            'state': (_s(x.get('state'), 20) or '').lower() or None, 'status': _s(x.get('status'), 100)} for x in items if _s(x.get('name'))], 'unreadable': bad}


# ── the read-back ─────────────────────────────────────────────────────
def judge(admin: bool, perms: list[tuple[str, str, dict]], reads: dict, actions: list[str] | None = None, token: dict | None = None) -> dict:
    """perms: (resource type, name, {'level', 'specific'}) for each resource looked at."""
    from .apireadback import verdict
    features = {f: {'ok': admin or bool(reads.get(f)), 'what': v['what'], 'on': reads.get(f) or [], 'add': 'Read on these resources for the StorageForge user group'} for f, v in READ.items()}
    wanted = {p for a in actions or [] for p in (GUIDE['actions'].get(a) or {}).get('privs', [])}
    over, extra = [], []
    if admin:
        over.append({'path': 'Komodo', 'priv': 'admin: every resource and every user', 'admin': True})
    for kind, name, p in perms:
        lv = p.get('level')
        if lv in ('Execute', 'Write') and not (lv == 'Execute' and 'Execute' in wanted and kind == 'Stack'):
            over.append({'path': f'{kind} {name}', 'priv': lv, 'admin': lv == 'Write' and kind == 'Server'})
        for s in p.get('specific') or []:
            if s in SPECIFIC_OVER:
                over.append({'path': f'{kind} {name}', 'priv': s, 'admin': SPECIFIC_OVER[s]})
            else:
                extra.append({'path': f'{kind} {name}', 'priv': s})
    return verdict('komodo', features, over, token, extra=extra, actions=actions)


def readback(client, row: dict) -> dict:
    from .apiconn import ApiError
    keys = parse_api_keys(client.post_read('/read/ListApiKeys'), row['token_id'])
    try:
        client.post_read('/read/ListUsers', {})
        admin = True
    except ApiError:
        admin = False
    reads, perms = {}, []
    servers = parse_servers(client.post_read('/read/ListServers'))['servers']
    stacks = parse_stacks(client.post_read('/read/ListStacks'))['stacks']
    deployments = parse_deployments(client.post_read('/read/ListDeployments'))['deployments']
    if servers:
        reads['servers'] = [s['name'] for s in servers]
        try:
            client.post_read('/read/ListContainers', {'server': servers[0]['id']})
            reads['containers'] = [servers[0]['name']]
        except ApiError:
            pass
    if stacks:
        reads['stacks'] = [s['name'] for s in stacks]
    if deployments:
        reads['deployments'] = [d['name'] for d in deployments]
    for kind, items in (('Server', servers), ('Stack', stacks), ('Deployment', deployments)):
        for x in items[:30]:
            try:
                perms.append((kind, x['name'], parse_permission(client.post_read('/read/GetPermission', {'target': {'type': kind, 'id': x['id']}}))))
            except ApiError:
                pass
    out = judge(admin, perms, reads, row.get('actions'), {'expire': keys['expire'], 'enable': None})
    if not keys['found']:
        out['notes'].append('the key in use is not among the calling user\'s keys: is the token ID the key Komodo showed?')
    return {**out, 'paths': {f'{k} {n}': {p.get('level') or '?': True, **{s: True for s in p.get('specific') or []}} for k, n, p in perms}}


# ── the read ──────────────────────────────────────────────────────────
def read(client, row: dict, rb: dict) -> tuple[list, list]:
    from .apiconn import ApiError
    objs, skipped = [], []
    servers = parse_servers(client.post_read('/read/ListServers'))['servers']
    names = {s['id']: s['name'] for s in servers}
    stacks = parse_stacks(client.post_read('/read/ListStacks'))['stacks']
    deployments = parse_deployments(client.post_read('/read/ListDeployments'))['deployments']
    for s in servers:
        objs.append(('environment', s['id'], s))
        if s.get('template') or s.get('state') not in (None, 'Ok'):
            continue
        try:
            for c in parse_containers(client.post_read('/read/ListContainers', {'server': s['id']}))['containers']:
                stack = next((st['name'] for st in stacks if st['server'] == s['id'] and c['name'].startswith(f'{st["name"]}-')), None)
                dep = next((d['name'] for d in deployments if d['server'] == s['id'] and d['container'] == c['name']), None)
                objs.append(('container', f'{s["id"]}/{c["name"]}', {**c, 'environment': s['id'], 'environment_name': s['name'], 'stack': stack, 'deployment': dep}))
        except ApiError as exc:
            skipped.append(f'{s["name"]} containers: {exc}'[:200])
    objs += [('stack', st['id'], {**st, 'environment': st['server'], 'environment_name': names.get(st['server'])}) for st in stacks]
    objs += [('deployment', d['id'], {**d, 'environment': d['server'], 'environment_name': names.get(d['server'])}) for d in deployments]
    if not servers:
        skipped.append('servers: the key sees none (Read on servers)')
    return objs, list(dict.fromkeys(skipped))
