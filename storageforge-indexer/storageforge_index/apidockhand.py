"""Dockhand through its API (roadmap section 13): environments, the stacks and containers in each, and which containers Dockhand itself
manages, for the Workloads view and section 6's "externally managed" detection (apiviews.managed_by is the hook).

    GET /api/license                  whether roles are enforced (an enterprise key) and, by whether the key comes back, whether the token
                                      may manage the license: the read-back. The license key itself is never kept
    GET /api/auth/tokens              the user's tokens with expiresAt; the one in use is found by its prefix, the 8 characters after dh_,
                                      which Dockhand shows beside each token. Nothing else of the list is kept
    GET /api/users                    answered only to a token holding users:view, which lists every account: said, not kept
    GET /api/environments             the environments the token may see (filtered by RBAC with an enterprise key)
    GET /api/containers?env=ID        each environment's containers
    GET /api/stacks?env=ID            each environment's Compose stacks, with how Dockhand came to know each (sourceType)
    GET /api/images?env=ID            image identities, tags and sizes
    GET /api/volumes?env=ID           named volumes and their drivers and mount points

The token is a Bearer token (dh_ and 43 characters) of the user it was made by; Dockhand gives a token no way to read its own
permissions, so the read-back says what it can tell and says plainly what it cannot. A Hawser agent token is never used: it is an
agent's connection, and Dockhand never returns one (hasHawserToken says one is stored).

Field names are those of the @openapi blocks in Dockhand's own routes (github.com/Finsys/dockhand, src/routes/api/..., version
1.0.58, fetched 2026-11-20). Each parse_ function takes the JSON text of one answer and never raises.
"""
from __future__ import annotations

import re

from .apiparse import _b, _i, _list, _load, _s, _when

FETCHED = '2026-11-20'
SOURCES = ['https://github.com/Finsys/dockhand/blob/main/src/lib/server/api-tokens.ts (dh_ Bearer tokens, expiry, the token is its user, free edition: everyone is effectively admin)',
           'https://github.com/Finsys/dockhand/blob/main/src/routes/api/auth/tokens/+server.ts (making a token needs a session and the password; expiresAt)',
           'https://github.com/Finsys/dockhand/blob/main/src/lib/server/db/drizzle.ts (the Admin, Operator and Viewer roles and their permissions)',
           'https://github.com/Finsys/dockhand/blob/main/src/routes/api/environments/+server.ts, containers/+server.ts, stacks/+server.ts, license/+server.ts (fields)',
           'https://github.com/Finsys/dockhand/blob/main/src/lib/server/license-state-core.ts (roles are enforced only with an enterprise key)']
READ = {
    'environments': {'perm': 'environments:view', 'what': 'the environments (Docker hosts) it may see'},
    'containers': {'perm': 'containers:view', 'what': 'the containers in each environment'},
    'images': {'perm': 'images:view', 'what': 'the images in each environment'},
    'volumes': {'perm': 'volumes:view', 'what': 'the volumes in each environment'},
    'stacks': {'perm': 'stacks:view', 'what': 'the Compose stacks in each environment, and which Dockhand manages'},
}
MAX_ENVIRONMENTS = 100

GUIDE = {
    'title': 'Dockhand',
    'least': 'Dockhand with an enterprise key, so roles are enforced; a dedicated user storageforge given only a role with view on environments, containers, stacks, images and volumes, scoped to the environments it should see; and an API token of that user with an expiry date',
    'role': 'StorageForge read (view on environments, containers, stacks, images, volumes)',
    'why_role': ('Dockhand enforces roles only with an enterprise key: without one every signed-in user, and so every token, has full access. '
                 'The built-in Viewer role also gives containers inspect and logs; inspect shows each container environment, where secrets often '
                 'are, so a role of its own without inspect and logs is narrower. Viewer is the fallback.'),
    'scope': 'A role can be global or tied to one environment: give the role once per environment StorageForge should see. A token carries its user exactly: the user is the boundary.',
    'read': {f: {'what': v['what'], 'privs': [v['perm']], 'paths': ['the environments the role is given on']} for f, v in READ.items()},
    'actions': {
        'redeploy': {'title': 'redeploy or update a stack', 'privs': ['stacks:edit', 'stacks:start'], 'on': 'the one environment', 'role': 'a role with stack edit and start on that environment'},
    },
    'admin': ['the Admin role', 'users, settings, license or secrets permissions', 'any token on the free edition'],
    'never': ['the Admin role or a token of an administrator', 'a Hawser agent token: it is the agent connection, not an API key',
              'Dockhand without an enterprise key: every user is an administrator there, so the read-back raises a finding for it',
              'plain HTTP: Dockhand serves HTTP on port 3000 by itself; put it behind an HTTPS proxy'],
    'check': 'Settings, Authentication, Roles and Users in Dockhand: the user holds only the StorageForge role',
    'expiry': {'allowed': True, 'read_back': True, 'how': 'a token is made with an expiry date (expiresAt); the read-back reads it from the token list, and a warning comes 30 days before it lapses'},
    'token_id_placeholder': 'storageforge',
    'scope_hint': ('The environments it should see, by name, separated by spaces (only for the guide).', 'docker1 docker2'),
    'fetched': FETCHED,
}


def steps(user: str, token: str, scope, expire: int) -> list[dict]:
    import time
    envs = [e for e in (scope if isinstance(scope, list) else str(scope or '').split()) if e] or ['<environment>']
    when = time.strftime('%Y-%m-%d', time.gmtime(expire))
    return [
        {'where': 'Dockhand, Settings, License', 'say': 'Check that an enterprise key is active. Without one, Dockhand gives every user full access and no role can narrow a token: StorageForge then reads it, but raises a finding that says so.', 'run': []},
        {'where': 'Settings, Authentication, Roles, Add role', 'say': 'Make a role "StorageForge read" with view on environments, containers, stacks, images and volumes, and nothing else: not inspect, logs, exec, edit, users, settings, license or secrets. '
         f'Tie it to each environment StorageForge should see ({", ".join(envs)}), not to all.', 'run': []},
        {'where': 'Settings, Authentication, Users, Add user', 'say': f'Make a user {user} with a long random password, and give it only that role.', 'run': []},
        {'where': f'signed in as {user}: Profile, API tokens, Create', 'say': f'Make a token named {token} with an expiry date ({when}, a year from now); Dockhand asks the password again. The token (dh_ and 43 characters) is shown once: copy it for the next screen.',
         'run': []},
    ]


def action_steps(action: str, spec: dict, user: str) -> list[dict]:
    return [{'where': 'Settings, Authentication, Roles', 'say': f'To {spec["title"]}: a second role with {", ".join(spec["privs"])}, tied to {spec["on"]}, given to {user}. Never the Admin role.', 'run': []}]


# ── parsers ───────────────────────────────────────────────────────────
def parse_license(text: str) -> dict:
    """{'enforces_roles', 'valid', 'may_manage'}: the key, when it comes back, only says the token may manage the license. It is dropped."""
    doc = _load(text)
    doc = doc if isinstance(doc, dict) else {}
    payload = doc.get('payload') if isinstance(doc.get('payload'), dict) else {}
    stored = doc.get('stored') if isinstance(doc.get('stored'), dict) else {}
    return {'enforces_roles': payload.get('type') == 'enterprise', 'valid': bool(_b(doc.get('valid'))) and bool(_b(doc.get('active'))),
            'type': _s(payload.get('type'), 20), 'may_manage': isinstance(stored.get('key'), str) and bool(stored.get('key'))}


def parse_tokens(text: str, prefix: str | None = None) -> dict:
    """{'expire': epoch, 0 for none, None when the token in use is not listed}: only the entry whose tokenPrefix is the one in use."""
    items, _ = _list(text)
    for x in items:
        if prefix and x.get('tokenPrefix') == prefix:
            return {'expire': 0 if x.get('expiresAt') in (None, '') else _when(x.get('expiresAt')), 'name': _s(x.get('name'), 100), 'found': True}
    return {'expire': None, 'found': False}


def parse_environments(text: str) -> dict:
    items, bad = _list(text)
    out = []
    for x in items[:MAX_ENVIRONMENTS]:
        if _i(x.get('id')) is None or not _s(x.get('name')):
            continue
        out.append({'id': _i(x['id']), 'name': _s(x['name'], 128), 'connection': _s(x.get('connectionType'), 20), 'host': _s(x.get('host'), 255),
                    'port': _i(x.get('port')), 'public_ip': _s(x.get('publicIp'), 64), 'hawser': bool(_b(x.get('hasHawserToken')))})
    return {'environments': out, 'unreadable': bad}


def parse_containers(text: str) -> dict:
    items, bad = _list(text)
    return {'containers': [{'id': _s(x.get('id'), 64), 'name': _s(x.get('name'), 255).lstrip('/'), 'image': _s(x.get('image'), 300), 'state': _s(x.get('state'), 20),
                            'status': _s(x.get('status'), 100)} for x in items if _s(x.get('name'))], 'unreadable': bad}


def parse_stacks(text: str) -> dict:
    items, bad = _list(text)
    out = []
    for x in items:
        if not _s(x.get('name')):
            continue
        names = [c[:255] for c in x.get('containers') or [] if isinstance(c, str)][:100] if isinstance(x.get('containers'), list) else []
        out.append({'name': _s(x['name'], 128), 'status': _s(x.get('status'), 40), 'source': _s(x.get('sourceType'), 20), 'containers': names})
    return {'stacks': out, 'unreadable': bad}


def parse_images(text: str) -> dict:
    items, bad = _list(text)
    out = []
    for x in items:
        image_id = _s(x.get('Id'), 128)
        if not image_id:
            continue
        tags = x.get('RepoTags')
        out.append({'id': image_id, 'tags': [tag[:255] for tag in tags if isinstance(tag, str)][:100] if isinstance(tags, list) else [],
                    'size': _i(x.get('Size')), 'created': _i(x.get('Created'))})
    return {'images': out, 'unreadable': bad}


def parse_volumes(text: str) -> dict:
    items, bad = _list(text)
    return {'volumes': [{'name': _s(x['Name'], 255), 'driver': _s(x.get('Driver'), 80),
                         'mountpoint': _s(x.get('Mountpoint'), 500), 'scope': _s(x.get('Scope'), 32),
                         'created': _s(x.get('CreatedAt'), 40)}
                        for x in items if _s(x.get('Name'))], 'unreadable': bad}


INVENTORY = {
    'containers': (parse_containers, 'container', 'name'),
    'stacks': (parse_stacks, 'stack', 'name'),
    'images': (parse_images, 'image', 'id'),
    'volumes': (parse_volumes, 'volume', 'name'),
}


# ── the read-back ─────────────────────────────────────────────────────
def token_prefix(secret: str | None) -> str | None:
    """The 8 characters after dh_: what Dockhand stores and shows to tell a user's tokens apart. Not the token."""
    return secret[3:11] if secret and re.fullmatch(r'dh_[A-Za-z0-9_-]{43}', secret) else None


def judge(lic: dict, reads: dict, users_visible: bool, actions: list[str] | None = None, token: dict | None = None) -> dict:
    from .apireadback import verdict
    features = {f: {'ok': bool(reads.get(f)), 'what': v['what'], 'on': reads.get(f) or [], 'add': f'{v["perm"]} in the StorageForge role, on the environment'} for f, v in READ.items()}
    over, extra, unknown = [], [], []
    if not lic['enforces_roles']:
        over.append({'path': 'Dockhand', 'priv': 'no enterprise key: every user has full access', 'admin': True})
    else:
        unknown.append('what this token may change: Dockhand gives a token no way to read its own permissions, so check the role in Settings, Authentication')
    if lic['may_manage']:
        over.append({'path': 'Dockhand', 'priv': 'license:manage', 'admin': True})
    if users_visible:
        extra.append({'path': 'Dockhand', 'priv': 'users:view (every account and its email)'})
    return verdict('dockhand', features, over, token, extra=extra, actions=actions, unknown=unknown)


def readback(client, row: dict) -> dict:
    from .apiconn import ApiError, CertificateChanged, NotPinned, Refused
    lic = parse_license(client.get('/license'))
    reads = {}
    try:
        envs = parse_environments(client.get('/environments'))['environments']
        reads['environments'] = [e['name'] for e in envs]
    except Refused:
        envs = []
    for feature in INVENTORY:
        for env in envs:
            try:
                client.get(f'/{feature}', env=env['id'])
            except (CertificateChanged, NotPinned):
                raise
            except ApiError:
                continue
            reads[feature] = [env['name']]
            break
    try:
        client.get('/users')
        users_visible = True
    except ApiError:
        users_visible = False
    token = {'expire': None, 'enable': None}
    try:
        token['expire'] = parse_tokens(client.get('/auth/tokens'), token_prefix(client._secret))['expire']
    except ApiError:
        pass
    out = judge(lic, reads, users_visible, row.get('actions'), token)
    return {**out, 'paths': {'Dockhand': {'enterprise': lic['enforces_roles'], 'license:manage': lic['may_manage'], 'users:view': users_visible}}}


# ── the read ──────────────────────────────────────────────────────────
def read(client, row: dict, rb: dict) -> tuple[list, list]:
    from .apiconn import ApiError, CertificateChanged, NotPinned
    objs, skipped = [], []
    feats = rb.get('features') or {}
    if not feats.get('environments', {}).get('ok'):
        return objs, ['environments: the token may see none (environments:view)']
    envs = parse_environments(client.get('/environments'))['environments']
    for e in envs:
        objs.append(('environment', str(e['id']), e))
        for feature, (parse, kind, key) in INVENTORY.items():
            if not feats.get(feature, {}).get('ok'):
                continue
            try:
                parsed = parse(client.get(f'/{feature}', env=e['id']))
            except (CertificateChanged, NotPinned):
                raise
            except ApiError as exc:
                skipped.append(f'{e["name"]} {feature}: {exc}'[:200])
                continue
            if parsed['unreadable']:
                skipped.append(f'{e["name"]} {feature}: the list was not readable')
            for x in parsed[feature]:
                objs.append((kind, f'{e["id"]}/{x[key]}', {**x, 'environment': e['id'], 'environment_name': e['name']}))
    for f in INVENTORY:
        if not feats.get(f, {}).get('ok'):
            skipped.append(f'{f}: could not confirm {READ[f]["perm"]} on any environment')
    return objs, list(dict.fromkeys(skipped))


# ── beside the scan, and the views ────────────────────────────────────
def host_of_environment(conn, row: dict, env: dict) -> str | None:
    """The scanned host an environment is: by its address or name; a socket environment is the host Dockhand itself runs on."""
    from .apiviews import _hosts
    if env.get('connection') == 'socket':
        return row.get('host')
    names = _hosts(conn)
    by_ip = {(ip or '').lower(): h for h, ip in conn.all('SELECT hostname, ip_address FROM hosts') if ip}
    for v in (env.get('host'), env.get('public_ip'), env.get('name')):
        v = (v or '').lower()
        if v and (names.get(v) or names.get(v.split('.')[0]) or by_ip.get(v)):
            return names.get(v) or names.get(v.split('.')[0]) or by_ip.get(v)
    return None


def panel_containers(conn, row: dict, objects: list[dict]) -> list[dict]:
    """Each container the panel lists, with its stack and the scanned host its environment is. Shared by Dockhand, Portainer and Komodo."""
    envs = {o['ref']: o for o in objects if o['kind'] == 'environment'}
    stack_of = {}
    for o in objects:
        if o['kind'] == 'stack':
            for c in o.get('containers') or []:
                stack_of[(str(o.get('environment')), c)] = o.get('name')
    out = []
    for o in objects:
        if o['kind'] != 'container':
            continue
        env = envs.get(str(o.get('environment'))) or {}
        out.append({**o, 'on_host': host_of_environment(conn, row, env) if env else None, 'stack': o.get('stack') or stack_of.get((str(o.get('environment')), o.get('name')))})
    return out


def compare(conn, row: dict, objects: list[dict]) -> dict:
    """Each container the panel lists against the containers the SSH scan's Docker reading lists on the same host: by name, with the
    state each side says. A host the panel reaches that is not scanned is listed as such."""
    from .runtimes import docker
    out = []
    by_host: dict = {}
    for c in panel_containers(conn, row, objects):
        by_host.setdefault(c['on_host'], []).append(c)
    for host, items in sorted(by_host.items(), key=lambda x: x[0] or ''):
        if not host:
            out.append({'host': None, 'scanned': False, 'containers': [{'name': c['name'], 'seen_by': ['api'], 'differs': []} for c in items],
                        'why': 'these environments are not a scanned host'})
            continue
        scanned = {c['name']: c for h in docker.listing(conn, host) for s in h['stacks'] for c in s['containers']}
        rows = []
        for name in sorted({c['name'] for c in items} | set(scanned)):
            a = next((c for c in items if c['name'] == name), None)
            s = scanned.get(name)
            if a and s:
                differs = [{'field': 'state', 'api': a.get('state'), 'ssh': s.get('state')}] if (a.get('state') or '') != (s.get('state') or '') else []
                rows.append({'name': name, 'seen_by': ['api', 'ssh'], 'differs': differs, 'stack': a.get('stack')})
            elif a:
                rows.append({'name': name, 'seen_by': ['api'], 'differs': [], 'stack': a.get('stack'), 'why': 'the last SSH scan of this host did not list it'})
            else:
                rows.append({'name': name, 'seen_by': ['ssh'], 'differs': [], 'why': 'the panel did not list it: the token may not see its environment, or it is not managed there'})
        out.append({'host': host, 'scanned': True, 'containers': rows})
    return {'containers': out}


def workloads(conn, row: dict, objects: list[dict]) -> list[dict]:
    return [{'host': c['on_host'], 'runtime': 'docker', 'kind': 'container', 'name': c['name'], 'state': c.get('state'), 'stack': c.get('stack'),
             'api': {'environment': c.get('environment_name'), 'image': c.get('image')}} for c in panel_containers(conn, row, objects)]


def map_nodes(conn, row: dict, objects: list[dict], hosts: dict, layers) -> list[dict]:
    """A container the scan does not draw (on a host that is not scanned, or not in its last reading), hanging from its host or the panel.
    One the scan draws gets the panel's reading beside it."""
    if 'workloads' not in layers:
        return []
    out = []
    for c in panel_containers(conn, row, objects):
        host = c['on_host']
        props = {'runtime': 'docker', 'state': c.get('state'), 'image': c.get('image'), 'stack': c.get('stack'), 'environment': c.get('environment_name'), 'panel': row['kind']}
        out.append({'attach': f'wl:{host}:docker::{c["name"]}' if host else None, 'id': f'api:{row["name"]}:ctr:{c["ref"]}', 'kind': 'Container',
                    'label': c['name'], 'layer': 'workloads', 'host': host, 'props': props, 'edges': [(f'host:{host}', 'RUNS_ON', f'{row["title"]} API')] if host else []})
    return out


def problems(conn, row: dict, objects: list[dict], now: float | None = None) -> dict:
    out = {}
    stopped = [o for o in objects if o['kind'] == 'container' and o.get('state') in ('exited', 'dead', 'restarting')]
    if stopped:
        out[f'api-panel-stopped:{row["name"]}'] = ('api-panel-stopped', row['host'] or row['name'], f'{len(stopped)} container(s) {row["title"]} {row["name"]} manages are not running',
                                                  ', '.join(f'{o["name"]} ({o.get("environment_name")}: {o.get("state")})' for o in stopped[:6]), 'info')
    return out
