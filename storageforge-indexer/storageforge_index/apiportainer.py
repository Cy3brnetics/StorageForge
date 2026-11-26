"""Portainer through its API (roadmap section 13): environments, stacks and the containers in each Docker environment, compared with
the SSH scan, and fed to the same views and the section 6 hook as Dockhand (apidockhand's panel functions, shared).

    GET /api/users/me                       the token's user: Role 1 is an administrator (the read-back)
    GET /api/system/version                 ServerEdition CE or EE: Community Edition has no read-only role
    GET /api/users/ID/effective-access      the role the user holds on each environment (Business Edition roles; the read-back)
    GET /api/endpoints?excludeSnapshots=true   the environments the token may see
    GET /api/stacks                         the stacks, with the environment of each (their Env variables are never copied)
    GET /api/endpoints/ID/docker/containers/json?all=1   each Docker environment's containers, through Portainer's Docker proxy (a GET)

An access token goes in the X-API-Key header and carries exactly the rights of the user who made it. Portainer access tokens have no
expiry date: the guide says to replace one on a schedule, and the read-back says the platform cannot set one.

Field names are those of Portainer's Go sources (github.com/portainer/portainer, develop: api/portainer.go User, Endpoint, Stack;
api/http/handler/users/user_effective_access.go; api/http/handler/system/version.go), fetched 2026-11-20, and Docker Engine's
container list (Id, Names, Image, State, Status, Labels) for the proxied call. Each parse_ function takes the JSON text of one answer
and never raises.
"""
from __future__ import annotations

from .apidockhand import compare, map_nodes, problems, workloads  # noqa: F401  the panel views are the same for every panel
from .apiparse import _i, _list, _load, _s

FETCHED = '2026-11-20'
SOURCES = ['https://docs.portainer.io/api/access (access tokens: My account, Access tokens; X-API-Key; the token has its user rights)',
           'https://github.com/portainer/portainer/blob/develop/api/portainer.go (User.Role 1 administrator 2 standard; Endpoint; Stack; APIKey has no expiry)',
           'https://github.com/portainer/portainer/blob/develop/api/http/handler/users/user_effective_access.go (roleName per environment)',
           'https://github.com/portainer/portainer/blob/develop/api/http/handler/system/version.go (ServerEdition CE/EE)']
READ_ROLES = {'Read-only user', 'Helpdesk'}
READ = {
    'environments': {'what': 'the environments the user is given'},
    'containers': {'what': 'the containers in each Docker environment'},
    'stacks': {'what': 'the stacks and the environment of each'},
}
DOCKER_TYPES = {1, 2, 4}           # Docker local, agent and edge agent environments; Kubernetes and Azure are not read
MAX_ENVIRONMENTS = 100

GUIDE = {
    'title': 'Portainer',
    'least': 'a dedicated user storageforge that is not an administrator, given the Read-only user role on the environments it should see (Business Edition), or only those environments (Community Edition), and an access token made by that user',
    'role': 'Read-only user (Business Edition); a standard user with only the chosen environments (Community Edition)',
    'why_role': ('An access token has exactly the rights of the user who made it, so the user is the boundary. Business Edition has a Read-only '
                 'user role per environment. Community Edition has no read-only role: a standard user given an environment can change what runs '
                 'there, so StorageForge reads it and the read-back raises a finding that says so.'),
    'scope': 'Give the user only the environments StorageForge should see (Environments, Manage access, or a team). Never the administrator token.',
    'read': {f: {'what': v['what'], 'privs': ['Read-only user'], 'paths': ['the environments the user is given']} for f, v in READ.items()},
    'actions': {
        'redeploy': {'title': 'redeploy or update a stack', 'privs': ['Operator'], 'on': 'the one environment', 'role': 'Operator on that environment'},
    },
    'admin': ['Role 1 (administrator)', 'Environment administrator'],
    'never': ['the admin user or any administrator (an administrator token reaches every environment and Portainer itself; refused here for admin)',
              'Environment administrator', 'a token from a downloaded kubeconfig: it only proxies Kubernetes'],
    'check': 'Users, storageforge, and Environments, Manage access: no administrator, only the chosen environments',
    'expiry': {'allowed': False, 'read_back': False, 'how': 'Portainer access tokens have no expiry date. Replace the token on a schedule (Keys, Platform connections, Replace the token checks the new one before the old one is dropped), and give the date you mean to replace it by, for the warning'},
    'token_id_placeholder': 'storageforge',
    'scope_hint': ('The environments it should see, by name (only for the guide).', 'docker1'),
    'fetched': FETCHED,
}


def steps(user: str, token: str, scope, expire: int) -> list[dict]:
    envs = [e for e in (scope if isinstance(scope, list) else str(scope or '').split()) if e] or ['<environment>']
    return [
        {'where': 'Portainer as an administrator: Administration, User-related, Users', 'say': f'Make a user {user} with a long random password. Do not tick Administrator.', 'run': []},
        {'where': 'Environments, each of ' + ', '.join(envs) + ', Manage access', 'say': f'Give {user} access to only these environments, with the Read-only user role (Business Edition). '
         'Community Edition has no roles: giving the environment lets the user change what runs on it, and the read-back will say so.', 'run': []},
        {'where': f'signed in as {user}: My account, Access tokens, Add access token', 'say': f'Make a token described as {token}; Portainer asks the password again. The token is shown once: copy it for the next screen. Portainer tokens do not expire: note the date you mean to replace it by.',
         'run': []},
    ]


def action_steps(action: str, spec: dict, user: str) -> list[dict]:
    return [{'where': 'Environments, the one environment, Manage access', 'say': f'To {spec["title"]}: give {user} the Operator role on {spec["on"]} only. Never Environment administrator or Administrator.', 'run': []}]


# ── parsers ───────────────────────────────────────────────────────────
def parse_me(text: str) -> dict:
    doc = _load(text)
    doc = doc if isinstance(doc, dict) else {}
    return {'id': _i(doc.get('Id')), 'user': _s(doc.get('Username'), 128), 'role': _i(doc.get('Role'))}


def parse_version(text: str) -> dict:
    doc = _load(text)
    doc = doc if isinstance(doc, dict) else {}
    return {'version': _s(doc.get('ServerVersion'), 40), 'edition': _s(doc.get('ServerEdition'), 10)}


def parse_access(text: str) -> dict:
    items, bad = _list(text)
    return {'access': [{'environment': _i(x.get('endpointId')), 'name': _s(x.get('endpointName'), 128), 'role': _s(x.get('roleName'), 60), 'via': _s(x.get('accessLocation'), 40)}
                       for x in items if _i(x.get('endpointId')) is not None], 'unreadable': bad}


def parse_endpoints(text: str) -> dict:
    items, bad = _list(text)
    out = []
    for x in items[:MAX_ENVIRONMENTS]:
        if _i(x.get('Id')) is None or not _s(x.get('Name')):
            continue
        url = _s(x.get('URL'), 255) or ''
        host = url.split('://', 1)[-1].rsplit(':', 1)[0] if url and not url.startswith('unix://') else None
        out.append({'id': _i(x['Id']), 'name': _s(x['Name'], 128), 'type': _i(x.get('Type')), 'url': url, 'host': host, 'public_ip': _s(x.get('PublicURL'), 255),
                    'connection': 'socket' if url.startswith('unix://') or url.startswith('npipe://') else 'remote', 'status': _i(x.get('Status'))})
    return {'environments': out, 'unreadable': bad}


def parse_stacks(text: str) -> dict:
    """Stacks. Env holds the stack's variables, often secrets: it is never copied."""
    items, bad = _list(text)
    return {'stacks': [{'id': _i(x.get('Id')), 'name': _s(x.get('Name'), 128), 'type': _i(x.get('Type')), 'environment': _i(x.get('EndpointId')),
                        'status': {1: 'active', 2: 'inactive'}.get(_i(x.get('Status')), None)} for x in items if _s(x.get('Name'))], 'unreadable': bad}


def parse_containers(text: str) -> dict:
    """Docker Engine's container list as Portainer's proxy passes it: Names start with a slash; the Compose project is a label."""
    items, bad = _list(text)
    out = []
    for x in items:
        names = [n for n in x.get('Names') or [] if isinstance(n, str)] if isinstance(x.get('Names'), list) else []
        if not names:
            continue
        labels = x.get('Labels') if isinstance(x.get('Labels'), dict) else {}
        out.append({'id': _s(x.get('Id'), 64), 'name': names[0].lstrip('/')[:255], 'image': _s(x.get('Image'), 300), 'state': _s(x.get('State'), 20),
                    'status': _s(x.get('Status'), 100), 'stack': _s(labels.get('com.docker.compose.project'), 128)})
    return {'containers': out, 'unreadable': bad}


# ── the read-back ─────────────────────────────────────────────────────
def judge(me: dict, edition: str | None, access: list[dict] | None, reads: dict, actions: list[str] | None = None) -> dict:
    from .apireadback import verdict
    features = {f: {'ok': bool(reads.get(f)) or me.get('role') == 1, 'what': v['what'], 'on': reads.get(f) or [],
                    'add': 'the Read-only user role for the user, on the environment'} for f, v in READ.items()}
    wanted = {p for a in actions or [] for p in (GUIDE['actions'].get(a) or {}).get('privs', [])}
    over, notes, unknown = [], ['Portainer access tokens have no expiry date: replace it on a schedule'], []
    if me.get('role') == 1:
        over.append({'path': 'Portainer', 'priv': 'administrator', 'admin': True})
    elif access is not None:
        for a in access:
            if a['role'] in READ_ROLES or a['role'] in wanted:
                continue
            over.append({'path': f'environment {a["name"] or a["environment"]}', 'priv': a['role'] or 'a role', 'admin': a['role'] == 'Environment administrator'})
    elif (edition or '').upper() == 'CE':
        for env in reads.get('environments') or []:
            over.append({'path': f'environment {env}', 'priv': 'standard user: Community Edition has no read-only role', 'admin': False})
    else:
        unknown.append('the role of the user on each environment (effective-access did not answer)')
    return verdict('portainer', features, over, {'expire': None, 'enable': None}, notes=notes, actions=actions, unknown=unknown)


def readback(client, row: dict) -> dict:
    from .apiconn import ApiError, Refused
    me = parse_me(client.get('/users/me'))
    if me['id'] is None:
        raise ApiError('Portainer answered /users/me without a user')
    try:
        edition = parse_version(client.get('/system/version'))['edition']
    except ApiError:
        edition = None
    access = None
    if me['role'] != 1:
        try:
            got = parse_access(client.get(f'/users/{me["id"]}/effective-access'))
            access = None if got['unreadable'] else got['access']
        except ApiError:
            access = None
    reads = {}
    try:
        envs = parse_endpoints(client.get('/endpoints', excludeSnapshots='true'))['environments']
        reads['environments'] = [e['name'] for e in envs]
    except Refused:
        envs = []
    docker = [e for e in envs if e['type'] in DOCKER_TYPES]
    if docker:
        try:
            client.get(f'/endpoints/{docker[0]["id"]}/docker/containers/json', all='1')
            reads['containers'] = [docker[0]['name']]
        except ApiError:
            pass
    try:
        client.get('/stacks')
        reads['stacks'] = ['all it may see']
    except Refused:
        pass
    out = judge(me, edition, access, reads, row.get('actions'))
    if me['user'] and me['user'] != row['token_id']:
        out['notes'].append(f'the token belongs to {me["user"]}, not {row["token_id"]}')
    return {**out, 'edition': edition, 'paths': {a['name'] or str(a['environment']): {a['role'] or '?': True} for a in access or []}}


# ── the read ──────────────────────────────────────────────────────────
def read(client, row: dict, rb: dict) -> tuple[list, list]:
    from .apiconn import ApiError
    objs, skipped = [('platform', 'version', {'edition': rb.get('edition')})], []
    feats = rb.get('features') or {}
    if not feats.get('environments', {}).get('ok'):
        return objs, ['environments: the user is given none']
    envs = parse_endpoints(client.get('/endpoints', excludeSnapshots='true'))['environments']
    names = {e['id']: e['name'] for e in envs}
    for e in envs:
        objs.append(('environment', str(e['id']), e))
        if e['type'] not in DOCKER_TYPES:
            skipped.append(f'{e["name"]}: only Docker environments are read')
            continue
        if feats.get('containers', {}).get('ok'):
            try:
                for c in parse_containers(client.get(f'/endpoints/{e["id"]}/docker/containers/json', all='1'))['containers']:
                    objs.append(('container', f'{e["id"]}/{c["name"]}', {**c, 'environment': e['id'], 'environment_name': e['name']}))
            except ApiError as exc:
                skipped.append(f'{e["name"]} containers: {exc}'[:200])
    if feats.get('stacks', {}).get('ok'):
        try:
            for s in parse_stacks(client.get('/stacks'))['stacks']:
                objs.append(('stack', f'{s["environment"]}/{s["name"]}', {**s, 'environment_name': names.get(s['environment'])}))
        except ApiError as exc:
            skipped.append(f'stacks: {exc}'[:200])
    return objs, list(dict.fromkeys(skipped))
