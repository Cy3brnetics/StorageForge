"""Pangolin through its Integration API (roadmap section 13): what the server publishes, at which domain, behind which login, and through
which site. The Newt side, a tunnel that runs on a host with its routes kept at the server, is read over SSH (tunnels.py, inframeasure):
this fills in what that side cannot say, and feeds the exposure view (section 2), where a resource Newt carries to a host is public
whatever that host's firewall says.

    GET /v1/org/ORG/api-key/KEYID/actions     the actions the key holds (the read-back)
    GET /v1/org/ORG/sites                     sites: name, niceId, type (newt, wireguard, local), online, the Newt version
    GET /v1/org/ORG/resources                 public resources: name, fullDomain, ssl, enabled, the login in front of it (sso, a
                                              password, a PIN, an email whitelist, header auth, mTLS), with their targets (site, ip,
                                              port) and sites
    GET /v1/org/ORG/domains                   the organization's domains

The key is the Integration API key: KEYID.SECRET in an Authorization: Bearer header (verifyApiKey splits it at the dot). The token ID
here is KEYID@ORG, since every call is scoped to the organization. An organization key reaches one organization; a root key reaches
every one and is never needed.

Field names are those of Pangolin's sources (github.com/fosrl/pangolin: server/routers/resource/listResources.ts,
site/listSites.ts, domain/listDomains.ts, server/auth/actions.ts, server/middlewares/integration/verifyApiKey.ts) and its OpenAPI
document (api.pangolin.net/v1/openapi.json), fetched 2026-11-20. Each parse_ function takes the JSON text of one answer and never raises.
"""
from __future__ import annotations

import json
import re

from .apiparse import _b, _i, _s

FETCHED = '2026-11-20'
SOURCES = ['https://docs.pangolin.net/manage/integration-api (organization keys, root keys, the permissions selector, Bearer)',
           'https://api.pangolin.net/v1/openapi.json (the Integration API: /org/{orgId}/sites, /resources, /domains, /api-key/{apiKeyId}/actions)',
           'https://github.com/fosrl/pangolin/blob/main/server/auth/actions.ts (the action names)',
           'https://github.com/fosrl/pangolin/blob/main/server/middlewares/integration/verifyApiKey.ts (Bearer KEYID.SECRET)',
           'https://github.com/fosrl/pangolin/blob/main/server/routers/resource/listResources.ts, site/listSites.ts, domain/listDomains.ts (fields)']
READ_ACTIONS = ['listSites', 'listResources', 'listTargets', 'listOrgDomains', 'listApiKeyActions']
READ = {
    'sites': {'action': 'listSites', 'what': 'the sites (where Newt runs) and whether each is online'},
    'resources': {'action': 'listResources', 'what': 'what is published, at which domain, behind which login, to which target'},
    'domains': {'action': 'listOrgDomains', 'what': 'the organization domains'},
}
# actions that give control of Pangolin itself: its keys, users, roles, identity providers and the organization
ADMIN = re.compile(r'(create|delete|update|set|remove|add|invite|generate|reset|approve|deny).*(ApiKey|User|Role|Org|Idp|Invitation|LoginPage|Certificate|ProvisioningKey)', re.I)
SECRET_READS = {'getVirtualApiKey'}            # a "get" that answers with a decrypted secret: never a read StorageForge needs
PAGE = 1000
MAX_PAGES = 10

GUIDE = {
    'title': 'Pangolin',
    'least': 'an organization API key (not a root key) whose permissions are only listSites, listResources, listTargets, listOrgDomains and listApiKeyActions',
    'role': 'listSites, listResources, listTargets, listOrgDomains, listApiKeyActions',
    'why_role': ('Each permission of a Pangolin key is one action. These five only list: the sites, the published resources with their targets '
                 'and logins, the domains, and the key\'s own permissions, which is how StorageForge checks the key. None of them changes anything.'),
    'scope': 'An organization key reaches its own organization only. A root key (Server Admin, API Keys) reaches every organization and is never needed.',
    'read': {f: {'what': v['what'], 'privs': [v['action']], 'paths': ['the organization']} for f, v in READ.items()},
    'actions': {},
    'no_actions': 'No action is offered: StorageForge only reads what Pangolin publishes.',
    'admin': ['a root key', 'create, update or delete on API keys, users, roles, the organization or identity providers', 'getVirtualApiKey (it answers with a decrypted secret)'],
    'never': ['a root key', 'any create, update, set or delete permission', 'getVirtualApiKey'],
    'check': 'Organization, API Keys, the key, Permissions: only the five list permissions',
    'expiry': {'allowed': False, 'read_back': False, 'how': 'Pangolin shows no expiry for an API key. Replace it on a schedule (Replace the token checks the new one before the old one is dropped), and give the date you mean to replace it by, for the warning'},
    'token_id_placeholder': 'KEYID@your-org',
    'scope_hint': ('The organization ID (only for the guide).', 'your-org'),
    'fetched': FETCHED,
}


def steps(user: str, token: str, scope, expire: int) -> list[dict]:
    org = (str(scope).split() or ['<org>'])[0] if scope else '<org>'
    return [
        {'where': f'Pangolin, organization {org}, API Keys, Create API Key', 'say': f'Name it {token}. In the permissions selector tick only listSites, listResources, listTargets, listOrgDomains and listApiKeyActions. Not a root key (Server Admin): an organization key.',
         'run': []},
        {'where': 'the same screen', 'say': f'Pangolin shows the key once, as KEYID.SECRET. On the next screen the token ID is KEYID@{org} (the part before the dot, then the organization) and the token is the part after the dot. '
         'The Integration API must be on (the self-hosting guide, Integration API) and reached over HTTPS, usually at api.YOUR-DOMAIN.', 'run': []},
        {'where': 'Organization, API Keys, the key', 'say': 'Check its permissions: only those five. StorageForge reads the same back through listApiKeyActions.', 'run': []},
    ]


def action_steps(action: str, spec: dict, user: str) -> list[dict]:
    from .apiguide import GuideError
    raise GuideError(GUIDE['no_actions'])


# ── parsers ───────────────────────────────────────────────────────────
def _data(text):
    """The data of a Pangolin answer ({data, success, error, message, status}), or None."""
    try:
        doc = json.loads(text)
    except (ValueError, TypeError, RecursionError):
        return None
    return doc.get('data') if isinstance(doc, dict) and isinstance(doc.get('data'), dict) else None


def _items(text, key: str) -> tuple[list, bool, int | None]:
    data = _data(text)
    if data is None or not isinstance(data.get(key), list):
        return [], True, None
    page = data.get('pagination') if isinstance(data.get('pagination'), dict) else {}
    return [x for x in data[key] if isinstance(x, dict)], False, _i(page.get('total'))


def parse_actions(text: str) -> dict:
    items, bad, _ = _items(text, 'actions')
    return {'actions': sorted({x['actionId'][:80] for x in items if isinstance(x.get('actionId'), str)}), 'unreadable': bad}


def parse_sites(text: str) -> dict:
    items, bad, total = _items(text, 'sites')
    out = []
    for x in items:
        if _i(x.get('siteId')) is None:
            continue
        out.append({'id': _i(x['siteId']), 'nice': _s(x.get('niceId'), 64), 'name': _s(x.get('name'), 128), 'type': _s(x.get('type'), 20), 'online': _b(x.get('online')),
                    'newt_version': _s(x.get('newtVersion'), 40), 'exit_node': _s(x.get('exitNodeName'), 128)})
    return {'sites': out, 'unreadable': bad, 'total': total}


def login_of(x: dict) -> list[str]:
    """What stands in front of a resource, from listResources' fields: [] means nothing does."""
    out = []
    if _b(x.get('sso')):
        out.append('Pangolin sign-in (SSO)')
    if x.get('passwordId') is not None:
        out.append('a password')
    if x.get('pincodeId') is not None:
        out.append('a PIN')
    if _b(x.get('whitelist')):
        out.append('an email whitelist')
    if x.get('headerAuthId') is not None:
        out.append('header authentication')
    if _b(x.get('mtls')):
        out.append('a client certificate (mTLS)')
    return out


def parse_resources(text: str) -> dict:
    items, bad, total = _items(text, 'resources')
    out = []
    for x in items:
        if _i(x.get('resourceId')) is None:
            continue
        targets = [t for t in x.get('targets') or [] if isinstance(t, dict)] if isinstance(x.get('targets'), list) else []
        out.append({'id': _i(x['resourceId']), 'nice': _s(x.get('niceId'), 64), 'name': _s(x.get('name'), 128), 'domain': _s(x.get('fullDomain'), 255),
                    'ssl': _b(x.get('ssl')), 'enabled': _b(x.get('enabled')), 'mode': _s(x.get('mode'), 20), 'proxy_port': _i(x.get('proxyPort')),
                    'login': login_of(x), 'health': _s(x.get('health'), 20),
                    'targets': [{'id': _i(t.get('targetId')), 'site': _i(t.get('siteId')), 'ip': _s(t.get('ip'), 255), 'port': _i(t.get('port')),
                                 'enabled': _b(t.get('enabled'))} for t in targets[:50]]})
    return {'resources': out, 'unreadable': bad, 'total': total}


def parse_domains(text: str) -> dict:
    items, bad, _ = _items(text, 'domains')
    return {'domains': [{'id': _s(x.get('domainId'), 64), 'base': _s(x.get('baseDomain'), 255), 'verified': _b(x.get('verified')), 'type': _s(x.get('type'), 20),
                         'failed': _b(x.get('failed'))} for x in items if _s(x.get('domainId'))], 'unreadable': bad}


# ── the read-back ─────────────────────────────────────────────────────
def judge(actions_held: list[str] | None, reads: dict, token: dict | None = None) -> dict:
    from .apireadback import verdict
    have = set(actions_held or [])
    features = {f: {'ok': (v['action'] in have) if actions_held is not None else bool(reads.get(f)), 'what': v['what'], 'on': ['the organization'] if reads.get(f) else [],
                    'add': f'{v["action"]} on the key'} for f, v in READ.items()}
    over, extra, unknown = [], [], []
    if actions_held is None:
        unknown.append('which permissions the key holds: give it listApiKeyActions')
    for a in sorted(have):
        if a in READ_ACTIONS:
            continue
        if a in SECRET_READS:
            over.append({'path': 'the organization', 'priv': a, 'admin': True})
        elif re.match(r'(list|get)[A-Z]', a):
            extra.append({'path': 'the organization', 'priv': a})
        else:
            over.append({'path': 'the organization', 'priv': a, 'admin': bool(ADMIN.match(a))})
    return verdict('pangolin', features, over, token, extra=extra, unknown=unknown,
                   notes=['Pangolin shows no expiry for an API key: replace it on a schedule'])


def ids(row: dict) -> tuple[str, str]:
    key, _, org = row['token_id'].partition('@')
    return key, org


def _pages(client, path: str, parse, key: str) -> tuple[list, bool]:
    out, cut = [], False
    for page in range(1, MAX_PAGES + 1):
        got = parse(client.get(path, pageSize=PAGE, page=page))
        out += got[key]
        if got['unreadable'] or not got[key] or len(got[key]) < PAGE or (got.get('total') is not None and len(out) >= got['total']):
            return out, False
        cut = page == MAX_PAGES
    return out, cut


def readback(client, row: dict) -> dict:
    from .apiconn import Refused
    key, org = ids(row)
    try:
        held = parse_actions(client.get(f'/org/{client.seg(org)}/api-key/{client.seg(key)}/actions'))
        held = None if held['unreadable'] else held['actions']
    except Refused:
        held = None
    reads = {}
    for f, path in (('sites', 'sites'), ('resources', 'resources'), ('domains', 'domains')):
        try:
            client.get(f'/org/{client.seg(org)}/{path}', **({'pageSize': 1} if f != 'domains' else {'limit': 1}))
            reads[f] = True
        except Refused:
            pass
    out = judge(held, reads, {'expire': None, 'enable': None})
    return {**out, 'paths': {'the organization': {a: True for a in held or []}}}


# ── the read ──────────────────────────────────────────────────────────
def read(client, row: dict, rb: dict) -> tuple[list, list]:
    from .apicollect import Reading
    _, org = ids(row)
    base = f'/org/{client.seg(org)}'
    r = Reading()
    feats = rb.get('features') or {}
    for feature, path, parse, key, kind in (('sites', '/sites', parse_sites, 'sites', 'site'), ('resources', '/resources', parse_resources, 'resources', 'resource')):
        if not feats.get(feature, {}).get('ok'):
            r.skip(f'{feature}: the key lacks {READ[feature]["action"]}')
            continue
        got = r.call(feature, lambda: _pages(client, base + path, parse, key))
        if got:
            items, cut = got
            r.objs += [(kind, str(x['id']), x) for x in items]
            if cut:
                r.cut(PAGE * MAX_PAGES, feature)
    if feats.get('domains', {}).get('ok'):
        got = r.call('domains', lambda: parse_domains(client.get(base + '/domains', limit=PAGE)))
        r.objs += [('domain', d['id'], d) for d in (got['domains'] if got else [])]
    else:
        r.skip('domains: the key lacks listOrgDomains')
    return r.result()


# ── exposure, the views ───────────────────────────────────────────────
def site_hosts(conn, row: dict, objects: list[dict]) -> dict:
    """Site id -> the scanned host it is: by the site's name or niceId; a local site is the Pangolin server itself."""
    from .apiviews import _hosts
    names = _hosts(conn)
    out = {}
    for o in objects:
        if o['kind'] != 'site':
            continue
        if o.get('type') == 'local':
            out[o['ref']] = row.get('host')
            continue
        for v in (o.get('name'), o.get('nice')):
            v = (v or '').lower()
            if v and (names.get(v) or names.get(v.split('.')[0])):
                out[o['ref']] = names.get(v) or names.get(v.split('.')[0])
                break
    return out


def published(conn, row: dict, objects: list[dict]) -> dict:
    """Scanned host -> what Pangolin publishes through a site that is that host, in the shape tunnels.py's readers give."""
    hosts = site_hosts(conn, row, objects)
    out: dict = {}
    for o in objects:
        if o['kind'] != 'resource' or o.get('enabled') is False:
            continue
        public = (f'{"https" if o.get("ssl") else "http"}://{o["domain"]}' if o.get('domain') and o.get('mode') in (None, 'http')
                  else f'{(o.get("mode") or "tcp")}://{row["base_url"].split("://", 1)[-1].rsplit(":", 1)[0]}:{o.get("proxy_port")}' if o.get('proxy_port') else o.get('domain'))
        for t in o.get('targets') or []:
            host = hosts.get(str(t.get('site')))
            if not host or t.get('enabled') is False:
                continue
            out.setdefault(host, []).append({'public': public, 'local': f'{t.get("ip")}:{t.get("port")}' if t.get('ip') and t.get('port') else t.get('ip'),
                                             'protocol': 'http' if o.get('mode') in (None, 'http') else o.get('mode'), 'name': o.get('name'),
                                             'login': ', '.join(o.get('login') or []) or 'none', 'connection': row['name']})
    return out


def fill_newt(conn, host: str, infra: dict | None) -> dict | None:
    """An infra reading with each running Newt's routes filled in from Pangolin's API, where a connection reads a site that is this
    host: the published list tunnels.py could not read on the host. Called from inframeasure.reading; changes nothing stored."""
    tunnels_ = ((infra or {}).get('access') or {}).get('tunnels') or []
    if not any(t.get('tool') == 'newt' and not t.get('published') for t in tunnels_):
        return infra
    from . import apiconn, apiread
    found, servers = [], []
    for row in apiconn.listing(conn):
        if row['kind'] != 'pangolin' or not row.get('read_ok'):
            continue
        got = published(conn, row, apiread.objects(conn, row['conn_id'])).get(host)
        if got:
            found += got
            servers.append(row['base_url'])
    if not found:
        return infra
    filled = []
    for t in tunnels_:
        if t.get('tool') == 'newt' and not t.get('published'):
            t = {**t, 'published': found[:500], 'remote': False, 'server': ', '.join(servers), 'source': 'api'}
        filled.append(t)
    return {**infra, 'access': {**infra['access'], 'tunnels': filled}}


def compare(conn, row: dict, objects: list[dict]) -> dict:
    """Each site against the SSH scan of the host it is: whether that host runs Newt, which is how the scan knows routes are kept here."""
    from .security import measurement
    hosts = site_hosts(conn, row, objects)
    out = []
    for o in objects:
        if o['kind'] != 'site':
            continue
        host = hosts.get(o['ref'])
        m = measurement(conn, host, 'infra') if host else None
        newt = any(t.get('tool') == 'newt' for t in ((m or {}).get('access') or {}).get('tunnels') or [])
        out.append({'site': o.get('name'), 'type': o.get('type'), 'online': o.get('online'), 'host': host,
                    'seen_by': ['api', 'ssh'] if newt else ['api'], 'why': None if newt or o.get('type') == 'local' else
                    ('the SSH scan of this host found no Newt running' if host else 'no scanned host has this site name')})
    return {'sites': out}


def map_nodes(conn, row: dict, objects: list[dict], hosts: dict, layers) -> list[dict]:
    """Each published resource as a route in the access layer, from the Newt tunnel on the host its site is (or the platform)."""
    out = []
    shosts = site_hosts(conn, row, objects)
    for o in objects:
        if o['kind'] != 'resource':
            continue
        edges = []
        for t in o.get('targets') or []:
            h = shosts.get(str(t.get('site')))
            if h:
                edges.append((f'tunnel:{h}:newt', 'ROUTES', f'Pangolin API: {o.get("domain") or o.get("name")} to {t.get("ip")}:{t.get("port")}'))
                edges.append((f'host:{h}', 'FRONTS', f'Pangolin API: {o.get("domain") or o.get("name")}'))
        out.append({'id': f'api:{row["name"]}:res:{o["ref"]}', 'kind': 'ProxyRoute', 'label': (o.get('domain') or o.get('name') or o['ref'])[:60], 'layer': 'access',
                    'host': None, 'props': {'proxy': 'pangolin', 'exposure': 'public', 'login': ', '.join(o.get('login') or []) or 'none', 'enabled': o.get('enabled'),
                                            'connection': row['name']}, 'edges': edges})
    return out


def problems(conn, row: dict, objects: list[dict], now: float | None = None) -> dict:
    out, host = {}, row['host'] or row['name']
    open_ = [o for o in objects if o['kind'] == 'resource' and o.get('enabled') is not False and not o.get('login') and o.get('mode') in (None, 'http')]
    if open_:
        out[f'api-pangolin-open:{row["name"]}'] = ('api-pangolin-open', host, f'{len(open_)} resource(s) Pangolin {row["name"]} publishes have no login in front',
                                                  ', '.join(o.get('domain') or o.get('name') or o['ref'] for o in open_[:8]) + '. Anyone who has the address reaches them.', 'warn')
    down = [o for o in objects if o['kind'] == 'site' and o.get('online') is False and o.get('type') != 'local']
    if down:
        out[f'api-pangolin-site:{row["name"]}'] = ('api-pangolin-site', host, f'{len(down)} Pangolin site(s) of {row["name"]} are offline', ', '.join(o.get('name') or o['ref'] for o in down[:8]), 'info')
    return out
