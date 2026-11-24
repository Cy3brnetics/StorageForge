#!/usr/bin/env python3
"""Tier 27, part 2: API connections to TrueNAS, Xen Orchestra, Portainer, Dockhand and Komodo (roadmap section 13, 0.5.10 part 2),
called from tiers_api.tier27 before its no-secret check, so every secret made here is looked for too.

NOT RUN. Written on 2026-11-20 where the KVM lab cannot run: no check below has ever passed or failed on a real VM, and none of this is
lab-tested. What was run is tests/test_apitruenas.py, test_apixo.py, test_apidockhand.py, test_apiportainer.py, test_apikomodo.py and
test_apipangolin.py on this machine, against a real TLS server on 127.0.0.1 answering with JSON built from each platform's documentation
and sources. A first run will most likely have to correct this file: the container images' settings and the set-up calls below are
taken from each project's documentation and were never tried. A check that cannot be made shows as skip or as failed, never as passed.

    guide-truenas      on sf-truenas, the guide's midclt commands run as written make the user, the privilege and the key
    readback-truenas   the read-back finds READONLY_ADMIN exactly right; read-truenas finds the pool tank
    refused-truenas    a key for truenas_admin is refused by StorageForge with the reason, before anything is sent
    over-truenas       SHARING_ADMIN added to the privilege raises the finding; removed, the next read clears it
    readback-xo        Xen Orchestra (from the sources, a container on the Docker host, sf-xcp added as its server): a user with
                       the guide's role reads back exact; read-xo finds sf-xcp's host
    over-xo            the same user made an administrator raises the critical finding
    readback-portainer Portainer CE in a container on the Docker host: a standard user given the local environment reads back
                       over (Community Edition has no read-only role), not critical; read-portainer finds the local environment
    readback-dockhand  Dockhand behind an HTTPS proxy on the Docker host, without an enterprise key: the read-back raises the
                       critical "every user has full access" finding, which is what the free edition is; read-dockhand-inventory checks images and a scratch volume
    readback-komodo    Komodo Core with FerretDB and a Periphery on the Docker host: a service user in a Read group reads back
                       exact; read-komodo finds the server
Pangolin is not here: it needs a public domain, DNS and a certificate the lab does not have. Its read is tested on this machine only.
"""
import json
import re
import shlex
import time

import demo
import roles

from tiers_platform import sudo

PORTAINER_IMAGE = 'portainer/portainer-ce:lts'
DOCKHAND_IMAGE = 'fnsys/dockhand:latest'
XO_IMAGE = 'ronivay/xen-orchestra:latest'
CADDY_IMAGE = 'caddy:2'


def node_with(ability):
    sel = roles.state_dir() / 'selection'
    chosen = sel.read_text().split()[1:] if sel.exists() else []
    nodes = [n for n in roles.pool().values() if n.can(ability) and n.name in chosen]
    return nodes[0] if nodes else None


def fingerprint_of(node, port):
    out = sudo(node.name, f'echo | openssl s_client -connect 127.0.0.1:{port} 2>/dev/null | openssl x509 -noout -fingerprint -sha256', check=False)
    return out.strip().split('=', 1)[1] if '=' in out else None


def connect(r, api, node, kind, name, url, token_id, secret, secrets_seen, port):
    """Adds the connection, checks the certificate shown against the one the platform serves, accepts it and reads."""
    secrets_seen.append(secret)
    added = api.post('/api/keys/platforms', {'kind': kind, 'name': name, 'url': url, 'token_id': token_id, 'token': secret})
    cid = added['connection']['conn_id']
    shown = (added.get('certificate') or {}).get('sha256')
    real = fingerprint_of(node, port)
    r.add(f'cert-{kind}', node.name, shown is not None and shown == real, f'shown {shown}, served {real}')
    api.post(f'/api/keys/platforms/{cid}/certificate', {'sha256': shown})
    status, got = api.raw('POST', f'/api/keys/platforms/{cid}/read', {})
    return cid, (got if status == 200 else None), got


def truenas(r, api, secrets_seen):
    node = node_with('truenas')
    if not node:
        r.add('guide-truenas', '-', None, 'no TrueNAS in this build: up --join sf-truenas')
        r.add('read-truenas-snapshot', '-', None, 'no TrueNAS in this build')
        return
    guide = api.get('/api/keys/platforms/guide/truenas')
    key = None
    for step in guide['steps']:
        for cmd in step['run']:
            out = sudo(node.name, cmd, check=False)
            m = re.search(r'"key"\s*:\s*"([^"]+)"', out)
            key = key or (m.group(1) if m and 'api_key.create' in cmd else None)
    r.add('guide-truenas', node.name, bool(key), 'the key was made by the commands the guide shows' if key else 'no key in what TrueNAS printed')
    status, out = api.raw('POST', '/api/keys/platforms', {'kind': 'truenas', 'name': 'tn-admin', 'url': f'https://{node.ip}', 'token_id': 'truenas_admin', 'token': 'x' * 64})
    r.add('refused-truenas', node.name, status == 400 and 'FULL_ADMIN' in json.dumps(out), f'HTTP {status}')
    if not key:
        return
    snapshot = f'tank@sf-lab-inventory-{time.time_ns()}'
    sudo(node.name, f'zfs snapshot {snapshot}')
    try:
        cid, got, raw = connect(r, api, node, 'truenas', 'truenas', f'https://{node.ip}', 'storageforge', key, secrets_seen, 443)
        rb = (got or {}).get('readback') or {}
        r.add('readback-truenas', node.name, rb.get('verdict') == 'exact', f'verdict {rb.get("verdict")}', json.dumps(raw)[:2000])
        objects = api.get(f'/api/keys/platforms/{cid}')['objects'] if got else []
        r.add('read-truenas', node.name, any(o.get('ref') == 'tank' for o in objects if o['kind'] == 'pool'),
              json.dumps((got or {}).get('counts')))
        r.add('read-truenas-snapshot', node.name, any(o.get('ref') == snapshot and o.get('dataset') == 'tank'
                                                      for o in objects if o['kind'] == 'snapshot'),
              'the read-only key can see the lab snapshot')
    finally:
        sudo(node.name, f'zfs destroy {snapshot}', check=False)
    widen = ("midclt call privilege.update \"$(midclt call privilege.query '[[\"name\", \"=\", \"StorageForge read\"]]' '{\"get\": true}' | jq .id)\" "
             "'{\"roles\": [\"READONLY_ADMIN\", \"SHARING_ADMIN\"]}'")
    sudo(node.name, widen, check=False)
    status, wide = api.raw('POST', f'/api/keys/platforms/{cid}/read', {})
    over = status == 200 and wide['readback']['verdict'] == 'over'
    sudo(node.name, widen.replace(', \\"SHARING_ADMIN\\"', '').replace(', "SHARING_ADMIN"', ''), check=False)
    status, back = api.raw('POST', f'/api/keys/platforms/{cid}/read', {})
    r.add('over-truenas', node.name, over and status == 200 and back['readback']['verdict'] == 'exact', f'widened: {over}, narrowed: {status == 200 and back["readback"]["verdict"]}')


def docker_host():
    return node_with('docker')


def self_signed(node, folder, cn):
    sudo(node.name, f'mkdir -p {folder} && openssl req -x509 -newkey rsa:2048 -nodes -keyout {folder}/key.pem -out {folder}/cert.pem -days 30 -subj /CN={cn} '
                    f'-addext subjectAltName=IP:{node.ip} >/dev/null 2>&1')


def http_json(node, method, url, body=None, headers=(), stdin=None):
    """A request from the Docker host itself (curl, its body on stdin so no secret is on a command line)."""
    hs = ' '.join(f'-H {shlex.quote(h)}' for h in headers)
    data = '--data-binary @-' if body is not None else ''
    out = sudo(node.name, f'curl -sk -X {method} {hs} -H "Content-Type: application/json" {data} {shlex.quote(url)}', stdin=json.dumps(body) if body is not None else stdin, check=False)
    try:
        return json.loads(out)
    except ValueError:
        return {'raw': out[:500]}


def portainer(r, api, secrets_seen):
    node = docker_host()
    if not node:
        r.add('readback-portainer', '-', None, 'no Docker host in this build')
        return
    password = 'Sf-lab-' + str(int(time.time()))
    sudo(node.name, f'docker rm -f sf-portainer >/dev/null 2>&1; docker run -d --name sf-portainer -p 9443:9443 -v /var/run/docker.sock:/var/run/docker.sock {PORTAINER_IMAGE}', check=False)
    demo.wait('Portainer to answer', lambda: 'Version' in json.dumps(http_json(node, 'GET', 'https://127.0.0.1:9443/api/status')), timeout=180)
    base = 'https://127.0.0.1:9443/api'
    http_json(node, 'POST', f'{base}/users/admin/init', {'Username': 'labadmin', 'Password': password})
    jwt = http_json(node, 'POST', f'{base}/auth', {'Username': 'labadmin', 'Password': password}).get('jwt')
    auth = (f'Authorization: Bearer {jwt}',)
    http_json(node, 'POST', f'{base}/endpoints?Name=local&EndpointCreationType=1', None, auth)
    uid = http_json(node, 'POST', f'{base}/users', {'Username': 'storageforge', 'Password': password, 'Role': 2}, auth).get('Id')
    http_json(node, 'PUT', f'{base}/endpoints/1', {'UserAccessPolicies': {str(uid): {'RoleId': 0}}}, auth)
    ujwt = http_json(node, 'POST', f'{base}/auth', {'Username': 'storageforge', 'Password': password}).get('jwt')
    token = http_json(node, 'POST', f'{base}/users/{uid}/tokens', {'description': 'storageforge', 'password': password}, (f'Authorization: Bearer {ujwt}',)).get('rawAPIKey')
    if not token:
        r.add('readback-portainer', node.name, False, 'no access token was made')
        return
    cid, got, raw = connect(r, api, node, 'portainer', 'portainer', f'https://{node.ip}:9443', 'storageforge', token, secrets_seen, 9443)
    rb = (got or {}).get('readback') or {}
    r.add('readback-portainer', node.name, rb.get('verdict') == 'over' and not rb.get('admin') and rb.get('edition') == 'CE', f'verdict {rb.get("verdict")}, edition {rb.get("edition")}', json.dumps(raw)[:2000])
    r.add('read-portainer', node.name, bool(got) and (got['counts'].get('environment') or 0) >= 1, json.dumps((got or {}).get('counts')))


def dockhand(r, api, secrets_seen):
    node = docker_host()
    if not node:
        r.add('readback-dockhand', '-', None, 'no Docker host in this build')
        r.add('read-dockhand-inventory', '-', None, 'no Docker host in this build')
        return
    password = 'Sf-lab-' + str(int(time.time()))
    self_signed(node, '/srv/sf-dockhand-tls', node.ip)
    sudo(node.name, 'cat > /srv/sf-dockhand-tls/Caddyfile', stdin=(
        ':3443 {\n  tls /tls/cert.pem /tls/key.pem\n  reverse_proxy 127.0.0.1:3000\n}\n'))
    sudo(node.name, 'docker rm -f sf-dockhand sf-dockhand-tls >/dev/null 2>&1 || true')
    sudo(node.name, f'docker run -d --name sf-dockhand -p 127.0.0.1:3000:3000 -v /var/run/docker.sock:/var/run/docker.sock {DOCKHAND_IMAGE}')
    sudo(node.name, f'docker run -d --name sf-dockhand-tls --network host -v /srv/sf-dockhand-tls:/tls:ro {CADDY_IMAGE} '
                    'caddy run --config /tls/Caddyfile --adapter caddyfile')
    base = 'http://127.0.0.1:3000/api'
    demo.wait('Dockhand to answer', lambda: 'authEnabled' in json.dumps(http_json(node, 'GET', f'{base}/auth/session')), timeout=180)
    http_json(node, 'POST', f'{base}/environments',
              {'name': 'sf-lab-docker', 'connectionType': 'socket', 'socketPath': '/var/run/docker.sock'})
    http_json(node, 'POST', f'{base}/users', {'username': 'storageforge', 'password': password})
    http_json(node, 'PUT', f'{base}/auth/settings', {'authEnabled': True})
    sudo(node.name, f'rm -f /tmp/sf-dh.jar; curl -s -c /tmp/sf-dh.jar -H "Content-Type: application/json" --data-binary @- {base}/auth/login >/dev/null',
         stdin=json.dumps({'username': 'storageforge', 'password': password}), check=False)
    out = sudo(node.name, f'curl -s -b /tmp/sf-dh.jar -H "Content-Type: application/json" --data-binary @- {base}/auth/tokens; rm -f /tmp/sf-dh.jar',
               stdin=json.dumps({'name': 'storageforge', 'password': password, 'expiresAt': time.strftime('%Y-%m-%dT00:00:00Z', time.gmtime(time.time() + 300 * 86400))}), check=False)
    m = re.search(r'"token"\s*:\s*"(dh_[^"]+)"', out)
    if not m:
        r.add('readback-dockhand', node.name, False, 'no token was made', out[:300])
        return
    volume = f'sf-dockhand-inventory-{time.time_ns()}'
    sudo(node.name, f'docker volume create {volume}')
    try:
        cid, got, raw = connect(r, api, node, 'dockhand', 'dockhand', f'https://{node.ip}:3443', 'storageforge', m.group(1), secrets_seen, 3443)
        rb = (got or {}).get('readback') or {}
        r.add('readback-dockhand', node.name, rb.get('verdict') == 'over' and rb.get('admin') and 'full access' in json.dumps(rb.get('over')),
              f'verdict {rb.get("verdict")} (the free edition must be a critical finding)', json.dumps(raw)[:2000])
        objects = api.get(f'/api/keys/platforms/{cid}')['objects'] if got else []
        volume_envs = {o['environment'] for o in objects if o['kind'] == 'volume' and o.get('name') == volume}
        image_envs = {o['environment'] for o in objects if o['kind'] == 'image' and any(t in (DOCKHAND_IMAGE, f'docker.io/{DOCKHAND_IMAGE}') for t in o.get('tags', []))}
        r.add('read-dockhand-inventory', node.name, bool(volume_envs & image_envs),
              'the scratch volume and the Dockhand image appear in the same environment')
    finally:
        sudo(node.name, f'docker volume rm {volume}', check=False)


def xen_orchestra(r, api, secrets_seen):
    node, xcp = docker_host(), node_with('xen')
    if not node or not xcp:
        r.add('readback-xo', '-', None, 'needs the Docker host and sf-xcp: up --join sf-xcp')
        return
    admin_pw = (demo.STATE / 'admin-password').read_text().strip()
    self_signed(node, '/srv/sf-xo-tls', node.ip)
    sudo(node.name, f'docker rm -f sf-xo >/dev/null 2>&1; docker run -d --name sf-xo -p 8443:443 -e HTTPS_PORT=443 -e CERT_PATH=/tls/cert.pem -e KEY_PATH=/tls/key.pem '
                    f'-v /srv/sf-xo-tls:/tls:ro --cap-add SYS_ADMIN --security-opt apparmor=unconfined {XO_IMAGE}', check=False)
    base = 'https://127.0.0.1:8443/rest/v0'
    basic = 'Authorization: Basic ' + __import__('base64').b64encode(b'admin@admin.net:admin').decode()
    demo.wait('Xen Orchestra to answer', lambda: isinstance(http_json(node, 'GET', f'{base}/users/me', None, (basic,)), dict) and
              http_json(node, 'GET', f'{base}/users/me', None, (basic,)).get('permission') == 'admin', timeout=600)
    http_json(node, 'POST', f'{base}/servers', {'host': xcp.ip, 'username': 'root', 'password': admin_pw, 'allowUnauthorized': True}, (basic,))
    password = 'Sf-lab-' + str(int(time.time()))
    uid = (http_json(node, 'POST', f'{base}/users', {'name': 'storageforge', 'password': password, 'permission': 'none'}, (basic,)) or {}).get('id')
    role = (http_json(node, 'POST', f'{base}/acl-roles', {'name': 'StorageForge read'}, (basic,)) or {}).get('id')
    for res in ('pool', 'host', 'vm', 'sr', 'backup-job', 'backup-log'):
        http_json(node, 'POST', f'{base}/acl-privileges', {'resource': res, 'action': 'read', 'effect': 'allow', 'roleId': role}, (basic,))
    http_json(node, 'PUT', f'{base}/acl-roles/{role}/users/{uid}', None, (basic,))
    ubasic = 'Authorization: Basic ' + __import__('base64').b64encode(f'storageforge:{password}'.encode()).decode()
    token = ((http_json(node, 'POST', f'{base}/users/me/authentication_tokens', {}, (ubasic,)) or {}).get('token') or {}).get('id')
    if not token:
        r.add('readback-xo', node.name, False, 'no token was made')
        return
    cid, got, raw = connect(r, api, node, 'xo', 'xo', f'https://{node.ip}:8443', 'storageforge', token, secrets_seen, 8443)
    rb = (got or {}).get('readback') or {}
    r.add('readback-xo', node.name, rb.get('verdict') == 'exact', f'verdict {rb.get("verdict")}', json.dumps(raw)[:2000])
    r.add('read-xo', node.name, bool(got) and (got['counts'].get('xo-host') or 0) >= 1, json.dumps((got or {}).get('counts')))
    http_json(node, 'PATCH', f'{base}/users/{uid}', {'permission': 'admin'}, (basic,))
    status, wide = api.raw('POST', f'/api/keys/platforms/{cid}/read', {})
    r.add('over-xo', node.name, status == 200 and wide['readback']['verdict'] == 'over' and wide['readback']['admin'], f'HTTP {status}')


KOMODO_COMPOSE = """services:
  ferretdb:
    image: ghcr.io/ferretdb/ferretdb:1
    environment: {FERRETDB_HANDLER: sqlite}
    volumes: [sqlite:/state]
  core:
    image: ghcr.io/moghtech/komodo-core:2
    depends_on: [ferretdb]
    ports: ["9120:9120"]
    environment:
      KOMODO_DATABASE_ADDRESS: ferretdb:27017
      KOMODO_INIT_ADMIN_USERNAME: labadmin
      KOMODO_INIT_ADMIN_PASSWORD_FILE: /run/secrets/admin
      KOMODO_PASSKEY_FILE: /run/secrets/passkey
      KOMODO_SSL_ENABLED: "true"
      KOMODO_SSL_KEY_FILE: /tls/key.pem
      KOMODO_SSL_CERT_FILE: /tls/cert.pem
    volumes: ["/srv/sf-komodo-tls:/tls:ro", "/srv/sf-komodo-secrets:/run/secrets:ro"]
  periphery:
    image: ghcr.io/moghtech/komodo-periphery:2
    environment: {PERIPHERY_PASSKEYS_FILE: /run/secrets/passkey}
    volumes: ["/var/run/docker.sock:/var/run/docker.sock", "/srv/sf-komodo-secrets:/run/secrets:ro"]
volumes: {sqlite: {}}
"""


def komodo(r, api, secrets_seen):
    node = docker_host()
    if not node:
        r.add('readback-komodo', '-', None, 'no Docker host in this build')
        return
    password = 'Sf-lab-' + str(int(time.time()))
    self_signed(node, '/srv/sf-komodo-tls', node.ip)
    sudo(node.name, 'mkdir -p /srv/sf-komodo /srv/sf-komodo-secrets && umask 077 && cat > /srv/sf-komodo-secrets/admin && head -c 24 /dev/urandom | base64 > /srv/sf-komodo-secrets/passkey',
         stdin=password, check=False)
    sudo(node.name, 'cat > /srv/sf-komodo/compose.yml && cd /srv/sf-komodo && docker compose up -d', stdin=KOMODO_COMPOSE, check=False)
    base = 'https://127.0.0.1:9120'
    demo.wait('Komodo to answer', lambda: 'jwt' in json.dumps(http_json(node, 'POST', f'{base}/auth/LoginLocalUser', {'username': 'labadmin', 'password': password})), timeout=300)
    jwt = http_json(node, 'POST', f'{base}/auth/LoginLocalUser', {'username': 'labadmin', 'password': password}).get('jwt')
    auth = (f'Authorization: {jwt}',)
    http_json(node, 'POST', f'{base}/write/CreateServer', {'name': 'docker-lab', 'config': {'address': 'https://periphery:8120', 'enabled': True}}, auth)
    user = http_json(node, 'POST', f'{base}/write/CreateServiceUser', {'username': 'storageforge', 'description': 'StorageForge reads'}, auth)
    group = http_json(node, 'POST', f'{base}/write/CreateUserGroup', {'name': 'storageforge-read'}, auth)
    http_json(node, 'POST', f'{base}/write/AddUserToUserGroup', {'user_group': group.get('_id', {}).get('$oid') or 'storageforge-read', 'user': 'storageforge'}, auth)
    for kind in ('Server', 'Stack', 'Deployment'):
        http_json(node, 'POST', f'{base}/write/UpdatePermissionOnResourceType', {'user_target': {'type': 'UserGroup', 'id': 'storageforge-read'}, 'resource_type': kind, 'permission': 'Read'}, auth)
    keys = http_json(node, 'POST', f'{base}/write/CreateApiKeyForServiceUser', {'user_id': (user.get('_id') or {}).get('$oid'), 'name': 'storageforge',
                                                                                'expires': int(time.time() + 300 * 86400) * 1000}, auth)
    if not keys.get('key') or not keys.get('secret'):
        r.add('readback-komodo', node.name, False, 'no API key was made', json.dumps({k: v for k, v in keys.items() if k != 'secret'})[:300])
        return
    cid, got, raw = connect(r, api, node, 'komodo', 'komodo', f'https://{node.ip}:9120', keys['key'], keys['secret'], secrets_seen, 9120)
    rb = (got or {}).get('readback') or {}
    r.add('readback-komodo', node.name, rb.get('verdict') == 'exact', f'verdict {rb.get("verdict")}', json.dumps(raw)[:2000])
    r.add('read-komodo', node.name, bool(got) and (got['counts'].get('environment') or 0) >= 1, json.dumps((got or {}).get('counts')))


def platforms(r, api, secrets_seen):
    for check in (truenas, xen_orchestra, portainer, dockhand, komodo):
        try:
            check(r, api, secrets_seen)
        except Exception as exc:            # one platform that will not come up must not stop the others, nor the no-secret check after
            r.add(f'{check.__name__}', '-', False, f'{type(exc).__name__}: {str(exc)[:200]}')
