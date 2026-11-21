#!/usr/bin/env python3
"""Tier 27 of the KVM lab: API connections to Proxmox VE, Backup Server and Datacenter Manager (roadmap section 13, 0.5.10).

NOT RUN. This file was written on 2026-11-20 where the KVM lab cannot run, so no check below has ever passed or failed on a real VM: it
is not lab-tested. What was run is tests/test_apiconn.py, test_apiguide.py, test_apireadback.py, test_apipve.py, test_apipbs.py and
test_apipdm.py on this machine, against a real TLS server on 127.0.0.1 answering with JSON built from each API's documentation. A first
run will most likely have to correct this file. A check that cannot be made shows as skip or as failed, never as passed.

The appliances join a build only by `lab.sh up --pick` or `--join`: sf-pve (already in nodes.conf), sf-pbs and sf-pdm (added for this
tier, installed from the vendor ISOs with Proxmox's own unattended installer, provision/appliance.py). sf-pbs gets a datastore store1 on
its data disk. sf-pdm gets sf-pve and sf-pbs as its remotes, each with a token of its own made on that remote.

    guide-<kind>            the guide's commands, fetched from StorageForge, run on the appliance as root exactly as written, make the
                            user and the token; the token's secret is taken from what the platform printed once
    cert-<kind>             the certificate StorageForge shows before anything is sent is the one openssl reads from the platform's own
                            certificate file, and is accepted
    readback-<kind>         the read-back finds the token exactly right: no feature short, nothing over
    read-<kind>             the read finds what the platform holds (a guest made with qm, the datastore store1, both remotes)
    short-pve               the token given PVEAuditor on /vms, /storage and /nodes only: the backup jobs alone are skipped, and the
                            read-back says to add Sys.Audit on /
    over-<kind>             a second token given the full role (Administrator, Admin) raises the security finding, critical
    over-cannot-mute        snoozing that finding is refused
    over-leaves             the token narrowed on the platform: the next read clears the finding
    cert-changed            sf-pve's certificate made again (pvecm updatecerts --force): the next read sends nothing, the connection
                            says certificate-changed, and a critical finding is raised
    no-secret               no token secret in the container's log, the audit log, a notification or any API answer of this tier
"""
import json
import re
import shlex
import time

import demo
import roles

from tiers_platform import sudo

CERT = {'pve': '/etc/pve/local/pve-ssl.pem', 'pbs': '/etc/proxmox-backup/proxy.pem', 'pdm': '/etc/proxmox-datacenter-manager/auth/api.pem'}
PORT = {'pve': 8006, 'pbs': 8007, 'pdm': 8443}
SCOPE = {'pve': None, 'pbs': 'store1', 'pdm': 'sf-pve sf-pbs'}
FULL_ROLE = {'pve': ('pveum acl modify / -token {t} -role Administrator', 'pveum acl delete / -token {t} -role Administrator'),
             'pbs': ('proxmox-backup-manager acl update / Admin --auth-id {t}', 'proxmox-backup-manager acl update / Admin --auth-id {t} --delete true'),
             'pdm': ('proxmox-datacenter-manager-client acl update / Administrator --auth-id {t}', 'proxmox-datacenter-manager-client acl delete / Administrator --auth-id {t}')}


def appliance(ability):
    nodes = [n for n in roles.pool().values() if n.can(ability) and n.name in (roles.state_dir() / 'selection').read_text().split()[1:]] \
        if (roles.state_dir() / 'selection').exists() else []
    return nodes[0] if nodes else None


def secret_from(kind, out):
    """The token's secret from what the platform printed the one time it shows it."""
    if kind == 'pve':                     # pveum prints a table: | value | <uuid> |
        m = re.search(r'value\s*[│|]\s*([0-9a-f-]{36})', out)
    else:                                 # proxmox-backup-manager prints Result: {"tokenid": ..., "value": ...}
        m = re.search(r'"value"\s*:\s*"([^"]+)"', out)
    return m.group(1) if m else None


def run_guide(node, kind, guide):
    """Each step's commands as written. Returns the secret the token step printed."""
    secret = None
    for step in guide['steps']:
        for cmd in step['run']:
            out = sudo(node.name, cmd, check=False)
            secret = secret or (secret_from(kind, out) if 'token add' in cmd or 'generate-token' in cmd else None)
    return secret


def pdm_token(node, user, token):
    """PDM's documentation gives no command that makes a token, so this asks its API on the appliance itself, as root@pam with the lab's
    admin password, the way its web interface does."""
    password = (demo.STATE / 'admin-password').read_text().strip()
    script = (f'set -e; t=$(curl -sk -d username=root@pam --data-urlencode password@- https://127.0.0.1:8443/api2/json/access/ticket); '
              'ticket=$(printf %s "$t" | python3 -c "import json,sys; print(json.load(sys.stdin)[\\"data\\"][\\"ticket\\"])"); '
              'csrf=$(printf %s "$t" | python3 -c "import json,sys; print(json.load(sys.stdin)[\\"data\\"][\\"CSRFPreventionToken\\"])"); '
              f'curl -sk -X POST -b "PDMAuthCookie=$ticket" -H "CSRFPreventionToken: $csrf" -d expire={int(time.time()) + 365 * 86400} '
              f'https://127.0.0.1:8443/api2/json/access/users/{user}/token/{token}')
    return secret_from('pdm', sudo(node.name, script, stdin=password, check=False))


def remotes_for_pdm(pdm, pve, pbs):
    """sf-pve and sf-pbs as PDM's remotes, each with an auditing token made on that remote for PDM."""
    for node, kind in ((pve, 'pve'), (pbs, 'pbs')):
        if not node:
            continue
        if kind == 'pve':
            out = sudo(node.name, 'pveum user add pdm@pve -comment PDM 2>/dev/null; pveum acl modify / -user pdm@pve -role PVEAuditor; '
                                  'pveum user token add pdm@pve pdm -privsep 1 2>&1; pveum acl modify / -token "pdm@pve!pdm" -role PVEAuditor', check=False)
        else:
            out = sudo(node.name, 'proxmox-backup-manager user create pdm@pbs 2>/dev/null; proxmox-backup-manager acl update /datastore/store1 DatastoreAudit --auth-id pdm@pbs; '
                                  'proxmox-backup-manager user generate-token pdm@pbs pdm 2>&1; proxmox-backup-manager acl update /datastore/store1 DatastoreAudit --auth-id "pdm@pbs!pdm"', check=False)
        secret = secret_from(kind, out)
        fp = sudo(node.name, f'openssl x509 -noout -fingerprint -sha256 -in {CERT[kind]}').strip().split('=', 1)[1]
        if secret:
            sudo(pdm.name, f'proxmox-datacenter-manager-admin remote add --type {kind} --id {node.name} --nodes {shlex.quote(f"hostname={node.ip},fingerprint={fp}")} '
                           f'--authid {shlex.quote(f"pdm@{kind}!pdm")} --token "$(cat)"', stdin=secret, check=False)


def connect(r, api, node, kind, name, token_id, secret, secrets_seen):
    """Adds the connection, checks the certificate against the platform's file, accepts it, and reads. Returns the read's answer or None."""
    secrets_seen.append(secret)
    added = api.post('/api/keys/platforms', {'kind': kind, 'name': name, 'url': f'https://{node.ip}:{PORT[kind]}', 'token_id': token_id, 'token': secret})
    cid = added['connection']['conn_id']
    shown = (added.get('certificate') or {}).get('sha256')
    real = sudo(node.name, f'openssl x509 -noout -fingerprint -sha256 -in {CERT[kind]}').strip().split('=', 1)[1]
    if name == kind:
        r.add(f'cert-{kind}', node.name, shown == real, f'shown {shown}, the file says {real}')
    api.post(f'/api/keys/platforms/{cid}/certificate', {'sha256': shown})
    status, got = api.raw('POST', f'/api/keys/platforms/{cid}/read', {})
    return cid, (got if status == 200 else None), got


def notification(api, key):
    center = api.get('/api/notifications')
    items = [x for group in ('items', 'quiet') for x in center.get(group) or []]
    return next((x for x in items if x.get('key') == key or x.get('alert_key') == key), None)


def tier27(r):
    api = demo.sign_in()
    nodes = {'pve': appliance('proxmox'), 'pbs': appliance('pbs'), 'pdm': appliance('pdm')}
    secrets_seen = []
    if nodes['pdm']:
        remotes_for_pdm(nodes['pdm'], nodes['pve'], nodes['pbs'])
    for kind, node in nodes.items():
        if not node:
            r.add(f'guide-{kind}', '-', None, f'no {kind} appliance in this build: up --join sf-{kind}')
            continue
        q = f'?scope={SCOPE[kind].replace(" ", "+")}' if SCOPE[kind] else ''
        guide = api.get(f'/api/keys/platforms/guide/{kind}{q}')
        secret = run_guide(node, kind, guide) if kind != 'pdm' else (run_guide(node, kind, guide) or pdm_token(node, 'storageforge@pdm', 'storageforge'))
        if kind == 'pdm' and secret:
            run_guide(node, kind, guide)          # the ACL steps again, now that the token exists
        r.add(f'guide-{kind}', node.name, bool(secret), 'the token was made by the commands the guide shows' if secret else 'no token secret in what the platform printed')
        if not secret:
            continue
        cid, got, raw = connect(r, api, node, kind, kind, f'storageforge@{kind}!storageforge', secret, secrets_seen)
        if not got:
            r.add(f'readback-{kind}', node.name, False, 'the read failed', json.dumps(raw)[:2000])
            continue
        rb = got['readback']
        r.add(f'readback-{kind}', node.name, rb['verdict'] == 'exact', f'verdict {rb["verdict"]}', json.dumps({'short': rb['short'], 'over': rb['over']}))
        counts = got['counts']
        want = {'pve': counts.get('node', 0) >= 1, 'pbs': counts.get('datastore', 0) >= 1, 'pdm': counts.get('remote', 0) >= 2}[kind]
        r.add(f'read-{kind}', node.name, want, json.dumps(counts))

        if kind == 'pve':                         # one privilege too few: Sys.Audit on / only
            sudo(node.name, 'pveum acl delete / -token "storageforge@pve!storageforge" -role PVEAuditor; '
                            'for p in /vms /storage /nodes; do pveum acl modify $p -token "storageforge@pve!storageforge" -role PVEAuditor; done')
            status, short = api.raw('POST', f'/api/keys/platforms/{cid}/read', {})
            feats = [s['feature'] for s in (short.get('readback') or {}).get('short', [])] if status == 200 else []
            r.add('short-pve', node.name, feats == ['backup-jobs'] and 'backup jobs: the token lacks Sys.Audit on /' in short.get('skipped', []), json.dumps(feats))
            sudo(node.name, 'pveum acl modify / -token "storageforge@pve!storageforge" -role PVEAuditor')

        # a second token with the full role: the finding, which cannot be muted, and which leaves when the token is narrowed
        tid = f'storageforge@{kind}!wide'
        made = sudo(node.name, f'pveum user token add storageforge@pve wide -privsep 1' if kind == 'pve' else
                    f'proxmox-backup-manager user generate-token storageforge@{kind} wide' if kind == 'pbs' else 'true', check=False)
        wide = secret_from(kind, made) if kind != 'pdm' else pdm_token(node, 'storageforge@pdm', 'wide')
        if not wide:
            r.add(f'over-{kind}', node.name, False, 'the second token was not made')
            continue
        grant, revoke = (c.format(t=shlex.quote(tid)) for c in FULL_ROLE[kind])
        guide_acl = {'pve': f'pveum acl modify / -user storageforge@pve -role Administrator; ', 'pbs': 'proxmox-backup-manager acl update / Admin --auth-id storageforge@pbs; ',
                     'pdm': 'proxmox-datacenter-manager-client acl update / Administrator --auth-id storageforge@pdm; '}[kind]
        sudo(node.name, guide_acl + grant, check=False)          # a token never has more than its user: the user is widened too, for this check
        wcid, wgot, wraw = connect(r, api, node, kind, f'{kind}-wide', tid, wide, secrets_seen)
        key = f'security-api-token:{kind}-wide'
        demo.wait('the alerts to be evaluated', lambda: notification(api, key), timeout=300) if wgot else None
        n = notification(api, key)
        r.add(f'over-{kind}', node.name, bool(n) and n.get('level') == 'crit', json.dumps(n)[:300] if n else json.dumps(wraw)[:300])
        if n:
            status, out = api.raw('POST', f'/api/notifications/snooze/{key}', {'seconds': 3600})
            r.add('over-cannot-mute', node.name, status >= 400, f'HTTP {status}')
        sudo(node.name, revoke, check=False)
        sudo(node.name, {'pve': 'pveum acl delete / -user storageforge@pve -role Administrator; pveum acl modify / -token "storageforge@pve!wide" -role PVEAuditor',
                         'pbs': 'proxmox-backup-manager acl update / Admin --auth-id storageforge@pbs --delete true; proxmox-backup-manager acl update /datastore/store1 DatastoreAudit --auth-id "storageforge@pbs!wide"',
                         'pdm': 'proxmox-datacenter-manager-client acl delete / Administrator --auth-id storageforge@pdm; proxmox-datacenter-manager-client acl update /resource/sf-pve Auditor --auth-id "storageforge@pdm!wide"'}[kind], check=False)
        api.raw('POST', f'/api/keys/platforms/{wcid}/read', {})
        gone = demo.wait('the finding to leave', lambda: not notification(api, key) or notification(api, key).get('state') == 'resolved', timeout=300) if n else False
        r.add('over-leaves', node.name, bool(gone), 'resolved after the token was narrowed' if gone else 'still open')

    pve = nodes['pve']
    if pve and any(c['name'] == 'pve' for c in api.get('/api/keys/platforms')['connections']):
        cid = next(c['conn_id'] for c in api.get('/api/keys/platforms')['connections'] if c['name'] == 'pve')
        sudo(pve.name, 'pvecm updatecerts --force && systemctl restart pveproxy', check=False)
        time.sleep(10)
        status, out = api.raw('POST', f'/api/keys/platforms/{cid}/read', {})
        row = out.get('connection') or {}
        r.add('cert-changed', pve.name, status == 502 and row.get('state') == 'certificate-changed', f'HTTP {status}, state {row.get("state")}')
    else:
        r.add('cert-changed', '-', None, 'no sf-pve connection to change the certificate under')

    import tiers_api2
    tiers_api2.platforms(r, api, secrets_seen)        # TrueNAS, Xen Orchestra and the panels (0.5.10 part 2)

    logs = demo.ssh('sf-ctl', f'{demo.COMPOSE} logs --no-color storageforge 2>&1 | tail -n 20000', check=False)
    answers = json.dumps([api.get('/api/keys/platforms'), api.get('/api/notifications')])
    audit = demo.ssh('sf-ctl', f'{demo.COMPOSE} exec -T storageforge python -c '
                     + shlex.quote("import sqlite3; c = sqlite3.connect('/app/data/index.db'); print(c.execute('SELECT group_concat(detail_json) FROM audit_log').fetchone()[0])"), check=False)
    leaked = [s[:6] for s in secrets_seen if s and (s in logs or s in answers or s in audit)]
    r.add('no-secret', 'sf-ctl', not leaked if secrets_seen else None, f'{len(secrets_seen)} secrets looked for' + (f'; found {leaked}' if leaked else ''))
