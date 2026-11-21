"""The permission guide (roadmap section 13): what a platform token needs, shown before a token is asked for.

Per platform: the least that reading needs, and apart from it what each action needs, on which object, said when the action is turned
on and never before. Then step by step how to make such a token on that platform, with the commands ready to copy. The recommendation
is always the narrowest that works, and never root, an admin key or a full-access role.

Written from each platform's documentation as published on FETCHED (the pages in SOURCES), not from memory: the role and privilege
names, the paths, the commands and their options are the ones those pages give. The read-back (apireadback.py) checks a token against
what is written here, so a privilege named here is also what the read-back allows.
"""
from __future__ import annotations

import re
import shlex
import time

FETCHED = '2026-11-20'
SOURCES = {
    'pve': ['https://pve.proxmox.com/pve-docs/chapter-pveum.html (Proxmox VE 9.2.15: API tokens, roles, privileges, paths, "Limited API Token for Monitoring")',
            'https://pve.proxmox.com/pve-docs/api-viewer/apidoc.js (the permission each API call checks)'],
    'pbs': ['https://pbs.proxmox.com/docs/user-management.html (API tokens, privileges, access roles, API token permissions)',
            'https://pbs.proxmox.com/docs/proxmox-backup-manager/synopsis.html (user create, user generate-token --expire, acl update)',
            'https://pbs.proxmox.com/docs/api-viewer/apidoc.js'],
    'pdm': ['https://pdm.proxmox.com/docs/access-control.html (Proxmox Datacenter Manager 1.1.10: API tokens, privileges, the three built-in roles, /resource paths)',
            'https://pdm.proxmox.com/docs/command-syntax.html (proxmox-datacenter-manager-client user create and acl update)',
            'https://pdm.proxmox.com/docs/api-viewer/apidoc.js'],
}
NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,63}')
EXPIRE_DAYS = 365

# What each platform's read-back sees, and what the guide allows. read: feature -> the privileges it needs (any one of the paths). Every
# privilege whose name ends in .Audit only reads; anything else changes something and is allowed only for an action turned on.
# admin: privileges that give control of the platform itself (its users, permissions, system), which no StorageForge feature needs.
GUIDES = {
    'pve': {
        'title': 'Proxmox VE',
        'least': 'a user storageforge@pve with no password, an API token with privilege separation on, and the token and the user given PVEAuditor on /',
        'role': 'PVEAuditor',
        'why_role': 'PVEAuditor has read only access: its privileges are the .Audit ones (VM.Audit, Sys.Audit, Datastore.Audit and the like), which view and change nothing.',
        'scope': 'On / for everything. To keep the rest of the cluster hidden, give it on /vms, /storage and /nodes instead; the backup jobs are then not read, since listing them checks Sys.Audit on /.',
        'read': {
            'guests': {'privs': ['VM.Audit'], 'paths': ['/', '/vms', '/pool'], 'what': 'guests (VMs and containers), their state, memory and disks'},
            'nodes': {'privs': ['Sys.Audit'], 'paths': ['/', '/nodes'], 'what': 'cluster nodes and their state'},
            'storage': {'privs': ['Datastore.Audit'], 'paths': ['/', '/storage'], 'what': 'storage, and the backups kept on it with their verification'},
            'backup-jobs': {'privs': ['Sys.Audit'], 'paths': ['/'], 'what': 'the backup jobs (/cluster/backup checks Sys.Audit on /)'},
        },
        'actions': {
            'snapshot': {'title': 'take and delete snapshots', 'privs': ['VM.Snapshot'], 'on': '/vms/<vmid> or /pool/<pool>', 'role': 'StorageForgeSnapshot'},
            'rollback': {'title': 'roll a guest back to a snapshot', 'privs': ['VM.Snapshot.Rollback'], 'on': '/vms/<vmid> or /pool/<pool>', 'role': 'StorageForgeRollback'},
            'backup': {'title': 'start a backup of a guest', 'privs': ['VM.Backup', 'Datastore.AllocateSpace'], 'on': '/vms/<vmid> for VM.Backup, and /storage/<target> for Datastore.AllocateSpace', 'role': 'StorageForgeBackup'},
            'power': {'title': 'start and stop guests', 'privs': ['VM.PowerMgmt'], 'on': '/vms/<vmid> or /pool/<pool>', 'role': 'StorageForgePower'},
        },
        'admin': ['Permissions.Modify', 'User.Modify', 'Realm.Allocate', 'Realm.AllocateUser', 'Group.Allocate', 'Sys.Modify', 'Sys.Console', 'Sys.PowerMgmt'],
        'never': ['root@pam or a token of root@pam (refused here)', 'the Administrator, PVEAdmin, PVEVMAdmin or PVESysAdmin role',
                  'a token with privilege separation off: it then has every right of its user', 'Permissions.Modify or Sys.Modify anywhere'],
        'check': 'pveum user token permissions storageforge@pve storageforge',
        'expiry': {'allowed': True, 'read_back': True, 'how': 'pveum user token add takes -expire (epoch seconds); the read-back reads it from the token, and a warning comes 30 days before it lapses'},
    },
    'pbs': {
        'title': 'Proxmox Backup Server',
        'least': 'a user storageforge@pbs with no password and an API token, both given DatastoreAudit on /datastore/<name> for each datastore it should see',
        'role': 'DatastoreAudit',
        'why_role': 'DatastoreAudit can view datastore metrics, settings and list content, but is not allowed to read the actual data.',
        'scope': 'One ACL entry per datastore (/datastore/<name>), not /datastore for all of them unless all should be seen. A new token has no permissions: it needs its own ACL entry, and can never do more than its user.',
        'read': {
            'datastores': {'privs': ['Datastore.Audit'], 'paths': ['/', '/datastore'], 'what': 'datastores, backup groups and snapshots with their verification, verify and prune jobs'},
        },
        'actions': {
            'restore-test': {'title': 'read backup contents to test a restore', 'privs': ['Datastore.Read'], 'on': '/datastore/<name>', 'role': 'DatastoreReader'},
            'backup': {'title': 'send backups from StorageForge itself', 'privs': ['Datastore.Backup'], 'on': '/datastore/<name>', 'role': 'DatastoreBackup'},
        },
        'admin': ['Permissions.Modify', 'Sys.Modify', 'Sys.Console', 'Sys.PowerManagement', 'Realm.Allocate', 'Datastore.Allocate', 'Remote.Modify'],
        'never': ['root@pam or a token of root@pam (refused here)', 'the Admin or DatastoreAdmin role', 'an ACL on / or /datastore when only some datastores should be seen'],
        'check': "proxmox-backup-manager user permissions 'storageforge@pbs!storageforge' --path /datastore/<name>",
        'expiry': {'allowed': True, 'read_back': True, 'how': 'proxmox-backup-manager user generate-token takes --expire (epoch seconds); the read-back reads it from the token, and a warning comes 30 days before it lapses'},
    },
    'pdm': {
        'title': 'Proxmox Datacenter Manager',
        'least': 'a user storageforge@pdm and an API token, both given the built-in Auditor role on /resource/<remote> for each remote it should see, not on /',
        'role': 'Auditor',
        'why_role': 'Auditor can view the status and configuration of things, but is not allowed to change settings. PDM has only three roles (NoAccess, Administrator, Auditor) and no custom ones, so the narrowest is Auditor on the narrowest path.',
        'scope': 'One ACL entry per remote (/resource/<remote>). A new token has no permissions: its rights are those of its own ACL entries, intersected with its user.',
        'read': {
            'remotes': {'privs': ['Resource.Audit'], 'paths': ['/', '/resource'], 'what': 'the remotes it may see, and their nodes, guests, storage and datastores'},
        },
        'actions': {},
        'no_actions': 'No action is offered: PDM has no built-in role narrower than Administrator that may manage or migrate guests, and StorageForge never recommends Administrator.',
        'admin': ['Access.Modify', 'System.Modify', 'Sys.Console', 'Sys.PowerManagement', 'Realm.Allocate'],
        'never': ['root@pam or a token of root@pam (refused here)', 'the Administrator role, on any path', 'the Auditor role on / when only some remotes should be seen'],
        'reach': 'PDM holds its own token to every remote it manages, so a PDM token reaches as far as PDM does. Connecting each Proxmox VE and Backup Server directly, each with its own narrower token, is the tighter choice.',
        'check': 'proxmox-datacenter-manager-client acl list',
        'expiry': {'allowed': True, 'read_back': True, 'how': 'the web interface sets an expiry date when it makes the token; the read-back reads it from the token, and a warning comes 30 days before it lapses'},
    },
}


class GuideError(ValueError):
    pass


def actions(kind: str) -> list[str]:
    return sorted((GUIDES.get(kind) or {}).get('actions', {}))


def _names(value, what: str) -> list[str]:
    if isinstance(value, str):
        value = value.replace(',', ' ').split()
    value = [str(x) for x in (value or [])]
    bad = [x for x in value if not NAME.fullmatch(x)]
    if bad:
        raise GuideError(f'{what} are letters, digits, dot, dash and underscore')
    return value


def _q(text: str) -> str:
    return shlex.quote(text)


def steps(kind: str, user: str = 'storageforge', token: str = 'storageforge', scope=None, now: float | None = None) -> list[dict]:
    """How to make the least token for reading, step by step. scope: pve: the paths ('/' when none); pbs: the datastores; pdm: the
    remotes. Each step: {'say', 'run' (commands to copy, may be empty), 'where'}."""
    if kind not in GUIDES:
        raise GuideError(f'the platform is one of {", ".join(GUIDES)}')
    for v, what in ((user, 'the user name'), (token, 'the token name')):
        if not NAME.fullmatch(v or ''):
            raise GuideError(f'{what} is letters, digits, dot, dash and underscore')
    expire = int((time.time() if now is None else now) + EXPIRE_DAYS * 86400)
    when = time.strftime('%Y-%m-%d', time.gmtime(expire))
    if kind in PLATFORMS:
        return module(kind).steps(user, token, scope, expire)
    if kind == 'pve':
        uid = f'{user}@pve'
        tid = f'{uid}!{token}'
        paths = [p for p in (scope if isinstance(scope, list) else str(scope or '/').split()) if p]
        bad = [p for p in paths if not re.fullmatch(r'/(vms|storage|nodes|pool(/[A-Za-z0-9._-]+)?)?', p)]
        if bad:
            raise GuideError('the paths are /, /vms, /storage, /nodes or /pool/<name>')
        acl_user = [f'pveum acl modify {p} -user {uid} -role PVEAuditor' for p in paths]
        acl_token = [f'pveum acl modify {p} -token {_q(tid)} -role PVEAuditor' for p in paths]
        return [
            {'where': 'a shell on any node of the cluster, as root', 'say': f'Make a user for StorageForge in the Proxmox VE realm. It gets no password, so it cannot sign in to the web interface; only its token is used.',
             'run': [f'pveum user add {uid} -comment {_q("StorageForge: reads through the API")}']},
            {'where': 'the same shell', 'say': 'Give the user PVEAuditor (read only). A token with privilege separation can never have a permission its user does not have, so the user needs it too.',
             'run': acl_user},
            {'where': 'the same shell', 'say': f'Make the token with privilege separation on (-privsep 1) and an expiry date ({when}, a year from now). The secret is shown once: copy it for the next screen.',
             'run': [f'pveum user token add {uid} {token} -privsep 1 -expire {expire}']},
            {'where': 'the same shell', 'say': 'Give the token itself PVEAuditor on the same paths: a separated token starts with no permissions.', 'run': acl_token},
            {'where': 'the same shell', 'say': 'Check what the token can do. Only .Audit privileges should be listed. StorageForge reads the same back after you enter the token.',
             'run': [f'pveum user token permissions {uid} {token}']},
        ]
    if kind == 'pbs':
        uid = f'{user}@pbs'
        tid = f'{uid}!{token}'
        stores = _names(scope, 'datastores') or ['<datastore>']
        return [
            {'where': 'a shell on the Backup Server, as root', 'say': 'Make a user for StorageForge in the Proxmox Backup authentication server realm, with no password.',
             'run': [f'proxmox-backup-manager user create {uid} --comment {_q("StorageForge: reads through the API")}']},
            {'where': 'the same shell', 'say': 'Give the user DatastoreAudit on each datastore StorageForge should see: it lists content but cannot read the data. An API token can never do more than its user.',
             'run': [f'proxmox-backup-manager acl update /datastore/{s} DatastoreAudit --auth-id {uid}' for s in stores]},
            {'where': 'the same shell', 'say': f'Make the token, with an expiry date ({when}, a year from now). The value is shown once: copy it for the next screen.',
             'run': [f'proxmox-backup-manager user generate-token {uid} {token} --expire {expire}']},
            {'where': 'the same shell', 'say': 'Give the token its own ACL entries: a new token has no permissions of its own.',
             'run': [f'proxmox-backup-manager acl update /datastore/{s} DatastoreAudit --auth-id {_q(tid)}' for s in stores]},
            {'where': 'the same shell', 'say': 'Check what the token can do: only Datastore.Audit should be listed.',
             'run': [f'proxmox-backup-manager user permissions {_q(tid)} --path /datastore/{s}' for s in stores]},
        ]
    uid = f'{user}@pdm'
    tid = f'{uid}!{token}'
    remotes = _names(scope, 'remotes') or ['<remote>']
    return [
        {'where': 'a shell on the Datacenter Manager, as root (the client asks for the root@pam password)', 'say': 'Make a user for StorageForge in the Proxmox Datacenter Manager realm, with no password.',
         'run': [f'proxmox-datacenter-manager-client user create {uid} --comment {_q("StorageForge: reads through the API")}']},
        {'where': 'the Datacenter Manager web interface, Configuration, Access Control', 'say': f'Make an API token for {uid} named {token}, with an expiry date ({when}). The documentation gives no command for this; the web interface makes it. The secret is shown once: copy it for the next screen.',
         'run': []},
        {'where': 'the shell again', 'say': 'Give the user the Auditor role on each remote StorageForge should see, not on /.',
         'run': [f'proxmox-datacenter-manager-client acl update /resource/{r} Auditor --auth-id {uid}' for r in remotes]},
        {'where': 'the same shell', 'say': 'Give the token the same: a new token has no permissions, and never more than its user.',
         'run': [f'proxmox-datacenter-manager-client acl update /resource/{r} Auditor --auth-id {_q(tid)}' for r in remotes]},
        {'where': 'the same shell', 'say': 'Check the entries: only Auditor, only on the remotes you chose.', 'run': ['proxmox-datacenter-manager-client acl list']},
    ]


def action_steps(kind: str, action: str, user: str = 'storageforge', token: str = 'storageforge') -> list[dict]:
    """What turning one action on needs, said at the moment it is turned on: a custom role holding only its privileges, given to the user
    and to the token on the one object. PBS has no custom roles, so its own narrowest built-in role is named."""
    g = GUIDES.get(kind) or {}
    a = (g.get('actions') or {}).get(action)
    if not a:
        raise GuideError(g.get('no_actions') or f'{g.get("title", kind)} has no action {action}')
    if kind in PLATFORMS:
        return module(kind).action_steps(action, a, user)
    if kind == 'pve':
        uid, tid = f'{user}@pve', f'{user}@pve!{token}'
        privs = ' '.join(a['privs'])
        target = '/vms/<vmid>'
        run = [f'pveum role add {a["role"]} -privs {_q(privs)}',
               f'pveum acl modify {target} -user {uid} -role {a["role"]}',
               f'pveum acl modify {target} -token {_q(tid)} -role {a["role"]}']
        if action == 'backup':
            run += [f'pveum acl modify /storage/<target> -user {uid} -role {a["role"]}', f'pveum acl modify /storage/<target> -token {_q(tid)} -role {a["role"]}']
        return [{'where': 'a shell on any node, as root', 'say': f'To {a["title"]}: a role with only {", ".join(a["privs"])}, on {a["on"]}, for the user and its token. Not on /.', 'run': run}]
    uid, tid = f'{user}@pbs', f'{user}@pbs!{token}'
    return [{'where': 'a shell on the Backup Server, as root', 'say': f'To {a["title"]}: {a["role"]} ({", ".join(a["privs"])}) on {a["on"]}, for the user and its token. PBS has no custom roles, so this is its narrowest.',
             'run': [f'proxmox-backup-manager acl update {a["on"]} {a["role"]} --auth-id {uid}', f'proxmox-backup-manager acl update {a["on"]} {a["role"]} --auth-id {_q(tid)}']}]


def guide(kind: str, **kw) -> dict:
    """Everything the connect screen shows before the token is asked for."""
    if kind not in GUIDES:
        raise GuideError(f'the platform is one of {", ".join(GUIDES)}')
    g = GUIDES[kind]
    return {'kind': kind, 'title': g['title'], 'least': g['least'], 'role': g['role'], 'why_role': g['why_role'], 'scope': g['scope'],
            'read': [{'feature': f, **v} for f, v in g['read'].items()],
            'actions': [{'action': k, **v} for k, v in g['actions'].items()], 'no_actions': g.get('no_actions'),
            'never': g['never'], 'reach': g.get('reach'), 'steps': steps(kind, **kw), 'sources': SOURCES[kind], 'fetched': g.get('fetched', FETCHED), 'expiry': g['expiry'],
            'label': 'not lab-tested'}


SCOPE_HINTS = {'pve': ('Paths: / for all, or /vms /storage /nodes to keep the rest hidden.', '/'),
               'pbs': ('The datastores it should see, separated by spaces.', 'store1'), 'pdm': ('The remotes it should see, separated by spaces.', 'pve-a pbs-b')}


def kinds() -> list[dict]:
    """The platforms, with what the connect screen says beside each field for them."""
    from . import apiconn
    out = []
    for k, g in GUIDES.items():
        spec = apiconn.KINDS[k]
        hint, placeholder = g.get('scope_hint') or SCOPE_HINTS.get(k, ('', ''))
        out.append({'kind': k, 'title': g['title'], 'least': g['least'], 'port': spec['port'], 'token_id_hint': spec['token_id'][1],
                    'token_id_placeholder': g.get('token_id_placeholder') or f'storageforge@{k}!storageforge', 'cert_file': spec['cert_file'],
                    'scope_hint': hint, 'scope_placeholder': placeholder})
    return out


# The platforms beyond Proxmox each keep their guide beside their reader: GUIDE (the same fields as GUIDES above), SOURCES (the pages it
# was written from, fetched on the date each gives), steps(user, token, scope, expire) and action_steps(action, spec, user).
PLATFORMS = {}


def module(kind: str):
    import importlib
    return importlib.import_module(f'.{PLATFORMS[kind]}', __package__)


def register(kind: str, module_name: str) -> None:
    PLATFORMS[kind] = module_name
    mod = module(kind)
    GUIDES[kind] = mod.GUIDE
    SOURCES[kind] = mod.SOURCES


register('truenas', 'apitruenas')
register('xo', 'apixo')
