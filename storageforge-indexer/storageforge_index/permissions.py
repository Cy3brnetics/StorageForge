"""What an account may do: the permission catalog, the built-in roles and which permission each route needs.
Roles only bundle permissions, and the code only ever asks about permissions. Custom roles are rows in `roles` (users.py)."""
from __future__ import annotations

import re

# group, then (permission, what it allows, high risk: it can lead to root on enrolled hosts)
CATALOG = (
    ('Search', (
        ('search.files', 'Search files across hosts', False),)),
    ('Inventory', (
        ('hosts.view', 'See hosts, the graph, capacity and designs', False),
        ('files.browse', 'Browse folders, copies, cold data and file changes', False),
        ('services.view', 'See Docker, Git and shares from the index', False),
        ('configs.view', 'See saved host configurations', False),)),
    ('Logs', (
        ('logs.view', 'Read the activity log and command output', False),
        ('hostlogs.view', "Read hosts' journals as scans collected them: sign-ins, sudo commands, service output", False),
        ('audit.view', 'Read the audit log', False),
        ('audit.verify', 'Verify the audit chain and sign evidence (unlocks the vault)', False),)),
    ('Scans', (
        ('scans.view', 'See scan jobs', False),
        ('scans.run', 'Run scans, set scan schedules and ignore lists', False),)),
    ('Planning', (
        ('plans.view', 'See moves, changes, tasks and schedules', False),
        ('plans.edit', 'Create and edit plans, tasks, shares and designs', True),
        ('plans.scripts', 'Download generated scripts and config bundles', False),
        ('hosts.command', 'Write and deploy raw commands, which run as root: command schedules, task command blocks, move hooks', True),)),
    ('Deploy', (
        ('deploy.view', 'See deploys, runs and jobs', False),
        ('deploy.report', 'Dry runs, job logs and snapshot browsing', False),
        ('deploy.apply', 'Apply deploys, run and pause jobs and schedules', True),
        ('deploy.destructive', 'Destructive applies, cutover and restore', True),
        ('deploy.setup', 'Make the deploy keys and adopt hosts', True),)),
    ('Live hosts', (
        ('git.live', 'Read Git status and history over SSH', False),
        ('git.sync', 'Run Git sync on hosts', True),)),
    ('Security', (
        ('security.view', 'See what hosts report: posture, holds, decoys, access control, quarantine, integrity and compliance', False),
        ('security.manage', 'Measure hosts, relabel, quarantine addresses, run AIDE and Lynis, sample files and set baselines', True),
        ('security.emergency', 'Pull the brake, airgap a host, apply and release holds, set retention policies, and use the offline key', True),
        ('security.sentinel', 'Set up the sentinel and its decoys, arm it, and with deploy.apply deploy, re-arm or remove it', True),)),
    ('Infrastructure', (
        ('workloads.view', 'See containers, VMs and instances across hosts, from the index', False),
        ('map.view', 'See interfaces, routes and listeners, from the index. Firewall rules and exposure also need security.view', False),
        ('map.edit', 'Save map views', False),)),
    ('Network devices', (
        ('devices.view', 'See routers, switches and firewalls, and the changes made to them, from the index', False),
        ('devices.manage', 'Add and remove devices, and read them', True),
        ('devices.apply', 'Change a device. Each change has a rollback timer on the device, and this is still root on your network', True),
        ('netscan.view', 'See what the nmap scanner found, and traffic statistics', False),
        ('netscan.run', 'Turn the nmap scanner and traffic monitoring on and off, name the ranges, run a scan', True),)),
    ('Host access', (
        ('keys.view', 'See public keys, bindings and scan access', False),
        ('keys.manage', 'Generate, install, bind and remove SSH keys', True),
        ('access.manage', 'Confirm host keys and grant scan or deploy access', True),
        ('hosts.retire', 'Retire hosts', False),)),
    ('Administration', (
        ('users.manage', 'Add and change accounts, create invite links', False),
        ('roles.manage', 'Create and change custom roles', False),
        ('settings.manage', 'Change report URL, alert channels and the example host', True),
        ('backups.view', 'See backups', False),
        ('backups.manage', 'Make backups and set where they are copied', True),)),
)
ALL = frozenset(p for _, perms in CATALOG for p, _, _ in perms)
HIGH_RISK = frozenset(p for _, perms in CATALOG for p, _, risky in perms if risky)

_VIEWER = frozenset({'search.files', 'hosts.view', 'files.browse', 'services.view', 'configs.view', 'logs.view', 'audit.view',
                     'scans.view', 'plans.view', 'deploy.view', 'keys.view', 'backups.view', 'security.view', 'workloads.view', 'map.view', 'devices.view', 'netscan.view'})
# Built-in roles cannot be changed or removed. Without a role here or in `roles`, an account may do nothing.
BUILTIN = {
    'search': ('Searches files across hosts, and nothing else', frozenset({'search.files'})),
    'viewer': ('Browses and searches', _VIEWER),
    'operator': ('Also plans, scans and deploys', _VIEWER | {'hostlogs.view', 'scans.run','plans.edit', 'plans.scripts', 'deploy.report', 'deploy.apply',
                                                            'deploy.destructive', 'deploy.setup', 'git.live', 'git.sync', 'security.manage', 'map.edit', 'devices.manage', 'devices.apply', 'netscan.run'}),
    'admin': ('Everything, including keys, accounts and settings', ALL),
}

ANYONE = ('/api/login', '/api/logout', '/api/reauth', '/api/me', '/api/me/password', '/api/enroll', '/api/enroll/check')
READ = ('GET', 'HEAD')
_ANY = ('GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'PATCH')
_WRITE = ('POST', 'PUT', 'DELETE', 'PATCH')
# First match wins. See required() for a route that matches nothing.
_RULES = tuple((methods, re.compile(pattern), perm) for methods, pattern, perm in (
    (_ANY, r'/api/(users|invites)(/.*)?', 'users.manage'),
    (READ, r'/api/roles', 'users.manage'),            # who can hand out roles needs to see them
    (_ANY, r'/api/roles(/.*)?', 'roles.manage'),
    (_ANY, r'/api/deploy/settings(/.*)?', 'settings.manage'),
    (_WRITE, r'/api/planner/example', 'settings.manage'),
    (_WRITE, r'/api/planner/offsite', 'plans.edit'),
    (_ANY, r'/api/audit/verify', 'audit.verify'),
    (READ, r'/api/audit', 'audit.view'),
    (READ, r'/api/log(/.*)?', 'logs.view'),
    (READ, r'/api/hostlogs(/.*)?', 'hostlogs.view'),

    (READ, r'/api/search(/hosts)?', 'search.files'),
    (READ, r'/api/planner/versions(/\d+)?', 'plans.view'),            # saved versions of a design (design_versions.py)
    (('POST',), r'/api/planner/versions/compare', 'plans.view'),      # a read: it saves nothing
    (READ, r'/api/(hosts|graph|canvas|capacity|planner/.*)', 'hosts.view'),
    (READ, r'/api/hosts/[^/]+/schedule', 'hosts.view'),
    (READ, r'/api/(browse|fs/browse|file-changes|dupes|filemap|files/ignore|folders/.*)', 'files.browse'),
    (READ, r'/api/clamav', 'files.browse'),
    (('POST',), r'/api/clamav/hosts/[^/]+/config', 'deploy.apply'),
    (('POST',), r'/api/clamav/hosts/[^/]+/collect', 'deploy.report'),
    (('POST',), r'/api/clamav/detections/\d+/(quarantine|restore|ignore)', 'deploy.destructive'),
    (READ, r'/api/(docker(/.*)?|git|git/ignore|shares/check)', 'services.view'),
    (READ, r'/api/security/compliance/script', 'plans.scripts'),
    (('POST',), r'/api/security/evidence', 'audit.verify'),                 # unlocks the vault, so not audit.view alone: the view checks that too
    (('POST',), r'/api/security/sentinel', 'security.sentinel'),
    (('POST',), r'/api/security/(compliance/reconverge|integrity/stage|worm/preview/stage|mac/context/stage|firewall/shares/stage)', 'plans.edit'),
    (('POST', 'DELETE'), r'/api/security/webauthn(/.*)?', 'security.emergency'),    # the touch only guards what this permission allows
    (_WRITE, r'/api/security/dash(/\d+)?', 'security.manage'),
    (('POST',), r'/api/security/(waivers|profiles|worm/policies/apply|worm/preview|integrity/aide/watch|mac/identity/deploy|mac/noise|mac/context|firewall/tiers|behavior/thresholds|behavior/filters|behavior/falco|behavior/yara|behavior/yara/rules|malware/preview|packages/check|packages/bundle)', 'security.manage'),
    (('DELETE',), r'/api/security/(waivers|profiles|behavior/yara/rules)/\d+', 'security.manage'),
    (('DELETE',), r'/api/security/worm/policies/\d+', 'security.emergency'),
    (('POST',), r'/api/security/(worm/freeze|worm/policies|incident/clean-room/sweep|playbooks|playbooks/runs/\d+)', 'security.emergency'),
    (('DELETE',), r'/api/security/playbooks/\d+', 'security.emergency'),
    (READ, r'/api/workloads(/.*)?', 'workloads.view'),
    (READ, r'/api/netscan(/.*)?', 'netscan.view'),
    (_WRITE, r'/api/netscan(/.*)?', 'netscan.run'),
    (READ, r'/api/traffic', 'netscan.view'),
    (_WRITE, r'/api/traffic(/.*)?', 'netscan.run'),
    (('POST',), r'/api/devices/changes/\d+/(apply|confirm)', 'devices.apply'),
    (('POST',), r'/api/devices/[^/]+/report', 'devices.apply'),
    (READ, r'/api/devices/changes/\d+', 'security.view'),       # a change holds the rule and its device commands, which /api/devices/<name> cuts out for a role without this (SF-63)
    (READ, r'/api/devices(/.*)?', 'devices.view'),
    (READ, r'/api/fleet', 'devices.view'),
    (('POST',), r'/api/dsl/compile', 'devices.view'),
    (('POST',), r'/api/dsl/whatif', 'security.view'),
    (('POST',), r'/api/dsl/stage', 'plans.edit'),
    (READ, r'/api/dsl/of', 'security.view'),
    (_WRITE, r'/api/devices(/.*)?', 'devices.manage'),
    (READ, r'/api/map/(exposure|reach|coverage)', 'security.view'),
    (READ, r'/api/map/designs/\d+/export', 'plans.scripts'),
    (READ, r'/api/(network|map(/.*)?)', 'map.view'),
    (_WRITE, r'/api/map/(views|manual|annotations)(/\d+)?', 'map.edit'),
    (('POST',), r'/api/map/whatif', 'security.view'),
    (('POST',), r'/api/map/stage', 'plans.edit'),
    (('POST',), r'/api/map/placeholders/.+/promote', 'keys.manage'),
    (_WRITE, r'/api/map/designs(/\d+)?', 'plans.edit'),
    (('POST',), r'/api/map/designs/\d+/stage', 'plans.edit'),
    (READ, r'/api/(firewall|exposure)', 'security.view'),
    (('POST',), r'/api/infra/measure', 'security.manage'),
    (READ, r'/api/infra/settings', 'hosts.view'),
    (('POST',), r'/api/infra/settings', 'security.manage'),

    # generated scripts name paths, logins and hosts in a form that can be run
    (READ, r'/api/.*/(script|ansible|install-script|cron|bundle)', 'plans.scripts'),
    (('POST',), r'/api/tasks/script', 'plans.scripts'),
    (READ, r'/api/hostconfigs(/.*)?', 'configs.view'),

    (READ, r'/api/jobs', 'scans.view'),
    (READ, r'/api/scans/signing', 'scans.view'),                       # signed scan payloads (scansign.py): what each host's last scan was
    (('PUT',), r'/api/scans/signing', 'keys.manage'),                  # what a host is trusted to sign with is key management: admins, not operators
    (('DELETE',), r'/api/scans/signing/[^/]+', 'keys.manage'),         # forgetting a pinned key lets the next signer be pinned in its place
    (_WRITE, r'/api/scan(/all)?', 'scans.run'),
    (_WRITE, r'/api/hosts/[^/]+/schedule', 'scans.run'),
    (_WRITE, r'/api/(files/ignore|git/ignore|git/survey)', 'scans.run'),

    (READ, r'/api/(moves|changes|tasks)(/.*)?', 'plans.view'),
    (READ, r'/api/scheduler/(runs|schedules/\d+/runs)', 'logs.view'),   # what a run printed, as /api/log/output
    (READ, r'/api/scheduler(/.*)?', 'plans.view'),
    (_WRITE, r'/api/(moves|changes|tasks|shares|planner)(/.*)?', 'plans.edit'),
    (('POST',), r'/api/scheduler/schedules/\d+/(run|pause|token)', 'deploy.apply'),
    (('POST',), r'/api/scheduler/schedules/\d+/verify', 'deploy.report'),
    (_WRITE, r'/api/scheduler/schedules(/\d+)?', 'plans.edit'),
    (('POST',), r'/api/(jobs|scheduler)/report', 'deploy.apply'),     # jobs report with a bearer token and no session
    (('POST',), r'/api/jobs/state', 'deploy.apply'),                  # likewise

    (READ, r'/api/deploy(/.*)?', 'deploy.view'),
    (READ, r'/api/remote/nodes', 'deploy.view'),
    (('POST',), r'/api/remote/nodes(/\d+/adopt)?', 'deploy.setup'),
    (('DELETE',), r'/api/remote/nodes/\d+', 'deploy.setup'),
    (('POST',), r'/api/deploy/(setup-script|adopt)', 'deploy.setup'),
    (('POST',), r'/api/deploy/access', 'access.manage'),
    (('POST',), r'/api/deploy/start', 'deploy.report'),               # apply and destructive are checked in the route
    (('POST',), r'/api/deploy/check', 'deploy.report'),
    (('POST',), r'/api/deploy/groups/[^/]+/(cancel|retry)', 'deploy.apply'),
    (('POST',), r'/api/deploy/jobs/[^/]+/(dryrun|log|snapshots|browse)', 'deploy.report'),
    (('POST',), r'/api/deploy/jobs/[^/]+/(cutover|restore)', 'deploy.destructive'),
    (('POST',), r'/api/deploy/jobs/[^/]+/dedupe', 'deploy.apply'),
    (('POST',), r'/api/deploy/jobs/[^/]+/(run|verify|pause|resume)', 'deploy.apply'),
    (('POST',), r'/api/deploy/jobs/[^/]+/retention', 'deploy.destructive'),      # a lower count deletes snapshots
    (('POST',), r'/api/deploy/jobs/[^/]+/forget', 'deploy.apply'),
    (('POST',), r'/api/deploy/snapjobs/probe', 'deploy.report'),
    (('POST',), r'/api/deploy/snapjobs/(import|snapper)', 'deploy.apply'),

    (_ANY, r'/api/git/(status|history|commit)', 'git.live'),
    (_WRITE, r'/api/git/sync', 'git.sync'),

    (READ, r'/api/(keys|access)', 'keys.view'),
    (_WRITE, r'/api/(keys|bindings)(/.*)?', 'keys.manage'),
    (_WRITE, r'/api/(hostkey|access/grant)(/.*)?', 'access.manage'),
    (('DELETE',), r'/api/hosts/[^/]+', 'hosts.retire'),

    # Security & Ransomware Defense
    (READ, r'/api/security/.*', 'security.view'),
    (('POST',), r'/api/security/report', 'deploy.apply'),       # sentinels report with a bearer token and no session
    (('POST',), r'/api/security/(incident/(brake|clean-room)|firewall/(airgap|vip)|worm/.*|events/\d+/ack)', 'security.emergency'),
    (_WRITE, r'/api/security/.*', 'security.manage'),

    (READ, r'/api/backups', 'backups.view'),
    (_WRITE, r'/api/backups(/.*)?', 'backups.manage'),
))
EVERYTHING = 'everything'    # what an unlisted route needs: only a role that holds the whole catalog


def required(method: str, path: str) -> str | None:
    """The permission a signed-in request needs, None for pages and the account's own routes. Default-deny: a new /api
    route nobody listed is open only to accounts holding every permission, until it gets a rule here."""
    if not path.startswith('/api/') or path in ANYONE:
        return None
    for methods, pattern, perm in _RULES:
        if method in methods and pattern.fullmatch(path):
            return perm
    return EVERYTHING


def allows(held: frozenset[str], method: str, path: str) -> bool:
    need = required(method, path)
    return need is None or (held >= ALL if need == EVERYTHING else need in held)
