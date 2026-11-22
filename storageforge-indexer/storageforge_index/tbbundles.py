"""Toolbox bundles, role profiles and per-host exclusions (roadmap sections 4.1 and 4.3; docs/toolbox.md).

A bundle is an ordered set of Toolbox catalog entries staged into a single change plan with one combined report:
  - dependency ordering (PKI/secrets -> identity -> VPN/overlay -> proxy/DNS/time -> detection -> apps/panels -> monitoring/backup)
  - deduplicated runtime installation and shared secret references
  - unified firewall / exposure summary with port-collision detection across entries
  - single change plan and whole-bundle reverse-order removal (keeping data by default)

Role profiles give each host role (edge, nas, hypervisor, container-host) a default tool set, while per-host exclusions omit
individual tools for one host. Entries marked `not-a-default` in the catalog never enter a role profile automatically.
"""
from __future__ import annotations

import json
import re
import time

from . import toolbox
from .db import Conn

ID_RE = re.compile(r'[a-z0-9][a-z0-9-]{0,63}')
NAME_MAX = 100
SUMMARY_MAX = 400

# Explicit dependency layer priority per tool, with category fallback below. Lower runs first.
TOOL_LAYER = {
    'openbao': 10, 'step-ca': 10, 'ssh-ca': 10, 'sops': 10, 'age': 10,
    'lldap': 20, 'authelia': 20, 'authentik': 20, 'keycloak': 20,
    'wireguard': 30, 'headscale': 30, 'headscale-ui': 32, 'zerotier': 30, 'nebula-lighthouse': 30,
    'strongswan': 30, 'openziti': 30, 'cloudflared': 35,
    'chrony': 38, 'unbound': 40, 'coredns': 40, 'dnsmasq': 40, 'pi-hole': 42, 'adguard-home': 42, 'technitium': 42,
    'caddy': 45, 'traefik': 45, 'nginx-proxy-manager': 45,
    'crowdsec': 50, 'fail2ban': 50, 'suricata': 52, 'zeek': 52, 'trivy': 54, 'grype': 54, 'openscap': 54,
    'samba': 60, 'nfs-server': 60, 'garage': 60, 'syncthing': 62, 'nextcloud': 64, 'jellyfin': 64,
    'cockpit': 60, 'dockge': 62, 'dockhand': 62, 'komodo': 62, 'portainer': 62, 'vaultwarden': 64,
    'forgejo': 64, 'zot': 60, 'apt-cacher-ng': 60, 'ansible': 65, 'opentofu': 65, 'puppet': 65, 'packer': 65, 'netbootxyz': 65,
    'prometheus': 70, 'loki': 72, 'grafana': 74, 'uptime-kuma': 75,
    'restic': 80, 'borg': 80, 'proxmox-backup-client': 80,
}

CATEGORY_LAYER = {
    'secrets': 10, 'identity': 20, 'vpn': 30, 'access': 35, 'proxy': 45, 'dns': 40, 'time': 38,
    'detection': 50, 'scanning': 54, 'storage': 60, 'panels': 62, 'provisioning': 65, 'monitoring': 70, 'backup': 80,
}

BUILTIN_BUNDLES = (
    {
        'id': 'private-access',
        'name': 'Private access',
        'summary': 'Management panels reachable over WireGuard behind Caddy and Authelia SSO.',
        'entries': ['wireguard', 'caddy', 'authelia'],
    },
    {
        'id': 'hardened-homelab',
        'name': 'Hardened homelab',
        'summary': 'Private access plus CrowdSec, Chrony NTS time sync, Uptime Kuma monitoring and restic backups.',
        'entries': ['wireguard', 'caddy', 'authelia', 'crowdsec', 'chrony', 'uptime-kuma', 'restic'],
    },
    {
        'id': 'container-host',
        'name': 'Container host',
        'summary': 'Caddy reverse proxy, Komodo workload manager, Trivy image scanner and Uptime Kuma monitoring.',
        'entries': ['caddy', 'komodo', 'trivy', 'uptime-kuma'],
    },
    {
        'id': 'hypervisor',
        'name': 'Hypervisor',
        'summary': 'Cockpit host console over WireGuard with Proxmox Backup Client and Uptime Kuma monitoring.',
        'entries': ['cockpit', 'wireguard', 'proxmox-backup-client', 'uptime-kuma'],
    },
    {
        'id': 'observability',
        'name': 'Observability',
        'summary': 'Uptime Kuma service checks, Cockpit host inspection and Chrony NTS time sync.',
        'entries': ['cockpit', 'chrony', 'uptime-kuma'],
    },
    {
        'id': 'zero-trust-gateway',
        'name': 'Zero-trust gateway',
        'summary': 'Internal step-ca PKI, Authentik identity provider and OpenZiti controller.',
        'entries': ['step-ca', 'authentik', 'openziti'],
    },
    {
        'id': 'backup-recovery',
        'name': 'Backup and recovery',
        'summary': 'Encrypted restic and Borg backups paired with StorageForge restore verification.',
        'entries': ['restic', 'borg'],
    },
)

DEFAULT_PROFILES = {
    'edge': {
        'label': 'Edge / gateway',
        'summary': 'VPN termination, reverse proxy, SSO, intrusion blocking and time sync.',
        'tools': ['wireguard', 'caddy', 'authelia', 'crowdsec', 'chrony'],
    },
    'nas': {
        'label': 'Storage / NAS',
        'summary': 'File sharing, encrypted backup, time sync and vulnerability scanning.',
        'tools': ['samba', 'nfs-server', 'restic', 'chrony', 'trivy'],
    },
    'hypervisor': {
        'label': 'Hypervisor',
        'summary': 'Host management over WireGuard with backup client and time sync.',
        'tools': ['cockpit', 'wireguard', 'proxmox-backup-client', 'chrony'],
    },
    'container-host': {
        'label': 'Container host',
        'summary': 'Container management, reverse proxy, image scanning and uptime checks.',
        'tools': ['caddy', 'komodo', 'trivy', 'uptime-kuma'],
    },
}


def _priority(tool_id: str, category: str | None) -> int:
    if tool_id in TOOL_LAYER:
        return TOOL_LAYER[tool_id]
    return CATEGORY_LAYER.get(category or '', 65)


def order_entries(conn: Conn | None, tool_ids: list[str]) -> list[str]:
    """Deduplicate and sort entries in dependency order."""
    seen: list[str] = []
    for raw in tool_ids or []:
        tid = str(raw or '').strip()
        if tid and tid not in seen:
            seen.append(tid)
    if not seen:
        return []
    cats: dict[str, str | None] = {}
    if conn is not None:
        for t in seen:
            row = toolbox.find(conn, t)
            cats[t] = (row or {}).get('category')
    pos = {t: i for i, t in enumerate(seen)}
    return sorted(seen, key=lambda t: (_priority(t, cats.get(t)), pos[t]))


def _builtin_map() -> dict[str, dict]:
    return {b['id']: b for b in BUILTIN_BUNDLES}


def list_bundles(conn: Conn) -> list[dict]:
    out = [{
        'id': b['id'],
        'name': b['name'],
        'summary': b['summary'],
        'entries': order_entries(conn, list(b['entries'])),
        'params': {},
        'user_defined': False,
    } for b in BUILTIN_BUNDLES]
    rows = conn.all('SELECT id, name, summary, entries_json, params_json, created_at, created_by, updated_at FROM toolbox_bundles ORDER BY name')
    for bid, name, summary, entries_json, params_json, cat, cby, uat in rows:
        entries = json.loads(entries_json or '[]')
        params = json.loads(params_json or '{}')
        out.append({
            'id': bid,
            'name': name,
            'summary': summary,
            'entries': order_entries(conn, entries),
            'params': params,
            'user_defined': True,
            'created_at': cat,
            'created_by': cby,
            'updated_at': uat,
        })
    return out


def get_bundle(conn: Conn, bundle_id: str) -> dict | None:
    bid = str(bundle_id or '').strip()
    return next((b for b in list_bundles(conn) if b['id'] == bid), None)


def save_bundle(conn: Conn, body: dict, actor: str) -> dict:
    bid = str(body.get('id') or '').strip()
    if not ID_RE.fullmatch(bid):
        raise toolbox.CatalogError('a bundle id is lower-case letters, digits and -, up to 64 characters')
    if bid in _builtin_map():
        raise toolbox.CatalogError(f'{bid} is a built-in bundle and cannot be overwritten')
    name = str(body.get('name') or '').strip()
    if not name or len(name) > NAME_MAX:
        raise toolbox.CatalogError('a bundle needs a plain name (up to 100 characters)')
    summary = str(body.get('summary') or '').strip()[:SUMMARY_MAX]
    raw_entries = body.get('entries')
    if not isinstance(raw_entries, list) or not raw_entries:
        raise toolbox.CatalogError('a bundle names at least one catalog entry')
    entries = order_entries(conn, [str(x) for x in raw_entries])
    if len(entries) > 25:
        raise toolbox.CatalogError('at most 25 entries per bundle')
    for tid in entries:
        row = toolbox.find(conn, tid)
        if not row or row['trust'] == 'refused':
            raise toolbox.CatalogError(f'{tid} is not an active catalog entry')
    params = body.get('params') if isinstance(body.get('params'), dict) else {}
    now = int(time.time())
    with conn.tx():
        conn.execute("""INSERT INTO toolbox_bundles (id, name, summary, entries_json, params_json, created_at, created_by, updated_at)
                        VALUES (:i, :n, :s, :e, :p, :t, :a, :t)
                        ON CONFLICT (id) DO UPDATE SET name = excluded.name, summary = excluded.summary, entries_json = excluded.entries_json,
                                                       params_json = excluded.params_json, updated_at = excluded.updated_at""",
                     {'i': bid, 'n': name, 's': summary, 'e': json.dumps(entries), 'p': json.dumps(params), 't': now, 'a': actor[:60]})
    return get_bundle(conn, bid)


def delete_bundle(conn: Conn, bundle_id: str) -> bool:
    bid = str(bundle_id or '').strip()
    if bid in _builtin_map():
        raise toolbox.CatalogError(f'{bid} is a built-in bundle and cannot be removed')
    cur = conn.execute('DELETE FROM toolbox_bundles WHERE id = :i', {'i': bid})
    return bool(cur.rowcount)


def _port_conflicts(conn: Conn, previews: list[dict]) -> list[dict]:
    """Detect conflicting host port bindings across entries in the same bundle."""
    claims: dict[tuple[str, int], list[tuple[str, str, str]]] = {}
    for pv in previews:
        resolved = pv.get('resolved') or {}
        exposure = resolved.get('exposure') or 'loopback'
        bind = resolved.get('bind') or ('127.0.0.1' if exposure == 'loopback' else '0.0.0.0')
        ports = list(resolved.get('ports') or [])
        if not ports and pv.get('method') == 'package':
            entry = (toolbox.find(conn, pv['tool']) or {}).get('entry') or {}
            ports = [{'proto': p.get('proto') or 'tcp', 'host': int(p['port'])} for p in (entry.get('requires') or {}).get('ports') or []]
        for p in ports:
            key = (p.get('proto') or 'tcp', int(p['host']))
            claims.setdefault(key, []).append((pv['tool'], pv['name'], bind))
    conflicts = []
    for (proto, port), holders in sorted(claims.items()):
        if len(holders) < 2:
            continue
        binds = [b for _, _, b in holders]
        if '0.0.0.0' in binds or len(set(binds)) < len(binds):
            names = ', '.join(n for _, n, _ in holders)
            conflicts.append({'proto': proto, 'port': port, 'tools': [t for t, _, _ in holders],
                              'text': f'Port {port}/{proto} is claimed by multiple tools in this bundle ({names})'})
    return conflicts


def _tool_params(bundle_params: dict, tool_id: str) -> dict:
    per_tool = (bundle_params.get('tools') or {}).get(tool_id) if isinstance(bundle_params.get('tools'), dict) else {}
    if not isinstance(per_tool, dict):
        per_tool = {}
    return {
        'method': per_tool.get('method'),
        'inputs': per_tool.get('inputs') if isinstance(per_tool.get('inputs'), dict) else bundle_params.get('inputs') or {},
        'exposure': per_tool.get('exposure') or bundle_params.get('exposure'),
        'bind': per_tool.get('bind') or bundle_params.get('bind'),
        'allow_from': per_tool.get('allow_from') or bundle_params.get('allow_from'),
    }


def preview_bundle(conn: Conn, host: str, bundle_id: str | None = None, *, entries: list[str] | None = None,
                   params: dict | None = None, name: str | None = None, accept_unsigned: bool = False) -> dict:
    """Preview an ordered multi-tool bundle plan, consolidating runtime installs, shared secrets, firewall rules and port checks."""
    host = toolbox.host_name(conn, host)
    bdef = None
    if bundle_id:
        bdef = get_bundle(conn, bundle_id)
        if not bdef:
            raise LookupError(f'no such bundle {bundle_id}')
    merged_params = dict((bdef or {}).get('params') or {})
    if isinstance(params, dict):
        merged_params.update(params)
    raw_list = entries if entries is not None else (bdef or {}).get('entries') or []
    ordered = order_entries(conn, [str(x) for x in raw_list])
    if not ordered:
        raise toolbox.CatalogError('a bundle needs at least one catalog entry')

    previews: list[dict] = []
    report: list[dict] = []
    say = lambda level, text, tool=None: report.append({'level': level, 'text': text, **({'tool': tool} if tool else {})})  # noqa: E731
    say('note', f'Dependency order: {" -> ".join(ordered)}')

    for tid in ordered:
        tp = _tool_params(merged_params, tid)
        pv = toolbox.preview(conn, host, tid, method=tp['method'], inputs=tp['inputs'], exposure=tp['exposure'],
                             bind=tp['bind'], allow_from=tp['allow_from'])
        previews.append(pv)
        for item in pv['report']:
            say(item['level'], f'{pv["name"]}: {item["text"]}', tid)

    conflicts = _port_conflicts(conn, previews)
    for c in conflicts:
        say('crit', c['text'])

    # Consolidate runtime-install, secret-file (shared secrets), and firewall tasks in deterministic bundle order.
    tasks: list[dict] = []
    seen_runtime = False
    seen_secrets: set[tuple[str, str]] = set()
    shared_secrets: list[dict] = []
    seen_fw: set[tuple] = set()
    firewall_rules: list[dict] = []
    exposures: list[dict] = []

    for pv in previews:
        tid = pv['tool']
        res = pv['resolved']
        if res.get('ports'):
            exposures.append({'tool': tid, 'name': pv['name'], 'exposure': res['exposure'], 'bind': res.get('bind') or '',
                              'ports': [toolbox.publish(p) for p in res['ports']], 'allow_from': _tool_params(merged_params, tid).get('allow_from') or ''})
        for t in pv['tasks']:
            ttype, p = t['type'], t['params']
            if ttype == 'runtime-install':
                if seen_runtime:
                    continue
                seen_runtime = True
                tasks.append({**t, 'note': f'shared container runtime for {name or (bdef or {}).get("name") or "bundle"}'})
            elif ttype == 'secret-file':
                skey = (p['secret'], p['path'])
                if skey in seen_secrets:
                    say('note', f'Shared secret {p["secret"]} at {p["path"]} reused across entries', tid)
                    continue
                seen_secrets.add(skey)
                shared_secrets.append({'secret': p['secret'], 'path': p['path'], 'tool': tid})
                tasks.append(t)
            elif ttype == 'fw-rule':
                fkey = tuple(sorted(p.items()))
                if fkey in seen_fw:
                    continue
                seen_fw.add(fkey)
                firewall_rules.append({'tool': tid, **p})
                tasks.append(t)
            else:
                tasks.append(t)

    # Move any shared runtime-install step to the very front so later container tools run cleanly.
    rt = [t for t in tasks if t['type'] == 'runtime-install']
    non_rt = [t for t in tasks if t['type'] != 'runtime-install']
    tasks = rt + non_rt

    # Whole-bundle rollback in reverse dependency order (keeps data).
    rollback_tasks = [{'host': host, 'type': 'tool-remove', 'params': {'tool': pv['tool'], 'method': pv['method']},
                       'note': f'reverse-order rollback of {pv["name"]} (keeps data)'}
                      for pv in reversed(previews)]

    unsigned_tools = [pv['tool'] for pv in previews if pv['trust'] == 'unsigned']
    if unsigned_tools and not accept_unsigned:
        say('warn', f'Unsigned custom entries require confirmation: {", ".join(unsigned_tools)}')

    return {
        'host': host,
        'bundle_id': (bdef or {}).get('id') or bundle_id or 'custom',
        'name': name or (bdef or {}).get('name') or 'Custom bundle',
        'order': ordered,
        'previews': previews,
        'tasks': tasks,
        'rollback_tasks': rollback_tasks,
        'report': report,
        'conflicts': conflicts,
        'shared_secrets': shared_secrets,
        'firewall_rules': firewall_rules,
        'exposures': exposures,
        'unsigned_tools': unsigned_tools,
    }


def stage_bundle(conn: Conn, host: str, bundle_id: str | None, actor: str, *, entries: list[str] | None = None,
                 params: dict | None = None, name: str | None = None, accept_unsigned: bool = False) -> dict:
    """Save the ordered bundle as one change plan and record all member tool installs against that plan."""
    from . import changes
    pv = preview_bundle(conn, host, bundle_id, entries=entries, params=params, name=name, accept_unsigned=accept_unsigned)
    if pv['unsigned_tools'] and not accept_unsigned:
        raise toolbox.CatalogError(f'bundle contains unsigned entries ({", ".join(pv["unsigned_tools"])}): accept unsigned entries to stage it')
    crits = [x['text'] for x in pv['report'] if x['level'] == 'crit' and 'secret' not in x['text']]
    if crits:
        raise toolbox.CatalogError('; '.join(crits))
    plan_title = toolbox._plan_name(conn, f'Toolbox bundle: {pv["name"]} on {pv["host"]}')
    plan_id = changes.save_plan(conn, {'name': plan_title, 'tasks': pv['tasks']}, actor)
    staged_installs = [toolbox.record_install(conn, item_pv, plan_id, actor) for item_pv in pv['previews']]
    return {
        'host': pv['host'],
        'bundle_id': pv['bundle_id'],
        'name': pv['name'],
        'order': pv['order'],
        'plan_id': plan_id,
        'tasks': pv['tasks'],
        'rollback_tasks': pv['rollback_tasks'],
        'report': pv['report'],
        'conflicts': pv['conflicts'],
        'shared_secrets': pv['shared_secrets'],
        'firewall_rules': pv['firewall_rules'],
        'exposures': pv['exposures'],
        'installs': [{'tool': x['tool'], 'method': x['method'], 'decoy_folders_added': x['decoy_folders_added']} for x in staged_installs],
    }


def stage_bundle_remove(conn: Conn, host: str, bundle_id: str, actor: str, with_data: bool = False) -> dict:
    """Stage reverse-order removal of all StorageForge-managed tools belonging to a bundle on a host."""
    from . import changes
    host = toolbox.host_name(conn, host)
    bdef = get_bundle(conn, bundle_id)
    if not bdef:
        raise LookupError(f'no such bundle {bundle_id}')
    order = list(reversed(order_entries(conn, bdef['entries'])))
    tasks: list[dict] = []
    kept: list[str] = []
    removing_ids: list[int] = []
    for tid in order:
        inst = toolbox.install_of(conn, host, tid)
        if not inst or inst['managed_by'] != 'storageforge' or inst['status'] in ('removed', 'remove-staged'):
            continue
        removing_ids.append(inst['id'])
        tasks.append({'host': host, 'type': 'tool-remove', 'params': {'tool': tid, 'method': inst['method']},
                      'note': f'bundle removal in reverse order ({tid}; data kept)'})
        kept.extend(inst['params'].get('data') or [])
        if with_data and inst['params'].get('data'):
            tasks.append({'host': host, 'type': 'tool-data-remove', 'params': {'tool': tid, 'confirm': tid},
                          'note': f'moved {tid} data to host trash'})
    if not tasks:
        raise toolbox.CatalogError(f'no StorageForge-managed tools from bundle {bdef["name"]} are installed on {host}')
    plan_title = toolbox._plan_name(conn, f'Toolbox bundle remove: {bdef["name"]} from {host}')
    plan_id = changes.save_plan(conn, {'name': plan_title, 'tasks': tasks}, actor)
    now = int(time.time())
    with conn.tx():
        for iid in removing_ids:
            conn.execute("UPDATE toolbox_installs SET status = 'remove-staged', plan_id = :p, updated_at = :n WHERE id = :i",
                         {'p': plan_id, 'n': now, 'i': iid})
    return {'host': host, 'bundle_id': bundle_id, 'order': order, 'plan_id': plan_id, 'tasks': tasks, 'kept': sorted(set(kept))}


# ── role profiles and per-host exclusions ────────────────────────────
def _profile_map(conn: Conn) -> dict[str, dict]:
    out = {k: {'role': k, 'label': v['label'], 'summary': v['summary'], 'tools': order_entries(conn, v['tools']),
               'params': {}, 'custom': False} for k, v in DEFAULT_PROFILES.items()}
    for role, tools_json, params_json, uat, uby in conn.all('SELECT role, tools_json, params_json, updated_at, updated_by FROM toolbox_profiles ORDER BY role'):
        tools = order_entries(conn, json.loads(tools_json or '[]'))
        params = json.loads(params_json or '{}')
        base = out.get(role) or {'label': role, 'summary': 'Custom host role profile'}
        out[role] = {'role': role, 'label': base['label'], 'summary': base['summary'], 'tools': tools,
                     'params': params, 'custom': True, 'updated_at': uat, 'updated_by': uby}
    return out


def set_role_profile(conn: Conn, role: str, tools: list[str], params: dict | None, actor: str) -> dict:
    r = str(role or '').strip()
    if not ID_RE.fullmatch(r):
        raise toolbox.CatalogError('a role name is lower-case letters, digits and -, up to 64 characters')
    if not isinstance(tools, list) or not tools:
        raise toolbox.CatalogError('a role profile needs at least one catalog entry')
    ordered = order_entries(conn, [str(x) for x in tools])
    for tid in ordered:
        row = toolbox.find(conn, tid)
        if not row or row['trust'] == 'refused':
            raise toolbox.CatalogError(f'{tid} is not an active catalog entry')
        labels = (row.get('entry') or {}).get('labels') or []
        if 'not-a-default' in labels:
            raise toolbox.CatalogError(f'{tid} carries not-a-default and cannot belong to a default role profile')
    now = int(time.time())
    with conn.tx():
        conn.execute("""INSERT INTO toolbox_profiles (role, tools_json, params_json, updated_at, updated_by) VALUES (:r, :t, :p, :n, :a)
                        ON CONFLICT (role) DO UPDATE SET tools_json = excluded.tools_json, params_json = excluded.params_json,
                                                         updated_at = excluded.updated_at, updated_by = excluded.updated_by""",
                     {'r': r, 't': json.dumps(ordered), 'p': json.dumps(params or {}), 'n': now, 'a': actor[:60]})
    return _profile_map(conn)[r]


def host_profile(conn: Conn, host: str) -> dict | None:
    name = toolbox.host_name(conn, host)
    rows = conn.all('SELECT role, excluded_json, updated_at, updated_by FROM toolbox_host_roles WHERE host = :h', {'h': name})
    if not rows:
        return None
    role, excluded_json, uat, uby = rows[0]
    profiles = _profile_map(conn)
    prof = profiles.get(role) or {'tools': [], 'params': {}}
    excluded = order_entries(conn, json.loads(excluded_json or '[]'))
    effective = [t for t in prof['tools'] if t not in set(excluded)]
    return {'host': name, 'role': role, 'profile_tools': prof['tools'], 'excluded': excluded,
            'tools': effective, 'params': prof.get('params') or {}, 'updated_at': uat, 'updated_by': uby}


def set_host_role(conn: Conn, host: str, role: str, excluded: list[str] | None, actor: str) -> dict:
    name = toolbox.host_name(conn, host)
    r = str(role or '').strip()
    profiles = _profile_map(conn)
    if r not in profiles:
        raise toolbox.CatalogError(f'unknown role profile {r!r}; expected one of {", ".join(sorted(profiles))}')
    ex = []
    for x in (excluded or []):
        tid = str(x or '').strip()
        if tid and tid not in ex:
            ex.append(tid)
    now = int(time.time())
    with conn.tx():
        conn.execute("""INSERT INTO toolbox_host_roles (host, role, excluded_json, updated_at, updated_by) VALUES (:h, :r, :e, :n, :a)
                        ON CONFLICT (host) DO UPDATE SET role = excluded.role, excluded_json = excluded.excluded_json,
                                                         updated_at = excluded.updated_at, updated_by = excluded.updated_by""",
                     {'h': name, 'r': r, 'e': json.dumps(ex), 'n': now, 'a': actor[:60]})
    return host_profile(conn, name)


def list_profiles(conn: Conn) -> dict:
    profiles = _profile_map(conn)
    hosts = []
    for (h,) in conn.all('SELECT host FROM toolbox_host_roles ORDER BY host'):
        try:
            hp = host_profile(conn, h)
        except LookupError:
            hp = None
        if hp:
            hosts.append(hp)
    return {'roles': list(profiles.values()), 'hosts': hosts}


def stage_host_profile(conn: Conn, host: str, actor: str, *, params: dict | None = None, accept_unsigned: bool = False) -> dict:
    hp = host_profile(conn, host)
    if not hp:
        raise LookupError(f'{host} has no role profile assigned')
    if not hp['tools']:
        raise toolbox.CatalogError(f'all tools in role {hp["role"]} are excluded on {hp["host"]}')
    merged = {**(hp.get('params') or {}), **(params or {})}
    return stage_bundle(conn, hp['host'], None, actor, entries=hp['tools'], params=merged,
                        name=f'Role {hp["role"]}', accept_unsigned=accept_unsigned)
