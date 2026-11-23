"""Workloads something else manages (roadmap section 6, externally managed), told by what the host itself shows, and a warning before a
plan step changes one. A panel, a unit or a hypervisor that manages a workload puts back what StorageForge changes, or fights it.

What tells:
- container labels the scan keeps: Komodo, Portainer, Coolify, Dockhand and Dockge labels, a managed-by label (Terraform modules and
  Helm-style tooling set one), Podman's PODMAN_SYSTEMD_UNIT, and the folder a compose project was started from (Portainer keeps stacks in
  /data/compose, Dockge in /opt/stacks), as the Docker page already reads it;
- systemd units: container-NAME.service from podman generate systemd, compose units, a Komodo periphery, and on the host a
  configuration management agent (Puppet, Chef, Salt, ansible-pull, CFEngine), which may put back anything;
- a Proxmox VE host (its guests, and LXC containers that pct made);
- libvirt metadata another tool wrote into a VM (oVirt, OpenStack Nova, or any namespace StorageForge does not know);
- a panel that runs on the host with the container engine socket: it can manage any container there, so those not claimed otherwise are
  marked as possibly its.

Platforms read through their own APIs (the API connection kind) are not read here: that comes with the API connection kind.
"""
from __future__ import annotations

from .runtimes.docker import _manager

LABEL_MANAGERS = (('komodo.', 'Komodo'), ('io.portainer.', 'Portainer'), ('coolify.', 'Coolify'), ('dockhand.', 'Dockhand'), ('dev.dockge.', 'Dockge'))
CONFIG_AGENTS = {'puppet.service': 'Puppet', 'pxp-agent.service': 'Puppet', 'chef-client.service': 'Chef', 'chef-client.timer': 'Chef', 'salt-minion.service': 'Salt',
                 'cfengine3.service': 'CFEngine'}
KNOWN_NS = {'http://libosinfo.org/xmlns/libvirt/domain/1.0': None, 'https://storageforge.invalid/vm': 'StorageForge',
            'http://ovirt.org/vm/1.0': 'oVirt', 'http://ovirt.org/vm/tune/1.0': 'oVirt', 'http://openstack.org/xmlns/libvirt/nova/1.0': 'OpenStack Nova',
            'http://openstack.org/xmlns/libvirt/nova/1.1': 'OpenStack Nova'}
PANEL_UNITS = (('komodo-periphery', 'Komodo'), ('periphery.', 'Komodo'), ('portainer', 'Portainer'), ('dockhand', 'Dockhand'), ('dockge', 'Dockge'), ('coolify', 'Coolify'))


def _m(by: str, how: str, level: str = 'warn') -> dict:
    return {'by': by, 'how': how, 'level': level}


def of_container(w: dict, units: set[str]) -> dict | None:
    labels = w.get('labels') or {}
    if labels.get('storageforge.managed') == 'true':
        return _m('StorageForge', 'made by a StorageForge step', 'ok')
    if labels.get('PODMAN_SYSTEMD_UNIT'):
        unit = labels['PODMAN_SYSTEMD_UNIT']
        return _m('systemd', f'the Quadlet unit {w["quadlet"]} ({unit}) recreates it' if w.get('quadlet') else f'the unit {unit} runs it')
    if f'container-{w["name"]}.service' in units:
        return _m('systemd', f'the unit container-{w["name"]}.service runs it')
    for prefix, name in LABEL_MANAGERS:
        if any(k.startswith(prefix) for k in labels):
            return _m(name, f'it carries {name} labels')
    for k, v in labels.items():
        if k.rsplit('.', 1)[-1].rsplit('/', 1)[-1] in ('managed-by', 'managed_by') and v:
            return _m(v, f'its label {k}={v}')
    project = labels.get('com.docker.compose.project')
    if project:
        where = labels.get('com.docker.compose.project.working_dir') or ''
        panel = _manager(where)
        if panel != 'compose':
            return _m(panel, f'{panel} keeps its compose project {project} in {where}')
        return _m('compose', f'compose project {project}' + (f' in {where}' if where else '') + ': the next compose up there puts back what is changed here', 'note')
    if labels.get('com.centurylinklabs.watchtower.enable') == 'true':
        return _m('Watchtower', 'Watchtower recreates it when its image changes', 'note')
    return None


def of_vm(w: dict) -> dict | None:
    others = [KNOWN_NS.get(ns, ns) for ns in w.get('metadata_ns') or [] if KNOWN_NS.get(ns, ns) not in (None, 'StorageForge')]
    if others:
        return _m(others[0] if others[0].startswith(('oVirt', 'OpenStack')) else 'another tool', f'its libvirt metadata names {", ".join(sorted(set(others)))}')
    if 'https://storageforge.invalid/vm' in (w.get('metadata_ns') or []):
        return _m('StorageForge', 'made by a StorageForge step', 'ok')
    return None


def annotate(workloads: list[dict], host: str, reading: dict | None, api_managed: dict | None = None) -> None:
    """Puts 'managed' ({'by', 'how', 'level'}) on each workload of one host that something manages, and a host-wide note where a
    configuration management agent runs."""
    r = reading or {}
    wu = r.get('wl_units') or {}
    units, markers, tools = set(wu.get('units') or []), set(wu.get('markers') or []), set(r.get('tools') or [])
    agents = sorted({CONFIG_AGENTS[u] for u in units if u in CONFIG_AGENTS} | ({'Puppet'} if 'puppet' in markers else set())
                    | ({'ansible-pull'} if any(u.startswith('ansible-pull') for u in units) else set()))
    pve = 'pve' in markers or 'pct' in tools or 'qm' in tools
    panels = sorted({name for u in units for key, name in PANEL_UNITS if u.startswith(key)}
                    | {w['panel'] for w in workloads if w.get('host') == host and w.get('panel') and w.get('state') == 'running'
                       and any((m.get('source') or '') in ('/var/run/docker.sock', '/run/docker.sock', '/run/podman/podman.sock') for m in w.get('mounts') or [])})
    api_managed = api_managed or {}
    for w in workloads:
        if w.get('host') != host:
            continue
        if w.get('runtime') == 'docker' and w.get('kind') == 'container' and w.get('name') in api_managed:
            am = api_managed[w['name']]
            w['managed'] = _m(am['panel'], f'managed by {am["panel"]} via API connection {am["connection"]}', 'warn')
            w['api'] = {'platform': am.get('panel'), 'connection': am.get('connection'), 'environment': am.get('environment')}
            continue
        m = None
        if w['runtime'] in ('docker', 'podman') and w.get('kind') == 'container':
            m = of_container(w, units)
            if m is None and panels and not w.get('panel'):
                m = _m(f'possibly {panels[0]}', f'{", ".join(panels)} runs here with the container engine socket, and can change any container', 'note')
        elif w['runtime'] == 'libvirt':
            m = of_vm(w)
        elif w['runtime'] == 'proxmox':
            m = _m('Proxmox VE', 'a Proxmox VE guest')
        elif w['runtime'] == 'lxc' and pve:
            m = _m('Proxmox VE', 'this host runs Proxmox VE, whose pct makes its LXC containers')
        if agents and (m is None or m['level'] == 'ok'):
            m = _m(' and '.join(agents), f'{" and ".join(agents)} runs on {host} and may put back what is changed by hand', 'note')
        if m:
            w['managed'] = m
            if m['level'] == 'warn':
                w.setdefault('findings', []).append(f'managed by {m["by"]}: {m["how"]}')


# ── the warning before a step changes one ───────────────────────────
TARGET = {'container': 'name', 'workload-action': 'name', 'workload-remove': 'name', 'vm-edit': 'name', 'vm-snapshot': 'name', 'vm-revert': 'name',
          'incus': 'name', 'lxc': 'name', 'image-update': 'stack', 'stack-snapshot': 'stack', 'stack': 'name'}


def warn_before(conn, kind: str, h: dict, p: dict, say) -> None:
    from . import workloads
    key = TARGET.get(kind)
    target = (p.get(key) or '') if key else ''
    if not target:
        return
    by_stack = kind in ('image-update', 'stack-snapshot', 'stack')
    runtime = p.get('runtime')
    seen = set()
    for w in workloads.listing(conn, h['name'])['workloads']:
        if runtime and w['runtime'] != runtime and not (runtime == 'libvirt' and w['runtime'] == 'libvirt'):
            continue
        if (w.get('stack') == target) if by_stack else (w['name'] == target):
            m = w.get('managed')
            if not m or m['level'] == 'ok' or m['by'] in seen:
                continue
            if kind == 'stack' and m['by'] == 'compose':
                continue                    # the stack step is compose itself; a project from another folder is refused by the script
            seen.add(m['by'])
            say(m['level'], f'{w["name"]} is managed by {m["by"]} ({m["how"]}): a change made here can be undone by it, or fight it. Change it there, or adopt it first')


def install() -> None:
    """Wraps the check of each step that changes a workload, so the warning comes with it."""
    from . import changes
    for kind in TARGET:
        spec = changes.EXTRA.get(kind)
        if not spec or getattr(spec['check'], 'warns_managed', False):
            continue
        inner = spec['check']

        def check(conn, c, h, p, say, _inner=inner, _kind=kind):
            _inner(conn, c, h, p, say)
            warn_before(conn, _kind, h, p, say)
        check.warns_managed = True
        spec['check'] = check
