"""One list of what runs on each host, whichever runtime it is on, read from the index: Docker and Podman from scans, VMs and
instances from measurements. Each mount is tied to the mount it sits on, so "what lives here?" covers VMs too. Findings are
things worth a look, said plainly, and a workload we could not read in full is `detail: False`, not clean.
"""
from __future__ import annotations

import re

from . import inframeasure
from .db import Conn
from .runtimes import docker

SOCKETS = ('/var/run/docker.sock', '/run/docker.sock', '/run/podman/podman.sock')
PANELS = (('Dockhand', r'dockhand'), ('Portainer', r'portainer'), ('Komodo', r'komodo'), ('Dockge', r'dockge'), ('Dokploy', r'dokploy'), ('Coolify', r'coolify'), ('CasaOS', r'casaos'))
RISKY_CAPS = ('SYS_ADMIN', 'ALL', 'NET_ADMIN', 'SYS_MODULE', 'SYS_PTRACE', 'DAC_READ_SEARCH')


def _mounts_of(conn: Conn, host: str) -> list[tuple[str, str]]:
    return conn.all("""SELECT m.mount_point, m.filesystem_type FROM mounts m JOIN hosts h ON h.host_id = m.host_id
                       WHERE lower(h.hostname) = lower(:h) AND m.scan_state <> 'gone'""", {'h': host})


def sits_on(mounts: list, path: str | None) -> dict | None:
    """The mount a path is on: the deepest one above it."""
    if not path or not path.startswith('/'):
        return None
    best = None
    for point, fs in mounts:
        if (path == point or point == '/' or path.startswith(point.rstrip('/') + '/')) and (best is None or len(point) > len(best[0])):
            best = (point, fs)
    return {'mount': best[0], 'filesystem': best[1]} if best else None


def container_findings(c: dict) -> list[str]:
    out = []
    if c.get('privileged'):
        out.append('runs privileged, which is root on the host')
    if any(m.get('source') in SOCKETS for m in c.get('mounts') or []):
        out.append('mounts the container engine socket, which is root on the host')
    if c.get('network_mode') == 'host':
        out.append('uses the host network')
    risky = [cap for cap in c.get('cap_add') or [] if cap.replace('CAP_', '') in RISKY_CAPS]
    if risky:
        out.append('adds capabilities: ' + ', '.join(risky))
    for o in c.get('security_opt') or []:
        if o in ('label=disable', 'label:disable', 'apparmor=unconfined', 'apparmor:unconfined', 'seccomp=unconfined', 'seccomp:unconfined'):
            out.append(f'turns off confinement: {o}')
    return out


def _container(host, runtime, c, mounts, volumes, stack=None, user=None) -> dict:
    vols = {v['name']: v for v in volumes}
    ms = []
    for m in c.get('mounts') or []:
        src = m.get('source') or (vols.get(m.get('name') or '') or {}).get('mountpoint')
        ms.append({'kind': m.get('type'), 'source': src, 'dest': m.get('dest'), 'rw': m.get('rw'), 'volume': m.get('name'), 'on': sits_on(mounts, src)})
    image = c.get('image') or ''
    panel = next((name for name, rx in PANELS if re.search(rx, image, re.I)), None)
    return {'host': host, 'runtime': runtime, 'kind': 'container', 'name': c.get('name'), 'state': c.get('state'), 'image': image, 'digests': c.get('digests') or [], 'stack': stack, 'user': user,
            'mounts': ms, 'ports': c.get('ports') or [], 'networks': c.get('networks') or [], 'health': c.get('health'), 'panel': panel, 'detail': bool(c.get('detail')),
            'security': {k: c.get(k) for k in ('privileged', 'cap_add', 'cap_drop', 'security_opt', 'readonly_root', 'apparmor', 'selinux', 'network_mode')} if c.get('detail') else None,
            'findings': container_findings(c)}


def _vm_findings(d: dict) -> list[str]:
    out = []
    for g in d.get('graphics') or []:
        listen = g.get('listen')
        if listen and listen not in ('127.0.0.1', '::1', 'localhost', 'none', 'socket'):
            out.append(f'{g.get("type")} console listens on {listen}')
    sec = d.get('seclabel') or {}
    if sec.get('type') == 'none':
        out.append('runs unconfined (no sVirt label)')
    if any(n.get('type') == 'bridge' for n in d.get('nics') or []):
        out.append('bridged: host INPUT firewall rules do not apply to its traffic')
    return out


def from_infra(host: str, m: dict, mounts: list) -> list[dict]:
    out = []
    for d in m.get('libvirt') or []:
        out.append({'host': host, 'runtime': 'libvirt', 'kind': 'vm', 'name': d.get('name'), 'state': d.get('state'), 'autostart': d.get('autostart'), 'vcpus': d.get('vcpus'), 'memory_mib': d.get('memory_mib'), 'firmware': d.get('firmware'), 'tpm': d.get('tpm'),
                    'mounts': [{'kind': 'disk', 'source': x.get('source'), 'dest': x.get('target'), 'format': x.get('format'), 'rw': not x.get('readonly'), 'on': sits_on(mounts, x.get('source'))} for x in d.get('disks') or [] if x.get('device') != 'cdrom'],
                    'networks': d.get('nics') or [], 'graphics': d.get('graphics') or [], 'ports': [], 'detail': not d.get('unreadable'), 'security': {'seclabel': d.get('seclabel')}, 'findings': _vm_findings(d)})
    for i in m.get('incus') or []:
        priv = (i.get('security') or {}).get('security.privileged') == 'true'
        devs = i.get('devices') or {}
        out.append({'host': host, 'runtime': 'incus', 'kind': 'vm' if i.get('type') == 'vm' else 'instance', 'name': i.get('name'), 'state': i.get('state'),
                    'mounts': [{'kind': 'disk', 'source': v.get('source') or v.get('pool'), 'dest': v.get('path'), 'on': sits_on(mounts, v.get('source'))} for v in devs.values() if v.get('type') == 'disk'],
                    'networks': [{'source': v.get('network') or v.get('parent'), 'type': v.get('nictype')} for v in devs.values() if v.get('type') == 'nic'], 'ports': [], 'detail': True, 'security': i.get('security') or {},
                    'findings': ['privileged instance'] if priv else []})
    for i in m.get('lxc') or []:
        out.append({'host': host, 'runtime': 'lxc', 'kind': 'instance', 'name': i.get('name'), 'state': i.get('state'), 'mounts': [], 'networks': [], 'ports': [], 'detail': False, 'security': None, 'findings': []})
    for g in m.get('proxmox') or []:
        out.append({'host': host, 'runtime': 'proxmox', 'kind': 'vm' if g.get('kind') == 'qemu' else 'instance', 'name': g.get('name'), 'vmid': g.get('vmid'), 'state': g.get('state'), 'memory_mib': g.get('memory_mib'), 'vcpus': g.get('cores'),
                    'mounts': [{'kind': 'disk', 'source': x.get('source'), 'dest': x.get('target'), 'on': None} for x in g.get('disks') or []], 'networks': g.get('nics') or [], 'ports': [], 'detail': True, 'managed_by': 'proxmox',
                    'security': {'unprivileged': g.get('unprivileged')}, 'findings': ['privileged container'] if g.get('kind') == 'lxc' and g.get('unprivileged') is False else []})
    for u in m.get('podman_rootless') or []:
        for c in u.get('containers') or []:
            out.append(_container(host, 'podman', c, mounts, [], user=u.get('user')))
    return out


def listing(conn: Conn, host: str | None = None) -> dict:
    """{'workloads': [...], 'hosts': [{'host', 'read': ..}]}. `read` says what each host's list is based on, so an empty list can be told from an unread one."""
    names = [r[0] for r in conn.all('SELECT hostname FROM hosts ORDER BY hostname')]
    if host:
        names = [n for n in names if n.lower() == host.lower() or n.split('.')[0].lower() == host.lower()]
    views = {h['host']: h for h in docker.listing(conn)}
    out, hosts = [], []
    for name in names:
        mounts = _mounts_of(conn, name)
        view = views.get(name)
        if view:
            for s in view['stacks']:
                for c in s['containers']:
                    out.append(_container(name, view['engine'] or 'docker', c, mounts, view['volumes'], stack=s.get('project')))
        m = inframeasure.reading(conn, name)
        if m:
            out += from_infra(name, m, mounts)
        hosts.append({'host': name, 'engine': (view or {}).get('engine'), 'containers_read_at': (view or {}).get('updated_at'), 'measured_at': (m or {}).get('measured_at'), 'measure_stale': (m or {}).get('stale')})
    return {'workloads': out, 'hosts': hosts}


def containers_of(conn: Conn, host: str) -> list[dict]:
    """A host's containers as docker.py records them, for the exposure engine."""
    out = []
    for view in docker.listing(conn, host):
        for s in view['stacks']:
            out += s['containers']
    m = inframeasure.reading(conn, host) or {}
    for u in m.get('podman_rootless') or []:
        out += u.get('containers') or []
    return out


