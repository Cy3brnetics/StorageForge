"""Adopting a workload by capturing it (roadmap section 6, the read side): the definition of a running container, VM or instance, written
from what the index read of it, as compose or a Quadlet unit (Docker and Podman), libvirt XML (libvirt) or Incus YAML (Incus). The capture
is kept, and each later reading is compared with it: a changed image, a mount or a published port added, a NIC moved, is drift.

A capture is a definition to recreate the workload from, not a copy of what the runtime holds: environment values are never read by a
scan, so they are not in it (the compose and Quadlet captures say where to add them), and a VM's XML holds what the reading keeps (CPU,
memory, firmware, disks, NICs, graphics, TPM, the guest agent channel), not every device libvirt adds by itself.

Nothing here runs on a host: capturing reads the index, and adopting saves the capture.
"""
from __future__ import annotations

import datetime as dt
import json
import re
import time
import xml.etree.ElementTree as ET

import yaml

from .db import Conn

FORMATS = {'docker': ('compose', 'quadlet'), 'podman': ('compose', 'quadlet'), 'libvirt': ('libvirt',), 'incus': ('incus',)}
SKIP_LABELS = re.compile(r'^(com\.docker\.compose\.|io\.podman\.compose\.|PODMAN_SYSTEMD_UNIT$)')


def _service(name: str) -> str:
    return re.sub(r'[^a-z0-9_-]', '-', (name or 'app').lower()).strip('-') or 'app'


def find(conn: Conn, host: str, runtime: str, name: str) -> dict | None:
    from . import workloads
    return next((w for w in workloads.listing(conn, host)['workloads'] if w['runtime'] == runtime and w['name'] == name), None)


# ── the fields drift is measured on ─────────────────────────────────
def facts(w: dict) -> dict:
    if w['runtime'] in ('docker', 'podman'):
        sec = w.get('security') or {}
        return {'image': w.get('image') or '', 'digests': sorted(w.get('digests') or []),
                'ports': sorted(f'{p.get("host_ip") or "0.0.0.0"}:{p.get("host_port")}->{p.get("port")}/{p.get("proto") or "tcp"}' for p in w.get('ports') or []),
                'mounts': sorted(f'{m.get("volume") or m.get("source")}:{m.get("dest")}:{"rw" if m.get("rw") else "ro"}' for m in w.get('mounts') or []),
                'networks': sorted(n.get('name') or '' for n in w.get('networks') or []), 'privileged': bool(sec.get('privileged')),
                'cap_add': sorted(sec.get('cap_add') or []), 'network_mode': sec.get('network_mode') or ''}
    if w['runtime'] == 'libvirt':
        return {'vcpus': str(w.get('vcpus') or ''), 'memory_mib': w.get('memory_mib'), 'firmware': w.get('firmware') or '',
                'disks': sorted(f'{d.get("target")}={d.get("source")}' for d in w.get('disks') or [] if d.get('device') != 'cdrom'),
                'nics': sorted(f'{n.get("type")}:{n.get("source")}:{n.get("mac")}' for n in w.get('networks') or []),
                'graphics': sorted(f'{g.get("type")}@{g.get("listen")}' for g in w.get('graphics') or [])}
    if w['runtime'] == 'incus':
        return {'type': w.get('kind') or '', 'profiles': sorted(w.get('profiles') or []),
                'devices': sorted(f'{k}:{v.get("type")}:{v.get("source") or v.get("pool") or v.get("network") or v.get("parent") or ""}:{v.get("path") or v.get("listen") or ""}'
                                  for k, v in (w.get('devices') or {}).items()),
                'security': sorted(f'{k}={v}' for k, v in (w.get('security') or {}).items())}
    return {}


def drift(captured: dict, now: dict) -> list[dict]:
    out = []
    for k, was in captured.items():
        cur = now.get(k)
        if cur == was:
            continue
        row = {'field': k, 'captured': was, 'now': cur}
        if isinstance(was, list) and isinstance(cur, list):
            row.update(added=[x for x in cur if x not in was], removed=[x for x in was if x not in cur])
        out.append(row)
    return out


# ── the definitions ─────────────────────────────────────────────────
def _head(w: dict, comment: str) -> str:
    return (f'{comment} Captured by StorageForge from {w["host"]} on {dt.date.today().isoformat()}: {w["runtime"]} {w["name"]}.\n'
            f'{comment} A scan never reads environment values, so none are here: give them with an env file of your own.\n')


def compose(w: dict) -> str:
    sec = w.get('security') or {}
    svc: dict = {'image': w.get('image') or '', 'container_name': w['name']}
    if w.get('restart') and w['restart'] != 'no':
        svc['restart'] = w['restart']
    ports = []
    for p in w.get('ports') or []:
        bind = p.get('host_ip') or '0.0.0.0'
        ports.append(f'{"" if bind in ("0.0.0.0", "::") else bind + ":"}{p["host_port"]}:{p["port"]}{"" if (p.get("proto") or "tcp") == "tcp" else "/" + p["proto"]}')
    if ports:
        svc['ports'] = ports
    vols, named = [], {}
    for m in w.get('mounts') or []:
        src = m.get('volume') if m.get('kind') == 'volume' and m.get('volume') else m.get('source')
        if not src or not m.get('dest'):
            continue
        vols.append(f'{src}:{m["dest"]}{"" if m.get("rw", True) else ":ro"}')
        if m.get('kind') == 'volume' and m.get('volume'):
            named[m['volume']] = {'external': True}
    if vols:
        svc['volumes'] = vols
    nets = {}
    if sec.get('network_mode') == 'host':
        svc['network_mode'] = 'host'
    else:
        names = [n.get('name') for n in w.get('networks') or [] if n.get('name') and n['name'] not in ('bridge', 'podman', 'default')]
        if names:
            svc['networks'] = names
            nets = {n: {'external': True} for n in names}
    if sec.get('privileged'):
        svc['privileged'] = True
    for k in ('cap_add', 'cap_drop', 'security_opt'):
        if sec.get(k):
            svc[k] = list(sec[k])
    if sec.get('readonly_root'):
        svc['read_only'] = True
    labels = {k: v for k, v in (w.get('labels') or {}).items() if not SKIP_LABELS.match(k)}
    if labels:
        svc['labels'] = labels
    doc: dict = {'services': {_service(w['name']): svc}}
    if named:
        doc['volumes'] = named          # external: the volumes already there are used, not new ones under a project prefix
    if nets:
        doc['networks'] = nets
    return _head(w, '#') + yaml.safe_dump(doc, sort_keys=False, default_flow_style=False)


def quadlet(w: dict) -> str:
    sec = w.get('security') or {}
    lines = [f'[Unit]', f'Description={w["name"]}, captured by StorageForge', '', '[Container]', f'Image={w.get("image") or ""}', f'ContainerName={w["name"]}']
    for p in w.get('ports') or []:
        bind = p.get('host_ip') or '0.0.0.0'
        lines.append(f'PublishPort={"" if bind in ("0.0.0.0", "::") else bind + ":"}{p["host_port"]}:{p["port"]}{"" if (p.get("proto") or "tcp") == "tcp" else "/" + p["proto"]}')
    for m in w.get('mounts') or []:
        src = m.get('volume') if m.get('kind') == 'volume' and m.get('volume') else m.get('source')
        if src and m.get('dest'):
            lines.append(f'Volume={src}:{m["dest"]}{"" if m.get("rw", True) else ":ro"}')
    if sec.get('network_mode') == 'host':
        lines.append('Network=host')
    else:
        for n in w.get('networks') or []:
            if n.get('name') and n['name'] not in ('bridge', 'podman', 'default'):
                lines.append(f'Network={n["name"]}')
    for cap in sec.get('cap_add') or []:
        lines.append(f'AddCapability={cap}')
    if sec.get('readonly_root'):
        lines.append('ReadOnly=true')
    for k, v in (w.get('labels') or {}).items():
        if not SKIP_LABELS.match(k) and re.fullmatch(r'[^\s"]+', k) and re.fullmatch(r'[^\s"]*', v or ''):
            lines.append(f'Label={k}={v}')
    lines += ['', '[Service]', 'Restart=always' if w.get('restart') in ('always', 'unless-stopped') else 'Restart=on-failure', '', '[Install]', 'WantedBy=default.target']
    return _head(w, '#') + '\n'.join(lines) + '\n'


def libvirt(w: dict) -> str:
    d = ET.Element('domain', type='kvm')
    ET.SubElement(d, 'name').text = w['name']
    ET.SubElement(d, 'memory', unit='MiB').text = str(w.get('memory_mib') or 1024)
    ET.SubElement(d, 'vcpu').text = str(w.get('vcpus') or 1)
    os_el = ET.SubElement(d, 'os', **({'firmware': 'efi'} if w.get('firmware') == 'uefi' else {}))
    ET.SubElement(os_el, 'type', arch='x86_64', **({'machine': w['machine']} if w.get('machine') else {})).text = 'hvm'
    feats = ET.SubElement(d, 'features')
    ET.SubElement(feats, 'acpi')
    ET.SubElement(feats, 'apic')
    ET.SubElement(d, 'cpu', mode=w.get('cpu_mode') or 'host-model')
    dev = ET.SubElement(d, 'devices')
    for x in w.get('disks') or []:
        if not x.get('source'):
            continue
        disk = ET.SubElement(dev, 'disk', type='file', device=x.get('device') or 'disk')
        ET.SubElement(disk, 'driver', name='qemu', type=x.get('format') or 'raw')
        ET.SubElement(disk, 'source', file=x['source'])
        ET.SubElement(disk, 'target', dev=x.get('target') or 'vda', bus=x.get('bus') or 'virtio')
        if x.get('readonly') or x.get('device') == 'cdrom':
            ET.SubElement(disk, 'readonly')
    for n in w.get('networks') or []:
        kind = n.get('type') if n.get('type') in ('network', 'bridge') else 'network'
        nic = ET.SubElement(dev, 'interface', type=kind)
        ET.SubElement(nic, 'source', **{'network' if kind == 'network' else 'bridge': n.get('source') or 'default'})
        if n.get('mac'):
            ET.SubElement(nic, 'mac', address=n['mac'])
        ET.SubElement(nic, 'model', type=n.get('model') or 'virtio')
    for g in w.get('graphics') or []:
        if g.get('type') in ('spice', 'vnc'):
            # a capture never widens a console: a listener on another address is kept off and said in the findings
            ET.SubElement(dev, 'graphics', type=g['type'], listen='127.0.0.1')
    if w.get('serial'):
        ET.SubElement(dev, 'console', type='pty')
    if w.get('agent'):
        ch = ET.SubElement(dev, 'channel', type='unix')
        ET.SubElement(ch, 'target', type='virtio', name='org.qemu.guest_agent.0')
    if w.get('tpm'):
        tpm = ET.SubElement(dev, 'tpm', model='tpm-crb')
        ET.SubElement(tpm, 'backend', type='emulator', version='2.0')
    ET.indent(d)
    head = f'Captured by StorageForge from {w["host"]} on {dt.date.today().isoformat()}: libvirt {w["name"]}. The fields the reading keeps, not every device.'
    return f'<!-- {head.replace("--", "- -")} -->\n' + ET.tostring(d, encoding='unicode') + '\n'


def incus(w: dict) -> str:
    config = {k: str(v) for k, v in (w.get('security') or {}).items()}
    doc = {'name': w['name'], 'type': 'virtual-machine' if w.get('kind') == 'vm' else 'container', 'profiles': list(w.get('profiles') or ['default']),
           'config': config, 'devices': {k: {kk: str(vv) for kk, vv in v.items()} for k, v in (w.get('devices') or {}).items()}}
    return _head(w, '#') + yaml.safe_dump(doc, sort_keys=False, default_flow_style=False)


RENDER = {'compose': compose, 'quadlet': quadlet, 'libvirt': libvirt, 'incus': incus}


def render(w: dict, fmt: str | None = None) -> tuple[str, str]:
    """(format, text) for one workload record of workloads.listing."""
    if w.get('detail') is False:       # a failed details pass, or a domain XML that could not be read: a capture would pass for complete
        raise ValueError(f'{w.get("name")} could not be read in full on {w.get("host")}: scan the host again before capturing it')
    allowed = FORMATS.get(w['runtime'])
    if not allowed:
        raise ValueError(f'a {w["runtime"]} workload cannot be captured here: {", ".join(FORMATS)} can')
    fmt = fmt or allowed[0]
    if fmt not in allowed:
        raise ValueError(f'a {w["runtime"]} workload is captured as {" or ".join(allowed)}')
    return fmt, RENDER[fmt](w)


# ── adopting: the capture kept ──────────────────────────────────────
def adopt(conn: Conn, host: str, runtime: str, name: str, fmt: str | None, actor: str, note: str = '') -> dict:
    w = find(conn, host, runtime, name)
    if not w:
        raise LookupError(f'no {runtime} workload {name} on {host} in the index')
    if w.get('state') == 'defined':
        raise ValueError(f'{name} is not running: there is nothing to capture but its unit')
    fmt, text = render(w, fmt)
    row = {'h': w['host'], 'r': runtime, 'n': name, 'f': fmt, 'd': text, 'j': json.dumps(facts(w)), 'o': (note or '')[:200], 't': int(time.time()), 'a': actor}
    with conn.tx():
        conn.execute('DELETE FROM workload_captures WHERE host = :h AND runtime = :r AND name = :n', row)
        conn.execute("""INSERT INTO workload_captures (host, runtime, name, format, definition, facts_json, note, captured_at, captured_by)
                        VALUES (:h, :r, :n, :f, :d, :j, :o, :t, :a)""", row)
    cid = conn.scalar('SELECT id FROM workload_captures WHERE host = :h AND runtime = :r AND name = :n', row)
    return {'id': cid, 'host': w['host'], 'runtime': runtime, 'name': name, 'format': fmt, 'definition': text}


def captures(conn: Conn, host: str | None = None) -> list[dict]:
    """Every capture with its drift against what the index reads now: 'same', 'drifted' or 'gone'."""
    from . import workloads
    rows = conn.all(f"""SELECT id, host, runtime, name, format, facts_json, note, captured_at, captured_by FROM workload_captures
                        {'WHERE lower(host) = lower(:h)' if host else ''} ORDER BY host, runtime, name""", {'h': host})
    live: dict = {}
    out = []
    for cid, h, rt, name, fmt, fj, note, at, by in rows:
        if h not in live:
            live[h] = {(w['runtime'], w['name']): w for w in workloads.listing(conn, h)['workloads']}
        w = live[h].get((rt, name))
        diff = drift(json.loads(fj), facts(w)) if w and w.get('state') != 'defined' else []
        out.append({'id': cid, 'host': h, 'runtime': rt, 'name': name, 'format': fmt, 'note': note, 'captured_at': at, 'captured_by': by,
                    'state': 'gone' if not w or w.get('state') == 'defined' else 'drifted' if diff else 'same', 'drift': diff})
    return out


def get(conn: Conn, cid: int) -> dict | None:
    rows = conn.all('SELECT id, host, runtime, name, format, definition, captured_at, captured_by FROM workload_captures WHERE id = :i', {'i': cid})
    return dict(zip(('id', 'host', 'runtime', 'name', 'format', 'definition', 'captured_at', 'captured_by'), rows[0])) if rows else None


def forget(conn: Conn, cid: int) -> bool:
    if not get(conn, cid):
        return False
    conn.execute('DELETE FROM workload_captures WHERE id = :i', {'i': cid})
    return True


def annotate(conn: Conn, workloads: list[dict]) -> None:
    """Puts on each listed workload its capture, if it was adopted, with its drift."""
    rows = conn.all('SELECT id, host, runtime, name, format, facts_json, captured_at FROM workload_captures')
    by = {(h, rt, n): (cid, fmt, fj, at) for cid, h, rt, n, fmt, fj, at in rows}
    for w in workloads:
        hit = by.get((w.get('host'), w.get('runtime'), w.get('name')))
        if hit:
            cid, fmt, fj, at = hit
            diff = drift(json.loads(fj), facts(w)) if w.get('state') != 'defined' else []
            w['capture'] = {'id': cid, 'format': fmt, 'captured_at': at, 'drift': diff}
