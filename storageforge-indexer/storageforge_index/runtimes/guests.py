"""VMs and instances, parsed from what a measurement read as root: libvirt, Incus, plain LXC, Proxmox, and rootless Podman.

Host output is not trusted. XML that declares entities is refused rather than parsed. Only known fields are kept, so a
secret in a guest's config has nowhere to land. Proxmox guests are listed and never managed: Proxmox does that.
"""
from __future__ import annotations

import base64
import binascii
import re
import xml.etree.ElementTree as ET

MAX_XML = 256 * 1024


def _b64(text: str) -> str | None:
    try:
        return base64.b64decode(text.encode(), validate=True).decode('utf-8', 'replace')
    except (binascii.Error, ValueError):
        return None


def _xml(text: str | None):
    if not text or len(text) > MAX_XML or '<!DOCTYPE' in text or '<!ENTITY' in text:
        return None
    try:
        return ET.fromstring(text)
    except ET.ParseError:
        return None


def parse_domain(text: str | None) -> dict | None:
    """One libvirt domain's XML. Graphics passwords are never read: dumpxml leaves them out unless asked, and this keeps no such field."""
    root = _xml(text)
    if root is None or root.tag != 'domain':
        return None
    mem = root.find('memory')
    mib = None
    if mem is not None and (mem.text or '').strip().isdigit():
        unit = (mem.get('unit') or 'KiB').lower()
        mib = int(mem.text) * {'b': 1 / 1048576, 'kib': 1 / 1024, 'k': 1 / 1024, 'mib': 1, 'm': 1, 'gib': 1024, 'g': 1024}.get(unit, 1 / 1024)
    disks = []
    for d in root.findall('./devices/disk'):
        src = d.find('source')
        src_path = None if src is None else src.get('file') or src.get('dev') or src.get('name') or (f"{src.get('pool')}/{src.get('volume')}" if src.get('pool') else None)
        drv, tgt = d.find('driver'), d.find('target')
        disks.append({'device': d.get('device'), 'source': src_path, 'format': None if drv is None else drv.get('type'), 'target': None if tgt is None else tgt.get('dev'),
                      'bus': None if tgt is None else tgt.get('bus'), 'backing': d.find('backingStore/source') is not None, 'readonly': d.find('readonly') is not None})
    nics = []
    for n in root.findall('./devices/interface'):
        src, mac, model = n.find('source'), n.find('mac'), n.find('model')
        nics.append({'type': n.get('type'), 'source': None if src is None else src.get('bridge') or src.get('network') or src.get('dev'),
                     'mac': None if mac is None else mac.get('address'), 'model': None if model is None else model.get('type')})
    graphics = []
    for g in root.findall('./devices/graphics'):
        listen = g.get('listen')
        li = g.find('listen')
        if listen is None and li is not None:
            listen = li.get('address') or (li.get('type') if li.get('type') == 'none' else None)
        graphics.append({'type': g.get('type'), 'listen': listen, 'port': g.get('port')})
    sec = root.find('seclabel')
    os_el = root.find('os')
    typ = None if os_el is None else os_el.find('type')
    cpu = root.find('cpu')
    agent = None
    for ch in root.findall('./devices/channel'):
        tgt = ch.find('target')
        if tgt is not None and tgt.get('name') == 'org.qemu.guest_agent.0':
            agent = tgt.get('state') or 'defined'      # connected or disconnected on a running VM; defined on one that is off
    osinfo = next((e.get('id') for e in root.iter() if e.tag.endswith('}os') and e.get('id', '').startswith('http')), None)
    loader = None if os_el is None else os_el.find('loader')
    return {'name': root.findtext('name'), 'uuid': root.findtext('uuid'), 'vcpus': root.findtext('vcpu'), 'memory_mib': int(mib) if mib is not None else None,
            'disks': disks, 'nics': nics, 'graphics': graphics, 'tpm': root.find('./devices/tpm') is not None,
            'firmware': None if os_el is None else ('uefi' if os_el.get('firmware') == 'efi' else os_el.get('firmware')) or ('uefi' if loader is not None else 'bios'),
            'secure_boot': loader is not None and loader.get('secure') == 'yes',
            'machine': None if typ is None else typ.get('machine'), 'arch': None if typ is None else typ.get('arch'),
            'cpu_mode': None if cpu is None else cpu.get('mode'), 'agent': agent, 'osinfo': osinfo,
            'serial': root.find('./devices/serial') is not None or root.find('./devices/console') is not None,
            'seclabel': None if sec is None else {'type': sec.get('type'), 'model': sec.get('model'), 'label': sec.findtext('label')}}


def parse_libvirt(lines: list[str]) -> list[dict]:
    """Each line: name, state, autostart, base64 of the XML, by tabs."""
    out = []
    for line in lines:
        f = line.split('\t')
        if len(f) < 4:
            continue
        d = parse_domain(_b64(f[3]))
        out.append({**(d or {'unreadable': True, 'name': f[0]}), 'name': f[0], 'state': f[1], 'autostart': f[2] == 'enable'})
    return out


def _info(text: str | None) -> dict:
    """virsh net-info or pool-info: Key: value lines."""
    out = {}
    for line in (text or '').splitlines():
        k, sep, v = line.partition(':')
        if sep:
            out[k.strip().lower()] = v.strip()
    return out


def parse_libvirt_snapshots(lines: list[str]) -> dict:
    """Lines of domain, snapshot, current (0 or 1) and base64 of the snapshot XML up to the domain it holds. -> {domain: [snapshot]}"""
    out: dict = {}
    for line in lines:
        f = line.split('\t')
        if len(f) < 4:
            continue
        root = _xml(_b64(f[3]))
        if root is None or root.tag != 'domainsnapshot':
            root = _xml((_b64(f[3]) or '') + '</domainsnapshot>')       # cut before its domain: the closing tag went with it
        if root is None or root.tag != 'domainsnapshot':
            continue
        mem = root.find('memory')
        disks = [{'name': d.get('name'), 'snapshot': d.get('snapshot'), 'file': None if d.find('source') is None else d.find('source').get('file')}
                 for d in root.findall('./disks/disk')]
        external = any(d['snapshot'] == 'external' for d in disks)
        created = root.findtext('creationTime') or ''
        out.setdefault(f[0], []).append({
            'name': root.findtext('name') or f[1], 'state': root.findtext('state'), 'parent': root.findtext('parent/name'),
            'created': int(created) if created.isdigit() else None, 'current': f[2] == '1', 'description': (root.findtext('description') or '')[:200],
            'memory': None if mem is None else mem.get('snapshot'), 'location': 'external' if external else 'internal',
            'disk_only': (root.findtext('state') == 'disk-snapshot'), 'disks': disks})
    for snaps in out.values():
        snaps.sort(key=lambda x: x['created'] or 0)
    return out


def with_snapshots(domains: list[dict], snaps: dict) -> list[dict]:
    for d in domains:
        d['snapshots'] = snaps.get(d.get('name'), [])
    return domains


def parse_libvirt_networks(lines: list[str]) -> list[dict]:
    out = []
    for line in lines:
        f = line.split('\t')
        root = _xml(_b64(f[1])) if len(f) > 1 else None
        if root is None:
            continue
        info = _info(_b64(f[2])) if len(f) > 2 else {}
        fwd, br, ip = root.find('forward'), root.find('bridge'), root.find('ip')
        rng = None if ip is None else ip.find('dhcp/range')
        out.append({'name': root.findtext('name'), 'mode': 'isolated' if fwd is None else fwd.get('mode') or 'nat', 'bridge': None if br is None else br.get('name'),
                    'address': None if ip is None else ip.get('address'), 'netmask': None if ip is None else ip.get('netmask') or ip.get('prefix'),
                    'dhcp': None if rng is None else f"{rng.get('start')}-{rng.get('end')}",
                    'active': info.get('active') == 'yes' if info else None, 'autostart': info.get('autostart') == 'yes' if info else None,
                    'persistent': info.get('persistent') == 'yes' if info else None})
    return out


def parse_libvirt_pools(lines: list[str]) -> list[dict]:
    out = []
    for line in lines:
        f = line.split('\t')
        root = _xml(_b64(f[1])) if len(f) > 1 else None
        if root is None:
            continue
        info = _info(_b64(f[2])) if len(f) > 2 else {}

        def num(k):
            v = (info.get(k) or '').split()[0] if info.get(k) else ''
            return int(v) if v.isdigit() else None
        src = root.find('source')
        out.append({'name': root.findtext('name'), 'type': root.get('type'), 'path': root.findtext('target/path'),
                    'source': None if src is None else (src.findtext('name') or (src.find('device').get('path') if src.find('device') is not None else None)),
                    'active': info.get('state') == 'running' if info else None, 'autostart': info.get('autostart') == 'yes' if info else None,
                    'capacity': num('capacity'), 'allocation': num('allocation'), 'available': num('available')})
    return out


# ── Incus and plain LXC ──────────────────────────────────────────────
def parse_incus(lines: list[str]) -> list[dict]:
    """Lines from the measure script. `i` is an instance by csv (name, state, type, profiles, IPv4, snapshots); `d` its device
    YAML as base64; `s` a security key. Never `incus list --format json`: its config can hold cloud-init data and secrets."""
    import csv
    import io
    import yaml
    out, by = [], {}
    for line in lines:
        tag, _, rest = line.partition('\t')
        if tag == 'i':
            row = next(csv.reader(io.StringIO(rest)), [])
            if len(row) >= 3:
                by[row[0]] = {'name': row[0], 'state': row[1].lower(), 'type': 'vm' if 'VIRTUAL' in row[2].upper() else 'container',
                              'profiles': (row[3] if len(row) > 3 else '').split(), 'ipv4': (row[4] if len(row) > 4 else '').split()[:1], 'snapshots': row[5] if len(row) > 5 else None,
                              'devices': {}, 'security': {}}
                out.append(by[row[0]])
        elif tag == 'd':
            name, _, data = rest.partition('\t')
            if name in by:
                try:
                    devices = yaml.safe_load(_b64(data) or '')
                except yaml.YAMLError:
                    devices = None
                by[name]['devices'] = {str(k): {x: str(v[x]) for x in ('type', 'source', 'path', 'pool', 'network', 'parent', 'nictype', 'listen', 'connect') if x in v}
                                       for k, v in (devices or {}).items() if isinstance(v, dict)} if isinstance(devices, dict) else {}
        elif tag == 's':
            name, key, val = (rest.split('\t') + ['', ''])[:3]
            if name in by and key in ('security.privileged', 'security.nesting') and val:
                by[name]['security'][key] = val
    return out


def parse_lxc(lines: list[str]) -> list[dict]:
    out = []
    for line in lines:
        f = line.split()
        if len(f) >= 2 and f[0] != 'NAME':
            out.append({'name': f[0], 'state': f[1].lower(), 'ipv4': [] if len(f) < 3 or f[2] == '-' else [f[2].rstrip(',')]})
    return out


# ── Proxmox ──────────────────────────────────────────────────────────
PVE_DISK = re.compile(r'(?:scsi|virtio|sata|ide|efidisk|tpmstate|rootfs|mp)\d*$')


def parse_proxmox(lines: list[str]) -> list[dict]:
    """`g <kind> <id> <name> <state>` then that guest's config lines as `c <key>: <value>`. The script only lets known keys through."""
    out, cur = [], None
    for line in lines:
        if line.startswith('g\t'):
            f = line.split('\t')
            if len(f) >= 5:
                cur = {'kind': f[1], 'vmid': f[2], 'name': f[3], 'state': f[4], 'disks': [], 'nics': [], 'cores': None, 'memory_mib': None, 'onboot': None, 'unprivileged': None}
                out.append(cur)
        elif line.startswith('c\t') and cur:
            key, _, val = line[2:].partition(': ')
            if PVE_DISK.match(key):
                cur['disks'].append({'target': key, 'source': val.split(',')[0]})
            elif re.fullmatch(r'net\d+', key):
                parts = dict(p.split('=', 1) for p in val.split(',') if '=' in p)
                mac = next((v for k, v in parts.items() if k.lower() in ('virtio', 'e1000', 'hwaddr', 'vmxnet3', 'rtl8139')), None)
                cur['nics'].append({'target': key, 'source': parts.get('bridge'), 'mac': mac})
            elif key in ('cores', 'memory') and val.isdigit():
                cur['cores' if key == 'cores' else 'memory_mib'] = int(val)
            elif key in ('onboot', 'unprivileged'):
                cur[key] = val == '1'
    return out
