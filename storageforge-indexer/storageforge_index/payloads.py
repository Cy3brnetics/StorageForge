"""Parsers for raw storage payloads, and builders for the report's node model.

Accepted inputs: a StorageForge blueprint (JSON or YAML), `lsblk -J -b`,
`/etc/fstab`, `df -h` or `df -B1 -P`, `zpool status`, and hosts already in
the index. Each produces or enriches a plain-dict node so a report can be
regenerated from saved files.
"""
from __future__ import annotations

import hashlib
import json
import posixpath
import re
from pathlib import Path

from .capacity import MiB, parse_size, pool_capacity
from .db import Conn, epoch
from .remote import DEFAULT_EXCLUDE_PATHS, NETWORK_FS, PSEUDO_FS, TMP_FS, is_under
from .stream import join_path, split_path


def node_skeleton(hostname: str) -> dict:
    return {'hostname': hostname, 'node_id': 'node-' + hashlib.sha1(hostname.encode()).hexdigest()[:8],
            'ip': None, 'os': None, 'last_scanned': None, 'disks': [], 'pools': [], 'mounts': [],
            'links': [], 'remotes': [], 'exports': [], 'protection': [], 'index': None, 'drift': [], 'sources': []}


def load_structured(path: str):
    text = Path(path).read_text()
    if path.endswith(('.yaml', '.yml')) or not text.lstrip().startswith(('{', '[')):
        try:
            import yaml
        except ImportError as exc:
            raise SystemExit('YAML input needs PyYAML (pip install pyyaml); JSON works without it') from exc
        return yaml.safe_load(text)
    return json.loads(text)


def _dev(name):
    return (name or '').removeprefix('/dev/')


def infer_media(bus, rota=None):
    b = (bus or '').lower()
    if 'iscsi' in b:
        return 'net'
    if 'nvme' in b:
        return 'ssd'
    if rota is not None:
        return 'hdd' if rota in (True, 1, '1') else 'ssd'
    return 'unknown'


def infer_tier(media):
    return {'net': 'remote', 'ssd': 'fast', 'hdd': 'mass'}.get(media, 'mass')


# StorageForge blueprint

def node_from_blueprint(bp: dict) -> dict:
    meta = bp.get('metadata') or {}
    node = node_skeleton(meta.get('host') or 'unknown')
    node['sources'].append(f'StorageForge blueprint ({bp.get("apiVersion", "unversioned")}, generated {meta.get("generated", "?")})')
    sizes, tiers = {}, {}
    for d in bp.get('devices') or []:
        dev = _dev(d.get('dev'))
        media = d.get('media') or infer_media(d.get('bus'))
        sector = d.get('sector') or {}
        disk = {'dev': dev, 'model': d.get('model'), 'serial': d.get('serial'), 'bus': d.get('bus'), 'media': media,
                'size': d.get('sizeBytes'), 'table': d.get('table'), 'tier': d.get('tier') or infer_tier(media),
                'log_sec': sector.get('logical'), 'phy_sec': sector.get('physical'), 'member': d.get('member'), 'parts': []}
        sizes[dev], tiers[dev] = disk['size'], disk['tier']
        for p in d.get('partitions') or []:
            start = p.get('startBytes')
            if start is None:
                start = round((p.get('startMiB') or 0) * MiB)
            part = {'dev': p['id'], 'start': start, 'size': p.get('sizeBytes'), 'fs': p.get('fs'), 'label': p.get('label'),
                    'uuid': None, 'mount': p.get('mount'), 'options': p.get('options') or [], 'member': p.get('member'),
                    'role': p.get('role'), 'subvols': p.get('subvolumes') or []}
            disk['parts'].append(part)
            sizes[p['id']], tiers[p['id']] = part['size'], disk['tier']
        node['disks'].append(disk)
    for p in bp.get('pools') or []:
        members = [_dev(m) for m in p.get('members') or []]
        msizes = [sizes.get(m) for m in members]
        pool = {'name': p['name'], 'type': p.get('type'), 'level': p.get('level'), 'members': members,
                'log': [_dev(m) for m in p.get('log') or []], 'cache': [_dev(m) for m in p.get('cache') or []],
                'spares': [], 'mount': p.get('mount'), 'fs': p.get('fs'), 'encryption': p.get('encryption'),
                'ashift': p.get('ashift'), 'tier': p.get('tier') or (tiers.get(members[0]) if members else None),
                'datasets': [{'name': f'{p["name"]}/{ds["name"]}', 'mount': ds.get('mount'),
                              'props': {k: ds[k] for k in ('recordsize', 'compression', 'sync') if k in ds}}
                             for ds in p.get('datasets') or []],
                'health': None, 'scan': None, 'device_errors': []}
        if p.get('type') == 'lvm' and p.get('vg') and not p.get('lv'):
            for ds in pool['datasets']:
                src = next(x for x in p['datasets'] if f'{p["name"]}/{x["name"]}' == ds['name'])
                ds['props'] = {k: src[k] for k in ('fs', 'sizeBytes') if k in src}
            pool.update(vg=p['vg'], lv=None, aliases=[f'{p["vg"]}/{ds["name"].split("/", 1)[1]}' for ds in pool['datasets']])
        elif p.get('type') == 'lvm' and p.get('vg') and p.get('lv'):
            pool.update(vg=p['vg'], lv=p['lv'], aliases=[f"mapper/{p['vg'].replace('-', '--')}-{p['lv'].replace('-', '--')}", f"{p['vg']}/{p['lv']}"])
        pool['cap'] = pool_capacity(pool['type'], pool['level'], [s for s in msizes if s], ashift=p.get('ashift') or 12,
                                    fs=p.get('fs'))
        node['pools'].append(pool)
    for m in bp.get('mounts') or []:
        node['mounts'].append({'target': m['target'], 'kind': m.get('kind'), 'fstype': m.get('fs'), 'spec': m.get('spec'),
                               'options': m.get('options') or [], 'tier': m.get('tier'), 'source': m.get('source'),
                               'total': None, 'used': None})
    if not node['mounts']:
        node['mounts'] = _derive_mounts(node, bp)
    for r in bp.get('remotes') or []:
        node['remotes'].append({'name': r.get('name'), 'proto': r.get('protocol'), 'endpoint': r.get('endpoint'),
                                'via': r.get('via'), 'mount': r.get('mount'), 'status': r.get('status')})
    for l in bp.get('links') or []:
        node['links'].append({'kind': l['kind'], 'path': l['path'], 'target': l['target'], 'health': l.get('health')})
    node['exports'] = [dict(e) for e in bp.get('exports') or []]
    node['protection'] = [dict(r) for r in bp.get('protection') or []]
    return node


def _derive_mounts(node, bp):
    out = []
    for d in node['disks']:
        for p in d['parts']:
            if p.get('subvols'):
                for sv in p['subvols']:
                    if sv.get('mount'):
                        out.append({'target': sv['mount'], 'kind': 'subvol', 'fstype': p['fs'], 'source': '/dev/' + p['dev'],
                                    'options': ['subvol=' + sv['name'], *p['options']], 'tier': d['tier']})
            elif p.get('mount') and not p.get('member'):
                out.append({'target': p['mount'], 'kind': 'block', 'fstype': p['fs'], 'source': '/dev/' + p['dev'],
                            'options': p['options'], 'tier': d['tier']})
    for pool in node['pools']:
        if pool.get('mount'):
            out.append({'target': pool['mount'], 'kind': 'zfs' if pool['type'] == 'zfs' else 'md', 'fstype': pool.get('fs') or 'zfs',
                        'source': pool['name'] if pool['type'] == 'zfs' else '/dev/' + pool['name'], 'options': [], 'tier': pool['tier']})
        for ds in pool['datasets']:
            if ds.get('mount') and pool['type'] == 'lvm':
                out.append({'target': ds['mount'], 'kind': 'block', 'fstype': ds['props'].get('fs'), 'source': '/dev/' + ds['name'],
                            'options': [], 'tier': pool['tier']})
            elif ds.get('mount'):
                out.append({'target': ds['mount'], 'kind': 'zfs', 'fstype': 'zfs', 'source': ds['name'], 'options': [], 'tier': pool['tier']})
    for r in bp.get('remotes') or []:
        if r.get('mount'):
            out.append({'target': r['mount'], 'kind': 'remote', 'fstype': r.get('protocol'), 'source': r.get('endpoint'),
                        'options': r.get('options') or [], 'tier': 'remote'})
    for l in bp.get('links') or []:
        if l['kind'] == 'bind':
            out.append({'target': l['path'], 'kind': 'bind', 'fstype': 'none', 'source': l['target'], 'spec': l['target'],
                        'options': ['bind'], 'tier': None})
    for m in out:
        m.setdefault('spec', None)
        m.update(total=None, used=None)
    return out


# /etc/fstab

def _unoctal(s):
    return re.sub(r'\\([0-7]{3})', lambda m: chr(int(m.group(1), 8)), s)


def parse_fstab(text: str) -> list[dict]:
    out = []
    for line in text.splitlines():
        line = line.split('#', 1)[0].strip()
        parts = line.split()
        if len(parts) < 3:
            continue
        out.append({'spec': _unoctal(parts[0]), 'target': _unoctal(parts[1]), 'fstype': parts[2],
                    'options': parts[3].split(',') if len(parts) > 3 else ['defaults'],
                    'pass': int(parts[5]) if len(parts) > 5 and parts[5].isdigit() else 0})
    return out


def apply_fstab(node: dict, entries: list[dict]):
    node['sources'].append(f'/etc/fstab ({len(entries)} entries)')
    by_target = {m['target']: m for m in node['mounts']}
    for e in entries:
        m = by_target.get(e['target'])
        if m:
            m['spec'], m['options'], m['fstab'] = e['spec'], e['options'], True
            if not m.get('fstype'):
                m['fstype'] = e['fstype']
        elif e['target'] != 'none':
            kind = 'remote' if e['fstype'] in NETWORK_FS or e['fstype'].startswith('fuse.') else \
                   'bind' if 'bind' in e['options'] else 'block'
            node['mounts'].append({'target': e['target'], 'kind': kind, 'fstype': e['fstype'], 'spec': e['spec'],
                                   'source': e['spec'], 'options': e['options'], 'tier': None, 'total': None,
                                   'used': None, 'fstab': True})


# df

def _df_size(tok):
    if tok in ('-', ''):
        return None
    return int(tok) if tok.isdigit() else parse_size(tok)


def parse_df(text: str) -> list[dict]:
    lines = [l for l in text.splitlines() if l.strip()]
    rows, carry = [], None
    for line in lines[1:]:
        parts = line.split()
        if carry is not None:
            parts = [carry] + parts
            carry = None
        if len(parts) == 1:   # df -h wraps long source names onto their own line
            carry = parts[0]
            continue
        if len(parts) < 6:
            continue
        rows.append({'source': parts[0], 'total': _df_size(parts[1]), 'used': _df_size(parts[2]),
                     'avail': _df_size(parts[3]), 'target': ' '.join(parts[5:])})
    return rows


def apply_df(node: dict, rows: list[dict]):
    node['sources'].append(f'df ({len(rows)} filesystems)')
    by_target = {m['target']: m for m in node['mounts']}
    for r in rows:
        m = by_target.get(r['target'])
        if m:
            m['total'], m['used'], m['avail'] = r['total'], r['used'], r['avail']
            m['source'] = m.get('source') or r['source']
        elif r['source'] not in ('tmpfs', 'devtmpfs', 'udev', 'overlay', 'none', 'efivarfs'):
            node['mounts'].append({'target': r['target'], 'kind': 'block', 'fstype': None, 'spec': None,
                                   'source': r['source'], 'options': [], 'tier': None,
                                   'total': r['total'], 'used': r['used'], 'avail': r['avail']})


# zpool status

VDEV_RE = re.compile(r'^(mirror|raidz[123]?|draid[123]?\S*)-\d+$')


def parse_zpool_status(text: str) -> list[dict]:
    pools, cur, section, vdev, vdev_indent, key = [], None, None, None, 0, None
    for raw in text.expandtabs(8).splitlines():
        line = raw.rstrip()
        m = re.match(r'^\s*(pool|state|scan|status|action|errors):\s*(.*)$', line)
        if m and m.group(1) == 'pool':
            cur = {'name': m.group(2).strip(), 'state': None, 'scan': None, 'status': None, 'errors': None,
                   'vdevs': [], 'log': [], 'cache': [], 'spares': [], 'special': [], 'device_errors': []}
            pools.append(cur)
            section, vdev, key = None, None, None
            continue
        if cur is None:
            continue
        if m:
            key = m.group(1)
            cur[key] = m.group(2).strip()
            continue
        if re.match(r'^\s*config:\s*$', line):
            key, section = None, 'pre'
            continue
        if key in ('scan', 'status', 'action') and line.startswith(' ' * 4) and section is None:
            cur[key] = f'{cur[key]} {line.strip()}'.strip()
            continue
        if section is None:
            continue
        tokens = line.split()
        if not tokens or tokens[0] == 'NAME':
            continue
        indent = len(line) - len(line.lstrip())
        name = tokens[0]
        if name == cur['name']:
            section = 'data'
            continue
        if name in ('logs', 'cache', 'spares', 'special', 'dedup'):
            section, vdev = {'logs': 'log', 'dedup': 'special'}.get(name, name), None
            continue
        if section == 'data' and VDEV_RE.match(name):
            vdev = {'type': VDEV_RE.match(name).group(1), 'members': [], 'state': tokens[1] if len(tokens) > 1 else None}
            vdev_indent = indent
            cur['vdevs'].append(vdev)
            continue
        if len(tokens) >= 5 and all(t.isdigit() for t in tokens[2:5]):
            r, w, c = (int(t) for t in tokens[2:5])
            if r or w or c:
                cur['device_errors'].append({'device': name, 'read': r, 'write': w, 'cksum': c})
        if section == 'data':
            if vdev is not None and indent > vdev_indent:
                vdev['members'].append(name)
            else:
                vdev = None
                cur['vdevs'].append({'type': 'disk', 'members': [name], 'state': tokens[1] if len(tokens) > 1 else None})
        elif section in ('log', 'cache', 'spares', 'special') and not VDEV_RE.match(name):
            cur[section].append(name)
    for p in pools:
        types = {v['type'] for v in p['vdevs']}
        p['level'] = types.pop() if len(types) == 1 else ('+'.join(sorted(types)) if types else None)
        if p['level'] == 'disk':
            p['level'] = 'stripe'
        p['width'] = len(p['vdevs'][0]['members']) if p['vdevs'] else None
    return pools


def apply_zpool_status(node: dict, statuses: list[dict]):
    node['sources'].append(f'zpool status ({len(statuses)} pool{"s" if len(statuses) != 1 else ""})')
    for st in statuses:
        pool = next((p for p in node['pools'] if p['name'] == st['name']), None)
        if pool is None:
            pool = {'name': st['name'], 'type': 'zfs', 'level': st['level'], 'members': [m for v in st['vdevs'] for m in v['members']],
                    'log': st['log'], 'cache': st['cache'], 'spares': st['spares'], 'mount': None, 'fs': None,
                    'encryption': None, 'tier': 'mass', 'datasets': [], 'cap': None}
            node['pools'].append(pool)
        pool.update(health=st['state'], scan=st['scan'], status_note=st['status'], errors=st['errors'],
                    device_errors=st['device_errors'], vdev_count=len(st['vdevs']), width=st['width'],
                    status_devices={'data': [m for v in st['vdevs'] for m in v['members']], 'log': st['log'],
                                    'cache': st['cache'], 'spares': st['spares']})
        if st['level'] and not pool.get('level'):
            pool['level'] = st['level']


# lsblk -J -b

def _b(v):
    return v in (True, 1, '1', 'true')


def _i(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


VIRTUAL_BLOCK = ('zram', 'loop', 'ram', 'fd', 'sr', 'nbd', 'dm-')
BUS = {'nvme': 'NVMe', 'sata': 'SATA', 'sas': 'SAS', 'iscsi': 'iSCSI LUN', 'usb': 'USB', 'ata': 'PATA', 'fc': 'Fibre Channel'}


def node_from_lsblk(data: dict, hostname: str, node: dict | None = None) -> dict:
    node = node or node_skeleton(hostname)
    node['sources'].append('lsblk -J')
    md: dict[str, dict] = {}
    lvm: dict[str, dict] = {}
    vgs: dict[str, dict] = {}
    zfs: dict[str, list] = {}
    for d in data.get('blockdevices') or []:
        if d.get('type') != 'disk' or d['name'].startswith(VIRTUAL_BLOCK):
            continue
        tran = (d.get('tran') or '').lower()
        media = 'net' if tran == 'iscsi' else ('ssd' if tran == 'nvme' else ('hdd' if _b(d.get('rota')) else 'ssd'))
        disk = {'dev': d['name'], 'model': (d.get('model') or '').strip() or None, 'serial': d.get('serial'),
                'bus': BUS.get(tran, tran.upper() or None), 'media': media, 'size': _i(d.get('size')),
                'table': {'dos': 'mbr'}.get(d.get('pttype'), d.get('pttype')), 'tier': infer_tier(media),
                'log_sec': _i(d.get('log-sec')), 'phy_sec': _i(d.get('phy-sec')), 'member': None, 'parts': []}
        node['disks'].append(disk)
        children = d.get('children') or []
        if not children and d.get('fstype'):
            children = [dict(d, type='part', start=0)]
        if _lvm_legs(d['name'], children, disk, lvm):
            disk['member'] = next(iter(_lvm_owner(d['name'], lvm)), None)
        elif vg := _lvm_plain(d['name'], _i(d.get('size')), children, disk, vgs):
            disk['member'] = vg
        for c in children:
            if c.get('type') != 'part':
                continue
            part = {'dev': c['name'], 'start': (_i(c.get('start')) or 0) * 512, 'size': _i(c.get('size')),
                    'fs': c.get('fstype'), 'label': c.get('label') or c.get('partlabel'), 'uuid': c.get('uuid'),
                    'mount': c.get('mountpoint'), 'options': [], 'member': None, 'role': None, 'subvols': []}
            if c.get('fstype') == 'zfs_member' and c.get('label'):
                part['member'] = c['label']
                zfs.setdefault(c['label'], []).append((part, disk))
            for g in c.get('children') or []:
                if (g.get('type') or '').startswith('raid'):
                    part['member'] = g['name']
                    entry = md.setdefault(g['name'], {'level': g['type'], 'members': [], 'fs': g.get('fstype'),
                                                      'mount': g.get('mountpoint'), 'label': g.get('label'), 'tier': disk['tier']})
                    entry['members'].append(part)
                elif g.get('type') == 'lvm' and _lvm_legs(c['name'], [g], disk, lvm):
                    part['member'] = next(iter(_lvm_owner(c['name'], lvm)), None)
                elif g.get('type') == 'lvm' and (vg := _lvm_plain(c['name'], _i(c.get('size')), [g], disk, vgs)):
                    part['member'] = part['member'] or vg
                elif g.get('type') == 'crypt':
                    part['crypt'] = g['name']
                    part['encrypted'] = 'LUKS'
                    part['fs'] = g.get('fstype') or part['fs']
                    part['uuid'] = g.get('uuid') or part['uuid']
                    part['mount'] = g.get('mountpoint') or part['mount']
            disk['parts'].append(part)
    by_uuid: dict[str, list] = {}
    for d in node['disks']:
        for p in d['parts']:
            if p.get('fs') == 'btrfs' and p.get('uuid') and not p.get('member'):
                by_uuid.setdefault(p['uuid'], []).append((p, d))
    for uuid, members in by_uuid.items():
        if len(members) < 2:
            continue
        name = members[0][0].get('label') or f'btrfs-{uuid[:8]}'
        for p, _ in members:
            p['member'], p['role'] = name, 'data'
        node['pools'].append({'name': name, 'type': 'btrfs', 'level': 'multi-device', 'members': [p['dev'] for p, _ in members],
                              'member_sizes': [p['size'] for p, _ in members], 'log': [], 'cache': [], 'spares': [],
                              'mount': members[0][0].get('mount'), 'fs': 'btrfs', 'encryption': None,
                              'tier': members[0][1]['tier'], 'datasets': [], 'cap': None, 'health': None, 'uuid': uuid})
    for name, e in md.items():
        node['pools'].append({'name': name, 'type': 'mdadm', 'level': e['level'], 'members': [p['dev'] for p in e['members']],
                              'log': [], 'cache': [], 'spares': [], 'mount': e['mount'], 'fs': e['fs'], 'encryption': None,
                              'tier': e['tier'], 'datasets': [], 'health': None,
                              'cap': pool_capacity('md', e['level'], [p['size'] for p in e['members']], fs=e['fs'])})
    for name, e in lvm.items():
        node['pools'].append(_lvm_pool(name, e))
    for name, e in vgs.items():
        node['pools'].append(_vg_pool(name, e))
    for name, members in zfs.items():
        node['pools'].append({'name': name, 'type': 'zfs', 'level': None, 'members': [p['dev'] for p, _ in members],
                              'member_parts': members, 'log': [], 'cache': [], 'spares': [], 'mount': None, 'fs': None,
                              'encryption': None, 'tier': members[0][1]['tier'], 'datasets': [], 'cap': None, 'health': None})
    return node


# LVM RAID: lsblk shows each leg as <vg>-<lv>_rimage_N (with a small _rmeta_N) on its own PV, and the LV under them.
# lvs gives the exact segment type when the scan user may run it; otherwise the level follows from the leg count and
# how many legs' worth of space the LV has (3 legs holding 2 legs of data is raid5).
LVM_LEG = re.compile(r'(.+)_(r|m)(image|meta|log)_(\d+)')


def _dm_split(name: str) -> tuple[str, str]:
    """Device-mapper names double hyphens inside VG and LV names: 'my--vg-data' is VG 'my-vg', LV 'data'."""
    parts = re.split(r'(?<!-)-(?!-)', name, maxsplit=1)
    return (parts[0].replace('--', '-'), parts[1].replace('--', '-')) if len(parts) == 2 else ('', name)


def _lvm_legs(pv: str, children: list, disk: dict, lvm: dict) -> bool:
    found = False
    for g in children:
        m = LVM_LEG.fullmatch(g.get('name') or '') if g.get('type') == 'lvm' else None
        if not m:
            continue
        found = True
        lv = next((x for x in g.get('children') or [] if x.get('name') == m.group(1)), {})
        e = lvm.setdefault(m.group(1), {'legs': {}, 'size': None, 'fs': None, 'mount': None, 'uuid': None, 'label': None,
                                        'tier': disk['tier']})
        e.update({k: v for k, v in {'size': _i(lv.get('size')), 'fs': lv.get('fstype'), 'mount': lv.get('mountpoint'),
                                    'uuid': lv.get('uuid'), 'label': lv.get('label')}.items() if v})
        if m.group(3) == 'image':
            e['legs'][int(m.group(4))] = (pv, _i(g.get('size')))
    return found


LVM_INTERNAL = re.compile(r'.+(_t(meta|data)|_[rm](image|meta|log)_\d+|_c(data|meta)|_vorigin|-(tpool|real|cow))$')


def _lvm_plain(pv: str, pv_size, children: list, disk: dict, vgs: dict) -> str | None:
    """Ordinary (linear or thin) LVs on a PV, grouped by volume group. Returns the VG name if any were found."""
    found = None

    def walk(items):
        nonlocal found
        for g in items:
            if g.get('type') != 'lvm':
                continue
            name = g.get('name') or ''
            if LVM_INTERNAL.fullmatch(name):          # thin-pool plumbing: the thin LVs sit further down
                walk(g.get('children') or [])
                continue
            vg, lv = _dm_split(name)
            if not vg:
                continue
            e = vgs.setdefault(vg, {'pvs': {}, 'lvs': {}, 'tier': disk['tier']})
            e['pvs'][pv] = pv_size
            mount = g.get('mountpoint')
            e['lvs'].setdefault(lv, {'dm': name, 'size': _i(g.get('size')), 'fs': g.get('fstype'), 'uuid': g.get('uuid'),
                                     'mount': mount if mount and mount.startswith('/') else None})
            found = found or vg
    walk(children)
    return found


def _vg_pool(vg: str, e: dict) -> dict:
    lvs = sorted(e['lvs'].items(), key=lambda kv: (kv[1]['mount'] is None, kv[1]['mount'] or kv[0]))
    return {'name': vg, 'type': 'lvm', 'level': 'linear', 'vg': vg, 'lv': None, 'level_source': 'volume group',
            'aliases': [a for lv, x in lvs for a in (f'mapper/{x["dm"]}', f'{vg}/{lv}')],
            'members': list(e['pvs']), 'member_sizes': list(e['pvs'].values()), 'log': [], 'cache': [], 'spares': [],
            'mount': None, 'fs': None, 'encryption': None, 'tier': e['tier'], 'health': None,
            'datasets': [{'name': f'{vg}/{lv}', 'mount': x['mount'], 'dev': f'mapper/{x["dm"]}',
                          'props': {k: v for k, v in (('fs', x['fs']), ('sizeBytes', x['size'])) if v}} for lv, x in lvs],
            'cap': pool_capacity('lvm', 'linear', list(e['pvs'].values()))}


def _lvm_owner(pv: str, lvm: dict):
    return (name for name, e in lvm.items() if any(p == pv for p, _ in e['legs'].values()))


def lvm_level(legs: int, leg_size, lv_size) -> tuple[str, str]:
    if legs < 2 or not leg_size or not lv_size:
        return 'raid1' if legs >= 2 else 'linear', 'guessed'
    k, n = round(lv_size / leg_size), legs
    if k == n:
        return 'raid0', f'inferred: {n} legs, {k} of data'
    if k == 1:
        return 'raid1', f'inferred: {n}-way mirror'
    if n == 4 and k == 2:
        return 'raid10', 'inferred: 4 legs, 2 of data (raid10 or raid6; lvs as root tells them apart)'
    if k == n - 1:
        return 'raid5', f'inferred: {n} legs, {k} of data'
    if k == n - 2:
        return 'raid6', f'inferred: {n} legs, {k} of data'
    if n % 2 == 0 and k == n // 2:
        return 'raid10', f'inferred: {n} legs, {k} of data'
    return 'raid', f'unrecognised: {n} legs, {k} of data'


def _lvm_pool(name: str, e: dict) -> dict:
    vg, lv = _dm_split(name)
    legs = [e['legs'][i] for i in sorted(e['legs'])]
    level, how = lvm_level(len(legs), min((s for _, s in legs if s), default=None), e['size'])
    return {'name': name, 'type': 'lvm', 'level': level, 'level_source': how, 'vg': vg, 'lv': lv,
            'aliases': [f'mapper/{name}', f'{vg}/{lv}'], 'members': [p for p, _ in legs],
            'member_sizes': [s for _, s in legs], 'log': [], 'cache': [], 'spares': [], 'mount': e['mount'],
            'fs': e['fs'], 'label': e['label'], 'encryption': None, 'tier': e['tier'], 'datasets': [], 'health': None,
            'cap': pool_capacity('lvm', level, [s for _, s in legs], fs=e['fs'])}


def apply_btrfs(node: dict, text: str):
    """Real btrfs profiles (raid1, raid10, dup, ...) and labels from /sys/fs/btrfs, readable without root."""
    info = {}
    for line in (text or '').splitlines():
        uuid, data, meta, label = (line.split('\t') + ['', '', '', ''])[:4]
        if uuid:
            info[uuid] = {'data': data.split(',')[0] or None, 'meta': meta.split(',')[0] or None, 'label': label or None}
    for p in node['pools']:
        b = info.get(p.get('uuid') or '')
        if p['type'] != 'btrfs' or not b or not b['data']:
            continue
        p.update(level=b['data'], meta_level=b['meta'], label=b['label'] or p.get('label'),
                 level_source='/sys/fs/btrfs')
        p['cap'] = pool_capacity('btrfs', b['data'], p.get('member_sizes') or [])
    for d in node['disks']:                     # single-device btrfs: dup vs single metadata is worth showing
        for part in d['parts']:
            b = info.get(part.get('uuid') or '')
            if b and part.get('fs') == 'btrfs' and not part.get('member'):
                part['btrfs_profile'] = f'{b["data"]}/{b["meta"]}'


def apply_lvs(node: dict, text: str):
    """Exact segment types and health from `lvs --reportformat json`, when the scan could run it."""
    try:
        rows = json.loads(text)['report'][0]['lv']
    except (ValueError, KeyError, IndexError, TypeError):
        return
    node['sources'].append('lvs')
    by = {(r.get('vg_name'), r.get('lv_name')): r for r in rows}
    for p in node['pools']:
        r = by.get((p.get('vg'), p.get('lv'))) if p['type'] == 'lvm' else None
        if not r:
            continue
        seg = (r.get('segtype') or '').lower()
        level = {'mirror': 'raid1', 'striped': 'raid0'}.get(seg, seg.split('_')[0])   # raid6_zr → raid6
        if level and level != p['level']:
            p['level'] = level
            p['cap'] = pool_capacity('lvm', level, p['member_sizes'], fs=p.get('fs'))
        p['level_source'] = f'lvs: {seg}'
        p['health'] = r.get('lv_health_status') or 'ONLINE'
        if r.get('copy_percent') not in (None, '', '100.00'):
            p['scan'] = f'resyncing {r["copy_percent"]}%'


def finalize_zfs_capacity(node: dict):
    """Pools seen via lsblk + zpool status: split members into data/log/cache by matching the status device names."""
    for pool in node['pools']:
        if pool['type'] != 'zfs' or pool.get('cap') or not pool.get('member_parts'):
            continue
        sd = pool.get('status_devices') or {}

        def role(part, disk):
            keys = [part['dev'], disk.get('serial') or '\0']
            for r in ('log', 'cache', 'spares'):
                if any(any(k in dev for k in keys) for dev in sd.get(r, [])):
                    return r
            return 'data'
        data = [(p, d) for p, d in pool['member_parts'] if role(p, d) == 'data']
        for p, d in pool['member_parts']:
            p['role'] = role(p, d)
        pool['members'] = [p['dev'] for p, _ in data]
        pool['log'] = [p['dev'] for p, d in pool['member_parts'] if p['role'] == 'log']
        pool['cache'] = [p['dev'] for p, d in pool['member_parts'] if p['role'] == 'cache']
        if pool.get('level'):
            pool['cap'] = pool_capacity('zfs', pool['level'], [p['size'] for p, _ in data],
                                        width=pool.get('width'))
        pool.pop('member_parts', None)


# NFS exports and SMB shares, so another host's network mount can be traced to the folder it comes from

def parse_nfs_exports(text: str) -> list[dict]:
    """/etc/exports or /var/lib/nfs/etab: a path, then clients with options. One entry per path."""
    out: dict[str, dict] = {}
    for raw in (text or '').replace('\\\n', ' ').splitlines():
        line = raw.split('#', 1)[0].strip()
        if not line.startswith(('/', '"')):
            continue
        if line.startswith('"'):
            path, _, rest = line[1:].partition('"')
        else:
            path, _, rest = line.partition(' ') if ' ' in line else line.partition('\t')
        path = _unoctal(path.strip())
        clients = [c for c in rest.split() if c]
        e = out.setdefault(path, {'protocol': 'NFS', 'name': path, 'path': path, 'clients': [], 'options': ''})
        for c in clients:
            host, _, opts = c.partition('(')
            e['clients'].append(host or '*')
            e['options'] = e['options'] or opts.rstrip(')')
    for e in out.values():
        e['clients'] = ' '.join(dict.fromkeys(e['clients']))
    return list(out.values())


SMB_SKIP = {'global', 'printers', 'print$', 'homes'}


def parse_smb_conf(text: str) -> list[dict]:
    """testparm -s or smb.conf: every [share] with a path, except the global and printer sections."""
    out, cur = [], None
    for raw in (text or '').splitlines():
        line = raw.strip()
        if not line or line[0] in '#;':
            continue
        if line.startswith('[') and line.endswith(']'):
            name = line[1:-1].strip()
            cur = None if name.lower() in SMB_SKIP else {'protocol': 'SMB', 'name': name, 'path': None, 'clients': '', 'options': ''}
            if cur:
                out.append(cur)
            continue
        if cur and '=' in line:
            k, _, v = (x.strip() for x in line.partition('='))
            k = k.lower()
            if k == 'path':
                cur['path'] = v.rstrip('/') or '/'
            elif k in ('valid users', 'hosts allow'):
                cur['clients'] = (cur['clients'] + ' ' + v).strip()
            elif k in ('read only', 'writable', 'writeable') and v.lower() in ('yes', 'no', 'true', 'false'):
                ro = (v.lower() in ('yes', 'true')) == (k == 'read only')
                cur['options'] = 'ro' if ro else 'rw'
    return [s for s in out if s['path']]


def share_key(e: dict) -> tuple:
    """What identifies a share whatever the scan or the design calls it: the path for NFS ('NFS' and 'NFSv4.2' alike),
    the share name for SMB."""
    p = str(e.get('protocol') or e.get('proto') or '').upper()
    if p.startswith(('SMB', 'CIFS')):
        return ('SMB', str(e.get('name') or '').lower())
    if p.startswith('NFS'):
        return ('NFS', str(e.get('path') or '').rstrip('/') or '/')
    return (p, e.get('path'), e.get('name'))


def is_designed(e: dict) -> bool:
    return bool(e.get('designed')) or not e.get('fromScan')


def merge_shares(scanned: list[dict], saved: list[dict]) -> list[dict]:
    """The shares a scan found plus the design's. A designed share the scan also found is one shares.py deployed (or
    one the operator described): it keeps the design's settings and client mounts, marked deployed. It stays designed,
    because the deploy script rewrites its own config from the design and would otherwise drop it."""
    designed = {share_key(e): e for e in saved or [] if is_designed(e)}
    out = []
    for e in scanned:
        d = designed.pop(share_key(e), None)
        out.append({**d, 'fromScan': True, 'designed': True} if d else e)
    return out + [{**d, 'fromScan': False, 'designed': True} for d in designed.values()]


def shares_from_inventory(inv: dict) -> list[dict]:
    return [dict(s, fromScan=True) for s in parse_nfs_exports(inv.get('nfs') or '') + parse_smb_conf(inv.get('smb') or '')]


# hosts already in the index

def node_from_index(conn: Conn, host: str, symlink_limit: int = 20000, stats: bool = True) -> dict:
    """stats adds the per-mount, largest-file and duplicate totals only reports show. They read every file row of the
    host, so callers that want the layout (designs, the graph) leave them out."""
    rows = conn.all("""SELECT host_id, hostname, ip_address, os_info, last_scanned_at, inventory_json FROM hosts
                       WHERE hostname = :x OR ip_address = :x OR ssh_host = :x""", {'x': host})
    if not rows:
        raise SystemExit(f'{host} is not in the index. Run: storageforge-index scan --host {host}')
    host_id, hostname, ip, os_info, last, inv = rows[0]
    inv = json.loads(inv) if isinstance(inv, str) else (inv or {})
    node = node_from_lsblk(inv['lsblk'], hostname) if inv.get('lsblk') else node_skeleton(hostname)
    node['sources'].insert(0, f'StorageForge index (host_id {host_id})')
    node.update(ip=ip, os=os_info, last_scanned=epoch(last))
    if inv.get('zpool_status'):
        apply_zpool_status(node, parse_zpool_status(inv['zpool_status']))
        finalize_zfs_capacity(node)
    if inv.get('lvs'):
        apply_lvs(node, inv['lvs'])
    if inv.get('btrfs'):
        apply_btrfs(node, inv['btrfs'])
    node['snapshots_seen'] = inv.get('snapshots') or {}
    node['health_report'] = inv.get('health')

    parts = {p['dev']: (p, d) for d in node['disks'] for p in d['parts']}
    disks = {d['dev']: d for d in node['disks']}
    mrows = conn.all("""SELECT m.mount_id, m.mount_point, m.source, m.filesystem_type, m.mount_options, m.total_bytes,
                               m.used_bytes, m.scan_state, m.skip_reason, b.mount_point, m.fs_root, b.fs_root,
                               m.dev_majmin, m.last_scan_id
                        FROM mounts m LEFT JOIN mounts b ON b.mount_id = m.bind_of_mount_id
                        WHERE m.host_id = :h AND m.scan_state <> 'gone' ORDER BY m.mount_point""", {'h': host_id})
    mount_ids = {}
    crypt = {p['crypt']: dev for dev, (p, _) in parts.items() if p.get('crypt')}
    for mid, mp, src, fs, opts, tot, used, state, why, bind_of, root, bind_root, majmin, last_scan in mrows:
        scanned = last_scan is not None
        if not scanned and (fs in PSEUDO_FS or fs in TMP_FS or fs.startswith('cgroup')
                            or mp.startswith(('/proc', '/sys', '/dev', '/run'))):
            continue
        dev = (src or '').removeprefix('/dev/').split('[')[0]
        dev = crypt.get(dev.removeprefix('mapper/'), dev)
        tier = None
        if dev in parts:
            tier = parts[dev][1]['tier']
            parts[dev][0]['mount'] = parts[dev][0]['mount'] or mp
        elif dev in disks:
            tier = disks[dev]['tier']
        pool = next((p for p in node['pools'] if dev == p['name'] or (src or '').split('/')[0] == p['name']
                     or dev in p['members'] or dev in p.get('aliases', ())), None)
        if pool:
            tier = pool['tier']
            lv = next((ds for ds in pool['datasets'] if dev in (ds.get('dev'), ds['name'])), None) if pool['type'] == 'lvm' else None
            if lv:
                lv['mount'] = lv['mount'] or mp
            elif fs == 'zfs' and '/' in (src or ''):
                if not any(ds['name'] == src for ds in pool['datasets']):
                    pool['datasets'].append({'name': src, 'mount': mp, 'props': {}})
            elif not pool.get('mount'):
                pool['mount'] = mp
            if pool['type'] == 'btrfs' and pool.get('cap') is None and tot:
                raw = float(sum(pool['member_sizes']))
                pool['cap'] = {'raw': raw, 'usable': float(tot), 'parity': max(0.0, raw - tot), 'overhead': 0.0,
                               'fs_reserve': 0.0, 'waste': 0.0, 'unused': 0.0, 'tolerance': None,
                               'layout': f'btrfs multi-device · {len(pool["members"])} devices (size from statfs)'}
        net = fs in NETWORK_FS
        kind = 'bind' if state == 'bind-alias' else 'remote' if net else 'zfs' if fs == 'zfs' else 'block'
        spec = src
        if dev in parts and parts[dev][0].get('uuid'):
            spec = 'UUID=' + parts[dev][0]['uuid']
        bind_src = None
        if kind == 'bind' and bind_of:
            rel = (root or '/')[len(bind_root or '/'):] if is_under(root or '/', bind_root or '/') else ''
            bind_src = (bind_of.rstrip('/') + '/' + rel.lstrip('/')).rstrip('/') or '/'
        m = {'target': mp, 'kind': kind, 'fstype': fs, 'spec': bind_src or spec, 'source': bind_src or src,
             'options': (opts or '').split(','), 'tier': 'remote' if net else tier, 'total': tot, 'used': used,
             'scan_state': state, 'skip_reason': why, 'majmin': majmin, 'scanned': scanned}
        node['mounts'].append(m)
        mount_ids[mp] = (mid, scanned)
        if net:
            node['remotes'].append({'name': src, 'proto': fs, 'endpoint': src, 'via': 'network', 'mount': mp, 'status': 'connected'})
        if kind == 'bind':
            node['links'].append({'kind': 'bind', 'path': mp, 'target': bind_src or '?', 'from_index': True, 'exists': True})

    node['exports'] = shares_from_inventory(inv)
    _index_links(conn, node, host_id, mount_ids, symlink_limit)
    if stats:
        node['index'] = _index_stats(conn, host_id)
    return node


# Links the OS manages: package alternatives, systemd enablement, usr-merge, zoneinfo, CA bundles. They say nothing about
# storage layout, and a Debian or Raspberry Pi OS install has hundreds, so they are counted but never listed.
SYSTEM_LINK_DIRS = ('/etc/alternatives', '/etc/systemd', '/etc/rc0.d', '/etc/rc1.d', '/etc/rc2.d', '/etc/rc3.d',
                    '/etc/rc4.d', '/etc/rc5.d', '/etc/rc6.d', '/etc/rcS.d', '/etc/init.d', '/etc/ssl', '/etc/ca-certificates',
                    '/etc/fonts', '/etc/X11', '/etc/xdg', '/etc/dbus-1', '/etc/udev', '/etc/pam.d', '/etc/profile.d',
                    '/usr', '/bin', '/sbin', '/lib', '/lib32', '/lib64', '/libx32', '/var/lib/dpkg', '/var/lib/systemd',
                    '/var/lib/dkms', '/var/lib/flatpak', '/var/lib/snapd', '/var/lib/pacman',
                    '/opt/vc', '/boot')
SYSTEM_LINK_FILES = ('/etc/localtime', '/etc/mtab', '/etc/os-release', '/etc/resolv.conf', '/etc/vconsole.conf',
                     '/etc/machine-id', '/etc/initramfs-tools/initramfs.conf')
MAX_HOPS = 40          # the kernel's ELOOP limit
LOCK_TARGET = re.compile(r'[^/]*:\+\d+')   # Firefox/Thunderbird profile locks: always dangling by design


def is_system_link(path: str) -> bool:
    return path in SYSTEM_LINK_FILES or any(is_under(path, d) for d in SYSTEM_LINK_DIRS)


def canonical(path: str, links: dict) -> tuple[str, bool]:
    """Resolve every component of path through the indexed symlinks, like realpath: /lib/x with /lib → usr/lib
    becomes /usr/lib/x. Returns (path, looped)."""
    parts = [p for p in path.split('/') if p]
    done, hops = '/', 0
    while parts:
        name = parts.pop(0)
        if name == '.':
            continue
        if name == '..':
            done = posixpath.dirname(done) or '/'
            continue
        cur = join_path(done, name)
        if cur in links:
            hops += 1
            if hops > MAX_HOPS:
                return cur, True
            target = links[cur][0]
            parts = [p for p in target.split('/') if p] + parts
            if target.startswith('/'):
                done = '/'
            continue
        done = cur
    return done, False


def _index_links(conn, node, host_id, mount_ids, limit):
    """Symlinks worth a report line: broken ones, loops, and ones that cross a mount boundary. Targets resolve through
    symlinked parents (usr-merge), and links the OS manages are left out."""
    rows = conn.all("""SELECT d.path, f.filename, f.symlink_target, m.mount_point FROM file_records f
                       JOIN directories d ON d.dir_id = f.dir_id JOIN mounts m ON m.mount_id = f.mount_id
                       WHERE m.host_id = :h AND f.is_symlink LIMIT :lim""", {'h': host_id, 'lim': limit})
    from .analysis import containing_mount, real_mounts
    mounts = real_mounts(node)
    links = {join_path(p, n): (t, mp) for p, n, t, mp in rows}
    picked, system = [], 0
    for path, (target, mp) in links.items():
        if is_system_link(path) or LOCK_TARGET.fullmatch(target):
            system += 1
            continue
        start = target if target.startswith('/') else posixpath.join(posixpath.dirname(path), target)
        resolved, looped = canonical(start, links)
        tm = containing_mount(resolved, mounts)
        exists = None
        if looped:
            exists = False
        elif any(is_under(resolved, x) for x in DEFAULT_EXCLUDE_PATHS):
            exists = None                       # /proc, /sys, /dev, /run are never walked
        elif resolved == '/':
            exists = True
        elif tm and mount_ids.get(tm['target'], (None, False))[1]:
            parent, name = split_path(resolved)
            exists = bool(conn.scalar('SELECT count(*) FROM file_records f JOIN directories d ON d.dir_id = f.dir_id '
                                      'WHERE d.mount_id = :m AND d.path = :p AND f.filename = :n',
                                      {'m': mount_ids[tm['target']][0], 'p': parent, 'n': name}))
        cross = bool(tm and tm['target'] != mp)
        if exists is False or cross:
            picked.append({'kind': 'symlink', 'path': path, 'target': target, 'resolved': resolved, 'exists': exists,
                           'from_index': True, 'cross_mount': cross, **({'note': 'ELOOP'} if looped else {})})
    node['index_symlinks'] = {'checked': len(links), 'reported': len(picked), 'system': system,
                              'capped': len(rows) >= limit}
    picked.sort(key=lambda l: (l['exists'] is not False, l['path']))
    node['links'].extend(picked[:200])


def _index_stats(conn, host_id) -> dict:
    p = {'h': host_id}
    by_mount = conn.all("""SELECT m.mount_point, m.filesystem_type, m.scan_state, count(f.file_id),
                                  sum(CASE WHEN f.is_directory THEN 1 ELSE 0 END),
                                  sum(CASE WHEN f.is_symlink THEN 1 ELSE 0 END), coalesce(sum(f.file_size_bytes), 0)
                           FROM mounts m LEFT JOIN file_records f ON f.mount_id = m.mount_id
                           WHERE m.host_id = :h AND m.last_scan_id IS NOT NULL
                           GROUP BY m.mount_point, m.filesystem_type, m.scan_state ORDER BY m.mount_point""", p)
    top_ext = conn.all("""SELECT f.extension, count(*), sum(f.file_size_bytes) FROM file_records f
                          JOIN mounts m ON m.mount_id = f.mount_id
                          WHERE m.host_id = :h AND NOT f.is_directory AND f.extension <> ''
                          GROUP BY f.extension ORDER BY 3 DESC LIMIT 10""", p)
    largest = conn.all("""SELECT d.path, f.filename, f.file_size_bytes, f.modified_at FROM file_records f
                          JOIN directories d ON d.dir_id = f.dir_id JOIN mounts m ON m.mount_id = f.mount_id
                          WHERE m.host_id = :h AND NOT f.is_directory
                          ORDER BY f.file_size_bytes DESC LIMIT 10""", p)
    dup = conn.all("""SELECT count(*), coalesce(sum(reclaim), 0) FROM (
                          SELECT (count(*) - 1) * max(f.file_size_bytes) AS reclaim FROM file_records f
                          JOIN mounts m ON m.mount_id = f.mount_id
                          WHERE m.host_id = :h AND f.checksum_hash IS NOT NULL
                          GROUP BY f.checksum_hash HAVING count(*) > 1) g""", p)
    scan = conn.all("""SELECT scan_id, status, entries_seen, added, modified, deleted, read_errors, duration_ms, started_at
                       FROM scans WHERE host_id = :h AND status <> 'running' ORDER BY scan_id DESC LIMIT 1""", p)
    return {
        'by_mount': [{'mount': r[0], 'fstype': r[1], 'entries': r[3], 'dirs': r[4] or 0, 'symlinks': r[5] or 0,
                      'bytes': r[6]} for r in by_mount],
        'top_ext': [{'ext': r[0], 'files': r[1], 'bytes': r[2]} for r in top_ext],
        'largest': [{'path': join_path(r[0], r[1]), 'bytes': r[2], 'mtime': epoch(r[3])} for r in largest],
        'dup_groups': dup[0][0] if dup else 0, 'dup_reclaimable': dup[0][1] if dup else 0,
        'last_scan': dict(zip(('scan_id', 'status', 'entries', 'added', 'modified', 'deleted', 'read_errors',
                               'duration_ms', 'started_at'), scan[0])) if scan else None,
    }


def merge_blueprint(node: dict, bp_node: dict):
    """Overlay design intent (tiers, remotes, protection, links) on a scanned host and record drift."""
    node['sources'].append(bp_node['sources'][0])
    bp_disks = {d['dev']: d for d in bp_node['disks']}
    for d in node['disks']:
        b = bp_disks.get(d['dev'])
        if b:
            d['tier'] = b.get('tier') or d['tier']
            d['bus'] = b.get('bus') or d['bus']
    have = {m['target'] for m in node['mounts']}
    for m in bp_node['mounts']:
        if m['target'].startswith('/') and m['target'] not in have:
            node['drift'].append({'title': f'Blueprint mount {m["target"]} is not mounted',
                                  'detail': f'The design expects {m.get("fstype") or m.get("kind")} from {m.get("source") or m.get("spec")} here.'})
    remotes = {r.get('mount'): r for r in node['remotes']}
    for r in bp_node['remotes']:
        if r.get('mount') in remotes:
            remotes[r['mount']].update({k: v for k, v in r.items() if v})
        else:
            node['remotes'].append(r)
    paths = {l['path'] for l in node['links']}
    node['links'].extend(l for l in bp_node['links'] if l['path'] not in paths)
    node['protection'] = bp_node['protection'] or node['protection']
    node['exports'] = merge_shares(node['exports'], bp_node['exports'])
    for bp_pool in bp_node['pools']:
        pool = next((p for p in node['pools'] if p['name'] == bp_pool['name']), None)
        if pool:
            pool['encryption'] = pool.get('encryption') or bp_pool.get('encryption')
            pool['tier'] = bp_pool.get('tier') or pool.get('tier')
