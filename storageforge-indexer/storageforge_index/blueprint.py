"""Planner bridge: turn a scanned host into a storageforge/v1 blueprint, and carry design intent across rescans.

The planner UI edits blueprints; graph.store_blueprint keeps them and graph.rebuild_host overlays them on scans.
A scan knows hardware, mounts and links. It cannot know sync, snapshot or backup policy, exports or tiers the
operator chose, so those come from the saved design when there is one and start as "None" rows otherwise.
"""
from __future__ import annotations

import datetime as dt
import re

from .payloads import node_from_index

MIB = 1 << 20
REMOTE_PROTO = {'nfs': 'NFSv3', 'nfs4': 'NFSv4.2', 'cifs': 'SMB3', 'smb3': 'SMB3', 'smbfs': 'SMB3', 'sshfs': 'SFTP',
                'fuse.sshfs': 'SFTP', 'fuse.rclone': 'S3 (rclone)', 'rclone': 'S3 (rclone)', 'fuse.s3fs': 'S3 (s3fs)'}
ZFS_LEVELS = ('stripe', 'mirror', 'raidz1', 'raidz2', 'raidz3')
MD_LEVELS = ('raid0', 'raid1', 'raid5', 'raid6', 'raid10', 'linear')
SKIP_PROTECT = ('/boot', '/boot/efi', '/efi')
EPHEMERAL = ('/tmp', '/var/tmp', '/var/cache')   # start excluded from 3-2-1; the operator can change it


def _subvol(source: str | None) -> str | None:
    m = re.search(r'\[/?([^\]]*)\]$', source or '')
    return m.group(1) if m and m.group(1) else None


def _level(pool: dict) -> str:
    lvl = (pool.get('level') or '').split('+')[0]
    if pool['type'] == 'zfs':
        return lvl if lvl in ZFS_LEVELS else 'stripe'
    if pool['type'] == 'mdadm':
        return lvl if lvl in MD_LEVELS else 'linear'
    return lvl if lvl in ('single', 'raid1', 'raid1c3', 'raid10') else 'single'


def from_node(node: dict, as_of: dt.date | None = None) -> dict:
    mounts = [m for m in node['mounts'] if m.get('target', '').startswith('/')]
    crypt = {p['crypt']: p['dev'] for d in node['disks'] for p in d['parts'] if p.get('crypt')}
    by_source: dict[str, list] = {}
    for m in mounts:
        dev = (m.get('source') or '').split('[')[0].removeprefix('/dev/')
        dev = crypt.get(dev.removeprefix('mapper/'), dev)        # LUKS: the mapper name belongs to its partition
        by_source.setdefault(dev, []).append(m)

    devices, protection = [], []

    def protect(node_id, name, path, enc=None):
        if path and path not in SKIP_PROTECT and path not in {r['path'] for r in protection}:
            protection.append({'node': node_id, 'dataset': name, 'path': path, 'ephemeral': path in EPHEMERAL,
                               'sync': {'state': 'None'},
                               'snapshots': {'enabled': False, 'tool': 'none', 'policy': '', 'count': 0, 'overhead': 0},
                               'backup': {'target': None, 'enc': enc or 'none', 'ratio': 1, 'last': None, 'offsite': False}})

    for d in node['disks']:
        parts = []
        for i, p in enumerate(d['parts'], 1):
            ms = by_source.get(p['dev'], [])
            subvols = [{'name': _subvol(m['source']), 'mount': m['target']} for m in ms
                       if p.get('fs') == 'btrfs' and _subvol(m['source'])]
            primary = None if subvols else (p.get('mount') or (ms[0]['target'] if ms else None))
            opts = next((m['options'] for m in ms if m['target'] == primary), None) or (ms[0]['options'] if ms else [])
            opts = [o for o in opts if o and not o.startswith(('subvol=', 'subvolid=', 'rw', 'relatime', 'seclabel'))]
            num = re.search(r'(\d+)$', p['dev'])
            parts.append({'id': p['dev'], 'uuid': p.get('uuid'), 'num': int(num.group(1)) if num and p['dev'] != d['dev'] else i,
                          'startBytes': p.get('start') or 0, 'sizeBytes': p.get('size') or 0,
                          'fs': 'swap' if p.get('fs') == 'swap' else (p.get('fs') or 'none'), 'label': p.get('label'),
                          'mount': primary, 'options': opts, 'member': p.get('member'), 'role': p.get('role'),
                          'subvolumes': subvols, 'encrypted': p.get('encrypted')})
            for sv in subvols:
                protect(f'sv:{p["dev"]}/{sv["name"]}', sv['name'], sv['mount'], p.get('encrypted'))
            if primary and not p.get('member') and p.get('fs') not in (None, 'swap', 'vfat'):
                protect(f'part:{p["dev"]}', p.get('label') or p['dev'], primary, p.get('encrypted'))
        devices.append({'dev': '/dev/' + d['dev'], 'model': d.get('model'), 'serial': d.get('serial'), 'bus': d.get('bus'),
                        'media': d.get('media'), 'tier': d.get('tier'), 'sizeBytes': d.get('size') or 0,
                        'sector': {'logical': d.get('log_sec') or 512, 'physical': d.get('phy_sec') or 4096},
                        'table': d.get('table') or 'gpt', 'member': d.get('member'), 'partitions': parts})

    pools = []
    for p in node['pools']:
        datasets = []
        for ds in p.get('datasets') or []:
            name = ds['name'].split('/', 1)[1] if '/' in ds['name'] else ds['name']
            datasets.append({'name': name, 'mount': ds.get('mount'), **(ds.get('props') or {})})
            protect(f'ds:{p["name"]}/{name}', ds['name'], ds.get('mount'))
        ptype = p['type'] if p['type'] in ('zfs', 'mdadm', 'btrfs') else 'mdadm'
        # a multi-device btrfs mounted by subvolume: the subvolumes (on its first member) are the mounts
        has_subvols = ptype == 'btrfs' and any(x['subvolumes'] for d in devices for x in d['partitions']
                                                 if x['id'] in (p.get('members') or []))
        mount = None if has_subvols else p.get('mount')
        pools.append({'name': p['name'], 'type': ptype, 'level': _level(p), 'tier': p.get('tier'),
                      'ashift': p.get('ashift') or 12, 'fs': p.get('fs'), 'mount': mount,
                      'encryption': p.get('encryption'), 'members': p.get('members') or [],
                      'log': p.get('log') or [], 'cache': p.get('cache') or [], 'datasets': datasets})
        if ptype != 'zfs':
            protect(f'pool:{p["name"]}', p['name'], mount)

    remotes = []
    for r in node['remotes']:
        m = next((x for x in mounts if x['target'] == r.get('mount')), {})
        remotes.append({'name': r.get('name') or r.get('endpoint'), 'protocol': REMOTE_PROTO.get(r.get('proto'), r.get('proto')),
                        'endpoint': r.get('endpoint'), 'via': r.get('via') or 'network', 'mount': r.get('mount'),
                        'status': r.get('status') or 'connected', 'options': m.get('options') or ['_netdev', 'nofail']})

    links = [{'kind': l['kind'], 'path': l['path'], 'target': l['target'],
              'health': 'crit' if l.get('exists') is False else 'ok', 'fromScan': True}
             for l in node['links'] if l.get('path') and l.get('target') and l['target'] != '?'][:100]

    return {'apiVersion': 'storageforge/v1', 'kind': 'StorageBlueprint',
            'metadata': {'host': node['hostname'], 'generated': (as_of or dt.date.today()).isoformat(),
                         'identifiers': 'UUID', 'source': 'scan', 'os': node.get('os'), 'ip': node.get('ip')},
            'devices': devices, 'pools': pools, 'remotes': remotes, 'links': links, 'exports': [],
            'protection': protection}


def from_index(conn, host: str) -> dict:
    return from_node(node_from_index(conn, host))


def merge_intent(scanned: dict, saved: dict | None) -> dict:
    """Fresh hardware from the scan, plus what only the operator knows from the saved design."""
    if not saved:
        return scanned
    out = dict(scanned, metadata=dict(scanned['metadata'], source='scan+design',
                                      identifiers=(saved.get('metadata') or {}).get('identifiers', 'UUID')))
    tiers = {d.get('dev'): d.get('tier') for d in saved.get('devices') or []}
    for d in out['devices']:
        d['tier'] = tiers.get(d['dev']) or d['tier']
    ptiers = {p.get('name'): p for p in saved.get('pools') or []}
    for p in out['pools']:
        sp = ptiers.get(p['name']) or {}
        p['tier'] = sp.get('tier') or p['tier']
        p['encryption'] = p.get('encryption') or sp.get('encryption')
    have = {r.get('mount') for r in out['remotes']}
    out['remotes'] = out['remotes'] + [r for r in saved.get('remotes') or [] if r.get('mount') not in have]
    paths = {l['path'] for l in out['links']}
    out['links'] = out['links'] + [l for l in saved.get('links') or [] if not l.get('fromScan') and l.get('path') not in paths]
    out['exports'] = saved.get('exports') or []
    rows = {r.get('node') or r.get('dataset'): r for r in saved.get('protection') or []}
    out['protection'] = [rows.pop(r['node'], None) or rows.pop(r['dataset'], None) or r for r in out['protection']]
    out['protection'] += list(rows.values())          # rows for things the scan did not see stay, flagged by the planner
    if saved.get('planner'):
        out['planner'] = saved['planner']
    return out
