"""What the page for a second system offers (roadmap section 7, phases 8 and 9), and the plans it stages.

    offer(conn)                 the images, and for each scanned host its disks with the room the last scan saw on them, the second
                                systems already on it, and what its login account is
    stage(conn, body, actor)    saves change plans from what the page's form holds, and runs nothing

Everything here is read from the index: no host is asked anything. So the room on a disk is what the last scan saw, and the
step looks again when it runs, on the host, and refuses a disk that is not as the plan thought.

A desktop for the new system is a plan of its own, for a host of its own. A plan's script does the steps of the machine it
runs on, which it knows by its host name, and the new system's host name is the name it was given: so the steps of that plan
name the new system as their host, and it is run once the machine has been started into it. It starts with `os-running`,
which stops it in any other system: that is what holds where the new system was given the name the old one has.
"""
from __future__ import annotations

from . import changes, desktop, steps_desktop, steps_osinstall
from .db import Conn, epoch, loads
from .payloads import VIRTUAL_BLOCK

GIB = 1024 ** 3
MIN_FREE = 3 * GIB                      # what os-install refuses below
EDGE = 1024 ** 2                        # a GPT keeps its first and last megabyte
WHOLE_DISK_USES = {'zfs_member': 'ZFS', 'linux_raid_member': 'an md array', 'LVM2_member': 'LVM', 'crypto_LUKS': 'LUKS', 'btrfs': 'btrfs', 'bcache': 'bcache'}
ESP_MOUNTS = ('/boot/efi', '/efi', '/boot')


def _walk(items):
    for b in items or []:
        yield b
        yield from _walk(b.get('children'))


def largest_gap(disk: dict) -> int | None:
    """The largest stretch of the disk no partition is in, in bytes, or None where the scan did not read where partitions
    start (an old lsblk). START is in 512-byte sectors whatever the disk's own sector size is: it is what /sys gives."""
    parts = [c for c in disk.get('children') or [] if c.get('type') == 'part']
    if any(c.get('start') is None or c.get('size') is None for c in parts) or not disk.get('size'):
        return None
    at, best = EDGE, 0
    for c in sorted(parts, key=lambda c: int(c['start'])):
        begin = int(c['start']) * 512
        best = max(best, begin - at)
        at = max(at, begin + int(c['size']))
    return max(best, int(disk['size']) - EDGE - at, 0)


def disks(inv: dict) -> list[dict]:
    """The disks of a host as the last scan's lsblk had them, each with whether os-install could use it and why not."""
    out = []
    for d in ((inv or {}).get('lsblk') or {}).get('blockdevices') or []:
        if d.get('type') != 'disk' or not (d.get('path') or d.get('name')) or str(d.get('name') or '').startswith(VIRTUAL_BLOCK):
            continue
        kids = d.get('children') or []
        below = list(_walk(kids))
        row = {'path': d.get('path') or '/dev/' + d['name'], 'size': d.get('size'), 'model': (d.get('model') or '').strip(), 'partitions': sum(1 for c in kids if c.get('type') == 'part'),
               'table': d.get('pttype') or '', 'running': any(b.get('mountpoint') == '/' for b in below), 'free': None, 'blank': False, 'usable': False, 'why': ''}
        if d.get('fstype') or (kids and not row['partitions']):
            use = WHOLE_DISK_USES.get(d.get('fstype') or '', d.get('fstype') or 'something that is not a partition table')
            row['why'] = f'the whole disk holds {use}'
        elif not kids and not d.get('pttype'):
            row.update(blank=True, free=max(int(d.get('size') or 0) - 2 * EDGE, 0))
            row['usable'] = row['free'] >= MIN_FREE
            row['why'] = '' if row['usable'] else 'under 3 GiB'
        elif d.get('pttype') != 'gpt':
            row['why'] = f'its partition table is {d.get("pttype") or "not known"}, not GPT'
        else:
            row['free'] = largest_gap(d)
            if row['free'] is None:
                row['why'] = 'the scan did not read where its partitions start: the step looks when it runs'
                row['usable'] = True
            elif row['free'] < MIN_FREE:
                row['why'] = 'under 3 GiB of unpartitioned space, and nothing is shrunk'
            else:
                row['usable'] = True
        out.append(row)
    return out


def systems(inv: dict) -> list[dict]:
    """Second systems os-install made on this host: the partitions it named, as the last scan saw them."""
    label, found = steps_osinstall.LABEL, {}
    for d in ((inv or {}).get('lsblk') or {}).get('blockdevices') or []:
        for b in _walk(d.get('children')):
            name = b.get('partlabel') or ''
            if not (name.startswith(label) and '-' in name[len(label):]):
                continue
            system = name[len(label):].rsplit('-', 1)[0]
            row = found.setdefault(system, {'name': system, 'disk': d.get('path') or '/dev/' + str(d.get('name')), 'size': 0, 'partitions': 0, 'running': False})
            row['size'] += int(b.get('size') or 0)
            row['partitions'] += 1
            row['running'] = row['running'] or any(x.get('mountpoint') == '/' for x in [b, *_walk(b.get('children'))])
    return sorted(found.values(), key=lambda s: s['name'])


def started_by(inv: dict) -> str:
    """'uefi' where the scan saw an EFI partition mounted, else 'unknown': a scan does not read the firmware."""
    for d in ((inv or {}).get('lsblk') or {}).get('blockdevices') or []:
        for b in _walk([d]):
            if b.get('fstype') == 'vfat' and b.get('mountpoint') in ESP_MOUNTS:
                return 'uefi'
    return 'unknown'


def offer(conn: Conn, keys: bool = True) -> dict:
    """keys: whether the account may see the SSH keys kept here (keys.view). Without it the form takes a pasted key only."""
    hosts = []
    for name, user, os_info, inv_json, scanned in conn.all('SELECT hostname, ssh_user, os_info, inventory_json, last_scanned_at FROM hosts ORDER BY lower(hostname)'):
        inv = loads(inv_json) or {}
        hosts.append({'host': name, 'user': inv.get('scan_user') or user or '', 'os': os_info or '', 'scanned_at': epoch(scanned), 'read': bool(inv.get('lsblk')),
                      'started_by': started_by(inv), 'disks': disks(inv), 'systems': systems(inv)})
    fields = {f['name']: f for f in steps_osinstall.INSTALL_FIELDS}
    return {'hosts': hosts,
            'images': [{'key': k, 'label': v[0], 'url': v[1], 'checksums': v[2]} for k, v in steps_osinstall.IMAGES.items()],
            'keys': [{'name': n, 'public_key': p} for n, p in conn.all('SELECT name, public_key FROM ssh_keys WHERE disabled_at IS NULL ORDER BY lower(name)')] if keys else [],
            'choices': {n: fields[n]['options'] for n in ('sudo', 'host_keys', 'network', 'carry')},
            'desktop': {'compositors': list(steps_desktop.DUX_COMPOSITORS), 'terminals': list(steps_desktop.TERMINALS), 'profile_compositors': list(desktop.COMPOSITORS),
                        'profiles': sorted(desktop.profiles(conn), key=str.lower), 'releases': steps_desktop.RELEASES},
            'min_free': MIN_FREE, 'scratch_gib': steps_osinstall.SCRATCH_GIB}


INSTALL = tuple(f['name'] for f in steps_osinstall.INSTALL_FIELDS)


def _plans(body: dict) -> list[dict]:
    kind, host, name = body.get('kind') or 'install', str(body.get('host') or ''), str(body.get('name') or '')
    if kind == 'boot':
        when = body.get('when') or 'once'
        return [{'name': f'{host}: start {name} {when}', 'tasks': [{'type': 'os-boot', 'host': host, 'params': {'name': name, 'when': when, 'restart': body.get('restart') or 'no'}}]}]
    if kind == 'remove':
        return [{'name': f'{host}: remove {name}', 'tasks': [{'type': 'os-remove', 'host': host, 'params': {'name': name}}]}]
    if kind != 'install':
        raise ValueError('kind is install, boot or remove')
    disk = str(body.get('disk') or '').strip()
    if disk and str(body.get('confirm') or '').strip() != disk:
        raise ValueError(f'type {disk} again to confirm the disk')
    tasks = [{'type': 'os-install', 'host': host, 'params': {k: body.get(k) for k in INSTALL if body.get(k) not in (None, '')}}]
    start = body.get('start') or 'no'
    if start not in ('no', 'once', 'restart'):
        raise ValueError('start is no, once or restart')
    if start != 'no':
        tasks.append({'type': 'os-boot', 'host': host, 'params': {'name': name, 'when': 'once', 'restart': 'yes' if start == 'restart' else 'no'}})
    plans = [{'name': f'{host}: install {name}', 'tasks': tasks}]
    want = body.get('desktop') or {}
    if not isinstance(want, dict):
        raise ValueError('desktop is an object')
    after = []
    if want.get('dux'):
        after.append({'type': 'dux-install', 'host': name, 'params': {'user': want.get('user') or body.get('user'), 'compositor': want.get('compositor'), 'terminal': want.get('terminal') or 'ghostty',
                                                                      'version': want.get('version') or '', 'installer_sha': want.get('installer_sha') or ''}})
    if want.get('profile'):
        after.append({'type': 'desktop-profile', 'host': name, 'params': {'profile': want['profile'], 'user': want.get('user') or body.get('user'),
                                                                          'compositor': want.get('profile_compositor') or want.get('compositor')}})
    if after:
        note = f'For {name}, the second system on {host}: run it after the machine has been started into {name} and scanned. Its steps name {name} as their host, which is what the new system calls itself.'
        guard = {'type': 'os-running', 'host': name, 'params': {'name': name}, 'note': note[:300]}
        plans.append({'name': f'{host}: desktop on {name}', 'notes': note, 'tasks': [guard] + after})
    return plans


def stage(conn: Conn, body: dict, actor: str) -> dict:
    """Save the plans the form asks for. All of them are checked before any is saved, so a refusal leaves nothing behind."""
    if not isinstance(body, dict):
        raise ValueError('the body is an object')
    plans = _plans(body)
    for p in plans:
        changes.normalize(changes.prepare(conn, p))
        if conn.scalar('SELECT 1 FROM change_plans WHERE lower(name) = lower(:n)', {'n': p['name']}):
            raise ValueError(f'a plan named "{p["name"]}" already exists: run it or delete it in Changes first')
    saved = [{'plan_id': changes.save_plan(conn, p, actor), 'name': p['name'], 'tasks': len(p['tasks'])} for p in plans]
    return {'plans': saved}
