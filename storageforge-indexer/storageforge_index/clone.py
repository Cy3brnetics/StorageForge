"""Copying one scanned host onto another, in any direction (docs/host-migration.md): the plans, and what is at risk.

build() turns "copy SOURCE to TARGET, with these choices" into ordinary plans, so nothing here runs anything:

  1. a change plan on the target: a snapshot before, the source's packages, its accounts, its data filesystems made
     on the target's disks and mounted where they were, and its share files. Formatting is the existing `format` step,
     with its three locks; the rest are the existing `mount`, `subvolume` and snapshot steps, and the steps of
     steps_clone.py.
  2. a Moves plan for user files: none, structure (folders with owners and modes, nothing in them), chosen folders, or
     everything. It copies and never deletes, and a file it would overwrite is kept beside it (keep_replaced).
  3. a change plan with the snapshot after, to run last.

Each is checked and run as any plan is. risks() lists every way the plans could lose or hide data, with what the index
knows of it, for the check to show and the operator to accept before running anything.
"""
from __future__ import annotations

import copy
import datetime as dt
import re

from . import changes, hostconfig, pkglist
from .changes import OS_MOUNTS
from .db import Conn
from .moves import host_slug

LEVELS = ('none', 'structure', 'all')
MODES = ('test', 'migrate')
# folders a desktop fills with what it can make again
CACHES = ['.cache/', '.var/app/*/cache/', '.local/share/Steam/', '.local/share/Trash/', '.mozilla/firefox/*/cache2/', '.thumbnails/']


def _label(text: str, fstype: str) -> str:
    raw = re.sub(r'[^A-Za-z0-9_-]', '', text.strip('/').replace('/', '-')) or 'data'
    return raw[:changes.LABEL_MAX.get(fstype, 16)]


def _host(conn: Conn, name: str) -> dict:
    hs = changes.hosts(conn)
    h = changes.find_host(hs, name)
    if not h:
        raise LookupError(f'{name} has not been scanned')
    return h


def _libvirt_home(conn: Conn, target: str) -> str | None:
    """The scanned libvirt host that runs a VM of this name, if any."""
    from . import inframeasure
    for (host,) in conn.all('SELECT hostname FROM hosts'):
        r = inframeasure.reading(conn, host) or {}
        if any((d.get('name') or '').lower() in (target.lower(), host_slug(target)) for d in r.get('libvirt') or []):
            return host
    return None


def _root(h: dict) -> dict | None:
    return next((m for m in h['mounts'] if m['target'] == '/'), None)


def _snapshot_tasks(conn: Conn, h: dict, when: str, stamp: str, notes: list, risks: list) -> list[dict]:
    """A snapshot of what the plans write to on the target: its VM disks if it is a VM we can see, else its root."""
    name = f'sf-clone-{when}-{stamp}'
    kvm = _libvirt_home(conn, h['name'])
    if kvm:
        return [{'type': 'workload-action', 'host': kvm, 'params': {'runtime': 'libvirt', 'name': h['name'], 'action': 'snapshot'},
                 'note': f'{when} the copy: every disk of the VM'}]
    root = _root(h) or {}
    fs, src = root.get('fstype') or '', root.get('source') or ''
    if fs == 'btrfs':
        return [{'type': 'snapshot', 'host': h['name'], 'params': {'source': '/', 'dest': f'/.snapshots/{name}', 'readonly': True}, 'note': f'{when} the copy'}]
    if fs == 'zfs' and re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.:/-]{0,199}', src):
        return [{'type': 'zfs-snapshot', 'host': h['name'], 'params': {'dataset': src, 'name': name, 'recursive': True}, 'note': f'{when} the copy'}]
    m = re.fullmatch(r'/dev/mapper/([A-Za-z0-9+_.]+?)-([A-Za-z0-9+_.]+)', src)
    if m and '--' not in src:
        return [{'type': 'lvm-snapshot', 'host': h['name'], 'params': {'vg': m[1], 'lv': m[2], 'name': name, 'size': '5G'}, 'note': f'{when} the copy'}]
    if when == 'before':
        risks.append({'level': 'crit', 'id': 'no-snapshot', 'text': f'{h["name"]}\'s root is {fs or "an unknown filesystem"} on {src or "an unknown device"}, which can\'t be snapshotted: '
                      'nothing the plans change on it can be undone. Back it up first, or copy to a VM instead'})
    return []


def _part_name(disk: str, num) -> str:
    return f'{disk}{"p" if disk[-1:].isdigit() else ""}{num}'


def _live_on(bp: dict, h: dict) -> dict:
    """Mount point -> the disk its live mount comes from, when the source is a disk or a partition of one."""
    on = {p['id']: _bare(d['dev']) for d in bp['devices'] for p in d['partitions']} | {_bare(d['dev']): _bare(d['dev']) for d in bp['devices']}
    return {m['target']: on[_bare(m.get('source'))] for m in h['mounts'] if _bare(m.get('source')) in on}


def _os_disks(bp: dict, h: dict) -> set:
    """Disks holding the running system: a partition or subvolume at /, /boot and the like, a member of a pool that is,
    or the disk a live system mount comes from (a whole-disk root has no partition to say so)."""
    on = {p['id']: _bare(d['dev']) for d in bp['devices'] for p in d['partitions']}
    os_ = {_bare(d['dev']) for d in bp['devices'] for p in d['partitions']
           if p.get('mount') in OS_MOUNTS or any(sv.get('mount') in OS_MOUNTS for sv in p.get('subvolumes') or [])}
    os_ |= {d for m, d in _live_on(bp, h).items() if m in OS_MOUNTS}
    for pool in bp['pools']:
        if pool.get('mount') in OS_MOUNTS or any(ds.get('mount') in OS_MOUNTS for ds in pool.get('datasets') or []):
            os_ |= {on.get(_bare(m), _bare(m)) for m in pool.get('members') or []}
    return os_


def _bare(dev) -> str:
    return str(dev or '').removeprefix('/dev/')


def _storage(conn: Conn, src: dict, tgt: dict, mapping: dict | str, notes: list, risks: list, not_carried: list, carried: set) -> list[dict]:
    """The source's data disks, laid out again on the target's: partitions, filesystems, btrfs, ZFS and LVM pools, and
    their mounts. The source's layout, moved onto the target's disks, is handed to fromdesign as a design for the
    target, so the steps are the ones the planner stages, in its order."""
    from . import blueprint, fromdesign
    sbp, tbp = blueprint.from_index(conn, src['name']), blueprint.from_index(conn, tgt['name'])
    s_os, t_os = _os_disks(sbp, src), _os_disks(tbp, tgt)
    s_live = _live_on(sbp, src)
    s_disks = {_bare(d['dev']): d for d in sbp['devices']}
    t_disks = {_bare(d['dev']): d for d in tbp['devices']}
    on = {p['id']: _bare(d['dev']) for d in sbp['devices'] for p in d['partitions']}
    data = [n for n, d in sorted(s_disks.items()) if n not in s_os and (d['partitions'] or d.get('member'))
            and not all(p.get('fs') == 'iso9660' for p in d['partitions'])]
    for pool in sbp['pools']:
        disks = {on.get(_bare(m), _bare(m)) for m in pool.get('members') or []}
        if disks & s_os and pool.get('mount') not in OS_MOUNTS:
            not_carried.append(f'{pool.get("name")} ({pool.get("type")}): it shares the system disk, which the copy leaves to the base install. Stage it by hand')
    if mapping == 'auto':
        free = [n for n, d in sorted(t_disks.items()) if n not in t_os and (d.get('serial') or '').startswith('sf-data')
                and not d['partitions'] and not d.get('member')]
        mapping = {f'/dev/{a}': f'/dev/{b}' for a, b in zip(data, free)}
    dmap = {}
    for key, dev in mapping.items():
        dev = _bare(dev)
        if key.startswith('/dev/'):
            sd = _bare(key)
        else:      # a mount point: the disk under it, when it is one disk
            under = {_bare(d['dev']) for d in sbp['devices'] for p in d['partitions'] if p.get('mount') == key
                     or any(sv.get('mount') == key for sv in p.get('subvolumes') or [])}
            under |= {on.get(_bare(m), _bare(m)) for pool in sbp['pools'] if key in {pool.get('mount')} | {ds.get('mount') for ds in pool.get('datasets') or []}
                      for m in pool.get('members') or []}
            if len(under) != 1:
                raise ValueError(f'{key} is on {len(under) or "no"} disk(s) of {src["name"]}: map its disks instead, as /dev/sdb=/dev/vdb')
            sd = under.pop()
        if sd not in s_disks:
            raise ValueError(f'{src["name"]} has no disk {sd}')
        if dev not in t_disks:
            raise ValueError(f'{tgt["name"]} has no disk {dev}')
        if dev in t_os:
            raise ValueError(f'/dev/{dev} holds the running system of {tgt["name"]}: the copy never writes to it')
        if dev in dmap.values():
            raise ValueError(f'/dev/{dev} is given for two disks')
        dmap[sd] = dev
    def mounts_on(sd):
        d = s_disks[sd]
        ids = {p['id'] for p in d['partitions']} | {sd}
        got = {p.get('mount') for p in d['partitions']} | {sv.get('mount') for p in d['partitions'] for sv in p.get('subvolumes') or []}
        for pool in sbp['pools']:
            if ids & {_bare(m) for m in pool.get('members') or []}:
                got |= {pool.get('mount')} | {ds.get('mount') for ds in pool.get('datasets') or []}
        got |= {m for m, d in s_live.items() if d == sd}
        return sorted(got - {None, ''})

    for sd in data:
        if sd not in dmap:
            what = ', '.join(mounts_on(sd)) or s_disks[sd].get('member') or 'its filesystems'
            not_carried.append(f'/dev/{sd} ({what}): no target disk given (--map /dev/{sd}=/dev/…)')

    design = copy.deepcopy(tbp)
    design['metadata'] = {**design.get('metadata', {}), 'host': tgt['name'], 'identifiers': 'LABEL'}
    rename = {}
    for sd, td in list(dmap.items()):
        d = s_disks[sd]
        parts = d['partitions']
        if any(p.get('encrypted') for p in parts):
            not_carried.append(f'/dev/{sd}: it is encrypted (LUKS), and its key is yours to keep. Set it up by hand')
            dmap.pop(sd)
            continue
        if not d.get('member') and all((p.get('fs') or 'none') == 'none' and not p.get('member') for p in parts):
            on_it = ', '.join(mounts_on(sd))
            not_carried.append(f'/dev/{sd}{f" ({on_it})" if on_it else ""}: the scan read no filesystem on it (lsblk gave none), so there is no layout to copy. Stage it by hand')
            dmap.pop(sd)
            continue
        whole_zfs = (parts and parts[0].get('fs') == 'zfs_member'
                     and all(p is parts[0] or ((p.get('fs') or 'none') == 'none' and (p.get('sizeBytes') or 0) <= 64 << 20) for p in parts))
        dev = {'dev': f'/dev/{td}', 'table': d.get('table') or 'gpt', 'member': d.get('member'), 'partitions': []}
        if whole_zfs:
            dev['member'] = parts[0].get('member')
            rename[parts[0]['id']] = td
        else:
            for i, p in enumerate(parts):
                pid = td if p['id'] == sd else _part_name(td, p.get('num') or i + 1)
                rename[p['id']] = pid
                q = {**p, 'id': pid, 'uuid': None}
                if p.get('fs') in changes.MKFS and not p.get('label') and p.get('mount'):
                    q['label'] = _label(p['mount'], p['fs'])
                if p.get('mount') or p.get('subvolumes'):
                    q['options'] = list(dict.fromkeys([*(p.get('options') or []), 'nofail']))
                if i == len(parts) - 1:
                    q['sizeBytes'], q['rest'] = None, True        # the last one takes the rest of the target disk
                dev['partitions'].append(q)
        rename[sd] = td
        design['devices'] = [x for x in design['devices'] if _bare(x['dev']) != td] + [dev]
        have_b, was_b = t_disks[td].get('sizeBytes') or 0, d.get('sizeBytes') or 0
        if not whole_zfs and have_b < sum(p.get('sizeBytes') or 0 for p in parts[:-1]) + (64 << 20):
            risks.append({'level': 'crit', 'id': f'small-{td}', 'text': f'/dev/{td} is smaller than the partitions of /dev/{sd} before its last one'})
        elif have_b < was_b - (64 << 20):
            risks.append({'level': 'warn', 'id': f'small-{td}', 'text': f'/dev/{td} ({have_b / 2**30:.1f} GiB) is smaller than /dev/{sd} '
                          f'({was_b / 2**30:.1f} GiB): what {src["name"]} keeps there has to fit'})
    # the target's pools on disks it gives up go; the source's pools come, on their new members
    t_on = {p['id']: _bare(d['dev']) for d in tbp['devices'] for p in d['partitions']}
    design['pools'] = [p for p in design['pools'] if not {t_on.get(_bare(m), _bare(m)) for m in p.get('members') or []} & set(dmap.values())]
    pooled = set()
    for pool in sbp['pools']:
        members = [_bare(m) for m in pool.get('members') or []]
        if not members or not all(m in rename for m in members):
            continue
        pooled |= set(members)
        q = {**copy.deepcopy(pool), 'members': [rename[m] for m in members], 'uuid': None}
        if q.get('mount') or q.get('datasets'):
            q['options'] = list(dict.fromkeys([*(q.get('options') or []), 'nofail']))
        design['pools'].append(q)
    # a btrfs that is in no pool is planned as a pool of one, so its subvolumes are made and mounted in the same plan
    for dev in design['devices']:
        for p in dev['partitions']:
            if p['id'] in rename.values() and p.get('fs') == 'btrfs' and p['id'] not in {rename.get(m) for m in pooled}:
                label = p.get('label') or _label(p.get('mount') or (p.get('subvolumes') or [{}])[0].get('mount') or p['id'], 'btrfs')
                p['label'] = label
                design['pools'].append({'name': label, 'type': 'btrfs', 'level': 'single', 'metaLevel': 'dup', 'members': [p['id']],
                                        'label': label, 'mount': p.get('mount') if not p.get('subvolumes') else None, 'options': p.get('options')})
    out = fromdesign.plan(conn, design, blank=set(dmap.values()))
    for m in out['manual']:
        not_carried.append(f'{m["what"]}: {m["why"]}')
    held = {td for td in dmap.values() if t_disks[td]['partitions'] or t_disks[td].get('member')}
    for td in sorted(set(dmap.values())):
        sd = next(k for k, v in dmap.items() if v == td)
        what = ', '.join(sorted({f'{p["fs"]} of {p["member"]}' if p.get('member') else p['fs'] for p in t_disks[td]['partitions']
                                 if (p.get('fs') or 'none') != 'none'})) or t_disks[td].get('member') or 'partitions'
        risks.append({'level': 'crit' if td in held else 'warn', 'id': f'format-/dev/{td}', 'destroys': True,
                      'text': f'/dev/{td} on {tgt["name"]} takes the layout of /dev/{sd}'
                      + (f': what it holds now ({what}) is destroyed' if td in held else ' (the last scan saw nothing on it)')
                      + '. The script does it only with --apply --destructive, and the device typed again'})
    tasks = []
    for t in out['tasks']:
        spec = changes.TYPES[t['type']]
        if any(f['name'] == 'confirm' for f in spec['fields']):
            t['params']['confirm'] = t['params'].get('device') or t['params'].get('disk') or t['params'].get('devices') or ''
        tasks.append({'type': t['type'], 'host': tgt['name'], 'params': t['params'], 'note': f'the layout of {src["name"]}'})
    made = {t['params'].get('target') for t in tasks if t['type'] == 'mount'} | {t['params'].get('mountpoint') for t in tasks if t['type'] in ('zfs-pool', 'zfs-dataset')}
    for pool in design['pools']:      # a ZFS dataset with no mountpoint of its own mounts under its pool
        if pool.get('type') == 'zfs' and pool.get('mount') in made:
            made |= {ds.get('mount') for ds in pool.get('datasets') or []}
    # what holds data on the copy: every mount made, less the top levels of btrfs that are only mounted to make subvolumes
    carried |= made - {t['params'].get('target') for t in tasks if t['type'] == 'unmount'} - set(OS_MOUNTS) - {None, ''}
    for m in hostconfig.build(conn, src['name']).get('mounts') or []:
        if m['kind'] == 'network':
            not_carried.append(f'{m["target"]} ({m["fstype"]}): a network mount. Add it by hand once the copy can reach the server')
        elif m['kind'] in ('device', 'zfs', 'derived') and m['target'] not in made and not any(m['target'] in x for x in not_carried):
            live = next((x.get('source') or '' for x in src['mounts'] if x['target'] == m['target']), '')
            md = re.match(r'/dev/md[/\w-]*', live)
            not_carried.append(f'{m["target"]} ({m["fstype"]}): ' + (f'on the mdadm array {md[0]}, which the copy does not make. Create it by hand, rescan, and copy again'
                                                                       if md else 'not made on the target by this. Stage it by hand'))
    return tasks


def build(conn: Conn, source: str, target: str, *, packages: bool = True, skip: str = '', accounts: bool = True, shares: bool = True,
          storage: dict | str = 'auto', files: str | list = 'none', mode: str = 'test', snapshots: bool = True) -> dict:
    if mode not in MODES:
        raise ValueError(f'mode is test or migrate, not {mode}')
    if isinstance(files, str) and files not in LEVELS:
        raise ValueError(f'files is one of {", ".join(LEVELS)}, or a list of folders')
    src, tgt = _host(conn, source), _host(conn, target)
    if src['name'].lower() == tgt['name'].lower():
        raise ValueError('the source and the target are the same host')
    rec = hostconfig.build(conn, src['name'])
    stamp = dt.datetime.now().strftime('%Y%m%d')
    risks, notes, not_carried = [], [], []
    title = f'Copy {src["name"]} to {tgt["name"]}'
    before = _snapshot_tasks(conn, tgt, 'before', stamp, notes, risks) if snapshots else []
    if not snapshots:
        risks.append({'level': 'warn', 'id': 'no-snapshot', 'text': 'no snapshot before or after: chosen'})
    tasks = list(before)
    pk = pkglist.for_host(conn, src['name'])
    if packages:
        if pk:
            tasks.append({'type': 'packages', 'host': tgt['name'], 'params': {'from_host': src['name'], 'skip': skip, 'apps': True}})
        else:
            not_carried.append(f'packages: {src["name"]} has no package list. Scan it again with this version')
    if accounts:
        tasks.append({'type': 'accounts', 'host': tgt['name'], 'params': {'from_host': src['name'], 'homes': True}})
    carried = set()
    tasks += _storage(conn, src, tgt, storage, notes, risks, not_carried, carried)
    if shares and any(hostconfig_share(p) for p in rec.get('files') or {}):
        tasks.append({'type': 'config-files', 'host': tgt['name'], 'params': {'from_host': src['name']}})
        if mode == 'test':
            notes.append('the copy serves the same shares: on the isolated network only the libvirt host can reach them')
    plans = {'changes': {'name': title, 'notes': f'{mode} copy, made by storageforge-index clone', 'tasks': tasks}}

    paths = []
    if files != 'none':
        mounts = [m['target'] for m in rec.get('mounts') or [] if m['kind'] == 'device']
        homes = sorted({u['home'] for u in (rec.get('accounts') or {}).get('users') or [] if (u.get('home') or '').startswith('/home/')})
        paths = list(files) if isinstance(files, list) else sorted(set(mounts) | carried | ({'/home'} if homes else set()))
        steps = []
        for p in paths:
            if not p.startswith('/'):
                raise ValueError(f'{p} is not a full path')
            steps.append({'method': 'copy', 'src': {'host': src['name'], 'path': p}, 'dst': {'host': tgt['name'], 'path': p},
                          'excludes': CACHES if p == '/home' or p.startswith('/home/') else [],
                          'options': {'keep_replaced': True, 'dirs_only': files == 'structure', 'one_fs': True}})
        if steps:
            plans['files'] = {'name': f'{title}: files', 'steps': steps}
            here = {m['target']: m for m in tgt['mounts']}
            busy = [f'{p} ({(here[p].get("used") or 0) // 2**30} GiB used)' for p in paths if p in here and (here[p].get('used') or 0) > 2**30]
            risks.append({'level': 'warn', 'id': 'files-replaced', 'text': 'files: a file of the same name on the target is replaced, and the one that was there is kept '
                          'beside it as <name>.sf-replaced-<date>. Nothing is deleted' + (f'. Already holding data: {", ".join(busy)}' if busy else '')})
            if files == 'structure':
                notes.append('structure: folders with their owners and modes, and no files')
    if snapshots and before:
        after = _snapshot_tasks(conn, tgt, 'after', stamp, notes, risks)
        if after:
            plans['after'] = {'name': f'{title}: snapshot after', 'tasks': after}

    fresh = [f'{m["target"]} ({(m.get("used") or 0) // 2**30} GiB)' for m in tgt['mounts']
             if m['target'] not in ('/', '/boot', '/boot/efi', '/efi') and (m.get('fstype') or '') in ('ext4', 'xfs', 'btrfs', 'zfs', 'f2fs') and (m.get('used') or 0) > 2**30]
    if fresh:
        risks.append({'level': 'warn', 'id': 'not-fresh', 'text': f'{tgt["name"]} is not freshly installed: it holds data on {", ".join(fresh[:6])}. The copy adds to it'})
    if mode == 'migrate':
        notes.append(f'migration: when the copy is checked, stop what writes on {src["name"]}, run the files plan again for what changed, then move the name and address over')
    else:
        notes.append(f'test: the copy has its own name and keys. Jobs, timers and network mounts of {src["name"]} are not copied, so it can\'t write to its backup targets')
    if pk and pk.get('foreign'):
        not_carried.append(f'{len(pk["foreign"])} package(s) from no package source (the AUR, a local file): {", ".join(pk["foreign"][:8])}')
    order = {'crit': 0, 'warn': 1, 'note': 2}
    return {'source': src['name'], 'target': tgt['name'], 'mode': mode, 'files': files, 'paths': paths, 'plans': plans,
            'risks': sorted(risks, key=lambda r: order.get(r['level'], 3)), 'notes': notes, 'not_carried': not_carried}


def hostconfig_share(path: str) -> bool:
    from .steps_clone import SHARE_FILE
    return bool(SHARE_FILE.fullmatch(path))


def save(conn: Conn, built: dict, actor: str) -> dict:
    """Save the plans. A name already taken gets the date on the end."""
    from . import moves
    stamp = dt.datetime.now().strftime('%Y-%m-%d %H%M')
    out = {}
    for key in ('changes', 'files', 'after'):
        body = built['plans'].get(key)
        if not body:
            continue
        taken = conn.scalar('SELECT 1 FROM change_plans WHERE lower(name) = lower(:n)' if key != 'files' else
                            'SELECT 1 FROM move_plans WHERE lower(name) = lower(:n)', {'n': body['name']})
        if taken:
            body = {**body, 'name': f'{body["name"]} {stamp}'[:80]}
        out[key] = (moves.save_plan if key == 'files' else changes.save_plan)(conn, body, actor)
    return out
