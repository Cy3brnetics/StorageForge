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

import datetime as dt
import re

from . import changes, hostconfig, pkglist
from .db import Conn
from .moves import host_slug

LEVELS = ('none', 'structure', 'all')
MODES = ('test', 'migrate')
# folders a desktop fills with what it can make again
CACHES = ['.cache/', '.var/app/*/cache/', '.local/share/Steam/', '.local/share/Trash/', '.mozilla/firefox/*/cache2/', '.thumbnails/']
_OPT = re.compile(r'[A-Za-z0-9_=.:/@+-]{1,100}')
_DROP = ('subvol=', 'subvolid=', 'x-systemd.', 'UUID=', 'PARTUUID=')


def _label(text: str, fstype: str) -> str:
    raw = re.sub(r'[^A-Za-z0-9_-]', '', text.strip('/').replace('/', '-')) or 'data'
    return raw[:changes.LABEL_MAX.get(fstype, 16)]


def _options(text: str) -> str:
    keep = [o for o in (text or '').split(',') if _OPT.fullmatch(o) and not o.startswith(_DROP) and o != 'defaults']
    return ','.join(dict.fromkeys(keep + ['nofail']))


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


def _storage(conn: Conn, rec: dict, target: dict, mapping: dict | str, notes: list, risks: list, not_carried: list) -> list[dict]:
    """The source's data filesystems, made on the target's disks: format, then mount (btrfs subvolumes through the top level)."""
    groups: dict[str, list] = {}
    for m in rec.get('mounts') or []:
        if m['kind'] == 'device':
            groups.setdefault(m['spec'], []).append(m)
        elif m['kind'] in ('zfs', 'network', 'derived'):
            not_carried.append(f'{m["target"]} ({m["fstype"]}, {m["kind"]}): not made on the target by this. Stage it by hand')
    labels = {d.get('uuid'): d.get('label') for d in rec.get('drives') or []}
    ordered = sorted(groups.items(), key=lambda kv: min(len(x['target']) for x in kv[1]))
    tgt = changes.Host(conn, target)
    free = [f'/dev/{d["dev"]}' for d in tgt.node['disks'] if (d.get('serial') or '').startswith('sf-data') and not d['parts'] and not d.get('member')]
    if mapping == 'auto':
        mapping = {}
        for (spec, ms), dev in zip(ordered, sorted(free)):
            mapping[ms[0]['target']] = dev
    tasks, used = [], set()
    for spec, ms in ordered:
        fs = ms[0]['fstype']
        dev = next((mapping[m['target']] for m in ms if m['target'] in mapping), None)
        where = ', '.join(m['target'] for m in ms)
        if not dev:
            not_carried.append(f'{where} ({fs}): no target disk given (--map {ms[0]["target"]}=/dev/…)')
            continue
        if fs not in changes.MKFS:
            not_carried.append(f'{where} ({fs}): StorageForge doesn\'t make {fs}. Stage it by hand')
            continue
        if dev in used:
            risks.append({'level': 'crit', 'id': f'disk-twice-{dev}', 'text': f'{dev} is given for two filesystems'})
            continue
        used.add(dev)
        label = _label(labels.get(spec.removeprefix('UUID=')) or ms[0]['target'], fs)
        info = tgt.device(dev)
        held = (info or {}).get('fs') or ((info or {}).get('kind') == 'disk' and (info or {}).get('parts') and 'partitions')
        risks.append({'level': 'crit' if held else 'warn', 'id': f'format-{dev}', 'destroys': True,
                      'text': f'formats {dev} on {target["name"]} as {fs}' + (f': it holds {held} now, which is destroyed' if held else ' (the last scan saw nothing on it)')
                      + '. The script does it only with --apply --destructive, and the device typed again'})
        tasks.append({'type': 'format', 'host': target['name'], 'params': {'device': dev, 'fstype': fs, 'label': label, 'wipe': bool(held), 'confirm': dev},
                      'note': f'for {where}'})
        subs = [(m, re.search(r'(?:^|,)subvol=/?([^,]+)', m['options'])) for m in ms]
        if fs == 'btrfs' and any(s for _, s in subs):
            top = f'/mnt/{label}-top'
            tasks.append({'type': 'mount', 'host': target['name'], 'params': {'source': f'LABEL={label}', 'target': top, 'fstype': 'btrfs', 'options': 'subvolid=5,noatime,nofail'},
                          'note': 'the top level, where its subvolumes are made'})
            for name in sorted({s[1] for _, s in subs if s}, key=lambda x: x.count('/')):
                tasks.append({'type': 'subvolume', 'host': target['name'], 'params': {'path': f'{top}/{name}'}})
            notes.append(f'the btrfs filesystem for {where} stays mounted at {top} too, as many setups keep it')
        for m, s in subs:
            tasks.append({'type': 'mount', 'host': target['name'],
                          'params': {'source': f'LABEL={label}', 'target': m['target'], 'fstype': fs, 'options': _options(m['options']),
                                     **({'subvol': s[1]} if s else {})}})
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
    tasks += _storage(conn, rec, tgt, storage, notes, risks, not_carried)
    if shares and any(hostconfig_share(p) for p in rec.get('files') or {}):
        tasks.append({'type': 'config-files', 'host': tgt['name'], 'params': {'from_host': src['name']}})
        if mode == 'test':
            notes.append('the copy serves the same shares: on the isolated network only the libvirt host can reach them')
    plans = {'changes': {'name': title, 'notes': f'{mode} copy, made by storageforge-index clone', 'tasks': tasks}}

    paths = []
    if files != 'none':
        mounts = [m['target'] for m in rec.get('mounts') or [] if m['kind'] == 'device']
        homes = sorted({u['home'] for u in (rec.get('accounts') or {}).get('users') or [] if (u.get('home') or '').startswith('/home/')})
        paths = list(files) if isinstance(files, list) else sorted(set(mounts) | ({'/home'} if homes else set()))
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
