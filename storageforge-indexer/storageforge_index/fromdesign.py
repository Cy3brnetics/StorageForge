"""Planner design → staged change plan: what the design adds to a scanned host, as Changes tasks.

The planner used to write its own Bash and Ansible from a design. Those scripts could wipe and repartition disks
behind nothing but DRY_RUN=0, outside the checks, the report-first runs, --destructive and the audit log that
change plans get. Now the planner hands the design to this module, which compares it with the latest scan
(blueprint.from_index, the same storageforge/v1 shape) and emits tasks of the types in changes.TYPES. They are
staged in the Changes tab like any other, so they are checked, saved, deployed and audited the same way.

Only additions and edits become tasks. Things the scan has and the design dropped are listed and left alone, and
anything Changes has no task type for (mdadm, multi-device btrfs, encrypted ZFS pools, ZFS log and cache devices, bind
mounts, hard links) is listed as "by hand" with the reason. Drive tasks keep an empty confirm field, so nobody can save
them without typing the device again in the Changes tab. Every task still goes through changes.normalize before it
can be saved or scripted, so text from the design reaches a script only through those field checks.
"""
from __future__ import annotations

from . import blueprint
from .changes import MKFS, MOUNT_FS, OS_MOUNTS, PROFILES, TYPES, CHECKS
from .moves import find_host, hosts

# The order tasks run in: drives first, then filesystems on them, then what mounts and links onto those.
ORDER = ['drive-tune', 'partition', 'partition-add', 'format', 'zfs-pool', 'zfs-dataset', 'lvm-vg', 'lvm-vg-extend', 'lvm-lv', 'btrfs-add', 'label',
         'btrfs-balance', 'subvolume', 'mount', 'mount-options', 'symlink']
# ZFS properties the planner edits. A scan knows some of them, and only those can be compared with what the host has.
DS_PROPS = ('recordsize', 'compression', 'sync', 'atime', 'xattr', 'acltype', 'dnodesize', 'logbias', 'primarycache', 'copies',
            'quota', 'reservation')
WHOLE_DISK_SLACK = 64 << 20        # a design's "rest of the disk" stops short of the end by the GPT backup and alignment
REMOTE_FS = {'NFSv3': 'nfs', 'NFSv4': 'nfs4', 'NFSv4.1': 'nfs4', 'NFSv4.2': 'nfs4', 'SMB3': 'cifs', 'SMB2': 'cifs'}
IGNORED_OPTS = ('defaults', 'rw', 'relatime', 'seclabel')


def _bare(dev) -> str:
    return str(dev or '').removeprefix('/dev/')


def _opts(opts) -> list[str]:
    return [o for o in (opts or []) if o and o not in IGNORED_OPTS and not o.startswith(('subvol=', 'subvolid='))]


def _spec(part: dict, scanned: bool, id_mode: str) -> str:
    """How fstab names a partition: its real UUID once the scan has seen it, else its label, else the device."""
    if id_mode == 'LABEL' and part.get('label'):
        return f'LABEL={part["label"]}'
    if scanned and part.get('uuid'):
        return f'UUID={part["uuid"]}'
    return f'LABEL={part["label"]}' if part.get('label') else f'/dev/{_bare(part.get("id"))}'


def plan(conn, design: dict) -> dict:
    """{host, name, tasks, manual, left}. tasks are change-plan tasks for that host; manual are design items Changes
    can't do, with why; left are things on the host the design no longer has, which the plan does not touch."""
    host_name = str((design.get('metadata') or {}).get('host') or '').strip()
    h = find_host(hosts(conn), host_name)
    if not h:
        raise LookupError(f'{host_name or "this host"} has not been scanned: change plans are checked against a scan. '
                          'Scan it first, or use the fstab, systemd and blueprint exports')
    host = h['name']
    have = blueprint.from_index(conn, host)
    id_mode = (design.get('metadata') or {}).get('identifiers') or 'UUID'
    mounted = {m['target'] for m in h['mounts']}
    tasks, manual, left = [], [], []

    def task(kind, **params):
        spec = TYPES[kind]
        full = {f['name']: params.get(f['name'], f.get('default', False if f['kind'] == 'bool' else '')) for f in spec['fields']}
        tasks.append({'type': kind, 'host': host, 'params': full, 'note': 'from the planner design'})

    def by_hand(what, why):
        manual.append({'what': what, 'why': why})

    def mount(source, target, fstype, options, subvol='', fsck_pass=''):
        if not target or target in mounted:
            return
        if fstype not in MOUNT_FS:
            by_hand(f'Mount {target}', f'{fstype or "this filesystem"} is not one Changes can mount')
        elif not CHECKS['spec'].fullmatch(source or ''):
            by_hand(f'Mount {source} at {target}', 'the source is not a UUID=, LABEL=, /dev/…, server:/path or //server/share')
        else:
            task('mount', source=source, subvol=subvol or '', target=target, fstype=fstype,
                 options=','.join(options or []) or 'defaults', fsck_pass=str(fsck_pass or ''))
            mounted.add(target)

    # ── devices and partitions ───────────────────────────────────────────
    have_disks = {_bare(d['dev']): d for d in have['devices']}
    have_parts = {p['id']: (p, d) for d in have['devices'] for p in d['partitions']}
    for d in design.get('devices') or []:
        dev = _bare(d.get('dev'))
        hd = have_disks.get(dev)
        if not hd:
            by_hand(f'/dev/{dev}', 'the scan has no such disk: plug it in and rescan, or check the device name')
            continue
        tune = d.get('tune') or {}
        if any(tune.get(k) for k in ('scheduler', 'read_ahead', 'spindown', 'write_cache')):
            task('drive-tune', device=f'/dev/{dev}', scheduler=tune.get('scheduler') or '', read_ahead=str(tune.get('read_ahead') or ''),
                 spindown=str(tune.get('spindown') or ''), write_cache=tune.get('write_cache') or '')
        os_disk = any(p.get('mount') in OS_MOUNTS or any(s.get('mount') in OS_MOUNTS for s in p.get('subvolumes') or [])
                      for p in hd['partitions'])
        want, now = d.get('partitions') or [], hd['partitions']
        new_parts = [p for p in want if p.get('id') not in have_parts]
        kept = {p.get('id') for p in want}
        spans = len(want) == 1 and (not want[0].get('sizeBytes') or want[0]['sizeBytes'] >= (hd.get('sizeBytes') or 0) - WHOLE_DISK_SLACK)
        if d.get('member') or not new_parts:
            pass
        elif os_disk:
            by_hand(f'Partitions on /dev/{dev}', 'it holds the running system: StorageForge never repartitions it')
        elif now and not all(x['id'] in kept for x in now):
            by_hand(f'Partitions on /dev/{dev}', 'it already has partitions and the design changes them. Repartitioning '
                    'erases the disk: stage "Partition a disk" with "replace them" yourself if you mean it')
        elif (d.get('table') or 'gpt') != 'gpt' and (now or not spans):
            by_hand(f'Partitions on /dev/{dev}', 'adding partitions one at a time needs a GPT table: change the table, or partition it by hand')
        else:
            for i, p in enumerate(new_parts):
                fs = p.get('fs') if p.get('fs') in MKFS else ''
                if spans and not now:
                    task('partition', disk=f'/dev/{dev}', fstype=fs, label=p.get('label') or '', wipe=False, confirm='',
                         table={'mbr': 'msdos'}.get(d.get('table'), d.get('table') or ''), flag=p.get('flag') or '', mkfs=p.get('mkfs') or '')
                else:
                    last = i == len(new_parts) - 1 and (p.get('rest') or not p.get('sizeBytes'))
                    task('partition-add', disk=f'/dev/{dev}', name=p.get('label') or f'{dev}-{p.get("num") or i + 1}',
                         size='' if last else f'{(p.get("sizeBytes") or 0) >> 20}M', fstype=fs, label=p.get('label') or '',
                         flag=p.get('flag') or '', mkfs=p.get('mkfs') or '', confirm='')
                if p.get('fs') not in (None, '', 'none') and not fs:
                    by_hand(f'{p["fs"]} on the new partition of /dev/{dev}', f'Changes formats as {", ".join(MKFS)} only')
                for sv in p.get('subvolumes') or []:
                    by_hand(f'Subvolume {sv.get("name")} on /dev/{dev}', 'the filesystem does not exist yet: '
                            'run this plan, rescan, and plan again for its subvolumes')
                if p.get('mount') and fs:
                    mount(_spec(p, False, id_mode), p['mount'], fs, _opts(p.get('options')), fsck_pass=p.get('pass'))

        for p in want:
            pid = p.get('id')
            if pid not in have_parts:
                continue
            hp, _ = have_parts[pid]
            fs_want, fs_have = p.get('fs') or 'none', hp.get('fs') or 'none'
            if fs_want != fs_have and fs_want != 'none':
                if fs_have == 'none' and fs_want in MKFS:
                    task('format', device=f'/dev/{pid}', fstype=fs_want, label=p.get('label') or '', wipe=False, confirm='', mkfs=p.get('mkfs') or '')
                    if p.get('mount'):
                        mount(_spec(p, False, id_mode), p['mount'], fs_want, _opts(p.get('options')), fsck_pass=p.get('pass'))
                elif fs_have == 'none':
                    by_hand(f'{fs_want} on /dev/{pid}', f'Changes formats as {", ".join(MKFS)} only')
                else:
                    by_hand(f'/dev/{pid}: {fs_have} → {fs_want}', 'reformatting erases what is on it: '
                            'stage "Format" with "destroy it" yourself if you mean it')
                continue
            if p.get('label') and p.get('label') != hp.get('label') and fs_have in MKFS:
                task('label', target=hp.get('mount') or f'/dev/{pid}', label=p['label'])
            spec = _spec(hp, True, id_mode)
            if p.get('mount'):
                if hp.get('mount') and hp['mount'] != p['mount']:
                    by_hand(f'Move /dev/{pid} from {hp["mount"]} to {p["mount"]}', 'stage "Unmount" and "Add a mount" '
                            'yourself: whatever uses the old path has to be stopped and pointed at the new one')
                elif hp.get('mount') == p['mount']:
                    if set(_opts(p.get('options'))) != set(_opts(hp.get('options'))) and _opts(p.get('options')):
                        task('mount-options', target=p['mount'], options=','.join(_opts(p.get('options'))))
                else:
                    mount(spec, p['mount'], fs_have, _opts(p.get('options')), fsck_pass=p.get('pass'))
            elif hp.get('mount') and hp['mount'] not in OS_MOUNTS:
                left.append(f'/dev/{pid} mounted at {hp["mount"]}')
            have_svs = {s.get('name'): s for s in hp.get('subvolumes') or []}
            top = None if have_svs else hp.get('mount')      # without subvolume mounts, the mount is the top level
            for sv in p.get('subvolumes') or []:
                name = str(sv.get('name') or '').strip('/')
                if not name:
                    continue
                if name not in have_svs:
                    if top:
                        task('subvolume', path=f'{top.rstrip("/")}/{name}', nocow=False)
                    else:
                        by_hand(f'Subvolume {name} on /dev/{pid}', 'the top level of this btrfs is not mounted anywhere, '
                                'so the plan has nowhere to create it. If it already exists, its mount below still works')
                if sv.get('mount') and sv['mount'] != (have_svs.get(name) or {}).get('mount'):
                    if (have_svs.get(name) or {}).get('mount'):
                        by_hand(f'Move subvolume {name} from {have_svs[name]["mount"]} to {sv["mount"]}',
                                'stage "Unmount" and "Add a mount" yourself')
                    else:
                        mount(spec, sv['mount'], 'btrfs', _opts(p.get('options')) or ['noatime'], subvol=name)

    # ── pools ────────────────────────────────────────────────────────────
    def lvm_volumes(vg, volumes, existing=()):
        for lv in volumes or []:
            if lv.get('name') in existing:
                continue
            size = lv.get('size') or lv.get('sizeBytes')
            if not size:
                by_hand(f'Logical volume {vg}/{lv.get("name")}', 'the design gives it no size')
                continue
            fs = lv.get('fs') if lv.get('fs') in MKFS else ''
            task('lvm-lv', vg=vg, lv=lv.get('name'), size=str(size), fstype=fs, label='')
            if lv.get('mount') and fs:
                mount(f'/dev/{vg}/{lv.get("name")}', lv['mount'], fs, _opts(lv.get('options')))

    have_pools = {p['name']: p for p in have['pools']}
    for pool in design.get('pools') or []:
        name, kind = pool.get('name'), pool.get('type')
        hp = have_pools.get(name)
        members = sorted(_bare(m) for m in pool.get('members') or [])
        if not hp and kind == 'zfs':
            why = ('it is encrypted, and its key is yours to keep: zpool create it by hand, rescan, then plan the rest'
                   if str(pool.get('encryption') or 'off') != 'off' else
                   'it has log or cache devices, which the task does not add: zpool create it by hand, rescan, then plan the rest'
                   if pool.get('log') or pool.get('cache') else
                   'it has no member devices' if not members else '')
            if why:
                by_hand(f'Create ZFS pool {name} ({pool.get("level")} on {", ".join(members) or "no members"})', why)
                continue
            task('zfs-pool', pool=name, level=pool.get('level') or 'stripe', devices=' '.join(f'/dev/{m}' for m in members),
                 mountpoint=pool.get('mount') or '', wipe=False, confirm='', ashift=str(pool.get('ashift') or ''),
                 pool_props=pool.get('properties') or '', fs_props=pool.get('fsProperties') or '')
        elif not hp and kind == 'lvm' and members and pool.get('vg'):
            task('lvm-vg', vg=pool['vg'], devices=' '.join(f'/dev/{m}' for m in members), wipe=False, confirm='')
            lvm_volumes(pool['vg'], pool.get('datasets'))
            continue
        elif not hp:
            what = {'mdadm': 'mdadm array', 'lvm': 'LVM volume group', 'btrfs': 'btrfs pool'}.get(kind, 'pool')
            by_hand(f'Create {what} {name} ({pool.get("level")} on {", ".join(members) or "no members"})',
                    {'lvm': 'the design does not name its volume group or members: stage "Create a volume group" in Changes, or create it by hand, then rescan'}.get(
                        kind, 'Changes has no task that creates these. Create it by hand, rescan, then plan the rest'))
            continue
        if kind == 'zfs':
            have_ds = {ds['name'].split('/', 1)[-1]: ds for ds in (hp or {}).get('datasets') or []}
            for ds in pool.get('datasets') or []:
                dn = ds.get('name')
                was = have_ds.get(dn)
                props = {k: str(ds[k]) for k in DS_PROPS if ds.get(k) not in (None, '')}
                if was is not None:          # only what the scan read can be compared; anything else would stage every time
                    props = {k: v for k, v in props.items() if was.get(k) is not None and str(was[k]) != v}
                move = ds.get('mount') if was is not None and ds.get('mount') and ds['mount'] != was.get('mount') else ''
                if was is None or props or move:
                    task('zfs-dataset', dataset=f'{name}/{dn}', mountpoint=ds.get('mount') or '' if was is None else move,
                         options=','.join(f'{k}={v}' for k, v in props.items()))
            continue
        if kind == 'lvm' and hp.get('vg'):
            for m in members:
                if m not in {_bare(x) for x in hp.get('members') or []}:
                    task('lvm-vg-extend', vg=hp['vg'], device=f'/dev/{m}', wipe=False, confirm='')
            lvm_volumes(hp['vg'], pool.get('datasets'), {hp.get('lv')} | {ds.get('name') for ds in hp.get('datasets') or []})
            if not pool.get('mount') or pool['mount'] == hp.get('mount'):
                continue
        target = pool.get('mount') or hp.get('mount') or next(
            (s['mount'] for d in have['devices'] for p in d['partitions'] if p['id'] in hp.get('members', [])
             for s in p.get('subvolumes') or [] if s.get('mount')), None)
        if kind == 'btrfs':
            new = [m for m in members if m not in {_bare(x) for x in hp.get('members') or []}]
            for m in new:
                if target:
                    task('btrfs-add', device=f'/dev/{m}', target=target, wipe=False, confirm='')
                else:
                    by_hand(f'Add /dev/{m} to {name}', 'the pool is not mounted anywhere')
            gone = [m for m in (_bare(x) for x in hp.get('members') or []) if m not in members]
            if gone:
                left.append(f'{", ".join("/dev/" + m for m in gone)} in btrfs pool {name} (removing devices is by hand)')
            level, meta = pool.get('level'), pool.get('metaLevel') or hp.get('metaLevel') or pool.get('level')
            if level != hp.get('level') or (pool.get('metaLevel') and pool['metaLevel'] != hp.get('metaLevel')):
                if level in PROFILES and meta in PROFILES and target:
                    task('btrfs-balance', target=target, data=level, metadata=meta)
                else:
                    by_hand(f'Convert {name} to {level}', 'Changes converts to ' + ', '.join(PROFILES) + ' on a mounted pool')
        elif members != sorted(_bare(x) for x in hp.get('members') or []) or pool.get('level') != hp.get('level'):
            by_hand(f'Reshape {kind} {name}', f'Changes has no {kind} tasks yet')
        if pool.get('mount') and pool['mount'] != hp.get('mount'):
            if hp.get('mount'):
                by_hand(f'Move {name} from {hp["mount"]} to {pool["mount"]}', 'stage "Unmount" and "Add a mount" yourself')
            else:
                src = (f'UUID={hp["uuid"]}' if hp.get('uuid') else
                       f'/dev/{hp["vg"]}/{hp["lv"]}' if kind == 'lvm' and hp.get('lv') else f'/dev/{name}')
                mount(src, pool['mount'], pool.get('fs') or ('btrfs' if kind == 'btrfs' else ''), _opts(pool.get('options')))

    # ── network mounts ───────────────────────────────────────────────────
    have_remote = {r.get('mount') for r in have['remotes']}
    for r in design.get('remotes') or []:
        target = r.get('mount')
        if not target or target in have_remote:
            continue
        fs = REMOTE_FS.get(str(r.get('protocol') or '').split(' ')[0])
        if not fs:
            by_hand(f'Mount {r.get("name") or r.get("endpoint")} at {target}', f'{r.get("protocol")} mounts are not a Changes task')
            continue
        opts = _opts(r.get('options'))
        mount(r.get('endpoint') or '', target, fs, opts + [o for o in ('_netdev', 'nofail') if o not in opts])

    # ── links ────────────────────────────────────────────────────────────
    have_links = {l['path'] for l in have['links']}
    for l in design.get('links') or []:
        if l.get('fromScan') or not l.get('path') or l['path'] in have_links:
            continue
        if l.get('kind') == 'symlink':
            task('symlink', path=l['path'], target=l.get('target') or '')
        else:
            by_hand(f'{l.get("kind")} {l["path"]} → {l.get("target")}',
                    'bind mounts and hard links are not Changes tasks yet: add them by hand')

    designed_mounts = ({p.get('mount') for d in design.get('devices') or [] for p in d.get('partitions') or []}
                       | {s.get('mount') for d in design.get('devices') or [] for p in d.get('partitions') or []
                          for s in p.get('subvolumes') or []}
                       | {p.get('mount') for p in design.get('pools') or []}
                       | {ds.get('mount') for p in design.get('pools') or [] for ds in p.get('datasets') or []}
                       | {r.get('mount') for r in design.get('remotes') or []})
    for d in have['devices']:
        for p in d['partitions']:
            for s in p.get('subvolumes') or []:
                if s.get('mount') and s['mount'] not in designed_mounts and s['mount'] not in OS_MOUNTS:
                    left.append(f'subvolume {s["name"]} mounted at {s["mount"]}')

    tasks.sort(key=lambda t: (ORDER.index(t['type']), t['params'].get('target', '').count('/')))
    for i, t in enumerate(tasks, 1):
        t['id'] = f'd{i}'
    return {'host': host, 'name': f'Design for {host}', 'tasks': tasks, 'manual': manual, 'left': sorted(set(left)),
            'destructive': sum(1 for t in tasks if TYPES[t['type']].get('destructive'))}
