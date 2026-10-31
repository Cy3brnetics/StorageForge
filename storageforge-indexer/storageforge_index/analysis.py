"""Checks run over a report node: link health, boot ordering, 3-2-1 status, capacity and findings."""
from __future__ import annotations

import datetime as dt
import posixpath

from .capacity import TiB, fmt_bin, fmt_dec
from .remote import NETWORK_FS, is_under

MOUNTABLE_FS = {'vfat', 'ext2', 'ext3', 'ext4', 'xfs', 'btrfs', 'f2fs', 'exfat', 'ntfs', 'ntfs3', 'bcachefs'}
SEVERITY = {'crit': 0, 'warn': 1, 'info': 2}


def use_pct(m: dict) -> float | None:
    """df's Use%: used / (used + available), so reserved blocks count as unavailable."""
    used, avail, total = m.get('used'), m.get('avail'), m.get('total')
    if used is None:
        return None
    if avail is not None and used + avail:
        return used / (used + avail) * 100
    return used / total * 100 if total else None


def real_mounts(node) -> list[dict]:
    return [m for m in node['mounts'] if (m.get('target') or '').startswith('/') and m.get('kind') != 'swap']


def containing_mount(path: str, mounts: list[dict]) -> dict | None:
    best = None
    for m in mounts:
        t = m.get('target') or ''
        if m.get('kind') in ('bind', 'swap') or not t.startswith('/'):
            continue
        if is_under(path, t) and (best is None or len(t) > len(best['target'])):
            best = m
    return best


def _remote_on(mount, node):
    if not mount:
        return None
    return next((r for r in node['remotes'] if r.get('mount') == mount['target']), None)


def resolve(link_path: str, target: str) -> str:
    """Absolute form of a symlink target; relative targets resolve against the link's directory."""
    if target.startswith('/'):
        return target
    return posixpath.normpath(posixpath.join(posixpath.dirname(link_path), target))


def link_health(link: dict, node: dict) -> tuple[str, str]:
    """('ok'|'info'|'warn'|'crit', explanation)."""
    mounts, kind, path, target = real_mounts(node), link['kind'], link['path'], link['target']
    if kind == 'symlink':
        t = resolve(path, target)
        seen = [path]
        for _ in range(40):
            nxt = next((l for l in node['links'] if l['kind'] == 'symlink' and l['path'] == t), None)
            if not nxt:
                break
            if nxt['path'] in seen:
                return 'crit', 'Circular symlink ' + ' → '.join(seen + [nxt['path']]) + ' (ELOOP)'
            seen.append(nxt['path'])
            t = resolve(nxt['path'], nxt['target'])
        return _target_state(t, link, node, mounts)
    if kind == 'bind':
        if is_under(path, target):
            return 'crit', 'The mount point lies inside its own source, which nests the tree inside itself'
        state = _target_state(target, link, node, mounts)
        if state[0] in ('crit', 'warn'):
            return state
        src = containing_mount(target, mounts)
        if link.get('health') == 'warn':
            return 'warn', f'{path} already holds data; the bind mount hides it until it is migrated'
        return 'ok', f'Needs {src["target"] if src else "its source"} mounted first (x-systemd.requires-mounts-for)'
    a, b = containing_mount(path, mounts), containing_mount(target, mounts)
    if not a or not b or a['target'] != b['target']:
        return 'crit', f'Hard link crosses filesystems ({a and a["target"]} vs {b and b["target"]}), which fails with EXDEV'
    return 'ok', f'Same filesystem ({a["target"]})'


def _target_state(t, link, node, mounts):
    m = containing_mount(t, mounts)
    if not m:
        return 'crit', 'No mounted filesystem contains the target'
    r = _remote_on(m, node)
    if r and r.get('status') not in (None, 'connected'):
        return 'crit', f'Target is on {m["target"]}, which is disconnected ({r.get("via") or r.get("proto")})'
    if link.get('exists') is False:
        return 'crit', f'Target {t} does not exist in the file index'
    if link.get('health') == 'crit':
        return 'crit', f'Target {t} is missing (flagged by the blueprint)'
    if link.get('exists') is None and link.get('from_index'):
        return 'info', f'Target is on {m["target"]}, which is not indexed; not verified'
    return 'ok', f'Resolves on {m["target"]}'


def boot_stages(node) -> list[list[dict]]:
    ms = real_mounts(node)
    deps = {}
    for m in ms:
        d = []
        parents = [x for x in ms if x is not m and x['target'] != m['target'] and is_under(m['target'], x['target'])]
        parent = max(parents, key=lambda x: len(x['target']), default=None)
        if parent:
            d.append(parent['target'])
        if m.get('kind') == 'bind':
            src = containing_mount(m.get('spec') or m.get('source') or '', ms)
            if src and src is not parent:
                d.append(src['target'])
        opts = m.get('options') or []
        if m.get('kind') == 'remote' or '_netdev' in opts:
            d.append('network-online.target')
        if m.get('kind') == 'zfs':
            d.append('zfs-import.target')
        deps[m['target']] = d
    level: dict[str, int] = {}

    def lvl(t, stack=()):
        if t in level:
            return level[t]
        if t in stack or t not in deps:
            return -1
        v = 1 + max((lvl(x, stack + (t,)) for x in deps[t]), default=-1)
        level[t] = v
        return v

    stages: list[list[dict]] = []
    for m in sorted(ms, key=lambda m: m['target']):
        i = max(lvl(m['target']), 0)
        while len(stages) <= i:
            stages.append([])
        if not any(x['mount']['target'] == m['target'] for x in stages[i]):
            stages[i].append({'mount': m, 'after': deps[m['target']]})
    return stages


def protection_status(row: dict, as_of: dt.date) -> tuple[str, list[str]]:
    """('protected'|'local-only'|'critical'|'excluded', reasons). Same rules as the dashboard."""
    if row.get('ephemeral'):
        return 'excluded', ['Ephemeral scratch space, intentionally unprotected']
    sync = (row.get('sync') or {}).get('state') or 'None'
    snap = row.get('snapshots') or {}
    bk = row.get('backup') or {}
    age = None
    if bk.get('target') and bk.get('last'):
        age = (as_of - dt.date.fromisoformat(str(bk['last'])[:10])).days
    why = []
    if sync == 'Lagging':
        why.append(f'replication lagging {(row.get("sync") or {}).get("lag") or ""}'.strip())
    if sync == 'Disconnected':
        why.append('replication target unreachable')
    stale = bk.get('target') and (age is None or age > 90)
    if stale:
        why.append('backup never validated' if age is None else f'backup not validated for {age} days')
    nothing = not snap.get('enabled') and not bk.get('target') and sync == 'None'
    if nothing:
        why.append('single copy: no snapshots, sync or backup')
    if sync in ('Lagging', 'Disconnected') or stale or (not snap.get('enabled') and not bk.get('target')):
        return 'critical', why or ['no snapshots and no backup']
    if snap.get('enabled') and bk.get('target') and bk.get('offsite') and age is not None and age <= 30:
        return 'protected', [f'snapshots plus offsite backup validated {age} d ago']
    if not bk.get('target'):
        why.append('no backup target')
    elif not bk.get('offsite'):
        why.append('backup is on the same site')
    elif age is not None and age > 30:
        why.append(f'backup validation is {age} d old')
    if not snap.get('enabled'):
        why.append('no snapshots')
    return 'local-only', why


def local_disks(node):
    return [d for d in node['disks'] if d.get('tier') != 'remote' and d.get('media') != 'net']


def capacity_summary(node) -> dict:
    disks = local_disks(node)
    ids = {d['dev'] for d in disks} | {p['dev'] for d in disks for p in d['parts']}
    raw = float(sum(d.get('size') or 0 for d in disks))
    s = {'raw': raw, 'usable': 0.0, 'parity': 0.0, 'overhead': 0.0, 'fs_reserve': 0.0, 'waste': 0.0,
         'allocated': None, 'free': None, 'remote_total': 0.0, 'remote_used': 0.0, 'pools': [], 'standalone': []}
    for p in node['pools']:
        c = p.get('cap')
        if not c or not any(m in ids for m in p['members']):
            continue
        for k in ('usable', 'parity', 'overhead', 'fs_reserve', 'waste'):
            s[k] += c[k]
        s['pools'].append(p)
    for d in disks:
        for part in d['parts']:
            if not part.get('member') and part.get('fs') in MOUNTABLE_FS:
                s['usable'] += part.get('size') or 0
                s['standalone'].append((d, part))
    seen, alloc, measured = set(), 0, False
    for m in real_mounts(node):
        net = m.get('kind') == 'remote' or m.get('fstype') in NETWORK_FS
        if m.get('used') is None or m.get('kind') == 'bind':
            continue
        if net or m.get('tier') == 'remote':
            s['remote_total'] += m.get('total') or 0
            s['remote_used'] += m.get('used') or 0
            continue
        key = m.get('majmin') or m.get('source') or m['target']
        if key in seen:
            continue
        seen.add(key)
        alloc += m['used']
        measured = True
    if measured:
        s['allocated'] = float(alloc)
        s['free'] = s['usable'] - alloc
    return s


def findings(node, as_of: dt.date) -> list[dict]:
    F = []

    def add(sev, title, detail):
        F.append({'sev': sev, 'title': title, 'detail': detail})

    for d in node['disks']:
        if d.get('table') in ('mbr', 'dos', 'msdos') and (d.get('size') or 0) > 2 * TiB:
            add('warn', f'/dev/{d["dev"]} uses MBR on a {fmt_dec(d["size"], 0)} disk',
                f'MBR addresses 2 TiB with 512-byte sectors; {fmt_bin(d["size"] - 2 * TiB)} is unreachable. '
                'Back up, then convert with `sgdisk -g`.')
        for p in d['parts']:
            if p.get('start') is not None and p['start'] % (1024 * 1024):
                pbs = d.get('phy_sec') or 4096
                bad = p['start'] % pbs != 0
                add('crit' if bad else 'warn', f'/dev/{p["dev"]} is misaligned (starts at sector {p["start"] // 512})',
                    f'The start is not a multiple of the {pbs}-byte physical sector, so 4K writes become '
                    'read-modify-write cycles. Recreate the partition at 1 MiB (sector 2048).' if bad else
                    'Not on a 1 MiB boundary. Recreate at sector 2048.')
            if d.get('media') == 'hdd' and any(o.startswith('discard') for o in p.get('options') or []):
                add('warn', f'`discard` on spinning disk /dev/{p["dev"]}',
                    'TRIM has no effect on a hard drive and some SATA bridges error on it. Remove the option.')
    for p in node['pools']:
        if p.get('cap') and p['cap']['tolerance'] == 0 and p['type'] != 'btrfs':
            add('crit', f'Pool {p["name"]} has no redundancy', 'One failed member loses the pool.')
        if p.get('health') and p['health'] != 'ONLINE':
            add('crit', f'Pool {p["name"]} is {p["health"]}', p.get('status_note') or 'Check `zpool status -x`.')
        for e in p.get('device_errors') or []:
            add('warn', f'Pool {p["name"]}: {e["device"]} reports errors (R/W/C {e["read"]}/{e["write"]}/{e["cksum"]})',
                'Run a scrub, check SMART and cabling, then `zpool clear` once the cause is known.')
    from .health import apply_report, problems
    apply_report(node, node.get('health_report'))
    for level, _, title, detail in problems(node, as_of):
        add(level, title, detail)
    root = next((m for m in real_mounts(node) if m['target'] == '/'), None)
    if root:
        disk = _disk_of(root, node)
        pool = next((p for p in node['pools'] if root.get('source') in (p['name'], f'/dev/{p["name"]}')), None)
        redundant = bool(pool and pool.get('cap') and pool['cap']['tolerance'] > 0)
        prow = next((r for r in node['protection'] if r.get('path') == '/'), None)
        snap = bool(prow and (prow.get('snapshots') or {}).get('enabled'))
        if not redundant and prow is not None and not snap:
            add('crit', 'Root filesystem is on a single device without snapshots',
                f'`/` lives on {disk and "/dev/" + disk["dev"] or root.get("source")}. A bad upgrade or a drive failure means a full rebuild.')
        elif not redundant and disk:
            add('warn', 'Root filesystem is on a single device',
                f'`/` lives on /dev/{disk["dev"]} with no mirror. Snapshots cover bad upgrades, not drive failure; '
                'keep the offsite backup validated or mirror the root.')
    for m in real_mounts(node):
        pct = use_pct(m)
        if pct is not None and m.get('kind') != 'bind':
            if pct >= 85:
                add('crit' if pct >= 95 else 'warn', f'{m["target"]} is {pct:.0f}% full',
                    f'{fmt_bin(m.get("avail") if m.get("avail") is not None else m["total"] - m["used"])} available. Filesystems fragment and slow down as they fill; copy-on-write ones (ZFS, btrfs) suffer first.')
    for r in node['remotes']:
        if r.get('status') not in (None, 'connected'):
            add('warn', f'Remote target {r.get("name") or r.get("endpoint")} is disconnected',
                f'{r.get("proto")} via {r.get("via")}: everything under {r.get("mount")} is unavailable.')
    for l in node['links']:
        if l.get('state') in ('crit', 'warn'):
            add(l['state'], f'{l["kind"]} {l["path"]}', l['note'])
    for row in node['protection']:
        st, why = protection_status(row, as_of)
        if st == 'critical':
            add('crit', f'{row.get("dataset")} protection is critical', '; '.join(why).capitalize() + '.')
    for d in node.get('drift') or []:
        add('warn', d['title'], d['detail'])
    if any(p['type'] == 'zfs' for p in node['pools']):
        add('info', 'ZFS snapshot space is not in the allocated figure',
            '`df` reports each dataset\'s referenced data only. Use `zfs list -o space` for snapshot usage.')
    F.sort(key=lambda f: SEVERITY[f['sev']])
    return F


def _disk_of(mount, node):
    src = (mount.get('source') or '').removeprefix('/dev/')
    for d in node['disks']:
        if src == d['dev'] or any(p['dev'] == src for p in d['parts']):
            return d
    return None
