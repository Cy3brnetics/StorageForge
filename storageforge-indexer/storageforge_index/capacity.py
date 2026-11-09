"""Capacity math (pool layouts, binary vs decimal units) and drive power estimates.

The pool formulas match the StorageForge dashboard's RAID calculator so a report
and the dashboard agree on usable space for the same blueprint.
"""
from __future__ import annotations

import math
import re

KiB = 1024
MiB = KiB ** 2
GiB = KiB ** 3
TiB = KiB ** 4


def _fmt(n, base, units, digits):
    if n is None:
        return 'n/a'
    v, i = float(n), 0
    while abs(v) >= base and i < len(units) - 1:
        v /= base
        i += 1
    return f'{v:.0f} {units[i]}' if i < 2 else f'{v:.{digits}f} {units[i]}'


def fmt_bin(n, digits=2):
    return _fmt(n, 1024, ('B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB', 'EiB'), digits)


def fmt_dec(n, digits=2):
    return _fmt(n, 1000, ('B', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB'), digits)


def both(n, digits=2):
    return 'n/a' if n is None else f'{fmt_bin(n, digits)} ({fmt_dec(n, digits)})'


# parse_size strips the text first, so spaces can only sit between the number and the unit, and digits split one
# way: linear time (two runs of spaces or digits side by side are quadratic on a long one)
_SIZE_RE = re.compile(r'([0-9]+(?:\.[0-9]+)?|\.[0-9]+)\s*([kmgtpe]?)(i?)(b?)', re.IGNORECASE)


def parse_size(text) -> int:
    """'100MB' → 10**8 (decimal); '100MiB' and '100M' → 100·2**20 (binary, as df, du and find print)."""
    m = _SIZE_RE.fullmatch(str(text).strip())
    if not m:
        raise ValueError(f'unrecognised size {text!r}; use e.g. 500K, 100MB, 1.5GiB or 2T')
    num, unit, binary, b = m.groups()
    if not unit:
        return int(float(num))
    power = 'kmgtpe'.index(unit.lower()) + 1
    base = 1024 if (binary or not b) else 1000
    return int(float(num) * base ** power)


FS_RESERVE = {
    'ext4': lambda reserve: (0.05 if reserve else 0.0) + 0.0156,   # root reserve + inode tables at 16 KiB/inode
    'ext3': lambda reserve: (0.05 if reserve else 0.0) + 0.0156,
    'xfs': lambda reserve: 0.008,
    'btrfs': lambda reserve: 0.01,
}


def raidz_efficiency(width: int, parity: int, recordsize: int, ashift: int) -> float:
    sector = 2 ** ashift
    d = math.ceil(recordsize / sector)
    p = parity * math.ceil(d / (width - parity))
    total = math.ceil((d + p) / (parity + 1)) * (parity + 1)
    return d / total


def _btrfs_alloc(sizes, copies, raid10=False):
    free = list(sizes)
    chunk = max(sizes) / 1500
    cap = 0.0
    for _ in range(200_000):
        idx = sorted((i for i, f in enumerate(free) if f >= chunk), key=lambda i: -free[i])
        if raid10:
            k = len(idx) - len(idx) % 2
            if k < 4:
                break
            for i in idx[:k]:
                free[i] -= chunk
            cap += chunk * k / 2
        else:
            if len(idx) < copies:
                break
            for i in idx[:copies]:
                free[i] -= chunk
            cap += chunk
    return cap


def pool_capacity(kind, level, sizes, *, width=None, recordsize=128 * KiB, ashift=12, fs=None, ext4_reserve=True) -> dict:
    """Usable space, parity and overhead for a pool. Sizes are bytes; returns floats in bytes."""
    sizes = [s for s in sizes if s]
    n, raw = len(sizes), float(sum(sizes))
    r = {'raw': raw, 'usable': 0.0, 'parity': 0.0, 'overhead': 0.0, 'fs_reserve': 0.0, 'waste': 0.0,
         'unused': 0.0, 'tolerance': 0, 'layout': f'{kind} {level}'}
    if not n:
        return r
    kind, level = (kind or '').lower(), (level or '').lower()
    if kind == 'zfs':
        P = {'raidz': 1, 'raidz1': 1, 'raidz2': 2, 'raidz3': 3}.get(level, 0)
        if level == 'mirror':
            w = max(2, min(width or 2, n))
        elif level in ('stripe', 'disk', ''):
            w = 1
        else:
            w = max(P + 1, min(width or n, n))
        groups, data, pad = n // w, 0.0, 0.0
        for g in range(groups):
            v = sizes[g * w:(g + 1) * w]
            m = min(v)
            r['waste'] += sum(v) - m * w
            if level == 'mirror':
                data += m
                r['parity'] += m * (w - 1)
            elif w == 1:
                data += m
            else:
                actual = m * w * raidz_efficiency(w, P, recordsize, ashift)
                data += actual
                r['parity'] += m * P
                pad += (w - P) * m - actual
        r['unused'] = float(sum(sizes[groups * w:]))
        slop = min(data / 32, 128 * GiB)
        r['overhead'] = pad + slop
        r['usable'] = data - slop
        r['tolerance'] = w - 1 if level == 'mirror' else P
        r['layout'] = f'zfs {level}' + (f' · {groups}×{w}-wide' if w > 1 else f' · {n} single-disk vdevs')
    elif kind in ('md', 'mdadm') or (kind == 'lvm' and level.startswith('raid')):   # LVM RAID is md raid underneath
        m = min(sizes)
        r['waste'] = raw - m * n
        lv = level.replace('raid', '')
        data, parity, tol = {'0': (n * m, 0, 0), '1': (m, (n - 1) * m, n - 1), '5': ((n - 1) * m, m, 1),
                             '6': ((n - 2) * m, 2 * m, 2), '10': (n * m / 2, n * m / 2, 1)}.get(lv, (n * m, 0, 0))
        reserve = data * FS_RESERVE.get(fs or '', lambda _: 0.0)(ext4_reserve)
        r.update(parity=float(parity), tolerance=tol, fs_reserve=reserve, usable=data - reserve,
                 layout=f'{"LVM" if kind == "lvm" else "mdadm"} {level} · {n} {"legs" if kind == "lvm" else "members"}')
    elif kind == 'btrfs' and level in ('raid5', 'raid6'):
        p = 1 if level == 'raid5' else 2               # parity per stripe; stripes span the devices with space left
        par = float(sum(sorted(sizes)[-p:])) if n > p else raw
        data = raw - par
        meta = data * 0.01 + 512 * MiB
        r.update(parity=par, overhead=meta, usable=data - meta, tolerance=p if n > p else 0,
                 layout=f'btrfs {level} · {n} devices')
    elif kind == 'btrfs':
        copies = {'raid1': 2, 'raid1c3': 3, 'raid1c4': 4, 'raid10': 2}.get(level, 1)
        data = raw if copies == 1 else _btrfs_alloc(sizes, copies, level == 'raid10')
        meta = data * 0.01 + 512 * MiB
        r.update(parity=data * (copies - 1), waste=max(0.0, raw - data * copies), overhead=meta,
                 usable=data - meta, tolerance=copies - 1, layout=f'btrfs {level} · {n} devices')
    else:
        reserve = raw * FS_RESERVE.get(fs or '', lambda _: 0.0)(ext4_reserve)
        r.update(usable=raw - reserve, fs_reserve=reserve, layout=f'{kind or "linear"} {level}'.strip())
    r['usable'] = max(0.0, r['usable'])      # too few devices for the level: nothing usable, never less
    return r


def forecast(points: list[tuple[int, int]], total: int, window: int = 30 * 86400) -> int | None:
    """Days until full from (time, used bytes), by a least-squares line over the last window. None when flat, shrinking,
    or there is under a day of history to draw a line through."""
    if not points or not total:
        return None
    newest = max(t for t, _ in points)
    recent = [(t, u) for t, u in points if t >= newest - window]
    if len(recent) < 2 or newest - min(t for t, _ in recent) < 86400:
        return None
    mt, mu = sum(t for t, _ in recent) / len(recent), sum(u for _, u in recent) / len(recent)
    spread = sum((t - mt) ** 2 for t, _ in recent)
    slope = sum((t - mt) * (u - mu) for t, u in recent) / spread if spread else 0
    if slope * 86400 < 1 << 20:      # under 1 MiB a day is noise
        return None
    last = max(recent)[1]
    return max(0, round((total - last) / (slope * 86400)))


def trends(conn, host: str | None = None, days: int = 30) -> list[dict]:
    """Per real mount: its usage over the last days and when it fills up at this rate. A filesystem counts once."""
    import time
    since = int(time.time()) - days * 86400
    rows = conn.all("""SELECT h.hostname, u.mount_point, u.at, u.used_bytes, u.total_bytes FROM mount_usage u JOIN hosts h ON h.host_id = u.host_id
                         WHERE u.at >= :s ORDER BY h.hostname, u.mount_point, u.at""", {'s': since})
    series: dict[tuple, list] = {}
    for name, mp, at, used, total in rows:
        if not host or name == host:
            series.setdefault((name, mp), []).append((at, used, total))
    out = []
    for (name, mp), pts in series.items():
        total = pts[-1][2]
        out.append({'host': name, 'mount': mp, 'used': pts[-1][1], 'total': total, 'points': [[t, u] for t, u, _ in pts],
                    'days_left': forecast([(t, u) for t, u, _ in pts], total)})
    return out


# key: (label, idle W, active W, spin-up W per drive). Typical datasheet figures for the class, not measurements.
POWER_CLASSES = {
    'nvme-gen5': ('NVMe SSD · PCIe Gen5', 5.0, 11.0, 0.0),
    'nvme-gen4': ('NVMe SSD · PCIe Gen4', 3.5, 8.0, 0.0),
    'nvme-gen3': ('NVMe SSD · PCIe Gen3', 2.5, 6.0, 0.0),
    'ssd': ('SATA/SAS SSD', 0.6, 3.5, 0.0),
    'hdd-enterprise': ('3.5" HDD · enterprise helium', 5.5, 9.5, 24.0),
    'hdd-nas': ('3.5" HDD · NAS / desktop', 4.0, 6.5, 22.0),
    'hdd-25': ('2.5" HDD', 1.0, 2.2, 5.0),
    'network': ('Network LUN (powered at its target)', 0.0, 0.0, 0.0),
}


def classify_drive(d: dict) -> str:
    bus, media, model = (d.get('bus') or '').lower(), (d.get('media') or '').lower(), (d.get('model') or '').lower()
    size = d.get('size') or 0
    if 'iscsi' in bus or media == 'net' or 'nbd' in bus:
        return 'network'
    if 'nvme' in bus or 'nvme' in media:
        if 'gen5' in bus or '5.0' in bus:
            return 'nvme-gen5'
        if 'gen3' in bus or '3.0' in bus:
            return 'nvme-gen3'
        return 'nvme-gen4'
    if media == 'ssd':
        return 'ssd'
    if media == 'hdd':
        if any(k in model for k in ('exos', 'ultrastar', 'ironwolf pro', 'wd gold', 'mg0', 'he1', 'he2')) or size >= 12e12:
            return 'hdd-enterprise'
        if '2.5' in model:
            return 'hdd-25'
        return 'hdd-nas'
    return 'ssd' if 'ssd' in model else 'hdd-nas'


def power_budget(disks: list[dict], idle_share: float = 0.75, kwh_price: float | None = None) -> dict:
    groups: dict[str, list[str]] = {}
    for d in disks:
        groups.setdefault(classify_drive(d), []).append(d['dev'])
    rows, idle, active, spin = [], 0.0, 0.0, 0.0
    for key in POWER_CLASSES:
        devs = groups.get(key)
        if not devs:
            continue
        label, i, a, s = POWER_CLASSES[key]
        n = len(devs)
        rows.append({'key': key, 'label': label, 'count': n, 'devices': devs, 'idle_each': i, 'active_each': a,
                     'idle_total': i * n, 'active_total': a * n, 'spinup_total': s * n})
        idle, active, spin = idle + i * n, active + a * n, spin + s * n
    blended = idle * idle_share + active * (1 - idle_share)
    kwh = blended * 8760 / 1000
    return {'rows': rows, 'idle': idle, 'active': active, 'spinup': spin, 'blended': blended,
            'idle_share': idle_share, 'kwh_year': kwh, 'cost_year': kwh * kwh_price if kwh_price else None,
            'kwh_price': kwh_price, 'btu_idle': idle * 3.412, 'btu_active': active * 3.412}
