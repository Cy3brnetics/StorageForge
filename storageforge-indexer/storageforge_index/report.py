"""StorageForge Architecture Report: renders one or more nodes as standardized Markdown.

The document is for people (headings, tables, an ASCII map) and for machines:
YAML front matter carries the headline numbers, every table keeps fixed
columns, and capacities are always written as binary first, decimal second.
"""
from __future__ import annotations

import datetime as dt

from .analysis import (boot_stages, use_pct, capacity_summary, containing_mount, findings, link_health,
                       local_disks, protection_status, real_mounts)
from .capacity import fmt_bin, fmt_dec, power_budget
from .health import unallocated

SEV_ICON = {'crit': '🔴', 'warn': '🟡', 'info': '🔵'}
PROT_LABEL = {'protected': '🟢 Protected', 'local-only': '🟡 Local Only', 'critical': '🔴 Critical', 'excluded': '⚪ Excluded'}
LINK_LABEL = {'ok': '🟢 OK', 'info': '🔵 Unverified', 'warn': '🟡 Warning', 'crit': '🔴 Broken'}
TIER_LABEL = {'fast': 'Fast NVMe/SSD', 'mass': 'Mass HDD', 'remote': 'Remote / mesh'}


def cell(v) -> str:
    if v is None or v == '' or v == []:
        return '—'
    return str(v).replace('|', '\\|').replace('\n', ' ')


def code(v) -> str:
    return f'`{str(v).replace("`", "ʼ").replace("|", chr(92) + "|")}`' if v not in (None, '', []) else '—'


def table(headers: list[str], rows: list[list], align: str | None = None) -> list[str]:
    align = align or 'l' * len(headers)
    sep = ['---:' if a == 'r' else ':---' for a in align]
    out = ['| ' + ' | '.join(headers) + ' |', '| ' + ' | '.join(sep) + ' |']
    out += ['| ' + ' | '.join(cell(c) if not str(c).startswith('`') else str(c) for c in r) + ' |' for r in rows]
    return out


def cap2(n, digits=2) -> str:
    return 'n/a' if n is None else f'{fmt_bin(n, digits)} · {fmt_dec(n, digits)}'


def ascii_map(node: dict) -> str:
    lines = [f'{node["hostname"]}  ({node["node_id"]})']
    mounts = real_mounts(node)

    def walk(items, prefix):
        for i, (text, kids) in enumerate(items):
            last = i == len(items) - 1
            lines.append(prefix + ('└── ' if last else '├── ') + text)
            if kids:
                walk(kids, prefix + ('    ' if last else '│   '))

    def links_on(target):
        out = []
        for l in node['links']:
            cm = containing_mount(l['target'] if l['target'].startswith('/') else l['path'], mounts)
            if cm and cm['target'] == target:
                arrow = {'symlink': '⇠', 'bind': '⇇', 'hardlink': '⇔'}.get(l['kind'], '·')
                flag = {'crit': '  ✗ broken', 'warn': '  ! warning'}.get(l.get('state'), '')
                out.append((f'{arrow} {l["path"]} ({l["kind"]}){flag}', None))
        return out or None

    tiers = []
    for tier, label in (('fast', 'FAST TIER'), ('mass', 'MASS TIER'), ('remote', 'REMOTE / MESH')):
        kids = []
        for d in (d for d in node['disks'] if d.get('tier') == tier):
            if d.get('member') and not d['parts']:
                dk = [(f'whole disk → pool {d["member"]}', None)]
            else:
                dk = []
                for p in d['parts']:
                    short = p['dev'].removeprefix(d['dev'])
                    head = f'{short:<4} {p.get("fs") or "—":<17} {fmt_bin(p.get("size")):>11}'
                    if p.get('member'):
                        dk.append((f'{head} → {p["member"]} ({p.get("role") or "data"})', None))
                    elif p.get('subvols'):
                        dk.append((head, [(f'{sv["name"]} → {sv["mount"]}', links_on(sv['mount'])) for sv in p['subvols'] if sv.get('mount')]))
                    elif p.get('mount'):
                        dk.append((f'{head} → {p["mount"]}', links_on(p['mount'])))
                    else:
                        dk.append((head, None))
            kids.append((f'{d["dev"]:<8} {d.get("model") or "?"} [{d.get("bus") or "?"}] {fmt_bin(d.get("size"))}', dk))
        for p in (p for p in node['pools'] if p.get('tier') == tier):
            usable = f'  usable {fmt_bin(p["cap"]["usable"])}' if p.get('cap') else ''
            pk = [(f'data: {" ".join(p["members"])}', None)]
            if p.get('log'):
                pk.append((f'log (SLOG): {" ".join(p["log"])}', None))
            if p.get('cache'):
                pk.append((f'cache (L2ARC): {" ".join(p["cache"])}', None))
            if p.get('mount'):
                pk.append((f'{p.get("fs") or p["name"]} → {p["mount"]}', links_on(p['mount'])))
            for ds in p.get('datasets') or []:
                props = ' '.join(f'{k}={v}' for k, v in (ds.get('props') or {}).items() if k != 'sync')
                pk.append((f'{ds["name"]} → {ds.get("mount") or "(no mountpoint)"}{"  [" + props + "]" if props else ""}',
                           links_on(ds['mount']) if ds.get('mount') else None))
            kids.append((f'{p["name"]}  {p["type"]} {p.get("level") or "?"}{usable}', pk))
        if tier == 'remote':
            for r in node['remotes']:
                state = '' if r.get('status') in (None, 'connected') else f'  ✗ {r["status"]}'
                kids.append((f'{r.get("endpoint")}  {r.get("proto")} via {r.get("via")} → {r.get("mount")}{state}',
                             links_on(r['mount']) if r.get('mount') else None))
        if kids:
            tiers.append((f'[{label}]', kids))
    walk(tiers, '')
    return '\n'.join(lines)


def _sync_text(row):
    s = row.get('sync') or {}
    state = s.get('state') or 'None'
    if state == 'None':
        return 'None'
    extra = ', '.join(x for x in (s.get('target'), f'lag {s["lag"]}' if s.get('lag') else None) if x)
    return f'{state} ({extra})' if extra else state


def _btrfs_section(nodes):
    """Space btrfs has handed out and what it holds, which df does not show. Scrub, errors and the rest need the collector."""
    rows = []
    for n in nodes:
        for fs in n.get('btrfs_fs') or []:
            if not fs.get('dev'):
                continue
            free = unallocated(fs)
            meta = fs.get('metat', 0) - fs.get('metau', 0) - fs.get('rsv', 0)
            saved = f'{100 * (1 - fs["disk_bytes"] / fs["uncompressed_bytes"]):.0f}%' if fs.get('uncompressed_bytes') else '—'
            snaps = f'{fs["snapshots"]}' if fs.get('snapshots') else '—'
            if fs.get('snapshot_exclusive'):
                snaps += f' ({fmt_bin(fs["snapshot_exclusive"])} alone)'
            rows.append([code(fs['name']), n['hostname'], '/'.join(['+'.join(fs['datas']), '+'.join(fs['metas'])]), fmt_bin(fs['dev']),
                         fmt_bin(free) if free is not None else 'unknown', fmt_bin(max(meta, 0)), fs.get('last_scrub') or '—', snaps, saved])
    if not rows:
        return []
    return ['### btrfs space and upkeep', ''] + table(
        ['Filesystem', 'Host', 'Data/metadata', 'Devices', 'Unallocated', 'Metadata free', 'Last scrub', 'Snapshots', 'Compression saved'], rows, 'lllrrrlll') + [
        '', '- Writes fail when unallocated space and free metadata both run out, even if df shows room. A "Reclaim free space" task returns half-empty chunks.', '']


def _snap_text(row):
    s = row.get('snapshots') or {}
    if not s.get('enabled'):
        return 'None'
    return f'{s.get("tool")}: {s.get("policy")}' if s.get('policy') else (s.get('tool') or 'Enabled')


def _backup_text(row, as_of):
    b = row.get('backup') or {}
    if not b.get('target'):
        return 'None'
    where = 'offsite' if b.get('offsite') else 'same site'
    validated = f'validated {b["last"]}' if b.get('last') else 'never validated'
    enc = f', {b["enc"]}' if b.get('enc') and b['enc'] != 'none' else ', unencrypted'
    return f'{b["target"]} ({where}{enc}; {validated})'


def render_report(nodes: list[dict], title: str | None = None, as_of: dt.date | None = None,
                  kwh_price: float | None = None, currency: str = '', idle_share: float = 0.75,
                  extra: list[str] | None = None) -> str:
    as_of = as_of or dt.date.today()
    generated = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')
    for n in nodes:
        for l in n['links']:
            l['state'], l['note'] = link_health(l, n)
    sums = [capacity_summary(n) for n in nodes]
    finds = [findings(n, as_of) for n in nodes]
    power = power_budget([d for n in nodes for d in n['disks']], idle_share, kwh_price)
    prot = [(n, r, *protection_status(r, as_of)) for n in nodes for r in n['protection']]

    def total(key):
        vals = [s[key] for s in sums]
        return None if any(v is None for v in vals) else sum(vals)

    raw, usable, alloc, free = total('raw'), total('usable'), total('allocated'), total('free')
    crit = sum(f['sev'] == 'crit' for fs in finds for f in fs)
    warn = sum(f['sev'] == 'warn' for fs in finds for f in fs)
    pcount = {k: sum(1 for *_, st, _w in prot if st == k) for k in PROT_LABEL}
    name = title or (nodes[0]['hostname'] if len(nodes) == 1 else f'{len(nodes)}-node storage network')
    scope = 'single-host' if len(nodes) == 1 else 'network'

    L = ['---', 'report: storageforge-architecture', 'schema_version: 1', f'system: {name}', f'scope: {scope}',
         f'generated_at: {generated}', f'as_of: {as_of.isoformat()}',
         'nodes: [' + ', '.join(n['hostname'] for n in nodes) + ']', 'capacity_bytes:',
         f'  raw: {int(raw)}', f'  usable: {int(usable)}',
         f'  allocated: {int(alloc) if alloc is not None else "null"}',
         f'  free: {int(free) if free is not None else "null"}',
         'protection: {' + ', '.join(f'{k.replace("-", "_")}: {v}' for k, v in pcount.items()) + '}',
         f'findings: {{critical: {crit}, warning: {warn}}}',
         f'power_watts: {{idle: {power["idle"]:.1f}, active: {power["active"]:.1f}}}', '---', '']

    L += [f'# StorageForge Architecture Report: {name}', '',
          f'> Generated {generated} · data as of {as_of.isoformat()} · scope: {scope} · '
          f'{crit} critical and {warn} warning findings', '']

    # 1. executive summary
    L += ['## 1. Executive Summary & Topology Blueprint', '', '### 1.1 System identity', '']
    L += table(['Node', 'Node ID', 'IP address', 'Operating system', 'Last scanned', 'Inputs'],
               [[code(n['hostname']), code(n['node_id']), n.get('ip'), n.get('os'),
                 dt.datetime.fromtimestamp(n['last_scanned'], dt.timezone.utc).strftime('%Y-%m-%d %H:%M UTC') if n.get('last_scanned') else 'not scanned (design input)',
                 '; '.join(n['sources'])] for n in nodes])
    L += ['', '### 1.2 Capacity', '']
    remote_total = sum(s['remote_total'] for s in sums)
    rows = [['Raw capacity', fmt_bin(raw), fmt_dec(raw), f'{sum(len(local_disks(n)) for n in nodes)} local block devices'],
            ['Usable capacity', fmt_bin(usable), fmt_dec(usable), f'{usable / raw * 100:.1f}% of raw after parity, mirrors, padding and reserves' if raw else ''],
            ['Allocated', fmt_bin(alloc), fmt_dec(alloc), f'{alloc / usable * 100:.1f}% of usable (from df)' if alloc is not None and usable else 'no df/findmnt data in the inputs'],
            ['Free headroom', fmt_bin(free), fmt_dec(free), 'usable − allocated' if free is not None else '—']]
    if remote_total:
        rows.append(['Remote / mesh (attached)', fmt_bin(remote_total), fmt_dec(remote_total), 'network mounts, not counted above'])
    L += table(['Metric', 'Binary', 'Decimal', 'Notes'], rows, 'lrrl')
    L += ['', '### 1.3 Key findings', '']
    flat = [(n, f) for n, fs in zip(nodes, finds) for f in fs]
    if not flat:
        L.append('No findings: every mount resolves, every link is healthy and every dataset has a protected copy.')
    for i, (n, f) in enumerate(flat, 1):
        host = f' ({n["hostname"]})' if len(nodes) > 1 else ''
        L.append(f'{i}. {SEV_ICON[f["sev"]]} **{f["title"]}**{host}. {f["detail"]}')
    L += ['', '### 1.4 Topology map', '',
          'Flow: physical device or remote target → pool / RAID → partition or dataset → mount point → link.', '',
          '```text']
    for n in nodes:
        L += [ascii_map(n), '']
    L[-1] = '```'
    L.append('')
    L += ['Legend: `⇠` symlink · `⇇` bind mount · `⇔` hard link · `✗` broken or offline.', '']

    # 2. inventory
    L += ['## 2. Node & Disk Inventory', '']
    for idx, n in enumerate(nodes, 1):
        L += [f'### 2.{idx} `{n["hostname"]}`', '', '#### Drives', '']
        L += table(['Device', 'Model', 'Serial', 'Interface', 'Media', 'Capacity', 'Sectors (L/P)', 'Table', 'Tier', 'Role'],
                   [[code('/dev/' + d['dev']), d.get('model'), code(d.get('serial')), d.get('bus'),
                     {'ssd': 'NVMe' if 'nvme' in (d.get('bus') or '').lower() else 'SSD', 'hdd': 'HDD', 'net': 'Network LUN'}.get(d.get('media'), d.get('media')),
                     cap2(d.get('size')), f'{d.get("log_sec") or "?"}/{d.get("phy_sec") or "?"}',
                     (d.get('table') or '—').upper(), TIER_LABEL.get(d.get('tier'), d.get('tier')),
                     f'whole-disk member of {d["member"]}' if d.get('member') else
                     ', '.join(sorted({p.get('member') or p.get('fs') or '?' for p in d['parts']})) or 'unpartitioned']
                    for d in n['disks']], 'llllllllll')
        parts = [(d, p) for d in n['disks'] for p in d['parts']]
        if parts:
            L += ['', '#### Partition layout', '']
            L += table(['Partition', 'Start', 'Size', 'Aligned', 'Filesystem', 'Label', 'Mount / membership'],
                       [[code('/dev/' + p['dev']), f'{p["start"] // 512} s' if p.get('start') is not None else '?',
                         cap2(p.get('size')), '✅ 1 MiB' if (p.get('start') or 0) % (1024 * 1024) == 0 else '❌ no',
                         p.get('fs'), code(p.get('label')),
                         f'{p["member"]} ({p.get("role") or "data"})' if p.get('member') else
                         ', '.join(f'{sv["name"]}→{sv["mount"]}' for sv in p['subvols'] if sv.get('mount')) if p.get('subvols') else p.get('mount')]
                        for d, p in parts], 'lrrllll')
        if n['pools']:
            L += ['', '#### Pools & arrays', '']
            L += table(['Pool', 'Type', 'Layout', 'Data members', 'Log / cache', 'Usable', 'Fault tolerance', 'Health'],
                       [[code(p['name']), p['type'], p['cap']['layout'] if p.get('cap') else p.get('level'),
                         ' '.join(p['members']), ' '.join([*(f'log:{x}' for x in p.get('log') or []), *(f'cache:{x}' for x in p.get('cache') or [])]) or '—',
                         cap2(p['cap']['usable']) if p.get('cap') else 'n/a',
                         f'{p["cap"]["tolerance"]} drive{"s" if p["cap"]["tolerance"] != 1 else ""}' if p.get('cap') and p['cap']['tolerance'] is not None else 'depends on profile',
                         ' · '.join(x for x in (p.get('health'), (p.get('scan') or '')[:90]) if x) or 'not reported']
                        for p in n['pools']])
            ds_rows = [[code(ds['name']), code(ds.get('mount')), ', '.join(f'{k}={v}' for k, v in (ds.get('props') or {}).items()),
                        p.get('encryption') or '—'] for p in n['pools'] for ds in p.get('datasets') or []]
            if ds_rows:
                L += ['', '#### Datasets & subvolumes', '']
                sv_rows = [[code(sv['name']), code(sv.get('mount')), f'btrfs on /dev/{p["dev"]}', '—']
                           for d in n['disks'] for p in d['parts'] for sv in p.get('subvols') or []]
                L += table(['Dataset / subvolume', 'Mountpoint', 'Properties', 'Encryption'], sv_rows + ds_rows)
        L += ['', '#### Filesystems & mount points', '']
        mrows = []
        for m in sorted(real_mounts(n), key=lambda m: m['target']):
            if m.get('kind') == 'bind':
                continue
            pct = f'{use_pct(m):.0f}%' if use_pct(m) is not None else '—'
            ident = m.get('spec') if m.get('kind') not in ('zfs',) else f'{m.get("source")} (zfs mountpoint)'
            mrows.append([code(m['target']), m.get('fstype'), code(m.get('source')), code(ident),
                          code(','.join(o for o in m.get('options') or [] if o)) if m.get('options') else '—',
                          fmt_bin(m.get('total')) if m.get('total') else '—', fmt_bin(m.get('used')) if m.get('used') is not None else '—', pct])
        L += table(['Mount point', 'FS', 'Source', 'fstab identifier', 'Mount flags', 'Size', 'Used', 'Use%'], mrows, 'llllllrr')
        L.append('')

    # 3. links
    L += ['## 3. Symbolic Link & Mount Binding Hierarchy', '']
    lrows = []
    for n in nodes:
        for l in n['links']:
            backing = containing_mount(l['target'] if l['target'].startswith('/') else l['path'], real_mounts(n))
            lrows.append([code(l['path']), code(l['target']),
                          {'symlink': 'Soft symlink', 'bind': 'Bind mount', 'hardlink': 'Hard link'}.get(l['kind'], l['kind']),
                          code(backing['target']) if backing else '—', LINK_LABEL[l['state']], l['note']]
                         + ([n['hostname']] if len(nodes) > 1 else []))
    if lrows:
        L += table(['Source path (link)', 'Target path', 'Mount type', 'Backing mount', 'Health', 'Check']
                   + (['Node'] if len(nodes) > 1 else []), lrows)
    else:
        L.append('No symlinks, bind mounts or hard links in the inputs.')
    if any(n.get('index_symlinks') for n in nodes):
        for n in nodes:
            s = n.get('index_symlinks')
            if s:
                L += ['', f'Index check on `{n["hostname"]}`: {s["checked"]:,} symlinks examined, {s["reported"]:,} listed '
                      f'(broken, looping or crossing a mount boundary)'
                      + (f'; {s["system"]:,} OS-managed links skipped' if s.get('system') else '') +
                      f'{"; symlink scan capped" if s["capped"] else ""}.']
    L += ['', '### 3.1 Boot sequence and ordering dependencies', '',
          'Each stage mounts only after every mount it depends on. Bind mounts carry '
          '`x-systemd.requires-mounts-for=<source>`; network mounts wait for `network-online.target`.', '']
    for n in nodes:
        if len(nodes) > 1:
            L += [f'**{n["hostname"]}**', '']
        for i, stage in enumerate(boot_stages(n)):
            items = []
            for e in stage:
                after = [a for a in e['after']]
                items.append(f'`{e["mount"]["target"]}`' + (f' (after {", ".join(after)})' if after else ''))
            L.append(f'{i + 1}. Stage {i}: ' + '; '.join(items))
        L.append('')
    warn_links = [(n, l) for n in nodes for l in n['links'] if l['state'] in ('crit', 'warn')]
    L += ['### 3.2 Link warnings', '']
    if warn_links:
        L += [f'- {SEV_ICON[l["state"]]} `{l["path"]}` → `{l["target"]}`: {l["note"]}.' for n, l in warn_links]
    else:
        L.append('- None.')
    L.append('')

    # 4. protection
    L += ['## 4. Resilience & Data Protection Matrix (3-2-1 Health Audit)', '']
    if prot:
        L += table(['Dataset / Path', 'Tier', 'Replication / Sync', 'Snapshot Retention', 'Offsite Backup Target', 'Protection Status'],
                   [[code(r.get('path') or r.get('dataset')), TIER_LABEL.get(r.get('tier'), r.get('tier')), _sync_text(r),
                     _snap_text(r), _backup_text(r, as_of), PROT_LABEL[st]] for n, r, st, why in prot])
        L += ['', '**Status rationale**', '']
        L += [f'- `{r.get("dataset")}` ({PROT_LABEL[st]}): {"; ".join(why)}.' for n, r, st, why in prot]
        L += ['', 'Rules: 🟢 needs snapshots plus an offsite backup validated within 30 days and healthy replication. '
              '🔴 means lagging or disconnected replication, a backup not validated for 90 days, or no snapshot and no backup. '
              'Everything else is 🟡.']
    else:
        L.append('No protection data in the inputs. Supply a StorageForge blueprint (`--blueprint`) to audit sync, '
                 'snapshot and backup state per dataset.')
    L.append('')

    # 5. economics
    L += ['## 5. Storage Economics & Operational Overhead', '', '### 5.1 Parity & reserve overhead', '']
    erows, t = [], {'raw': 0.0, 'parity': 0.0, 'overhead': 0.0, 'fs_reserve': 0.0, 'waste': 0.0, 'usable': 0.0}
    for n, s in zip(nodes, sums):
        for p in s['pools']:
            c = p['cap']
            erows.append([code(p['name']), c['layout'], fmt_bin(c['raw']), fmt_bin(c['parity']), fmt_bin(c['overhead']),
                          fmt_bin(c['fs_reserve'] + c['waste'] + c['unused']), fmt_bin(c['usable']),
                          f'{c["usable"] / c["raw"] * 100:.1f}%' if c['raw'] else '—'])
            for k in t:
                t[k] += c[k]
            t['fs_reserve'] += c['waste'] + c['unused']
        for d, p in s['standalone']:
            erows.append([code('/dev/' + p['dev']), f'{p.get("fs")} single device', fmt_bin(p['size']), fmt_bin(0), fmt_bin(0),
                          fmt_bin(0), fmt_bin(p['size']), '100.0%'])
            t['raw'] += p['size']
            t['usable'] += p['size']
    erows.append(['**Total**', '', f'**{fmt_bin(t["raw"])}**', f'**{fmt_bin(t["parity"])}**', f'**{fmt_bin(t["overhead"])}**',
                  f'**{fmt_bin(t["fs_reserve"])}**', f'**{fmt_bin(t["usable"])}**',
                  f'**{t["usable"] / t["raw"] * 100:.1f}%**' if t['raw'] else '—'])
    L += table(['Volume', 'Layout', 'Raw', 'Parity / mirror', 'Padding & slop', 'FS reserve & waste', 'Usable', 'Efficiency'],
               erows, 'llrrrrrr')
    unpart = sum((d.get('size') or 0) - sum(p.get('size') or 0 for p in d['parts']) for n in nodes for d in local_disks(n) if not d.get('member'))
    L += ['', f'Unallocated or unaddressable space outside any volume: {cap2(unpart)}. '
          'Partition sizes are counted as usable before filesystem metadata; ZFS figures assume 128 KiB records.', '']
    L += _btrfs_section(nodes)
    L += ['### 5.2 Power & thermal budget', '']
    L += table(['Drive class', 'Count', 'Idle W / drive', 'Active W / drive', 'Idle total', 'Active total', 'Devices'],
               [[r['label'], r['count'], f'{r["idle_each"]:.1f}', f'{r["active_each"]:.1f}', f'{r["idle_total"]:.1f} W',
                 f'{r["active_total"]:.1f} W', ' '.join(r['devices'])] for r in power['rows']]
               + [['**Total**', sum(r['count'] for r in power['rows']), '', '', f'**{power["idle"]:.1f} W**',
                   f'**{power["active"]:.1f} W**', '']], 'lrrrrrl')
    L += ['', f'- Heat load: {power["btu_idle"]:.0f} BTU/h idle, {power["btu_active"]:.0f} BTU/h under load (W × 3.412).',
          f'- Annual energy at {power["idle_share"] * 100:.0f}% idle / {100 - power["idle_share"] * 100:.0f}% active: '
          f'{power["blended"]:.1f} W average, {power["kwh_year"]:.0f} kWh/year'
          + (f', about {currency}{power["cost_year"]:.0f}/year at {currency}{kwh_price:.2f}/kWh.' if power['cost_year'] else '.'),
          f'- Spin-up surge: {power["spinup"]:.0f} W on the 12 V rail if every hard drive starts at once. '
          + ('Enable staggered spin-up on the HBA or backplane.' if power['spinup'] > 150 else 'Within typical PSU headroom.'),
          '- Drive power excludes the host, HBA, fans and the remote targets. Figures are class averages from datasheets, '
          'not measurements; replace them with wall readings when you have them.', '']

    # appendix: file index
    L += extra or []
    indexed = [n for n in nodes if n.get('index')]
    if indexed:
        L += ['## Appendix A. File index snapshot', '']
        for n in indexed:
            ix = n['index']
            last = ix.get('last_scan') or {}
            L += [f'### `{n["hostname"]}`', '']
            if last:
                L += [f'Last scan #{last["scan_id"]} ({last["status"]}): {last["entries"]:,} entries, '
                      f'+{last["added"]:,} / ~{last["modified"]:,} / -{last["deleted"]:,} since the previous scan, '
                      f'{last["read_errors"]:,} unreadable paths, {(last["duration_ms"] or 0) / 1000:.1f} s.', '']
            L += table(['Mount', 'FS', 'Entries', 'Directories', 'Symlinks', 'Indexed bytes'],
                       [[code(r['mount']), r['fstype'], f'{r["entries"]:,}', f'{r["dirs"]:,}', f'{r["symlinks"]:,}', cap2(r['bytes'])]
                        for r in ix['by_mount']], 'llrrrr')
            if ix['top_ext']:
                L += ['', '**Largest file types**', '']
                L += table(['Extension', 'Files', 'Bytes'], [[code('.' + r['ext']), f'{r["files"]:,}', cap2(r['bytes'])] for r in ix['top_ext']], 'lrr')
            if ix['largest']:
                L += ['', '**Largest files**', '']
                L += table(['Path', 'Size', 'Modified'],
                           [[code(r['path']), cap2(r['bytes']), dt.datetime.fromtimestamp(r['mtime'], dt.timezone.utc).strftime('%Y-%m-%d')]
                            for r in ix['largest']], 'lrl')
            if ix['dup_groups']:
                L += ['', f'Duplicates: {ix["dup_groups"]:,} groups of identical files, {cap2(ix["dup_reclaimable"])} reclaimable '
                      '(`storageforge-index dupes`).']
            L.append('')

    L += ['## Appendix B. Method', '',
          '- Binary units (KiB, MiB, GiB, TiB = 2¹⁰ … 2⁴⁰ bytes) come first, decimal units (KB … TB = 10³ … 10¹² bytes) second. '
          'Drive labels use decimal; `df -h`, `lsblk` and ZFS use binary.',
          '- RAIDZ usable space includes allocation padding for 128 KiB records and the 1/32 slop reservation (capped at 128 GiB). '
          'mdadm arrays include ext4 root reserve and inode tables where ext4 is used.',
          '- Allocated space counts each filesystem once, even when several subvolumes or bind mounts expose it.',
          '- Protection status follows the StorageForge dashboard rules and uses the "as of" date above.', '']
    return '\n'.join(L)
