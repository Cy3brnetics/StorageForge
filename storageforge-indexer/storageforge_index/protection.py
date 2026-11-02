"""What StorageForge deployed or scans found, in the 3-2-1 matrix. Deployed mirror and rsnapshot jobs and scheduled storage
tasks fill the sync, snapshot and backup cells of the dataset holding their source, with their last good run. A row no
job or task covers keeps what was typed into the design, and so does a row whose job is later removed: the typed values
wait under row['hand'].
"""
from __future__ import annotations

import datetime as dt
import json

from .alerts import get_setting, set_setting
from .db import Conn, epoch, loads
from .moves import host_slug, slug
from .remote import is_under

CELLS = ('sync', 'snapshots', 'backup')
OFFSITE_KEY = 'hosts.offsite'


def offsite_hosts(conn: Conn) -> set[str]:
    return set(get_setting(conn, OFFSITE_KEY) or [])


def set_offsite(conn: Conn, host: str, offsite: bool, actor: str):
    hosts = offsite_hosts(conn) - {host_slug(host)}
    set_setting(conn, OFFSITE_KEY, sorted(hosts | ({host_slug(host)} if offsite else set())), actor)


def _date(ts) -> str | None:
    return dt.date.fromtimestamp(ts).isoformat() if ts else None


def _facts_from_jobs(conn: Conn, host: str, offsite: set[str]) -> list[dict]:
    from .jobs import overview
    out = []
    for j in overview(conn):
        source = j['source'] or j['runner']
        if j['method'] == 'snapper' and j['src'] and host_slug(source) == host_slug(host):
            out.append({'path': j['src'], 'why': f'job {j["name"]}', 'job': j['id'],
                        'snapshots': {'enabled': True, 'tool': 'snapper', 'policy': j['schedule'] or 'imported', 'count': j.get('count') or 0, 'overhead': 0}})
        if j['method'] not in ('mirror', 'rsnapshot'):
            continue
        places = j.get('places') or [{'host': source, 'path': s} for s in (j.get('sources') or ([j['src']] if j.get('src') else []))]
        here = [p['path'] for p in places if host_slug(p['host']) == host_slug(host)]
        if not here:
            continue
        ok = j['last_ok'] or {}
        away = host_slug(j['runner']) != host_slug(host)     # an imported rsnapshot can pull from other hosts, so ask per host
        fact = {'why': f'job {j["name"]}', 'job': j['id']}
        if j['method'] == 'rsnapshot' and not away:
            fact['snapshots'] = {'enabled': True, 'tool': 'rsnapshot', 'policy': j['schedule'] or '', 'count': 0, 'overhead': 0}
        fact['backup'] = {'target': f'{j["runner"]}:{j["dst"]}', 'last': _date(ok.get('end') or ok.get('start')),
                          'offsite': away and host_slug(j['runner']) in offsite}
        if j['method'] == 'mirror':
            bad = {'failed': 'last run failed', 'stale': 'no good run on schedule', 'paused': 'paused'}.get(j['state'])
            fact['sync'] = {'state': 'Lagging' if bad else 'Rsync Scheduled', 'target': fact['backup']['target'], 'lag': bad or ''}
        out.extend({**fact, 'path': src} for src in here)     # an imported rsnapshot can back up several
    return out


def _facts_from_tasks(conn: Conn, host: str, offsite: set[str]) -> list[dict]:
    from .tasks import walk
    bodies = {slug(b['name']): b for b in (json.loads(r[0]) for r in conn.all('SELECT body_json FROM storage_tasks'))}
    out = []
    for where, ref, detail in conn.all("SELECT host, ref, detail_json FROM deployed WHERE kind = 'tasks'"):
        task = bodies.get(ref)
        if not task or not (loads(detail) or {}).get('schedule', task['schedule']):
            continue
        good = conn.all("""SELECT finished_at, started_at FROM task_runs WHERE lower(host) = lower(:h) AND task = :t AND exit_code = 0
                           ORDER BY started_at DESC LIMIT 1""", {'h': where, 't': ref})
        last = _date(good[0][0] or good[0][1]) if good else None
        here = host_slug(where) == host_slug(host)
        why = f'task {task["name"]}'

        def backup(src_host, target_host, src, dst):
            if host_slug(src_host) == host_slug(host):
                away = host_slug(target_host) != host_slug(src_host)
                out.append({'path': src, 'why': why,
                            'backup': {'target': f'{target_host}:{dst}', 'last': last, 'offsite': away and host_slug(target_host) in offsite}})
        for _, b in walk(task['blocks']):
            if b['off']:
                continue
            t, p = b['type'], b['params']
            if t in ('rsync', 'rotate') and p['src'] and p['dst']:
                backup(p.get('src_host') or where, p.get('dst_host') or where, p['src'], p['dst'])
            elif t == 'btrfs_send' and p['into'] and p['dst']:
                backup(where, p['dst_host'] or where, p['into'], p['dst'])
            elif t == 'btrfs_snapshot' and here and p['subvol']:
                out.append({'path': p['subvol'], 'why': why,
                            'snapshots': {'enabled': True, 'tool': 'btrfs', 'policy': task['schedule'], 'count': 0, 'overhead': 0}})
            elif t == 'zfs_snapshot' and here and p['dataset']:
                out.append({'dataset': p['dataset'], 'why': why,
                            'snapshots': {'enabled': True, 'tool': 'zfs', 'policy': task['schedule'], 'count': 0, 'overhead': 0}})
            elif t == 'zfs_send' and here and p['dataset'] and p['dst']:
                target = p['dst_host'] or where
                out.append({'dataset': p['dataset'], 'why': why,
                            'backup': {'target': f'{target}:{p["dst"]}', 'last': last,
                                       'offsite': host_slug(target) != host_slug(where) and host_slug(target) in offsite}})
    return out


def _facts_detected(conn: Conn, host: str) -> list[dict]:
    """Backups nothing here deployed: restic, borg and rsnapshot folders in the index, and snapshots a scan saw."""
    row = conn.all('SELECT host_id, inventory_json FROM hosts WHERE lower(hostname) = lower(:h)', {'h': host})
    if not row:
        return []
    hid, inv = row[0]
    inv = inv if isinstance(inv, dict) else json.loads(inv or '{}')
    out = []
    tracked = [json.loads(r[0]).get('root') or '\0' for r in conn.all(     # already a job, so no second guess at what it backs up
        "SELECT spec_json FROM jobs WHERE plan_id IS NULL AND removed_at IS NULL AND method = 'rsnapshot' AND lower(runner_host) = lower(:h)", {'h': host})]
    # SQLite's filename index is NOCASE, so a plain = walks every file on the host: this runs on each design load
    indexed = 'f.filename = :n COLLATE NOCASE AND ' if conn.dialect == 'sqlite' else ''
    for name, tool, siblings in (('keys', 'restic', ('snapshots', 'index', 'data', 'config')), ('hints.1', 'borg', ('config', 'data', 'README')),
                                 ('daily.0', 'rsnapshot', ()), ('hourly.0', 'rsnapshot', ())):
        for dir_id, path, newest in conn.all(f"""SELECT d.dir_id, d.path, max(f.modified_at) FROM file_records f JOIN directories d ON d.dir_id = f.dir_id
                                                 JOIN mounts m ON m.mount_id = f.mount_id WHERE {indexed}m.host_id = :h AND f.filename = :n
                                                 GROUP BY d.dir_id, d.path""", {'h': hid, 'n': name}):
            if tool == 'rsnapshot' and any(is_under(path, r) for r in tracked):
                continue
            if all(conn.scalar('SELECT 1 FROM file_records WHERE dir_id = :d AND filename = :n', {'d': dir_id, 'n': s}) for s in siblings):
                out.append({'repo': path, 'why': f'detected {tool} at {path}', 'tool': tool, 'newest': epoch(newest)})
    snaps = inv.get('snapshots') or {}
    for ds, s in (snaps.get('zfs') or {}).items():
        out.append({'dataset': ds, 'why': f'detected {s["count"]} ZFS snapshots',
                    'snapshots': {'enabled': True, 'tool': 'zfs', 'policy': f'newest {_date(s["newest"])}', 'count': s['count'], 'overhead': 0}})
    for ds in snaps.get('sanoid') or []:
        out.append({'dataset': ds, 'why': 'detected a sanoid policy',
                    'snapshots': {'enabled': True, 'tool': 'sanoid', 'policy': 'sanoid.conf', 'count': 0, 'overhead': 0}})
    for name, path in (snaps.get('snapper_paths') or {}).items():
        out.append({'path': path, 'why': f'detected snapper config {name}',
                    'snapshots': {'enabled': True, 'tool': 'snapper', 'policy': f'config {name}', 'count': 0, 'overhead': 0}})
    for tool in snaps.get('tools') or []:         # both are set up for the system's own subvolumes as a rule, and their configs need root to read
        out.append({'path': '/', 'why': f'detected {tool}',
                    'snapshots': {'enabled': True, 'tool': tool, 'policy': f'{tool} is configured', 'count': 0, 'overhead': 0}})
    for target, b in ((inv.get('health') or {}).get('btrfs') or {}).items():
        if b.get('snapshots'):
            out.append({'path': target, 'why': f'detected {b["snapshots"]} btrfs snapshots',
                        'snapshots': {'enabled': True, 'tool': 'btrfs', 'policy': f'newest {b["newest_snapshot"][:10]}' if b.get('newest_snapshot') else 'read-only subvolumes',
                                      'count': b['snapshots'], 'overhead': b.get('snapshot_exclusive') or 0}})
    return out


def _row_for(fact: dict, rows: list[dict]) -> dict | None:
    if 'dataset' in fact:
        return next((r for r in rows if fact['dataset'] in (r.get('dataset'), str(r.get('node')).removeprefix('ds:'))), None)
    held = [r for r in rows if r.get('path') and is_under(fact['path'], r['path'])]
    return max(held, key=lambda r: len(r['path']), default=None)


def _better(new: dict, old: dict | None) -> bool:
    """One row, several backups: an offsite one wins, then the newest."""
    if not old or not old.get('target'):
        return True
    return (bool(new.get('offsite')), new.get('last') or '') > (bool(old.get('offsite')), old.get('last') or '')


def as_typed(rows: list[dict]) -> list[dict]:
    """Rows as the operator typed them, without what overlay filled in. A design is saved like this, and what is deployed
    is looked up afresh each time it is read."""
    out = []
    for r in rows or []:
        r = json.loads(json.dumps(r))
        r.update(r.pop('hand', None) or {})
        r.pop('deployed', None)
        out.append(r)
    return out


def overlay(conn: Conn, host: str, rows: list[dict]) -> list[dict]:
    """A copy of the rows with what is deployed for this host filled in, marked row['deployed'] = [what covers it]."""
    out = as_typed(rows)
    offsite = offsite_hosts(conn)
    live = [r for r in out if not r.get('ephemeral')]
    taken = {}

    def mark(r, why):
        if 'deployed' not in r:
            r['hand'] = {k: r.get(k) for k in CELLS}
            r['deployed'] = []
        r['deployed'].append(why)
    for fact in _facts_from_jobs(conn, host, offsite) + _facts_from_tasks(conn, host, offsite):
        r = _row_for(fact, live)
        if r is None:
            continue
        mark(r, fact['why'])
        seen = taken.setdefault(id(r), {})
        for cell in ('sync', 'snapshots'):
            if cell in fact and cell not in seen:
                r[cell] = seen[cell] = fact[cell]
        if 'backup' in fact and _better(fact['backup'], seen.get('backup')):
            seen['backup'] = fact['backup']
            r['backup'] = {'enc': (r.get('backup') or {}).get('enc') or 'none', 'ratio': (r.get('backup') or {}).get('ratio') or 1, **fact['backup']}
    for fact in _facts_detected(conn, host):
        if 'repo' in fact:      # it can't say what it backs up: the host's other datasets get it where they have nothing, never as offsite
            holder = _row_for({'path': fact['repo']}, live)
            for r in live:
                if r is not holder and not (r.get('backup') or {}).get('target'):
                    mark(r, fact['why'])
                    r['backup'] = {'target': f'{fact["tool"]} {fact["repo"]} (detected)', 'enc': 'unknown', 'ratio': 1, 'last': _date(fact['newest']), 'offsite': False}
            continue
        r = _row_for(fact, live)
        if r is not None and not (r.get('snapshots') or {}).get('enabled'):
            mark(r, fact['why'])
            r['snapshots'] = fact['snapshots']
    return out


def fill_node(conn: Conn, node: dict):
    """The graph and report: with no design, only the rows something deployed covers, not a matrix of red ones."""
    from .blueprint import from_node
    rows = node.get('protection') or []
    if rows:
        node['protection'] = overlay(conn, node['hostname'], rows)
    else:
        node['protection'] = [r for r in overlay(conn, node['hostname'], from_node(node)['protection']) if r.get('deployed')]
