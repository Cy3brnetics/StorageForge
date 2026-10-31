"""What StorageForge itself deployed, in the 3-2-1 matrix. Deployed mirror and rsnapshot jobs and scheduled storage
tasks fill the sync, snapshot and backup cells of the dataset holding their source, with their last good run. A row no
job or task covers keeps what was typed into the design, and so does a row whose job is later removed: the typed values
wait under row['hand'].
"""
from __future__ import annotations

import datetime as dt
import json

from .alerts import get_setting, set_setting
from .db import Conn, loads
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
        if j['method'] not in ('mirror', 'rsnapshot') or not j['src'] or host_slug(source) != host_slug(host):
            continue
        ok = j['last_ok'] or {}
        away = host_slug(j['runner']) != host_slug(source)
        fact = {'path': j['src'], 'why': f'job {j["name"]}', 'job': j['id']}
        if j['method'] == 'rsnapshot' and not away:
            fact['snapshots'] = {'enabled': True, 'tool': 'rsnapshot', 'policy': j['schedule'] or '', 'count': 0, 'overhead': 0}
        fact['backup'] = {'target': f'{j["runner"]}:{j["dst"]}', 'last': _date(ok.get('end') or ok.get('start')),
                          'offsite': away and host_slug(j['runner']) in offsite}
        if j['method'] == 'mirror':
            bad = {'failed': 'last run failed', 'stale': 'no good run on schedule', 'paused': 'paused'}.get(j['state'])
            fact['sync'] = {'state': 'Lagging' if bad else 'Rsync Scheduled', 'target': fact['backup']['target'], 'lag': bad or ''}
        out.append(fact)
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


def overlay(conn: Conn, host: str, rows: list[dict]) -> list[dict]:
    """A copy of the rows with what is deployed for this host filled in, marked row['deployed'] = [what covers it]."""
    out = []
    for r in rows or []:
        r = json.loads(json.dumps(r))
        r.update(r.pop('hand', None) or {})        # a saved row comes back as typed; the jobs below are looked up afresh
        r.pop('deployed', None)
        out.append(r)
    offsite = offsite_hosts(conn)
    live = [r for r in out if not r.get('ephemeral')]
    taken = {}
    for fact in _facts_from_jobs(conn, host, offsite) + _facts_from_tasks(conn, host, offsite):
        r = _row_for(fact, live)
        if r is None:
            continue
        if 'deployed' not in r:
            r['hand'] = {k: r.get(k) for k in CELLS}
            r['deployed'] = []
        r['deployed'].append(fact['why'])
        seen = taken.setdefault(id(r), {})
        for cell in ('sync', 'snapshots'):
            if cell in fact and cell not in seen:
                r[cell] = seen[cell] = fact[cell]
        if 'backup' in fact and _better(fact['backup'], seen.get('backup')):
            seen['backup'] = fact['backup']
            r['backup'] = {'enc': (r.get('backup') or {}).get('enc') or 'none', 'ratio': (r.get('backup') or {}).get('ratio') or 1, **fact['backup']}
    return out


def fill_node(conn: Conn, node: dict):
    """The graph and report: with no design, only the rows something deployed covers, not a matrix of red ones."""
    from .blueprint import from_node
    rows = node.get('protection') or []
    if rows:
        node['protection'] = overlay(conn, node['hostname'], rows)
    else:
        node['protection'] = [r for r in overlay(conn, node['hostname'], from_node(node)['protection']) if r.get('deployed')]
