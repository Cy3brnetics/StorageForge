"""Report sections 6 to 11: what the app has learned and deployed since the report was first written. Built from the same
functions the API uses, so the report and the web UI agree. A section that can't be built says so and the rest still print."""
from __future__ import annotations

import datetime as dt

from .capacity import fmt_bin, trends
from .db import Conn
from .report import code, table


def _when(ts) -> str:
    return dt.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M') if ts else 'never'


def _jobs(conn: Conn) -> list[str]:
    from .jobs import overview
    rows = [[code(j['name']), j['method'], j['source'] or '—', j['runner'], j['state'],
             _when((j['last'] or {}).get('end') or (j['last'] or {}).get('start')),
             _when((j['last_ok'] or {}).get('end') or (j['last_ok'] or {}).get('start'))] for j in overview(conn)]
    return table(['Job', 'Method', 'Source', 'Runs on', 'State', 'Last run', 'Last good run'], rows) if rows else ['No jobs are deployed.']


def _tasks(conn: Conn) -> list[str]:
    tasks = conn.all("SELECT host, ref, deployed_at FROM deployed WHERE kind = 'tasks' ORDER BY host, ref")
    moves = conn.scalar('SELECT count(*) FROM move_plans')
    plans = conn.scalar('SELECT count(*) FROM change_plans')
    lines = table(['Storage task', 'Host', 'Deployed'], [[code(r), h, _when(at)] for h, r, at in tasks]) if tasks else ['No storage tasks are deployed.']
    return [*lines, '', f'{moves} move plan(s) and {plans} change plan(s) are saved.']


def _alerts(conn: Conn) -> list[str]:
    from .alerts import drift, list_alerts
    open_ = list_alerts(conn, limit=1000)
    lines = table(['Alert', 'Detail', 'Since'], [[a['title'], a['message'] or '', _when(a['first_at'])] for a in open_]) if open_ else ['No open alerts.']
    changed = drift(conn)
    if changed:
        lines += ['', '**Changed by hand on the host**', '', *[f'- {d["host"]}: {d["text"]}' for d in changed]]
    return lines


def _capacity(conn: Conn) -> list[str]:
    rows = [t for t in trends(conn) if t['days_left'] is not None]
    if not rows:
        return ['No mount is on a course to fill up, or there is not yet a day of history.']
    return table(['Host', 'Mount', 'Used', 'Size', 'Full in about'],
                 [[t['host'], code(t['mount']), fmt_bin(t['used']), fmt_bin(t['total']), f'{t["days_left"]:,} days']
                  for t in sorted(rows, key=lambda t: t['days_left'])])


def _git(conn: Conn) -> list[str]:
    from .gitrepos import listing
    g = listing(conn)
    if not g['repos']:
        return ['No repositories found.']
    lines = ['States: ' + ', '.join(f'{k} {v}' for k, v in g['summary'].items() if v) + '.']
    at_risk = [r for r in g['repos'] if r['state'] in ('single copy', 'uncommitted', 'unpushed')]
    if at_risk:
        lines += ['', *table(['Repository', 'Host', 'State'], [[code(r['path']), r['host'], r['state']] for r in at_risk[:50]])]
        if len(at_risk) > 50:
            lines += ['', f'And {len(at_risk) - 50} more.']
    return lines


def _docker(conn: Conn) -> list[str]:
    from .docker import listing
    rows = [[h['host'] if 'host' in h else h.get('hostname'), s['project'] or 'standalone', s.get('state') or '',
             len(s.get('containers') or [])] for h in listing(conn) for s in h['stacks']]
    return table(['Host', 'Stack', 'State', 'Containers'], rows) if rows else ['No container engines found.']


def _shares_and_access(conn: Conn, nodes: list[dict]) -> list[str]:
    shares = [[n['hostname'], e.get('protocol') or e.get('proto') or '', code(e.get('path') or e.get('name')), ', '.join(e.get('clients') or []) if isinstance(e.get('clients'), list) else (e.get('clients') or '')]
              for n in nodes for e in n.get('exports') or []]
    lines = table(['Host', 'Protocol', 'Share', 'Clients'], shares) if shares else ['No NFS or SMB shares found.']
    denied = conn.all("""SELECT h.hostname, count(*) FROM scan_denied d JOIN scans s ON s.scan_id = d.scan_id JOIN hosts h ON h.host_id = s.host_id
                         WHERE s.scan_id = (SELECT max(x.scan_id) FROM scans x WHERE x.host_id = s.host_id AND x.status <> 'running')
                         GROUP BY h.hostname ORDER BY h.hostname""")
    if denied:
        lines += ['', '**Folders the last scan could not read**', '', *[f'- {h}: {n:,}' for h, n in denied]]
    return lines


def sections(conn: Conn, nodes: list[dict]) -> list[str]:
    out = []
    for title, build in (('6. Deployed Jobs', lambda: _jobs(conn)), ('7. Storage Tasks & Plans', lambda: _tasks(conn)),
                         ('8. Open Alerts & Drift', lambda: _alerts(conn)), ('9. Capacity Trend', lambda: _capacity(conn)),
                         ('10. Shares & Unreadable Folders', lambda: _shares_and_access(conn, nodes)),
                         ('11. Git Repositories & Containers', lambda: [*_git(conn), '', *_docker(conn)])):
        try:
            body = build()
        except Exception as exc:
            body = [f'This section could not be built: {exc}']
        out += [f'## {title}', '', *body, '']
    return out
