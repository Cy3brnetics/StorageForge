"""What has been done, in one list: the audit log, deploy runs, scan jobs, runs of installed tasks, and logs fetched
from hosts. Nothing new is recorded here. Each source keeps its own table, this reads them together, newest first, and
writes the result out as CSV, JSON or text.

An entry is {id, ts, source, host, actor, action, outcome, summary, detail, has_output}. outcome is one of OUTCOMES,
whatever the source calls it. entry() adds the output of one deploy run or fetched log, which lists leave out for size.
"""
from __future__ import annotations

import csv
import datetime as dt
import heapq
import io
import json

from .db import Conn

SOURCES = {'audit': 'Audit log', 'deploy': 'Deploys', 'scan': 'Scans', 'task': 'Task runs',
           'schedule': 'Schedule runs', 'hostlog': 'Fetched logs'}
OUTCOMES = ('ok', 'warn', 'failed', 'denied', 'info', 'running')
MAX_EXPORT = 20000

# what each source's status means as an outcome; a status not listed shows as failed rather than as fine
DEPLOY = {'ok': 'ok', 'incomplete': 'warn', 'refused': 'denied', 'cancelled': 'info', 'skipped': 'info', 'running': 'running',
          'queued': 'running', 'failed': 'failed'}
SCAN = {'ok': 'ok', 'partial': 'warn', 'failed': 'failed', 'running': 'running', 'queued': 'running'}
SCHEDULE = {'verified': 'ok', 'reported': 'ok', 'ok': 'ok', 'verify_failed': 'warn', 'failed': 'failed', 'running': 'running'}
HOSTLOG = {'fetched': 'info', 'pending': 'running', 'failed': 'failed'}


def _ts(v) -> float:
    if isinstance(v, dt.datetime):
        return v.timestamp()
    return float(v or 0)


def _like(q: str) -> str:
    return '%' + q.lower().replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_') + '%'


def _detail(v) -> dict:
    if isinstance(v, dict):
        return v
    try:
        return json.loads(v or '{}')
    except ValueError:
        return {}


def _where(host_col: str, ts_col: str, f: dict, text_cols: tuple[str, ...], params: dict, scale: float = 1,
           status_col: str = '', statuses: tuple[str, ...] | None = None) -> str:
    """The WHERE for one source, and its parameters into params. scale: the source's time units per second."""
    w = []
    if f.get('host'):
        w.append(f'{host_col} = :host')
        params['host'] = f['host']
    if f.get('since') is not None:
        w.append(f'{ts_col} >= :since')
        params['since'] = int(f['since'] * scale)
    if f.get('until') is not None:
        w.append(f'{ts_col} <= :until')
        params['until'] = int(f['until'] * scale)
    if f.get('q'):
        w.append('(' + ' OR '.join(f"lower(CAST({c} AS TEXT)) LIKE :q ESCAPE '\\'" for c in text_cols) + ')')
        params['q'] = _like(f['q'])
    if statuses is not None:
        names = [f's{i}' for i in range(len(statuses))]
        params.update(zip(names, statuses))
        w.append(f'{status_col} IN ({", ".join(":" + n for n in names)})' if names else '1 = 0')
    return ' WHERE ' + ' AND '.join(w) if w else ''


def _statuses(mapping: dict, wanted: set | None) -> tuple[str, ...] | None:
    """The source's own statuses for the outcomes asked for; None when every status is wanted."""
    return tuple(k for k, v in mapping.items() if v in wanted) if wanted else None


def _audit(conn: Conn, f: dict, n: int) -> list[dict]:
    p = {'n': n}
    where = _where('target_host', 'ts_us', f, ('action', 'actor', 'target_host', 'detail_json'), p, 1e6,
                   'outcome', tuple(sorted(f['outcomes'])) if f.get('outcomes') else None)
    rows = conn.all('SELECT audit_id, ts_us, actor, action, target_host, key_fingerprint, outcome, detail_json, entry_hash '
                    f'FROM audit_log{where} ORDER BY audit_id DESC LIMIT :n', p)
    return [{'id': f'audit:{r[0]}', 'ts': r[1] / 1e6, 'source': 'audit', 'host': r[4], 'actor': r[2], 'action': r[3],
             'outcome': r[6], 'summary': r[3], 'detail': {**_detail(r[7]), **({'key': r[5]} if r[5] else {})},
             'has_output': False, 'hash': r[8]} for r in rows]


def _deploy(conn: Conn, f: dict, n: int) -> list[dict]:
    p = {'n': n}
    where = _where('r.host', 'r.started_at', f, ('r.kind', 'r.ref', 'r.host', 'r.actor', 'r.status', 'g.title'), p,
                   status_col='r.status', statuses=_statuses(DEPLOY, f.get('outcomes')))
    rows = conn.all(f"""SELECT r.run_id, r.group_id, r.host, r.kind, r.ref, r.mode, r.status, r.exit_code, r.actor, r.started_at,
                               r.finished_at, r.script_sha, r.host_state, g.title, length(r.output)
                        FROM deploy_runs r LEFT JOIN deploy_groups g ON g.group_id = r.group_id{where}
                        ORDER BY r.started_at DESC, r.run_id DESC LIMIT :n""", p)
    out = []
    for r in rows:
        what = r[13] or ' '.join(x for x in (r[3], r[4]) if x)
        out.append({'id': f'deploy:{r[0]}', 'ts': _ts(r[9]), 'source': 'deploy', 'host': r[2], 'actor': r[8], 'action': f'deploy.{r[3]}.{r[5]}',
                    'outcome': DEPLOY.get(r[6], 'failed'), 'summary': f'{r[5]}: {what}',
                    'detail': {k: v for k, v in (('group', r[1]), ('kind', r[3]), ('ref', r[4]), ('mode', r[5]), ('status', r[6]),
                                                 ('exit_code', r[7]), ('finished_at', r[10]), ('script_sha', r[11]),
                                                 ('host_state', r[12])) if v is not None},
                    'has_output': bool(r[14])})
    return out


def _scan(conn: Conn, f: dict, n: int) -> list[dict]:
    p = {'n': n}
    where = _where('host', 'queued_at', f, ('host', 'requested_by', 'status', 'result_json'), p,
                   status_col='status', statuses=_statuses(SCAN, f.get('outcomes')))
    rows = conn.all(f"""SELECT job_id, host, requested_by, status, queued_at, started_at, finished_at, result_json
                        FROM scan_jobs{where} ORDER BY queued_at DESC, job_id DESC LIMIT :n""", p)
    return [{'id': f'scan:{r[0]}', 'ts': _ts(r[5] or r[4]), 'source': 'scan', 'host': r[1], 'actor': r[2], 'action': 'scan',
             'outcome': SCAN.get(r[3], 'failed'), 'summary': f'scan of {r[1]}: {r[3]}',
             'detail': {'status': r[3], 'finished_at': _ts(r[6]) or None, **({'result': _detail(r[7])} if r[7] else {})},
             'has_output': False} for r in rows]


def _task(conn: Conn, f: dict, n: int) -> list[dict]:
    p = {'n': n}
    where = _where('host', 'started_at', f, ('host', 'task', 'via'), p)
    wanted = f.get('outcomes')
    if wanted:
        cond = []
        if 'ok' in wanted:
            cond.append('exit_code = 0')
        if 'failed' in wanted:
            cond.append('exit_code <> 0')
        if 'running' in wanted:
            cond.append('exit_code IS NULL')
        where += (' AND ' if where else ' WHERE ') + ('(' + ' OR '.join(cond) + ')' if cond else '1 = 0')
    rows = conn.all(f"""SELECT host, task, started_at, finished_at, exit_code, via FROM task_runs{where}
                        ORDER BY started_at DESC LIMIT :n""", p)
    return [{'id': f'task:{r[0]}:{r[1]}:{r[2]}', 'ts': _ts(r[2]), 'source': 'task', 'host': r[0], 'actor': f'timer ({r[5]})', 'action': f'task.{r[1]}',
             'outcome': 'running' if r[4] is None else 'ok' if r[4] == 0 else 'failed',
             'summary': f'task {r[1]}' + ('' if r[4] is None else f': exit {r[4]}'),
             'detail': {'finished_at': r[3], 'exit_code': r[4], 'seen_by': r[5]}, 'has_output': False} for r in rows]


def _hostlog(conn: Conn, f: dict, n: int) -> list[dict]:
    p = {'n': n}
    where = _where('host', 'found_at', f, ('host', 'kind', 'ref', 'reason', 'detail_json'), p,
                   status_col='state', statuses=_statuses(HOSTLOG, f.get('outcomes')))
    rows = conn.all(f"""SELECT log_key, host, kind, ref, reason, detail_json, state, found_at, fetched_at, length(output)
                        FROM host_logs{where} ORDER BY found_at DESC LIMIT :n""", p)
    out = []
    for r in rows:
        outcome = HOSTLOG.get(r[6], 'info')
        out.append({'id': f'hostlog:{r[0]}', 'ts': _ts(r[7]), 'source': 'hostlog', 'host': r[1], 'actor': 'scan', 'action': f'hostlog.{r[2]}',
                    'outcome': outcome, 'summary': f'{r[4]}' + (f' ({r[3]})' if r[3] else ''),
                    'detail': {**_detail(r[5]), 'state': r[6], 'fetched_at': r[8]}, 'has_output': bool(r[9])})
    return out


def _schedule(conn: Conn, f: dict, n: int) -> list[dict]:
    p = {'n': n}
    where = _where('r.host', 'r.started_at', f, ('r.host', 'r.status', 'r.report_source', 's.name', 's.task_type'), p,
                   status_col='r.status', statuses=_statuses(SCHEDULE, f.get('outcomes')))
    rows = conn.all(f"""SELECT r.run_id, r.schedule_id, s.name, s.task_type, r.host, r.status, r.started_at,
                               r.finished_at, r.exit_code, r.verified, r.report_source, length(r.output)
                        FROM schedule_runs r
                        LEFT JOIN schedules s ON s.schedule_id = r.schedule_id{where}
                        ORDER BY r.started_at DESC, r.run_id DESC LIMIT :n""", p)
    out = []
    for r in rows:
        sname = r[2] or f'schedule #{r[1]}'
        out.append({
            'id': f'schedule:{r[0]}',
            'ts': _ts(r[6]),
            'source': 'schedule',
            'host': r[4],
            'actor': r[10] or 'cron',
            'action': f'schedule.{r[3] or "run"}',
            'outcome': SCHEDULE.get(r[5], 'failed'),
            'summary': f'schedule {sname}: {r[5]}' + ('' if r[8] is None else f' (exit {r[8]})'),
            'detail': {'schedule_id': r[1], 'finished_at': r[7], 'exit_code': r[8], 'verified': r[9], 'status': r[5]},
            'has_output': bool(r[11]),
        })
    return out


READERS = {'audit': _audit, 'deploy': _deploy, 'scan': _scan, 'task': _task, 'schedule': _schedule, 'hostlog': _hostlog}


def clean_filter(host=None, sources=None, outcomes=None, q=None, since=None, until=None) -> dict:
    """Checks a filter from the API or CLI. sources and outcomes are comma-separated or lists; times are unix seconds
    or an ISO date. Raises ValueError for anything else."""
    def many(v, known, what):
        items = [x.strip() for x in (v.split(',') if isinstance(v, str) else v or []) if x.strip()]
        bad = [x for x in items if x not in known]
        if bad:
            raise ValueError(f'unknown {what}: {", ".join(bad)} (one of {", ".join(known)})')
        return set(items)

    def when(v, end=False):
        if v in (None, ''):
            return None
        try:
            return float(v)
        except (TypeError, ValueError):
            pass
        try:
            d = dt.datetime.fromisoformat(str(v))
        except ValueError:
            raise ValueError(f'{v!r} is not a time: give unix seconds or a date like 2026-10-30') from None
        if end and len(str(v)) == 10:          # a date as an end means the whole of that day
            d += dt.timedelta(days=1, seconds=-1)
        return d.timestamp()
    host = str(host or '').strip() or None
    text = str(q or '').strip()[:200] or None
    return {'host': host, 'sources': many(sources, tuple(SOURCES), 'source') or set(SOURCES), 'outcomes': many(outcomes, OUTCOMES, 'outcome'),
            'q': text, 'since': when(since), 'until': when(until, end=True)}


def entries(conn: Conn, f: dict, limit: int = 100, offset: int = 0) -> list[dict]:
    """Newest first across the sources. Each source gives up to limit + offset rows: enough for any place in the merge."""
    want = limit + offset
    streams = [READERS[s](conn, f, want) for s in READERS if s in f['sources']]
    merged = heapq.merge(*streams, key=lambda e: e['ts'], reverse=True)
    return [e for i, e in enumerate(merged) if offset <= i < want]


def page(conn: Conn, f: dict, limit: int = 100, offset: int = 0) -> dict:
    """One page, and whether there is more after it."""
    rows = entries(conn, f, limit + 1, offset)
    return {'entries': rows[:limit], 'more': len(rows) > limit, 'offset': offset, 'limit': limit,
            'sources': SOURCES, 'outcomes': OUTCOMES}


def output_of(conn: Conn, entry_id: str) -> str:
    source, _, ref = entry_id.partition(':')
    if source == 'deploy' and ref.isdigit():
        return conn.scalar('SELECT output FROM deploy_runs WHERE run_id = :r', {'r': int(ref)}) or ''
    if source == 'schedule' and ref.isdigit():
        return conn.scalar('SELECT output FROM schedule_runs WHERE run_id = :r', {'r': int(ref)}) or ''
    if source == 'hostlog':
        return conn.scalar('SELECT output FROM host_logs WHERE log_key = :k', {'k': ref}) or ''
    return ''


def with_output(conn: Conn, rows: list[dict]) -> list[dict]:
    return [{**e, 'output': output_of(conn, e['id'])} if e['has_output'] else e for e in rows]


# ── export ──────────────────────────────────────────────────────────────────
def iso(ts: float | None) -> str:
    if not ts:
        return ''
    return dt.datetime.fromtimestamp(ts, dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def _cell(v) -> str:
    """A spreadsheet runs a cell that starts with one of these as a formula. Hosts and scripts can put text in the log,
    so a value is never left able to do that when the file is opened."""
    s = '' if v is None else str(v)
    return "'" + s if s[:1] in ('=', '+', '-', '@', '\t', '\r') else s


def to_csv(rows: list[dict]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator='\r\n')
    w.writerow(['time_utc', 'source', 'host', 'actor', 'action', 'outcome', 'summary', 'detail', 'output'])
    for e in rows:
        w.writerow([_cell(x) for x in (iso(e['ts']), e['source'], e['host'], e['actor'], e['action'], e['outcome'], e['summary'],
                                       json.dumps(e['detail'], sort_keys=True, default=str) if e['detail'] else '', e.get('output', ''))])
    return buf.getvalue()


def to_text(rows: list[dict], f: dict) -> str:
    head = [f'StorageForge log, written {iso(dt.datetime.now(dt.timezone.utc).timestamp())}', f'{len(rows)} entries, newest first']
    if f.get('host'):
        head.append(f'host: {f["host"]}')
    out = ['\n'.join(head), '']
    for e in rows:
        out.append(f'{iso(e["ts"])}  {e["outcome"]:<7}  {e["source"]:<7}  {e["host"] or "-"}  {e["actor"] or "-"}  {e["summary"]}')
        if e['detail']:
            out.append('    ' + json.dumps(e['detail'], sort_keys=True, default=str))
        if e.get('output'):
            out += ['    | ' + line for line in e['output'].splitlines()]
    return '\n'.join(out) + '\n'


def to_json(rows: list[dict], f: dict) -> str:
    return json.dumps({'written': iso(dt.datetime.now(dt.timezone.utc).timestamp()),
                       'filter': {k: (sorted(v) if isinstance(v, set) else v) for k, v in f.items()},
                       'count': len(rows), 'entries': [{**e, 'time_utc': iso(e['ts'])} for e in rows]},
                      indent=1, default=str) + '\n'


FORMATS = {'csv': ('text/csv; charset=utf-8', 'csv'), 'json': ('application/json', 'json'), 'text': ('text/plain; charset=utf-8', 'txt')}


def export(conn: Conn, f: dict, fmt: str, output: bool = False, limit: int = MAX_EXPORT) -> tuple[str, int]:
    """(file contents, entries in it). Audit entries keep their chain hash, so a copy can be held against the log."""
    if fmt not in FORMATS:
        raise ValueError(f'format is one of {", ".join(FORMATS)}')
    rows = entries(conn, f, min(limit, MAX_EXPORT))
    if output:
        rows = with_output(conn, rows)
    text = to_csv(rows) if fmt == 'csv' else to_json(rows, f) if fmt == 'json' else to_text(rows, f)
    return text, len(rows)
