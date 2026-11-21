"""The monitoring view of host logs (roadmap section 3, phase 4): per host, what it logged in the last hour against its usual, the log
alerts open on it, the kinds of line it logged for the first time, whether it has gone silent, and how its lines come in (the last line,
when it arrived, the delay, lines missing from the journal's numbering, signed or not).

Read only, and made from what is stored: hostlogs (lines, status and counts), loganomaly (baselines, new kinds, silence) and the open
alerts the notification center holds. Hosts that need someone come first: silent or with a critical alert, then a warning, then the rest.
"""
from __future__ import annotations

import time

from . import hostlogs, loganomaly, netconsole
from .db import Conn

# the alerts that are about what a host logs, or about its lines not coming
KINDS = ('log-rule', 'log-volume', 'log-new-kind', 'log-silence', 'log-unit-silence', 'log-gap', 'log-pstore', 'agent-silent')
_RANK = {'crit': 0, 'warn': 1, 'info': 2}


def _alerts(conn: Conn) -> dict:
    out: dict = {}
    marks = ', '.join(f':k{i}' for i in range(len(KINDS)))
    for key, kind, title, message, level, host, first_at in conn.all(
            f"SELECT alert_key, kind, title, message, level, host, first_at FROM alerts WHERE state = 'open' AND kind IN ({marks}) ORDER BY first_at DESC",
            {f'k{i}': k for i, k in enumerate(KINDS)}):
        if host:
            out.setdefault(host, []).append({'key': key, 'kind': kind, 'title': title, 'message': message, 'level': level if level in _RANK else 'info', 'first_at': first_at})
    for v in out.values():
        v.sort(key=lambda a: (_RANK[a['level']], -(a['first_at'] or 0)))
    return out


def _ingest(s: dict | None, extra: tuple | None, nc: dict | None) -> dict:
    """How the host's lines come: the journal (scan or agent), and beside it netconsole and pstore, which come even with no journal."""
    fresh_at, kinds_over, p_at, p_n, p_read, p_note = extra or (None, 0, None, 0, 0, '')
    side = {'netconsole': {k: nc[k] for k in ('address', 'port', 'enabled', 'last_at', 'packets', 'dropped')} if nc else None,
            'pstore': {'at': p_at, 'records': p_n, 'read': bool(p_read), 'note': p_note or ''} if p_n else None}
    if not s:
        return {'state': 'never', 'via': None, 'signed': False, **side}
    return {'state': s['state'], 'note': s['note'], 'via': s['via'], 'signed': s['signed'], 'last_line': s['newest'], 'last_arrival': fresh_at,
            'last_pickup': s['collected_at'], 'pushed_at': s['pushed_at'], 'delay_ms': s['delay_ms'], 'gaps': s['gaps'], 'gap_at': s['gap_at'],
            'lines': s['lines'], 'over_rate': s['over_rate'], 'over_total': s['over_total'], 'rate_per_day': s['rate_per_day'], 'kinds_over': kinds_over or 0, **side}


def monitor(conn: Conn, now: float | None = None, host: str | None = None) -> dict:
    now = time.time() if now is None else now
    status = {s['host']: s for s in hostlogs.status(conn, host)}
    extra = {r[0]: r[1:] for r in conn.all('SELECT host, fresh_at, kinds_over, pstore_at, pstore_records, pstore_read, pstore_note FROM host_log_status')}
    nc = {x['host']: x for x in netconsole.sources(conn)}
    names = sorted({r[0] for r in conn.all('SELECT hostname FROM hosts')} | set(status)) if not host else [host]
    alerts = _alerts(conn)
    rows = []
    for name in names:
        s = status.get(name)
        s = s if s and s['state'] != 'side' else None         # only netconsole or pstore lines: no journal collected yet
        a = loganomaly.assess(conn, name, now) if s else None
        kinds = loganomaly.new_kinds(conn, name, now) if s else {'learning': True, 'learned_at': None, 'count': 0, 'kinds': [], 'over': 0}
        open_ = alerts.get(name, [])
        silent = bool(a and a['silent'])
        worst = min([_RANK[x['level']] for x in open_] + ([0 if a['pushed'] else 1] if silent else []) + [3])
        rows.append({'host': name, 'rank': worst, 'level': ('crit', 'warn', 'info', 'ok')[worst],
                     'rate': {'hour': a['hour'], 'usual': a['usual'], 'limit': a['limit'], 'weeks': a['weeks'], 'learning': a['learning'],
                              'learned_at': a.get('learned_at'), 'known_until': a['known_until'], 'loud': a['loud']} if a else None,
                     'silent': a['silent'] if a else None, 'silent_units': a['silent_units'] if a else [], 'pushed': bool(a and a['pushed']),
                     'alerts': open_, 'new_kinds': kinds, 'ingest': _ingest(s, extra.get(name), nc.get(name))})
    rows.sort(key=lambda r: (r['rank'], r['host']))
    return {'hosts': rows, 'silent': [r['host'] for r in rows if r['silent']], 'at': int(now),
            'netconsole': netconsole.status(), 'baseline': {'weeks': loganomaly.BASELINE_WEEKS, 'min_weeks': loganomaly.MIN_WEEKS, 'floor': loganomaly.VOLUME_FLOOR,
                         'silence_secs': loganomaly.SILENCE_SECS, 'learn_days': loganomaly.LEARN_DAYS}}
