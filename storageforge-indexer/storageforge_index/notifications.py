"""The notification center: one place for everything that wants a person's attention, most critical first.

It grows out of alerts.py, which gathers every problem, opens, refreshes and resolves an alert for each, and pushes to the channels.
This adds what a person does with them: who is on it, a snooze, a mute by host and kind, and a history that survives an alert
opening again.

What cannot be ignored: a critical notification, configuration drift, and a security finding. Those cannot be snoozed or muted, and
leave the list only when resolved. An acknowledgement on one says someone is on it, with a name and a note, and removes nothing.
Everything else can be snoozed for a time or muted by host and kind. A snoozed or muted notification is still listed, apart, and
is not pushed.
"""
from __future__ import annotations

import fnmatch
import re
import time

from .db import Conn

LEVELS = ('crit', 'warn', 'info')
SECURITY_KINDS = ('clamav', 'shared-key', 'map-listener', 'device-telnet', 'toolbox-cve', 'toolbox-bouncer-vip', 'toolbox-suricata')      # beside every kind that starts with security-
MAX_SNOOZE = 30 * 86400
NOTE_CHARS = 500
EVENTS = ('opened', 'escalated', 'resolved', 'acknowledged', 'unacknowledged', 'snoozed', 'unsnoozed', 'fix-prepared', 'undo-prepared')
WHY_NOT = 'critical notifications, configuration drift and security findings cannot be snoozed or muted: they leave when they are resolved'


def level_of(level) -> str:
    """The three levels of the center. Sources say crit and warn; anything else they may say is information."""
    return level if level in ('crit', 'warn') else 'info'


def is_security(kind: str) -> bool:
    return kind.startswith('security-') or kind in SECURITY_KINDS


def ignorable(kind: str, level: str) -> bool:
    return level != 'crit' and kind != 'drift' and not is_security(kind)


def host_of(conn: Conn, kind: str, ref, hosts: set | None = None) -> str | None:
    """The host an alert is about, from its reference: `host`, `host:thing`, a job or a schedule. None when it is about no one host."""
    ref = str(ref or '')
    hosts = known_hosts(conn) if hosts is None else hosts
    if ref.lower() in hosts:
        return hosts[ref.lower()]
    head = ref.split(':', 1)[0]
    if ':' in ref and head.lower() in hosts:
        return hosts[head.lower()]
    if kind in ('job-failed', 'job-stale', 'verify'):
        row = conn.all('SELECT runner_host, source_host FROM jobs WHERE job_id = :j', {'j': ref})
        return (row[0][0] or row[0][1]) if row else None
    if kind in ('schedule-failed', 'schedule-stale') and ref.isdigit():
        return conn.scalar('SELECT host FROM schedules WHERE schedule_id = :s', {'s': int(ref)})
    return None


def known_hosts(conn: Conn) -> dict:
    return {r[0].lower(): r[0] for r in conn.all('SELECT hostname FROM hosts')}


def record(conn: Conn, key: str, kind: str, host, level: str, title: str, event: str, actor: str | None = None, note: str = '', at: int | None = None):
    conn.execute("""INSERT INTO notification_events (alert_key, kind, host, level, title, event, actor, note, at)
                    VALUES (:k, :kind, :h, :l, :t, :e, :a, :n, :at)""",
                 {'k': key, 'kind': kind, 'h': host, 'l': level, 't': title[:500], 'e': event, 'a': actor, 'n': (note or '')[:NOTE_CHARS], 'at': int(time.time()) if at is None else at})


# ── mutes ───────────────────────────────────────────────────────────
def mutes(conn: Conn, now: float | None = None) -> list[dict]:
    now = time.time() if now is None else now
    rows = conn.all('SELECT mute_id, host, kind, note, until_at, created_by, created_at FROM notification_mutes ORDER BY mute_id')
    return [dict(zip(('id', 'host', 'kind', 'note', 'until', 'by', 'at'), r)) for r in rows if r[4] is None or r[4] > now]


def muted_by(rules: list[dict], kind: str, host, level: str) -> dict | None:
    """The rule that mutes this, or None. Never one for what cannot be ignored, whatever the rule says."""
    if not ignorable(kind, level):
        return None
    return next((m for m in rules if fnmatch.fnmatchcase(kind, m['kind']) and fnmatch.fnmatchcase((host or '').lower(), m['host'].lower())), None)


def mute(conn: Conn, host: str, kind: str, actor: str, note: str = '', days: float | None = None) -> dict:
    host, kind = str(host or '*').strip()[:200] or '*', str(kind or '*').strip()[:80] or '*'
    if kind == 'drift' or is_security(kind):
        raise ValueError(WHY_NOT)
    if days is not None and not 0 < float(days) <= 365:
        raise ValueError('a mute lasts from a moment to a year, or until it is removed')
    now = int(time.time())
    with conn.tx():
        mid = conn.scalar("""INSERT INTO notification_mutes (host, kind, note, until_at, created_by, created_at)
                             VALUES (:h, :k, :n, :u, :a, :t) RETURNING mute_id""",
                          {'h': host, 'k': kind, 'n': str(note or '')[:NOTE_CHARS], 'u': now + int(float(days) * 86400) if days else None, 'a': actor, 't': now})
    return next(m for m in mutes(conn, now) if m['id'] == mid)


def unmute(conn: Conn, mute_id: int) -> bool:
    with conn.tx():
        return conn.execute('DELETE FROM notification_mutes WHERE mute_id = :i', {'i': mute_id}).rowcount > 0


# ── the list ────────────────────────────────────────────────────────
_COLS = 'alert_key, kind, ref, title, message, state, first_at, last_at, notified_at, resolved_at, level, host, acked_by, acked_at, ack_note, snoozed_until, snoozed_by'


def _item(r, rules: list[dict], now: float) -> dict:
    x = dict(zip(('key', 'kind', 'ref', 'title', 'message', 'state', 'first_at', 'last_at', 'notified_at', 'resolved_at', 'level', 'host'), r[:12]))
    x['level'] = level_of(x['level'])
    x['ignorable'] = ignorable(x['kind'], x['level'])
    x['security'] = is_security(x['kind'])
    x['acked'] = {'by': r[12], 'at': r[13], 'note': r[14] or ''} if r[12] else None
    x['snoozed_until'] = r[15] if x['ignorable'] and r[15] and r[15] > now else None
    m = muted_by(rules, x['kind'], x['host'], x['level'])
    x['muted'] = m['id'] if m else None
    x['quiet'] = bool(x['snoozed_until'] or m)
    return x


def get(conn: Conn, key: str) -> dict | None:
    now = time.time()
    rows = conn.all(f"SELECT {_COLS} FROM alerts WHERE alert_key = :k AND state = 'open'", {'k': key})
    return _item(rows[0], mutes(conn, now), now) if rows else None


def center(conn: Conn, host: str | None = None, kind: str | None = None, level: str | None = None, now: float | None = None) -> dict:
    """Open notifications in groups: critical, then warning, then information; within a level, the group with the newest first. One group
    per host and kind with a count, so a flood is one row. Snoozed and muted ones are listed apart, in `quiet`."""
    now = time.time() if now is None else now
    rules = mutes(conn, now)
    items = [_item(r, rules, now) for r in conn.all(f"SELECT {_COLS} FROM alerts WHERE state = 'open'")]
    for x in items:
        fix = fix_for(conn, x)
        x['fix'] = {'label': fix['label'], 'undo': fix['undo'], 'plan': _last_plan(conn, x['key'], x['first_at'])} if fix else None
    if host:
        items = [x for x in items if (x['host'] or '').lower() == host.lower()]
    if kind:
        items = [x for x in items if x['kind'] == kind]
    if level:
        if level not in LEVELS:
            raise ValueError(f'level is one of {", ".join(LEVELS)}')
        items = [x for x in items if x['level'] == level]

    def grouped(which):
        groups: dict = {}
        for x in sorted(which, key=lambda x: (-x['first_at'], x['key'])):
            g = groups.setdefault((x['host'], x['kind'], x['level']), {'host': x['host'], 'kind': x['kind'], 'level': x['level'], 'count': 0, 'newest': x['first_at'],
                                                                         'ignorable': x['ignorable'], 'security': x['security'], 'items': []})
            g['count'] += 1
            g['items'].append(x)
        return sorted(groups.values(), key=lambda g: (LEVELS.index(g['level']), -g['newest'], g['host'] or '', g['kind']))
    loud = [x for x in items if not x['quiet']]
    return {'groups': grouped(loud), 'quiet': grouped([x for x in items if x['quiet']]), 'counts': {lv: sum(x['level'] == lv for x in loud) for lv in LEVELS},
            'total': len(loud), 'mutes': rules, 'kinds': sorted({x['kind'] for x in items}), 'hosts': sorted({x['host'] for x in items if x['host']})}


# ── prepared fixes ──────────────────────────────────────────────────
# A fix is a change plan made ready, never applied from here: it is opened in Changes, where its report is read and its deploy takes the
# password, as any plan's does. One is offered only where there is a way back, which is a second plan made the same way. So far one kind
# has both: a service that keeps failing is restarted, and the way back stops it again, which is how it was found. A stale job run now,
# a scan run again or a full disk have no fix here: the first two cannot be taken back, and nothing here deletes data.
_UNIT_IN_LINE = re.compile(r'(?<![A-Za-z0-9:_.@-])([A-Za-z0-9:_@-][A-Za-z0-9:_.@-]{0,190}\.service)\b')
_INVERSE = {'restarted': 'stopped', 'started': 'stopped'}


def fix_for(conn: Conn, x: dict) -> dict | None:
    """The fix this notification carries: {label, undo, tasks}, or None. Worked out from the index and the alert, never from a client."""
    from . import steps_services
    if x['kind'] != 'log-rule' or not x.get('host'):
        return None
    parts = x['key'].split(':', 2)
    if len(parts) != 3 or not parts[1].isdigit():
        return None
    rule = conn.all('SELECT builtin FROM log_rules WHERE rule_id = :r', {'r': int(parts[1])})
    if not rule or rule[0][0] != 'unit-failed':
        return None
    sample = conn.scalar('SELECT sample FROM log_rule_hits WHERE rule_id = :r AND host = :h ORDER BY bucket DESC LIMIT 1', {'r': int(parts[1]), 'h': x['host']}) or ''
    m = _UNIT_IN_LINE.search(sample)
    if not m or re.fullmatch(steps_services.OWN_WAY_IN, m[1]):
        return None                 # no unit named, or one that is done by hand on the host: nothing is offered
    unit = m[1]
    return {'label': f'Restart {unit} on {x["host"]}', 'undo': f'Stop {unit} again, as it was found',
            'tasks': [{'type': 'unit-state', 'host': x['host'], 'params': {'unit': unit, 'state': 'restarted'}}]}


def _last_plan(conn: Conn, key: str, since: int) -> int | None:
    note = conn.scalar("SELECT note FROM notification_events WHERE alert_key = :k AND event = 'fix-prepared' AND at >= :t ORDER BY event_id DESC LIMIT 1", {'k': key, 't': since})
    m = re.match(r'plan (\d+)\b', note or '')
    return int(m[1]) if m else None


def prepare_fix(conn: Conn, key: str, actor: str) -> dict:
    """Saves the fix as a change plan and says which. Nothing runs: the plan is reported and deployed in Changes, behind the password."""
    from . import changes
    x = _open(conn, key)
    fix = fix_for(conn, x)
    if not fix:
        raise ValueError('this notification has no prepared fix: one is offered only where it can be taken back')
    with conn.tx():
        plan = changes.save_plan(conn, {'name': f'Fix: {fix["label"]}'[:120], 'tasks': fix['tasks']}, actor)
        record(conn, key, x['kind'], x['host'], x['level'], x['title'], 'fix-prepared', actor, f'plan {plan}: {fix["label"]}')
    return {'plan': plan, 'label': fix['label'], 'undo': fix['undo'], 'host': x['host'], 'kind': x['kind'], 'level': x['level']}


def prepare_undo(conn: Conn, plan_id: int, actor: str) -> dict:
    """The way back of a fix that was prepared here, as a plan of its own. Its notification may be resolved by now: the history says what
    the fix was. A plan that was not prepared as a fix has no way back made for it."""
    from . import changes
    row = conn.all("""SELECT alert_key, kind, host, level, title FROM notification_events
                      WHERE event = 'fix-prepared' AND (note = :n OR note LIKE :p) ORDER BY event_id DESC LIMIT 1""", {'n': f'plan {plan_id}', 'p': f'plan {plan_id}:%'})
    if not row:
        raise LookupError('no fix was prepared as that plan')
    key, kind, host, level, title = row[0]
    if kind != 'log-rule':
        raise ValueError('this notification fix has no supported undo')
    try:
        plan = changes.get_plan(conn, plan_id)
    except (KeyError, LookupError, ValueError):
        raise LookupError('that plan is gone: there is nothing to work the way back out from') from None
    tasks = []
    for t in plan['tasks']:
        back = _INVERSE.get((t.get('params') or {}).get('state')) if t.get('type') == 'unit-state' else None
        if not back:
            raise ValueError('that plan was changed since it was prepared, and holds a step with no way back')
        tasks.append({'type': 'unit-state', 'host': t['host'], 'params': {'unit': t['params']['unit'], 'state': back}})
    label = '; '.join(f'stop {t["params"]["unit"]} on {t["host"]}' for t in tasks)
    with conn.tx():
        undo = changes.save_plan(conn, {'name': f'Undo: {label}'[:120], 'tasks': tasks}, actor)
        record(conn, key, kind, host, level, title, 'undo-prepared', actor, f'plan {undo}: the way back of plan {plan_id}')
    return {'plan': undo, 'of': plan_id, 'label': label, 'host': host, 'kind': kind, 'level': level}


def summary(conn: Conn) -> dict:
    """What the shared chrome shows on every page: how many are open at each level, without the snoozed and muted."""
    c = center(conn)
    return {'counts': c['counts'], 'total': c['total']}


# ── what a person does with one ─────────────────────────────────────
def _open(conn: Conn, key: str) -> dict:
    x = get(conn, key)
    if not x:
        raise LookupError('no open notification has that key')
    return x


def acknowledge(conn: Conn, key: str, actor: str, note: str = '') -> dict:
    """A name and a note saying someone is on it. It removes nothing, and anything can carry one."""
    x = _open(conn, key)
    now = int(time.time())
    with conn.tx():
        conn.execute('UPDATE alerts SET acked_by = :a, acked_at = :t, ack_note = :n WHERE alert_key = :k', {'a': actor, 't': now, 'n': str(note or '')[:NOTE_CHARS], 'k': key})
        record(conn, key, x['kind'], x['host'], x['level'], x['title'], 'acknowledged', actor, note, now)
    return get(conn, key)


def unacknowledge(conn: Conn, key: str, actor: str) -> dict:
    x = _open(conn, key)
    with conn.tx():
        conn.execute('UPDATE alerts SET acked_by = NULL, acked_at = NULL, ack_note = NULL WHERE alert_key = :k', {'k': key})
        record(conn, key, x['kind'], x['host'], x['level'], x['title'], 'unacknowledged', actor)
    return get(conn, key)


def snooze(conn: Conn, key: str, seconds: float, actor: str, note: str = '') -> dict:
    x = _open(conn, key)
    if not x['ignorable']:
        raise ValueError(WHY_NOT)
    if not 60 <= float(seconds) <= MAX_SNOOZE:
        raise ValueError('a snooze lasts from a minute to 30 days')
    now = int(time.time())
    with conn.tx():
        conn.execute('UPDATE alerts SET snoozed_until = :u, snoozed_by = :a WHERE alert_key = :k', {'u': now + int(float(seconds)), 'a': actor, 'k': key})
        record(conn, key, x['kind'], x['host'], x['level'], x['title'], 'snoozed', actor, note or f'until {time.strftime("%Y-%m-%d %H:%M", time.localtime(now + int(float(seconds))))}', now)
    return get(conn, key)


def unsnooze(conn: Conn, key: str, actor: str) -> dict:
    x = _open(conn, key)
    with conn.tx():
        conn.execute('UPDATE alerts SET snoozed_until = NULL, snoozed_by = NULL WHERE alert_key = :k', {'k': key})
        record(conn, key, x['kind'], x['host'], x['level'], x['title'], 'unsnoozed', actor)
    return get(conn, key)


# ── history ─────────────────────────────────────────────────────────
def history(conn: Conn, q: str | None = None, host: str | None = None, kind: str | None = None, event: str | None = None, limit: int = 100, offset: int = 0) -> dict:
    """Everything that happened to a notification, newest first: opened, resolved, and what people did, with who."""
    where, p = [], {'n': max(1, min(int(limit), 500)) + 1, 'o': max(0, int(offset))}
    if q:
        where.append("(lower(title) LIKE :q ESCAPE '!' OR lower(note) LIKE :q ESCAPE '!' OR lower(alert_key) LIKE :q ESCAPE '!')")
        p['q'] = '%' + str(q).lower()[:200].replace('!', '!!').replace('%', '!%').replace('_', '!_') + '%'
    if host:
        where.append('lower(host) = :h')
        p['h'] = host.lower()
    if kind:
        where.append('kind = :k')
        p['k'] = kind
    if event:
        if event not in EVENTS:
            raise ValueError(f'event is one of {", ".join(EVENTS)}')
        where.append('event = :e')
        p['e'] = event
    rows = conn.all(f"""SELECT event_id, alert_key, kind, host, level, title, event, actor, note, at FROM notification_events
                        {'WHERE ' + ' AND '.join(where) if where else ''} ORDER BY at DESC, event_id DESC LIMIT :n OFFSET :o""", p)
    out = [dict(zip(('id', 'key', 'kind', 'host', 'level', 'title', 'event', 'actor', 'note', 'at'), r)) for r in rows]
    return {'events': out[:p['n'] - 1], 'more': len(out) >= p['n'], 'limit': p['n'] - 1, 'offset': p['o']}
