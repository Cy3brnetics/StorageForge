"""Anomalies in host logs (roadmap section 3, phase 3): what a host logs measured against what it usually logs, from the 5-minute
counts hostlogs.store keeps for 400 days, and the kinds of line it has logged before. Three things are said, each through the
notification center as one more source in alerts.problems():

    log-volume        a host, or units on it, logging far more than in the same hour of the week over the last two to four weeks:
                      more than the median of those weeks by four times their spread, by the median itself, and by a floor of
                      VOLUME_FLOOR lines, so a unit that logs two lines an hour and logs nine says nothing. A warning, one per host.
    log-new-kind      lines of a kind the host never logged before: the message with its numbers, hex, addresses and paths blanked,
                      hashed with the program that wrote it. One notification per host however many new kinds came in a day, and a
                      host keeps at most KINDS_PER_HOST kinds, so a flood of new kinds is one notification and bounded storage.
                      Information, or a warning when a new kind came at err or worse.
    log-silence       a host that usually logs in this part of the week and has sent nothing for SILENCE_SECS, which is how a
                      lockup shows. Critical when its agent pushes its lines (they come as they are written, so silence is real
                      time), a warning when they come with scans.
    log-unit-silence  units that log every week in this part of it and have been quiet for UNIT_SILENCE_SECS while their host goes on
                      logging. A warning, one per host.

Nothing is said until it can be: volume and silence need MIN_WEEKS whole weeks of counts for the host, and new kinds start to count
LEARN_DAYS after a host's first line, since before that every kind is new. Critical cannot be snoozed or muted (section 12, as
notifications.ignorable says); the warnings and information can.

Times: the counts are by the host's clock held to the controller's (hostlogs.store), and the same hour of the week is seven times
86,400 seconds back, so a change to or from summer time moves it by an hour for a week. Silence of a host is measured from when its
last new line arrived here, by the controller's clock (host_log_status.fresh_at), so a host with its clock wrong does not look
silent; silence of a unit is measured against its own host's newest line, both by the host's clock. The text of a line is the host's
word and is shown as text only.
"""
from __future__ import annotations

import hashlib
import re
import statistics
import time

from .db import Conn
from .hostlogs import COUNT_KEEP_DAYS, COUNT_SECS, LEVELS, NAME_CHARS

WEEK_SECS = 7 * 86400
WEEK = WEEK_SECS // COUNT_SECS          # buckets in a week
BASELINE_WEEKS, MIN_WEEKS = 4, 2
VOLUME_SECS = 3600                      # the window measured: the last hour
VOLUME_FLOOR = 50                       # lines over the usual before a unit is called loud, however quiet it usually is
SPREAD_K = 4
STALE_SECS = 6 * 3600                   # lines that came with a scan this long ago say nothing about now
SILENCE_SECS = 1800
SILENCE_FLOOR = 10                      # lines a host usually logs in the silent span, at least, before its silence is said
UNIT_SILENCE_SECS = 2 * 3600
UNIT_SILENCE_FLOOR = 12
SPAN_MAX = 86400                        # the most of a silent span held against the weeks before
KINDS_PER_HOST = 5000
LEARN_DAYS = 7
NEW_WINDOW = 86400                      # a new kind is said for a day after it first came
SHAPE_CHARS, SAMPLE_CHARS = 300, 500
LIST_MAX = 5                            # units or kinds named in one notification; the count says the rest

# Blanked in this order, each a pattern that reads a line once: no nested repetition (SF-52). What is left is the shape of the line.
_SHAPES = (
    (re.compile(r'(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b'), '<id>'),
    (re.compile(r'(?i)\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b'), '<mac>'),
    (re.compile(r'\b\d{1,3}(?:\.\d{1,3}){3}\b'), '<ip>'),
    (re.compile(r'(?i)(?<![\w:])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?![\w:])'), '<ip>'),
    (re.compile(r'''(?<![\w.~-])(?:~|\.{1,2})?/[^\s'"()\[\]{}<>,;]*'''), '<path>'),
    (re.compile(r'(?i)\b0x[0-9a-f]+\b'), '<hex>'),
    (re.compile(r'(?i)\b(?=[0-9]*[a-f])(?=[a-f]*\d)[0-9a-f]{6,}\b'), '<hex>'),
    (re.compile(r'\d+'), '#'),
    (re.compile(r'\s+'), ' '),
)


def shape(message: str) -> str:
    """The kind of a line: its text with what changes from line to line blanked."""
    s = str(message or '')
    for pattern, blank in _SHAPES:
        s = pattern.sub(blank, s)
    return s.strip()[:SHAPE_CHARS]


def kind_of(line: dict) -> tuple[str, str, str]:
    """(hash, program, shape). The program is who journald saw write the line when it says, else the name the line gives itself."""
    program = (line.get('comm') or line.get('ident') or line.get('unit') or '')[:NAME_CHARS]
    s = shape(line.get('message') or '')
    return hashlib.sha256(f'{program}\0{s}'.encode()).hexdigest()[:32], program, s


# ── new kinds of line, as lines arrive ──────────────────────────────
def note(conn: Conn, host: str, lines: list[dict], now: float) -> int:
    """Records the kinds of the lines that are new this pickup, inside hostlogs.store's transaction. Returns how many kinds were new."""
    if not lines:
        return 0
    seen: dict = {}
    for x in lines:
        key, program, s = kind_of(x)
        k = seen.get(key)
        if k:
            k['n'] += 1
            k['priority'] = min(k['priority'], x['priority'])
        else:
            seen[key] = {'program': program or None, 'shape': s, 'sample': (x.get('message') or '')[:SAMPLE_CHARS], 'priority': x['priority'], 'n': 1}
    keys, here = list(seen), {}
    for i in range(0, len(keys), 500):
        part = keys[i:i + 500]
        here.update(conn.all(f"SELECT kind_hash, priority FROM host_log_kinds WHERE host = :h AND kind_hash IN ({', '.join(f':k{j}' for j in range(len(part)))})",
                             {'h': host, **{f'k{j}': k for j, k in enumerate(part)}}))
    t = int(now)
    for key in here:
        k = seen[key]
        conn.execute('UPDATE host_log_kinds SET last_at = :t, lines = lines + :n, priority = :p WHERE host = :h AND kind_hash = :k',
                     {'t': t, 'n': k['n'], 'p': min(k['priority'], here[key]), 'h': host, 'k': key})
    new = sorted((k for k in keys if k not in here), key=lambda k: seen[k]['priority'])     # if there is room for only some, the worst first
    room = max(0, KINDS_PER_HOST - int(conn.scalar('SELECT count(*) FROM host_log_kinds WHERE host = :h', {'h': host}) or 0))
    for key in new[:room]:
        k = seen[key]
        conn.execute("""INSERT INTO host_log_kinds (host, kind_hash, program, shape, sample, priority, first_at, last_at, lines)
                        VALUES (:h, :k, :p, :s, :m, :pr, :t, :t, :n) ON CONFLICT (host, kind_hash) DO NOTHING""",
                     {'h': host, 'k': key, 'p': k['program'], 's': k['shape'], 'm': k['sample'], 'pr': k['priority'], 't': t, 'n': k['n']})
    if len(new) > room:
        conn.execute('UPDATE host_log_status SET kinds_over = kinds_over + :o WHERE host = :h', {'o': len(new) - room, 'h': host})
    # a kind not seen for as long as counts are kept is forgotten, and would be new again
    conn.execute('DELETE FROM host_log_kinds WHERE host = :h AND last_at < :t', {'h': host, 't': int(now - COUNT_KEEP_DAYS * 86400)})
    return min(len(new), room)


def new_kinds(conn: Conn, host: str, now: float | None = None, limit: int = LIST_MAX) -> dict:
    """The kinds this host logged for the first time in the last NEW_WINDOW, worst and newest first, once it has been learned."""
    now = time.time() if now is None else now
    start = conn.scalar('SELECT min(first_at) FROM host_log_kinds WHERE host = :h', {'h': host})
    if start is None:
        return {'learning': True, 'learned_at': None, 'count': 0, 'kinds': [], 'over': 0}
    learned = int(start) + LEARN_DAYS * 86400
    since = max(learned, int(now - NEW_WINDOW))
    count = int(conn.scalar('SELECT count(*) FROM host_log_kinds WHERE host = :h AND first_at >= :s', {'h': host, 's': since}) or 0)
    rows = conn.all("""SELECT program, shape, sample, priority, first_at, last_at, lines FROM host_log_kinds WHERE host = :h AND first_at >= :s
                       ORDER BY priority, first_at DESC, kind_hash LIMIT :n""", {'h': host, 's': since, 'n': limit})
    over = int(conn.scalar('SELECT kinds_over FROM host_log_status WHERE host = :h', {'h': host}) or 0)
    return {'learning': now < learned, 'learned_at': learned, 'count': count, 'over': over,
            'kinds': [{'program': r[0], 'shape': r[1], 'sample': r[2], 'level': LEVELS[r[3]], 'priority': r[3], 'first_at': r[4], 'last_at': r[5], 'lines': r[6]} for r in rows]}


# ── the counts against the weeks before ─────────────────────────────
def _sums(conn: Conn, host: str, ranges: list[tuple[int, int]]) -> dict:
    """{unit: [lines in each range]} for buckets from a (inclusive) to b (exclusive), every priority together."""
    p: dict = {'h': host}
    whens, ors = [], []
    for i, (a, b) in enumerate(ranges):
        p[f'a{i}'], p[f'b{i}'] = a, b
        whens.append(f'WHEN bucket >= :a{i} AND bucket < :b{i} THEN {i}')
        ors.append(f'(bucket >= :a{i} AND bucket < :b{i})')
    out: dict = {}
    for unit, which, n in conn.all(f"""SELECT unit, CASE {' '.join(whens)} END, sum(lines) FROM host_log_counts
                                       WHERE host = :h AND ({' OR '.join(ors)}) GROUP BY 1, 2""", p):
        out.setdefault(unit, [0] * len(ranges))[int(which)] += int(n)
    return out


def _usual(samples: list[int]) -> tuple[float, float]:
    """The median of the weeks, and their spread (the median distance from it, scaled to read as a standard deviation)."""
    med = statistics.median(samples)
    return med, 1.4826 * statistics.median(abs(s - med) for s in samples)


def loud_limit(samples: list[int]) -> float:
    """More lines than this in the window is loud."""
    med, spread = _usual(samples)
    return med + max(SPREAD_K * spread, med, VOLUME_FLOOR)


def known_until(via, state, collected_at, now: float) -> float | None:
    """Up to when this host's logging is known: now for a host whose agent pushes its lines as they are written, the last good pickup for
    one whose lines come with scans, and None when that is too long ago or the last pickup failed."""
    if via == 'agent':
        return now
    if state in ('ok', 'partial') and collected_at and now - collected_at <= STALE_SECS:
        return min(float(collected_at), now)
    return None


def _label(unit: str) -> str:
    return unit or 'lines with no unit'


def assess(conn: Conn, host: str, now: float | None = None) -> dict:
    """What a host logs against what it usually logs: the last hour, the weeks it is held against, loud units, and silence."""
    now = time.time() if now is None else now
    row = next(iter(conn.all('SELECT via, state, collected_at, fresh_at FROM host_log_status WHERE host = :h', {'h': host})), None)
    out = {'host': host, 'weeks': 0, 'learning': True, 'known_until': None, 'hour': None, 'usual': None, 'limit': None, 'loud': [], 'silent': None,
           'silent_units': [], 'pushed': bool(row and row[0] == 'agent')}
    if not row:
        return out
    via, state, collected_at, fresh_at = row
    first = conn.scalar('SELECT min(bucket) FROM host_log_counts WHERE host = :h', {'h': host})
    known = known_until(via, state, collected_at, now)
    out['known_until'] = known
    if first is None or known is None:
        return out
    end = int(known // COUNT_SECS)              # buckets before this one are whole
    span = VOLUME_SECS // COUNT_SECS
    weeks = [k for k in range(1, BASELINE_WEEKS + 1) if end - span - k * WEEK >= first]
    out['weeks'] = len(weeks)
    out['learning'] = len(weeks) < MIN_WEEKS
    out['learned_at'] = (first + span + MIN_WEEKS * WEEK) * COUNT_SECS
    if out['learning']:
        return out
    # the last hour, and the same hour of each week before
    sums = _sums(conn, host, [(end - span, end)] + [(end - span - k * WEEK, end - k * WEEK) for k in weeks])
    totals = [sum(v[i] for v in sums.values()) for i in range(len(weeks) + 1)]
    out['hour'], out['usual'], out['limit'] = totals[0], _usual(totals[1:])[0], loud_limit(totals[1:])
    loud = []
    for unit, v in sums.items():
        limit = loud_limit(v[1:])
        if v[0] > limit:
            loud.append({'unit': unit, 'lines': v[0], 'usual': _usual(v[1:])[0], 'limit': limit})
    if totals[0] > out['limit'] and not loud:
        loud.append({'unit': None, 'lines': totals[0], 'usual': out['usual'], 'limit': out['limit']})
    out['loud'] = sorted(loud, key=lambda x: (-(x['lines'] / max(x['usual'], 1)), x['unit'] or ''))
    # silence of the host: nothing new since fresh_at, held against the same span of the weeks before
    since = fresh_at or collected_at
    if since and known - since >= SILENCE_SECS:
        b = int(max(since, known - SPAN_MAX) // COUNT_SECS) + 1
        back = [k for k in weeks if b - k * WEEK >= first]
        if len(back) >= MIN_WEEKS and end > b:
            got = _sums(conn, host, [(b - k * WEEK, end - k * WEEK) for k in back])
            samples = [sum(v[i] for v in got.values()) for i in range(len(back))]
            if min(samples) >= 1 and statistics.median(samples) >= SILENCE_FLOOR:
                out['silent'] = {'since': int(since), 'usual': statistics.median(samples), 'secs': int(known - since)}
    if out['silent']:
        return out
    # silence of units, by the host's own clock: each unit's newest line against the host's newest
    newest = conn.scalar('SELECT max(bucket) FROM host_log_counts WHERE host = :h AND bucket <= :e', {'h': host, 'e': end})
    if newest is None:
        return out
    gap = UNIT_SILENCE_SECS // COUNT_SECS
    quiet = conn.all("""SELECT unit, max(bucket) FROM host_log_counts WHERE host = :h AND unit <> '' AND bucket >= :a AND bucket <= :e
                        GROUP BY unit HAVING max(bucket) <= :q""", {'h': host, 'a': newest - BASELINE_WEEKS * WEEK, 'e': newest, 'q': newest - gap})
    for unit, last in quiet[:200]:
        b, e = int(last) + 1, int(newest) + 1
        b = max(b, e - SPAN_MAX // COUNT_SECS)
        back = [k for k in weeks if b - k * WEEK >= first]
        if len(back) < MIN_WEEKS:
            continue
        p = {'h': host, 'u': unit}
        cases = []
        for i, k in enumerate(back):
            p[f'a{i}'], p[f'b{i}'] = b - k * WEEK, e - k * WEEK
            cases.append(f'sum(CASE WHEN bucket >= :a{i} AND bucket < :b{i} THEN lines ELSE 0 END)')
        samples = [int(x or 0) for x in conn.all(f"SELECT {', '.join(cases)} FROM host_log_counts WHERE host = :h AND unit = :u", p)[0]]
        if min(samples) >= 1 and statistics.median(samples) >= UNIT_SILENCE_FLOOR:
            out['silent_units'].append({'unit': unit, 'since': (int(last) + 1) * COUNT_SECS, 'usual': statistics.median(samples)})
    out['silent_units'].sort(key=lambda x: (x['since'], x['unit']))
    return out


# ── as sources of alerts ────────────────────────────────────────────
def _when(ts) -> str:
    return time.strftime('%Y-%m-%d %H:%M', time.localtime(ts))


def _n(x: float) -> str:
    return f'{x:,.0f}' if x >= 10 or x == int(x) else f'{x:.1f}'


def _more(items: list, total: int, what: str) -> str:
    return f'; and {total - len(items)} more {what}' if total > len(items) else ''


def problems(conn: Conn, now: float | None = None) -> dict:
    """{key: (kind, ref, title, message, level)} for alerts.problems(): at most one of each kind per host."""
    now = time.time() if now is None else now
    out = {}
    for (host,) in conn.all('SELECT host FROM host_log_status ORDER BY host'):
        a = assess(conn, host, now)
        if a['loud']:
            shown = a['loud'][:LIST_MAX]
            text = '; '.join(f'{_label(x["unit"]) if x["unit"] is not None else "all of it"}: {_n(x["lines"])} lines, usually {_n(x["usual"])}' for x in shown)
            out[f'log-volume:{host}'] = ('log-volume', host, f'{host} is logging much more than usual',
                                         f'In the last hour, against the same hour of the last {a["weeks"]} weeks: {text}{_more(shown, len(a["loud"]), "unit(s)")}', 'warn')
        if a['silent']:
            s = a['silent']
            how = 'its agent pushes its lines as they are written, and none came' if a['pushed'] else 'the scans since brought none'
            out[f'log-silence:{host}'] = ('log-silence', host, f'{host} has stopped logging',
                                          f'No new line since {_when(s["since"])}: {how}. It usually logs {_n(s["usual"])} lines in this part of the week. '
                                          'A host that locks up, loses its disk or has its logging stopped looks like this', 'crit' if a['pushed'] else 'warn')
        if a['silent_units']:
            shown = a['silent_units'][:LIST_MAX]
            text = '; '.join(f'{x["unit"]} since {_when(x["since"])}, usually {_n(x["usual"])} lines by now' for x in shown)
            out[f'log-unit-silence:{host}'] = ('log-unit-silence', host, f'Services on {host} have stopped logging',
                                               f'{text}{_more(shown, len(a["silent_units"]), "unit(s)")}. The host itself goes on logging', 'warn')
    for (host,) in conn.all('SELECT DISTINCT host FROM host_log_kinds ORDER BY host'):
        k = new_kinds(conn, host, now)
        if not k['count']:
            continue
        first = k['kinds'][0]
        worst = min(x['priority'] for x in k['kinds'])
        over = f' {k["over"]} more were not kept: this host has as many kinds as one host keeps ({KINDS_PER_HOST}).' if k['over'] else ''
        out[f'log-new-kind:{host}'] = ('log-new-kind', host, f'{host} logged {k["count"]} new kind(s) of line',
                                       f'Kinds of line it had not logged before, in the last day. The worst, at {first["level"]}, from '
                                       f'{first["program"] or "a program with no name"}: {first["sample"]}{over}', 'warn' if worst <= 3 else 'info')
    return out
