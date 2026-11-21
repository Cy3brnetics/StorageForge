"""Host logs: what each host's journal said, picked up by the scan, or pushed as it is written by the agent's logs plugin on a host
that has one (agentingest.py, roadmap section 3 phase 2), and kept here to search. A host without the agent's logs plugin gets its
lines with each scan; to see newer logs there, scan the host. A host whose agent pushes its lines is not asked again by the scan while
lines keep coming (PUSH_FRESH_SECS), and is again as soon as they stop.

A scan asks for what is new since the last one, up to LINES_IMPORTANT at warning or worse and LINES_ROUTINE at info or
worse, so a chatty service can't push errors out. Lines are one row each: time, host, level, unit, program, pid, message.

The journal holds what programs chose to print, which can include passwords, so known secret shapes are removed before a
line is stored. That catches common forms, not every form. It is also the host's own word: anyone on the host can write
to it, so a line says what was logged, not that it happened. `ident` is whatever the writer called itself; `unit`, `uid`,
`comm` and `exe` are journald's own account of who wrote the line, which a writer that is not root cannot choose.

What is kept is decided by when a line arrived, never by the time the host stamped on it: a host with a wrong or lying clock
cannot have its lines deleted as they are stored, or push other lines out with ones stamped ahead. Each host has a rate
(RATE_PER_DAY, with one day of it saved up), sized so that a host at its rate for KEEP_DAYS fills KEEP_ROWS and no more.
Lines over it are not stored, routine ones first, and how many is recorded: a flood costs the flood, not the older lines.
Every new line is also counted per unit, level and 5 minutes in host_log_counts, stored or not, and those counts are kept
for COUNT_KEEP_DAYS, because a baseline needs weeks of them.

Reading the whole journal takes membership of systemd-journal, which `access script` adds. Without it journalctl shows the
scan user only its own lines, so nothing is stored and the status says why, and the first scan with access reads back
FIRST_DAYS.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import re
import time

from .db import Conn
from . import logbook

LEVELS = ('emerg', 'alert', 'crit', 'err', 'warning', 'notice', 'info', 'debug')
LINES_IMPORTANT, LINES_ROUTINE = 2000, 5000
STREAM_BYTES = 8 << 20          # per stream: a line with a long message is bigger than it looks
MESSAGE_CHARS, NAME_CHARS = 4000, 200
FIRST_DAYS = 7                  # how far back the first scan of a host reads
OVERLAP_SECS = 300              # read a little of what the last scan saw: lines can arrive late, and repeats are dropped
FUTURE_SECS = 86400
KEEP_DAYS = int(os.environ.get('STORAGEFORGE_LOG_KEEP_DAYS', '30'))
KEEP_ROWS = int(os.environ.get('STORAGEFORGE_LOG_KEEP_ROWS', '500000'))     # per host
# a host at this rate for KEEP_DAYS fills KEEP_ROWS exactly, so the row limit never has to take an older line to make room for a newer one
RATE_PER_DAY = float(os.environ.get('STORAGEFORGE_LOG_RATE_PER_DAY', '0')) or KEEP_ROWS / max(KEEP_DAYS, 1)
COUNT_SECS = 300
COUNT_KEEP_DAYS = int(os.environ.get('STORAGEFORGE_LOG_COUNT_KEEP_DAYS', '400'))
MAX_EXPORT = 20000
PUSH_FRESH_SECS = 600           # a host whose agent pushed lines this recently is not asked for them by the scan too
JOURNAL_GROUPS = {'systemd-journal', 'adm', 'wheel', 'root'}                # the groups journald's files are readable by
FIELDS = 'MESSAGE,PRIORITY,_SYSTEMD_UNIT,SYSLOG_IDENTIFIER,_PID,_UID,_COMM,_EXE'    # never _CMDLINE: that is where passwords sit. __SEQNUM and its ID always come
HINTS = {'limited': "the scan user can't read the whole journal: run `access script --host <host>` on it as root, then scan again",
         'no_journal': 'this host has no journalctl, so there is nothing to collect'}


def enabled() -> bool:
    return os.environ.get('STORAGEFORGE_HOST_LOGS', '1') not in ('0', 'false', 'no', 'off')


def script(since: int) -> str:
    """int(since) so nothing but a number reaches the shell. Priorities and sizes are constants."""
    return f"""PATH="$PATH:/usr/sbin:/sbin"
command -v journalctl >/dev/null 2>&1 || {{ echo '@@nojournal'; exit 0; }}
echo "@@who $(id -u) $(id -nG 2>/dev/null)"
fields=; journalctl --output-fields=MESSAGE -o json -n 0 --no-pager >/dev/null 2>&1 && fields=--output-fields={FIELDS}
# -r: newest first. With --since, journalctl before 254 takes -n as the first lines since then and from 254 as the last, so without -r a
# host on an older systemd (Ubuntu 22.04, Enterprise Linux 9) that logged more than one pickup keeps sent its oldest lines and lost its
# newest, for good: the next pickup starts after them. Found in the KVM lab. Newest first, both take the newest, and head cuts the oldest.
pull() {{ LC_ALL=C journalctl $fields -o json --no-pager --since "@{int(since)}" -r "$@" 2>/dev/null | head -c {STREAM_BYTES}; echo; }}
echo '@@important'; pull -p warning -n {LINES_IMPORTANT}
echo '@@routine'; pull -p info -n {LINES_ROUTINE}
echo '@@end'
"""


# ── secrets ─────────────────────────────────────────────────────────
_SECRET_WORD = r'(?:password|passwd|passphrase|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|authorization|cookie)'
_VALUE = r'''(?:"[^"]*"|'[^']*'|\S+)'''
_SCRUB = (
    # key=value, key: value, "key":"value", and an optional scheme word: PASSWORD=x, MYSQL_PASSWORD=x, Authorization: Bearer x
    # Both of these start only where a run of word characters starts, and a lookahead reads the run once for the secret word. Written the plain way
    # (the key's own characters before and after the word) they began at every character of a long run and read on from each: the square of the
    # run's length, 0.8 seconds for one line of 4000 letters (SF-52). The match still begins at the start of the key, so what is kept is the same.
    (re.compile(rf'''(?i)(?<![\w.-])(?=[\w.-]*?{_SECRET_WORD})([\w.-]+["']?\s*[=:]\s*)(?:(?:bearer|basic|token)\s+)?{_VALUE}'''), r'\1[redacted]'),
    (re.compile(rf'(?i)(?<![\w-])(--(?=[\w-]*?(?:password|passwd|passphrase|token|secret|api-?key))[\w-]+[\s=]+){_VALUE}'), r'\1[redacted]'),
    (re.compile(r'(?i)\b(sshpass\s+-p\s*)\S+'), r'\1[redacted]'),
    (re.compile(r'(?i)\b(mysql(?:dump|admin)?\b[^|;&]{0,200}?\s-p)\S+'), r'\1[redacted]'),
    (re.compile(r'(?i)\b(bearer\s+)[A-Za-z0-9._~+/=-]{8,}'), r'\1[redacted]'),
    (re.compile(r'(://[^/\s:@]+:)[^/\s@]+(@)'), r'\1[redacted]\2'),
    (re.compile(r'\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+'), '[redacted]'),     # JWT
    (re.compile(r'\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_\w{20,}|glpat-[\w-]{16,}|xox[abprs]-[\w-]{10,}|sk-[\w-]{20,}|AKIA[0-9A-Z]{16})\b'), '[redacted]'),
)
_PRIVATE_KEY = re.compile(r'-----BEGIN [A-Z ]*PRIVATE KEY')
# what a line has to hold for any pattern above to match: a check that is linear in the line, so most lines never reach the patterns
_HINTS = ('password', 'passwd', 'passphrase', 'pwd', 'secret', 'token', 'key', 'authorization', 'cookie', 'bearer', 'sshpass', 'mysql', '://', 'eyj',
          'ghp_', 'gho_', 'ghu_', 'ghs_', 'ghr_', 'github_pat_', 'glpat-', 'xox', 'sk-', 'akia')
_CONTROL = re.compile(r'[\x00-\x1f\x7f-\x9f\u2028\u2029\u202a-\u202e\u2066-\u2069]+')    # terminal escapes, line breaks, text direction


def scrub(message: str) -> str:
    if _PRIVATE_KEY.search(message):
        return '[redacted: this line held a private key]'
    if message.isascii():                # (a letter that only looks like another one matches in the patterns, so the shortcut is for plain text)
        low = message.lower()
        if not any(h in low for h in _HINTS):
            return message
    for pattern, replacement in _SCRUB:
        message = pattern.sub(replacement, message)
    return message


def _text(value, limit: int) -> str:
    """A journal field as one safe line. A field not valid UTF-8 comes as a list of bytes; one set twice as a list of values."""
    if isinstance(value, list):
        if value and all(isinstance(b, int) and 0 <= b < 256 for b in value):
            value = bytes(value).decode('utf-8', 'replace')
        else:
            value = next((v for v in value if isinstance(v, str)), '')
    if not isinstance(value, str):
        return ''
    value = value.encode('utf-8', 'replace').decode('utf-8')            # a lone surrogate from JSON would not store
    return _CONTROL.sub(' ', value).strip()[:limit]


# ── reading what the host sent ──────────────────────────────────────
def parse(output: str, now: float | None = None) -> dict:
    """{'state': ok|partial|limited|no_journal, 'lines': [...], 'cut': bool}. Hosts are not trusted to send sense: a bad
    line is skipped, and sizes are limited here too."""
    now = time.time() if now is None else now
    state, stream, counts, lines, cut, finished, keys = 'ok', None, {}, [], False, False, set()
    for raw in output.splitlines():
        if raw == '@@nojournal':
            return {'state': 'no_journal', 'lines': [], 'cut': False}
        if raw.startswith('@@who '):
            who = raw.split()[1:]
            if not who or (who[0] != '0' and not JOURNAL_GROUPS & set(who[1:])):
                return {'state': 'limited', 'lines': [], 'cut': False}
        elif raw in ('@@important', '@@routine'):
            stream = raw[2:]
            counts[stream] = 0
        elif raw == '@@end':
            finished = True
        elif raw.strip() and stream:
            try:
                row = json.loads(raw)
                line = _line(row, now)
            except (ValueError, TypeError, KeyError, RecursionError):
                cut = True            # head stopped mid-line, or the host sent junk
                continue
            counts[stream] += 1
            if line and line['key'] not in keys:
                keys.add(line['key'])
                lines.append(line)
    if counts.get('important', 0) >= LINES_IMPORTANT or counts.get('routine', 0) >= LINES_ROUTINE:
        cut = True
    if not finished:
        state, cut = 'partial', True
    return {'state': state, 'lines': lines, 'cut': cut}


def _line(row: dict, now: float) -> dict | None:
    if not isinstance(row, dict):
        raise ValueError('not an object')
    at_us = int(row['__REALTIME_TIMESTAMP'])
    # a host with its clock ahead must not hold the newest place in every search
    at_us = max(0, min(at_us, int((now + FUTURE_SECS) * 1e6)))
    message = scrub(_text(row.get('MESSAGE'), MESSAGE_CHARS))
    if not message:         # journald sends null for a field over 4 KiB
        message = '[message too long for the journal to print]' if row.get('MESSAGE', '') is None else ''
    if not message:
        return None
    try:
        priority = int(_text(row.get('PRIORITY'), 2))
    except ValueError:
        priority = 6
    priority = priority if 0 <= priority <= 7 else 6
    try:
        pid = int(_text(row.get('_PID'), 10)) or None
    except ValueError:
        pid = None
    identity = _text(row.get('__CURSOR'), 500) or f'{at_us}|{message}'
    return {'key': hashlib.sha256(identity.encode()).hexdigest()[:32], 'at_us': at_us, 'priority': priority,
            'unit': _text(row.get('_SYSTEMD_UNIT'), NAME_CHARS) or None, 'ident': _text(row.get('SYSLOG_IDENTIFIER'), NAME_CHARS) or None,
            'pid': pid, 'message': message, 'uid': _number(row.get('_UID'), 0xffffffff), 'comm': _text(row.get('_COMM'), NAME_CHARS) or None,
            'exe': _text(row.get('_EXE'), NAME_CHARS) or None, 'seqnum': _number(row.get('__SEQNUM'), (1 << 63) - 1),
            'seqnum_id': (_text(row.get('__SEQNUM_ID'), 64) if re.fullmatch(r'[0-9a-f]{32}', _text(row.get('__SEQNUM_ID'), 64)) else None)}


def _number(value, most: int) -> int | None:
    """A journal field that should be a whole number from 0 to most, or None: a host may send anything."""
    text = _text(value, 24)
    return int(text) if text.isascii() and text.isdigit() and int(text) <= most else None


# ── storing it ──────────────────────────────────────────────────────
def since_for(conn: Conn, host: str, now: float) -> int:
    first = int(now) - min(FIRST_DAYS, KEEP_DAYS) * 86400
    newest = conn.scalar('SELECT newest_us FROM host_log_status WHERE host = :h', {'h': host})
    return first if not newest else max(first, min(int(newest // 1000000), int(now)) - OVERLAP_SECS)


def _set_status(conn: Conn, host: str, now: int, state: str, new: int, cut: bool, newest_us: int | None, note: str):
    conn.execute("""INSERT INTO host_log_status (host, collected_at, state, new_lines, cut, newest_us, note)
                    VALUES (:h, :t, :s, :n, :c, :u, :o)
                    ON CONFLICT (host) DO UPDATE SET collected_at = :t, state = :s, new_lines = :n, cut = :c,
                                                     newest_us = COALESCE(:u, host_log_status.newest_us), note = :o""",
                 {'h': host, 't': now, 's': state, 'n': new, 'c': 1 if cut else 0, 'u': newest_us, 'o': note[:500]})


def _allowance(conn: Conn, host: str, now: float) -> float:
    """How many lines this host may store now: what it had left, plus the rate for the time since, up to a day's worth."""
    row = next(iter(conn.all('SELECT rate_tokens, rate_at FROM host_log_status WHERE host = :h', {'h': host})), None)
    if not row or row[0] is None or row[1] is None:
        return RATE_PER_DAY
    return min(RATE_PER_DAY, max(0.0, float(row[0])) + max(0.0, now - row[1]) * RATE_PER_DAY / 86400)


def store(conn: Conn, host: str, parsed: dict, now: float | None = None, via: str | None = None, counts: dict | None = None) -> int:
    """Saves one scan's lines, or one push of the agent's (via='agent'). Returns how many were new; `counts` gets 'hits', how many of
    them a log rule matched."""
    now = time.time() if now is None else now
    lines, state, cut = parsed['lines'], parsed['state'], parsed['cut']
    new = over = 0
    counted: dict = {}
    arrived = []          # the lines that are new this pickup, stored or over the rate: what the log rules are held against
    with conn.tx():
        left = _allowance(conn, host, now)
        # which of them are new: a pickup reads the last five minutes again, and a line already here costs nothing and counts for nothing
        keys, here = [x['key'] for x in lines], set()
        for i in range(0, len(keys), 500):
            part = keys[i:i + 500]
            here.update(r[0] for r in conn.all(f"SELECT line_key FROM host_log_lines WHERE host = :h AND line_key IN ({', '.join(f':k{j}' for j in range(len(part)))})",
                                               {'h': host, **{f'k{j}': k for j, k in enumerate(part)}}))
        fresh = [x for x in lines if x['key'] not in here]
        # the rate takes routine lines before warnings, and within each the older before the newer
        fresh.sort(key=lambda x: (x['priority'] > 4, -x['at_us']))
        keep, lost = fresh[:int(left)], fresh[int(left):]
        over = len(lost)
        # stored oldest first, so that under the row limit, which goes by arrival and then by row, a pickup's newest lines are the last to go
        for x in sorted(keep, key=lambda x: x['at_us']):
            new += conn.execute("""INSERT INTO host_log_lines (host, line_key, at_us, priority, unit, ident, pid, message, collected_at, uid, comm, exe, seqnum, seqnum_id, via)
                                   VALUES (:h, :k, :a, :p, :u, :i, :d, :m, :t, :uid, :comm, :exe, :seq, :sid, :via) ON CONFLICT (host, line_key) DO NOTHING""",
                                {'h': host, 'k': x['key'], 'a': x['at_us'], 'p': x['priority'], 'u': x['unit'], 'i': x['ident'], 'd': x['pid'], 'm': x['message'],
                                 't': int(now), 'uid': x.get('uid'), 'comm': x.get('comm'), 'exe': x.get('exe'), 'seq': x.get('seqnum'), 'sid': x.get('seqnum_id'), 'via': via}).rowcount
        left -= new
        for x in fresh:
            arrived.append(x)
            # by the host's clock, since that is when it happened, but never after now: a clock ahead does not write the future's counts
            bucket = int(min(x['at_us'] / 1e6, now) // COUNT_SECS)
            key = (x['unit'] or '', x['priority'], bucket)
            counted[key] = counted.get(key, 0) + 1
        for (unit, priority, bucket), n in counted.items():
            conn.execute("""INSERT INTO host_log_counts (host, unit, priority, bucket, lines) VALUES (:h, :u, :p, :b, :n)
                            ON CONFLICT (host, unit, priority, bucket) DO UPDATE SET lines = host_log_counts.lines + :n""",
                         {'h': host, 'u': unit, 'p': priority, 'b': bucket, 'n': n})
        # not advanced by a line stamped in the future, or the next scan would ask from then and find nothing
        seen = [x['at_us'] for x in lines if x['at_us'] <= now * 1e6]
        note = HINTS.get(state, '')
        if cut:
            note = 'more lines were logged than one scan keeps: the oldest of them were not collected. Scan more often to get them all.'
        if over:
            note = (f'{over} line(s) were over this host\'s rate of {int(RATE_PER_DAY)} a day and were not stored, routine ones first. They are counted. '
                    'Raise STORAGEFORGE_LOG_KEEP_ROWS or STORAGEFORGE_LOG_RATE_PER_DAY to keep more.')
        _set_status(conn, host, int(now), state, new, cut, max(seen) if seen else None, note)
        conn.execute('UPDATE host_log_status SET rate_tokens = :l, rate_at = :t, over_rate = :o, over_total = over_total + :o, via = :v WHERE host = :h',
                     {'h': host, 'l': left, 't': int(now), 'o': over, 'v': via or 'scan'})
        if arrived:
            from . import logrules          # it takes its levels and its 5 minutes from here
            hits = logrules.match_new(conn, host, arrived, now)
            if counts is not None:
                counts['hits'] = counts.get('hits', 0) + hits
        prune(conn, host, now)
    return new


def prune(conn: Conn, host: str, now: float):
    """By arrival. The time a host stamps on a line decides where it is shown, never whether it is kept."""
    conn.execute('DELETE FROM host_log_lines WHERE host = :h AND collected_at < :t', {'h': host, 't': int(now - KEEP_DAYS * 86400)})
    edge = next(iter(conn.all('SELECT collected_at, line_id FROM host_log_lines WHERE host = :h ORDER BY collected_at DESC, line_id DESC LIMIT 1 OFFSET :n', {'h': host, 'n': KEEP_ROWS})), None)
    if edge is not None:
        conn.execute('DELETE FROM host_log_lines WHERE host = :h AND (collected_at < :t OR (collected_at = :t AND line_id <= :i))', {'h': host, 't': edge[0], 'i': edge[1]})
    conn.execute('DELETE FROM host_log_counts WHERE host = :h AND bucket < :b', {'h': host, 'b': int((now - COUNT_KEEP_DAYS * 86400) // COUNT_SECS)})


def pushing(conn: Conn, host: str, now: float | None = None) -> bool:
    """Whether the host's agent is pushing its lines: they came in the last PUSH_FRESH_SECS."""
    at = conn.scalar("SELECT pushed_at FROM host_log_status WHERE host = :h AND via = 'agent'", {'h': host})
    return bool(at) and (now or time.time()) - at < PUSH_FRESH_SECS


def collect(conn: Conn, t, host: str, log=lambda _: None) -> dict | None:
    """One scan's log pickup. A failure here is said and recorded; it never costs the scan its files."""
    if not enabled():
        return None
    now = time.time()
    if pushing(conn, host, now):
        # the agent sends them as they are written, signed: asking again over SSH would only read the same lines twice
        log('  host logs: pushed by the agent as they are written; not asked for by the scan')
        return {'state': 'agent', 'new': 0}
    try:
        parsed = parse(t.run(script(since_for(conn, host, now)), timeout=90), now)
    except Exception as exc:
        with conn.tx():
            _set_status(conn, host, int(now), 'failed', 0, False, None, str(exc))
        log(f'  host logs: {exc}')
        return {'state': 'failed', 'new': 0}
    new = store(conn, host, parsed, now)
    if parsed['state'] in HINTS:
        log(f'  host logs: {HINTS[parsed["state"]]}')
    else:
        log(f'  host logs: {new} new line(s)' + (' (more were logged than one scan keeps)' if parsed['cut'] else ''))
    return {'state': parsed['state'], 'new': new}


# ── searching it ────────────────────────────────────────────────────
def clean_filter(host=None, unit=None, level=None, q=None, since=None, until=None) -> dict:
    """level: warning means warning or worse. Raises ValueError for what can't be understood."""
    f = logbook.clean_filter(host, None, None, q, since, until)
    level = str(level or '').strip().lower()
    if level and level not in LEVELS:
        raise ValueError(f'unknown level: {level} (one of {", ".join(LEVELS)})')
    return {'host': f['host'], 'q': f['q'], 'since': f['since'], 'until': f['until'],
            'unit': str(unit or '').strip()[:NAME_CHARS] or None, 'level': level or None}


def _rows(conn: Conn, f: dict, limit: int, offset: int = 0) -> list[dict]:
    p = {'n': limit, 'o': offset}
    where = logbook._where('host', 'at_us', f, ('message', 'unit', 'ident'), p, scale=1000000)
    extra = []
    if f.get('level'):
        extra.append('priority <= :lvl')
        p['lvl'] = LEVELS.index(f['level'])
    if f.get('unit'):
        extra.append('(unit = :unit OR ident = :unit OR unit = :unit_s)')
        p['unit'], p['unit_s'] = f['unit'], f'{f["unit"]}.service'
    if extra:
        where += (' AND ' if where else ' WHERE ') + ' AND '.join(extra)
    rows = conn.all(f"""SELECT at_us, host, priority, unit, ident, pid, message, uid, comm, exe, collected_at, via FROM host_log_lines{where}
                        ORDER BY at_us DESC, line_id DESC LIMIT :n OFFSET :o""", p)
    return [{'ts': r[0] / 1e6, 'host': r[1], 'level': LEVELS[r[2]], 'priority': r[2], 'unit': r[3], 'ident': r[4], 'pid': r[5], 'message': r[6],
             'uid': r[7], 'comm': r[8], 'exe': r[9], 'arrived': r[10], 'via': r[11] or 'scan', 'signed': r[11] == 'agent'} for r in rows]


def page(conn: Conn, f: dict, limit: int = 100, offset: int = 0) -> dict:
    rows = _rows(conn, f, limit + 1, offset)
    return {'entries': rows[:limit], 'more': len(rows) > limit, 'limit': limit, 'offset': offset}


def status(conn: Conn, host: str | None = None) -> list[dict]:
    """Per host: the last pickup, what is kept, and the oldest and newest lines. A host never collected isn't listed."""
    rows = conn.all(f"""SELECT s.host, s.collected_at, s.state, s.new_lines, s.cut, s.note,
                               (SELECT count(*) FROM host_log_lines l WHERE l.host = s.host),
                               (SELECT min(at_us) FROM host_log_lines l WHERE l.host = s.host),
                               (SELECT max(at_us) FROM host_log_lines l WHERE l.host = s.host), s.over_rate, s.over_total,
                               s.via, s.pushed_at, s.push_delay_ms, s.push_lines, s.seq_gaps, s.seq_gap_at
                        FROM host_log_status s {'WHERE s.host = :h' if host else ''} ORDER BY s.host""", {'h': host})
    # how the lines come: pushed by the agent as they are written, in batches its key signed, or collected by the scan over SSH
    return [{'host': r[0], 'collected_at': r[1], 'state': r[2], 'new_lines': r[3], 'cut': bool(r[4]), 'note': r[5], 'lines': r[6],
             'oldest': r[7] / 1e6 if r[7] else None, 'newest': r[8] / 1e6 if r[8] else None, 'over_rate': r[9], 'over_total': r[10], 'rate_per_day': int(RATE_PER_DAY),
             'via': r[11] or 'scan', 'signed': r[11] == 'agent', 'pushed_at': r[12], 'delay_ms': r[13], 'pushed_lines': r[14] or 0, 'gaps': r[15] or 0,
             'gap_at': r[16]} for r in rows]


# ── counts and units, for the Logs view ─────────────────────────────
HOUR_US = 3600 * 1000000
MAX_HOURS = 24 * 31 + 48        # hours in one answer, newest kept: a month of retention plus a day each way
MAX_UNITS = 200


def range_filter(host=None, since=None, until=None) -> dict:
    """Host and time range only. Raises ValueError for a time that can't be read or a range that ends before it starts."""
    f = clean_filter(host, None, None, None, since, until)
    if f['since'] is not None and f['until'] is not None and f['since'] > f['until']:
        raise ValueError('since is after until')
    return f


def counts(conn: Conn, f: dict) -> dict:
    """Stored lines in the range by level and by UTC hour. by_hour is oldest first, holds only hours with lines, and is cut to
    the newest MAX_HOURS (truncated says so); by_level always lists every level."""
    p: dict = {}
    where = logbook._where('host', 'at_us', f, (), p, scale=1000000)
    totals = dict(conn.all(f'SELECT priority, count(*) FROM host_log_lines{where} GROUP BY priority', p))
    cap = MAX_HOURS * len(LEVELS)
    p = {'n': cap + 1}
    where = logbook._where('host', 'at_us', f, (), p, scale=1000000)
    rows = conn.all(f"""SELECT at_us / {HOUR_US}, priority, count(*) FROM host_log_lines{where}
                        GROUP BY 1, 2 ORDER BY 1 DESC, 2 LIMIT :n""", p)
    truncated = len(rows) > cap
    hours: dict[int, dict] = {}
    for hour, priority, n in rows[:cap]:
        hours.setdefault(int(hour), {})[LEVELS[priority]] = n
    if truncated:                              # the oldest hour read may be only part of an hour: leave it out
        hours.pop(min(hours), None)
    for h in sorted(hours)[:-MAX_HOURS] if len(hours) > MAX_HOURS else ():
        del hours[h]
        truncated = True
    by_hour = [{'hour': dt.datetime.fromtimestamp(h * 3600, dt.timezone.utc).strftime('%Y-%m-%dT%H:00:00Z'),
                'total': sum(lv.values()), 'levels': lv} for h, lv in sorted(hours.items())]
    return {'host': f['host'], 'total': sum(totals.values()), 'by_level': {name: totals.get(i, 0) for i, name in enumerate(LEVELS)},
            'by_hour': by_hour, 'truncated': truncated}


def units(conn: Conn, host: str | None = None) -> list[dict]:
    """The unit names stored (a line with none is not counted), most lines first, at most MAX_UNITS."""
    p: dict = {'n': MAX_UNITS}
    where = ' AND host = :h' if host else ''
    if host:
        p['h'] = host
    rows = conn.all(f"""SELECT unit, count(*) FROM host_log_lines WHERE unit IS NOT NULL{where}
                        GROUP BY unit ORDER BY 2 DESC, 1 LIMIT :n""", p)
    return [{'unit': r[0], 'lines': r[1]} for r in rows]


# ── files ───────────────────────────────────────────────────────────
FORMATS = logbook.FORMATS
COLUMNS = ('time', 'host', 'level', 'unit', 'ident', 'pid', 'message')


def _iso(ts: float) -> str:
    return dt.datetime.fromtimestamp(ts, dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%fZ')


def as_line(e: dict) -> str:
    name = e['unit'] or e['ident'] or '-'
    return f'{_iso(e["ts"])} {e["host"]} {e["level"]:<7} {name}{"[" + str(e["pid"]) + "]" if e["pid"] else ""}: {e["message"]}'


def export(conn: Conn, f: dict, fmt: str, limit: int = MAX_EXPORT) -> tuple[str, int]:
    """(file contents, lines in it), newest first."""
    if fmt not in FORMATS:
        raise ValueError(f'format is one of {", ".join(FORMATS)}')
    rows = _rows(conn, f, max(1, min(limit, MAX_EXPORT)))
    if fmt == 'json':
        return json.dumps([{**e, 'time': _iso(e['ts'])} for e in rows], indent=1) + '\n', len(rows)
    if fmt == 'text':
        return ''.join(as_line(e) + '\n' for e in rows), len(rows)
    import csv
    import io
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(COLUMNS)
    for e in rows:
        w.writerow([_iso(e['ts'])] + [logbook._cell(e[c]) for c in COLUMNS[1:]])     # a host can write =cmd|... into a log
    return out.getvalue(), len(rows)
