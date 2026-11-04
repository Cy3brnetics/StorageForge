"""Host logs: what each host's journal said, picked up by the scan and kept here to search. Nothing runs between scans
and nothing streams: to see newer logs, scan the host.

A scan asks for what is new since the last one, up to LINES_IMPORTANT at warning or worse and LINES_ROUTINE at info or
worse, so a chatty service can't push errors out. Lines are one row each: time, host, level, unit, program, pid, message.

The journal holds what programs chose to print, which can include passwords, so known secret shapes are removed before a
line is stored. That catches common forms, not every form. It is also the host's own word: anyone on the host can write
to it, so a line says what was logged, not that it happened. Only `unit` comes from journald rather than the program.

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
MAX_EXPORT = 20000
JOURNAL_GROUPS = {'systemd-journal', 'adm', 'wheel', 'root'}                # the groups journald's files are readable by
FIELDS = 'MESSAGE,PRIORITY,_SYSTEMD_UNIT,SYSLOG_IDENTIFIER,_PID'            # never _CMDLINE: that is where passwords sit
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
pull() {{ LC_ALL=C journalctl $fields -o json --no-pager --since "@{int(since)}" "$@" 2>/dev/null | head -c {STREAM_BYTES}; echo; }}
echo '@@important'; pull -p warning -n {LINES_IMPORTANT}
echo '@@routine'; pull -p info -n {LINES_ROUTINE}
echo '@@end'
"""


# ── secrets ─────────────────────────────────────────────────────────
_SECRET_WORD = r'(?:password|passwd|passphrase|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|authorization|cookie)'
_VALUE = r'''(?:"[^"]*"|'[^']*'|\S+)'''
_SCRUB = (
    # key=value, key: value, "key":"value", and an optional scheme word: PASSWORD=x, MYSQL_PASSWORD=x, Authorization: Bearer x
    (re.compile(rf'''(?i)([\w.-]*{_SECRET_WORD}[\w.-]*["']?\s*[=:]\s*)(?:(?:bearer|basic|token)\s+)?{_VALUE}'''), r'\1[redacted]'),
    (re.compile(rf'(?i)(--[\w-]*(?:password|passwd|passphrase|token|secret|api-?key)[\w-]*[\s=]+){_VALUE}'), r'\1[redacted]'),
    (re.compile(r'(?i)\b(sshpass\s+-p\s*)\S+'), r'\1[redacted]'),
    (re.compile(r'(?i)\b(mysql(?:dump|admin)?\b[^|;&]*?\s-p)\S+'), r'\1[redacted]'),
    (re.compile(r'(?i)\b(bearer\s+)[A-Za-z0-9._~+/=-]{8,}'), r'\1[redacted]'),
    (re.compile(r'(://[^/\s:@]+:)[^/\s@]+(@)'), r'\1[redacted]\2'),
    (re.compile(r'\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+'), '[redacted]'),     # JWT
    (re.compile(r'\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_\w{20,}|glpat-[\w-]{16,}|xox[abprs]-[\w-]{10,}|sk-[\w-]{20,}|AKIA[0-9A-Z]{16})\b'), '[redacted]'),
)
_PRIVATE_KEY = re.compile(r'-----BEGIN [A-Z ]*PRIVATE KEY')
_CONTROL = re.compile(r'[\x00-\x1f\x7f-\x9f  ‪-‮⁦-⁩]+')    # terminal escapes, line breaks, text direction


def scrub(message: str) -> str:
    if _PRIVATE_KEY.search(message):
        return '[redacted: this line held a private key]'
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
            'pid': pid, 'message': message}


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


def store(conn: Conn, host: str, parsed: dict, now: float | None = None) -> int:
    """Saves one scan's lines. Returns how many were new."""
    now = time.time() if now is None else now
    lines, state, cut = parsed['lines'], parsed['state'], parsed['cut']
    new = 0
    with conn.tx():
        for x in lines:
            new += conn.execute("""INSERT INTO host_log_lines (host, line_key, at_us, priority, unit, ident, pid, message, collected_at)
                                   VALUES (:h, :k, :a, :p, :u, :i, :d, :m, :t) ON CONFLICT (host, line_key) DO NOTHING""",
                                {'h': host, 'k': x['key'], 'a': x['at_us'], 'p': x['priority'], 'u': x['unit'], 'i': x['ident'],
                                 'd': x['pid'], 'm': x['message'], 't': int(now)}).rowcount
        # not advanced by a line stamped in the future, or the next scan would ask from then and find nothing
        seen = [x['at_us'] for x in lines if x['at_us'] <= now * 1e6]
        note = HINTS.get(state, '')
        if cut:
            note = 'more lines were logged than one scan keeps: the oldest of them were not collected. Scan more often to get them all.'
        _set_status(conn, host, int(now), state, new, cut, max(seen) if seen else None, note)
        prune(conn, host, now)
    return new


def prune(conn: Conn, host: str, now: float):
    conn.execute('DELETE FROM host_log_lines WHERE host = :h AND at_us < :t', {'h': host, 't': int((now - KEEP_DAYS * 86400) * 1e6)})
    edge = conn.scalar('SELECT at_us FROM host_log_lines WHERE host = :h ORDER BY at_us DESC LIMIT 1 OFFSET :n', {'h': host, 'n': KEEP_ROWS})
    if edge is not None:
        conn.execute('DELETE FROM host_log_lines WHERE host = :h AND at_us <= :t', {'h': host, 't': edge})


def collect(conn: Conn, t, host: str, log=lambda _: None) -> dict | None:
    """One scan's log pickup. A failure here is said and recorded; it never costs the scan its files."""
    if not enabled():
        return None
    now = time.time()
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
    rows = conn.all(f"""SELECT at_us, host, priority, unit, ident, pid, message FROM host_log_lines{where}
                        ORDER BY at_us DESC, line_id DESC LIMIT :n OFFSET :o""", p)
    return [{'ts': r[0] / 1e6, 'host': r[1], 'level': LEVELS[r[2]], 'priority': r[2], 'unit': r[3], 'ident': r[4], 'pid': r[5], 'message': r[6]} for r in rows]


def page(conn: Conn, f: dict, limit: int = 100, offset: int = 0) -> dict:
    rows = _rows(conn, f, limit + 1, offset)
    return {'entries': rows[:limit], 'more': len(rows) > limit, 'limit': limit, 'offset': offset}


def status(conn: Conn, host: str | None = None) -> list[dict]:
    """Per host: the last pickup, what is kept, and the oldest and newest lines. A host never collected isn't listed."""
    rows = conn.all(f"""SELECT s.host, s.collected_at, s.state, s.new_lines, s.cut, s.note,
                               (SELECT count(*) FROM host_log_lines l WHERE l.host = s.host),
                               (SELECT min(at_us) FROM host_log_lines l WHERE l.host = s.host),
                               (SELECT max(at_us) FROM host_log_lines l WHERE l.host = s.host)
                        FROM host_log_status s {'WHERE s.host = :h' if host else ''} ORDER BY s.host""", {'h': host})
    return [{'host': r[0], 'collected_at': r[1], 'state': r[2], 'new_lines': r[3], 'cut': bool(r[4]), 'note': r[5], 'lines': r[6],
             'oldest': r[7] / 1e6 if r[7] else None, 'newest': r[8] / 1e6 if r[8] else None} for r in rows]


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
