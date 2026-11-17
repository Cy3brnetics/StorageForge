"""Log rules: a notification when a host logs something worth one. A rule says which lines it means (host, unit, program, lowest
level, text) and how many of them in how long. Lines are matched as they arrive (hostlogs.store), counted per rule, host and 5 minutes
by when they arrived, and a rule whose count over its window reaches its threshold is one more source in alerts.problems(): one open
alert per rule and host, however many lines there were, resolved when the count falls back under.

No pattern here is a regular expression (SF-52: one 4,000-character line took a regex 154 s). A pattern is plain text with `*` for
anything, and `|` between alternatives; matching is a run of substring searches, so its cost is bounded by the line and the pattern.
Case is ignored.

`program` is matched against what journald saw write the line (`_COMM`) when the line has it, and only otherwise against the name the
line gives itself, which anyone on the host can choose: a rule about sshd is not set off by `logger -t sshd`.

The built-in rules are for storage hosts. Their text is StorageForge's and follows the release; whether each is on, its threshold,
window and level are the operator's, and are kept across upgrades.
"""
from __future__ import annotations

import time

from .db import Conn
from .hostlogs import COUNT_SECS, LEVELS

PATTERN_CHARS, MAX_ALTERNATIVES, MAX_STARS = 300, 20, 20
MIN_WINDOW, MAX_WINDOW = 300, 7 * 86400
MAX_RULES = 200
HIT_KEEP_SECS = MAX_WINDOW + 86400
RULE_LEVELS = ('crit', 'warn', 'info')
FIELDS = ('name', 'host', 'unit', 'program', 'min_level', 'text', 'threshold', 'window_secs', 'level', 'enabled', 'note')

# key, name, program, lowest level, text, threshold, window, level, on
BUILTIN = (
    ('oom', 'Out of memory: a process was killed', 'kernel', 'warning', '*Out of memory: Killed process*|*invoked oom-killer*|*oom-kill:*', 1, 3600, 'crit', True),
    ('io-error', 'Disk or controller I/O errors', 'kernel', 'warning',
     '*I/O error, dev *|*Buffer I/O error on dev*|*critical medium error*|*Medium Error*|*ata*: failed command:*|*nvme*: I/O * timeout*|*UNC*media error*', 1, 3600, 'crit', True),
    ('fs-error', 'Filesystem errors (ext4, XFS, btrfs)', 'kernel', 'warning',
     '*EXT4-fs error*|*EXT4-fs (*): Remounting filesystem read-only*|*XFS (*): *corruption*|*XFS (*): Metadata*|*XFS (*): Filesystem has been shut down*|*BTRFS error*|*BTRFS critical*|*BTRFS: error*', 1, 3600, 'crit', True),
    ('pool-degraded', 'A ZFS pool or an md array is degraded', '*', 'warning',
     '*pool * is DEGRADED*|*state of pool*DEGRADED*|*statechange*FAULTED*|*vdev state changed*state=*FAULTED*|*md/raid*: Disk failure on *|*md*: Operation continuing on * devices*|*md*: * active with * out of * devices*', 1, 3600, 'crit', True),
    ('share-down', 'An NFS or SMB server is not responding', 'kernel', 'warning', '*nfs: server * not responding*|*CIFS: VFS: *has not responded in*|*CIFS*server * not responding*', 1, 1800, 'warn', True),
    ('unit-failed', 'Services failing', 'systemd', 'warning', '*Failed with result *|Failed to start *', 3, 3600, 'warn', True),
    ('segfault', 'Programs crashing', 'kernel', 'info', '*segfault at *|*general protection fault*', 3, 3600, 'warn', True),
    ('disk-full', 'No space left on a device', '*', 'warning', '*No space left on device*', 3, 3600, 'warn', True),
    ('ssh-failed', 'A burst of failed SSH logins', 'sshd*', 'info', 'Failed password for *|Invalid user * from *|*authentication failure*rhost=*|Connection closed by authenticating user *', 20, 600, 'warn', False),
    ('sudo-failed', 'A burst of failed sudo logins', 'sudo', 'notice', '*authentication failure*|*incorrect password attempt*', 5, 600, 'warn', False),
)


# ── patterns ────────────────────────────────────────────────────────
def compile_pattern(text: str) -> list[list[str]] | None:
    """A pattern as its alternatives, each the pieces between its stars, lower case. None for the pattern that matches anything."""
    text = str(text or '*').strip().lower()
    if len(text) > PATTERN_CHARS:
        raise ValueError(f'a pattern is at most {PATTERN_CHARS} characters')
    alts = [a.strip() for a in text.split('|')]
    if any(not a for a in alts):
        raise ValueError('a pattern has an empty alternative: take the stray | out')
    if len(alts) > MAX_ALTERNATIVES:
        raise ValueError(f'a pattern has at most {MAX_ALTERNATIVES} alternatives')
    if any(a.count('*') > MAX_STARS for a in alts):
        raise ValueError(f'an alternative has at most {MAX_STARS} stars')
    if any(not a.strip('*') for a in alts):
        return None
    return [a.split('*') for a in alts]


def matches(compiled: list[list[str]] | None, value: str) -> bool:
    """Whether a compiled pattern takes the value. Each alternative is its pieces found in order, the first at the start and the last
    at the end unless a star stands there."""
    if compiled is None:
        return True
    s = (value or '').lower()
    for parts in compiled:
        if len(parts) == 1:
            if s == parts[0]:
                return True
            continue
        first, last = parts[0], parts[-1]
        if not s.startswith(first):
            continue
        pos, ok = len(first), True
        for piece in parts[1:-1]:
            at = s.find(piece, pos)
            if at < 0:
                ok = False
                break
            pos = at + len(piece)
        if ok and len(s) - pos >= len(last) and s.endswith(last):
            return True
    return False


# ── the rules ───────────────────────────────────────────────────────
_COLS = 'rule_id, name, builtin, host, unit, program, min_level, text, threshold, window_secs, level, enabled, note, updated_by, updated_at'


def ensure_builtin(conn: Conn):
    """The built-in rules are there, with this release's text. What the operator may change on one is left as they set it."""
    have = {r[0]: r[1:] for r in conn.all('SELECT builtin, name, program, min_level, text FROM log_rules WHERE builtin IS NOT NULL')}
    now = int(time.time())
    for key, name, program, lowest, text, threshold, window, level, on in BUILTIN:
        want = (name, program, LEVELS.index(lowest), text)
        if key not in have:
            conn.execute("""INSERT INTO log_rules (name, builtin, program, min_level, text, threshold, window_secs, level, enabled, updated_at)
                            VALUES (:n, :k, :p, :l, :t, :th, :w, :lv, :e, :at)""",
                         {'n': name, 'k': key, 'p': program, 'l': want[2], 't': text, 'th': threshold, 'w': window, 'lv': level, 'e': 1 if on else 0, 'at': now})
        elif tuple(have[key]) != want:
            conn.execute('UPDATE log_rules SET name = :n, program = :p, min_level = :l, text = :t WHERE builtin = :k', {'n': name, 'p': program, 'l': want[2], 't': text, 'k': key})


def _rule(r) -> dict:
    x = dict(zip(('id', 'name', 'builtin', 'host', 'unit', 'program', 'min_level', 'text', 'threshold', 'window_secs', 'level', 'enabled', 'note', 'updated_by', 'updated_at'), r))
    x['min_level'], x['enabled'] = LEVELS[x['min_level']], bool(x['enabled'])
    return x


def rules(conn: Conn) -> list[dict]:
    with conn.tx():
        ensure_builtin(conn)
    return [_rule(r) for r in conn.all(f'SELECT {_COLS} FROM log_rules ORDER BY builtin IS NULL, rule_id')]


def clean(body: dict, builtin: bool = False) -> dict:
    """What may be saved, or ValueError saying what is wrong. On a built-in rule only enabled, threshold, window, level and the note change."""
    out = {}
    if not builtin:
        name = str(body.get('name') or '').strip()
        if not 1 <= len(name) <= 100:
            raise ValueError('a rule needs a name of up to 100 characters')
        out['name'] = name
        for field in ('host', 'unit', 'program', 'text'):
            value = str(body.get(field) or '*').strip()
            compile_pattern(value)
            out[field] = value
        lowest = str(body.get('min_level') or 'debug').strip().lower()
        if lowest not in LEVELS:
            raise ValueError(f'the lowest level is one of {", ".join(LEVELS)}')
        out['min_level'] = LEVELS.index(lowest)
        if all(compile_pattern(out[f]) is None for f in ('unit', 'program', 'text')) and out['min_level'] >= LEVELS.index('info'):
            raise ValueError('this rule would match every line a host logs: give it a unit, a program, some text, or a level of notice or worse')
    try:
        threshold = int(1 if body.get('threshold') is None else body['threshold'])
        window = int(3600 if body.get('window_secs') is None else body['window_secs'])
    except (TypeError, ValueError):
        raise ValueError('the threshold and the window are whole numbers') from None
    if not 1 <= threshold <= 1_000_000:
        raise ValueError('the threshold is from 1 to a million lines')
    if not MIN_WINDOW <= window <= MAX_WINDOW:
        raise ValueError('the window is from 5 minutes to 7 days')
    level = str(body.get('level') or 'warn')
    if level not in RULE_LEVELS:
        raise ValueError(f'the level is one of {", ".join(RULE_LEVELS)}')
    return {**out, 'threshold': threshold, 'window_secs': window, 'level': level, 'enabled': 1 if body.get('enabled', True) else 0, 'note': str(body.get('note') or '')[:500]}


def save(conn: Conn, body: dict, actor: str, rule_id: int | None = None) -> dict:
    with conn.tx():
        ensure_builtin(conn)
        if rule_id is None:
            if conn.scalar('SELECT count(*) FROM log_rules') >= MAX_RULES:
                raise ValueError(f'there are {MAX_RULES} rules already')
            values = clean(body)
            if conn.scalar('SELECT 1 FROM log_rules WHERE name = :n', {'n': values['name']}):
                raise ValueError('a rule has that name already')
            rule_id = conn.scalar(f"""INSERT INTO log_rules ({', '.join(values)}, updated_by, updated_at)
                                      VALUES ({', '.join(':' + k for k in values)}, :by, :at) RETURNING rule_id""", {**values, 'by': actor, 'at': int(time.time())})
        else:
            row = conn.all('SELECT builtin FROM log_rules WHERE rule_id = :i', {'i': rule_id})
            if not row:
                raise LookupError('no such rule')
            values = clean(body, builtin=row[0][0] is not None)
            if 'name' in values and conn.scalar('SELECT 1 FROM log_rules WHERE name = :n AND rule_id <> :i', {'n': values['name'], 'i': rule_id}):
                raise ValueError('a rule has that name already')
            conn.execute(f"UPDATE log_rules SET {', '.join(f'{k} = :{k}' for k in values)}, updated_by = :by, updated_at = :at WHERE rule_id = :i",
                         {**values, 'by': actor, 'at': int(time.time()), 'i': rule_id})
    return next(r for r in rules(conn) if r['id'] == rule_id)


def delete(conn: Conn, rule_id: int) -> dict:
    row = conn.all(f'SELECT {_COLS} FROM log_rules WHERE rule_id = :i', {'i': rule_id})
    if not row:
        raise LookupError('no such rule')
    if row[0][2] is not None:
        raise ValueError('a built-in rule is turned off, not deleted')
    with conn.tx():
        conn.execute('DELETE FROM log_rule_hits WHERE rule_id = :i', {'i': rule_id})
        conn.execute('DELETE FROM log_rules WHERE rule_id = :i', {'i': rule_id})
    return _rule(row[0])


# ── matching, as lines arrive ───────────────────────────────────────
def _compiled(conn: Conn) -> list[tuple]:
    out = []
    for r in conn.all('SELECT rule_id, host, unit, program, min_level, text FROM log_rules WHERE enabled = 1'):
        try:
            out.append((r[0], compile_pattern(r[1]), compile_pattern(r[2]), compile_pattern(r[3]), r[4], compile_pattern(r[5])))
        except ValueError:          # a rule that was saved by an older release and no longer compiles matches nothing
            continue
    return out


def match_new(conn: Conn, host: str, lines: list[dict], now: float) -> int:
    """Counts the lines that are new this pickup against every rule that is on. Called inside hostlogs.store's transaction."""
    if not lines:
        return 0
    ensure_builtin(conn)
    compiled = [c for c in _compiled(conn) if matches(c[1], host)]
    bucket, total = int(now // COUNT_SECS), 0
    for rule_id, _h, unit, program, min_level, text in compiled:
        hits, sample = 0, ''
        for x in lines:
            if x['priority'] > min_level:
                continue
            unit_name = x.get('unit') or ''
            if unit is not None and not (matches(unit, unit_name) or matches(unit, unit_name.removesuffix('.service'))):
                continue
            if program is not None and not matches(program, x.get('comm') or x.get('ident') or ''):
                continue
            if not matches(text, x['message']):
                continue
            hits += 1
            sample = x['message']
        if hits:
            total += hits
            conn.execute("""INSERT INTO log_rule_hits (rule_id, host, bucket, hits, sample) VALUES (:r, :h, :b, :n, :s)
                            ON CONFLICT (rule_id, host, bucket) DO UPDATE SET hits = log_rule_hits.hits + :n, sample = :s""",
                         {'r': rule_id, 'h': host, 'b': bucket, 'n': hits, 's': sample[:300]})
    conn.execute('DELETE FROM log_rule_hits WHERE bucket < :b', {'b': int((now - HIT_KEEP_SECS) // COUNT_SECS)})
    return total


# ── as a source of alerts ───────────────────────────────────────────
def problems(conn: Conn, now: float | None = None) -> dict:
    """{key: (kind, ref, title, message, level)} for alerts.problems(): one per rule and host over its threshold in its window."""
    now = time.time() if now is None else now
    out = {}
    for rule_id, name, threshold, window, level in conn.all('SELECT rule_id, name, threshold, window_secs, level FROM log_rules WHERE enabled = 1'):
        since = int((now - window) // COUNT_SECS)
        for host, hits, newest in conn.all("""SELECT host, sum(hits), max(bucket) FROM log_rule_hits WHERE rule_id = :r AND bucket >= :b
                                              GROUP BY host HAVING sum(hits) >= :t""", {'r': rule_id, 'b': since, 't': threshold}):
            sample = conn.scalar('SELECT sample FROM log_rule_hits WHERE rule_id = :r AND host = :h AND bucket = :b', {'r': rule_id, 'h': host, 'b': newest}) or ''
            span = f'{window // 3600} h' if window % 3600 == 0 else f'{window // 60} min'
            out[f'log-rule:{rule_id}:{host}'] = ('log-rule', f'{host}:{rule_id}', f'{name} on {host}',
                                                  f'{int(hits)} line(s) in the last {span} (the rule asks for {threshold}). The last: {sample}', level)
    return out
