"""Unified Scheduler: schedules any task StorageForge can do (Storage task blocks, Change plans,
Move plans, Host scans, and arbitrary Commands) as cron jobs on client hosts with comprehensive server-side verification.
"""
from __future__ import annotations

import datetime as dt
import functools
import hashlib
import json
import re
import secrets
import shlex
import subprocess
import sys
import time
import zoneinfo
from typing import Any

from . import site
from . import alerts, changes, moves, schedscript, tasks
from .db import Conn, epoch
from .moves import find_host, host_slug, hosts, slug
from .scriptkit import HELPERS, longest_gap

CRON_ALIASES = {
    '@yearly': '0 0 1 1 *',
    '@annually': '0 0 1 1 *',
    '@monthly': '0 0 1 * *',
    '@weekly': '0 0 * * 0',
    '@daily': '0 0 * * *',
    '@midnight': '0 0 * * *',
    '@hourly': '0 * * * *',
}

MONTH_NAMES = {'jan': 1, 'feb': 2, 'mar': 3, 'apr': 4, 'may': 5, 'jun': 6,
               'jul': 7, 'aug': 8, 'sep': 9, 'oct': 10, 'nov': 11, 'dec': 12}
DOW_NAMES = {'sun': 0, 'mon': 1, 'tue': 2, 'wed': 3, 'thu': 4, 'fri': 5, 'sat': 6}

TASK_TYPES = ('task', 'change', 'move', 'shares', 'scan', 'command')
CONCURRENCY_POLICIES = ('skip', 'queue', 'replace')
VERIFY_POLICIES = ('comprehensive', 'state_only', 'report_only', 'none')
NAME_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$')
HOST_RE = re.compile(r'^(?!-)([A-Za-z0-9._-]{1,32}@)?(?!-)[A-Za-z0-9.:_\[\]-]{1,253}$')
WINDOW_RE = re.compile(r'^\d{2}:\d{2}-\d{2}:\d{2}$')
MASK = '••••••'
# Variables that change what a shell or interpreter runs: a schedule's env must not turn a reviewed script into something else
UNSAFE_ENV = re.compile(r'(LD_|BASH_|GIT_|PYTHON|PERL|RUBY|NODE_).*|ENV|PATH|IFS|SHELLOPTS|BASHOPTS|PS4|HOME', re.I)
REGEX_SECONDS = 2


class StillDeployed(ValueError):
    pass


# ── Cron Expression Parsing & Calculation ──────────────────────────────────────

def _parse_field(field_str: str, min_val: int, max_val: int, name_map: dict[str, int] | None = None) -> set[int]:
    """Parses a single cron field (supports *, lists, ranges, steps, and optional name mappings)."""
    s = field_str.strip().lower()
    if name_map:
        for name, val in name_map.items():
            s = re.sub(rf'\b{name}\b', str(val), s)
    values = set()
    for part in s.split(','):
        part = part.strip()
        if not part:
            continue
        step = 1
        if '/' in part:
            subparts = part.split('/')
            if len(subparts) != 2:
                raise ValueError(f'invalid step expression: {part}')
            part, step_str = subparts[0], subparts[1]
            try:
                step = int(step_str)
                if step <= 0:
                    raise ValueError
            except ValueError:
                raise ValueError(f'invalid step value: {step_str}') from None

        if part in ('*', ''):
            start, end = min_val, max_val
        elif '-' in part:
            rng = part.split('-')
            if len(rng) != 2:
                raise ValueError(f'invalid range expression: {part}')
            try:
                start, end = int(rng[0]), int(rng[1])
            except ValueError:
                raise ValueError(f'invalid range bounds: {part}') from None
        else:
            try:
                val = int(part)
                start = end = val
            except ValueError:
                raise ValueError(f'invalid field item: {part}') from None

        if start < min_val or end > max_val or start > end:
            raise ValueError(f'value out of range [{min_val}-{max_val}]: {part}')
        for v in range(start, end + 1, step):
            values.add(v)
    if not values:
        raise ValueError('cron field resolved to no values')
    return values


def parse_cron(expr: str) -> tuple[set[int], set[int], set[int], set[int], set[int]]:
    """Parses a cron expression into sets of (minutes, hours, dom, months, dow)."""
    raw = expr.strip()
    raw = CRON_ALIASES.get(raw, raw)
    parts = raw.split()
    if len(parts) != 5:
        raise ValueError(f'cron expression must have 5 fields (minute hour dom month dow), got {len(parts)}: {expr!r}')
    mins = _parse_field(parts[0], 0, 59)
    hours = _parse_field(parts[1], 0, 23)
    dom = _parse_field(parts[2], 1, 31)
    months = _parse_field(parts[3], 1, 12, MONTH_NAMES)
    dow = _parse_field(parts[4], 0, 7, DOW_NAMES)
    if 7 in dow:
        dow.add(0)  # 0 and 7 are both Sunday
    return mins, hours, dom, months, dow


def validate_cron(expr: str) -> bool:
    try:
        parse_cron(expr)
        return True
    except Exception:
        return False


def next_run(expr: str, after_ts: int | None = None, tz_name: str = 'UTC') -> int:
    """Computes next unix timestamp matching the cron expression strictly after after_ts."""
    mins, hours, doms, months, dows = parse_cron(expr)
    try:
        tz = zoneinfo.ZoneInfo(tz_name or 'UTC')
    except Exception:
        tz = zoneinfo.ZoneInfo('UTC')

    now_ts = int(time.time()) if after_ts is None else int(after_ts)
    dt_cur = dt.datetime.fromtimestamp(now_ts, tz=tz)
    # Start looking from the next full minute
    dt_next = (dt_cur + dt.timedelta(minutes=1)).replace(second=0, microsecond=0)

    # Search up to 5 years ahead minute by minute / day jump
    for _ in range(5 * 366 * 24 * 60):
        if dt_next.month not in months:
            # Advance to first day of next month
            y = dt_next.year + (1 if dt_next.month == 12 else 0)
            m = 1 if dt_next.month == 12 else dt_next.month + 1
            dt_next = dt_next.replace(year=y, month=m, day=1, hour=0, minute=0)
            continue
        weekday = (dt_next.weekday() + 1) % 7  # 0 = Sunday, 1 = Monday ... 6 = Saturday
        if dt_next.day not in doms or weekday not in dows:
            # Advance to next day at 00:00
            dt_next = (dt_next + dt.timedelta(days=1)).replace(hour=0, minute=0)
            continue
        if dt_next.hour not in hours:
            # Advance to next hour at 00 min
            dt_next = (dt_next + dt.timedelta(hours=1)).replace(minute=0)
            continue
        if dt_next.minute in mins:
            return int(dt_next.timestamp())
        dt_next += dt.timedelta(minutes=1)

    raise ValueError(f'cannot find next run occurrence within 5 years for cron: {expr}')


@functools.lru_cache(maxsize=512)
def period(expr: str) -> int:
    """The longest wait between runs of a cron expression, in seconds: a schedule is only late once that has passed."""
    try:
        mins, hours, doms, months, dows = parse_cron(expr)
    except ValueError:
        return 86400
    gap = longest_gap(lambda d: d.month in months and d.day in doms and (d.weekday() + 1) % 7 in dows, [h * 60 + m for h in hours for m in mins])
    return max(60, gap) if gap else 86400


# ── Configuration Normalization ───────────────────────────────────────────────

def normalize_config(body: dict) -> dict:
    """Validates and normalizes all configuration options for a schedule."""
    cfg = dict(body.get('config') or body.get('config_json') or {})
    if isinstance(cfg, str):
        try:
            cfg = json.loads(cfg)
        except Exception:
            cfg = {}

    tz = str(cfg.get('timezone') or 'UTC').strip()
    try:
        zoneinfo.ZoneInfo(tz)
    except Exception:
        tz = 'UTC'

    window = str(cfg.get('window') or '').strip()
    if window and not WINDOW_RE.fullmatch(window):
        raise ValueError('window must be in HH:MM-HH:MM format, e.g. "02:00-05:00"')

    timeout = int(cfg.get('timeout_sec') if cfg.get('timeout_sec') is not None else 3600)
    if not (0 <= timeout <= 864000):
        raise ValueError('timeout_sec must be between 0 (none) and 864000 seconds')

    concurrency = str(cfg.get('concurrency_policy') or 'skip').strip().lower()
    if concurrency not in CONCURRENCY_POLICIES:
        raise ValueError(f'concurrency_policy must be one of {", ".join(CONCURRENCY_POLICIES)}')

    retries = int(cfg.get('retry_count') or 0)
    if not (0 <= retries <= 10):
        raise ValueError('retry_count must be between 0 and 10')

    retry_delay = int(cfg.get('retry_delay_sec') or 30)
    if not (1 <= retry_delay <= 3600):
        raise ValueError('retry_delay_sec must be between 1 and 3600')

    retry_backoff = float(cfg.get('retry_backoff') or 1.0)
    if not (1.0 <= retry_backoff <= 10.0):
        raise ValueError('retry_backoff must be between 1.0 and 10.0')

    nice = int(cfg.get('nice') if cfg.get('nice') is not None else 10)
    if not (-20 <= nice <= 19):
        raise ValueError('nice must be between -20 and 19')

    ionice_class = str(cfg.get('ionice_class') or 'best-effort').strip().lower()
    if ionice_class not in ('idle', 'best-effort', 'realtime'):
        raise ValueError('ionice_class must be idle, best-effort, or realtime')

    ionice_priority = int(cfg.get('ionice_priority') if cfg.get('ionice_priority') is not None else 7)
    if not (0 <= ionice_priority <= 7):
        raise ValueError('ionice_priority must be between 0 and 7')

    user = str(cfg.get('user') or 'root').strip()
    if not re.fullmatch(r'^[a-z_][a-z0-9_-]{0,31}$', user):
        raise ValueError('invalid user name')

    raw_env = cfg.get('env') or {}
    env = {}
    if isinstance(raw_env, dict):
        for k, v in raw_env.items():
            if re.fullmatch(r'^[A-Za-z_][A-Za-z0-9_]*$', str(k)) and not UNSAFE_ENV.fullmatch(str(k)):
                env[str(k)] = str(v)[:1000]

    jitter = int(cfg.get('jitter_sec') or 0)
    if not (0 <= jitter <= 300):
        raise ValueError('jitter_sec must be between 0 and 300')

    verify_policy = str(cfg.get('verify_policy') or 'comprehensive').strip().lower()
    if verify_policy not in VERIFY_POLICIES:
        raise ValueError(f'verify_policy must be one of {", ".join(VERIFY_POLICIES)}')

    raw_vr = cfg.get('verify_rules') or {}
    if not isinstance(raw_vr, dict):
        raise ValueError('verify_rules must be an object')
    verify_rules = {
        'require_exit_zero': bool(raw_vr.get('require_exit_zero', True)),
        'check_mounts': [str(p).strip() for p in raw_vr.get('check_mounts') or [] if str(p).strip().startswith('/')],
        'min_free_gib': {str(p): int(g) for p, g in (raw_vr.get('min_free_gib') or {}).items() if int(g) > 0},
        'paths_must_exist': [str(p).strip() for p in raw_vr.get('paths_must_exist') or [] if str(p).strip().startswith('/')],
        'paths_must_not_exist': [str(p).strip() for p in raw_vr.get('paths_must_not_exist') or [] if str(p).strip().startswith('/')],
        'output_must_match': str(raw_vr.get('output_must_match') or '').strip()[:200],
        'output_must_not_match': str(raw_vr.get('output_must_not_match') or '').strip()[:200],
        'auto_rescan': bool(raw_vr.get('auto_rescan')),
    }

    notify_on = list(cfg.get('notify_on') or ['failure', 'verify_failure'])

    return {
        'timezone': tz,
        'window': window,
        'timeout_sec': timeout,
        'concurrency_policy': concurrency,
        'retry_count': retries,
        'retry_delay_sec': retry_delay,
        'retry_backoff': retry_backoff,
        'nice': nice,
        'ionice_class': ionice_class,
        'ionice_priority': ionice_priority,
        'user': user,
        'env': env,
        'jitter_sec': jitter,
        'verify_policy': verify_policy,
        'verify_rules': verify_rules,
        'notify_on': notify_on,
        'destructive': False,      # stays in the record so a deployed schedule's hash does not change; see _no_destructive
    }


def normalize_schedule(body: dict) -> dict:
    """Validates top-level schedule fields."""
    name = str(body.get('name') or '').strip()
    if not NAME_RE.fullmatch(name):
        raise ValueError('name must be 1-80 characters using alphanumeric, dots, dashes, or underscores')
    host = str(body.get('host') or '').strip()
    if not host or not HOST_RE.fullmatch(host):
        raise ValueError('host must be a valid host identifier')
    cron_expr = str(body.get('cron_expr') or '').strip()
    if not validate_cron(cron_expr):
        raise ValueError(f'invalid cron expression: {cron_expr!r}')
    task_type = str(body.get('task_type') or '').strip().lower()
    if task_type not in TASK_TYPES:
        raise ValueError(f'task_type must be one of {", ".join(TASK_TYPES)}')
    task_ref = str(body.get('task_ref') or '').strip()
    if not task_ref:
        raise ValueError('task_ref cannot be empty')

    cfg = normalize_config(body)
    return {
        'name': name,
        'host': host,
        'cron_expr': cron_expr,
        'task_type': task_type,
        'task_ref': task_ref,
        'config': cfg,
        'paused': 1 if body.get('paused') else 0,
    }


def _plan_id(conn: Conn, table: str, ref: str) -> int:
    pid = int(ref) if ref.isdigit() else conn.scalar(f'SELECT plan_id FROM {table} WHERE lower(name) = lower(:n)', {'n': ref})
    if not pid:
        raise LookupError(f'plan "{ref}" not found')
    return pid


def _target_hash(conn: Conn, schedule: dict) -> str:
    """A fingerprint of what the schedule runs, the same one a deploy of the plan itself uses."""
    from . import jobs, shares
    ttype, ref = schedule['task_type'], schedule['task_ref']
    try:
        if ttype == 'task':
            return tasks.task_hash(_resolve_task(conn, ref))
        if ttype == 'change':
            return changes.plan_hash(changes.get_plan(conn, _plan_id(conn, 'change_plans', ref)))
        if ttype == 'move':
            return jobs.plan_hash(moves.get_plan(conn, _plan_id(conn, 'move_plans', ref)))
        if ttype == 'shares':
            return shares.design_hash(conn, ref) or ''
    except LookupError:
        return 'missing'
    return ''


def schedule_hash(conn: Conn, schedule: dict) -> str:
    """Returns a 16-char SHA-256 fingerprint of the schedule and of what it runs: editing the plan changes it too."""
    text = json.dumps(normalize_schedule(schedule), sort_keys=True) + _target_hash(conn, schedule)
    return hashlib.sha256(text.encode()).hexdigest()[:16]


def holds_commands(conn: Conn, schedule: dict) -> bool:
    """Whether deploying this schedule puts raw commands on its host, in itself or in what it runs."""
    ttype, ref = schedule['task_type'], schedule['task_ref']
    try:
        if ttype == 'task':
            return tasks.has_command(_resolve_task(conn, ref))
        if ttype == 'move':
            return moves.has_raw_hooks(moves.get_plan(conn, _plan_id(conn, 'move_plans', ref)))
    except LookupError:
        return False
    return ttype == 'command'


def check_target(conn: Conn, schedule: dict):
    """What a schedule runs must be meant for the host it runs on: a script applies whatever it holds, wherever it lands."""
    from .fsmap import same_host
    ttype, ref, host = schedule['task_type'], schedule['task_ref'], schedule['host']
    if ttype == 'task':
        named = [_resolve_task(conn, ref)['host']]
    elif ttype == 'change':
        named = [t['host'] for t in changes.get_plan(conn, _plan_id(conn, 'change_plans', ref)).get('tasks') or []]
    elif ttype == 'move':
        named = [s['dst']['host'] for s in moves.get_plan(conn, _plan_id(conn, 'move_plans', ref)).get('steps') or []]
    elif ttype == 'shares':
        named = [ref]
    else:
        return
    other = sorted({n for n in named if n and not same_host(n, host)})
    if other:
        raise ValueError(f'this {ttype} is for {", ".join(other)}, not {host}: schedule it there')


def _check_save(conn: Conn, body: dict, s: dict):
    """Refuses at save what would fail, or run something else, on a timer later. Saved rows are not held to this, so a
    schedule from an older version can still be read, hashed and uninstalled."""
    _no_destructive(body)
    if s['task_type'] == 'scan':
        raise ValueError('StorageForge scans hosts from the server: set the host\'s own scan interval instead')
    raw = (body.get('config') or body.get('config_json') or {})
    unsafe = sorted(k for k in (raw.get('env') or {}) if UNSAFE_ENV.fullmatch(str(k)))
    if unsafe:
        raise ValueError(f'these variables would change what the script runs: {", ".join(unsafe)}')
    # Generated scripts read no variables, so here one could only change a program they call (RSYNC_RSH, TAR_OPTIONS and
    # more than any list can name), which would make a plan a root shell without hosts.command.
    if s['config']['env'] and s['task_type'] != 'command':
        raise ValueError('only a command schedule takes environment variables')
    if s['config']['window'] and not moves.WINDOW_RE.fullmatch(s['config']['window']):
        raise ValueError('window must be real times, e.g. "02:00-05:00"')
    for key in ('output_must_match', 'output_must_not_match'):
        try:
            re.compile(s['config']['verify_rules'][key])
        except re.error as exc:
            raise ValueError(f'{key} is not a valid pattern: {exc}') from None
    if s['config']['user'] != 'root' and s['task_type'] != 'command':
        raise ValueError('only a command can run as another user: tasks, plans and shares need root')
    try:
        check_target(conn, s)
        s['task_ref'] = _ref_to_id(conn, s)
    except LookupError as exc:
        raise ValueError(str(exc)) from None


def _ref_to_id(conn: Conn, s: dict) -> str:
    """What a schedule runs, by id: a name typed here would break, or point elsewhere, when plans are renamed."""
    if s['task_type'] == 'task':
        return str(_resolve_task(conn, s['task_ref'])['id'])
    if s['task_type'] == 'change':
        return str(_plan_id(conn, 'change_plans', s['task_ref']))
    if s['task_type'] == 'move':
        return str(_plan_id(conn, 'move_plans', s['task_ref']))
    return s['task_ref']


# ── Database Operations ────────────────────────────────────────────────────────

def _no_destructive(body: dict):
    """Destructive steps wipe drives: one-off work that a person holding deploy.destructive applies from a change plan,
    never something a timer repeats."""
    cfg = body.get('config') or body.get('config_json')
    if isinstance(cfg, dict) and cfg.get('destructive'):
        raise ValueError('a schedule cannot run destructive steps: apply those once, from the change plan')


def masked(schedule: dict) -> dict:
    """A schedule for someone who may look at it but not edit it."""
    cfg = schedule['config']
    return {**schedule, 'task_ref': MASK if schedule['task_type'] == 'command' else schedule['task_ref'],
            'config': {**cfg, 'env': {k: MASK for k in cfg.get('env') or {}}}}


def create_schedule(conn: Conn, body: dict, actor: str) -> tuple[dict, str]:
    """Creates a new scheduled task and generates an authentication token for client execution reporting."""
    s = normalize_schedule(body)
    _check_save(conn, body, s)
    now = int(time.time())
    next_ts = next_run(s['cron_expr'], now, s['config']['timezone']) if not s['paused'] else None

    # Generate 32-byte hex bearer token
    token = secrets.token_hex(32)
    token_hash = hashlib.sha256(token.encode()).hexdigest()

    clash = conn.scalar('SELECT schedule_id FROM schedules WHERE lower(name) = lower(:n)', {'n': s['name']})
    if clash:
        raise ValueError(f'a schedule named "{s["name"]}" already exists')

    params = {
        'n': s['name'],
        'h': s['host'],
        'c': s['cron_expr'],
        't': s['task_type'],
        'r': s['task_ref'],
        'cfg': json.dumps(s['config']),
        'p': s['paused'],
        'th': token_hash,
        'now': now,
        'a': actor,
        'nxt': next_ts,
    }

    with conn.tx():
        sid = conn.scalar("""INSERT INTO schedules
            (name, host, cron_expr, task_type, task_ref, config_json, paused, auth_token_hash,
             created_at, updated_at, created_by, next_run_at)
            VALUES (:n, :h, :c, :t, :r, :cfg, :p, :th, :now, :now, :a, :nxt)
            RETURNING schedule_id""", params)

    return get_schedule(conn, sid), token


def get_schedule(conn: Conn, schedule_id: int) -> dict:
    rows = conn.all("""SELECT schedule_id, name, host, cron_expr, task_type, task_ref, config_json,
                              paused, created_at, updated_at, created_by, last_run_at, next_run_at, last_status
                       FROM schedules WHERE schedule_id = :id""", {'id': schedule_id})
    if not rows:
        raise LookupError(f'no schedule #{schedule_id}')
    r = rows[0]
    return {
        'schedule_id': r[0],
        'name': r[1],
        'host': r[2],
        'cron_expr': r[3],
        'task_type': r[4],
        'task_ref': r[5],
        'config': json.loads(r[6]),
        'paused': bool(r[7]),
        'created_at': r[8],
        'updated_at': r[9],
        'created_by': r[10],
        'last_run_at': r[11],
        'next_run_at': r[12],
        'last_status': r[13],
    }


def get_schedule_by_name(conn: Conn, name: str) -> dict | None:
    sid = conn.scalar('SELECT schedule_id FROM schedules WHERE lower(name) = lower(:n)', {'n': name.strip()})
    return get_schedule(conn, sid) if sid else None


def list_schedules(conn: Conn, host: str | None = None, task_type: str | None = None,
                   paused: bool | None = None) -> list[dict]:
    sql = """SELECT schedule_id, name, host, cron_expr, task_type, task_ref, config_json,
                    paused, created_at, updated_at, created_by, last_run_at, next_run_at, last_status
             FROM schedules WHERE 1=1"""
    p: dict[str, Any] = {}
    if host:
        sql += ' AND lower(host) = lower(:h)'
        p['h'] = host.strip()
    if task_type:
        sql += ' AND task_type = :t'
        p['t'] = task_type.strip()
    if paused is not None:
        sql += ' AND paused = :p'
        p['p'] = 1 if paused else 0
    sql += ' ORDER BY name'

    out = []
    for r in conn.all(sql, p):
        out.append({
            'schedule_id': r[0],
            'name': r[1],
            'host': r[2],
            'cron_expr': r[3],
            'task_type': r[4],
            'task_ref': r[5],
            'config': json.loads(r[6]),
            'paused': bool(r[7]),
            'created_at': r[8],
            'updated_at': r[9],
            'created_by': r[10],
            'last_run_at': r[11],
            'next_run_at': r[12],
            'last_status': r[13],
        })
    return out


def merged(curr: dict, body: dict) -> dict:
    """A saved schedule with an edit's fields over it."""
    return {
        'name': body.get('name', curr['name']),
        'host': body.get('host', curr['host']),
        'cron_expr': body.get('cron_expr', curr['cron_expr']),
        'task_type': body.get('task_type', curr['task_type']),
        'task_ref': body.get('task_ref', curr['task_ref']),
        'config': {**curr['config'], **(body.get('config') or body.get('config_json') or {})},
        'paused': body.get('paused', curr['paused']),
    }


def update_schedule(conn: Conn, schedule_id: int, body: dict, actor: str) -> dict:
    curr = get_schedule(conn, schedule_id)
    s = normalize_schedule(merged(curr, body))
    _check_save(conn, body, s)
    now = int(time.time())

    clash = conn.scalar('SELECT schedule_id FROM schedules WHERE lower(name) = lower(:n) AND schedule_id != :id',
                        {'n': s['name'], 'id': schedule_id})
    if clash:
        raise ValueError(f'a schedule named "{s["name"]}" already exists')

    next_ts = next_run(s['cron_expr'], now, s['config']['timezone']) if not s['paused'] else None

    params = {
        'id': schedule_id,
        'n': s['name'],
        'h': s['host'],
        'c': s['cron_expr'],
        't': s['task_type'],
        'r': s['task_ref'],
        'cfg': json.dumps(s['config']),
        'p': s['paused'],
        'now': now,
        'nxt': next_ts,
    }

    conn.execute("""UPDATE schedules
                    SET name = :n, host = :h, cron_expr = :c, task_type = :t, task_ref = :r,
                        config_json = :cfg, paused = :p, updated_at = :now, next_run_at = :nxt
                    WHERE schedule_id = :id""", params)
    return get_schedule(conn, schedule_id)


def changed_since_deploy(conn: Conn, schedule: dict) -> bool:
    """Whether a host holds this schedule in another form than it has now. Pausing alone is not a change."""
    same = {schedule_hash(conn, {**schedule, 'paused': p}) for p in (0, 1)}
    return any(d['hash'] not in same for d in installed(conn).get(str(schedule['schedule_id']), []))


def delete_schedule(conn: Conn, schedule_id: int, actor: str):
    if installed(conn).get(str(schedule_id)):
        raise StillDeployed('this schedule is installed on a host: uninstall it first')
    conn.execute('DELETE FROM schedules WHERE schedule_id = :id', {'id': schedule_id})


def pause_schedule(conn: Conn, schedule_id: int, paused: bool, actor: str) -> dict:
    curr = get_schedule(conn, schedule_id)
    now = int(time.time())
    next_ts = next_run(curr['cron_expr'], now, curr['config']['timezone']) if not paused else None
    conn.execute('UPDATE schedules SET paused = :p, updated_at = :now, next_run_at = :nxt WHERE schedule_id = :id',
                 {'id': schedule_id, 'p': 1 if paused else 0, 'now': now, 'nxt': next_ts})
    return get_schedule(conn, schedule_id)


def token_for_schedule(conn: Conn, schedule_id: int, actor: str) -> str:
    """Rotates and returns a fresh authentication token for the schedule."""
    token = secrets.token_hex(32)
    _set_token(conn, schedule_id, token)
    return token


def _set_token(conn: Conn, schedule_id: int, token: str):
    conn.execute('UPDATE schedules SET auth_token_hash = :th, pending_token_hash = NULL, updated_at = :now WHERE schedule_id = :id',
                 {'id': schedule_id, 'th': hashlib.sha256(token.encode()).hexdigest(), 'now': int(time.time())})


def _pending_token(conn: Conn, schedule_id: int) -> str:
    """A token for a deploy to carry. A deploy that fails says nothing about whether the host got it (the install may have
    finished before the task failed), so it works beside the current one until the host reports with it or the deploy ends well."""
    token = secrets.token_hex(32)
    conn.execute('UPDATE schedules SET pending_token_hash = :th WHERE schedule_id = :id',
                 {'id': schedule_id, 'th': hashlib.sha256(token.encode()).hexdigest()})
    return token


def schedule_for_token(conn: Conn, token: str) -> dict | None:
    if not token or len(token) < 16:
        return None
    th = hashlib.sha256(token.encode()).hexdigest()
    rows = conn.all('SELECT schedule_id, auth_token_hash FROM schedules WHERE auth_token_hash = :th OR pending_token_hash = :th', {'th': th})
    if not rows:
        return None
    sid, current = rows[0]
    if current != th:            # the host has the new token: the old one is done
        conn.execute('UPDATE schedules SET auth_token_hash = :th, pending_token_hash = NULL WHERE schedule_id = :id', {'id': sid, 'th': th})
    return get_schedule(conn, sid)


# ── Unified Script Generator ──────────────────────────────────────────────────

def _resolve_task(conn: Conn, tref: str) -> dict:
    task_obj = None
    if tref.isdigit():
        try:
            task_obj = tasks.get_task(conn, int(tref))
        except LookupError:
            pass
    if not task_obj:
        for t in tasks.list_tasks(conn):
            if t['name'].lower() == tref.lower() or t['slug'] == tref.lower():
                task_obj = tasks.get_task(conn, t['id'])
                break
    if not task_obj:
        raise LookupError(f'storage task "{tref}" not found')
    return task_obj


def generate_task_script(conn: Conn, schedule: dict) -> tuple[str, list[str]]:
    """Compiles any StorageForge task (task, change, move, shares, scan, command) into an executable script and arguments."""
    ttype = schedule['task_type']
    tref = schedule['task_ref']

    if ttype == 'task':
        task_obj = _resolve_task(conn, tref)
        return tasks.script(conn, task_obj), ['--run']

    elif ttype == 'change':
        plan_id = int(tref) if tref.isdigit() else conn.scalar(
            'SELECT plan_id FROM change_plans WHERE lower(name) = lower(:n)', {'n': tref})
        if not plan_id:
            raise LookupError(f'change plan "{tref}" not found')
        p = changes.get_plan(conn, plan_id)
        return changes.script(conn, p), ['--apply']

    elif ttype == 'move':
        plan_id = int(tref) if tref.isdigit() else conn.scalar(
            'SELECT plan_id FROM move_plans WHERE lower(name) = lower(:n)', {'n': tref})
        if not plan_id:
            raise LookupError(f'move plan "{tref}" not found')
        p = moves.get_plan(conn, plan_id)
        return moves.script(conn, p), ['--run']

    elif ttype == 'shares':
        from . import shares
        return shares.script(conn, tref or schedule['host']), ['--apply']

    elif ttype == 'scan':
        # Scanner invocation
        sc = f"""#!/bin/bash
set -euo pipefail
# from an older version: storageforge-index is not on client hosts, so this cannot work. Scans now run from the server
echo "StorageForge automated scan of {schedule['host']}"
exec storageforge-index scan {shlex.quote(schedule['host'])}
"""
        return sc, []

    elif ttype == 'command':
        # Generic command script
        sc = f"""#!/bin/bash
set -euo pipefail
{tref}
"""
        return sc, []

    raise ValueError(f'unsupported task_type: {ttype}')


# ── Comprehensive Server Verification Engine ──────────────────────────────────

def verify_run(conn: Conn, schedule: dict, report: dict) -> dict:
    """Verifies a completed run on the server against configured verify rules and the StorageForge index."""
    cfg = schedule['config']
    policy = cfg.get('verify_policy', 'comprehensive')
    if policy == 'none':
        return {'passed': True, 'checks': [{'name': 'policy_none', 'status': 'ok', 'message': 'verification skipped by policy'}],
                'verified_at': int(time.time()), 'state_checked': False, 'summary': 'Verification skipped'}

    checks = []
    passed = True

    if policy != 'state_only':
        # Check 1: Exit code verification
        exit_code = report.get('exit_code')
        req_zero = cfg['verify_rules'].get('require_exit_zero', True)
        if req_zero and exit_code != 0:
            passed = False
            checks.append({'name': 'exit_code', 'status': 'crit',
                           'message': f'task failed with non-zero exit code: {exit_code}'})
        else:
            checks.append({'name': 'exit_code', 'status': 'ok',
                           'message': f'exit code is {exit_code}'})

        # Check 2: Output pattern checks
        output = str(report.get('output') or '')
        must_match = cfg['verify_rules'].get('output_must_match')
        if report.get('no_output') and (must_match or cfg['verify_rules'].get('output_must_not_match')):
            checks.append({'name': 'output_patterns', 'status': 'warn', 'message': 'this run arrived with a scan, without its output: patterns not checked'})
            must_match = None
        if must_match:
            if _search(must_match, output):
                checks.append({'name': 'output_must_match', 'status': 'ok',
                               'message': f'output matched required pattern: {must_match}'})
            else:
                passed = False
                checks.append({'name': 'output_must_match', 'status': 'crit',
                               'message': f'output did not match required pattern: {must_match}'})

        must_not_match = cfg['verify_rules'].get('output_must_not_match')
        if must_not_match and not report.get('no_output'):
            if _search(must_not_match, output) is not False:     # could not tell: not proof that it is absent
                passed = False
                checks.append({'name': 'output_must_not_match', 'status': 'crit',
                               'message': f'output contained forbidden pattern: {must_not_match}'})
            else:
                checks.append({'name': 'output_must_not_match', 'status': 'ok',
                               'message': 'output contains no forbidden patterns'})
    else:
        output = str(report.get('output') or '')

    # What the output says about the work itself
    if not report.get('no_output'):
        if schedule['task_type'] in ('task', 'move'):
            if 'the copy differs' in output or 'rsync failed' in output:
                passed = False
                checks.append({'name': f'{schedule["task_type"]}_integrity', 'status': 'crit',
                               'message': 'output reports a transfer or verification failure'})
        elif schedule['task_type'] == 'change':
            if 'problem(s)' in output or 'CONFLICT' in output:
                passed = False
                checks.append({'name': 'change_conflicts', 'status': 'crit',
                               'message': 'change plan output reported conflicts or problems'})

    # "verified" is only ever said from a scan newer than the run. Until then the run is just what the host reported.
    def result(checked: bool, summary: str) -> dict:
        return {'passed': passed, 'checks': checks, 'verified_at': int(time.time()), 'state_checked': checked,
                'summary': summary if passed else 'One or more verification checks failed'}

    if policy == 'report_only':
        return result(False, 'The host reported this; the index is not checked for this schedule')

    h_rows = conn.all('SELECT host_id, hostname FROM hosts WHERE lower(hostname) = lower(:h)', {'h': schedule['host']})
    if not h_rows:
        checks.append({'name': 'host_indexed', 'status': 'warn', 'message': f'host {schedule["host"]} is not in the StorageForge index'})
        return result(False, 'The host reported this; it has no index to check against')
    hid, hname = h_rows[0][0], h_rows[0][1]
    done = report.get('finished_at') or report.get('started_at') or 0
    scanned = epoch(conn.scalar("""SELECT max(finished_at) FROM scans WHERE host_id = :hid AND status IN ('ok', 'partial')""", {'hid': hid}))
    if not scanned or scanned < done:
        checks.append({'name': 'state_pending', 'status': 'info', 'message': 'waiting for a scan newer than this run to check the host itself'})
        return result(False, 'The host reported this; the next scan checks it')

    mounts_db = conn.all("""SELECT mount_point, filesystem_type, total_bytes, used_bytes, scan_state
                            FROM mounts WHERE host_id = :hid AND scan_state <> 'gone'""", {'hid': hid})
    mount_map = {m[0]: {'fs': m[1], 'total': m[2], 'used': m[3], 'state': m[4]} for m in mounts_db}

    for mp in cfg['verify_rules'].get('check_mounts') or []:
        if mp in mount_map:
            checks.append({'name': f'mount_{mp}', 'status': 'ok', 'message': f'{mp} is mounted ({mount_map[mp]["fs"]})'})
        else:
            passed = False
            checks.append({'name': f'mount_{mp}', 'status': 'crit', 'message': f'{mp} is NOT mounted on {hname}'})

    for path, min_gib in (cfg['verify_rules'].get('min_free_gib') or {}).items():
        best_mount = None
        for mp in sorted(mount_map.keys(), key=len, reverse=True):
            if path == mp or path.startswith(mp.rstrip('/') + '/'):
                best_mount = mount_map[mp]
                break
        if best_mount and best_mount['total'] is not None and best_mount['used'] is not None:
            free_gib = (best_mount['total'] - best_mount['used']) / (1024 ** 3)
            if free_gib >= min_gib:
                checks.append({'name': f'free_space_{path}', 'status': 'ok',
                               'message': f'{path} has {free_gib:.1f} GiB free (threshold: {min_gib} GiB)'})
            else:
                passed = False
                checks.append({'name': f'free_space_{path}', 'status': 'crit',
                               'message': f'{path} has only {free_gib:.1f} GiB free, below required {min_gib} GiB'})

    def in_index(p: str) -> bool:
        full = "CASE WHEN d.path = '/' THEN '/' || f.filename ELSE d.path || '/' || f.filename END"
        return bool(conn.scalar(f"""SELECT 1 FROM file_records f JOIN mounts m ON f.mount_id = m.mount_id
                                    JOIN directories d ON f.dir_id = d.dir_id WHERE m.host_id = :hid AND {full} = :p""", {'hid': hid, 'p': p})
                    or conn.scalar("""SELECT 1 FROM directories d JOIN mounts m ON d.mount_id = m.mount_id
                                      WHERE m.host_id = :hid AND d.path = :p""", {'hid': hid, 'p': p}))

    for p in cfg['verify_rules'].get('paths_must_exist') or []:
        if in_index(p):
            checks.append({'name': f'path_exists_{p}', 'status': 'ok', 'message': f'path {p} is in the index'})
        else:
            passed = False
            checks.append({'name': f'path_exists_{p}', 'status': 'crit', 'message': f'path {p} is not in an index newer than the run'})

    for p in cfg['verify_rules'].get('paths_must_not_exist') or []:
        if in_index(p):
            passed = False
            checks.append({'name': f'path_absent_{p}', 'status': 'crit', 'message': f'forbidden path {p} still exists in the index'})
        else:
            checks.append({'name': f'path_absent_{p}', 'status': 'ok', 'message': f'path {p} is absent from the index'})

    if schedule['task_type'] == 'task':
        try:
            t_chk = tasks.check(conn, _resolve_task(conn, schedule['task_ref']))
            checks.append({'name': 'task_check', 'status': 'warn' if t_chk['crit'] else 'ok',
                           'message': f'task check reports {t_chk["crit"]} critical issue(s) against the index' if t_chk['crit'] else 'task blocks fit the index'})
        except LookupError:
            pass
    elif schedule['task_type'] == 'shares':
        from . import shares
        try:
            s_chk = shares.check(conn, schedule['task_ref'] or schedule['host'])
            checks.append({'name': 'shares_check', 'status': 'warn' if s_chk['crit'] else 'ok',
                           'message': f'share design has {s_chk["crit"]} critical issue(s)' if s_chk['crit'] else f'{len(s_chk["exports"])} share(s) fit the index'})
        except LookupError:
            pass
    return result(True, 'Checked against a scan newer than the run')


def run_status(exit_code: int, v_result: dict) -> tuple[str, int]:
    """(status, verified). verified: the scan agrees · reported: the host says so, and nothing has checked · verify_failed: a check failed."""
    if exit_code != 0:
        return 'failed', -1 if not v_result['passed'] else 0
    if not v_result['passed']:
        return 'verify_failed', -1
    return ('verified', 1) if v_result.get('state_checked') else ('reported', 0)


def _search(pattern: str, output: str) -> bool | None:
    """re.search in a child process with a time limit: the pattern comes from a form and the output from a host, and a
    bad pair could otherwise hold a web thread for as long as it likes. None when it could not tell."""
    code = 'import json,re,sys; p,o=json.load(sys.stdin); sys.exit(0 if re.search(p,o) else 1)'
    try:
        rc = subprocess.run([sys.executable, '-I', '-c', code], input=json.dumps([pattern, output]), text=True,
                            capture_output=True, timeout=REGEX_SECONDS).returncode
    except subprocess.TimeoutExpired:
        return None
    return {0: True, 1: False}.get(rc)


def _verified(conn: Conn, schedule: dict, report: dict) -> dict:
    """verify_run that cannot lose a report: an error in checking is a failed check, and the run is still recorded."""
    try:
        return verify_run(conn, schedule, report)
    except Exception as exc:
        return {'passed': False, 'checks': [{'name': 'verify_error', 'status': 'crit', 'message': f'could not verify: {exc}'[:300]}],
                'verified_at': int(time.time()), 'summary': 'Verification could not run'}


def pause_pending(conn: Conn, schedule: dict) -> bool:
    """Paused here, but a host still holds the version from before: its timer is still running."""
    from . import deploy
    want = schedule_hash(conn, schedule)
    return any(d['ref'] == str(schedule['schedule_id']) and d['hash'] != want for d in deploy.deployed(conn, kind='schedules'))


def reverify_run(conn: Conn, run_id: int, schedule_id: int | None = None) -> dict:
    """Re-runs server verification on an existing schedule_run against the latest StorageForge index. schedule_id: the
    schedule the caller means; a run of another one is not found."""
    rows = conn.all("""SELECT run_id, schedule_id, host, status, started_at, finished_at, exit_code, output, nonce
                       FROM schedule_runs WHERE run_id = :id""", {'id': run_id})
    if not rows or (schedule_id is not None and rows[0][1] != schedule_id):
        raise LookupError(f'no schedule run #{run_id}')
    r = rows[0]
    schedule = get_schedule(conn, r[1])
    report = {
        'schedule_id': r[1],
        'started_at': r[4],
        'finished_at': r[5],
        'exit_code': r[6],
        'output': r[7],
        'nonce': r[8],
        'no_output': not r[7],
    }
    v_result = _verified(conn, schedule, report)
    exit_code = r[6] if r[6] is not None else -1
    status, verified = run_status(exit_code, v_result)
    with conn.tx():
        conn.execute("""UPDATE schedule_runs
                        SET status = :st, verified = :v, verify_result_json = :vj, verified_at = :va
                        WHERE run_id = :id""",
                     {'st': status, 'v': verified, 'vj': json.dumps(v_result), 'va': v_result['verified_at'], 'id': run_id})
        latest_id = conn.scalar('SELECT max(run_id) FROM schedule_runs WHERE schedule_id = :sid', {'sid': schedule['schedule_id']})
        if latest_id == run_id:
            conn.execute('UPDATE schedules SET last_status = :st WHERE schedule_id = :sid',
                         {'st': status, 'sid': schedule['schedule_id']})
    return {
        'run_id': run_id,
        'schedule_id': schedule['schedule_id'],
        'status': status,
        'verified': verified,
        'verify_result': v_result,
    }


def verify_schedule(conn: Conn, schedule_id: int) -> dict:
    """Verifies a schedule's latest run if one exists, or performs a live state_only verification against the index."""
    schedule = get_schedule(conn, schedule_id)
    latest = conn.scalar('SELECT run_id FROM schedule_runs WHERE schedule_id = :sid ORDER BY started_at DESC, run_id DESC LIMIT 1',
                         {'sid': schedule_id})
    if latest:
        return reverify_run(conn, int(latest))
    fake_sched = {**schedule, 'config': {**schedule['config'], 'verify_policy': 'state_only'}}
    v_result = verify_run(conn, fake_sched, {'exit_code': 0, 'output': '', 'started_at': 0})     # the index as it stands
    status, verified = run_status(0, v_result)
    return {
        'run_id': None,
        'schedule_id': schedule_id,
        'status': status,
        'verified': verified,
        'verify_result': v_result,
    }


# ── Execution Ingest & Reporting ──────────────────────────────────────────────

def ingest_report(conn: Conn, report: dict, report_source: str) -> dict:
    """Ingests a run report from a client, validates it, and triggers server-side verification."""
    sid = int(report.get('schedule_id') or 0)
    schedule = get_schedule(conn, sid)

    started_at = int(report.get('started_at') or time.time())
    finished_at = int(report.get('finished_at') or time.time())
    exit_code = int(report.get('exit_code') if report.get('exit_code') is not None else -1)
    output = str(report.get('output') or '')[:262144]  # 256 KiB cap
    nonce = str(report.get('nonce') or secrets.token_hex(16))[:64]
    if started_at > time.time() + 3600:
        raise ValueError('this run says it started in the future')
    seen = conn.scalar('SELECT run_id FROM schedule_runs WHERE schedule_id = :sid AND nonce = :n', {'sid': sid, 'n': nonce})
    if seen:                     # a repeat, or a replay: the first answer stands
        return {'run_id': seen, 'schedule_id': sid, 'duplicate': True, 'auto_rescan': False}

    # Run server verification
    v_result = _verified(conn, schedule, report)
    status, verified = run_status(exit_code, v_result)

    with conn.tx():
        run_id = conn.scalar("""INSERT INTO schedule_runs
            (schedule_id, host, status, started_at, finished_at, exit_code, output,
             verified, verify_result_json, verified_at, nonce, report_source)
            VALUES (:sid, :h, :st, :s, :f, :rc, :out, :v, :vj, :va, :nc, :src)
            RETURNING run_id""", {
            'sid': sid,
            'h': schedule['host'],
            'st': status,
            's': started_at,
            'f': finished_at,
            'rc': exit_code,
            'out': output,
            'v': verified,
            'vj': json.dumps(v_result),
            'va': v_result['verified_at'],
            'nc': nonce,
            'src': report_source[:60],
        })

        # Update next_run_at and last_status
        next_ts = next_run(schedule['cron_expr'], finished_at, schedule['config']['timezone']) if not schedule['paused'] else None
        conn.execute("""UPDATE schedules
                        SET last_run_at = :lr, next_run_at = :nxt, last_status = :st
                        WHERE schedule_id = :sid""",
                     {'sid': sid, 'lr': started_at, 'nxt': next_ts, 'st': status})

    # Trigger alerts if configured
    cfg = schedule['config']
    notify_on = cfg.get('notify_on', ['failure', 'verify_failure'])
    should_alert = False
    if 'failure' in notify_on and exit_code != 0:
        should_alert = True
    if 'verify_failure' in notify_on and not v_result['passed']:
        should_alert = True

    if should_alert:
        try:
            alerts_conf = alerts.get_setting(conn, 'alerts')
            alerts.send(alerts_conf, f'StorageForge Schedule Alert: {schedule["name"]} ({status})',
                        f'Host: {schedule["host"]}\nStatus: {status}\nExit code: {exit_code}\n'
                        f'Verification: {v_result["summary"]}\nOutput snippet:\n{output[-500:]}',
                        'failed', {'schedule': schedule['name'], 'run_id': run_id, 'host': schedule['host']})
        except Exception:
            pass

    return {
        'run_id': run_id,
        'schedule_id': sid,
        'status': status,
        'verified': verified,
        'verify_result': v_result,
        'auto_rescan': bool(cfg['verify_rules'].get('auto_rescan')),
    }


def verify_pending(conn: Conn, host: str, limit: int = 50) -> int:
    """After a scan of host: the runs it can now check, which until now were only what the host reported."""
    rows = conn.all("""SELECT run_id FROM schedule_runs WHERE lower(host) = lower(:h) AND status = 'reported'
                        ORDER BY run_id DESC LIMIT :n""", {'h': host, 'n': limit})
    return sum(1 for (run_id,) in rows if reverify_run(conn, run_id)['status'] != 'reported')


def ingest_scan_schedules(conn: Conn, host: str, text: str) -> int:
    """Ingests schedule run records from /var/lib/storageforge/scheduler/*/runs.jsonl collected during a host scan."""
    if not text:
        return 0
    added = 0
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith('{'):
            continue
        try:
            rec = json.loads(line)
            sid = int(rec.get('schedule_id') or 0)
            started = int(rec.get('started_at') or 0)
        except Exception:
            continue
        if not sid or not started:
            continue
        try:
            sched = get_schedule(conn, sid)
        except LookupError:
            continue
        if host_slug(sched['host']) != host_slug(host) and sched['host'].lower() != host.lower():
            continue
        nonce = str(rec.get('nonce') or f'scan-{sid}-{started}')[:64]
        exists = conn.scalar("""SELECT 1 FROM schedule_runs
                                WHERE schedule_id = :sid AND (nonce = :nc OR started_at = :s)""",
                             {'sid': sid, 'nc': nonce, 's': started})
        if exists:
            continue
        rec['nonce'] = nonce
        try:
            ingest_report(conn, rec, f'scan:{host}')
        except ValueError:       # one bad line must not stop a scan
            continue
        added += 1
    return added


def get_schedule_runs(conn: Conn, schedule_id: int | None = None, host: str | None = None,
                      limit: int = 50) -> list[dict]:
    sql = """SELECT r.run_id, r.schedule_id, s.name, r.host, r.status, r.started_at,
                    r.finished_at, r.exit_code, r.output, r.verified, r.verify_result_json,
                    r.verified_at, r.nonce, r.report_source
             FROM schedule_runs r
             JOIN schedules s USING (schedule_id)
             WHERE 1=1"""
    p: dict[str, Any] = {'lim': max(1, min(limit, 500))}
    if schedule_id is not None:
        sql += ' AND r.schedule_id = :sid'
        p['sid'] = schedule_id
    if host:
        sql += ' AND lower(r.host) = lower(:h)'
        p['h'] = host.strip()
    sql += ' ORDER BY r.started_at DESC LIMIT :lim'

    out = []
    for row in conn.all(sql, p):
        out.append({
            'run_id': row[0],
            'schedule_id': row[1],
            'schedule_name': row[2],
            'host': row[3],
            'status': row[4],
            'started_at': row[5],
            'finished_at': row[6],
            'exit_code': row[7],
            'output': row[8],
            'verified': row[9],
            'verify_result': json.loads(row[10]) if row[10] else {},
            'verified_at': row[11],
            'nonce': row[12],
            'report_source': row[13],
        })
    return out


# ── Client Deployment Package Generation ──────────────────────────────────────

LIB = '/usr/local/lib/storageforge/scheduler'
_WEEKDAYS = ('Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat')


def generate_cron_entry(schedule: dict) -> str:
    """The line for a host without systemd. It wakes every minute and the runner decides: not every cron has CRON_TZ, so only
    the runner can keep the schedule's own timezone."""
    sid = schedule['schedule_id']
    cfg = schedule['config']
    comment = f"# StorageForge schedule {schedule['name']} (#{sid}): {schedule['cron_expr']} in {cfg.get('timezone') or 'UTC'}"
    return f"{comment}\n* * * * * root {LIB}/run-{sid}.sh --if-due\n"


def on_calendar(schedule: dict) -> str:
    """The same times as systemd writes them. Like parse_cron's reading of cron, a day has to match both day fields."""
    mins, hours, doms, months, dows = parse_cron(schedule['cron_expr'])
    ls = lambda v, every: '*' if len(v) == every else ','.join(str(x) for x in sorted(v))   # noqa: E731
    days = sorted(dows - {7})
    prefix = '' if len(days) == 7 else ','.join(_WEEKDAYS[d] for d in days) + ' '
    return (f'{prefix}*-{ls(months, 12)}-{ls(doms, 31)} {ls(hours, 24)}:{ls(mins, 60)}:00 '
            f'{schedule["config"].get("timezone") or "UTC"}')


def _heredoc(target: str, text: str) -> str:
    """Quoted, under a delimiter made from the text itself: a line in a value cannot end it, or be chosen to."""
    mark = 'SF_' + hashlib.sha256(text.encode()).hexdigest()[:24]
    return f"cat >{target} <<'{mark}'\n{text.rstrip(chr(10))}\n{mark}\n"


def _remove_block(sid: int, token: bool = True) -> str:
    """Bash that takes a schedule off this host, whichever version put it there. token=False keeps the report token, for a
    reinstall from a downloaded script, which carries none."""
    keep = f'/etc/storageforge/scheduler/{sid}.token ' if token else ''
    return f"""systemctl disable --now sf-sched-{sid}.timer >/dev/null 2>&1 || true
rm -f /etc/systemd/system/sf-sched-{sid}.service /etc/systemd/system/sf-sched-{sid}.timer
[[ -d /run/systemd/system ]] && systemctl daemon-reload 2>/dev/null || true
rm -f /etc/cron.d/sf-sched-{sid} {LIB}/task-{sid}.sh {LIB}/run-{sid}.sh /etc/storageforge/scheduler/{sid}.json {keep}/var/lib/storageforge/managed/sched-{sid}.sha256
if [[ -f /etc/crontabs/root ]]; then sed -i '/{LIB.replace('/', chr(92) + '/')}\\/run-{sid}\\.sh/d' /etc/crontabs/root; fi
ls /etc/storageforge/scheduler/*.json >/dev/null 2>&1 || rm -f /usr/local/sbin/storageforge-scheduler   # the Python runner of older versions
"""


@site.stamped
def generate_install_script(conn: Conn, schedule: dict, report_url: str | None, token: str) -> str:
    """The script that puts a schedule on its host. With no flags it only reports, like every script StorageForge writes.
    token: empty leaves the host without one, and it reports through scans."""
    from .jobs import REPORT_CA, report_ca
    sid = schedule['schedule_id']
    cfg = schedule['config']
    q = shlex.quote
    task_script, script_args = generate_task_script(conn, schedule)
    env = {k: v for k, v in (cfg.get('env') or {}).items() if not UNSAFE_ENV.fullmatch(k)} if schedule['task_type'] == 'command' else {}    # a row from before the env rules too
    task_sh, run_sh = f'{LIB}/task-{sid}.sh', f'{LIB}/run-{sid}.sh'
    # it can hold what the schedule view masks: only whoever runs it reads it
    user = cfg.get('user') or 'root'
    task_access = 'chmod 0700 "$TASK_SH"' if user == 'root' else f'chgrp "$(id -g {q(user)} 2>/dev/null || echo 0)" "$TASK_SH"; chmod 0750 "$TASK_SH"'
    runner = schedscript.runner_script(schedule, script_args, parse_cron(schedule['cron_expr']), report_url, env, task_sh)
    paused = 1 if schedule.get('paused') else 0
    # a dry run shows the command itself: the person reading it is who approves it
    shown_command = f'info {q("runs: " + schedule["task_ref"])}' if schedule['task_type'] == 'command' else ':'
    ca = report_ca(report_url)
    keep_token = '' if not token else f"( umask 077; printf '%s\\n' {q(token)} >/etc/storageforge/scheduler/{sid}.token )\n"
    calendar = on_calendar(schedule)
    jitter = int(cfg.get('jitter_sec') or 0)
    cron_line = generate_cron_entry(schedule)
    service = (f'[Unit]\nDescription=StorageForge schedule {schedule["name"]} (#{sid})\n[Service]\nType=oneshot\n'
               f'ExecStart={run_sh} --timer\nTimeoutStartSec=infinity\n')
    timer = (f'[Unit]\nDescription=Timer for StorageForge schedule #{sid}\n[Timer]\nOnCalendar={calendar}\n'
             f'Persistent=false\n[Install]\nWantedBy=timers.target\n')
    return f"""#!/usr/bin/env bash
# StorageForge schedule {schedule['name']} (#{sid}): {schedule['cron_expr']}
set -euo pipefail
export LC_ALL=C PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

MODE=report
for arg in "$@"; do
  case "$arg" in
    --report) MODE=report ;;
    --install|--apply) MODE=install ;;
    --uninstall) MODE=uninstall ;;
    --run) MODE=run ;;
  esac
done
{HELPERS}
SID={sid}
SCHED_NAME={q(schedule['name'])}
PAUSED={paused}
CALENDAR={q(calendar)}
UNIT=sf-sched-$SID
TASK_SH={task_sh}
RUN_SH={run_sh}
CRON_FILE=/etc/cron.d/$UNIT
MANAGED=/var/lib/storageforge/managed/sched-$SID.sha256
wakes_by_systemd() {{ [[ -d /run/systemd/system ]] && systemd-analyze calendar "$CALENDAR" >/dev/null 2>&1; }}
has_cron() {{ command -v crond >/dev/null || command -v cron >/dev/null; }}

if [[ $MODE == report ]]; then
  section "Schedule $SCHED_NAME (#$SID)"
  {shown_command}
  [[ -x $RUN_SH ]] && ok "$RUN_SH" || missing "$RUN_SH needs to be installed"
  [[ -x $TASK_SH ]] && ok "$TASK_SH" || missing "$TASK_SH needs to be installed"
  if ((PAUSED)); then ok "paused: no timer"
  elif wakes_by_systemd; then ok "wakes by systemd: $CALENDAR"
  elif has_cron; then ok "wakes by cron, each minute"
  else conflict "this host has neither systemd nor cron: nothing could wake the schedule"
  fi
  finished
  exit 0
fi

if [[ $(id -u) -ne 0 ]]; then
  echo "error: this must be run as root (sudo)" >&2
  exit 1
fi

if [[ $MODE == uninstall ]]; then
  section "Remove schedule $SCHED_NAME (#$SID)"
  {_remove_block(sid)}
  ok "removed schedule #$SID"
  finished
  exit 0
fi

section "Installing schedule $SCHED_NAME (#$SID)"
{_remove_block(sid, token=False)}mkdir -p {LIB} /etc/storageforge/scheduler /var/lib/storageforge/scheduler/$SID /var/lib/storageforge/managed
chmod 0755 /var/lib/storageforge /var/lib/storageforge/scheduler /var/lib/storageforge/scheduler/$SID /var/lib/storageforge/managed 2>/dev/null || true
chmod 0700 /etc/storageforge/scheduler
{_heredoc('"$TASK_SH"', task_script)}{task_access}
ok "$TASK_SH"
{_heredoc('"$RUN_SH"', runner)}chmod 0700 "$RUN_SH"
ok "$RUN_SH"
{keep_token}{_heredoc(REPORT_CA, ca) + f'chmod 0644 {REPORT_CA}' if ca else ''}
if ((PAUSED)); then
  ok "schedule is paused: no timer"
elif wakes_by_systemd; then
{_heredoc('"/etc/systemd/system/$UNIT.service"', service)}{_heredoc('"/etc/systemd/system/$UNIT.timer"', timer)}  systemctl daemon-reload
  systemctl enable --now "$UNIT.timer" >/dev/null
  ok "timer on: $CALENDAR"
elif has_cron && [[ -d /etc/cron.d ]]; then
{_heredoc('"$CRON_FILE"', cron_line)}  chmod 0644 "$CRON_FILE"
  ok "$CRON_FILE"
elif has_cron && [[ -f /etc/crontabs/root ]]; then
  printf '%s\\n' {q(f"* * * * * {run_sh} --if-due")} >>/etc/crontabs/root
  ok "/etc/crontabs/root"
else
  conflict "this host has neither systemd nor cron: nothing can wake the schedule"
  exit 1
fi
sha256sum "$RUN_SH" "$TASK_SH" >"$MANAGED"
chmod 0644 "$MANAGED"
info {q(f"jitter: up to {jitter} s") if jitter else q("no jitter")}

if [[ $MODE == run ]]; then
  section "Running schedule $SCHED_NAME (#$SID) now"
  "$RUN_SH" --run
fi
finished
"""


def deploy_items(db, conn: Conn, schedule: dict, mode: str, report_url: str | None, actor: str,
                 run_now: bool = False, remove: bool = False) -> list[dict]:
    """deploy.start_group items for deploying, running, or uninstalling a schedule over SSH via storageforge-run."""
    from . import deploy
    home = find_host(hosts(conn), schedule['host'])
    host_name = home['name'] if home else schedule['host']
    sid = schedule['schedule_id']
    ref = str(sid)
    digest = schedule_hash(conn, schedule)
    if not remove and not schedule.get('paused'):
        check_target(conn, schedule)

    # The old token keeps working until the host holds the new one, so a deploy that fails leaves reports working
    promote = None
    if remove:
        token = 'uninstall'
    elif run_now or mode == 'apply':
        token = promote = _pending_token(conn, sid)
    else:
        token = '<issued-on-deploy>'

    text = generate_install_script(conn, schedule, report_url, token)

    def mark(target_host: str, gone: bool = False):
        def hook(res):
            if res.get('status') != 'ok':
                return
            c = db.connect()
            try:
                if gone:
                    c.execute("DELETE FROM deployed WHERE host = :h AND kind = 'schedules' AND ref = :r",
                              {'h': target_host, 'r': ref})
                else:
                    if promote:
                        _set_token(c, sid, promote)
                    deploy.mark_deployed(c, target_host, 'schedules', ref, digest,
                                         {'name': schedule['name'], 'cron_expr': schedule['cron_expr'],
                                          'task_type': schedule['task_type'], 'schedule_id': sid}, actor)
            finally:
                c.close()
        return hook

    if run_now:
        return [{'host': host_name, 'script': text, 'args': ['--run'], 'kind': 'schedules', 'ref': ref,
                 'mode': 'apply', 'on_ok': mark(host_name, False)}]
    if mode != 'apply':
        return [{'host': host_name, 'script': text, 'args': ['--report'], 'kind': 'schedules', 'ref': ref, 'mode': 'report'}]

    items = [{'host': host_name, 'script': text, 'args': ['--uninstall' if remove else '--install'],
              'kind': 'schedules', 'ref': ref, 'mode': 'apply', 'on_ok': mark(host_name, remove)}]
    for d in deploy.deployed(conn, kind='schedules'):
        if d['ref'] == ref and d['host'] != host_name:
            items.append({'host': d['host'], 'script': text, 'args': ['--uninstall'], 'kind': 'schedules',
                          'ref': ref, 'mode': 'apply', 'on_ok': mark(d['host'], True)})
    return items


def orphan_script(sid: int) -> str:
    return f"""#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
{HELPERS}
section "Deleted schedule #{sid}"
if [[ ${{1:-}} == --uninstall ]]; then
  {_remove_block(sid)}
  ok "removed"
else
  [[ -e {LIB}/run-{sid}.sh || -e {LIB}/task-{sid}.sh || -e /etc/cron.d/sf-sched-{sid} || -e /etc/systemd/system/sf-sched-{sid}.timer ]] && missing "schedule #{sid} will be removed" || ok "nothing here"
fi
finished
"""


def orphan_items(db, conn: Conn, schedule_id: int, mode: str, actor: str) -> list[dict]:
    """Deploy items that take a schedule whose row is gone off the hosts still holding it. Only what deployed it says
    where it is, so this reads the deployed table. Reports with no flags, like every script."""
    from . import deploy
    sid, ref = int(schedule_id), str(int(schedule_id))
    text = orphan_script(sid)

    def forget(host: str):
        def hook(res):
            if res.get('status') != 'ok':
                return
            c = db.connect()
            try:
                c.execute("DELETE FROM deployed WHERE host = :h AND kind = 'schedules' AND ref = :r", {'h': host, 'r': ref})
            finally:
                c.close()
        return hook

    hosts_with = [d['host'] for d in deploy.deployed(conn, kind='schedules') if d['ref'] == ref]
    if mode != 'apply':
        return [{'host': h, 'script': text, 'args': [], 'kind': 'schedules', 'ref': ref, 'mode': 'report'} for h in hosts_with]
    return [{'host': h, 'script': text, 'args': ['--uninstall'], 'kind': 'schedules', 'ref': ref, 'mode': 'apply', 'on_ok': forget(h)}
            for h in hosts_with]


def installed(conn: Conn) -> dict:
    """schedule_id (str) → [{host, hash, at, by}] for schedules deployed via storageforge-run."""
    from . import deploy
    out: dict[str, list] = {}
    for d in deploy.deployed(conn, kind='schedules'):
        out.setdefault(str(d['ref']), []).append({'host': d['host'], 'hash': d['hash'], 'at': d['at'], 'by': d['by']})
    return out

