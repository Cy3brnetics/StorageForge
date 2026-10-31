"""Unified Scheduler: schedules any task StorageForge can do (Storage task blocks, Change plans,
Move plans, Host scans, and arbitrary Commands) as cron jobs on client hosts with comprehensive server-side verification.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import re
import secrets
import shlex
import time
import zoneinfo
from typing import Any

from . import alerts, changes, moves, schedscript, tasks
from .db import Conn
from .moves import find_host, host_slug, hosts, slug
from .scriptkit import HELPERS

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


def period(expr: str) -> int:
    """Estimates the period in seconds between runs of a cron expression (used for staleness alerts)."""
    try:
        t1 = next_run(expr, 1700000000)
        t2 = next_run(expr, t1)
        return max(60, t2 - t1)
    except Exception:
        return 86400


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
            if re.fullmatch(r'^[A-Za-z_][A-Za-z0-9_]*$', str(k)):
                env[str(k)] = str(v)[:1000]

    catchup = bool(cfg.get('catchup'))
    jitter = int(cfg.get('jitter_sec') or 0)
    if not (0 <= jitter <= 300):
        raise ValueError('jitter_sec must be between 0 and 300')

    verify_policy = str(cfg.get('verify_policy') or 'comprehensive').strip().lower()
    if verify_policy not in VERIFY_POLICIES:
        raise ValueError(f'verify_policy must be one of {", ".join(VERIFY_POLICIES)}')

    raw_vr = cfg.get('verify_rules') or {}
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
        'catchup': catchup,
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


def schedule_hash(schedule: dict) -> str:
    """Returns a 16-char SHA-256 fingerprint of the normalized schedule definition."""
    return hashlib.sha256(json.dumps(normalize_schedule(schedule), sort_keys=True).encode()).hexdigest()[:16]


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
    _no_destructive(body)
    s = normalize_schedule(body)
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


def update_schedule(conn: Conn, schedule_id: int, body: dict, actor: str) -> dict:
    _no_destructive(body)
    curr = get_schedule(conn, schedule_id)
    # Merge existing fields
    merged = {
        'name': body.get('name', curr['name']),
        'host': body.get('host', curr['host']),
        'cron_expr': body.get('cron_expr', curr['cron_expr']),
        'task_type': body.get('task_type', curr['task_type']),
        'task_ref': body.get('task_ref', curr['task_ref']),
        'config': {**curr['config'], **(body.get('config') or body.get('config_json') or {})},
        'paused': body.get('paused', curr['paused']),
    }
    s = normalize_schedule(merged)
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
    th = hashlib.sha256(token.encode()).hexdigest()
    conn.execute('UPDATE schedules SET auth_token_hash = :th, updated_at = :now WHERE schedule_id = :id',
                 {'id': schedule_id, 'th': th, 'now': int(time.time())})
    return token


def schedule_for_token(conn: Conn, token: str) -> dict | None:
    if not token or len(token) < 16:
        return None
    th = hashlib.sha256(token.encode()).hexdigest()
    sid = conn.scalar('SELECT schedule_id FROM schedules WHERE auth_token_hash = :th', {'th': th})
    return get_schedule(conn, sid) if sid else None


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
                'verified_at': int(time.time()), 'summary': 'Verification skipped'}

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
        if must_match:
            if re.search(must_match, output):
                checks.append({'name': 'output_must_match', 'status': 'ok',
                               'message': f'output matched required pattern: {must_match}'})
            else:
                passed = False
                checks.append({'name': 'output_must_match', 'status': 'crit',
                               'message': f'output did not match required pattern: {must_match}'})

        must_not_match = cfg['verify_rules'].get('output_must_not_match')
        if must_not_match:
            if re.search(must_not_match, output):
                passed = False
                checks.append({'name': 'output_must_not_match', 'status': 'crit',
                               'message': f'output contained forbidden pattern: {must_not_match}'})
            else:
                checks.append({'name': 'output_must_not_match', 'status': 'ok',
                               'message': 'output contains no forbidden patterns'})
    else:
        output = str(report.get('output') or '')

    # If policy is report_only, we don't query host index
    if policy == 'report_only':
        summary = 'Report verified successfully' if passed else 'Report verification failed'
        return {'passed': passed, 'checks': checks, 'verified_at': int(time.time()), 'summary': summary}

    # Query host state in index
    h_rows = conn.all('SELECT host_id, hostname FROM hosts WHERE lower(hostname) = lower(:h)',
                      {'h': schedule['host']})
    if not h_rows:
        checks.append({'name': 'host_indexed', 'status': 'warn',
                       'message': f'host {schedule["host"]} is not in the StorageForge index'})
    else:
        hid, hname = h_rows[0][0], h_rows[0][1]
        mounts_db = conn.all("""SELECT mount_point, filesystem_type, total_bytes, used_bytes, scan_state
                                FROM mounts WHERE host_id = :hid AND scan_state <> 'gone'""", {'hid': hid})
        mount_map = {m[0]: {'fs': m[1], 'total': m[2], 'used': m[3], 'state': m[4]} for m in mounts_db}

        # Check 3: Mount point checks
        for mp in cfg['verify_rules'].get('check_mounts') or []:
            if mp in mount_map:
                checks.append({'name': f'mount_{mp}', 'status': 'ok',
                               'message': f'{mp} is mounted ({mount_map[mp]["fs"]})'})
            else:
                passed = False
                checks.append({'name': f'mount_{mp}', 'status': 'crit',
                               'message': f'{mp} is NOT mounted on {hname}'})

        # Check 4: Free space checks
        for path, min_gib in (cfg['verify_rules'].get('min_free_gib') or {}).items():
            best_mount = None
            for mp in sorted(mount_map.keys(), key=len, reverse=True):
                if path == mp or path.startswith(mp.rstrip('/') + '/'):
                    best_mount = mount_map[mp]
                    break
            if best_mount and best_mount['total'] is not None and best_mount['used'] is not None:
                free_bytes = best_mount['total'] - best_mount['used']
                free_gib = free_bytes / (1024 ** 3)
                if free_gib >= min_gib:
                    checks.append({'name': f'free_space_{path}', 'status': 'ok',
                                   'message': f'{path} has {free_gib:.1f} GiB free (threshold: {min_gib} GiB)'})
                else:
                    passed = False
                    checks.append({'name': f'free_space_{path}', 'status': 'crit',
                                   'message': f'{path} has only {free_gib:.1f} GiB free, below required {min_gib} GiB'})

        # Check 5: Paths must exist in index
        for p in cfg['verify_rules'].get('paths_must_exist') or []:
            found = conn.scalar("""SELECT 1 FROM file_records f
                                   JOIN mounts m ON f.mount_id = m.mount_id
                                   JOIN directories d ON f.dir_id = d.dir_id
                                   WHERE m.host_id = :hid AND (d.path || '/' || f.filename) = :p""",
                                {'hid': hid, 'p': p})
            if not found:
                found = conn.scalar("""SELECT 1 FROM directories d
                                       JOIN mounts m ON d.mount_id = m.mount_id
                                       WHERE m.host_id = :hid AND d.path = :p""",
                                    {'hid': hid, 'p': p})
            if found:
                checks.append({'name': f'path_exists_{p}', 'status': 'ok',
                               'message': f'path {p} confirmed in index'})
            else:
                checks.append({'name': f'path_exists_{p}', 'status': 'warn',
                               'message': f'path {p} not confirmed in latest index (may need rescan)'})

        # Check 5b: Paths must NOT exist in index
        for p in cfg['verify_rules'].get('paths_must_not_exist') or []:
            found = conn.scalar("""SELECT 1 FROM file_records f
                                   JOIN mounts m ON f.mount_id = m.mount_id
                                   JOIN directories d ON f.dir_id = d.dir_id
                                   WHERE m.host_id = :hid AND (d.path || '/' || f.filename) = :p""",
                                {'hid': hid, 'p': p})
            if not found:
                found = conn.scalar("""SELECT 1 FROM directories d
                                       JOIN mounts m ON d.mount_id = m.mount_id
                                       WHERE m.host_id = :hid AND d.path = :p""",
                                    {'hid': hid, 'p': p})
            if found:
                passed = False
                checks.append({'name': f'path_absent_{p}', 'status': 'crit',
                               'message': f'forbidden path {p} still exists in index'})
            else:
                checks.append({'name': f'path_absent_{p}', 'status': 'ok',
                               'message': f'path {p} is absent in index'})

        # Check 6: Task-type specific verifications
        if schedule['task_type'] == 'scan':
            last_scan = conn.scalar('SELECT max(started_at) FROM scans WHERE host_id = :hid', {'hid': hid})
            run_start = report.get('started_at', 0)
            if last_scan and last_scan >= run_start - 60:
                checks.append({'name': 'scan_completion', 'status': 'ok',
                               'message': 'host scan registered in index successfully'})
            else:
                checks.append({'name': 'scan_completion', 'status': 'warn',
                               'message': 'no fresh scan recorded in index for this host'})

        elif schedule['task_type'] == 'task':
            if 'the copy differs' in output or 'rsync failed' in output:
                passed = False
                checks.append({'name': 'task_integrity', 'status': 'crit',
                               'message': 'task output indicates transfer/verification failure'})
            try:
                t_obj = _resolve_task(conn, schedule['task_ref'])
                t_chk = tasks.check(conn, t_obj)
                if t_chk['crit'] > 0:
                    checks.append({'name': 'task_check', 'status': 'warn',
                                   'message': f'task check reports {t_chk["crit"]} critical issue(s) against index'})
                else:
                    checks.append({'name': 'task_check', 'status': 'ok',
                                   'message': 'task blocks verified against index'})
            except Exception:
                pass

        elif schedule['task_type'] == 'change':
            if 'problem(s)' in output or 'CONFLICT' in output:
                passed = False
                checks.append({'name': 'change_conflicts', 'status': 'crit',
                               'message': 'change plan output reported conflicts or problems'})
            else:
                checks.append({'name': 'change_conflicts', 'status': 'ok',
                               'message': 'change plan applied without conflicts'})

        elif schedule['task_type'] == 'move':
            if 'the copy differs' in output or 'rsync failed' in output:
                passed = False
                checks.append({'name': 'move_integrity', 'status': 'crit',
                               'message': 'move plan output reported copy or verification failure'})
            else:
                checks.append({'name': 'move_integrity', 'status': 'ok',
                               'message': 'move plan step completed cleanly'})

        elif schedule['task_type'] == 'shares':
            from . import shares
            try:
                s_chk = shares.check(conn, schedule['task_ref'] or schedule['host'])
                if s_chk['crit'] > 0:
                    checks.append({'name': 'shares_check', 'status': 'warn',
                                   'message': f'share design has {s_chk["crit"]} critical issue(s)'})
                else:
                    checks.append({'name': 'shares_check', 'status': 'ok',
                                   'message': f'{len(s_chk["exports"])} share(s) checked against index'})
            except Exception:
                pass

    summary = 'All verification checks passed' if passed else 'One or more verification checks failed'
    return {
        'passed': passed,
        'checks': checks,
        'verified_at': int(time.time()),
        'summary': summary,
    }


def reverify_run(conn: Conn, run_id: int) -> dict:
    """Re-runs server verification on an existing schedule_run against the latest StorageForge index."""
    rows = conn.all("""SELECT run_id, schedule_id, host, status, started_at, finished_at, exit_code, output, nonce
                       FROM schedule_runs WHERE run_id = :id""", {'id': run_id})
    if not rows:
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
    }
    v_result = verify_run(conn, schedule, report)
    verified = 1 if v_result['passed'] else -1
    exit_code = r[6] if r[6] is not None else -1
    status = 'verified' if (exit_code == 0 and v_result['passed']) else 'verify_failed' if exit_code == 0 else 'failed'
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
    v_result = verify_run(conn, fake_sched, {'exit_code': 0, 'output': '', 'started_at': int(time.time())})
    return {
        'run_id': None,
        'schedule_id': schedule_id,
        'status': 'verified' if v_result['passed'] else 'verify_failed',
        'verified': 1 if v_result['passed'] else -1,
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

    # Run server verification
    v_result = verify_run(conn, schedule, report)
    verified = 1 if v_result['passed'] else -1
    status = 'verified' if (exit_code == 0 and v_result['passed']) else 'verify_failed' if exit_code == 0 else 'failed'

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
        ingest_report(conn, rec, f'scan:{host}')
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

def generate_cron_entry(schedule: dict) -> str:
    """Generates standard /etc/cron.d/ entry for this schedule."""
    sid = schedule['schedule_id']
    user = schedule['config'].get('user', 'root')
    expr = schedule['cron_expr']
    comment = f"# StorageForge schedule {schedule['name']} (#{sid})"
    cmd = f"/usr/local/sbin/storageforge-scheduler run {sid}"
    return f"{comment}\n{expr} {user} {cmd}\n"


def generate_client_config(schedule: dict, report_url: str, token: str, script_args: list[str] | None = None) -> str:
    """Generates JSON config for client daemon and runner in /etc/storageforge/scheduler/<id>.json."""
    sid = schedule['schedule_id']
    data = {
        'schedule_id': sid,
        'name': schedule['name'],
        'host': schedule['host'],
        'cron_expr': schedule['cron_expr'],
        'task_type': schedule['task_type'],
        'task_ref': schedule['task_ref'],
        'paused': bool(schedule.get('paused')),
        'report_url': report_url.rstrip('/'),
        'token': token,
        'script_path': f'/usr/local/lib/storageforge/scheduler/task-{sid}.sh',
        'script_args': list(script_args or []),
        'config': schedule['config'],
    }
    return json.dumps(data, indent=2)


def generate_install_script(conn: Conn, schedule: dict, report_url: str, token: str) -> str:
    """Generates a self-contained installation & management script for target client hosts."""
    sid = schedule['schedule_id']
    task_script, script_args = generate_task_script(conn, schedule)
    cron_entry = generate_cron_entry(schedule)
    client_config = generate_client_config(schedule, report_url, token, script_args=script_args)
    runner_bin = schedscript.scheduler_binary()
    paused_flag = 1 if schedule.get('paused') else 0

    return f"""#!/usr/bin/env bash
# StorageForge Scheduler Install Script for "{schedule['name']}" (#{sid})
set -euo pipefail
export LC_ALL=C PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

MODE=install
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
SCHED_NAME={shlex.quote(schedule['name'])}
PAUSED={paused_flag}
BIN=/usr/local/sbin/storageforge-scheduler
TASK_SH=/usr/local/lib/storageforge/scheduler/task-{sid}.sh
CFG_JSON=/etc/storageforge/scheduler/{sid}.json
CRON_FILE=/etc/cron.d/sf-sched-{sid}
MANAGED=/var/lib/storageforge/managed/sched-{sid}.sha256

if [[ $MODE == report ]]; then
  section "Schedule $SCHED_NAME (#$SID)"
  [[ -x $BIN ]] && ok "$BIN" || missing "$BIN needs to be installed"
  [[ -x $TASK_SH ]] && ok "$TASK_SH" || missing "$TASK_SH needs to be installed"
  [[ -f $CFG_JSON ]] && ok "$CFG_JSON" || missing "$CFG_JSON needs to be installed"
  if ((PAUSED)); then
    [[ ! -e $CRON_FILE ]] && ok "paused (no cron entry)" || missing "$CRON_FILE will be removed (schedule is paused)"
  else
    [[ -f $CRON_FILE ]] && ok "$CRON_FILE ({schedule['cron_expr']})" || missing "$CRON_FILE ({schedule['cron_expr']}) needs to be installed"
  fi
  finished
  exit 0
fi

if [[ $(id -u) -ne 0 ]]; then
  echo "error: install must be run as root (sudo)" >&2
  exit 1
fi

if [[ $MODE == uninstall ]]; then
  section "Remove schedule $SCHED_NAME (#$SID)"
  rm -f "$TASK_SH" "$CFG_JSON" "$CRON_FILE" "$MANAGED"
  ok "removed schedule #$SID files and cron entry"
  finished
  exit 0
fi

section "Installing StorageForge Scheduler for task: $SCHED_NAME (#$SID)"
mkdir -p /usr/local/sbin /usr/local/lib/storageforge/scheduler /etc/storageforge/scheduler "/var/lib/storageforge/scheduler/$SID" /var/lib/storageforge/managed /etc/cron.d
chmod 0755 /var/lib/storageforge /var/lib/storageforge/scheduler "/var/lib/storageforge/scheduler/$SID" /var/lib/storageforge/managed 2>/dev/null || true

# 0. Install standalone storageforge-scheduler client runner & daemon
cat <<'EOF_SF_SCHED_BIN' > "$BIN"
{runner_bin}
EOF_SF_SCHED_BIN
chmod 0755 "$BIN"
ok "$BIN"

# 1. Install task execution script
cat <<'EOF_TASK' > "$TASK_SH"
{task_script}
EOF_TASK
chmod 0755 "$TASK_SH"
ok "$TASK_SH"

# 2. Install scheduler client config
cat <<'EOF_CFG' > "$CFG_JSON"
{client_config}
EOF_CFG
chmod 0600 "$CFG_JSON"
ok "$CFG_JSON"

# 3. Install or remove cron job according to paused state
if ((PAUSED)); then
  rm -f "$CRON_FILE"
  ok "schedule is paused (cron entry omitted)"
  sha256sum "$BIN" "$TASK_SH" > "$MANAGED"
else
  cat <<'EOF_CRON' > "$CRON_FILE"
{cron_entry}
EOF_CRON
  chmod 0644 "$CRON_FILE"
  ok "Installed successfully: $CRON_FILE"
  sha256sum "$BIN" "$TASK_SH" "$CRON_FILE" > "$MANAGED"
fi
chmod 0644 "$MANAGED"

if [[ $MODE == run ]]; then
  section "Running schedule $SCHED_NAME (#$SID) now"
  "$BIN" run "$SID"
fi
finished
"""


def deploy_items(db, conn: Conn, schedule: dict, mode: str, report_url: str, actor: str,
                 run_now: bool = False, remove: bool = False) -> list[dict]:
    """deploy.start_group items for deploying, running, or uninstalling a schedule over SSH via storageforge-run."""
    from . import deploy
    home = find_host(hosts(conn), schedule['host'])
    host_name = home['name'] if home else schedule['host']
    sid = schedule['schedule_id']
    ref = str(sid)
    digest = schedule_hash(schedule)

    # Rotate/issue a client reporting token when applying or running now; use a placeholder for dry-run report
    if mode == 'apply' or run_now:
        token = token_for_schedule(conn, sid, actor) if not remove else 'uninstall'
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


def orphan_items(db, conn: Conn, schedule_id: int, mode: str, actor: str) -> list[dict]:
    """Deploy items that take a schedule whose row is gone off the hosts still holding it. Only what deployed it says
    where it is, so this reads the deployed table. Reports with no flags, like every script."""
    from . import deploy
    sid, ref = int(schedule_id), str(int(schedule_id))
    paths = (f'/usr/local/lib/storageforge/scheduler/task-{sid}.sh', f'/etc/storageforge/scheduler/{sid}.json',
             f'/etc/cron.d/sf-sched-{sid}', f'/var/lib/storageforge/managed/sched-{sid}.sha256')
    text = f"""#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
MODE=report
[[ ${{1:-}} == --uninstall ]] && MODE=uninstall
{HELPERS}
section "Deleted schedule #{sid}"
for f in {' '.join(paths)}; do
  [[ -e $f ]] || continue
  if [[ $MODE == uninstall ]]; then rm -f -- "$f"; ok "removed $f"; else missing "$f will be removed"; fi
done
finished
"""

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

