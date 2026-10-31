#!/usr/bin/env python3
"""Lightweight client-side scheduler runner and daemon: storageforge-scheduler.
Can run standalone, be invoked by cron (/etc/cron.d/ or crontab), or run as a background daemon.
Self-contained with zero non-stdlib dependencies so it can be installed directly as /usr/local/sbin/storageforge-scheduler.
"""
from __future__ import annotations

import argparse
import datetime as dt
import fcntl
import glob
import json
import os
import pwd
import random
import re
import secrets
import shutil
import signal
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
import zoneinfo
from pathlib import Path

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
REPORT_MAX = 480 << 10    # the server takes 512 KiB


def _parse_field(field_str: str, min_val: int, max_val: int, name_map: dict[str, int] | None = None) -> set[int]:
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
        dow.add(0)
    return mins, hours, dom, months, dow


def mins_from_str(s: str) -> int:
    h, m = s.split(':')
    return int(h) * 60 + int(m)


def in_window(window: str, now_dt: dt.datetime | None = None) -> bool:
    """Checks if current time is inside "HH:MM-HH:MM" window (supports crossing midnight)."""
    if not window or '-' not in window:
        return True
    now = now_dt or dt.datetime.now()
    cur = now.hour * 60 + now.minute
    p1, p2 = window.split('-')
    start, end = mins_from_str(p1), mins_from_str(p2)
    if start <= end:
        return start <= cur < end
    return cur >= start or cur < end


def load_config(id_or_path: str, config_dir: str = '/etc/storageforge/scheduler') -> dict:
    if os.path.isfile(id_or_path):
        with open(id_or_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    p = os.path.join(config_dir, f'{id_or_path}.json')
    if os.path.isfile(p):
        with open(p, 'r', encoding='utf-8') as f:
            return json.load(f)
    raise FileNotFoundError(f'no scheduler config found for {id_or_path}')


def now_in(cfg: dict, now_dt: dt.datetime | None = None) -> dt.datetime:
    """The time in the schedule's own timezone, which need not be the host's."""
    try:
        tz = zoneinfo.ZoneInfo(cfg.get('timezone') or 'UTC')
    except Exception:
        tz = dt.timezone.utc
    return now_dt or dt.datetime.now(tz=tz)


def is_due(conf: dict, now_dt: dt.datetime | None = None) -> bool:
    now = now_in(conf.get('config') or {}, now_dt)
    mins, hours, doms, months, dows = parse_cron(conf.get('cron_expr', ''))
    return (now.minute in mins and now.hour in hours and now.day in doms and now.month in months
            and (now.weekday() + 1) % 7 in dows)


def task_command(cfg: dict, script_path: str, script_args: list[str]) -> list[str]:
    """The task with its CPU and I/O priority, where the host has the tools for them."""
    cmd = ['bash', script_path, *script_args]
    classes = {'realtime': '1', 'best-effort': '2', 'idle': '3'}
    if cfg.get('ionice_class') in classes and shutil.which('ionice'):
        klass = classes[cfg['ionice_class']]
        cmd = ['ionice', '-c', klass, *([] if klass == '3' else ['-n', str(int(cfg.get('ionice_priority', 7)))]), *cmd]
    if cfg.get('nice') is not None and shutil.which('nice'):
        cmd = ['nice', '-n', str(int(cfg['nice'])), *cmd]
    return cmd


def as_user(name: str | None) -> dict:
    """Popen arguments to run the task as config.user. Only root can switch; an unknown user raises, and the run fails."""
    if not name or name == 'root' or os.geteuid() != 0:
        return {}
    p = pwd.getpwnam(name)
    return {'user': p.pw_uid, 'group': p.pw_gid, 'extra_groups': os.getgrouplist(name, p.pw_gid)}


def fit_report(report: dict) -> bytes:
    """The report as JSON, under what the server accepts. A long run keeps its end, where the result and any error are."""
    while True:
        data = json.dumps(report).encode('utf-8')
        if len(data) <= REPORT_MAX or not report.get('output'):
            return data
        report = {**report, 'output': '[start of output cut]\n' + report['output'][len(report['output']) // 2:]}


def send_report(report_url: str, token: str, report: dict, ca_file: str | None = None) -> bool:
    """Sends execution report back to StorageForge server via HTTP/HTTPS POST."""
    if not report_url:
        return False
    url = f"{report_url.rstrip('/')}/api/scheduler/report"
    data = fit_report(report)
    req = urllib.request.Request(url, data=data, method='POST')
    req.add_header('Content-Type', 'application/json')
    req.add_header('Authorization', f'Bearer {token}')
    ctx = None
    ca = ca_file or os.environ.get('STORAGEFORGE_REPORT_CA_FILE') or '/etc/storageforge/report-ca.pem'
    if url.startswith('https://') and ca and os.path.isfile(ca):
        try:
            ctx = ssl.create_default_context(cafile=ca)
        except Exception:
            ctx = None
    try:
        with urllib.request.urlopen(req, timeout=30, context=ctx) as resp:
            return resp.status in (200, 201)
    except Exception as exc:
        print(f"storageforge-scheduler: failed to send report: {exc}", file=sys.stderr)
        return False


def run_schedule(conf: dict, var_dir: str = '/var/lib/storageforge/scheduler',
                 locks_dir: str = '/run/lock', no_jitter: bool = True) -> int:
    """Executes a single scheduled task according to its client configuration."""
    sid = conf.get('schedule_id', 'unknown')
    cfg = conf.get('config', {})
    script_path = conf.get('script_path') or ''
    script_args = [str(x) for x in (conf.get('script_args') or [])]

    if conf.get('paused'):
        print(f"storageforge-scheduler: skipping {sid}, schedule is paused")
        return 0

    # 1. Window check
    window = cfg.get('window')
    if window and not in_window(window, now_in(cfg)):
        print(f"storageforge-scheduler: skipping {sid}, current time outside window ({window})")
        return 0

    # Optional random jitter
    jitter = int(cfg.get('jitter_sec') or 0)
    if jitter > 0 and not no_jitter:
        time.sleep(random.randint(0, jitter))

    # 2. Concurrency Lock
    os.makedirs(locks_dir, exist_ok=True)
    lock_file = os.path.join(locks_dir, f'sf-sched-{sid}.lock')
    lock_fd = open(lock_file, 'a+')     # not w+: that empties the file before policy replace can read the PID

    policy = cfg.get('concurrency_policy', 'skip')
    try:
        if policy == 'skip':
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        elif policy == 'queue':
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
        elif policy == 'replace':
            lock_fd.seek(0)
            existing_pid = lock_fd.read().strip()
            if existing_pid.isdigit():
                try:
                    os.kill(int(existing_pid), signal.SIGTERM)
                    time.sleep(1)
                except ProcessLookupError:
                    pass
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        print(f"storageforge-scheduler: task {sid} is already running (policy: skip)")
        lock_fd.close()
        return 0

    # Write current PID
    lock_fd.seek(0)
    lock_fd.truncate()
    lock_fd.write(str(os.getpid()))
    lock_fd.flush()

    # 3. Environment & Retries
    env = dict(os.environ)
    for k, v in (cfg.get('env') or {}).items():
        env[str(k)] = str(v)

    timeout = int(cfg.get('timeout_sec') if cfg.get('timeout_sec') is not None else 3600)
    retries = int(cfg.get('retry_count') or 0)
    retry_delay = int(cfg.get('retry_delay_sec') or 30)
    retry_backoff = float(cfg.get('retry_backoff') or 1.0)

    started_at = int(time.time())
    nonce = secrets.token_hex(16)
    exit_code = -1
    full_output = []

    cur_delay = retry_delay
    attempts = 0
    max_attempts = retries + 1

    while attempts < max_attempts:
        attempts += 1
        if attempts > 1:
            print(f"storageforge-scheduler: retry attempt {attempts}/{max_attempts} after delay {cur_delay}s...")
            time.sleep(cur_delay)
            cur_delay = int(cur_delay * retry_backoff)

        cmd = task_command(cfg, script_path, script_args) if script_path else ['echo', 'no script path specified']
        try:
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                 env=env, text=True, bufsize=1, **as_user(cfg.get('user')))
            out, _ = p.communicate(timeout=timeout if timeout > 0 else None)
            exit_code = p.returncode
            full_output.append(out or '')
            if exit_code == 0:
                break
        except subprocess.TimeoutExpired:
            p.kill()
            out, _ = p.communicate()
            exit_code = 124
            full_output.append(out or '')
            full_output.append(f"\n[ERROR: Process timed out after {timeout} seconds]\n")
            break
        except Exception as exc:
            exit_code = 1
            full_output.append(f"\n[ERROR executing task: {exc}]\n")
            break

    finished_at = int(time.time())
    combined_output = '\n'.join(full_output)

    # 4. Local Run Tracking (0755 dir, 0644 files so non-root scans can collect runs.jsonl)
    run_dir = os.path.join(var_dir, str(sid))
    os.makedirs(run_dir, mode=0o755, exist_ok=True)
    try:
        os.chmod(var_dir, 0o755)
        os.chmod(run_dir, 0o755)
    except OSError:
        pass

    report = {
        'schedule_id': sid,
        'nonce': nonce,
        'started_at': started_at,
        'finished_at': finished_at,
        'exit_code': exit_code,
        'output': combined_output,
        'attempts': attempts,
    }

    last_path = os.path.join(run_dir, 'last.json')
    runs_path = os.path.join(run_dir, 'runs.jsonl')

    try:
        with open(last_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2)
        os.chmod(last_path, 0o644)
    except Exception:
        pass

    try:
        compact = {**report, 'output': combined_output[-4096:]}
        with open(runs_path, 'a', encoding='utf-8') as f:
            f.write(json.dumps(compact) + '\n')
        os.chmod(runs_path, 0o644)
    except Exception:
        pass

    # 5. Report back to server
    token = conf.get('token', '')
    report_url = conf.get('report_url', '')
    if report_url and token:
        send_report(report_url, token, report)

    # Clean up lock
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        lock_fd.close()
    except Exception:
        pass

    return exit_code


def daemon_tick(config_dir: str = '/etc/storageforge/scheduler',
                var_dir: str = '/var/lib/storageforge/scheduler',
                locks_dir: str = '/run/lock',
                now_dt: dt.datetime | None = None) -> list[int]:
    """Evaluates all schedule configs in config_dir for the current minute and spawns due jobs."""
    spawned = []
    confs = glob.glob(os.path.join(config_dir, '*.json'))
    for path in sorted(confs):
        try:
            conf = load_config(path)
            if conf.get('paused'):
                continue
            if is_due(conf, now_dt):
                subprocess.Popen([sys.executable, os.path.abspath(__file__),
                                  'run', path, '--var-dir', var_dir, '--lock-dir', locks_dir, '--jitter'],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                spawned.append(conf.get('schedule_id'))
        except Exception as err:
            print(f"daemon error processing {path}: {err}", file=sys.stderr)
    return spawned


def daemon_loop(config_dir: str = '/etc/storageforge/scheduler',
                var_dir: str = '/var/lib/storageforge/scheduler',
                locks_dir: str = '/run/lock',
                poll_sec: int = 20, once: bool = False):
    """Background daemon that parses cron expressions for all configs and spawns runs when due."""
    print(f"storageforge-scheduler daemon started, watching {config_dir} (poll={poll_sec}s)")
    last_checked_key = None

    while True:
        try:
            now_utc = dt.datetime.now(dt.timezone.utc)
            cur_key = (now_utc.year, now_utc.month, now_utc.day, now_utc.hour, now_utc.minute)
            if cur_key != last_checked_key:
                last_checked_key = cur_key
                daemon_tick(config_dir=config_dir, var_dir=var_dir, locks_dir=locks_dir)
        except Exception as exc:
            print(f"daemon exception: {exc}", file=sys.stderr)

        if once:
            break
        time.sleep(poll_sec)


def scheduler_binary() -> str:
    return Path(__file__).read_text(encoding='utf-8')


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog='storageforge-scheduler',
                                     description='StorageForge lightweight client-side task scheduler & runner')
    sub = parser.add_subparsers(dest='cmd', required=True)

    # run command
    r = sub.add_parser('run', help='run a scheduled task once')
    r.add_argument('id', help='schedule ID or path to JSON config')
    r.add_argument('--config-dir', default='/etc/storageforge/scheduler')
    r.add_argument('--var-dir', default='/var/lib/storageforge/scheduler')
    r.add_argument('--lock-dir', default='/run/lock')
    r.add_argument('--jitter', action='store_true', help='apply configured random jitter delay before running')
    r.add_argument('--if-due', action='store_true', help='do nothing unless the schedule is due this minute, in its own timezone')

    # daemon command
    d = sub.add_parser('daemon', help='run background scheduler daemon')
    d.add_argument('--config-dir', default='/etc/storageforge/scheduler')
    d.add_argument('--var-dir', default='/var/lib/storageforge/scheduler')
    d.add_argument('--lock-dir', default='/run/lock')
    d.add_argument('--poll-sec', type=int, default=20)
    d.add_argument('--once', action='store_true', help='evaluate current minute once and exit')

    # list command
    l = sub.add_parser('list', help='list installed schedules')
    l.add_argument('--config-dir', default='/etc/storageforge/scheduler')

    # status command
    s = sub.add_parser('status', help='show status of a schedule')
    s.add_argument('id')
    s.add_argument('--var-dir', default='/var/lib/storageforge/scheduler')

    args = parser.parse_args(argv)

    if args.cmd == 'run':
        try:
            conf = load_config(args.id, args.config_dir)
            if args.if_due and (conf.get('paused') or not is_due(conf)):
                return 0
            return run_schedule(conf, args.var_dir, args.lock_dir, no_jitter=not args.jitter)
        except Exception as exc:
            print(f"storageforge-scheduler: error: {exc}", file=sys.stderr)
            return 1

    elif args.cmd == 'daemon':
        daemon_loop(args.config_dir, args.var_dir, args.lock_dir, args.poll_sec, once=args.once)
        return 0

    elif args.cmd == 'list':
        confs = glob.glob(os.path.join(args.config_dir, '*.json'))
        if not confs:
            print("No schedules installed.")
            return 0
        print(f"{'ID':<6} {'NAME':<24} {'CRON':<16} {'TYPE':<10} {'TARGET':<20}")
        print("-" * 80)
        for path in sorted(confs):
            try:
                c = load_config(path)
                print(f"{str(c.get('schedule_id', '')): <6} {c.get('name', ''):<24} "
                      f"{c.get('cron_expr', ''):<16} {c.get('task_type', ''):<10} {c.get('task_ref', ''):<20}")
            except Exception:
                pass
        return 0

    elif args.cmd == 'status':
        run_file = os.path.join(args.var_dir, str(args.id), 'last.json')
        if not os.path.isfile(run_file):
            print(f"No run records found for schedule {args.id}")
            return 1
        with open(run_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
            print(json.dumps(data, indent=2))
        return 0

    return 0


if __name__ == '__main__':
    sys.exit(main())
