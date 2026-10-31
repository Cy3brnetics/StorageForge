"""Confirmation and log fetching for deployed scripts.

Scans collect completion records for deploy runs (/var/lib/storageforge/run/runs.jsonl) and
installed storage tasks (/var/lib/storageforge/tasks/*.last and runs.jsonl).

When a scan runs:
  1. Matches nonces in deploy_runs to confirm how each deploy run finished on the host.
     Updates status (e.g. from interrupted/unknown to ok/failed) and records host_state/host_exit.
  2. Ingests task runs into task_runs.
  3. If a deploy run or scheduled task failed, automatically runs a signed read-only log fetch
     via deploy access (once per problem) and records it in host_logs and the run output.
"""
from __future__ import annotations

import json
import time
import traceback

from . import deploy
from .db import Conn, Database


def ingest_tasks(conn: Conn, host: str, text: str) -> int:
    """Ingest storage task runs read by a scan from /var/lib/storageforge/tasks/."""
    n = 0
    now = int(time.time())
    for line in (text or '').splitlines():
        line = line.strip()
        if not line or not line.startswith('{'):
            continue
        try:
            r = json.loads(line)
        except ValueError:
            continue
        if not isinstance(r, dict) or not r.get('task') or 'started' not in r:
            continue
        task = str(r['task'])[:100]
        started = int(r['started'])
        finished = int(r.get('finished') or started)
        rc = int(r.get('rc', 0))
        # check if already recorded
        have = conn.scalar("SELECT count(*) FROM task_runs WHERE host = :h AND task = :t AND started_at = :s",
                           {'h': host, 't': task, 's': started})
        if not have:
            conn.execute("""INSERT INTO task_runs (host, task, started_at, finished_at, exit_code, via, received_at)
                            VALUES (:h, :t, :s, :f, :rc, 'scan', :now)""",
                         {'h': host, 't': task, 's': started, 'f': finished, 'rc': rc, 'now': now})
            n += 1
        else:
            conn.execute("""UPDATE task_runs SET finished_at = :f, exit_code = :rc
                            WHERE host = :h AND task = :t AND started_at = :s AND (exit_code IS NULL OR exit_code != :rc)""",
                         {'h': host, 't': task, 's': started, 'f': finished, 'rc': rc})
    return n


def ingest_runs(conn: Conn, host: str, text: str) -> list[dict]:
    """Match nonces from the host's deploy runner log and update deploy_runs."""
    now = int(time.time())
    confirmed = []
    seen_nonces = set()
    for line in (text or '').splitlines():
        line = line.strip()
        if not line or not line.startswith('{'):
            continue
        try:
            r = json.loads(line)
        except ValueError:
            continue
        if not isinstance(r, dict) or not r.get('nonce'):
            continue
        nonce = str(r['nonce'])
        seen_nonces.add(nonce)
        rc = int(r.get('rc', 0))
        fin = int(r.get('finished') or now)

        row = conn.all("""SELECT run_id, status, exit_code, confirmed_at, output, mode FROM deploy_runs
                          WHERE nonce = :n AND lower(host) = lower(:h)""", {'n': nonce, 'h': host})
        if not row:
            continue
        rid, status, cur_exit, conf_at, cur_out, mode = row[0]
        if conf_at and cur_exit == rc:
            continue

        # The same reading the run got when it ended: exit code 0 with steps left stays incomplete
        new_status = deploy.run_status(rc, mode, cur_out or '')
        note = f"\n[confirmed by scan at {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(now))}: host finished with exit code {rc}]\n"
        conn.execute("""UPDATE deploy_runs
                        SET host_state = 'finished', host_exit = :rc, confirmed_at = :now,
                            status = :st, exit_code = :rc, finished_at = COALESCE(finished_at, :fin),
                            output = output || :note
                        WHERE run_id = :rid""",
                     {'rc': rc, 'now': now, 'st': new_status, 'fin': fin, 'note': note, 'rid': rid})
        confirmed.append({'run_id': rid, 'nonce': nonce, 'rc': rc, 'status': new_status})

    # For runs that started > 10 minutes ago, are still running/queued, but not in seen_nonces
    stale_cutoff = now - 600
    rows = conn.all("""SELECT run_id, nonce FROM deploy_runs
                       WHERE lower(host) = lower(:h) AND status IN ('running', 'queued') AND started_at < :cutoff""",
                    {'h': host, 'cutoff': stale_cutoff})
    for rid, nonce in rows:
        if nonce and nonce not in seen_nonces:
            note = f"\n[scan at {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(now))}: no record of this run on host; marked absent]\n"
            conn.execute("""UPDATE deploy_runs
                            SET host_state = 'absent', confirmed_at = :now, status = 'failed',
                                output = output || :note
                            WHERE run_id = :rid""",
                         {'now': now, 'note': note, 'rid': rid})
            confirmed.append({'run_id': rid, 'nonce': nonce, 'rc': -1, 'status': 'failed'})

    return confirmed


def fetch_problem_logs(db: Database, conn: Conn, host: str, confirmed: list[dict], log=None) -> int:
    """Fetch logs from host for failed deploy runs or tasks using deploy access (once per problem)."""
    if not deploy.ready(conn, host):
        return 0

    now = int(time.time())
    fetched = 0

    # 1. Failed deploy runs
    # Check confirmed runs or any failed deploy run on this host in the last 7 days without logs
    failed_runs = [c for c in confirmed if c.get('rc') != 0]
    if not failed_runs:
        rows = conn.all("""SELECT run_id, nonce, exit_code FROM deploy_runs
                           WHERE lower(host) = lower(:h) AND status IN ('failed', 'refused')
                             AND started_at > :since ORDER BY run_id DESC LIMIT 5""",
                        {'h': host, 'since': now - 7 * 86400})
        failed_runs = [{'run_id': r[0], 'nonce': r[1], 'rc': r[2]} for r in rows]

    for fr in failed_runs:
        rid = fr['run_id']
        nonce = fr.get('nonce')
        log_key = f'deploy:{rid}'
        existing = conn.scalar("SELECT state FROM host_logs WHERE log_key = :k", {'k': log_key})
        if existing in ('fetched', 'failed'):
            continue
        if not existing:
            conn.execute("""INSERT INTO host_logs (log_key, host, kind, ref, reason, state, found_at)
                            VALUES (:k, :h, 'deploy', :r, :re, 'pending', :t)""",
                         {'k': log_key, 'h': host, 'r': str(rid), 're': f'deploy run {rid} failed with rc {fr.get("rc")}', 't': now})

        # Fetch the log
        script = ("tail -n 100 /var/log/storageforge/run.log 2>/dev/null || "
                  "journalctl -u storageforge-deploy -n 100 --no-pager 2>&1 || true")
        if nonce:
            script = (f"grep -C 10 -F {nonce} /var/log/storageforge/run.log 2>/dev/null || "
                      "tail -n 100 /var/log/storageforge/run.log 2>/dev/null || true")

        try:
            res = deploy.run(db, host, script, kind='log_fetch', ref=str(rid), mode='report',
                             actor='system', require_ready=True)
            out = res.get('output', '').strip()
            conn.execute("""UPDATE host_logs
                            SET state = 'fetched', output = :o, fetched_at = :t, fetch_run = :fr
                            WHERE log_key = :k""",
                         {'o': out, 't': int(time.time()), 'fr': res.get('run_id'), 'k': log_key})
            if out:
                conn.execute("UPDATE deploy_runs SET output = output || :append WHERE run_id = :r",
                             {'append': f"\n--- host logs fetched by scan ---\n{out}\n", 'r': rid})
            fetched += 1
            if log:
                log(f'  fetched logs for failed deploy run #{rid}')
        except Exception as exc:
            conn.execute("UPDATE host_logs SET state = 'failed', attempts = attempts + 1 WHERE log_key = :k", {'k': log_key})
            if log:
                log(f'  could not fetch logs for deploy run #{rid}: {exc}')

    # 2. Failed storage tasks
    failed_tasks = conn.all("""SELECT t1.task, t1.started_at, t1.exit_code
                               FROM task_runs t1
                               JOIN (SELECT host, task, max(started_at) as max_s FROM task_runs WHERE lower(host) = lower(:h) GROUP BY host, task) t2
                                 ON t1.task = t2.task AND t1.started_at = t2.max_s
                               WHERE lower(t1.host) = lower(:h) AND t1.exit_code != 0 AND t1.started_at > :since
                               ORDER BY t1.started_at DESC LIMIT 3""",
                            {'h': host, 'since': now - 7 * 86400})
    for task_name, s_at, rc in failed_tasks:
        log_key = f'task:{host}:{task_name}:{s_at}'
        existing = conn.scalar("SELECT state FROM host_logs WHERE log_key = :k", {'k': log_key})
        if existing in ('fetched', 'failed'):
            continue
        if not existing:
            conn.execute("""INSERT INTO host_logs (log_key, host, kind, ref, reason, state, found_at)
                            VALUES (:k, :h, 'task', :r, :re, 'pending', :t)""",
                         {'k': log_key, 'h': host, 'r': task_name, 're': f'task {task_name} failed with exit {rc}', 't': now})
        script = f"journalctl -u sf-task-{task_name} -n 100 --no-pager 2>&1 || cat /var/log/messages 2>/dev/null || true"
        try:
            res = deploy.run(db, host, script, kind='log_fetch', ref=task_name, mode='report',
                             actor='system', require_ready=True)
            out = res.get('output', '').strip()
            conn.execute("""UPDATE host_logs
                            SET state = 'fetched', output = :o, fetched_at = :t, fetch_run = :fr
                            WHERE log_key = :k""",
                         {'o': out, 't': int(time.time()), 'fr': res.get('run_id'), 'k': log_key})
            fetched += 1
            if log:
                log(f'  fetched logs for failed storage task {task_name}')
        except Exception as exc:
            conn.execute("UPDATE host_logs SET state = 'failed', attempts = attempts + 1 WHERE log_key = :k", {'k': log_key})
            if log:
                log(f'  could not fetch logs for task {task_name}: {exc}')

    return fetched


def ingest_scan(db: Database, conn: Conn, host: str, runs_text: str, tasks_text: str,
                schedules_text: str = '', log=None) -> dict:
    """Invoked after scan inventory is collected: confirms deploy runs, tasks, schedules, and fetches problem logs."""
    from . import scheduler
    n_tasks = ingest_tasks(conn, host, tasks_text) if tasks_text else 0
    n_sched = scheduler.ingest_scan_schedules(conn, host, schedules_text) if schedules_text else 0
    confirmed = ingest_runs(conn, host, runs_text) if runs_text else []
    fetched = fetch_problem_logs(db, conn, host, confirmed, log=log)
    return {'tasks': n_tasks, 'schedules': n_sched, 'confirmed': len(confirmed), 'logs_fetched': fetched}
