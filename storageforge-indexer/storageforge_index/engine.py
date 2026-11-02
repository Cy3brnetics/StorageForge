"""One deploy as one thing: it has a title, a state, phases, and can be stopped, retried and found again later.

    start(items) ──► deploy_groups row + one queued deploy_runs row per item, in order, seen by the UI at once
                     phase 0: up to PARALLEL hosts side by side ──► phase 1 ──► ...
                     apply: a host that fails stops what has not started; a report always runs everywhere
                     cancel: nothing new starts; force also stops the ssh of what is running
                     end: state = cancelled | failed | incomplete | ok, then after(host) per applied host (rescans)

An item is a dict of deploy.run arguments, plus on_ok, on_fail and phase. Items without a phase run one at a time in
the order given. Generators give one when hosts don't depend on each other: only they know that. One host never runs
two scripts at once, across groups too (deploy.run takes the host's lock).

Runs live in deploy_runs as before; deploy_groups only adds what a run can't say about the deploy it belongs to.
"""
from __future__ import annotations

import json
import os
import re
import threading
import time
import uuid

from . import deploy, errlog
from .db import Database

PARALLEL = max(1, int(os.environ.get('STORAGEFORGE_DEPLOY_PARALLEL', '4')))
GROUP_FIELDS = ('group_id', 'kind', 'ref', 'mode', 'title', 'state', 'options_json', 'digest', 'report_group', 'retry_of',
                'actor', 'started_at', 'finished_at')
_LINE = re.compile(r'^  (?:\x1b\[[0-9;]*m)?(ok|missing|conflict|->|other|failed|warning)(?:\b|\s)', re.M)
_guard = threading.Lock()
_live: dict[str, '_Live'] = {}


class _Live:
    """What a running group shares with its runs: the cancel request, and the ssh of each run to stop on a forced one."""

    def __init__(self):
        self.cancelled = False
        self.by: str | None = None
        self.procs: dict[int, object] = {}

    def attach(self, run_id: int, proc):
        with _guard:
            self.procs[run_id] = proc
            stop = self.cancelled == 'force'
        if stop:
            proc.kill()

    def detach(self, run_id: int):
        with _guard:
            self.procs.pop(run_id, None)


def start(db: Database, items: list[dict], actor: str, *, title: str | None = None, kind: str | None = None,
          ref: str | None = None, mode: str | None = None, options: dict | None = None, digest: str | None = None,
          report_group: str | None = None, retry_of: str | None = None, stop_on_failure: bool | None = None,
          after=None, parallel: int | None = None) -> str:
    """Run items in a background thread and return the group id to poll. after(host) is called once for each host an
    apply item ran on, failed or not, once the group has ended."""
    gid = uuid.uuid4().hex
    first = items[0] if items else {}
    mode = mode or first.get('mode', 'report')
    if stop_on_failure is None:
        stop_on_failure = mode == 'apply'
    limit = max(1, parallel or PARALLEL)
    now = int(time.time())
    # a report changes nothing, so every host can go at once; an apply goes in the order given unless it says otherwise
    phases = [0 if it.get('mode', mode) != 'apply' else it.get('phase', i) for i, it in enumerate(items)]
    conn = db.connect()
    try:
        conn.execute("""INSERT INTO deploy_groups (group_id, kind, ref, mode, title, state, options_json, digest, report_group,
                                                   retry_of, actor, started_at)
                        VALUES (:g, :k, :r, :m, :ti, 'running', :o, :d, :rg, :ro, :a, :t)""",
                     {'g': gid, 'k': kind or first.get('kind', ''), 'r': str(ref if ref is not None else first.get('ref') or ''),
                      'm': mode, 'ti': title, 'o': json.dumps(options or {}), 'd': digest, 'rg': report_group, 'ro': retry_of,
                      'a': actor, 't': now})
        ids = [conn.scalar("""INSERT INTO deploy_runs (group_id, host, kind, ref, mode, status, actor, started_at, phase)
                              VALUES (:g, :h, :k, :r, :m, 'queued', :a, :t, :p) RETURNING run_id""",
                           {'g': gid, 'h': it['host'], 'k': it['kind'], 'r': it.get('ref'), 'm': it.get('mode', mode),
                            'a': actor, 't': now, 'p': ph}) for it, ph in zip(items, phases)]
    finally:
        conn.close()
    live = _Live()
    with _guard:
        _live[gid] = live
    threading.Thread(target=lambda: _protect(lambda: _work(db, gid, ids, items, phases, live, stop_on_failure, limit, after)),
                     name=f'deploy-{gid[:8]}', daemon=True).start()
    return gid


def _work(db, gid, ids, items, phases, live, stop_on_failure, limit, after):
    state = {'failed': False}
    applied: dict[str, bool] = {}
    wake = threading.Condition()
    busy = [0]

    def one(rid, it):
        try:
            args = {k: v for k, v in it.items() if k not in ('on_ok', 'on_fail', 'phase')}
            res = deploy.run(db, group_id=gid, actor=_actor(db, gid), run_id=rid, live=live, **args)
            hook = it.get('on_ok' if res['status'] in deploy.FINISHED else 'on_fail')
            if hook:
                _protect(lambda: hook(res))
            if res['status'] not in deploy.FINISHED and stop_on_failure:
                state['failed'] = True
        except Exception:
            errlog.trace()
            state['failed'] = state['failed'] or stop_on_failure
        finally:
            with wake:
                busy[0] -= 1
                wake.notify_all()

    try:
        for phase in sorted(set(phases)):
            batch = [(r, it) for r, it, p in zip(ids, items, phases) if p == phase]
            for rid, it in batch:
                with wake:
                    while busy[0] >= limit:
                        wake.wait(1)
                if live.cancelled:
                    _not_run(db, rid, 'cancelled', f'not run: cancelled by {live.by}')
                    continue
                if state['failed']:
                    _not_run(db, rid, 'skipped', 'not run: an earlier host failed')
                    continue
                if it.get('mode') == 'apply':
                    applied[it['host']] = True
                with wake:
                    busy[0] += 1
                threading.Thread(target=lambda rid=rid, it=it: one(rid, it), name=f'deploy-run-{rid}', daemon=True).start()
            with wake:             # the next phase waits for this one: its hosts may depend on what this one set up
                while busy[0]:
                    wake.wait(1)
    finally:
        _finish(db, gid)
        with _guard:
            _live.pop(gid, None)
    if after:
        for h in applied:
            _protect(lambda h=h: after(h))


def _actor(db, gid) -> str | None:
    conn = db.connect()
    try:
        return conn.scalar('SELECT actor FROM deploy_groups WHERE group_id = :g', {'g': gid})
    finally:
        conn.close()


def _not_run(db, rid, status, text):
    conn = db.connect()
    try:
        conn.execute('UPDATE deploy_runs SET status = :s, output = :o, finished_at = :t WHERE run_id = :r',
                     {'s': status, 'o': text, 't': int(time.time()), 'r': rid})
    finally:
        conn.close()


def outcome(statuses: list[str]) -> str:
    """A group's state from its runs' statuses. A skipped host is the failure that caused it, not a state of its own."""
    for state, among in (('running', ('running', 'queued')), ('cancelled', ('cancelled',)), ('failed', ('failed', 'refused', 'skipped')),
                         ('incomplete', ('incomplete',))):
        if any(s in among for s in statuses):
            return state
    return 'ok'


def _finish(db, gid):
    conn = db.connect()
    try:
        rows = [r[0] for r in conn.all('SELECT status FROM deploy_runs WHERE group_id = :g', {'g': gid})]
        conn.execute("UPDATE deploy_groups SET state = :s, finished_at = :t WHERE group_id = :g",
                     {'s': outcome([s if s not in ('queued', 'running') else 'failed' for s in rows]), 't': int(time.time()), 'g': gid})
    finally:
        conn.close()


def _protect(fn):
    try:
        fn()
    except Exception:
        errlog.trace()


def cancel(db, gid: str, actor: str, force: bool = False) -> dict:
    """Nothing new starts. force also kills the ssh of what is running: the host sees its connection drop, and a script
    part way through stops at its next write, so what it finished stays done. Every script is safe to run again."""
    with _guard:
        live = _live.get(gid)
        if not live:
            raise LookupError('that deploy is not running')
        live.cancelled = 'force' if force or live.cancelled == 'force' else True
        live.by = actor
        procs = list(live.procs.values()) if force else []
    for p in procs:
        try:
            p.kill()
        except OSError:
            pass
    return {'group': gid, 'cancelled': True, 'killed': len(procs)}


def running(gid: str) -> bool:
    with _guard:
        return gid in _live


# ── reading them back ───────────────────────────────────────────────
def summarize(text: str | None) -> dict:
    """How many of each kind of line a run printed: what the UI shows before anyone opens the output."""
    out = {'ok': 0, 'missing': 0, 'conflict': 0, 'did': 0}
    for m in _LINE.finditer(text or ''):
        key = {'->': 'did', 'failed': 'conflict', 'warning': 'missing'}.get(m.group(1), m.group(1))
        if key in out:
            out[key] += 1
    return out


def _row(r) -> dict:
    g = dict(zip(GROUP_FIELDS, r))
    g['options'] = json.loads(g.pop('options_json') or '{}')
    return g


def get(conn, gid: str) -> dict | None:
    rows = conn.all(f'SELECT {", ".join(GROUP_FIELDS)} FROM deploy_groups WHERE group_id = :g', {'g': gid})
    return _row(rows[0]) if rows else None


def runs(conn, gid: str) -> list[dict]:
    out = deploy.group(conn, gid)
    for r in out:
        r['summary'] = summarize(r.get('output'))
        log_row = conn.all("SELECT state, output, fetched_at FROM host_logs WHERE log_key = :k", {'k': f'deploy:{r["run_id"]}'})
        if log_row and log_row[0][0] == 'fetched':
            r['fetched_log'] = {'output': log_row[0][1], 'fetched_at': log_row[0][2]}
    return out


def recent(conn, limit: int = 30, host: str | None = None) -> list[dict]:
    """Deploys, newest first, each with how its hosts went."""
    where = 'WHERE group_id IN (SELECT group_id FROM deploy_runs WHERE host = :h)' if host else ''
    rows = conn.all(f'SELECT {", ".join(GROUP_FIELDS)} FROM deploy_groups {where} ORDER BY started_at DESC, group_id LIMIT :l',
                    {'h': host, 'l': limit})
    out = [_row(r) for r in rows]
    ids = {f'g{i}': g['group_id'] for i, g in enumerate(out)}
    by: dict[str, list] = {}
    if ids:
        for gid, h, status in conn.all(f"""SELECT group_id, host, status FROM deploy_runs WHERE group_id IN ({", ".join(":" + k for k in ids)})
                                           ORDER BY run_id""", ids):
            by.setdefault(gid, []).append({'host': h, 'status': status})
    for g in out:
        g['hosts'] = by.get(g['group_id'], [])
    return out


def unfinished_hosts(conn, gid: str) -> list[str]:
    """The hosts of a group that did not end well, in order: what a retry has to do."""
    seen, out = set(), []
    for r in deploy.group(conn, gid):
        if r['host'] not in seen and r['status'] not in deploy.FINISHED:
            seen.add(r['host'])
            out.append(r['host'])
    return out


def close_interrupted(conn, now: int | None = None):
    """After a restart nothing is running, whatever the table says."""
    conn.execute("UPDATE deploy_groups SET state = 'interrupted', finished_at = :t WHERE state = 'running'", {'t': now or int(time.time())})
