"""The agent's plugins past the first four, taken from what the receiver stored, on agentingest's background thread (roadmap section
11.4; docs/agent.md). Each reading is handed to the module for its plugin and kind, under the host the receiver stored it under (from
the key that signed the batch, never one a reading names), then deleted: what was made of it is kept in that module's tables.

    take(db, now)        the readings waiting, oldest first, at most RECORDS_PER_TICK: {plugin: readings taken}
    problems(conn, now)  every plugin module's notifications, for agentwatch.problems
"""
from __future__ import annotations

import json
import time

from . import agentdisks, agentfiles, agentscan, errlog


def _sentinel_events(conn, host: str, body: dict, at: int) -> int:
    """The sentinel's events an agent carried: the host's claim, through the checks and limits of the sentinel's own reports, marked
    as come through the agent (security.ingest_events with via 'agent'), which is never a witness for an action on another host."""
    from .security import ingest_events
    lines = [x for x in (body.get('lines') if isinstance(body.get('lines'), list) else [])[:500] if isinstance(x, str) and len(x) <= 16 << 10]
    return ingest_events(conn, host, '\n'.join(lines), 'agent')
from .db import Database

RECORDS_PER_TICK = 500


def _takers() -> dict:
    return {('disks', 'smart'): agentdisks.take_smart, ('disks', 'errors'): agentdisks.take_errors,
            ('files', 'changes'): agentfiles.take_changes, ('files', 'reads'): agentfiles.take_reads, ('files', 'watching'): agentfiles.take_watching,
            ('scan', 'inventory'): agentscan.take_inventory, ('sentinel', 'events'): _sentinel_events}


def take(db: Database, now: float | None = None) -> dict:
    now = int(now or time.time())
    takers = _takers()
    plugins = sorted({p for p, _k in takers})
    conn = db.connect()
    out: dict[str, int] = {}
    try:
        marks = ', '.join(f':p{i}' for i in range(len(plugins)))
        rows = conn.all(f"""SELECT record_id, host, plugin, kind, received_at, body_json FROM agent_records WHERE plugin IN ({marks})
                            ORDER BY record_id LIMIT :n""", {'n': RECORDS_PER_TICK, **{f'p{i}': p for i, p in enumerate(plugins)}})
        done = []
        for record_id, host, plugin, kind, received_at, body_json in rows:
            done.append(record_id)
            taker = takers.get((plugin, kind))
            try:
                body = json.loads(body_json or '{}')
            except ValueError:
                continue
            if taker is None or not isinstance(body, dict):
                continue
            try:
                taker(conn, host, body, int(received_at or now))
                out[plugin] = out.get(plugin, 0) + 1
            except (ValueError, TypeError, KeyError, RecursionError):
                errlog.trace()        # a reading of a form nothing here reads: dropped, the rest go on
        for i in range(0, len(done), 200):
            part = done[i:i + 200]
            conn.execute(f"DELETE FROM agent_records WHERE record_id IN ({', '.join(f':r{j}' for j in range(len(part)))})", {f'r{j}': r for j, r in enumerate(part)})
    finally:
        conn.close()
    return out


def problems(conn, now: float | None = None) -> dict:
    out = {}
    for module in (agentdisks, agentfiles, agentscan):
        try:
            out.update(module.problems(conn, now))
        except Exception:
            errlog.trace()
    return out
