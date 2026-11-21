"""What the web app takes from what agents reported, a few seconds after the receiver stored it, on a background thread of its own and
never on a web request's (roadmap sections 11.3 and 3 phase 2; the receiver, a process of its own, stored it: agentreceiver.py).

    run(db, wake)      the loop: every TICK_SECS, take_once(db), and wake the notification center when something changed
    take_once(db)      agents' last words (agentguard.take_reports, which acts only on the agent that sent one), the lines their logs
                       plugins pushed (take_lines), whether an agent with the heartbeat plugin went silent (silent_beats), and
                       the readings of the disks, files, scan and sentinel plugins (agentplugins.take)
    take_lines(db)     pushed journal lines into the host's logs: the host is the one the receiver stored them under, from the key
                       that signed the batch, never one a line names. Each line goes through hostlogs.store, as a scan's do: scrubbed
                       of secrets, the host's rate, the log rules matched as the lines arrive. Per host it also keeps the delay (when a
                       line arrived here against the time its host stamped on it), the numbers missing from the journal's own
                       numbering (__SEQNUM: lines deleted on the host, or never sent; debug lines the plugin leaves out it says, and
                       they are not counted), and that the lines came signed

The receiver's database role writes only its own three tables; moving what agents said into the rest of StorageForge happens here,
on the web app's side, so that role stays as narrow as it is.
"""
from __future__ import annotations

import json
import statistics
import time

from . import agentguard, agentplugins, agentwatch, errlog, hostlogs
from .db import Database

TICK_SECS = 5
RECORDS_PER_TICK = 500          # pushed readings taken per tick, oldest first; more wait for the next


def _lines_of(body: dict) -> list:
    lines = body.get('lines') if isinstance(body, dict) else None
    return [x for x in lines if isinstance(x, dict)][:1000] if isinstance(lines, list) else []


def take_lines(db: Database, now: float | None = None, counts: dict | None = None) -> dict:
    """Moves pushed lines into host logs. Returns {host: new lines stored}; `counts` gets 'hits', the lines a log rule matched."""
    conn = db.connect()
    stored = {}
    counts = {} if counts is None else counts
    try:
        rows = conn.all("""SELECT record_id, host, received_at, body_json FROM agent_records WHERE plugin = 'logs' AND kind = 'lines'
                           ORDER BY record_id LIMIT :n""", {'n': RECORDS_PER_TICK})
        by_host: dict[str, list] = {}
        for record_id, host, received_at, body_json in rows:
            try:
                body = json.loads(body_json or '{}')
            except ValueError:
                body = {}
            by_host.setdefault(host, []).append((record_id, received_at, body if isinstance(body, dict) else {}))
        for host, records in by_host.items():
            stored[host] = _take_host(conn, host, records, now, counts)
            ids = [r[0] for r in records]
            for i in range(0, len(ids), 200):
                part = ids[i:i + 200]
                conn.execute(f"DELETE FROM agent_records WHERE record_id IN ({', '.join(f':r{j}' for j in range(len(part)))})", {f'r{j}': r for j, r in enumerate(part)})
    finally:
        conn.close()
    return stored


def _take_host(conn, host: str, records: list, now: float | None, counts: dict) -> int:
    now = time.time() if now is None else now
    status = next(iter(conn.all('SELECT seq_id, seq_last FROM host_log_status WHERE host = :h', {'h': host})), (None, None))
    seq_id, seq_last = status
    lines, delays, gaps = [], [], 0
    for _record_id, received_at, body in records:
        for raw in _lines_of(body):
            try:
                line = hostlogs._line(raw, now)
            except (ValueError, TypeError, KeyError, RecursionError):
                continue
            if not line:
                continue
            sid, n = line.get('seqnum_id'), line.get('seqnum')
            skipped = raw.get('skipped') if isinstance(raw.get('skipped'), int) and raw.get('skipped') >= 0 else 0
            if sid and n is not None:
                if sid == seq_id and seq_last is not None and n > seq_last:
                    gaps += max(0, n - seq_last - 1 - skipped)
                if sid != seq_id or seq_last is None or n > seq_last:
                    seq_id, seq_last = sid, n
            delays.append(max(0, int(received_at * 1000 - line['at_us'] // 1000)))
            lines.append(line)
        # the reading's cursor covers the debug entries after its last line: counting goes on from there
        c = body.get('cursor')
        if isinstance(c, dict) and c.get('s') == seq_id and isinstance(c.get('i'), int) and seq_last is not None and c['i'] > seq_last:
            seq_last = c['i']
    new = hostlogs.store(conn, host, {'state': 'ok', 'lines': lines, 'cut': False}, now, via='agent', counts=counts) if lines else 0
    conn.execute("""UPDATE host_log_status SET pushed_at = :t, push_delay_ms = :d, push_lines = push_lines + :n, seq_id = :sid, seq_last = :sl,
                    seq_gaps = seq_gaps + :g, seq_gap_at = CASE WHEN :g > 0 THEN :t ELSE seq_gap_at END WHERE host = :h""",
                 {'t': int(now), 'd': int(statistics.median(delays)) if delays else None, 'n': len(lines), 'sid': seq_id, 'sl': seq_last, 'g': gaps, 'h': host})
    return new


class Beats:
    """Which agents with the heartbeat plugin are silent now, so the notification center is woken the moment one goes silent rather
    than at its next tick."""

    def __init__(self):
        self.silent: set[str] = set()

    def changed(self, db: Database, now: float | None = None) -> bool:
        conn = db.connect()
        try:
            now_silent = set(agentwatch.silent_beats(conn, now))
        finally:
            conn.close()
        changed = now_silent != self.silent
        self.silent = now_silent
        return changed


def take_once(db: Database, beats: Beats | None = None) -> dict:
    counts = {}
    out = {'wiped': agentguard.take_reports(db), 'lines': sum(take_lines(db, counts=counts).values()), 'hits': counts.get('hits', 0)}
    out['readings'] = agentplugins.take(db)       # the disks, files, scan and sentinel plugins (agentplugins.py)
    if beats is not None:
        out['silence'] = beats.changed(db)
    return out


def run(db: Database, wake=None, tick: float = TICK_SECS):
    time.sleep(tick)
    beats = Beats()
    while True:
        try:
            done = take_once(db, beats)
            # a log rule a pushed line matched is a notification now, not at the notification center's next tick
            if wake and (done['wiped'] or done.get('silence') or done['hits'] or done.get('readings')):
                wake()
        except Exception:
            errlog.trace()
        time.sleep(tick)
