"""Interface counters over time, and what stands out in them. Off until someone turns it on, and when on, it still sends nothing: every number is one a device or host's own counters
gave at an ordinary reading. A counter that went backwards means the device rebooted, so that interval is skipped and never reads as a huge negative rate.

    anomaly: an interface moving far more than its own recent normal, or errors and drops where there were none
"""
from __future__ import annotations

import statistics
import time

from .db import Conn

KEY = 'traffic.enabled'
KEEP_SECS = 14 * 86400
MIN_BASELINE = 12
STDDEVS = 4.0
MIN_RATE = 1 << 20        # a jump below a megabyte a second is nobody's emergency
WINDOW = 288


def enabled(conn: Conn) -> bool:
    from .alerts import get_setting
    return bool(get_setting(conn, KEY))


def set_enabled(conn: Conn, on: bool, actor: str) -> dict:
    from .alerts import set_setting
    set_setting(conn, KEY, bool(on), actor[:60])
    return {'enabled': bool(on)}


def record(conn: Conn, host: str, counters: list[dict], now: int | None = None) -> int:
    if not counters or not enabled(conn):
        return 0
    now = now or int(time.time())
    with conn.tx():
        for c in counters:
            conn.execute("""INSERT INTO traffic_samples (host, iface, at, rx_bytes, tx_bytes, rx_drop, tx_drop, rx_error, tx_error) VALUES (:h, :i, :t, :rb, :tb, :rd, :td, :re, :te)
                            ON CONFLICT (host, iface, at) DO NOTHING""",
                         {'h': host, 'i': c['iface'], 't': now, 'rb': c['rx_bytes'], 'tb': c['tx_bytes'], 'rd': c['rx_drop'], 'td': c['tx_drop'], 're': c['rx_error'], 'te': c['tx_error']})
        conn.execute('DELETE FROM traffic_samples WHERE host = :h AND at < :t', {'h': host, 't': now - KEEP_SECS})
    return len(counters)


def rates(rows: list[tuple]) -> list[dict]:
    """rows: (at, rx, tx, rx_drop, tx_drop, rx_err, tx_err), oldest first. Differences between neighbours, with resets left out."""
    out = []
    for a, b in zip(rows, rows[1:]):
        secs = b[0] - a[0]
        deltas = [y - x for x, y in zip(a[1:], b[1:])]
        if secs <= 0 or any(d < 0 for d in deltas):
            continue
        out.append({'at': b[0], 'rx_rate': deltas[0] / secs, 'tx_rate': deltas[1] / secs, 'drops': deltas[2] + deltas[3], 'errors': deltas[4] + deltas[5]})
    return out


def judge(series: list[dict]) -> list[dict]:
    """What the latest interval says, against what came before it."""
    if len(series) < 2:
        return []
    *past, now = series
    found = []
    for key, label in (('rx_rate', 'receiving'), ('tx_rate', 'sending')):
        history = [p[key] for p in past]
        if len(history) >= MIN_BASELINE:
            mean, dev = statistics.fmean(history), statistics.pstdev(history)
            if now[key] > MIN_RATE and now[key] > mean + STDDEVS * max(dev, mean * 0.1):
                found.append({'kind': 'rate', 'text': f'{label} {now[key] / (1 << 20):.1f} MiB/s, against a usual {mean / (1 << 20):.1f}', 'value': now[key], 'usual': mean})
    if now['errors'] > 0 and not any(p['errors'] for p in past):
        found.append({'kind': 'errors', 'text': f'{now["errors"]} errors, where there had been none', 'value': now['errors'], 'usual': 0})
    if now['drops'] > 0 and not any(p['drops'] for p in past):
        found.append({'kind': 'drops', 'text': f'{now["drops"]} packets dropped, where there had been none', 'value': now['drops'], 'usual': 0})
    return found


def stats(conn: Conn, host: str | None = None) -> list[dict]:
    """Per interface: the recent series, and whatever stands out in it."""
    where = 'WHERE host = :h ' if host else ''
    pairs = conn.all(f'SELECT DISTINCT host, iface FROM traffic_samples {where}ORDER BY host, iface', {'h': host} if host else {})
    out = []
    for h, iface in pairs:
        rows = conn.all('SELECT at, rx_bytes, tx_bytes, rx_drop, tx_drop, rx_error, tx_error FROM traffic_samples WHERE host = :h AND iface = :i ORDER BY at DESC LIMIT :l', {'h': h, 'i': iface, 'l': WINDOW})
        series = rates([tuple(r) for r in reversed(rows)])
        out.append({'host': h, 'iface': iface, 'series': series[-96:], 'latest': series[-1] if series else None, 'anomalies': judge(series)})
    return out


def anomalies(conn: Conn) -> list[dict]:
    return [{'host': s['host'], 'iface': s['iface'], **a} for s in stats(conn) for a in s['anomalies']]
