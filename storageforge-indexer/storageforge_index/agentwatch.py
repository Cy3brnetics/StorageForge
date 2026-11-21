"""What the web app makes of what agents said (roadmap section 11.2; the receiver that stored it is agentreceiver.py).

Everything here reads the receiver's tables and treats every row as an agent's claim: each reading goes out labelled *reported by
agent*, never mixed with what a scan over SSH measured, and where both say something about the same thing they are compared and a
disagreement is a notification. The receiver cannot act on anything; this module only reads and raises notifications, which reach a
host through a person.

    records(conn, host)     what the host's agent reported, newest first, each labelled as its claim
    peer(conn, host)        the receiver's own count for the host's agent: batches, gaps, repeats, refusals, when it was last heard
    problems(conn)          for the notification center (alerts.problems):
        agent-silent:HOST           an enrolled agent with a tunnel has not been heard from: stopped, wiped, cut off, or hiding
        agent-gap:HOST              batches missing (deleted on the way, or the agent's own count lost) or played again
        security-agent-claim:HOST   the agent says it is on another machine than SSH reads: a lie, or another machine with its key
        agent-manifest:HOST         the agent says it runs another manifest than the controller last gave its host
        agent-refused:HOST          batches refused for their form or for the agent's quota
        security-agent-wiped:HOST   the agent was wiped (roadmap 11.3): a check from outside found something, or it found tampering
                                    in its own container. Its key is revoked. Cannot be ignored; leaves when an admin enrolls an
                                    agent there again or removes it
        agent-unchecked:HOST        the check from outside has not run for an hour: the host could not be reached over SSH
        agent-held:HOST             an agent asked for an action on others, held for a person (agentaction.py)
"""
from __future__ import annotations

import json
import time

from . import agentaction
from .db import Conn

SILENT_SECS = 300            # five beats missed
RECENT_SECS = 86400
LABEL = 'reported by agent'


def _loads(text):
    try:
        return json.loads(text) if text else None
    except ValueError:
        return None


def records(conn: Conn, host: str, plugin: str | None = None, limit: int = 100) -> list[dict]:
    q = 'SELECT record_id, plugin, kind, claimed_at, received_at, body_json, counter, seq FROM agent_records WHERE host = :h'
    params = {'h': host, 'n': max(1, min(int(limit), 1000))}
    if plugin:
        q += ' AND plugin = :p'
        params['p'] = plugin
    rows = conn.all(q + ' ORDER BY record_id DESC LIMIT :n', params)
    return [{'id': r[0], 'plugin': r[1], 'kind': r[2], 'claimed_at': r[3], 'received_at': r[4], 'body': _loads(r[5]), 'counter': r[6], 'seq': r[7],
             'source': 'agent', 'label': LABEL} for r in rows]


PEER = ('fingerprint', 'last_counter', 'batches', 'records', 'gaps', 'lost', 'repeats', 'resent', 'malformed', 'over_quota', 'pruned', 'sessions',
        'first_seen', 'last_seen', 'last_address', 'version', 'claims_json')


def peer(conn: Conn, host: str) -> dict | None:
    fp = conn.scalar('SELECT fingerprint FROM agents WHERE host = :h', {'h': host})
    if not fp:
        return None
    rows = conn.all(f'SELECT {", ".join(PEER)} FROM agent_peers WHERE fingerprint = :f', {'f': fp})
    if not rows:
        return {'fingerprint': fp, 'heard': False, 'label': LABEL}
    d = dict(zip(PEER, rows[0]))
    d['claims'] = _loads(d.pop('claims_json'))
    return d | {'heard': True, 'label': LABEL}


def events(conn: Conn, host: str, since: int, kinds: tuple) -> dict:
    marks = ', '.join(f':k{i}' for i in range(len(kinds)))
    rows = conn.all(f'SELECT kind, sum(count) FROM agent_events WHERE host = :h AND at >= :t AND kind IN ({marks}) GROUP BY kind',
                    {'h': host, 't': since, **{f'k{i}': k for i, k in enumerate(kinds)}})
    return {k: int(n or 0) for k, n in rows}


def problems(conn: Conn, now: float | None = None) -> dict:
    now = int(now or time.time())
    out = agentaction.problems(conn, now)
    from .agentguard import UNCHECKED_SECS
    for host, detail, wiped_at in conn.all("SELECT host, detail, wiped_at FROM agents WHERE enabled = 1 AND state = 'wiped'"):
        when = time.strftime('%Y-%m-%d %H:%M', time.localtime(wiped_at)) if wiped_at else 'at some point'
        out[f'security-agent-wiped:{host}'] = ('security-agent-wiped', host, f'The agent on {host} was wiped',
                                               f'{when}: {str(detail or "")[:600]}. Its key is revoked and its container stopped. Scans over SSH go on; '
                                               'look at the host, then enroll an agent again (an admin) or remove it', 'crit')
    for host, checked_at, check_json, enrolled_at in conn.all("""SELECT host, checked_at, check_json, enrolled_at FROM agents
                                                                 WHERE enabled = 1 AND state = 'running' AND fingerprint IS NOT NULL"""):
        last = _loads(check_json) or {}
        since = checked_at if last.get('ok') else None
        if since is None and checked_at is not None and enrolled_at and now - enrolled_at > UNCHECKED_SECS:
            out[f'agent-unchecked:{host}'] = ('agent-unchecked', host, f'The agent on {host} could not be checked from outside',
                                              f'the last try said: {str(last.get("error") or "")[:300]}', 'warn')
    rows = conn.all("""SELECT a.host, a.fingerprint, a.manifest_sha, a.updated_at, a.endpoint, h.machine_id, p.last_seen, p.claims_json
                       FROM agents a LEFT JOIN hosts h ON h.hostname = a.host LEFT JOIN agent_peers p ON p.fingerprint = a.fingerprint
                       WHERE a.enabled = 1 AND a.state = 'running' AND a.fingerprint IS NOT NULL""")
    for host, fp, manifest_sha, updated_at, endpoint, machine, last_seen, claims_json in rows:
        if endpoint:
            if last_seen is None and now - (updated_at or now) > SILENT_SECS:
                out[f'agent-silent:{host}'] = ('agent-silent', host, f'The agent on {host} has not reported', 'it has a tunnel and has not opened a session since it was set up', 'warn')
            elif last_seen is not None and now - last_seen > SILENT_SECS:
                out[f'agent-silent:{host}'] = ('agent-silent', host, f'The agent on {host} went silent',
                                               f'last heard {time.strftime("%Y-%m-%d %H:%M", time.localtime(last_seen))}: stopped, wiped, cut off, or hiding what it sees. Scans over SSH go on', 'warn')
        e = events(conn, host, now - RECENT_SECS, ('gap', 'repeat', 'malformed', 'over-quota', 'lost'))
        if e.get('gap') or e.get('repeat'):
            out[f'agent-gap:{host}'] = ('agent-gap', host, f'Batches from the agent on {host} are missing or came again',
                                        f'in the last day: {e.get("gap", 0)} missing, {e.get("repeat", 0)} played again with other bytes', 'warn')
        if e.get('malformed') or e.get('over-quota'):
            out[f'agent-refused:{host}'] = ('agent-refused', host, f'Batches from the agent on {host} were refused',
                                            f'in the last day: {e.get("malformed", 0)} malformed, {e.get("over-quota", 0)} over its quota', 'info')
        said = (_loads(claims_json) or {}) if claims_json else {}
        claimed_machine = ((said.get('claims') or {}) if isinstance(said.get('claims'), dict) else {}).get('machine')
        if claimed_machine and machine and claimed_machine != machine:
            out[f'security-agent-claim:{host}'] = ('security-agent-claim', host, f'The agent on {host} says it is on another machine',
                                                   'its machine id is not the one SSH reads on this host: the agent is lying, or its key is on another machine', 'warn')
        claimed_manifest = (said.get('manifest') or {}).get('sha256') if isinstance(said.get('manifest'), dict) else None
        if claimed_manifest and manifest_sha and claimed_manifest != manifest_sha:
            out[f'agent-manifest:{host}'] = ('agent-manifest', host, f'The agent on {host} says it runs another manifest',
                                             'not the one the controller last gave this host: an old one is in force there, or the agent is lying', 'warn')
    return out
