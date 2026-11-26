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
        agent-ssh-down:HOST         the agent's health plugin says nothing listens on the host's SSH port: the agent still reports while
                                    SSH is down (roadmap 11.2, "either one fails alone")
        log-gap:HOST                numbers missing from the journal lines the agent pushed: lines deleted on the host, or never sent

An agent with the heartbeat plugin is silent after BEAT_SILENT_SECS rather than SILENT_SECS, and agentingest wakes the notification
center the moment one goes silent.
"""
from __future__ import annotations

import json
import time

from . import agentaction
from .db import Conn

SILENT_SECS = 300            # five beats missed
BEAT_SILENT_SECS = 30        # three beats of the heartbeat plugin missed
HEALTH_FRESH_SECS = 300      # a health reading older than this says nothing about now
GAP_SECS = 86400
RECENT_SECS = 86400
LABEL = 'reported by agent'      # the one definition: agentdisks, agentfiles, agentscan and agentmonitor take it from here


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


def plugins_by_host(conn: Conn, host: str | None = None) -> dict:
    """{host: the plugins its delivered manifest names, in the manifest's order}, for every host with a manifest or for one. A manifest
    that is not JSON, or not the object with a list of plugins that a manifest is, names none: one host's bad row costs no other host
    its alerts."""
    out = {}
    rows = conn.all('SELECT host, manifest FROM agent_deliveries') if host is None else conn.all('SELECT host, manifest FROM agent_deliveries WHERE host = :h', {'h': host})
    for h, manifest in rows:
        m = _loads(manifest)
        plugins = m.get('plugins') if isinstance(m, dict) else None
        out[h] = [str(e.get('name')) for e in plugins if isinstance(e, dict)] if isinstance(plugins, list) else []
    return out


def _with_plugin(conn: Conn, name: str) -> set:
    """The hosts whose delivered manifest names the plugin."""
    return {host for host, names in plugins_by_host(conn).items() if name in names}


def silent_beats(conn: Conn, now: float | None = None) -> list[str]:
    """Running agents with the heartbeat plugin that were heard from once and not for BEAT_SILENT_SECS."""
    now = int(now or time.time())
    beating = _with_plugin(conn, 'heartbeat')
    rows = conn.all("""SELECT a.host, p.last_seen FROM agents a JOIN agent_peers p ON p.fingerprint = a.fingerprint
                       WHERE a.enabled = 1 AND a.state = 'running' AND a.endpoint IS NOT NULL""")
    return sorted(host for host, last_seen in rows if host in beating and last_seen and now - last_seen > BEAT_SILENT_SECS)


def ssh_said(conn: Conn, host: str, now: float | None = None) -> dict | None:
    """What the host's agent last said of SSH, from its health plugin, if it said it recently: {'process', 'listening', 'read'}."""
    now = int(now or time.time())
    rows = conn.all("""SELECT kind, body_json FROM agent_records WHERE host = :h AND plugin = 'health' AND kind IN ('health', 'ssh') AND received_at >= :t
                       ORDER BY record_id DESC LIMIT 1""", {'h': host, 't': now - HEALTH_FRESH_SECS})
    if not rows:
        return None
    body = _loads(rows[0][1]) or {}
    said = body.get('ssh') if rows[0][0] == 'health' else body
    return said if isinstance(said, dict) and isinstance(said.get('listening'), list) else None


def problems(conn: Conn, now: float | None = None) -> dict:
    now = int(now or time.time())
    out = agentaction.problems(conn, now)
    from . import agentplugins
    out.update(agentplugins.problems(conn, now))     # the disks, files, scan and sentinel plugins
    for host in silent_beats(conn, now):
        out[f'agent-silent:{host}'] = ('agent-silent', host, f'The agent on {host} went silent',
                                       f'its heartbeat stopped more than {BEAT_SILENT_SECS} seconds ago: stopped, wiped, cut off, or hiding what it sees. Scans over SSH go on', 'warn')
    for host, port in conn.all("""SELECT a.host, h.ssh_port FROM agents a LEFT JOIN hosts h ON h.hostname = a.host
                                  WHERE a.enabled = 1 AND a.state = 'running' AND a.fingerprint IS NOT NULL"""):
        said = ssh_said(conn, host, now)
        port = int(port or 22)
        if said and said.get('read') is not False and port not in said['listening']:
            why = f'nothing listens on port {port}' + ('' if said.get('process') else ', and no sshd process runs')
            out[f'agent-ssh-down:{host}'] = ('agent-ssh-down', host, f'The agent on {host} says SSH is down',
                                             f'{LABEL}: {why}. Scans, deploys and the console go over SSH and will fail until it is back; the agent goes on reporting', 'warn')
    for host, gaps, gap_at in conn.all('SELECT host, seq_gaps, seq_gap_at FROM host_log_status WHERE seq_gap_at >= :t', {'t': now - GAP_SECS}):
        out[f'log-gap:{host}'] = ('log-gap', host, f'Lines are missing from the journal of {host}',
                                  f'{int(gaps or 0)} numbered line(s) of the journal its agent pushed never came, the last on '
                                  f'{time.strftime("%Y-%m-%d %H:%M", time.localtime(gap_at))}: deleted on the host, or lost on the way', 'warn')
    from .agentguard import UNCHECKED_SECS
    for host, detail, wiped_at in conn.all("SELECT host, detail, wiped_at FROM agents WHERE enabled = 1 AND state = 'wiped'"):
        when = time.strftime('%Y-%m-%d %H:%M', time.localtime(wiped_at)) if wiped_at else 'at some point'
        out[f'security-agent-wiped:{host}'] = ('security-agent-wiped', host, f'The agent on {host} was wiped',
                                               f'{when}: {str(detail or "")[:600]}. Its key is revoked and its container stopped. Scans over SSH go on; '
                                               'look at the host, then enroll an agent again (an admin) or remove it', 'crit')
    for host, checked_at, check_json, enrolled_at in conn.all("""SELECT host, checked_at, check_json, enrolled_at FROM agents
                                                                 WHERE enabled = 1 AND state = 'running' AND fingerprint IS NOT NULL"""):
        last = _loads(check_json) or {}
        if checked_at is None:
            continue
        # One check that could not run is not news: it is when the last one that did run, or the enrolment, is older than UNCHECKED_SECS,
        # or when nothing has tried at all for that long.
        last_ok = last.get('last_ok') or (checked_at if last.get('ok') else None)
        failing = not last.get('ok') and now - (last_ok or enrolled_at or now) > UNCHECKED_SECS
        if failing or now - checked_at > UNCHECKED_SECS:
            said = f'the last try said: {str(last.get("error") or "")[:300]}' if not last.get('ok') else f'no check has run since {time.strftime("%Y-%m-%d %H:%M", time.localtime(checked_at))}'
            out[f'agent-unchecked:{host}'] = ('agent-unchecked', host, f'The agent on {host} could not be checked from outside', said, 'warn')
    rows = conn.all("""SELECT a.host, a.fingerprint, a.manifest_sha, a.updated_at, a.endpoint, h.machine_id, p.last_seen, p.claims_json
                       FROM agents a LEFT JOIN hosts h ON h.hostname = a.host LEFT JOIN agent_peers p ON p.fingerprint = a.fingerprint
                       WHERE a.enabled = 1 AND a.state = 'running' AND a.fingerprint IS NOT NULL""")
    for host, fp, manifest_sha, updated_at, endpoint, machine, last_seen, claims_json in rows:
        if endpoint and f'agent-silent:{host}' not in out:
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
