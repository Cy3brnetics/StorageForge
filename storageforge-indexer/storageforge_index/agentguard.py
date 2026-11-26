"""Wipe and stop (roadmap section 11.3; docs/agent.md): an agent whose container holds anything its manifest does not account for loses
its access and is stopped.

    check(db, host)            the check from outside, over SSH: storageforge-agentctl compares the running container with the
                               manifest and the agent's folders with what it keeps (agent/src/outside.rs). Any finding wipes it.
    wipe(db, host, why)        the key revoked here first, which nothing on the host can undo; then over SSH the container stopped
                               and left stopped, whatever its restart policy, and its key and plugin files deleted there; and a
                               notification that cannot be ignored. Only an admin enrolls an agent there again (agent.privilege and a
                               fresh password), and the audit log records it.
    tick(db)                   on a timer, from the web app's background thread: every running agent is checked every CHECK_SECS,
                               and again after each scan of its host
    take_reports(db)           an agent that found tampering in its own container wipes itself and says so in its last record; that
                               report goes through agentaction.on_self, so that it acts on the agent that sent it and nobody else

A check that cannot run (the host unreachable, SSH refused) wipes nothing: not being able to look is not a finding. It is recorded,
and after UNCHECKED_SECS without a check that ran it is a notification.
"""
from __future__ import annotations

import json
import time

from . import agentaction, deploy, sfagent
from .db import epoch
from .db import Database

CHECK_SECS = 900
UNCHECKED_SECS = 3600
CHECKS_PER_TICK = 4
SYSTEM = 'storageforge'


def _store_check(conn, name: str, result: dict):
    now = int(time.time())
    if result.get('ok'):
        result['last_ok'] = now
    else:
        # A failed check keeps the time of the last one that ran, so that one failure is not "unchecked": agentwatch counts from it.
        before = conn.all('SELECT checked_at, check_json FROM agents WHERE host = :h', {'h': name})
        try:
            old = json.loads(before[0][1] or '{}') if before else {}
        except ValueError:
            old = {}
        old = old if isinstance(old, dict) else {}
        last_ok = old.get('last_ok') or (before[0][0] if before and old.get('ok') else None)
        if last_ok:
            result['last_ok'] = int(last_ok)
    conn.execute('UPDATE agents SET checked_at = :t, check_json = :j WHERE host = :h',
                 {'t': now, 'j': json.dumps(result, separators=(',', ':'))[:8000], 'h': name})


def _words(items, most: int = 50, chars: int = 300) -> list[str]:
    return [str(x)[:chars] for x in items[:most]] if isinstance(items, list) else []


def check(db: Database, host: str, actor: str = SYSTEM) -> dict:
    """The check from outside for one host's agent. Returns what it found; wipes the agent when it found anything."""
    conn = db.connect()
    try:
        name = deploy.canonical(conn, host)
        row = sfagent.get(conn, name)
        if not row or not row['fingerprint'] or row['state'] not in ('running', 'stopped'):
            return {'host': name, 'checked': False, 'why': 'no agent is enrolled there'}
        try:
            got = sfagent.call(db, name, 'check', actor=actor, timeout=180)
        except sfagent.AgentError as exc:
            result = {'ok': False, 'error': str(exc)[:500]}
            _store_check(conn, name, result)
            return {'host': name, 'checked': False, 'why': result['error']}
        findings = _words(got.get('findings'))
        result = {'ok': True, 'clean': not findings, 'findings': findings, 'checked': _words(got.get('checked'), 20, 80),
                  'waiting': _words(got.get('waiting'), 20), 'running': got.get('running') is True}
        _store_check(conn, name, result)
    finally:
        conn.close()
    if findings:
        wiped = wipe(db, name, findings, actor=actor, source='check')
        return {'host': name, 'checked': True, 'clean': False, 'findings': findings, 'wiped': wiped}
    return {'host': name, 'checked': True, 'clean': True, 'findings': [], 'waiting': result['waiting'], 'running': result['running']}


def wipe(db: Database, host: str, why: list[str], actor: str = SYSTEM, source: str = 'check') -> dict:
    """Ends a host's agent's access. The key is revoked here before anything is asked of the host: the receiver drops the key from
    its pinned list within seconds and ends its session, and nothing on the host can put it back."""
    conn = db.connect()
    try:
        name = deploy.canonical(conn, host)
        row = sfagent.get(conn, name)
        if not row or not row['fingerprint']:
            return {'host': name, 'wiped': False, 'why': 'no agent is enrolled there'}
        if row['state'] == 'wiped':
            return {'host': name, 'wiped': True, 'already': True}
        fp = row['fingerprint']
        reasons = [str(w)[:300] for w in why][:20] or ['no reason was given']
        sfagent._save(conn, name, actor, state='wiped', public_key=None, detail=('wiped: ' + '; '.join(reasons))[:1900])
        conn.execute('UPDATE agents SET wiped_at = :t WHERE host = :h', {'t': int(time.time()), 'h': name})
        conn.execute('DELETE FROM agent_deliveries WHERE host = :h', {'h': name})
        sfagent._audit(db, conn, actor, 'agent.wipe', 'ok', name, fp, {'why': reasons, 'source': source})
        problems = []
        try:
            got = sfagent.call(db, name, 'wipe', actor=actor, timeout=300, reason='; '.join(reasons)[:500])
            if got.get('stopped') is not True:
                problems.append('no container of the agent was recorded on the host to stop')
        except sfagent.AgentError as exc:
            problems.append(f'over SSH: {exc}'[:500])
        if problems:
            sfagent._save(conn, name, actor, detail=(('wiped: ' + '; '.join(reasons))[:1400] + ' | on the host: ' + '; '.join(problems))[:1900])
        return {'host': name, 'wiped': True, 'why': reasons, 'problems': problems}
    finally:
        conn.close()


def due(conn, now: float | None = None) -> list[str]:
    """Running agents whose last check is older than CHECK_SECS, or older than their host's last scan."""
    now = int(now or time.time())
    rows = conn.all("""SELECT a.host, a.checked_at, h.last_scanned_at FROM agents a LEFT JOIN hosts h ON h.hostname = a.host
                       WHERE a.enabled = 1 AND a.state = 'running' AND a.fingerprint IS NOT NULL ORDER BY a.checked_at IS NOT NULL, a.checked_at""")
    return [host for host, checked, scanned in rows if checked is None or now - checked >= CHECK_SECS or (scanned and epoch(scanned) > checked)]


def tick(db: Database) -> int:
    """Checks the agents that are due, a few at a time. Returns how many were checked."""
    conn = db.connect()
    try:
        hosts = due(conn)[:CHECKS_PER_TICK]
    finally:
        conn.close()
    for host in hosts:
        check(db, host)
    return len(hosts)


def take_reports(db: Database) -> int:
    """Agents' last words: a record under the name `agent`, kind `wipe`, from an agent that found tampering in its own container and
    wiped itself. It acts on the agent whose key sent it (the host the receiver stored it under), through agentaction.on_self, and is
    taken only from the agent pinned for that host now. Returns how many reports were taken."""
    conn = db.connect()
    taken = 0
    try:
        rows = conn.all("""SELECT record_id, host, fingerprint, body_json FROM agent_records WHERE plugin = 'agent' AND kind = 'wipe'
                           ORDER BY record_id LIMIT 50""")
        for record_id, host, fp, body_json in rows:
            try:
                body = json.loads(body_json or '{}')
            except ValueError:
                body = {}
            reasons = _words(body.get('why') if isinstance(body, dict) else None, 20)
            row = sfagent.get(conn, host)
            if row and row['fingerprint'] == fp and row['state'] in ('running', 'stopped'):
                agentaction.on_self(conn, host, fp, 'wipe-self', lambda h: wipe(db, h, ['the agent wiped itself: ' + '; '.join(reasons or ['it gave no reason'])], source='agent'),
                                    named=body if isinstance(body, dict) else None, detail='the agent said: ' + '; '.join(reasons)[:600])
                taken += 1
            conn.execute('DELETE FROM agent_records WHERE record_id = :r', {'r': record_id})
    finally:
        conn.close()
    return taken
