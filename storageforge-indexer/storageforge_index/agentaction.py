"""What an agent's report may cause (roadmap section 11.2, "Its actions affect only itself" and "Anything wider needs a second
witness"; docs/agent.md).

Everything an agent says is a claim. Most of it goes to a person, through the notification center, and causes nothing. This module
is the one road by which a report causes an action, and it holds two rules:

- **A report acts by itself only on the agent that sent it.** `on_self` takes the reporter as the receiver knew it, from the key the
  session was opened with (the host column the receiver wrote), and the action is carried out against that host and nothing else.
  Whatever the message names (a host, an address, a machine id, a client) is kept as a claim beside the action and never chosen as
  its target: an agent can accuse only itself. Only protective actions are in SELF: today one, `wipe-self`, an agent that says it
  found tampering in its own container and wiped itself, whose key the controller then revokes and whose container it stops over
  SSH. Nothing a lying agent gains from that it could not have by stopping.
- **Anything wider needs an independent second witness, or a person.** `wider` takes an action that would touch another host or
  client (freezing a share, dropping a client from every share), the reporter, and the witnesses that agree. A witness counts only
  when it is independent of the reporter: a scan over SSH, a decoy hit, or the share host's own sentinel, about the same target,
  recently. An agent never witnesses for itself, and another agent's report is not a witness either. Without one the action is not
  taken: it is held, and a person is told (agentwatch.problems, `agent-held:HOST`).

No wider action exists yet: the shadow-copy tripwire and the share freeze (sections 11.4 and 9) are to go through `wider` when they
are built. Every call here, done, held or refused, is a row of agent_actions.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass

from .db import Conn

# Protective actions a report may cause by itself, against its sender only. Each value says what it does, for the record.
SELF = {'wipe-self': 'the agent said it found tampering in its own container and wiped itself: its key is revoked here and its container stopped over SSH'}
# Who may witness a wider action: sources independent of every agent.
WITNESS_SOURCES = ('scan', 'decoy', 'sentinel')
WITNESS_SECS = 900
HELD_SECS = 86400


class Refused(Exception):
    """An action no report may cause."""


@dataclass(frozen=True)
class Witness:
    source: str           # 'scan' (measured over SSH), 'decoy' (a decoy file was touched), 'sentinel' (the share host's own)
    host: str             # whose scan, decoy or sentinel
    target: str           # what it saw: the same target the action is about
    at: float             # when
    via: str = ''         # how it reached the controller: 'agent' when an agent carried it (the sentinel plugin), which makes it an agent's word


def _record(conn: Conn, host: str, fp: str | None, action: str, target: str, outcome: str, named=None, witnesses=None, detail: str = ''):
    conn.execute("""INSERT INTO agent_actions (at, host, fingerprint, action, target, named_json, witnesses_json, outcome, detail)
                    VALUES (:t, :h, :f, :a, :g, :n, :w, :o, :d)""",
                 {'t': int(time.time()), 'h': host, 'f': fp, 'a': action, 'g': target, 'n': json.dumps(named)[:2000] if named is not None else None,
                  'w': json.dumps([w.__dict__ for w in witnesses])[:4000] if witnesses else None, 'o': outcome, 'd': str(detail)[:1000]})


def on_self(conn: Conn, reporter: str, fingerprint: str | None, action: str, perform, named=None, detail: str = '') -> str:
    """Carries out a protective action a report caused, against the reporter and nobody else. `reporter` is the host the receiver
    stored the record under, worked out from the key; `named` is whatever the message itself names, kept as a claim. `perform(host)`
    does it. Returns 'done', or 'failed' when perform raised (the row says why)."""
    if action not in SELF:
        _record(conn, reporter, fingerprint, action, reporter, 'refused', named, detail=f'{action} is not an action a report may cause by itself')
        raise Refused(f'{action} is not an action an agent\'s report may cause by itself')
    if not reporter:
        raise Refused('a report with no sender known from its key causes nothing')
    accused = _named_host(named)
    if accused and accused != reporter:
        # it named someone else: kept as its claim, and the action still falls on the reporter alone
        detail = (detail + '; ' if detail else '') + f'the report named {accused[:100]}, which is not taken: an agent can accuse only itself'
    try:
        perform(reporter)
    except Exception as exc:
        _record(conn, reporter, fingerprint, action, reporter, 'failed', named, detail=f'{detail}; {exc}'[:1000])
        return 'failed'
    _record(conn, reporter, fingerprint, action, reporter, 'done', named, detail=detail or SELF[action])
    return 'done'


def _named_host(named) -> str | None:
    if isinstance(named, dict):
        for k in ('host', 'hostname', 'target', 'address', 'client'):
            if isinstance(named.get(k), str) and named[k]:
                return named[k]
    return named if isinstance(named, str) and named else None


def independent(reporter: str, target: str, witnesses: list[Witness], now: float | None = None) -> list[Witness]:
    """The witnesses that count for an action about `target` asked for by the agent of `reporter`: of a kind no agent is, about the
    same target, recent, and not the reporter's own (a sentinel on the reporter's host is the reporter's word by another road)."""
    now = time.time() if now is None else now
    return [w for w in witnesses
            if w.source in WITNESS_SOURCES and w.target == target and now - WITNESS_SECS <= w.at <= now + 60
            and not (w.source == 'sentinel' and w.host == reporter)
            # a sentinel's event an agent carried (the sentinel plugin) is that agent's word, and an agent is never a witness
            and w.via != 'agent']


def wider(conn: Conn, reporter: str, fingerprint: str | None, action: str, target: str, witnesses: list[Witness], perform,
          named=None, now: float | None = None) -> str:
    """An action that reaches past the reporter, asked for by its report. Taken only when an independent witness agrees
    (`independent`); otherwise held for a person. Returns 'done', 'held' or 'failed'."""
    if action in SELF:
        raise Refused(f'{action} is an action on the reporter itself: on_self takes it')
    agreed = independent(reporter, target, witnesses, now)
    if not agreed:
        _record(conn, reporter, fingerprint, action, target, 'held', named, witnesses,
                'no independent witness agreed: a scan over SSH, a decoy hit or the share host\'s own sentinel. A person decides')
        return 'held'
    try:
        perform(target)
    except Exception as exc:
        _record(conn, reporter, fingerprint, action, target, 'failed', named, agreed, str(exc))
        return 'failed'
    _record(conn, reporter, fingerprint, action, target, 'done', named, agreed, f'{len(agreed)} independent witness(es) agreed')
    return 'done'


def recent(conn: Conn, host: str | None = None, limit: int = 50) -> list[dict]:
    q = 'SELECT action_id, at, host, fingerprint, action, target, named_json, witnesses_json, outcome, detail FROM agent_actions'
    p: dict = {'n': max(1, min(int(limit), 500))}
    if host:
        q += ' WHERE host = :h'
        p['h'] = host
    rows = conn.all(q + ' ORDER BY action_id DESC LIMIT :n', p)
    keys = ('id', 'at', 'host', 'fingerprint', 'action', 'target', 'named', 'witnesses', 'outcome', 'detail')
    out = []
    for r in rows:
        d = dict(zip(keys, r))
        for k in ('named', 'witnesses'):
            try:
                d[k] = json.loads(d[k]) if d[k] else None
            except ValueError:
                d[k] = None
        out.append(d)
    return out


def problems(conn: Conn, now: float | None = None) -> dict:
    """For the notification center: wider actions held for a person in the last day, one notification per reporting host."""
    now = int(now or time.time())
    out = {}
    for host, n, last in conn.all("""SELECT host, count(*), max(action) FROM agent_actions WHERE outcome = 'held' AND at >= :t GROUP BY host""",
                                  {'t': now - HELD_SECS}):
        out[f'agent-held:{host}'] = ('agent-held', host, f'The agent on {host} asked for an action on others',
                                     f'{n} request(s) in the last day ({last}), held because no independent witness agreed: look before acting', 'warn')
    return out
