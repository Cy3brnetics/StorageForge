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

No wider action exists yet: wait—see WIDER below: the shadow-copy tripwire and the share freeze (sections 11.4 and 9) go
through `wider` (`tripwire_drop` and `freeze_share`). Every call here, done, held or refused, is a row of agent_actions.
"""
from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass

from .db import Conn

# Protective actions a report may cause by itself, against its sender only. Each value says what it does, for the record.
SELF = {'wipe-self': 'the agent said it found tampering in its own container and wiped itself: its key is revoked here and its container stopped over SSH'}
# Actions that reach past the reporter and require an independent second witness (or a person).
WIDER = {
    'shadow-copy-tripwire': 'drop the reporting client\'s pinned address from shares after a shadow-copy tripwire event',
    'freeze-share': 'freeze a share after independent corroboration',
    'drop-client': 'drop a client from shares',
}
# Who may witness a wider action: sources independent of every agent.
WITNESS_SOURCES = ('scan', 'decoy', 'sentinel')
WITNESS_SECS = 900
HELD_SECS = 86400

_VSS_PATTERNS = (
    ('vssadmin delete shadows', re.compile(r'\bvssadmin(?:\.exe)?\b.*\bdelete\b.*\bshadows\b', re.I)),
    ('wmic shadowcopy delete', re.compile(r'\bwmic(?:\.exe)?\b.*\bshadowcopy\b.*\bdelete\b', re.I)),
    ('PowerShell Win32_ShadowCopy removal', re.compile(r'\bwin32_shadowcopy\b.*\b(?:delete|remove-ciminstance|remove-wmiobject)\b|\b(?:remove-ciminstance|remove-wmiobject)\b.*\bwin32_shadowcopy\b', re.I)),
    ('wbadmin delete catalog', re.compile(r'\bwbadmin(?:\.exe)?\b.*\bdelete\b.*\b(?:catalog|systemstatebackup)\b', re.I)),
    ('bcdedit recoveryenabled no', re.compile(r'\bbcdedit(?:\.exe)?\b.*\brecoveryenabled\b.*\b(?:no|off|0)\b', re.I)),
)


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


def detect_shadow_copy_tamper(body: dict) -> str | None:
    """Matches Windows shadow-copy deletion commands or vanished shadow copies in a tripwire reading."""
    if not isinstance(body, dict):
        return None
    cmd = ' '.join(str(body.get('command') or '').split())
    if cmd:
        for label, pat in _VSS_PATTERNS:
            if pat.search(cmd[:8192]):
                return label
    before, after = body.get('before'), body.get('after')
    if body.get('reason') == 'shadows_vanished' or (
        isinstance(before, int) and isinstance(after, int) and not isinstance(before, bool) and not isinstance(after, bool) and 0 <= after < before
    ):
        return 'shadow copies vanished'
    return None


def pinned_client_address(conn: Conn, reporter: str) -> str | None:
    """The address pinned for `reporter` at enrollment (hosts.ssh_host), never an address named inside an agent report."""
    if not reporter:
        return None
    addr = conn.scalar('SELECT ssh_host FROM hosts WHERE lower(hostname) = lower(:h)', {'h': reporter})
    return str(addr).strip() if isinstance(addr, str) and str(addr).strip() else None


def _names(text: str, target: str) -> bool:
    """Whether `target` is in the text as a whole address or name, so 10.0.0.1 is not found inside 10.0.0.11."""
    return bool(target) and re.search(r'(?<![\w.:-])' + re.escape(target) + r'(?![\w-]|\.\w)', text) is not None


def recent_witnesses(conn: Conn, reporter: str, target: str, now: float | None = None) -> list[Witness]:
    """Independent witnesses already recorded near `now` for `target` (scans, non-agent sentinels, or tripped decoys)."""
    now = float(time.time() if now is None else now)
    cutoff = int(now) - WITNESS_SECS
    out: list[Witness] = []
    rows = conn.all("""SELECT host, kind, occurred_at, via, detail FROM security_events
                       WHERE occurred_at >= :t AND via != 'agent' AND kind IN ('canary_tripped', 'canary_source', 'brake_ran')
                       ORDER BY occurred_at DESC LIMIT 200""", {'t': cutoff})
    for ev_host, _kind, occurred_at, via, detail in rows:
        src = 'sentinel' if via == 'sentinel' else 'scan' if via in ('scan', 'measure') else None
        if not src:
            continue
        detail_str = str(detail or '')
        if ev_host == target or _names(detail_str, target):
            out.append(Witness(source=src, host=ev_host, target=target, at=float(occurred_at or now), via=via))
    canaries = conn.all("""SELECT host, path, tripped_at FROM security_canaries
                           WHERE status = 'tripped' AND tripped_at >= :t""", {'t': cutoff})
    for chost, cpath, cat in canaries:
        if target in (chost, cpath, f'share:{cpath}'):
            has_agent_only = conn.scalar("""SELECT 1 FROM security_events WHERE host = :h AND kind = 'canary_tripped'
                                            AND occurred_at = :at AND via = 'agent' LIMIT 1""", {'h': chost, 'at': cat})
            has_indep = conn.scalar("""SELECT 1 FROM security_events WHERE host = :h AND kind = 'canary_tripped'
                                       AND occurred_at = :at AND via != 'agent' LIMIT 1""", {'h': chost, 'at': cat})
            if has_indep or not has_agent_only:
                out.append(Witness(source='decoy', host=chost, target=target, at=float(cat or now), via='decoy'))
    return out


def _named_claims(body: dict | None) -> dict | None:
    if not isinstance(body, dict):
        return None
    keep = {k: str(body[k])[:300] for k in ('host', 'hostname', 'address', 'client', 'ip', 'command', 'pid', 'process', 'reason', 'before', 'after')
            if body.get(k) is not None}
    return keep or None


def tripwire_drop(conn: Conn, reporter: str, fingerprint: str | None, body: dict,
                  witnesses: list[Witness] | None = None, perform=None, now: float | None = None) -> dict:
    """Shadow-copy tripwire action (sections 11.2 & 11.4): drops ONLY the address pinned for `reporter` at enrollment,
    never an address named inside `body`, and executes only when an independent second witness agrees."""
    reason = detect_shadow_copy_tamper(body)
    if not reason:
        raise Refused('no shadow-copy tampering indicator matched')
    named = _named_claims(body)
    target = pinned_client_address(conn, reporter)
    if not target:
        _record(conn, reporter, fingerprint, 'shadow-copy-tripwire', '', 'refused', named, detail=f'no pinned enrollment address for {reporter}')
        raise Refused(f'no pinned enrollment address is recorded for {reporter}')
    wlist = recent_witnesses(conn, reporter, target, now) if witnesses is None else witnesses
    outcome = wider(conn, reporter, fingerprint, 'shadow-copy-tripwire', target, wlist, perform or (lambda _target: None), named=named, now=now)
    return {'outcome': outcome, 'target': target, 'reason': reason, 'named': named}


def freeze_share(conn: Conn, reporter: str, fingerprint: str | None, share: str,
                 witnesses: list[Witness] | None = None, perform=None, named=None, now: float | None = None) -> dict:
    """Freezes `share` when requested by an agent, gated through `wider` (independent second witness required)."""
    target = str(share or '').strip()
    if not target or len(target) > 500:
        raise Refused('freeze-share requires a share target')
    wlist = recent_witnesses(conn, reporter, target, now) if witnesses is None else witnesses
    outcome = wider(conn, reporter, fingerprint, 'freeze-share', target, wlist, perform or (lambda _target: None), named=named, now=now)
    return {'outcome': outcome, 'target': target}
