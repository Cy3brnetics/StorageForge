"""The operator's own security policy, and the detection and containment built on it: waivers, custom compliance profiles, drift,
retention policies, evidence, identity anomalies, Falco, YARA, playbooks, dashboards, offline bundles, ban tiers and thresholds.

security.py's two rules hold here too. Every number comes from a measurement. A row means it happened: what acts on a host goes
through deploy.run, takes preview, report and apply, and is recorded only when the run on the host confirmed it. A policy here can
add a hold, drop a client or stage a plan. Nothing a host reports can release a hold, disarm anything or clear an alarm.

A waiver hides a finding from the count, with a reason, a name and an end date. It does not make the finding go away, and the page
still shows it. Nothing here certifies anything: an evidence file is a signed record of what was measured and done, for an auditor
to weigh. Only an auditor can attest.
"""
from __future__ import annotations

import fnmatch
import hashlib
import ipaddress
import json
import re
import shlex
import time
import uuid

from . import alerts, changes, deploy, secscripts as sx, security
from .db import Conn, loads
from .scriptkit import HELPERS, PACKAGES, need_line

NOW = lambda: int(time.time())  # noqa: E731
DRIFT = 'security.drift.'
THRESHOLDS = 'security.thresholds'
AVC_NOISE = 'security.avc_noise'
CONTEXT_MAP = 'security.context_map'
SCAN_FILTERS = 'security.scan_filters'
AIDE_WATCH = 'security.aide_watch'
BAN_TIERS = 'security.ban_tiers'
PLAYBOOK_CURSOR = 'security.playbook_cursor'
IDENTITY = 'security.identity.'
FALCO_RULES = 'security.falco_rules'
FREEZES = 'security.freezes'
READING_KEEP = 400
LATERAL = ('/etc/shadow', '/etc/gshadow', '/root/', '/etc/ssh/', '/etc/sudoers')
DEFAULT_BAN_TIERS = {'1': {'label': 'Probe or suspicious churn', 'minutes': 15}, '2': {'label': 'Decoy changed', 'minutes': 1440}, '3': {'label': 'Active encryption', 'minutes': 0}}
DEFAULT_SCAN_FILTERS = {'skip_over_mb': 500, 'skip_ext': ['.mkv', '.iso', '.tar', '.mp4', '.mov'], 'deep_ext': ['.exe', '.elf', '.sh', '.bat', '.ps1', '.docm', '.xlsm', '.zip', '.7z']}
PROFILE_PRESETS = {
    'tier-1-core-storage': {'base': 'cis-l2', 'label': 'Core storage appliance: strict', 'overrides': {'target_lynis': 85, 'min_worm_days': 14}},
    'tier-2-remote-backup': {'base': 'cis-l1', 'label': 'Remote backup node: smallest attack surface', 'overrides': {'target_lynis': 80, 'min_worm_days': 30, 'add': ['fence', 'worm']}},
    'tier-3-lab': {'base': 'cis-l1', 'label': 'Lab or development node: softened', 'overrides': {'target_lynis': 60, 'min_worm_days': 7, 'drop': ['aide']}},
}


# ── waivers ──────────────────────────────────────────────────────────
def list_waivers(conn: Conn, host: str | None = None, include_expired: bool = False) -> list[dict]:
    now = NOW()
    rows = conn.all('SELECT id, host, finding, reason, approver, expires_at, created_at FROM security_waivers ORDER BY created_at DESC')
    out = [{'id': r[0], 'host': r[1], 'finding': r[2], 'reason': r[3], 'approver': r[4], 'expires_at': r[5], 'created_at': r[6], 'expired': bool(r[5] and r[5] <= now)} for r in rows]
    if host:
        out = [w for w in out if w['host'] in ('*', host)]
    return out if include_expired else [w for w in out if not w['expired']]


def waived(conn: Conn, host: str) -> dict:
    return {w['finding']: w for w in list_waivers(conn, host)}


def save_waiver(conn: Conn, body: dict, actor: str) -> dict:
    host = '*' if body.get('host') == '*' else security.known_host(conn, body.get('host'))
    finding = str(body.get('finding') or '').strip()
    if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,60}', finding):
        raise ValueError('a waiver names a compliance check or a Lynis finding, such as sysctl or KRNL-6000')
    reason = security.clean_text(body.get('reason') or '', 500).strip()
    if len(reason) < 8:
        raise ValueError('a waiver needs a real reason: someone will ask')
    days = security._int(body.get('days'), 0)
    if days is None or not 1 <= days <= 730:
        raise ValueError('a waiver ends, in 1 to 730 days')
    now = NOW()
    conn.execute("""INSERT INTO security_waivers (host, finding, reason, approver, expires_at, created_at) VALUES (:h, :f, :r, :a, :e, :t)
                    ON CONFLICT (host, finding) DO UPDATE SET reason = excluded.reason, approver = excluded.approver, expires_at = excluded.expires_at, created_at = excluded.created_at""",
                 {'h': host, 'f': finding, 'r': reason, 'a': actor, 'e': now + days * 86400, 't': now})
    return {'ok': True, 'host': host, 'finding': finding, 'expires_at': now + days * 86400}


def delete_waiver(conn: Conn, waiver_id: int):
    conn.execute('DELETE FROM security_waivers WHERE id = :i', {'i': waiver_id})


# ── profiles: a standard, adjusted. What is ours is labelled as ours ─
def list_profiles(conn: Conn) -> list[dict]:
    return [{'id': r[0], 'name': r[1], 'base': r[2], 'overrides': loads(r[3]) or {}, 'updated_at': r[4]} for r in conn.all('SELECT id, name, base, overrides_json, updated_at FROM security_profiles ORDER BY name')]


def save_profile(conn: Conn, body: dict, actor: str) -> dict:
    name = str(body.get('name') or '').strip()
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9 ._-]{0,59}', name):
        raise ValueError('a profile needs a plain name')
    base = str(body.get('base') or '')
    if base not in security.STANDARDS:
        raise ValueError(f'no such standard: {base[:40]}')
    o = body.get('overrides') or {}
    clean = {}
    for key, lo, hi in (('target_lynis', 0, 100), ('min_worm_days', 0, 3650)):
        if o.get(key) not in (None, ''):
            v = security._int(o[key])
            if v is None or not lo <= v <= hi:
                raise ValueError(f'{key} is {lo} to {hi}')
            clean[key] = v
    for key in ('add', 'drop'):
        vals = [str(x) for x in o.get(key) or []]
        bad = [x for x in vals if x not in security.CHECKS]
        if bad:
            raise ValueError(f'no such check: {bad[0][:40]}')
        if vals:
            clean[key] = vals
    now = NOW()
    conn.execute("""INSERT INTO security_profiles (name, base, overrides_json, created_by, updated_at) VALUES (:n, :b, :o, :a, :t)
                    ON CONFLICT (name) DO UPDATE SET base = excluded.base, overrides_json = excluded.overrides_json, updated_at = excluded.updated_at""",
                 {'n': name, 'b': base, 'o': json.dumps(clean), 'a': actor, 't': now})
    return {'ok': True, 'name': name, 'id': f'custom:{name}'}


def delete_profile(conn: Conn, profile_id: int):
    conn.execute('DELETE FROM security_profiles WHERE id = :i', {'i': profile_id})


def std_for(conn: Conn, profile: str) -> dict:
    """A built-in standard, or a custom profile laid over one. Thresholds are StorageForge's suggestions either way: no standard sets them."""
    if profile in security.STANDARDS:
        return security.STANDARDS[profile]
    if profile.startswith('preset:') and profile[7:] in PROFILE_PRESETS:
        spec = PROFILE_PRESETS[profile[7:]]
        name, base, o = spec['label'], spec['base'], spec['overrides']
    elif profile.startswith('custom:'):
        rows = conn.all('SELECT base, overrides_json FROM security_profiles WHERE name = :n', {'n': profile[7:]})
        if not rows:
            raise ValueError(f'no such profile: {profile[:60]}')
        name, base, o = profile[7:], rows[0][0], loads(rows[0][1]) or {}
    else:
        raise ValueError(f'no such standard: {profile[:40]}')
    std = security.STANDARDS[base]
    controls = {k: v for k, v in std['controls'].items() if k not in (o.get('drop') or [])}
    for c in o.get('add') or []:
        controls.setdefault(c, f'added by {name}')
    return {'name': f'{name} (on {std["name"]})', 'target_lynis': o.get('target_lynis', std['target_lynis']), 'min_worm_days': o.get('min_worm_days', std['min_worm_days']), 'controls': controls, 'custom': True}


# ── readings over time, and drift ────────────────────────────────────
def record_reading(conn: Conn, host: str, kind: str, value, detail: dict | None = None, at: int | None = None):
    at = at or NOW()
    conn.execute("""INSERT INTO security_readings (host, kind, at, value, detail_json) VALUES (:h, :k, :t, :v, :d)
                    ON CONFLICT (host, kind, at) DO UPDATE SET value = excluded.value, detail_json = excluded.detail_json""",
                 {'h': host, 'k': kind, 't': at, 'v': value, 'd': json.dumps(detail or {})})
    conn.execute("""DELETE FROM security_readings WHERE host = :h AND kind = :k AND at NOT IN
                    (SELECT at FROM security_readings WHERE host = :h AND kind = :k ORDER BY at DESC LIMIT :n)""", {'h': host, 'k': kind, 'n': READING_KEEP})


def trend(conn: Conn, host: str, kind: str, limit: int = 60) -> list[dict]:
    rows = conn.all(f'SELECT at, value FROM security_readings WHERE lower(host) = lower(:h) AND kind = :k ORDER BY at DESC LIMIT {int(limit)}', {'h': host, 'k': kind})
    return [{'at': a, 'value': v} for a, v in reversed(rows)]


def after_measure(conn: Conn, host: str, data: dict, at: int):
    """Keeps what makes a trend, picks up what only a measurement carries, and notices a check that passed before and fails now."""
    ly = data.get('lynis') or {}
    if ly.get('hardening_index') is not None:
        record_reading(conn, host, 'lynis', ly['hardening_index'], at=ly.get('at') or at)
    ingest_falco(conn, host, data.get('falco_alerts') or [])
    profile = alerts.get_setting(conn, security.profile_key(host)) or 'cis-l1'
    try:
        status = security.compliance_status(conn, host, profile)
    except ValueError:
        return
    failing = sorted(c['id'] for c in status['checks'] if c['result'] == 'fail')
    record_reading(conn, host, 'compliance', status['score'], {'profile': profile, 'failing': failing}, at)
    was = alerts.get_setting(conn, DRIFT + host) or {}
    if was.get('profile') != profile:
        alerts.set_setting(conn, DRIFT + host, {'profile': profile, 'baseline': failing, 'new': [], 'at': at}, 'measure')
        return
    new = sorted(set(failing) - set(was.get('baseline') or []))
    healed = sorted(set(was.get('baseline') or []) - set(failing))
    alerts.set_setting(conn, DRIFT + host, {'profile': profile, 'baseline': sorted((set(was.get('baseline') or []) - set(healed))), 'new': new, 'at': at}, 'measure')


def drift_of(conn: Conn, host: str) -> dict:
    return alerts.get_setting(conn, DRIFT + host) or {'new': []}


def problems(conn: Conn) -> dict:
    out = {}
    for (name,) in conn.all('SELECT hostname FROM hosts'):
        d = drift_of(conn, name)
        if d.get('new'):
            labels = ', '.join(security.CHECKS.get(c, c) for c in d['new'])
            out[f'security-drift:{name}'] = ('security-drift', name, f'{name} has drifted from {d.get("profile")}', f'Passed before and fails now: {labels}. Re-converge staged a plan if you asked for one.', 'warn')
    for r in pending_runs(conn):
        out[f'security-playbook:{r["id"]}'] = ('security-playbook', r['host'], f'A playbook is waiting on {r["host"]}: {r["playbook"]}', f'It wants to: {", ".join(r["actions"])}. Confirm or dismiss it in Security.', 'crit')
    return out


# ── findings become plans ────────────────────────────────────────────
def stage_plan(conn: Conn, name: str, tasks: list[dict], actor: str) -> int:
    pid = conn.scalar('SELECT plan_id FROM change_plans WHERE lower(name) = lower(:n)', {'n': name})
    return changes.save_plan(conn, {'name': name, 'tasks': tasks}, actor, pid)


def lynis_tasks(host: str, m: dict) -> tuple[list[dict], list[dict]]:
    """(steps, what has no step). From what Lynis itself reported, so a finding with no safe mapping is listed and not guessed at."""
    from .steps_infra import SSHD_KEYS
    tasks, by_hand, seen = [], [], set()
    ly = m.get('lynis') or {}
    for f in (ly.get('warnings') or []) + (ly.get('suggestions') or []):
        fid, detail = f.get('id') or '', f.get('detail') or ''
        if fid == 'SSH-7408':
            k = re.match(r'([A-Za-z]+) \(set \S+ to (\S+?)\)', detail)
            if k and k[1] in SSHD_KEYS and k[1] not in seen:
                seen.add(k[1])
                tasks.append({'type': 'sshd-option', 'host': host, 'params': {'key': k[1], 'value': k[2].lower() if k[2].isalpha() else k[2], 'rollback': '10' if k[1] in ('AllowTcpForwarding', 'PermitRootLogin') else ''}, 'note': f'Lynis {fid}'})
                continue
        if fid == 'AUTH-9328' and 'umask' not in seen:
            seen.add('umask')
            tasks.append({'type': 'umask-set', 'host': host, 'params': {'value': '027'}, 'note': f'Lynis {fid}'})
            continue
        if fid == 'KRNL-6000':
            for k, want in sx.SYSCTLS.items():
                have = (m.get('sysctl') or {}).get(k)
                if have is not None and have != want and k not in seen:
                    seen.add(k)
                    tasks.append({'type': 'sysctl-set', 'host': host, 'params': {'key': k, 'value': want}, 'note': f'Lynis {fid}'})
            continue
        by_hand.append({'id': fid, 'text': f.get('text')})
    return tasks, by_hand


def stage_lynis(conn: Conn, body: dict, actor: str) -> dict:
    host = security.known_host(conn, body.get('host'))
    m = security.measurement(conn, host)
    if not m or not m.get('lynis'):
        return {'ok': False, 'host': host, 'error': 'no Lynis audit has been read from this host'}
    only = set(body.get('findings') or [])
    tasks, by_hand = lynis_tasks(host, m)
    w = waived(conn, host)
    tasks = [t for t in tasks if t.get('note', '').split(' ')[-1] not in w and (not only or t.get('note', '').split(' ')[-1] in only)]
    if not tasks:
        return {'ok': True, 'host': host, 'plan_id': None, 'tasks': 0, 'by_hand': by_hand, 'message': 'no finding here maps to a step. The ones listed are for a person'}
    return {'ok': True, 'host': host, 'plan_id': stage_plan(conn, f'Hardening: {host}'[:80], tasks, actor), 'tasks': len(tasks), 'by_hand': by_hand}


def reconverge_tasks(conn: Conn, host: str, profile: str) -> tuple[list[dict], list[str]]:
    status = security.compliance_status(conn, host, profile)
    m = security.measurement(conn, host) or {}
    tasks, by_hand = [], []
    for c in status['checks']:
        if c['result'] != 'fail':
            continue
        if c['id'] == 'sysctl':
            tasks += [{'type': 'sysctl-set', 'host': host, 'params': {'key': k, 'value': v}, 'note': f'{profile}: sysctl'} for k, v in sx.SYSCTLS.items() if (m.get('sysctl') or {}).get(k) not in (None, v)]
        elif c['id'] == 'umask':
            tasks.append({'type': 'umask-set', 'host': host, 'params': {'value': sx.UMASK}, 'note': f'{profile}: umask'})
        elif c['id'] == 'booleans':
            tasks += [{'type': 'selinux-boolean', 'host': host, 'params': {'name': b['name'], 'value': b['expected']}, 'note': f'{profile}: booleans'} for b in m.get('booleans') or [] if b.get('ok') is False]
        elif c['id'] == 'nts':
            tasks.append({'type': 'chrony-nts', 'host': host, 'params': {'servers': 'time.cloudflare.com,nts.netnod.se'}, 'note': f'{profile}: nts'})
        else:
            by_hand.append(f'{c["label"]}: {c["detail"]}')
    return tasks, by_hand


def reconverge(conn: Conn, body: dict, actor: str) -> dict:
    host = security.known_host(conn, body.get('host'))
    profile = str(body.get('profile') or alerts.get_setting(conn, security.profile_key(host)) or 'cis-l1')
    tasks, by_hand = reconverge_tasks(conn, host, profile)
    plan = stage_plan(conn, f'Re-converge: {host}'[:80], tasks, actor) if tasks else None
    return {'ok': True, 'host': host, 'profile': profile, 'plan_id': plan, 'tasks': len(tasks), 'by_hand': by_hand, 'message': f'{len(tasks)} step(s) staged in Changes' if tasks else 'Nothing here can be staged'}


# ── retention: policies, a freeze, a rollback preview ────────────────
def list_policies(conn: Conn) -> list[dict]:
    return [{'id': r[0], 'host': r[1], 'pattern': r[2], 'days': r[3], 'legal': bool(r[4]), 'auto': bool(r[5]), 'updated_at': r[6]} for r in conn.all('SELECT id, host, pattern, days, legal, auto, updated_at FROM security_retention_policies ORDER BY host, pattern')]


def save_policy(conn: Conn, body: dict, actor: str) -> dict:
    host = '*' if body.get('host') == '*' else security.known_host(conn, body.get('host'))
    pattern = str(body.get('pattern') or '').strip()
    if not re.fullmatch(r'[A-Za-z0-9_.:/*?-]{1,200}', pattern):
        raise ValueError('a pattern is a dataset or path with * in it, such as tank/prod/* or /data/*')
    days = security._int(body.get('days'), 0)
    legal = body.get('legal') is True
    if not legal and (days is None or not 1 <= days <= 3650):
        raise ValueError('days is 1 to 3650, or make it a legal hold')
    pid = conn.scalar('INSERT INTO security_retention_policies (host, pattern, days, legal, auto, created_by, updated_at) VALUES (:h, :p, :d, :l, :a, :b, :t) RETURNING id',
                      {'h': host, 'p': pattern, 'd': days or 0, 'l': int(legal), 'a': int(body.get('auto') is True), 'b': actor, 't': NOW()})
    return {'ok': True, 'id': pid}


def delete_policy(conn: Conn, policy_id: int):
    conn.execute('DELETE FROM security_retention_policies WHERE id = :i', {'i': policy_id})


def _held_names(conn: Conn, host: str) -> set:
    return {r[0] for r in conn.all("SELECT snapshot FROM security_retention_holds WHERE lower(host) = lower(:h) AND status <> 'released'", {'h': host})}


def policy_targets(conn: Conn, host: str) -> list[dict]:
    """The newest snapshot of each dataset a policy names that has no hold yet. From the last measurement: unread is nothing to do, not done."""
    m = security.measurement(conn, host) or {}
    snaps = m.get('snapshots') or []
    held = _held_names(conn, host)
    newest = {}
    for s in snaps:
        ds, _, name = s.partition('@')
        if name:
            newest[ds] = s
    out = []
    for p in list_policies(conn):
        if p['host'] not in ('*', host):
            continue
        for ds, snap in newest.items():
            if fnmatch.fnmatch(ds, p['pattern']) or fnmatch.fnmatch('/' + ds, p['pattern']):
                if snap not in held and not snap.split('@')[1].startswith('sf-incident'):
                    out.append({'policy': p['id'], 'dataset': ds, 'snapshot': snap, 'days': p['days'], 'legal': p['legal']})
    return out


def apply_policies(db, conn: Conn, body: dict, actor: str) -> dict:
    host, mode = security.known_host(conn, body.get('host')), security._mode(body)
    targets = policy_targets(conn, host)
    if mode == 'preview':
        return {'ok': True, 'mode': mode, 'host': host, 'targets': targets, 'measured_at': (security.measurement(conn, host) or {}).get('measured_at')}
    done, failed = [], []
    for t in targets:
        res = security.apply_hold(db, conn, {'host': host, 'snapshot': t['snapshot'], 'retention_days': t['days'] or None, 'legal_hold': t['legal'], 'mode': mode}, actor)
        (done if res.get('ok') else failed).append({**t, 'error': res.get('error')})
    return {'ok': not failed, 'mode': mode, 'host': host, 'done': done, 'failed': failed, **({'error': f'{len(failed)} hold(s) failed'} if failed else {})}


FREEZE_BODY = r"""
section "Legal freeze of $TARGET"
if [[ $KIND == zfs ]]; then
  command -v zfs >/dev/null || { conflict "this host has no zfs command"; exit 1; }
  zfs list -H "$TARGET" >/dev/null 2>&1 || { conflict "no dataset $TARGET"; exit 1; }
  n=0; held=0
  while IFS= read -r s; do
    [[ -n $s ]] || continue; n=$((n + 1))
    if zfs holds -H "$s" 2>/dev/null | awk -F'\t' -v t="$TAG" '$2 == t {f = 1} END {exit !f}'; then ok "$s"; held=$((held + 1)); continue; fi
    if ((APPLY)); then doing "hold $s"; zfs hold -- "$TAG" "$s" || { conflict "could not hold $s"; continue; }; echo "HELD zfs $(printf %s "$s" | base64 -w0) $(printf %s "$TAG" | base64 -w0)"; held=$((held + 1))
    else missing "$s would be held"; fi
  done < <(zfs list -H -t snapshot -r -o name "$TARGET")
  echo "FROZE $held of $n"
else
  command -v btrfs >/dev/null || { conflict "this host has no btrfs command"; exit 1; }
  [[ -d $TARGET ]] || { conflict "no folder $TARGET"; exit 1; }
  # read-only stops writes, and does not stop `btrfs subvolume delete`: guarded, not impossible
  n=0; held=0
  while IFS= read -r s; do
    [[ -n $s ]] || continue; p=$TARGET/$s; [[ -d $p ]] || continue; n=$((n + 1))
    if ((APPLY)); then doing "read-only $p"; btrfs property set -ts "$p" ro true || { conflict "could not hold $p"; continue; }; echo "HELD btrfs $(printf %s "$p" | base64 -w0) $(printf %s "$TAG" | base64 -w0)"; held=$((held + 1))
    elif [[ $(btrfs property get -ts "$p" ro 2>/dev/null) == ro=true ]]; then ok "$p"; held=$((held + 1))
    else missing "$p would be read-only"; fi
  done < <(btrfs subvolume list -s -o "$TARGET" 2>/dev/null | sed -n 's/.* path //p' | sed "s|^.*/||")
  echo "FROZE $held of $n"
fi
finished
"""


def freeze(db, conn: Conn, body: dict, actor: str) -> dict:
    """Every snapshot under a dataset, held until released. A scheduled prune fails on a held ZFS snapshot, which is the point."""
    host, mode = security.known_host(conn, body.get('host')), security._mode(body)
    target = str(body.get('target') or '').strip()
    kind = 'btrfs' if target.startswith('/') else 'zfs'
    if kind == 'btrfs':
        target = security.clean_path(target, 'the folder')
    elif not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.:/-]{0,199}', target):
        raise ValueError('name a ZFS dataset, or a btrfs folder')
    tag = 'sf-legal-freeze'
    script = sx.head() + sx.APPLY_ONLY + f'TARGET={shlex.quote(target)} KIND={kind} TAG={tag}\n' + FREEZE_BODY
    res, out = security._act(db, host, script, mode, f'freeze:{target}'[:200], actor, r'^FROZE ', 1800)
    out.update(host=host, target=target)
    if res and mode == 'apply' and out['ok']:
        now = NOW()
        n = 0
        for m in re.finditer(r'^HELD (zfs|btrfs) (\S+) (\S+)$', res['output'], re.M):
            snap = security._b64text(m[2])
            if snap:
                security._record_hold(conn, host, m[1], snap, tag, None, True, actor, now)
                n += 1
        out['held'] = n
        frozen = alerts.get_setting(conn, FREEZES) or []
        alerts.set_setting(conn, FREEZES, [f for f in frozen if not (f['host'] == host and f['target'] == target)] + [{'host': host, 'target': target, 'at': now, 'by': actor}], actor)
    return out


PREVIEW_BODY = r"""
if [[ $SNAP == *@* ]]; then
  command -v zfs >/dev/null || { echo "ERROR no zfs command"; exit 0; }
  zfs list -H -t snapshot "$SNAP" >/dev/null 2>&1 || { echo "ERROR no snapshot $SNAP"; exit 0; }
  timeout 300 zfs diff -H "$SNAP" 2>/dev/null | head -n 20000 | awk -F'\t' '{c[$1]++; if (n[$1]++ < 40) print "S\t" $1 "\t" $2} END {for (k in c) print "C\t" k "\t" c[k]}'
else
  [[ -d $SNAP && -d $LIVE ]] || { echo "ERROR no folder $SNAP or $LIVE"; exit 0; }
  command -v rsync >/dev/null || { echo "ERROR no rsync on this host"; exit 0; }
  # what restoring it would do, by checksum so a same-sized overwrite shows too
  timeout 300 rsync -anci --delete --no-specials --no-devices -- "$SNAP/" "$LIVE/" 2>/dev/null | head -n 20000 | awk '{k = ($1 ~ /^\*deleting/) ? "+" : ($1 ~ /^>f\+/) ? "-" : "M"; p = $0; sub(/^[^ ]+ +/, "", p); c[k]++; if (n[k]++ < 40) print "S\t" k "\t" p} END {for (k in c) print "C\t" k "\t" c[k]}'
fi
echo "DONE"
"""


def rollback_preview(db, conn: Conn, body: dict, actor: str) -> dict:
    """What would change, on the host, read only. `zfs diff` counts: M modified, + added since, - removed since, R renamed."""
    host = security.known_host(conn, body.get('host'))
    snap = str(body.get('snapshot') or '').strip()
    live = ''
    if not security.ZFS_SNAP_RE.fullmatch(snap):
        snap = security.clean_path(snap, 'the snapshot')
        live = security.clean_path(body.get('live') or '', 'the live folder')
    script = '#!/usr/bin/env bash\n# Written by StorageForge. Only reads.\nset -u\nexport LC_ALL=C\n' + f'SNAP={shlex.quote(snap)} LIVE={shlex.quote(live)}\n' + PREVIEW_BODY
    res = security._run(db, host, script, ref=f'preview:{snap}'[:200], mode='report', actor=actor, timeout=400)
    output = res.get('output') or ''
    err = re.search(r'^ERROR (.*)$', output, re.M)     # the script stops here with no DONE, so this comes first
    if res['status'] == 'ok' and err:
        return {'ok': False, 'host': host, 'error': err[1]}
    if res['status'] != 'ok' or 'DONE' not in output:
        return security._result(res, 'report', 'the preview did not finish: see the output', host=host)
    counts = {m[1]: int(m[2]) for m in re.finditer(r'^C\t(\S+)\t(\d+)$', output, re.M)}
    samples = [{'what': m[1], 'path': m[2]} for m in re.finditer(r'^S\t(\S+)\t(.*)$', output, re.M)]
    return {'ok': True, 'host': host, 'snapshot': snap, 'counts': counts, 'samples': samples, 'run_id': res.get('run_id')}


def stage_rollback(conn: Conn, body: dict, actor: str) -> dict:
    host = security.known_host(conn, body.get('host'))
    snap = str(body.get('snapshot') or '').strip()
    if security.ZFS_SNAP_RE.fullmatch(snap):
        ds, name = snap.split('@', 1)
        task = {'type': 'zfs-rollback', 'host': host, 'params': {'dataset': ds, 'snapshot': name}}
    else:
        task = {'type': 'subvolume-restore', 'host': host, 'params': {'source': security.clean_path(snap, 'the snapshot'), 'path': security.clean_path(body.get('live') or '', 'the live folder')}}
    return {'ok': True, 'host': host, 'plan_id': stage_plan(conn, f'Roll back: {host} from {snap}'[:80], [task], actor)}


# ── evidence: a signed record of what was measured and done ──────────
STATEMENT = ('This is a record of what StorageForge measured and did, signed so it can be shown not to have been changed since. It is evidence, '
             'not an attestation: a check passing is not a control met, a hold shown here could be released by root on that host, and only an auditor can attest.')


def evidence(db, conn: Conn, host: str | None, since: int | None, until: int | None, actor: str) -> dict:
    from .vault import Vault
    name = security.known_host(conn, host) if host else None
    until = until or NOW()
    since = since or until - 90 * 86400
    who = {'h': name, 'a': since, 'b': until}
    where = 'AND lower(host) = lower(:h)' if name else ''
    holds = [dict(zip(('id', 'host', 'snapshot', 'hold_tag', 'filesystem', 'created_at', 'expires_at', 'legal_hold', 'status', 'verified_at', 'missing_at'), r)) for r in conn.all(
        f'SELECT id, host, snapshot, hold_tag, filesystem, created_at, expires_at, legal_hold, status, verified_at, missing_at FROM security_retention_holds WHERE created_at <= :b {where} ORDER BY created_at', who)]
    events = [dict(zip(('uuid', 'host', 'kind', 'severity', 'occurred_at', 'via', 'summary', 'acknowledged_by', 'acknowledged_at'), r)) for r in conn.all(
        f'SELECT uuid, host, kind, severity, occurred_at, via, summary, acknowledged_by, acknowledged_at FROM security_events WHERE occurred_at BETWEEN :a AND :b {where} ORDER BY occurred_at', who)]
    audit_where = 'AND lower(target_host) = lower(:h)' if name else ''
    audit = [dict(zip(('at_us', 'actor', 'action', 'target_host', 'outcome', 'entry_hash'), r)) for r in conn.all(
        f"SELECT ts_us, actor, action, target_host, outcome, entry_hash FROM audit_log WHERE ts_us BETWEEN :a * 1000000 AND :b * 1000000 AND action LIKE 'security.%' {audit_where} ORDER BY audit_id", who)]
    doc = {'kind': 'storageforge-evidence/v1', 'statement': STATEMENT, 'generated_at': NOW(), 'generated_by': actor, 'host': name, 'from': since, 'to': until, 'holds': holds, 'events': events, 'audit': audit,
           'audit_chain_head': conn.scalar('SELECT entry_hash FROM audit_log ORDER BY audit_id DESC LIMIT 1')}
    text = json.dumps(doc, sort_keys=True, separators=(',', ':'))
    with Vault(db, conn).unlock() as v:
        key = deploy._signer(v)
        signature = deploy.sshsig(key, text.encode(), namespace='storageforge-evidence')
        from cryptography.hazmat.primitives import serialization
        pub = key.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()
    return {'document': text, 'signature': signature, 'public_key': pub,
            'verify': 'echo "storageforge namespaces=\\"storageforge-evidence\\" <public_key>" >signers; ssh-keygen -Y verify -f signers -I storageforge -n storageforge-evidence -s evidence.sig <evidence.json'}


# ── identity: who is connected to Samba, sampled ─────────────────────
SESSIONS_SCRIPT = r"""#!/bin/bash
# storageforge-sessions: written by StorageForge. Once a minute: who is connected to Samba, from where, and to which shares.
# Sampled from smbstatus, so it sees what is connected at that moment and nothing that came and went between. Only reads.
set -u
export LC_ALL=C PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
CONF=/etc/storageforge/security STATE=/var/lib/storageforge/security
MAX_SHARES=10 OFF_FROM= OFF_TO= REPORT_URL=
# shellcheck disable=SC1091
. "$CONF/identity.conf"
[[ -r $CONF/sentinel.conf ]] && . <(grep -a '^REPORT_URL=' "$CONF/sentinel.conf")
command -v smbstatus >/dev/null || exit 0
now=$(date +%s); hour=$(date +%-H)
LOG=$STATE/sessions.tsv SEEN=$STATE/identity.seen EVENTS=$STATE/events.tsv
b64() { printf %s "$1" | base64 -w0; }
emit() { # kind key summary
  grep -qsxF "$2" "$SEEN" && return 0
  printf '%s\n' "$2" >>"$SEEN"
  local line
  line=$(printf 'ev\t%s\t%s\t%s\t%s\t%s' "$(cat /proc/sys/kernel/random/uuid)" "$1" "$now" "$(b64 "$3")" "$(b64 "$2")")
  printf '%s\n' "$line" >>"$EVENTS"
  if [[ -n $REPORT_URL && -r $CONF/report.header ]] && command -v curl >/dev/null; then
    local ca=(); [[ -r /etc/storageforge/report-ca.pem ]] && ca=(--cacert /etc/storageforge/report-ca.pem)
    curl -fsS -m 5 ${ca[@]+"${ca[@]}"} -H @"$CONF/report.header" -H 'Content-Type: application/json' --data-binary "{\"lines\":[\"${line//$'\t'/\\t}\"]}" "$REPORT_URL/api/security/report" >/dev/null 2>&1
  fi
}
rows=$(awk -v now="$now" 'FNR == NR { if ($1 ~ /^[0-9]+$/ && NF >= 4) { user[$1] = $2; ip[$1] = $4 } next }
       $2 ~ /^[0-9]+$/ && ($2 in user) && $1 != "IPC$" { print now "\t" user[$2] "\t" ip[$2] "\t" $1 }' <(smbstatus -b 2>/dev/null) <(smbstatus -S 2>/dev/null))
[[ -n $rows ]] && printf '%s\n' "$rows" >>"$LOG"
if [[ -e $LOG ]] && (($(stat -c %s "$LOG") > 2097152)); then tail -n 5000 "$LOG" >"$LOG.new" && mv -f "$LOG.new" "$LOG"; fi
[[ -e $SEEN ]] && (($(stat -c %s "$SEEN") > 65536)) && : >"$SEEN"
day=$((now / 86400))
while IFS=$'\t' read -r user shares clients subnets; do
  [[ -n $user ]] || continue
  ((shares > MAX_SHARES)) && emit identity_enumeration "$day:enum:$user" "$user is connected to $shares shares at once, from $clients"
  ((subnets > 1)) && emit identity_multi_subnet "$day:subnet:$user" "$user is connected from $subnets networks at once: $clients"
  if [[ -n $OFF_FROM && -n $OFF_TO ]]; then
    if { ((OFF_FROM <= OFF_TO)) && ((hour >= OFF_FROM && hour < OFF_TO)); } || { ((OFF_FROM > OFF_TO)) && ((hour >= OFF_FROM || hour < OFF_TO)); }; then
      emit identity_off_hours "$day:off:$user" "$user is connected to $shares share(s) off hours, from $clients"
    fi
  fi
done < <(awk -F'\t' -v t="$((now - 300))" '$1 >= t { s[$2 FS $4] = 1; c[$2 FS $3] = 1; split($3, o, "."); n[$2 FS o[1] "." o[2] "." o[3]] = 1 }
  END { for (k in s) { split(k, a, FS); sh[a[1]]++ } for (k in c) { split(k, a, FS); cl[a[1]] = cl[a[1]] (cl[a[1]] ? "," : "") a[2] } for (k in n) { split(k, a, FS); ne[a[1]]++ }
        for (u in sh) print u "\t" sh[u] "\t" cl[u] "\t" ne[u] }' "$LOG" 2>/dev/null)
"""

SESSIONS_UNIT = """[Unit]
Description=StorageForge: who is connected to Samba

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/storageforge-sessions
"""

SESSIONS_TIMER = """[Unit]
Description=StorageForge: who is connected to Samba, each minute

[Timer]
OnBootSec=2min
OnUnitActiveSec=60s
AccuracySec=10s

[Install]
WantedBy=timers.target
"""

IDENTITY_BODY = r"""
section "Who is connected to Samba, sampled each minute"
if ((UNINSTALL)); then
  if ((APPLY)); then
    systemctl disable --now storageforge-sessions.timer 2>/dev/null || :
    rm -f /usr/local/sbin/storageforge-sessions /etc/systemd/system/storageforge-sessions.service /etc/systemd/system/storageforge-sessions.timer "$CONF/identity.conf" "$STATE/sessions.tsv" "$STATE/identity.seen"
    reload_systemd || :
    ok "removed, along with what it had recorded"; echo "IDENTITY off"
  else missing "would remove the sampler and what it recorded"; fi
  finished; exit 0
fi
command -v smbstatus >/dev/null || { conflict "this host has no Samba: nothing to sample"; exit 1; }
if ((APPLY == 0)); then missing "would sample smbstatus each minute, and keep who connected from where in $STATE/sessions.tsv: up to 2 MB"; finished; exit 0; fi
mkdir -p "$CONF" "$STATE"
cat >/usr/local/sbin/storageforge-sessions <<'SF_SESSIONS'
@SCRIPT@SF_SESSIONS
chmod 0755 /usr/local/sbin/storageforge-sessions
cat >/etc/systemd/system/storageforge-sessions.service <<'SF_UNIT'
@UNIT@SF_UNIT
cat >/etc/systemd/system/storageforge-sessions.timer <<'SF_UNIT'
@TIMER@SF_UNIT
printf 'MAX_SHARES=%s\nOFF_FROM=%s\nOFF_TO=%s\n' "$MAX_SHARES_VALUE" "$OFF_FROM_VALUE" "$OFF_TO_VALUE" >"$CONF/identity.conf"
reload_systemd
systemctl enable --now storageforge-sessions.timer
systemctl is-active -q storageforge-sessions.timer || { conflict "the timer did not start"; exit 1; }
ok "sampling each minute"; echo "IDENTITY on"
finished
"""


def identity_script(max_shares: int, off_from, off_to, remove: bool = False) -> str:
    body = IDENTITY_BODY.replace('@SCRIPT@', SESSIONS_SCRIPT).replace('@UNIT@', SESSIONS_UNIT).replace('@TIMER@', SESSIONS_TIMER)
    return (sx.head() + sx.APPLY_ONLY + f'UNINSTALL={int(remove)} MAX_SHARES_VALUE={int(max_shares)} OFF_FROM_VALUE={shlex.quote("" if off_from is None else str(off_from))} OFF_TO_VALUE={shlex.quote("" if off_to is None else str(off_to))}\n' + body)


def identity_config(conn: Conn, host: str) -> dict:
    return alerts.get_setting(conn, IDENTITY + host) or {'enabled': False, 'max_shares': 10, 'off_from': None, 'off_to': None}


def identity_deploy(db, conn: Conn, body: dict, actor: str) -> dict:
    """Off by default. It writes down who connected from where on the host, which is a decision about people and needs making."""
    host, mode = security.known_host(conn, body.get('host')), security._mode(body)
    enabled = body.get('enabled') is not False
    max_shares = security._int(body.get('max_shares'), 10)
    if max_shares is None or not 2 <= max_shares <= 1000:
        raise ValueError('max_shares is 2 to 1000')
    hours = []
    for key in ('off_from', 'off_to'):
        v = body.get(key)
        h = None if v in (None, '') else security._int(v)
        if h is not None and not 0 <= h <= 23:
            raise ValueError('hours are 0 to 23')
        hours.append(h)
    res, out = security._act(db, host, identity_script(max_shares, hours[0], hours[1], not enabled), mode, 'identity', actor, r'^IDENTITY (on|off)$')
    out.update(host=host, enabled=enabled)
    if res and mode == 'apply' and out['ok']:
        alerts.set_setting(conn, IDENTITY + host, {'enabled': enabled, 'max_shares': max_shares, 'off_from': hours[0], 'off_to': hours[1]}, actor)
    return out


def identity_view(conn: Conn, host: str) -> dict:
    m = security.measurement(conn, host) or {}
    sessions = m.get('sessions') or []
    latest = max((s['at'] for s in sessions), default=None)
    kinds = ('identity_enumeration', 'identity_multi_subnet', 'identity_off_hours')
    return {'host': host, 'config': identity_config(conn, host), 'measured_at': m.get('measured_at'), 'sessions': [s for s in sessions if s['at'] == latest][:200], 'sampled_at': latest,
            'events': [e for e in security.list_events(conn, host, 200, False) if e['kind'] in kinds]}


def parse_sessions(lines: list[str]) -> list[dict]:
    out = []
    for line in lines[-200:]:
        f = line.split('\t')
        if len(f) == 4 and f[0].isdigit():
            out.append({'at': int(f[0]), 'user': security.clean_text(f[1], 80), 'client': security.clean_text(f[2], 64), 'share': security.clean_text(f[3], 120)})
    return out


# ── Falco: rules as data, alerts as events ───────────────────────────
DEFAULT_FALCO = r"""# StorageForge rules. Falco rules look at one event at a time, so "many renames fast" cannot be said here: that is what the
# change rate between scans is for. These catch what one event can show.
- macro: sf_storage
  condition: (fd.name startswith "$STORAGE_MOUNT_ONE")
- list: sf_ransom_suffixes
  items: [.locked, .crypto, .crypt, .encrypted, .wncry, .cerber, .ryk]
- rule: StorageForge rename to a ransomware suffix
  desc: A file renamed to a name ransomware uses
  condition: evt.type in (rename, renameat, renameat2) and evt.dir = < and (fs.path.target endswith .locked or fs.path.target endswith .crypto or fs.path.target endswith .encrypted or fs.path.target endswith .wncry)
  output: "rename to a ransomware suffix (target=%fs.path.target proc=%proc.name user=%user.name)"
  priority: CRITICAL
- rule: StorageForge immutable flag removed
  desc: chattr -i, as something does before it deletes what was protected
  condition: evt.type = execve and evt.dir = < and proc.name = chattr and proc.args contains "-i"
  output: "immutable flag removed (proc=%proc.name user=%user.name)"
  priority: WARNING
- rule: StorageForge disk destruction
  desc: The commands that destroy pools, snapshots and filesystems
  condition: evt.type = execve and evt.dir = < and proc.name in (wipefs, mkfs, zpool, fdisk, sgdisk) and not proc.pname in ($AUTHORIZED_BACKUP_SCRIPTS)
  output: "disk destruction command (proc=%proc.name user=%user.name)"
  priority: CRITICAL
- rule: StorageForge program run from a storage mount
  desc: A program started from where data lives
  condition: evt.type = execve and evt.dir = < and proc.exepath startswith "$STORAGE_MOUNT_ONE"
  output: "program run from a storage mount (exe=%proc.exepath user=%user.name)"
  priority: WARNING
"""

# Falco's package signing key, from its documentation's key table and the key its site serves. It expires 2028-12-10: when Falco
# moves to a new one, installs refuse here until this changes, which is the point. A host that has Falco already never gets this far.
FALCO_KEY_FINGERPRINT = '478B2FBBC75F4237B731DA4365106822B35B1B1F'
# Downloads the key to $FK, and refuses a file that is not exactly that key. The script's signature says nothing about what a download returns.
FALCO_KEY_FETCH = r"""
FK=$(mktemp); trap 'rm -f "$FK"' EXIT
curl -fsSL https://falco.org/repo/falcosecurity-packages.asc -o "$FK" || { conflict "could not fetch Falco's key"; exit 1; }
command -v gpg >/dev/null || { conflict "gpg is needed to check Falco's key: install gnupg"; exit 1; }
listed=$(gpg --show-keys --with-colons "$FK" 2>/dev/null)
fpr=$(awk -F: '$1 == "fpr" {print $10; exit}' <<<"$listed")
if [[ $(grep -c '^pub:' <<<"$listed") != 1 || $fpr != "@FINGERPRINT@" ]]; then
  conflict "Falco's key is not the expected one (got ${fpr:-nothing}): nothing was installed. If Falco has moved to a new key, check it against falco.org and update StorageForge"; exit 1
fi
""".replace('@FINGERPRINT@', FALCO_KEY_FINGERPRINT)
# Written here rather than downloaded, since this file decides whether packages are checked at all. No gpgkey line: a package manager
# told to say yes would import whatever that URL returned, so only the key checked above is trusted.
FALCO_RPM_REPO = '''[falcosecurity-rpm]
name=falcosecurity-rpm
baseurl=https://download.falco.org/packages/rpm
gpgcheck=1
repo_gpgcheck=0
enabled=1
'''

FALCO_BODY = r"""
section "Falco"
if ((UNINSTALL)); then
  if ((APPLY)); then
    rm -f /etc/falco/rules.d/storageforge.yaml /etc/falco/config.d/storageforge.yaml "$STATE/falco.jsonl"
    for u in falco-modern-bpf falco-bpf falco-kmod falco; do systemctl is-active -q "$u" 2>/dev/null && systemctl restart "$u"; done
    ok "StorageForge rules removed. Falco itself stays: remove the package if you want it gone"; echo "FALCO off"
  else missing "would remove the StorageForge rules"; fi
  finished; exit 0
fi
if ! command -v falco >/dev/null; then
  if ((APPLY == 0)); then missing "Falco is not installed: --apply adds its vendor's repository, and installs it"; finished; exit 0; fi
  # it comes from its vendor, not the distro. The key and the repository are what is written here, and nothing else
  export FALCO_FRONTEND=noninteractive FALCO_DRIVER_CHOICE=modern_ebpf
  m=$(pm)
  @KEY_FETCH@
  case $m in
    apt-get)
      mkdir -p /usr/share/keyrings
      gpg --dearmor --batch --yes -o /usr/share/keyrings/falco-archive-keyring.gpg <"$FK" || { conflict "could not store Falco's key"; exit 1; }
      echo "deb [signed-by=/usr/share/keyrings/falco-archive-keyring.gpg] https://download.falco.org/packages/deb stable main" >/etc/apt/sources.list.d/falcosecurity.list
      apt-get -o DPkg::Lock::Timeout=120 update -qq 2>&1 | tail -n 2
      DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=120 install -y -qq dialog falco 2>&1 | tail -n 3 ;;
    dnf|yum)
      rpm --import "$FK" || { conflict "could not store Falco's key"; exit 1; }
      cat >/etc/yum.repos.d/falcosecurity.repo <<'SF_FALCO_REPO'
@RPM_REPO@SF_FALCO_REPO
      "$m" install -y -q falco 2>&1 | tail -n 3 ;;
    zypper)
      rpm --import "$FK" || { conflict "could not store Falco's key"; exit 1; }
      cat >/etc/zypp/repos.d/falcosecurity.repo <<'SF_FALCO_REPO'
@RPM_REPO@SF_FALCO_REPO
      zypper -nq install falco 2>&1 | tail -n 3 ;;
    *) conflict "Falco has no repository for $m: install it by hand"; exit 1 ;;
  esac
  command -v falco >/dev/null || { conflict "Falco did not install"; exit 1; }
  ok "Falco is installed"
fi
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
cat >"$tmp/rules.yaml" <<'SF_FALCO_RULES'
@RULES@
SF_FALCO_RULES
base=()
for f in /etc/falco/falco_rules.yaml /etc/falco/rules.d/falco_rules.yaml; do [[ -r $f ]] && base+=(-V "$f"); done
if falco "${base[@]}" -V "$tmp/rules.yaml" >"$tmp/out" 2>&1; then ok "Falco accepts these rules"
else conflict "Falco rejects these rules: $(tail -n 8 "$tmp/out")"; exit 1; fi
if ((APPLY == 0)); then missing "would install these rules"; finished; exit 0; fi
mkdir -p /etc/falco/rules.d /etc/falco/config.d "$STATE"
install -m 0644 "$tmp/rules.yaml" /etc/falco/rules.d/storageforge.yaml
cat >/etc/falco/config.d/storageforge.yaml <<SF_FALCO_CONF
json_output: true
json_include_output_property: false
file_output:
  enabled: true
  keep_alive: true
  filename: $STATE/falco.jsonl
SF_FALCO_CONF
durable /etc/falco/rules.d/storageforge.yaml
unit=
for u in falco-modern-bpf falco-custom falco-bpf falco-kmod; do systemctl cat "$u.service" >/dev/null 2>&1 && { unit=$u; break; }; done
[[ -n $unit ]] || { conflict "no Falco service to start"; exit 1; }
systemctl enable -q "$unit.service" 2>/dev/null || :
systemctl restart "$unit.service" || { conflict "$unit did not start: $(journalctl -u "$unit" -n 5 --no-pager 2>/dev/null | tail -n 3)"; exit 1; }
sleep 3
systemctl is-active -q "$unit.service" || { conflict "$unit stopped: $(journalctl -u "$unit" -n 5 --no-pager 2>/dev/null | tail -n 3)"; exit 1; }
ok "$unit is running with these rules"
echo "FALCO on"
finished
"""


def falco_rules(conn: Conn) -> str:
    return alerts.get_setting(conn, FALCO_RULES) or DEFAULT_FALCO


def render_falco(conn: Conn, host: str, text: str) -> str:
    """The macros a rule can use, filled in from the index, and never from what someone typed."""
    mounts = [r[0] for r in conn.all("""SELECT m.mount_point FROM mounts m JOIN hosts h ON h.host_id = m.host_id WHERE lower(h.hostname) = lower(:h) AND m.scan_state = 'indexed' AND m.mount_point NOT IN ('/', '/boot', '/boot/efi', '/var', '/usr') ORDER BY m.mount_point""", {'h': host})]
    canaries = [r[0] for r in conn.all('SELECT path FROM security_canaries WHERE lower(host) = lower(:h)', {'h': host})]
    one = mounts[0] if mounts else '/nonexistent-storageforge'
    return (text.replace('$STORAGE_MOUNT_ONE', one).replace('$STORAGE_MOUNTS', ', '.join(json.dumps(m) for m in mounts) or '/nonexistent-storageforge')
            .replace('$CANARY_PATHS', ', '.join(json.dumps(c) for c in canaries) or '/nonexistent-storageforge').replace('$AUTHORIZED_BACKUP_SCRIPTS', 'storageforge-job, restic, rsnapshot'))


def falco_script(rules: str, remove: bool = False) -> str:
    # a quoted heredoc: the rules reach the host as data, and the terminator cannot appear in them
    if 'SF_FALCO_RULES' in rules:
        raise ValueError('the rules may not hold that word')
    return sx.head() + PACKAGES + sx.APPLY_ONLY + f'UNINSTALL={int(remove)}\n' + FALCO_BODY.replace('@KEY_FETCH@', FALCO_KEY_FETCH).replace('@RPM_REPO@', FALCO_RPM_REPO).replace('@RULES@', rules.rstrip('\n'))


def falco_deploy(db, conn: Conn, body: dict, actor: str) -> dict:
    host, mode = security.known_host(conn, body.get('host')), security._mode(body)
    remove = body.get('enabled') is False
    if body.get('rules') is not None:
        check_falco_yaml(str(body['rules']))
    text = str(body['rules']) if body.get('rules') is not None else falco_rules(conn)
    res, out = security._act(db, host, falco_script(render_falco(conn, host, text), remove), mode, 'falco', actor, r'^FALCO (on|off)$', 1200)
    out.update(host=host)
    if res and mode == 'apply' and out['ok'] and body.get('rules') is not None:
        alerts.set_setting(conn, FALCO_RULES, text, actor)
    return out


def check_falco_yaml(text: str):
    import yaml
    if len(text) > 200_000:
        raise ValueError('those rules are too long')
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ValueError(f'not YAML: {str(exc)[:300]}') from None
    if not isinstance(doc, list) or not all(isinstance(x, dict) and ({'rule', 'macro', 'list', 'required_engine_version'} & set(x)) for x in doc):
        raise ValueError('Falco rules are a list of rule, macro and list entries')


def parse_falco(lines: list[str]) -> list[dict]:
    out = []
    for line in lines[-200:]:
        f = line.split('\t')
        if len(f) == 7 and f[0] == 'a':
            out.append({'rule': security.clean_text(f[1], 200), 'priority': f[2].lower(), 'time': f[3], 'proc': security.clean_text(f[4], 100), 'path': security.clean_text(f[5], 300), 'user': security.clean_text(f[6], 80)})
    return out


def ingest_falco(conn: Conn, host: str, alerts_seen: list[dict]) -> int:
    """Warnings and worse become events, so they reach the alerts and the playbooks. Below that, the host keeps them."""
    new = 0
    for a in alerts_seen:
        kind = {'emergency': 'falco_crit', 'alert': 'falco_crit', 'critical': 'falco_crit', 'error': 'falco_crit', 'warning': 'falco_warn'}.get(a['priority'])
        if not kind:
            continue
        key = str(uuid.uuid5(uuid.NAMESPACE_URL, f'falco:{host}:{a["time"]}:{a["rule"]}:{a["path"]}'))
        summary = f'{a["rule"]}: {a["proc"] or "?"}' + (f' on {a["path"]}' if a['path'] else '') + (f' as {a["user"]}' if a['user'] else '')
        new += bool(security.record_event(conn, host, kind, summary, json.dumps(a), 'measure', None, key))
    return new


# ── YARA: rules as data, on changed files, beside ClamAV ─────────────
RULE_NAME = re.compile(r'[A-Za-z][A-Za-z0-9_ -]{0,79}')
DEFAULT_YARA = {'Ransom note wording': '''rule Ransomware_Extortion_Note_Pattern {
    strings:
        $s1 = "your files have been encrypted" nocase
        $s2 = "send bitcoin to the following address" nocase
        $s3 = "DECRYPT_FILES" ascii
    condition:
        2 of ($s*)
}
'''}
YARA_SCAN = r"""#!/usr/bin/env bash
# Written by StorageForge. Only reads: a match is reported, never touched. Rules first, then the file list, over stdin.
set -u
export LC_ALL=C
command -v yara >/dev/null || { echo "NO yara"; exit 0; }
dir=$(mktemp -d); trap 'rm -rf "$dir"' EXIT
rules=$dir/rules.yar list=$dir/list
while IFS= read -r line; do [[ $line == @@files ]] && break; printf '%s\n' "$line"; done >"$rules"
yara -w "$rules" /dev/null >"$dir/check" 2>&1 || { echo "BADRULES"; head -n 5 "$dir/check"; exit 0; }
n=0
while IFS= read -r line; do
  p=$(base64 -d <<<"$line" 2>/dev/null) || continue
  [[ -f $p && ! -L $p ]] || continue
  printf '%s\n' "$p" >>"$list"; n=$((n + 1))
done
start=$(date +%s)
hits=0
if ((n)); then
  while IFS= read -r p; do
    while read -r rule _; do
      [[ -n $rule ]] || continue
      printf 'found\t%s\t%s\n' "$(printf %s "$p" | base64 -w0)" "YARA:$(tr -cd 'A-Za-z0-9._:+-' <<<"$rule")"; hits=$((hits + 1))
    done < <(timeout 60 nice -n 19 yara -w "$rules" "$p" 2>/dev/null)
  done <"$list"
fi
echo "SCANNED $n $hits $(($(date +%s) - start))"
"""

YARA_TREE = r"""#!/usr/bin/env bash
# Written by StorageForge. Only reads: a sweep of a clean room, with ClamAV if it is here, and these YARA rules if they are.
set -u
export LC_ALL=C
ROOT=$1
[[ -d $ROOT ]] && findmnt -no OPTIONS --target "$ROOT" | grep -qE '(^|,)ro(,|$)' || { echo "NOTCLEANROOM $ROOT is not mounted read-only"; exit 0; }
dir=$(mktemp -d); trap 'rm -rf "$dir"' EXIT
cat >"$dir/rules.yar"
files=$(find "$ROOT" -xdev -type f | wc -l)
echo "FILES $files"
if command -v clamscan >/dev/null; then
  nice -n 19 clamscan -r --no-summary --infected --stdout "$ROOT" >"$dir/clam" 2>/dev/null; echo "CLAM rc=$?"
  while IFS= read -r line; do [[ $line == *' FOUND' ]] && echo "HIT clamav ${line% FOUND}"; done <"$dir/clam"
else echo "CLAM absent"; fi
if command -v yara >/dev/null && [[ -s $dir/rules.yar ]]; then
  nice -n 19 yara -w -r "$dir/rules.yar" "$ROOT" >"$dir/yara" 2>/dev/null; echo "YARA rc=$?"
  while IFS= read -r line; do echo "HIT yara $line"; done <"$dir/yara"
else echo "YARA absent"; fi
echo "SWEEP done"
"""


def list_yara(conn: Conn) -> list[dict]:
    rows = conn.all('SELECT id, name, body, enabled, updated_at FROM security_yara_rules ORDER BY name')
    return [{'id': r[0], 'name': r[1], 'body': r[2], 'enabled': bool(r[3]), 'updated_at': r[4]} for r in rows]


def save_yara(conn: Conn, body: dict, actor: str) -> dict:
    name = str(body.get('name') or '').strip()
    text = str(body.get('body') or '')
    if not RULE_NAME.fullmatch(name):
        raise ValueError('a rule set needs a plain name')
    if not re.search(r'\brule\s+\w+', text) or len(text) > 200_000:
        raise ValueError('that does not look like a YARA rule')
    conn.execute("""INSERT INTO security_yara_rules (name, body, enabled, created_by, updated_at) VALUES (:n, :b, :e, :a, :t)
                    ON CONFLICT (name) DO UPDATE SET body = excluded.body, enabled = excluded.enabled, updated_at = excluded.updated_at""",
                 {'n': name, 'b': text, 'e': int(body.get('enabled') is not False), 'a': actor, 't': NOW()})
    return {'ok': True, 'name': name}


def delete_yara(conn: Conn, rule_id: int):
    conn.execute('DELETE FROM security_yara_rules WHERE id = :i', {'i': rule_id})


def yara_text(conn: Conn) -> str:
    rows = [r['body'] for r in list_yara(conn) if r['enabled']]
    return '\n'.join(rows or DEFAULT_YARA.values())


def scan_filters(conn: Conn) -> dict:
    return {**DEFAULT_SCAN_FILTERS, **(alerts.get_setting(conn, SCAN_FILTERS) or {})}


def filtered_paths(conn: Conn, host: str, limit: int = 5000) -> list[str]:
    """What the last scan saw change, less what the filter skips. A file in the deep list is never skipped."""
    f = scan_filters(conn)
    scans = security._latest_scans(conn, host, 1)
    if not scans:
        return []
    rows = conn.all(f"""SELECT parent_path, filename, new_size FROM file_changes WHERE scan_id = :s AND change_type IN ('added', 'modified') AND NOT is_directory ORDER BY new_modified_at DESC LIMIT {int(limit) * 2}""", {'s': scans[0]['id']})
    skip, deep, limit_bytes = tuple(f['skip_ext']), tuple(f['deep_ext']), f['skip_over_mb'] * (1 << 20)
    out = []
    for parent, name, size in rows:
        low = name.lower()
        if not low.endswith(deep) and (low.endswith(skip) or (size or 0) > limit_bytes):
            continue
        out.append(security._full(parent, name))
    return out[:limit]


def yara_scan(db, conn: Conn, body: dict, actor: str) -> dict:
    """Found files join ClamAV's list, so quarantine and restore work the same. dry: a test of a rule set, and nothing is recorded."""
    from . import clamav
    host = security.known_host(conn, body.get('host'))
    dry = body.get('dry') is True
    paths = filtered_paths(conn, host)
    if not paths:
        return {'ok': False, 'host': host, 'error': 'the last scan saw no changed files to scan'}
    rules = str(body['rules']) if dry and body.get('rules') else yara_text(conn)
    data = (rules + '\n@@files\n' + ''.join(sx.b64(p) + '\n' for p in paths)).encode()
    res = security._run(db, host, YARA_SCAN, ref='yara-scan', mode='report', actor=actor, timeout=1800, data=data)
    if res['status'] != 'ok':
        return security._result(res, 'report', host=host)
    output = res.get('output') or ''
    if 'NO yara' in output:
        return security._result(res, 'report', f'{host} has no YARA: install it with the baseline, or the package', host=host)
    if 'BADRULES' in output:
        return security._result(res, 'report', 'YARA refused these rules: see the output', host=host)
    m = re.search(r'^SCANNED (\d+) (\d+) (\d+)$', output, re.M)
    if not m:
        return security._result(res, 'report', 'YARA did not finish: see the output', host=host)
    if dry:
        return {'ok': True, 'host': host, 'dry': True, 'scanned': int(m[1]), 'hits': int(m[2]), 'seconds': int(m[3]), 'matches': re.findall(r'^found\t\S+\t(.+)$', output, re.M)[:50], 'run_id': res.get('run_id')}
    return {'ok': True, 'host': host, 'asked': len(paths), 'scanned': int(m[1]), 'seconds': int(m[3]), 'found': clamav.add_found(conn, host, output), 'run_id': res.get('run_id')}


def clean_room_sweep(db, conn: Conn, body: dict, actor: str) -> dict:
    host = security.known_host(conn, body.get('host'))
    mount = security.clean_path(body.get('mount') or '/mnt/sf-cleanroom', 'the mount point')
    res = security._run(db, host, YARA_TREE, [mount], ref=f'sweep:{mount}'[:200], mode='report', actor=actor, timeout=3600, data=yara_text(conn).encode())
    output = res.get('output') or ''
    if res['status'] != 'ok':
        return security._result(res, 'report', host=host)
    if 'NOTCLEANROOM' in output:
        return {'ok': False, 'host': host, 'error': f'{mount} is not mounted read-only: mount the clean room first'}
    if 'SWEEP done' not in output:
        return security._result(res, 'report', 'the sweep did not finish: see the output', host=host)
    hits = re.findall(r'^HIT (\w+) (.*)$', output, re.M)
    files = re.search(r'^FILES (\d+)$', output, re.M)
    ran = [t for t in ('clam', 'yara') if re.search(rf'^{t.upper()} rc=', output, re.M)]
    return {'ok': True, 'host': host, 'mount': mount, 'files': int(files[1]) if files else None, 'hits': [{'tool': a, 'what': b} for a, b in hits[:200]], 'ran': ran, 'clean': not hits and bool(ran),
            'message': ('Found nothing with ' + ' and '.join(ran)) if not hits and ran else None, 'run_id': res.get('run_id')}


# ── playbooks: if this happens, do that ──────────────────────────────
TRIGGERS = {'canary_tripped': 'A decoy changed', 'falco_crit': 'Falco: critical', 'falco_warn': 'Falco: warning', 'identity_enumeration': 'One user on many shares', 'identity_multi_subnet': 'One user on several networks',
            'identity_off_hours': 'Connected off hours', 'clock_jump': 'The clock jumped', 'hold_missing': 'A hold is gone from the host', 'entropy_flagged': 'Changed files look encrypted', 'velocity': 'Files changing much faster than usual'}
ACTIONS = {'triage': 'Save what is only in memory', 'drop_client': 'Drop the client', 'snapshot': 'Snapshot and hold', 'freeze': 'Make it read-only', 'measure': 'Measure the host now', 'notify': 'Send an alert'}
BRAKE = {'triage': 'triage', 'drop_client': 'quarantine', 'snapshot': 'snapshot', 'freeze': 'freeze'}


def list_playbooks(conn: Conn) -> list[dict]:
    rows = conn.all('SELECT id, name, trigger_kind, conditions_json, actions_json, enabled, dry_run, updated_at FROM security_playbooks ORDER BY name')
    return [{'id': r[0], 'name': r[1], 'trigger': r[2], 'conditions': loads(r[3]) or {}, 'actions': loads(r[4]) or [], 'enabled': bool(r[5]), 'dry_run': bool(r[6]), 'updated_at': r[7]} for r in rows]


def save_playbook(conn: Conn, body: dict, actor: str) -> dict:
    name = str(body.get('name') or '').strip()
    if not RULE_NAME.fullmatch(name):
        raise ValueError('a playbook needs a plain name')
    trigger = str(body.get('trigger') or '')
    if trigger not in TRIGGERS:
        raise ValueError('trigger is one of ' + ', '.join(TRIGGERS))
    actions = [a for a in ACTIONS if a in (body.get('actions') or [])]
    if not actions:
        raise ValueError('a playbook has to do something')
    c = body.get('conditions') or {}
    conditions = {k: security.clean_text(c[k], 200).strip() for k in ('host', 'path') if c.get(k)}
    # it starts by saying what it would do. Turning that off is a choice, made after watching it
    conn.execute("""INSERT INTO security_playbooks (name, trigger_kind, conditions_json, actions_json, enabled, dry_run, created_by, updated_at) VALUES (:n, :k, :c, :a, :e, :d, :b, :t)
                    ON CONFLICT (name) DO UPDATE SET trigger_kind = excluded.trigger_kind, conditions_json = excluded.conditions_json, actions_json = excluded.actions_json, enabled = excluded.enabled, dry_run = excluded.dry_run, updated_at = excluded.updated_at""",
                 {'n': name, 'k': trigger, 'c': json.dumps(conditions), 'a': json.dumps(actions), 'e': int(body.get('enabled') is not False), 'd': int(body.get('mode', 'dry_run') == 'dry_run'), 'b': actor, 't': NOW()})
    if body.get('mode') == 'confirm':
        conn.execute("UPDATE security_playbooks SET conditions_json = :c WHERE name = :n", {'c': json.dumps({**conditions, 'confirm': True}), 'n': name})
    return {'ok': True, 'name': name}


def delete_playbook(conn: Conn, playbook_id: int):
    conn.execute('DELETE FROM security_playbooks WHERE id = :i', {'i': playbook_id})


def event_fields(detail: str) -> dict:
    out = {}
    for part in (detail or '').split(';'):
        k, _, v = part.partition('=')
        if k in ('path_b64', 'client', 'pid', 'event'):
            out[k] = v
    if out.get('path_b64'):
        out['path'] = security._b64text(out['path_b64']) or ''
    return out


def _matches(pb: dict, host: str, fields: dict) -> bool:
    c = pb['conditions']
    if c.get('host') and not fnmatch.fnmatch(host, c['host']):
        return False
    if c.get('path') and not (fields.get('path') or '').startswith(c['path']):
        return False
    return True


def _client_of(conn: Conn, host: str, event_id: int, fields: dict) -> str:
    """A trip's first event names the path, and the next one, canary_source, says who. Attribution comes a moment later, if at all."""
    if fields.get('client'):
        return fields['client']
    path = fields.get('path_b64')
    if not path:
        return ''
    for detail in (r[0] for r in conn.all("SELECT detail FROM security_events WHERE lower(host) = lower(:h) AND kind = 'canary_source' AND event_id >= :e ORDER BY event_id LIMIT 20", {'h': host, 'e': event_id})):
        f = event_fields(detail)
        if f.get('path_b64') == path and f.get('client'):
            return f['client']
    return ''


def run_actions(db, conn: Conn, pb: dict, host: str, event: dict, fields: dict) -> dict:
    """Each action reports what it really did. A brake step runs through the same program a person pulls, with a run on the host behind it."""
    actor = f'playbook:{pb["name"]}'[:60]
    steps, failed = [], []
    brake = [BRAKE[a] for a in pb['actions'] if a in BRAKE]
    if brake:
        client = _client_of(conn, host, event['id'], fields)
        out = security.brake(db, conn, {'host': host, 'path': fields.get('path') or '', 'client_ip': client, 'actions': brake, 'mode': 'apply', 'reason': f'{pb["name"]}: {event["summary"]}'[:200], 'minutes': ban_minutes(conn, 2)}, actor)
        steps += out.get('steps') or []
        if out.get('error'):
            failed.append(out['error'])
    if 'measure' in pb['actions']:
        m = security.measure(db, conn, host, actor)
        steps.append({'step': 'measure', 'status': 'ok' if m.get('ok') else 'failed', 'detail': m.get('error') or ''})
    if 'notify' in pb['actions']:
        res = alerts.send(alerts.get_setting(conn, 'alerts'), f'{pb["name"]}: {host}', event['summary'], 'crit', {'kind': 'playbook', 'ref': host})
        steps.append({'step': 'notify', 'status': 'ok', 'detail': '; '.join(res)})
    return {'steps': steps, 'failed': failed}


def _record_run(conn: Conn, pb: dict, host: str, event_id, outcome: str, detail: dict) -> int:
    return conn.scalar('INSERT INTO security_playbook_runs (playbook_id, event_id, host, at, outcome, detail_json) VALUES (:p, :e, :h, :t, :o, :d) RETURNING id',
                       {'p': pb['id'], 'e': event_id, 'h': host, 't': NOW(), 'o': outcome, 'd': json.dumps(detail, default=str)[:8000]})


def fire(db, conn: Conn, trigger: str, host: str, event: dict) -> list[int]:
    fields = event_fields(event.get('detail') or '')
    runs = []
    for pb in list_playbooks(conn):
        if not pb['enabled'] or pb['trigger'] != trigger or not _matches(pb, host, fields):
            continue
        if pb['dry_run']:
            runs.append(_record_run(conn, pb, host, event['id'], 'would', {'actions': pb['actions'], 'summary': event['summary']}))
        elif pb['conditions'].get('confirm'):
            runs.append(_record_run(conn, pb, host, event['id'], 'pending', {'actions': pb['actions'], 'summary': event['summary'], 'fields': fields}))
        else:
            out = run_actions(db, conn, pb, host, event, fields)
            runs.append(_record_run(conn, pb, host, event['id'], 'failed' if out['failed'] else 'ran', {'actions': pb['actions'], 'summary': event['summary'], **out}))
    return runs


def note_velocity(conn: Conn):
    """A change rate above a host's own usual is worked out from scans, so here it becomes an event a playbook can follow. Once for each scan."""
    for (name,) in conn.all('SELECT hostname FROM hosts'):
        v = security.velocity(conn, name)
        if v.get('anomaly'):
            latest = v['latest']
            security.record_event(conn, name, 'velocity', f'{latest["files_per_hour"]} files an hour against a usual {v["baseline_median"]}', '', 'scan', latest['at'], str(uuid.uuid5(uuid.NAMESPACE_URL, f'velocity:{name}:{latest["at"]}')))


def process_events(db, conn: Conn) -> int:
    """New events since the last look, in order. The cursor moves first: a host that cannot be reached must not be braked again and again."""
    cursor = alerts.get_setting(conn, PLAYBOOK_CURSOR)
    newest = conn.scalar('SELECT max(event_id) FROM security_events') or 0
    if cursor is None:                # the first look starts from now: history does not fire playbooks
        alerts.set_setting(conn, PLAYBOOK_CURSOR, newest, 'system')
        return 0
    if newest <= cursor:
        return 0
    alerts.set_setting(conn, PLAYBOOK_CURSOR, newest, 'system')
    done = 0
    for eid, host, kind, summary, detail in conn.all('SELECT event_id, host, kind, summary, detail FROM security_events WHERE event_id > :c ORDER BY event_id LIMIT 500', {'c': cursor}):
        if kind in TRIGGERS:
            done += len(fire(db, conn, kind, host, {'id': eid, 'summary': summary, 'detail': detail}))
    return done


def pending_runs(conn: Conn) -> list[dict]:
    rows = conn.all("""SELECT r.id, r.playbook_id, p.name, r.event_id, r.host, r.at, r.detail_json FROM security_playbook_runs r JOIN security_playbooks p ON p.id = r.playbook_id
                       WHERE r.outcome = 'pending' ORDER BY r.at DESC LIMIT 100""")
    return [{'id': r[0], 'playbook_id': r[1], 'playbook': r[2], 'event_id': r[3], 'host': r[4], 'at': r[5], **{k: v for k, v in (loads(r[6]) or {}).items() if k in ('actions', 'summary')}} for r in rows]


def playbook_runs(conn: Conn, limit: int = 100) -> list[dict]:
    rows = conn.all(f"""SELECT r.id, p.name, r.host, r.at, r.outcome, r.detail_json FROM security_playbook_runs r JOIN security_playbooks p ON p.id = r.playbook_id ORDER BY r.at DESC, r.id DESC LIMIT {int(limit)}""")
    return [{'id': r[0], 'playbook': r[1], 'host': r[2], 'at': r[3], 'outcome': r[4], 'detail': loads(r[5]) or {}} for r in rows]


def decide_run(db, conn: Conn, run_id: int, confirm: bool, actor: str) -> dict:
    rows = conn.all("SELECT r.playbook_id, r.event_id, r.host, r.detail_json FROM security_playbook_runs r WHERE r.id = :i AND r.outcome = 'pending'", {'i': run_id})
    if not rows:
        raise LookupError('nothing is waiting there')
    pid, eid, host, raw = rows[0]
    detail = loads(raw) or {}
    pb = next((p for p in list_playbooks(conn) if p['id'] == pid), None)
    if not confirm or not pb:
        conn.execute("UPDATE security_playbook_runs SET outcome = 'dismissed', detail_json = :d WHERE id = :i", {'d': json.dumps({**detail, 'by': actor}), 'i': run_id})
        return {'ok': True, 'host': host, 'outcome': 'dismissed'}
    out = run_actions(db, conn, pb, host, {'id': eid, 'summary': detail.get('summary') or ''}, detail.get('fields') or {})
    outcome = 'failed' if out['failed'] else 'ran'
    conn.execute('UPDATE security_playbook_runs SET outcome = :o, detail_json = :d WHERE id = :i', {'o': outcome, 'd': json.dumps({**detail, **out, 'by': actor}, default=str)[:8000], 'i': run_id})
    return {'ok': not out['failed'], 'host': host, 'outcome': outcome, 'steps': out['steps'], **({'error': '; '.join(out['failed'])} if out['failed'] else {})}


# ── ban tiers ────────────────────────────────────────────────────────
def ban_tiers(conn: Conn) -> dict:
    return alerts.get_setting(conn, BAN_TIERS) or DEFAULT_BAN_TIERS


def save_ban_tiers(conn: Conn, body: dict, actor: str) -> dict:
    out = {}
    for t in ('1', '2', '3'):
        v = (body.get('tiers') or {}).get(t) or {}
        minutes = security._int(v.get('minutes'))
        if minutes is None or not 0 <= minutes <= 525600:
            raise ValueError(f'tier {t}: minutes is 0 (until lifted) to 525600')
        out[t] = {'label': security.clean_text(v.get('label') or DEFAULT_BAN_TIERS[t]['label'], 80), 'minutes': minutes}
    alerts.set_setting(conn, BAN_TIERS, out, actor)
    return {'ok': True, 'tiers': out}


def ban_minutes(conn: Conn, tier: int) -> int:
    return int(ban_tiers(conn).get(str(tier), {}).get('minutes') or 0)


def next_tier(conn: Conn, host: str, ip: str, asked: int) -> int:
    """A second offence inside 30 days goes up a tier, and a tier never goes down by itself."""
    prior = conn.scalar('SELECT max(tier) FROM security_ban_history WHERE lower(host) = lower(:h) AND ip_address = :i AND at > :t', {'h': host, 'i': ip, 't': NOW() - 30 * 86400})
    return min(3, max(asked, prior + 1)) if prior else asked


def record_ban(conn: Conn, host: str, ip: str, tier: int, reason: str):
    conn.execute('INSERT INTO security_ban_history (host, ip_address, tier, at, reason) VALUES (:h, :i, :t, :a, :r)', {'h': host, 'i': ip, 't': tier, 'a': NOW(), 'r': reason[:200]})


# ── thresholds and filters ───────────────────────────────────────────
def thresholds(conn: Conn) -> dict:
    return alerts.get_setting(conn, THRESHOLDS) or {'velocity': {}, 'entropy': []}


def save_thresholds(conn: Conn, body: dict, actor: str) -> dict:
    vel = {}
    for host, v in (body.get('velocity') or {}).items():
        name = security.known_host(conn, host)
        factor, floor = float(v.get('factor') or security.VELOCITY_FACTOR), security._int(v.get('floor'), security.VELOCITY_FLOOR)
        if not 1 <= factor <= 100 or floor is None or not 1 <= floor <= 10_000_000:
            raise ValueError('a factor is 1 to 100, and a floor 1 to 10,000,000 files an hour')
        vel[name] = {'factor': factor, 'floor': floor}
    ent = []
    for e in body.get('entropy') or []:
        prefix = security.clean_path(e.get('prefix'), 'a folder')
        t = float(e.get('threshold') or 0)
        if not 1 <= t <= 8:
            raise ValueError('an entropy threshold is 1 to 8 bits a byte')
        ent.append({'prefix': prefix, 'threshold': t})
    out = {'velocity': vel, 'entropy': ent}
    alerts.set_setting(conn, THRESHOLDS, out, actor)
    return {'ok': True, **out}


def velocity_limits(conn: Conn, host: str) -> tuple[float, int]:
    v = thresholds(conn)['velocity'].get(host) or {}
    return v.get('factor', security.VELOCITY_FACTOR), v.get('floor', security.VELOCITY_FLOOR)


def entropy_limit(conn: Conn, path: str) -> float:
    best, limit = -1, security.ENTROPY_FLAG
    for e in thresholds(conn)['entropy']:
        if (path == e['prefix'] or path.startswith(e['prefix'].rstrip('/') + '/')) and len(e['prefix']) > best:
            best, limit = len(e['prefix']), e['threshold']
    return limit


def avc_noise(conn: Conn) -> list[dict]:
    return alerts.get_setting(conn, AVC_NOISE) or []


def save_avc_noise(conn: Conn, body: dict, actor: str) -> dict:
    rows = [{'daemon': security.clean_text(x.get('daemon') or '*', 60), 'path': security.clean_text(x.get('path') or '*', 200)} for x in (body.get('rules') or [])[:200]]
    alerts.set_setting(conn, AVC_NOISE, rows, actor)
    return {'ok': True, 'rules': rows}


def mark_avc(conn: Conn, avc: list[dict]) -> list[dict]:
    """Noise is folded away, never deleted. A daemon reaching for something it should never want stands out, noise rule or not."""
    noise = avc_noise(conn)
    out = []
    for a in avc:
        lateral = any(str(a.get('path') or '').startswith(p) for p in LATERAL) and a.get('storage')
        quiet = not lateral and any(fnmatch.fnmatch(str(a.get('daemon') or ''), n['daemon']) and fnmatch.fnmatch(str(a.get('path') or ''), n['path']) for n in noise)
        out.append({**a, 'lateral': lateral, 'noise': quiet})
    return out


def context_map(conn: Conn) -> list[dict]:
    return alerts.get_setting(conn, CONTEXT_MAP) or []


def save_context_map(conn: Conn, body: dict, actor: str) -> dict:
    rows = []
    for x in (body.get('rules') or [])[:200]:
        t = str(x.get('type') or '')
        if not security.SE_TYPE_RE.fullmatch(t):
            raise ValueError(f'{t[:40]} is not an SELinux type')
        rows.append({'pattern': security.clean_path(x.get('pattern'), 'a path pattern'), 'type': t})
    alerts.set_setting(conn, CONTEXT_MAP, rows, actor)
    return {'ok': True, 'rules': rows}


def context_drift(conn: Conn, host: str, fcontext: list[dict]) -> list[dict]:
    rules = context_map(conn)
    out = []
    for f in fcontext:
        want = next((r['type'] for r in rules if fnmatch.fnmatch(f['path'], r['pattern'])), None)
        if want and f.get('live') != want:
            out.append({'path': f['path'], 'live': f.get('live'), 'want': want})
    return out


def stage_context(conn: Conn, body: dict, actor: str) -> dict:
    host = security.known_host(conn, body.get('host'))
    m = security.measurement(conn, host) or {}
    tasks = [{'type': 'selinux-relabel', 'host': host, 'params': {'path': d['path'], 'type': d['want']}} for d in context_drift(conn, host, m.get('fcontext') or [])]
    if not tasks:
        return {'ok': True, 'host': host, 'plan_id': None, 'tasks': 0, 'message': 'every mount the last measurement read matches its rule'}
    return {'ok': True, 'host': host, 'plan_id': stage_plan(conn, f'Labels: {host}'[:80], tasks, actor), 'tasks': len(tasks)}


def aide_watch(conn: Conn) -> list[str]:
    return alerts.get_setting(conn, AIDE_WATCH) or []


def save_aide_watch(conn: Conn, body: dict, actor: str) -> dict:
    rows = sorted({security.clean_path(p, 'a path') for p in (body.get('paths') or [])[:200]})
    alerts.set_setting(conn, AIDE_WATCH, rows, actor)
    return {'ok': True, 'paths': rows}


# ── offline packages ─────────────────────────────────────────────────
TOOLS = ('auditd', 'aide', 'lynis', 'nftables', 'chrony', 'inotify-tools', 'yara')
CHECK_BODY = r"""
pm_is=$(pm)
echo "PM $pm_is"
while read -r what cmd; do
  if command -v "$cmd" >/dev/null; then echo "TOOL $what present"; continue; fi
  pkg=$(pkg_for "$pm_is" "$what")
  case $pm_is in
    apt-get) v=$(apt-cache policy "$pkg" 2>/dev/null | awk '/Candidate:/ {print $2}'); [[ -n $v && $v != "(none)" ]] && r=installable || r=blocked ;;
    dnf|yum) "$pm_is" -q --cacheonly list --available "$pkg" >/dev/null 2>&1 && r=installable || { "$pm_is" -q list --available "$pkg" >/dev/null 2>&1 && r=installable || r=blocked; } ;;
    zypper) zypper -nq --no-refresh info "$pkg" 2>/dev/null | grep -q '^Name' && r=installable || r=blocked ;;
    pacman) pacman -Si "$pkg" >/dev/null 2>&1 && r=installable || r=blocked ;;
    *) r=blocked ;;
  esac
  echo "TOOL $what $r"
done <<'SF_TOOLS'
@TOOLS@SF_TOOLS
echo "DONE"
"""

BUNDLE_BODY = r"""
section "Offline bundle"
m=$(pm); arch=$(uname -m); . /etc/os-release 2>/dev/null; distro=${ID:-unknown}-${VERSION_ID:-0}
name=sf-security-bundle-$distro-$arch; dir=/var/lib/storageforge/bundles; work=$dir/$name.work
info "packages for $distro on $arch, downloaded with $m on this host. Use it on hosts of the same distro and version"
if ((APPLY == 0)); then missing "would download: $PKGS"; finished; exit 0; fi
rm -rf "$work"; mkdir -p "$work"
case $m in
  apt-get) (cd "$work" && for p in $PKGS; do apt-get -o DPkg::Lock::Timeout=120 download $(apt-cache depends --recurse --no-recommends --no-suggests --no-conflicts --no-breaks --no-replaces --no-enhances "$p" 2>/dev/null | grep '^[a-zA-Z0-9]' | sort -u) 2>/dev/null || apt-get download "$p"; done) ;;
  dnf|yum) "$m" download -q --resolve --destdir "$work" $PKGS ;;
  zypper) zypper -nq --pkg-cache-dir "$work" install -y --download-only $PKGS ;;
  pacman) pacman -Sw --noconfirm --cachedir "$work" $PKGS ;;
  *) conflict "no package manager here to download with"; exit 1 ;;
esac
count=$(find "$work" -type f | wc -l)
((count)) || { conflict "nothing was downloaded: is this host online?"; exit 1; }
tar -C "$work" -czf "$dir/$name.tar.gz" .
sum=$(sha256sum "$dir/$name.tar.gz" | cut -d' ' -f1)
rm -rf "$work"
ok "$count packages in $dir/$name.tar.gz"
echo "BUNDLE $dir/$name.tar.gz $sum $count"
finished
"""


def package_check(db, conn: Conn, body: dict, actor: str) -> dict:
    """Satisfied, installable or blocked for each tool, from the host's own package lists. Read only."""
    from .scriptkit import NEEDS
    host = security.known_host(conn, body.get('host'))
    tools = ''.join(f'{w} {NEEDS[w][0]}\n' for w in TOOLS)
    script = sx.head() + PACKAGES + 'APPLY=0\n' + _tools_map() + CHECK_BODY.replace('@TOOLS@', tools)
    res = security._run(db, host, script, ref='packages', mode='report', actor=actor, timeout=300)
    if res['status'] != 'ok' or 'DONE' not in (res.get('output') or ''):
        return security._result(res, 'report', 'the check did not finish: see the output', host=host)
    out = {m[1]: m[2] for m in re.finditer(r'^TOOL (\S+) (\S+)$', res['output'], re.M)}
    pm = re.search(r'^PM (\S+)$', res['output'], re.M)
    now = NOW()
    security._save_measurement(conn, host, 'packages', now, 'check', {'pm': pm[1] if pm else None, 'tools': out})
    return {'ok': True, 'host': host, 'pm': pm[1] if pm else None, 'tools': out, 'checked_at': now, 'run_id': res.get('run_id')}


def _tools_map() -> str:
    from .scriptkit import NEEDS
    lines = ['pkg_for() { case "$1:$2" in\n']
    for w in TOOLS:
        for pm, name in NEEDS[w][1].items():
            lines.append(f'  {pm}:{w}) echo {shlex.quote(name)} ;;\n')
    lines.append('  *) echo "$2" ;;\nesac; }\n')
    return ''.join(lines)


def bundle(db, conn: Conn, body: dict, actor: str) -> dict:
    """Runs on an online host of the same distro. The file stays on that host until someone moves it, with its checksum."""
    host, mode = security.known_host(conn, body.get('host')), security._mode(body)
    # the distro's own names, worked out on the host
    script = sx.head() + PACKAGES + sx.APPLY_ONLY + _tools_map() + 'PKGS=$(for w in ' + ' '.join(TOOLS) + '; do pkg_for "$(pm)" "$w"; done | tr "\\n" " ")\n' + BUNDLE_BODY
    res, out = security._act(db, host, script, mode, 'bundle', actor, r'^BUNDLE ', 1800)
    out.update(host=host)
    if res and mode == 'apply' and out['ok']:
        m = re.search(r'^BUNDLE (\S+) (\S+) (\d+)$', res['output'], re.M)
        out.update(path=m[1], sha256=m[2], packages=int(m[3]))
    return out


# ── the whole picture, in tiles ──────────────────────────────────────
TILES = {'posture': 'Fleet state', 'alarms': 'Alarms', 'decoys': 'Decoys', 'blocked': 'Who is dropped', 'holds': 'Holds', 'entropy': 'Files that look encrypted', 'avc': 'Storage denials', 'lynis': 'Hardening index', 'compliance': 'Checks passing', 'exposure': 'Widest exposure', 'playbooks': 'Playbooks'}


def tile(conn: Conn, kind: str, host: str | None) -> dict:
    """Every number here was measured. A tile with nothing to read says so; it never shows zero for unread."""
    if kind not in TILES:
        raise LookupError(f'no such tile: {kind[:40]}')
    names = [security.known_host(conn, host)] if host else [r[0] for r in conn.all('SELECT hostname FROM hosts ORDER BY hostname')]
    if kind == 'posture':
        p = security.posture(conn, host)
        return {'state': p['state'], 'text': p['banner']}
    if kind == 'alarms':
        rows = [e for n in names for e in security.list_events(conn, n, 20, False) if not e['acknowledged_at']]
        return {'rows': [{'label': e['summary'][:120], 'value': e['severity'], 'at': e['occurred_at'], 'host': e['host']} for e in sorted(rows, key=lambda e: -e['occurred_at'])[:10]]}
    if kind == 'decoys':
        rows = conn.all('SELECT host, status FROM security_canaries')
        armed, tripped = sum(1 for h, s in rows if s == 'armed' and h in names), sum(1 for h, s in rows if s == 'tripped' and h in names)
        return {'stats': [{'label': 'Armed', 'value': armed}, {'label': 'Tripped', 'value': tripped}]} if rows else {'none': 'No decoys deployed'}
    if kind == 'blocked':
        rows = security.firewall_view(conn, host)['quarantine']
        return {'rows': [{'label': q['ip_address'], 'value': q['reason'][:80], 'at': q['added_at'], 'host': q['host']} for q in rows[:10]]} if rows else {'none': 'Nobody is dropped'}
    if kind == 'holds':
        h = security.worm_view(conn, host)['summary']
        return {'stats': [{'label': 'Active', 'value': h['active']}, {'label': 'Seen on host', 'value': h['verified']}, {'label': 'Gone from host', 'value': h['missing']}, {'label': 'Expiring in a day', 'value': h['expiring_24h']}]}
    if kind == 'entropy':
        rows = []
        for n in names:
            e = security.measurement(conn, n, 'entropy')
            if e:
                rows += [{'label': f['path'][-80:], 'value': f['entropy'], 'host': n} for f in e.get('flagged') or []]
        return {'rows': rows[:10]} if rows else {'none': 'Nothing flagged, or nothing sampled'}
    if kind == 'avc':
        rows = []
        for n in names:
            m = security.measurement(conn, n)
            if m:
                rows += [{'label': f'{a.get("daemon")} on {a.get("path")}', 'value': a.get('action'), 'at': a.get('at'), 'host': n} for a in mark_avc(conn, m.get('avc') or []) if a.get('storage') and not a['noise']]
        return {'rows': rows[:10]} if rows else {'none': 'No storage denials in what was read'}
    if kind in ('lynis', 'compliance'):
        series = {n: trend(conn, n, kind, 30) for n in names}
        rows = [{'label': n, 'value': v[-1]['value'], 'series': [x['value'] for x in v]} for n, v in series.items() if v]
        return {'rows': rows} if rows else {'none': 'Not measured'}
    if kind == 'exposure':
        from . import exposure, inframeasure, netfacts, workloads
        rows = []
        for n in names:
            rep = exposure.host_report(netfacts.reading(conn, n), inframeasure.reading(conn, n), workloads.containers_of(conn, n), n, _router_forwards(conn))
            rows += [{'label': f'{i["port"]}/{i["proto"]} {i.get("container") or ",".join(i.get("process") or [])}', 'value': i['level'], 'host': n} for i in rep['items'] if i['level'] in ('any', 'lan', 'vpn', 'unknown')]
        rows.sort(key=lambda r: -exposure.ORDER[r['value']])
        return {'rows': rows[:10]} if rows else {'none': 'Nothing reachable from outside in what was read'}
    if kind == 'playbooks':
        rows = playbook_runs(conn, 10)
        return {'rows': [{'label': r['playbook'], 'value': r['outcome'], 'at': r['at'], 'host': r['host']} for r in rows]} if rows else {'none': 'Nothing has fired'}
    return {}


def list_dashboards(conn: Conn, owner: str) -> list[dict]:
    return [{'id': r[0], 'name': r[1], 'layout': loads(r[2]) or [], 'updated_at': r[3]} for r in conn.all('SELECT id, name, layout_json, updated_at FROM security_dashboards WHERE owner = :o ORDER BY name', {'o': owner})]


def save_dashboard(conn: Conn, body: dict, owner: str) -> dict:
    name = str(body.get('name') or '').strip()
    if not RULE_NAME.fullmatch(name):
        raise ValueError('a dashboard needs a plain name')
    layout = []
    for t in (body.get('layout') or [])[:40]:
        if t.get('kind') not in TILES:
            raise ValueError('no such tile')
        layout.append({'kind': t['kind'], 'w': min(4, max(1, int(t.get('w') or 1))), 'h': min(4, max(1, int(t.get('h') or 1)))})
    conn.execute("""INSERT INTO security_dashboards (owner, name, layout_json, updated_at) VALUES (:o, :n, :l, :t)
                    ON CONFLICT (owner, name) DO UPDATE SET layout_json = excluded.layout_json, updated_at = excluded.updated_at""", {'o': owner, 'n': name, 'l': json.dumps(layout), 't': NOW()})
    return {'ok': True, 'name': name}


def delete_dashboard(conn: Conn, dash_id: int, owner: str):
    conn.execute('DELETE FROM security_dashboards WHERE id = :i AND owner = :o', {'i': dash_id, 'o': owner})


# ── who can reach each share ─────────────────────────────────────────
def share_matrix(conn: Conn, host: str) -> dict:
    """Each share's declared clients, what the firewall really allows on its ports, and who is connected. Reads the index only."""
    from . import exposure, inframeasure, netfacts, shares, workloads
    from .steps_infra import NFS, SMB
    name = security.known_host(conn, host)
    report = exposure.host_report(netfacts.reading(conn, name), inframeasure.reading(conn, name), workloads.containers_of(conn, name), name, _router_forwards(conn))
    infra = inframeasure.reading(conn, name) or {}
    levels = {i['port']: i for i in report['items'] if i['proto'] == 'tcp'}
    connected = infra.get('storage_clients') or []
    rows = []
    try:
        exports = shares.design_exports(conn, name)
    except (ValueError, LookupError):      # no design saved: the rest of the panel still has something to say
        exports = []
    for e in exports:
        protocol = shares.proto(e)
        ports = [int(p) for p in (SMB if protocol == 'SMB' else NFS).split(',')]
        declared = sorted({str(r.get('clients')) for r in e.get('rules') or [] if r.get('clients')}) if protocol != 'SMB' else [str(e.get('clients') or '')] if e.get('clients') else []
        firewall = next((levels[p] for p in ports if p in levels), None)
        here = [c for c in connected if c['port'] in ports]
        rows.append({'name': e.get('name'), 'path': e.get('path'), 'protocol': protocol, 'declared': declared, 'firewall': (firewall or {}).get('level'), 'rule': (firewall or {}).get('rule'), 'fenced_to': (firewall or {}).get('fenced_to'), 'why': (firewall or {}).get('why'),
                     'connected': here})
    known = {c['client'] for c in connected}
    return {'host': name, 'read': report.get('firewall_read'), 'measured_at': infra.get('measured_at'), 'shares': rows, 'clients': sorted(known), 'caveat': exposure.CAVEAT}


def stage_fence(conn: Conn, body: dict, actor: str) -> dict:
    host = security.known_host(conn, body.get('host'))
    clients = str(body.get('clients') or '').replace(' ', '')
    for part in clients.split(','):
        ipaddress.ip_network(part, strict=False)
    name = re.sub(r'[^A-Za-z0-9_.-]', '-', str(body.get('name') or 'share'))[:40]
    task = {'type': 'fw-fence', 'host': host, 'params': {'name': name, 'service': str(body.get('service') or 'smb'), 'ports': str(body.get('ports') or ''), 'clients': clients, 'iface': str(body.get('iface') or ''), 'state': 'present', 'rollback': '10'}}
    return {'ok': True, 'host': host, 'plan_id': stage_plan(conn, f'Fences: {host}'[:80], [task], actor)}


# ── a timeline for one investigation ─────────────────────────────────
def timeline(conn: Conn, args: dict) -> list[dict]:
    """Alarms, what people and playbooks did, and quarantines, in one line, narrowed to one client, user, dataset, protocol or host."""
    host, client, user, dataset, protocol = (args.get(k) or None for k in ('host', 'client', 'user', 'dataset', 'protocol'))
    limit = 500
    rows = []
    for e in security.list_events(conn, host, limit):
        rows.append({'at': e['occurred_at'], 'source': 'event', 'host': e['host'], 'severity': e['severity'], 'text': e['summary'], 'detail': e.get('detail') or '', 'kind': e['kind']})
    params = {'h': host}
    for ts, who, action, target, outcome, detail in conn.all(f"""SELECT ts_us, actor, action, target_host, outcome, detail_json FROM audit_log WHERE action LIKE 'security.%' {'AND lower(target_host) = lower(:h)' if host else ''} ORDER BY audit_id DESC LIMIT {limit}""", params):
        rows.append({'at': ts // 1000000, 'source': 'action', 'host': target, 'severity': 'info' if outcome == 'ok' else 'warn', 'text': f'{who}: {action} ({outcome})', 'detail': detail or '', 'kind': action, 'user': who})
    for h, ip, tier, at, reason in conn.all(f"SELECT host, ip_address, tier, at, reason FROM security_ban_history {'WHERE lower(host) = lower(:h)' if host else ''} ORDER BY at DESC LIMIT {limit}", params):
        rows.append({'at': at, 'source': 'ban', 'host': h, 'severity': 'warn', 'text': f'{ip} dropped, tier {tier}: {reason}', 'detail': ip, 'kind': 'ban'})

    def keep(r):
        blob = f'{r["text"]} {r["detail"]}'
        if client and client not in blob:
            return False
        if user and user not in blob and r.get('user') != user:
            return False
        if dataset and dataset not in blob:
            return False
        if protocol and protocol.lower() not in blob.lower():
            return False
        return True
    return sorted((r for r in rows if keep(r)), key=lambda r: -r['at'])[:limit]


# ── once a minute, from security.tick ────────────────────────────────
def tick(db) -> dict:
    from . import errlog
    conn = db.connect()
    done = {'fired': 0, 'policy_holds': 0}
    try:
        try:
            note_velocity(conn)
            done['fired'] = process_events(db, conn)
        except Exception:
            errlog.trace()
        last = alerts.get_setting(conn, 'security.policy_last') or 0
        if NOW() - last >= 86400 and conn.scalar('SELECT 1 FROM security_retention_policies WHERE auto = 1 LIMIT 1'):
            alerts.set_setting(conn, 'security.policy_last', NOW(), 'system')
            for (name,) in conn.all('SELECT hostname FROM hosts'):
                if not deploy.ready(conn, name) or security.clock_frozen(conn, name):
                    continue
                auto = {p['id'] for p in list_policies(conn) if p['auto'] and p['host'] in ('*', name)}
                for t in [t for t in policy_targets(conn, name) if t['policy'] in auto]:
                    try:
                        res = security.apply_hold(db, conn, {'host': name, 'snapshot': t['snapshot'], 'retention_days': t['days'] or None, 'legal_hold': t['legal'], 'mode': 'apply'}, 'policy')
                        done['policy_holds'] += bool(res.get('ok'))
                    except Exception:
                        errlog.trace()
    finally:
        conn.close()
    return done


_ = (hashlib, HELPERS, need_line)


def _router_forwards(conn) -> list[dict]:
    from . import netdevice
    return netdevice.forwards(conn)
