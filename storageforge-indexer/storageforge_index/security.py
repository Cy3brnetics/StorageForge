"""Ransomware defense: what hosts report about themselves, and what signed runs did to them.

Two rules hold this module together, and a security page that breaks them is worse than none:

    Every number comes from a measurement. What has not been measured is None, and the UI says so. Nothing is assumed to
    be fine: a host nobody has looked at is "unknown", never "secure".

    A row means it happened. A hold, a quarantine or a decoy is recorded after a signed run on the host (secscripts.py)
    has confirmed it, from a line the script prints only after checking. A failed run changes nothing here and says why.

Measurements and events come from the host they describe, and a compromised host can lie about itself. So what they say
can only raise an alarm: nothing a host reports releases a hold, disarms anything or clears an alert. Retention expiry
lives on the controller's clock for the same reason, which is why moving a host's clock cannot expire a hold.

See docs/ransomware-defense.md for what this does and does not protect against.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import ipaddress
import json
import re
import secrets
import socket
import statistics
import threading
import time
import uuid

from . import alerts, deploy, secscripts as sx
from .db import Conn, epoch, loads
from .runner import connect_address

# ── limits and names ─────────────────────────────────────────────────
ZFS_SNAP_RE = re.compile(r'[A-Za-z0-9_.:/-]{1,200}@[A-Za-z0-9_.:-]{1,200}')
TAG_RE = re.compile(r'sf-[A-Za-z0-9_.-]{1,60}')
SE_TYPE_RE = re.compile(r'[a-z0-9_]{1,64}_t')
UUID_RE = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}')
SE_TYPES = ('samba_share_t', 'public_content_t', 'public_content_rw_t', 'container_file_t')
# Only what is off on a stock host, so "too open" means someone opened it. The nfs_export_all_* pair is shown but not judged:
# it is on by default on the RHEL family, and turning it off stops exports that are not specially labelled.
EXPECTED_BOOLEANS = {'samba_export_all_rw': 'off', 'samba_export_all_ro': 'off', 'samba_enable_home_dirs': 'off'}
STORAGE_DAEMONS = frozenset({'smbd', 'nmbd', 'nfsd', 'rpc.mountd', 'rsync', 'zfs', 'btrfs', 'podman', 'dockerd', 'containerd'})

CLOCK_JUMP = 60                     # seconds a clock may be off before releases stop on that host
MEASURE_EVERY = 6 * 3600            # how often a host with the sentinel or holds is read without being asked
STALE_AFTER = 24 * 3600             # a measurement older than this says nothing about now
DEFAULT_COOL_OFF = 24
COOL_OFF_HOURS = (12, 24, 48, 72)
MIN_CIDR = {4: 16, 6: 48}           # a network wider than this is a mistake, not a quarantine
EVENT_SEVERITY = {'canary_tripped': 'crit', 'clock_jump': 'crit', 'brake_ran': 'crit', 'watcher_stopped': 'warn', 'canary_source': 'warn',
                  'sentinel_started': 'info', 'sentinel_test': 'info', 'hold_missing': 'crit', 'events_dropped': 'warn', 'break_glass_used': 'crit',
                  'falco_crit': 'crit', 'falco_warn': 'warn', 'identity_enumeration': 'crit', 'identity_multi_subnet': 'warn', 'identity_off_hours': 'warn', 'entropy_flagged': 'warn', 'velocity': 'warn'}
HOST_EVENTS = frozenset({'canary_tripped', 'canary_source', 'clock_jump', 'brake_ran', 'watcher_stopped', 'sentinel_started', 'sentinel_test',
                         'identity_enumeration', 'identity_multi_subnet', 'identity_off_hours'})
EVENTS_PER_HOUR = 300               # what one host may store in an hour, whatever its token sends
EVENTS_PER_KIND = 100               # ... and of any one kind, so a flood of one cannot hide another
HOST_DETAIL = 2048                  # characters of detail kept for an event a host sent (a decoy path is well under this)
MAX_EVENTS_PER_HOST = 5000          # the newest this many stay, however old
DEFAULT_DECOYS = ('_AAAPasswords.docx', '!Financial_2026.xlsx', '00_Index.pdf')
MAX_DECOYS = 500
SAMPLE_FILES = 500

# What ransomware leaves behind, as a scan sees it. Only ever a reason to look.
RANSOM_SUFFIXES = ('.locked', '.locky', '.crypto', '.crypt', '.encrypted', '.wncry', '.wannacry', '.cerber', '.zepto', '.odin', '.ryk',
                   '.ryuk', '.conti', '.lockbit', '.lockbit3', '.akira', '.phobos', '.dharma', '.hive', '.clop', '.basta', '.royal', '.blackcat')
RANSOM_NOTES = ('how_to_decrypt%', 'how-to-decrypt%', 'how_to_recover%', 'readme_decrypt%', 'decrypt_files%', 'decrypt_instructions%',
                '%restore_my_files%', '%restore-my-files%', 'read_me_now%', 'recover_files%', '_readme.txt')
VELOCITY_FLOOR = 500                # files an hour: below this, a multiple of a quiet baseline is still quiet
VELOCITY_FACTOR = 3
VELOCITY_MIN_BASELINE = 5
ENTROPY_FLAG = 7.92
# Compressed data looks just like ciphertext to entropy. Encrypting a file destroys its header, so a known one clears it.
KNOWN_MAGIC = ('504b0304', '504b0506', '1f8b', '425a68', 'fd377a58', '377abcaf', '52617221', '28b52ffd', '89504e47', 'ffd8ff', '47494638',
               '25504446', '49443303', '4f676753', '664c6143', '1a45dfa3', '52494646', '53514c69', 'd0cf11e0')
COMPRESSED_NAMES = ('.zip', '.gz', '.tgz', '.xz', '.bz2', '.zst', '.7z', '.rar', '.jpg', '.jpeg', '.png', '.gif', '.webp', '.heic', '.mp4', '.mkv',
                    '.mov', '.avi', '.webm', '.mp3', '.flac', '.ogg', '.m4a', '.qcow2', '.vmdk', '.iso', '.docx', '.xlsx', '.pptx', '.pdf')

BREAK_GLASS = 'security.break_glass_sha256'
COOL_OFF = 'security.cool_off_hours'
VIP = 'security.vip'
CONTROLLER_CLOCK = 'security.controller_clock'


def clock_key(host: str) -> str:
    return f'security.clock:{host.lower()}'


def host_key(host: str) -> str:
    return f'security.host:{host.lower()}'


def profile_key(host: str) -> str:
    return f'security.profile:{host.lower()}'


def known_host(conn: Conn, host) -> str:
    """Anything that runs on a host names one that has been scanned: nothing here acts on a name it has never seen."""
    name = deploy.canonical(conn, str(host or '').strip())
    if not name or not conn.scalar('SELECT 1 FROM hosts WHERE hostname = :h', {'h': name}):
        raise ValueError(f'{str(host or "")[:80]!r} has not been scanned')
    return name


def clean_path(value, what: str = 'path') -> str:
    p = str(value or '').strip()
    if not p.startswith('/') or '/../' in p + '/' or len(p) > 1000 or any(ord(c) < 32 or ord(c) == 127 for c in p):
        raise ValueError(f'{what} must be an absolute path: {p[:80]}')
    return p.rstrip('/') or '/'


def clean_text(value, limit: int = 500) -> str:
    """Text a host sent, or an operator typed, ready to be stored: no control characters, not unbounded."""
    return re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', str(value or ''))[:limit]


def _b64text(value: str) -> str | None:
    try:
        return base64.b64decode(value, validate=True).decode('utf-8', 'replace')
    except (binascii.Error, ValueError):
        return None


def _mode(body: dict) -> str:
    mode = str(body.get('mode') or 'report')
    if mode not in ('preview', 'report', 'apply'):
        raise ValueError('mode is preview, report or apply')
    return mode


def _result(res: dict, mode: str, error: str | None = None, **more) -> dict:
    ok = res['status'] in deploy.FINISHED and not error
    out = {'ok': ok, 'mode': mode, 'status': res['status'], 'output': res.get('output') or '', 'run_id': res.get('run_id'), **more}
    if not ok:
        out['error'] = error or f'the run ended {res["status"]}: see the output'
    return out


def _run(db, host: str, script: str, args=(), *, ref: str, mode: str, actor: str, timeout: int = 300, data=None) -> dict:
    return deploy.run(db, host, script, list(args), kind='security', ref=ref, mode=mode, actor=actor, timeout=timeout, data=data)


def _act(db, host: str, script: str, mode: str, ref: str, actor: str, marker: str | None = None, timeout: int = 300) -> tuple[dict | None, dict]:
    """Show the script, dry-run it or apply it. Returns (the run, or None for a preview, and the answer so far)."""
    if mode == 'preview':
        return None, {'ok': True, 'mode': mode, 'script': script}
    res = _run(db, host, script, ['--apply'] if mode == 'apply' else [], ref=ref, mode=mode, actor=actor, timeout=timeout)
    missing_marker = mode == 'apply' and marker and res['status'] in deploy.FINISHED and not re.search(marker, res.get('output') or '', re.M)
    return res, _result(res, mode, 'the script ended without confirming it' if missing_marker else None)


# ── events ───────────────────────────────────────────────────────────
def record_event(conn: Conn, host: str, kind: str, summary: str, detail: str = '', via: str = 'controller', occurred: int | None = None, event_uuid: str | None = None) -> bool:
    """False if this event was already recorded. The severity is decided here, not by whoever reported it."""
    event_uuid = event_uuid or str(uuid.uuid4())
    if conn.scalar('SELECT 1 FROM security_events WHERE uuid = :u', {'u': event_uuid}):
        return False
    now = int(time.time())
    conn.execute("""INSERT INTO security_events (uuid, host, kind, severity, occurred_at, received_at, via, summary, detail)
                    VALUES (:u, :h, :k, :s, :o, :r, :v, :su, :d)""",
                 {'u': event_uuid, 'h': host, 'k': kind, 's': EVENT_SEVERITY.get(kind, 'warn'), 'o': occurred or now, 'r': now, 'v': via[:60],
                  'su': clean_text(summary), 'd': clean_text(detail, 8000)})
    return True


def parse_event_line(line: str) -> dict | None:
    """ev, uuid, kind, epoch, summary (base64), detail (base64). None for anything else."""
    f = line.split('\t')
    if len(f) != 6 or f[0] != 'ev' or not UUID_RE.fullmatch(f[1]) or f[2] not in HOST_EVENTS or not f[3].isdigit():
        return None
    summary, detail = _b64text(f[4]), _b64text(f[5])
    if summary is None or detail is None:
        return None
    return {'uuid': f[1], 'kind': f[2], 'at': int(f[3]), 'summary': summary, 'detail': detail}


def ingest_events(conn: Conn, host: str, text: str, via: str = 'scan', stats: dict | None = None) -> int:
    """Event lines from a host: its report, a scan or a measurement carry the same file, so each counts once.

    A host can lie and can send as many lines as it likes, so what it may store is bounded: EVENTS_PER_HOUR rows an hour for the host
    (EVENTS_PER_KIND of any one kind, so a noisy kind cannot hide a real one), each with at most HOST_DETAIL characters of detail. What is
    dropped is counted in stats['dropped'] and, once an hour, in one events_dropped event."""
    now, new, dropped = int(time.time()), 0, 0
    budget = _event_budget(conn, host, now)
    for line in (text or '').splitlines()[:2000]:
        ev = parse_event_line(line)
        if not ev:
            continue
        if conn.scalar('SELECT 1 FROM security_events WHERE uuid = :u', {'u': ev['uuid']}):
            continue
        if budget['all'] <= 0 or budget.get(ev['kind'], EVENTS_PER_KIND) <= 0:
            dropped += 1
            continue
        budget['all'] -= 1
        budget[ev['kind']] = budget.get(ev['kind'], EVENTS_PER_KIND) - 1
        # a clock moved forward must not push the alarm it set off out of sight: nothing is dated ahead of us
        if not record_event(conn, host, ev['kind'], ev['summary'], ev['detail'][:HOST_DETAIL], via, min(ev['at'], now), ev['uuid']):
            continue
        new += 1
        if ev['kind'] == 'canary_tripped':
            m = re.search(r'path_b64=([A-Za-z0-9+/=]+)', ev['detail'])
            path = _b64text(m[1]) if m else None
            if path:
                conn.execute("""UPDATE security_canaries SET status = 'tripped', tripped_at = :t
                                WHERE lower(host) = lower(:h) AND path = :p AND status = 'armed'""", {'t': min(ev['at'], now), 'h': host, 'p': path})
        elif ev['kind'] == 'clock_jump':
            freeze_clock(conn, host, ev['summary'], via)
        # brake_ran is only an alarm here: its text came from the host, so it writes no hold and no quarantine (the signed run does)
    if stats is not None:
        stats['dropped'] = dropped
    if dropped and not conn.scalar("SELECT 1 FROM security_events WHERE lower(host) = lower(:h) AND kind = 'events_dropped' AND received_at > :t", {'h': host, 't': now - 3600}):
        record_event(conn, host, 'events_dropped', f'{host} sent more events than the controller keeps; the rest were dropped',
                     f'At most {EVENTS_PER_HOUR} events an hour ({EVENTS_PER_KIND} of one kind) are kept for a host. {dropped} were dropped in the first report that went over.', via)
    return new


def _event_budget(conn: Conn, host: str, now: int) -> dict:
    """How many more events this host may store this hour: in all ('all') and per kind."""
    rows = conn.all("""SELECT kind, count(*) FROM security_events WHERE lower(host) = lower(:h) AND received_at > :t GROUP BY kind""", {'h': host, 't': now - 3600})
    budget = {'all': EVENTS_PER_HOUR - sum(n for _, n in rows)}
    for kind, n in rows:
        budget[kind] = EVENTS_PER_KIND - n
    return budget


def prune_events(conn: Conn, now: int):
    """Old events go: info after 90 days, acknowledged warn and crit after a year, and beyond MAX_EVENTS_PER_HOST the oldest of any host."""
    conn.execute("DELETE FROM security_events WHERE severity = 'info' AND occurred_at < :t", {'t': now - 90 * 86400})
    conn.execute("DELETE FROM security_events WHERE acknowledged_at IS NOT NULL AND occurred_at < :t", {'t': now - 365 * 86400})
    for (host,) in conn.all('SELECT host FROM security_events GROUP BY host HAVING count(*) > :n', {'n': MAX_EVENTS_PER_HOST}):
        cutoff = conn.scalar('SELECT event_id FROM security_events WHERE host = :h ORDER BY event_id DESC LIMIT 1 OFFSET :n', {'h': host, 'n': MAX_EVENTS_PER_HOST})
        if cutoff:
            conn.execute('DELETE FROM security_events WHERE host = :h AND event_id <= :c', {'h': host, 'c': cutoff})


def _record_brake_output(conn: Conn, host: str, output: str, actor: str, now: int):
    """What the brake confirmed it did, from the output of a signed run the controller made. Never from text a host sent on its own
    (a report, a scan): see ingest_events. Even so, each value is checked before it becomes a row."""
    for raw in re.findall(r'^QUARANTINED (\S+)$', output or '', re.M):
        try:
            ip = clean_target(conn, host, raw)
        except ValueError:
            continue
        conn.execute('DELETE FROM security_quarantine WHERE lower(host) = lower(:h) AND ip_address = :ip', {'h': host, 'ip': ip})
        conn.execute("""INSERT INTO security_quarantine (host, ip_address, reason, added_at, expires_at, actor)
                        VALUES (:h, :ip, 'emergency brake', :t, NULL, :a)""", {'h': host, 'ip': ip, 't': now, 'a': actor})
    for fs, snap, tag in re.findall(r'^HELD (zfs|btrfs) (\S+) (\S+)$', output or '', re.M):
        s, t = _b64text(snap), _b64text(tag)
        if not s or not t or not TAG_RE.fullmatch(t):
            continue
        if not ZFS_SNAP_RE.fullmatch(s):
            try:
                s = clean_path(s, 'the snapshot')
            except ValueError:
                continue
        _record_hold(conn, host, fs, s, t, None, True, actor, now)


def list_events(conn: Conn, host: str | None = None, limit: int = 200, include_info: bool = True) -> list[dict]:
    where = ['lower(host) = lower(:h)'] if host else []
    if not include_info:
        where.append("severity <> 'info'")
    rows = conn.all(f"""SELECT event_id, host, kind, severity, occurred_at, received_at, via, summary, detail, acknowledged_by, acknowledged_at
                        FROM security_events {'WHERE ' + ' AND '.join(where) if where else ''} ORDER BY occurred_at DESC, event_id DESC LIMIT {int(limit)}""", {'h': host})
    keys = ('id', 'host', 'kind', 'severity', 'occurred_at', 'received_at', 'via', 'summary', 'detail', 'acknowledged_by', 'acknowledged_at')
    return [dict(zip(keys, r)) for r in rows]


def acknowledge_event(conn: Conn, event_id: int, actor: str) -> dict:
    rows = conn.all('SELECT host, kind FROM security_events WHERE event_id = :i', {'i': event_id})
    if not rows:
        raise LookupError(f'no event {event_id}')
    conn.execute('UPDATE security_events SET acknowledged_by = :a, acknowledged_at = :t WHERE event_id = :i', {'a': actor, 't': int(time.time()), 'i': event_id})
    return {'ok': True, 'host': rows[0][0], 'kind': rows[0][1]}


def report_host(conn: Conn, token: str) -> str | None:
    """The host a sentinel's report token belongs to. It can only add events about itself."""
    if not token:
        return None
    want = hashlib.sha256(token.encode()).hexdigest()
    for key, value in conn.all("SELECT key, value_json FROM settings WHERE key LIKE 'security.host:%'"):
        saved = loads(value) or {}
        if saved.get('token_sha') and secrets.compare_digest(saved['token_sha'], want):
            return saved.get('host') or key.split(':', 1)[1]
    return None


# ── measuring ────────────────────────────────────────────────────────
def _sections(text: str) -> dict | None:
    out: dict[str, list[str]] = {}
    cur = None
    for line in (text or '').splitlines():
        if line.startswith('@@') and re.fullmatch(r'@@[a-z_0-9]+', line):
            cur = line[2:]
            out[cur] = []
        elif cur:
            out[cur].append(line)
    return out if 'end' in out and 'now' in out else None     # cut short: a part reading must not look like a whole one


def _int(text, default=None):
    try:
        return int(str(text).strip())
    except (TypeError, ValueError):
        return default


def _parse_avc(line: str) -> dict | None:
    def field(name):
        m = re.search(rf'\b{name}="?([^" ]+)"?', line)
        return clean_text(m[1], 300) if m else None
    at = re.search(r'audit\((\d+)', line)
    action = re.search(r'denied\s+\{\s*([^}]*?)\s*\}', line)
    if not action:
        return None
    comm = field('comm')
    return {'at': int(at[1]) if at else None, 'daemon': comm, 'action': clean_text(action[1], 100), 'path': field('path') or field('name'),
            'scontext': field('scontext'), 'tcontext': field('tcontext'), 'storage': comm in STORAGE_DAEMONS}


def _parse_chrony(lines: list[str]) -> dict | None:
    if not lines or not lines[0].strip():
        return None
    f = lines[0].split(',')
    try:
        return {'source': clean_text(f[1], 100), 'stratum': int(f[2]), 'offset_ms': round(abs(float(f[4])) * 1000, 3), 'leap': clean_text(f[-1], 40),
                'synced': f[-1].strip() != 'Not synchronised'}
    except (IndexError, ValueError):
        return None


def _parse_aide(lines: list[str]) -> dict:
    out = {'baseline_at': None, 'last_action': None, 'last_at': None, 'exit_code': None, 'added': None, 'removed': None, 'changed': None, 'entries': []}
    for line in lines:
        w = line.split()
        if len(w) == 2 and w[0] == 'db':
            out['baseline_at'] = _int(w[1])
        elif len(w) == 3 and w[0] in ('init', 'check'):
            out.update(last_action=w[0], last_at=_int(w[1]), exit_code=_int(w[2]))
        elif (m := re.match(r'\s*(Added|Removed|Changed) (?:entries|files):\s*(\d+)', line)):
            out[m[1].lower()] = int(m[2])
        elif len(out['entries']) < 100 and re.search(r': /', line):
            out['entries'].append(clean_text(line, 300))
    return out


def _parse_lynis(lines: list[str]) -> dict | None:
    if not lines:
        return None
    out = {'at': None, 'hardening_index': None, 'warnings': [], 'suggestions': []}
    for line in lines:
        if line.startswith('at '):
            out['at'] = _int(line[3:])
        elif line.startswith('hardening_index='):
            out['hardening_index'] = _int(line.split('=', 1)[1])
        elif line.startswith(('warning[]=', 'suggestion[]=')):
            bucket = 'warnings' if line.startswith('w') else 'suggestions'
            f = line.split('=', 1)[1].split('|')
            out[bucket].append({'id': clean_text(f[0], 40), 'text': clean_text(f[1] if len(f) > 1 else '', 300), 'detail': clean_text(f[2], 200) if len(f) > 2 and f[2] not in ('-', '') else ''})
    return out


def parse_measure(text: str) -> dict | None:
    """One reading of a host. None unless the script ran to its end. Nothing is filled in: absent stays absent."""
    s = _sections(text)
    if s is None:
        return None
    host_now = _int(s['now'][0]) if s['now'] else None
    if host_now is None:
        return None
    tools = [t.strip() for t in s.get('tools', []) if t.strip()]
    booleans = []
    for line in s.get('sebool', []):
        m = re.match(r'(\S+) --> (on|off)$', line.strip())
        if m:
            booleans.append({'name': m[1], 'value': m[2], 'expected': EXPECTED_BOOLEANS.get(m[1]), 'ok': EXPECTED_BOOLEANS.get(m[1]) in (None, m[2])})
    apparmor = {'enabled': 'enabled' in [x.strip() for x in s.get('apparmor', [])], 'enforce': None, 'complain': None}
    for line in s.get('apparmor', []):
        w = line.split()
        if len(w) == 2 and w[0] in ('enforce', 'complain'):
            apparmor[w[0]] = _int(w[1])
    audit = [x.strip() for x in s.get('auditd', []) if x.strip()]
    sentinel = [x.strip() for x in s.get('sentinel', []) if x.strip()]
    fence = [x.strip() for x in s.get('fence', [])]
    sysctl = {}
    for line in s.get('sysctl', []):
        if '=' in line:
            k, v = line.split('=', 1)
            sysctl[k.strip()] = v.strip() or None
    canaries, btrfs, fcontext = {}, {}, []
    for line in s.get('canaries', []):
        f = line.split('\t')
        path = _b64text(f[0]) if len(f) == 2 else None
        if path:
            canaries[path] = None if f[1] == 'gone' else f[1]
    for line in s.get('holds_btrfs', []):
        f = line.split('\t')
        path = _b64text(f[0]) if len(f) == 2 else None
        if path:
            btrfs[path] = f[1].strip() == 'ro=true'
    for line in s.get('fcontext', []):
        f = line.split('\t')
        path = _b64text(f[0]) if len(f) == 3 else None
        if path and f[1]:
            live = (f[1].split(':') + [''] * 3)[2]
            want = (f[2].split(':') + [''] * 3)[2] if f[2] else None
            fcontext.append({'path': path, 'live': clean_text(live, 80), 'expected': clean_text(want, 80) if want else None, 'aligned': None if not want else live == want})
    ntp = dict(line.split('=', 1) for line in s.get('timedatectl', []) if '=' in line)
    falco = [x.strip() for x in s.get('falco', [])]
    return {
        'host_now': host_now,
        'uptime': _int(s['uptime'][0]) if s.get('uptime') else None,
        'tools': tools,
        'selinux': (s.get('selinux') or [None])[0],
        'booleans': booleans,
        'apparmor': apparmor,
        'avc': [a for a in map(_parse_avc, s.get('avc', [])) if a],
        'chrony': _parse_chrony(s.get('chrony', [])),
        'nts_sources': sum(1 for line in s.get('chrony_auth', []) if ',NTS,' in line),
        'ntp_synced': {'yes': True, 'no': False}.get(ntp.get('NTPSynchronized', '').strip()),
        'auditd': {'active': audit[0] == 'active' if audit else None, 'storageforge_rules': _int(audit[1]) if len(audit) > 1 else None},
        'fence': 'storageforge_fence' in fence,
        'airgap': 'storageforge_airgap' in fence,
        'quarantined': [q.strip() for q in s.get('quarantined', [])[:2000] if q.strip()],
        'sysctl': sysctl,
        'umask': next((m[1] for line in s.get('umask', []) if (m := re.match(r'umask (\d{3,4})$', line.strip()))), None),
        'aide': _parse_aide(s.get('aide', [])) if 'aide' in tools else None,
        'lynis': _parse_lynis(s.get('lynis', [])),
        'falco': {'installed': 'falco' in tools, 'active': 'active' in falco},
        'sentinel': {'active': bool(sentinel) and sentinel[0] == 'active', 'armed': any(x == 'ARMED=1' for x in sentinel)},
        'holds_zfs': [line.split('\t')[:2] for line in s.get('holds_zfs', []) if line.count('\t') == 1],
        'holds_btrfs': btrfs,
        'zfs_allow': [clean_text(x, 300) for x in s.get('zfs_allow', [])],
        'canaries': canaries,
        'fcontext': fcontext,
        'shadow_copy2_shares': _int((s.get('samba') or [None])[0]),
        'audit_rules': [clean_text(x, 300) for x in s.get('audit_rules', [])[:60]],
        'snapshots': [x.strip() for x in s.get('snapshots', [])[-500:] if ZFS_SNAP_RE.fullmatch(x.strip())],
        'sessions': _secplus().parse_sessions(s.get('sessions', [])),
        'falco_alerts': _secplus().parse_falco(s.get('falco_alerts', [])),
    }


def _secplus():
    from . import secplus
    return secplus


def freeze_clock(conn: Conn, host: str, reason: str, by: str, cause: str = 'jump'):
    """Releases stop on this host until someone looks. Only a person clears it: a good reading afterwards proves nothing,
    and neither does a reading from another host."""
    state = alerts.get_setting(conn, clock_key(host)) or {}
    if state.get('frozen'):
        return
    now = int(time.time())
    alerts.set_setting(conn, clock_key(host), {'frozen': True, 'reason': clean_text(reason), 'at': now, 'cause': cause}, by[:60])


def clear_clock(conn: Conn, host: str, actor: str) -> dict:
    name = known_host(conn, host)
    was = alerts.get_setting(conn, clock_key(name)) or {}
    alerts.set_setting(conn, clock_key(name), {'frozen': False, 'cleared_by': actor, 'cleared_at': int(time.time())}, actor)
    return {'ok': True, 'host': name, 'was_frozen': bool(was.get('frozen')), 'reason': was.get('reason')}


def clock_frozen(conn: Conn, host: str) -> bool:
    return bool((alerts.get_setting(conn, clock_key(host)) or {}).get('frozen'))


def _measure_inputs(conn: Conn, host: str) -> dict:
    holds = conn.all("""SELECT snapshot, filesystem FROM security_retention_holds WHERE lower(host) = lower(:h) AND status <> 'released'""", {'h': host})
    canaries = [r[0] for r in conn.all('SELECT path FROM security_canaries WHERE lower(host) = lower(:h)', {'h': host})]
    mounts = [r[0] for r in conn.all("""SELECT m.mount_point FROM mounts m JOIN hosts h ON h.host_id = m.host_id
                                        WHERE lower(h.hostname) = lower(:h) AND m.scan_state = 'indexed' ORDER BY m.mount_point LIMIT 100""", {'h': host})]
    return {'zfs_snaps': sorted({s for s, fs in holds if fs == 'zfs'}), 'btrfs_paths': sorted({s for s, fs in holds if fs == 'btrfs'}),
            'canaries': canaries, 'mounts': mounts}


def measure(db, conn: Conn, host, actor: str) -> dict:
    """Read the host now, through the runner. The only thing it changes is what we know."""
    name = known_host(conn, host)
    started = int(time.time())
    res = _run(db, name, sx.measure_script(**_measure_inputs(conn, name)), ref='measure', mode='report', actor=actor, timeout=300)
    finished = int(time.time())
    output = res.get('output') or ''
    if res['status'] == 'refused' and 'clocks differ' in output:     # the runner's own check caught it first
        freeze_clock(conn, name, 'the host refused a signed run because the clocks differ by more than the runner allows', 'measure')
    if res['status'] != 'ok':
        return _result(res, 'report', host=name)
    data = parse_measure(output)
    if data is None:
        return _result(res, 'report', 'the reading was cut short: nothing was recorded', host=name)
    ingest_events(conn, name, '\n'.join(_sections(output).get('events', [])), 'measure')
    store_measurement(conn, name, data, started, finished, 'measure')
    return {'ok': True, 'host': name, 'measured_at': finished, 'run_id': res.get('run_id')}


def store_measurement(conn: Conn, host: str, data: dict, started: int, finished: int, via: str):
    # The host's clock was read between these two moments, so anything outside them by more than the margin is real.
    off = 0 if started - CLOCK_JUMP <= data['host_now'] <= finished + CLOCK_JUMP else data['host_now'] - finished
    data['clock_offset'] = off
    if off:
        freeze_clock(conn, host, f'the clock on {host} and the controller differ by {off} s', via, 'offset')
    _save_measurement(conn, host, 'host', finished, via, data)
    _reconcile(conn, host, data, finished)
    _secplus().after_measure(conn, host, data, finished)


def _save_measurement(conn: Conn, host: str, kind: str, at: int, via: str, data: dict):
    conn.execute('DELETE FROM security_measurements WHERE host = :h AND kind = :k', {'h': host, 'k': kind})
    conn.execute('INSERT INTO security_measurements (host, kind, measured_at, via, data_json) VALUES (:h, :k, :t, :v, :d)',
                 {'h': host, 'k': kind, 't': at, 'v': via, 'd': json.dumps(data)})


def measurement(conn: Conn, host: str, kind: str = 'host') -> dict | None:
    rows = conn.all('SELECT measured_at, via, data_json FROM security_measurements WHERE lower(host) = lower(:h) AND kind = :k', {'h': host, 'k': kind})
    if not rows:
        return None
    return {**(loads(rows[0][2]) or {}), 'measured_at': rows[0][0], 'via': rows[0][1], 'stale': time.time() - rows[0][0] > STALE_AFTER}


def _reconcile(conn: Conn, host: str, data: dict, now: int):
    """What we recorded against what the host shows. Something gone that should be there is an alarm: that is what it looks
    like when someone with root has been at the holds or the decoys."""
    live = {(s, t) for s, t in data['holds_zfs']}
    for hid, snap, tag, fs, missing in conn.all("""SELECT id, snapshot, hold_tag, filesystem, missing_at FROM security_retention_holds
                                                   WHERE lower(host) = lower(:h) AND status <> 'released'""", {'h': host}):
        there = (snap, tag) in live if fs == 'zfs' else data['holds_btrfs'].get(snap) is True
        if there:
            conn.execute('UPDATE security_retention_holds SET verified_at = :t, missing_at = NULL WHERE id = :i', {'t': now, 'i': hid})
        elif not missing:
            conn.execute('UPDATE security_retention_holds SET missing_at = :t WHERE id = :i', {'t': now, 'i': hid})
            record_event(conn, host, 'hold_missing', f'the hold {tag} on {snap} is gone from the host', via='measure')
    for cid, path, sha, status in conn.all('SELECT id, path, sha256, status FROM security_canaries WHERE lower(host) = lower(:h)', {'h': host}):
        if path not in data['canaries']:
            continue
        seen = data['canaries'][path]
        if seen == sha:
            conn.execute('UPDATE security_canaries SET verified_at = :t WHERE id = :i', {'t': now, 'i': cid})
        elif status == 'armed':
            conn.execute("UPDATE security_canaries SET status = 'tripped', tripped_at = :t WHERE id = :i", {'t': now, 'i': cid})
            what = 'is gone' if seen is None else 'no longer matches what was written'
            record_event(conn, host, 'canary_tripped', f'{path} {what}', f'path_b64={sx.b64(path)};event=MEASURED', 'measure', now,
                         str(uuid.uuid5(uuid.NAMESPACE_URL, f'{host}:{path}:{seen}:{sha}')))


# ── retention holds and who may release them ─────────────────────────
def cool_off_hours(conn: Conn) -> int:
    h = _int(alerts.get_setting(conn, COOL_OFF), DEFAULT_COOL_OFF)
    return h if h in COOL_OFF_HOURS else DEFAULT_COOL_OFF


def set_cool_off(conn: Conn, hours, actor: str) -> dict:
    """It can only go up from here. Shortening it is what an attacker would do first."""
    h = _int(hours)
    if h not in COOL_OFF_HOURS:
        raise ValueError('the cool-off is 12, 24, 48 or 72 hours')
    if h < cool_off_hours(conn):
        raise ValueError(f'the cool-off cannot be shortened from here: it is {cool_off_hours(conn)} h')
    alerts.set_setting(conn, COOL_OFF, h, actor)
    return {'ok': True, 'hours': h}


def established_admins(conn: Conn, now: int | None = None) -> list[str]:
    """Admins old enough to count. An attacker who has one admin account could make a second and approve themselves,
    so an account counts only after it has existed for longer than the cool-off."""
    cutoff = (now or int(time.time())) - cool_off_hours(conn) * 3600
    return [r[0] for r in conn.all("SELECT username FROM users WHERE role = 'admin' AND disabled_at IS NULL AND created_at <= :c", {'c': cutoff})]


def _person(actor: str) -> str:
    """The account behind an actor: audit rows and timelocks say web:name, and accounts just name."""
    return str(actor).removeprefix('web:').lower()


def quorum_state(conn: Conn) -> dict:
    admins = established_admins(conn)
    dual, hours = len(admins) >= 2, cool_off_hours(conn)
    return {'mode': 'dual_admin' if dual else 'cool_off', 'label': f'Two admins must agree ({len(admins)} established)' if dual else f'One admin: {hours} h cool-off',
            'established_admins': len(admins), 'cool_off_hours': hours, 'break_glass_armed': bool(alerts.get_setting(conn, BREAK_GLASS))}


def _record_hold(conn: Conn, host: str, fs: str, snapshot: str, tag: str, expires: int | None, legal: bool, actor: str, now: int) -> int:
    """A hold can only get stronger here: a later date stands, a legal hold stays, and asking again shortens nothing."""
    rows = conn.all('SELECT id, expires_at, legal_hold FROM security_retention_holds WHERE lower(host) = lower(:h) AND snapshot = :s AND hold_tag = :t',
                    {'h': host, 's': snapshot, 't': tag})
    never = legal or expires is None
    if rows:
        hid, old_exp, old_legal = rows[0]
        keep_legal = bool(old_legal) or legal
        new_exp = None if keep_legal or never or old_exp is None else max(old_exp, expires)
        conn.execute("""UPDATE security_retention_holds SET expires_at = :e, legal_hold = :l, status = 'locked', verified_at = :t, missing_at = NULL WHERE id = :i""",
                     {'e': new_exp, 'l': 1 if keep_legal else 0, 't': now, 'i': hid})
        return hid
    return conn.scalar("""INSERT INTO security_retention_holds (host, snapshot, hold_tag, filesystem, created_at, expires_at, legal_hold, status, applied_by, verified_at)
                          VALUES (:h, :s, :t, :f, :c, :e, :l, 'locked', :a, :c) RETURNING id""",
                       {'h': host, 's': snapshot, 't': tag, 'f': fs, 'c': now, 'e': None if never else expires, 'l': 1 if legal else 0, 'a': actor})


def apply_hold(db, conn: Conn, body: dict, actor: str) -> dict:
    host, mode = known_host(conn, body.get('host')), _mode(body)
    snapshot = str(body.get('snapshot') or '').strip()
    if not ZFS_SNAP_RE.fullmatch(snapshot):
        snapshot = clean_path(snapshot, 'the snapshot (dataset@name, or a btrfs path)')
    legal = body.get('legal_hold') is True
    days = _int(body.get('retention_days'), 0) or 0
    if not legal and not 1 <= days <= 3650:
        raise ValueError('retention_days is 1 to 3650, or ask for a legal hold')
    tag = str(body.get('hold_tag') or ('sf-legal' if legal else f'sf-worm-{days}d'))
    if not TAG_RE.fullmatch(tag):
        raise ValueError('a hold tag starts with sf- and holds only letters, digits, ., _ and -')
    res, out = _act(db, host, sx.hold_script(snapshot, tag, body.get('create') is True), mode, f'hold:{snapshot}'[:200], actor, r'^HELD ')
    out.update(host=host, snapshot=snapshot, hold_tag=tag)
    if res and mode == 'apply' and out['ok']:
        fs = re.search(r'^HELD (zfs|btrfs) ', res['output'], re.M)[1]
        now = int(time.time())
        out['hold_id'] = _record_hold(conn, host, fs, snapshot, tag, now + days * 86400, legal, actor, now)
    return out


def hold_rows(conn: Conn, host: str | None = None) -> list[dict]:
    rows = conn.all(f"""SELECT id, host, snapshot, hold_tag, filesystem, created_at, expires_at, legal_hold, status, applied_by, verified_at, missing_at
                        FROM security_retention_holds {'WHERE lower(host) = lower(:h)' if host else ''} ORDER BY created_at DESC LIMIT 1000""", {'h': host})
    keys = ('id', 'host', 'snapshot', 'hold_tag', 'filesystem', 'created_at', 'expires_at', 'legal_hold', 'status', 'applied_by', 'verified_at', 'missing_at')
    now = int(time.time())
    out = [dict(zip(keys, r)) for r in rows]
    for h in out:
        h['legal_hold'] = bool(h['legal_hold'])
        h['expired'] = bool(h['expires_at'] and h['expires_at'] <= now and not h['legal_hold'])
    return out


def _timelocks(conn: Conn, host: str | None = None, status: str = 'pending') -> list[dict]:
    where = ['status = :st'] + (["(host = '' OR lower(host) = lower(:h))"] if host else [])
    rows = conn.all(f"""SELECT id, action, target_ref, host, actor, mode, requested_at, executes_at, status, decided_by, decided_at, break_glass_used, detail_json, output
                        FROM security_timelock_queue WHERE {' AND '.join(where)} ORDER BY requested_at DESC LIMIT 200""", {'st': status, 'h': host})
    keys = ('id', 'action', 'target_ref', 'host', 'actor', 'mode', 'requested_at', 'executes_at', 'status', 'decided_by', 'decided_at', 'break_glass_used', 'detail', 'output')
    out = [dict(zip(keys, r)) for r in rows]
    now = int(time.time())
    for t in out:
        t['detail'] = loads(t['detail']) or {}
        t['break_glass_used'] = bool(t['break_glass_used'])
        t['remaining_seconds'] = max(0, t['executes_at'] - now) if t['mode'] == 'cool_off' else None
    return out


def worm_view(conn: Conn, host: str | None = None) -> dict:
    holds = hold_rows(conn, host)
    active = [h for h in holds if h['status'] != 'released']
    now = int(time.time())
    return {
        'holds': holds,
        'summary': {'active': len(active), 'verified': sum(1 for h in active if h['verified_at'] and not h['missing_at']),
                    'missing': sum(1 for h in active if h['missing_at']), 'legal': sum(1 for h in active if h['legal_hold']),
                    'expired': sum(1 for h in active if h['expired']),
                    'expiring_24h': sum(1 for h in active if h['expires_at'] and 0 < h['expires_at'] - now <= 86400 and not h['legal_hold'])},
        'quorum': quorum_state(conn),
        'pending': _timelocks(conn, host),
        'clock': clock_view(conn, host) if host else None,
    }


def clock_view(conn: Conn, host: str) -> dict:
    state = alerts.get_setting(conn, clock_key(host)) or {}
    m = measurement(conn, host)
    out = {'frozen': bool(state.get('frozen')), 'reason': state.get('reason'), 'frozen_at': state.get('at'), 'measured_at': None, 'offset_seconds': None,
           'chrony': None, 'nts_sources': None, 'ntp_synced': None, 'stale': None}
    if m:
        out.update(measured_at=m['measured_at'], offset_seconds=m.get('clock_offset'), chrony=m.get('chrony'), nts_sources=m.get('nts_sources'),
                   ntp_synced=m.get('ntp_synced'), stale=m['stale'])
    return out


def request_release(db, conn: Conn, body: dict, actor: str) -> dict:
    """Asking starts the wait; it releases nothing. A hold past its date needs no wait. A legal hold has to be named as one."""
    rows = conn.all('SELECT id, host, snapshot, hold_tag, status, legal_hold, expires_at FROM security_retention_holds WHERE id = :i', {'i': _int(body.get('hold_id'), 0)})
    if not rows:
        raise LookupError('no such hold')
    hid, host, snap, tag, status, legal, expires = rows[0]
    if status != 'locked':
        return {'ok': False, 'host': host, 'error': f'this hold is {status}'}
    if clock_frozen(conn, host):
        return {'ok': False, 'host': host, 'error': f'the clock guard has stopped releases on {host}: look at why, then clear it'}
    if legal and body.get('release_legal') is not True:
        return {'ok': False, 'host': host, 'error': 'this is a legal hold: say so explicitly to ask for its release'}
    now = int(time.time())
    if expires and expires <= now and not legal:
        return _execute_release(db, conn, {'id': None, 'host': host, 'detail': {'hold_id': hid, 'snapshot': snap, 'hold_tag': tag}}, actor)
    q = quorum_state(conn)
    executes = now if q['mode'] == 'dual_admin' else now + q['cool_off_hours'] * 3600
    tid = conn.scalar("""INSERT INTO security_timelock_queue (action, target_ref, host, actor, mode, requested_at, executes_at, status, detail_json)
                         VALUES ('worm_release', :ref, :h, :a, :m, :r, :e, 'pending', :d) RETURNING id""",
                      {'ref': f'{snap}#{tag}', 'h': host, 'a': actor, 'm': q['mode'], 'r': now, 'e': executes,
                       'd': json.dumps({'hold_id': hid, 'snapshot': snap, 'hold_tag': tag})})
    conn.execute("UPDATE security_retention_holds SET status = 'release_pending' WHERE id = :i", {'i': hid})
    return {'ok': True, 'host': host, 'timelock_id': tid, 'mode': q['mode'], 'executes_at': executes if q['mode'] == 'cool_off' else None,
            'message': 'waiting for a second admin' if q['mode'] == 'dual_admin' else f'releases in {q["cool_off_hours"]} h unless someone aborts it'}


def _execute_release(db, conn: Conn, t: dict, actor: str) -> dict:
    d = t['detail']
    res = _run(db, t['host'], sx.release_script(d['snapshot'], d['hold_tag']), ['--apply'], ref=f'release:{d["snapshot"]}'[:200], mode='apply', actor=actor)
    done = res['status'] in deploy.FINISHED and 'RELEASED ' in (res.get('output') or '')
    now = int(time.time())
    conn.execute(f"UPDATE security_retention_holds SET status = '{'released' if done else 'locked'}', legal_hold = CASE WHEN :r = 1 THEN 0 ELSE legal_hold END WHERE id = :i",
                 {'i': d['hold_id'], 'r': 1 if done else 0})
    if t.get('id'):
        conn.execute('UPDATE security_timelock_queue SET status = :s, decided_by = COALESCE(decided_by, :a), decided_at = :t, output = :o WHERE id = :i',
                     {'s': 'executed' if done else 'failed', 'a': actor, 't': now, 'o': (res.get('output') or '')[-20000:], 'i': t['id']})
    return _result(res, 'apply', None if done else 'the hold is still on the host: see the output', host=t['host'], timelock_id=t.get('id'), status_after='released' if done else 'locked')


def _pending(conn: Conn, tid) -> dict | None:
    rows = _timelocks(conn)
    return next((t for t in rows if t['id'] == _int(tid, 0)), None)


def approve(db, conn: Conn, body: dict, actor: str) -> dict:
    t = _pending(conn, body.get('timelock_id'))
    if not t:
        raise LookupError('nothing is waiting under that id')
    if t['mode'] != 'dual_admin':
        return {'ok': False, 'host': t['host'], 'error': f'this is waiting out a cool-off: nobody can approve it early. It runs in {t["remaining_seconds"]} s, or use the offline key'}
    if _person(t['actor']) == _person(actor):
        return {'ok': False, 'host': t['host'], 'error': 'a second admin has to approve this, not the one who asked'}
    if _person(actor) not in {a.lower() for a in established_admins(conn)}:
        return {'ok': False, 'host': t['host'], 'error': 'your account is too new to approve this'}
    if t['host'] and clock_frozen(conn, t['host']):
        return {'ok': False, 'host': t['host'], 'error': f'the clock guard has stopped releases on {t["host"]}'}
    conn.execute('UPDATE security_timelock_queue SET decided_by = :a, decided_at = :t WHERE id = :i', {'a': actor, 't': int(time.time()), 'i': t['id']})
    if t['action'] == 'worm_release':
        return _execute_release(db, conn, t, actor)
    return {'ok': True, 'host': t['host'], 'timelock_id': t['id'], 'message': 'approved'}


def abort(conn: Conn, body: dict, actor: str) -> dict:
    t = _pending(conn, body.get('timelock_id'))
    if not t:
        raise LookupError('nothing is waiting under that id')
    conn.execute("UPDATE security_timelock_queue SET status = 'aborted', decided_by = :a, decided_at = :t WHERE id = :i", {'a': actor, 't': int(time.time()), 'i': t['id']})
    if t['detail'].get('hold_id'):
        conn.execute("UPDATE security_retention_holds SET status = 'locked' WHERE id = :i AND status = 'release_pending'", {'i': t['detail']['hold_id']})
    return {'ok': True, 'host': t['host'], 'timelock_id': t['id'], 'status_after': 'aborted'}


def break_glass_status(conn: Conn) -> dict:
    return {'armed': bool(alerts.get_setting(conn, BREAK_GLASS))}


def mint_break_glass(conn: Conn, actor: str) -> dict:
    """The first key anyone may make. A new one replaces the old, so it waits out the same timelock it could otherwise skip:
    if an admin account alone could mint a key, the key would protect nothing from that account."""
    now = int(time.time())
    if alerts.get_setting(conn, BREAK_GLASS):
        due = [t for t in _timelocks(conn) if t['action'] == 'break_glass_rotate' and _person(t['actor']) == _person(actor)
               and ((t['mode'] == 'cool_off' and t['executes_at'] <= now) or (t['mode'] == 'dual_admin' and t['decided_by']))]
        if not due:
            mine = [t for t in _timelocks(conn) if t['action'] == 'break_glass_rotate']
            if mine:
                return {'ok': False, 'error': 'a replacement is already waiting', 'timelock_id': mine[0]['id']}
            q = quorum_state(conn)
            executes = now if q['mode'] == 'dual_admin' else now + q['cool_off_hours'] * 3600
            tid = conn.scalar("""INSERT INTO security_timelock_queue (action, target_ref, host, actor, mode, requested_at, executes_at, status)
                                 VALUES ('break_glass_rotate', 'offline key', '', :a, :m, :r, :e, 'pending') RETURNING id""",
                              {'a': actor, 'm': q['mode'], 'r': now, 'e': executes})
            return {'ok': True, 'requested': True, 'timelock_id': tid, 'mode': q['mode'], 'executes_at': executes,
                    'message': 'a second admin has to approve replacing the key' if q['mode'] == 'dual_admin' else f'you can make the new key in {q["cool_off_hours"]} h'}
        conn.execute("UPDATE security_timelock_queue SET status = 'executed', decided_at = :t, decided_by = COALESCE(decided_by, :a) WHERE id = :i", {'t': now, 'a': actor, 'i': due[0]['id']})
    key = secrets.token_hex(32)
    alerts.set_setting(conn, BREAK_GLASS, hashlib.sha256(key.encode()).hexdigest(), actor)
    return {'ok': True, 'break_glass_key': key, 'message': 'Print this and lock it away. It is not stored and will not be shown again.'}


def use_break_glass(db, conn: Conn, body: dict, actor: str) -> dict:
    """The offline key skips the wait and the second admin, for one release, loudly. It does not skip the clock guard."""
    key = str(body.get('break_glass_key') or '').strip()
    t = _pending(conn, body.get('timelock_id'))
    if not t or t['action'] != 'worm_release':
        raise LookupError('no release is waiting under that id')
    stored = alerts.get_setting(conn, BREAK_GLASS)
    if not stored or not secrets.compare_digest(str(stored), hashlib.sha256(key.encode()).hexdigest()):
        return {'ok': False, 'host': t['host'], 'error': 'that is not the offline key'}
    if clock_frozen(conn, t['host']):
        return {'ok': False, 'host': t['host'], 'error': f'the clock guard has stopped releases on {t["host"]}: clear it first'}
    conn.execute('UPDATE security_timelock_queue SET break_glass_used = 1, decided_by = :a, decided_at = :t WHERE id = :i', {'a': actor, 't': int(time.time()), 'i': t['id']})
    record_event(conn, t['host'], 'break_glass_used', f'{actor} used the offline key to release {t["target_ref"]}')
    return _execute_release(db, conn, t, actor)


# ── what runs without anyone asking ──────────────────────────────────
_clock_seen: list[tuple[float, float]] = []


def _controller_clock_ok(conn: Conn) -> bool:
    """A cool-off is measured on this machine's clock, so moving that clock would end one early. Boot time keeps counting
    through a suspend and cannot be set: if the wall clock runs away from it, nothing executes until someone looks."""
    if (alerts.get_setting(conn, CONTROLLER_CLOCK) or {}).get('frozen'):
        return False
    wall, boot = time.time(), time.clock_gettime(time.CLOCK_BOOTTIME)
    if _clock_seen:
        moved = abs((wall - _clock_seen[0][0]) - (boot - _clock_seen[0][1]))
        if moved > CLOCK_JUMP:
            alerts.set_setting(conn, CONTROLLER_CLOCK, {'frozen': True, 'reason': f'this machine\'s clock moved {int(moved)} s', 'at': int(wall)}, 'system')
            return False
    _clock_seen[:] = [(wall, boot)]
    return True


def controller_clock_suspect(conn: Conn) -> dict | None:
    """Each host is compared only with this machine, so a wrong clock here looks like every host being wrong. Several hosts
    off by the same amount, and the most of them at that, points back here: unrelated clocks do not drift in step."""
    now = int(time.time())
    offsets = [(loads(d) or {}).get('clock_offset') or 0 for d, at in conn.all("SELECT data_json, measured_at FROM security_measurements WHERE kind = 'host'") if now - at <= STALE_AFTER]
    off = [o for o in offsets if o]
    if len(off) < 2:
        return None
    middle = statistics.median(off)
    agree = sum(1 for o in off if abs(o - middle) <= 10)
    if agree < 2 or agree * 2 <= len(offsets):
        return None
    return {'seconds': abs(int(middle)), 'direction': 'behind' if middle > 0 else 'ahead', 'agree': agree, 'measured': len(offsets)}


def clear_controller_clock(conn: Conn, actor: str) -> dict:
    """A person saying this machine's clock was the trouble, and is right now. So hosts frozen only for differing from it go
    too. A host whose own clock jumped stays frozen: that is about the host."""
    alerts.set_setting(conn, CONTROLLER_CLOCK, {'frozen': False, 'cleared_by': actor, 'cleared_at': int(time.time())}, actor)
    _clock_seen.clear()
    cleared = []
    for key, value in conn.all("SELECT key, value_json FROM settings WHERE key LIKE 'security.clock:%'"):
        state = loads(value) or {}
        if state.get('frozen') and state.get('cause') == 'offset':
            alerts.set_setting(conn, key, {'frozen': False, 'cleared_by': actor, 'cleared_at': int(time.time())}, actor)
            cleared.append(key.split(':', 1)[1])
    return {'ok': True, 'hosts_cleared': cleared}


def tick(db) -> dict:
    """Once a minute. Each part stands alone: one unreachable host must not hold up the rest."""
    from . import errlog
    conn = db.connect()
    done = {'released': 0, 'measured': 0}
    try:
        now = int(time.time())
        # a dual-admin request whose second admin has gone would wait forever: it falls back to the cool-off from when it was asked
        if len(established_admins(conn)) < 2:
            conn.execute("""UPDATE security_timelock_queue SET mode = 'cool_off', executes_at = requested_at + :c
                            WHERE status = 'pending' AND mode = 'dual_admin' AND decided_by IS NULL""", {'c': cool_off_hours(conn) * 3600})
        clock_ok = _controller_clock_ok(conn) and not controller_clock_suspect(conn)
        if clock_ok:
            for t in _timelocks(conn):
                if t['action'] == 'worm_release' and t['mode'] == 'cool_off' and t['executes_at'] <= now and not clock_frozen(conn, t['host']):
                    try:
                        if _execute_release(db, conn, t, f'timelock (asked by {t["actor"]})')['ok']:
                            done['released'] += 1
                    except Exception:
                        errlog.trace()
        conn.execute('DELETE FROM security_quarantine WHERE expires_at IS NOT NULL AND expires_at <= :t', {'t': now})    # the kernel already let them go
        prune_events(conn, now)
        want = {d['host'] for d in deploy.deployed(conn, kind='security')} | {r[0] for r in conn.all("SELECT DISTINCT host FROM security_retention_holds WHERE status <> 'released'")}
        # with this machine's clock in doubt, every host would look wrong against it, and be frozen for it
        for host in sorted(want) if clock_ok else ():
            m = conn.scalar("SELECT measured_at FROM security_measurements WHERE host = :h AND kind = 'host'", {'h': host})
            if deploy.ready(conn, host) and (m is None or now - m >= MEASURE_EVERY):
                try:
                    if measure(db, conn, host, 'system')['ok']:
                        done['measured'] += 1
                except Exception:
                    errlog.trace()
    finally:
        conn.close()
    try:
        done.update(_secplus().tick(db))
    except Exception:
        errlog.trace()
    return done


# ── decoys and the sentinel ──────────────────────────────────────────
def sentinel_config(conn: Conn, host: str) -> dict:
    saved = alerts.get_setting(conn, host_key(host)) or {}
    return {'folders': saved.get('folders') or [], 'names': saved.get('names') or list(DEFAULT_DECOYS), 'armed': bool(saved.get('armed')),
            'actions': saved.get('actions') or list(sx.BRAKE_ACTIONS), 'minutes': saved.get('minutes', 60),
            'spread': saved.get('spread') or 'root', 'paths': saved.get('paths') or []}


SPREADS = ('root', 'top', 'random', 'recent')


def spread_folders(conn: Conn, host: str, folders: list[str], how: str) -> list[str]:
    """Where decoys go inside each folder, from the index. root: only there. top: its first level too. random: some folders further
    down, the same ones each time for this host. recent: folders the last scan saw change, where encryption would start."""
    if how == 'root':
        return list(folders)
    out = list(folders)
    for root in folders:
        prefix = root.rstrip('/') + '/'
        if how == 'recent':
            scans = _latest_scans(conn, host, 1)
            rows = conn.all('SELECT DISTINCT parent_path FROM file_changes WHERE scan_id = :s AND parent_path LIKE :p LIMIT 500', {'s': scans[0]['id'], 'p': prefix + '%'}) if scans else []
            found = sorted(r[0] for r in rows)
        else:
            rows = conn.all("""SELECT d.path FROM directories d JOIN mounts m ON m.mount_id = d.mount_id JOIN hosts h ON h.host_id = m.host_id
                                WHERE lower(h.hostname) = lower(:h) AND d.path LIKE :p LIMIT 5000""", {'h': host, 'p': prefix + '%'})
            found = sorted(r[0] for r in rows)
            if how == 'top':
                found = [d for d in found if '/' not in d[len(prefix):]]
            else:
                found = sorted(found, key=lambda d: hashlib.sha256(f'{host}:{d}'.encode()).hexdigest())[:40]
        out += [d for d in found if '/.' not in d[len(prefix) - 1:]]
    return sorted(set(out))


def decoy_name(pattern: str, folder: str) -> str:
    """{Dept} is the folder's own name and {Year} this year, so a decoy looks like it belongs where it is."""
    dept = re.sub(r'[^A-Za-z0-9_-]', '', folder.rstrip('/').rsplit('/', 1)[-1]).capitalize() or 'Share'
    return pattern.replace('{Dept}', dept).replace('{Year}', time.strftime('%Y'))


def suggested_folders(conn: Conn, host: str) -> list[str]:
    from .shares import design_exports
    try:
        return sorted({str(e['path']) for e in design_exports(conn, host) if str(e.get('path') or '').startswith('/')})
    except Exception:           # a design that cannot be read suggests nothing; it must not stop this panel
        return []


def save_sentinel_config(conn: Conn, host, body: dict, actor: str) -> dict:
    """What the next deploy installs. Saving changes nothing on the host. Arming is off until someone turns it on, since
    an armed sentinel freezes shares by itself on the strength of one changed file."""
    name = known_host(conn, host)
    cur = alerts.get_setting(conn, host_key(name)) or {}
    folders = sorted({clean_path(p, 'a folder') for p in body.get('folders') or []})
    names = [str(n) for n in (body.get('names') or DEFAULT_DECOYS)]
    for n in names:
        if not n or len(n) > 100 or n != n.strip() or '/' in n or n in ('.', '..') or any(ord(c) < 32 or ord(c) == 127 for c in n):
            raise ValueError(f'not a file name: {n[:40]!r}')
    spread = str(body.get('spread') or 'root')
    if spread not in SPREADS:
        raise ValueError('spread is one of ' + ', '.join(SPREADS))
    expanded = spread_folders(conn, name, folders, spread)
    if len(expanded) * len(names) > MAX_DECOYS:
        raise ValueError(f'that is more than {MAX_DECOYS} decoys')
    paths = [f'{d.rstrip("/")}/{decoy_name(n, d)}' for d in expanded for n in names]
    body = {**body, '_spread': {'spread': spread, 'paths': paths}}
    actions = [a for a in sx.BRAKE_ACTIONS if a in (body.get('actions') or sx.BRAKE_ACTIONS)]
    minutes = _int(body.get('minutes'), 60)
    if minutes is None or not 0 <= minutes <= 525600:
        raise ValueError('minutes is 0 (until lifted) to 525600')
    alerts.set_setting(conn, host_key(name), {**cur, **body['_spread'], 'host': name, 'folders': folders, 'names': names, 'armed': body.get('armed') is True, 'actions': actions, 'minutes': minutes}, actor)
    return {'ok': True, 'host': name, **sentinel_config(conn, name)}


def decoy_paths(config: dict) -> list[str]:
    return config.get('paths') or [f'{d.rstrip("/")}/{n}' for d in config['folders'] for n in config['names']]


def vip_list(conn: Conn) -> list[str]:
    return list(alerts.get_setting(conn, VIP) or [])


def save_vips(conn: Conn, values, actor: str) -> dict:
    nets = sorted({str(ipaddress.ip_network(str(v).strip(), strict=False)) for v in values or [] if str(v).strip()})
    alerts.set_setting(conn, VIP, nets, actor)
    return {'ok': True, 'vips': nets}


def digest(conn: Conn, host: str) -> str:
    """What a deploy is made from, to tell whether a dry run still describes it. The report token is new each time, and left out."""
    name = deploy.canonical(conn, host)
    return hashlib.sha256(json.dumps([sentinel_config(conn, name), vip_list(conn), alerts.get_setting(conn, 'report_url')], sort_keys=True).encode()).hexdigest()[:16]


def _install(conn: Conn, host: str, token: str = '', rearm: bool = False) -> str:
    from .jobs import report_ca
    cfg = sentinel_config(conn, host)
    url = (alerts.get_setting(conn, 'report_url') or '').rstrip('/')
    return sx.install_script(decoys=decoy_paths(cfg), armed=cfg['armed'], actions=cfg['actions'], minutes=cfg['minutes'], report_url=url if token else '', token=token,
                             vips=vip_list(conn) + _controller_ips(conn, host), report_ca=report_ca(url), rearm=rearm)


def deploy_items(db, conn: Conn, host: str, mode: str, actor: str, remove: bool = False, rearm: bool = False) -> list[dict]:
    name = known_host(conn, host)
    cfg = sentinel_config(conn, name)
    if not remove and not cfg['folders']:
        raise ValueError(f'say which folders on {name} get decoys first')
    if mode != 'apply':
        return [{'host': name, 'script': _install(conn, name, rearm=rearm), 'args': [], 'kind': 'security', 'ref': name, 'mode': 'report'}]
    token = secrets.token_urlsafe(32) if not remove and alerts.get_setting(conn, 'report_url') else ''

    def done(res):
        c = db.connect()
        try:
            if remove:
                c.execute("DELETE FROM deployed WHERE host = :h AND kind = 'security'", {'h': name})
                c.execute('DELETE FROM security_canaries WHERE lower(host) = lower(:h)', {'h': name})
                saved = alerts.get_setting(c, host_key(name)) or {}
                saved.pop('token_sha', None)
                alerts.set_setting(c, host_key(name), saved, actor)
                return
            record_decoys(c, name, res.get('output') or '')
            if token:
                saved = alerts.get_setting(c, host_key(name)) or {}
                alerts.set_setting(c, host_key(name), {**saved, 'host': name, 'token_sha': hashlib.sha256(token.encode()).hexdigest()}, actor)
            deploy.mark_deployed(c, name, 'security', 'security', digest(c, name), {'armed': cfg['armed'], 'decoys': len(decoy_paths(cfg))}, actor)
        finally:
            c.close()
    return [{'host': name, 'script': _install(conn, name, token, rearm), 'args': ['--uninstall' if remove else '--apply'], 'kind': 'security', 'ref': name, 'mode': 'apply', 'on_ok': done}]


def record_decoys(conn: Conn, host: str, output: str):
    """The decoys the deploy says it wrote, with the hashes it read back. A decoy it did not confirm is not a decoy."""
    now = int(time.time())
    seen = []
    for line, sha, size in re.findall(r'^CANARY (\S+) ([0-9a-f]{64}) (\d+)$', output, re.M):
        path = _b64text(line)
        if not path:
            continue
        seen.append(path)
        rows = conn.all('SELECT id, sha256 FROM security_canaries WHERE lower(host) = lower(:h) AND path = :p', {'h': host, 'p': path})
        if rows and rows[0][1] == sha:
            conn.execute("UPDATE security_canaries SET verified_at = :t WHERE id = :i", {'t': now, 'i': rows[0][0]})
        elif rows:
            conn.execute("UPDATE security_canaries SET sha256 = :s, size = :z, deployed_at = :t, status = 'armed', tripped_at = NULL, verified_at = :t WHERE id = :i",
                         {'s': sha, 'z': int(size), 't': now, 'i': rows[0][0]})
        else:
            conn.execute("""INSERT INTO security_canaries (host, path, sha256, size, deployed_at, status, verified_at)
                            VALUES (:h, :p, :s, :z, :t, 'armed', :t)""", {'h': host, 'p': path, 's': sha, 'z': int(size), 't': now})
    for cid, path in conn.all('SELECT id, path FROM security_canaries WHERE lower(host) = lower(:h)', {'h': host}):
        if path not in seen:
            conn.execute('DELETE FROM security_canaries WHERE id = :i', {'i': cid})


def canaries_view(conn: Conn, host: str | None = None) -> dict:
    rows = conn.all(f"""SELECT id, host, path, sha256, size, deployed_at, status, tripped_at, verified_at FROM security_canaries
                        {'WHERE lower(host) = lower(:h)' if host else ''} ORDER BY host, path LIMIT 2000""", {'h': host})
    keys = ('id', 'host', 'path', 'sha256', 'size', 'deployed_at', 'status', 'tripped_at', 'verified_at')
    decoys = [dict(zip(keys, r)) for r in rows]
    out = {'canaries': decoys, 'summary': {'armed': sum(1 for c in decoys if c['status'] == 'armed'), 'tripped': sum(1 for c in decoys if c['status'] == 'tripped')},
           'report_url': bool(alerts.get_setting(conn, 'report_url'))}
    if host:
        m = measurement(conn, host)
        marks = deploy.deployed(conn, host=deploy.canonical(conn, host), kind='security')
        out.update(config=sentinel_config(conn, host), suggested=suggested_folders(conn, host), installed=bool(marks), deploy_ready=deploy.ready(conn, host),
                   out_of_date=bool(marks) and marks[0]['hash'] != digest(conn, host), sentinel=(m or {}).get('sentinel'), auditd=(m or {}).get('auditd'),
                   tools=(m or {}).get('tools'), shadow_copy2_shares=(m or {}).get('shadow_copy2_shares'), measured_at=(m or {}).get('measured_at'), audit_rules=(m or {}).get('audit_rules') or [],
                   last_test=next((e for e in list_events(conn, host, 50) if e['kind'] == 'sentinel_test'), None))
    return out


def test_sentinel(db, conn: Conn, body: dict, actor: str) -> dict:
    """A real write to a file only the sentinel cares about, timed until the event appears. No brake, no alarm."""
    name = known_host(conn, body.get('host'))
    res = _run(db, name, _install(conn, name), ['--test'], ref='sentinel-test', mode='report', actor=actor, timeout=60)
    m = re.search(r'^LATENCY (\d+)$', res.get('output') or '', re.M)
    return _result(res, 'report', None if m else 'the sentinel did not react', host=name, latency_ms=int(m[1]) if m else None)


# ── access control ───────────────────────────────────────────────────
def mac_view(conn: Conn, host: str) -> dict:
    m = measurement(conn, host)
    if not m:
        return {'host': host, 'measured_at': None}
    aa = m.get('apparmor') or {}
    framework = 'selinux' if m.get('selinux') else 'apparmor' if aa.get('enabled') else None
    return {'host': host, 'measured_at': m['measured_at'], 'stale': m['stale'], 'framework': framework, 'selinux_mode': m.get('selinux'), 'apparmor': aa,
            'booleans': m.get('booleans') or [], 'fcontext': m.get('fcontext') or [], 'avc': _secplus().mark_avc(conn, m.get('avc') or []), 'se_types': SE_TYPES,
            'context_map': _secplus().context_map(conn), 'context_drift': _secplus().context_drift(conn, host, m.get('fcontext') or []), 'noise_rules': _secplus().avc_noise(conn)}


def remediate_mac(db, conn: Conn, body: dict, actor: str) -> dict:
    host, mode = known_host(conn, body.get('host')), _mode(body)
    boolean = body.get('boolean')
    if boolean:
        if boolean not in EXPECTED_BOOLEANS:
            raise ValueError(f'only these booleans: {", ".join(EXPECTED_BOOLEANS)}')
        value = 'on' if body.get('value') in (True, 'on') else 'off'
        _, out = _act(db, host, sx.boolean_script(boolean, value), mode, f'boolean:{boolean}', actor)
        return {**out, 'host': host}
    path, se_type = clean_path(body.get('path')), str(body.get('type') or '')
    if se_type not in SE_TYPES or not SE_TYPE_RE.fullmatch(se_type):
        raise ValueError(f'the type is one of {", ".join(SE_TYPES)}')
    if path in ('/', '/etc', '/usr', '/var', '/boot', '/root', '/home'):
        raise ValueError(f'relabelling {path} would break the host')
    _, out = _act(db, host, sx.relabel_script(path, se_type), mode, f'relabel:{path}'[:200], actor)
    return {**out, 'host': host, 'path': path, 'type': se_type}


# ── firewall ─────────────────────────────────────────────────────────
def _controller_ips(conn: Conn, host: str) -> list[str]:
    """The address this machine would reach the host from. Connecting a UDP socket picks the route and sends nothing. Behind
    NAT the host sees something else, so scripts also ask the host who is really on the other end of their own SSH session."""
    try:
        addr = connect_address(conn, host)
        info = socket.getaddrinfo(addr, 22, type=socket.SOCK_DGRAM)[0]
        with socket.socket(info[0], socket.SOCK_DGRAM) as s:
            s.connect(info[4])
            return [ipaddress.ip_address(s.getsockname()[0]).compressed]
    except (OSError, ValueError):
        return []


def clean_target(conn: Conn, host: str, raw) -> str:
    """A single address or a sane network that is none of the machines this fleet cannot do without."""
    text = str(raw or '').strip()
    try:
        net = ipaddress.ip_network(text, strict=False)
    except ValueError:
        raise ValueError(f'not an IP address or network: {text[:60]}') from None
    if net.prefixlen < MIN_CIDR[net.version]:
        raise ValueError(f'/{net.prefixlen} is too wide to quarantine (at most /{MIN_CIDR[net.version]})')
    if net.is_loopback or net.is_unspecified or net.is_multicast or net.is_link_local:
        raise ValueError(f'{net} cannot be quarantined')
    for raw_vip in vip_list(conn) + _controller_ips(conn, host):
        vip = ipaddress.ip_network(raw_vip, strict=False)
        if vip.version == net.version and vip.overlaps(net):
            raise ValueError(f'{net} covers {vip}, which is on the exempt list or is how StorageForge reaches this host')
    return str(net.network_address) if net.prefixlen == net.max_prefixlen else str(net)


def firewall_view(conn: Conn, host: str | None = None) -> dict:
    now = int(time.time())
    rows = conn.all(f"""SELECT id, host, ip_address, reason, added_at, expires_at, actor FROM security_quarantine
                        {'WHERE lower(host) = lower(:h)' if host else ''} ORDER BY added_at DESC LIMIT 1000""", {'h': host})
    m = measurement(conn, host) if host else None
    live = set((m or {}).get('quarantined') or [])
    entries = [{'id': i, 'host': h, 'ip_address': ip, 'reason': r, 'added_at': a, 'expires_at': e, 'actor': who,
                'remaining_seconds': None if e is None else max(0, e - now), 'live': (ip in live) if m else None}
               for i, h, ip, r, a, e, who in rows if e is None or e > now]
    tools = (m or {}).get('tools') or []
    return {'quarantine': entries, 'vips': vip_list(conn), 'controller': _controller_ips(conn, host) if host else [], 'measured_at': (m or {}).get('measured_at'),
            'fence_present': (m or {}).get('fence'), 'airgap': (m or {}).get('airgap'), 'unknown_drops': sorted(live - {e['ip_address'] for e in entries}),
            'firewalls': [t for t in ('nft', 'firewall-cmd', 'ufw', 'iptables') if t in tools]}


def quarantine(db, conn: Conn, body: dict, actor: str) -> dict:
    host, mode = known_host(conn, body.get('host')), _mode(body)
    ip = clean_target(conn, host, body.get('ip_address'))
    tier = _int(body.get('tier'))
    if tier is not None:                                # a repeat offender goes up a tier by itself
        if tier not in (1, 2, 3):
            raise ValueError('a tier is 1, 2 or 3')
        tier = _secplus().next_tier(conn, host, ip, tier)
        minutes = _secplus().ban_minutes(conn, tier)
    else:
        minutes = _int(body.get('minutes'), 60)
    if minutes is None or not 0 <= minutes <= 525600:
        raise ValueError('minutes is 0 (until lifted) to 525600')
    reason = clean_text(body.get('reason') or 'by hand', 200)
    res, out = _act(db, host, sx.quarantine_script(ip, minutes * 60), mode, f'quarantine:{ip}', actor, rf'^QUARANTINED {re.escape(ip)}$')
    out.update(host=host, ip_address=ip, tier=tier, minutes=minutes)
    if res and mode == 'apply' and out['ok']:
        now = int(time.time())
        _secplus().record_ban(conn, host, ip, tier or 0, reason)
        conn.execute('DELETE FROM security_quarantine WHERE lower(host) = lower(:h) AND ip_address = :ip', {'h': host, 'ip': ip})
        conn.execute("""INSERT INTO security_quarantine (host, ip_address, reason, added_at, expires_at, actor)
                        VALUES (:h, :ip, :r, :t, :e, :a)""", {'h': host, 'ip': ip, 'r': reason, 't': now, 'e': now + minutes * 60 if minutes else None, 'a': actor})
    return out


def lift_quarantine(db, conn: Conn, host, ip: str, mode: str, actor: str) -> dict:
    name = known_host(conn, host)
    try:
        net = ipaddress.ip_network(str(ip).strip(), strict=False)
    except ValueError:
        raise ValueError('not an IP address or network') from None
    target = str(net.network_address) if net.prefixlen == net.max_prefixlen else str(net)
    res, out = _act(db, name, sx.unquarantine_script(target), _mode({'mode': mode}), f'lift:{target}', actor, rf'^LIFTED {re.escape(target)}$')
    out.update(host=name, ip_address=target)
    if res and mode == 'apply' and out['ok']:
        conn.execute('DELETE FROM security_quarantine WHERE lower(host) = lower(:h) AND ip_address = :ip', {'h': name, 'ip': target})
    return out


def airgap(db, conn: Conn, body: dict, actor: str) -> dict:
    """Cuts everything but this machine. If this machine turns out to be cut too, the host undoes it by itself."""
    host, mode = known_host(conn, body.get('host')), _mode(body)
    enable = body.get('enabled') is not False
    script = sx.airgap_script(_controller_ips(conn, host))
    if mode == 'preview':
        return {'ok': True, 'mode': mode, 'host': host, 'script': script}
    if mode == 'report':
        return {**_result(_run(db, host, script, [], ref='airgap', mode='report', actor=actor), 'report'), 'host': host}
    if not enable:
        res = _run(db, host, script, ['--disarm'], ref='airgap-off', mode='apply', actor=actor)
        out = _result(res, 'apply', None if 'AIRGAP off' in (res.get('output') or '') else 'the airgap may still be on: see the output')
        return {**out, 'host': host, 'airgap': not out['ok'], 'measured': measure(db, conn, host, actor)['ok']}
    res = _run(db, host, script, ['--apply'], ref='airgap', mode='apply', actor=actor)
    output = res.get('output') or ''
    if 'AIRGAP on' in output:
        return {**_result(res, 'apply'), 'host': host, 'airgap': True}
    if 'AIRGAP pending' not in output:
        return {**_result(res, 'apply', 'the airgap did not engage: see the output'), 'host': host, 'airgap': False}
    confirm = _run(db, host, script, ['--confirm'], ref='airgap-confirm', mode='apply', actor=actor, timeout=60)
    output += confirm.get('output') or ''
    if 'AIRGAP on' not in (confirm.get('output') or ''):
        return {'ok': False, 'mode': 'apply', 'host': host, 'airgap': False, 'status': confirm['status'], 'output': output,
                'error': 'StorageForge could not reach the host through the airgap: it lifts itself within 10 minutes'}
    measured = measure(db, conn, host, actor)['ok']
    return {'ok': True, 'mode': 'apply', 'host': host, 'airgap': True, 'status': 'ok', 'output': output, 'measured': measured}


# ── behaviour: what scans and samples show ───────────────────────────
def _latest_scans(conn: Conn, host: str, limit: int = 40) -> list[dict]:
    rows = conn.all(f"""SELECT s.scan_id, s.finished_at, s.added, s.modified, s.deleted FROM scans s JOIN hosts h ON h.host_id = s.host_id
                        WHERE lower(h.hostname) = lower(:h) AND s.status IN ('ok', 'partial') AND s.finished_at IS NOT NULL
                        ORDER BY s.finished_at DESC LIMIT {int(limit)}""", {'h': host})
    return [{'id': r[0], 'at': epoch(r[1]), 'added': r[2], 'modified': r[3], 'deleted': r[4]} for r in rows]


def _full(parent: str, name: str) -> str:
    return f'/{name}' if parent == '/' else f'{parent}/{name}'


def velocity(conn: Conn, host: str) -> dict:
    """How fast files change between scans, against this host's own past. A scan only sees the difference between two
    moments, so this is an after-the-fact signal that catches what no decoy was in the path of."""
    scans = _latest_scans(conn, host)
    series = []
    for cur, prev in zip(scans, scans[1:]):
        hours = max((cur['at'] - prev['at']) / 3600, 1 / 60)
        total = cur['added'] + cur['modified'] + cur['deleted']
        series.append({'at': cur['at'], 'changes': total, 'files_per_hour': round(total / hours, 1), 'added': cur['added'], 'modified': cur['modified'], 'deleted': cur['deleted']})
    out = {'scans': len(scans), 'series': list(reversed(series)), 'latest': series[0] if series else None, 'baseline_median': None, 'threshold': None, 'anomaly': False,
           'ransom_names': 0, 'ransom_samples': [], 'appended_extensions': 0}
    if len(series) > VELOCITY_MIN_BASELINE:
        base = statistics.median(s['files_per_hour'] for s in series[1:])
        out['baseline_median'] = round(base, 1)
        factor, floor = _secplus().velocity_limits(conn, host)
        out['threshold'] = round(max(base * factor, floor), 1)
        out['anomaly'] = series[0]['files_per_hour'] > out['threshold']
    if scans:
        out.update(_scan_signs(conn, scans[0]['id']))
    return out


# A finished scan never changes, so what it shows is worked out once and kept: posture, the alert loop and the security tick
# all ask, every minute, and before this each asked SQLite again. One computation per scan, however many ask at once.
_SIGNS: dict = {}
_SIGNS_LOCK = threading.Lock()
_SIGNS_KEEP = 256


def _scan_signs(conn: Conn, scan_id: int) -> dict:
    # kept by the scan and what it holds: after a reset, or in another database, the same scan id is another scan
    key = (scan_id, conn.scalar('SELECT finished_at FROM scans WHERE scan_id = :s', {'s': scan_id}),
           conn.scalar('SELECT count(*) FROM file_changes WHERE scan_id = :s', {'s': scan_id}))
    with _SIGNS_LOCK:
        got = _SIGNS.get(key)
        if got is None:
            got = _SIGNS[key] = {'done': threading.Event(), 'value': None}
            mine = True
            while len(_SIGNS) > _SIGNS_KEEP:
                _SIGNS.pop(next(iter(_SIGNS)))
        else:
            mine = False
    if mine:
        try:
            got['value'] = _scan_signs_now(conn, scan_id)
        except Exception:
            with _SIGNS_LOCK:
                _SIGNS.pop(key, None)          # the next asker tries again
            raise
        finally:
            got['done'].set()
    elif not got['done'].wait(600):
        raise TimeoutError(f'the signs of scan {scan_id} are still being worked out')
    if got['value'] is None:
        return _scan_signs(conn, scan_id)
    return dict(got['value'])


def _appended(conn: Conn, scan_id: int) -> int:
    """Files added beside one deleted in the same folder with an extension put after its name (report.docx gone,
    report.docx.xyz there): how a rename-in-place encryptor looks, whatever its extension. A set of the deleted names
    and one pass over the added ones, so it takes as long as the scan has changes: the self-join this replaces compared
    every added file with every deleted one, 6 billion pairs for one scan that moved a big folder."""
    gone = {(m, p, f) for m, p, f in conn.all("SELECT mount_id, parent_path, filename FROM file_changes WHERE scan_id = :s AND change_type = 'deleted'",
                                              {'s': scan_id})}
    if not gone:
        return 0
    n = 0
    for m, p, f in conn.all("SELECT mount_id, parent_path, filename FROM file_changes WHERE scan_id = :s AND change_type = 'added' AND NOT is_directory",
                            {'s': scan_id}):
        dot = f.find('.', 1)
        while dot != -1:
            if (m, p, f[:dot]) in gone:
                n += 1
                break
            dot = f.find('.', dot + 1)
    return n


def _scan_signs_now(conn: Conn, scan_id: int) -> dict:
    likes = {f's{i}': f'%{s}' for i, s in enumerate(RANSOM_SUFFIXES)} | {f'n{i}': n for i, n in enumerate(RANSOM_NOTES)}
    match = ' OR '.join(f'lower(filename) LIKE :{k}' for k in likes)
    where = f"scan_id = :s AND change_type IN ('added', 'modified') AND NOT is_directory AND ({match})"
    p = {'s': scan_id, **likes}
    n = conn.scalar(f'SELECT count(*) FROM file_changes WHERE {where}', p) or 0
    samples = [_full(a, b) for a, b in conn.all(f'SELECT parent_path, filename FROM file_changes WHERE {where} LIMIT 20', p)] if n else []
    return {'ransom_names': n, 'ransom_samples': samples, 'appended_extensions': _appended(conn, scan_id)}


def changed_paths(conn: Conn, host: str, limit: int = SAMPLE_FILES, skip_compressed: bool = False) -> list[str]:
    scans = _latest_scans(conn, host, 1)
    if not scans:
        return []
    rows = conn.all(f"""SELECT parent_path, filename FROM file_changes WHERE scan_id = :s AND change_type IN ('added', 'modified') AND NOT is_directory
                        ORDER BY new_modified_at DESC LIMIT {int(limit) * 4}""", {'s': scans[0]['id']})
    out = [_full(a, b) for a, b in rows if not (skip_compressed and b.lower().endswith(COMPRESSED_NAMES))]
    return out[:limit]


def parse_entropy(text: str) -> list[dict]:
    out = []
    for line in (text or '').splitlines():
        f = line.split('\t')
        if len(f) != 5 or f[0] != 'E':
            continue
        path = _b64text(f[1])
        try:
            h, size = float(f[2]), int(f[4])
        except ValueError:
            continue
        if path and 0 <= h <= 8 and re.fullmatch(r'[0-9a-f]{0,32}', f[3]):
            known = f[3].startswith(KNOWN_MAGIC) or f[3][8:16] == '66747970'     # mp4: ftyp at offset 4
            out.append({'path': path, 'entropy': h, 'head': f[3], 'size': size, 'known_header': known, 'flagged': h >= ENTROPY_FLAG and not known})
    return out


def sample_entropy(db, conn: Conn, body: dict, actor: str) -> dict:
    """Reads the first 4 KiB of files the last scan saw change, on the host. It looks at contents, so it is asked for."""
    name = known_host(conn, body.get('host'))
    paths = changed_paths(conn, name, skip_compressed=True)
    if not paths:
        return {'ok': False, 'host': name, 'error': 'the last scan saw no changed files to sample'}
    res = _run(db, name, sx.entropy_script(), ref='entropy', mode='report', actor=actor, timeout=600, data=''.join(sx.b64(p) + '\n' for p in paths).encode())
    if res['status'] != 'ok':
        return _result(res, 'report', host=name)
    if 'NO python3' in (res.get('output') or ''):
        return _result(res, 'report', f'{name} has no python3 to sample with', host=name)
    samples = parse_entropy(res['output'])
    for sample in samples:                                 # a folder can have its own line: stricter for documents, looser for media
        limit = _secplus().entropy_limit(conn, sample['path'])
        if limit != ENTROPY_FLAG:
            sample['flagged'] = sample['entropy'] >= limit and not sample['known_header']
    buckets = {'low': sum(1 for s in samples if s['entropy'] < 6), 'mid': sum(1 for s in samples if 6 <= s['entropy'] < 7.5), 'high': sum(1 for s in samples if 7.5 <= s['entropy'] < ENTROPY_FLAG),
               'ciphertext_like': sum(1 for s in samples if s['entropy'] >= ENTROPY_FLAG)}
    flagged = [s for s in samples if s['flagged']]
    now = int(time.time())
    if flagged:
        record_event(conn, name, 'entropy_flagged', f'{len(flagged)} changed file(s) look encrypted on {name}', json.dumps([f['path'] for f in flagged[:20]]), 'sample', now)
    _save_measurement(conn, name, 'entropy', now, 'sample', {'asked': len(paths), 'read': len(samples), 'threshold': ENTROPY_FLAG, 'buckets': buckets, 'flagged_count': len(flagged), 'flagged': flagged[:200]})
    return {'ok': True, 'host': name, 'read': len(samples), 'flagged': len(flagged), 'run_id': res.get('run_id')}


def diff_scan(db, conn: Conn, body: dict, actor: str) -> dict:
    """ClamAV on only what the last scan saw change. Findings go in the Malware panel beside those of the full scan, and
    nothing here closes one of them: a partial scan says nothing about the files it did not read."""
    from . import clamav
    name = known_host(conn, body.get('host'))
    paths = changed_paths(conn, name, limit=5000)
    if not paths:
        return {'ok': False, 'host': name, 'error': 'the last scan saw no changed files to scan'}
    res = _run(db, name, sx.DIFF_SCAN, ref='diff-scan', mode='report', actor=actor, timeout=1800, data=''.join(sx.b64(p) + '\n' for p in paths).encode())
    if res['status'] != 'ok':
        return _result(res, 'report', host=name)
    output = res.get('output') or ''
    if 'NO clamscan' in output:
        return _result(res, 'report', f'{name} has no ClamAV: deploy it from the Malware panel first', host=name)
    m = re.search(r'^SCANNED (\d+) (\d+) (\d+)$', output, re.M)
    if not m or int(m[2]) not in (0, 1):
        return _result(res, 'report', 'ClamAV did not finish: see the output', host=name)
    found = clamav.add_found(conn, name, output)
    return {'ok': True, 'host': name, 'asked': len(paths), 'scanned': int(m[1]), 'seconds': int(m[3]), 'found': found, 'run_id': res.get('run_id')}


def behavior_view(conn: Conn, host: str) -> dict:
    m = measurement(conn, host)
    sp = _secplus()
    return {'host': host, 'velocity': velocity(conn, host), 'entropy': measurement(conn, host, 'entropy'), 'falco': (m or {}).get('falco'), 'measured_at': (m or {}).get('measured_at'),
            'falco_events': [e for e in list_events(conn, host, 100) if e['kind'] in ('falco_crit', 'falco_warn')][:50], 'falco_rules': sp.falco_rules(conn), 'thresholds': sp.thresholds(conn), 'scan_filters': sp.scan_filters(conn), 'yara': sp.list_yara(conn)}


# ── integrity ────────────────────────────────────────────────────────
def integrity_view(conn: Conn, host: str) -> dict:
    m = measurement(conn, host)
    if not m:
        return {'host': host, 'measured_at': None}
    return {'host': host, 'measured_at': m['measured_at'], 'stale': m['stale'], 'aide': m.get('aide'), 'lynis': m.get('lynis'),
            'tools': [t for t in m.get('tools') or [] if t in ('aide', 'lynis')]}


def run_tool(db, conn: Conn, body: dict, actor: str) -> dict:
    host, mode, tool = known_host(conn, body.get('host')), _mode(body), str(body.get('tool') or '')
    if tool not in ('aide-init', 'aide-check', 'lynis'):
        raise ValueError('tool is aide-init, aide-check or lynis')
    _, out = _act(db, host, sx.tool_script(tool, _secplus().aide_watch(conn)), mode, tool, actor)
    return {**out, 'host': host, 'tool': tool}


# ── compliance: every line is a reading, and none of it is an attestation ─
CHECKS = {
    'sysctl': 'Kernel hardening settings',
    'umask': 'Default umask for logins',
    'auditd': 'auditd running, with StorageForge rules loaded',
    'mac': 'SELinux enforcing, or AppArmor on',
    'booleans': 'Storage SELinux booleans are tight',
    'aide': 'AIDE baseline exists, and its last check found no changes',
    'lynis': 'Lynis hardening index at target',
    'time': 'Clock synchronized, and not off the controller',
    'nts': 'At least one NTS-authenticated time source',
    'fence': 'Quarantine table present',
    'decoys': 'Decoys armed, with the sentinel running',
    'worm': 'A verified hold of the required length',
    'malware': 'ClamAV deployed and reporting',
}
STANDARDS = {
    'cis-l1': {'name': 'CIS Linux Level 1', 'target_lynis': 78, 'min_worm_days': 7, 'controls': {
        'sysctl': 'Network and kernel parameters', 'umask': 'Default umask', 'auditd': 'System auditing', 'aide': 'Filesystem integrity checking', 'time': 'Time synchronization'}},
    'cis-l2': {'name': 'CIS Linux Level 2', 'target_lynis': 85, 'min_worm_days': 14, 'controls': {
        'sysctl': 'Network and kernel parameters', 'umask': 'Default umask', 'auditd': 'System auditing', 'mac': 'Mandatory access control', 'booleans': 'Mandatory access control',
        'aide': 'Filesystem integrity checking', 'lynis': 'Hardening index', 'time': 'Time synchronization', 'nts': 'Time synchronization', 'fence': 'Host firewall', 'decoys': 'Detection', 'worm': 'Backups'}},
    'nist-800-53': {'name': 'NIST SP 800-53 Rev 5', 'target_lynis': 85, 'min_worm_days': 30, 'controls': {
        'auditd': 'AU-2, AU-12', 'decoys': 'SI-4', 'malware': 'SI-3', 'aide': 'SI-7', 'fence': 'SC-7', 'worm': 'CP-9, CP-10', 'mac': 'AC-3', 'time': 'AU-8', 'nts': 'AU-8', 'sysctl': 'CM-6'}},
    'hipaa': {'name': 'HIPAA Security Rule, technical safeguards', 'target_lynis': 84, 'min_worm_days': 30, 'controls': {
        'mac': '§164.312(a)(1)', 'auditd': '§164.312(b)', 'decoys': '§164.312(b)', 'aide': '§164.312(c)(1)', 'worm': '§164.308(a)(7)'}},
    'pci-dss': {'name': 'PCI-DSS v4.0', 'target_lynis': 86, 'min_worm_days': 90, 'controls': {
        'fence': 'Req 1', 'malware': 'Req 5', 'auditd': 'Req 10', 'time': 'Req 10', 'aide': 'Req 11'}},
    'soc2': {'name': 'SOC 2 (Trust Services Criteria)', 'target_lynis': 82, 'min_worm_days': 14, 'controls': {
        'mac': 'CC6.1', 'fence': 'CC6.6', 'decoys': 'CC7.2', 'lynis': 'CC7.1', 'worm': 'A1.2', 'auditd': 'CC7.2'}},
    'iso-27001': {'name': 'ISO/IEC 27001:2022 Annex A', 'target_lynis': 84, 'min_worm_days': 30, 'controls': {
        'malware': 'A.8.7', 'auditd': 'A.8.15', 'decoys': 'A.8.16', 'time': 'A.8.17', 'fence': 'A.8.20', 'worm': 'A.8.13'}},
    'cmmc-l2': {'name': 'CMMC 2.0 Level 2', 'target_lynis': 88, 'min_worm_days': 60, 'controls': {
        'auditd': 'AU.L2-3.3.1', 'malware': 'SI.L2-3.14.2', 'fence': 'SC.L2-3.13.1', 'mac': 'AC.L2-3.1.1', 'worm': 'MP.L2-3.8.9', 'time': 'AU.L2-3.3.7'}},
}


def _check(conn: Conn, host: str, m: dict, check: str, std: dict) -> tuple[str, str]:
    """pass, fail, or unknown when the reading cannot say. Unknown is never counted as a pass."""
    tools = m.get('tools') or []
    if check == 'sysctl':
        values = m.get('sysctl') or {}
        bad = [f'{k} is {values[k]}' for k, want in sx.SYSCTLS.items() if values.get(k) not in (None, want)]
        if not any(values.get(k) is not None for k in sx.SYSCTLS):
            return 'unknown', 'no values read'
        return ('fail', '; '.join(bad)) if bad else ('pass', f'{len(sx.SYSCTLS)} settings')
    if check == 'umask':
        return ('pass', m['umask']) if m.get('umask') == sx.UMASK else ('fail', f'{m.get("umask") or "not set"}, want {sx.UMASK}')
    if check == 'auditd':
        a = m.get('auditd') or {}
        if a.get('active') is None:
            return 'fail', 'auditd is not installed'
        return ('pass', f'{a.get("storageforge_rules")} rules') if a['active'] and a.get('storageforge_rules') else ('fail', 'not running' if not a['active'] else 'no StorageForge rules loaded')
    if check == 'mac':
        if m.get('selinux'):
            return ('pass', 'SELinux enforcing') if m['selinux'] == 'Enforcing' else ('fail', f'SELinux is {m["selinux"]}')
        aa = m.get('apparmor') or {}
        return ('pass', f'AppArmor, {aa.get("enforce")} profiles enforcing') if aa.get('enabled') else ('fail', 'neither is on')
    if check == 'booleans':
        if not m.get('selinux'):
            return 'unknown', 'not an SELinux host'
        bad = [b['name'] for b in m.get('booleans') or [] if not b['ok']]
        return ('fail', ', '.join(bad)) if bad else ('pass', 'as expected')
    if check == 'aide':
        a = m.get('aide')
        if not a:
            return 'fail', 'AIDE is not installed'
        if not a.get('baseline_at'):
            return 'fail', 'no baseline'
        if a.get('last_action') != 'check' or a.get('exit_code') is None:
            return 'unknown', 'there is a baseline, but no check has run'
        return ('pass', 'last check clean') if a['exit_code'] == 0 else ('fail', f'last check exit code {a["exit_code"]}')
    if check == 'lynis':
        ly = m.get('lynis') or {}
        if ly.get('hardening_index') is None:
            return 'unknown', 'no audit has run'
        return ('pass' if ly['hardening_index'] >= std['target_lynis'] else 'fail'), f'{ly["hardening_index"]} of {std["target_lynis"]}'
    if check == 'time':
        if clock_frozen(conn, host):
            return 'fail', 'the clock guard is tripped'
        c = m.get('chrony')
        if c:
            return ('pass', f'{c["offset_ms"]} ms from {c["source"]}') if c['synced'] else ('fail', 'chrony is not synchronized')
        if m.get('ntp_synced') is None:
            return 'unknown', 'neither chrony nor timedatectl could say'
        return ('pass', 'timedatectl says synchronized') if m['ntp_synced'] else ('fail', 'not synchronized')
    if check == 'nts':
        if 'chronyc' not in tools:
            return 'fail', 'chrony is not installed'
        return ('pass', f'{m["nts_sources"]} sources') if m.get('nts_sources') else ('fail', 'no NTS sources')
    if check == 'fence':
        return ('pass', 'present') if m.get('fence') else ('fail', 'not present')
    if check == 'decoys':
        armed = conn.scalar("SELECT count(*) FROM security_canaries WHERE lower(host) = lower(:h) AND status = 'armed'", {'h': host}) or 0
        active = (m.get('sentinel') or {}).get('active')
        return ('pass', f'{armed} armed') if armed and active else ('fail', 'the sentinel is not running' if armed else 'no decoys are armed')
    if check == 'worm':
        need, now = std['min_worm_days'] * 86400, int(time.time())
        for h in hold_rows(conn, host):
            if h['status'] != 'released' and h['verified_at'] and not h['missing_at'] and (h['legal_hold'] or (h['expires_at'] and h['expires_at'] - h['created_at'] >= need and h['expires_at'] > now)):
                return 'pass', h['snapshot']
        return 'fail', f'no verified hold of {std["min_worm_days"]} days'
    if check == 'malware':
        return ('pass', 'deployed') if deploy.deployed(conn, host=deploy.canonical(conn, host), kind='clamav') else ('fail', 'not deployed')
    raise KeyError(check)


def compliance_standards(conn: Conn | None = None) -> dict:
    out = {'standards': [{'id': k, 'name': v['name'], 'target_lynis': v['target_lynis'], 'min_worm_days': v['min_worm_days'],
                          'checks': [{'id': c, 'label': CHECKS[c], 'control': ref} for c, ref in v['controls'].items()]} for k, v in STANDARDS.items()],
           'note': 'Readings mapped to controls they help with. Not an audit, a certification or an attestation. The Lynis and retention targets are StorageForge\'s suggestions: no standard sets those numbers, and a custom profile can change them.'}
    if conn is not None:
        sp = _secplus()
        out['presets'] = [{'id': f'preset:{k}', 'name': v['label'], 'base': v['base'], 'overrides': v['overrides']} for k, v in sp.PROFILE_PRESETS.items()]
        out['custom'] = [{'id': f'custom:{p["name"]}', 'pk': p['id'], 'name': p['name'], 'base': p['base'], 'overrides': p['overrides']} for p in sp.list_profiles(conn)]
        out['checks'] = CHECKS
    return out


def compliance_status(conn: Conn, host: str, profile: str | None = None) -> dict:
    name = known_host(conn, host)
    profile = profile or alerts.get_setting(conn, profile_key(name)) or 'cis-l2'
    std, m = _secplus().std_for(conn, profile), measurement(conn, name)
    base = {'host': name, 'profile': profile, 'standard': std['name'], 'measured_at': (m or {}).get('measured_at'), 'stale': (m or {}).get('stale')}
    if not m:
        return {**base, 'score': None, 'passed': 0, 'failed': 0, 'unknown': len(std['controls']), 'checks': [
            {'id': c, 'label': CHECKS[c], 'control': ref, 'result': 'unknown', 'detail': 'not measured'} for c, ref in std['controls'].items()]}
    checks = []
    waivers = _secplus().waived(conn, name)
    for c, ref in std['controls'].items():
        result, detail = _check(conn, name, m, c, std)
        row = {'id': c, 'label': CHECKS[c], 'control': ref, 'result': result, 'detail': clean_text(detail, 300)}
        if result == 'fail' and c in waivers:     # still shown, and it says why it does not count
            row.update(result='waived', waiver={k: waivers[c][k] for k in ('reason', 'approver', 'expires_at')})
        checks.append(row)
    counted = [c for c in checks if c['result'] != 'waived']
    passed = sum(1 for c in counted if c['result'] == 'pass')
    return {**base, 'score': round(passed * 100 / len(counted)) if counted else None, 'passed': passed, 'failed': sum(1 for c in counted if c['result'] == 'fail'),
            'unknown': sum(1 for c in counted if c['result'] == 'unknown'), 'waived': len(checks) - len(counted), 'checks': checks, 'drift': _secplus().drift_of(conn, name).get('new') or []}


def compliance_init(db, conn: Conn, body: dict, actor: str) -> dict:
    """Sets the baseline this script can verify. The score moves when a measurement sees the result, not because this ran."""
    host, mode, profile = known_host(conn, body.get('host')), _mode(body), str(body.get('profile') or 'cis-l2')
    _secplus().std_for(conn, profile)
    res, out = _act(db, host, sx.compliance_script(profile, host), mode, f'compliance:{profile}', actor, None, 900)
    out.update(host=host, profile=profile)
    if res and mode == 'apply' and out['ok']:
        alerts.set_setting(conn, profile_key(host), profile, actor)
        out['measured'] = measure(db, conn, host, actor)['ok']
    return out


# ── an incident ──────────────────────────────────────────────────────
def brake(db, conn: Conn, body: dict, actor: str) -> dict:
    """Pulled by hand: the same program an armed sentinel runs, and the answer is what each of its steps reports."""
    host, mode = known_host(conn, body.get('host')), _mode(body)
    actions = [a for a in sx.BRAKE_ACTIONS if a in (body.get('actions') or sx.BRAKE_ACTIONS)]
    if not actions:
        raise ValueError('choose at least one step')
    path = clean_path(body['path'], 'the path') if body.get('path') else ''
    client = clean_target(conn, host, body['client_ip']) if body.get('client_ip') else ''
    pid = _int(body.get('pid'), 0) or 0
    if pid < 0:
        raise ValueError('bad pid')
    reason = clean_text(body.get('reason') or f'by hand: {actor}', 200)
    if mode == 'preview':
        return {'ok': True, 'mode': mode, 'host': host, 'script': sx.brake_program()}
    args = sx.brake_args(path, client, pid, reason, actions, _int(body.get('minutes'), 0) or 0, apply=mode == 'apply')
    res = _run(db, host, sx.brake_program(), args, ref='brake', mode=mode, actor=actor, timeout=180)
    output = res.get('output') or ''
    steps = [{'step': m[0], 'status': m[1], 'detail': clean_text(m[2], 400)} for m in re.findall(r'^STEP (\w+) (ok|failed|skipped) ?(.*)$', output, re.M)]
    failed = [s['step'] for s in steps if s['status'] == 'failed']
    if mode == 'apply':
        now = int(time.time())
        _record_brake_output(conn, host, output, actor, now)
        record_event(conn, host, 'brake_ran', f'{actor} pulled the brake: ' + ', '.join(f'{s["step"]} {s["status"]}' for s in steps), output[-8000:], 'manual')
    error = None
    if res['status'] != 'ok' and not steps:
        error = f'the brake did not run ({res["status"]}): see the output'
    elif failed:
        error = 'these steps failed: ' + ', '.join(failed)
    return {'ok': not error, 'mode': mode, 'host': host, 'status': res['status'], 'steps': steps, 'output': output, 'run_id': res.get('run_id'), **({'error': error} if error else {})}


def blast_radius(conn: Conn, host: str, at: int | None = None) -> dict:
    """What the index and the last sample say about an incident. Who sees "clean" must know how old that word is, so
    it comes with the scan it rests on, and without a scan since the incident there are no counts at all."""
    name = known_host(conn, host)
    if at is None:
        rows = conn.all("""SELECT occurred_at FROM security_events WHERE lower(host) = lower(:h) AND severity = 'crit' AND kind IN ('canary_tripped', 'brake_ran')
                           ORDER BY acknowledged_at IS NULL DESC, occurred_at DESC LIMIT 1""", {'h': name})
        at = rows[0][0] if rows else None
    out = {'host': name, 'incident_at': at, 'scan_at': None, 'total_files': None, 'changed_since': None, 'unchanged_files': None, 'ransom_names': None, 'appended_extensions': None,
           'entropy_flagged': None, 'entropy_at': None, 'newest_hold': None, 'rpo_seconds': None}
    if at is None:
        return out
    scans = [s for s in _latest_scans(conn, name, 100) if s['at'] >= at]
    hold = next((h for h in hold_rows(conn, name) if h['verified_at'] and h['created_at'] <= at and h['status'] != 'released'), None)
    if hold:
        out['newest_hold'] = {'snapshot': hold['snapshot'], 'created_at': hold['created_at']}
        out['rpo_seconds'] = at - hold['created_at']
    entropy = measurement(conn, name, 'entropy')
    if entropy and entropy['measured_at'] >= at:
        out.update(entropy_flagged=entropy.get('flagged_count'), entropy_at=entropy['measured_at'])
    if scans:
        total = conn.scalar("""SELECT count(*) FROM file_records f JOIN mounts m ON m.mount_id = f.mount_id JOIN hosts h ON h.host_id = m.host_id
                               WHERE lower(h.hostname) = lower(:h)""", {'h': name}) or 0
        changed = sum(s['added'] + s['modified'] + s['deleted'] for s in scans)
        signs = _scan_signs(conn, scans[0]['id'])
        out.update(scan_at=scans[0]['at'], total_files=total, changed_since=changed, unchanged_files=max(0, total - changed), ransom_names=signs['ransom_names'],
                   appended_extensions=signs['appended_extensions'])
    return out


def clean_room(db, conn: Conn, body: dict, actor: str) -> dict:
    host, mode = known_host(conn, body.get('host')), _mode(body)
    snapshot = str(body.get('snapshot') or '').strip()
    if not ZFS_SNAP_RE.fullmatch(snapshot):
        snapshot = clean_path(snapshot, 'the snapshot (dataset@name, or a btrfs path)')
    mount = clean_path(body.get('mount') or '/mnt/sf-cleanroom', 'the mount point')
    if mount in ('/', '/mnt', '/etc', '/usr', '/var', '/boot', '/root', '/home', '/srv'):
        raise ValueError(f'{mount} cannot be a clean room')
    script = sx.cleanroom_script(snapshot, mount)
    if mode == 'preview':
        return {'ok': True, 'mode': mode, 'host': host, 'script': script}
    args = ['--remove'] if body.get('remove') is True else ['--apply'] if mode == 'apply' else []
    res = _run(db, host, script, args, ref=f'cleanroom:{snapshot}'[:200], mode=mode, actor=actor, timeout=180)
    return {**_result(res, mode), 'host': host, 'snapshot': snapshot, 'mount': mount}


# ── the whole picture ────────────────────────────────────────────────
def host_coverage(conn: Conn, host: str) -> dict:
    """What is really known about one host, and every reason it is not fine yet."""
    m = measurement(conn, host)
    marks = deploy.deployed(conn, host=host, kind='security')
    states = [r[0] for r in conn.all('SELECT status FROM security_canaries WHERE lower(host) = lower(:h)', {'h': host})]
    armed, tripped = [s for s in states if s == 'armed'], [s for s in states if s == 'tripped']
    holds = [h for h in hold_rows(conn, host) if h['status'] != 'released']
    verified = [h for h in holds if h['verified_at'] and not h['missing_at']]
    crit = [e for e in list_events(conn, host, 100, False) if e['severity'] == 'crit' and not e['acknowledged_at']]
    vel = velocity(conn, host)
    critical, warnings, gaps = [], [], []
    if tripped:
        critical.append(f'{len(tripped)} decoy(s) tripped')
    if crit:
        critical.append(f'{len(crit)} unacknowledged alarm(s)')
    if clock_frozen(conn, host):
        critical.append('the clock guard is tripped: releases are stopped')
    if (lost := [h for h in holds if h['missing_at']]):
        critical.append(f'{len(lost)} hold(s) gone from the host')
    if vel['ransom_names']:
        critical.append(f'the last scan saw {vel["ransom_names"]} file(s) named like ransomware')
    if vel['appended_extensions'] >= 50:
        critical.append(f'the last scan saw {vel["appended_extensions"]} files renamed with an extra extension')
    if vel['anomaly']:
        warnings.append(f'{vel["latest"]["files_per_hour"]} files an hour against a usual {vel["baseline_median"]}')
    if not m:
        gaps.append('never measured')
    else:
        if m['stale']:
            gaps.append('the last measurement is over a day old')
        if m.get('airgap'):
            critical.append('the airgap is engaged')
        if m.get('clock_offset'):
            warnings.append(f'the clock is {m["clock_offset"]} s off')
        if not m.get('selinux') and not (m.get('apparmor') or {}).get('enabled'):
            warnings.append('no mandatory access control')
        elif m.get('selinux') and m['selinux'] != 'Enforcing':
            warnings.append(f'SELinux is {m["selinux"]}')
        if bad := [b['name'] for b in m.get('booleans') or [] if not b['ok']]:
            warnings.append('booleans too open: ' + ', '.join(bad))
        aide = m.get('aide') or {}
        if aide.get('last_action') == 'check' and aide.get('exit_code'):
            warnings.append(f'AIDE found changes (exit code {aide["exit_code"]})')
        if (m.get('lynis') or {}).get('hardening_index') is not None and m['lynis']['hardening_index'] < 70:
            warnings.append(f'Lynis hardening index {m["lynis"]["hardening_index"]}')
        if m.get('zfs_allow'):
            warnings.append('someone other than root may destroy or release snapshots: ' + '; '.join(m['zfs_allow'][:2]))
        if marks and not (m.get('sentinel') or {}).get('active'):
            warnings.append('the sentinel is deployed but not running')
    if not marks:
        gaps.append('no sentinel')
    if not armed:
        gaps.append('no decoys armed')
    if not verified:
        gaps.append('no verified retention hold')
    state = 'critical' if critical else 'warning' if warnings else 'unknown' if gaps else 'secure'
    return {'host': host, 'state': state, 'critical': critical, 'warnings': warnings, 'gaps': gaps, 'measured_at': (m or {}).get('measured_at'), 'stale': (m or {}).get('stale'),
            'sentinel': bool(marks), 'sentinel_active': (m or {}).get('sentinel', {}).get('active') if m else None, 'armed': (m or {}).get('sentinel', {}).get('armed') if m else None,
            'decoys_armed': len(armed), 'decoys_tripped': len(tripped), 'holds_active': len(holds), 'holds_verified': len(verified),
            'deploy_ready': deploy.ready(conn, host), 'mac': (m or {}).get('selinux') or ('AppArmor' if (m or {}).get('apparmor', {}).get('enabled') else None) if m else None,
            'lynis': ((m or {}).get('lynis') or {}).get('hardening_index')}


def posture(conn: Conn, host: str | None = None) -> dict:
    names = [known_host(conn, host)] if host else [r[0] for r in conn.all('SELECT hostname FROM hosts ORDER BY hostname')]
    hosts = [host_coverage(conn, n) for n in names]
    rank = {'critical': 3, 'warning': 2, 'unknown': 1, 'secure': 0}
    state = max((h['state'] for h in hosts), key=rank.get, default='unknown')
    controller = alerts.get_setting(conn, CONTROLLER_CLOCK) or {}
    if controller.get('frozen'):
        state = 'critical'
    measured = sum(1 for h in hosts if h['measured_at'] and not h['stale'])
    suspect = controller_clock_suspect(conn)
    if suspect:
        state = 'critical'
    if suspect:
        banner = (f'This machine\'s clock looks {suspect["seconds"]} s {suspect["direction"]}: {suspect["agree"]} of {suspect["measured"]} hosts differ from it by the same amount. '
                  'Fix its time sync first; the hosts are probably fine.')
    elif not hosts:
        banner = 'No hosts have been scanned, so there is nothing to say yet.'
    elif state == 'critical':
        reasons = sorted({f'{h["host"]}: {c}' for h in hosts for c in h['critical']})
        banner = '; '.join(reasons[:3]) + (f'; and {len(reasons) - 3} more' if len(reasons) > 3 else '') if reasons else 'This machine\'s clock moved: timelocks have stopped.'
    elif state == 'warning':
        n = sum(1 for h in hosts if h['state'] == 'warning')
        banner = f'{n} of {len(hosts)} host(s) need a look; {measured} measured in the last day.'
    elif state == 'unknown':
        banner = f'Not everything can be vouched for: {measured} of {len(hosts)} host(s) measured in the last day. See what is missing below.'
    else:
        banner = f'All {len(hosts)} host(s) measured in the last day, with decoys armed and holds verified, and nothing wrong found.'
    pending = _timelocks(conn, host)
    return {'state': state, 'banner': banner, 'hosts': hosts, 'measured_hosts': measured, 'total_hosts': len(hosts), 'quorum': quorum_state(conn), 'pending_timelocks': pending,
            'controller_clock': controller if controller.get('frozen') else None, 'clock_suspect': suspect, 'events': list_events(conn, host, 50, False)}


def problems(conn: Conn) -> dict:
    """Alerts, through the channels already set up. These are the out-of-band warning a timelock depends on: if someone
    stole an admin's password and asked for a release, this is how the admin hears of it in time to abort."""
    out: dict = {}
    for e in list_events(conn, None, 200, False):
        if e['severity'] == 'crit' and not e['acknowledged_at']:
            out[f'security-event:{e["id"]}'] = ('security-event', str(e['id']), f'{e["host"]}: {e["summary"]}'[:200], f'{e["kind"]} at {time.strftime("%Y-%m-%d %H:%M", time.localtime(e["occurred_at"]))}', 'crit')
    for t in _timelocks(conn):
        target = t['target_ref'] if t['action'] == 'worm_release' else 'the offline key'
        when = 'waiting for a second admin' if t['mode'] == 'dual_admin' else f'runs {time.strftime("%Y-%m-%d %H:%M", time.localtime(t["executes_at"]))}'
        out[f'security-timelock:{t["id"]}'] = ('security-timelock', str(t['id']), f'{t["actor"]} asked to release {target}', f'{when}. If that was not them, abort it in the WORM panel.', 'crit')
    controller = alerts.get_setting(conn, CONTROLLER_CLOCK) or {}
    if controller.get('frozen'):
        out['security-controller-clock'] = ('security-clock', 'controller', 'This machine\'s clock moved: timelocks have stopped', str(controller.get('reason') or ''), 'crit')
    suspect = controller_clock_suspect(conn)
    if suspect:
        out['security-controller-suspect'] = ('security-clock', 'controller', f'This machine\'s clock looks {suspect["seconds"]} s {suspect["direction"]}',
                                              f'{suspect["agree"]} of {suspect["measured"]} hosts differ from it by the same amount. Timelocks have stopped. Past 10 minutes, hosts refuse signed runs.', 'crit')
    for (name,) in conn.all('SELECT hostname FROM hosts'):
        if clock_frozen(conn, name) and not suspect:
            out[f'security-clock:{name}'] = ('security-clock', name, f'Clock guard tripped on {name}: releases stopped', str((alerts.get_setting(conn, clock_key(name)) or {}).get('reason') or ''), 'crit')
        vel = velocity(conn, name)
        if vel['ransom_names']:
            out[f'security-names:{name}'] = ('security-names', name, f'{name}: {vel["ransom_names"]} file(s) named like ransomware', '; '.join(vel['ransom_samples'][:5]), 'crit')
        if vel['appended_extensions'] >= 50:
            out[f'security-renames:{name}'] = ('security-renames', name, f'{name}: {vel["appended_extensions"]} files renamed with an extra extension', 'the shape a rename-in-place encryptor leaves', 'crit')
        if vel['anomaly']:
            out[f'security-velocity:{name}'] = ('security-velocity', name, f'{name}: files changing much faster than usual', f'{vel["latest"]["files_per_hour"]} an hour; usually {vel["baseline_median"]}', 'warn')
        marks = deploy.deployed(conn, host=name, kind='security')
        m = measurement(conn, name)
        if marks:
            if m and not (m.get('sentinel') or {}).get('active') and not m['stale']:
                out[f'security-sentinel:{name}'] = ('security-sentinel', name, f'The sentinel on {name} is not running', 'its decoys are not being watched', 'crit')
            if (not m or m['stale']) and time.time() - marks[0]['at'] > STALE_AFTER:
                out[f'security-stale:{name}'] = ('security-stale', name, f'No recent security reading from {name}', 'it may be unreachable, or someone has stopped it answering', 'warn')
    out.update(_secplus().problems(conn))
    return out
