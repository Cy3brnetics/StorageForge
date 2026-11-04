"""Alerts and drift for deployments: failed or stale jobs, checksum verifies that found differences, and hosts whose
deployed files changed by hand. Open alerts show in the Deploy tab; each one opening (and resolving) can also be pushed
to ntfy, Gotify or a webhook. Settings live in the settings table.

Drift comes from what scans collect on each host (remote.py @@managed): sha256sum -c of the files deploys recorded,
StorageForge's fstab lines, and the job timers. Pending changes (a plan or design edited since its last deploy) are
shown too, but are not alerts.
"""
from __future__ import annotations

import http.client
import ipaddress
import fnmatch
import json
import os
import re
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from .db import Conn, epoch, loads

URL_RE = re.compile(r'https?://[^\s"<>]{3,500}')
# The report URL also ends up in scripts run as root on hosts: scheme, host, port and a plain path, no shell characters.
REPORT_URL_RE = re.compile(r'https?://(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9.-]{1,253})(:\d{1,5})?(/[A-Za-z0-9._~/-]*)?')
TOPIC_RE = re.compile(r'[A-Za-z0-9_-]{1,64}')
DEFAULTS = {'report_url': '', 'alerts': {'ntfy': {'url': '', 'topic': '', 'token': ''}, 'gotify': {'url': '', 'token': ''},
                                         'webhook': {'url': ''}, 'pagerduty': {'routing_key': ''}, 'routes': [], 'notify_resolved': True}}
FILLS_UP_DAYS = int(os.environ.get('STORAGEFORGE_FILLS_UP_DAYS', '14'))
LARGE_DELETE = int(os.environ.get('STORAGEFORGE_LARGE_DELETE', '10000'))   # files gone in one scan
SECRET_FIELDS = (('ntfy', 'token'), ('gotify', 'token'), ('pagerduty', 'routing_key'))
_lock = threading.Lock()


# ── settings ────────────────────────────────────────────────────────
def get_setting(conn: Conn, key: str):
    v = conn.scalar('SELECT value_json FROM settings WHERE key = :k', {'k': key})
    return json.loads(v) if v else json.loads(json.dumps(DEFAULTS.get(key)))


def set_setting(conn: Conn, key: str, value, actor: str):
    conn.execute('DELETE FROM settings WHERE key = :k', {'k': key})
    conn.execute('INSERT INTO settings (key, value_json, updated_at, updated_by) VALUES (:k, :v, :t, :a)',
                 {'k': key, 'v': json.dumps(value), 't': int(time.time()), 'a': actor})


def settings(conn: Conn, reveal: bool = False) -> dict:
    s = {'report_url': get_setting(conn, 'report_url'), 'alerts': get_setting(conn, 'alerts')}
    if not reveal:      # tokens are write-only from the UI
        for ch, f in SECRET_FIELDS:
            s['alerts'].setdefault(ch, {})[f] = '••••••' if s['alerts'][ch].get(f) else ''
    return s


def public_settings(conn: Conn) -> dict:
    """For accounts that see deploys but not the settings: which channels are on, and nothing that could post to them.
    A webhook's or ntfy topic's address is itself the credential."""
    s = settings(conn)
    for ch in ('ntfy', 'gotify', 'webhook'):
        c = s['alerts'][ch]
        u = urllib.parse.urlsplit(c.get('url') or '')
        c['url'] = f'{u.scheme}://{u.netloc.rpartition("@")[2]}' if u.netloc else ''
        if c.get('topic'):
            c['topic'] = '••••••'
    return s


def save_settings(conn: Conn, body: dict, actor: str) -> dict:
    url = str(body.get('report_url') or '').strip().rstrip('/')
    if url and not REPORT_URL_RE.fullmatch(url):
        raise ValueError('the report URL must be http(s)://host:port (optionally /path), as the hosts reach StorageForge')
    set_setting(conn, 'report_url', url, actor)
    cur, new = get_setting(conn, 'alerts'), body.get('alerts') or {}
    for ch, fields in (('ntfy', ('url', 'topic', 'token')), ('gotify', ('url', 'token')), ('webhook', ('url',))):
        old_origin = _origin(cur[ch].get('url'))
        for f in fields:
            given = (new.get(ch) or {}).get(f)
            v = str(cur[ch].get(f, '') if given is None else given or '').strip()
            if (ch, f) in SECRET_FIELDS and (given is None or v == '••••••'):    # the stored token, kept
                # ...unless the server changed, down to the scheme and port (https -> http would send it in clear
                # text, another port can be another service): then it is not sent there until typed in again
                v = cur[ch].get(f, '') if _origin(cur[ch].get('url')) == old_origin else ''
            if f == 'url' and v and not URL_RE.fullmatch(v):
                raise ValueError(f'{ch}: the URL must start with http:// or https://')
            if f == 'url' and v:
                _check_target(v, ch)
            if f == 'topic' and v and not TOPIC_RE.fullmatch(v):
                raise ValueError('ntfy topic: letters, digits, - and _ only')
            cur[ch][f] = v.rstrip('/') if f == 'url' else v
    key = (new.get('pagerduty') or {}).get('routing_key')
    if key is not None:
        if key != '••••••':
            if key and not re.fullmatch(r'[A-Za-z0-9_-]{20,64}', str(key)):
                raise ValueError('pagerduty: that is not a routing key')
            cur['pagerduty'] = {'routing_key': str(key)}
    if new.get('routes') is not None:
        routes = []
        for r in new['routes'][:50]:
            level = r.get('level') if r.get('level') in ('any', 'crit', 'warn') else 'any'
            channels = [c for c in r.get('channels') or [] if c in CHANNELS]
            if not channels:
                raise ValueError('a route needs at least one channel')
            routes.append({'level': level, 'host': re.sub(r'[^A-Za-z0-9_.*?-]', '', str(r.get('host') or '*'))[:100] or '*', 'channels': channels})
        cur['routes'] = routes
    cur['notify_resolved'] = bool(new.get('notify_resolved', cur.get('notify_resolved', True)))
    set_setting(conn, 'alerts', cur, actor)
    return settings(conn)


# ── sending ─────────────────────────────────────────────────────────
def _host(url: str | None) -> str:
    return (urllib.parse.urlsplit(url or '').hostname or '').lower()


def _origin(url: str | None) -> tuple:
    u = urllib.parse.urlsplit(url or '')
    try:
        port = u.port
    except ValueError:
        port = None
    return u.scheme.lower(), (u.hostname or '').lower(), port or {'https': 443, 'http': 80}.get(u.scheme.lower())


def _refused(addr: str) -> bool:
    """Loopback, link-local, unspecified, multicast or reserved, also behind the IPv6 forms that carry an IPv4
    address (::ffff:127.0.0.1, 6to4 2002:7f00:1::, Teredo)."""
    ip = ipaddress.ip_address(addr.split('%')[0])
    ips = [ip, getattr(ip, 'ipv4_mapped', None), getattr(ip, 'sixtofour', None), *(getattr(ip, 'teredo', None) or ())]
    return any(x.is_loopback or x.is_link_local or x.is_unspecified or x.is_multicast or x.is_reserved
               for x in ips if x is not None)


def _resolve(host: str, port: int | None, what: str = '') -> list[str]:
    """host's addresses, each one an allowed alert destination, or ValueError."""
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except (OSError, UnicodeError):
        raise ValueError(f'{what + ": " if what else ""}cannot resolve {host}') from None
    addrs = list(dict.fromkeys(sa[0] for *_, sa in infos))
    for a in addrs:
        if _refused(a):
            where = host if host.strip('[]') == a.split('%')[0] else f'{host} ({a})'
            raise ValueError(f'{what + ": " if what else ""}{where} is not an allowed alert destination '
                             f'(loopback, link-local or multicast)')
    return addrs


def _check_target(url: str, what: str = ''):
    """Alerts go to the LAN or the internet, never to this container, link-local (cloud metadata) or multicast
    addresses. Private ranges stay allowed: a self-hosted ntfy or Gotify on the LAN is the usual setup."""
    _resolve(_host(url) or url, None, what)


def _connect(address, timeout=socket._GLOBAL_DEFAULT_TIMEOUT, source_address=None, **kw):
    """socket.create_connection for alert requests: resolves once, checks what it got, and connects to exactly that.
    Checking the name and letting urllib resolve it again would let a DNS answer change in between (rebinding)."""
    host, port = address
    err = None
    for a in _resolve(host, port):
        try:
            return socket.create_connection((a, port), timeout, source_address)
        except OSError as exc:
            err = exc
    raise err or OSError(f'cannot reach {host}')


class _CheckedHTTP(http.client.HTTPConnection):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._create_connection = _connect


class _CheckedHTTPS(http.client.HTTPSConnection):     # the certificate is still checked against the name
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._create_connection = _connect


class _HTTP(urllib.request.HTTPHandler):
    def http_open(self, req):
        return self.do_open(_CheckedHTTP, req)


class _HTTPS(urllib.request.HTTPSHandler):
    def https_open(self, req):
        return self.do_open(_CheckedHTTPS, req, context=self._context)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):     # a redirect could point anywhere the check above refuses
        return None


_opener = urllib.request.build_opener(_NoRedirect, _HTTP, _HTTPS, urllib.request.ProxyHandler({}))


def _post(url: str, data: bytes, headers: dict):
    _check_target(url)
    req = urllib.request.Request(url, data=data, headers={'User-Agent': 'StorageForge', **headers}, method='POST')
    with _opener.open(req, timeout=15) as r:
        r.read(1000)


def _why(exc: Exception) -> str:
    """Enough to fix a setting (HTTP status, refused target) without turning the test button into a port scanner."""
    if isinstance(exc, urllib.error.HTTPError):
        return f'the server answered HTTP {exc.code}'
    if isinstance(exc, ValueError):
        return str(exc)
    return 'could not deliver it'


PAGERDUTY_URL = 'https://events.pagerduty.com/v2/enqueue'
CHANNELS = ('ntfy', 'gotify', 'webhook', 'pagerduty')


def routed(cfg: dict, level: str, ref) -> set | None:
    """Which channels this goes to. None: all of them. With routes set and none matching it still goes everywhere, because an alert
    nobody receives is worse than one too many."""
    routes = cfg.get('routes') or []
    if not routes:
        return None
    hits = [r for r in routes if r.get('level') in ('any', level) and fnmatch.fnmatch(str(ref or ''), r.get('host') or '*')]
    return {c for r in hits for c in r.get('channels') or []} or None


def send(cfg: dict, title: str, message: str, level: str = 'warn', extra: dict | None = None) -> list[str]:
    """Push one notification to every configured channel. Returns what was sent (or why not), per channel."""
    out = []
    prio = {'crit': 5, 'warn': 4, 'ok': 2}.get(level, 3)
    n, g, w, pd = cfg.get('ntfy') or {}, cfg.get('gotify') or {}, cfg.get('webhook') or {}, cfg.get('pagerduty') or {}
    chosen = routed(cfg, level, (extra or {}).get('ref'))
    if chosen is not None:
        n, g, w, pd = (x if name in chosen else {} for x, name in ((n, 'ntfy'), (g, 'gotify'), (w, 'webhook'), (pd, 'pagerduty')))
    if pd.get('routing_key') and level != 'ok':
        try:
            _post(PAGERDUTY_URL, json.dumps({'routing_key': pd['routing_key'], 'event_action': 'trigger', 'dedup_key': str((extra or {}).get('key') or title)[:255],
                                             'payload': {'summary': title[:1024], 'source': 'storageforge', 'severity': 'critical' if level == 'crit' else 'warning', 'custom_details': {'message': message[:2000]}}}).encode(),
                  {'Content-Type': 'application/json'})
            out.append('pagerduty: sent')
        except Exception as exc:
            out.append(f'pagerduty: {_why(exc)}')
    if n.get('url') and n.get('topic'):
        try:
            h = {'Title': title.encode('ascii', 'replace').decode(), 'Priority': str(prio),
                 'Tags': 'white_check_mark' if level == 'ok' else 'warning'}
            if n.get('token'):
                h['Authorization'] = f'Bearer {n["token"]}'
            _post(f'{n["url"]}/{n["topic"]}', message.encode(), h)
            out.append('ntfy: sent')
        except Exception as exc:
            out.append(f'ntfy: {_why(exc)}')
    if g.get('url') and g.get('token'):
        try:
            _post(f'{g["url"]}/message', json.dumps({'title': title, 'message': message, 'priority': prio * 2}).encode(),
                  {'Content-Type': 'application/json', 'X-Gotify-Key': g['token']})
            out.append('gotify: sent')
        except Exception as exc:
            out.append(f'gotify: {_why(exc)}')
    if w.get('url'):
        try:
            _post(w['url'], json.dumps({'source': 'storageforge', 'title': title, 'message': message, 'level': level,
                                        'at': int(time.time()), **(extra or {})}).encode(), {'Content-Type': 'application/json'})
            out.append('webhook: sent')
        except Exception as exc:
            out.append(f'webhook: {_why(exc)}')
    return out or ['no channel is set up']


# ── drift ───────────────────────────────────────────────────────────
def drift(conn: Conn) -> list[dict]:
    """Per host: deployed files changed or missing, fstab lines gone, job timers missing or disabled; and plans or
    designs changed since their last deploy (pending)."""
    from . import deploy, jobs, moves, scheduler, shares
    out = []
    expected = {}
    for r in conn.all('SELECT job_id, runner_host, spec_json, paused FROM jobs WHERE removed_at IS NULL AND plan_id IS NOT NULL'):      # an imported job's timers are its own
        spec = json.loads(r[2] or '{}')
        if spec and not r[3]:
            try:
                expected.setdefault(r[1], set()).update(jobs.units({**spec, 'id': r[0]})[1])
            except (KeyError, TypeError):
                pass
    for host, inv in conn.all('SELECT hostname, inventory_json FROM hosts'):
        text = (loads(inv) or {}).get('managed')
        if text is None:
            continue
        section, timers = '', {}
        for line in text.splitlines():
            if line.startswith('## '):
                section = line[3:].strip()
            elif line.startswith('TIMER '):
                _, name, *state = line.split()
                timers[name] = state[0] if state else 'unknown'
            elif line.startswith('LINE-MISSING '):
                out.append({'host': host, 'ref': section, 'kind': 'changed', 'text': f'fstab line gone: {line[13:]}'})
            elif re.search(r': FAILED$', line) and 'open or read' not in line:
                out.append({'host': host, 'ref': section, 'kind': 'changed', 'text': f'{line.rsplit(":", 1)[0]} was changed by hand'})
            elif 'No such file' in line and line.startswith('sha256sum:'):
                out.append({'host': host, 'ref': section, 'kind': 'changed',
                            'text': f'{line.split(":")[1].strip()} was removed by hand'})
        for t in sorted(expected.get(host, ())):
            if t not in timers:
                out.append({'host': host, 'ref': t.split('.')[0].removeprefix('sf-job-'), 'kind': 'changed',
                            'text': f'{t} is missing'})
            elif timers[t] not in ('enabled', 'unknown'):
                out.append({'host': host, 'ref': t.split('.')[0].removeprefix('sf-job-'), 'kind': 'changed',
                            'text': f'{t} is {timers[t]} (StorageForge enabled it)'})
    for d in deploy.deployed(conn):
        if d['kind'] == 'shares' and d['host'] == d['ref']:
            now = shares.design_hash(conn, d['host'])
            if now and now != d['hash']:
                out.append({'host': d['host'], 'ref': d['ref'], 'kind': 'pending',
                            'text': 'the shares in the design changed since they were deployed'})
        elif d['kind'] == 'jobs':
            row = conn.all('SELECT plan_id, body_json FROM move_plans WHERE plan_id = :p',
                           {'p': int(d['ref'].lstrip('p') or 0)})
            try:
                cur = jobs.plan_hash({**json.loads(row[0][1]), 'id': row[0][0]}) if row else None
            except (ValueError, KeyError):
                cur = None
            if cur != d['hash']:
                out.append({'host': d['host'], 'ref': d['ref'], 'kind': 'pending',
                            'text': 'the move plan was deleted since it was deployed: remove its jobs' if not row
                            else 'the move plan changed since it was deployed'})
        elif d['kind'] == 'schedules':
            try:
                sched = scheduler.get_schedule(conn, int(d['ref']))
                cur = scheduler.schedule_hash(conn, sched)
            except (LookupError, ValueError):
                sched, cur = None, None
            if cur != d['hash']:
                out.append({'host': d['host'], 'ref': f'sched-{d["ref"]}', 'kind': 'pending',
                            'schedule': int(d['ref']), 'deleted': not sched,
                            'text': 'the schedule was deleted since it was deployed: uninstall it' if not sched
                            else f'schedule "{sched["name"]}" changed since it was deployed'})
    del moves
    return out


# ── what the scans and this server know ─────────────────────────────
DISK_WARN = int(os.environ.get('STORAGEFORGE_DISK_WARN_PCT', '90'))
DISK_CRIT = int(os.environ.get('STORAGEFORGE_DISK_CRIT_PCT', '95'))
UNKNOWN_SCAN_DAYS = 7            # how long a failed scan of something not yet a host keeps its alert
GONE_DAYS = 30                   # a mount missing this long was removed on purpose: stop alerting
CERT_WARN_DAYS, CERT_CRIT_DAYS = 30, 7
BACKUP_STALE_DAYS = 3
NO_USAGE_FS = {'tmpfs', 'devtmpfs', 'squashfs', 'iso9660', 'overlay', 'ramfs', 'nfs', 'nfs4', 'cifs', 'smb3', 'fuse.sshfs'}    # always full, or another host's disk


def scan_problems(conn: Conn) -> dict:
    """A host's latest scan job failed; a mount a scan saw recently is gone; a filesystem is nearly full; a pool is unwell."""
    from .capacity import trends
    from .payloads import node_from_index
    now = {}
    for t in trends(conn):
        if t['days_left'] is not None and t['days_left'] <= FILLS_UP_DAYS:
            now[f'disk-filling:{t["host"]}:{t["mount"]}'] = ('disk-filling', f'{t["host"]}:{t["mount"]}', f'{t["mount"]} on {t["host"]} fills up in about {t["days_left"]} days',
                                                             'at the rate of the last 30 days', 'warn')
    for hid, host in conn.all('SELECT host_id, hostname FROM hosts'):
        last = conn.all("SELECT deleted, scan_id FROM scans WHERE host_id = :h AND status <> 'running' ORDER BY scan_id DESC LIMIT 1", {'h': hid})
        if last and (last[0][0] or 0) >= LARGE_DELETE:
            now[f'large-delete:{host}'] = ('large-delete', host, f'{last[0][0]:,} files vanished on {host}', f'in scan #{last[0][1]}: check that this was meant', 'warn')
    latest = {}
    for host, status, result, queued in conn.all("""SELECT host, status, result_json, queued_at FROM scan_jobs
                                                    WHERE status NOT IN ('queued', 'running') ORDER BY job_id"""):
        latest[host] = (status, result, queued)
    known = {r[0] for r in conn.all('SELECT hostname FROM hosts')}
    for host, (status, result, queued) in latest.items():
        # a name no host answers to may be a typo, and nothing can retire it: it stops alerting after a while
        if status == 'failed' and (host in known or time.time() - (queued or 0) < UNKNOWN_SCAN_DAYS * 86400):
            why = str((loads(result) or {}).get('error') or '')
            now[f'scan-failed:{host}'] = ('scan-failed', host, f'Scan failed on {host}', why, 'warn')
    cutoff = time.time() - GONE_DAYS * 86400
    hosts = conn.all('SELECT host_id, hostname FROM hosts')
    for hid, host in hosts:
        newest = epoch(conn.scalar('SELECT max(finished_at) FROM scans WHERE host_id = :h', {'h': hid}))
        seen_fs = set()
        from .analysis import use_pct
        from .payloads import parse_df
        inv = loads(conn.scalar('SELECT inventory_json FROM hosts WHERE host_id = :h', {'h': hid})) or {}
        avail = {r['target']: r['avail'] for r in parse_df(inv.get('df') or '')}
        for mp, source, fs, total, used, state, seen in conn.all(
                """SELECT mount_point, source, filesystem_type, total_bytes, used_bytes, scan_state, seen_at
                   FROM mounts WHERE host_id = :h ORDER BY mount_point""", {'h': hid}):
            kind = (fs or '').lower()
            if state == 'gone':
                seen_at = epoch(seen)
                if kind not in NO_USAGE_FS and seen_at and seen_at > cutoff and newest and total:
                    now[f'mount-gone:{host}:{mp}'] = ('mount-gone', f'{host}:{mp}', f'{mp} is gone on {host}',
                                                      f'{source} was there until {time.strftime("%Y-%m-%d %H:%M", time.localtime(seen_at))}', 'warn')
                continue
            base = (source or mp).split('[')[0]          # btrfs subvolumes share one filesystem: one alert for it
            if state == 'bind-alias' or kind in NO_USAGE_FS or not total or base in seen_fs:
                continue
            seen_fs.add(base)
            free = avail.get(mp)        # btrfs RAID: the total is raw, so only used against available says how full it is
            pct = use_pct({'used': used or 0, 'avail': free, 'total': total})
            free = total - (used or 0) if free is None else free
            if pct >= DISK_CRIT:
                now[f'disk-crit:{host}:{mp}'] = ('disk-crit', f'{host}:{mp}', f'{mp} is {pct:.0f}% full on {host}',
                                                 f'{free / 2**30:,.1f} GiB free at the last scan', 'crit')
            elif pct >= DISK_WARN:
                now[f'disk-warn:{host}:{mp}'] = ('disk-warn', f'{host}:{mp}', f'{mp} is {pct:.0f}% full on {host}',
                                                 f'{free / 2**30:,.1f} GiB free at the last scan', 'warn')
        try:
            node = node_from_index(conn, host, symlink_limit=0, stats=False)
            pools = node['pools']
            from .health import apply_report, problems as health_problems
            apply_report(node, node.get('health_report'))
            for level, key, title, detail in health_problems(node):
                now[f'health:{host}:{key}'] = ('health', f'{host}:{key}', title, detail, level)
        except (KeyError, ValueError, TypeError, SystemExit):
            continue
        for p in pools:
            health = str(p.get('health') or 'ONLINE')
            if health.upper() not in ('ONLINE', 'OK', ''):
                now[f'pool:{host}:{p["name"]}'] = ('pool', f'{host}:{p["name"]}', f'Pool {p["name"]} is {health} on {host}',
                                                   p.get('status_note') or '', 'crit')
            errors = p.get('device_errors') or []
            if errors:
                now[f'pool-errors:{host}:{p["name"]}'] = (
                    'pool-errors', f'{host}:{p["name"]}', f'Pool {p["name"]} reports device errors on {host}',
                    '; '.join(f'{e["device"]} R/W/C {e["read"]}/{e["write"]}/{e["cksum"]}' for e in errors), 'warn')
    return now


def backup_problems(conn: Conn) -> dict:
    """The nightly backup failed, or the newest one is old (the thread stopped, or the volume went read-only)."""
    from . import backup
    now = {}
    rows = conn.all("""SELECT outcome, detail_json FROM audit_log WHERE actor = 'system' AND action = 'backup.create'
                        ORDER BY audit_id DESC LIMIT 1""")
    if rows and rows[0][0] == 'failed':
        now['backup-failed'] = ('backup-failed', 'backup', 'The nightly backup failed', str((loads(rows[0][1]) or {}).get('error') or ''), 'crit')
    copied = conn.all("SELECT outcome, target_host, detail_json FROM audit_log WHERE action = 'backup.copy' ORDER BY audit_id DESC LIMIT 1")
    if copied and copied[0][0] == 'failed':
        now['backup-copy-failed'] = ('backup-copy-failed', 'backup', f'The backup copy to {copied[0][1]} failed',
                                     str((loads(copied[0][2]) or {}).get('error') or ''), 'crit')
    if rows:
        try:
            found = [b for b in backup.listing() if b['kind'] == 'essentials']
        except OSError:
            found = []
        if found and found[0]['created'] < time.time() - BACKUP_STALE_DAYS * 86400:
            now['backup-stale'] = ('backup-stale', 'backup', f'No backup in {BACKUP_STALE_DAYS} days',
                                   f'the newest is {time.strftime("%Y-%m-%d %H:%M", time.localtime(found[0]["created"]))}', 'warn')
    return now


def cert_problems() -> dict:
    """The HTTPS certificate is near its end: browsers warn, and jobs reporting over https stop being accepted."""
    from cryptography import x509
    path = os.environ.get('STORAGEFORGE_REPORT_CA_FILE')
    if not path:
        return {}
    try:
        ends = x509.load_pem_x509_certificate(Path(path).read_bytes()).not_valid_after_utc.timestamp()
    except (OSError, ValueError):
        return {}
    days = (ends - time.time()) / 86400
    if days > CERT_WARN_DAYS:
        return {}
    level = 'crit' if days <= CERT_CRIT_DAYS else 'warn'
    text = f'ended {-days:.0f} days ago' if days < 0 else f'ends in {days:.0f} days'
    return {f'cert-{level}': (f'cert-{level}', 'tls', f'The HTTPS certificate {text}', 'See "Certificates" in docs/operations.md', level)}


# ── evaluation ──────────────────────────────────────────────────────
def _map_problems(conn: Conn) -> dict:
    from .infragraph import problems as map_problems
    return map_problems(conn)


def _device_problems(conn: Conn) -> dict:
    from .netdevice import warnings
    return {f'device-telnet:{w["device"]}': ('device-telnet', w['device'], f'{w["device"]} is managed over Telnet', w['text'], 'warn') for w in warnings(conn) if w['level'] == 'warn'}


def problems(conn: Conn) -> dict:
    from . import authkeys, clamav, jobs, scheduler, security, site
    now = {**scan_problems(conn), **backup_problems(conn), **cert_problems(), **site.shared_problems(conn),
           **authkeys.problems(conn), **clamav.problems(conn), **security.problems(conn), **_map_problems(conn), **_device_problems(conn)}
    for j in jobs.overview(conn):
        if j['state'] == 'failed':
            now[f'job-failed:{j["id"]}'] = ('job-failed', j['id'], f'Job failed: {j["name"]}',
                                            (j['last'] or {}).get('message') or '', 'crit')
        elif j['state'] == 'stale':
            last = (j['last_ok'] or {}).get('end')
            now[f'job-stale:{j["id"]}'] = ('job-stale', j['id'], f'No good run: {j["name"]}',
                                           f'last good run {time.strftime("%Y-%m-%d %H:%M", time.localtime(last))}' if last
                                           else 'it has not completed a run yet', 'warn')
        v = j.get('verify')
        if v and v['rc'] not in (0, None):
            now[f'verify:{j["id"]}'] = ('verify', j['id'], f'Verify found differences: {j["name"]}', v.get('message') or '', 'warn')
    for d in drift(conn):
        if d['kind'] == 'changed':
            key = f'drift:{d["host"]}:{d["ref"]}'
            prev = now.get(key)
            now[key] = ('drift', f'{d["host"]}:{d["ref"]}', f'Changed by hand on {d["host"]}',
                        ((prev[3] + '; ') if prev else '') + d['text'], 'warn')
    # Storage tasks: failed or stale
    for d in conn.all("SELECT host, ref, detail_json FROM deployed WHERE kind = 'tasks'"):
        host, tslug, djson = d
        detail = loads(djson) or {}
        tname = detail.get('name') or tslug
        sched = detail.get('schedule')
        truns = conn.all("""SELECT started_at, finished_at, exit_code FROM task_runs
                            WHERE lower(host) = lower(:h) AND task = :t ORDER BY started_at DESC LIMIT 5""",
                         {'h': host, 't': tslug})
        if truns:
            last_start, last_end, last_rc = truns[0]
            if last_rc is not None and last_rc != 0:
                now[f'task-failed:{host}:{tslug}'] = ('task-failed', f'{host}:{tslug}', f'Task failed: {tname} on {host}',
                                                      f'exit code {last_rc}', 'crit')
            if sched:
                per = jobs.period(sched)
                good = next((r for r in truns if r[2] == 0), None)
                last_good = (good[1] or good[0]) if good else last_start
                if time.time() - last_good > 2 * per + 3600:
                    now[f'task-stale:{host}:{tslug}'] = ('task-stale', f'{host}:{tslug}', f'No good run: task {tname} on {host}',
                                                         f'scheduled on {sched}', 'warn')
    # Unified Scheduler: failed, verify_failed, or stale schedules
    for s in scheduler.list_schedules(conn):
        if s['paused'] and not scheduler.pause_pending(conn, s):     # stays watched until the host has it
            continue
        sid = s['schedule_id']
        sruns = scheduler.get_schedule_runs(conn, schedule_id=sid, limit=5)
        if sruns:
            latest = sruns[0]
            if latest['status'] in ('failed', 'verify_failed'):
                summ = (latest.get('verify_result') or {}).get('summary') or f'exit code {latest.get("exit_code")}'
                now[f'schedule-failed:{sid}'] = (
                    'schedule-failed', str(sid),
                    f'Schedule {latest["status"].replace("_", " ")}: {s["name"]} on {s["host"]}',
                    summ, 'crit'
                )
            per = scheduler.period(s['cron_expr'])
            good = next((r for r in sruns if r['status'] in ('verified', 'reported')), None)
            last_good = (good['finished_at'] or good['started_at']) if good else latest['started_at']
            if time.time() - last_good > 2 * per + 3600:
                now[f'schedule-stale:{sid}'] = (
                    'schedule-stale', str(sid),
                    f'No verified run: schedule {s["name"]} on {s["host"]}',
                    f'cron {s["cron_expr"]}', 'warn'
                )
    return now


def evaluate(db) -> dict:
    """Open new alerts, refresh open ones, resolve the ones that are gone; notify on each change."""
    with _lock:
        conn = db.connect()
        try:
            cfg = get_setting(conn, 'alerts')
            now_t = int(time.time())
            current = problems(conn)
            open_ = {r[0]: r for r in conn.all("SELECT alert_key, title, message FROM alerts WHERE state = 'open'")}
            sent = []
            for key, (kind, ref, title, message, level) in current.items():
                if key in open_:
                    conn.execute('UPDATE alerts SET last_at = :t, message = :m WHERE alert_key = :k',
                                 {'t': now_t, 'm': message[:2000], 'k': key})
                    continue
                conn.execute('DELETE FROM alerts WHERE alert_key = :k', {'k': key})
                conn.execute("""INSERT INTO alerts (alert_key, kind, ref, title, message, state, first_at, last_at)
                                VALUES (:k, :kind, :r, :ti, :m, 'open', :t, :t)""",
                             {'k': key, 'kind': kind, 'r': ref, 'ti': title, 'm': message[:2000], 't': now_t})
                res = send(cfg, title, message or title, level, {'state': 'open', 'kind': kind, 'ref': ref})
                if not res[0].startswith('no channel'):
                    conn.execute('UPDATE alerts SET notified_at = :t WHERE alert_key = :k', {'t': now_t, 'k': key})
                sent.append((key, res))
            for key, (_k, title, _m) in open_.items():
                if key not in current:
                    conn.execute("UPDATE alerts SET state = 'resolved', resolved_at = :t WHERE alert_key = :k",
                                 {'t': now_t, 'k': key})
                    if cfg.get('notify_resolved', True):
                        send(cfg, f'Resolved: {title}', f'Resolved: {title}', 'ok', {'state': 'resolved', 'key': key})
            return {'open': len(current), 'new': len(sent)}
        finally:
            conn.close()


def list_alerts(conn: Conn, include_resolved: bool = False, limit: int = 100) -> list[dict]:
    rows = conn.all(f"""SELECT alert_key, kind, ref, title, message, state, first_at, last_at, notified_at, resolved_at
                        FROM alerts {'' if include_resolved else "WHERE state = 'open'"} ORDER BY last_at DESC LIMIT :l""",
                    {'l': limit})
    return [dict(zip(('key', 'kind', 'ref', 'title', 'message', 'state', 'first_at', 'last_at', 'notified_at',
                      'resolved_at'), r)) for r in rows]
