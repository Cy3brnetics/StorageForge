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
import json
import re
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from .db import Conn

URL_RE = re.compile(r'https?://[^\s"<>]{3,500}')
# The report URL also ends up in scripts run as root on hosts: scheme, host, port and a plain path, no shell characters.
REPORT_URL_RE = re.compile(r'https?://(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9.-]{1,253})(:\d{1,5})?(/[A-Za-z0-9._~/-]*)?')
TOPIC_RE = re.compile(r'[A-Za-z0-9_-]{1,64}')
DEFAULTS = {'report_url': '', 'alerts': {'ntfy': {'url': '', 'topic': '', 'token': ''}, 'gotify': {'url': '', 'token': ''},
                                         'webhook': {'url': ''}, 'notify_resolved': True}}
SECRET_FIELDS = (('ntfy', 'token'), ('gotify', 'token'))
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
            s['alerts'][ch][f] = '••••••' if s['alerts'][ch].get(f) else ''
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


def send(cfg: dict, title: str, message: str, level: str = 'warn', extra: dict | None = None) -> list[str]:
    """Push one notification to every configured channel. Returns what was sent (or why not), per channel."""
    out = []
    prio = {'crit': 5, 'warn': 4, 'ok': 2}.get(level, 3)
    n, g, w = cfg.get('ntfy') or {}, cfg.get('gotify') or {}, cfg.get('webhook') or {}
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
    from . import deploy, jobs, moves, shares
    out = []
    expected = {}
    for r in conn.all('SELECT job_id, runner_host, spec_json, paused FROM jobs WHERE removed_at IS NULL'):
        spec = json.loads(r[2] or '{}')
        if spec and not r[3]:
            try:
                expected.setdefault(r[1], set()).update(jobs.units({**spec, 'id': r[0]})[1])
            except (KeyError, TypeError):
                pass
    for host, inv in conn.all('SELECT hostname, inventory_json FROM hosts'):
        text = (json.loads(inv or '{}') or {}).get('managed')
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
    del moves
    return out


# ── evaluation ──────────────────────────────────────────────────────
def problems(conn: Conn) -> dict:
    from . import jobs
    now = {}
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
