"""HTTP API and graph UI on Flask, with Flask-Login sessions for local accounts. Meant to sit behind a TLS
reverse proxy or on loopback.

GET  /healthz                       liveness + readiness (no auth)
GET  /login                         sign-in page (the only page served without a session)
GET  /                              graph UI; without a valid session, a redirect to /login?next=/
GET  /planner                       storage planner UI; likewise
POST /api/login  {"username", "password"}   start a session (cookie)
POST /api/logout                    end it
POST /api/reauth  {"password"}      confirm the password before commands run on hosts (good for REAUTH_WINDOW)
GET|PUT /api/me                     the signed-in user; PUT {"session_minutes"} sets how long sessions last (30-480)
GET  /api/hosts                     indexed hosts
GET  /api/graph[?host=]             nodes and edges
GET  /api/canvas[?host=]            Obsidian .canvas download
GET  /api/search?q=&host=&size_gt=&type=&under=&limit=
GET  /api/jobs                      recent scan jobs
GET  /api/audit[?limit=]            newest audit entries
GET  /api/audit/verify              hash-chain verification (unlocks the vault)
GET  /api/log[?host=&sources=&outcomes=&q=&since=&until=&limit=&offset=]   what has been done, from every source
GET  /api/log/output?id=             the full output of one deploy run or fetched log
GET  /api/log/export?format=csv|json|text[&output=1&...]   the same list as a file
POST /api/scan  {"host": "…"}       queue a vault-backed scan
POST /api/scan/all                  queue a scan of every host with a scan binding
GET  /api/keys                      vault keys (public halves) and host bindings
POST /api/keys  {"name", "type"}     generate a key inside the vault
POST /api/hostkey/confirm  {"host", "port", "fingerprint"}   a person compared the host key: pin it, passwords may go there
POST /api/keys/install  {"key", "host", "user", "port", "password", "bind"}
                                    ssh-copy-id the public key, then optionally bind it for scans
GET  /api/access?host=               per host: how scans read the disks, and folders they could not open
GET  /api/access/script?host=&remove=1   the read-only scan access setup (or removal) script, to run as root
POST /api/access/grant  {"host", "password", "admin_user", "remove"}   run that script once over SSH with sudo
GET  /api/folders/duplicates?host=&min_files=&min_size=   folders that are copies by name and structure
GET  /api/browse?host=&path=         subfolders of a path with their indexed sizes (for picking move sources)
GET  /api/moves                      saved move plans;  POST creates one from {"name", "steps": [...]}
GET|PUT|DELETE /api/moves/<id>       one plan
POST /api/moves/check                check a plan (saved or not) against the index: sizes, space, mounts, loops
GET  /api/moves/<id>/script          the Bash script that runs the plan (copy, verify, cutover, install)
GET  /api/folders/cold?host=&years=&min_size=   folders whose newest file is older than the cutoff
GET  /api/git?host=                  git repositories found by scans, with their copies and archive state
GET  /api/shares/check?host=         the NFS/SMB shares in a host's design, checked against the index
GET  /api/shares/script?host=        the script that deploys them on the server and mounts them on clients
POST /api/shares/validate  {"host", "export", "index"|"was"}   check one share before saving it (folder, access, mount points)
POST /api/shares  {"host", "export", "index"|"was"}   add the share to the host's design, or replace share #index or the share "was" {protocol, name, path}
DELETE /api/shares?host=&index= or &protocol=&name=&path=      remove a designed share from the host's design
GET  /api/fs/browse?host=&path=      folders and files at a path from the index, with mounts, shares and planned mounts
GET  /api/tasks                      saved storage tasks, block types, templates and where tasks are installed
POST /api/tasks  {"name", "host", "schedule", "blocks": [...], "on_fail": [...]}   save a new task
GET|PUT|DELETE /api/tasks/<id>       one task
POST /api/tasks/check                check a task (saved or not) against the index, block by block
POST /api/tasks/script               the Bash script of a task (saved or not)
GET  /api/changes/types              the task types of change plans, with their fields (the UI builds its forms from it)
GET  /api/changes                    saved change plans;  POST creates one from {"name", "tasks": [...]}
GET|PUT|DELETE /api/changes/<id>     one plan
POST /api/changes/check              check a plan against the index, task by task, in order
GET  /api/changes/<id>/script        the Bash script (report, --apply, --destructive)
GET  /api/changes/<id>/ansible       the same plan as an Ansible playbook
GET  /api/docker?host=               containers, compose stacks (running, stopped, stored), volumes, unused volumes
GET  /api/docker/usage?host=&path=   containers that use a folder (bind mounts and volume data)
GET  /api/deploy                     deploy access per host, deployed jobs and shares, open alerts, drift, settings
POST /api/deploy/setup-script        {"remove"?}: the deploy setup script, to run as root by hand (makes the deploy keys)
POST /api/deploy/access              {"host", "password", "admin_user"?, "remove"?}: set deploy access up (or remove it) with sudo once
POST /api/deploy/adopt               {"host"}: after running the setup script by hand, bind the key and test a signed run
POST /api/deploy/start               {"kind": jobs|shares|changes|tasks, "ref", "mode": report|apply, "title"?, "report_group"?, "paused"?, "destructive"?}
GET  /api/deploy/groups              recent deploys and how their hosts went
GET  /api/deploy/groups/<id>         one deploy and its runs, with their output (poll while running)
POST /api/deploy/groups/<id>/cancel  {"force"?}: nothing new starts; force also stops what is running
POST /api/deploy/groups/<id>/retry   run it again on the hosts that did not finish (every host, for jobs)
POST /api/deploy/check               {"host"}: what the host can run: a signed probe, or from its last scan if not set up
GET  /api/deploy/runs[/<id>]         deploy history, or one run's output
GET  /api/deploy/jobs/<id>           one deployed job and its run history
POST /api/deploy/jobs/<id>/<verb>    run, dryrun, verify, pause, resume, cutover, log, snapshots
POST /api/deploy/jobs/<id>/browse  {"snapshot", "path"}   a folder inside an rsnapshot snapshot (runs ls on the host)
POST /api/deploy/jobs/<id>/restore   {"snapshot", "path"}: copy it back to the source as <path>.restored-<time>
GET|PUT /api/deploy/settings         report URL and alert channels;  POST /api/deploy/settings/test sends a test alert
POST /api/jobs/report                a job's run result (Authorization: Bearer <job token>; no session)
GET  /api/hostconfigs[?host=]         saved host configurations: the newest of each host, or every version of one
GET  /api/hostconfigs/<id>            one version: what it holds, and what changed since the version before
GET  /api/hostconfigs/script?host=&id=   the reinstall script (mounts, accounts, shares, symlinks)
GET  /api/hostconfigs/bundle?host=&id=   a .tar.gz of scripts, records and config files (every host without host=)
GET  /api/backups                    backups on disk;  POST {"kind": "essentials"|"full"} makes one now
GET  /api/planner/hosts             scanned hosts and saved designs
GET  /api/planner/design?host=&source=saved|scan   a design: the saved one, or built from the latest scan
PUT  /api/planner/example  {"show"}  show or remove the built-in example host "atlas" for everyone
GET  /api/planner/activity?host=     staged changes, moves, shares, deployed jobs and drift on a host
PUT  /api/planner/design            save a storageforge/v1 blueprint (overlaid on the graph and reports)
POST /api/planner/changes           a design (saved or not) against the latest scan: the change-plan tasks it needs,
                                    what Changes can't do, and what the design leaves alone. Stages nothing
"""
from __future__ import annotations

import functools
import ipaddress
import json
import os
import queue
import re
import secrets
import socket
import subprocess
import sys
import threading
import time
import traceback
from datetime import timedelta
from pathlib import Path
from urllib.parse import urlencode

from flask import Flask, Response, g, jsonify, redirect, request, send_from_directory, session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import LoginManager, current_user, login_required, login_user, logout_user
from werkzeug.exceptions import HTTPException
from werkzeug.middleware.proxy_fix import ProxyFix

from . import (__version__, access, alerts, blueprint, canvas, changes, deploy, docker, engine, folders, gitrepos, graph, jobs, logbook, preflight,
               fromdesign, fsmap, hostconfig, hostkeys, keyinstall, moves, reinstall, shares, tasks, users)
from .capacity import parse_size
from .db import Database, epoch
from .hostkeys import HostKeyNeeded
from .remote import RemoteError
from .runner import connect_address, scan_via_vault
from .scanner import ScanOptions
from .search import SearchQuery, run_search
from .vault import AuditLog, SecretBuffer, Vault, VaultError, fingerprint

STATIC = Path(__file__).with_name('static')
SECURITY_HEADERS = {
    # style-src-attr allows style="" attributes (the planner sizes bars and swatches inline); never <style> or scripts.
    'Content-Security-Policy': "default-src 'self'; img-src 'self' data:; style-src 'self'; style-src-attr 'unsafe-inline'; "
                               "script-src 'self'; "
                               "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
    'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer', 'X-Frame-Options': 'DENY',
    'Cross-Origin-Opener-Policy': 'same-origin', 'Cache-Control': 'no-store',
}
MAX_BODY = 4096
# all: every request · changes (default): requests that change something, rate-limit hits and server errors · off
ACCESS_LOG = os.environ.get('STORAGEFORGE_ACCESS_LOG', 'changes').lower()
SCAN_WORKERS = max(1, int(os.environ.get('STORAGEFORGE_SCAN_WORKERS', '4')))  # hosts scanned at once
BACKUP_HOUR = int(os.environ.get('STORAGEFORGE_BACKUP_HOUR', '3'))          # local hour for the nightly backup and prune
BACKUP_KEEP = int(os.environ.get('STORAGEFORGE_BACKUP_KEEP', '14'))         # essentials backups kept
BACKUP_FULL = int(os.environ.get('STORAGEFORGE_BACKUP_FULL_KEEP', '0'))     # full backups kept nightly (0: on demand only)
CONFIG_EXPORT_DIR = os.environ.get('STORAGEFORGE_CONFIG_EXPORT_DIR')         # nightly host config bundle: mount another machine's storage here
ALERT_TICK = 300                  # alerts and drift are re-evaluated this often (and right after a job reports)
SCHEDULE_TICK = 600               # the scheduler looks for due hosts this often (seconds)
MAX_BLUEPRINT = 2 << 20           # planner designs are the one large body we accept
# Failed sign-ins allowed before /api/login answers 429; successful ones are not counted.
LOGIN_LIMIT_PER_IP = '10 per minute; 50 per hour'
LOGIN_LIMIT_PER_USER = '5 per minute; 20 per hour'     # per account and client network (/24, /64)
LOGIN_LIMIT_PER_ACCOUNT = '100 per day'                # per account from anywhere: the backstop for spread-out guessing
INSTALL_LIMIT = '10 per minute'     # each attempt is one password try on the target
# Routes that run commands on hosts want the account password typed again within this many seconds.
REAUTH_WINDOW = 300
KEY_NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,63}')


def session_secret_from_env() -> str:
    s = os.environ.get('STORAGEFORGE_SESSION_SECRET')
    path = os.environ.get('STORAGEFORGE_SESSION_SECRET_FILE')
    if not s and path:
        s = Path(path).read_text().strip()
    if s and len(s) < 32:
        raise SystemExit('STORAGEFORGE_SESSION_SECRET must be at least 32 characters (openssl rand -base64 48)')
    if not s:
        print('warning: STORAGEFORGE_SESSION_SECRET is not set; sessions end when the server restarts', file=sys.stderr)
        s = secrets.token_urlsafe(48)
    return s


class App:
    def __init__(self, db: Database, scan_interval: int | None = None, parallel: int = 4):
        self.db, self.parallel, self.scan_db = db, parallel, db.patient()
        self.audit_key = None
        conn = db.connect()
        try:   # keep only the audit MAC key in memory; the KEK is wiped right after unlock
            with Vault(db, conn).unlock() as v:
                self.audit_key = SecretBuffer(32)
                self.audit_key.buf[:32] = v.audit_key.view()
                self.audit_key.length = 32
        except VaultError as exc:
            print(f'warning: vault locked ({exc}); API audit entries use plain SHA-256 chaining', file=sys.stderr)
        finally:
            conn.close()
        self.queue: queue.Queue[int] = queue.Queue()
        self.enqueue_lock = threading.Lock()
        self.workers = [threading.Thread(target=self._work, name=f'scan-worker-{i}', daemon=True) for i in range(SCAN_WORKERS)]
        for w in self.workers:
            w.start()
        conn = db.connect()
        try:   # jobs interrupted by a restart are marked failed, not left "running" forever
            conn.execute("UPDATE deploy_runs SET status = 'failed', finished_at = :t, output = output || :o "
                         "WHERE status IN ('queued', 'running')",
                         {'t': int(time.time()), 'o': '\ninterrupted by restart: this run may or may not have finished on the host\n'})
            engine.close_interrupted(conn)
            conn.execute("UPDATE scan_jobs SET status = 'failed', finished_at = :t, result_json = :r "
                         "WHERE status IN ('queued', 'running')",
                         {'t': int(time.time()), 'r': json.dumps({'error': 'interrupted by restart'})})
        finally:
            conn.close()
        if scan_interval:
            threading.Thread(target=self._schedule, args=(scan_interval,), name='scheduler', daemon=True).start()
        threading.Thread(target=self._nightly, name='nightly', daemon=True).start()
        self.alerts_wake = threading.Event()
        threading.Thread(target=self._alerts, name='alerts', daemon=True).start()

    def _alerts(self):
        time.sleep(30)
        while True:
            try:
                alerts.evaluate(self.db)
            except Exception:
                traceback.print_exc()
            self.alerts_wake.wait(ALERT_TICK)
            self.alerts_wake.clear()

    @staticmethod
    def canonical(conn, host: str) -> str:
        """One name per machine: a binding's IP, an ssh alias and the hostname all queue as the indexed hostname, so
        the scheduler and "Scan now" can't start two scans of one host under different names."""
        row = conn.all("""SELECT hostname FROM hosts WHERE lower(hostname) = lower(:h) OR ssh_host = :h OR ip_address = :h
                          ORDER BY CASE WHEN lower(hostname) = lower(:h) THEN 0 WHEN ssh_host = :h THEN 1 ELSE 2 END,
                                   last_scanned_at DESC""", {'h': host})   # a host's self-reported IP comes last
        return row[0][0] if row else host

    def enqueue(self, host: str, actor: str) -> int:
        conn = self.db.connect()
        try:
            host = self.canonical(conn, host)
            with self.enqueue_lock:     # workers run side by side: two requests at once must not start one host twice
                busy = conn.scalar("SELECT job_id FROM scan_jobs WHERE host = :h AND status IN ('queued', 'running')", {'h': host})
                if busy:
                    return busy
                jid = conn.scalar("INSERT INTO scan_jobs (host, requested_by, queued_at) VALUES (:h, :a, :t) RETURNING job_id",
                                  {'h': host, 'a': actor, 't': int(time.time())})
        finally:
            conn.close()
        self.queue.put(jid)
        return jid

    def audit(self, conn, actor: str, action: str, outcome: str, host: str | None, detail: dict):
        AuditLog(self.db, conn, self.audit_key).append(actor, action, outcome, host, None, detail)

    def _work(self):
        while True:
            jid = self.queue.get()
            conn = self.scan_db.connect()
            try:
                host, actor = conn.all('SELECT host, requested_by FROM scan_jobs WHERE job_id = :j', {'j': jid})[0]
                conn.execute("UPDATE scan_jobs SET status = 'running', started_at = :t WHERE job_id = :j",
                             {'t': int(time.time()), 'j': jid})
                try:
                    opts = ScanOptions(parallel=self.parallel, include_fstypes=[
                        x for x in os.environ.get('STORAGEFORGE_INCLUDE_FSTYPES', '').split(',') if x])
                    res = scan_via_vault(self.scan_db, host, opts, actor=actor,
                                         log=lambda m: print(f'[job {jid}] {m}', file=sys.stderr, flush=True))
                    status, result = res['status'], res
                except Exception as exc:
                    status, result = 'failed', {'error': str(exc)}
                conn.execute('UPDATE scan_jobs SET status = :s, finished_at = :t, result_json = :r WHERE job_id = :j',
                             {'s': status, 't': int(time.time()), 'r': json.dumps(result, default=str), 'j': jid})
                self.scan_db.prune(conn)             # cheap deletes; keeps change history and denied lists bounded
            except Exception:
                traceback.print_exc()
            finally:
                conn.close()

    def bound_hosts(self) -> list[str]:
        """Hosts bound by name for scanning, under their indexed hostnames."""
        return self.due_hosts(0)

    def due_hosts(self, interval: int, now: float | None = None) -> list[str]:
        """Bound hosts whose last scan job (of any outcome) is older than the interval. A restart therefore never
        triggers a burst of scans, and a host that keeps failing is retried once per interval, not every tick."""
        now = now or time.time()
        conn = self.db.connect()
        try:
            due = []
            for (pattern,) in conn.all("""SELECT DISTINCT host_pattern FROM key_bindings
                                          WHERE pattern_kind = 'host' AND allowed_actions LIKE :a""", {'a': '%scan%'}):
                name = self.canonical(conn, pattern)
                last = conn.scalar('SELECT max(queued_at) FROM scan_jobs WHERE host IN (:n, :p)', {'n': name, 'p': pattern})
                done = epoch(conn.scalar('SELECT last_scanned_at FROM hosts WHERE hostname = :n', {'n': name}))
                last = max(x for x in (last, done, 0) if x is not None) or None     # CLI scans count too
                if name not in due and (last is None or now - last >= interval * 0.95):
                    due.append(name)
            return due
        finally:
            conn.close()

    def nightly_once(self) -> dict:
        """Backups and retention. Runs at BACKUP_HOUR, and at start-up when the newest essentials backup is a day old."""
        from . import backup
        conn = self.db.connect()
        out = {}
        try:
            try:
                out['backup'] = backup.create(self.db, 'essentials', keep=BACKUP_KEEP)
                if BACKUP_FULL:
                    out['full'] = backup.create(self.db, 'full', keep=BACKUP_FULL)
                self.audit(conn, 'system', 'backup.create', 'ok', None, {k: v['path'] for k, v in out.items()})
            except (Exception, SystemExit) as exc:
                out['error'] = str(exc)
                self.audit(conn, 'system', 'backup.create', 'failed', None, {'error': str(exc)[:300]})
            if CONFIG_EXPORT_DIR:
                try:
                    out['hostconfigs'] = hostconfig.export_to(conn, CONFIG_EXPORT_DIR)
                    self.audit(conn, 'system', 'hostconfig.export', 'ok', None, out['hostconfigs'])
                except Exception as exc:
                    out['hostconfigs_error'] = str(exc)
                    self.audit(conn, 'system', 'hostconfig.export', 'failed', None, {'error': str(exc)[:300]})
            out['pruned'] = self.db.prune(conn)
        finally:
            conn.close()
        print(f'nightly: {out}', file=sys.stderr, flush=True)
        return out

    def _nightly(self):
        from . import backup
        time.sleep(120)                          # let start-up and any first scan settle
        try:
            newest = backup.listing()
            if self.db.dialect == 'sqlite' and (not [b for b in newest if b['kind'] == 'essentials']
                                                or time.time() - newest[0]['created'] > 86400):
                self.nightly_once()
        except Exception:
            traceback.print_exc()
        while True:
            now = time.localtime()
            wait = ((BACKUP_HOUR - now.tm_hour) % 24) * 3600 - now.tm_min * 60 - now.tm_sec
            time.sleep(wait if wait > 0 else wait + 86400)
            try:
                if self.db.dialect == 'sqlite':
                    self.nightly_once()
                else:
                    conn = self.db.connect()
                    try:
                        self.db.prune(conn)
                    finally:
                        conn.close()
            except Exception:
                traceback.print_exc()

    def _schedule(self, interval: int):
        while True:
            try:
                for h in self.due_hosts(interval):
                    self.enqueue(h, 'scheduler')
            except Exception:
                traceback.print_exc()
            time.sleep(min(interval, SCHEDULE_TICK))


class _FromProxy:
    """X-Forwarded-For and -Proto, believed only from the proxy (proxy_host: its name or address). Anything else that
    reaches the app directly, on a Docker network it shares, could claim any client address. The name is looked up
    again every 30 seconds (a recreated proxy container gets a new address), and at most every 5 for an unknown peer."""

    def __init__(self, app, hops: int, proxy_host: str):
        # Proto from the nearest proxy only: it is the one that terminated TLS
        self.plain, self.fixed, self.proxy_host = app, ProxyFix(app, x_for=hops, x_proto=1), proxy_host
        self.addrs: set[str] = set()
        self.at = 0.0

    def _is_proxy(self, peer: str) -> bool:
        now = time.time()
        if now - self.at > 30 or (peer not in self.addrs and now - self.at > 5):
            self.at = now
            try:
                self.addrs = {ai[4][0] for ai in socket.getaddrinfo(self.proxy_host, None, proto=socket.IPPROTO_TCP)}
            except OSError:
                self.addrs = set()
        return peer in self.addrs

    def __call__(self, environ, start_response):
        # /healthz uses no forwarded header and needs no lookup: compose starts the proxy only once the app is healthy, so
        # until then the name doesn't exist, and a DNS server that is slow to say so would time out the health check
        if environ.get('PATH_INFO') == '/healthz':
            return self.plain(environ, start_response)
        if not self.proxy_host or self._is_proxy(environ.get('REMOTE_ADDR', '')):
            return self.fixed(environ, start_response)
        return self.plain(environ, start_response)


def create_app(core: App, session_secret: str, secure_cookies: bool = False, proxy_hops: int = 0,
               proxy_host: str = '') -> Flask:
    web = Flask(__name__, static_folder=None)
    if proxy_hops:   # trust X-Forwarded-For from this many proxies, so limits and audit see the real client
        web.wsgi_app = _FromProxy(web.wsgi_app, proxy_hops, proxy_host)
    web.config.update(
        SECRET_KEY=session_secret, MAX_CONTENT_LENGTH=MAX_BODY,
        # __Host-: browsers only accept it over https, for Path=/ and without Domain, so no other site or subdomain can set it
        SESSION_COOKIE_NAME='__Host-sf_session' if secure_cookies else 'sf_session',
        SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Strict',
        SESSION_COOKIE_SECURE=secure_cookies,
        # the cookie signature's age limit; each user's own (shorter) session length is checked in load_user
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=users.MAX_SESSION_MINUTES),
    )
    db = core.db
    login = LoginManager(web)
    login.session_protection = 'strong'
    limiter = Limiter(get_remote_address, app=web, storage_uri='memory://', headers_enabled=True)

    def conn():
        if 'conn' not in g:
            g.conn = db.connect()
        return g.conn

    @web.teardown_appcontext
    def close_conn(_exc):
        c = g.pop('conn', None)
        if c is not None:
            c.close()

    @login.user_loader
    def load_user(session_id):
        user = users.load(conn(), session_id)
        if user and not users.session_alive(conn(), session.get('sid'), user.user_id):
            return None                       # signed out (here or elsewhere): a copied cookie is dead too
        if user and time.time() - session.get('login_at', 0) > user.session_minutes * 60:
            users.end_session(conn(), session.get('sid'))
            g.session_expired = True
            return None
        return user

    @login.unauthorized_handler
    def unauthorized():
        if g.get('session_expired'):
            session.clear()
            return jsonify(error='your session ended: sign in again'), 401
        return jsonify(error='sign in required'), 401

    def password_stale():
        """A 403 asking for the password again when it was last typed more than REAUTH_WINDOW ago, else None."""
        if time.time() - session.get('auth_at', 0) > REAUTH_WINDOW:
            return jsonify(error='confirm your password to run commands on hosts', reauth=True), 403
        return None

    def password_confirmed(view):
        @functools.wraps(view)
        def wrapped(*args, **kwargs):
            return password_stale() or view(*args, **kwargs)
        return wrapped

    @web.before_request
    def body_limit():
        if request.path in ('/api/planner/design', '/api/planner/changes') and request.method in ('PUT', 'POST'):
            request.max_content_length = MAX_BLUEPRINT

    @web.after_request
    def headers(resp: Response):
        for k, v in SECURITY_HEADERS.items():
            resp.headers.setdefault(k, v)
        resp.headers['Server'] = 'StorageForge'
        if ACCESS_LOG == 'all' or (ACCESS_LOG == 'changes' and (request.method not in ('GET', 'HEAD') or resp.status_code >= 500
                                                                  or resp.status_code == 429)):
            print(f'{request.remote_addr} {request.method} {request.path} {resp.status_code}', file=sys.stderr, flush=True)
        return resp

    @web.errorhandler(Exception)
    def on_error(exc):
        if isinstance(exc, HTTPException):
            return jsonify(error=exc.description), exc.code
        if isinstance(exc, HostKeyNeeded):   # the UI shows the fingerprint, then POSTs /api/hostkey/confirm and retries
            return jsonify(error=str(exc), hostkey=exc.as_dict()), 409
        if isinstance(exc, (ValueError, VaultError)):
            return jsonify(error=str(exc)), 400
        traceback.print_exc()
        return jsonify(error=f'internal error: {type(exc).__name__}'), 500

    def actor() -> str:
        return f'web:{current_user.username}' if current_user.is_authenticated else f'web:{request.remote_addr}'

    def arg_num(name: str, default, lo, hi, kind=int):
        """A numeric query argument held to [lo, hi]: a negative LIMIT means "no limit" in SQLite."""
        raw = request.args.get(name)
        try:
            v = kind(raw) if raw not in (None, '') else default
        except ValueError:
            raise ValueError(f'{name} must be a number') from None
        if v != v or v in (float('inf'), float('-inf')):        # nan, inf
            raise ValueError(f'{name} must be a number')
        return max(lo, min(v, hi))

    def json_body() -> dict:
        # JSON only: a cross-site form cannot send application/json without a CORS preflight, which we never grant.
        body = request.get_json(silent=True) if request.is_json else None
        if not isinstance(body, dict):
            raise ValueError('expected a JSON object body')
        return body

    # pages: only /login without a session; the app and planner pages and their scripts need one
    def page(name):
        resp = send_from_directory(STATIC, name, max_age=0)
        resp.headers['Cache-Control'] = 'no-store'      # never kept for the back button after signing out
        return resp

    def safe_next(value: str | None) -> str:
        # a path on this site only: "//evil" or "/\\evil" would leave it
        return value if value and re.fullmatch(r'/(?![/\\])[^\s]*', value) else '/'

    def to_login():
        args = {'next': request.full_path.rstrip('?')}
        if g.get('session_expired'):
            session.clear()
            args['ended'] = '1'
        return redirect('/login?' + urlencode(args))

    @web.get('/')
    @web.get('/index.html')
    def index():
        return page('index.html') if current_user.is_authenticated else to_login()

    @web.get('/planner')
    def planner():
        return page('planner.html') if current_user.is_authenticated else to_login()

    @web.get('/login')
    def login_page():
        if current_user.is_authenticated:
            return redirect(safe_next(request.args.get('next')))
        return page('login.html')

    @web.get('/<any("login.js", "style.css", "favicon.svg"):name>')
    def public_static(name):
        resp = send_from_directory(STATIC, name, max_age=0)
        resp.headers['Cache-Control'] = 'no-cache'
        return resp

    @web.get('/<any("session.js", "app.js", "topology.js", "checks.js", "moves.js", "changes.js", "gitview.js", "rebuildview.js", "dockerview.js", "deployview.js", "fsbrowse.js", "sharewiz.js", "tasks.js", "planner.js", "planner.css"):name>')
    @login_required
    def static(name):
        resp = send_from_directory(STATIC, name, max_age=0)
        resp.headers['Cache-Control'] = 'no-cache'
        return resp

    @web.get('/healthz')
    def healthz():
        checks = {}
        try:
            c = conn()
            c.scalar('SELECT 1')
            checks['database'] = 'ok'
            checks['vault'] = 'initialised' if c.scalar('SELECT count(*) FROM vault_meta') else 'not initialised'
            checks['users'] = users.count(c)
        except Exception as exc:
            checks['database'] = f'error: {type(exc).__name__}'
        checks['worker'] = 'ok' if all(w.is_alive() for w in core.workers) else 'dead'
        healthy = checks.get('database') == 'ok' and checks['worker'] == 'ok'
        code = 200 if healthy else 503
        # details (version, users, vault state) only for the container's own HEALTHCHECK and signed-in users
        local = request.remote_addr in ('127.0.0.1', '::1') and 'X-Forwarded-For' not in request.headers
        if not (local or current_user.is_authenticated):
            return jsonify(status='ok' if healthy else 'unhealthy'), code
        return jsonify(status='ok' if healthy else 'unhealthy', version=__version__, **checks), code

    def login_username() -> str:
        body = request.get_json(silent=True) if request.is_json else None
        return 'user:' + (str(body.get('username', '')).lower()[:64] if isinstance(body, dict) else '')

    def client_net() -> str:
        try:
            ip = ipaddress.ip_address(request.remote_addr or '')
        except ValueError:
            return request.remote_addr or ''
        return str(ipaddress.ip_network(f'{ip}/{24 if ip.version == 4 else 64}', strict=False))

    def login_user_net() -> str:
        # Someone guessing from elsewhere uses up this account's tries on *their* network, not the owner's.
        return f'{login_username()}@{client_net()}'

    def failed(resp: Response) -> bool:
        return resp.status_code == 401

    signed_in_from: set[tuple[str, str]] = set()      # (username, network) of sign-ins since the server started

    def known_network() -> bool:
        """This account signed in from this network before (a live session, or since the server started): its owner,
        most likely. The per-account daily limit is for guessing spread over many networks, so it does not lock the
        owner out from where they usually sign in."""
        user, net = login_username()[5:], client_net()
        if not user or (user, net) in signed_in_from:
            return bool(user)
        for (client,) in conn().all('SELECT s.client FROM web_sessions s JOIN users u ON u.user_id = s.user_id '
                                    'WHERE lower(u.username) = :u', {'u': user}):
            try:
                ip = ipaddress.ip_address(client or '')
            except ValueError:
                continue
            if str(ipaddress.ip_network(f'{ip}/{24 if ip.version == 4 else 64}', strict=False)) == net:
                return True
        return False

    breaches: dict[tuple, float] = {}
    breaches_lock = threading.Lock()

    def limited(limit):
        # every refused request is a breach: one audit row per limit and client every 5 minutes, not one per request
        key = (str(limit.limit), login_username(), client_net())
        now = time.time()
        with breaches_lock:
            if now - breaches.get(key, 0) < 300:
                return
            breaches[key] = now
            for k in [k for k, t in breaches.items() if now - t >= 300]:
                del breaches[k]
        core.audit(conn(), f'web:{request.remote_addr}', 'web.login.limited', 'denied', None,
                   {'username': login_username()[5:], 'limit': str(limit.limit)})

    # session
    @web.post('/api/login')
    @limiter.limit(LOGIN_LIMIT_PER_IP, deduct_when=failed, on_breach=limited,
                   error_message='too many failed sign-ins; try again later')
    @limiter.limit(LOGIN_LIMIT_PER_USER, key_func=login_user_net, deduct_when=failed, on_breach=limited,
                   error_message='too many failed sign-ins for this account; try again later')
    @limiter.limit(LOGIN_LIMIT_PER_ACCOUNT, key_func=login_username, deduct_when=failed, on_breach=limited,
                   exempt_when=known_network, error_message='too many failed sign-ins for this account today; try again later')
    def api_login():
        body = json_body()
        name, password = str(body.get('username', '')), str(body.get('password', ''))
        if not name or not password:     # nothing was guessed: no try used up, nothing for the audit log
            return jsonify(error='enter a username and a password'), 400
        user = users.authenticate(conn(), name, password)
        core.audit(conn(), f'web:{request.remote_addr}', 'web.login', 'ok' if user else 'denied', None, {'username': name[:64]})
        if not user:
            return jsonify(error='wrong username or password'), 401
        session.clear()
        session['login_at'] = session['auth_at'] = int(time.time())
        session['sid'] = users.start_session(conn(), user.user_id, request.remote_addr)
        signed_in_from.add((user.username.lower(), client_net()))
        login_user(user)
        return jsonify(username=user.username)

    @web.post('/api/logout')
    def api_logout():
        users.end_session(conn(), session.get('sid'))
        logout_user()
        session.clear()
        return jsonify(ok=True)

    @web.post('/api/reauth')
    @login_required
    @limiter.limit(LOGIN_LIMIT_PER_USER, key_func=lambda: f'reauth:{current_user.get_id()}',
                   deduct_when=lambda resp: resp.status_code == 403, error_message='too many wrong passwords; try again later')
    def api_reauth():
        ok = users.confirm(conn(), current_user.user_id, str(json_body().get('password', '')))
        core.audit(conn(), actor(), 'web.reauth', 'ok' if ok else 'denied', None, {})
        if not ok:
            return jsonify(error='wrong password'), 403     # not 401: the session itself is still good
        session['auth_at'] = int(time.time())
        return jsonify(ok=True, until=session['auth_at'] + REAUTH_WINDOW)

    def me():
        login_at = session.get('login_at', 0)
        return dict(username=current_user.username, session_minutes=current_user.session_minutes,
                    session_ends=login_at + current_user.session_minutes * 60, min_minutes=users.SESSION_MINUTES,
                    max_minutes=users.MAX_SESSION_MINUTES)

    @web.get('/api/me')
    @login_required
    def api_me():
        return jsonify(me())

    @web.put('/api/me')
    @login_required
    @password_confirmed
    def api_me_update():
        try:
            minutes = int(json_body().get('session_minutes'))
        except (TypeError, ValueError):
            raise ValueError('session_minutes must be a number') from None
        current_user.session_minutes = users.set_session_minutes(conn(), current_user.user_id, minutes)
        core.audit(conn(), actor(), 'web.session-length', 'ok', None, {'minutes': minutes})
        return jsonify(me())

    # data
    @web.get('/api/hosts')
    @login_required
    def api_hosts():
        rows = conn().all('SELECT hostname, ip_address, os_info, last_scanned_at FROM hosts ORDER BY hostname')
        graph_hosts = [r[0] for r in conn().all("SELECT label FROM graph_nodes WHERE kind = 'Host' AND host IS NOT NULL ORDER BY label")]
        return jsonify(indexed=[dict(zip(('hostname', 'ip', 'os', 'last_scanned_at'), (*r[:3], epoch(r[3]))))
                                for r in rows],
                       graph=graph_hosts)

    @web.get('/api/graph')
    @login_required
    def api_graph():
        return Response(json.dumps(graph.load(conn(), request.args.get('host') or None), default=str),
                        mimetype='application/json')

    @web.get('/api/canvas')
    @login_required
    def api_canvas():
        host = request.args.get('host') or None
        name = f'storageforge-{host or "network"}.canvas'.replace('/', '_').replace('"', '')
        return Response(canvas.dumps(graph.load(conn(), host)), mimetype='application/json',
                        headers={'Content-Disposition': f'attachment; filename="{name}"'})

    @web.get('/api/search')
    @login_required
    def api_search():
        q = request.args
        sq = SearchQuery(pattern=q.get('q') or None, hosts=[q['host']] if q.get('host') else [],
                         size_gt=parse_size(q['size_gt']) if q.get('size_gt') else None,
                         ftype=q.get('type') if q.get('type') in ('f', 'd', 'l') else None,
                         under=q.get('under') or None, limit=arg_num('limit', 100, 1, 500), sort='path')
        if not (sq.pattern or sq.size_gt or sq.under):
            raise ValueError('give q, size_gt or under')
        return Response(json.dumps({'results': run_search(db, conn(), sq)}, default=str), mimetype='application/json')

    @web.get('/api/jobs')
    @login_required
    def api_jobs():
        rows = conn().all("""SELECT job_id, host, requested_by, status, queued_at, started_at, finished_at, result_json
                             FROM scan_jobs ORDER BY job_id DESC LIMIT 50""")
        return jsonify(jobs=[dict(zip(('job_id', 'host', 'requested_by', 'status', 'queued_at', 'started_at',
                                       'finished_at'), r[:7])) | {'result': json.loads(r[7] or 'null')} for r in rows])

    @web.get('/api/audit')
    @login_required
    def api_audit():
        limit = arg_num('limit', 100, 1, 1000)
        return Response(json.dumps({'entries': AuditLog(db, conn(), None).tail(limit)}, default=str),
                        mimetype='application/json')

    @web.get('/api/audit/verify')
    @login_required
    def api_audit_verify():
        with Vault(db, conn()).unlock() as v:
            log = AuditLog(db, conn(), v.audit_key)
            ok, n, bad = log.verify()
            weak = log.unkeyed()                 # keyless entries after keyed ones: rewritable by a database writer
        return jsonify(valid=ok, entries_checked=n, first_bad_id=bad, **weak)

    def log_filter():
        a = request.args
        return logbook.clean_filter(a.get('host'), a.get('sources'), a.get('outcomes'), a.get('q'), a.get('since'), a.get('until'))

    @web.get('/api/log')
    @login_required
    def api_log():
        return Response(json.dumps(logbook.page(conn(), log_filter(), arg_num('limit', 100, 1, 500), arg_num('offset', 0, 0, logbook.MAX_EXPORT)),
                                   default=str), mimetype='application/json')

    @web.get('/api/log/output')
    @login_required
    def api_log_output():
        return jsonify(id=request.args.get('id', ''), output=logbook.output_of(conn(), request.args.get('id', '')))

    @web.get('/api/log/export')
    @login_required
    def api_log_export():
        f, fmt = log_filter(), request.args.get('format') or 'csv'
        text, n = logbook.export(conn(), f, fmt, request.args.get('output') in ('1', 'true'))
        core.audit(conn(), actor(), 'log.export', 'ok', f['host'], {'format': fmt, 'entries': n, 'q': f['q'],
                                                                    'sources': sorted(f['sources']), 'outcomes': sorted(f['outcomes'])})
        mime, ext = logbook.FORMATS[fmt]
        stamp = time.strftime('%Y%m%d-%H%M%S', time.gmtime())
        return Response(text, mimetype=mime.split(';')[0], headers={
            'Content-Disposition': f'attachment; filename="storageforge-log-{stamp}.{ext}"', 'X-Content-Type-Options': 'nosniff'})

    @web.post('/api/scan')
    @login_required
    def api_scan():
        host = str(json_body().get('host', '')).strip()
        if not host or len(host) > 253 or any(c.isspace() for c in host):
            raise ValueError('body must be {"host": "<hostname or IP>"}')
        jid = core.enqueue(host, actor())
        core.audit(conn(), actor(), 'api.scan.request', 'info', host, {'job_id': jid})
        return jsonify(job_id=jid), 202

    @web.post('/api/scan/all')
    @login_required
    def api_scan_all():
        json_body()
        jobs = {h: core.enqueue(h, actor()) for h in core.bound_hosts()}
        core.audit(conn(), actor(), 'api.scan.request_all', 'info', None, {'jobs': jobs})
        return jsonify(jobs=jobs), 202

    # vault keys: generate, install with ssh-copy-id, bind
    @web.get('/api/keys')
    @login_required
    def api_keys():
        v = Vault(db, conn())
        keys = [k | {'public_key': v.public_key(k['name'])} for k in v.list_keys()]
        return jsonify(keys=keys, bindings=v.bindings())

    @web.post('/api/keys')
    @login_required
    def api_key_generate():
        body = json_body()
        name, kind = str(body.get('name', '')).strip(), str(body.get('type') or 'ed25519')
        if not KEY_NAME.fullmatch(name):
            raise ValueError('key name: letters, digits, . _ - only (max 64)')
        if kind not in ('ed25519', 'rsa'):
            raise ValueError('type must be ed25519 or rsa')
        if conn().scalar('SELECT 1 FROM ssh_keys WHERE name = :n', {'n': name}):
            raise ValueError(f'a key named {name!r} already exists')
        with Vault(db, conn()).unlock() as v:
            info = v.generate_key(name, kind)
        core.audit(conn(), actor(), 'vault.key.generate', 'ok', None,
                   {'name': name, 'type': info['type'], 'fingerprint': info['fingerprint']})
        return jsonify(info), 201

    @web.post('/api/keys/install')
    @login_required
    @password_confirmed
    @limiter.limit(INSTALL_LIMIT, key_func=lambda: f'install:{current_user.get_id()}')
    def api_key_install():
        body = json_body()
        name, host, user = (str(body.get(k, '')).strip() for k in ('key', 'host', 'user'))
        password = str(body.get('password', ''))
        port = int(body.get('port') or 22)
        keyinstall.validate(host, user, port)
        public = Vault(db, conn()).public_key(name)
        detail = {'key': name, 'user': user, 'port': port}
        try:
            # First: even the key-only probe would pin whatever key the host shows, so a person checks it before
            # anything connects (and the password goes only to that key)
            hostkeys.require_confirmed(conn(), host, port)
            if keyinstall.key_login_works(db, conn(), name, host, user, port):   # already installed: no duplicate line
                res = {'host': host, 'user': user, 'port': port, 'keys_added': 0, 'verified': True}
            else:
                res = keyinstall.install_public_key(public, host, user, password, port)
                res['verified'] = keyinstall.key_login_works(db, conn(), name, host, user, port)
        except keyinstall.InstallError as exc:
            core.audit(conn(), actor(), 'ssh.copy-id', 'failed', host, detail | {'error': str(exc)})
            return jsonify(error=str(exc)), 502
        finally:
            del password
        core.audit(conn(), actor(), 'ssh.copy-id', 'ok' if res['verified'] else 'failed', host,
                   detail | {'fingerprint': fingerprint(public), 'keys_added': res['keys_added'], 'verified': res['verified']})
        if not res['verified']:
            return jsonify(error='ssh-copy-id finished, but logging in with the key still fails. Check that the host '
                                 'allows public key login and that ~/.ssh is not group- or world-writable.'), 502
        if body.get('bind'):
            v = Vault(db, conn())
            existing = next((b for b in v.bindings() if b['key'] == name and b['pattern'] == host and b['user'] == user), None)
            if existing:
                res['binding_id'] = existing['binding_id']
            else:
                actions = 'scan,checksum' if body.get('checksum') else 'scan'
                res['binding_id'] = v.bind(name, host, user, port, actions)
                core.audit(conn(), actor(), 'vault.bind', 'ok', host, detail | {'binding_id': res['binding_id'], 'actions': actions})
        return jsonify(res)

    @web.post('/api/hostkey/confirm')
    @login_required
    @password_confirmed
    def api_hostkey_confirm():
        body = json_body()
        host, fp = str(body.get('host', '')).strip(), str(body.get('fingerprint', '')).strip()
        port = int(body.get('port') or 22)
        if not re.fullmatch(r'SHA256:[A-Za-z0-9+/]{43}', fp):
            raise ValueError('fingerprint must look like SHA256:… (43 characters)')
        res = hostkeys.confirm(conn(), host, port, fp, actor())
        core.audit(conn(), actor(), 'ssh.hostkey.confirm', 'ok', host, {'port': port, 'fingerprint': fp})
        return jsonify(res)

    # planner designs (storageforge/v1 blueprints)
    @web.get('/api/access')
    @login_required
    def api_access():
        return jsonify(hosts=access.status(conn(), request.args.get('host') or None))

    @web.get('/api/access/script')
    @login_required
    def api_access_script():
        host = request.args.get('host', '').strip()
        user = request.args.get('user', '').strip()
        if host and not user:
            with Vault(db, conn()).unlock() as v:
                user = v.resolve(connect_address(conn(), host), 'scan').user
        if not user:
            raise ValueError('give host (to use its scan user) or user')
        script = (access.remove_script if request.args.get('remove') else access.setup_script)(user)
        return jsonify(user=user, script=script, readonly_dir=access.READONLY_DIR, group=access.GROUP)

    @web.post('/api/access/grant')
    @login_required
    @password_confirmed
    @limiter.limit(INSTALL_LIMIT, key_func=lambda: f'grant:{current_user.get_id()}')
    def api_access_grant():
        body = json_body()
        host, admin = str(body.get('host', '')).strip(), str(body.get('admin_user') or '').strip() or None
        password, remove = str(body.get('password', '')), bool(body.get('remove'))
        keyinstall.validate(host, admin or 'root', 22)
        action = 'access.revoke' if remove else 'access.grant'
        try:
            res = access.grant(db, conn(), host, password, admin, remove, str(body.get('admin_key') or '').strip() or None)
        except (RemoteError, subprocess.TimeoutExpired) as exc:
            msg = str(exc) if isinstance(exc, RemoteError) else 'timed out'
            core.audit(conn(), actor(), action, 'failed', host, {'via': admin, 'error': msg})
            return jsonify(error=msg), 502
        finally:
            del password
        core.audit(conn(), actor(), action, 'ok', host, {'user': res['user'], 'via': res['via']})
        return jsonify(res)

    @web.get('/api/browse')
    @login_required
    def api_browse():
        return jsonify(moves.browse(conn(), request.args.get('host', ''), request.args.get('path') or '/'))

    @web.get('/api/moves')
    @login_required
    def api_moves():
        return jsonify(plans=moves.list_plans(conn()))

    @web.post('/api/moves')
    @login_required
    def api_moves_create():
        pid = moves.save_plan(conn(), json_body(), actor())
        core.audit(conn(), actor(), 'moves.save', 'ok', None, {'plan': pid})
        return jsonify(moves.get_plan(conn(), pid)), 201

    @web.route('/api/moves/<int:plan_id>', methods=['GET', 'PUT', 'DELETE'])
    @login_required
    def api_move(plan_id):
        try:
            if request.method == 'PUT':
                moves.save_plan(conn(), json_body(), actor(), plan_id)
                core.audit(conn(), actor(), 'moves.save', 'ok', None, {'plan': plan_id})
            elif request.method == 'DELETE':
                moves.get_plan(conn(), plan_id)
                if [d for d in deploy.deployed(conn(), kind='jobs') if d['ref'] == f'p{plan_id}']:
                    return jsonify(error='this plan has jobs deployed on hosts: remove them first (Deploy tab → Remove from hosts)'), 409
                moves.delete_plan(conn(), plan_id)
                core.audit(conn(), actor(), 'moves.delete', 'ok', None, {'plan': plan_id})
                return jsonify(deleted=plan_id)
            return jsonify(moves.get_plan(conn(), plan_id))
        except LookupError as exc:
            return jsonify(error=str(exc)), 404

    @web.post('/api/moves/check')
    @login_required
    def api_moves_check():
        return jsonify(moves.check(conn(), moves.normalize(json_body())))

    @web.get('/api/moves/<int:plan_id>/script')
    @login_required
    def api_move_script(plan_id):
        try:
            plan = moves.get_plan(conn(), plan_id)
        except LookupError as exc:
            return jsonify(error=str(exc)), 404
        name = moves.slug(plan['name']) + '.sh'
        core.audit(conn(), actor(), 'moves.script', 'ok', None, {'plan': plan_id})
        return Response(moves.script(conn(), plan), mimetype='text/x-shellscript',
                        headers={'Content-Disposition': f'attachment; filename="{name}"'})

    @web.get('/api/git')
    @login_required
    def api_git():
        return jsonify(gitrepos.listing(conn(), request.args.get('host') or None, bool(request.args.get('all'))))

    @web.post('/api/git/survey')
    @login_required
    def api_git_survey():
        body = (request.get_json(silent=True) or {}) if request.is_json else {}
        host = body.get('host') or request.args.get('host')
        if not host:
            hosts = [r[0] for r in conn().all('SELECT hostname FROM hosts ORDER BY hostname')]
            results = []
            for h in hosts:
                try:
                    results.append(gitrepos.survey_host(db, h, actor()))
                except Exception as exc:
                    results.append({'host': h, 'error': str(exc), 'repos': 0})
            core.audit(conn(), actor(), 'git.survey', 'ok', None, {'count': len(hosts)})
            return jsonify(results=results, repos=gitrepos.listing(conn())['repos'])
        try:
            res = gitrepos.survey_host(db, host, actor())
            core.audit(conn(), actor(), 'git.survey', 'ok', host, {'repos': res.get('repos', 0)})
            return jsonify(res)
        except LookupError as exc:
            return jsonify(error=str(exc)), 404
        except Exception as exc:
            return jsonify(error=str(exc)), 502

    @web.route('/api/git/status', methods=['GET', 'POST'])
    @login_required
    def api_git_status():
        body = (request.get_json(silent=True) or {}) if request.method == 'POST' and request.is_json else {}
        host = body.get('host') or request.args.get('host')
        path = body.get('path') or request.args.get('path')
        if not host or not path:
            return jsonify(error='host and path are required'), 400
        try:
            return jsonify(gitrepos.repo_status(db, host, path, actor()))
        except LookupError as exc:
            return jsonify(error=str(exc)), 404
        except Exception as exc:
            return jsonify(error=str(exc)), 502

    @web.post('/api/git/sync')
    @login_required
    def api_git_sync():
        try:
            body = json_body()
        except ValueError as exc:
            return jsonify(error=str(exc)), 400
        host = body.get('host')
        path = body.get('path')
        action = body.get('action') or 'sync'
        if not host or not path:
            return jsonify(error='host and path are required'), 400
        if action == 'push':
            stale = password_stale()
            if stale:
                return stale
        try:
            return jsonify(gitrepos.repo_sync(db, host, path, action, actor()))
        except ValueError as exc:
            return jsonify(error=str(exc)), 400
        except LookupError as exc:
            return jsonify(error=str(exc)), 404
        except Exception as exc:
            return jsonify(error=str(exc)), 502

    @web.get('/api/git/history')
    @login_required
    def api_git_history():
        host = request.args.get('host')
        path = request.args.get('path')
        if not host or not path:
            return jsonify(error='host and path are required'), 400
        try:
            max_c = min(int(request.args.get('max', 50)), 200)
        except ValueError:
            max_c = 50
        try:
            return jsonify(gitrepos.repo_history(db, host, path, max_c))
        except LookupError as exc:
            return jsonify(error=str(exc)), 404
        except Exception as exc:
            return jsonify(error=str(exc)), 502

    @web.get('/api/git/commit')
    @login_required
    def api_git_commit():
        host = request.args.get('host')
        path = request.args.get('path')
        sha = request.args.get('sha')
        if not host or not path or not sha:
            return jsonify(error='host, path and sha are required'), 400
        try:
            return jsonify(gitrepos.repo_commit(db, host, path, sha))
        except ValueError as exc:
            return jsonify(error=str(exc)), 400
        except LookupError as exc:
            return jsonify(error=str(exc)), 404
        except Exception as exc:
            return jsonify(error=str(exc)), 502

    @web.get('/api/shares/check')
    @login_required
    def api_shares_check():
        try:
            return jsonify(shares.check(conn(), request.args.get('host', '')))
        except LookupError as exc:
            return jsonify(error=str(exc)), 404

    @web.get('/api/shares/script')
    @login_required
    def api_shares_script():
        host = request.args.get('host', '')
        try:
            text = shares.script(conn(), host)
        except LookupError as exc:
            return jsonify(error=str(exc)), 404
        core.audit(conn(), actor(), 'shares.script', 'ok', host, {})
        return Response(text, mimetype='text/x-shellscript',
                        headers={'Content-Disposition': f'attachment; filename="shares-{moves.host_slug(host)}.sh"'})

    @web.post('/api/shares/validate')
    @login_required
    def api_shares_validate():
        body = json_body()
        idx = body.get('index')
        try:
            return jsonify(shares.validate(conn(), str(body.get('host', '')), body.get('export') or {},
                                           None if idx is None else int(idx), body.get('was') or None))
        except LookupError as exc:
            return jsonify(error=str(exc)), 404

    @web.route('/api/shares', methods=['POST', 'DELETE'])
    @login_required
    def api_shares_save():
        try:
            if request.method == 'DELETE':
                host, idx = request.args.get('host', ''), int(request.args.get('index', -1))
                was = {k: request.args[k] for k in ('protocol', 'name', 'path') if k in request.args} or None
                res = shares.remove_export(db, conn(), host, idx, was)
                core.audit(conn(), actor(), 'shares.remove', 'ok', host, {'index': idx})
                return jsonify(res)
            body = json_body()
            idx = body.get('index')
            res = shares.save_export(db, conn(), str(body.get('host', '')), body.get('export') or {},
                                     None if idx is None else int(idx), actor(), body.get('was') or None)
            core.audit(conn(), actor(), 'shares.save', 'ok', res['host'],
                       {'index': res['index'], 'path': res['export']['path'], 'proto': res['export']['protocol']})
            return jsonify(res)
        except LookupError as exc:
            return jsonify(error=str(exc)), 404

    @web.get('/api/fs/browse')
    @login_required
    def api_fs_browse():
        try:
            return jsonify(fsmap.browse(conn(), request.args.get('host', ''), request.args.get('path') or '/'))
        except LookupError as exc:
            return jsonify(error=str(exc)), 404

    @web.route('/api/tasks', methods=['GET', 'POST'])
    @login_required
    def api_tasks():
        c = conn()
        if request.method == 'POST':
            tid = tasks.save_task(c, json_body(), actor())
            core.audit(c, actor(), 'tasks.save', 'ok', None, {'task': tid})
            return jsonify(tasks.get_task(c, tid)), 201
        return jsonify(tasks=tasks.list_tasks(c), types=tasks.TYPES, categories=tasks.CATEGORIES,
                       templates=tasks.TEMPLATES, schedules=tasks.SCHEDULES, installed=tasks.installed(c))

    @web.route('/api/tasks/<int:task_id>', methods=['GET', 'PUT', 'DELETE'])
    @login_required
    def api_task(task_id):
        c = conn()
        try:
            if request.method == 'PUT':
                tasks.save_task(c, json_body(), actor(), task_id)
                core.audit(c, actor(), 'tasks.save', 'ok', None, {'task': task_id})
            elif request.method == 'DELETE':
                t = tasks.get_task(c, task_id)
                if tasks.installed(c).get(moves.slug(t['name'])):
                    return jsonify(error='this task is installed on a host: uninstall it first'), 409
                tasks.delete_task(c, task_id)
                core.audit(c, actor(), 'tasks.delete', 'ok', None, {'task': task_id})
                return jsonify(deleted=task_id)
            return jsonify(tasks.get_task(c, task_id))
        except LookupError as exc:
            return jsonify(error=str(exc)), 404

    @web.post('/api/tasks/check')
    @login_required
    def api_tasks_check():
        return jsonify(tasks.check(conn(), json_body()))

    @web.post('/api/tasks/script')
    @login_required
    def api_tasks_script():
        body = json_body()
        name = 'task-' + moves.slug(str(body.get('name') or 'task')) + '.sh'
        core.audit(conn(), actor(), 'tasks.script', 'ok', None, {'task': body.get('id'), 'name': body.get('name')})
        return Response(tasks.script(conn(), body), mimetype='text/x-shellscript',
                        headers={'Content-Disposition': f'attachment; filename="{name}"'})

    @web.get('/api/changes/types')
    @login_required
    def api_change_types():
        return jsonify(types=changes.TYPES)

    @web.get('/api/changes')
    @login_required
    def api_changes():
        return jsonify(plans=changes.list_plans(conn()))

    @web.post('/api/changes')
    @login_required
    def api_changes_create():
        pid = changes.save_plan(conn(), json_body(), actor())
        core.audit(conn(), actor(), 'changes.save', 'ok', None, {'plan': pid})
        return jsonify(changes.get_plan(conn(), pid)), 201

    @web.route('/api/changes/<int:plan_id>', methods=['GET', 'PUT', 'DELETE'])
    @login_required
    def api_change(plan_id):
        try:
            if request.method == 'PUT':
                changes.save_plan(conn(), json_body(), actor(), plan_id)
                core.audit(conn(), actor(), 'changes.save', 'ok', None, {'plan': plan_id})
            elif request.method == 'DELETE':
                changes.get_plan(conn(), plan_id)
                changes.delete_plan(conn(), plan_id)
                core.audit(conn(), actor(), 'changes.delete', 'ok', None, {'plan': plan_id})
                return jsonify(deleted=plan_id)
            return jsonify(changes.get_plan(conn(), plan_id))
        except LookupError as exc:
            return jsonify(error=str(exc)), 404

    @web.post('/api/changes/<int:plan_id>/ran')
    @login_required
    def api_change_mark_ran(plan_id):
        try:
            plan = changes.mark_ran(conn(), plan_id, actor())
            core.audit(conn(), actor(), 'changes.ran', 'ok', None, {'plan': plan_id})
            return jsonify(plan)
        except LookupError as exc:
            return jsonify(error=str(exc)), 404

    @web.post('/api/changes/check')
    @login_required
    def api_changes_check():
        return jsonify(changes.check(conn(), changes.normalize(json_body())))

    @web.get('/api/changes/<int:plan_id>/<any("script", "ansible"):kind>')
    @login_required
    def api_change_out(plan_id, kind):
        try:
            plan = changes.get_plan(conn(), plan_id)
        except LookupError as exc:
            return jsonify(error=str(exc)), 404
        text = changes.script(conn(), plan) if kind == 'script' else changes.ansible(conn(), plan)
        name = f'changes-{moves.slug(plan["name"])}.' + ('sh' if kind == 'script' else 'yml')
        core.audit(conn(), actor(), f'changes.{kind}', 'ok', None, {'plan': plan_id})
        return Response(text, mimetype='text/x-shellscript' if kind == 'script' else 'application/yaml',
                        headers={'Content-Disposition': f'attachment; filename="{name}"'})

    @web.get('/api/docker')
    @login_required
    def api_docker():
        return jsonify(hosts=docker.listing(conn(), request.args.get('host') or None))

    @web.get('/api/docker/usage')
    @login_required
    def api_docker_usage():
        host, path = request.args.get('host') or None, request.args.get('path') or ''
        if path:
            if not host:
                raise ValueError('give host with path')
            return jsonify(usage=docker.users_of(conn(), host, path))
        return jsonify(usage=docker.usage(conn(), host))

    # ── deployments ───────────────────────────────────────────────────
    @web.get('/api/deploy')
    @login_required
    def api_deploy():
        c = conn()
        return jsonify(access=deploy.access(c), jobs=jobs.overview(c), deployed=deploy.deployed(c), checks=preflight.stored(c),
                       groups=engine.recent(c, 25), keys=[r[0] for r in c.all('SELECT name FROM ssh_keys ORDER BY name')],
                       alerts=alerts.list_alerts(c), drift=alerts.drift(c), settings=alerts.settings(c),
                       runs=deploy.history(c, limit=30), plans=moves.list_plans(c))

    @web.post('/api/deploy/setup-script')     # POST with a JSON body: it makes the deploy keys on first use
    @login_required
    def api_deploy_setup_script():
        remove = bool(json_body().get('remove'))
        core.audit(conn(), actor(), 'deploy.setup-script', 'ok', None, {})
        return Response(deploy.setup_for_download(db, conn()) if not remove else deploy.remove_script(),
                        mimetype='text/x-shellscript',
                        headers={'Content-Disposition': 'attachment; filename="storageforge-deploy-setup.sh"'})

    @web.post('/api/deploy/access')
    @login_required
    @password_confirmed
    @limiter.limit(INSTALL_LIMIT, key_func=lambda: f'deploy-access:{current_user.get_id()}')
    def api_deploy_access():
        body = json_body()
        host, admin = str(body.get('host', '')).strip(), str(body.get('admin_user') or '').strip() or None
        password = str(body.get('password', ''))
        keyinstall.validate(host, admin or 'root', 22)
        try:
            return jsonify(deploy.enroll(db, conn(), host, password, admin, actor(), bool(body.get('remove')),
                                         str(body.get('admin_key') or '').strip() or None))
        except (RemoteError, subprocess.TimeoutExpired) as exc:
            return jsonify(error=str(exc) if isinstance(exc, RemoteError) else 'timed out'), 502
        finally:
            del password

    @web.post('/api/deploy/adopt')
    @login_required
    @password_confirmed
    def api_deploy_adopt():
        return jsonify(deploy.adopt(db, conn(), str(json_body().get('host', '')).strip(), actor()))

    def deploy_items_for(c, kind, ref, mode, options):
        """The runs of one deploy. Also what a retry rebuilds them from: each keeps its options, none its old script."""
        if kind == 'jobs':
            pid = int(ref)
            try:
                plan = moves.get_plan(c, pid)
            except LookupError:            # a deleted plan: deploying it empty removes its jobs from the hosts
                plan = {'id': pid, 'name': f'deleted plan {pid}', 'steps': []}
            if options.get('remove'):
                plan = {**plan, 'steps': []}
            return jobs.deploy_items(db, c, plan, mode, alerts.get_setting(c, 'report_url'), actor(), bool(options.get('paused')))
        if kind == 'shares':
            return shares.deploy_items(db, c, str(ref or ''), mode, actor())
        if kind == 'changes':
            return changes.deploy_items(db, c, changes.get_plan(c, int(ref)), mode, actor(), bool(options.get('destructive')))
        if kind == 'tasks':
            return tasks.deploy_items(db, c, tasks.get_task(c, int(ref)), mode, actor(), bool(options.get('run')), bool(options.get('remove')))
        raise ValueError('kind is jobs, shares, changes or tasks')

    def deploy_digest(c, kind, ref):
        """A fingerprint of what this deploy is made from, to tell whether a dry run still describes it."""
        try:
            if kind == 'jobs':
                return jobs.plan_hash(moves.get_plan(c, int(ref)))
            if kind == 'shares':
                return shares.design_hash(c, str(ref or ''))
            if kind == 'changes':
                return changes.plan_hash(changes.get_plan(c, int(ref)))
            if kind == 'tasks':
                return tasks.task_hash(tasks.get_task(c, int(ref)))
        except LookupError:
            return None
        return None

    @web.post('/api/deploy/start')
    @login_required
    @password_confirmed
    def api_deploy_start():
        body = json_body()
        kind, mode, ref = body.get('kind'), body.get('mode', 'report'), body.get('ref')
        if mode not in ('report', 'apply'):
            raise ValueError('mode is report or apply')
        c = conn()
        options = {k: bool(body[k]) for k in ('remove', 'paused', 'destructive', 'run') if body.get(k)}
        items = deploy_items_for(c, kind, ref, mode, options)
        if not items:
            raise ValueError('nothing to deploy: no hosts are involved')
        missing = [it['host'] for it in items if not deploy.ready(c, it['host'])]
        if missing:
            return jsonify(error='set up deploy access first on: ' + ', '.join(sorted(set(missing))), hosts=sorted(set(missing))), 409
        blocked = preflight.blockers(c, [it['host'] for it in items], kind)
        if blocked:
            return jsonify(error='; '.join(f'{b["host"]}: {b["text"]}' for b in blocked), blockers=blocked), 409
        digest = deploy_digest(c, kind, ref)
        report = str(body.get('report_group') or '')
        if report and mode == 'apply':      # the dry run someone read must still describe what this applies
            seen = engine.get(c, report) if re.fullmatch(r'[0-9a-f]{32}', report) else None
            if seen and seen['digest'] != digest:
                return jsonify(error='the plan changed since this dry run: run the dry run again', stale=True), 409
        who = actor()
        # every view reads the index: without a rescan, an apply that worked looks like nothing changed
        title = str(body.get('title') or f'{kind} {ref}')[:200]
        gid = deploy.start_group(db, items, who, stop_on_failure=mode == 'apply', after=lambda h: core.enqueue(h, who), title=title,
                                 kind=kind, ref=str(ref), mode=mode, options=options, digest=digest, report_group=report or None)
        core.audit(c, actor(), 'deploy.start', 'ok', None, {'kind': kind, 'ref': ref, 'mode': mode, 'group': gid})
        return jsonify(group=gid, hosts=[it['host'] for it in items], digest=digest)

    @web.get('/api/deploy/groups')
    @login_required
    def api_deploy_groups():
        return jsonify(groups=engine.recent(conn(), arg_num('limit', 30, 1, 200), request.args.get('host') or None))

    @web.post('/api/deploy/groups/<gid>/cancel')
    @login_required
    def api_deploy_group_cancel(gid):
        if not re.fullmatch(r'[0-9a-f]{32}', gid):
            raise ValueError('bad group id')
        res = engine.cancel(db, gid, actor(), bool(json_body().get('force')))
        core.audit(conn(), actor(), 'deploy.cancel', 'ok', None, {'group': gid, 'force': bool(json_body().get('force'))})
        return jsonify(res)

    @web.post('/api/deploy/groups/<gid>/retry')
    @login_required
    @password_confirmed
    def api_deploy_group_retry(gid):
        if not re.fullmatch(r'[0-9a-f]{32}', gid):
            raise ValueError('bad group id')
        c = conn()
        g = engine.get(c, gid)
        if not g:
            raise LookupError('no such deploy')
        if engine.running(gid):
            return jsonify(error='that deploy is still running'), 409
        if g['kind'] not in ('jobs', 'shares', 'changes', 'tasks'):
            raise ValueError('only plans and designs can be retried')
        items = deploy_items_for(c, g['kind'], g['ref'], g['mode'], g['options'])
        if g['kind'] != 'jobs':       # job keys are new on every apply, so a job's two hosts must get them together
            left = set(engine.unfinished_hosts(c, gid))
            items = [it for it in items if it['host'] in left]
        if not items:
            raise ValueError('every host of that deploy finished')
        who = actor()
        new = deploy.start_group(db, items, who, stop_on_failure=g['mode'] == 'apply', after=lambda h: core.enqueue(h, who),
                                 title=g['title'], kind=g['kind'], ref=g['ref'], mode=g['mode'], options=g['options'],
                                 digest=deploy_digest(c, g['kind'], g['ref']), retry_of=gid)
        core.audit(c, who, 'deploy.retry', 'ok', None, {'group': new, 'retry_of': gid})
        return jsonify(group=new, hosts=[it['host'] for it in items], kind=g['kind'], ref=g['ref'], mode=g['mode'], title=g['title'], extra=g['options'])

    @web.post('/api/deploy/check')
    @login_required
    def api_deploy_check():
        host = str(json_body().get('host', '')).strip()
        keyinstall.validate(host, 'root', 22)
        return jsonify(preflight.host_report(db, conn(), host, actor()))

    @web.get('/api/deploy/groups/<gid>')
    @login_required
    def api_deploy_group(gid):
        if not re.fullmatch(r'[0-9a-f]{32}', gid):
            raise ValueError('bad group id')
        c = conn()
        return jsonify(runs=engine.runs(c, gid), group=engine.get(c, gid))

    @web.get('/api/deploy/runs')
    @login_required
    def api_deploy_runs():
        return jsonify(runs=deploy.history(conn(), request.args.get('host') or None, arg_num('limit', 50, 1, 500)))

    @web.get('/api/deploy/runs/<int:run_id>')
    @login_required
    def api_deploy_run(run_id):
        try:
            return jsonify(deploy.output(conn(), run_id))
        except LookupError as exc:
            return jsonify(error=str(exc)), 404

    @web.get('/api/deploy/jobs/<jid>')
    @login_required
    def api_deploy_job(jid):
        try:
            return jsonify(job=jobs.get(conn(), jid), runs=jobs.runs(conn(), jid, 100))
        except LookupError as exc:
            return jsonify(error=str(exc)), 404

    @web.post('/api/deploy/jobs/<jid>/<any("run", "dryrun", "verify", "pause", "resume", "cutover", "log", "snapshots"):verb>')
    @login_required
    def api_deploy_job_action(jid, verb):
        if verb not in ('dryrun', 'log', 'snapshots'):   # these only read
            stale = password_stale()
            if stale:
                return stale
        try:
            return jsonify(jobs.action(db, conn(), jid, verb, actor()))
        except LookupError as exc:
            return jsonify(error=str(exc)), 404

    @web.post('/api/deploy/jobs/<jid>/browse')     # POST: it runs a command on the host, so no GET can trigger it
    @login_required
    def api_deploy_job_browse(jid):
        body = json_body()
        return jsonify(jobs.browse(db, conn(), jid, str(body.get('snapshot', '')), str(body.get('path', '')), actor()))

    @web.post('/api/deploy/jobs/<jid>/restore')
    @login_required
    @password_confirmed
    def api_deploy_job_restore(jid):
        # Runs in the background (a restore can take hours): the answer is the group to poll, like a deploy's
        body = json_body()
        snapshot, rel, who = str(body.get('snapshot', '')), str(body.get('path', '')), actor()
        j, target, parent = jobs.restore_target(conn(), jid, snapshot, rel)

        def work(gid):
            c = db.connect()
            try:
                jobs.restore(db, c, jid, snapshot, rel, who, gid=gid, target=target)
            finally:
                c.close()
        gid = deploy.start_task(db, j['source'], 'restore', jid, who, work)
        return jsonify(group=gid, target=target, parent=parent), 202

    @web.route('/api/deploy/settings', methods=['GET', 'PUT'])
    @login_required
    def api_deploy_settings():
        if request.method == 'PUT':
            # the report URL goes into every job a deploy writes, and the alert channels hold tokens
            stale = password_stale()
            if stale:
                return stale
            s = alerts.save_settings(conn(), json_body(), actor())
            core.audit(conn(), actor(), 'deploy.settings', 'ok', None, {})
            return jsonify(s)
        return jsonify(alerts.settings(conn()))

    @web.post('/api/deploy/settings/test')
    @login_required
    @limiter.limit('10 per minute')
    def api_deploy_settings_test():
        return jsonify(sent=alerts.send(alerts.get_setting(conn(), 'alerts'), 'StorageForge test alert',
                                        f'Sent by {current_user.username} from the Deploy tab.', 'ok', {'state': 'test'}))

    @web.post('/api/jobs/report')
    @limiter.limit('120 per minute')
    def api_jobs_report():
        auth = request.headers.get('Authorization', '')
        token = auth[7:].strip() if auth.startswith('Bearer ') else ''
        jid = jobs.job_for_token(conn(), token)
        if not jid:
            return jsonify(error='unknown job token'), 401
        body = json_body()
        if body.get('job') != jid:
            return jsonify(error='this token belongs to another job'), 403
        new = jobs.ingest(conn(), body, f'report:{request.remote_addr}'[:60])   # where it came from, for the record
        if new:
            core.alerts_wake.set()
        return jsonify(ok=True, new=new)

    @web.get('/api/hostconfigs')
    @login_required
    def api_hostconfigs():
        host = request.args.get('host') or None
        missing = []
        if not host:
            have = {v[0] for v in conn().all('SELECT DISTINCT lower(hostname) FROM host_configs')}
            missing = [n for (n,) in conn().all('SELECT hostname FROM hosts ORDER BY lower(hostname)') if n.lower() not in have]
        return jsonify(versions=hostconfig.versions(conn(), host), not_captured=missing, keep=hostconfig.KEEP)

    @web.get('/api/hostconfigs/script')
    @login_required
    def api_hostconfig_script():
        host, cid = request.args.get('host', ''), arg_num('id', 0, 0, 2**53)
        v = hostconfig.get(conn(), cid) if cid else hostconfig.latest(conn(), host)
        if not v:
            return jsonify(error=f'nothing captured for {host}: scan it first'), 404
        core.audit(conn(), actor(), 'hostconfig.script', 'ok', v['host'], {'version': v['config_id']})
        return Response(reinstall.script(v).encode('utf-8', 'surrogateescape'), mimetype='text/x-shellscript',
                        headers={'Content-Disposition': f'attachment; filename="reinstall-{moves.host_slug(v["host"])}.sh"'})

    @web.get('/api/hostconfigs/bundle')
    @login_required
    def api_hostconfig_bundle():
        host, cid = request.args.get('host') or None, arg_num('id', 0, 0, 2**53)
        try:
            data = hostconfig.bundle(conn(), [host] if host else None, cid or None)
        except LookupError as exc:
            return jsonify(error=str(exc)), 404
        core.audit(conn(), actor(), 'hostconfig.export', 'ok', host, {'version': cid or None, 'bytes': len(data)})
        name = f'hostconfig-{moves.host_slug(host)}.tar.gz' if host else 'hostconfigs.tar.gz'
        return Response(data, mimetype='application/gzip', headers={'Content-Disposition': f'attachment; filename="{name}"'})

    @web.get('/api/hostconfigs/<int:config_id>')
    @login_required
    def api_hostconfig(config_id):
        v = hostconfig.get(conn(), config_id)
        if not v:
            return jsonify(error='no such version'), 404
        body = v['body']
        prev = conn().scalar('SELECT max(config_id) FROM host_configs WHERE hostname = :h AND config_id < :i', {'h': v['host'], 'i': config_id})
        old = hostconfig.get(conn(), prev) if prev else None
        return jsonify(config_id=config_id, host=v['host'], captured_at=v['captured_at'], summary=hostconfig.summary(body),
                       mounts=body.get('mounts') or [], datasets=body.get('datasets') or [], crypt=body.get('crypt') or [],
                       files=sorted(body.get('files') or {}), unreadable=body.get('unreadable') or [],
                       exports=body.get('exports') or [], links=body.get('links') or [], accounts=body.get('accounts') or {},
                       previous=prev, changes=hostconfig.diff(old['body'], body) if old else [])

    @web.get('/api/backups')
    @login_required
    def api_backups():
        from . import backup
        return jsonify(backups=backup.listing() if db.dialect == 'sqlite' else [], hour=BACKUP_HOUR, keep=BACKUP_KEEP,
                       full_keep=BACKUP_FULL)

    @web.post('/api/backups')
    @login_required
    @limiter.limit('6 per hour', key_func=lambda: f'backup:{current_user.get_id()}')
    def api_backup_now():
        from . import backup
        if db.dialect != 'sqlite':
            return jsonify(error='backups of a PostgreSQL database are pg_dump\'s job: pg_dump -Fc storageforge > storageforge.dump'), 400
        kind = 'full' if (json_body().get('kind') == 'full') else 'essentials'
        res = backup.create(db, kind, keep=BACKUP_KEEP if kind == 'essentials' else max(BACKUP_FULL, 2))
        core.audit(conn(), actor(), 'backup.create', 'ok', None, {'path': res['path'], 'bytes': res['bytes']})
        return jsonify(res)

    folder_cache: dict = {}
    folder_lock = threading.Lock()

    def folder_result(key: tuple, compute):
        """Folder analysis is slow on big indexes: kept until the index changes. A scan adds its scan id when it starts
        and its files as it goes, so nothing is kept while one runs; it would hold half of it under the new id."""
        latest, running = conn().all("SELECT max(scan_id), count(CASE WHEN status = 'running' THEN 1 END) FROM scans")[0]
        key = (*key, latest)
        with folder_lock:
            hit = folder_cache.get(key)
        if hit is not None:
            return hit
        result = compute()
        if not running:
            with folder_lock:
                for k in [k for k in folder_cache if k[-1] != latest or len(folder_cache) >= 8]:
                    del folder_cache[k]       # the Cleanup tab asks for cold and duplicate folders at once: both stay
                folder_cache[key] = result
        return result

    @web.get('/api/folders/cold')
    @login_required
    def api_folders_cold():
        host = request.args.get('host') or None
        years = arg_num('years', 2.0, 0.1, 100.0, float)
        min_size = parse_size(request.args.get('min_size') or '1GiB')
        return jsonify(folder_result(('cold', host, years, min_size),
                                     lambda: folders.cold_folders(conn(), host, years, min_size, limit=200)))

    @web.get('/api/folders/duplicates')
    @login_required
    def api_folder_dupes():
        host = request.args.get('host') or None
        min_files = arg_num('min_files', 3, 1, 1_000_000)
        min_size = parse_size(request.args.get('min_size') or '1MiB')
        return jsonify(folder_result(('dupes', host, min_files, min_size),
                                     lambda: folders.duplicate_folders(conn(), host, min_files, min_size, limit=200)))

    def scanned(host: str) -> bool:
        return bool(conn().scalar('SELECT 1 FROM hosts WHERE hostname = :h', {'h': host}))

    scan_designs = {}                        # host: (scan_mark, the design as JSON), kept until the next scan changes it

    def scan_design(host: str) -> dict:
        mark, kept = blueprint.scan_mark(conn(), host), scan_designs.get(host)
        if kept and kept[0] == mark:         # a fresh copy each time: merge_intent writes into it
            bp = json.loads(kept[1])
            bp['metadata']['generated'] = time.strftime('%Y-%m-%d')
            return bp
        bp = blueprint.from_index(conn(), host)
        scan_designs[host] = (mark, json.dumps(bp))
        return bp

    @web.get('/api/planner/hosts')
    @login_required
    def api_planner_hosts():
        hosts = {r[0]: {'host': r[0], 'scanned': True, 'last_scanned_at': epoch(r[1]), 'saved': False, 'saved_at': None}
                 for r in conn().all('SELECT hostname, last_scanned_at FROM hosts ORDER BY hostname')}
        for name, at in conn().all('SELECT hostname, imported_at FROM blueprints ORDER BY hostname'):
            hosts.setdefault(name, {'host': name, 'scanned': False, 'last_scanned_at': None})
            hosts[name].update(saved=True, saved_at=at)
        return jsonify(hosts=sorted(hosts.values(), key=lambda h: h['host']),
                       example=not alerts.get_setting(conn(), 'planner.hide_example'))

    @web.put('/api/planner/example')
    @login_required
    def api_planner_example():
        show = bool(json_body().get('show'))
        alerts.set_setting(conn(), 'planner.hide_example', not show, actor())
        core.audit(conn(), actor(), 'planner.example', 'ok', None, {'show': show})
        return jsonify(example=show)

    @web.get('/api/planner/activity')
    @login_required
    def api_planner_activity():
        host = request.args.get('host', '').strip()
        if not host:
            raise ValueError('give host')
        return jsonify(planner_activity(conn(), host))

    @web.get('/api/planner/design')
    @login_required
    def api_planner_design():
        host, source = request.args.get('host', '').strip(), request.args.get('source') or 'saved'
        if not host:
            raise ValueError('give host')
        saved = graph.stored_blueprint(conn(), host)
        saved_at = conn().scalar('SELECT imported_at FROM blueprints WHERE hostname = :h', {'h': host})
        if source == 'saved' and saved:
            return jsonify(host=host, source='saved', saved_at=saved_at, scanned=scanned(host), blueprint=saved)
        if not scanned(host):
            return jsonify(error=f'{host} has no saved design and has not been scanned'), 404
        bp = blueprint.merge_intent(scan_design(host), saved)
        return jsonify(host=host, source='scan', saved_at=saved_at, scanned=True, blueprint=bp)

    @web.post('/api/planner/changes')
    @login_required
    def api_planner_changes():
        bp = json_body()
        if bp.get('apiVersion') != 'storageforge/v1' or bp.get('kind') != 'StorageBlueprint':
            raise ValueError('expected a storageforge/v1 StorageBlueprint')
        try:
            return jsonify(fromdesign.plan(conn(), bp))
        except LookupError as exc:           # not scanned: there is nothing to compare the design with
            return jsonify(error=str(exc)), 409

    @web.put('/api/planner/design')
    @login_required
    def api_planner_save():
        bp = json_body()
        if bp.get('apiVersion') != 'storageforge/v1' or bp.get('kind') != 'StorageBlueprint':
            raise ValueError('expected a storageforge/v1 StorageBlueprint')
        blueprint.check_text(bp)             # it ends up in build, share and change scripts, and in every view
        host = str((bp.get('metadata') or {}).get('host') or '').strip()
        if not host or len(host) > 253 or any(c.isspace() for c in host):
            raise ValueError('metadata.host must be a hostname')
        if 'layout' not in bp:       # the planner page does not carry the topology layout: keep the saved one
            kept = (graph.stored_blueprint(conn(), host) or {}).get('layout')
            if kept:
                bp['layout'] = kept
        graph.store_blueprint(conn(), bp)
        rebuilt = None
        if scanned(host):            # overlay the design on the scanned graph right away
            rebuilt = dict(zip(('nodes', 'edges'), graph.rebuild_host(db, conn(), host)))
        else:                        # a planned host: the design is the whole graph
            from .payloads import node_from_blueprint
            nodes, edges = graph.build(node_from_blueprint(bp))
            graph.save(db, conn(), host, nodes, edges)
            rebuilt = {'nodes': len(nodes), 'edges': len(edges)}
        core.audit(conn(), actor(), 'planner.save', 'ok', host,
                   {'devices': len(bp.get('devices') or []), 'pools': len(bp.get('pools') or []),
                    'protection': len(bp.get('protection') or []), 'graph': rebuilt})
        return jsonify(host=host, saved_at=int(time.time()), graph=rebuilt)

    return web


def planner_activity(c, host: str) -> dict:
    """What the rest of StorageForge holds for one host, for the planner's overview: staged changes, data moves,
    designed shares, deployed jobs, drift and unreadable folders."""
    same_host = fsmap.same_host
    staged = []
    for p in changes.list_plans(c):
        mine = [t for t in changes.get_plan(c, p['id']).get('tasks') or [] if same_host(t['host'], host)]
        if mine:
            staged.append({'id': p['id'], 'name': p['name'], 'tasks': len(mine),
                           'types': sorted({changes.TYPES.get(t['type'], {}).get('label', t['type']) for t in mine})})
    moving = []
    for p in moves.list_plans(c):
        steps = moves.get_plan(c, p['id']).get('steps') or []
        mine = [s for s in steps if same_host(s['src']['host'], host) or same_host(s['dst']['host'], host)]
        if mine:
            moving.append({'id': p['id'], 'name': p['name'], 'steps': len(mine)})
    try:
        sh = shares.check(c, host)
        designed = {'exports': len(sh['exports']), 'crit': sh['crit'], 'warn': sh['warn']}
    except LookupError:
        designed = None
    running = [{'id': j['id'], 'name': j['name'], 'method': j['method'], 'state': j['state'], 'src': j['src'], 'dst': j['dst']}
               for j in jobs.overview(c) if same_host(j['runner'] or '', host) or same_host(j['source'] or '', host)]
    acc = next(iter(access.status(c, host, limit=0)), None)
    return {'host': host, 'changes': staged, 'moves': moving, 'shares': designed, 'jobs': running,
            'deployed': [{'kind': d['kind'], 'ref': d['ref'], 'at': d['at']} for d in deploy.deployed(c) if same_host(d['host'], host)],
            'drift': [x for x in alerts.drift(c) if same_host(x['host'], host)],
            'unreadable': acc['denied_total'] if acc else None, 'access': acc['access'] if acc else None}


def serve(db: Database, host: str, port: int, scan_interval: int | None, parallel: int = 4):
    from waitress import serve as waitress_serve
    conn = db.connect()
    try:
        if not users.count(conn):
            print('warning: no web users yet; create one with: storageforge-index user add <name>', file=sys.stderr)
        stale = conn.all("SELECT scan_id FROM scans WHERE status = 'running'")   # killed by the last shutdown
        if stale:
            conn.execute(f"UPDATE scans SET status = 'failed', finished_at = {db.ts(':now')} WHERE status = 'running'",
                         {'now': int(time.time())})
            print(f'marked {len(stale)} interrupted scan(s) as failed', file=sys.stderr)
    finally:
        conn.close()
    secure = os.environ.get('STORAGEFORGE_COOKIE_SECURE', '0').lower() in ('1', 'true', 'yes')
    hops = int(os.environ.get('STORAGEFORGE_PROXY_HOPS', '0'))
    web = create_app(App(db, scan_interval, parallel), session_secret_from_env(), secure, hops,
                     os.environ.get('STORAGEFORGE_PROXY_HOST', ''))
    print(f'StorageForge {__version__} listening on http://{host}:{port}', file=sys.stderr, flush=True)
    waitress_serve(web, host=host, port=port, threads=8, ident='StorageForge', _quiet=True)
